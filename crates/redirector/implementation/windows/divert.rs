//! The few WinDivert calls the redirector makes, through a WinDivert.dll loaded when first needed.
//!
//! httptap.exe carries WinDivert's DLL and driver and writes them beside itself where missing, so one may put another build there.
//! https://reqrypt.org/windivert-doc.html

use std::ffi::{CStr, c_void};
use std::fs;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BAD_EXE_FORMAT, ERROR_DRIVER_BLOCKED,
    ERROR_DRIVER_FAILED_PRIOR_UNLOAD, ERROR_FILE_NOT_FOUND, ERROR_INVALID_IMAGE_HASH, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::core::BOOL;

use smoltcp::wire::IpProtocol;

use crate::packet::Transport;
use crate::table::Flow;

/// The names of the functions the redirector calls, in the order of `Library`'s fields.
///
/// https://reqrypt.org/windivert-doc.html#divert_open
const SYMBOLS: [&CStr; 5] = [
    c"WinDivertOpen",
    c"WinDivertRecv",
    c"WinDivertSend",
    c"WinDivertShutdown",
    c"WinDivertClose",
];
/// The file name of the DLL.
const LIBRARY_NAME: &str = "WinDivert.dll";
/// The file name of the driver, which the DLL installs from its own folder.
const DRIVER_NAME: &str = "WinDivert64.sys";
/// The folder beside the executable the files are written to, named for their version.
const FOLDER: &str = "httptap-windivert-2.2.2";
/// The files written to the folder: WinDivert 2.2.2's signed x64 release, unchanged.
///
/// https://github.com/basil00/WinDivert/releases/tag/v2.2.2
const FILES: [(&str, &[u8]); 2] = [
    (LIBRARY_NAME, include_bytes!("windivert/WinDivert.dll")),
    (DRIVER_NAME, include_bytes!("windivert/WinDivert64.sys")),
];
/// The layer of IP packets.
///
/// https://reqrypt.org/windivert-doc.html#divert_open
pub(crate) const NETWORK: u32 = 0;
/// The layer of socket operations, which names the process behind each.
///
/// https://reqrypt.org/windivert-doc.html#divert_open
pub(crate) const SOCKET: u32 = 3;
/// The flag that copies packets or events instead of taking them.
///
/// https://reqrypt.org/windivert-doc.html#divert_open
pub(crate) const SNIFF: u64 = 0x0001;
/// The flag that makes a handle only receive.
///
/// https://reqrypt.org/windivert-doc.html#divert_open
pub(crate) const RECEIVE_ONLY: u64 = 0x0004;
/// The flag that makes a handle only send.
///
/// https://reqrypt.org/windivert-doc.html#divert_open
pub(crate) const SEND_ONLY: u64 = 0x0008;
/// The event of a `connect()`, or of a UDP socket's first datagram to an address.
///
/// https://reqrypt.org/windivert-doc.html#divert_address
const SOCKET_CONNECT: u64 = 4;
/// The event of an `accept()`.
///
/// https://reqrypt.org/windivert-doc.html#divert_address
const SOCKET_ACCEPT: u64 = 6;
/// The shutdown of both receiving and sending, which wakes a blocked receive.
///
/// https://reqrypt.org/windivert-doc.html#divert_shutdown
const SHUTDOWN_BOTH: u32 = 0x3;
/// The error when the Base Filtering Engine service is disabled.
///
/// https://reqrypt.org/windivert-doc.html#divert_open
const EPT_S_NOT_REGISTERED: u32 = 1753;
/// The bit where the event starts in an address's flags, after the 8-bit layer.
const EVENT_SHIFT: u32 = u8::BITS;
/// The bit set for an outbound packet.
///
/// https://github.com/basil00/WinDivert/blob/master/include/windivert.h
const OUTBOUND_BIT: u32 = 17;
/// The bit set for an IPv6 packet or event.
///
/// https://github.com/basil00/WinDivert/blob/master/include/windivert.h
const IPV6_BIT: u32 = 20;
/// The 32-bit words of an address in an event, which holds IPv4 as an IPv4-mapped IPv6 address.
const ADDRESS_WORDS: usize = size_of::<Ipv6Addr>() / size_of::<u32>();
/// The bytes of the layer-specific part of an address.
///
/// https://reqrypt.org/windivert-doc.html#divert_address
const LAYER_DATA: usize = 64;
/// The bytes of a whole address, which the struct must match.
///
/// https://reqrypt.org/windivert-doc.html#divert_address
const ADDRESS_SIZE: usize = 80;
const _: () =
    assert!(size_of::<Address>() == ADDRESS_SIZE && size_of::<SocketData>() <= LAYER_DATA);

/// An untyped function pointer from `GetProcAddress`, before its cast.
type Symbol = unsafe extern "system" fn() -> isize;
/// WinDivertOpen: a handle for a filter on a layer.
type Open =
    unsafe extern "C" fn(filter: *const u8, layer: u32, priority: i16, flags: u64) -> HANDLE;
/// The signature of WinDivertRecv, a blocking receive of a packet or event.
type Receive = unsafe extern "C" fn(
    handle: HANDLE,
    packet: *mut c_void,
    length: u32,
    received: *mut u32,
    address: *mut Address,
) -> BOOL;
/// The signature of WinDivertSend, the injection of one packet.
type Inject = unsafe extern "C" fn(
    handle: HANDLE,
    packet: *const c_void,
    length: u32,
    sent: *mut u32,
    address: *const Address,
) -> BOOL;
/// The signature of WinDivertShutdown, an end to receiving, sending or both.
type Shutdown = unsafe extern "C" fn(handle: HANDLE, how: u32) -> BOOL;
/// The signature of WinDivertClose, the release of a handle.
type Close = unsafe extern "C" fn(handle: HANDLE) -> BOOL;

/// The table of WinDivert.dll function pointers, loaded once per process.
#[derive(Debug)]
pub(crate) struct Library {
    open: Open,
    recv: Receive,
    send: Inject,
    shutdown: Shutdown,
    close: Close,
}

/// An open WinDivert handle, closed when dropped.
#[derive(Debug)]
pub(crate) struct Handle {
    library: &'static Library,
    raw: HANDLE,
}

// SAFETY: WinDivert handles are kernel handles that WinDivert lets any thread receive and send on.
unsafe impl Send for Handle {}
// SAFETY: as above.
unsafe impl Sync for Handle {}

/// The WINDIVERT_ADDRESS of a captured packet or event: timestamp, flags and layer data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Address {
    timestamp: i64,
    /// The layer, the event, and one-bit flags such as outbound and IPv6.
    flags: u64,
    /// The layer's own part, a union in C; a socket event's is a `SocketData`.
    data: [u64; LAYER_DATA / size_of::<u64>()],
}

/// The WINDIVERT_DATA_SOCKET of a socket event: its process ID and 5-tuple.
#[repr(C)]
#[derive(Clone, Copy)]
struct SocketData {
    _endpoint: u64,
    _parent_endpoint: u64,
    process_id: u32,
    local: [u32; ADDRESS_WORDS],
    remote: [u32; ADDRESS_WORDS],
    local_port: u16,
    remote_port: u16,
    protocol: u8,
}

/// Loads the DLL once and returns its functions, or `Unsupported` saying what is missing.
pub(crate) fn library() -> std::io::Result<&'static Library> {
    static LIBRARY: OnceLock<Result<Library, String>> = OnceLock::new();
    match LIBRARY.get_or_init(|| load().map_err(|fault| fault.to_string())) {
        Ok(library) => Ok(library),
        Err(reason) => Err(Error::new(ErrorKind::Unsupported, reason.clone())),
    }
}

/// Writes the files to the folder beside the executable where missing, then loads the DLL from there and finds its functions.
fn load() -> std::io::Result<Library> {
    let executable = std::env::current_exe()?;
    let folder = executable.parent().unwrap_or(&executable).join(FOLDER);
    for (name, bytes) in FILES {
        let path = folder.join(name);
        write_missing(&path, bytes).map_err(|fault| {
            Error::other(format!(
                "{} could not be written ({fault}); run httptap where it may write beside itself",
                path.display()
            ))
        })?;
    }
    let path = folder.join(LIBRARY_NAME);
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([u16::MIN]).collect();
    // SAFETY: the path is terminated; the flags look for what the DLL needs only in its folder and System32.
    let module = unsafe {
        LoadLibraryExW(
            wide.as_ptr(),
            ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        let system = Error::last_os_error();
        let path = path.display();
        return Err(Error::other(
            if system.raw_os_error() == Some(ERROR_BAD_EXE_FORMAT as i32) {
                format!("{path} could not be loaded ({system}); WinDivert runs only on x64 Windows")
            } else {
                format!(
                    "{path} could not be loaded ({system}); delete the {FOLDER} folder so httptap writes it again"
                )
            },
        ));
    }
    let find = |symbol: &CStr| {
        // SAFETY: the module is loaded and never unloaded, and the symbol is a terminated string.
        unsafe { GetProcAddress(module, symbol.as_ptr().cast()) }.ok_or_else(Error::last_os_error)
    };
    let [open, recv, send, shutdown, close] = SYMBOLS;
    // SAFETY: each symbol is the WinDivert 2 function whose C signature the field's type spells out.
    unsafe {
        Ok(Library {
            open: std::mem::transmute::<Symbol, Open>(find(open)?),
            recv: std::mem::transmute::<Symbol, Receive>(find(recv)?),
            send: std::mem::transmute::<Symbol, Inject>(find(send)?),
            shutdown: std::mem::transmute::<Symbol, Shutdown>(find(shutdown)?),
            close: std::mem::transmute::<Symbol, Close>(find(close)?),
        })
    }
}

/// Writes the file unless it is there, through a temporary file so no process sees part of it.
fn write_missing(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    fs::create_dir_all(path.parent().unwrap_or(path))?;
    let temporary = path.with_extension(std::process::id().to_string());
    fs::write(&temporary, bytes)?;
    let renamed = fs::rename(&temporary, path);
    let _ = fs::remove_file(&temporary);
    if path.exists() { Ok(()) } else { renamed }
}

/// Returns the code of the last error a system call on this thread set.
fn last_error() -> u32 {
    Error::last_os_error()
        .raw_os_error()
        .map_or(u32::MAX, |code| code as u32)
}

/// Returns what an error opening a handle means, as `Unsupported` where the system cannot divert.
fn open_error(code: u32) -> Error {
    let system = Error::from_raw_os_error(code as i32);
    let reason = match code {
        ERROR_ACCESS_DENIED => format!(
            "httptap must run as Administrator on Windows to load the WinDivert driver ({system}); run it from an elevated terminal"
        ),
        ERROR_FILE_NOT_FOUND => format!(
            "{DRIVER_NAME} is missing beside {LIBRARY_NAME} ({system}); delete the {FOLDER} folder beside httptap so it writes both again"
        ),
        ERROR_INVALID_IMAGE_HASH => format!(
            "Windows refused the signature of {DRIVER_NAME} ({system}); delete the {FOLDER} folder beside httptap so it writes the signed driver again"
        ),
        ERROR_DRIVER_FAILED_PRIOR_UNLOAD => format!(
            "another version of the WinDivert driver is loaded ({system}); close the program using it, or restart Windows"
        ),
        ERROR_DRIVER_BLOCKED => format!(
            "the WinDivert driver is blocked by security software, or by a virtual machine that allows no drivers ({system})"
        ),
        EPT_S_NOT_REGISTERED => format!(
            "the Base Filtering Engine service is disabled ({system}); start it with `sc start BFE`"
        ),
        _ => return Error::other(format!("WinDivert could not open a handle: {system}")),
    };
    Error::new(ErrorKind::Unsupported, reason)
}

impl Handle {
    /// Opens a handle on the layer for what the filter matches, at the priority, with the flags.
    pub(crate) fn open(
        library: &'static Library,
        filter: &CStr,
        layer: u32,
        priority: i16,
        flags: u64,
    ) -> std::io::Result<Self> {
        // SAFETY: the filter is a terminated string that outlives the call.
        let raw = unsafe { (library.open)(filter.as_ptr().cast(), layer, priority, flags) };
        if raw == INVALID_HANDLE_VALUE {
            return Err(open_error(last_error()));
        }
        Ok(Self { library, raw })
    }

    /// Waits for the next packet or event, writing a packet into the buffer and returning its length and address.
    pub(crate) fn receive(&self, buffer: &mut [u8]) -> std::io::Result<(usize, Address)> {
        let mut address = Address::zeroed();
        let mut length = u32::MIN;
        let packet = if buffer.is_empty() {
            ptr::null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };
        let capacity = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: the buffer holds `capacity` bytes, and the address and length are writable locals.
        let received =
            unsafe { (self.library.recv)(self.raw, packet, capacity, &mut length, &mut address) };
        if received == BOOL::default() {
            return Err(Error::last_os_error());
        }
        Ok((length as usize, address))
    }

    /// Injects the packet with the address, which says the direction it travels.
    pub(crate) fn send(&self, packet: &[u8], address: &Address) -> std::io::Result<()> {
        let length =
            u32::try_from(packet.len()).map_err(|_| Error::from(ErrorKind::InvalidInput))?;
        // SAFETY: the packet holds `length` bytes, and the address is a whole WINDIVERT_ADDRESS.
        let sent = unsafe {
            (self.library.send)(
                self.raw,
                packet.as_ptr().cast(),
                length,
                ptr::null_mut(),
                address,
            )
        };
        if sent == BOOL::default() {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    /// Stops the handle, so a receive that waits on it returns an error.
    pub(crate) fn shut_down(&self) {
        // SAFETY: the handle is open until dropped.
        unsafe { (self.library.shutdown)(self.raw, SHUTDOWN_BOTH) };
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is open, and nothing uses it after this.
        unsafe { (self.library.close)(self.raw) };
    }
}

impl Address {
    /// Returns an address with every field zero: an inbound IPv4 packet on no interface.
    fn zeroed() -> Self {
        Self {
            timestamp: i64::default(),
            flags: u64::MIN,
            data: Default::default(),
        }
    }

    /// Returns the address that injects a packet for the program on the outbound path, which loops it back to the local socket.
    ///
    /// mitmproxy injects this way, as an inbound packet needs the interface it would have arrived on.
    pub(crate) fn toward_program() -> Self {
        let mut address = Self::zeroed();
        address.flags |= 1 << OUTBOUND_BIT;
        address
    }

    /// Returns the flow a socket event is about, the process behind it, and whether the process opened it; none for other events and protocols.
    pub(crate) fn socket_flow(&self) -> Option<(Flow, u32, bool)> {
        let event = (self.flags >> EVENT_SHIFT) & u64::from(u8::MAX);
        // SAFETY: a socket event's layer data is a SocketData, plain data that fits and is aligned.
        let data = unsafe { ptr::read(self.data.as_ptr().cast::<SocketData>()) };
        let transport = match data.protocol {
            protocol if protocol == u8::from(IpProtocol::Tcp) => Transport::Tcp,
            protocol if protocol == u8::from(IpProtocol::Udp) => Transport::Udp,
            _ => return None,
        };
        let opened = match event {
            SOCKET_CONNECT => true,
            SOCKET_ACCEPT => false,
            _ => return None,
        };
        let remote = SocketAddr::new(self.ip(data.remote), data.remote_port);
        Some((
            Flow::new(transport, data.local_port, remote),
            data.process_id,
            opened,
        ))
    }

    /// Returns an address of an event, held as host-order words with the least significant first.
    fn ip(&self, words: [u32; ADDRESS_WORDS]) -> IpAddr {
        let bits = words.iter().rev().fold(u128::MIN, |bits, word| {
            (bits << u32::BITS) | u128::from(*word)
        });
        if self.flags & (1 << IPV6_BIT) == u64::MIN {
            IpAddr::V4(Ipv4Addr::from(words[usize::MIN]))
        } else {
            IpAddr::V6(Ipv6Addr::from(bits))
        }
    }
}
