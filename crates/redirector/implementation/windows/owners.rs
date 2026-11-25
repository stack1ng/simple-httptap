//! Finding which process owns a local TCP or UDP endpoint, from Windows' tables of connections and listeners.
//!
//! It decides the flows whose socket event never came, so none of the program's traffic passes by guess.
//!
//! https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
    MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::core::BOOL;

use crate::packet::Transport;

/// How many times a table is asked for again after it grew between asking its size and reading it.
///
/// https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable#return-value
const TRIES: usize = 4;
/// The bytes before a table's rows: its row count.
///
/// https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcptable_owner_pid
const COUNT_SIZE: usize = size_of::<u32>();

/// Returns the process that owns the local port, for TCP the one connected to the remote end, if Windows knows it.
pub(crate) fn owner(transport: Transport, local_port: u16, remote: SocketAddr) -> Option<u32> {
    match transport {
        Transport::Tcp => tcp_owner(local_port, remote),
        Transport::Udp => udp_owner(local_port, remote.is_ipv6()),
    }
}

/// Returns the process of the TCP connection from the local port to the remote end.
fn tcp_owner(local_port: u16, remote: SocketAddr) -> Option<u32> {
    let remote_ip = remote.ip().to_canonical();
    if let IpAddr::V4(ip) = remote_ip {
        let rows: Vec<MIB_TCPROW_OWNER_PID> = read_table(|buffer, size| {
            // SAFETY: the buffer holds `size` bytes, or is null when only the size is asked for.
            unsafe { GetExtendedTcpTable(buffer, size, BOOL::default(), u32::from(AF_INET), TCP_TABLE_OWNER_PID_ALL, u32::MIN) }
        })?;
        return rows
            .iter()
            .find(|row| port(row.dwLocalPort) == local_port && port(row.dwRemotePort) == remote.port() && Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)) == ip)
            .map(|row| row.dwOwningPid);
    }
    let rows: Vec<MIB_TCP6ROW_OWNER_PID> = read_table(|buffer, size| {
        // SAFETY: as above.
        unsafe { GetExtendedTcpTable(buffer, size, BOOL::default(), u32::from(AF_INET6), TCP_TABLE_OWNER_PID_ALL, u32::MIN) }
    })?;
    rows.iter()
        .find(|row| port(row.dwLocalPort) == local_port && port(row.dwRemotePort) == remote.port() && IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)) == remote_ip)
        .map(|row| row.dwOwningPid)
}

/// Returns the process of the UDP socket bound to the local port, in the family of the remote end.
fn udp_owner(local_port: u16, ipv6: bool) -> Option<u32> {
    if !ipv6 {
        let rows: Vec<MIB_UDPROW_OWNER_PID> = read_table(|buffer, size| {
            // SAFETY: as above.
            unsafe { GetExtendedUdpTable(buffer, size, BOOL::default(), u32::from(AF_INET), UDP_TABLE_OWNER_PID, u32::MIN) }
        })?;
        if let Some(row) = rows.iter().find(|row| port(row.dwLocalPort) == local_port) {
            return Some(row.dwOwningPid);
        }
    }
    let rows: Vec<MIB_UDP6ROW_OWNER_PID> = read_table(|buffer, size| {
        // SAFETY: as above.
        unsafe { GetExtendedUdpTable(buffer, size, BOOL::default(), u32::from(AF_INET6), UDP_TABLE_OWNER_PID, u32::MIN) }
    })?;
    rows.iter().find(|row| port(row.dwLocalPort) == local_port).map(|row| row.dwOwningPid)
}

/// Returns the port a table holds in network order in the low two bytes of a double word.
fn port(stored: u32) -> u16 {
    u16::from_be(u16::try_from(stored & u32::from(u16::MAX)).unwrap_or_default())
}

/// Reads a table through the call, which takes a buffer and its size: its count, then its rows of type `R`.
fn read_table<R: Copy>(call: impl Fn(*mut std::ffi::c_void, &mut u32) -> u32) -> Option<Vec<R>> {
    let mut size = u32::MIN;
    for _ in usize::MIN..TRIES {
        let mut buffer = vec![u8::MIN; usize::try_from(size).ok()?];
        let pointer = if buffer.is_empty() { std::ptr::null_mut() } else { buffer.as_mut_ptr().cast() };
        match call(pointer, &mut size) {
            NO_ERROR if buffer.len() >= COUNT_SIZE => {
                let count = usize::try_from(u32::from_ne_bytes(buffer[..COUNT_SIZE].try_into().ok()?)).ok()?;
                let first = COUNT_SIZE.next_multiple_of(align_of::<R>());
                let rows = buffer.get(first..first + count * size_of::<R>())?;
                // SAFETY: the rows are `count` values of `R`, plain data, read unaligned from the byte buffer.
                return Some((0..count).map(|index| unsafe { rows.as_ptr().add(index * size_of::<R>()).cast::<R>().read_unaligned() }).collect());
            }
            ERROR_INSUFFICIENT_BUFFER | NO_ERROR => continue,
            _ => return None,
        }
    }
    None
}
