//! The start of a program in new network and mount namespaces whose only route is a TUN device.
//!
//! The namespaces sit in a new user namespace unless this process is root. The program's process sets them up between fork
//! and exec with system calls alone, as a forked child of a threaded process must, and hands the TUN device back.

use std::ffi::{CStr, CString, OsString};
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Result, Write};
use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};

use simple_httptap_redirector::Program;

use crate::stack::{MTU, NameServers};

/// The resolver configuration the namespace gets a copy of, its loopback name servers moved to addresses the TUN device reaches.
const RESOLV_CONF: &str = "/etc/resolv.conf";
/// The path of the resolver configuration, for mounting over.
const RESOLV_CONF_PATH: &CStr = c"/etc/resolv.conf";
/// The keyword of a resolver configuration line that names a name server.
const NAMESERVER: &str = "nameserver";
/// The address glibc asks when the resolver configuration names no name server.
const DEFAULT_NAME_SERVER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// The namespace's address of the first loopback name server, the next ones following it, in a block no internet host has.
///
/// https://www.rfc-editor.org/rfc/rfc6890#section-2.2.2
const FIRST_NAME_SERVER: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 53);
/// The namespace's IPv4 address, on the TUN device, in the same block as the name servers.
///
/// https://www.rfc-editor.org/rfc/rfc6890#section-2.2.2
const NAMESPACE_IPV4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// The namespace's IPv6 address, on the TUN device, a unique local address.
///
/// https://www.rfc-editor.org/rfc/rfc4193#section-3.1
const NAMESPACE_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd68, 0x7474, 0x7074, 0x6170, 0, 0, 0, 1);
/// The name of the TUN device in the namespace.
const TUN_NAME: &CStr = c"httptap0";
/// The name of the loopback device, which a new network namespace has down.
const LOOPBACK_NAME: &CStr = c"lo";
/// The device that makes TUN devices.
const TUN_DEVICE: &CStr = c"/dev/net/tun";
/// The root of the mount tree, which the namespace makes private so its mounts stay its own.
const ROOT_PATH: &CStr = c"/";
/// The file that says whether the user namespace may call setgroups, which an unprivileged one must deny before mapping a group.
const SETGROUPS: &CStr = c"/proc/self/setgroups";
/// What the setgroups file is set to, so an unprivileged process may map its group.
const DENY: &[u8] = b"deny";
/// The file that maps the user namespace's user IDs to the outer ones.
const UID_MAP: &CStr = c"/proc/self/uid_map";
/// The file that maps the user namespace's group IDs to the outer ones.
const GID_MAP: &CStr = c"/proc/self/gid_map";
/// The sysctl that is on where AppArmor takes every privilege from an unprivileged user namespace, as Ubuntu 24.04 does.
const APPARMOR_RESTRICTION: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
/// The text a boolean sysctl's file holds when the setting is enabled.
const SYSCTL_ON: &str = "1";
/// The user ID of root, the least there is.
const ROOT: libc::uid_t = libc::uid_t::MIN;
/// The variable sudo sets to the user ID of the user who ran it.
const SUDO_UID: &str = "SUDO_UID";
/// The variable sudo sets to the group ID of the user who ran it.
const SUDO_GID: &str = "SUDO_GID";
/// The variable a login sets to the user's home folder.
const HOME: &str = "HOME";
/// The variable a login sets to the user's name.
const USER: &str = "USER";
/// The variable a login sets to the user's name, as older programs read it.
const LOGNAME: &str = "LOGNAME";
/// The start of the name of each resolver file this process writes in the temporary folder.
const RESOLVER_FILE_PREFIX: &str = "simple-httptap-resolv.conf.";
/// The permissions of the resolver file: everyone reads it, as everyone reads /etc/resolv.conf.
const RESOLVER_MODE: libc::mode_t = libc::S_IRUSR | libc::S_IWUSR | libc::S_IRGRP | libc::S_IROTH;
/// The netlink message type of an acknowledgement or an error.
///
/// https://github.com/torvalds/linux/blob/master/include/uapi/linux/netlink.h
const NLMSG_ERROR: u16 = 2;
/// The netlink flags of a request that wants an acknowledgement and creates something that must not exist yet.
///
/// https://github.com/torvalds/linux/blob/master/include/uapi/linux/netlink.h
const CREATE_FLAGS: u16 = 0x1 | 0x4 | 0x400 | 0x200;
/// The address attribute of the local address.
///
/// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_addr.h
const IFA_LOCAL: u16 = 2;
/// The address attribute of the address at the other end, or of the address itself on IPv6.
///
/// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_addr.h
const IFA_ADDRESS: u16 = 1;
/// The address flag that skips duplicate address detection, so the IPv6 address is usable at once.
///
/// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_addr.h
const IFA_F_NODAD: u8 = 0x02;
/// The prefix length that covers one IPv4 address and no other: its full width in bits.
const IPV4_HOST_PREFIX: u8 = Ipv4Addr::BITS as u8;
/// The prefix length that covers one IPv6 address and no other: its full width in bits.
const IPV6_HOST_PREFIX: u8 = Ipv6Addr::BITS as u8;
/// The alignment of netlink messages and attributes.
///
/// https://github.com/torvalds/linux/blob/master/include/uapi/linux/netlink.h
const NETLINK_ALIGNMENT: usize = 4;
/// The length of a netlink attribute's header: its length and its type.
const ATTRIBUTE_HEADER: usize = size_of::<u16>() + size_of::<u16>();
/// The bytes a netlink request is built in: its header, a route message, and two attributes of an IPv6 address, the most here.
const MESSAGE_CAPACITY: usize = size_of::<libc::nlmsghdr>()
    + size_of::<RouteMessage>()
    + ATTRIBUTE_HEADER
    + size_of::<Ipv6Addr>()
    + ATTRIBUTE_HEADER
    + size_of::<Ipv6Addr>();
/// The bytes a netlink answer is read into: an error's answer, which repeats the request after the error number.
const ANSWER_CAPACITY: usize = size_of::<libc::nlmsghdr>() + size_of::<i32>() + MESSAGE_CAPACITY;
/// The bytes of a report from the child: the step, then the error number if it failed.
const REPORT_LENGTH: usize = size_of::<u8>() + size_of::<i32>();
/// The step code of a child that set everything up and sends the TUN device with it.
const READY: u8 = u8::MAX;

/// The number given to the next resolver file, which tells apart those this process writes.
static NEXT_RESOLVER_FILE: AtomicU64 = AtomicU64::new(u64::MIN);

/// The child running in the namespaces and the TUN device that carries its packets.
pub(crate) struct Started {
    pub(crate) child: Child,
    pub(crate) tun: OwnedFd,
    pub(crate) names: NameServers,
}

/// Starts the program in new namespaces whose only route is a TUN device, returning it with the device.
pub(crate) fn start(program: &Program) -> Result<Started> {
    let host = std::fs::read_to_string(RESOLV_CONF).ok();
    let (resolver, pairs) = host.as_deref().map(rewrite_resolver).unwrap_or_default();
    // The namespace sees the host's file unless a name server had to move.
    let resolver_file = if pairs.is_empty() {
        None
    } else {
        Some(ResolverFile::write(&resolver)?)
    };
    // SAFETY: geteuid has no preconditions and cannot fail.
    let root = unsafe { libc::geteuid() } == ROOT;
    let account = if root { sudo_account() } else { None };
    let (reports, report) = UnixDatagram::pair()?;
    let setup = Setup {
        report: OwnedFd::from(report),
        maps: (!root).then(Maps::of_this_process),
        resolver: resolver_file.as_ref().map(|file| file.path.clone()),
        identity: account
            .as_ref()
            .map(|account| (account.uid, account.gid, account.groups.clone())),
    };
    let mut command = Command::new(&program.path);
    command.args(&program.arguments);
    // Under sudo, HOME may still be root's; the program gets the user's, as a login would give it.
    if let Some((name, home)) = account.as_ref().and_then(|account| account.names.as_ref()) {
        command.env(HOME, home).env(USER, name).env(LOGNAME, name);
    }
    for (name, value) in &program.environment {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    // SAFETY: the setup makes system calls alone, on memory it holds, so it is sound between fork and exec.
    unsafe { command.pre_exec(move || setup.run()) };
    let spawned = command.spawn();
    drop(command);
    // The child mounted the file, if it got that far, so its path is no longer needed.
    drop(resolver_file);
    let report = receive(&reports);
    match (spawned, report) {
        (Ok(child), Some(Report::Ready(tun))) => Ok(Started {
            child,
            tun,
            names: NameServers::new(pairs),
        }),
        (Ok(mut child), _) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(Error::other(
                "the program's process gave no TUN device back",
            ))
        }
        (Err(_), Some(Report::Failed(step, number))) => Err(failure(step, number, root)),
        (Err(error), _) => Err(error),
    }
}

/// Returns the resolver configuration with its loopback name servers moved, and each moved one's new address with its old.
///
/// A moved name server's new address is one the TUN device reaches.
fn rewrite_resolver(host: &str) -> (String, Vec<(IpAddr, IpAddr)>) {
    let mut pairs = Vec::new();
    let mut named = false;
    let mut rewritten = String::new();
    for line in host.lines() {
        let mut words = line.split_whitespace();
        let server = (words.next() == Some(NAMESERVER))
            .then(|| words.next())
            .flatten();
        named |= server.is_some();
        match server
            .and_then(|server| server.parse::<IpAddr>().ok())
            .filter(IpAddr::is_loopback)
        {
            Some(outside) => {
                rewritten.push_str(&format!("{NAMESERVER} {}\n", moved(&mut pairs, outside)))
            }
            None => rewritten.push_str(&format!("{line}\n")),
        }
    }
    if !named {
        rewritten.push_str(&format!(
            "{NAMESERVER} {}\n",
            moved(&mut pairs, DEFAULT_NAME_SERVER)
        ));
    }
    (rewritten, pairs)
}

/// Gives the loopback name server the next address in the namespace and returns that address.
fn moved(pairs: &mut Vec<(IpAddr, IpAddr)>, outside: IpAddr) -> IpAddr {
    let offset = u32::try_from(pairs.len()).unwrap_or(u32::MAX);
    let inside = IpAddr::V4(Ipv4Addr::from(
        u32::from(FIRST_NAME_SERVER).saturating_add(offset),
    ));
    pairs.push((inside, outside));
    inside
}

/// A resolver configuration written to a temporary file for the child to mount, removed when dropped.
struct ResolverFile {
    path: CString,
}

impl ResolverFile {
    /// Writes the text to a new file in the temporary folder that everyone can read.
    fn write(text: &str) -> Result<Self> {
        // The process's ID in the high half and its count in the low half tell every file apart.
        let count = NEXT_RESOLVER_FILE.fetch_add(u64::from(true), Ordering::Relaxed);
        let mut name = OsString::from(RESOLVER_FILE_PREFIX);
        name.push(((u64::from(std::process::id()) << u32::BITS) | count).to_string());
        let path: PathBuf = std::env::temp_dir().join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(RESOLVER_MODE)
            .open(&path)?;
        let path = CString::new(path.into_os_string().into_vec()).map_err(Error::other)?;
        let written = file.write_all(text.as_bytes());
        let resolver = Self { path };
        written.map(|()| resolver)
    }
}

impl Drop for ResolverFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(OsString::from_vec(self.path.as_bytes().to_vec()));
    }
}

/// The account of the user who ran sudo, which the program runs as.
///
/// It has their IDs and groups, and their name and home if the passwd database has them.
struct Account {
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
    /// The user's name and home folder.
    names: Option<(OsString, OsString)>,
}

/// Returns the account sudo was run from, if `SUDO_UID` names one and its group is known.
fn sudo_account() -> Option<Account> {
    let uid: libc::uid_t = std::env::var(SUDO_UID).ok()?.parse().ok()?;
    let entry = passwd(uid);
    let gid = std::env::var(SUDO_GID)
        .ok()
        .and_then(|gid| gid.parse().ok())
        .or(entry.as_ref().map(|(_, _, primary)| *primary))?;
    let groups = entry
        .as_ref()
        .map_or_else(|| vec![gid], |(name, _, _)| group_list(name, gid));
    let names = entry.map(|(name, home, _)| (OsString::from_vec(name.into_bytes()), home));
    Some(Account {
        uid,
        gid,
        groups,
        names,
    })
}

/// Returns the name, home and primary group of the user from the passwd database.
fn passwd(uid: libc::uid_t) -> Option<(CString, OsString, libc::gid_t)> {
    // SAFETY: sysconf takes a name alone; a negative answer means no limit is known.
    let suggested = usize::try_from(unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) })
        .unwrap_or(size_of::<libc::passwd>());
    let mut buffer = vec![libc::c_char::default(); suggested];
    loop {
        let mut entry = MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: every pointer is to memory of the length given, alive for the call.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        };
        if status == libc::ERANGE {
            // The buffer doubles until the entry fits.
            buffer.resize(buffer.len() + buffer.len(), libc::c_char::default());
            continue;
        }
        if found.is_null() {
            return None;
        }
        // SAFETY: getpwuid_r filled the entry, whose strings point into the buffer, which is still alive.
        let entry = unsafe { entry.assume_init() };
        // SAFETY: the entry's strings end in NUL, as getpwuid_r writes them.
        let (name, home) = unsafe { (CStr::from_ptr(entry.pw_name), CStr::from_ptr(entry.pw_dir)) };
        return Some((
            name.to_owned(),
            OsString::from_vec(home.to_bytes().to_vec()),
            entry.pw_gid,
        ));
    }
}

/// Returns the user's supplementary groups with the group, or the group alone if the database does not say.
fn group_list(name: &CStr, gid: libc::gid_t) -> Vec<libc::gid_t> {
    // getgrouplist says how many groups there are when the list is too short for them.
    let mut groups = vec![gid];
    loop {
        let mut count = libc::c_int::try_from(groups.len()).unwrap_or(libc::c_int::MAX);
        // SAFETY: the list holds as many groups as the count says.
        let status =
            unsafe { libc::getgrouplist(name.as_ptr(), gid, groups.as_mut_ptr(), &mut count) };
        let wanted = usize::try_from(count).unwrap_or(usize::MIN);
        if !status.is_negative() {
            groups.truncate(wanted);
            return groups;
        }
        if wanted <= groups.len() {
            return vec![gid];
        }
        groups.resize(wanted, gid);
    }
}

/// The contents of a new user namespace's uid_map and gid_map, each mapping this process's own ID to itself.
struct Maps {
    uid: Vec<u8>,
    gid: Vec<u8>,
}

impl Maps {
    /// Returns the maps of this process's effective user and group.
    fn of_this_process() -> Self {
        // SAFETY: geteuid and getegid have no preconditions and cannot fail.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        Self {
            uid: format!("{uid} {uid} 1").into_bytes(),
            gid: format!("{gid} {gid} 1").into_bytes(),
        }
    }
}

/// A step of the child's setup, named in the error it fails with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Step {
    UserNamespace,
    Mapping,
    Namespaces,
    PrivateMounts,
    Resolver,
    Loopback,
    Tunnel,
    Address,
    Route,
    Handover,
    Identity,
}

/// Every step with what it does, to read a step back from its code and to follow "could not" in its error.
const STEPS: &[(Step, &str)] = &[
    (Step::UserNamespace, "make a user namespace"),
    (
        Step::Mapping,
        "map this user and group into the user namespace",
    ),
    (Step::Namespaces, "make network and mount namespaces"),
    (
        Step::PrivateMounts,
        "make the mount namespace's mounts private",
    ),
    (
        Step::Resolver,
        "mount the namespace's own resolver configuration",
    ),
    (Step::Loopback, "bring up the namespace's loopback device"),
    (Step::Tunnel, "make a TUN device"),
    (Step::Address, "give the TUN device its address"),
    (
        Step::Route,
        "route the namespace's traffic through the TUN device",
    ),
    (Step::Handover, "hand the TUN device back to httptap"),
    (Step::Identity, "switch to the user who ran sudo"),
];

impl Step {
    /// Returns what the step does, to follow "could not".
    fn describe(self) -> &'static str {
        STEPS
            .iter()
            .find(|(step, _)| *step == self)
            .map_or_else(Default::default, |(_, description)| *description)
    }

    /// Returns the step with the code, if one has it.
    fn from_code(code: u8) -> Option<Self> {
        STEPS
            .iter()
            .map(|(step, _)| *step)
            .find(|step| *step as u8 == code)
    }
}

/// Advice where users may not make user namespaces, naming the sysctl each kind of system uses.
const USER_NAMESPACE_FIX: &str = "this system lets no unprivileged process make a user namespace. Run httptap with sudo, or allow \
     them: on Ubuntu `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`, elsewhere `sudo sysctl \
     kernel.unprivileged_userns_clone=1` or a nonzero user.max_user_namespaces; a container also needs its seccomp profile lifted";
/// Advice where /dev/net/tun is missing: load the module, or pass the device in.
const TUN_FIX: &str = "this system has no TUN device. Load the module with `sudo modprobe tun`; a container needs `--device` with it";
/// Advice where AppArmor strips user namespaces of capabilities: sudo, or the rule off.
const APPARMOR_FIX: &str = "AppArmor takes every privilege from an unprivileged user namespace here, as Ubuntu 24.04 does. Run \
     httptap with sudo, or `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`";
/// Advice for a root lacking CAP_SYS_ADMIN or CAP_NET_ADMIN: grant them and the device.
const ROOT_FIX: &str = "root here lacks the privilege, as in a container: give it `--privileged`, or `--cap-add NET_ADMIN \
     --cap-add SYS_ADMIN` and the TUN device with `--device`";
/// The fix for a system that denies an unprivileged user the step for another reason.
const SUDO_FIX: &str = "the system does not let this user do it. Run httptap with sudo";

/// A child's report on its setup, which carries either the TUN device or the failed step and its error number.
enum Report {
    Ready(OwnedFd),
    Failed(Step, i32),
}

/// Returns the error for a setup that failed at the step with the error number, saying what the system lacks and how to give it.
fn failure(step: Step, number: i32, root: bool) -> Error {
    let cause = Error::from_raw_os_error(number);
    let denied = matches!(number, libc::EPERM | libc::EACCES);
    let unsupported = |fix: &str| {
        Error::new(
            ErrorKind::Unsupported,
            format!("could not {} ({cause}); {fix}", step.describe()),
        )
    };
    match step {
        Step::UserNamespace | Step::Mapping => unsupported(USER_NAMESPACE_FIX),
        Step::Tunnel if matches!(number, libc::ENOENT | libc::ENODEV | libc::ENXIO) => {
            unsupported(TUN_FIX)
        }
        _ if denied && !root && is_restricted_by_apparmor() => unsupported(APPARMOR_FIX),
        _ if denied && root => unsupported(ROOT_FIX),
        _ if denied
            || (step == Step::Namespaces
                && matches!(
                    number,
                    libc::EINVAL | libc::ENOSPC | libc::EUSERS | libc::ENOSYS
                )) =>
        {
            unsupported(SUDO_FIX)
        }
        _ => Error::new(
            cause.kind(),
            format!("could not {} for the program: {cause}", step.describe()),
        ),
    }
}

/// Returns whether AppArmor restricts unprivileged user namespaces here.
fn is_restricted_by_apparmor() -> bool {
    std::fs::read_to_string(APPARMOR_RESTRICTION).is_ok_and(|value| value.trim() == SYSCTL_ON)
}

/// Returns the report the child sent, if it sent one.
fn receive(socket: &UnixDatagram) -> Option<Report> {
    let mut data = [u8::MIN; REPORT_LENGTH];
    let mut control = Rights::new();
    let mut parts = [libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    }];
    // SAFETY: an all-zero msghdr is valid, and the fields set point at memory of the lengths given, alive for the call.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = parts.as_mut_ptr();
    message.msg_iovlen = parts.len() as _;
    message.msg_control = (&raw mut control).cast();
    message.msg_controllen = size_of::<Rights>() as _;
    // SAFETY: the message describes memory this function owns.
    let length = unsafe {
        libc::recvmsg(
            socket.as_raw_fd(),
            &mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    // SAFETY: recvmsg set the control length to what it wrote, within the buffer.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    // SAFETY: a non-null header is within the control buffer, and SCM_RIGHTS data is a descriptor.
    let tun = (!header.is_null()).then(|| unsafe {
        ((*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS).then(
            || {
                OwnedFd::from_raw_fd(std::ptr::read_unaligned(
                    libc::CMSG_DATA(header).cast::<RawFd>(),
                ))
            },
        )
    });
    let tun = tun.flatten();
    let [code, number @ ..] = data;
    match (usize::try_from(length).ok()?, tun) {
        (_, Some(tun)) if code == READY => Some(Report::Ready(tun)),
        (REPORT_LENGTH, _) => {
            Step::from_code(code).map(|step| Report::Failed(step, i32::from_ne_bytes(number)))
        }
        _ => None,
    }
}

/// A control message buffer the size of one passed descriptor, aligned as its header must be.
#[repr(C)]
struct Rights {
    header: libc::cmsghdr,
    descriptor: RawFd,
}

impl Rights {
    /// Returns a buffer of zeros.
    fn new() -> Self {
        // SAFETY: an all-zero cmsghdr and descriptor are valid values.
        unsafe { std::mem::zeroed() }
    }
}

/// The child's work between fork and exec, prepared beforehand so it needs only system calls.
struct Setup {
    /// The child's end of the socket pair it reports on.
    report: OwnedFd,
    /// The maps of a new user namespace, none if this process is root and needs none.
    maps: Option<Maps>,
    /// The resolver file to mount over /etc/resolv.conf, if any.
    resolver: Option<CString>,
    /// The user, group and supplementary groups to run the program as, if root runs it for someone.
    identity: Option<(libc::uid_t, libc::gid_t, Vec<libc::gid_t>)>,
}

/// The result of a step of the setup: the error number it failed with.
type Outcome<T> = std::result::Result<T, (Step, i32)>;

impl Setup {
    /// Sets the namespaces up and sends the TUN device, or reports the step that failed and returns its error.
    fn run(&self) -> Result<()> {
        self.set_up().map_err(|(step, number)| {
            let mut report = [u8::MIN; REPORT_LENGTH];
            let (code, rest) = report.split_at_mut(size_of::<u8>());
            code.copy_from_slice(&[step as u8]);
            rest.copy_from_slice(&number.to_ne_bytes());
            // SAFETY: the report is a buffer of its length.
            unsafe {
                libc::send(
                    self.report.as_raw_fd(),
                    report.as_ptr().cast(),
                    report.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            Error::from_raw_os_error(number)
        })
    }

    /// Runs every step in order.
    fn set_up(&self) -> Outcome<()> {
        if let Some(maps) = &self.maps {
            // SAFETY: unshare takes flags alone.
            check(
                unsafe { libc::unshare(libc::CLONE_NEWUSER) },
                Step::UserNamespace,
            )?;
            // A kernel before 3.19 has no setgroups file and needs no denial.
            match write_file(SETGROUPS, DENY) {
                Err(libc::ENOENT) | Ok(()) => {}
                Err(number) => return Err((Step::Mapping, number)),
            }
            write_file(UID_MAP, &maps.uid).map_err(|number| (Step::Mapping, number))?;
            write_file(GID_MAP, &maps.gid).map_err(|number| (Step::Mapping, number))?;
        }
        // SAFETY: unshare takes flags alone.
        check(
            unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) },
            Step::Namespaces,
        )?;
        let none = std::ptr::null();
        // SAFETY: the paths end in NUL; the other pointers may be null for these flags.
        check(
            unsafe {
                libc::mount(
                    none,
                    ROOT_PATH.as_ptr(),
                    none,
                    libc::MS_REC | libc::MS_PRIVATE,
                    none.cast(),
                )
            },
            Step::PrivateMounts,
        )?;
        if let Some(resolver) = &self.resolver {
            // SAFETY: the paths end in NUL; the other pointers may be null for a bind mount.
            let mounted = check(
                unsafe {
                    libc::mount(
                        resolver.as_ptr(),
                        RESOLV_CONF_PATH.as_ptr(),
                        none,
                        libc::MS_BIND,
                        none.cast(),
                    )
                },
                Step::Resolver,
            );
            // A system with no resolver configuration has nothing to mount over.
            if !matches!(mounted, Err((_, libc::ENOENT)) | Ok(_)) {
                mounted?;
            }
        }
        // SAFETY: socket takes values alone; the descriptor it returns is closed below.
        let control = Descriptor(check(
            unsafe {
                libc::socket(
                    libc::AF_INET,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                    libc::IPPROTO_UDP,
                )
            },
            Step::Loopback,
        )?);
        bring_up(control.0, LOOPBACK_NAME, None).map_err(|number| (Step::Loopback, number))?;
        let tun = Descriptor(make_tun().map_err(|number| (Step::Tunnel, number))?);
        let index =
            bring_up(control.0, TUN_NAME, Some(MTU)).map_err(|number| (Step::Tunnel, number))?;
        let route = Descriptor(check(
            // SAFETY: socket takes values alone; the descriptor it returns is closed below.
            unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    libc::NETLINK_ROUTE,
                )
            },
            Step::Address,
        )?);
        add_address(route.0, index, IpAddr::V4(NAMESPACE_IPV4))
            .map_err(|number| (Step::Address, number))?;
        add_default_route(route.0, index, false).map_err(|number| (Step::Route, number))?;
        // A namespace with IPv6 off still carries IPv4; its programs find IPv6 unreachable and fall back.
        if add_address(route.0, index, IpAddr::V6(NAMESPACE_IPV6)).is_ok() {
            let _ = add_default_route(route.0, index, true);
        }
        hand_over(self.report.as_raw_fd(), tun.0).map_err(|number| (Step::Handover, number))?;
        if let Some((uid, gid, groups)) = &self.identity {
            // SAFETY: the list holds as many groups as its length says.
            check(
                unsafe { libc::setgroups(groups.len(), groups.as_ptr()) },
                Step::Identity,
            )?;
            // SAFETY: setgid and setuid take values alone.
            check(unsafe { libc::setgid(*gid) }, Step::Identity)?;
            // SAFETY: as above.
            check(unsafe { libc::setuid(*uid) }, Step::Identity)?;
        }
        Ok(())
    }
}

/// An open file descriptor of the child's, closed when dropped.
struct Descriptor(RawFd);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor is this value's alone.
        unsafe { libc::close(self.0) };
    }
}

/// Returns the call's result, or the step with the error number if it failed.
fn check(result: libc::c_int, step: Step) -> Outcome<libc::c_int> {
    if result.is_negative() {
        Err((step, errno()))
    } else {
        Ok(result)
    }
}

/// Returns the error number of the last failed call.
fn errno() -> i32 {
    Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

/// Writes the bytes to the file at the path in one write, as a /proc map file wants them.
fn write_file(path: &CStr, bytes: &[u8]) -> std::result::Result<(), i32> {
    // SAFETY: the path ends in NUL.
    let file = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if file.is_negative() {
        return Err(errno());
    }
    let file = Descriptor(file);
    // SAFETY: the bytes are a buffer of their length.
    let written = unsafe { libc::write(file.0, bytes.as_ptr().cast(), bytes.len()) };
    if usize::try_from(written) == Ok(bytes.len()) {
        Ok(())
    } else {
        Err(errno())
    }
}

/// Returns a request about the named device.
fn make_interface_request(name: &CStr) -> libc::ifreq {
    // SAFETY: an all-zero ifreq is valid.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.to_bytes()) {
        *slot = *byte as libc::c_char;
    }
    request
}

/// Brings the named device up, with the MTU if given, and returns its index.
fn bring_up(
    control: RawFd,
    name: &CStr,
    mtu: Option<usize>,
) -> std::result::Result<libc::c_uint, i32> {
    let mut request = make_interface_request(name);
    if let Some(mtu) = mtu {
        request.ifr_ifru.ifru_mtu = libc::c_int::try_from(mtu).unwrap_or(libc::c_int::MAX);
        // SAFETY: the request names the device and holds the MTU.
        if unsafe { libc::ioctl(control, libc::SIOCSIFMTU as _, &mut request) }.is_negative() {
            return Err(errno());
        }
    }
    // SAFETY: the request names the device; the call fills its flags.
    if unsafe { libc::ioctl(control, libc::SIOCGIFFLAGS as _, &mut request) }.is_negative() {
        return Err(errno());
    }
    // SAFETY: the call above filled the flags.
    request.ifr_ifru.ifru_flags =
        unsafe { request.ifr_ifru.ifru_flags } | libc::IFF_UP as libc::c_short;
    // SAFETY: the request names the device and holds its flags.
    if unsafe { libc::ioctl(control, libc::SIOCSIFFLAGS as _, &mut request) }.is_negative() {
        return Err(errno());
    }
    // SAFETY: the request names the device; the call fills its index.
    if unsafe { libc::ioctl(control, libc::SIOCGIFINDEX as _, &mut request) }.is_negative() {
        return Err(errno());
    }
    // SAFETY: the call above filled the index.
    libc::c_uint::try_from(unsafe { request.ifr_ifru.ifru_ifindex }).map_err(|_| libc::ENODEV)
}

/// Makes the TUN device and returns its descriptor, which does not block and is closed on exec.
fn make_tun() -> std::result::Result<RawFd, i32> {
    // SAFETY: the path ends in NUL.
    let tun = unsafe {
        libc::open(
            TUN_DEVICE.as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if tun.is_negative() {
        return Err(errno());
    }
    let mut request = make_interface_request(TUN_NAME);
    request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    // SAFETY: the request names the device and holds its flags.
    if unsafe { libc::ioctl(tun, libc::TUNSETIFF as _, &mut request) }.is_negative() {
        let number = errno();
        drop(Descriptor(tun));
        return Err(number);
    }
    Ok(tun)
}

/// A netlink request built in place, with no allocation.
struct Message {
    bytes: [u8; MESSAGE_CAPACITY],
    length: usize,
}

impl Message {
    /// Returns a request of the type with its header, which wants an acknowledgement.
    fn new(kind: u16) -> Self {
        let mut message = Self {
            bytes: [u8::MIN; MESSAGE_CAPACITY],
            length: usize::MIN,
        };
        // The length, written last, then the type, the flags, the sequence number and the port.
        message.put(&u32::MIN.to_ne_bytes());
        message.put(&kind.to_ne_bytes());
        message.put(&CREATE_FLAGS.to_ne_bytes());
        message.put(&u32::MIN.to_ne_bytes());
        message.put(&u32::MIN.to_ne_bytes());
        message
    }

    /// Appends the bytes, or drops them if the request is full.
    fn put(&mut self, bytes: &[u8]) {
        if let Some(slot) = self.bytes.get_mut(self.length..self.length + bytes.len()) {
            slot.copy_from_slice(bytes);
            self.length += bytes.len();
        }
    }

    /// Appends an attribute of the type with the payload, padded to the alignment.
    fn put_attribute(&mut self, kind: u16, payload: &[u8]) {
        let length = u16::try_from(ATTRIBUTE_HEADER + payload.len()).unwrap_or(u16::MAX);
        self.put(&length.to_ne_bytes());
        self.put(&kind.to_ne_bytes());
        self.put(payload);
        self.length = self
            .length
            .next_multiple_of(NETLINK_ALIGNMENT)
            .min(MESSAGE_CAPACITY);
    }

    /// Writes the length into the header and returns the request's bytes.
    fn finish(&mut self) -> &[u8] {
        let length = u32::try_from(self.length).unwrap_or(u32::MAX).to_ne_bytes();
        self.bytes[..length.len()].copy_from_slice(&length);
        &self.bytes[..self.length]
    }
}

/// Sends the request and returns whether the kernel acknowledged it, or the error number it answered.
fn ask(route: RawFd, message: &mut Message) -> std::result::Result<(), i32> {
    let request = message.finish();
    // SAFETY: the request is a buffer of its length.
    let sent = unsafe {
        libc::send(
            route,
            request.as_ptr().cast(),
            request.len(),
            libc::c_int::default(),
        )
    };
    if usize::try_from(sent) != Ok(request.len()) {
        return Err(errno());
    }
    let mut answer = [u8::MIN; ANSWER_CAPACITY];
    // SAFETY: the answer is a buffer of its length.
    let received = unsafe {
        libc::recv(
            route,
            answer.as_mut_ptr().cast(),
            answer.len(),
            libc::c_int::default(),
        )
    };
    let header = size_of::<libc::nlmsghdr>();
    if usize::try_from(received).map_or(true, |received| received < header + size_of::<i32>()) {
        return Err(libc::EIO);
    }
    // SAFETY: the answer holds a header and an error number, read unaligned.
    let (kind, error) = unsafe {
        let kind = std::ptr::read_unaligned(answer.as_ptr().cast::<libc::nlmsghdr>()).nlmsg_type;
        (
            kind,
            std::ptr::read_unaligned(answer.as_ptr().add(header).cast::<i32>()),
        )
    };
    match kind {
        NLMSG_ERROR if error.is_negative() => Err(-error),
        NLMSG_ERROR => Ok(()),
        _ => Err(libc::EIO),
    }
}

/// The body of a request about an address, after its netlink header.
///
/// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_addr.h
#[repr(C)]
#[derive(Clone, Copy)]
struct AddressMessage {
    family: u8,
    prefix_length: u8,
    flags: u8,
    scope: u8,
    index: u32,
}

/// The body of a request about a route, after its netlink header.
///
/// https://github.com/torvalds/linux/blob/master/include/uapi/linux/rtnetlink.h
#[repr(C)]
#[derive(Clone, Copy)]
struct RouteMessage {
    family: u8,
    destination_length: u8,
    source_length: u8,
    type_of_service: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    kind: u8,
    flags: u32,
}

/// Returns the bytes of a message body, which has no padding between its fields or after them.
fn body_bytes<T: Copy>(body: &T) -> &[u8] {
    // SAFETY: the bodies are repr(C) with no padding, so every byte is initialized, and the slice lives as long as the body.
    unsafe { std::slice::from_raw_parts((body as *const T).cast::<u8>(), size_of::<T>()) }
}

/// Gives the device the address alone, with no prefix around it.
fn add_address(route: RawFd, index: libc::c_uint, address: IpAddr) -> std::result::Result<(), i32> {
    let mut message = Message::new(libc::RTM_NEWADDR);
    let (family, prefix_length, flags) = match address {
        IpAddr::V4(_) => (libc::AF_INET, IPV4_HOST_PREFIX, u8::MIN),
        IpAddr::V6(_) => (libc::AF_INET6, IPV6_HOST_PREFIX, IFA_F_NODAD),
    };
    let family = u8::try_from(family).map_err(|_| libc::EAFNOSUPPORT)?;
    message.put(body_bytes(&AddressMessage {
        family,
        prefix_length,
        flags,
        scope: libc::RT_SCOPE_UNIVERSE,
        index,
    }));
    match address {
        IpAddr::V4(address) => {
            message.put_attribute(IFA_LOCAL, &address.octets());
            message.put_attribute(IFA_ADDRESS, &address.octets());
        }
        IpAddr::V6(address) => message.put_attribute(IFA_ADDRESS, &address.octets()),
    }
    ask(route, &mut message)
}

/// Routes every address of the family through the device.
fn add_default_route(
    route: RawFd,
    index: libc::c_uint,
    ipv6: bool,
) -> std::result::Result<(), i32> {
    let mut message = Message::new(libc::RTM_NEWROUTE);
    // An IPv4 route with no gateway reaches its addresses on the device, as `ip route add default dev` makes it.
    let (family, scope) = if ipv6 {
        (libc::AF_INET6, libc::RT_SCOPE_UNIVERSE)
    } else {
        (libc::AF_INET, libc::RT_SCOPE_LINK)
    };
    let family = u8::try_from(family).map_err(|_| libc::EAFNOSUPPORT)?;
    let body = RouteMessage {
        family,
        destination_length: u8::MIN,
        source_length: u8::MIN,
        type_of_service: u8::MIN,
        table: libc::RT_TABLE_MAIN,
        protocol: libc::RTPROT_BOOT,
        scope,
        kind: libc::RTN_UNICAST,
        flags: u32::MIN,
    };
    message.put(body_bytes(&body));
    message.put_attribute(libc::RTA_OIF, &index.to_ne_bytes());
    ask(route, &mut message)
}

/// Sends the TUN device's descriptor over the socket with the ready code.
fn hand_over(socket: RawFd, tun: RawFd) -> std::result::Result<(), i32> {
    let mut data = [READY];
    let mut control = Rights::new();
    let mut parts = [libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    }];
    // SAFETY: an all-zero msghdr is valid, and the fields set point at memory of the lengths given, alive for the call.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = parts.as_mut_ptr();
    message.msg_iovlen = parts.len() as _;
    message.msg_control = (&raw mut control).cast();
    let descriptor_length = size_of::<RawFd>() as libc::c_uint;
    // SAFETY: CMSG_SPACE computes a length alone.
    message.msg_controllen = unsafe { libc::CMSG_SPACE(descriptor_length) } as _;
    // SAFETY: the control buffer holds one header and a descriptor, as CMSG_SPACE says.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(descriptor_length) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), tun);
    }
    // SAFETY: the message describes memory this function owns.
    if unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) }.is_negative() {
        Err(errno())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that a loopback name server moves to the namespace's first address and every other line stays.
    #[test]
    fn moves_loopback_name_servers() {
        let (rewritten, pairs) = rewrite_resolver(
            "nameserver 127.0.0.53\noptions edns0 trust-ad\nnameserver 192.0.2.1\nsearch lan\n",
        );
        assert_eq!(
            rewritten,
            "nameserver 198.18.0.53\noptions edns0 trust-ad\nnameserver 192.0.2.1\nsearch lan\n"
        );
        assert_eq!(
            pairs,
            vec![(IpAddr::V4(FIRST_NAME_SERVER), "127.0.0.53".parse().unwrap())]
        );
    }

    /// Checks that a configuration with no name server gets the one glibc would ask, moved.
    #[test]
    fn names_the_default_name_server() {
        let (rewritten, pairs) = rewrite_resolver("search lan\n");
        assert_eq!(rewritten, "search lan\nnameserver 198.18.0.53\n");
        assert_eq!(
            pairs,
            vec![(IpAddr::V4(FIRST_NAME_SERVER), DEFAULT_NAME_SERVER)]
        );
    }

    /// Checks that a configuration whose name servers are all reachable stays as it was and moves nothing.
    #[test]
    fn leaves_reachable_name_servers() {
        let (rewritten, pairs) = rewrite_resolver("nameserver 192.0.2.1\nnameserver 2001:db8::1\n");
        assert_eq!(rewritten, "nameserver 192.0.2.1\nnameserver 2001:db8::1\n");
        assert!(pairs.is_empty());
    }
}
