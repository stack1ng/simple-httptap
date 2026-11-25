//! Tests that a program's TCP and UDP traffic, and its child's, reaches a SOCKS5 proxy and the replies come back.
//!
//! The proxy here echoes what it gets and records what it was asked for. The program is this test binary again, run with a
//! variable that tells its one test to act as the program or its child.
#![cfg(target_os = "linux")]

use std::io::{ErrorKind, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use simple_httptap_redirector::{Capture, Program, Redirector};
use simple_httptap_redirector_linux::NamespaceRedirector;

/// The variable that tells this binary's test which part to play.
const ROLE: &str = "SIMPLE_HTTPTAP_REDIRECTION_ROLE";
/// The variable that tells the program which effective user ID it should run as.
const EXPECTED_UID: &str = "SIMPLE_HTTPTAP_REDIRECTION_UID";
/// The effective user ID root has, as /proc/self/status shows it.
const ROOT_UID: &str = "0";
/// The role of the program the redirector starts.
const PROGRAM_ROLE: &str = "program";
/// The role of the child the program starts.
const CHILD_ROLE: &str = "child";
/// The test that plays a role when the variable names one.
const ROLE_TEST: &str = "plays_its_role";
/// A TCP destination, in TEST-NET-1, which no host has, so only the proxy answers.
const TCP_TARGET: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 7);
/// A UDP destination in TEST-NET-1, where only the proxy answers.
const UDP_TARGET: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 53);
/// The TCP destination the child connects to.
const CHILD_TARGET: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), 80);
/// A TCP destination the proxy says refused the connection.
const REFUSED_TARGET: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)), 9);
/// An IPv6 TCP destination, in the documentation prefix, tried where the namespace has IPv6.
const IPV6_TARGET: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    7,
);
/// The bytes the program sends and gets back on one connection, enough to fill every window on the way.
const BULK: usize = 4 * 1024 * 1024;
/// How long any one exchange may take.
const PATIENCE: Duration = Duration::from_secs(30);
/// The bytes the proxy puts before each datagram it echoes.
const ECHO_PREFIX: &[u8] = b"echo:";
/// The port of a name server.
const DNS_PORT: u16 = 53;
/// The resolver configuration, the host's outside the namespace and the namespace's own inside it.
const RESOLVER_CONFIGURATION: &str = "/etc/resolv.conf";
/// The datagram the program sends its name server, which the proxy echoes rather than sends on.
const NAME_QUERY: &[u8] = b"name query";
/// The datagram the program sends.
const PING: &[u8] = b"ping";
/// The bytes the child sends.
const CHILD_BYTES: &[u8] = b"from the child";
/// The SOCKS5 version byte.
const VERSION_5: u8 = 5;
/// The SOCKS5 method that asks for no authentication.
const METHOD_NONE: u8 = 0;
/// The SOCKS5 COMMAND_CONNECT command.
const COMMAND_CONNECT: u8 = 1;
/// The SOCKS5 UDP ASSOCIATE command.
const COMMAND_UDP_ASSOCIATE: u8 = 3;
/// The SOCKS5 address type of an IPv4 address.
const ADDRESS_IPV4: u8 = 1;
/// The SOCKS5 address type of an IPv6 address.
const ADDRESS_IPV6: u8 = 4;
/// The SOCKS5 reply of a request carried out.
const REPLY_SUCCEEDED: u8 = 0;
/// The SOCKS5 reply of a destination that refused the connection.
const REPLY_REFUSED: u8 = 5;
/// The bytes the proxy reads at once.
const BUFFER: usize = 64 * 1024;

/// A request the proxy got.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Asked {
    Connect(SocketAddr),
    Associate,
    Datagram(SocketAddr, Vec<u8>),
}

/// The requests the proxy got, in order.
type Log = Arc<Mutex<Vec<Asked>>>;

/// Checks that the program's TCP and UDP traffic and its child's goes through the proxy and that the replies come back.
#[test]
fn carries_a_program_and_its_child_through_the_proxy() {
    let log = Log::default();
    let proxy = start_proxy(log.clone());
    let program = Program {
        path: std::env::current_exe()
            .expect("this test has a path")
            .into(),
        arguments: role_arguments(),
        environment: vec![
            (ROLE.into(), Some(PROGRAM_ROLE.into())),
            (EXPECTED_UID.into(), Some(expected_uid().into())),
        ],
    };
    let capture = match NamespaceRedirector.launch(&program, proxy) {
        Err(fault) if fault.kind() == ErrorKind::Unsupported => {
            eprintln!("skipped, as this system cannot redirect: {fault}");
            return;
        }
        launched => launched.expect("the program starts"),
    };
    let status = capture.wait().expect("the program exits");
    assert!(status.success(), "the program failed: {status}");
    let asked = log.lock().expect("the log is whole").clone();
    for wanted in [
        Asked::Connect(TCP_TARGET),
        Asked::Associate,
        Asked::Datagram(UDP_TARGET, PING.to_vec()),
        Asked::Connect(REFUSED_TARGET),
        Asked::Connect(CHILD_TARGET),
        Asked::Datagram(
            SocketAddr::new(first_name_server(), DNS_PORT),
            NAME_QUERY.to_vec(),
        ),
    ] {
        assert!(
            asked.contains(&wanted),
            "the proxy was not asked for {wanted:?}, only {asked:?}"
        );
    }
}

/// Plays the program or its child when the role variable says so, and does nothing otherwise.
#[test]
fn plays_its_role() {
    match std::env::var(ROLE).as_deref() {
        Ok(PROGRAM_ROLE) => act_as_the_program(),
        Ok(CHILD_ROLE) => echo_through(CHILD_TARGET, CHILD_BYTES.to_vec()),
        _ => {}
    }
}

/// Returns the arguments that run this binary's role test alone.
fn role_arguments() -> Vec<std::ffi::OsString> {
    ["--exact", ROLE_TEST, "--nocapture", "--test-threads=1"]
        .map(Into::into)
        .to_vec()
}

/// Sends what the program sends and checks every answer.
///
/// That is a bulk TCP exchange, a datagram, a name query, a refused connection, IPv6 where there is any, and a child's.
fn act_as_the_program() {
    assert_eq!(
        Some(effective_uid()),
        std::env::var(EXPECTED_UID).ok(),
        "the program runs as the user it should"
    );

    let bulk: Vec<u8> = (usize::MIN..BULK)
        .map(|index| index.to_le_bytes()[usize::MIN])
        .collect();
    echo_through(TCP_TARGET, bulk);

    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), u16::MIN))
        .expect("a UDP socket binds");
    socket
        .set_read_timeout(Some(PATIENCE))
        .expect("the timeout is set");
    socket
        .send_to(PING, UDP_TARGET)
        .expect("the datagram is sent");
    let mut reply = vec![u8::MIN; BUFFER];
    let (length, from) = socket.recv_from(&mut reply).expect("a reply comes");
    assert_eq!(
        from, UDP_TARGET,
        "the reply comes from where the datagram went"
    );
    assert_eq!(&reply[..length], [ECHO_PREFIX, PING].concat());

    let refused = TcpStream::connect_timeout(&REFUSED_TARGET, PATIENCE).map(|_| ());
    assert_eq!(
        refused.map_err(|fault| fault.kind()),
        Err(ErrorKind::ConnectionRefused)
    );

    match TcpStream::connect_timeout(&IPV6_TARGET, PATIENCE) {
        Ok(stream) => {
            drop(stream);
            echo_through(IPV6_TARGET, PING.to_vec());
            println!("IPv6 went through the proxy too");
        }
        Err(fault) => println!("the namespace has no IPv6 here: {fault}"),
    }

    let name_server = SocketAddr::new(first_name_server(), DNS_PORT);
    assert!(
        !name_server.ip().is_loopback(),
        "the namespace still names a loopback name server: {name_server}"
    );
    socket
        .send_to(NAME_QUERY, name_server)
        .expect("the query is sent");
    let (length, from) = socket.recv_from(&mut reply).expect("an answer comes");
    assert_eq!(
        from, name_server,
        "the answer comes from the name server the program asked"
    );
    assert_eq!(&reply[..length], [ECHO_PREFIX, NAME_QUERY].concat());

    let child = Command::new(std::env::current_exe().expect("this test has a path"))
        .args(role_arguments())
        .env(ROLE, CHILD_ROLE)
        .status()
        .expect("the child starts");
    assert!(child.success(), "the child failed: {child}");
}

/// Returns the first name server of the resolver configuration, or the one glibc asks if it names none.
fn first_name_server() -> IpAddr {
    let resolver = std::fs::read_to_string(RESOLVER_CONFIGURATION).unwrap_or_default();
    let mut servers = resolver
        .lines()
        .filter_map(|line| line.strip_prefix("nameserver"))
        .filter_map(|rest| rest.trim().parse().ok());
    servers.next().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// Returns the effective user ID the program should run as: the one sudo was run from if root under sudo, else this test's.
fn expected_uid() -> String {
    let own = effective_uid();
    match std::env::var("SUDO_UID") {
        Ok(sudo) if own == ROOT_UID => sudo,
        _ => own,
    }
}

/// Returns this process's effective user ID, from the second field of the Uid line of its status.
fn effective_uid() -> String {
    let status = std::fs::read_to_string("/proc/self/status").expect("the process has a status");
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .expect("the status has a Uid line");
    line.split_whitespace()
        .nth(usize::from(true))
        .expect("the Uid line has an effective ID")
        .to_owned()
}

/// Sends the bytes to the destination, ends the sending side, and checks the same bytes come back before the other side ends.
fn echo_through(destination: SocketAddr, bytes: Vec<u8>) {
    let mut stream =
        TcpStream::connect_timeout(&destination, PATIENCE).expect("the connection opens");
    stream
        .set_read_timeout(Some(PATIENCE))
        .expect("the timeout is set");
    let mut writer = stream.try_clone().expect("the stream clones");
    let expected = bytes.clone();
    let sending = thread::spawn(move || {
        writer.write_all(&bytes).expect("the bytes are sent");
        writer
            .shutdown(Shutdown::Write)
            .expect("the sending side ends");
    });
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).expect("the echo ends");
    sending.join().expect("the sender finishes");
    assert_eq!(echoed.len(), expected.len(), "the echo has every byte");
    assert!(echoed == expected, "the echo has the same bytes");
}

/// Starts a SOCKS5 proxy on a loopback port that echoes every stream and datagram and logs what it was asked for.
fn start_proxy(log: Log) -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), u16::MIN))
        .expect("the proxy binds");
    let address = listener.local_addr().expect("the proxy has an address");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let log = log.clone();
            thread::spawn(move || serve(stream, &log));
        }
    });
    address
}

/// Serves one SOCKS5 client: greets it, carries out its request, and echoes.
fn serve(mut stream: TcpStream, log: &Log) -> std::io::Result<()> {
    let [_version, methods] = read_array(&mut stream)?;
    let mut offered = vec![u8::MIN; usize::from(methods)];
    stream.read_exact(&mut offered)?;
    stream.write_all(&[VERSION_5, METHOD_NONE])?;
    let [_version, command, _reserved, kind] = read_array(&mut stream)?;
    let destination = read_address(&mut stream, kind)?;
    let record = |asked| log.lock().expect("the log is whole").push(asked);
    match command {
        COMMAND_CONNECT => {
            record(Asked::Connect(destination));
            if destination == REFUSED_TARGET {
                return reply(&mut stream, REPLY_REFUSED, destination);
            }
            reply(&mut stream, REPLY_SUCCEEDED, destination)?;
            echo(stream)
        }
        COMMAND_UDP_ASSOCIATE => {
            record(Asked::Associate);
            let relay =
                UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), u16::MIN))?;
            reply(&mut stream, REPLY_SUCCEEDED, relay.local_addr()?)?;
            let log = log.clone();
            thread::spawn(move || echo_datagrams(&relay, &log));
            // The association lasts until the client closes its stream.
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).map(|_| ())
        }
        _ => Err(ErrorKind::Unsupported.into()),
    }
}

/// Echoes every byte of the stream back until the client ends its side, then ends this side.
fn echo(mut stream: TcpStream) -> std::io::Result<()> {
    let mut buffer = vec![u8::MIN; BUFFER];
    loop {
        let length = stream.read(&mut buffer)?;
        if length == usize::MIN {
            return stream.shutdown(Shutdown::Write);
        }
        stream.write_all(&buffer[..length])?;
    }
}

/// Answers each datagram of the relay from the address it was sent to, with the echo prefix before its payload.
fn echo_datagrams(relay: &UdpSocket, log: &Log) -> std::io::Result<()> {
    let mut buffer = vec![u8::MIN; BUFFER];
    loop {
        let (length, client) = relay.recv_from(&mut buffer)?;
        let mut datagram = &buffer[..length];
        let [_, _, _fragment, kind] = read_array(&mut datagram)?;
        let destination = read_address(&mut datagram, kind)?;
        log.lock()
            .expect("the log is whole")
            .push(Asked::Datagram(destination, datagram.to_vec()));
        let mut answer = vec![u8::MIN, u8::MIN, u8::MIN];
        put_address(&mut answer, destination);
        answer.extend_from_slice(ECHO_PREFIX);
        answer.extend_from_slice(datagram);
        relay.send_to(&answer, client)?;
    }
}

/// Writes a SOCKS5 reply with the code and the address.
fn reply(stream: &mut TcpStream, code: u8, address: SocketAddr) -> std::io::Result<()> {
    let mut message = vec![VERSION_5, code, u8::MIN];
    put_address(&mut message, address);
    stream.write_all(&message)
}

/// Appends a SOCKS5 address: its type, its bytes and its port.
fn put_address(message: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            message.push(ADDRESS_IPV4);
            message.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            message.push(ADDRESS_IPV6);
            message.extend_from_slice(&ip.octets());
        }
    }
    message.extend_from_slice(&address.port().to_be_bytes());
}

/// Reads a SOCKS5 address of the type.
fn read_address(reader: &mut impl Read, kind: u8) -> std::io::Result<SocketAddr> {
    let ip = match kind {
        ADDRESS_IPV4 => IpAddr::from(Ipv4Addr::from(read_array(reader)?)),
        ADDRESS_IPV6 => IpAddr::from(Ipv6Addr::from(read_array::<{ size_of::<Ipv6Addr>() }>(
            reader,
        )?)),
        _ => return Err(ErrorKind::Unsupported.into()),
    };
    Ok(SocketAddr::new(ip, u16::from_be_bytes(read_array(reader)?)))
}

/// Reads as many bytes as the array holds.
fn read_array<const N: usize>(reader: &mut impl Read) -> std::io::Result<[u8; N]> {
    let mut bytes = [u8::MIN; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
