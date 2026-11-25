//! The tests every implementation of simple-httptap-proxy runs, written against its traits alone.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use simple_httptap_authority::Authority;
use simple_httptap_keylog::Keylog;
use simple_httptap_proxy::{Listener, Mode, Proxy};

/// Bytes that are no TLS and no HTTP, so the proxy passes them through as they are.
const PLAIN_BYTES: &[u8] = b"\0plain bytes through a tunnel";
/// The SOCKS5 greeting that offers only the method without authentication.
const GREETING: &[u8] = &[5, 1, 0];
/// The server's answer choosing the method without authentication.
const NO_AUTHENTICATION_CHOSEN: [u8; 2] = [5, 0];
/// The first bytes of a request: the version, the command and the reserved byte.
const CONNECT: [u8; 3] = [5, 1, 0];
const BIND: [u8; 3] = [5, 2, 0];
const UDP_ASSOCIATE: [u8; 3] = [5, 3, 0];
/// The status of a reply to a request that succeeded.
const SUCCEEDED: u8 = 0;
/// The status of a reply to a command the proxy does not carry out.
const COMMAND_NOT_SUPPORTED: u8 = 7;
/// The bytes of a reply with an IPv4 address: version, status, reserved, type, address and port.
const IPV4_REPLY_SIZE: usize = 10;
/// The address type of IPv4.
const IPV4: u8 = 1;
/// The header of a whole relayed UDP datagram before its address: two reserved bytes and fragment zero.
const UDP_HEADER_START: [u8; 3] = [0, 0, 0];
/// How long a test waits for a datagram.
const DATAGRAM_WAIT: Duration = Duration::from_secs(5);
/// The largest datagram the tests read.
const DATAGRAM_LIMIT: usize = 2048;
/// The name of the key log file in each test's temporary folder.
const KEYLOG_FILE: &str = "keys.log";

/// Binds the proxy in each mode's turn with its authority and key log in a new temporary folder and its sink made anew.
fn bind_proxy<T: Proxy>(proxy: &T, mode: Mode) -> T::Listener {
    let folder = tempfile::tempdir().expect("a temporary folder").keep();
    let signer = T::Authority::default().open(&folder).expect("the authority opens");
    let keys = T::Keylog::default().open(&folder.join(KEYLOG_FILE)).expect("the key log opens");
    proxy.bind(signer, T::Sink::default(), keys, mode, None).expect("the proxy binds")
}

/// Starts the proxy serving and returns its address.
fn serve<T: Proxy>(proxy: &T, mode: Mode) -> SocketAddr {
    let listener = bind_proxy(proxy, mode);
    let address = listener.local_address();
    thread::spawn(move || listener.serve());
    address
}

/// Connects to the proxy, greets it, and sends a request for the command and IPv4 address; returns the reply.
fn request(proxy: SocketAddr, command: [u8; 3], target: SocketAddr) -> (TcpStream, [u8; IPV4_REPLY_SIZE]) {
    let SocketAddr::V4(target) = target else { panic!("an IPv4 target") };
    let mut stream = TcpStream::connect(proxy).expect("the proxy accepts");
    stream.write_all(GREETING).expect("the greeting goes");
    let mut chosen = [u8::MIN; 2];
    stream.read_exact(&mut chosen).expect("the method comes back");
    assert_eq!(chosen, NO_AUTHENTICATION_CHOSEN);
    let mut message = command.to_vec();
    message.push(IPV4);
    message.extend(target.ip().octets());
    message.extend(target.port().to_be_bytes());
    stream.write_all(&message).expect("the request goes");
    let mut reply = [u8::MIN; IPV4_REPLY_SIZE];
    stream.read_exact(&mut reply).expect("the reply comes");
    (stream, reply)
}

/// Returns the address in an IPv4 reply.
fn bound_address(reply: &[u8; IPV4_REPLY_SIZE]) -> SocketAddr {
    let octets: [u8; 4] = reply[4..8].try_into().expect("four octets");
    SocketAddr::from((Ipv4Addr::from(octets), u16::from_be_bytes([reply[8], reply[9]])))
}

/// Checks that the proxy listens on a loopback port the operating system picked.
pub fn listens_on_loopback<T: Proxy>(proxy: T) {
    let address = bind_proxy(&proxy, Mode::PassThrough).local_address();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), u16::MIN);
}

/// Checks that a CONNECT carries bytes that are no TLS to the target and back unchanged, in either mode.
pub fn keeps_tcp_bytes_unchanged<T: Proxy>(proxy: T) {
    for mode in [Mode::PassThrough, Mode::Intercept] {
        let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, u16::MIN)).expect("an echo server");
        let target = echo.local_addr().expect("the echo server's address");
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("the proxy connects");
            let mut received = vec![u8::MIN; PLAIN_BYTES.len()];
            stream.read_exact(&mut received).expect("the bytes arrive");
            stream.write_all(&received).expect("the bytes go back");
        });
        let (mut client, reply) = request(serve(&proxy, mode), CONNECT, target);
        assert_eq!(reply[1], SUCCEEDED, "the CONNECT succeeds in {mode:?}");
        client.write_all(PLAIN_BYTES).expect("the bytes go");
        let mut echoed = vec![u8::MIN; PLAIN_BYTES.len()];
        client.read_exact(&mut echoed).expect("the bytes come back");
        assert_eq!(echoed, PLAIN_BYTES);
    }
}

/// Checks that a UDP association relays a datagram to the target and its answer back unchanged.
pub fn keeps_udp_datagrams_unchanged<T: Proxy>(proxy: T) {
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, u16::MIN)).expect("an echo server");
    let target = echo.local_addr().expect("the echo server's address");
    thread::spawn(move || {
        let mut buffer = [u8::MIN; DATAGRAM_LIMIT];
        let (size, from) = echo.recv_from(&mut buffer).expect("the datagram arrives");
        echo.send_to(&buffer[..size], from).expect("the datagram goes back");
    });
    let unspecified = SocketAddr::from((Ipv4Addr::UNSPECIFIED, u16::MIN));
    let (_control, reply) = request(serve(&proxy, Mode::PassThrough), UDP_ASSOCIATE, unspecified);
    assert_eq!(reply[1], SUCCEEDED);
    let relay = bound_address(&reply);
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, u16::MIN)).expect("a client socket");
    socket.set_read_timeout(Some(DATAGRAM_WAIT)).expect("a read timeout");
    let SocketAddr::V4(target_v4) = target else { panic!("an IPv4 target") };
    let mut header = UDP_HEADER_START.to_vec();
    header.push(IPV4);
    header.extend(target_v4.ip().octets());
    header.extend(target_v4.port().to_be_bytes());
    let mut datagram = header.clone();
    datagram.extend_from_slice(PLAIN_BYTES);
    socket.send_to(&datagram, relay).expect("the datagram goes");
    let mut buffer = [u8::MIN; DATAGRAM_LIMIT];
    let (size, from) = socket.recv_from(&mut buffer).expect("the answer comes back");
    assert_eq!(from, relay);
    assert_eq!(&buffer[..header.len()], header.as_slice(), "the answer names the target it came from");
    assert_eq!(&buffer[header.len()..size], PLAIN_BYTES);
}

/// Checks that a BIND, which the proxy does not carry out, is answered as not supported.
pub fn refuses_bind<T: Proxy>(proxy: T) {
    let unspecified = SocketAddr::from((Ipv4Addr::LOCALHOST, u16::MAX));
    let (_stream, reply) = request(serve(&proxy, Mode::PassThrough), BIND, unspecified);
    assert_eq!(reply[1], COMMAND_NOT_SUPPORTED);
}

/// Runs each suite function above as its own test on a value made anew for every test.
///
/// List every suite function here, in the order above, and nothing else.
#[macro_export]
macro_rules! tests {
    ($value:expr) => {
        #[test]
        fn listens_on_loopback() {
            $crate::listens_on_loopback($value);
        }

        #[test]
        fn keeps_tcp_bytes_unchanged() {
            $crate::keeps_tcp_bytes_unchanged($value);
        }

        #[test]
        fn keeps_udp_datagrams_unchanged() {
            $crate::keeps_udp_datagrams_unchanged($value);
        }

        #[test]
        fn refuses_bind() {
            $crate::refuses_bind($value);
        }
    };
}
