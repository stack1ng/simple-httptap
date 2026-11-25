//! The tests every implementation of simple-httptap-proxy runs, written against its traits alone.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;

use simple_httptap_authority::Authority;
use simple_httptap_proxy::{Listener, Proxy};

/// Bytes that are no TLS, so the proxy passes them through without ending TLS.
const PLAIN_BYTES: &[u8] = b"\0plain bytes through a tunnel";
/// The start of the status line of a tunnel the proxy opened.
const TUNNEL_OPENED: &str = "HTTP/1.1 200";
/// The empty line that ends a head.
const HEAD_END: &str = "\r\n";

/// Binds the proxy with its authority opened in a new temporary folder and its sink made anew.
fn bind_proxy<T: Proxy>(proxy: &T) -> T::Listener {
    let folder = tempfile::tempdir().expect("a temporary folder").keep();
    let signer = T::Authority::default().open(&folder).expect("the authority opens");
    proxy.bind(signer, T::Sink::default(), None).expect("the proxy binds")
}

/// Checks that the proxy listens on a loopback port the operating system picked.
pub fn listens_on_loopback<T: Proxy>(proxy: T) {
    let address = bind_proxy(&proxy).local_address();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), u16::MIN);
}

/// Checks that a CONNECT tunnel carries bytes that are no TLS to the target and back unchanged.
pub fn keeps_tunnel_bytes_unchanged<T: Proxy>(proxy: T) {
    let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, u16::MIN)).expect("an echo server");
    let target = echo.local_addr().expect("the echo server's address");
    thread::spawn(move || {
        let (mut stream, _) = echo.accept().expect("the proxy connects");
        let mut received = vec![u8::MIN; PLAIN_BYTES.len()];
        stream.read_exact(&mut received).expect("the bytes arrive");
        stream.write_all(&received).expect("the bytes go back");
    });
    let listener = bind_proxy(&proxy);
    let address = listener.local_address();
    thread::spawn(move || listener.serve());

    let mut client = TcpStream::connect(address).expect("the proxy accepts");
    write!(client, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").expect("the request goes");
    let mut reader = BufReader::new(client.try_clone().expect("a second handle"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("the status line");
    assert!(line.starts_with(TUNNEL_OPENED), "the tunnel opens: {line}");
    while line != HEAD_END {
        line.clear();
        reader.read_line(&mut line).expect("a field line");
    }
    client.write_all(PLAIN_BYTES).expect("the bytes go");
    let mut echoed = vec![u8::MIN; PLAIN_BYTES.len()];
    reader.read_exact(&mut echoed).expect("the bytes come back");
    assert_eq!(echoed, PLAIN_BYTES);
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
        fn keeps_tunnel_bytes_unchanged() {
            $crate::keeps_tunnel_bytes_unchanged($value);
        }
    };
}
