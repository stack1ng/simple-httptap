//! A SOCKS5 client with no authentication: CONNECT for TCP and UDP ASSOCIATE for UDP.
//!
//! https://www.rfc-editor.org/rfc/rfc1928

use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// The protocol version, the first byte of every message.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-3
const SOCKS5_VERSION: u8 = 5;
/// The method code a client offers to go without credentials, and the only one this client accepts back.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-3
const NO_AUTHENTICATION_METHOD: u8 = 0;
/// The number of methods the greeting offers: no authentication alone.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-3
const METHODS_OFFERED: u8 = 1;
/// The command that opens a TCP connection to the address.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-4
const CONNECT_COMMAND: u8 = 1;
/// The command that opens a UDP relay.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-4
const UDP_ASSOCIATE_COMMAND: u8 = 3;
/// The address type byte that says four IPv4 octets follow.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-5
const IPV4_TYPE: u8 = 1;
/// The address type of a domain name, a length byte and that many bytes.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-5
const DOMAIN_TYPE: u8 = 3;
/// The address type byte that says sixteen IPv6 octets follow.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-5
const IPV6_TYPE: u8 = 4;
/// The reply that says the request succeeded.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-6
const SUCCEEDED_REPLY: u8 = 0;
/// The fragment number of a datagram that is whole, the only kind sent or accepted.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-7
const WHOLE_FRAGMENT: u8 = 0;
/// The bytes of an IPv4 address.
const IPV4_LENGTH: usize = size_of::<Ipv4Addr>();
/// The bytes of an IPv6 address.
const IPV6_LENGTH: usize = size_of::<Ipv6Addr>();
/// The bytes of a port.
const PORT_LENGTH: usize = size_of::<u16>();

/// A UDP relay the proxy opened, which lasts as long as its control connection.
#[derive(Debug)]
pub(crate) struct Association {
    /// The TCP connection that asked for the relay; the relay ends when it closes.
    pub(crate) control: TcpStream,
    /// A socket connected to the relay, which carries datagrams wrapped by `wrap`.
    pub(crate) socket: UdpSocket,
}

/// Opens a TCP connection to the destination through the proxy.
pub(crate) async fn connect(
    proxy: SocketAddr,
    destination: SocketAddr,
) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.set_nodelay(true)?;
    request(&mut stream, CONNECT_COMMAND, destination).await?;
    Ok(stream)
}

/// Asks the proxy for a UDP relay and connects a loopback socket to it.
pub(crate) async fn associate(proxy: SocketAddr) -> std::io::Result<Association> {
    let mut control = TcpStream::connect(proxy).await?;
    let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), u16::MIN);
    let mut relay = request(&mut control, UDP_ASSOCIATE_COMMAND, unspecified).await?;
    if relay.ip().is_unspecified() {
        relay.set_ip(proxy.ip());
    }
    let socket = UdpSocket::bind(SocketAddr::new(proxy.ip(), u16::MIN)).await?;
    socket.connect(relay).await?;
    Ok(Association { control, socket })
}

/// Returns the datagram that asks the relay to send the payload to the destination.
pub(crate) fn wrap(destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut datagram = vec![u8::MIN, u8::MIN, WHOLE_FRAGMENT];
    encode(destination, &mut datagram);
    datagram.extend_from_slice(payload);
    datagram
}

/// Returns the address a datagram from the relay came from and its payload; none for a fragment, a domain name or what is malformed.
pub(crate) fn unwrap(datagram: &[u8]) -> Option<(SocketAddr, &[u8])> {
    let [_, _, WHOLE_FRAGMENT, kind, rest @ ..] = datagram else {
        return None;
    };
    let (ip, rest) = match *kind {
        IPV4_TYPE => {
            let (octets, rest) = rest.split_first_chunk::<IPV4_LENGTH>()?;
            (IpAddr::from(*octets), rest)
        }
        IPV6_TYPE => {
            let (octets, rest) = rest.split_first_chunk::<IPV6_LENGTH>()?;
            (IpAddr::from(*octets), rest)
        }
        _ => return None,
    };
    let (port, payload) = rest.split_first_chunk::<PORT_LENGTH>()?;
    Some((SocketAddr::new(ip, u16::from_be_bytes(*port)), payload))
}

/// Greets the proxy without authentication and sends it the command, returning the address it reports bound.
async fn request(
    stream: &mut TcpStream,
    command: u8,
    address: SocketAddr,
) -> std::io::Result<SocketAddr> {
    stream
        .write_all(&[SOCKS5_VERSION, METHODS_OFFERED, NO_AUTHENTICATION_METHOD])
        .await?;
    let (version, method) = (stream.read_u8().await?, stream.read_u8().await?);
    if version != SOCKS5_VERSION || method != NO_AUTHENTICATION_METHOD {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "the SOCKS5 proxy at {} wants authentication or is no SOCKS5 proxy",
                stream.peer_addr()?
            ),
        ));
    }
    let mut message = vec![SOCKS5_VERSION, command, u8::MIN];
    encode(address, &mut message);
    stream.write_all(&message).await?;
    let (version, reply, _reserved) = (
        stream.read_u8().await?,
        stream.read_u8().await?,
        stream.read_u8().await?,
    );
    if version != SOCKS5_VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "the SOCKS5 proxy replied with another version",
        ));
    }
    let bound = read_address(stream).await?;
    if reply != SUCCEEDED_REPLY {
        return Err(Error::new(
            ErrorKind::ConnectionRefused,
            format!("the SOCKS5 proxy refused {address} with reply {reply}"),
        ));
    }
    Ok(bound)
}

/// Appends the address in SOCKS5's form: its type, its bytes and its port.
fn encode(address: SocketAddr, message: &mut Vec<u8>) {
    match address.ip() {
        IpAddr::V4(ip) => {
            message.push(IPV4_TYPE);
            message.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            message.push(IPV6_TYPE);
            message.extend_from_slice(&ip.octets());
        }
    }
    message.extend_from_slice(&address.port().to_be_bytes());
}

/// Reads an address in SOCKS5's form; a domain name reads as the unspecified IPv4 address.
async fn read_address(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<SocketAddr> {
    let ip = match stream.read_u8().await? {
        IPV4_TYPE => IpAddr::V4(Ipv4Addr::from(stream.read_u32().await?)),
        IPV6_TYPE => IpAddr::V6(Ipv6Addr::from(stream.read_u128().await?)),
        DOMAIN_TYPE => {
            let mut name = vec![u8::MIN; usize::from(stream.read_u8().await?)];
            stream.read_exact(&mut name).await?;
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
        kind => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("the SOCKS5 proxy sent address type {kind}"),
            ));
        }
    };
    Ok(SocketAddr::new(ip, stream.read_u16().await?))
}

/// A SOCKS5 proxy on loopback for tests, which sends back whatever it is sent.
#[cfg(test)]
pub(crate) mod echo {
    use super::*;

    use tokio::net::TcpListener;

    /// The reply that says the destination refused the connection.
    ///
    /// https://www.rfc-editor.org/rfc/rfc1928#section-6
    const REFUSED: u8 = 5;

    /// Starts the proxy: CONNECT streams echo unless it refuses them, and datagrams come back from where they were sent.
    pub(crate) async fn start(refuse: bool) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, u16::MIN))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(serve(stream, refuse));
            }
        });
        address
    }

    /// Answers one client's greeting and request, then echoes.
    async fn serve(mut stream: TcpStream, refuse: bool) {
        let (_version, methods) = (
            stream.read_u8().await.unwrap(),
            stream.read_u8().await.unwrap(),
        );
        stream
            .read_exact(&mut vec![u8::MIN; usize::from(methods)])
            .await
            .unwrap();
        stream
            .write_all(&[SOCKS5_VERSION, NO_AUTHENTICATION_METHOD])
            .await
            .unwrap();
        let (_version, command, _reserved) = (
            stream.read_u8().await.unwrap(),
            stream.read_u8().await.unwrap(),
            stream.read_u8().await.unwrap(),
        );
        read_address(&mut stream).await.unwrap();
        let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, u16::MIN))
            .await
            .unwrap();
        let bound = if command == UDP_ASSOCIATE_COMMAND {
            relay.local_addr().unwrap()
        } else {
            stream.local_addr().unwrap()
        };
        let mut reply = vec![
            SOCKS5_VERSION,
            if refuse { REFUSED } else { SUCCEEDED_REPLY },
            u8::MIN,
        ];
        encode(bound, &mut reply);
        stream.write_all(&reply).await.unwrap();
        if refuse {
            return;
        }
        if command == UDP_ASSOCIATE_COMMAND {
            tokio::spawn(async move {
                let mut buffer = vec![u8::MIN; usize::from(u16::MAX)];
                while let Ok((length, sender)) = relay.recv_from(&mut buffer).await {
                    let (destination, payload) = unwrap(&buffer[..length]).unwrap();
                    relay
                        .send_to(&wrap(destination, payload), sender)
                        .await
                        .unwrap();
                }
            });
            let _ = stream.read_to_end(&mut Vec::new()).await;
        } else {
            let (mut reader, mut writer) = stream.split();
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address a test connects to.
    const DESTINATION: &str = "198.51.100.7:443";

    /// Checks that a wrapped datagram unwraps to its address and payload.
    #[test]
    fn unwraps_what_it_wraps() {
        for destination in [DESTINATION, "[2001:db8::7]:443"] {
            let destination = destination.parse().unwrap();
            assert_eq!(
                unwrap(&wrap(destination, b"hello")),
                Some((destination, &b"hello"[..]))
            );
        }
    }

    /// Checks that a stream opened with CONNECT carries bytes both ways.
    #[tokio::test]
    async fn connects_through_a_proxy() {
        let proxy = echo::start(false).await;
        let mut stream = connect(proxy, DESTINATION.parse().unwrap()).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut received = String::new();
        stream.read_to_string(&mut received).await.unwrap();
        assert_eq!(received, "ping");
    }

    /// Checks that a refusal from the proxy is an error.
    #[tokio::test]
    async fn fails_when_the_proxy_refuses() {
        let proxy = echo::start(true).await;
        let refusal = connect(proxy, DESTINATION.parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(refusal.kind(), ErrorKind::ConnectionRefused);
    }

    /// Checks that a datagram sent through an association comes back from its destination.
    #[tokio::test]
    async fn relays_datagrams() {
        let association = associate(echo::start(false).await).await.unwrap();
        let destination = DESTINATION.parse().unwrap();
        association
            .socket
            .send(&wrap(destination, b"ping"))
            .await
            .unwrap();
        let mut buffer = vec![u8::MIN; usize::from(u16::MAX)];
        let length = association.socket.recv(&mut buffer).await.unwrap();
        assert_eq!(unwrap(&buffer[..length]), Some((destination, &b"ping"[..])));
    }
}
