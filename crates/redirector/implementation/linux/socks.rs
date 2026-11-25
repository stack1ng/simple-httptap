//! A SOCKS5 client as RFC 1928 says, with no authentication: CONNECT for a TCP stream, UDP ASSOCIATE for datagrams.

use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The version byte every SOCKS5 message but a datagram starts with.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-3
const VERSION: u8 = 5;
/// The method a client with no credentials offers, and the only one this client accepts.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-3
const NO_AUTHENTICATION: u8 = 0;
/// The command that opens a TCP stream to the address.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-4
const CONNECT: u8 = 1;
/// The command that opens a relay for UDP datagrams.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-4
const UDP_ASSOCIATE: u8 = 3;
/// The byte a reserved field always holds.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-4
const RESERVED: u8 = 0;
/// The address type of an IPv4 address.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-5
const IPV4: u8 = 1;
/// The address type of a domain name, which a length byte starts.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-5
const DOMAIN: u8 = 3;
/// The address type of an IPv6 address.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-5
const IPV6: u8 = 4;
/// The reply code of a request the proxy carried out.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-6
const SUCCEEDED: u8 = 0;
/// The fragment number of a datagram that is whole, the only kind this client sends or takes.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-7
const WHOLE: u8 = 0;

/// Opens a TCP stream to the destination through the proxy.
pub(crate) async fn connect(proxy: SocketAddr, destination: SocketAddr) -> Result<TcpStream> {
    let (stream, _) = request(proxy, CONNECT, destination).await?;
    Ok(stream)
}

/// Opens a UDP relay at the proxy for datagrams from any address, returning the stream it lasts as long as and the relay's address.
pub(crate) async fn associate(proxy: SocketAddr) -> Result<(TcpStream, SocketAddr)> {
    let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), u16::MIN);
    let (stream, relay) = request(proxy, UDP_ASSOCIATE, unspecified).await?;
    let relay = relay.ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "the SOCKS5 proxy named its UDP relay by a domain name",
        )
    })?;
    // A relay at no particular address is at the proxy's.
    let host = if relay.ip().is_unspecified() {
        proxy.ip()
    } else {
        relay.ip()
    };
    Ok((stream, SocketAddr::new(host, relay.port())))
}

/// Greets the proxy, makes the request, and returns the stream with the address the reply bound, none if a name.
async fn request(
    proxy: SocketAddr,
    command: u8,
    address: SocketAddr,
) -> Result<(TcpStream, Option<SocketAddr>)> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.set_nodelay(true)?;
    let greeting = [VERSION, u8::from(true), NO_AUTHENTICATION];
    stream.write_all(&greeting).await?;
    let (version, method) = (stream.read_u8().await?, stream.read_u8().await?);
    if (version, method) != (VERSION, NO_AUTHENTICATION) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "the SOCKS5 proxy wants an authentication this client lacks",
        ));
    }
    let mut message = vec![VERSION, command, RESERVED];
    put_address(&mut message, address);
    stream.write_all(&message).await?;
    let (version, reply, _reserved) = (
        stream.read_u8().await?,
        stream.read_u8().await?,
        stream.read_u8().await?,
    );
    if version != VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "the proxy does not speak SOCKS5",
        ));
    }
    let bound = read_address(&mut stream).await?;
    if reply != SUCCEEDED {
        return Err(Error::new(
            ErrorKind::ConnectionRefused,
            format!("the SOCKS5 proxy refused with reply {reply}"),
        ));
    }
    Ok((stream, bound))
}

/// Appends the address in SOCKS5's form: its type, its bytes, and its port.
fn put_address(message: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            message.push(IPV4);
            message.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            message.push(IPV6);
            message.extend_from_slice(&ip.octets());
        }
    }
    message.extend_from_slice(&address.port().to_be_bytes());
}

/// Reads an address in SOCKS5's form off the stream, returning none for a domain name, which it skips.
async fn read_address(stream: &mut TcpStream) -> Result<Option<SocketAddr>> {
    let ip = match stream.read_u8().await? {
        IPV4 => {
            let mut octets = Ipv4Addr::UNSPECIFIED.octets();
            stream.read_exact(&mut octets).await?;
            Some(IpAddr::from(octets))
        }
        IPV6 => {
            let mut octets = Ipv6Addr::UNSPECIFIED.octets();
            stream.read_exact(&mut octets).await?;
            Some(IpAddr::from(octets))
        }
        DOMAIN => {
            let mut name = vec![u8::MIN; usize::from(stream.read_u8().await?)];
            stream.read_exact(&mut name).await?;
            None
        }
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the SOCKS5 proxy replied with an unknown address type",
            ));
        }
    };
    let port = stream.read_u16().await?;
    Ok(ip.map(|ip| SocketAddr::new(ip, port)))
}

/// Returns the datagram the relay sends on to the destination: SOCKS5's header, then the payload.
pub(crate) fn wrap(destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut datagram = vec![RESERVED, RESERVED, WHOLE];
    put_address(&mut datagram, destination);
    datagram.extend_from_slice(payload);
    datagram
}

/// Returns the source and the payload of a whole datagram the relay brought, or none if it is a fragment or a name's.
pub(crate) fn unwrap(datagram: &[u8]) -> Option<(SocketAddr, &[u8])> {
    let [_, _, fragment, kind, rest @ ..] = datagram else {
        return None;
    };
    if *fragment != WHOLE {
        return None;
    }
    let (ip, rest) = match *kind {
        IPV4 => rest
            .split_first_chunk()
            .map(|(octets, rest)| (IpAddr::from(Ipv4Addr::from(*octets)), rest))?,
        IPV6 => rest
            .split_first_chunk()
            .map(|(octets, rest)| (IpAddr::from(Ipv6Addr::from(*octets)), rest))?,
        _ => return None,
    };
    let (port, payload) = rest.split_first_chunk()?;
    Some((SocketAddr::new(ip, u16::from_be_bytes(*port)), payload))
}
