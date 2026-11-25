//! SOCKS5 as RFC 1928 says: the server side clients speak to, and the client side for an upstream proxy.
//!
//! https://www.rfc-editor.org/rfc/rfc1928

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use simple_httptap_proxy::Upstream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// The protocol version every SOCKS5 message starts with.
const VERSION: u8 = 5;
/// The method that needs no authentication.
const NO_AUTHENTICATION: u8 = 0x00;
/// The username/password method.
///
/// https://www.rfc-editor.org/rfc/rfc1929
const USERNAME_PASSWORD: u8 = 0x02;
/// The answer that none of the client's methods is acceptable.
const NO_ACCEPTABLE_METHODS: u8 = 0xFF;
/// The version of the username/password subnegotiation.
const USERNAME_PASSWORD_VERSION: u8 = 0x01;
/// The username/password status that means success.
const AUTHENTICATED: u8 = 0x00;
/// The reserved byte in requests, replies and UDP headers.
const RESERVED: u8 = 0x00;
/// The address type of an IPv4 address.
const IPV4: u8 = 0x01;
/// The address type of a domain name, its length first.
const DOMAIN_NAME: u8 = 0x03;
/// The address type of an IPv6 address.
const IPV6: u8 = 0x04;
/// The fragment number of a whole UDP datagram, the only kind this proxy relays.
const WHOLE_DATAGRAM: u8 = 0x00;
/// The bytes before a UDP datagram's address: two reserved bytes and the fragment number.
const UDP_HEADER_START: usize = 3;
/// The bytes of a port.
const PORT_SIZE: usize = size_of::<u16>();

/// A command a client asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Connect,
    Bind,
    UdpAssociate,
}

impl Command {
    /// The command's code on the wire.
    const fn code(self) -> u8 {
        match self {
            Self::Connect => 0x01,
            Self::Bind => 0x02,
            Self::UdpAssociate => 0x03,
        }
    }

    /// Returns the command a code names, or none for an unknown one.
    fn from_code(code: u8) -> Option<Self> {
        [Self::Connect, Self::Bind, Self::UdpAssociate].into_iter().find(|command| command.code() == code)
    }
}

/// A reply's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Succeeded,
    GeneralFailure,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Status {
    /// The status's code on the wire.
    const fn code(self) -> u8 {
        match self {
            Self::Succeeded => 0x00,
            Self::GeneralFailure => 0x01,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
        }
    }

    /// Returns the status that best tells a client why a connection failed.
    pub(crate) fn of(fault: &std::io::Error) -> Self {
        match fault.kind() {
            std::io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NotFound => Self::HostUnreachable,
            std::io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            _ => Self::GeneralFailure,
        }
    }
}

/// A destination as a client names it: an IP address or a domain name, with a port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Address {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(address) => address.fmt(formatter),
            Self::Domain(name, port) => write!(formatter, "{name}:{port}"),
        }
    }
}

impl Address {
    /// Returns the host without its port, an IPv6 address without brackets.
    pub(crate) fn host(&self) -> String {
        match self {
            Self::Ip(address) => address.ip().to_string(),
            Self::Domain(name, _) => name.clone(),
        }
    }

    /// Appends the address in SOCKS5's form: its type, the address, then the port.
    fn encode(&self, output: &mut Vec<u8>) {
        let port = match self {
            Self::Ip(SocketAddr::V4(address)) => {
                output.push(IPV4);
                output.extend(address.ip().octets());
                address.port()
            }
            Self::Ip(SocketAddr::V6(address)) => {
                output.push(IPV6);
                output.extend(address.ip().octets());
                address.port()
            }
            Self::Domain(name, port) => {
                output.push(DOMAIN_NAME);
                output.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
                output.extend(name.as_bytes().iter().take(usize::from(u8::MAX)));
                *port
            }
        };
        output.extend(port.to_be_bytes());
    }

    /// Reads an address in SOCKS5's form off a stream.
    async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Self> {
        let kind = reader.read_u8().await?;
        let ip = match kind {
            IPV4 => {
                let mut octets = [u8::MIN; size_of::<u32>()];
                reader.read_exact(&mut octets).await?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            IPV6 => {
                let mut octets = [u8::MIN; size_of::<u128>()];
                reader.read_exact(&mut octets).await?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            DOMAIN_NAME => {
                let mut name = vec![u8::MIN; usize::from(reader.read_u8().await?)];
                reader.read_exact(&mut name).await?;
                let port = reader.read_u16().await?;
                let name = String::from_utf8(name).map_err(|_| invalid("a domain name that is not UTF-8"))?;
                return Ok(Self::Domain(name, port));
            }
            _ => return Err(unsupported_address_type(kind)),
        };
        Ok(Self::Ip(SocketAddr::new(ip, reader.read_u16().await?)))
    }

    /// Returns the address at the start of the bytes, and how many bytes it took.
    fn parse(bytes: &[u8]) -> Option<(Self, usize)> {
        let (&kind, rest) = bytes.split_first()?;
        let (address, size) = match kind {
            IPV4 => {
                let octets: [u8; size_of::<u32>()] = rest.get(..size_of::<u32>())?.try_into().ok()?;
                (IpAddr::V4(Ipv4Addr::from(octets)), size_of::<u32>())
            }
            IPV6 => {
                let octets: [u8; size_of::<u128>()] = rest.get(..size_of::<u128>())?.try_into().ok()?;
                (IpAddr::V6(Ipv6Addr::from(octets)), size_of::<u128>())
            }
            DOMAIN_NAME => {
                let (&length, rest) = rest.split_first()?;
                let length = usize::from(length);
                let name = String::from_utf8(rest.get(..length)?.to_vec()).ok()?;
                let port = u16::from_be_bytes(rest.get(length..length + PORT_SIZE)?.try_into().ok()?);
                return Some((Self::Domain(name, port), 1 + 1 + length + PORT_SIZE));
            }
            _ => return None,
        };
        let port = u16::from_be_bytes(rest.get(size..size + PORT_SIZE)?.try_into().ok()?);
        Some((Self::Ip(SocketAddr::new(address, port)), 1 + size + PORT_SIZE))
    }

    /// Returns the first socket address the destination resolves to.
    pub(crate) async fn resolve(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Ip(address) => Ok(*address),
            Self::Domain(name, port) => tokio::net::lookup_host((name.as_str(), *port))
                .await?
                .next()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("{name} has no address"))),
        }
    }
}

/// Returns the error of malformed SOCKS5 bytes.
fn invalid(detail: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("SOCKS5: {detail}"))
}

/// Returns the error of an address type no SOCKS5 version has.
fn unsupported_address_type(kind: u8) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Unsupported, format!("SOCKS5: address type {kind}"))
}

/// What a client asked for: a command and its destination, or a request the proxy can only refuse.
#[derive(Debug)]
pub(crate) enum Request {
    Valid { command: Command, address: Address },
    Refusable { status: Status, detail: String },
}

/// Answers the client's greeting, choosing no authentication, then reads its request.
///
/// A client that offers no method without authentication is told so, and its connection fails.
pub(crate) async fn accept<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> std::io::Result<Request> {
    expect_version(stream.read_u8().await?)?;
    let mut methods = vec![u8::MIN; usize::from(stream.read_u8().await?)];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&NO_AUTHENTICATION) {
        stream.write_all(&[VERSION, NO_ACCEPTABLE_METHODS]).await?;
        return Err(invalid("the client offered no method without authentication"));
    }
    stream.write_all(&[VERSION, NO_AUTHENTICATION]).await?;
    expect_version(stream.read_u8().await?)?;
    let code = stream.read_u8().await?;
    let _reserved = stream.read_u8().await?;
    let address = match Address::read(stream).await {
        Ok(address) => address,
        Err(fault) if fault.kind() == std::io::ErrorKind::Unsupported => {
            return Ok(Request::Refusable { status: Status::AddressTypeNotSupported, detail: fault.to_string() });
        }
        Err(fault) => return Err(fault),
    };
    Ok(match Command::from_code(code) {
        Some(command @ (Command::Connect | Command::UdpAssociate)) => Request::Valid { command, address },
        Some(Command::Bind) => Request::Refusable { status: Status::CommandNotSupported, detail: format!("BIND {address} is not supported") },
        None => Request::Refusable { status: Status::CommandNotSupported, detail: format!("SOCKS5 command {code} is not known") },
    })
}

/// Writes a reply with its status and the address the proxy bound for the request.
pub(crate) async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, status: Status, bound: SocketAddr) -> std::io::Result<()> {
    let mut message = vec![VERSION, status.code(), RESERVED];
    Address::Ip(bound).encode(&mut message);
    stream.write_all(&message).await?;
    stream.flush().await
}

/// Returns an error unless the byte is SOCKS5's version.
fn expect_version(version: u8) -> std::io::Result<()> {
    if version == VERSION {
        return Ok(());
    }
    Err(invalid(&format!("version {version}, not {VERSION}")))
}

/// Returns a UDP datagram for a relay: the header with the address, then the payload.
pub(crate) fn wrap_datagram(address: &Address, payload: &[u8]) -> Vec<u8> {
    let mut datagram = vec![RESERVED, RESERVED, WHOLE_DATAGRAM];
    address.encode(&mut datagram);
    datagram.extend_from_slice(payload);
    datagram
}

/// Returns the address and payload of a relayed UDP datagram, or none if it is malformed or a fragment.
pub(crate) fn unwrap_datagram(datagram: &[u8]) -> Option<(Address, &[u8])> {
    let header = datagram.get(..UDP_HEADER_START)?;
    if header != [RESERVED, RESERVED, WHOLE_DATAGRAM] {
        return None;
    }
    let (address, size) = Address::parse(&datagram[UDP_HEADER_START..])?;
    Some((address, &datagram[UDP_HEADER_START + size..]))
}

/// Greets the upstream proxy, authenticating if it asks, and sends the request; returns its reply's bound address.
async fn request_upstream(stream: &mut TcpStream, upstream: &Upstream, command: Command, address: &Address) -> std::io::Result<Address> {
    let mut greeting = vec![VERSION];
    if upstream.credentials.is_some() {
        greeting.extend([2, NO_AUTHENTICATION, USERNAME_PASSWORD]);
    } else {
        greeting.extend([1, NO_AUTHENTICATION]);
    }
    stream.write_all(&greeting).await?;
    expect_version(stream.read_u8().await?)?;
    match (stream.read_u8().await?, &upstream.credentials) {
        (NO_AUTHENTICATION, _) => {}
        (USERNAME_PASSWORD, Some(credentials)) => {
            let mut message = vec![USERNAME_PASSWORD_VERSION];
            for part in [&credentials.user, &credentials.password] {
                let part = part.as_bytes();
                message.push(u8::try_from(part.len()).map_err(|_| invalid("a user name or password longer than 255 bytes"))?);
                message.extend_from_slice(part);
            }
            stream.write_all(&message).await?;
            let _version = stream.read_u8().await?;
            if stream.read_u8().await? != AUTHENTICATED {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "the upstream SOCKS5 proxy refused the user name and password"));
            }
        }
        (method, _) => return Err(invalid(&format!("the upstream proxy chose method {method}, which this proxy cannot speak"))),
    }
    let mut request = vec![VERSION, command.code(), RESERVED];
    address.encode(&mut request);
    stream.write_all(&request).await?;
    expect_version(stream.read_u8().await?)?;
    let status = stream.read_u8().await?;
    let _reserved = stream.read_u8().await?;
    let bound = Address::read(stream).await?;
    if status != Status::Succeeded.code() {
        return Err(std::io::Error::other(format!("the upstream SOCKS5 proxy refused {address} with status {status}")));
    }
    Ok(bound)
}

/// Connects to the destination through the upstream SOCKS5 proxy.
pub(crate) async fn connect_upstream(upstream: &Upstream, address: &Address) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(&upstream.address).await?;
    request_upstream(&mut stream, upstream, Command::Connect, address).await?;
    Ok(stream)
}

/// Asks the upstream SOCKS5 proxy to relay UDP, returning the connection that keeps it and its relay's address.
pub(crate) async fn associate_upstream(upstream: &Upstream) -> std::io::Result<(TcpStream, SocketAddr)> {
    let mut stream = TcpStream::connect(&upstream.address).await?;
    let unspecified = Address::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), u16::MIN));
    let relay = match request_upstream(&mut stream, upstream, Command::UdpAssociate, &unspecified).await? {
        Address::Ip(relay) if relay.ip().is_unspecified() => SocketAddr::new(stream.peer_addr()?.ip(), relay.port()),
        Address::Ip(relay) => relay,
        domain @ Address::Domain(..) => domain.resolve().await?,
    };
    Ok((stream, relay))
}
