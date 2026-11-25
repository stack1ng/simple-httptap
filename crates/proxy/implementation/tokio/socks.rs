//! SOCKS5 as RFC 1928 says: the server side clients speak to, and the client side for an upstream proxy.
//!
//! https://www.rfc-editor.org/rfc/rfc1928

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use simple_httptap_proxy::Upstream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// The protocol version every SOCKS5 message starts with.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-3
const SOCKS_VERSION: u8 = 5;
/// The method code a client offers, and a server chooses, to go without authentication.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-3
const METHOD_NO_AUTHENTICATION: u8 = 0x00;
/// The method code for authenticating with a user name and password, as RFC 1929 lays out.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-3
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
/// The answer that none of the client's methods is acceptable.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-3
const NO_ACCEPTABLE_METHODS: u8 = 0xFF;
/// The greeting's method count and methods when the upstream is given no credentials.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-3
const METHODS_WITHOUT_CREDENTIALS: [u8; 2] = [1, METHOD_NO_AUTHENTICATION];
/// The greeting's method count and methods when the upstream is given credentials.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-3
const METHODS_WITH_CREDENTIALS: [u8; 3] = [2, METHOD_NO_AUTHENTICATION, METHOD_USERNAME_PASSWORD];
/// The version of the username/password subnegotiation.
///
/// https://www.rfc-editor.org/rfc/rfc1929#section-2
const USERNAME_PASSWORD_VERSION: u8 = 0x01;
/// The username/password status that means success.
///
/// https://www.rfc-editor.org/rfc/rfc1929#section-2
const AUTHENTICATED: u8 = 0x00;
/// The reserved byte in requests, replies and UDP headers.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-4
const RESERVED: u8 = 0x00;
/// The address type saying four octets of IPv4 address follow.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-5
const ATYP_IPV4: u8 = 0x01;
/// The address type of a domain name, its length first.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-5
const ATYP_DOMAIN_NAME: u8 = 0x03;
/// The address type saying sixteen octets of IPv6 address follow.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-5
const ATYP_IPV6: u8 = 0x04;
/// The fragment number of a whole UDP datagram, the only kind this proxy relays.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-7
const WHOLE_DATAGRAM: u8 = 0x00;
/// The bytes before a UDP datagram's address: two reserved bytes and the fragment number.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-7
const UDP_HEADER_START: usize = 3;
/// The separator between a domain name and its port when an address is shown.
const PORT_SEPARATOR: char = ':';
/// The detail of the error that fails a connection whose request names a host in bytes that are not UTF-8.
const DOMAIN_NOT_UTF8: &str = "a domain name that is not UTF-8";
/// The detail of the error that ends a client's connection once it is told no method it offered is acceptable.
const AUTHENTICATION_REQUIRED: &str = "the client offered no method without authentication";
/// The detail of the error that stops an upstream request, as RFC 1929 gives each credential one length byte.
const CREDENTIALS_TOO_LONG: &str = "a user name or password longer than 255 bytes";
/// The bytes of a port.
const PORT_SIZE: usize = size_of::<u16>();

/// A command a client asks for, each with its code on the wire.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl Command {
    /// Returns the command's code on the wire.
    const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the command a code names, or none for an unknown one.
    fn from_code(code: u8) -> Option<Self> {
        [Self::Connect, Self::Bind, Self::UdpAssociate].into_iter().find(|command| command.code() == code)
    }
}

/// A reply's status, each with its code on the wire.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-6
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Status {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl Status {
    /// Returns the status's code on the wire.
    const fn code(self) -> u8 {
        self as u8
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
            Self::Domain(name, port) => write!(formatter, "{name}{PORT_SEPARATOR}{port}"),
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
                output.push(ATYP_IPV4);
                output.extend(address.ip().octets());
                address.port()
            }
            Self::Ip(SocketAddr::V6(address)) => {
                output.push(ATYP_IPV6);
                output.extend(address.ip().octets());
                address.port()
            }
            Self::Domain(name, port) => {
                output.push(ATYP_DOMAIN_NAME);
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
            ATYP_IPV4 => {
                let mut octets = [u8::MIN; size_of::<u32>()];
                reader.read_exact(&mut octets).await?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            ATYP_IPV6 => {
                let mut octets = [u8::MIN; size_of::<u128>()];
                reader.read_exact(&mut octets).await?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            ATYP_DOMAIN_NAME => {
                let mut name = vec![u8::MIN; usize::from(reader.read_u8().await?)];
                reader.read_exact(&mut name).await?;
                let port = reader.read_u16().await?;
                let name = String::from_utf8(name).map_err(|_| invalid(DOMAIN_NOT_UTF8))?;
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
            ATYP_IPV4 => {
                let octets: [u8; size_of::<u32>()] = rest.get(..size_of::<u32>())?.try_into().ok()?;
                (IpAddr::V4(Ipv4Addr::from(octets)), size_of::<u32>())
            }
            ATYP_IPV6 => {
                let octets: [u8; size_of::<u128>()] = rest.get(..size_of::<u128>())?.try_into().ok()?;
                (IpAddr::V6(Ipv6Addr::from(octets)), size_of::<u128>())
            }
            ATYP_DOMAIN_NAME => {
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
    if !methods.contains(&METHOD_NO_AUTHENTICATION) {
        stream.write_all(&[SOCKS_VERSION, NO_ACCEPTABLE_METHODS]).await?;
        return Err(invalid(AUTHENTICATION_REQUIRED));
    }
    stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTHENTICATION]).await?;
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
    let mut message = vec![SOCKS_VERSION, status.code(), RESERVED];
    Address::Ip(bound).encode(&mut message);
    stream.write_all(&message).await?;
    stream.flush().await
}

/// Returns an error unless the byte is SOCKS5's version.
fn expect_version(version: u8) -> std::io::Result<()> {
    if version == SOCKS_VERSION {
        return Ok(());
    }
    Err(invalid(&format!("version {version}, not {SOCKS_VERSION}")))
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
    let mut greeting = vec![SOCKS_VERSION];
    if upstream.credentials.is_some() {
        greeting.extend(METHODS_WITH_CREDENTIALS);
    } else {
        greeting.extend(METHODS_WITHOUT_CREDENTIALS);
    }
    stream.write_all(&greeting).await?;
    expect_version(stream.read_u8().await?)?;
    match (stream.read_u8().await?, &upstream.credentials) {
        (METHOD_NO_AUTHENTICATION, _) => {}
        (METHOD_USERNAME_PASSWORD, Some(credentials)) => {
            let mut message = vec![USERNAME_PASSWORD_VERSION];
            for part in [&credentials.user, &credentials.password] {
                let part = part.as_bytes();
                message.push(u8::try_from(part.len()).map_err(|_| invalid(CREDENTIALS_TOO_LONG))?);
                message.extend_from_slice(part);
            }
            stream.write_all(&message).await?;
            let _version = stream.read_u8().await?;
            if stream.read_u8().await? != AUTHENTICATED {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "the upstream SOCKS5 proxy refused the user name and password"));
            }
        }
        (method, _) => {
            return Err(invalid(&format!("the upstream proxy chose method {method}, which this proxy cannot speak")));
        }
    }
    let mut request = vec![SOCKS_VERSION, command.code(), RESERVED];
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
