//! A SOCKS5 proxy on an ephemeral loopback port that forwards every byte unchanged and reports what it saw.
//!
//! It carries TCP with CONNECT and UDP with UDP ASSOCIATE, and reads TLS and QUIC with the secrets in a key log.
//!
//! https://www.rfc-editor.org/rfc/rfc1928

use std::net::SocketAddr;

use simple_httptap_authority::Authority;
use simple_httptap_keylog::Keylog;
use simple_httptap_sink::Sink;

/// A maker of proxies.
pub trait Proxy {
    /// The authority whose certificates the proxy presents when it intercepts.
    type Authority: Authority;
    /// The destination of every event.
    type Sink: Sink;
    /// The key log the proxy reads secrets from, and writes them to when it intercepts.
    type Keylog: Keylog;
    /// A proxy bound to its port.
    type Listener: Listener;

    /// Binds a loopback port the system picks; connections go out through the upstream if given.
    fn bind(
        &self,
        signer: <Self::Authority as Authority>::Signer,
        sink: Self::Sink,
        keys: <Self::Keylog as Keylog>::Keys,
        mode: Mode,
        upstream: Option<Upstream>,
    ) -> std::io::Result<Self::Listener>;
}

/// A proxy bound to its port and ready to serve.
pub trait Listener: Send + 'static {
    /// Returns the address SOCKS5 clients connect to.
    fn local_address(&self) -> SocketAddr;

    /// Writes that it is listening, then serves clients until the sink fails.
    fn serve(self) -> std::io::Result<()>;
}

/// Where the secrets that decrypt TLS and QUIC come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The client logs its own secrets, and every byte passes through untouched, exactly as the client sent it.
    PassThrough,
    /// The proxy ends TLS with its own certificates and logs the secrets of its own connections to servers.
    ///
    /// The server then sees the proxy's TLS, not the client's.
    Intercept,
}

/// A SOCKS5 proxy to go out through, as `host:port`, with any user name and password it asks for.
///
/// https://www.rfc-editor.org/rfc/rfc1929
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub address: String,
    pub credentials: Option<Credentials>,
}

/// A user name and password for SOCKS5's username/password authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub user: String,
    pub password: String,
}
