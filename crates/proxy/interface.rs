//! A loopback SOCKS5 proxy that forwards TCP and UDP unchanged, reporting what it reads with a key log's secrets.
//!
//! https://www.rfc-editor.org/rfc/rfc1928

use std::net::SocketAddr;

use simple_httptap_authority::Authority;
use simple_httptap_keylog::Keylog;
use simple_httptap_sink::Sink;

/// A maker of proxies.
pub trait Proxy {
    /// The certificate issuer used when intercepting.
    type Authority: Authority;
    type Sink: Sink;
    /// The source of secrets, and their sink when intercepting.
    type Keylog: Keylog;
    type Listener: Listener;

    /// Binds a system-picked loopback port; connections leave via any upstream.
    fn bind(
        &self,
        signer: <Self::Authority as Authority>::Signer,
        sink: Self::Sink,
        keys: <Self::Keylog as Keylog>::Keys,
        mode: Mode,
        upstream: Option<Upstream>,
    ) -> std::io::Result<Self::Listener>;
}

/// A bound proxy, ready to serve.
pub trait Listener: Send + 'static {
    /// Returns the address SOCKS5 clients connect to.
    fn local_address(&self) -> SocketAddr;

    /// Writes that it listens, then serves until the sink fails.
    fn serve(self) -> std::io::Result<()>;
}

/// The source of the secrets that decrypt TLS and QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The client logs its secrets and every byte passes untouched.
    PassThrough,
    /// The proxy ends TLS with its certificates; servers see its TLS, whose secrets it logs.
    Intercept,
}

/// An upstream SOCKS5 proxy, as `host:port`, with any credentials it needs.
///
/// https://www.rfc-editor.org/rfc/rfc1929
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub address: String,
    pub credentials: Option<Credentials>,
}

/// A user name and password for SOCKS5 authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub user: String,
    pub password: String,
}
