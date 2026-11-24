//! An HTTP proxy on an ephemeral loopback port that forwards every byte unchanged and reports what it saw.

use std::net::SocketAddr;

use simple_httptap_authority::Authority;
use simple_httptap_sink::Sink;

/// A maker of proxies.
pub trait Proxy {
    /// The authority whose certificates the proxy presents.
    type Authority: Authority;
    /// The destination of every event.
    type Sink: Sink;
    /// A proxy bound to its port.
    type Listener: Listener;

    /// Binds a loopback port the system picks; connections go out through the upstream if given.
    fn bind(
        &self,
        signer: <Self::Authority as Authority>::Signer,
        sink: Self::Sink,
        upstream: Option<Upstream>,
    ) -> std::io::Result<Self::Listener>;
}

/// A proxy bound to its port and ready to serve.
pub trait Listener: Send + 'static {
    /// Returns the address clients connect to.
    fn local_address(&self) -> SocketAddr;

    /// Writes that it is listening, then serves clients until the sink fails.
    fn serve(self) -> std::io::Result<()>;
}

/// An HTTP proxy to go out through, as `host:port`, with any `Proxy-Authorization` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub address: String,
    pub authorization: Option<String>,
}
