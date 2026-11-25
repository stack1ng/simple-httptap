//! A writer of everything the proxy sees, one event at a time, in the order it happened.

use std::net::SocketAddr;

use simple_httptap_decoder::Decoded;

/// A destination for events, shared by every connection.
pub trait Sink: Default + Send + Sync + 'static {
    /// Writes one event in full; an error means nothing more can be written, and the proxy stops.
    fn write_event(&self, event: &Event) -> std::io::Result<()>;
}

/// A thing the proxy saw: it listens, a connection opens, bytes decode, a request is refused, it closes, or capture failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Listening { address: SocketAddr },
    Opened(Connection),
    Decoded { connection: u64, decoded: Decoded },
    Refused { connection: u64, detail: String },
    Closed { connection: u64 },
    Failed { detail: String },
}

/// A connection through the proxy, numbered while it runs, with the target the client asked for.
///
/// `tls` says whether it was TLS or QUIC, decrypted with the key log; `protocol` is what it agreed, such as `h2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub id: u64,
    pub client: SocketAddr,
    pub target: String,
    pub transport: Transport,
    pub tls: bool,
    pub protocol: Option<String>,
}

/// The transport a connection used: a TCP stream, or UDP datagrams, which QUIC uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}
