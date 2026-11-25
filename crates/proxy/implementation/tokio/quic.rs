//! An intercepted QUIC connection: ended toward the client with the proxy's certificate, and made again to the server.
//!
//! The proxy's own QUIC to the server logs its secrets to the key log. Streams and datagrams are relayed between the
//! two, and the watch decrypts the server side's datagrams with the logged secrets, as it does any QUIC.

use std::fmt;
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Connection, Endpoint, EndpointConfig, TokioRuntime, UdpPoller, VarInt};
use simple_httptap_authority::Signer;
use simple_httptap_decoder::Direction;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;

use crate::Shared;
use crate::socks::{self, Address};
use crate::udp::DATAGRAM_LIMIT;
use crate::watch::{Copy, HTTP3};

/// The application protocols the proxy offers a QUIC client: HTTP/3, its last draft, and the interop test protocol.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-3.1
const PROTOCOLS: &[&[u8]] = &[HTTP3, b"h3-29", b"hq-interop"];
/// The error code the proxy closes a connection with when its other side closed without one.
///
/// https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.close
const NO_ERROR: VarInt = VarInt::from_u32(0);
/// The reason the proxy gives a client when the server could not be reached.
const UNREACHABLE: &[u8] = b"httptap could not reach the server";

/// A datagram one way: to the client, from the destination it names.
type Datagram = (Address, Vec<u8>);

/// Intercepts one QUIC connection whose first datagram from the client is `first`, relaying until either side ends.
///
/// Returns why the connection could not be made, for the refused event.
pub(crate) async fn intercept(
    shared: Arc<Shared>,
    client: SocketAddr,
    target: Address,
    first: Vec<u8>,
    from_client: mpsc::UnboundedReceiver<Vec<u8>>,
    replies: mpsc::UnboundedSender<Datagram>,
    copies: mpsc::UnboundedSender<Copy>,
) -> Result<(), String> {
    let destination = target.resolve().await.map_err(|fault| format!("resolving {target}: {fault}"))?;
    let toward_client = ClientSocket::new(client, destination, target.clone(), first, from_client, replies);
    let server_config = server_config(&shared)?;
    let client_endpoint = Endpoint::new_with_abstract_socket(EndpointConfig::default(), Some(server_config), Arc::new(toward_client), Arc::new(TokioRuntime))
        .map_err(|fault| format!("a QUIC endpoint for the client: {fault}"))?;
    let incoming = client_endpoint.accept().await.ok_or("the client's QUIC endpoint closed")?;
    let mut connecting = incoming.accept().map_err(|fault| format!("accepting the client's QUIC: {fault}"))?;
    let handshake = connecting.handshake_data().await.map_err(|fault| format!("the client's QUIC handshake: {fault}"))?;
    let handshake = handshake.downcast::<HandshakeData>().map_err(|_| "the client's QUIC handshake data")?;
    let host = handshake.server_name.clone().unwrap_or_else(|| target.host());
    let protocols: Vec<Vec<u8>> = handshake.protocol.clone().into_iter().collect();

    let toward_server = ServerSocket::open(&shared, destination, target.clone(), copies).await.map_err(|fault| format!("a UDP socket toward {target}: {fault}"))?;
    let server_endpoint = Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, Arc::new(toward_server), Arc::new(TokioRuntime))
        .map_err(|fault| format!("a QUIC endpoint toward {target}: {fault}"))?;
    let mut client_config = shared.client_config.clone();
    client_config.alpn_protocols = protocols;
    let client_config = QuicClientConfig::try_from(client_config).map_err(|fault| format!("QUIC toward {target}: {fault}"))?;
    let server = match server_endpoint.connect_with(quinn::ClientConfig::new(Arc::new(client_config)), destination, &host) {
        Ok(connecting) => connecting.await,
        Err(fault) => {
            drop(connecting);
            return Err(format!("QUIC to {target} as {host}: {fault}"));
        }
    };
    let server = match server {
        Ok(server) => server,
        Err(fault) => {
            if let Ok(client) = connecting.await {
                client.close(NO_ERROR, UNREACHABLE);
            }
            return Err(format!("QUIC to {target} as {host}: {fault}"));
        }
    };
    let client = connecting.await.map_err(|fault| format!("QUIC with the client for {host}: {fault}"))?;
    relay(&client, &server).await;
    client_endpoint.wait_idle().await;
    server_endpoint.wait_idle().await;
    Ok(())
}

/// Returns the configuration for the client's side: certificates made for whatever name the client asks for.
fn server_config(shared: &Arc<Shared>) -> Result<quinn::ServerConfig, String> {
    let mut config = ServerConfig::builder_with_provider(Arc::clone(&shared.provider))
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .map_err(|fault| format!("QUIC's TLS: {fault}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Certificates { shared: Arc::clone(shared), issued: Mutex::default() }));
    config.alpn_protocols = PROTOCOLS.iter().map(|protocol| protocol.to_vec()).collect();
    config.max_early_data_size = u32::MAX;
    let config = QuicServerConfig::try_from(config).map_err(|fault| format!("QUIC's TLS: {fault}"))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(config)))
}

/// Relays every stream and datagram between the two connections until one closes, then closes the other alike.
async fn relay(client: &Connection, server: &Connection) {
    loop {
        tokio::select! {
            accepted = client.accept_bi() => {
                let Ok((send, receive)) = accepted else { break };
                let Ok((server_send, server_receive)) = server.open_bi().await else { break };
                tokio::spawn(copy_stream(receive, server_send));
                tokio::spawn(copy_stream(server_receive, send));
            }
            accepted = server.accept_bi() => {
                let Ok((send, receive)) = accepted else { break };
                let Ok((client_send, client_receive)) = client.open_bi().await else { break };
                tokio::spawn(copy_stream(receive, client_send));
                tokio::spawn(copy_stream(client_receive, send));
            }
            accepted = client.accept_uni() => {
                let Ok(receive) = accepted else { break };
                let Ok(send) = server.open_uni().await else { break };
                tokio::spawn(copy_stream(receive, send));
            }
            accepted = server.accept_uni() => {
                let Ok(receive) = accepted else { break };
                let Ok(send) = client.open_uni().await else { break };
                tokio::spawn(copy_stream(receive, send));
            }
            datagram = client.read_datagram() => {
                let Ok(datagram) = datagram else { break };
                let _ = server.send_datagram(datagram);
            }
            datagram = server.read_datagram() => {
                let Ok(datagram) = datagram else { break };
                let _ = client.send_datagram(datagram);
            }
        }
    }
    for (closed, other) in [(client, server), (server, client)] {
        if let Some(quinn::ConnectionError::ApplicationClosed(close)) = closed.close_reason() {
            other.close(close.error_code, &close.reason);
        }
    }
    client.close(NO_ERROR, &[]);
    server.close(NO_ERROR, &[]);
}

/// Copies one stream's bytes to the other side's stream, then ends it, or resets it if the source was reset.
async fn copy_stream(mut receive: quinn::RecvStream, mut send: quinn::SendStream) {
    let mut buffer = vec![u8::MIN; DATAGRAM_LIMIT];
    loop {
        match receive.read(&mut buffer).await {
            Ok(Some(read)) => {
                if send.write_all(&buffer[..read]).await.is_err() {
                    return;
                }
            }
            Ok(None) => {
                let _ = send.finish();
                return;
            }
            Err(quinn::ReadError::Reset(code)) => {
                let _ = send.reset(code);
                return;
            }
            Err(_) => {
                let _ = send.reset(NO_ERROR);
                return;
            }
        }
    }
}

/// The certificates the proxy shows QUIC clients, made per name as they ask and kept for the connection.
struct Certificates {
    shared: Arc<Shared>,
    issued: Mutex<Option<Arc<CertifiedKey>>>,
}

impl fmt::Debug for Certificates {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(std::any::type_name::<Self>())
    }
}

impl ResolvesServerCert for Certificates {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let mut issued = self.issued.lock().ok()?;
        if let Some(key) = issued.as_ref() {
            return Some(Arc::clone(key));
        }
        let name = hello.server_name()?;
        let certificate = self.shared.signer.issue_certificate(name).ok()?;
        let chain: Vec<CertificateDer<'static>> = certificate.chain.into_iter().map(CertificateDer::from).collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificate.private_key));
        let key = CertifiedKey::from_der(chain, key, &self.shared.provider).ok()?;
        let key = Arc::new(key);
        *issued = Some(Arc::clone(&key));
        Some(key)
    }
}

/// A socket toward the client: the SOCKS5 flow's datagrams in, its replies out, all from one address.
struct ClientSocket {
    client: SocketAddr,
    local: SocketAddr,
    target: Address,
    first: Mutex<Option<Vec<u8>>>,
    from_client: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    replies: mpsc::UnboundedSender<Datagram>,
}

impl ClientSocket {
    /// Makes the socket, which hands out the first datagram before any other.
    fn new(
        client: SocketAddr,
        local: SocketAddr,
        target: Address,
        first: Vec<u8>,
        from_client: mpsc::UnboundedReceiver<Vec<u8>>,
        replies: mpsc::UnboundedSender<Datagram>,
    ) -> Self {
        Self { client, local, target, first: Mutex::new(Some(first)), from_client: Mutex::new(from_client), replies }
    }
}

impl fmt::Debug for ClientSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple(std::any::type_name::<Self>()).field(&self.client).finish()
    }
}

impl AsyncUdpSocket for ClientSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> std::io::Result<()> {
        for datagram in segments(transmit) {
            let _ = self.replies.send((self.target.clone(), datagram.to_vec()));
        }
        Ok(())
    }

    fn poll_recv(&self, context: &mut Context<'_>, buffers: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<std::io::Result<usize>> {
        let first = self.first.lock().ok().and_then(|mut first| first.take());
        let datagram = match first {
            Some(datagram) => datagram,
            None => {
                let Ok(mut from_client) = self.from_client.lock() else {
                    return Poll::Pending;
                };
                match from_client.poll_recv(context) {
                    Poll::Ready(Some(datagram)) => datagram,
                    Poll::Ready(None) | Poll::Pending => return Poll::Pending,
                }
            }
        };
        Poll::Ready(Ok(deliver(&datagram, self.client, buffers, meta)))
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// A socket toward the server, straight or through the upstream proxy's relay, that copies every datagram to the watch.
struct ServerSocket {
    socket: UdpSocket,
    destination: SocketAddr,
    relay: Option<(SocketAddr, Address, tokio::net::TcpStream)>,
    copies: mpsc::UnboundedSender<Copy>,
}

impl ServerSocket {
    /// Opens a socket of its own toward the destination, through the upstream proxy if there is one.
    async fn open(shared: &Shared, destination: SocketAddr, target: Address, copies: mpsc::UnboundedSender<Copy>) -> std::io::Result<Self> {
        let Some(upstream) = &shared.upstream else {
            let socket = UdpSocket::bind(unspecified(destination.ip())).await?;
            return Ok(Self { socket, destination, relay: None, copies });
        };
        let (control, relay) = socks::associate_upstream(upstream).await?;
        let socket = UdpSocket::bind(unspecified(relay.ip())).await?;
        Ok(Self { socket, destination, relay: Some((relay, target, control)), copies })
    }
}

impl fmt::Debug for ServerSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple(std::any::type_name::<Self>()).field(&self.destination).finish()
    }
}

impl AsyncUdpSocket for ServerSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ServerPoller(self))
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> std::io::Result<()> {
        for datagram in segments(transmit) {
            match &self.relay {
                Some((relay, target, _)) => self.socket.try_send_to(&socks::wrap_datagram(target, datagram), *relay)?,
                None => self.socket.try_send_to(datagram, transmit.destination)?,
            };
            let _ = self.copies.send((Direction::Client, datagram.to_vec()));
        }
        Ok(())
    }

    fn poll_recv(&self, context: &mut Context<'_>, buffers: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<std::io::Result<usize>> {
        let mut storage = vec![u8::MIN; DATAGRAM_LIMIT];
        loop {
            let mut read = tokio::io::ReadBuf::new(&mut storage);
            let from = match self.socket.poll_recv_from(context, &mut read) {
                Poll::Ready(Ok(from)) => from,
                Poll::Ready(Err(fault)) => return Poll::Ready(Err(fault)),
                Poll::Pending => return Poll::Pending,
            };
            let payload = match &self.relay {
                Some(_) => match socks::unwrap_datagram(read.filled()) {
                    Some((_, payload)) => payload.to_vec(),
                    None => continue,
                },
                None if from == self.destination => read.filled().to_vec(),
                None => continue,
            };
            let _ = self.copies.send((Direction::Server, payload.clone()));
            return Poll::Ready(Ok(deliver(&payload, self.destination, buffers, meta)));
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

/// A writability check on the UDP socket toward the server, ready once that socket can send.
#[derive(Debug)]
struct ServerPoller(Arc<ServerSocket>);

impl UdpPoller for ServerPoller {
    fn poll_writable(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.0.socket.poll_send_ready(context)
    }
}

/// The poller of the socket toward the client, which hands datagrams to a channel and so can always send.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Returns the datagrams a transmit holds: one, or several of the segment size.
fn segments<'a>(transmit: &'a Transmit<'_>) -> Vec<&'a [u8]> {
    match transmit.segment_size {
        Some(size) if size != usize::MIN => transmit.contents.chunks(size).collect(),
        _ => vec![transmit.contents],
    }
}

/// Copies a datagram into the first buffer and describes it, returning how many datagrams were delivered: one.
fn deliver(datagram: &[u8], from: SocketAddr, buffers: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> usize {
    let (Some(buffer), Some(slot)) = (buffers.first_mut(), meta.first_mut()) else {
        return usize::MIN;
    };
    let length = datagram.len().min(buffer.len());
    buffer[..length].copy_from_slice(&datagram[..length]);
    *slot = RecvMeta { addr: from, len: length, stride: length, ecn: None, dst_ip: None };
    ONE_DATAGRAM
}

/// The count of datagrams `deliver` reports, as it fills only the first buffer.
///
/// https://docs.rs/quinn/latest/quinn/trait.AsyncUdpSocket.html#tymethod.poll_recv
const ONE_DATAGRAM: usize = 1;

/// Returns the unspecified address of the family of an address, for binding a socket that reaches it.
fn unspecified(family: IpAddr) -> SocketAddr {
    let ip = if family.is_ipv4() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(Ipv6Addr::UNSPECIFIED) };
    SocketAddr::new(ip, u16::MIN)
}
