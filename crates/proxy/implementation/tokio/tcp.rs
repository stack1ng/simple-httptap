//! A TCP connection a client asked for with CONNECT: relayed byte for byte, or with TLS ended at both sides.
//!
//! Either way, the watch reads the bytes that went to and came from the server.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::StreamExt;
use simple_httptap_decoder::Direction;
use simple_httptap_proxy::Mode;
use simple_httptap_sink::{Connection, Event, Transport};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::rustls::ContentType;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::server::Acceptor;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tokio_util::io::ReaderStream;

use crate::Shared;
use crate::socks::{self, Address, Status};
use crate::watch::{Copy, Watch};

/// How long an intercepting proxy waits for a client's first byte before taking it for a protocol where the server speaks first.
const FIRST_BYTE_WAIT: Duration = Duration::from_secs(1);

/// Connects to the CONNECT's destination, answers the client, and serves the connection until both sides close.
pub(crate) async fn serve(shared: Arc<Shared>, id: u64, mut client: TcpStream, peer: SocketAddr, target: Address) {
    let upstream = match shared.connect(&target).await {
        Ok(upstream) => upstream,
        Err(fault) => {
            let _ = socks::reply(&mut client, Status::of(&fault), unspecified()).await;
            shared.emit(Event::Refused { connection: id, detail: format!("connecting to {target}: {fault}") });
            shared.emit(Event::Closed { connection: id });
            return;
        }
    };
    let bound = upstream.local_addr().unwrap_or_else(|_| unspecified());
    if let Err(fault) = socks::reply(&mut client, Status::Succeeded, bound).await {
        shared.emit(Event::Refused { connection: id, detail: format!("answering the CONNECT to {target}: {fault}") });
        shared.emit(Event::Closed { connection: id });
        return;
    }
    let connection = Connection { id, client: peer, target: target.to_string(), transport: Transport::Tcp, tls: false, protocol: None };
    let (copies, received) = mpsc::unbounded_channel();
    let watching = tokio::spawn(Watch::new(Arc::clone(&shared), connection).run(received));
    if shared.mode == Mode::Intercept && starts_tls(&client).await {
        if let Err(detail) = intercept(&shared, client, upstream, &target, copies).await {
            shared.emit(Event::Refused { connection: id, detail });
        }
    } else {
        relay(client, upstream, copies).await;
    }
    let _ = watching.await;
}

/// Returns the address a reply names when there is none to tell.
fn unspecified() -> SocketAddr {
    SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, u16::MIN))
}

/// Returns whether the client's first byte, within a moment, starts a TLS handshake.
async fn starts_tls(client: &TcpStream) -> bool {
    let mut first = [u8::MIN];
    matches!(
        tokio::time::timeout(FIRST_BYTE_WAIT, client.peek(&mut first)).await,
        Ok(Ok(read)) if read != usize::MIN && first[0] == u8::from(ContentType::Handshake)
    )
}

/// Forwards bytes both ways until both sides close, sending a copy of each to the watch.
async fn relay<C, U>(client: C, upstream: U, copies: mpsc::UnboundedSender<Copy>)
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (client_reader, mut client_writer) = tokio::io::split(client);
    let (upstream_reader, mut upstream_writer) = tokio::io::split(upstream);
    let outward_copies = copies.clone();
    let outward = async move {
        forward(client_reader, &mut upstream_writer, Some((Direction::Client, outward_copies))).await;
        let _ = upstream_writer.shutdown().await;
    };
    let inward = async move {
        forward(upstream_reader, &mut client_writer, Some((Direction::Server, copies))).await;
        let _ = client_writer.shutdown().await;
    };
    tokio::join!(outward, inward);
}

/// Copies bytes from the reader to the writer until either ends, sending each chunk to the watch if asked.
async fn forward<R, W>(reader: R, writer: &mut W, copies: Option<(Direction, mpsc::UnboundedSender<Copy>)>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut chunks = ReaderStream::new(reader);
    while let Some(Ok(chunk)) = chunks.next().await {
        if let Some((direction, copies)) = &copies {
            let _ = copies.send((*direction, chunk.to_vec()));
        }
        if writer.write_all(&chunk).await.is_err() {
            return;
        }
    }
}

/// Ends the client's TLS with a certificate for its host, after reaching the server with TLS of the proxy's own.
///
/// The server's side runs through a tee, so the watch decrypts what really went to the server, with the secrets
/// the proxy's TLS logged.
async fn intercept(
    shared: &Shared,
    client: TcpStream,
    upstream: TcpStream,
    target: &Address,
    copies: mpsc::UnboundedSender<Copy>,
) -> Result<(), String> {
    let start = LazyConfigAcceptor::new(Acceptor::default(), client)
        .await
        .map_err(|fault| format!("reading the client's TLS hello for {target}: {fault}"))?;
    let hello = start.client_hello();
    let host = hello.server_name().map_or_else(|| target.host(), str::to_owned);
    let offered: Vec<Vec<u8>> = hello.alpn().map(|protocols| protocols.map(<[u8]>::to_vec).collect()).unwrap_or_default();
    let mut config = shared.client_config.clone();
    config.alpn_protocols = offered;
    let name = ServerName::try_from(host.clone()).map_err(|fault| format!("the host {host:?}: {fault}"))?;
    let tee = Tee { inner: upstream, copies };
    let upstream = TlsConnector::from(Arc::new(config))
        .connect(name, tee)
        .await
        .map_err(|fault| format!("TLS to {target} as {host}: {fault}"))?;
    let chosen = upstream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let server_config = shared.server_config(&host, chosen)?;
    let client = start.into_stream(Arc::new(server_config)).await.map_err(|fault| format!("TLS with the client for {host}: {fault}"))?;
    let (client_reader, mut client_writer) = tokio::io::split(client);
    let (upstream_reader, mut upstream_writer) = tokio::io::split(upstream);
    let outward = async move {
        forward(client_reader, &mut upstream_writer, None).await;
        let _ = upstream_writer.shutdown().await;
    };
    let inward = async move {
        forward(upstream_reader, &mut client_writer, None).await;
        let _ = client_writer.shutdown().await;
    };
    tokio::join!(outward, inward);
    Ok(())
}

/// A stream to the server that sends the watch a copy of every byte read from it or written to it.
struct Tee<S> {
    inner: S,
    copies: mpsc::UnboundedSender<Copy>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tee<S> {
    fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(context, buffer);
        if let Poll::Ready(Ok(())) = &polled {
            let read = &buffer.filled()[before..];
            if !read.is_empty() {
                let _ = self.copies.send((Direction::Server, read.to_vec()));
            }
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tee<S> {
    fn poll_write(mut self: Pin<&mut Self>, context: &mut Context<'_>, bytes: &[u8]) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(context, bytes);
        if let Poll::Ready(Ok(written)) = &polled {
            if *written != usize::MIN {
                let _ = self.copies.send((Direction::Client, bytes[..*written].to_vec()));
            }
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
