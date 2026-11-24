//! A proxy on tokio that forwards every byte unchanged and hands a copy of each to a decoder.
//!
//! When a tunnel's client starts TLS, it reads the client's hello, reaches the target offering the same
//! protocols, then finishes the client's handshake with a host certificate and the protocol chosen.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use simple_httptap_authority::Signer;
use simple_httptap_authority_rcgen::{RcgenAuthority, RcgenSigner};
use simple_httptap_decoder::{ConnectionDecoder, Decoded, Decoder, Direction};
use simple_httptap_decoder_http1::Http1;
use simple_httptap_decoder_http2::Http2;
use simple_httptap_proxy::{Listener, Proxy, Upstream};
use simple_httptap_sink::{Connection, Event, Sink};
use simple_httptap_sink_ndjson::NdJson;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio_rustls::rustls::server::Acceptor;
use tokio_rustls::rustls::{ClientConfig, ContentType, ServerConfig};
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tokio_util::io::ReaderStream;

/// The maker of proxies on tokio, which sign with rcgen and write JSON lines.
#[derive(Debug)]
pub struct TokioProxy;

impl Proxy for TokioProxy {
    type Authority = RcgenAuthority;
    type Sink = NdJson;
    type Listener = TokioListener;

    fn bind(&self, signer: RcgenSigner, sink: NdJson, upstream: Option<Upstream>) -> std::io::Result<TokioListener> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, u16::MIN))?;
        let address = listener.local_addr()?;
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let client_config = client_config(&provider).map_err(std::io::Error::other)?;
        let shared = Shared {
            signer,
            sink,
            upstream,
            provider,
            client_config,
            next_connection: AtomicU64::default(),
            failure: Mutex::default(),
            failed: Notify::new(),
        };
        Ok(TokioListener { listener, address, shared: Arc::new(shared) })
    }
}

/// A proxy bound to a loopback port, not yet serving.
pub struct TokioListener {
    listener: std::net::TcpListener,
    address: SocketAddr,
    shared: Arc<Shared>,
}

impl Listener for TokioListener {
    fn local_address(&self) -> SocketAddr {
        self.address
    }

    fn serve(self) -> std::io::Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        runtime.block_on(async move {
            self.listener.set_nonblocking(true)?;
            let listener = tokio::net::TcpListener::from_std(self.listener)?;
            self.shared.emit(Event::Listening { address: self.address });
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, client) = accepted?;
                        tokio::spawn(Arc::clone(&self.shared).handle(stream, client));
                    }
                    () = self.shared.failed.notified() => {
                        let failure = self.shared.failure.lock().ok().and_then(|mut failure| failure.take());
                        return Err(failure.unwrap_or_else(|| std::io::Error::other(SINK_FAILED)));
                    }
                }
            }
        })
    }
}

/// The state all connections of one proxy share: its signer, sink, upstream and TLS settings.
struct Shared {
    signer: RcgenSigner,
    sink: NdJson,
    upstream: Option<Upstream>,
    provider: Arc<CryptoProvider>,
    client_config: ClientConfig,
    next_connection: AtomicU64,
    /// The sink's first error, which stops the proxy.
    failure: Mutex<Option<std::io::Error>>,
    failed: Notify,
}

/// The status a proxy answers CONNECT with once it reached the target.
const TUNNEL_OPENED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
/// The response to a request that is no proxy request.
const BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
/// The line ending of an HTTP/1 head.
const LINE_END: &str = "\r\n";
/// The colon before a target's port, which an IPv6 host has only inside brackets.
///
/// https://www.rfc-editor.org/rfc/rfc3986#section-3.2
const HOST_PORT_SEPARATOR: &str = ":";
/// The error of a proxy whose sink failed without saying how.
const SINK_FAILED: &str = "the sink failed";
/// The application protocol name of HTTP/2 in TLS.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-3.2
const HTTP2_PROTOCOL: &[u8] = b"h2";
/// The scheme of a plain HTTP request's absolute target.
const HTTP_SCHEME: &str = "http";

/// Returns the configuration for connecting to targets, which trusts what the operating system trusts.
fn client_config(provider: &Arc<CryptoProvider>) -> Result<ClientConfig, tokio_rustls::rustls::Error> {
    use rustls_platform_verifier::BuilderVerifierExt;

    Ok(ClientConfig::builder_with_provider(Arc::clone(provider))
        .with_safe_default_protocol_versions()?
        .with_platform_verifier()?
        .with_no_client_auth())
}

/// A message head read off a connection, with the bytes read after it.
struct Head {
    bytes: Vec<u8>,
    after: Vec<u8>,
}

impl Head {
    /// Returns the request line's method and target, or the status line's version and status.
    fn first_two_words(&self) -> (String, String) {
        let line = self.bytes.split(|byte| LINE_END.as_bytes().contains(byte)).next().unwrap_or_default();
        let mut words = line.split(u8::is_ascii_whitespace).map(|word| String::from_utf8_lossy(word).into_owned());
        (words.next().unwrap_or_default(), words.next().unwrap_or_default())
    }
}

impl Shared {
    /// Writes an event, or stops the proxy if the sink cannot.
    fn emit(&self, event: Event) {
        if let Err(fault) = self.sink.write_event(&event) {
            if let Ok(mut failure) = self.failure.lock() {
                failure.get_or_insert(fault);
            }
            self.failed.notify_one();
        }
    }

    /// Writes each decoded result as its own event of the connection, in order.
    fn emit_decoded(&self, connection: u64, decoded: Vec<Decoded>) {
        for each in decoded {
            self.emit(Event::Decoded { connection, decoded: each });
        }
    }

    /// Serves one client connection and writes that it closed.
    async fn handle(self: Arc<Self>, stream: TcpStream, client: SocketAddr) {
        let connection = self.next_connection.fetch_add(1, Ordering::Relaxed);
        if let Err(detail) = self.serve_connection(connection, stream, client).await {
            self.emit(Event::Refused { connection, detail });
        }
        self.emit(Event::Closed { connection });
    }

    /// Reads the client's proxy request and serves it as a tunnel or a plain HTTP exchange.
    async fn serve_connection(&self, connection: u64, mut stream: TcpStream, client: SocketAddr) -> Result<(), String> {
        let head = read_head(&mut stream).await.map_err(|fault| format!("reading the proxy request: {fault}"))?;
        let (method, target) = head.first_two_words();
        if method == http::Method::CONNECT.as_str() {
            return self.serve_tunnel(connection, stream, client, head, target).await;
        }
        let Some(authority) = plain_authority(&target) else {
            let _ = stream.write_all(BAD_REQUEST).await;
            return Err(format!("not a proxy request: {method} {target}"));
        };
        let upstream = self.connect(&authority).await?;
        self.emit(Event::Opened(Connection { id: connection, client, target: authority, tls: false, protocol: None }));
        let mut first = head.bytes;
        first.extend(head.after);
        self.relay(connection, stream, upstream, Http1.start_connection(), first).await;
        Ok(())
    }

    /// Opens the CONNECT tunnel and serves it, ending TLS if the client starts it.
    async fn serve_tunnel(
        &self,
        connection: u64,
        mut stream: TcpStream,
        client: SocketAddr,
        head: Head,
        target: String,
    ) -> Result<(), String> {
        let upstream = self.connect(&target).await?;
        stream.write_all(TUNNEL_OPENED).await.map_err(|fault| format!("answering the CONNECT: {fault}"))?;
        let mut connect = Http1.start_connection();
        let mut connect_request = connect.decode(Direction::Client, &head.bytes);
        connect_request.extend(connect.finish());
        let mut first_byte = [u8::MIN];
        let starts_tls = head.after.is_empty()
            && stream.peek(&mut first_byte).await.is_ok_and(|read| read != usize::MIN)
            && first_byte[0] == u8::from(ContentType::Handshake);
        if !starts_tls {
            self.emit(Event::Opened(Connection { id: connection, client, target, tls: false, protocol: None }));
            self.emit_decoded(connection, connect_request);
            self.relay(connection, stream, upstream, Http1.start_connection(), head.after).await;
            return Ok(());
        }
        let start = LazyConfigAcceptor::new(Acceptor::default(), stream)
            .await
            .map_err(|fault| format!("reading the client's TLS hello for {target}: {fault}"))?;
        let hello = start.client_hello();
        let host = hello.server_name().map_or_else(|| host_of(&target), str::to_owned);
        let offered: Vec<Vec<u8>> = hello.alpn().map(|protocols| protocols.map(<[u8]>::to_vec).collect()).unwrap_or_default();
        let mut config = self.client_config.clone();
        config.alpn_protocols = offered;
        let name = ServerName::try_from(host.clone()).map_err(|fault| format!("the host {host:?}: {fault}"))?;
        let upstream = TlsConnector::from(Arc::new(config))
            .connect(name, upstream)
            .await
            .map_err(|fault| format!("TLS to {target} as {host}: {fault}"))?;
        let chosen = upstream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let server_config = self.server_config(&host, chosen.clone())?;
        let stream = start
            .into_stream(Arc::new(server_config))
            .await
            .map_err(|fault| format!("TLS with the client for {host}: {fault}"))?;
        let protocol = chosen.as_deref().map(|chosen| String::from_utf8_lossy(chosen).into_owned());
        self.emit(Event::Opened(Connection { id: connection, client, target, tls: true, protocol }));
        self.emit_decoded(connection, connect_request);
        if chosen.as_deref() == Some(HTTP2_PROTOCOL) {
            self.relay(connection, stream, upstream, Http2.start_connection(), Vec::new()).await;
        } else {
            self.relay(connection, stream, upstream, Http1.start_connection(), Vec::new()).await;
        }
        Ok(())
    }

    /// Returns the configuration for the client's side of TLS: a certificate for the host and the chosen protocol.
    fn server_config(&self, host: &str, chosen: Option<Vec<u8>>) -> Result<ServerConfig, String> {
        let issued = self.signer.issue_certificate(host).map_err(|fault| format!("a certificate for {host}: {fault}"))?;
        let chain = issued.chain.into_iter().map(CertificateDer::from).collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.private_key));
        let mut config = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .and_then(|builder| builder.with_no_client_auth().with_single_cert(chain, key))
            .map_err(|fault| format!("TLS for {host}: {fault}"))?;
        config.alpn_protocols = chosen.into_iter().collect();
        Ok(config)
    }

    /// Connects to the target's host and port, through the upstream proxy if there is one.
    async fn connect(&self, target: &str) -> Result<TcpStream, String> {
        let Some(upstream) = &self.upstream else {
            return TcpStream::connect(target).await.map_err(|fault| format!("connecting to {target}: {fault}"));
        };
        let mut stream = TcpStream::connect(&upstream.address)
            .await
            .map_err(|fault| format!("connecting to the upstream proxy {}: {fault}", upstream.address))?;
        let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(authorization) = &upstream.authorization {
            request.push_str(&format!("{}: {authorization}\r\n", http::header::PROXY_AUTHORIZATION));
        }
        request.push_str(LINE_END);
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|fault| format!("asking the upstream proxy for {target}: {fault}"))?;
        let head = read_head(&mut stream).await.map_err(|fault| format!("the upstream proxy's answer: {fault}"))?;
        let (_, status) = head.first_two_words();
        let opened = http::StatusCode::from_bytes(status.as_bytes()).is_ok_and(|status| status.is_success());
        if !opened || !head.after.is_empty() {
            return Err(format!("the upstream proxy refused {target}: {}", String::from_utf8_lossy(&head.bytes).trim_end()));
        }
        Ok(stream)
    }

    /// Forwards bytes both ways until both sides close, handing a copy of each to the decoder.
    ///
    /// The first bytes, already read from the client, go to the target before anything else.
    async fn relay<C, U, D>(&self, connection: u64, client: C, upstream: U, mut decoder: D, first: Vec<u8>)
    where
        C: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
        D: ConnectionDecoder,
    {
        let (client_reader, mut client_writer) = tokio::io::split(client);
        let (upstream_reader, mut upstream_writer) = tokio::io::split(upstream);
        let (copies, mut received) = mpsc::unbounded_channel();
        let first_written = first.is_empty() || upstream_writer.write_all(&first).await.is_ok();
        if !first.is_empty() {
            let _ = copies.send((Direction::Client, first));
        }
        let (outward_copies, inward_copies) = (copies.clone(), copies);
        let outward = async move {
            if first_written {
                forward(client_reader, &mut upstream_writer, Direction::Client, outward_copies).await;
            }
            let _ = upstream_writer.shutdown().await;
        };
        let inward = async move {
            forward(upstream_reader, &mut client_writer, Direction::Server, inward_copies).await;
            let _ = client_writer.shutdown().await;
        };
        let decoding = async {
            while let Some((direction, bytes)) = received.recv().await {
                self.emit_decoded(connection, decoder.decode(direction, &bytes));
            }
            self.emit_decoded(connection, decoder.finish());
        };
        tokio::join!(outward, inward, decoding);
    }
}

/// Copies bytes from the reader to the writer until either ends, sending each chunk for decoding as it arrives.
async fn forward<R, W>(reader: R, writer: &mut W, direction: Direction, copies: mpsc::UnboundedSender<(Direction, Vec<u8>)>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut chunks = ReaderStream::new(reader);
    while let Some(Ok(chunk)) = chunks.next().await {
        let _ = copies.send((direction, chunk.to_vec()));
        if writer.write_all(&chunk).await.is_err() {
            return;
        }
    }
}

/// Reads an HTTP/1 head off the stream, ending at its empty line, with whatever was read past it.
async fn read_head<T: AsyncRead + Unpin>(stream: &mut T) -> std::io::Result<Head> {
    let mut reader = BufReader::new(stream);
    let mut bytes = Vec::new();
    loop {
        let line_start = bytes.len();
        let read = reader.read_until(*LINE_END.as_bytes().last().unwrap_or(&u8::MIN), &mut bytes).await?;
        if read == usize::MIN {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the connection closed in a head"));
        }
        if line_start != usize::MIN && bytes[line_start..].iter().all(|byte| LINE_END.as_bytes().contains(byte)) {
            return Ok(Head { bytes, after: reader.buffer().to_vec() });
        }
    }
}

/// Returns the host of a plain HTTP request's absolute target with its port, the scheme's default if none.
fn plain_authority(target: &str) -> Option<String> {
    let url = url::Url::parse(target).ok().filter(|url| url.scheme() == HTTP_SCHEME)?;
    let host = url.host_str()?;
    Some([host, &url.port_or_known_default()?.to_string()].join(HOST_PORT_SEPARATOR))
}

/// Returns the host of a `host:port` target, an IPv6 address without its brackets.
fn host_of(target: &str) -> String {
    if let Ok(address) = target.parse::<SocketAddr>() {
        return address.ip().to_string();
    }
    target.rsplit_once(HOST_PORT_SEPARATOR).map_or(target, |(host, _)| host).to_owned()
}
