//! A SOCKS5 proxy on tokio that forwards every byte unchanged and hands a copy of each to a watch.
//!
//! The watch decrypts TLS and QUIC with the secrets in the key log and decodes what they carry. When the proxy
//! intercepts, it ends the client's TLS itself and logs the secrets of its own TLS to servers in the same key log.

mod quic;
mod socks;
mod tcp;
mod udp;
mod watch;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use simple_httptap_authority::Signer;
use simple_httptap_authority_rcgen::{RcgenAuthority, RcgenSigner};
use simple_httptap_keylog::Keys;
use simple_httptap_keylog_file::{FileKeylog, FileKeys};
use simple_httptap_proxy::{Listener, Mode, Proxy, Upstream};
use simple_httptap_sink::{Event, Sink};
use simple_httptap_sink_ndjson::NdJson;
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{ClientConfig, KeyLog, ServerConfig};

use crate::socks::{Address, Command, Request};

/// The maker of proxies on tokio, which sign with rcgen, log keys to files and write JSON lines.
#[derive(Debug)]
pub struct TokioProxy;

impl Proxy for TokioProxy {
    type Authority = RcgenAuthority;
    type Sink = NdJson;
    type Keylog = FileKeylog;
    type Listener = TokioListener;

    fn bind(&self, signer: RcgenSigner, sink: NdJson, keys: FileKeys, mode: Mode, upstream: Option<Upstream>) -> std::io::Result<TokioListener> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, u16::MIN))?;
        let address = listener.local_addr()?;
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let keys = Arc::new(keys);
        let client_config = client_config(&provider, Arc::clone(&keys)).map_err(std::io::Error::other)?;
        let shared = Shared {
            signer,
            sink,
            keys,
            mode,
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
#[derive(Debug)]
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

/// The state all connections of one proxy share: its signer, sink, key log, mode, upstream and TLS settings.
pub(crate) struct Shared {
    signer: RcgenSigner,
    sink: NdJson,
    keys: Arc<FileKeys>,
    mode: Mode,
    upstream: Option<Upstream>,
    provider: Arc<CryptoProvider>,
    client_config: ClientConfig,
    next_connection: AtomicU64,
    /// The sink's first error, which stops the proxy.
    failure: Mutex<Option<std::io::Error>>,
    failed: Notify,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Shared").field("mode", &self.mode).field("upstream", &self.upstream).finish_non_exhaustive()
    }
}

/// The error of a proxy whose sink failed without saying how.
const SINK_FAILED: &str = "the sink failed";

/// Returns the configuration for reaching servers when intercepting, which trusts what the system trusts.
///
/// It logs every secret to the key log, which is how the watch decrypts what went to the server.
fn client_config(provider: &Arc<CryptoProvider>, keys: Arc<FileKeys>) -> Result<ClientConfig, tokio_rustls::rustls::Error> {
    use rustls_platform_verifier::BuilderVerifierExt;

    let mut config = ClientConfig::builder_with_provider(Arc::clone(provider))
        .with_safe_default_protocol_versions()?
        .with_platform_verifier()?
        .with_no_client_auth();
    config.key_log = Arc::new(KeyLogger(keys));
    Ok(config)
}

/// The rustls key log that records each secret in the proxy's key log.
struct KeyLogger(Arc<FileKeys>);

impl std::fmt::Debug for KeyLogger {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeyLogger")
    }
}

impl KeyLog for KeyLogger {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if let Err(fault) = self.0.record(label, client_random, secret) {
            eprintln!("httptap: writing a secret to the key log: {fault}");
        }
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

    /// Returns the next connection's number.
    fn next_id(&self) -> u64 {
        self.next_connection.fetch_add(1, Ordering::Relaxed)
    }

    /// Reads the client's SOCKS5 request and serves it: a TCP connection, or a UDP association.
    async fn handle(self: Arc<Self>, mut stream: TcpStream, client: SocketAddr) {
        match socks::accept(&mut stream).await {
            Ok(Request::Valid { command: Command::Connect, address }) => {
                let id = self.next_id();
                tcp::serve(self, id, stream, client, address).await;
            }
            Ok(Request::Valid { command: _, address: _ }) => udp::serve(self, stream, client).await,
            Ok(Request::Refusable { status, detail }) => {
                let _ = socks::reply(&mut stream, status, SocketAddr::from((Ipv4Addr::UNSPECIFIED, u16::MIN))).await;
                let id = self.next_id();
                self.emit(Event::Refused { connection: id, detail });
                self.emit(Event::Closed { connection: id });
            }
            Err(fault) => {
                let id = self.next_id();
                self.emit(Event::Refused { connection: id, detail: format!("reading the SOCKS5 request: {fault}") });
                self.emit(Event::Closed { connection: id });
            }
        }
    }

    /// Connects to the destination, through the upstream proxy if there is one.
    async fn connect(&self, target: &Address) -> std::io::Result<TcpStream> {
        if let Some(upstream) = &self.upstream {
            return socks::connect_upstream(upstream, target).await;
        }
        match target {
            Address::Ip(address) => TcpStream::connect(address).await,
            Address::Domain(name, port) => TcpStream::connect((name.as_str(), *port)).await,
        }
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
}
