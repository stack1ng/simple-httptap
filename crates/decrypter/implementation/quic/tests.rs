//! Checks of the decrypter against the sample packets of RFC 9001 and RFC 9369, and against real quinn sessions.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use simple_httptap_keylog::{Keylog, Keys};
use simple_httptap_keylog_file::{FileKeylog, FileKeys};

use super::*;

/// The connection ID the client's first Initial goes to in the samples of both RFCs.
const SAMPLE_ID: &str = "8394c8f03e515708";
/// The client random of the ClientHello in the samples of both RFCs.
const SAMPLE_RANDOM: &str = "ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c";
/// The secret of the ChaCha20-Poly1305 sample short header packet in both RFCs.
const SAMPLE_SECRET: &str = "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b";
/// The protocol the quinn endpoints agree on.
const PROTOCOL: &[u8] = b"httptap-test";
/// The name of the key log file the quinn client writes, in each session's temporary folder.
const KEYLOG_NAME: &str = "sslkeylogfile.txt";
/// What the client sends on its unidirectional stream.
const CLIENT_UNI: &[u8] = b"the client's unidirectional stream";
/// What the client sends in a DATAGRAM frame.
const CLIENT_DATAGRAM: &[u8] = b"the client's datagram";
/// What the server sends in a DATAGRAM frame.
const SERVER_DATAGRAM: &[u8] = b"the server's datagram";
/// What the client writes on a unidirectional stream it then resets.
const CUT_SHORT: &[u8] = b"cut short";
/// The application error code the client resets that stream with.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.4
const RESET_CODE: u32 = 7;
/// The stream the client resets, its second unidirectional one.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-2.1
const RESET_STREAM_ID: u64 = 6;
/// What the client sends as 0-RTT data on a resumed connection.
const EARLY_REQUEST: &[u8] = b"a request sent before the handshake ended";
/// What the server answers it with.
const EARLY_RESPONSE: &[u8] = b"the answer to the early request";

/// Returns the bytes hex digits spell, skipping whitespace.
fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .chars()
        .filter_map(|digit| digit.to_digit(16))
        .map(|digit| digit as u8)
        .collect();
    digits
        .chunks(2)
        .map(|pair| pair[0] << 4 | pair[1])
        .collect()
}

/// Returns a key log in a new temporary folder with nothing in it.
fn empty_keys() -> (tempfile::TempDir, FileKeys) {
    let folder = tempfile::tempdir().expect("a temporary folder");
    let keys = FileKeylog
        .open(&folder.path().join(KEYLOG_NAME))
        .expect("the key log opens");
    (folder, keys)
}

/// Returns bytes that count up and wrap, so a misplaced run shows.
fn pattern(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| (index % 251) as u8 ^ seed)
        .collect()
}

#[test]
fn derives_the_initial_secrets_and_keys_of_rfc_9001() {
    let suite = suite(AES_128_GCM_SHA256).expect("the Initial suite");
    let initial = hkdf::Salt::new(suite.hash, VERSION_1.salt).extract(&unhex(SAMPLE_ID));
    let client = expand(&initial, CLIENT_INITIAL, suite.hash.len()).expect("a secret");
    assert_eq!(
        client,
        unhex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
    );
    let server = expand(&initial, SERVER_INITIAL, suite.hash.len()).expect("a secret");
    assert_eq!(
        server,
        unhex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
    );
    let labels = VERSION_1.labels;
    assert_eq!(
        expand_secret(suite, &client, labels.key, 16),
        Some(unhex("1f369613dd76d5467730efcbe3b1a22d"))
    );
    assert_eq!(
        expand_secret(suite, &client, labels.iv, 12),
        Some(unhex("fa044b2f42a3fd3b46fb255c"))
    );
    assert_eq!(
        expand_secret(suite, &client, labels.hp, 16),
        Some(unhex("9f50449e04a0e810283a1e9933adedd2"))
    );
    assert_eq!(
        expand_secret(suite, &server, labels.key, 16),
        Some(unhex("cf3a5331653c364c88f0f379b6067e37"))
    );
    assert_eq!(
        expand_secret(suite, &server, labels.iv, 12),
        Some(unhex("0ac1493ca1905853b0bba03e"))
    );
    assert_eq!(
        expand_secret(suite, &server, labels.hp, 16),
        Some(unhex("c206b8d9b9f0f37644430b490eeaa314"))
    );
}

#[test]
fn derives_the_initial_secrets_and_keys_of_rfc_9369() {
    let suite = suite(AES_128_GCM_SHA256).expect("the Initial suite");
    let initial = hkdf::Salt::new(suite.hash, VERSION_2.salt).extract(&unhex(SAMPLE_ID));
    let client = expand(&initial, CLIENT_INITIAL, suite.hash.len()).expect("a secret");
    assert_eq!(
        client,
        unhex("14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b")
    );
    let server = expand(&initial, SERVER_INITIAL, suite.hash.len()).expect("a secret");
    assert_eq!(
        server,
        unhex("0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1")
    );
    let labels = VERSION_2.labels;
    assert_eq!(
        expand_secret(suite, &client, labels.key, 16),
        Some(unhex("8b1a0bc121284290a29e0971b5cd045d"))
    );
    assert_eq!(
        expand_secret(suite, &client, labels.iv, 12),
        Some(unhex("91f73e2351d8fa91660e909f"))
    );
    assert_eq!(
        expand_secret(suite, &client, labels.hp, 16),
        Some(unhex("45b95e15235d6f45a6b19cbcb0294ba9"))
    );
    assert_eq!(
        expand_secret(suite, &server, labels.key, 16),
        Some(unhex("82db637861d55e1d011f19ea71d5d2a7"))
    );
    assert_eq!(
        expand_secret(suite, &server, labels.iv, 12),
        Some(unhex("dd13c276499c0249d3310652"))
    );
    assert_eq!(
        expand_secret(suite, &server, labels.hp, 16),
        Some(unhex("edf6d05c83121201b436e16877593c3a"))
    );
}

/// Opens a sample Initial packet with the sample's Initial keys, returning its packet number and plaintext.
fn open_sample(version: Version, direction: Direction, packet: &[u8]) -> (u64, Vec<u8>) {
    let keys = InitialKeys::derive(version, &unhex(SAMPLE_ID)).expect("Initial keys");
    let keys = if direction == Direction::Client {
        &keys.client
    } else {
        &keys.server
    };
    let mut connection = Connection::default();
    let Parsed::Long(long) = connection.parse(direction, packet) else {
        panic!("a long header")
    };
    assert_eq!(long.end, packet.len());
    keys.open(packet, long.number_at, None)
        .expect("the sample opens")
}

/// Returns the CRYPTO frame the sample client Initials of both RFCs carry, before their padding.
fn sample_client_hello_frame() -> Vec<u8> {
    unhex(include_str!("vectors/client-hello-frame.hex"))
}

#[test]
fn opens_the_sample_initial_packets_of_rfc_9001() {
    let client = unhex(include_str!("vectors/rfc9001-client-initial.hex"));
    let (number, plain) = open_sample(VERSION_1, Direction::Client, &client);
    assert_eq!(number, 2);
    assert_eq!(plain.len(), 1162);
    let hello = sample_client_hello_frame();
    assert_eq!(plain[..hello.len()], hello[..]);
    assert!(
        plain[245..].iter().all(|byte| *byte == 0),
        "PADDING after the CRYPTO frame"
    );
    let server = unhex(include_str!("vectors/rfc9001-server-initial.hex"));
    let (number, plain) = open_sample(VERSION_1, Direction::Server, &server);
    assert_eq!(number, 1);
    assert_eq!(
        plain,
        unhex(
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200
             130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304"
        )
    );
}

#[test]
fn opens_the_sample_initial_packets_of_rfc_9369() {
    let client = unhex(include_str!("vectors/rfc9369-client-initial.hex"));
    let (number, plain) = open_sample(VERSION_2, Direction::Client, &client);
    assert_eq!((number, plain.len()), (2, 1162));
    let hello = sample_client_hello_frame();
    assert_eq!(plain[..hello.len()], hello[..]);
    let server = unhex(include_str!("vectors/rfc9369-server-initial.hex"));
    let (number, plain) = open_sample(VERSION_2, Direction::Server, &server);
    assert_eq!(number, 1);
    assert_eq!(plain[..6], unhex("020000000006")[..]);
}

/// Opens the ChaCha20-Poly1305 sample short header packet and checks its key update secret.
fn open_short_sample(version: Version, packet: &str, next_secret: &str) {
    let suite = suite(CHACHA20_POLY1305_SHA256).expect("ChaCha20");
    let mut application =
        Application::new(suite, version, unhex(SAMPLE_SECRET)).expect("1-RTT keys");
    assert_eq!(
        application.update().expect("the next keys").secret,
        unhex(next_secret)
    );
    let unprotected = unprotect(
        &unhex(packet),
        1,
        SHORT_PROTECTED,
        &application.protection,
        Some(654_360_563),
    )
    .expect("unprotected");
    assert_eq!(unprotected.number, 654_360_564);
    assert_eq!(
        unprotected.bytes[..unprotected.header],
        unhex("4200bff4")[..]
    );
    assert_eq!(application.open(&unprotected), Some(vec![0x01]));
}

#[test]
fn opens_the_chacha20_short_header_samples_and_updates_their_keys() {
    open_short_sample(
        VERSION_1,
        "4cfe4189655e5cd55c41f69080575d7999c25a5bfb",
        "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9",
    );
    open_short_sample(
        VERSION_2,
        "5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba",
        "c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88",
    );
}

#[test]
fn decodes_packet_numbers_as_rfc_9000_shows() {
    assert_eq!(decode_number(Some(0xa82f_30ea), 0x9b32, 2), 0xa82f_9b32);
    assert_eq!(decode_number(None, 0, 1), 0);
    assert_eq!(decode_number(Some(255), 1, 1), 257);
    assert_eq!(decode_number(Some(300), 0xff, 1), 255);
}

#[test]
fn learns_the_handshake_from_the_sample_initials_of_both_versions() {
    for (client, server) in [
        (
            include_str!("vectors/rfc9001-client-initial.hex"),
            include_str!("vectors/rfc9001-server-initial.hex"),
        ),
        (
            include_str!("vectors/rfc9369-client-initial.hex"),
            include_str!("vectors/rfc9369-server-initial.hex"),
        ),
    ] {
        let (_folder, keys) = empty_keys();
        let mut connection = Quic.start_connection();
        assert!(
            connection
                .decrypt(Direction::Client, &unhex(client), &keys)
                .is_empty()
        );
        assert!(
            connection
                .decrypt(Direction::Server, &unhex(server), &keys)
                .is_empty()
        );
        assert_eq!(connection.0.client_random, Some(unhex(SAMPLE_RANDOM)));
        assert_eq!(
            connection.0.suite.map(|suite| suite.aead),
            Some(&aead::AES_128_GCM)
        );
        assert!(!connection.is_waiting());
        assert_eq!(connection.finish(), [Decrypted::Agreed { protocol: None }]);
    }
}

#[test]
fn takes_initial_keys_from_a_retry_and_gives_the_retry_back() {
    let (_folder, keys) = empty_keys();
    let mut connection = Quic.start_connection();
    connection.decrypt(
        Direction::Client,
        &unhex(include_str!("vectors/rfc9001-client-initial.hex")),
        &keys,
    );
    let retry = unhex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
    assert_eq!(
        connection.decrypt(Direction::Server, &retry, &keys),
        [Decrypted::Opaque {
            direction: Direction::Server,
            bytes: retry
        }]
    );
    assert_eq!(
        connection.0.initial_ids.first(),
        Some(&unhex("f067a5502a4262b5"))
    );
}

#[test]
fn gives_back_what_is_no_quic_it_decrypts() {
    let (_folder, keys) = empty_keys();
    let negotiation = unhex("80000000000008f067a5502a4262b5000000016b3343cf");
    let unknown = unhex("c0ff00001d088394c8f03e5157080000449e00000002");
    let dns = unhex("12340100000100000000000003777777076578616d706c6503636f6d0000010001");
    let mut connection = Quic.start_connection();
    assert_eq!(
        connection.decrypt(Direction::Server, &negotiation, &keys),
        [Decrypted::Opaque {
            direction: Direction::Server,
            bytes: negotiation
        }]
    );
    let decrypted = connection.decrypt(Direction::Client, &unknown, &keys);
    let [
        Decrypted::Fault { detail, .. },
        Decrypted::Opaque { bytes, .. },
    ] = decrypted.as_slice()
    else {
        panic!("{decrypted:?}")
    };
    assert!(detail.contains("0xff00001d"), "{detail}");
    assert_eq!(*bytes, unknown);
    assert_eq!(
        connection.decrypt(Direction::Client, &dns, &keys),
        [Decrypted::Opaque {
            direction: Direction::Client,
            bytes: dns
        }]
    );
    assert!(!connection.is_waiting());
}

#[test]
fn reassembles_data_out_of_order_retransmitted_and_overlapping() {
    let mut stream = Reassembly::default();
    assert_eq!(stream.insert(6, b"ghij"), b"");
    assert_eq!(stream.insert(3, b"def"), b"");
    assert_eq!(stream.insert(0, b"abcd"), b"abcdefghij");
    assert_eq!(stream.insert(2, b"cdefgh"), b"");
    stream.end = Some(12);
    assert!(!stream.take_end());
    assert_eq!(stream.insert(8, b"ijkl"), b"kl");
    assert!(stream.take_end());
    assert!(!stream.take_end());
    assert!(!stream.has_gap());
}

/// A rustls key log that writes into a key log file, as a browser does.
#[derive(Debug)]
struct Logger(FileKeys);

impl rustls::KeyLog for Logger {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        self.0
            .record(label, client_random, secret)
            .expect("the secret is written");
    }
}

/// How a quinn session goes.
#[derive(Clone, Copy)]
struct Options {
    /// The cipher suite the client prefers, which the server then chooses.
    suite: rustls::SupportedCipherSuite,
    /// Whether the server answers the client's first Initial with a Retry.
    retry: bool,
}

/// One connection between quinn endpoints: its datagrams in the order the relay saw them, and the key log.
struct Session {
    folder: tempfile::TempDir,
    datagrams: Vec<(Direction, Vec<u8>)>,
}

impl Session {
    /// Returns the path of the key log the client wrote.
    fn keylog(&self) -> PathBuf {
        self.folder.path().join(KEYLOG_NAME)
    }
}

/// Returns what the client sends on its bidirectional stream, big enough for a few hundred packets.
fn request() -> Vec<u8> {
    pattern(300_000, 0x5a)
}

/// Returns what the server answers on that stream.
fn response() -> Vec<u8> {
    pattern(120_000, 0xa5)
}

/// Returns what the server sends on its unidirectional stream.
fn server_uni() -> Vec<u8> {
    pattern(200_000, 0x3c)
}

/// Runs the future on a new runtime, failing if it takes over a minute.
fn run<T>(future: impl Future<Output = T>) -> T {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), future)
            .await
            .expect("the session ends in time")
    })
}

/// A quinn server and a client that trusts it, which writes its secrets to the key log in the folder.
struct Endpoints {
    folder: tempfile::TempDir,
    server: quinn::Endpoint,
    client: quinn::Endpoint,
}

/// Makes a server and client that allow 0-RTT, the client preferring the suite.
fn endpoints(suite: rustls::SupportedCipherSuite) -> Endpoints {
    let folder = tempfile::tempdir().expect("a temporary folder");
    let keys = FileKeylog
        .open(&folder.path().join(KEYLOG_NAME))
        .expect("the key log opens");
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("a certificate");
    let certificate = certified.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let provider = Arc::new(rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            suite,
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ],
        ..rustls::crypto::ring::default_provider()
    });

    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key.into())
        .expect("a server configuration");
    server_crypto.alpn_protocols = vec![PROTOCOL.to_vec()];
    server_crypto.max_early_data_size = u32::MAX;
    let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .expect("a QUIC server configuration");
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(server_crypto)),
        loopback(),
    )
    .expect("a server");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).expect("the root");
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![PROTOCOL.to_vec()];
    client_crypto.enable_early_data = true;
    client_crypto.key_log = Arc::new(Logger(keys));
    let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
        .expect("a QUIC client configuration");
    let mut client = quinn::Endpoint::client(loopback()).expect("a client");
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));
    Endpoints {
        folder,
        server,
        client,
    }
}

/// Runs a session between a quinn client and server through a relay that records every datagram.
fn record(options: Options) -> Session {
    run(record_async(options))
}

/// Runs the session of [`record`]: streams both ways, key updates, a reset stream and a datagram each way.
async fn record_async(options: Options) -> Session {
    let Endpoints {
        folder,
        server,
        client,
    } = endpoints(options.suite);
    let datagrams = Recorded::default();
    let relay = relay(
        server.local_addr().expect("the server's address"),
        datagrams.clone(),
    )
    .await;
    let serving = tokio::spawn(serve(server, options.retry));
    let connection = client
        .connect(relay.0, "localhost")
        .expect("a connection starts")
        .await
        .expect("the handshake ends");
    let (mut send, mut receive) = connection.open_bi().await.expect("a stream");
    let request = request();
    let (first, second) = request.split_at(request.len() / 2);
    send.write_all(first).await.expect("written");
    connection.force_key_update();
    send.write_all(second).await.expect("written");
    send.finish().expect("finished");
    assert_eq!(
        receive.read_to_end(usize::MAX).await.expect("the response"),
        response()
    );
    connection.force_key_update();
    let mut uni = connection.open_uni().await.expect("a stream");
    uni.write_all(CLIENT_UNI).await.expect("written");
    uni.finish().expect("finished");
    let mut cut = connection.open_uni().await.expect("a stream");
    cut.write_all(CUT_SHORT).await.expect("written");
    cut.reset(RESET_CODE.into()).expect("reset");
    connection
        .send_datagram(CLIENT_DATAGRAM.to_vec().into())
        .expect("a datagram");
    let mut incoming = connection.accept_uni().await.expect("the server's stream");
    assert_eq!(
        incoming
            .read_to_end(usize::MAX)
            .await
            .expect("the server's stream"),
        server_uni()
    );
    assert_eq!(
        connection
            .read_datagram()
            .await
            .expect("the server's datagram"),
        SERVER_DATAGRAM
    );
    connection.close(0u32.into(), b"done");
    client.wait_idle().await;
    serving.await.expect("the server ends");
    relay.1.abort();
    let datagrams = datagrams.lock().expect("the datagrams").clone();
    Session { folder, datagrams }
}

/// Runs a connection, then a second through another relay that resumes it and sends its request as 0-RTT data.
///
/// Returns the second connection's session.
async fn record_resumed() -> Session {
    let Endpoints {
        folder,
        server,
        client,
    } = endpoints(rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256);
    let address = server.local_addr().expect("the server's address");
    let serving = tokio::spawn(serve_twice(server));
    let first_relay = relay(address, Recorded::default()).await;
    let first = client
        .connect(first_relay.0, "localhost")
        .expect("a connection starts")
        .await
        .expect("the handshake ends");
    exchange(&first).await;
    first.close(0u32.into(), b"done");
    let datagrams = Recorded::default();
    let second_relay = relay(address, datagrams.clone()).await;
    let connecting = client
        .connect(second_relay.0, "localhost")
        .expect("a connection starts");
    let Ok((second, accepted)) = connecting.into_0rtt() else {
        panic!("the client resumes with 0-RTT")
    };
    let exchanged = exchange(&second);
    let (accepted, ()) = tokio::join!(accepted, exchanged);
    assert!(accepted, "the server accepts the 0-RTT data");
    second.close(0u32.into(), b"done");
    client.wait_idle().await;
    serving.await.expect("the server ends");
    first_relay.1.abort();
    second_relay.1.abort();
    let datagrams = datagrams.lock().expect("the datagrams").clone();
    Session { folder, datagrams }
}

/// Sends the early request on a new stream and checks the early response.
async fn exchange(connection: &quinn::Connection) {
    let (mut send, mut receive) = connection.open_bi().await.expect("a stream");
    send.write_all(EARLY_REQUEST).await.expect("written");
    send.finish().expect("finished");
    assert_eq!(
        receive.read_to_end(usize::MAX).await.expect("the response"),
        EARLY_RESPONSE
    );
}

/// Serves two connections one after the other, answering the early request on each.
async fn serve_twice(server: quinn::Endpoint) {
    for _ in 0..2 {
        let connection = server
            .accept()
            .await
            .expect("a connection")
            .await
            .expect("the handshake ends");
        let (mut send, mut receive) = connection.accept_bi().await.expect("the client's stream");
        assert_eq!(
            receive.read_to_end(usize::MAX).await.expect("the request"),
            EARLY_REQUEST
        );
        send.write_all(EARLY_RESPONSE).await.expect("written");
        send.finish().expect("finished");
        connection.closed().await;
    }
    server.wait_idle().await;
}

/// Returns a loopback address with a port the system picks.
fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// Serves one connection: answers the client's streams and datagram, then waits for it to close.
async fn serve(server: quinn::Endpoint, retry: bool) {
    let connection = loop {
        let incoming = server.accept().await.expect("a connection");
        if retry && !incoming.remote_address_validated() {
            incoming.retry().expect("a Retry");
            continue;
        }
        break incoming.await.expect("the handshake ends");
    };
    let (mut send, mut receive) = connection.accept_bi().await.expect("the client's stream");
    assert_eq!(
        receive.read_to_end(usize::MAX).await.expect("the request"),
        request()
    );
    send.write_all(&response()).await.expect("written");
    send.finish().expect("finished");
    let mut uni = connection.accept_uni().await.expect("the client's stream");
    assert_eq!(
        uni.read_to_end(usize::MAX)
            .await
            .expect("the client's stream"),
        CLIENT_UNI
    );
    assert_eq!(
        connection
            .read_datagram()
            .await
            .expect("the client's datagram"),
        CLIENT_DATAGRAM
    );
    let mut out = connection.open_uni().await.expect("a stream");
    out.write_all(&server_uni()).await.expect("written");
    out.finish().expect("finished");
    connection
        .send_datagram(SERVER_DATAGRAM.to_vec().into())
        .expect("a datagram");
    connection.closed().await;
    server.wait_idle().await;
}

/// The datagrams a relay recorded, shared with its task.
type Recorded = Arc<Mutex<Vec<(Direction, Vec<u8>)>>>;

/// Starts a relay between the client and the server that records every datagram, returning its address and task.
async fn relay(
    server: SocketAddr,
    datagrams: Recorded,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let facing_client = tokio::net::UdpSocket::bind(loopback())
        .await
        .expect("a socket");
    let facing_server = tokio::net::UdpSocket::bind(loopback())
        .await
        .expect("a socket");
    let address = facing_client.local_addr().expect("the relay's address");
    let task = tokio::spawn(async move {
        let mut client = None;
        let (mut from_client, mut from_server) = (vec![0; 65_536], vec![0; 65_536]);
        loop {
            tokio::select! {
                received = facing_client.recv_from(&mut from_client) => {
                    let (length, sender) = received.expect("a datagram");
                    client = Some(sender);
                    datagrams.lock().expect("the datagrams").push((Direction::Client, from_client[..length].to_vec()));
                    facing_server.send_to(&from_client[..length], server).await.expect("sent on");
                }
                received = facing_server.recv_from(&mut from_server) => {
                    let (length, _) = received.expect("a datagram");
                    datagrams.lock().expect("the datagrams").push((Direction::Server, from_server[..length].to_vec()));
                    if let Some(client) = client {
                        facing_client.send_to(&from_server[..length], client).await.expect("sent on");
                    }
                }
            }
        }
    });
    (address, task)
}

/// What a connection decrypter gave back, put together.
#[derive(Debug, Default)]
struct Gathered {
    /// Each stream's bytes and whether it ended, by whether the client sent them and the stream.
    streams: BTreeMap<(bool, u64), (Vec<u8>, bool)>,
    datagrams: Vec<(Direction, Vec<u8>)>,
    agreed: Vec<Option<Vec<u8>>>,
    opaque: Vec<(Direction, Vec<u8>)>,
    faults: Vec<String>,
}

impl Gathered {
    /// Adds what a connection decrypter gave, checking nothing comes before the agreement or after a stream's end.
    fn add(&mut self, decrypted: Vec<Decrypted>) {
        for each in decrypted {
            match each {
                Decrypted::Agreed { protocol } => self.agreed.push(protocol),
                Decrypted::Plain {
                    direction,
                    stream,
                    bytes,
                    fin,
                } => {
                    assert_eq!(self.agreed.len(), 1, "plaintext only after one agreement");
                    let Some(stream) = stream else {
                        assert!(!fin);
                        self.datagrams.push((direction, bytes));
                        continue;
                    };
                    let (all, ended) = self
                        .streams
                        .entry((direction == Direction::Client, stream))
                        .or_default();
                    assert!(!*ended, "nothing after the end of stream {stream}");
                    assert!(
                        !bytes.is_empty() || fin,
                        "no empty plaintext without an end"
                    );
                    all.extend(bytes);
                    *ended = fin;
                }
                Decrypted::Opaque { direction, bytes } => self.opaque.push((direction, bytes)),
                Decrypted::Fault { detail, .. } => self.faults.push(detail),
            }
        }
    }

    /// Checks it is the whole session, every stream ended, with only the reset's fault and no opaque datagram but those allowed.
    fn check_whole(&self, opaque_allowed: usize) {
        assert_eq!(
            self.faults,
            [format!(
                "stream {RESET_STREAM_ID} was reset with error code 0x{RESET_CODE:x}"
            )]
        );
        assert_eq!(self.agreed, [Some(PROTOCOL.to_vec())]);
        let expected = BTreeMap::from([
            ((true, 0), (request(), true)),
            ((false, 0), (response(), true)),
            ((true, 2), (CLIENT_UNI.to_vec(), true)),
            ((false, 3), (server_uni(), true)),
        ]);
        for (key, (bytes, ended)) in &self.streams {
            if *key == (true, RESET_STREAM_ID) {
                assert!(
                    CUT_SHORT.starts_with(bytes) && !ended,
                    "the reset stream has {bytes:?}"
                );
                continue;
            }
            let (expected_bytes, expected_end) = &expected[key];
            assert!(
                bytes == expected_bytes,
                "stream {key:?} has {} bytes, not the {} sent",
                bytes.len(),
                expected_bytes.len()
            );
            assert_eq!(ended, expected_end, "stream {key:?}");
        }
        let reset = self.streams.contains_key(&(true, RESET_STREAM_ID));
        assert_eq!(self.streams.len(), expected.len() + usize::from(reset));
        let mut datagrams = self
            .datagrams
            .iter()
            .map(|(direction, bytes)| (*direction == Direction::Client, bytes.as_slice()))
            .collect::<Vec<_>>();
        datagrams.sort();
        assert_eq!(
            datagrams,
            [(false, SERVER_DATAGRAM), (true, CLIENT_DATAGRAM)]
        );
        assert_eq!(self.opaque.len(), opaque_allowed, "opaque datagrams");
    }
}

/// Decrypts the datagrams in the order given with the key log the session's client wrote.
fn decrypt_all(
    session: &Session,
    datagrams: &[(Direction, Vec<u8>)],
) -> (QuicConnection, Gathered) {
    let keys = FileKeylog
        .open(&session.keylog())
        .expect("the key log opens");
    let mut connection = Quic.start_connection();
    let mut gathered = Gathered::default();
    for (direction, bytes) in datagrams {
        gathered.add(connection.decrypt(*direction, bytes, &keys));
    }
    assert!(!connection.is_waiting());
    gathered.add(connection.finish());
    (connection, gathered)
}

/// Returns the datagrams with each run after the first reversed, as a network that reorders might deliver them.
///
/// A relay always sees the client's first Initial first, so it stays first.
fn reordered(datagrams: &[(Direction, Vec<u8>)], window: usize) -> Vec<(Direction, Vec<u8>)> {
    let (first, rest) = datagrams.split_first().expect("a datagram");
    std::iter::once(first.clone())
        .chain(
            rest.chunks(window)
                .flat_map(|run| run.iter().rev().cloned()),
        )
        .collect()
}

/// Returns the generations of 1-RTT keys each side reached.
fn generations(connection: &QuicConnection) -> (u64, u64) {
    let count = |side: &Side| {
        side.application
            .as_ref()
            .map_or(0, |application| application.current.count)
    };
    (count(&connection.0.client), count(&connection.0.server))
}

#[test]
fn decrypts_a_quinn_session_with_aes_128_gcm_and_key_updates() {
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    let session = record(Options {
        suite,
        retry: false,
    });
    assert!(
        session.datagrams.len() > 300,
        "{} datagrams",
        session.datagrams.len()
    );
    let (connection, gathered) = decrypt_all(&session, &session.datagrams);
    gathered.check_whole(0);
    let (client, server) = generations(&connection);
    assert!(
        client >= 1 && server >= 1,
        "key updates: {client} and {server}"
    );
    for window in [2, 3, 5] {
        let (_, gathered) = decrypt_all(&session, &reordered(&session.datagrams, window));
        gathered.check_whole(0);
    }
}

#[test]
fn decrypts_a_quinn_session_with_aes_256_gcm_after_a_retry() {
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384;
    let session = record(Options { suite, retry: true });
    let (connection, gathered) = decrypt_all(&session, &session.datagrams);
    gathered.check_whole(1);
    let [(Direction::Server, retry)] = gathered.opaque.as_slice() else {
        panic!("the Retry: {:?}", gathered.opaque)
    };
    assert_eq!(
        retry[0] & LONG_FORM | retry[0] & LONG_TYPE,
        LONG_FORM | LONG_TYPE,
        "a version 1 Retry"
    );
    assert_eq!(
        connection.0.suite.map(|suite| suite.aead),
        Some(&aead::AES_256_GCM)
    );
}

#[test]
fn decrypts_a_reordered_quinn_session_with_chacha20_poly1305() {
    let suite = rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256;
    let session = record(Options {
        suite,
        retry: false,
    });
    let (connection, gathered) = decrypt_all(&session, &reordered(&session.datagrams, 4));
    gathered.check_whole(0);
    assert_eq!(
        connection.0.suite.map(|suite| suite.aead),
        Some(&aead::CHACHA20_POLY1305)
    );
}

/// Returns a session with AES-128-GCM and no Retry, recorded once for the tests that only change the key log.
fn plain_session() -> &'static Session {
    static SESSION: std::sync::OnceLock<Session> = std::sync::OnceLock::new();
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    SESSION.get_or_init(|| {
        record(Options {
            suite,
            retry: false,
        })
    })
}

/// Feeds every datagram of the session to a new connection decrypter whose key log is empty for now.
fn decrypt_without_secrets(
    session: &Session,
) -> (tempfile::TempDir, FileKeys, QuicConnection, Gathered) {
    let (folder, keys) = empty_keys();
    let mut connection = Quic.start_connection();
    let mut gathered = Gathered::default();
    for (direction, bytes) in &session.datagrams {
        gathered.add(connection.decrypt(*direction, bytes, &keys));
    }
    assert!(connection.is_waiting());
    assert!(
        gathered.streams.is_empty() && gathered.opaque.is_empty() && gathered.faults.is_empty(),
        "{gathered:?}"
    );
    (folder, keys, connection, gathered)
}

/// Writes the session's key log into the file at the path, as a browser would write it late.
fn write_late(session: &Session, path: &Path) {
    std::fs::write(
        path,
        std::fs::read(session.keylog()).expect("the session's key log"),
    )
    .expect("written");
}

#[test]
fn decrypts_what_it_held_once_the_secrets_come() {
    let session = plain_session();
    let (folder, keys, mut connection, mut gathered) = decrypt_without_secrets(session);
    write_late(session, &folder.path().join(KEYLOG_NAME));
    gathered.add(connection.retry(&keys));
    assert!(!connection.is_waiting());
    gathered.add(connection.finish());
    gathered.check_whole(0);
}

/// Returns whether the datagram's first packet has a short header.
fn is_short(datagram: &[u8]) -> bool {
    datagram[0] & LONG_FORM == 0
}

#[test]
fn gives_back_what_it_held_opaque_when_it_gives_up() {
    let session = plain_session();
    let (_folder, keys, mut connection, mut gathered) = decrypt_without_secrets(session);
    gathered.add(connection.give_up());
    assert!(!connection.is_waiting());
    assert_eq!(gathered.agreed, [None]);
    let [client, server] = gathered.faults.as_slice() else {
        panic!("a fault for each side: {:?}", gathered.faults)
    };
    let random = hex(connection
        .0
        .client_random
        .as_deref()
        .expect("the client random"));
    assert!(
        client.contains(&random) && client.contains(CLIENT_HANDSHAKE_TRAFFIC_SECRET),
        "{client}"
    );
    assert!(
        server.contains(&random) && server.contains(SERVER_HANDSHAKE_TRAFFIC_SECRET),
        "{server}"
    );
    let held: Vec<_> = session
        .datagrams
        .iter()
        .filter(|(_, bytes)| {
            gathered
                .opaque
                .contains(&(Direction::Client, bytes.clone()))
                || gathered
                    .opaque
                    .contains(&(Direction::Server, bytes.clone()))
        })
        .cloned()
        .collect();
    assert_eq!(
        gathered.opaque, held,
        "opaque exactly as received, in order"
    );
    assert!(
        session
            .datagrams
            .iter()
            .filter(|(_, bytes)| is_short(bytes))
            .all(|datagram| gathered.opaque.contains(datagram))
    );
    let (direction, last) = session.datagrams.last().expect("a datagram");
    assert_eq!(
        connection.decrypt(*direction, last, &keys),
        [Decrypted::Opaque {
            direction: *direction,
            bytes: last.clone()
        }]
    );
    assert!(connection.finish().is_empty());
}

#[test]
fn gives_back_what_it_held_opaque_when_the_connection_finishes() {
    let session = plain_session();
    let (_folder, keys, mut connection, mut gathered) = decrypt_without_secrets(session);
    gathered.add(connection.finish());
    assert!(!connection.is_waiting());
    assert_eq!(gathered.agreed, [None]);
    assert!(
        gathered
            .faults
            .iter()
            .any(|fault| fault.contains(SERVER_HANDSHAKE_TRAFFIC_SECRET)),
        "{:?}",
        gathered.faults
    );
    assert!(
        session
            .datagrams
            .iter()
            .filter(|(_, bytes)| is_short(bytes))
            .all(|datagram| gathered.opaque.contains(datagram))
    );
    let (direction, last) = session.datagrams.last().expect("a datagram");
    assert!(connection.decrypt(*direction, last, &keys).is_empty());
    assert!(
        connection.retry(&keys).is_empty()
            && connection.give_up().is_empty()
            && connection.finish().is_empty()
    );
}

#[test]
fn faults_a_packet_its_keys_do_not_open_and_reads_on() {
    let session = plain_session();
    let middle = session.datagrams.len() / 2;
    let index = middle
        + session.datagrams[middle..]
            .iter()
            .position(|(_, bytes)| is_short(bytes))
            .expect("a short header");
    let (direction, original) = &session.datagrams[index];
    let mut junk = original.clone();
    *junk.last_mut().expect("a byte") ^= 1;
    let mut datagrams = session.datagrams.clone();
    datagrams.insert(index + 1, (*direction, junk.clone()));
    let (_, mut gathered) = decrypt_all(session, &datagrams);
    let position = gathered
        .faults
        .iter()
        .position(|fault| fault.contains("do not open"))
        .expect("a fault for the junk");
    gathered.faults.remove(position);
    assert_eq!(gathered.opaque, [(*direction, junk)]);
    gathered.opaque.clear();
    gathered.check_whole(0);
}

#[test]
fn decrypts_the_0rtt_data_of_a_resumed_quinn_session() {
    let session = run(record_resumed());
    for datagrams in [session.datagrams.clone(), reordered(&session.datagrams, 3)] {
        let (connection, gathered) = decrypt_all(&session, &datagrams);
        assert!(
            connection.0.client.early.is_some(),
            "the client sent 0-RTT packets"
        );
        assert_eq!(
            (gathered.faults.as_slice(), gathered.opaque.as_slice()),
            (&[][..], &[][..])
        );
        assert_eq!(gathered.agreed, [Some(PROTOCOL.to_vec())]);
        let expected = BTreeMap::from([
            ((true, 0), (EARLY_REQUEST.to_vec(), true)),
            ((false, 0), (EARLY_RESPONSE.to_vec(), true)),
        ]);
        assert_eq!(gathered.streams, expected);
    }
}
