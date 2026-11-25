//! A decrypter of TLS 1.2 and 1.3 records on a TCP stream, with the secrets an NSS key log holds.
//!
//! A side's records are read in order and held, from the first that needs a missing secret, until the
//! key log has it or the decrypter gives up. Only application data comes out.

use std::fmt;
use std::mem;

use aes::cipher::{BlockDecrypt, KeyInit, KeySizeUser};
use aes::{Aes128, Aes256};
use ring::{aead, hkdf, hmac};
use simple_httptap_decoder::Direction;
use simple_httptap_decrypter::{ConnectionDecrypter, Decrypted, Decrypter};
use simple_httptap_keylog::{
    CLIENT_EARLY_TRAFFIC_SECRET, CLIENT_HANDSHAKE_TRAFFIC_SECRET, CLIENT_RANDOM,
    CLIENT_TRAFFIC_SECRET_0, Keys, SERVER_HANDSHAKE_TRAFFIC_SECRET, SERVER_TRAFFIC_SECRET_0,
};

/// The decrypter of TLS 1.2 and 1.3 records on a TCP stream.
#[derive(Debug)]
pub struct Tls;

impl Decrypter for Tls {
    type Connection = TlsConnection;

    fn start_connection(&self) -> TlsConnection {
        TlsConnection(Reader {
            client: Side::new(Direction::Client),
            server: Side::new(Direction::Server),
            shared: Shared::default(),
            finished: false,
        })
    }
}

/// A decrypter of one connection's two record streams, whose debug output leaves out its secrets.
#[derive(Debug)]
pub struct TlsConnection(Reader);

impl ConnectionDecrypter for TlsConnection {
    fn decrypt(&mut self, direction: Direction, bytes: &[u8], keys: &dyn Keys) -> Vec<Decrypted> {
        self.0.decrypt(direction, bytes, keys)
    }

    fn retry(&mut self, keys: &dyn Keys) -> Vec<Decrypted> {
        self.0.retry(keys)
    }

    fn is_waiting(&self) -> bool {
        self.0.is_waiting()
    }

    fn give_up(&mut self) -> Vec<Decrypted> {
        self.0.give_up()
    }

    fn finish(&mut self) -> Vec<Decrypted> {
        self.0.finish()
    }
}

/// The reading of one connection: each side's records, and what both share.
#[derive(Debug)]
struct Reader {
    client: Side,
    server: Side,
    shared: Shared,
    finished: bool,
}

impl Reader {
    /// Reads what one side sent next, after which nothing comes out once finished.
    fn decrypt(&mut self, direction: Direction, bytes: &[u8], keys: &dyn Keys) -> Vec<Decrypted> {
        if self.finished || bytes.is_empty() {
            return Vec::new();
        }
        self.side(direction).buffer.extend_from_slice(bytes);
        self.pump(direction, keys);
        mem::take(&mut self.shared.output)
    }

    /// Reads again what both sides hold, now that the key log may have more secrets.
    fn retry(&mut self, keys: &dyn Keys) -> Vec<Decrypted> {
        if self.finished {
            return Vec::new();
        }
        self.pump(Direction::Client, keys);
        mem::take(&mut self.shared.output)
    }

    /// Returns whether either side holds records for want of a secret, not of the other side's hello.
    fn is_waiting(&self) -> bool {
        [&self.client, &self.server]
            .iter()
            .any(|side| side.want.as_ref().is_some_and(|want| want.secret))
    }

    /// Fails each side waiting for a secret, and every later side that needs one it lacks.
    fn give_up(&mut self) -> Vec<Decrypted> {
        if self.finished {
            return Vec::new();
        }
        let Self {
            client,
            server,
            shared,
            ..
        } = self;
        shared.gave_up = true;
        for side in [client, server] {
            if let Some(want) = side.want.take_if(|want| want.secret) {
                side.fail(shared, want.detail);
            }
        }
        self.settle();
        mem::take(&mut self.shared.output)
    }

    /// Gives back no protocol if none was agreed, then what each side holds, with why it held it.
    fn finish(&mut self) -> Vec<Decrypted> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        let Self {
            client,
            server,
            shared,
            ..
        } = self;
        shared.agree(None);
        for side in [client, server] {
            match side.want.take() {
                Some(want) => side.fail(shared, want.detail),
                None => {
                    side.opaque = true;
                    side.flush(shared);
                }
            }
        }
        mem::take(&mut self.shared.output)
    }

    /// Returns the reading of the side that sent in the direction.
    fn side(&mut self, direction: Direction) -> &mut Side {
        match direction {
            Direction::Client => &mut self.client,
            Direction::Server => &mut self.server,
        }
    }

    /// Reads records from both sides, the given one first, until neither can read more.
    ///
    /// Either side's progress can free the other, since each needs the other's hello.
    fn pump(&mut self, first: Direction, keys: &dyn Keys) {
        loop {
            let mut progressed = false;
            for direction in [first, other(first)] {
                while self.step(direction, keys) {
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
        self.settle();
    }

    /// Drops the bytes both sides read, and settles on no protocol once the server can no longer tell one.
    fn settle(&mut self) {
        for side in [&mut self.client, &mut self.server] {
            side.buffer.drain(..side.read);
            side.read = usize::MIN;
        }
        if self.server.opaque {
            self.shared.agree(None);
        }
    }

    /// Reads one record of the side, returning whether it read or gave back anything.
    fn step(&mut self, direction: Direction, keys: &dyn Keys) -> bool {
        let Self {
            client,
            server,
            shared,
            ..
        } = self;
        let (side, peer) = match direction {
            Direction::Client => (client, server),
            Direction::Server => (server, client),
        };
        side.step(shared, keys, peer.opaque)
    }
}

/// Bytes derived from a secret, which debug output leaves out.
struct Secret<T>(T);

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

/// What debug output shows in place of a secret.
const REDACTED: &str = "<secret>";
/// How faults name the client.
const CLIENT_NAME: &str = "client";
/// How faults name the server.
const SERVER_NAME: &str = "server";
/// The fault of a decrypted TLS 1.3 record that is all padding.
const NO_CONTENT_TYPE: &str = "a decrypted record had no content type";
/// The name of the ClientHello message in faults.
const CLIENT_HELLO_NAME: &str = "ClientHello";
/// The name of the ServerHello message in faults.
const SERVER_HELLO_NAME: &str = "ServerHello";
/// The name of the EncryptedExtensions message in faults.
const ENCRYPTED_EXTENSIONS_NAME: &str = "EncryptedExtensions";
/// The name of the ALPN extension in faults.
const ALPN_NAME: &str = "ALPN extension";
/// The fault of a record opened in a stage that has no keys, which reading never does.
const WRONG_STAGE: &str = "a record was opened in a stage without keys";

/// The bytes of a record's header: its content type, version and length.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-5.1
const HEADER_SIZE: usize = 5;
/// Where a record header's major version byte stands.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1
const MAJOR_OFFSET: usize = 1;
/// Where a record header's length starts, after its content type and version.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1
const LENGTH_OFFSET: usize = 3;
/// The longest record fragment any version allows: 2^14 bytes and 2048 of expansion.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3
const MAX_FRAGMENT: usize = 18_432;
/// The major version byte of every TLS record.
///
/// https://www.rfc-editor.org/rfc/rfc5246#appendix-E.1
const MAJOR_VERSION: u8 = 3;
/// The content type of a ChangeCipherSpec record.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1
const CHANGE_CIPHER_SPEC: u8 = 20;
/// The content type of an alert record.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1
const ALERT: u8 = 21;
/// The content type of a handshake record.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1
const HANDSHAKE: u8 = 22;
/// The content type of an application data record, and the outer type of every encrypted TLS 1.3 record.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-5.2
const APPLICATION_DATA: u8 = 23;
/// The version number of TLS 1.2.
///
/// https://www.rfc-editor.org/rfc/rfc5246#appendix-A.1
const TLS12: u16 = 0x0303;
/// The version number of TLS 1.3, which only the supported_versions extension carries.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.1
const TLS13: u16 = 0x0304;
/// The bytes of a handshake message's header: its type and a three-byte length.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4
const HANDSHAKE_HEADER_SIZE: usize = 4;
/// The handshake type of a ClientHello.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4
const CLIENT_HELLO: u8 = 1;
/// The handshake type of a ServerHello or HelloRetryRequest.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4
const SERVER_HELLO: u8 = 2;
/// The handshake type of the message that ends a client's 0-RTT data.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.5
const END_OF_EARLY_DATA: u8 = 5;
/// The handshake type of a TLS 1.3 server's EncryptedExtensions.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.3.1
const ENCRYPTED_EXTENSIONS: u8 = 8;
/// The handshake type of a Finished message.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.4.4
const FINISHED: u8 = 20;
/// The handshake type of a TLS 1.3 KeyUpdate.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.6.3
const KEY_UPDATE: u8 = 24;
/// The bytes of a hello's random.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
const RANDOM_SIZE: usize = 32;
/// The random of a ServerHello that is a HelloRetryRequest, SHA-256 of "HelloRetryRequest".
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3
const HELLO_RETRY_RANDOM: [u8; RANDOM_SIZE] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];
/// The extension that carries the application protocols offered and the one chosen.
///
/// https://www.rfc-editor.org/rfc/rfc7301#section-3.1
const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 16;
/// The extension by which a TLS 1.2 server agrees to MAC its CBC records after encrypting them.
///
/// https://www.rfc-editor.org/rfc/rfc7366#section-2
const ENCRYPT_THEN_MAC: u16 = 22;
/// The extension by which a TLS 1.3 client offers 0-RTT data.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.10
const EARLY_DATA: u16 = 42;
/// The extension by which a TLS 1.3 server names the version it chose.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.1
const SUPPORTED_VERSIONS: u16 = 43;
/// The bytes of an alert: its level and description.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-7.2
const ALERT_SIZE: usize = 2;
/// The level of an alert that ends the connection.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-7.2
const FATAL: u8 = 2;
/// The prefix of every TLS 1.3 HKDF label.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-7.1
const LABEL_PREFIX: &[u8] = b"tls13 ";
/// The label that derives a TLS 1.3 record key from a traffic secret.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-7.3
const KEY_LABEL: &[u8] = b"key";
/// The label that derives a TLS 1.3 record IV from a traffic secret.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-7.3
const IV_LABEL: &[u8] = b"iv";
/// The label that derives the next TLS 1.3 application traffic secret after a KeyUpdate.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-7.2
const UPDATE_LABEL: &[u8] = b"traffic upd";
/// The label that derives a TLS 1.2 key block from the master secret.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-6.3
const KEY_EXPANSION: &[u8] = b"key expansion";
/// The sides whose keys a TLS 1.2 key block holds, the client's before the server's.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-6.3
const SIDES: usize = 2;
/// The bytes of the implicit salt that starts a TLS 1.2 AES-GCM nonce.
///
/// https://www.rfc-editor.org/rfc/rfc5288#section-3
const GCM_SALT_SIZE: usize = 4;
/// The bytes of the explicit nonce that starts each TLS 1.2 AES-GCM record.
///
/// https://www.rfc-editor.org/rfc/rfc5288#section-3
const GCM_EXPLICIT_SIZE: usize = 8;
/// The bytes of an AES block, and of a CBC record's IV.
const BLOCK_SIZE: usize = size_of::<aes::Block>();
/// The TLS 1.3 suite of AES-128-GCM, hashing with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// The TLS 1.3 suite of AES-256-GCM, hashing with SHA-384.
///
/// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
/// The TLS 1.3 suite of ChaCha20-Poly1305, hashing with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
/// Every TLS 1.3 suite this decrypter reads, tried in turn on 0-RTT data whose suite is unknown.
const SUITES_13: &[u16] = &[
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
];
/// The TLS 1.2 suite of RSA key transport and AES-128-GCM, hashing with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc5288#section-3
const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009C;
/// The TLS 1.2 suite of RSA key transport and AES-256-GCM, hashing with SHA-384.
///
/// https://www.rfc-editor.org/rfc/rfc5288#section-3
const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009D;
/// The TLS 1.2 suite of finite-field Diffie-Hellman signed with RSA and AES-128-GCM, hashing with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc5288#section-3
const TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009E;
/// The TLS 1.2 suite of finite-field Diffie-Hellman signed with RSA and AES-256-GCM, hashing with SHA-384.
///
/// https://www.rfc-editor.org/rfc/rfc5288#section-3
const TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009F;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with ECDSA and AES-128-GCM, hashing with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc5289#section-3.2
const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02B;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with ECDSA and AES-256-GCM, hashing with SHA-384.
///
/// https://www.rfc-editor.org/rfc/rfc5289#section-3.2
const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xC02C;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with RSA and AES-128-GCM, hashing with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc5289#section-3.2
const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02F;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with RSA and AES-256-GCM, hashing with SHA-384.
///
/// https://www.rfc-editor.org/rfc/rfc5289#section-3.2
const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xC030;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with RSA and ChaCha20-Poly1305, hashing with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc7905#section-2
const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xCCA8;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with ECDSA and ChaCha20-Poly1305, hashing with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc7905#section-2
const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xCCA9;
/// The TLS 1.2 suite of finite-field Diffie-Hellman signed with RSA and ChaCha20-Poly1305, hashing with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc7905#section-2
const TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xCCAA;
/// The TLS 1.2 suite of RSA key transport and AES-128-CBC, MACs with SHA-1.
///
/// https://www.rfc-editor.org/rfc/rfc5246#appendix-A.5
const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002F;
/// The TLS 1.2 suite of finite-field Diffie-Hellman signed with RSA and AES-128-CBC, MACs with SHA-1.
///
/// https://www.rfc-editor.org/rfc/rfc5246#appendix-A.5
const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0x0033;
/// The TLS 1.2 suite of RSA key transport and AES-256-CBC, MACs with SHA-1.
///
/// https://www.rfc-editor.org/rfc/rfc5246#appendix-A.5
const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
/// The TLS 1.2 suite of finite-field Diffie-Hellman signed with RSA and AES-256-CBC, MACs with SHA-1.
///
/// https://www.rfc-editor.org/rfc/rfc5246#appendix-A.5
const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0039;
/// The TLS 1.2 suite of RSA key transport and AES-128-CBC, MACs with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc5246#appendix-A.5
const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003C;
/// The TLS 1.2 suite of RSA key transport and AES-256-CBC, MACs with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc5246#appendix-A.5
const TLS_RSA_WITH_AES_256_CBC_SHA256: u16 = 0x003D;
/// The TLS 1.2 suite of finite-field Diffie-Hellman signed with RSA and AES-128-CBC, MACs with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc5246#appendix-A.5
const TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x0067;
/// The TLS 1.2 suite of finite-field Diffie-Hellman signed with RSA and AES-256-CBC, MACs with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc5246#appendix-A.5
const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: u16 = 0x006B;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with ECDSA and AES-128-CBC, MACs with SHA-1.
///
/// https://www.rfc-editor.org/rfc/rfc8422#section-6
const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xC009;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with ECDSA and AES-256-CBC, MACs with SHA-1.
///
/// https://www.rfc-editor.org/rfc/rfc8422#section-6
const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: u16 = 0xC00A;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with RSA and AES-128-CBC, MACs with SHA-1.
///
/// https://www.rfc-editor.org/rfc/rfc8422#section-6
const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xC013;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with RSA and AES-256-CBC, MACs with SHA-1.
///
/// https://www.rfc-editor.org/rfc/rfc8422#section-6
const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xC014;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with ECDSA and AES-128-CBC, MACs with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc5289#section-3.1
const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: u16 = 0xC023;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with ECDSA and AES-256-CBC, MACs with SHA-384.
///
/// https://www.rfc-editor.org/rfc/rfc5289#section-3.1
const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: u16 = 0xC024;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with RSA and AES-128-CBC, MACs with SHA-256.
///
/// https://www.rfc-editor.org/rfc/rfc5289#section-3.1
const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xC027;
/// The TLS 1.2 suite of elliptic-curve Diffie-Hellman signed with RSA and AES-256-CBC, MACs with SHA-384.
///
/// https://www.rfc-editor.org/rfc/rfc5289#section-3.1
const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: u16 = 0xC028;

/// What both sides' reading shares: the hellos, whether the protocol was told, and what came out, in order.
#[derive(Debug, Default)]
struct Shared {
    client_hello: Option<ClientHello>,
    server_hello: Option<ServerHello>,
    /// Whether the agreed protocol came out, which every plaintext waits for.
    agreed: bool,
    /// Whether the decrypter stopped waiting for secrets, so a missing one makes a side opaque.
    gave_up: bool,
    /// What came out before the agreed protocol was known, from the first plaintext on.
    pending: Vec<Decrypted>,
    output: Vec<Decrypted>,
}

impl Shared {
    /// Gives back what was read, keeping it, and all after it, until the protocol is agreed if it is plaintext.
    fn emit(&mut self, decrypted: Decrypted) {
        if self.agreed || (self.pending.is_empty() && !matches!(decrypted, Decrypted::Plain { .. }))
        {
            self.output.push(decrypted);
        } else {
            self.pending.push(decrypted);
        }
    }

    /// Gives back the agreed protocol the first time only, then what waited for it.
    fn agree(&mut self, protocol: Option<Vec<u8>>) {
        if self.agreed {
            return;
        }
        self.agreed = true;
        self.output.push(Decrypted::Agreed { protocol });
        self.output.append(&mut self.pending);
    }

    /// Returns the server's latest hello, or what to do while it has not come.
    fn server_hello(&self, peer_gone: bool) -> Result<&ServerHello, Stop> {
        self.server_hello.as_ref().ok_or_else(|| {
            missing(
                peer_gone,
                &format!("the {SERVER_NAME}'s {SERVER_HELLO_NAME}"),
            )
        })
    }

    /// Returns the client's random, or what to do while its ClientHello has not come.
    fn client_random(&self, peer_gone: bool) -> Result<&[u8], Stop> {
        let hello = self.client_hello.as_ref().ok_or_else(|| {
            missing(
                peer_gone,
                &format!("the {CLIENT_NAME}'s {CLIENT_HELLO_NAME}"),
            )
        })?;
        Ok(&hello.random)
    }
}

/// What a ClientHello tells the decrypter.
#[derive(Debug)]
struct ClientHello {
    random: Vec<u8>,
    /// Whether the client offered 0-RTT data.
    early_data: bool,
}

/// What a ServerHello or HelloRetryRequest tells the decrypter.
#[derive(Debug)]
struct ServerHello {
    /// The version chosen, from supported_versions if there, else the legacy version.
    version: u16,
    suite: u16,
    random: Vec<u8>,
    /// Whether it is a HelloRetryRequest, after which the real ServerHello is still to come.
    retry: bool,
    encrypt_then_mac: bool,
    /// The application protocol in a TLS 1.2 ServerHello.
    protocol: Option<Vec<u8>>,
}

/// Why a side cannot read its next record now.
enum Stop {
    /// It waits for what is missing.
    Hold(Want),
    /// It gives back the record and the rest of the side opaque, for the reason.
    Fail(String),
}

/// What a side waits for before it can read its next record.
#[derive(Debug)]
struct Want {
    detail: String,
    /// Whether it is a secret from the key log, rather than a hello from the other side.
    secret: bool,
}

/// Returns how to wait for the other side's hello, or how to fail once that side can never send it.
fn missing(peer_gone: bool, what: &str) -> Stop {
    let detail = format!("{what} never came");
    if peer_gone {
        Stop::Fail(detail)
    } else {
        Stop::Hold(Want {
            detail,
            secret: false,
        })
    }
}

/// Returns the secret under the label for the client random, or how to wait for it, or fail once given up.
fn lookup(
    keys: &dyn Keys,
    label: &str,
    client_random: &[u8],
    gave_up: bool,
) -> Result<Vec<u8>, Stop> {
    keys.secret(label, client_random).ok_or_else(|| {
        let detail = format!(
            "the key log has no {label} for client random {}",
            hex(client_random)
        );
        if gave_up {
            Stop::Fail(detail)
        } else {
            Stop::Hold(Want {
                detail,
                secret: true,
            })
        }
    })
}

/// Returns the fault for a cipher suite this decrypter cannot decrypt.
fn unsupported(suite: u16) -> Stop {
    Stop::Fail(format!("cipher suite {suite:#06x} is not supported"))
}

/// Returns the bytes as lower-case hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Returns the other side of the connection.
fn other(direction: Direction) -> Direction {
    match direction {
        Direction::Client => Direction::Server,
        Direction::Server => Direction::Client,
    }
}

/// Returns how faults name the side.
fn name(direction: Direction) -> &'static str {
    match direction {
        Direction::Client => CLIENT_NAME,
        Direction::Server => SERVER_NAME,
    }
}

/// The reading of the records one side sent.
#[derive(Debug)]
struct Side {
    direction: Direction,
    /// The bytes not given back yet, the first `read` of them already read.
    buffer: Vec<u8>,
    read: usize,
    /// Whether a record was read yet, as the first must be a handshake or an alert.
    started: bool,
    /// Whether the rest of the side comes back as sent.
    opaque: bool,
    stage: Stage,
    /// Handshake bytes that are not a whole message yet.
    messages: Vec<u8>,
    /// What the side waits for before reading its next record, if anything.
    want: Option<Want>,
}

/// How a side's next records are protected.
#[derive(Debug)]
enum Stage {
    /// In the clear: before a TLS 1.2 ChangeCipherSpec, or before a TLS 1.3 ServerHello.
    Clear,
    /// TLS 1.3 client records that are 0-RTT data until one does not open under the early secret.
    Early(Traffic),
    /// TLS 1.3 records under a handshake traffic secret, until the side's Finished.
    Handshake(Traffic),
    /// TLS 1.3 records under an application traffic secret.
    Application(Traffic),
    /// Records under keys from a TLS 1.2 master secret, after the side's ChangeCipherSpec.
    Tls12(Cipher12),
}

/// What a whole or partial record at the start of a side's unread bytes is.
enum Frame {
    /// Not all of the record has come.
    Partial,
    /// The bytes are no TLS record.
    Foreign,
    /// A whole record of this many bytes.
    Whole(usize),
}

/// Returns what the bytes start with; the first record of a side must be a handshake or an alert.
fn frame(bytes: &[u8], started: bool) -> Frame {
    let Some(&kind) = bytes.first() else {
        return Frame::Partial;
    };
    let known = if started {
        (CHANGE_CIPHER_SPEC..=APPLICATION_DATA).contains(&kind)
    } else {
        kind == HANDSHAKE || kind == ALERT
    };
    if !known
        || bytes
            .get(MAJOR_OFFSET)
            .is_some_and(|major| *major != MAJOR_VERSION)
    {
        return Frame::Foreign;
    }
    let Some(length) = bytes
        .get(LENGTH_OFFSET..)
        .and_then(|rest| Cursor(rest).u16())
    else {
        return Frame::Partial;
    };
    let length = HEADER_SIZE + usize::from(length);
    if length > HEADER_SIZE + MAX_FRAGMENT {
        Frame::Foreign
    } else if bytes.len() < length {
        Frame::Partial
    } else {
        Frame::Whole(length)
    }
}

impl Side {
    /// Returns the reading of a side that sent nothing yet.
    fn new(direction: Direction) -> Self {
        Self {
            direction,
            buffer: Vec::new(),
            read: usize::MIN,
            started: false,
            opaque: false,
            stage: Stage::Clear,
            messages: Vec::new(),
            want: None,
        }
    }

    /// Gives back the unread bytes opaque, returning whether there were any.
    fn flush(&mut self, shared: &mut Shared) -> bool {
        let unread = self.buffer.split_off(self.read);
        self.buffer.clear();
        self.read = usize::MIN;
        if unread.is_empty() {
            return false;
        }
        shared.emit(Decrypted::Opaque {
            direction: self.direction,
            bytes: unread,
        });
        true
    }

    /// Stops reading the side, giving back the fault and then every unread byte as sent.
    fn fail(&mut self, shared: &mut Shared, detail: String) {
        shared.emit(Decrypted::Fault {
            direction: self.direction,
            detail,
        });
        self.opaque = true;
        self.flush(shared);
    }

    /// Reads the side's next whole record, returning whether it read or gave back anything.
    fn step(&mut self, shared: &mut Shared, keys: &dyn Keys, peer_gone: bool) -> bool {
        self.want = None;
        if self.opaque {
            return self.flush(shared);
        }
        let unread = &self.buffer[self.read..];
        let length = match frame(unread, self.started) {
            Frame::Partial => return false,
            Frame::Foreign => {
                self.fail(
                    shared,
                    format!(
                        "the {} sent bytes that are no TLS records",
                        name(self.direction)
                    ),
                );
                return true;
            }
            Frame::Whole(length) => length,
        };
        let record = unread[..length].to_vec();
        match self.read_record(shared, &record, keys, peer_gone) {
            Ok(()) => {
                self.read += length;
                self.started = true;
                true
            }
            Err(Stop::Hold(want)) => {
                self.want = Some(want);
                false
            }
            Err(Stop::Fail(detail)) => {
                self.fail(shared, detail);
                true
            }
        }
    }

    /// Reads one whole record, decrypting it if its stage protects it.
    fn read_record(
        &mut self,
        shared: &mut Shared,
        record: &[u8],
        keys: &dyn Keys,
        peer_gone: bool,
    ) -> Result<(), Stop> {
        let (header, fragment) = record.split_at(HEADER_SIZE);
        let kind = header.first().copied().unwrap_or_default();
        if let Stage::Tls12(cipher) = &mut self.stage {
            let content = cipher.open(header, fragment, keys, shared.gave_up)?;
            return self.read_content(shared, kind, &content, peer_gone);
        }
        match kind {
            HANDSHAKE => self.read_handshake(shared, fragment),
            ALERT => {
                self.read_alert(shared, fragment);
                Ok(())
            }
            CHANGE_CIPHER_SPEC => self.change_cipher_spec(shared, peer_gone),
            _ => {
                let (kind, content) = self.open(shared, header, fragment, keys, peer_gone)?;
                self.read_content(shared, kind, &content, peer_gone)
            }
        }
    }

    /// Reads the content of a decrypted record of the type.
    fn read_content(
        &mut self,
        shared: &mut Shared,
        kind: u8,
        content: &[u8],
        peer_gone: bool,
    ) -> Result<(), Stop> {
        match kind {
            APPLICATION_DATA => {
                if !content.is_empty() {
                    shared.emit(Decrypted::Plain {
                        direction: self.direction,
                        stream: None,
                        bytes: content.to_vec(),
                        fin: false,
                    });
                }
                Ok(())
            }
            HANDSHAKE => self.read_handshake(shared, content),
            ALERT => {
                self.read_alert(shared, content);
                Ok(())
            }
            CHANGE_CIPHER_SPEC if matches!(self.stage, Stage::Tls12(_)) => {
                self.change_cipher_spec(shared, peer_gone)
            }
            other => Err(Stop::Fail(format!(
                "the {} sent a record of content type {other}",
                name(self.direction)
            ))),
        }
    }

    /// Reads a ChangeCipherSpec: TLS 1.2 starts encrypting after it, TLS 1.3 sends it only for middleboxes.
    fn change_cipher_spec(&mut self, shared: &Shared, peer_gone: bool) -> Result<(), Stop> {
        let hello = shared.server_hello(peer_gone)?;
        match hello.version {
            TLS13 => Ok(()),
            TLS12 => {
                let client_random = shared.client_random(peer_gone)?.to_vec();
                self.stage = Stage::Tls12(Cipher12 {
                    direction: self.direction,
                    suite: hello.suite,
                    client_random,
                    server_random: hello.random.clone(),
                    encrypt_then_mac: hello.encrypt_then_mac,
                    keys: None,
                    sequence: u64::MIN,
                });
                Ok(())
            }
            version => Err(Stop::Fail(format!(
                "TLS version {version:#06x} is not supported"
            ))),
        }
    }

    /// Opens a TLS 1.3 encrypted record under the side's current secret, returning its inner type and content.
    fn open(
        &mut self,
        shared: &Shared,
        header: &[u8],
        fragment: &[u8],
        keys: &dyn Keys,
        peer_gone: bool,
    ) -> Result<(u8, Vec<u8>), Stop> {
        let hello = shared.server_hello(peer_gone)?;
        if hello.version != TLS13 {
            return Err(Stop::Fail(format!(
                "the {} sent application data before ChangeCipherSpec",
                name(self.direction)
            )));
        }
        if let Stage::Clear = self.stage {
            let early_data = shared
                .client_hello
                .as_ref()
                .is_some_and(|hello| hello.early_data);
            self.stage = match self.direction {
                Direction::Server => {
                    return Err(Stop::Fail(format!(
                        "the {SERVER_NAME} encrypted a record before its {SERVER_HELLO_NAME}"
                    )));
                }
                Direction::Client if early_data => {
                    Stage::Early(Traffic::new(CLIENT_EARLY_TRAFFIC_SECRET))
                }
                Direction::Client if hello.retry => {
                    return Err(missing(
                        peer_gone,
                        &format!("the {SERVER_HELLO_NAME} after the HelloRetryRequest"),
                    ));
                }
                Direction::Client => {
                    Stage::Handshake(Traffic::new(CLIENT_HANDSHAKE_TRAFFIC_SECRET))
                }
            };
        }
        let opening = Opening {
            keys,
            client_random: shared.client_random(peer_gone)?,
            suite: hello.suite,
            gave_up: shared.gave_up,
            direction: self.direction,
            header,
            fragment,
        };
        match &mut self.stage {
            Stage::Early(early) => {
                if let Some(opened) = early.open_early(&opening)? {
                    return Ok(opened);
                }
                if hello.retry {
                    return Err(Stop::Fail(format!(
                        "0-RTT record {} did not decrypt",
                        early.sequence
                    )));
                }
                let mut handshake = Traffic::new(CLIENT_HANDSHAKE_TRAFFIC_SECRET);
                let opened = handshake.open(&opening)?;
                self.stage = Stage::Handshake(handshake);
                Ok(opened)
            }
            Stage::Handshake(traffic) | Stage::Application(traffic) => traffic.open(&opening),
            Stage::Clear | Stage::Tls12(_) => Err(Stop::Fail(WRONG_STAGE.to_owned())),
        }
    }

    /// Reads handshake bytes, acting on each message they complete.
    fn read_handshake(&mut self, shared: &mut Shared, bytes: &[u8]) -> Result<(), Stop> {
        self.messages.extend_from_slice(bytes);
        while let Some((kind, body)) = next_message(&mut self.messages) {
            self.read_message(shared, kind, &body)?;
        }
        Ok(())
    }

    /// Acts on one handshake message: hellos, and the messages after which the side's keys change.
    fn read_message(&mut self, shared: &mut Shared, kind: u8, body: &[u8]) -> Result<(), Stop> {
        let malformed = |what: &str| {
            Stop::Fail(format!(
                "the {} sent a malformed {what}",
                name(self.direction)
            ))
        };
        match (self.direction, kind) {
            (Direction::Client, CLIENT_HELLO) => {
                shared.client_hello =
                    Some(parse_client_hello(body).ok_or_else(|| malformed(CLIENT_HELLO_NAME))?);
                if let Stage::Early(_) = self.stage {
                    self.stage = Stage::Clear;
                }
            }
            (Direction::Client, END_OF_EARLY_DATA) => {
                self.stage = Stage::Handshake(Traffic::new(CLIENT_HANDSHAKE_TRAFFIC_SECRET))
            }
            (Direction::Server, SERVER_HELLO) => {
                let hello = parse_server_hello(body).ok_or_else(|| malformed(SERVER_HELLO_NAME))?;
                if !hello.retry {
                    if hello.version == TLS13 {
                        self.stage =
                            Stage::Handshake(Traffic::new(SERVER_HANDSHAKE_TRAFFIC_SECRET));
                    } else {
                        shared.agree(hello.protocol.clone());
                    }
                }
                shared.server_hello = Some(hello);
            }
            (Direction::Server, ENCRYPTED_EXTENSIONS) => {
                let extensions =
                    extensions(body).ok_or_else(|| malformed(ENCRYPTED_EXTENSIONS_NAME))?;
                let protocol = extensions
                    .iter()
                    .find(|(kind, _)| *kind == APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
                shared.agree(match protocol {
                    Some((_, data)) => {
                        Some(parse_protocol(data).ok_or_else(|| malformed(ALPN_NAME))?)
                    }
                    None => None,
                });
            }
            (_, FINISHED) => {
                if let Stage::Handshake(_) = self.stage {
                    let label = match self.direction {
                        Direction::Client => CLIENT_TRAFFIC_SECRET_0,
                        Direction::Server => SERVER_TRAFFIC_SECRET_0,
                    };
                    self.stage = Stage::Application(Traffic::new(label));
                }
            }
            (_, KEY_UPDATE) => {
                if let Stage::Application(traffic) = &mut self.stage {
                    traffic.update();
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Reads alerts; a fatal one is a fault, after which the side's bytes come back opaque.
    fn read_alert(&mut self, shared: &mut Shared, bytes: &[u8]) {
        for alert in bytes.chunks(ALERT_SIZE) {
            if let [level, description] = alert
                && *level == FATAL
            {
                shared.emit(Decrypted::Fault {
                    direction: self.direction,
                    detail: format!(
                        "the {} sent fatal alert {description}",
                        name(self.direction)
                    ),
                });
                self.opaque = true;
            }
        }
    }
}

/// Takes the next whole handshake message out of the bytes, returning its type and body.
fn next_message(bytes: &mut Vec<u8>) -> Option<(u8, Vec<u8>)> {
    let (&kind, length) = bytes.get(..HANDSHAKE_HEADER_SIZE)?.split_first()?;
    let length = length
        .iter()
        .fold(usize::MIN, |sum, byte| sum << u8::BITS | usize::from(*byte));
    if bytes.len() < HANDSHAKE_HEADER_SIZE + length {
        return None;
    }
    let body = bytes[HANDSHAKE_HEADER_SIZE..HANDSHAKE_HEADER_SIZE + length].to_vec();
    bytes.drain(..HANDSHAKE_HEADER_SIZE + length);
    Some((kind, body))
}

/// A reader of a handshake message's fields, each read giving none past the end.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    /// Takes the next count bytes.
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (taken, rest) = self.0.split_at_checked(count)?;
        self.0 = rest;
        Some(taken)
    }

    /// Takes the next byte.
    fn u8(&mut self) -> Option<u8> {
        let (&byte, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(byte)
    }

    /// Takes the next two bytes as a big-endian number.
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(
            self.take(size_of::<u16>())?.try_into().ok()?,
        ))
    }

    /// Takes a vector whose length is the byte before it.
    fn vector8(&mut self) -> Option<&'a [u8]> {
        let length = self.u8()?;
        self.take(usize::from(length))
    }

    /// Takes a vector whose length is the two bytes before it.
    fn vector16(&mut self) -> Option<&'a [u8]> {
        let length = self.u16()?;
        self.take(usize::from(length))
    }
}

/// Returns each extension's type and data from a list with its two-byte length first, or none when there is no list.
fn extensions(bytes: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let mut list = Cursor(Cursor(bytes).vector16()?);
    let mut found = Vec::new();
    while !list.0.is_empty() {
        found.push((list.u16()?, list.vector16()?));
    }
    Some(found)
}

/// Returns the first protocol of an ALPN extension, the one a server chose.
fn parse_protocol(data: &[u8]) -> Option<Vec<u8>> {
    Some(Cursor(Cursor(data).vector16()?).vector8()?.to_vec())
}

/// Returns the random of a ClientHello, and whether it offered 0-RTT data.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
fn parse_client_hello(body: &[u8]) -> Option<ClientHello> {
    let mut cursor = Cursor(body);
    cursor.u16()?;
    let random = cursor.take(RANDOM_SIZE)?.to_vec();
    cursor.vector8()?;
    cursor.vector16()?;
    cursor.vector8()?;
    let early_data = extensions(cursor.0)?
        .iter()
        .any(|(kind, _)| *kind == EARLY_DATA);
    Some(ClientHello { random, early_data })
}

/// Returns what a ServerHello or HelloRetryRequest chose.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3
fn parse_server_hello(body: &[u8]) -> Option<ServerHello> {
    let mut cursor = Cursor(body);
    let version = cursor.u16()?;
    let random = cursor.take(RANDOM_SIZE)?.to_vec();
    cursor.vector8()?;
    let suite = cursor.u16()?;
    cursor.u8()?;
    let retry = random == HELLO_RETRY_RANDOM;
    let mut hello = ServerHello {
        version,
        suite,
        random,
        retry,
        encrypt_then_mac: false,
        protocol: None,
    };
    for (kind, data) in extensions(cursor.0)? {
        match kind {
            SUPPORTED_VERSIONS => hello.version = Cursor(data).u16()?,
            APPLICATION_LAYER_PROTOCOL_NEGOTIATION => hello.protocol = Some(parse_protocol(data)?),
            ENCRYPT_THEN_MAC => hello.encrypt_then_mac = true,
            _ => {}
        }
    }
    Some(hello)
}

/// What opening one TLS 1.3 record needs besides the secret of its stage.
struct Opening<'a> {
    keys: &'a dyn Keys,
    client_random: &'a [u8],
    /// The suite the server chose.
    suite: u16,
    gave_up: bool,
    direction: Direction,
    header: &'a [u8],
    fragment: &'a [u8],
}

/// A TLS 1.3 cipher suite's AEAD and hash.
#[derive(Debug, Clone, Copy)]
struct Suite13 {
    aead: &'static aead::Algorithm,
    hkdf: hkdf::Algorithm,
}

/// Returns the TLS 1.3 suite, if this decrypter reads it.
fn suite13(id: u16) -> Option<Suite13> {
    match id {
        TLS_AES_128_GCM_SHA256 => Some(Suite13 {
            aead: &aead::AES_128_GCM,
            hkdf: hkdf::HKDF_SHA256,
        }),
        TLS_AES_256_GCM_SHA384 => Some(Suite13 {
            aead: &aead::AES_256_GCM,
            hkdf: hkdf::HKDF_SHA384,
        }),
        TLS_CHACHA20_POLY1305_SHA256 => Some(Suite13 {
            aead: &aead::CHACHA20_POLY1305,
            hkdf: hkdf::HKDF_SHA256,
        }),
        _ => None,
    }
}

/// One side's TLS 1.3 records under one traffic secret and those KeyUpdates derive from it.
#[derive(Debug)]
struct Traffic {
    /// The key log label of the secret it starts from.
    label: &'static str,
    keys: Option<TrafficKeys>,
    /// The records opened under the current key.
    sequence: u64,
}

/// A TLS 1.3 traffic secret, found in the key log or updated from one, and the record key it derives.
#[derive(Debug)]
struct TrafficKeys {
    suite: Suite13,
    secret: Secret<Vec<u8>>,
    key: RecordKey,
}

impl TrafficKeys {
    /// Derives the record key of the secret under the suite.
    fn new(suite: Suite13, secret: Vec<u8>) -> Option<Self> {
        let key = RecordKey::new(suite, &secret)?;
        Some(Self {
            suite,
            secret: Secret(secret),
            key,
        })
    }
}

impl Traffic {
    /// Returns the records under the secret of the label, before the key log was read for it.
    fn new(label: &'static str) -> Self {
        Self {
            label,
            keys: None,
            sequence: u64::MIN,
        }
    }

    /// Opens the next record, finding the secret in the key log first if need be.
    fn open(&mut self, opening: &Opening<'_>) -> Result<(u8, Vec<u8>), Stop> {
        let keys = match &mut self.keys {
            Some(keys) => keys,
            empty => {
                let suite = suite13(opening.suite).ok_or_else(|| unsupported(opening.suite))?;
                let secret = lookup(
                    opening.keys,
                    self.label,
                    opening.client_random,
                    opening.gave_up,
                )?;
                empty.insert(
                    TrafficKeys::new(suite, secret).ok_or_else(|| unsupported(opening.suite))?,
                )
            }
        };
        let plaintext = keys
            .key
            .open(self.sequence, opening.header, opening.fragment)
            .ok_or_else(|| {
                Stop::Fail(format!(
                    "record {} the {} sent did not decrypt under {}",
                    self.sequence,
                    name(opening.direction),
                    self.label
                ))
            })?;
        self.sequence += 1;
        inner(plaintext)
    }

    /// Opens the next record if it is 0-RTT data, trying every suite of the secret's hash until one opens it.
    ///
    /// None means it is not: the server rejected the 0-RTT data, or it ended, so the record is under the handshake secret.
    fn open_early(&mut self, opening: &Opening<'_>) -> Result<Option<(u8, Vec<u8>)>, Stop> {
        if let Some(keys) = &self.keys {
            let Some(plaintext) = keys
                .key
                .open(self.sequence, opening.header, opening.fragment)
            else {
                return Ok(None);
            };
            self.sequence += 1;
            return inner(plaintext).map(Some);
        }
        let secret = lookup(
            opening.keys,
            self.label,
            opening.client_random,
            opening.gave_up,
        )?;
        let candidates = std::iter::once(opening.suite).chain(SUITES_13.iter().copied());
        for suite in candidates
            .filter_map(suite13)
            .filter(|suite| hkdf::KeyType::len(&suite.hkdf) == secret.len())
        {
            let Some(keys) = TrafficKeys::new(suite, secret.clone()) else {
                continue;
            };
            if let Some(plaintext) = keys
                .key
                .open(self.sequence, opening.header, opening.fragment)
            {
                self.keys = Some(keys);
                self.sequence += 1;
                return inner(plaintext).map(Some);
            }
        }
        Ok(None)
    }

    /// Moves to the next secret after a KeyUpdate, its records counted from zero.
    fn update(&mut self) {
        if let Some(keys) = &mut self.keys {
            let length = hkdf::KeyType::len(&keys.suite.hkdf);
            let secret = expand_label(keys.suite.hkdf, &keys.secret.0, UPDATE_LABEL, length);
            if let Some(updated) = TrafficKeys::new(keys.suite, secret) {
                *keys = updated;
            }
        }
        self.sequence = u64::MIN;
    }
}

/// Returns a TLS 1.3 record's inner content type and its content, without the padding after it.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-5.2
fn inner(mut plaintext: Vec<u8>) -> Result<(u8, Vec<u8>), Stop> {
    let Some(end) = plaintext.iter().rposition(|byte| *byte != u8::MIN) else {
        return Err(Stop::Fail(NO_CONTENT_TYPE.to_owned()));
    };
    let kind = plaintext[end];
    plaintext.truncate(end);
    Ok((kind, plaintext))
}

/// An AEAD key and the IV each record's nonce is the sequence number XORed into.
#[derive(Debug)]
struct RecordKey {
    key: aead::LessSafeKey,
    iv: Secret<[u8; aead::NONCE_LEN]>,
}

impl RecordKey {
    /// Derives a TLS 1.3 record key and IV from a traffic secret.
    ///
    /// https://www.rfc-editor.org/rfc/rfc8446#section-7.3
    fn new(suite: Suite13, secret: &[u8]) -> Option<Self> {
        let key = expand_label(suite.hkdf, secret, KEY_LABEL, suite.aead.key_len());
        let iv = expand_label(suite.hkdf, secret, IV_LABEL, aead::NONCE_LEN);
        Some(Self {
            key: aead::LessSafeKey::new(aead::UnboundKey::new(suite.aead, &key).ok()?),
            iv: Secret(iv.try_into().ok()?),
        })
    }

    /// Returns the plaintext of the record with the sequence number, the AAD given, or none if it does not open.
    fn open(&self, sequence: u64, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        open(&self.key, xor_nonce(&self.iv.0, sequence)?, aad, sealed)
    }
}

/// Returns the plaintext of the sealed bytes, or none if they do not open.
fn open(key: &aead::LessSafeKey, nonce: aead::Nonce, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let mut buffer = sealed.to_vec();
    let length = key
        .open_in_place(nonce, aead::Aad::from(aad), &mut buffer)
        .ok()?
        .len();
    buffer.truncate(length);
    Some(buffer)
}

/// Returns the nonce of the record with the sequence number: the IV with the number XORed into its end.
fn xor_nonce(iv: &[u8; aead::NONCE_LEN], sequence: u64) -> Option<aead::Nonce> {
    let mut nonce = *iv;
    for (byte, number) in nonce
        .iter_mut()
        .rev()
        .zip(sequence.to_be_bytes().iter().rev())
    {
        *byte ^= number;
    }
    Some(aead::Nonce::assume_unique_for_key(nonce))
}

/// An output length for ring's HKDF.
struct Length(usize);

impl hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

/// Returns HKDF-Expand-Label of the secret with an empty context.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-7.1
fn expand_label(algorithm: hkdf::Algorithm, secret: &[u8], label: &[u8], length: usize) -> Vec<u8> {
    let full_label = [LABEL_PREFIX, label].concat();
    let output_length = u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes();
    let label_length = [u8::try_from(full_label.len()).unwrap_or(u8::MAX)];
    let context_length = [u8::MIN];
    let info: &[&[u8]] = &[&output_length, &label_length, &full_label, &context_length];
    let mut output = vec![u8::MIN; length];
    let prk = hkdf::Prk::new_less_safe(algorithm, secret);
    if let Ok(okm) = prk.expand(info, Length(length)) {
        okm.fill(&mut output).ok();
    }
    output
}

/// Returns TLS 1.2's PRF of the secret, label and seed, as many bytes as asked.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-5
fn prf(
    algorithm: hmac::Algorithm,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    length: usize,
) -> Vec<u8> {
    let key = hmac::Key::new(algorithm, secret);
    let label_seed = [label, seed].concat();
    let mut chain = hmac::sign(&key, &label_seed);
    let mut output = Vec::with_capacity(length);
    while output.len() < length {
        let mut context = hmac::Context::with_key(&key);
        context.update(chain.as_ref());
        context.update(&label_seed);
        output.extend_from_slice(context.sign().as_ref());
        chain = hmac::sign(&key, chain.as_ref());
    }
    output.truncate(length);
    output
}

/// A TLS 1.2 cipher suite's PRF hash and how it protects records.
#[derive(Debug, Clone, Copy)]
struct Suite12 {
    prf: hmac::Algorithm,
    bulk: Bulk,
}

/// How a TLS 1.2 suite protects records.
#[derive(Debug, Clone, Copy)]
enum Bulk {
    /// AES-GCM with an implicit salt and an explicit nonce in each record.
    Gcm(&'static aead::Algorithm),
    /// ChaCha20-Poly1305 with a nonce made as TLS 1.3 makes it.
    ChaCha,
    /// AES-CBC with an HMAC, after or before encrypting.
    Cbc { aes256: bool, mac: hmac::Algorithm },
}

/// Returns the TLS 1.2 suite, if this decrypter reads it.
fn suite12(id: u16) -> Option<Suite12> {
    let (prf, bulk) = match id {
        TLS_RSA_WITH_AES_128_GCM_SHA256
        | TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            (hmac::HMAC_SHA256, Bulk::Gcm(&aead::AES_128_GCM))
        }
        TLS_RSA_WITH_AES_256_GCM_SHA384
        | TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            (hmac::HMAC_SHA384, Bulk::Gcm(&aead::AES_256_GCM))
        }
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        | TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => (hmac::HMAC_SHA256, Bulk::ChaCha),
        TLS_RSA_WITH_AES_128_CBC_SHA
        | TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => (
            hmac::HMAC_SHA256,
            Bulk::Cbc {
                aes256: false,
                mac: hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            },
        ),
        TLS_RSA_WITH_AES_256_CBC_SHA
        | TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => (
            hmac::HMAC_SHA256,
            Bulk::Cbc {
                aes256: true,
                mac: hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            },
        ),
        TLS_RSA_WITH_AES_128_CBC_SHA256
        | TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => (
            hmac::HMAC_SHA256,
            Bulk::Cbc {
                aes256: false,
                mac: hmac::HMAC_SHA256,
            },
        ),
        TLS_RSA_WITH_AES_256_CBC_SHA256 | TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => (
            hmac::HMAC_SHA256,
            Bulk::Cbc {
                aes256: true,
                mac: hmac::HMAC_SHA256,
            },
        ),
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => (
            hmac::HMAC_SHA384,
            Bulk::Cbc {
                aes256: true,
                mac: hmac::HMAC_SHA384,
            },
        ),
        _ => return None,
    };
    Some(Suite12 { prf, bulk })
}

impl Bulk {
    /// Returns the bytes of each side's MAC key, encryption key and implicit IV in the key block.
    fn sizes(self) -> (usize, usize, usize) {
        match self {
            Self::Gcm(algorithm) => (usize::MIN, algorithm.key_len(), GCM_SALT_SIZE),
            Self::ChaCha => (
                usize::MIN,
                aead::CHACHA20_POLY1305.key_len(),
                aead::NONCE_LEN,
            ),
            Self::Cbc { aes256, mac } => {
                let key = if aes256 {
                    Aes256::key_size()
                } else {
                    Aes128::key_size()
                };
                (mac.digest_algorithm().output_len(), key, usize::MIN)
            }
        }
    }
}

/// One side's TLS 1.2 records after its ChangeCipherSpec, under the keys of the hellos before it.
#[derive(Debug)]
struct Cipher12 {
    direction: Direction,
    suite: u16,
    client_random: Vec<u8>,
    server_random: Vec<u8>,
    encrypt_then_mac: bool,
    /// The keys, once the key log had the master secret.
    keys: Option<Keys12>,
    sequence: u64,
}

impl Cipher12 {
    /// Opens the next record, finding the master secret in the key log first if need be.
    fn open(
        &mut self,
        header: &[u8],
        fragment: &[u8],
        keys: &dyn Keys,
        gave_up: bool,
    ) -> Result<Vec<u8>, Stop> {
        let record_keys = match &mut self.keys {
            Some(record_keys) => record_keys,
            empty => {
                let suite = suite12(self.suite).ok_or_else(|| unsupported(self.suite))?;
                let master = lookup(keys, CLIENT_RANDOM, &self.client_random, gave_up)?;
                let seed = [self.server_random.as_slice(), &self.client_random].concat();
                let made =
                    Keys12::new(suite, &master, &seed, self.direction, self.encrypt_then_mac);
                empty.insert(made.ok_or_else(|| unsupported(self.suite))?)
            }
        };
        let plaintext = record_keys
            .open(self.sequence, header, fragment)
            .ok_or_else(|| {
                Stop::Fail(format!(
                    "record {} the {} sent did not decrypt under {CLIENT_RANDOM}",
                    self.sequence,
                    name(self.direction)
                ))
            })?;
        self.sequence += 1;
        Ok(plaintext)
    }
}

/// One side's TLS 1.2 record keys.
#[derive(Debug)]
enum Keys12 {
    /// AES-GCM: the key and the implicit salt.
    Gcm {
        key: aead::LessSafeKey,
        salt: Secret<Vec<u8>>,
    },
    /// ChaCha20-Poly1305: the key and the IV each nonce XORs the sequence number into.
    ChaCha {
        key: aead::LessSafeKey,
        iv: Secret<[u8; aead::NONCE_LEN]>,
    },
    /// AES-CBC: the cipher, the MAC key, and whether the MAC covers the ciphertext rather than the plaintext.
    Cbc {
        cipher: BlockCipher,
        mac: hmac::Key,
        encrypt_then_mac: bool,
    },
}

impl Keys12 {
    /// Derives the side's keys from the master secret and the randoms, server's first.
    ///
    /// https://www.rfc-editor.org/rfc/rfc5246#section-6.3
    fn new(
        suite: Suite12,
        master: &[u8],
        seed: &[u8],
        direction: Direction,
        encrypt_then_mac: bool,
    ) -> Option<Self> {
        let (mac_size, key_size, iv_size) = suite.bulk.sizes();
        let block = prf(
            suite.prf,
            master,
            KEY_EXPANSION,
            seed,
            (mac_size + key_size + iv_size) * SIDES,
        );
        let mut cursor = Cursor(&block);
        let macs = (cursor.take(mac_size)?, cursor.take(mac_size)?);
        let keys = (cursor.take(key_size)?, cursor.take(key_size)?);
        let ivs = (cursor.take(iv_size)?, cursor.take(iv_size)?);
        let (mac, key, iv) = match direction {
            Direction::Client => (macs.0, keys.0, ivs.0),
            Direction::Server => (macs.1, keys.1, ivs.1),
        };
        let aead_key = |algorithm| {
            aead::UnboundKey::new(algorithm, key)
                .ok()
                .map(aead::LessSafeKey::new)
        };
        Some(match suite.bulk {
            Bulk::Gcm(algorithm) => Self::Gcm {
                key: aead_key(algorithm)?,
                salt: Secret(iv.to_vec()),
            },
            Bulk::ChaCha => Self::ChaCha {
                key: aead_key(&aead::CHACHA20_POLY1305)?,
                iv: Secret(iv.try_into().ok()?),
            },
            Bulk::Cbc {
                aes256,
                mac: algorithm,
            } => Self::Cbc {
                cipher: BlockCipher::new(aes256, key)?,
                mac: hmac::Key::new(algorithm, mac),
                encrypt_then_mac,
            },
        })
    }

    /// Returns the content of the record with the sequence number, or none if it does not open.
    fn open(&self, sequence: u64, header: &[u8], fragment: &[u8]) -> Option<Vec<u8>> {
        let kind_and_version = header.get(..LENGTH_OFFSET)?;
        match self {
            Self::Gcm { key, salt } => {
                let (explicit, sealed) = fragment.split_at_checked(GCM_EXPLICIT_SIZE)?;
                let length = sealed.len().checked_sub(key.algorithm().tag_len())?;
                let nonce =
                    aead::Nonce::try_assume_unique_for_key(&[salt.0.as_slice(), explicit].concat())
                        .ok()?;
                open(
                    key,
                    nonce,
                    &additional_data(sequence, kind_and_version, length)?,
                    sealed,
                )
            }
            Self::ChaCha { key, iv } => {
                let length = fragment.len().checked_sub(key.algorithm().tag_len())?;
                open(
                    key,
                    xor_nonce(&iv.0, sequence)?,
                    &additional_data(sequence, kind_and_version, length)?,
                    fragment,
                )
            }
            Self::Cbc {
                cipher,
                mac,
                encrypt_then_mac,
            } => {
                let mac_size = mac.algorithm().digest_algorithm().output_len();
                if *encrypt_then_mac {
                    let (sealed, tag) =
                        fragment.split_at_checked(fragment.len().checked_sub(mac_size)?)?;
                    let mut covered = additional_data(sequence, kind_and_version, sealed.len())?;
                    covered.extend_from_slice(sealed);
                    hmac::verify(mac, &covered, tag).ok()?;
                    cipher.open(sealed)
                } else {
                    let plaintext = cipher.open(fragment)?;
                    let (content, tag) =
                        plaintext.split_at_checked(plaintext.len().checked_sub(mac_size)?)?;
                    let mut covered = additional_data(sequence, kind_and_version, content.len())?;
                    covered.extend_from_slice(content);
                    hmac::verify(mac, &covered, tag).ok()?;
                    Some(content.to_vec())
                }
            }
        }
    }
}

/// Returns what a TLS 1.2 record's AEAD tag or MAC covers before its content: the sequence number, type, version and length.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3.3
fn additional_data(sequence: u64, kind_and_version: &[u8], length: usize) -> Option<Vec<u8>> {
    let mut data = sequence.to_be_bytes().to_vec();
    data.extend_from_slice(kind_and_version);
    data.extend_from_slice(&u16::try_from(length).ok()?.to_be_bytes());
    Some(data)
}

/// An AES key for CBC records, boxed as its round keys are large.
#[derive(Debug)]
enum BlockCipher {
    Aes128(Box<Aes128>),
    Aes256(Box<Aes256>),
}

impl BlockCipher {
    /// Returns the cipher of the key, AES-256 or AES-128.
    fn new(aes256: bool, key: &[u8]) -> Option<Self> {
        if aes256 {
            Aes256::new_from_slice(key)
                .ok()
                .map(|cipher| Self::Aes256(Box::new(cipher)))
        } else {
            Aes128::new_from_slice(key)
                .ok()
                .map(|cipher| Self::Aes128(Box::new(cipher)))
        }
    }

    /// Returns the plaintext of an explicit IV and CBC blocks, without the padding, or none if they or it are malformed.
    ///
    /// https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3.2
    fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        let (iv, blocks) = sealed.split_at_checked(BLOCK_SIZE)?;
        if blocks.is_empty() || !blocks.len().is_multiple_of(BLOCK_SIZE) {
            return None;
        }
        let mut plaintext = blocks.to_vec();
        let mut previous = iv;
        for (block, sealed_block) in plaintext
            .chunks_exact_mut(BLOCK_SIZE)
            .zip(blocks.chunks_exact(BLOCK_SIZE))
        {
            let array = aes::Block::from_mut_slice(block);
            match self {
                Self::Aes128(cipher) => cipher.decrypt_block(array),
                Self::Aes256(cipher) => cipher.decrypt_block(array),
            }
            for (byte, chained) in block.iter_mut().zip(previous) {
                *byte ^= chained;
            }
            previous = sealed_block;
        }
        let padding = *plaintext.last()?;
        let content = plaintext
            .len()
            .checked_sub(usize::from(padding))?
            .checked_sub(size_of::<u8>())?;
        if plaintext[content..].iter().any(|byte| *byte != padding) {
            return None;
        }
        plaintext.truncate(content);
        Some(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    use aes::cipher::BlockEncrypt;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::ring::{cipher_suite, default_provider, kx_group};
    use rustls::crypto::{
        CryptoProvider, SupportedKxGroup, verify_tls12_signature, verify_tls13_signature,
    };
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };
    use rustls::{
        ClientConfig, ClientConnection, ConnectionCommon, DigitallySignedStruct, ServerConfig,
        ServerConnection, SignatureScheme, SupportedCipherSuite,
    };
    use simple_httptap_keylog::Keylog;
    use simple_httptap_keylog_file::{FileKeylog, FileKeys};

    use super::*;

    /// The application protocol both sides offer in tests that agree on one.
    const H2: &[u8] = b"h2";
    /// The name the client connects to and the certificate is for.
    const HOST: &str = "localhost";

    /// A verifier that takes any server certificate, but checks the handshake's signatures.
    #[derive(Debug)]
    struct AnyCertificate(Arc<CryptoProvider>);

    impl ServerCertVerifier for AnyCertificate {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            certificate: &CertificateDer<'_>,
            signed: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                certificate,
                signed,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            certificate: &CertificateDer<'_>,
            signed: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                certificate,
                signed,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// The secrets a client logged, kept until a test writes them to a key log.
    #[derive(Debug, Default)]
    struct Logged(Mutex<Vec<Entry>>);

    /// A logged secret's label, client random and secret.
    type Entry = (String, Vec<u8>, Vec<u8>);

    impl rustls::KeyLog for Logged {
        fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
            self.0.lock().unwrap().push((
                label.to_owned(),
                client_random.to_vec(),
                secret.to_vec(),
            ));
        }
    }

    impl Logged {
        /// Writes every secret logged so far to the key log.
        fn write_to(&self, keys: &FileKeys) {
            for (label, client_random, secret) in self.0.lock().unwrap().iter() {
                keys.record(label, client_random, secret).unwrap();
            }
        }

        /// Returns the client random of the last connection logged.
        fn last_client_random(&self) -> Vec<u8> {
            self.0.lock().unwrap().last().unwrap().1.clone()
        }
    }

    /// Returns an empty key log file in a new temporary folder, and the folder, which is deleted when dropped.
    fn empty_keys() -> (tempfile::TempDir, FileKeys) {
        let folder = tempfile::tempdir().unwrap();
        let keys = FileKeylog.open(&folder.path().join("keys.log")).unwrap();
        (folder, keys)
    }

    /// A client and a server config made for each other, and what the client logs.
    struct Pair {
        client: Arc<ClientConfig>,
        server: Arc<ServerConfig>,
        logged: Arc<Logged>,
    }

    /// Returns configs that agree only on the suite, offering the protocol and allowing 0-RTT data if asked.
    fn pair(
        suite: SupportedCipherSuite,
        protocol: Option<&[u8]>,
        server_groups: Option<Vec<&'static dyn SupportedKxGroup>>,
        early_data: bool,
    ) -> Pair {
        let certified = rcgen::generate_simple_self_signed(vec![HOST.to_owned()]).unwrap();
        let mut provider = default_provider();
        provider.cipher_suites = vec![suite];
        let mut server_provider = provider.clone();
        if let Some(groups) = server_groups {
            server_provider.kx_groups = groups;
        }
        let provider = Arc::new(provider);
        let versions = &[suite.version()];
        let mut client = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
            .with_no_client_auth();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let mut server = ServerConfig::builder_with_provider(Arc::new(server_provider))
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .unwrap();
        let logged = Arc::new(Logged::default());
        client.key_log = logged.clone();
        client.enable_early_data = early_data;
        if early_data {
            server.max_early_data_size = 16_384;
        }
        if let Some(protocol) = protocol {
            client.alpn_protocols = vec![protocol.to_vec()];
            server.alpn_protocols = vec![protocol.to_vec()];
        }
        Pair {
            client: Arc::new(client),
            server: Arc::new(server),
            logged,
        }
    }

    /// The bytes each side of one connection sent, in the flights they crossed in, and the plaintext each wrote.
    #[derive(Default)]
    struct Transcript {
        flights: Vec<(Direction, Vec<u8>)>,
        client_wrote: Vec<u8>,
        server_wrote: Vec<u8>,
        early_data_accepted: bool,
    }

    impl Transcript {
        /// Returns every byte the side sent.
        fn sent(&self, side: Direction) -> Vec<u8> {
            self.flights
                .iter()
                .filter(|(direction, _)| *direction == side)
                .flat_map(|(_, bytes)| bytes.clone())
                .collect()
        }
    }

    /// Moves what one side has to send to the other, returning whether there was anything.
    fn send<A, B>(
        from: &mut ConnectionCommon<A>,
        to: &mut ConnectionCommon<B>,
        direction: Direction,
        transcript: &mut Transcript,
    ) -> bool {
        let mut bytes = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut bytes).unwrap();
        }
        if bytes.is_empty() {
            return false;
        }
        let mut rest = bytes.as_slice();
        while !rest.is_empty() {
            to.read_tls(&mut rest).unwrap();
            to.process_new_packets().unwrap();
            to.reader().read_to_end(&mut Vec::new()).ok();
        }
        transcript.flights.push((direction, bytes));
        true
    }

    /// Moves bytes both ways until neither side has anything to send, and reads what each received.
    fn exchange(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
        transcript: &mut Transcript,
    ) {
        while send(&mut **client, &mut **server, Direction::Client, transcript)
            | send(&mut **server, &mut **client, Direction::Server, transcript)
        {}
        if let Some(mut early) = server.early_data() {
            early.read_to_end(&mut Vec::new()).ok();
        }
    }

    /// Returns bytes of a pattern that differs with the seed.
    fn payload(seed: u8, length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    /// Writes the bytes as application data on the side, noting them.
    fn write<D>(connection: &mut ConnectionCommon<D>, bytes: &[u8], wrote: &mut Vec<u8>) {
        connection.writer().write_all(bytes).unwrap();
        wrote.extend_from_slice(bytes);
    }

    /// Runs one connection: a handshake, then a request and a response each longer than a record.
    fn converse(pair: &Pair, early: Option<&[u8]>, key_update: bool) -> Transcript {
        let mut client =
            ClientConnection::new(pair.client.clone(), ServerName::try_from(HOST).unwrap())
                .unwrap();
        let mut server = ServerConnection::new(pair.server.clone()).unwrap();
        let mut transcript = Transcript::default();
        if let Some(early) = early {
            client
                .early_data()
                .expect("the session allows 0-RTT data")
                .write_all(early)
                .unwrap();
            transcript.client_wrote.extend_from_slice(early);
        }
        exchange(&mut client, &mut server, &mut transcript);
        transcript.early_data_accepted = client.is_early_data_accepted();
        write(
            &mut client,
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &mut transcript.client_wrote,
        );
        write(
            &mut client,
            &payload(1, 20_000),
            &mut transcript.client_wrote,
        );
        exchange(&mut client, &mut server, &mut transcript);
        write(
            &mut server,
            &payload(2, 40_000),
            &mut transcript.server_wrote,
        );
        exchange(&mut client, &mut server, &mut transcript);
        if key_update {
            client.refresh_traffic_keys().unwrap();
            write(
                &mut client,
                b"after the client's update",
                &mut transcript.client_wrote,
            );
            exchange(&mut client, &mut server, &mut transcript);
            server.refresh_traffic_keys().unwrap();
            write(
                &mut server,
                b"after the server's update",
                &mut transcript.server_wrote,
            );
            exchange(&mut client, &mut server, &mut transcript);
            client.refresh_traffic_keys().unwrap();
            write(
                &mut client,
                b"after a second update",
                &mut transcript.client_wrote,
            );
            exchange(&mut client, &mut server, &mut transcript);
        }
        transcript
    }

    /// The order a test feeds the two sides' bytes in.
    #[derive(Debug, Clone, Copy)]
    enum Order {
        AsSent,
        ClientFirst,
        ServerFirst,
    }

    /// A deterministic source of piece sizes.
    struct Pieces(u64);

    impl Pieces {
        /// Returns the next size, from one to the most.
        fn next(&mut self, most: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            1 + (self.0 % most as u64) as usize
        }
    }

    /// Feeds the flights to the connection in the order, in pieces of random sizes, returning what came out.
    fn feed(
        connection: &mut TlsConnection,
        flights: &[(Direction, Vec<u8>)],
        keys: &dyn Keys,
        order: Order,
        seed: u64,
    ) -> Vec<Decrypted> {
        let side = |side: Direction| {
            (
                side,
                flights
                    .iter()
                    .filter(|(direction, _)| *direction == side)
                    .flat_map(|(_, bytes)| bytes.clone())
                    .collect(),
            )
        };
        let flights = match order {
            Order::AsSent => flights.to_vec(),
            Order::ClientFirst => vec![side(Direction::Client), side(Direction::Server)],
            Order::ServerFirst => vec![side(Direction::Server), side(Direction::Client)],
        };
        let mut pieces = Pieces(seed);
        let mut decrypted = Vec::new();
        for (direction, bytes) in flights {
            let mut rest = bytes.as_slice();
            while !rest.is_empty() {
                let (piece, after) = rest.split_at(pieces.next(700).min(rest.len()));
                decrypted.extend(connection.decrypt(direction, piece, keys));
                rest = after;
            }
        }
        decrypted
    }

    /// Returns the plaintext the side sent, in order.
    fn plain(decrypted: &[Decrypted], side: Direction) -> Vec<u8> {
        let mut plain = Vec::new();
        for each in decrypted {
            if let Decrypted::Plain {
                direction,
                stream,
                bytes,
                fin,
            } = each
                && *direction == side
            {
                assert_eq!((*stream, *fin), (None, false));
                plain.extend_from_slice(bytes);
            }
        }
        plain
    }

    /// Returns the opaque bytes the side sent, in order.
    fn opaque(decrypted: &[Decrypted], side: Direction) -> Vec<u8> {
        let mut opaque = Vec::new();
        for each in decrypted {
            if let Decrypted::Opaque { direction, bytes } = each
                && *direction == side
            {
                opaque.extend_from_slice(bytes);
            }
        }
        opaque
    }

    /// Returns what came out, short enough for a failure message.
    fn summary(decrypted: &[Decrypted]) -> Vec<String> {
        decrypted
            .iter()
            .map(|each| match each {
                Decrypted::Agreed { protocol } => format!("Agreed {protocol:?}"),
                Decrypted::Plain {
                    direction, bytes, ..
                } => format!("Plain {direction:?} {}", bytes.len()),
                Decrypted::Opaque { direction, bytes } => {
                    format!("Opaque {direction:?} {}", bytes.len())
                }
                Decrypted::Fault { direction, detail } => format!("Fault {direction:?} {detail}"),
            })
            .collect()
    }

    /// Checks one agreement on the protocol came out before any plaintext.
    fn assert_agreed_once(decrypted: &[Decrypted], protocol: Option<&[u8]>) {
        let agreed: Vec<usize> = decrypted
            .iter()
            .enumerate()
            .filter(|(_, each)| matches!(each, Decrypted::Agreed { .. }))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(agreed.len(), 1, "{:?}", summary(decrypted));
        assert_eq!(
            decrypted[agreed[0]],
            Decrypted::Agreed {
                protocol: protocol.map(<[u8]>::to_vec)
            }
        );
        let first_plain = decrypted
            .iter()
            .position(|each| matches!(each, Decrypted::Plain { .. }));
        assert!(
            first_plain.is_none_or(|first| agreed[0] < first),
            "{:?}",
            summary(decrypted)
        );
    }

    /// Checks everything each side wrote came out, and nothing opaque.
    fn assert_decrypted(decrypted: &[Decrypted], transcript: &Transcript, protocol: Option<&[u8]>) {
        assert_agreed_once(decrypted, protocol);
        assert!(
            decrypted
                .iter()
                .all(|each| matches!(each, Decrypted::Agreed { .. } | Decrypted::Plain { .. })),
            "{:?}",
            summary(decrypted)
        );
        assert!(
            plain(decrypted, Direction::Client) == transcript.client_wrote,
            "the client's plaintext differs"
        );
        assert!(
            plain(decrypted, Direction::Server) == transcript.server_wrote,
            "the server's plaintext differs"
        );
    }

    /// Checks the transcript decrypts whole with the logged secrets, its bytes fed in several orders and piece sizes.
    fn assert_decrypts(pair: &Pair, transcript: &Transcript, protocol: Option<&[u8]>) {
        let (_folder, keys) = empty_keys();
        pair.logged.write_to(&keys);
        for (order, seed) in [
            (Order::AsSent, 1),
            (Order::AsSent, 2),
            (Order::ClientFirst, 3),
            (Order::ServerFirst, 4),
        ] {
            let mut connection = Tls.start_connection();
            let mut decrypted = feed(&mut connection, &transcript.flights, &keys, order, seed);
            assert!(
                !connection.is_waiting(),
                "{order:?}: {:?}",
                summary(&decrypted)
            );
            decrypted.extend(connection.finish());
            assert_decrypted(&decrypted, transcript, protocol);
            assert!(connection.finish().is_empty());
        }
    }

    /// Checks the bytes are whole records, none of them encrypted TLS 1.3 records.
    fn assert_clear_records(mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let Frame::Whole(length) = frame(bytes, true) else {
                panic!("not whole records")
            };
            assert_ne!(bytes[0], APPLICATION_DATA);
            bytes = &bytes[length..];
        }
    }

    #[test]
    fn decrypts_tls13_with_aes_128_gcm() {
        let pair = pair(
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            Some(H2),
            None,
            false,
        );
        assert_decrypts(&pair, &converse(&pair, None, false), Some(H2));
    }

    #[test]
    fn decrypts_tls13_with_aes_256_gcm_and_no_protocol() {
        let pair = pair(cipher_suite::TLS13_AES_256_GCM_SHA384, None, None, false);
        assert_decrypts(&pair, &converse(&pair, None, false), None);
    }

    #[test]
    fn decrypts_tls13_with_chacha20_poly1305() {
        let pair = pair(
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            Some(H2),
            None,
            false,
        );
        assert_decrypts(&pair, &converse(&pair, None, false), Some(H2));
    }

    #[test]
    fn decrypts_tls12_with_aes_128_gcm() {
        let pair = pair(
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            Some(b"http/1.1"),
            None,
            false,
        );
        assert_decrypts(&pair, &converse(&pair, None, false), Some(b"http/1.1"));
    }

    #[test]
    fn decrypts_tls12_with_aes_256_gcm_and_no_protocol() {
        let pair = pair(
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            None,
            None,
            false,
        );
        assert_decrypts(&pair, &converse(&pair, None, false), None);
    }

    #[test]
    fn decrypts_tls12_with_chacha20_poly1305() {
        let pair = pair(
            cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            Some(H2),
            None,
            false,
        );
        assert_decrypts(&pair, &converse(&pair, None, false), Some(H2));
    }

    #[test]
    fn follows_key_updates() {
        let pair = pair(
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            Some(H2),
            None,
            false,
        );
        assert_decrypts(&pair, &converse(&pair, None, true), Some(H2));
    }

    #[test]
    fn follows_a_hello_retry_request() {
        let pair = pair(
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            Some(H2),
            Some(vec![kx_group::SECP384R1]),
            false,
        );
        let transcript = converse(&pair, None, false);
        let (_, server_first) = &transcript.flights[1];
        assert_eq!(
            server_first[HEADER_SIZE + HANDSHAKE_HEADER_SIZE + size_of::<u16>()..][..RANDOM_SIZE],
            HELLO_RETRY_RANDOM
        );
        assert_decrypts(&pair, &transcript, Some(H2));
    }

    #[test]
    fn decrypts_a_resumed_tls12_session() {
        let pair = pair(
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            Some(H2),
            None,
            false,
        );
        converse(&pair, None, false);
        let resumed = converse(&pair, None, false);
        let (direction, server_first) = &resumed.flights[1];
        assert_eq!(*direction, Direction::Server);
        let Frame::Whole(server_hello) = frame(server_first, false) else {
            panic!("no first record")
        };
        assert_eq!(
            server_first[server_hello], CHANGE_CIPHER_SPEC,
            "the server did not resume"
        );
        assert_decrypts(&pair, &resumed, Some(H2));
    }

    #[test]
    fn decrypts_accepted_0rtt_data() {
        let pair = pair(cipher_suite::TLS13_AES_128_GCM_SHA256, Some(H2), None, true);
        converse(&pair, None, false);
        let resumed = converse(&pair, Some(b"early request"), false);
        assert!(resumed.early_data_accepted);
        assert_decrypts(&pair, &resumed, Some(H2));
    }

    #[test]
    fn decrypts_rejected_0rtt_data() {
        let pair = pair(
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            Some(H2),
            None,
            true,
        );
        converse(&pair, None, false);
        let mut rejecting = (*pair.server).clone();
        rejecting.max_early_data_size = 0;
        let rejecting = Pair {
            client: pair.client.clone(),
            server: Arc::new(rejecting),
            logged: pair.logged.clone(),
        };
        let resumed = converse(&rejecting, Some(b"early request"), false);
        assert!(!resumed.early_data_accepted);
        assert_decrypts(&pair, &resumed, Some(H2));
    }

    #[test]
    fn waits_for_secrets_logged_late() {
        for suite in [
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ] {
            let pair = pair(suite, Some(H2), None, false);
            let transcript = converse(&pair, None, false);
            let (_folder, keys) = empty_keys();
            let mut connection = Tls.start_connection();
            let mut decrypted = feed(
                &mut connection,
                &transcript.flights,
                &keys,
                Order::AsSent,
                5,
            );
            assert!(connection.is_waiting());
            assert!(
                decrypted
                    .iter()
                    .all(|each| matches!(each, Decrypted::Agreed { .. })),
                "{:?}",
                summary(&decrypted)
            );
            assert!(connection.retry(&keys).is_empty());
            pair.logged.write_to(&keys);
            decrypted.extend(connection.retry(&keys));
            assert!(!connection.is_waiting());
            decrypted.extend(connection.finish());
            assert_decrypted(&decrypted, &transcript, Some(H2));
        }
    }

    #[test]
    fn gives_up_with_every_held_byte_opaque() {
        let pair = pair(
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            Some(H2),
            None,
            false,
        );
        let transcript = converse(&pair, None, false);
        let (_folder, keys) = empty_keys();
        let mut connection = Tls.start_connection();
        let (before, after) = transcript.flights.split_at(2);
        let mut decrypted = feed(&mut connection, before, &keys, Order::AsSent, 6);
        assert!(connection.is_waiting());
        assert!(decrypted.is_empty(), "{:?}", summary(&decrypted));
        decrypted.extend(connection.give_up());
        assert!(!connection.is_waiting());
        let random = hex(&pair.logged.last_client_random());
        let fault = decrypted.iter().find_map(|each| match each {
            Decrypted::Fault { detail, .. } => Some(detail.clone()),
            _ => None,
        });
        assert!(
            fault.is_some_and(|detail| detail.contains(&random)),
            "{:?}",
            summary(&decrypted)
        );
        let given_up = decrypted.len();
        decrypted.extend(feed(&mut connection, after, &keys, Order::AsSent, 7));
        assert!(
            decrypted[given_up..]
                .iter()
                .all(|each| matches!(each, Decrypted::Opaque { .. } | Decrypted::Fault { .. }))
        );
        decrypted.extend(connection.finish());
        assert_agreed_once(&decrypted, None);
        for side in [Direction::Client, Direction::Server] {
            let sent = transcript.sent(side);
            let opaque = opaque(&decrypted, side);
            assert!(!opaque.is_empty() && sent.ends_with(&opaque));
            assert_clear_records(&sent[..sent.len() - opaque.len()]);
        }
        assert!(
            plain(&decrypted, Direction::Client).is_empty()
                && plain(&decrypted, Direction::Server).is_empty()
        );
    }

    #[test]
    fn finishes_with_a_cut_record_opaque() {
        let pair = pair(cipher_suite::TLS13_AES_128_GCM_SHA256, None, None, false);
        let mut transcript = converse(&pair, None, false);
        let (_folder, keys) = empty_keys();
        pair.logged.write_to(&keys);
        let (direction, last) = transcript.flights.last_mut().unwrap();
        assert_eq!(*direction, Direction::Server);
        last.truncate(last.len() - 3);
        let mut connection = Tls.start_connection();
        let mut decrypted = feed(
            &mut connection,
            &transcript.flights,
            &keys,
            Order::AsSent,
            8,
        );
        decrypted.extend(connection.finish());
        assert!(connection.finish().is_empty());
        assert_agreed_once(&decrypted, None);
        let sent = transcript.sent(Direction::Server);
        let opaque = opaque(&decrypted, Direction::Server);
        assert!(
            !opaque.is_empty()
                && opaque.len() <= HEADER_SIZE + MAX_FRAGMENT
                && sent.ends_with(&opaque)
        );
        assert!(
            transcript
                .server_wrote
                .starts_with(&plain(&decrypted, Direction::Server))
        );
        assert!(plain(&decrypted, Direction::Client) == transcript.client_wrote);
    }

    #[test]
    fn faults_on_a_record_that_does_not_decrypt() {
        let pair = pair(
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            None,
            None,
            false,
        );
        let mut transcript = converse(&pair, None, false);
        let (_folder, keys) = empty_keys();
        pair.logged.write_to(&keys);
        let (_, last) = transcript.flights.last_mut().unwrap();
        last[HEADER_SIZE + GCM_EXPLICIT_SIZE] ^= 1;
        let tampered = last.clone();
        let mut connection = Tls.start_connection();
        let mut decrypted = feed(
            &mut connection,
            &transcript.flights,
            &keys,
            Order::AsSent,
            9,
        );
        decrypted.extend(connection.finish());
        assert!(decrypted.iter().any(|each| matches!(
            each,
            Decrypted::Fault {
                direction: Direction::Server,
                ..
            }
        )));
        assert!(opaque(&decrypted, Direction::Server) == tampered);
        assert!(plain(&decrypted, Direction::Client) == transcript.client_wrote);
    }

    /// The TLS 1.2 handshake and records of a made-up connection, under a CBC suite this test seals itself.
    struct Made {
        flights: Vec<(Direction, Vec<u8>)>,
        client_random: [u8; RANDOM_SIZE],
        master: Vec<u8>,
        client_wrote: Vec<u8>,
        server_wrote: Vec<u8>,
    }

    /// Returns a record of the type around the body.
    fn record(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut record = vec![kind];
        record.extend(TLS12.to_be_bytes());
        record.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
        record.extend(body);
        record
    }

    /// Returns a handshake message of the type around the body.
    fn message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut message = vec![kind];
        message.extend(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        message.extend(body);
        message
    }

    /// Returns a TLS 1.2 ClientHello or ServerHello record offering or choosing the suite.
    fn hello(kind: u8, random: &[u8], suite: u16, extensions: &[u8]) -> Vec<u8> {
        let mut body = TLS12.to_be_bytes().to_vec();
        body.extend(random);
        body.push(0);
        if kind == CLIENT_HELLO {
            body.extend(2u16.to_be_bytes());
            body.extend(suite.to_be_bytes());
            body.extend([1, 0]);
        } else {
            body.extend(suite.to_be_bytes());
            body.push(0);
        }
        body.extend(u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend(extensions);
        record(HANDSHAKE, &message(kind, &body))
    }

    /// One side's CBC sealing, as a TLS 1.2 peer does it.
    struct Sealer {
        key: Vec<u8>,
        mac: hmac::Key,
        encrypt_then_mac: bool,
        sequence: u64,
    }

    impl Sealer {
        /// Returns the plaintext CBC-encrypted under the IV.
        fn encrypt(&self, iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
            let mut sealed = plaintext.to_vec();
            let mut previous = iv.to_vec();
            for block in sealed.chunks_exact_mut(BLOCK_SIZE) {
                for (byte, chained) in block.iter_mut().zip(&previous) {
                    *byte ^= chained;
                }
                let array = aes::Block::from_mut_slice(block);
                match self.key.len() {
                    16 => Aes128::new_from_slice(&self.key)
                        .unwrap()
                        .encrypt_block(array),
                    _ => Aes256::new_from_slice(&self.key)
                        .unwrap()
                        .encrypt_block(array),
                }
                previous = block.to_vec();
            }
            sealed
        }

        /// Returns the content padded to whole blocks, with a block more of padding on odd sequence numbers.
        fn pad(&self, content: &[u8]) -> Vec<u8> {
            let extra = if self.sequence % 2 == 1 {
                BLOCK_SIZE
            } else {
                0
            };
            let padding = BLOCK_SIZE - 1 - content.len() % BLOCK_SIZE + extra;
            let mut padded = content.to_vec();
            padded.extend(std::iter::repeat_n(padding as u8, padding + 1));
            padded
        }

        /// Returns the record of the type around the content, sealed.
        fn seal(&mut self, kind: u8, content: &[u8]) -> Vec<u8> {
            let iv = [self.sequence as u8 ^ 0x5A; BLOCK_SIZE];
            let kind_and_version = [&[kind][..], &TLS12.to_be_bytes()].concat();
            let fragment = if self.encrypt_then_mac {
                let mut sealed = iv.to_vec();
                sealed.extend(self.encrypt(&iv, &self.pad(content)));
                let mut covered =
                    additional_data(self.sequence, &kind_and_version, sealed.len()).unwrap();
                covered.extend(&sealed);
                sealed.extend(hmac::sign(&self.mac, &covered).as_ref());
                sealed
            } else {
                let mut covered =
                    additional_data(self.sequence, &kind_and_version, content.len()).unwrap();
                covered.extend(content);
                let mut plaintext = content.to_vec();
                plaintext.extend(hmac::sign(&self.mac, &covered).as_ref());
                let mut sealed = iv.to_vec();
                sealed.extend(self.encrypt(&iv, &self.pad(&plaintext)));
                sealed
            };
            self.sequence += 1;
            record(kind, &fragment)
        }
    }

    /// Returns a whole made-up TLS 1.2 connection under the suite, sealed with CBC if it is a CBC suite.
    fn made_up(suite: u16, encrypt_then_mac: bool) -> Made {
        let client_random = [0x11; RANDOM_SIZE];
        let server_random = [0x22; RANDOM_SIZE];
        let master = payload(3, 48);
        let extensions: &[u8] = if encrypt_then_mac {
            &[0, 22, 0, 0]
        } else {
            &[]
        };
        let (mac_size, key_size, _) =
            suite12(suite).map_or((32, 16, 0), |known| known.bulk.sizes());
        let prf_hash = suite12(suite).map_or(hmac::HMAC_SHA256, |known| known.prf);
        let seed = [server_random, client_random].concat();
        let block = prf(
            prf_hash,
            &master,
            KEY_EXPANSION,
            &seed,
            (mac_size + key_size) * SIDES,
        );
        let mac_algorithm = match mac_size {
            20 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            32 => hmac::HMAC_SHA256,
            _ => hmac::HMAC_SHA384,
        };
        let sealer = |mac: &[u8], key: &[u8]| Sealer {
            key: key.to_vec(),
            mac: hmac::Key::new(mac_algorithm, mac),
            encrypt_then_mac,
            sequence: 0,
        };
        let mut client = sealer(&block[..mac_size], &block[mac_size * 2..][..key_size]);
        let mut server = sealer(
            &block[mac_size..][..mac_size],
            &block[mac_size * 2 + key_size..][..key_size],
        );
        let finished = message(FINISHED, &[0x33; 12]);
        let change = record(CHANGE_CIPHER_SPEC, &[1]);
        let client_wrote = payload(4, 3_000);
        let server_wrote = [b"server first".to_vec(), payload(5, 17_000)].concat();
        let mut server_flight = hello(SERVER_HELLO, &server_random, suite, extensions);
        server_flight.extend(&change);
        server_flight.extend(server.seal(HANDSHAKE, &finished));
        server_flight.extend(server.seal(APPLICATION_DATA, b"server first"));
        let mut client_flight = change.clone();
        client_flight.extend(client.seal(HANDSHAKE, &finished));
        client_flight.extend(client.seal(APPLICATION_DATA, &[]));
        client_flight.extend(client.seal(APPLICATION_DATA, &client_wrote));
        let mut last = Vec::new();
        for chunk in server_wrote[b"server first".len()..].chunks(16_384) {
            last.extend(server.seal(APPLICATION_DATA, chunk));
        }
        last.extend(server.seal(ALERT, &[1, 0]));
        let flights = vec![
            (
                Direction::Client,
                hello(CLIENT_HELLO, &client_random, suite, extensions),
            ),
            (Direction::Server, server_flight),
            (Direction::Client, client_flight),
            (Direction::Server, last),
        ];
        Made {
            flights,
            client_random,
            master,
            client_wrote,
            server_wrote,
        }
    }

    #[test]
    fn decrypts_tls12_with_cbc() {
        let suites = [
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        ];
        for (suite, encrypt_then_mac) in suites
            .into_iter()
            .flat_map(|suite| [(suite, false), (suite, true)])
        {
            let made = made_up(suite, encrypt_then_mac);
            let (_folder, keys) = empty_keys();
            keys.record(CLIENT_RANDOM, &made.client_random, &made.master)
                .unwrap();
            let transcript = Transcript {
                flights: made.flights,
                client_wrote: made.client_wrote,
                server_wrote: made.server_wrote,
                early_data_accepted: false,
            };
            for (order, seed) in [(Order::AsSent, 10), (Order::ClientFirst, 11)] {
                let mut connection = Tls.start_connection();
                let mut decrypted = feed(&mut connection, &transcript.flights, &keys, order, seed);
                decrypted.extend(connection.finish());
                assert_decrypted(&decrypted, &transcript, None);
            }
        }
    }

    #[test]
    fn faults_on_an_unsupported_suite() {
        let ccm = 0xC0AC;
        let made = made_up(ccm, false);
        let (_folder, keys) = empty_keys();
        keys.record(CLIENT_RANDOM, &made.client_random, &made.master)
            .unwrap();
        let mut connection = Tls.start_connection();
        let mut decrypted = feed(&mut connection, &made.flights, &keys, Order::AsSent, 12);
        decrypted.extend(connection.finish());
        assert_agreed_once(&decrypted, None);
        for side in [Direction::Client, Direction::Server] {
            let fault = decrypted.iter().any(|each| matches!(each, Decrypted::Fault { direction, detail } if *direction == side && detail.contains("0xc0ac")));
            assert!(fault, "{:?}", summary(&decrypted));
            let sent: Vec<u8> = made
                .flights
                .iter()
                .filter(|(direction, _)| *direction == side)
                .flat_map(|(_, bytes)| bytes.clone())
                .collect();
            let opaque = opaque(&decrypted, side);
            assert!(sent.ends_with(&opaque) && opaque.len() > HEADER_SIZE);
        }
    }
}
