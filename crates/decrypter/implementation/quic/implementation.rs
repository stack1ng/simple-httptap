//! A decrypter of the QUIC packets in one flow's UDP datagrams, versions 1 and 2, with the secrets of a key log.
//!
//! It follows the handshake only as far as the client random, the cipher suite and the ALPN, and puts each side's
//! streams back in order. A datagram that needs what it has not seen yet waits, in order, where it stopped.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::mem;

use ring::aead::quic::{self as protection, HeaderProtectionKey};
use ring::aead::{self, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hkdf::{self, KeyType};
use simple_httptap_decoder::Direction;
use simple_httptap_decrypter::{ConnectionDecrypter, Decrypted, Decrypter};
use simple_httptap_keylog::{
    CLIENT_EARLY_TRAFFIC_SECRET, CLIENT_HANDSHAKE_TRAFFIC_SECRET, CLIENT_TRAFFIC_SECRET_0, Keys,
    SERVER_HANDSHAKE_TRAFFIC_SECRET, SERVER_TRAFFIC_SECRET_0,
};

/// The decrypter of QUIC versions 1 and 2 in UDP datagrams.
#[derive(Debug)]
pub struct Quic;

impl Decrypter for Quic {
    type Connection = QuicConnection;

    fn start_connection(&self) -> QuicConnection {
        QuicConnection(Connection::default())
    }
}

/// A decrypter of the datagrams of one QUIC flow, both ways.
#[derive(Debug)]
pub struct QuicConnection(Connection);

impl ConnectionDecrypter for QuicConnection {
    fn decrypt(&mut self, direction: Direction, bytes: &[u8], keys: &impl Keys) -> Vec<Decrypted> {
        self.0.decrypt(direction, bytes, keys)
    }

    fn retry(&mut self, keys: &impl Keys) -> Vec<Decrypted> {
        self.0.retry(keys)
    }

    fn awaits_secret(&self) -> bool {
        self.0.awaits_secret()
    }

    fn give_up(&mut self) -> Vec<Decrypted> {
        self.0.give_up()
    }

    fn finish(&mut self) -> Vec<Decrypted> {
        self.0.finish()
    }
}

/// QUIC version 1.
///
/// https://www.rfc-editor.org/rfc/rfc9001#section-5.2
const VERSION_1: Version = Version {
    number: 0x0000_0001,
    salt: &[
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ],
    labels: Labels {
        key: "quic key",
        iv: "quic iv",
        hp: "quic hp",
        ku: "quic ku",
    },
    types: &[
        LongType::Initial,
        LongType::ZeroRtt,
        LongType::Handshake,
        LongType::Retry,
    ],
};
/// QUIC version 2, version 1 with another number, salt, labels and order of long-header types.
///
/// https://www.rfc-editor.org/rfc/rfc9369#section-3
const VERSION_2: Version = Version {
    number: 0x6b33_43cf,
    salt: &[
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
        0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    ],
    labels: Labels {
        key: "quicv2 key",
        iv: "quicv2 iv",
        hp: "quicv2 hp",
        ku: "quicv2 ku",
    },
    types: &[
        LongType::Retry,
        LongType::Initial,
        LongType::ZeroRtt,
        LongType::Handshake,
    ],
};
/// The version field of a Version Negotiation packet.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
const VERSION_NEGOTIATION: u32 = u32::MIN;
/// The bit of the first byte that marks a long header.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-17.2
const LONG_FORM: u8 = 0x80;
/// The bits of a long header's first byte that give its packet type.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-17.2
const LONG_TYPE: u8 = 0x30;
/// The bits of the first byte that header protection hides in a long header.
///
/// https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1
const LONG_PROTECTED: u8 = 0x0f;
/// The bits of the first byte that header protection hides in a short header.
///
/// https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1
const SHORT_PROTECTED: u8 = 0x1f;
/// The bits of the first byte, once unprotected, that give the packet number's length less one.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-17.2
const NUMBER_LENGTH: u8 = 0x03;
/// The bit of a short header's first byte, once unprotected, that says which generation of keys sealed it.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-17.3.1
const KEY_PHASE: u8 = 0x04;
/// The bytes of the longest packet number, which the header protection sample always skips.
///
/// https://www.rfc-editor.org/rfc/rfc9001#section-5.4.2
const MAX_NUMBER_LENGTH: usize = size_of::<u32>();
/// The longest connection ID versions 1 and 2 allow.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-17.2
const MAX_CONNECTION_ID: usize = 20;
/// One more than the largest packet number.
///
/// https://www.rfc-editor.org/rfc/rfc9000#appendix-A.3
const NUMBER_LIMIT: u64 = 1 << 62;
/// The bits of a variable-length integer's first byte that are value; the two above give its length.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-16
const VARINT_VALUE: u8 = 0x3f;
/// The label of the client's Initial secret.
///
/// https://www.rfc-editor.org/rfc/rfc9001#section-5.2
const CLIENT_INITIAL: &str = "client in";
/// The label of the server's Initial secret.
///
/// https://www.rfc-editor.org/rfc/rfc9001#section-5.2
const SERVER_INITIAL: &str = "server in";
/// What TLS 1.3 puts before every HKDF label.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-7.1
const HKDF_LABEL_PREFIX: &str = "tls13 ";
/// The context of every label QUIC expands, empty, as its one length byte.
///
/// https://www.rfc-editor.org/rfc/rfc9001#section-5.1
const NO_CONTEXT: &[u8] = &[u8::MIN];
/// The cipher suite TLS_AES_128_GCM_SHA256, which also protects Initial packets.
///
/// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4
const AES_128_GCM_SHA256: u16 = 0x1301;
/// The cipher suite TLS_AES_256_GCM_SHA384.
///
/// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4
const AES_256_GCM_SHA384: u16 = 0x1302;
/// The cipher suite TLS_CHACHA20_POLY1305_SHA256.
///
/// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4
const CHACHA20_POLY1305_SHA256: u16 = 0x1303;
/// The handshake type of a ClientHello, which a client sends in Initial packets.
///
/// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.3
const CLIENT_HELLO_TYPE: u8 = 1;
/// The handshake type of a ServerHello, which a server sends in Initial packets.
///
/// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.3
const SERVER_HELLO_TYPE: u8 = 2;
/// The handshake type of EncryptedExtensions, which a server sends in Handshake packets.
///
/// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.3
const ENCRYPTED_EXTENSIONS_TYPE: u8 = 8;
/// The bytes of a handshake message's length.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4
const MESSAGE_LENGTH: usize = 3;
/// The bytes of a hello's random.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
const RANDOM: usize = 32;
/// The type of the ALPN extension.
///
/// https://www.rfc-editor.org/rfc/rfc7301#section-3.1
const ALPN: u16 = 16;
/// The frames made of variable-length integers alone, none of which matters here, by type, with how many.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19
/// https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency-11#section-4
const INTEGER_FRAMES: &[(u64, usize)] = &[
    (0x00, 0),
    (0x01, 0),
    (0x05, 2),
    (0x10, 1),
    (0x11, 2),
    (0x12, 1),
    (0x13, 1),
    (0x14, 1),
    (0x15, 2),
    (0x16, 1),
    (0x17, 1),
    (0x19, 1),
    (0x1e, 0),
    (0x1f, 0),
    (0xaf, 4),
];
/// The type of an ACK frame.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.3
const ACK: u64 = 0x02;
/// The type of an ACK frame with ECN counts.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.3
const ACK_ECN: u64 = 0x03;
/// The ECN counts an ACK_ECN frame adds.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.3.2
const ECN_COUNTS: usize = 3;
/// The type of a RESET_STREAM frame.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.4
const RESET_STREAM: u64 = 0x04;
/// The type of a CRYPTO frame.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.6
const CRYPTO: u64 = 0x06;
/// The type of a NEW_TOKEN frame.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.7
const NEW_TOKEN: u64 = 0x07;
/// The first type of a STREAM frame; the three bits below are its flags.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.8
const STREAM: u64 = 0x08;
/// The flag of a STREAM frame that has an offset.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.8
const STREAM_OFFSET: u64 = 0x04;
/// The flag of a STREAM frame that has a length; without it the data takes the rest of the packet.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.8
const STREAM_LENGTH: u64 = 0x02;
/// The flag of a STREAM frame that ends its stream.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.8
const STREAM_FIN: u64 = 0x01;
/// The highest STREAM frame type, with the offset, length and FIN flags all set, which ends the STREAM type range.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.8
const STREAM_LAST: u64 = STREAM | STREAM_OFFSET | STREAM_LENGTH | STREAM_FIN;
/// The type of a NEW_CONNECTION_ID frame.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.15
const NEW_CONNECTION_ID: u64 = 0x18;
/// The bytes of the stateless reset token a NEW_CONNECTION_ID frame ends with.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.15
const RESET_TOKEN: usize = 16;
/// The type of a PATH_CHALLENGE frame.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.17
const PATH_CHALLENGE: u64 = 0x1a;
/// The frame type that echoes a PATH_CHALLENGE's data back, skipped as its challenge is.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.18
const PATH_RESPONSE: u64 = 0x1b;
/// The bytes of a PATH_CHALLENGE or PATH_RESPONSE frame's data.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.17
const PATH_DATA: usize = 8;
/// The type of a CONNECTION_CLOSE frame for a transport error.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.19
const TRANSPORT_CLOSE: u64 = 0x1c;
/// The type of a CONNECTION_CLOSE frame for an application's error.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19.19
const APPLICATION_CLOSE: u64 = 0x1d;
/// The transport error code of a close without an error.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-20.1
const NO_ERROR: u64 = u64::MIN;
/// The type of a DATAGRAM frame that takes the rest of the packet.
///
/// https://www.rfc-editor.org/rfc/rfc9221#section-4
const DATAGRAM: u64 = 0x30;
/// The type of a DATAGRAM frame with a length.
///
/// https://www.rfc-editor.org/rfc/rfc9221#section-4
const DATAGRAM_LENGTH: u64 = 0x31;
/// What a datagram waits for when a server packet comes before the client's first Initial.
const NO_CLIENT_INITIAL: &str =
    "the client's first Initial packet, whose connection ID the Initial keys come from";
/// What a datagram waits for before its secrets can be looked up.
const NO_CLIENT_HELLO: &str = "the ClientHello, whose client random names the secrets";
/// What a datagram waits for before keys can be made from its secret.
const NO_SERVER_HELLO: &str = "the ServerHello, which names the cipher suite";
/// What a short header waits for when the other side issued no connection ID it knows.
const NO_CONNECTION_ID: &str =
    "a connection ID the other side issued, which short headers start with";

/// A QUIC version's number and what differs between versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Version {
    number: u32,
    /// The salt of the HKDF-Extract that makes the Initial secret.
    salt: &'static [u8],
    labels: Labels,
    /// The long-header packet types, by the value of their type bits.
    types: &'static [LongType],
}

/// A version's HKDF labels for a secret's key, IV, header protection key and next-generation secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Labels {
    key: &'static str,
    iv: &'static str,
    hp: &'static str,
    ku: &'static str,
}

/// A type of long-header packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LongType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

/// A long-header packet that carries frames, by its keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Initial,
    ZeroRtt,
    Handshake,
}

/// A packet number space, numbered and acknowledged on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Space {
    Initial,
    Handshake,
    Application,
}

impl Kind {
    /// Returns the packet number space packets of the kind are numbered in.
    fn space(self) -> Space {
        match self {
            Kind::Initial => Space::Initial,
            Kind::Handshake => Space::Handshake,
            Kind::ZeroRtt => Space::Application,
        }
    }
}

/// The algorithms of a TLS 1.3 cipher suite: its AEAD, its header protection and its hash.
#[derive(Debug, Clone, Copy)]
struct Suite {
    aead: &'static aead::Algorithm,
    protection: &'static protection::Algorithm,
    hash: hkdf::Algorithm,
}

/// Returns the algorithms of a cipher suite QUIC uses, by its TLS code point.
fn suite(code: u16) -> Option<Suite> {
    let (aead, protection, hash) = match code {
        AES_128_GCM_SHA256 => (&aead::AES_128_GCM, &protection::AES_128, hkdf::HKDF_SHA256),
        AES_256_GCM_SHA384 => (&aead::AES_256_GCM, &protection::AES_256, hkdf::HKDF_SHA384),
        CHACHA20_POLY1305_SHA256 => (
            &aead::CHACHA20_POLY1305,
            &protection::CHACHA20,
            hkdf::HKDF_SHA256,
        ),
        _ => return None,
    };
    Some(Suite {
        aead,
        protection,
        hash,
    })
}

/// An output length for HKDF-Expand.
struct Length(usize);

impl KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

/// Returns HKDF-Expand-Label of a secret with an empty context.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-7.1
fn expand(secret: &hkdf::Prk, label: &str, length: usize) -> Option<Vec<u8>> {
    let length_bytes = u16::try_from(length).ok()?.to_be_bytes();
    let label_length = [u8::try_from(HKDF_LABEL_PREFIX.len() + label.len()).ok()?];
    let info = [
        &length_bytes[..],
        &label_length,
        HKDF_LABEL_PREFIX.as_bytes(),
        label.as_bytes(),
        NO_CONTEXT,
    ];
    let mut output = vec![u8::MIN; length];
    secret
        .expand(&info, Length(length))
        .ok()?
        .fill(&mut output)
        .ok()?;
    Some(output)
}

/// Returns HKDF-Expand-Label of a secret's bytes with the suite's hash.
fn expand_secret(suite: Suite, secret: &[u8], label: &str, length: usize) -> Option<Vec<u8>> {
    expand(&hkdf::Prk::new_less_safe(suite.hash, secret), label, length)
}

/// A packet protection key and the IV its nonces come from.
#[derive(Debug)]
struct Aead {
    key: LessSafeKey,
    iv: [u8; NONCE_LEN],
}

impl Aead {
    /// Makes the key and IV of a secret.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9001#section-5.1
    fn derive(suite: Suite, version: Version, secret: &[u8]) -> Option<Self> {
        let key = expand_secret(suite, secret, version.labels.key, suite.aead.key_len())?;
        let iv = expand_secret(suite, secret, version.labels.iv, NONCE_LEN)?;
        Some(Self {
            key: LessSafeKey::new(UnboundKey::new(suite.aead, &key).ok()?),
            iv: iv.try_into().ok()?,
        })
    }

    /// Returns the plaintext of an unprotected packet, or none if these keys did not seal it.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9001#section-5.3
    fn open(&self, packet: &Unprotected) -> Option<Vec<u8>> {
        let (header, sealed) = packet.bytes.split_at(packet.header);
        let mut nonce = self.iv;
        for (byte, number) in nonce.iter_mut().rev().zip(packet.number.to_le_bytes()) {
            *byte ^= number;
        }
        let mut payload = sealed.to_vec();
        let length = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(header),
                &mut payload,
            )
            .ok()?
            .len();
        payload.truncate(length);
        Some(payload)
    }
}

/// A header protection key, which says which algorithm it is when printed.
struct Protection(HeaderProtectionKey);

impl fmt::Debug for Protection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.algorithm().fmt(formatter)
    }
}

impl Protection {
    /// Makes the header protection key of a secret.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9001#section-5.4
    fn derive(suite: Suite, version: Version, secret: &[u8]) -> Option<Self> {
        let key = expand_secret(suite, secret, version.labels.hp, suite.protection.key_len())?;
        Some(Self(HeaderProtectionKey::new(suite.protection, &key).ok()?))
    }
}

/// A packet with its header protection removed: its bytes, where its header ends, and its full packet number.
#[derive(Debug)]
struct Unprotected {
    bytes: Vec<u8>,
    header: usize,
    number: u64,
}

/// Returns a copy of the packet with its header protection removed, its packet number decoded against the largest.
///
/// https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1
fn unprotect(
    packet: &[u8],
    number_at: usize,
    hidden: u8,
    protection: &Protection,
    largest: Option<u64>,
) -> Option<Unprotected> {
    let sample_at = number_at.checked_add(MAX_NUMBER_LENGTH)?;
    let sample =
        packet.get(sample_at..sample_at.checked_add(protection.0.algorithm().sample_len())?)?;
    let [first_mask, number_masks @ ..] = protection.0.new_mask(sample).ok()?;
    let mut bytes = packet.to_vec();
    let first = bytes.first_mut()?;
    *first ^= first_mask & hidden;
    let length = usize::from(*first & NUMBER_LENGTH) + 1;
    let header = number_at + length;
    let mut truncated = u64::MIN;
    for (byte, mask) in bytes
        .get_mut(number_at..header)?
        .iter_mut()
        .zip(number_masks)
    {
        *byte ^= mask;
        truncated = truncated << u8::BITS | u64::from(*byte);
    }
    Some(Unprotected {
        bytes,
        header,
        number: decode_number(largest, truncated, length),
    })
}

/// Returns the full packet number closest to the one after the largest that ends in the truncated one.
///
/// https://www.rfc-editor.org/rfc/rfc9000#appendix-A.3
fn decode_number(largest: Option<u64>, truncated: u64, length: usize) -> u64 {
    let expected = largest.map_or(u64::MIN, |largest| largest + 1);
    let bits = u32::try_from(length)
        .unwrap_or(u32::MAX)
        .saturating_mul(u8::BITS);
    let window = 1u64.checked_shl(bits).unwrap_or(NUMBER_LIMIT);
    let half = window >> 1;
    let candidate = (expected & !(window - 1)) | truncated;
    if candidate + half <= expected && candidate < NUMBER_LIMIT.saturating_sub(window) {
        candidate + window
    } else if candidate > expected + half && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

/// The keys of one side's packets of a kind: packet protection and header protection.
#[derive(Debug)]
struct PacketKeys {
    aead: Aead,
    protection: Protection,
}

impl PacketKeys {
    /// Makes the keys of a secret.
    fn derive(suite: Suite, version: Version, secret: &[u8]) -> Option<Self> {
        Some(Self {
            aead: Aead::derive(suite, version, secret)?,
            protection: Protection::derive(suite, version, secret)?,
        })
    }

    /// Returns the packet number and plaintext of a long-header packet, or none if these keys did not seal it.
    fn open(
        &self,
        packet: &[u8],
        number_at: usize,
        largest: Option<u64>,
    ) -> Option<(u64, Vec<u8>)> {
        let unprotected = unprotect(packet, number_at, LONG_PROTECTED, &self.protection, largest)?;
        Some((unprotected.number, self.aead.open(&unprotected)?))
    }
}

/// Both sides' Initial keys for one version and one connection ID.
#[derive(Debug)]
struct InitialKeys {
    version: u32,
    id: Vec<u8>,
    client: PacketKeys,
    server: PacketKeys,
}

impl InitialKeys {
    /// Makes both sides' Initial keys from the connection ID the client's first Initial went to.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9001#section-5.2
    fn derive(version: Version, id: &[u8]) -> Option<Self> {
        let suite = suite(AES_128_GCM_SHA256)?;
        let initial = hkdf::Salt::new(suite.hash, version.salt).extract(id);
        let client = expand(&initial, CLIENT_INITIAL, suite.hash.len())?;
        let server = expand(&initial, SERVER_INITIAL, suite.hash.len())?;
        Some(Self {
            version: version.number,
            id: id.to_vec(),
            client: PacketKeys::derive(suite, version, &client)?,
            server: PacketKeys::derive(suite, version, &server)?,
        })
    }
}

/// One side's 1-RTT keys: the header protection key that stays, and the generations of packet keys around the current.
#[derive(Debug)]
struct Application {
    suite: Suite,
    version: Version,
    protection: Protection,
    current: Generation,
    /// The generation before, for packets that come late.
    previous: Option<Generation>,
    /// The generation after, made when first tried.
    next: Option<Generation>,
}

/// One generation of 1-RTT packet keys.
#[derive(Debug)]
struct Generation {
    secret: Vec<u8>,
    aead: Aead,
    /// How many key updates came before it.
    count: u64,
    /// The smallest packet number it opened.
    first: Option<u64>,
}

impl Generation {
    /// Returns the key phase bit of packets this generation sealed.
    fn phase(&self) -> bool {
        self.count & 1 == 1
    }

    /// Returns the plaintext of a packet, noting its number, or none if this generation did not seal it.
    fn open(&mut self, packet: &Unprotected) -> Option<Vec<u8>> {
        let plain = self.aead.open(packet)?;
        self.first = Some(
            self.first
                .map_or(packet.number, |first| first.min(packet.number)),
        );
        Some(plain)
    }
}

impl Application {
    /// Makes the first generation of a side's 1-RTT keys.
    fn new(suite: Suite, version: Version, secret: Vec<u8>) -> Option<Self> {
        let protection = Protection::derive(suite, version, &secret)?;
        let aead = Aead::derive(suite, version, &secret)?;
        let current = Generation {
            secret,
            aead,
            count: u64::MIN,
            first: None,
        };
        Some(Self {
            suite,
            version,
            protection,
            current,
            previous: None,
            next: None,
        })
    }

    /// Returns the generation after the current one.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9001#section-6.1
    fn update(&self) -> Option<Generation> {
        let secret = expand_secret(
            self.suite,
            &self.current.secret,
            self.version.labels.ku,
            self.suite.hash.len(),
        )?;
        let aead = Aead::derive(self.suite, self.version, &secret)?;
        Some(Generation {
            secret,
            aead,
            count: self.current.count + 1,
            first: None,
        })
    }

    /// Returns the plaintext of a 1-RTT packet, moving to the next generation of keys if it was sealed with them.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9001#section-6.3
    fn open(&mut self, packet: &Unprotected) -> Option<Vec<u8>> {
        let phase = packet.bytes.first()? & KEY_PHASE != u8::MIN;
        if phase == self.current.phase() {
            return self.current.open(packet);
        }
        let late = self
            .current
            .first
            .is_some_and(|first| packet.number < first);
        if late
            && let Some(plain) = self
                .previous
                .as_mut()
                .and_then(|previous| previous.open(packet))
        {
            return Some(plain);
        }
        if self.next.is_none() {
            self.next = self.update();
        }
        if let Some(plain) = self.next.as_mut().and_then(|next| next.open(packet)) {
            let next = self.next.take()?;
            self.previous = Some(mem::replace(&mut self.current, next));
            return Some(plain);
        }
        if late {
            return None;
        }
        self.previous
            .as_mut()
            .and_then(|previous| previous.open(packet))
    }
}

/// The bytes of a stream or of CRYPTO frames, put back in order from frames that may come late, twice or overlapping.
#[derive(Debug, Default)]
struct Reassembly {
    /// How many bytes from the start were handed over.
    delivered: u64,
    /// The bytes after a gap, by offset.
    waiting: BTreeMap<u64, Vec<u8>>,
    /// The stream's final size, once a frame ended it.
    end: Option<u64>,
    /// Whether the end was handed over.
    ended: bool,
}

impl Reassembly {
    /// Adds bytes at an offset and returns those that now follow on from what was handed over, each once.
    fn insert(&mut self, offset: u64, bytes: &[u8]) -> Vec<u8> {
        let end = offset.saturating_add(bytes.len() as u64);
        if end > self.delivered && !bytes.is_empty() {
            let skip = usize::try_from(self.delivered.saturating_sub(offset)).unwrap_or(usize::MAX);
            let start = offset.max(self.delivered);
            let kept = &bytes[skip.min(bytes.len())..];
            let longer = self
                .waiting
                .get(&start)
                .is_none_or(|waiting| waiting.len() < kept.len());
            if longer {
                self.waiting.insert(start, kept.to_vec());
            }
        }
        let mut ready = Vec::new();
        while let Some(entry) = self.waiting.first_entry() {
            if *entry.key() > self.delivered {
                break;
            }
            let (start, chunk) = entry.remove_entry();
            let skip = usize::try_from(self.delivered - start).unwrap_or(usize::MAX);
            if let Some(new) = chunk.get(skip..) {
                ready.extend_from_slice(new);
                self.delivered += new.len() as u64;
            }
        }
        ready
    }

    /// Returns whether the stream's end is reached and not handed over yet, marking it handed over.
    fn take_end(&mut self) -> bool {
        let reached = !self.ended && self.end == Some(self.delivered);
        self.ended |= reached;
        reached
    }

    /// Returns whether bytes past a gap, or a final size not reached, were left over.
    fn has_gap(&self) -> bool {
        !self.waiting.is_empty() || self.end.is_some_and(|end| end != self.delivered)
    }
}

/// The handshake bytes one side sent in a space, and those of a message not whole yet.
#[derive(Debug, Default)]
struct Handshake {
    reassembly: Reassembly,
    buffer: Vec<u8>,
}

/// The state of one side's sending: its keys, each space's largest packet number, its handshake and its streams.
#[derive(Debug, Default)]
struct Side {
    /// The largest packet number it decrypted in each space.
    largest: BTreeMap<Space, u64>,
    crypto: BTreeMap<Space, Handshake>,
    handshake: Option<PacketKeys>,
    early: Option<PacketKeys>,
    application: Option<Application>,
    /// The connection IDs this side issued, which the other side's short headers start with.
    issued: Vec<Vec<u8>>,
    streams: BTreeMap<u64, Reassembly>,
    /// The streams it reset, whose later data is ignored.
    reset: BTreeSet<u64>,
}

/// A datagram not wholly read yet, and where it stopped.
#[derive(Debug)]
struct Held {
    direction: Direction,
    bytes: Vec<u8>,
    /// Where the next packet starts; the packets before it were read.
    at: usize,
    /// Whether it comes back opaque, as one of its packets could not be read.
    opaque: bool,
    wait: Option<Wait>,
}

/// The cause of a held datagram's wait: a missing secret or something not shown yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Wait {
    /// A secret the key log lacks, by label.
    Secret(&'static str),
    /// Something the connection has not shown yet, as packets came out of order.
    Later(&'static str),
}

/// The outcome for a packet that cannot be read now: a wait, or a failure that makes it opaque.
#[derive(Debug)]
enum Unread {
    Wait(Wait),
    /// It cannot be decrypted, for the reason.
    Failed(String),
}

/// A packet's header as far as it can be read under header protection, or why the bytes are not read as one.
#[derive(Debug)]
enum Parsed<'a> {
    Long(Long<'a>),
    /// A short-header packet, which takes the rest of the datagram, with the lengths its connection ID may have.
    Short {
        lengths: Vec<usize>,
    },
    /// A Retry, which takes the rest of the datagram and changes the Initial keys.
    Retry {
        scid: &'a [u8],
    },
    /// Bytes it does not decrypt, with the fault that says why, if one should.
    Opaque(Option<String>),
    Wait(Wait),
}

/// A long-header packet with frames: its version, its kind, where its packet number starts and where it ends.
#[derive(Debug)]
struct Long<'a> {
    version: Version,
    kind: Kind,
    dcid: &'a [u8],
    number_at: usize,
    end: usize,
}

/// A decrypted frame, reduced to the fields that carry plaintext, keys, resets, connection IDs or closes.
#[derive(Debug)]
enum Frame<'a> {
    Ignored,
    Crypto {
        offset: u64,
        data: &'a [u8],
    },
    Stream {
        id: u64,
        offset: u64,
        data: &'a [u8],
        fin: bool,
    },
    Reset {
        id: u64,
        code: u64,
    },
    NewConnectionId(&'a [u8]),
    Close {
        transport: bool,
        code: u64,
        reason: &'a [u8],
    },
    Datagram(&'a [u8]),
    Unknown(u64),
}

/// A reader of big-endian numbers, variable-length integers and runs of bytes from the front of a slice.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// Takes the next bytes.
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (taken, rest) = self.0.split_at_checked(count)?;
        self.0 = rest;
        Some(taken)
    }

    /// Takes a big-endian number of the size.
    fn number(&mut self, size: usize) -> Option<u64> {
        Some(
            self.take(size)?
                .iter()
                .fold(u64::MIN, |value, byte| value << u8::BITS | u64::from(*byte)),
        )
    }

    /// Takes a byte.
    fn u8(&mut self) -> Option<u8> {
        u8::try_from(self.number(size_of::<u8>())?).ok()
    }

    /// Takes a big-endian u16.
    fn u16(&mut self) -> Option<u16> {
        u16::try_from(self.number(size_of::<u16>())?).ok()
    }

    /// Takes a variable-length integer.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9000#section-16
    fn varint(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let length = 1usize << (first >> VARINT_VALUE.count_ones());
        let rest = self.number(length - 1)?;
        Some(u64::from(first & VARINT_VALUE) << ((length - 1) as u32 * u8::BITS) | rest)
    }

    /// Takes a variable-length integer and as many bytes as it says.
    fn varint_bytes(&mut self) -> Option<&'a [u8]> {
        let length = usize::try_from(self.varint()?).ok()?;
        self.take(length)
    }

    /// Takes a byte and as many bytes as it says.
    fn u8_bytes(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }

    /// Takes a big-endian u16 and as many bytes as it says.
    fn u16_bytes(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }

    /// Takes a long header's connection ID, which a byte gives the length of.
    fn connection_id(&mut self) -> Option<&'a [u8]> {
        self.u8_bytes().filter(|id| id.len() <= MAX_CONNECTION_ID)
    }

    /// Takes everything left.
    fn rest(&mut self) -> &'a [u8] {
        mem::take(&mut self.0)
    }
}

/// Returns a frame's fields after its type, or none if the packet ends inside it.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-19
fn read_frame<'a>(kind: u64, reader: &mut Reader<'a>) -> Option<Frame<'a>> {
    let frame = match kind {
        ACK | ACK_ECN => {
            let (_largest, _delay, ranges, _first) = (
                reader.varint()?,
                reader.varint()?,
                reader.varint()?,
                reader.varint()?,
            );
            for _ in u64::MIN..ranges {
                reader.varint()?;
                reader.varint()?;
            }
            if kind == ACK_ECN {
                for _ in usize::MIN..ECN_COUNTS {
                    reader.varint()?;
                }
            }
            Frame::Ignored
        }
        RESET_STREAM => {
            let (id, code, _size) = (reader.varint()?, reader.varint()?, reader.varint()?);
            Frame::Reset { id, code }
        }
        CRYPTO => Frame::Crypto {
            offset: reader.varint()?,
            data: reader.varint_bytes()?,
        },
        NEW_TOKEN => {
            reader.varint_bytes()?;
            Frame::Ignored
        }
        STREAM..=STREAM_LAST => {
            let id = reader.varint()?;
            let offset = if kind & STREAM_OFFSET == u64::MIN {
                u64::MIN
            } else {
                reader.varint()?
            };
            let data = if kind & STREAM_LENGTH == u64::MIN {
                reader.rest()
            } else {
                reader.varint_bytes()?
            };
            Frame::Stream {
                id,
                offset,
                data,
                fin: kind & STREAM_FIN != u64::MIN,
            }
        }
        NEW_CONNECTION_ID => {
            let (_sequence, _retire) = (reader.varint()?, reader.varint()?);
            let id = reader.connection_id()?;
            reader.take(RESET_TOKEN)?;
            Frame::NewConnectionId(id)
        }
        PATH_CHALLENGE | PATH_RESPONSE => {
            reader.take(PATH_DATA)?;
            Frame::Ignored
        }
        TRANSPORT_CLOSE | APPLICATION_CLOSE => {
            let code = reader.varint()?;
            if kind == TRANSPORT_CLOSE {
                reader.varint()?;
            }
            Frame::Close {
                transport: kind == TRANSPORT_CLOSE,
                code,
                reason: reader.varint_bytes()?,
            }
        }
        DATAGRAM => Frame::Datagram(reader.rest()),
        DATAGRAM_LENGTH => Frame::Datagram(reader.varint_bytes()?),
        _ => {
            let Some(&(_, count)) = INTEGER_FRAMES.iter().find(|(known, _)| *known == kind) else {
                return Some(Frame::Unknown(kind));
            };
            for _ in usize::MIN..count {
                reader.varint()?;
            }
            Frame::Ignored
        }
    };
    Some(frame)
}

/// Returns the side that sent the other way.
fn other(direction: Direction) -> Direction {
    match direction {
        Direction::Client => Direction::Server,
        Direction::Server => Direction::Client,
    }
}

/// Returns the bytes as lower-case hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The state of one flow so far: its handshake, each side's keys and streams, and the datagrams it holds.
#[derive(Debug, Default)]
struct Connection {
    /// The version the server last sent a long header in, or else the client.
    version: Option<Version>,
    /// The connection IDs Initial keys may come from, likeliest first: a Retry's, then those the client's Initials went to.
    initial_ids: Vec<Vec<u8>>,
    initial_keys: Vec<InitialKeys>,
    client_random: Option<Vec<u8>>,
    suite: Option<Suite>,
    agreed: bool,
    /// Plaintext that waits for the agreement, which comes before it.
    unagreed: Vec<Decrypted>,
    client: Side,
    server: Side,
    held: VecDeque<Held>,
    /// The labels of the secrets the key log lacked during this call, so each is looked up once a call.
    absent: BTreeSet<&'static str>,
    /// How many times it learned something that may let a held datagram go on.
    learned: u64,
    gave_up: bool,
    finished: bool,
    /// Whether a fault said the flow's version is one it does not decrypt.
    told_version: bool,
}

impl Connection {
    /// Reads one datagram after those it holds and returns what they gave.
    fn decrypt(&mut self, direction: Direction, bytes: &[u8], keys: &impl Keys) -> Vec<Decrypted> {
        let mut out = Vec::new();
        if self.finished || bytes.is_empty() {
            return out;
        }
        self.held.push_back(Held {
            direction,
            bytes: bytes.to_vec(),
            at: usize::MIN,
            opaque: false,
            wait: None,
        });
        self.absent.clear();
        self.drain(keys, &mut out);
        out
    }

    /// Tries the datagrams it holds again and returns what they gave.
    fn retry(&mut self, keys: &impl Keys) -> Vec<Decrypted> {
        let mut out = Vec::new();
        if !self.finished {
            self.absent.clear();
            self.drain(keys, &mut out);
        }
        out
    }

    /// Returns whether a datagram it holds waits for a secret.
    fn awaits_secret(&self) -> bool {
        !self.gave_up
            && self
                .held
                .iter()
                .any(|held| matches!(held.wait, Some(Wait::Secret(_))))
    }

    /// Hands back the datagrams that wait for secrets opaque, and from now on those that need a missing one.
    fn give_up(&mut self) -> Vec<Decrypted> {
        let mut out = Vec::new();
        if self.finished {
            return out;
        }
        self.gave_up = true;
        if self
            .held
            .iter()
            .any(|held| matches!(held.wait, Some(Wait::Secret(_))))
        {
            self.agree(None, &mut out);
            self.release(|wait| matches!(wait, Some(Wait::Secret(_))), &mut out);
        }
        out
    }

    /// Hands back everything it holds opaque, says what streams were left with gaps, and stops.
    fn finish(&mut self) -> Vec<Decrypted> {
        let mut out = Vec::new();
        if self.finished {
            return out;
        }
        self.finished = true;
        self.agree(None, &mut out);
        self.release(|_| true, &mut out);
        for (direction, side) in [
            (Direction::Client, &self.client),
            (Direction::Server, &self.server),
        ] {
            for (id, stream) in &side.streams {
                if stream.has_gap() {
                    let detail = format!(
                        "stream {id} ended with a gap after byte {} that never filled",
                        stream.delivered
                    );
                    out.push(Decrypted::Fault { direction, detail });
                }
            }
        }
        out
    }

    /// Hands back the held datagrams the filter picks, opaque, after faults that say what they waited for.
    fn release(&mut self, picked: impl Fn(Option<Wait>) -> bool, out: &mut Vec<Decrypted>) {
        let (released, kept): (Vec<Held>, Vec<Held>) = mem::take(&mut self.held)
            .into_iter()
            .partition(|held| picked(held.wait));
        self.held = kept.into();
        let random = self.client_random.as_deref().map(hex).unwrap_or_default();
        for direction in [Direction::Client, Direction::Server] {
            let waits: BTreeSet<Wait> = released
                .iter()
                .filter(|held| held.direction == direction)
                .filter_map(|held| held.wait)
                .collect();
            let secrets: Vec<&str> = waits
                .iter()
                .filter_map(|wait| {
                    if let Wait::Secret(label) = wait {
                        Some(*label)
                    } else {
                        None
                    }
                })
                .collect();
            if !secrets.is_empty() {
                let detail = format!("the key log has no {secrets:?} for client random {random}");
                out.push(Decrypted::Fault { direction, detail });
            }
            for wait in &waits {
                if let Wait::Later(what) = wait {
                    out.push(Decrypted::Fault {
                        direction,
                        detail: format!("the connection closed before {what} came"),
                    });
                }
            }
        }
        out.extend(released.into_iter().map(|held| Decrypted::Opaque {
            direction: held.direction,
            bytes: held.bytes,
        }));
    }

    /// Reads the held datagrams in order, again while anything moved on.
    fn drain(&mut self, keys: &dyn Keys, out: &mut Vec<Decrypted>) {
        loop {
            let learned = self.learned;
            let mut moved = false;
            let mut index = usize::MIN;
            while let Some(mut held) = self.held.remove(index) {
                let absent =
                    matches!(held.wait, Some(Wait::Secret(label)) if self.absent.contains(label));
                let at = held.at;
                if !absent && self.advance(&mut held, keys, out) {
                    moved = true;
                    continue;
                }
                moved |= held.at != at;
                self.held.insert(index, held);
                index += 1;
            }
            if !moved && learned == self.learned {
                return;
            }
        }
    }

    /// Reads a datagram's packets from where it stopped, returning whether it is done; if not, it says what it waits for.
    fn advance(&mut self, held: &mut Held, keys: &dyn Keys, out: &mut Vec<Decrypted>) -> bool {
        let direction = held.direction;
        held.wait = None;
        while let Some(rest) = held.bytes.get(held.at..).filter(|rest| !rest.is_empty()) {
            if held.at > usize::MIN && rest.iter().all(|byte| *byte == u8::MIN) {
                break;
            }
            let (end, read) = match self.parse(direction, rest) {
                Parsed::Long(long) => (
                    long.end,
                    self.read_long(direction, &rest[..long.end], &long, keys, out),
                ),
                Parsed::Short { lengths } => (
                    rest.len(),
                    self.read_short(direction, rest, &lengths, keys, out),
                ),
                Parsed::Retry { scid } => {
                    if direction == Direction::Server {
                        self.retried(scid);
                    }
                    held.opaque = true;
                    break;
                }
                Parsed::Opaque(fault) => {
                    let trailing = (held.at > usize::MIN).then(|| TRAILING.to_owned());
                    if let Some(detail) = fault.or(trailing) {
                        out.push(Decrypted::Fault { direction, detail });
                    }
                    held.opaque = true;
                    break;
                }
                Parsed::Wait(wait) => (usize::MIN, Err(Unread::Wait(wait))),
            };
            match read {
                Ok(()) => {}
                Err(Unread::Wait(Wait::Secret(_))) if self.gave_up => held.opaque = true,
                Err(Unread::Wait(wait)) => {
                    held.wait = Some(wait);
                    return false;
                }
                Err(Unread::Failed(detail)) => {
                    out.push(Decrypted::Fault { direction, detail });
                    held.opaque = true;
                }
            }
            held.at += end;
        }
        if held.opaque {
            out.push(Decrypted::Opaque {
                direction,
                bytes: mem::take(&mut held.bytes),
            });
        }
        true
    }

    /// Reads the header of the packet the bytes start with, learning the version and connection ID a long one has.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9000#section-17
    fn parse<'a>(&mut self, direction: Direction, bytes: &'a [u8]) -> Parsed<'a> {
        let mut reader = Reader(bytes);
        let Some(first) = reader.u8() else {
            return Parsed::Opaque(None);
        };
        if first & LONG_FORM == u8::MIN {
            return self.parse_short(direction, bytes);
        }
        let Some(number) = reader.number(size_of::<u32>()) else {
            return Parsed::Opaque(None);
        };
        if number == u64::from(VERSION_NEGOTIATION) {
            return Parsed::Opaque(None);
        }
        let Some(version) = [VERSION_1, VERSION_2]
            .into_iter()
            .find(|version| u64::from(version.number) == number)
        else {
            let told = mem::replace(&mut self.told_version, true);
            return Parsed::Opaque(
                (!told).then(|| format!("QUIC version 0x{number:08x} is not one it decrypts")),
            );
        };
        self.parse_long(direction, version, first, reader, bytes)
            .unwrap_or_else(|| Parsed::Opaque(Some(CUT_HEADER.to_owned())))
    }

    /// Reads the rest of a long header of a version it decrypts.
    fn parse_long<'a>(
        &mut self,
        direction: Direction,
        version: Version,
        first: u8,
        mut reader: Reader<'a>,
        bytes: &'a [u8],
    ) -> Option<Parsed<'a>> {
        let dcid = reader.connection_id()?;
        let scid = reader.connection_id()?;
        if self.version != Some(version)
            && (direction == Direction::Server || self.version.is_none())
        {
            self.version = Some(version);
            self.learned += 1;
        }
        self.issued(direction, scid);
        let kind = match version.types.get(usize::from(
            (first & LONG_TYPE) >> LONG_TYPE.trailing_zeros(),
        ))? {
            LongType::Retry => return Some(Parsed::Retry { scid }),
            LongType::Initial => {
                reader.varint_bytes()?;
                Kind::Initial
            }
            LongType::ZeroRtt => Kind::ZeroRtt,
            LongType::Handshake => Kind::Handshake,
        };
        let length = usize::try_from(reader.varint()?).ok()?;
        let number_at = bytes.len() - reader.0.len();
        let end = number_at
            .checked_add(length)
            .filter(|end| *end <= bytes.len())?;
        Some(Parsed::Long(Long {
            version,
            kind,
            dcid,
            number_at,
            end,
        }))
    }

    /// Reads a short header, whose connection ID is one the other side issued, of a length it must know.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9000#section-17.3.1
    fn parse_short<'a>(&self, direction: Direction, bytes: &[u8]) -> Parsed<'a> {
        if self.version.is_none() {
            return Parsed::Opaque(None);
        }
        let issued = &self.side(other(direction)).issued;
        let after_first = bytes.get(size_of::<u8>()..).unwrap_or_default();
        let mut lengths: Vec<usize> = issued
            .iter()
            .filter(|id| after_first.starts_with(id))
            .map(Vec::len)
            .collect();
        if lengths.is_empty() {
            lengths = issued.iter().map(Vec::len).collect();
        }
        if lengths.is_empty() {
            return Parsed::Wait(Wait::Later(NO_CONNECTION_ID));
        }
        lengths.sort_unstable_by(|one, other| other.cmp(one));
        lengths.dedup();
        Parsed::Short { lengths }
    }

    /// Notes a connection ID the side issued.
    fn issued(&mut self, direction: Direction, id: &[u8]) {
        let side = self.side_mut(direction);
        if !side.issued.iter().any(|issued| issued == id) {
            side.issued.push(id.to_vec());
            self.learned += 1;
        }
    }

    /// Makes the connection ID a server's Retry gave the one Initial keys come from first.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9001#section-5.2
    fn retried(&mut self, scid: &[u8]) {
        if self.initial_ids.first().is_some_and(|id| id == scid) {
            return;
        }
        self.initial_ids.retain(|id| id != scid);
        self.initial_ids.insert(usize::MIN, scid.to_vec());
        self.learned += 1;
    }

    /// Decrypts a long-header packet and reads its frames.
    fn read_long(
        &mut self,
        direction: Direction,
        packet: &[u8],
        long: &Long<'_>,
        keys: &dyn Keys,
        out: &mut Vec<Decrypted>,
    ) -> Result<(), Unread> {
        let Long {
            version,
            kind,
            dcid,
            number_at,
            ..
        } = *long;
        let space = kind.space();
        let largest = self.side(direction).largest.get(&space).copied();
        let opened = match kind {
            Kind::Initial => {
                if direction == Direction::Client && !self.initial_ids.iter().any(|id| id == dcid) {
                    self.initial_ids.push(dcid.to_vec());
                    self.learned += 1;
                }
                if self.initial_ids.is_empty() {
                    return Err(Unread::Wait(Wait::Later(NO_CLIENT_INITIAL)));
                }
                self.open_initial(direction, version, packet, number_at, largest)
            }
            Kind::Handshake => self
                .load_handshake_keys(direction, version, keys)?
                .open(packet, number_at, largest),
            Kind::ZeroRtt if direction == Direction::Client => self
                .early_keys(version, keys)?
                .open(packet, number_at, largest),
            Kind::ZeroRtt => None,
        };
        let Some((number, plain)) = opened else {
            if kind == Kind::Initial && !self.client.largest.contains_key(&Space::Initial) {
                return Err(Unread::Wait(Wait::Later(NO_CLIENT_INITIAL)));
            }
            return Err(Unread::Failed(format!(
                "an {kind:?} packet its keys do not open"
            )));
        };
        let side = self.side_mut(direction);
        side.largest
            .insert(space, largest.map_or(number, |largest| largest.max(number)));
        self.read_frames(direction, space, &plain, out);
        Ok(())
    }

    /// Returns the number and plaintext of an Initial packet, trying the keys of each connection ID they may come from.
    fn open_initial(
        &mut self,
        direction: Direction,
        version: Version,
        packet: &[u8],
        number_at: usize,
        largest: Option<u64>,
    ) -> Option<(u64, Vec<u8>)> {
        for index in usize::MIN..self.initial_ids.len() {
            let id = &self.initial_ids[index];
            let found = self
                .initial_keys
                .iter()
                .position(|keys| keys.version == version.number && keys.id == *id);
            let position = match found {
                Some(position) => position,
                None => {
                    let derived = InitialKeys::derive(version, id)?;
                    self.initial_keys.push(derived);
                    self.initial_keys.len() - 1
                }
            };
            let initial = &self.initial_keys[position];
            let keys = match direction {
                Direction::Client => &initial.client,
                Direction::Server => &initial.server,
            };
            if let Some(opened) = keys.open(packet, number_at, largest) {
                return Some(opened);
            }
        }
        None
    }

    /// Returns the secret under the label for this connection, or what it waits for before it has it.
    fn secret(&mut self, label: &'static str, keys: &dyn Keys) -> Result<(Suite, Vec<u8>), Unread> {
        let random = self
            .client_random
            .as_ref()
            .ok_or(Unread::Wait(Wait::Later(NO_CLIENT_HELLO)))?;
        let suite = self
            .suite
            .ok_or(Unread::Wait(Wait::Later(NO_SERVER_HELLO)))?;
        if self.absent.contains(label) {
            return Err(Unread::Wait(Wait::Secret(label)));
        }
        let Some(secret) = keys.secret(label, random) else {
            self.absent.insert(label);
            return Err(Unread::Wait(Wait::Secret(label)));
        };
        Ok((suite, secret))
    }

    /// Returns a side's Handshake keys, making them from the key log the first time.
    fn load_handshake_keys(
        &mut self,
        direction: Direction,
        version: Version,
        keys: &dyn Keys,
    ) -> Result<&PacketKeys, Unread> {
        if self.side(direction).handshake.is_none() {
            let label = match direction {
                Direction::Client => CLIENT_HANDSHAKE_TRAFFIC_SECRET,
                Direction::Server => SERVER_HANDSHAKE_TRAFFIC_SECRET,
            };
            let (suite, secret) = self.secret(label, keys)?;
            self.side_mut(direction).handshake = PacketKeys::derive(suite, version, &secret);
        }
        self.side(direction)
            .handshake
            .as_ref()
            .ok_or_else(|| Unread::Failed(NO_KEYS.to_owned()))
    }

    /// Returns the client's 0-RTT keys, making them from the key log the first time.
    fn early_keys(&mut self, version: Version, keys: &dyn Keys) -> Result<&PacketKeys, Unread> {
        if self.client.early.is_none() {
            let (suite, secret) = self.secret(CLIENT_EARLY_TRAFFIC_SECRET, keys)?;
            self.client.early = PacketKeys::derive(suite, version, &secret);
        }
        self.client
            .early
            .as_ref()
            .ok_or_else(|| Unread::Failed(NO_KEYS.to_owned()))
    }

    /// Decrypts a short-header packet, trying each length its connection ID may have, and reads its frames.
    fn read_short(
        &mut self,
        direction: Direction,
        packet: &[u8],
        lengths: &[usize],
        keys: &dyn Keys,
        out: &mut Vec<Decrypted>,
    ) -> Result<(), Unread> {
        let version = self
            .version
            .ok_or(Unread::Wait(Wait::Later(NO_CLIENT_INITIAL)))?;
        if self.side(direction).application.is_none() {
            let label = match direction {
                Direction::Client => CLIENT_TRAFFIC_SECRET_0,
                Direction::Server => SERVER_TRAFFIC_SECRET_0,
            };
            let (suite, secret) = self.secret(label, keys)?;
            let application = Application::new(suite, version, secret);
            self.side_mut(direction).application =
                Some(application.ok_or_else(|| Unread::Failed(NO_KEYS.to_owned()))?);
        }
        let side = self.side_mut(direction);
        let largest = side.largest.get(&Space::Application).copied();
        let Some(application) = side.application.as_mut() else {
            return Ok(());
        };
        for length in lengths {
            let number_at = size_of::<u8>() + length;
            let Some(unprotected) = unprotect(
                packet,
                number_at,
                SHORT_PROTECTED,
                &application.protection,
                largest,
            ) else {
                continue;
            };
            if let Some(plain) = application.open(&unprotected) {
                side.largest.insert(
                    Space::Application,
                    largest.map_or(unprotected.number, |largest| {
                        largest.max(unprotected.number)
                    }),
                );
                self.read_frames(direction, Space::Application, &plain, out);
                return Ok(());
            }
        }
        let count = application.current.count;
        Err(Unread::Failed(format!(
            "a 1-RTT packet that key generation {count} and those next to it do not open"
        )))
    }

    /// Reads the frames of a decrypted packet, stopping with a fault at one it cannot read.
    fn read_frames(
        &mut self,
        direction: Direction,
        space: Space,
        payload: &[u8],
        out: &mut Vec<Decrypted>,
    ) {
        let mut reader = Reader(payload);
        while !reader.0.is_empty() {
            let Some(kind) = reader.varint() else {
                out.push(Decrypted::Fault {
                    direction,
                    detail: CUT_FRAME_TYPE.to_owned(),
                });
                return;
            };
            let frame = read_frame(kind, &mut reader);
            let result = match frame {
                Some(frame) => self.apply(direction, space, frame, out),
                None => Err(format!("a frame of type 0x{kind:x} cut short")),
            };
            if let Err(detail) = result {
                out.push(Decrypted::Fault {
                    direction,
                    detail: format!("{detail}; the rest of the packet is skipped"),
                });
                return;
            }
        }
    }

    /// Acts on one frame the side sent.
    fn apply(
        &mut self,
        direction: Direction,
        space: Space,
        frame: Frame<'_>,
        out: &mut Vec<Decrypted>,
    ) -> Result<(), String> {
        match frame {
            Frame::Ignored => {}
            Frame::Crypto { offset, data } => {
                self.read_crypto(direction, space, offset, data, out)?
            }
            Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => self.read_stream(direction, id, offset, data, fin, out),
            Frame::Reset { id, code } => {
                let side = self.side_mut(direction);
                side.streams.remove(&id);
                if side.reset.insert(id) {
                    out.push(Decrypted::Fault {
                        direction,
                        detail: format!("stream {id} was reset with error code 0x{code:x}"),
                    });
                }
            }
            Frame::NewConnectionId(id) => self.issued(direction, id),
            Frame::Close {
                transport,
                code,
                reason,
            } => {
                if transport && code != NO_ERROR {
                    let reason = String::from_utf8_lossy(reason);
                    let detail =
                        format!("closed the connection with transport error 0x{code:x}: {reason}");
                    out.push(Decrypted::Fault { direction, detail });
                }
            }
            Frame::Datagram(data) => self.hand_over(
                Decrypted::Plain {
                    direction,
                    stream: None,
                    bytes: data.to_vec(),
                    fin: false,
                },
                out,
            ),
            Frame::Unknown(kind) => return Err(format!("a frame of unknown type 0x{kind:x}")),
        }
        Ok(())
    }

    /// Hands over the stream bytes that now follow on from those before, and its end once reached.
    fn read_stream(
        &mut self,
        direction: Direction,
        id: u64,
        offset: u64,
        data: &[u8],
        fin: bool,
        out: &mut Vec<Decrypted>,
    ) {
        let side = self.side_mut(direction);
        if side.reset.contains(&id) {
            return;
        }
        let stream = side.streams.entry(id).or_default();
        if fin && stream.end.is_none() {
            stream.end = Some(offset.saturating_add(data.len() as u64));
        }
        let bytes = stream.insert(offset, data);
        let fin = stream.take_end();
        if !bytes.is_empty() || fin {
            self.hand_over(
                Decrypted::Plain {
                    direction,
                    stream: Some(id),
                    bytes,
                    fin,
                },
                out,
            );
        }
    }

    /// Puts CRYPTO bytes back in order and reads the handshake messages it needs from them.
    fn read_crypto(
        &mut self,
        direction: Direction,
        space: Space,
        offset: u64,
        data: &[u8],
        out: &mut Vec<Decrypted>,
    ) -> Result<(), String> {
        if !self.wants(direction, space) {
            return Ok(());
        }
        let handshake = self.side_mut(direction).crypto.entry(space).or_default();
        let ready = handshake.reassembly.insert(offset, data);
        handshake.buffer.extend(ready);
        while self.wants(direction, space) {
            let handshake = self.side_mut(direction).crypto.entry(space).or_default();
            let Some((kind, body)) = take_message(&mut handshake.buffer) else {
                break;
            };
            self.read_message(direction, space, kind, &body, out)?;
        }
        Ok(())
    }

    /// Returns whether it still needs handshake messages the side sends in the space.
    fn wants(&self, direction: Direction, space: Space) -> bool {
        match (direction, space) {
            (Direction::Client, Space::Initial) => self.client_random.is_none(),
            (Direction::Server, Space::Initial) => true,
            (Direction::Server, Space::Handshake) => !self.agreed,
            _ => false,
        }
    }

    /// Learns the client random, the cipher suite or the ALPN from a handshake message.
    ///
    /// https://www.rfc-editor.org/rfc/rfc8446#section-4
    fn read_message(
        &mut self,
        direction: Direction,
        space: Space,
        kind: u8,
        body: &[u8],
        out: &mut Vec<Decrypted>,
    ) -> Result<(), String> {
        let mut reader = Reader(body);
        match (direction, space, kind) {
            (Direction::Client, Space::Initial, CLIENT_HELLO_TYPE) => {
                reader.u16().ok_or(CUT_HELLO)?;
                self.client_random = Some(reader.take(RANDOM).ok_or(CUT_HELLO)?.to_vec());
                self.learned += 1;
            }
            (Direction::Server, Space::Initial, SERVER_HELLO_TYPE) => {
                let code = server_hello_suite(&mut reader).ok_or(CUT_HELLO)?;
                self.suite = Some(suite(code).ok_or_else(|| {
                    format!("the server chose cipher suite 0x{code:04x}, which QUIC does not use")
                })?);
                self.learned += 1;
            }
            (Direction::Server, Space::Handshake, ENCRYPTED_EXTENSIONS_TYPE) => {
                let protocol =
                    alpn(&mut reader).ok_or("an EncryptedExtensions message cut short")?;
                self.agree(protocol, out);
            }
            _ => {}
        }
        Ok(())
    }

    /// Says what protocol the connection agreed on, the first time, and hands over the plaintext that waited for it.
    fn agree(&mut self, protocol: Option<Vec<u8>>, out: &mut Vec<Decrypted>) {
        if !mem::replace(&mut self.agreed, true) {
            out.push(Decrypted::Agreed { protocol });
            out.append(&mut self.unagreed);
        }
    }

    /// Hands over plaintext, or keeps it until the connection agreed on a protocol.
    fn hand_over(&mut self, plain: Decrypted, out: &mut Vec<Decrypted>) {
        if self.agreed {
            out.push(plain);
        } else {
            self.unagreed.push(plain);
        }
    }

    /// Returns what the side sent.
    fn side(&self, direction: Direction) -> &Side {
        match direction {
            Direction::Client => &self.client,
            Direction::Server => &self.server,
        }
    }

    /// Returns the client's or the server's state, whichever sent in the direction, for updating it.
    fn side_mut(&mut self, direction: Direction) -> &mut Side {
        match direction {
            Direction::Client => &mut self.client,
            Direction::Server => &mut self.server,
        }
    }
}

/// The fault of a hello too short for the field it is read for.
const CUT_HELLO: &str = "a hello message cut short";
/// The fault of bytes after a datagram's packets that are neither padding nor a packet.
const TRAILING: &str = "bytes after the datagram's packets that are no QUIC packet";
/// The fault of a long header that the datagram ends inside.
const CUT_HEADER: &str = "a long header cut short";
/// The fault of a packet that ends inside a frame's type.
const CUT_FRAME_TYPE: &str = "a frame type cut short";
/// The fault of a secret that keys cannot be made from, as it is not as long as its hash.
const NO_KEYS: &str = "no keys could be made from the key log's secret";

/// Takes a whole handshake message from the front of the bytes, returning its type and body.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4
fn take_message(buffer: &mut Vec<u8>) -> Option<(u8, Vec<u8>)> {
    let mut reader = Reader(buffer);
    let kind = reader.u8()?;
    let length = usize::try_from(reader.number(MESSAGE_LENGTH)?).ok()?;
    let body = reader.take(length)?.to_vec();
    buffer.drain(..size_of::<u8>() + MESSAGE_LENGTH + length);
    Some((kind, body))
}

/// Returns the cipher suite a ServerHello's body names.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3
fn server_hello_suite(reader: &mut Reader<'_>) -> Option<u16> {
    reader.u16()?;
    reader.take(RANDOM)?;
    reader.u8_bytes()?;
    reader.u16()
}

/// Returns the protocol an EncryptedExtensions body's ALPN extension names, or none without one.
///
/// https://www.rfc-editor.org/rfc/rfc7301#section-3.1
fn alpn(reader: &mut Reader<'_>) -> Option<Option<Vec<u8>>> {
    let mut extensions = Reader(reader.u16_bytes()?);
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.u16_bytes()?;
        if kind == ALPN {
            let mut names = Reader(Reader(data).u16_bytes()?);
            return Some(Some(names.u8_bytes()?.to_vec()));
        }
    }
    Some(None)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
