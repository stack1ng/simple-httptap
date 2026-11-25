//! The watching of one connection's bytes: decrypted with the key log where they are TLS or QUIC, then decoded.
//!
//! Every connection, whichever way its secrets came, goes through here, so all are read the same way.

use std::sync::Arc;
use std::time::{Duration, Instant};

use simple_httptap_decoder::{ConnectionDecoder, Decoded, Decoder, Direction};
use simple_httptap_decoder_http1::Http1;
use simple_httptap_decoder_http2::Http2;
use simple_httptap_decoder_http3::Http3;
use simple_httptap_decrypter::{ConnectionDecrypter, Decrypted, Decrypter};
use simple_httptap_decrypter_quic::Quic;
use simple_httptap_decrypter_tls::Tls;
use simple_httptap_sink::{Connection, Event, Transport};
use tokio::sync::mpsc;

use crate::Shared;

/// How often a connection that waits for a secret looks in the key log again.
///
/// https://docs.rs/tokio/latest/tokio/time/fn.timeout.html
const RETRY_INTERVAL: Duration = Duration::from_millis(25);
/// How long a connection waits for a secret before it gives up and reports its bytes as they are.
///
/// https://doc.rust-lang.org/std/time/struct.Instant.html#method.elapsed
const SECRET_WAIT: Duration = Duration::from_secs(5);
/// The record type a TLS connection starts with, a handshake.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-5.1
const TLS_HANDSHAKE: u8 = 22;
/// The bit of a QUIC long header, which every packet that starts a connection has.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-17.2
const QUIC_LONG_HEADER: u8 = 0x80;
/// The bit set in every QUIC version 1 and 2 packet.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-17.2
const QUIC_FIXED_BIT: u8 = 0x40;
/// The bytes of a long header's first byte and version.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-17.2
const QUIC_VERSION_END: usize = 5;
/// The QUIC versions this proxy decrypts: 1, and 2.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-15, https://www.rfc-editor.org/rfc/rfc9369#section-3.1
const QUIC_VERSIONS: [[u8; 4]; 2] = [[0x00, 0x00, 0x00, 0x01], [0x6b, 0x33, 0x43, 0xcf]];
/// The least a client's first datagram may be, padded so, which no DNS query or other short datagram is.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-14.1
const QUIC_FIRST_DATAGRAM: usize = 1200;
/// What every HTTP/2 client sends first without TLS, with prior knowledge.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-3.4
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0";
/// The application protocol name of HTTP/2.
const HTTP2: &[u8] = b"h2";
/// The application protocol name of HTTP/3.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-3.1
pub(crate) const HTTP3: &[u8] = b"h3";

/// A copy of bytes one side sent: a run of a TCP stream, or one UDP datagram.
pub(crate) type Copy = (Direction, Vec<u8>);

/// The way a connection's bytes are read, settled by its first bytes.
enum Reading {
    /// Nothing came yet, so it is not known.
    Undecided,
    /// Bytes that are no encryption this proxy reads, decoded straight away if a decoder knows them.
    Clear(Option<Box<dyn ConnectionDecoder>>),
    /// TLS or QUIC, decrypted first, then decoded once the handshake agreed on a protocol a decoder knows.
    Encrypted { decrypter: Box<dyn ConnectionDecrypter>, decoder: Option<Box<dyn ConnectionDecoder>> },
}

/// The watcher of one connection, holding how its bytes are read and whether its opened event was written.
pub(crate) struct Watch {
    shared: Arc<Shared>,
    connection: Connection,
    opened: bool,
    reading: Reading,
}

impl Watch {
    /// Starts watching a connection whose bytes are not known yet.
    pub(crate) fn new(shared: Arc<Shared>, connection: Connection) -> Self {
        Self { shared, connection, opened: false, reading: Reading::Undecided }
    }

    /// Reads copies until both sides closed, waiting for secrets in between, then writes the end.
    pub(crate) async fn run(mut self, mut copies: mpsc::UnboundedReceiver<Copy>) {
        let mut waiting_since: Option<Instant> = None;
        loop {
            let next = if self.awaits_secret() {
                tokio::time::timeout(RETRY_INTERVAL, copies.recv()).await.ok()
            } else {
                Some(copies.recv().await)
            };
            match next {
                Some(Some((direction, bytes))) => self.read(direction, &bytes),
                Some(None) => break,
                None => self.retry(),
            }
            if !self.awaits_secret() {
                waiting_since = None;
            } else if waiting_since.get_or_insert_with(Instant::now).elapsed() > SECRET_WAIT {
                self.give_up();
                waiting_since = None;
            }
        }
        self.finish();
    }

    /// Returns whether the decrypter holds bytes for want of a secret.
    fn awaits_secret(&self) -> bool {
        matches!(&self.reading, Reading::Encrypted { decrypter, .. } if decrypter.is_waiting())
    }

    /// Reads bytes one side sent, deciding how to read the connection on its first bytes.
    fn read(&mut self, direction: Direction, bytes: &[u8]) {
        if matches!(self.reading, Reading::Undecided) {
            self.reading = self.decide(direction, bytes);
        }
        match &mut self.reading {
            Reading::Encrypted { decrypter, .. } => {
                let decrypted = decrypter.decrypt(direction, bytes, self.shared.keys.as_ref());
                self.take(decrypted);
            }
            Reading::Clear(decoder) => {
                let decoded = match decoder {
                    Some(decoder) => decoder.decode(direction, bytes),
                    None => vec![Decoded::Unparsed { direction, bytes: bytes.to_vec() }],
                };
                self.open(false, None);
                self.emit(decoded);
            }
            Reading::Undecided => {}
        }
    }

    /// Returns how to read a connection whose first bytes these are.
    fn decide(&self, direction: Direction, bytes: &[u8]) -> Reading {
        let first = bytes.first().copied().unwrap_or_default();
        match self.connection.transport {
            Transport::Tcp if direction == Direction::Client && first == TLS_HANDSHAKE => {
                Reading::Encrypted { decrypter: Box::new(Tls.start_connection()), decoder: None }
            }
            Transport::Tcp if bytes.starts_with(HTTP2_PREFACE) => Reading::Clear(Some(Box::new(Http2.start_connection()))),
            Transport::Tcp => Reading::Clear(Some(Box::new(Http1.start_connection()))),
            Transport::Udp if direction == Direction::Client && is_quic_start(bytes) => {
                Reading::Encrypted { decrypter: Box::new(Quic.start_connection()), decoder: None }
            }
            Transport::Udp => Reading::Clear(None),
        }
    }

    /// Tries again what the decrypter holds for want of a secret.
    fn retry(&mut self) {
        if let Reading::Encrypted { decrypter, .. } = &mut self.reading {
            let decrypted = decrypter.retry(self.shared.keys.as_ref());
            self.take(decrypted);
        }
    }

    /// Makes the decrypter stop waiting for secrets and writes what it held as it was sent.
    fn give_up(&mut self) {
        if let Reading::Encrypted { decrypter, .. } = &mut self.reading {
            let decrypted = decrypter.give_up();
            self.take(decrypted);
        }
    }

    /// Writes what is left once both sides closed: the decrypter's, then the decoder's.
    fn finish(&mut self) {
        match &mut self.reading {
            Reading::Encrypted { decrypter, .. } => {
                let decrypted = decrypter.finish();
                self.take(decrypted);
                if let Reading::Encrypted { decoder: Some(decoder), .. } = &mut self.reading {
                    let decoded = decoder.finish();
                    self.emit(decoded);
                }
            }
            Reading::Clear(Some(decoder)) => {
                let decoded = decoder.finish();
                self.emit(decoded);
            }
            Reading::Clear(None) | Reading::Undecided => {}
        }
        self.open(matches!(self.reading, Reading::Encrypted { .. }), None);
        self.shared.emit(Event::Closed { connection: self.connection.id });
    }

    /// Writes what the decrypter gave: the protocol in the opened event, plaintext through the decoder.
    fn take(&mut self, decrypted: Vec<Decrypted>) {
        for each in decrypted {
            match each {
                Decrypted::Agreed { protocol } => {
                    self.open(true, protocol.clone());
                    self.choose_decoder(protocol.as_deref());
                }
                Decrypted::Plain { direction, stream, bytes, fin } => {
                    self.open(true, None);
                    let decoded = match (&mut self.reading, stream) {
                        (Reading::Encrypted { decoder: Some(decoder), .. }, Some(stream)) => {
                            decoder.decode_stream(direction, stream, &bytes, fin)
                        }
                        (Reading::Encrypted { decoder: Some(decoder), .. }, None) => decoder.decode(direction, &bytes),
                        _ => vec![Decoded::Unparsed { direction, bytes }],
                    };
                    self.emit(decoded);
                }
                Decrypted::Opaque { direction, bytes } => {
                    self.open(true, None);
                    self.emit(vec![Decoded::Unparsed { direction, bytes }]);
                }
                Decrypted::Fault { direction, detail } => {
                    self.open(true, None);
                    self.emit(vec![Decoded::Fault { direction, detail }]);
                }
            }
        }
    }

    /// Starts the decoder for the protocol the handshake agreed on, if a decoder knows it.
    ///
    /// TLS that agreed on no protocol is taken for HTTP/1, as clients that send no ALPN speak it.
    fn choose_decoder(&mut self, protocol: Option<&[u8]>) {
        let transport = self.connection.transport;
        let Reading::Encrypted { decoder, .. } = &mut self.reading else {
            return;
        };
        if decoder.is_some() {
            return;
        }
        *decoder = match (transport, protocol) {
            (Transport::Tcp, Some(HTTP2)) => Some(Box::new(Http2.start_connection())),
            (Transport::Tcp, _) => Some(Box::new(Http1.start_connection())),
            (Transport::Udp, Some(HTTP3)) => Some(Box::new(Http3.start_connection())),
            (Transport::Udp, _) => None,
        };
    }

    /// Writes the opened event once, with whether the connection was encrypted and the protocol agreed on.
    fn open(&mut self, tls: bool, protocol: Option<Vec<u8>>) {
        if self.opened {
            return;
        }
        self.opened = true;
        let mut connection = self.connection.clone();
        connection.tls = tls;
        connection.protocol = protocol.map(|protocol| String::from_utf8_lossy(&protocol).into_owned());
        self.shared.emit(Event::Opened(connection));
    }

    /// Writes each decoded result as its own event of the connection, in order.
    fn emit(&self, decoded: Vec<Decoded>) {
        for each in decoded {
            self.shared.emit(Event::Decoded { connection: self.connection.id, decoded: each });
        }
    }
}

/// Returns whether a datagram is the first of a QUIC connection: long enough, with a long header of a known version.
pub(crate) fn is_quic_start(datagram: &[u8]) -> bool {
    let Some(&first) = datagram.first() else {
        return false;
    };
    datagram.len() >= QUIC_FIRST_DATAGRAM
        && first & (QUIC_LONG_HEADER | QUIC_FIXED_BIT) == QUIC_LONG_HEADER | QUIC_FIXED_BIT
        && datagram.get(1..QUIC_VERSION_END).is_some_and(|version| QUIC_VERSIONS.iter().any(|known| known == version))
}
