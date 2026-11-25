//! Decryption of forwarded connection bytes with key log secrets.

use simple_httptap_decoder::Direction;
use simple_httptap_keylog::Keys;

/// A protocol's decrypter, which starts one per connection.
pub trait Decrypter {
    type Connection: ConnectionDecrypter;

    fn start_connection(&self) -> Self::Connection;
}

/// A connection's decrypter, which returns every byte once, decrypted or as sent.
pub trait ConnectionDecrypter: Send + 'static {
    /// Reads a side's next stream bytes or datagram, returning what it decrypts.
    fn decrypt(&mut self, direction: Direction, bytes: &[u8], keys: &dyn Keys) -> Vec<Decrypted>;

    /// Returns held bytes the key log now decrypts.
    fn retry(&mut self, keys: &dyn Keys) -> Vec<Decrypted>;

    /// Returns whether bytes await a secret.
    fn is_waiting(&self) -> bool;

    /// Stops waiting: held and later secret-needing bytes come back opaque.
    fn give_up(&mut self) -> Vec<Decrypted>;

    /// Returns what is left at close, held bytes opaque; then nothing.
    fn finish(&mut self) -> Vec<Decrypted>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decrypted {
    /// The ALPN protocol, or none, agreed before any plaintext.
    Agreed { protocol: Option<Vec<u8>> },
    /// Plaintext on a stream such as QUIC's, or the connection; `fin` ends the stream.
    Plain { direction: Direction, stream: Option<u64>, bytes: Vec<u8>, fin: bool },
    /// Bytes that stay encrypted or are not the protocol, as sent.
    Opaque { direction: Direction, bytes: Vec<u8> },
    /// Why the side's later bytes come back opaque.
    Fault { direction: Direction, detail: String },
}
