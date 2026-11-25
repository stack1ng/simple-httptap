//! A reader of a connection's encrypted bytes that decrypts them with the secrets a key log holds, never changing them.
//!
//! It only watches: the bytes it reads were already sent on, so a secret it lacks costs readability, not the connection.

use simple_httptap_decoder::Direction;
use simple_httptap_keylog::Keys;

/// A protocol's decrypter, which starts one connection decrypter per connection.
pub trait Decrypter {
    /// The state of one connection, started anew for each.
    type Connection: ConnectionDecrypter;

    /// Starts decrypting a new connection.
    fn start_connection(&self) -> Self::Connection;
}

/// A decrypter of one connection that gives back every byte, decrypted or as it was sent.
///
/// What it cannot decrypt yet for want of a secret it holds, and gives back once the key log has the secret,
/// or opaque once it gives up.
pub trait ConnectionDecrypter: Send + 'static {
    /// Reads what one side sent next, a run of a stream's bytes or one whole datagram, and returns what it decrypted.
    fn decrypt(&mut self, direction: Direction, bytes: &[u8], keys: &dyn Keys) -> Vec<Decrypted>;

    /// Tries again what it holds for want of a secret, returning what it could decrypt now.
    fn retry(&mut self, keys: &dyn Keys) -> Vec<Decrypted>;

    /// Returns whether it holds bytes for want of a secret.
    fn is_waiting(&self) -> bool;

    /// Stops waiting for secrets: what it holds comes back opaque, and so does everything it reads later that needs them.
    fn give_up(&mut self) -> Vec<Decrypted>;

    /// Returns what is left once the connection closed, held bytes opaque, after which it returns nothing more.
    fn finish(&mut self) -> Vec<Decrypted>;
}

/// What a decrypter learned or decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decrypted {
    /// The handshake agreed on an application protocol, or on none, before any plaintext of the connection.
    Agreed { protocol: Option<Vec<u8>> },
    /// Plaintext one side sent, on a stream of the connection's own, such as a QUIC stream, or on the connection.
    ///
    /// `fin` says the side ended the stream with these bytes.
    Plain { direction: Direction, stream: Option<u64>, bytes: Vec<u8>, fin: bool },
    /// Bytes one side sent that stay encrypted, or that are not the protocol at all, exactly as sent.
    Opaque { direction: Direction, bytes: Vec<u8> },
    /// Why the bytes of the side after it come back opaque.
    Fault { direction: Direction, detail: String },
}
