//! A decrypter of TLS records on a TCP stream, with the secrets in a key log; for now it decrypts nothing.

use simple_httptap_decoder::Direction;
use simple_httptap_decrypter::{ConnectionDecrypter, Decrypted, Decrypter};
use simple_httptap_keylog::Keys;

/// The decrypter of TLS records on a TCP stream.
#[derive(Debug)]
pub struct Tls;

impl Decrypter for Tls {
    type Connection = TlsConnection;

    fn start_connection(&self) -> TlsConnection {
        TlsConnection { finished: false }
    }
}

/// A decrypter of one connection.
#[derive(Debug)]
pub struct TlsConnection {
    finished: bool,
}

impl ConnectionDecrypter for TlsConnection {
    fn decrypt(&mut self, direction: Direction, bytes: &[u8], _keys: &dyn Keys) -> Vec<Decrypted> {
        if self.finished || bytes.is_empty() {
            return Vec::new();
        }
        vec![Decrypted::Opaque { direction, bytes: bytes.to_vec() }]
    }

    fn retry(&mut self, _keys: &dyn Keys) -> Vec<Decrypted> {
        Vec::new()
    }

    fn is_waiting(&self) -> bool {
        false
    }

    fn give_up(&mut self) -> Vec<Decrypted> {
        Vec::new()
    }

    fn finish(&mut self) -> Vec<Decrypted> {
        self.finished = true;
        Vec::new()
    }
}
