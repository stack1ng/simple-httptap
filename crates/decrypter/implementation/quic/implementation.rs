//! A decrypter of QUIC packets in UDP datagrams, with the secrets in a key log; for now it decrypts nothing.

use simple_httptap_decoder::Direction;
use simple_httptap_decrypter::{ConnectionDecrypter, Decrypted, Decrypter};
use simple_httptap_keylog::Keys;

/// The decrypter of QUIC packets in UDP datagrams.
#[derive(Debug)]
pub struct Quic;

impl Decrypter for Quic {
    type Connection = QuicConnection;

    fn start_connection(&self) -> QuicConnection {
        QuicConnection { finished: false }
    }
}

/// A decrypter of one connection.
#[derive(Debug)]
pub struct QuicConnection {
    finished: bool,
}

impl ConnectionDecrypter for QuicConnection {
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
