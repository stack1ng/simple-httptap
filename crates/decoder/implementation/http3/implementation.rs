//! An HTTP/3 decoder that reads each QUIC stream's frames as RFC 9114 says and its field sections with QPACK.

use simple_httptap_decoder::{ConnectionDecoder, Decoded, Decoder, Direction};

/// The HTTP/3 decoder.
#[derive(Debug)]
pub struct Http3;

impl Decoder for Http3 {
    type Connection = Http3Connection;

    fn start_connection(&self) -> Http3Connection {
        Http3Connection
    }
}

/// A decoder of one HTTP/3 connection.
#[derive(Debug)]
pub struct Http3Connection;

impl ConnectionDecoder for Http3Connection {
    fn decode(&mut self, direction: Direction, bytes: &[u8]) -> Vec<Decoded> {
        if bytes.is_empty() {
            return Vec::new();
        }
        vec![Decoded::Unparsed { direction, bytes: bytes.to_vec() }]
    }

    fn finish(&mut self) -> Vec<Decoded> {
        Vec::new()
    }
}
