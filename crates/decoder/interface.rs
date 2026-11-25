//! A reader of a connection's bytes that turns them into the HTTP messages they carry, exactly as sent.

/// An HTTP version's decoder, which starts one connection decoder per connection.
pub trait Decoder {
    /// The state of one connection, started anew for each.
    type Connection: ConnectionDecoder;

    /// Starts decoding a new connection.
    fn start_connection(&self) -> Self::Connection;
}

/// A decoder of one connection that gives back every byte, in a message or unparsed.
pub trait ConnectionDecoder: Send + 'static {
    /// Reads the next bytes one side sent and returns everything they completed.
    fn decode(&mut self, direction: Direction, bytes: &[u8]) -> Vec<Decoded>;

    /// Reads the next bytes one side sent on a transport stream, such as a QUIC stream.
    ///
    /// `fin` says the side ended the stream with them. A version whose transport has no streams, every one before
    /// HTTP/3, gives them back unparsed.
    fn decode_stream(&mut self, direction: Direction, stream: u64, bytes: &[u8], fin: bool) -> Vec<Decoded> {
        let _ = (stream, fin);
        if bytes.is_empty() {
            return Vec::new();
        }
        vec![Decoded::Unparsed { direction, bytes: bytes.to_vec() }]
    }

    /// Returns what is left once the connection closed, a message cut short with `complete` false.
    fn finish(&mut self) -> Vec<Decoded>;
}

/// The side of a connection that sent some bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Client,
    Server,
}

/// A message, bytes that are no HTTP, or a fault ending HTTP on a side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    Message(Message),
    Unparsed { direction: Direction, bytes: Vec<u8> },
    Fault { direction: Direction, detail: String },
}

/// An HTTP request or response, its fields in sent order and case.
///
/// The body has no chunked framing and keeps its content coding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub kind: Kind,
    pub stream: Option<u64>,
    pub start_line: Option<Vec<u8>>,
    pub fields: Vec<Field>,
    pub body: Vec<u8>,
    pub trailers: Vec<Field>,
    pub complete: bool,
}

/// A request or a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Request,
    Response,
}

/// A header or trailer field, byte for byte, its value without surrounding whitespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}
