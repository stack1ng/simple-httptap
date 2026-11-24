//! An HTTP/2 decoder that reads each side's frames as RFC 9113 says and its field blocks with HPACK.

use std::collections::BTreeMap;
use std::mem;

use simple_httptap_decoder::{ConnectionDecoder, Decoded, Decoder, Direction, Field, Kind, Message};

/// The HTTP/2 decoder.
#[derive(Debug)]
pub struct Http2;

impl Decoder for Http2 {
    type Connection = Http2Connection;

    fn start_connection(&self) -> Http2Connection {
        Http2Connection(Reader::default())
    }
}

/// A decoder of one HTTP/2 connection.
pub struct Http2Connection(Reader);

impl ConnectionDecoder for Http2Connection {
    fn decode(&mut self, direction: Direction, bytes: &[u8]) -> Vec<Decoded> {
        self.0.decode(direction, bytes)
    }

    fn finish(&mut self) -> Vec<Decoded> {
        self.0.finish()
    }
}

/// The reading of one connection: each side's frames and HPACK table, and the messages of each stream.
#[derive(Default)]
struct Reader {
    client: Side,
    server: Side,
    /// The messages being sent on each stream, by stream.
    streams: BTreeMap<u32, Exchange>,
}

impl Reader {
    /// Reads the next bytes one side sent and returns everything they completed.
    fn decode(&mut self, direction: Direction, bytes: &[u8]) -> Vec<Decoded> {
        let mut decoded = Vec::new();
        self.side(direction).buffer.extend_from_slice(bytes);
        while let Some(frame) = self.next_frame(direction, &mut decoded) {
            if let Err(detail) = self.read_frame(direction, frame, &mut decoded) {
                self.fail(direction, detail, &mut decoded);
            }
        }
        decoded
    }

    /// Returns everything left once the connection closed.
    fn finish(&mut self) -> Vec<Decoded> {
        let mut decoded = Vec::new();
        for direction in [Direction::Client, Direction::Server] {
            let side = self.side(direction);
            if side.block.take().is_some() {
                decoded.push(Decoded::Fault {
                    direction,
                    detail: CUT_BLOCK.to_owned(),
                });
            }
            if !side.buffer.is_empty() {
                decoded.push(Decoded::Unparsed { direction, bytes: mem::take(&mut side.buffer) });
            }
        }
        for (_, exchange) in mem::take(&mut self.streams) {
            exchange.finish(&mut decoded);
        }
        decoded
    }
}

/// What every HTTP/2 client sends before its first frame.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-3.4
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// The bytes of a frame's payload length.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-4.1
const LENGTH_SIZE: usize = 3;
/// The bytes of a frame's header: its length, type, flags and stream.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-4.1
const FRAME_HEADER_SIZE: usize = LENGTH_SIZE + 2 + size_of::<u32>();
/// The bits of a stream identifier, all but the reserved first one.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-4.1
const STREAM_MASK: u32 = u32::MAX >> 1;
/// The type of a DATA frame.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-6.1
const DATA: u8 = 0x0;
/// The type of a HEADERS frame.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-6.2
const HEADERS: u8 = 0x1;
/// The type of a RST_STREAM frame.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-6.4
const RST_STREAM: u8 = 0x3;
/// The type of a PUSH_PROMISE frame.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-6.6
const PUSH_PROMISE: u8 = 0x5;
/// The type of a CONTINUATION frame.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-6.10
const CONTINUATION: u8 = 0x9;
/// The flag that ends a stream's side.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-6.1
const END_STREAM: u8 = 0x1;
/// The flag that ends a field block.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-6.2
const END_HEADERS: u8 = 0x4;
/// The flag that says a payload is padded.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-6.1
const PADDED: u8 = 0x8;
/// The flag that says a HEADERS frame carries priority.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-6.2
const PRIORITY: u8 = 0x20;
/// The bytes of the priority in a HEADERS frame: a stream dependency and a weight.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-6.2
const PRIORITY_SIZE: usize = size_of::<u32>() + size_of::<u8>();
/// The name of the pseudo-header field with a response's status.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-8.3.2
const STATUS: &[u8] = b":status";
/// The fault reported when the bytes end before a field block's END_HEADERS flag.
const CUT_BLOCK: &str = "the connection closed inside a field block";
/// The fault for a client whose bytes start otherwise, so its side is then passed on unparsed.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-3.4
const NO_PREFACE: &str = "the client did not start with the HTTP/2 preface";
/// The first digit of an informational status.
///
/// https://www.rfc-editor.org/rfc/rfc9110#section-15.2
const INFORMATIONAL_DIGIT: u8 = b'1';

/// The bytes one side sent that are not read yet, and the state of reading its frames.
#[derive(Default)]
struct Side {
    buffer: Vec<u8>,
    /// Whether the client's preface has been read; the server sends none.
    prefaced: bool,
    /// Whether a fault stopped this side being read as HTTP/2.
    failed: bool,
    /// The decoder of the field blocks this side sends, whose table the blocks keep up to date.
    hpack: loona_hpack::Decoder<'static>,
    /// A field block still waiting for its CONTINUATION frames.
    block: Option<Block>,
}

/// A field block that started in one frame and goes on in CONTINUATION frames.
struct Block {
    stream: u32,
    /// The stream a PUSH_PROMISE reserves, or none for HEADERS.
    promised: Option<u32>,
    ends_stream: bool,
    fragments: Vec<u8>,
}

/// One frame, taken out of the buffer.
struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

/// The request and response of one stream, as far as they have come.
#[derive(Default)]
struct Exchange {
    request: Option<Message>,
    response: Option<Message>,
}

impl Reader {
    /// Returns the state of the side that sent in the direction.
    fn side(&mut self, direction: Direction) -> &mut Side {
        match direction {
            Direction::Client => &mut self.client,
            Direction::Server => &mut self.server,
        }
    }

    /// Stops reading the side as HTTP/2 and hands over what it has left as unparsed bytes.
    fn fail(&mut self, direction: Direction, detail: String, decoded: &mut Vec<Decoded>) {
        decoded.push(Decoded::Fault { direction, detail });
        let side = self.side(direction);
        side.failed = true;
        if !side.buffer.is_empty() {
            decoded.push(Decoded::Unparsed { direction, bytes: mem::take(&mut side.buffer) });
        }
    }

    /// Takes the next whole frame out of the side's buffer, after the client's preface.
    fn next_frame(&mut self, direction: Direction, decoded: &mut Vec<Decoded>) -> Option<Frame> {
        let side = self.side(direction);
        if side.failed {
            if !side.buffer.is_empty() {
                decoded.push(Decoded::Unparsed { direction, bytes: mem::take(&mut side.buffer) });
            }
            return None;
        }
        if direction == Direction::Client && !side.prefaced {
            let compared = side.buffer.len().min(PREFACE.len());
            if side.buffer[..compared] != PREFACE[..compared] {
                self.fail(direction, NO_PREFACE.to_owned(), decoded);
                return None;
            }
            if compared < PREFACE.len() {
                return None;
            }
            side.buffer.drain(..PREFACE.len());
            side.prefaced = true;
        }
        let header = side.buffer.get(..FRAME_HEADER_SIZE)?;
        let (length, rest) = header.split_at(LENGTH_SIZE);
        let mut length_bytes = [u8::MIN; size_of::<u32>()];
        length_bytes[size_of::<u32>() - LENGTH_SIZE..].copy_from_slice(length);
        let length = usize::try_from(u32::from_be_bytes(length_bytes)).ok()?;
        let [kind, flags, stream @ ..] = rest else { return None };
        let stream = u32::from_be_bytes(*<&[u8; size_of::<u32>()]>::try_from(stream).ok()?) & STREAM_MASK;
        let (kind, flags) = (*kind, *flags);
        if side.buffer.len() < FRAME_HEADER_SIZE + length {
            return None;
        }
        let frame: Vec<u8> = side.buffer.drain(..FRAME_HEADER_SIZE + length).collect();
        Some(Frame { kind, flags, stream, payload: frame[FRAME_HEADER_SIZE..].to_vec() })
    }

    /// Reads one frame of the side into the messages of its stream.
    fn read_frame(&mut self, direction: Direction, frame: Frame, decoded: &mut Vec<Decoded>) -> Result<(), String> {
        let side = self.side(direction);
        if let Some(mut block) = side.block.take() {
            if frame.kind != CONTINUATION || frame.stream != block.stream {
                return Err("a field block was not continued by its CONTINUATION frames".to_owned());
            }
            block.fragments.extend(frame.payload);
            if frame.flags & END_HEADERS == u8::MIN {
                side.block = Some(block);
                return Ok(());
            }
            return self.read_block(direction, block, decoded);
        }
        match frame.kind {
            DATA => {
                let data = unpad(&frame.payload, frame.flags)?;
                let message = self
                    .message(direction, frame.stream)
                    .ok_or_else(|| format!("DATA on stream {} before its fields", frame.stream))?;
                message.body.extend_from_slice(data);
                if frame.flags & END_STREAM != u8::MIN {
                    self.end_message(direction, frame.stream, decoded);
                }
                Ok(())
            }
            HEADERS => {
                let mut fragment = unpad(&frame.payload, frame.flags)?;
                if frame.flags & PRIORITY != u8::MIN {
                    fragment = fragment.get(PRIORITY_SIZE..).ok_or("a HEADERS frame too short for its priority")?;
                }
                let block = Block {
                    stream: frame.stream,
                    promised: None,
                    ends_stream: frame.flags & END_STREAM != u8::MIN,
                    fragments: fragment.to_vec(),
                };
                self.start_block(direction, block, frame.flags, decoded)
            }
            PUSH_PROMISE => {
                let payload = unpad(&frame.payload, frame.flags)?;
                let (promised, fragment) = payload
                    .split_first_chunk::<{ size_of::<u32>() }>()
                    .ok_or("a PUSH_PROMISE frame too short for its stream")?;
                let block = Block {
                    stream: frame.stream,
                    promised: Some(u32::from_be_bytes(*promised) & STREAM_MASK),
                    ends_stream: false,
                    fragments: fragment.to_vec(),
                };
                self.start_block(direction, block, frame.flags, decoded)
            }
            RST_STREAM => {
                if let Some(exchange) = self.streams.remove(&frame.stream) {
                    exchange.finish(decoded);
                }
                Ok(())
            }
            CONTINUATION => Err(format!("a CONTINUATION frame on stream {} outside a field block", frame.stream)),
            _ => Ok(()),
        }
    }

    /// Reads a field block now, or waits for its CONTINUATION frames if the frame did not end it.
    fn start_block(&mut self, direction: Direction, block: Block, flags: u8, decoded: &mut Vec<Decoded>) -> Result<(), String> {
        if flags & END_HEADERS == u8::MIN {
            self.side(direction).block = Some(block);
            return Ok(());
        }
        self.read_block(direction, block, decoded)
    }

    /// Decodes a whole field block and gives its fields to the message they start or end.
    fn read_block(&mut self, direction: Direction, block: Block, decoded: &mut Vec<Decoded>) -> Result<(), String> {
        let fields: Vec<Field> = self
            .side(direction)
            .hpack
            .decode(&block.fragments)
            .map_err(|fault| format!("a field block HPACK cannot decode: {fault:?}"))?
            .into_iter()
            .map(|(name, value)| Field { name, value })
            .collect();
        if let Some(promised) = block.promised {
            decoded.push(Decoded::Message(Message {
                kind: Kind::Request,
                stream: Some(promised),
                start_line: None,
                fields,
                body: Vec::new(),
                trailers: Vec::new(),
                complete: true,
            }));
            return Ok(());
        }
        match self.message(direction, block.stream) {
            Some(message) => message.trailers = fields,
            None => {
                let informational = direction == Direction::Server && is_informational(&fields);
                let message = Message {
                    kind: match direction {
                        Direction::Client => Kind::Request,
                        Direction::Server => Kind::Response,
                    },
                    stream: Some(block.stream),
                    start_line: None,
                    fields,
                    body: Vec::new(),
                    trailers: Vec::new(),
                    complete: informational,
                };
                if informational {
                    decoded.push(Decoded::Message(message));
                    return Ok(());
                }
                let exchange = self.streams.entry(block.stream).or_default();
                match direction {
                    Direction::Client => exchange.request = Some(message),
                    Direction::Server => exchange.response = Some(message),
                }
            }
        }
        if block.ends_stream {
            self.end_message(direction, block.stream, decoded);
        }
        Ok(())
    }

    /// Returns the message the side is sending on the stream, if its fields have come.
    fn message(&mut self, direction: Direction, stream: u32) -> Option<&mut Message> {
        let exchange = self.streams.get_mut(&stream)?;
        match direction {
            Direction::Client => exchange.request.as_mut(),
            Direction::Server => exchange.response.as_mut(),
        }
    }

    /// Hands over the message the side ended on the stream, and forgets the stream once both sides ended.
    fn end_message(&mut self, direction: Direction, stream: u32, decoded: &mut Vec<Decoded>) {
        let Some(exchange) = self.streams.get_mut(&stream) else { return };
        let message = match direction {
            Direction::Client => exchange.request.take(),
            Direction::Server => exchange.response.take(),
        };
        if let Some(message) = message {
            decoded.push(Decoded::Message(Message { complete: true, ..message }));
        }
        if exchange.request.is_none() && exchange.response.is_none() {
            self.streams.remove(&stream);
        }
    }
}

impl Exchange {
    /// Hands over the stream's unfinished messages, request first.
    fn finish(self, decoded: &mut Vec<Decoded>) {
        decoded.extend(self.request.into_iter().chain(self.response).map(Decoded::Message));
    }
}

/// Returns a payload without its padding, if the flags say it has some.
///
/// https://www.rfc-editor.org/rfc/rfc9113#section-6.1
fn unpad(payload: &[u8], flags: u8) -> Result<&[u8], String> {
    if flags & PADDED == u8::MIN {
        return Ok(payload);
    }
    let (padding, rest) = payload.split_first().ok_or("a padded frame without its padding length")?;
    let end = rest.len().checked_sub(usize::from(*padding)).ok_or("padding longer than its frame")?;
    Ok(&rest[..end])
}

/// Returns whether response fields have an informational status, which another response follows.
fn is_informational(fields: &[Field]) -> bool {
    fields
        .iter()
        .find(|field| field.name == STATUS)
        .is_some_and(|field| field.value.first() == Some(&INFORMATIONAL_DIGIT))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a frame's bytes.
    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let length = u32::try_from(payload.len()).expect("a short payload").to_be_bytes();
        let mut bytes = length[size_of::<u32>() - LENGTH_SIZE..].to_vec();
        bytes.extend([kind, flags]);
        bytes.extend(stream.to_be_bytes());
        bytes.extend(payload);
        bytes
    }

    /// Returns a field block with the fields, each a literal never added to the table.
    fn block(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut encoder = loona_hpack::Encoder::new();
        encoder.encode(fields.iter().copied())
    }

    #[test]
    fn keeps_field_order_bodies_and_trailers() {
        let request_fields: &[(&[u8], &[u8])] =
            &[(b":method", b"POST"), (b":path", b"/"), (b"zebra", b"1"), (b"apple", b"2"), (b"zebra", b"3")];
        let mut client = PREFACE.to_vec();
        client.extend(frame(HEADERS, END_HEADERS, 1, &block(request_fields)));
        client.extend(frame(DATA, END_STREAM, 1, b"hi"));
        let mut server = frame(HEADERS, END_HEADERS, 1, &block(&[(STATUS, b"103")]));
        let response = block(&[(STATUS, b"200"), (b"b", b"x"), (b"a", b"y")]);
        let (first, second) = response.split_at(1);
        server.extend(frame(HEADERS, u8::MIN, 1, first));
        server.extend(frame(CONTINUATION, END_HEADERS, 1, second));
        server.extend(frame(DATA, PADDED, 1, &[2, b'o', b'k', u8::MIN, u8::MIN]));
        server.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &block(&[(b"t", b"z")])));

        let mut decoder = Http2.start_connection();
        let mut decoded = decoder.decode(Direction::Client, &client);
        for byte in &server {
            decoded.extend(decoder.decode(Direction::Server, std::slice::from_ref(byte)));
        }
        decoded.extend(decoder.finish());
        let [Decoded::Message(request), Decoded::Message(early), Decoded::Message(response)] = decoded.as_slice() else {
            panic!("three messages: {decoded:?}");
        };
        let names: Vec<&[u8]> = request.fields.iter().map(|field| field.name.as_slice()).collect();
        assert_eq!(names, [&b":method"[..], b":path", b"zebra", b"apple", b"zebra"]);
        assert_eq!((request.body.as_slice(), request.complete), (&b"hi"[..], true));
        assert_eq!(early.fields, [Field { name: STATUS.to_vec(), value: b"103".to_vec() }]);
        assert_eq!(response.body, b"ok");
        assert_eq!(response.trailers, [Field { name: b"t".to_vec(), value: b"z".to_vec() }]);
        assert!(response.complete);
    }

    #[test]
    fn hands_over_a_stream_cut_short() {
        let mut client = PREFACE.to_vec();
        client.extend(frame(HEADERS, END_HEADERS, 3, &block(&[(b":method", b"PUT")])));
        client.extend(frame(DATA, u8::MIN, 3, b"part"));
        let mut decoder = Http2.start_connection();
        assert!(decoder.decode(Direction::Client, &client).is_empty());
        let decoded = decoder.finish();
        let [Decoded::Message(request)] = decoded.as_slice() else { panic!("one message: {decoded:?}") };
        assert_eq!((request.stream, request.body.as_slice(), request.complete), (Some(3), &b"part"[..], false));
    }
}
