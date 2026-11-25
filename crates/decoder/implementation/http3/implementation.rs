//! An HTTP/3 decoder that reads each QUIC stream's frames as RFC 9114 says and its field sections with QPACK.

mod qpack;

use std::collections::{BTreeMap, BTreeSet};
use std::mem;

use qpack::{Cursor, Huffman, STATUS_NAME, Section, Table};
use simple_httptap_decoder::{
    ConnectionDecoder, Decoded, Decoder, Direction, Field, Kind, Message,
};

/// The HTTP/3 decoder.
#[derive(Debug)]
pub struct Http3;

impl Decoder for Http3 {
    type Connection = Http3Connection;

    fn start_connection(&self) -> Http3Connection {
        Http3Connection(Reader::default())
    }
}

/// A decoder of one HTTP/3 connection.
#[derive(Debug)]
pub struct Http3Connection(Reader);

impl ConnectionDecoder for Http3Connection {
    fn decode(&mut self, direction: Direction, bytes: &[u8]) -> Vec<Decoded> {
        unparsed(direction, bytes).into_iter().collect()
    }

    fn decode_stream(
        &mut self,
        direction: Direction,
        stream: u64,
        bytes: &[u8],
        fin: bool,
    ) -> Vec<Decoded> {
        self.0.decode_stream(direction, stream, bytes, fin)
    }

    fn finish(&mut self) -> Vec<Decoded> {
        self.0.finish()
    }
}

/// The bit of a stream ID that is set when the server opened the stream.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-2.1
const SERVER_INITIATED: u64 = 0x1;
/// The bit of a stream ID that is set when only its opener sends on it.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-2.1
const UNIDIRECTIONAL: u64 = 0x2;
/// The type of a DATA frame.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
const DATA_FRAME: u64 = 0x0;
/// The type of a HEADERS frame.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-7.2.2
const HEADERS_FRAME: u64 = 0x1;
/// The type of a CANCEL_PUSH frame.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
const CANCEL_PUSH: u64 = 0x3;
/// The type of a SETTINGS frame.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
const SETTINGS: u64 = 0x4;
/// The type of a PUSH_PROMISE frame.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
const PUSH_PROMISE_FRAME: u64 = 0x5;
/// The type of a GOAWAY frame.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
const GOAWAY: u64 = 0x7;
/// The type of a MAX_PUSH_ID frame.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
const MAX_PUSH_ID: u64 = 0xd;
/// The HTTP/2 frame types HTTP/3 reserves, which an endpoint must not send: PRIORITY, PING, WINDOW_UPDATE and CONTINUATION.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
const HTTP2_ONLY: [u64; 4] = [0x2, 0x6, 0x8, 0x9];
/// The first of the reserved stream, frame and setting types, which are to be ignored.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
const RESERVED_FIRST: u64 = 0x21;
/// The step between one reserved type and the next.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
const RESERVED_STEP: u64 = 0x1f;
/// The type of a control stream.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
const CONTROL_STREAM: u64 = 0x0;
/// The type of a push stream.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-6.2.2
const PUSH_STREAM: u64 = 0x1;
/// The type of a QPACK encoder stream.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.2
const ENCODER_STREAM: u64 = 0x2;
/// The type of a QPACK decoder stream.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.2
const DECODER_STREAM: u64 = 0x3;
/// The frame type that starts a WebTransport bidirectional stream, whose bytes after it are no HTTP.
///
/// https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-13.html#section-4.3
const WEBTRANSPORT_STREAM: u64 = 0x41;
/// The setting that bounds the dynamic table the sender of the SETTINGS decodes with.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-5
const QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
/// The setting that bounds how many streams the sender of the SETTINGS lets wait on its dynamic table.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-5
const QPACK_BLOCKED_STREAMS: u64 = 0x7;
/// The first digit of an informational status, which another response follows.
///
/// https://www.rfc-editor.org/rfc/rfc9110#section-15.2
const INFORMATIONAL: u8 = b'1';

/// The fault for bytes on a unidirectional stream from the peer that did not open it.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-2.1
const WRONG_SENDER: &str = "bytes from the peer that did not open a unidirectional stream";
/// The fault for a request or push stream that ended without a message's fields.
const NO_FIELDS: &str = "a stream ended before its fields";
/// The fault for a stream that ended partway through a frame.
const CUT_FRAME: &str = "a stream ended inside a frame";
/// The fault for a control or QPACK encoder stream that ended, which the connection needs to its end.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
const CLOSED_CRITICAL: &str = "a critical stream was closed";
/// The fault for a stream that ended before its type or push ID came whole.
const CUT_HEADER: &str = "a stream ended inside its type or push ID";
/// The fault for a field section that still waited for its dynamic table entries or SETTINGS at the end.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-2.1.2
const STILL_BLOCKED: &str =
    "a field section still waited for its dynamic table entries or SETTINGS";

/// The reading of one connection: each peer's streams and QPACK state, and the server's pushes.
#[derive(Debug, Default)]
struct Reader {
    client: Peer,
    server: Peer,
    /// The pushes the server promised or opened, by push ID.
    pushes: BTreeMap<u64, Push>,
    huffman: Huffman,
}

/// What one peer sent: its streams, its SETTINGS, and the dynamic table of the field sections it encodes.
#[derive(Debug, Default)]
struct Peer {
    /// The SETTINGS from its control stream, once they came.
    settings: Option<Settings>,
    table: Table,
    /// Its side of each stream it sent on, by stream ID.
    streams: BTreeMap<u64, Half>,
    /// The types of the unidirectional streams it may open only once and opened.
    critical: BTreeSet<u64>,
}

/// The settings that shape how the other peer's field sections decode.
#[derive(Debug, Clone, Copy, Default)]
struct Settings {
    max_table_capacity: u64,
    blocked_streams: u64,
}

/// A push: the stream it came on once opened, and the requests promised for it until then.
#[derive(Debug, Default)]
struct Push {
    stream: Option<u64>,
    promised: Vec<Message>,
}

/// One peer's side of a stream: the bytes not read yet, and what they are being read as.
#[derive(Debug)]
struct Half {
    buffer: Vec<u8>,
    /// Whether the peer ended its side, so no bytes follow the buffer's.
    fin: bool,
    role: Role,
    /// Whether a client's bidirectional stream carries HTTP, once its first frame type came.
    http: Option<bool>,
}

/// What a side of a stream is read as.
#[derive(Debug)]
enum Role {
    /// A unidirectional stream whose type has not come whole.
    Untyped,
    /// A client's bidirectional stream whose first frame type has not come whole.
    Opening,
    /// The server's side of a client's bidirectional stream, waiting to learn whether the client's carries HTTP.
    Answering,
    /// A push stream whose push ID has not come whole.
    Pushing,
    /// A control stream, and whether its SETTINGS came.
    Control(bool),
    Encoder,
    /// A stream whose bytes are read and dropped, such as a QPACK decoder stream.
    Ignored,
    /// A stream whose bytes come back unparsed, being no HTTP, past a fault, or past the stream's end.
    Unparsed,
    Messages(Messages),
}

/// The messages one side of a request or push stream sends.
#[derive(Debug)]
struct Messages {
    kind: Kind,
    /// The stream the messages say they are on.
    stream: u64,
    /// The message after its final fields, until it ends.
    message: Option<Message>,
    /// Whether the message's trailers came, after which only unknown frames may.
    trailed: bool,
    /// Whether PUSH_PROMISE frames may come, as on the server's side of a request stream.
    promises: bool,
    /// The Required Insert Count of the field section at the front, once read, kept while it waits.
    required: Option<u64>,
    /// Whether the field section at the front waits for its dynamic table entries or SETTINGS.
    blocked: bool,
}

/// What reading the front of a side came to.
enum Step {
    /// It read something, and may read more.
    Next,
    /// It read something that may unblock the field sections of the peer it names.
    Wake(Direction),
    /// It needs more bytes, or a waiting field section to unblock.
    Wait,
}

/// A whole frame at the front of a buffer.
struct Frame {
    payload: Vec<u8>,
    /// The bytes of the whole frame, header and payload.
    length: usize,
}

impl Reader {
    /// Reads the next bytes one side sent on a stream and returns everything they and the stream's end completed.
    fn decode_stream(
        &mut self,
        direction: Direction,
        stream: u64,
        bytes: &[u8],
        fin: bool,
    ) -> Vec<Decoded> {
        let mut decoded = Vec::new();
        if bytes.is_empty() && !fin {
            return decoded;
        }
        let half = self
            .peer(direction)
            .streams
            .entry(stream)
            .or_insert_with(|| {
                let (half, fault) = Half::open(direction, stream);
                decoded.extend(fault.map(|detail| Decoded::Fault {
                    direction,
                    detail: detail.to_owned(),
                }));
                half
            });
        half.buffer.extend_from_slice(bytes);
        half.fin |= fin;
        self.pump(direction, stream, &mut decoded);
        let answer = self
            .server
            .streams
            .get(&stream)
            .is_some_and(|half| matches!(half.role, Role::Answering));
        if direction == Direction::Client && answer {
            self.pump(Direction::Server, stream, &mut decoded);
        }
        decoded
    }

    /// Returns everything left once the connection closed.
    fn finish(&mut self) -> Vec<Decoded> {
        let mut decoded = Vec::new();
        let streams: BTreeSet<u64> = self
            .client
            .streams
            .keys()
            .chain(self.server.streams.keys())
            .copied()
            .collect();
        for stream in streams {
            for direction in [Direction::Client, Direction::Server] {
                if let Some(half) = self.peer(direction).streams.remove(&stream) {
                    half.finish(direction, &mut decoded);
                }
            }
        }
        for push in mem::take(&mut self.pushes).into_values() {
            decoded.extend(push.promised.into_iter().map(Decoded::Message));
        }
        decoded
    }

    /// Returns what the peer that sent in the direction sent.
    fn peer(&mut self, direction: Direction) -> &mut Peer {
        match direction {
            Direction::Client => &mut self.client,
            Direction::Server => &mut self.server,
        }
    }

    /// Reads as much of one side of a stream as it can, then retries the field sections what it read unblocks.
    fn pump(&mut self, direction: Direction, stream: u64, decoded: &mut Vec<Decoded>) {
        let Some(mut half) = self.peer(direction).streams.remove(&stream) else {
            return;
        };
        let woken = self.read(direction, stream, &mut half, decoded);
        self.peer(direction).streams.insert(stream, half);
        if let Some(sender) = woken {
            let blocked: Vec<u64> = self
                .peer(sender)
                .streams
                .iter()
                .filter(|(_, half)| half.is_blocked())
                .map(|(stream, _)| *stream)
                .collect();
            for stream in blocked {
                self.pump(sender, stream, decoded);
            }
        }
    }

    /// Reads the side's buffer as its role says, and its end once all is read, returning whose sections to retry.
    fn read(
        &mut self,
        direction: Direction,
        stream: u64,
        half: &mut Half,
        decoded: &mut Vec<Decoded>,
    ) -> Option<Direction> {
        let mut woken = None;
        loop {
            let step = match half.role {
                Role::Unparsed => {
                    decoded.extend(unparsed(direction, &mem::take(&mut half.buffer)));
                    return woken;
                }
                Role::Ignored => {
                    half.buffer.clear();
                    return woken;
                }
                Role::Untyped => self.read_stream_type(direction, stream, half),
                Role::Opening => Ok(open_request(stream, half)),
                Role::Answering => Ok(
                    match self
                        .client
                        .streams
                        .get(&stream)
                        .and_then(|client| client.http)
                    {
                        Some(true) => {
                            half.role = Role::Messages(Messages::new(Kind::Response, stream, true));
                            Step::Next
                        }
                        Some(false) => {
                            half.role = Role::Unparsed;
                            Step::Next
                        }
                        None => Step::Wait,
                    },
                ),
                Role::Pushing => self.read_push_id(stream, half, decoded),
                Role::Control(_) => self.read_control(direction, half),
                Role::Encoder => self.read_encoder(direction, half),
                Role::Messages(_) => self.read_message_frame(direction, stream, half, decoded),
            };
            match step {
                Ok(Step::Next) => {}
                Ok(Step::Wake(sender)) => woken = Some(sender),
                Ok(Step::Wait) => break,
                Err(detail) => {
                    half.fail(direction, detail, decoded);
                    return woken;
                }
            }
        }
        if half.fin {
            half.end(direction, decoded);
        }
        woken
    }

    /// Reads a unidirectional stream's type and takes up the role it gives.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9114#section-6.2
    fn read_stream_type(
        &mut self,
        direction: Direction,
        stream: u64,
        half: &mut Half,
    ) -> Result<Step, String> {
        let mut cursor = Cursor::new(&half.buffer);
        let Ok(kind) = cursor.varint() else {
            return Ok(Step::Wait);
        };
        let role = match kind {
            CONTROL_STREAM => Role::Control(false),
            PUSH_STREAM if direction == Direction::Server => Role::Pushing,
            PUSH_STREAM => return Err(format!("the client opened push stream {stream}")),
            ENCODER_STREAM => Role::Encoder,
            DECODER_STREAM => Role::Ignored,
            _ if is_reserved(kind) => Role::Ignored,
            _ => {
                half.role = Role::Unparsed;
                return Ok(Step::Next);
            }
        };
        if kind != PUSH_STREAM && !self.peer(direction).critical.insert(kind) {
            return Err(format!(
                "a second unidirectional stream of type {kind}, on stream {stream}"
            ));
        }
        let read = cursor.read();
        half.buffer.drain(..read);
        half.role = role;
        Ok(Step::Next)
    }

    /// Reads a push stream's push ID, and hands over the requests promised for it as on this stream.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9114#section-4.6
    fn read_push_id(
        &mut self,
        stream: u64,
        half: &mut Half,
        decoded: &mut Vec<Decoded>,
    ) -> Result<Step, String> {
        let mut cursor = Cursor::new(&half.buffer);
        let Ok(id) = cursor.varint() else {
            return Ok(Step::Wait);
        };
        let push = self.pushes.entry(id).or_default();
        if push.stream.is_some() {
            return Err(format!("a second push stream for push ID {id}"));
        }
        push.stream = Some(stream);
        let read = cursor.read();
        half.buffer.drain(..read);
        let stream_id = Some(stream);
        decoded.extend(push.promised.drain(..).map(|promised| {
            Decoded::Message(Message {
                stream: stream_id,
                ..promised
            })
        }));
        half.role = Role::Messages(Messages::new(Kind::Response, stream, false));
        Ok(Step::Next)
    }

    /// Reads a control stream's next frame, keeping its SETTINGS and skipping the frames that touch no message.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    fn read_control(&mut self, direction: Direction, half: &mut Half) -> Result<Step, String> {
        let Role::Control(set) = half.role else {
            return Ok(Step::Wait);
        };
        let Some(kind) = frame_type(&half.buffer) else {
            return Ok(Step::Wait);
        };
        if kind == SETTINGS && set {
            return Err("a second SETTINGS frame".to_owned());
        }
        if !set && kind != SETTINGS {
            return Err(format!(
                "a control stream starting with a frame of type {kind}, not SETTINGS"
            ));
        }
        if matches!(kind, DATA_FRAME | HEADERS_FRAME | PUSH_PROMISE_FRAME)
            || HTTP2_ONLY.contains(&kind)
        {
            return Err(format!("a frame of type {kind} on the control stream"));
        }
        let Some(frame) = frame(&half.buffer) else {
            return Ok(Step::Wait);
        };
        if kind != SETTINGS {
            half.buffer.drain(..frame.length);
            return Ok(Step::Next);
        }
        self.peer(direction).settings = Some(read_settings(&frame.payload)?);
        half.buffer.drain(..frame.length);
        half.role = Role::Control(true);
        Ok(Step::Wake(other(direction)))
    }

    /// Reads a QPACK encoder stream's next instruction into the sender's dynamic table.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9204#section-4.3
    fn read_encoder(&mut self, direction: Direction, half: &mut Half) -> Result<Step, String> {
        let (sender, receiver) = match direction {
            Direction::Client => (&mut self.client, &self.server),
            Direction::Server => (&mut self.server, &self.client),
        };
        let allowed = receiver
            .settings
            .map(|settings| settings.max_table_capacity);
        match sender
            .table
            .read_instruction(&half.buffer, allowed, &mut self.huffman)
        {
            Ok(read) => {
                half.buffer.drain(..read);
                Ok(Step::Wake(direction))
            }
            Err(qpack::Error::Short) => Ok(Step::Wait),
            Err(qpack::Error::Malformed(detail)) => Err(detail),
        }
    }

    /// Reads the next frame of a request or push stream into its messages.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9114#section-4.1
    fn read_message_frame(
        &mut self,
        direction: Direction,
        stream: u64,
        half: &mut Half,
        decoded: &mut Vec<Decoded>,
    ) -> Result<Step, String> {
        let Role::Messages(messages) = &mut half.role else {
            return Ok(Step::Wait);
        };
        let Some(kind) = frame_type(&half.buffer) else {
            return Ok(Step::Wait);
        };
        let misplaced = match kind {
            DATA_FRAME => messages.message.is_none() || messages.trailed,
            HEADERS_FRAME => messages.trailed,
            PUSH_PROMISE_FRAME => !messages.promises,
            CANCEL_PUSH | SETTINGS | GOAWAY | MAX_PUSH_ID => true,
            _ => HTTP2_ONLY.contains(&kind),
        };
        if misplaced {
            return Err(format!(
                "a frame of type {kind} where stream {stream} may not have one"
            ));
        }
        let Some(frame) = frame(&half.buffer) else {
            return Ok(Step::Wait);
        };
        match kind {
            DATA_FRAME => messages
                .message
                .iter_mut()
                .for_each(|message| message.body.extend_from_slice(&frame.payload)),
            HEADERS_FRAME => {
                let Some(fields) = self.section(direction, &frame.payload, messages)? else {
                    return Ok(Step::Wait);
                };
                messages.take_fields(fields, decoded);
            }
            PUSH_PROMISE_FRAME => {
                let mut cursor = Cursor::new(&frame.payload);
                let id = cursor
                    .varint()
                    .map_err(|_| "a PUSH_PROMISE frame too short for its push ID")?;
                let Some(fields) = self.section(direction, cursor.rest(), messages)? else {
                    return Ok(Step::Wait);
                };
                self.promise(id, stream, fields, decoded);
            }
            _ => {}
        }
        half.buffer.drain(..frame.length);
        Ok(Step::Next)
    }

    /// Decodes a field section the peer sent, or returns none and marks the messages blocked if it must wait.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9204#section-2.1.2
    fn section(
        &mut self,
        direction: Direction,
        payload: &[u8],
        messages: &mut Messages,
    ) -> Result<Option<Vec<Field>>, String> {
        let (sender, receiver) = match direction {
            Direction::Client => (&self.client, &self.server),
            Direction::Server => (&self.server, &self.client),
        };
        let allowed = receiver
            .settings
            .map(|settings| settings.max_table_capacity);
        match qpack::decode_section(
            payload,
            &sender.table,
            allowed,
            &mut messages.required,
            &mut self.huffman,
        )? {
            Section::Fields(fields) => {
                messages.required = None;
                messages.blocked = false;
                Ok(Some(fields))
            }
            Section::Blocked => {
                let others = sender
                    .streams
                    .values()
                    .filter(|half| half.is_blocked())
                    .count() as u64;
                if let Some(settings) = receiver.settings
                    && others >= settings.blocked_streams
                {
                    return Err(format!(
                        "more than {} streams waiting on the dynamic table",
                        settings.blocked_streams
                    ));
                }
                messages.blocked = true;
                Ok(None)
            }
        }
    }

    /// Hands over a promised request now if its push stream is known, or keeps it until it is.
    ///
    /// Until then the request says it is on the stream that promised it.
    /// https://www.rfc-editor.org/rfc/rfc9114#section-4.6
    fn promise(&mut self, id: u64, stream: u64, fields: Vec<Field>, decoded: &mut Vec<Decoded>) {
        let push = self.pushes.entry(id).or_default();
        let message = Message {
            kind: Kind::Request,
            stream: Some(push.stream.unwrap_or(stream)),
            start_line: None,
            fields,
            body: Vec::new(),
            trailers: Vec::new(),
            complete: true,
        };
        match push.stream {
            Some(_) => decoded.push(Decoded::Message(message)),
            None => push.promised.push(message),
        }
    }
}

impl Half {
    /// Starts a side of a stream with the role its ID and sender give it, and a fault if they do not fit.
    fn open(direction: Direction, stream: u64) -> (Self, Option<&'static str>) {
        let opener = match stream & SERVER_INITIATED {
            u64::MIN => Direction::Client,
            _ => Direction::Server,
        };
        let (role, fault) = match (stream & UNIDIRECTIONAL != u64::MIN, opener, direction) {
            (false, Direction::Client, Direction::Client) => (Role::Opening, None),
            (false, Direction::Client, Direction::Server) => (Role::Answering, None),
            (false, Direction::Server, _) => (Role::Unparsed, None),
            (true, opener, direction) if opener == direction => (Role::Untyped, None),
            (true, ..) => (Role::Unparsed, Some(WRONG_SENDER)),
        };
        (
            Self {
                buffer: Vec::new(),
                fin: false,
                role,
                http: None,
            },
            fault,
        )
    }

    /// Returns whether a field section at the front of the side waits.
    fn is_blocked(&self) -> bool {
        matches!(&self.role, Role::Messages(messages) if messages.blocked)
    }

    /// Stops reading the side, handing over its message cut short, the fault, and its bytes unparsed.
    fn fail(&mut self, direction: Direction, detail: String, decoded: &mut Vec<Decoded>) {
        if let Role::Messages(messages) = &mut self.role {
            decoded.extend(messages.message.take().map(Decoded::Message));
        }
        decoded.push(Decoded::Fault { direction, detail });
        decoded.extend(unparsed(direction, &mem::take(&mut self.buffer)));
        self.role = Role::Unparsed;
    }

    /// Reads the end of the side once every whole frame before it is read.
    fn end(&mut self, direction: Direction, decoded: &mut Vec<Decoded>) {
        match &mut self.role {
            Role::Messages(messages) if messages.blocked => {}
            Role::Messages(messages) if self.buffer.is_empty() => {
                match messages.message.take() {
                    Some(message) => decoded.push(Decoded::Message(Message {
                        complete: true,
                        ..message
                    })),
                    None => decoded.push(Decoded::Fault {
                        direction,
                        detail: NO_FIELDS.to_owned(),
                    }),
                }
                self.role = Role::Unparsed;
            }
            Role::Messages(_) => self.fail(direction, CUT_FRAME.to_owned(), decoded),
            Role::Control(_) | Role::Encoder => {
                self.fail(direction, CLOSED_CRITICAL.to_owned(), decoded)
            }
            Role::Untyped | Role::Pushing if !self.buffer.is_empty() => {
                self.fail(direction, CUT_HEADER.to_owned(), decoded);
            }
            _ => {}
        }
    }

    /// Hands over what is left of the side once the connection closed.
    fn finish(mut self, direction: Direction, decoded: &mut Vec<Decoded>) {
        if let Role::Messages(messages) = &mut self.role {
            decoded.extend(messages.message.take().map(Decoded::Message));
            if messages.blocked {
                let detail = STILL_BLOCKED.to_owned();
                decoded.push(Decoded::Fault { direction, detail });
            }
        }
        decoded.extend(unparsed(direction, &self.buffer));
    }
}

impl Messages {
    /// Starts reading the messages of a kind on a stream.
    fn new(kind: Kind, stream: u64, promises: bool) -> Self {
        Self {
            kind,
            stream,
            message: None,
            trailed: false,
            promises,
            required: None,
            blocked: false,
        }
    }

    /// Takes a field section's fields as a message's fields or its trailers, handing over an informational response.
    fn take_fields(&mut self, fields: Vec<Field>, decoded: &mut Vec<Decoded>) {
        if let Some(message) = &mut self.message {
            message.trailers = fields;
            self.trailed = true;
            return;
        }
        let informational = self.kind == Kind::Response && is_informational(&fields);
        let message = Message {
            kind: self.kind,
            stream: Some(self.stream),
            start_line: None,
            fields,
            body: Vec::new(),
            trailers: Vec::new(),
            complete: informational,
        };
        match informational {
            true => decoded.push(Decoded::Message(message)),
            false => self.message = Some(message),
        }
    }
}

/// Reads the first frame type of a client's bidirectional stream, which says whether it carries an HTTP request.
fn open_request(stream: u64, half: &mut Half) -> Step {
    let Some(kind) = frame_type(&half.buffer) else {
        return Step::Wait;
    };
    let http = kind != WEBTRANSPORT_STREAM;
    half.http = Some(http);
    half.role = match http {
        true => Role::Messages(Messages::new(Kind::Request, stream, false)),
        false => Role::Unparsed,
    };
    Step::Next
}

/// Returns the type of the frame at the front of the bytes, once it came whole.
fn frame_type(bytes: &[u8]) -> Option<u64> {
    Cursor::new(bytes).varint().ok()
}

/// Returns the frame at the front of the bytes, once it came whole.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-7.1
fn frame(bytes: &[u8]) -> Option<Frame> {
    let mut cursor = Cursor::new(bytes);
    cursor.varint().ok()?;
    let length = cursor.varint().ok()?;
    let payload = cursor.take(length).ok()?.to_vec();
    Some(Frame {
        payload,
        length: cursor.read(),
    })
}

/// Returns the settings a SETTINGS frame's payload holds.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
fn read_settings(payload: &[u8]) -> Result<Settings, String> {
    let mut cursor = Cursor::new(payload);
    let mut settings = Settings::default();
    let mut seen = BTreeSet::new();
    while !cursor.rest().is_empty() {
        let (Ok(id), Ok(value)) = (cursor.varint(), cursor.varint()) else {
            return Err("a SETTINGS frame cut short".to_owned());
        };
        if !seen.insert(id) {
            return Err(format!("setting {id} twice in a SETTINGS frame"));
        }
        match id {
            QPACK_MAX_TABLE_CAPACITY => settings.max_table_capacity = value,
            QPACK_BLOCKED_STREAMS => settings.blocked_streams = value,
            _ => {}
        }
    }
    Ok(settings)
}

/// Returns whether a type is one of those reserved to exercise the rule that unknown types are ignored.
fn is_reserved(kind: u64) -> bool {
    kind.checked_sub(RESERVED_FIRST)
        .is_some_and(|offset| offset % RESERVED_STEP == u64::MIN)
}

/// Returns the peer that did not send in the direction.
fn other(direction: Direction) -> Direction {
    match direction {
        Direction::Client => Direction::Server,
        Direction::Server => Direction::Client,
    }
}

/// Returns response fields' informational status, if they have one.
fn is_informational(fields: &[Field]) -> bool {
    fields
        .iter()
        .find(|field| field.name == STATUS_NAME.as_bytes())
        .is_some_and(|field| field.value.first() == Some(&INFORMATIONAL))
}

/// Returns the bytes as unparsed from the side, unless there are none.
fn unparsed(direction: Direction, bytes: &[u8]) -> Option<Decoded> {
    (!bytes.is_empty()).then(|| Decoded::Unparsed {
        direction,
        bytes: bytes.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client's first unidirectional stream, here its control stream.
    const CLIENT_CONTROL: u64 = 2;
    /// The client's second unidirectional stream, here its QPACK encoder stream.
    const CLIENT_ENCODER: u64 = 6;
    /// The server's first unidirectional stream, here its control stream.
    const SERVER_CONTROL: u64 = 3;
    /// The server's second unidirectional stream, here a push stream.
    const SERVER_PUSH: u64 = 7;
    /// The table capacity the server allows, as in RFC 9204's examples.
    const CAPACITY: u64 = 220;
    /// The client's encoder stream of RFC 9204 Appendix B.2: a capacity and two inserts.
    const B2_INSERTS: &[u8] = b"\x3f\xbd\x01\xc0\x0fwww.example.com\xc1\x0c/sample/path";
    /// RFC 9204 Appendix B.2's field section, which needs both of its inserts.
    const B2_SECTION: &[u8] = b"\x03\x81\x10\x11";

    /// Returns a QUIC variable-length integer's shortest bytes.
    fn varint(value: u64) -> Vec<u8> {
        if value < 0x40 {
            vec![value as u8]
        } else if value < 0x4000 {
            ((value as u16) | 0x4000).to_be_bytes().to_vec()
        } else {
            ((value as u32) | 0x8000_0000).to_be_bytes().to_vec()
        }
    }

    /// Returns a frame's bytes.
    fn frame(kind: u64, payload: &[u8]) -> Vec<u8> {
        let mut bytes = varint(kind);
        bytes.extend(varint(payload.len() as u64));
        bytes.extend(payload);
        bytes
    }

    /// Returns a prefixed integer's bytes, the bits above the prefix set as in the pattern.
    fn integer(pattern: u8, prefix: u32, mut value: u64) -> Vec<u8> {
        let mask = (1u64 << prefix) - 1;
        if value < mask {
            return vec![pattern | value as u8];
        }
        let mut bytes = vec![pattern | mask as u8];
        value -= mask;
        while value >= 0x80 {
            bytes.push(value as u8 | 0x80);
            value >>= 7;
        }
        bytes.push(value as u8);
        bytes
    }

    /// Returns a field section that needs no dynamic table, each field a literal with a literal name.
    fn section(fields: &[(&str, &str)]) -> Vec<u8> {
        let mut bytes = vec![0, 0];
        for (name, value) in fields {
            bytes.extend(integer(0x20, 3, name.len() as u64));
            bytes.extend(name.as_bytes());
            bytes.extend(integer(0, 7, value.len() as u64));
            bytes.extend(value.as_bytes());
        }
        bytes
    }

    /// Returns a HEADERS frame with the fields.
    fn headers(fields: &[(&str, &str)]) -> Vec<u8> {
        frame(HEADERS_FRAME, &section(fields))
    }

    /// Returns a control stream's bytes up to its SETTINGS.
    fn control(capacity: u64, blocked: u64) -> Vec<u8> {
        let mut settings = varint(QPACK_MAX_TABLE_CAPACITY);
        settings.extend(varint(capacity));
        settings.extend(varint(QPACK_BLOCKED_STREAMS));
        settings.extend(varint(blocked));
        let mut bytes = varint(CONTROL_STREAM);
        bytes.extend(frame(SETTINGS, &settings));
        bytes
    }

    /// Returns fields from text.
    fn fields(fields: &[(&str, &str)]) -> Vec<Field> {
        fields
            .iter()
            .map(|(name, value)| Field {
                name: name.as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            })
            .collect()
    }

    /// Returns the messages decoded, failing if anything else was.
    fn messages(decoded: Vec<Decoded>) -> Vec<Message> {
        decoded
            .into_iter()
            .map(|each| match each {
                Decoded::Message(message) => message,
                other => panic!("only messages: {other:?}"),
            })
            .collect()
    }

    /// The request every exchange below starts with.
    const GET: &[(&str, &str)] = &[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "example.com"),
        (":path", "/"),
    ];

    #[test]
    fn reads_a_get_whose_body_is_split_across_frames_and_calls() {
        let mut server = headers(&[(STATUS_NAME, "200"), ("content-type", "text/plain")]);
        server.extend(frame(DATA_FRAME, b"hel"));
        server.extend(frame(RESERVED_FIRST + RESERVED_STEP, b"skipped"));
        server.extend(frame(0x2a, b"unknown"));
        server.extend(frame(DATA_FRAME, b"lo"));
        let mut runs: Vec<Vec<&[u8]>> = (0..=server.len())
            .map(|at| vec![&server[..at], &server[at..]])
            .collect();
        runs.push(server.chunks(1).collect());
        for run in runs {
            let mut decoder = Http3.start_connection();
            let mut decoded = decoder.decode_stream(
                Direction::Client,
                CLIENT_CONTROL,
                &control(CAPACITY, 16),
                false,
            );
            decoded.extend(decoder.decode_stream(
                Direction::Server,
                SERVER_CONTROL,
                &control(CAPACITY, 16),
                false,
            ));
            decoded.extend(decoder.decode_stream(Direction::Client, 0, &headers(GET), true));
            let last = run.len() - 1;
            for (at, chunk) in run.into_iter().enumerate() {
                decoded.extend(decoder.decode_stream(Direction::Server, 0, chunk, at == last));
            }
            decoded.extend(decoder.finish());
            let [request, response] = messages(decoded)
                .try_into()
                .expect("a request and a response");
            assert_eq!(
                (request.kind, request.stream, request.start_line.as_ref()),
                (Kind::Request, Some(0), None)
            );
            assert_eq!((request.fields, request.complete), (fields(GET), true));
            assert_eq!(
                response.fields,
                fields(&[(STATUS_NAME, "200"), ("content-type", "text/plain")])
            );
            assert_eq!(
                (response.kind, response.body.as_slice(), response.complete),
                (Kind::Response, &b"hello"[..], true)
            );
        }
    }

    #[test]
    fn reads_a_post_with_its_body_and_trailers() {
        let mut client = headers(&[(":method", "POST"), (":path", "/upload")]);
        client.extend(frame(DATA_FRAME, b"a=1"));
        client.extend(frame(DATA_FRAME, b"&b=2"));
        client.extend(headers(&[("x-checksum", "abc")]));
        let mut decoder = Http3.start_connection();
        let mut decoded = decoder.decode_stream(Direction::Client, 4, &client, false);
        assert!(
            decoded.is_empty(),
            "the request waits for its end: {decoded:?}"
        );
        decoded.extend(decoder.decode_stream(Direction::Client, 4, &[], true));
        decoded.extend(decoder.decode_stream(
            Direction::Server,
            4,
            &headers(&[(STATUS_NAME, "204")]),
            true,
        ));
        let [request, response] = messages(decoded)
            .try_into()
            .expect("a request and a response");
        assert_eq!(
            (request.stream, request.body.as_slice(), request.complete),
            (Some(4), &b"a=1&b=2"[..], true)
        );
        assert_eq!(request.trailers, fields(&[("x-checksum", "abc")]));
        assert_eq!(
            (response.stream, response.body.len(), response.complete),
            (Some(4), 0, true)
        );
    }

    #[test]
    fn hands_over_informational_responses_before_the_final_one() {
        let mut server = headers(&[(STATUS_NAME, "100")]);
        server.extend(headers(&[
            (STATUS_NAME, "103"),
            ("link", "</style.css>; rel=preload"),
        ]));
        server.extend(headers(&[(STATUS_NAME, "200")]));
        server.extend(frame(DATA_FRAME, b"ok"));
        let mut decoder = Http3.start_connection();
        let mut decoded = decoder.decode_stream(Direction::Client, 0, &headers(GET), true);
        decoded.extend(decoder.decode_stream(Direction::Server, 0, &server, true));
        let [_, continuing, early, last] = messages(decoded)
            .try_into()
            .expect("a request and three responses");
        assert_eq!(
            (continuing.fields, continuing.complete),
            (fields(&[(STATUS_NAME, "100")]), true)
        );
        assert_eq!(
            early.fields,
            fields(&[(STATUS_NAME, "103"), ("link", "</style.css>; rel=preload")])
        );
        assert!(early.complete);
        assert_eq!((last.body.as_slice(), last.complete), (&b"ok"[..], true));
    }

    #[test]
    fn decodes_a_blocked_section_once_the_encoder_stream_catches_up() {
        let mut request = frame(HEADERS_FRAME, B2_SECTION);
        request.extend(frame(DATA_FRAME, b"after"));
        let mut encoder = varint(ENCODER_STREAM);
        encoder.extend(B2_INSERTS);
        let mut decoder = Http3.start_connection();
        assert!(
            decoder
                .decode_stream(
                    Direction::Server,
                    SERVER_CONTROL,
                    &control(CAPACITY, 16),
                    false
                )
                .is_empty()
        );
        assert!(
            decoder
                .decode_stream(Direction::Client, 0, &request, true)
                .is_empty()
        );
        let (early, late) = encoder.split_at(encoder.len() - 1);
        assert!(
            decoder
                .decode_stream(Direction::Client, CLIENT_ENCODER, early, false)
                .is_empty()
        );
        let [request] =
            messages(decoder.decode_stream(Direction::Client, CLIENT_ENCODER, late, false))
                .try_into()
                .expect("the request");
        assert_eq!(
            request.fields,
            fields(&[(":authority", "www.example.com"), (":path", "/sample/path")])
        );
        assert_eq!(
            (request.body.as_slice(), request.complete),
            (&b"after"[..], true)
        );
    }

    #[test]
    fn waits_for_the_settings_a_section_needs() {
        let mut encoder = varint(ENCODER_STREAM);
        encoder.extend(B2_INSERTS);
        let mut decoder = Http3.start_connection();
        assert!(
            decoder
                .decode_stream(Direction::Client, CLIENT_ENCODER, &encoder, false)
                .is_empty()
        );
        assert!(
            decoder
                .decode_stream(
                    Direction::Client,
                    0,
                    &frame(HEADERS_FRAME, B2_SECTION),
                    true
                )
                .is_empty()
        );
        let decoded = decoder.decode_stream(
            Direction::Server,
            SERVER_CONTROL,
            &control(CAPACITY, 16),
            false,
        );
        let [request] = messages(decoded).try_into().expect("the request");
        assert_eq!((request.fields.len(), request.complete), (2, true));
    }

    #[test]
    fn hands_over_a_section_still_blocked_at_finish() {
        let mut request = frame(HEADERS_FRAME, B2_SECTION);
        request.extend(frame(DATA_FRAME, b"after"));
        let mut decoder = Http3.start_connection();
        decoder.decode_stream(
            Direction::Server,
            SERVER_CONTROL,
            &control(CAPACITY, 16),
            false,
        );
        assert!(
            decoder
                .decode_stream(Direction::Client, 0, &request, true)
                .is_empty()
        );
        let decoded = decoder.finish();
        let [
            Decoded::Fault {
                direction: Direction::Client,
                ..
            },
            Decoded::Unparsed {
                direction: Direction::Client,
                bytes,
            },
        ] = decoded.as_slice()
        else {
            panic!("a fault and the stream's bytes: {decoded:?}");
        };
        assert_eq!(bytes, &request);
        assert!(decoder.finish().is_empty());
    }

    #[test]
    fn faults_a_section_past_the_blocked_streams_setting() {
        let mut decoder = Http3.start_connection();
        decoder.decode_stream(
            Direction::Server,
            SERVER_CONTROL,
            &control(CAPACITY, 0),
            false,
        );
        let decoded = decoder.decode_stream(
            Direction::Client,
            0,
            &frame(HEADERS_FRAME, B2_SECTION),
            true,
        );
        assert!(
            matches!(
                decoded.as_slice(),
                [Decoded::Fault { .. }, Decoded::Unparsed { .. }]
            ),
            "{decoded:?}"
        );
    }

    #[test]
    fn reads_a_server_push_and_its_promise() {
        let css: &[(&str, &str)] = &[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/a.css"),
        ];
        let mut promise = varint(0);
        promise.extend(section(css));
        let mut unopened = varint(1);
        unopened.extend(section(css));
        let mut server = frame(PUSH_PROMISE_FRAME, &promise);
        server.extend(frame(PUSH_PROMISE_FRAME, &unopened));
        server.extend(headers(&[(STATUS_NAME, "200")]));
        let mut push = varint(PUSH_STREAM);
        push.extend(varint(0));
        push.extend(headers(&[
            (STATUS_NAME, "200"),
            ("content-type", "text/css"),
        ]));
        push.extend(frame(DATA_FRAME, b"body{}"));

        let mut decoder = Http3.start_connection();
        let mut decoded = decoder.decode_stream(Direction::Client, 0, &headers(GET), true);
        decoded.extend(decoder.decode_stream(Direction::Server, 0, &server, true));
        decoded.extend(decoder.decode_stream(Direction::Server, SERVER_PUSH, &push, true));
        decoded.extend(decoder.finish());
        let [request, response, promised, pushed, unopened] =
            messages(decoded).try_into().expect("five messages");
        assert_eq!((request.stream, response.stream), (Some(0), Some(0)));
        assert_eq!(
            (
                promised.kind,
                promised.stream,
                promised.fields,
                promised.complete
            ),
            (Kind::Request, Some(SERVER_PUSH), fields(css), true)
        );
        assert_eq!(
            (pushed.kind, pushed.stream, pushed.body.as_slice()),
            (Kind::Response, Some(SERVER_PUSH), &b"body{}"[..])
        );
        assert!(pushed.complete);
        assert_eq!((unopened.stream, unopened.fields), (Some(0), fields(css)));
    }

    #[test]
    fn returns_garbage_on_a_request_stream_while_others_decode() {
        let garbage = [frame(HEADERS_FRAME, b"\x00\x00\xff"), b"more".to_vec()].concat();
        let mut decoder = Http3.start_connection();
        let decoded = decoder.decode_stream(Direction::Client, 0, &garbage, false);
        let [
            Decoded::Fault {
                direction: Direction::Client,
                ..
            },
            Decoded::Unparsed { bytes, .. },
        ] = decoded.as_slice()
        else {
            panic!("a fault and the garbage: {decoded:?}");
        };
        assert_eq!(bytes, &garbage);
        let decoded = decoder.decode_stream(Direction::Client, 0, b"even more", true);
        assert_eq!(
            decoded,
            [Decoded::Unparsed {
                direction: Direction::Client,
                bytes: b"even more".to_vec()
            }]
        );
        let [request] = messages(decoder.decode_stream(Direction::Client, 4, &headers(GET), true))
            .try_into()
            .expect("a request");
        assert_eq!((request.stream, request.complete), (Some(4), true));
    }

    #[test]
    fn hands_over_a_message_cut_short_at_finish() {
        let mut client = headers(GET);
        client.extend(frame(DATA_FRAME, b"part"));
        let cut = [0x00, 0x05, b'a'];
        client.extend(cut);
        let mut decoder = Http3.start_connection();
        assert!(
            decoder
                .decode_stream(Direction::Client, 0, &client, false)
                .is_empty()
        );
        let decoded = decoder.finish();
        let [Decoded::Message(request), Decoded::Unparsed { bytes, .. }] = decoded.as_slice()
        else {
            panic!("the request and the cut frame: {decoded:?}");
        };
        assert_eq!(
            (request.body.as_slice(), request.complete),
            (&b"part"[..], false)
        );
        assert_eq!(bytes, &cut);
        assert!(decoder.finish().is_empty());
    }

    #[test]
    fn returns_a_control_stream_that_breaks_the_rules_unparsed() {
        let settings = frame(SETTINGS, &[QPACK_MAX_TABLE_CAPACITY as u8]);
        let stream = [varint(CONTROL_STREAM), settings.clone()].concat();
        let mut decoder = Http3.start_connection();
        let decoded = decoder.decode_stream(Direction::Server, SERVER_CONTROL, &stream, false);
        let [Decoded::Fault { .. }, Decoded::Unparsed { bytes, .. }] = decoded.as_slice() else {
            panic!("a fault and the SETTINGS frame: {decoded:?}");
        };
        assert_eq!(bytes, &settings);
        let mut second = varint(CONTROL_STREAM);
        second.extend(frame(SETTINGS, &[]));
        let decoded = decoder.decode_stream(Direction::Server, SERVER_PUSH, &second, false);
        assert!(
            matches!(
                decoded.as_slice(),
                [Decoded::Fault { .. }, Decoded::Unparsed { .. }]
            ),
            "{decoded:?}"
        );
    }

    #[test]
    fn returns_streams_that_are_no_http_unparsed() {
        let mut webtransport = varint(WEBTRANSPORT_STREAM);
        webtransport.extend(b"\x00raw");
        let mut unknown_uni = varint(0x54);
        unknown_uni.extend(b"\x00data");
        let mut reserved_uni = varint(RESERVED_FIRST);
        reserved_uni.extend(b"dropped");
        let mut decoder_stream = varint(DECODER_STREAM);
        decoder_stream.push(0x84);
        let mut decoder = Http3.start_connection();
        let mut decoded = decoder.decode_stream(Direction::Server, 4, b"answer", false);
        decoded.extend(decoder.decode_stream(Direction::Client, 4, &webtransport, false));
        decoded.extend(decoder.decode_stream(
            Direction::Client,
            CLIENT_CONTROL,
            &unknown_uni,
            false,
        ));
        decoded.extend(decoder.decode_stream(
            Direction::Client,
            CLIENT_ENCODER,
            &reserved_uni,
            false,
        ));
        decoded.extend(decoder.decode_stream(
            Direction::Server,
            SERVER_CONTROL,
            &decoder_stream,
            false,
        ));
        decoded.extend(decoder.decode_stream(Direction::Server, 1, b"server bidi", false));
        decoded.extend(decoder.decode(Direction::Client, b"no stream"));
        decoded.extend(decoder.finish());
        let expected = [
            Decoded::Unparsed {
                direction: Direction::Client,
                bytes: webtransport,
            },
            Decoded::Unparsed {
                direction: Direction::Server,
                bytes: b"answer".to_vec(),
            },
            Decoded::Unparsed {
                direction: Direction::Client,
                bytes: unknown_uni,
            },
            Decoded::Unparsed {
                direction: Direction::Server,
                bytes: b"server bidi".to_vec(),
            },
            Decoded::Unparsed {
                direction: Direction::Client,
                bytes: b"no stream".to_vec(),
            },
        ];
        assert_eq!(decoded, expected);
    }
}
