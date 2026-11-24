//! An HTTP/1 decoder that frames each side's messages as RFC 9112 says and keeps every byte it is given.

use std::collections::VecDeque;
use std::mem;

use http::{Method, StatusCode};
use simple_httptap_decoder::{ConnectionDecoder, Decoded, Decoder, Direction, Field, Kind, Message};

/// The HTTP/1 decoder.
#[derive(Debug)]
pub struct Http1;

impl Decoder for Http1 {
    type Connection = Http1Connection;

    fn start_connection(&self) -> Http1Connection {
        Http1Connection(Reader::default())
    }
}

/// A decoder of one HTTP/1 connection.
#[derive(Debug)]
pub struct Http1Connection(Reader);

impl ConnectionDecoder for Http1Connection {
    fn decode(&mut self, direction: Direction, bytes: &[u8]) -> Vec<Decoded> {
        self.0.decode(direction, bytes)
    }

    fn finish(&mut self) -> Vec<Decoded> {
        self.0.finish()
    }
}

/// The reading of one connection: each side's state and the methods of the requests still unanswered.
#[derive(Debug, Default)]
struct Reader {
    client: Side,
    server: Side,
    /// The methods of the requests whose responses are still to come, oldest first.
    methods: VecDeque<Vec<u8>>,
}

impl Reader {
    /// Reads the next bytes one side sent and returns everything they completed.
    fn decode(&mut self, direction: Direction, bytes: &[u8]) -> Vec<Decoded> {
        let mut decoded = Vec::new();
        self.side(direction).buffer.extend_from_slice(bytes);
        self.advance(direction, &mut decoded);
        decoded
    }

    /// Returns everything left once the connection closed.
    fn finish(&mut self) -> Vec<Decoded> {
        let mut decoded = Vec::new();
        for direction in [Direction::Client, Direction::Server] {
            self.side(direction).finish(direction, &mut decoded);
        }
        decoded
    }
}

/// The line feed that ends every line of a message head.
///
/// https://www.rfc-editor.org/rfc/rfc9112#section-2.2
const LINE_FEED: u8 = b'\n';
/// The carriage return before a line feed, which a recipient may go without.
///
/// https://www.rfc-editor.org/rfc/rfc9112#section-2.2
const CARRIAGE_RETURN: u8 = b'\r';
/// The space between the parts of a start line.
///
/// https://www.rfc-editor.org/rfc/rfc9112#section-3
const SPACE: u8 = b' ';
/// The horizontal tab, which with the space is the whitespace around a field value.
///
/// https://www.rfc-editor.org/rfc/rfc9110#section-5.6.3
const HORIZONTAL_TAB: u8 = b'\t';
/// The colon between a field's name and its value.
///
/// https://www.rfc-editor.org/rfc/rfc9112#section-5
const COLON: u8 = b':';
/// The comma between the members of a list field, such as several transfer codings.
///
/// https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1
const COMMA: u8 = b',';
/// The semicolon before a chunk's extensions.
///
/// https://www.rfc-editor.org/rfc/rfc9112#section-7.1.1
const SEMICOLON: u8 = b';';
/// The base a chunk's size is written in.
///
/// https://www.rfc-editor.org/rfc/rfc9112#section-7.1
const CHUNK_SIZE_RADIX: u32 = 16;
/// The parts of a request line: method, target and version.
///
/// https://www.rfc-editor.org/rfc/rfc9112#section-3
const REQUEST_LINE_PARTS: usize = 3;
/// The start of the version in a start line.
const VERSION_PREFIX: &[u8] = b"HTTP/";
/// The transfer coding that frames a body in chunks.
const CHUNKED: &[u8] = b"chunked";

/// The bytes one side sent that are not read yet, and the state of reading them.
#[derive(Debug, Default)]
struct Side {
    buffer: Vec<u8>,
    state: State,
}

/// The reading state of one side.
#[derive(Debug, Default)]
enum State {
    /// Waiting for the head of the next message.
    #[default]
    Head,
    /// Reading a message's body.
    Body { message: Message, framing: Framing },
    /// Holding the client's bytes after a request to switch protocols, until the response says whether it did.
    Held,
    /// No longer reading HTTP: after a protocol switch, a tunnel or a fault.
    Unparsed,
}

/// The rule that ends a body.
#[derive(Debug)]
enum Framing {
    /// After this many more bytes.
    Length(u64),
    /// In chunks, at the given step.
    Chunked(Chunk),
    /// When the connection closes.
    Close,
}

/// The step of reading a chunked body.
#[derive(Debug)]
enum Chunk {
    /// The line with the next chunk's size.
    Size,
    /// This many more bytes of the chunk's data.
    Data(u64),
    /// The line ending after a chunk's data.
    DataEnd,
    /// The trailer fields after the last chunk.
    Trailers,
}

/// The outcome of one step of a chunked body.
enum Progress {
    /// On to the next step.
    Next(Chunk),
    /// Waiting at the step for more bytes.
    Wait(Chunk),
    /// The body ended.
    Done,
}

/// An announcement, made by a message head, of what follows it.
enum Body {
    /// No body; the next message follows.
    None,
    /// A body framed so.
    Framed(Framing),
    /// The connection stops being HTTP after this message.
    Switch,
    /// The client asked to switch protocols, so what it sends next waits for the response.
    Hold,
}

impl Reader {
    /// Returns the state of the side that sent in the direction.
    fn side(&mut self, direction: Direction) -> &mut Side {
        match direction {
            Direction::Client => &mut self.client,
            Direction::Server => &mut self.server,
        }
    }

    /// Reads what the side has buffered as far as it goes, and the client's too once a response lets it go on.
    fn advance(&mut self, direction: Direction, decoded: &mut Vec<Decoded>) {
        while let Some(released) = self.step(direction, decoded) {
            if released {
                self.advance(Direction::Client, decoded);
            }
        }
    }

    /// Reads one step of the side, returning none when it needs more bytes.
    ///
    /// It returns true when the step was a response that lets the client's held bytes go on.
    fn step(&mut self, direction: Direction, decoded: &mut Vec<Decoded>) -> Option<bool> {
        let side = self.side(direction);
        match mem::take(&mut side.state) {
            State::Unparsed => {
                side.state = State::Unparsed;
                if !side.buffer.is_empty() {
                    decoded.push(Decoded::Unparsed { direction, bytes: mem::take(&mut side.buffer) });
                }
                None
            }
            State::Held => {
                side.state = State::Held;
                None
            }
            State::Head => self.read_head(direction, decoded),
            State::Body { mut message, framing } => match read_body(&mut side.buffer, &mut message, framing) {
                Ok(Some(framing)) => {
                    side.state = State::Body { message, framing };
                    None
                }
                Ok(None) => {
                    decoded.push(Decoded::Message(message));
                    Some(false)
                }
                Err(detail) => {
                    decoded.push(Decoded::Message(message));
                    decoded.push(Decoded::Fault { direction, detail });
                    side.state = State::Unparsed;
                    Some(false)
                }
            },
        }
    }

    /// Reads the next message head of the side if it is all there.
    fn read_head(&mut self, direction: Direction, decoded: &mut Vec<Decoded>) -> Option<bool> {
        let side = self.side(direction);
        let blank = blank_lines_length(&side.buffer);
        if blank != usize::MIN {
            decoded.push(Decoded::Unparsed { direction, bytes: side.buffer.drain(..blank).collect() });
        }
        let Some(length) = head_length(&side.buffer) else {
            side.state = State::Head;
            return None;
        };
        let (start_line, fields) = match parse_head(&side.buffer[..length], direction) {
            Ok(head) => head,
            Err(detail) => {
                decoded.push(Decoded::Fault { direction, detail });
                side.state = State::Unparsed;
                return Some(false);
            }
        };
        side.buffer.drain(..length);
        let body = match direction {
            Direction::Client => self.frame_request(&start_line, &fields),
            Direction::Server => self.frame_response(&start_line, &fields),
        };
        let message = Message {
            kind: match direction {
                Direction::Client => Kind::Request,
                Direction::Server => Kind::Response,
            },
            stream: None,
            start_line: Some(start_line),
            fields,
            body: Vec::new(),
            trailers: Vec::new(),
            complete: false,
        };
        let (state, released) = match body {
            Err(detail) => {
                decoded.push(Decoded::Message(message));
                decoded.push(Decoded::Fault { direction, detail });
                (State::Unparsed, false)
            }
            Ok(Body::None) => {
                decoded.push(Decoded::Message(Message { complete: true, ..message }));
                (State::Head, self.release_client(direction, State::Head))
            }
            Ok(Body::Framed(framing)) => {
                (State::Body { message, framing }, self.release_client(direction, State::Head))
            }
            Ok(Body::Switch) => {
                decoded.push(Decoded::Message(Message { complete: true, ..message }));
                (State::Unparsed, self.release_client(direction, State::Unparsed))
            }
            Ok(Body::Hold) => {
                decoded.push(Decoded::Message(Message { complete: true, ..message }));
                (State::Held, false)
            }
        };
        self.side(direction).state = state;
        Some(released)
    }

    /// Lets the client's held bytes go on in the state once a final response came, returning whether it did.
    fn release_client(&mut self, direction: Direction, state: State) -> bool {
        if direction != Direction::Server || !matches!(self.client.state, State::Held) {
            return false;
        }
        self.client.state = state;
        true
    }

    /// Says how the request's body is framed and remembers its method for the response.
    fn frame_request(&mut self, start_line: &[u8], fields: &[Field]) -> Result<Body, String> {
        let method = start_line.split(|byte| *byte == SPACE).next().unwrap_or_default().to_vec();
        let asks_to_switch =
            method == Method::CONNECT.as_str().as_bytes() || find_field(fields, http::header::UPGRADE.as_str());
        self.methods.push_back(method);
        Ok(match frame_by_fields(fields)? {
            Some(Framing::Close) => return Err("a request's last transfer coding is not chunked".to_owned()),
            Some(framing) => Body::Framed(framing),
            None if asks_to_switch => Body::Hold,
            None => Body::None,
        })
    }

    /// Says how the response's body is framed, from its status and the method of the request it answers.
    fn frame_response(&mut self, start_line: &[u8], fields: &[Field]) -> Result<Body, String> {
        let status = status_of(start_line)?;
        if status == StatusCode::SWITCHING_PROTOCOLS {
            self.methods.pop_front();
            return Ok(Body::Switch);
        }
        if status.is_informational() {
            return Ok(Body::None);
        }
        let method = self.methods.pop_front().unwrap_or_default();
        if method == Method::CONNECT.as_str().as_bytes() && status.is_success() {
            return Ok(Body::Switch);
        }
        if method == Method::HEAD.as_str().as_bytes()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED
        {
            return Ok(Body::None);
        }
        Ok(Body::Framed(frame_by_fields(fields)?.unwrap_or(Framing::Close)))
    }
}

impl Side {
    /// Hands over everything left once the connection closed.
    fn finish(&mut self, direction: Direction, decoded: &mut Vec<Decoded>) {
        if let State::Body { mut message, framing } = mem::replace(&mut self.state, State::Unparsed) {
            message.complete = matches!(framing, Framing::Close);
            decoded.push(Decoded::Message(message));
        }
        if !self.buffer.is_empty() {
            decoded.push(Decoded::Unparsed { direction, bytes: mem::take(&mut self.buffer) });
        }
    }
}

/// Returns the length of the empty lines at the start of the bytes, which a recipient skips before a start line.
///
/// https://www.rfc-editor.org/rfc/rfc9112#section-2.2
fn blank_lines_length(bytes: &[u8]) -> usize {
    let mut length = usize::MIN;
    loop {
        let rest = &bytes[length..];
        if rest.starts_with(&[LINE_FEED]) {
            length += 1;
        } else if rest.starts_with(&[CARRIAGE_RETURN, LINE_FEED]) {
            length += 2;
        } else {
            return length;
        }
    }
}

/// Returns the length of the head at the start of the bytes, its empty last line included, if it is all there.
fn head_length(bytes: &[u8]) -> Option<usize> {
    let mut start = usize::MIN;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != LINE_FEED {
            continue;
        }
        if start != usize::MIN && trim_carriage_return(&bytes[start..index]).is_empty() {
            return Some(index + 1);
        }
        start = index + 1;
    }
    None
}

/// Removes the carriage return at the end of a line, if it has one.
fn trim_carriage_return(line: &[u8]) -> &[u8] {
    line.strip_suffix(&[CARRIAGE_RETURN]).unwrap_or(line)
}

/// Parses a head into its start line and its fields, checking the start line has the form its side sends.
fn parse_head(head: &[u8], direction: Direction) -> Result<(Vec<u8>, Vec<Field>), String> {
    let mut lines: Vec<&[u8]> = head.split(|byte| *byte == LINE_FEED).map(trim_carriage_return).collect();
    lines.pop();
    let (start_line, field_lines) = lines.split_first().ok_or("an empty head")?;
    let parts: Vec<&[u8]> = start_line.splitn(REQUEST_LINE_PARTS, |byte| *byte == SPACE).collect();
    let well_formed = match direction {
        Direction::Client => {
            parts.len() == REQUEST_LINE_PARTS
                && parts.iter().all(|part| !part.is_empty())
                && parts.last().is_some_and(|version| version.starts_with(VERSION_PREFIX))
        }
        Direction::Server => parts.len() > 1 && parts[0].starts_with(VERSION_PREFIX),
    };
    if !well_formed {
        return Err(format!("not an HTTP/1 start line: {:?}", String::from_utf8_lossy(start_line)));
    }
    Ok((start_line.to_vec(), parse_fields(field_lines)?))
}

/// Parses field lines, skipping the empty line that ends them and joining obsolete folded lines with a space.
///
/// https://www.rfc-editor.org/rfc/rfc9112#section-5.2
fn parse_fields(lines: &[&[u8]]) -> Result<Vec<Field>, String> {
    let mut fields: Vec<Field> = Vec::new();
    for line in lines.iter().filter(|line| !line.is_empty()) {
        if line.starts_with(&[SPACE]) || line.starts_with(&[HORIZONTAL_TAB]) {
            let field = fields.last_mut().ok_or("a folded line before any field")?;
            field.value.push(SPACE);
            field.value.extend_from_slice(trim_whitespace(line));
            continue;
        }
        let colon = line
            .iter()
            .position(|byte| *byte == COLON)
            .ok_or_else(|| format!("a field line without a colon: {:?}", String::from_utf8_lossy(line)))?;
        let name = &line[..colon];
        if name.is_empty() || name.iter().any(is_whitespace) {
            return Err(format!("a field name that is empty or has whitespace: {:?}", String::from_utf8_lossy(name)));
        }
        fields.push(Field { name: name.to_vec(), value: trim_whitespace(&line[colon + 1..]).to_vec() });
    }
    Ok(fields)
}

/// Returns whether the byte is a space or a tab.
fn is_whitespace(byte: &u8) -> bool {
    *byte == SPACE || *byte == HORIZONTAL_TAB
}

/// Removes the spaces and tabs around a value.
fn trim_whitespace(value: &[u8]) -> &[u8] {
    let start = value.iter().position(|byte| !is_whitespace(byte)).unwrap_or(value.len());
    let end = value.iter().rposition(|byte| !is_whitespace(byte)).map_or(start, |last| last + 1);
    &value[start..end]
}

/// Returns whether a field has the name, in any case.
fn find_field(fields: &[Field], name: &str) -> bool {
    fields.iter().any(|field| field.name.eq_ignore_ascii_case(name.as_bytes()))
}

/// Returns the values of every field with the name, in any case, split at commas, in order.
fn find_list_values<'a>(fields: &'a [Field], name: &'a str) -> impl Iterator<Item = &'a [u8]> {
    fields
        .iter()
        .filter(move |field| field.name.eq_ignore_ascii_case(name.as_bytes()))
        .flat_map(|field| field.value.split(|byte| *byte == COMMA).map(trim_whitespace))
}

/// Returns the three-digit code after the version in a status line.
fn status_of(start_line: &[u8]) -> Result<StatusCode, String> {
    let code = start_line.split(|byte| *byte == SPACE).nth(1).unwrap_or_default();
    StatusCode::from_bytes(code).map_err(|_| format!("not a status code: {:?}", String::from_utf8_lossy(code)))
}

/// Says how the fields frame the body: chunked, by length, until the connection closes, or none given.
///
/// https://www.rfc-editor.org/rfc/rfc9112#section-6.3
fn frame_by_fields(fields: &[Field]) -> Result<Option<Framing>, String> {
    if let Some(last) = find_list_values(fields, http::header::TRANSFER_ENCODING.as_str()).last() {
        return Ok(Some(if last.eq_ignore_ascii_case(CHUNKED) {
            Framing::Chunked(Chunk::Size)
        } else {
            Framing::Close
        }));
    }
    let mut length = None;
    for value in find_list_values(fields, http::header::CONTENT_LENGTH.as_str()) {
        let parsed: u64 = std::str::from_utf8(value)
            .ok()
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| format!("not a content length: {:?}", String::from_utf8_lossy(value)))?;
        if length.is_some_and(|known| known != parsed) {
            return Err("content lengths that disagree".to_owned());
        }
        length = Some(parsed);
    }
    Ok(length.map(Framing::Length))
}

/// Moves body bytes from the buffer into the message, returning the framing left, or none once the body ended.
fn read_body(buffer: &mut Vec<u8>, message: &mut Message, framing: Framing) -> Result<Option<Framing>, String> {
    let mut chunk = match framing {
        Framing::Close => {
            message.body.append(buffer);
            return Ok(Some(Framing::Close));
        }
        Framing::Length(remaining) => {
            let remaining = remaining - take_up_to(buffer, remaining, &mut message.body);
            if remaining != u64::MIN {
                return Ok(Some(Framing::Length(remaining)));
            }
            message.complete = true;
            return Ok(None);
        }
        Framing::Chunked(chunk) => chunk,
    };
    loop {
        chunk = match read_chunk(buffer, message, chunk)? {
            Progress::Next(next) => next,
            Progress::Wait(waiting) => return Ok(Some(Framing::Chunked(waiting))),
            Progress::Done => return Ok(None),
        };
    }
}

/// Moves up to the count of bytes from the front of the buffer to the body, returning how many it moved.
fn take_up_to(buffer: &mut Vec<u8>, count: u64, body: &mut Vec<u8>) -> u64 {
    let length = usize::try_from(count).map_or(buffer.len(), |count| count.min(buffer.len()));
    body.extend(buffer.drain(..length));
    length as u64
}

/// Removes and returns the next whole line from the buffer, without its line ending.
fn take_line(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let end = buffer.iter().position(|byte| *byte == LINE_FEED)?;
    let line: Vec<u8> = buffer.drain(..=end).collect();
    Some(trim_carriage_return(&line[..end]).to_vec())
}

/// Reads one step of a chunked body.
///
/// https://www.rfc-editor.org/rfc/rfc9112#section-7.1
fn read_chunk(buffer: &mut Vec<u8>, message: &mut Message, chunk: Chunk) -> Result<Progress, String> {
    Ok(match chunk {
        Chunk::Size => {
            let Some(line) = take_line(buffer) else { return Ok(Progress::Wait(Chunk::Size)) };
            let size = line.split(|byte| *byte == SEMICOLON).next().map(trim_whitespace).unwrap_or_default();
            let size = std::str::from_utf8(size)
                .ok()
                .and_then(|text| u64::from_str_radix(text, CHUNK_SIZE_RADIX).ok())
                .ok_or_else(|| format!("not a chunk size: {:?}", String::from_utf8_lossy(&line)))?;
            Progress::Next(if size == u64::MIN { Chunk::Trailers } else { Chunk::Data(size) })
        }
        Chunk::Data(remaining) => {
            if buffer.is_empty() {
                return Ok(Progress::Wait(Chunk::Data(remaining)));
            }
            let remaining = remaining - take_up_to(buffer, remaining, &mut message.body);
            Progress::Next(if remaining == u64::MIN { Chunk::DataEnd } else { Chunk::Data(remaining) })
        }
        Chunk::DataEnd => {
            let Some(line) = take_line(buffer) else { return Ok(Progress::Wait(Chunk::DataEnd)) };
            if !line.is_empty() {
                return Err("chunk data longer than its size".to_owned());
            }
            Progress::Next(Chunk::Size)
        }
        Chunk::Trailers => {
            let Some(line) = take_line(buffer) else { return Ok(Progress::Wait(Chunk::Trailers)) };
            if line.is_empty() {
                message.complete = true;
                return Ok(Progress::Done);
            }
            message.trailers.extend(parse_fields(&[&line])?);
            Progress::Next(Chunk::Trailers)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns every message the bytes decode to, each side's bytes given in one piece and then byte by byte.
    fn decode_both_ways(client: &[u8], server: &[u8]) -> Vec<Vec<Decoded>> {
        let whole = {
            let mut decoder = Http1.start_connection();
            let mut decoded = decoder.decode(Direction::Client, client);
            decoded.extend(decoder.decode(Direction::Server, server));
            decoded.extend(decoder.finish());
            decoded
        };
        let piecewise = {
            let mut decoder = Http1.start_connection();
            let mut decoded = Vec::new();
            for byte in client {
                decoded.extend(decoder.decode(Direction::Client, std::slice::from_ref(byte)));
            }
            for byte in server {
                decoded.extend(decoder.decode(Direction::Server, std::slice::from_ref(byte)));
            }
            decoded.extend(decoder.finish());
            decoded
        };
        vec![whole, piecewise]
    }

    /// Returns the field names of a message in order.
    fn names(message: &Message) -> Vec<&[u8]> {
        message.fields.iter().map(|field| field.name.as_slice()).collect()
    }

    #[test]
    fn keeps_field_order_case_and_bodies() {
        let client = b"POST /a HTTP/1.1\r\nZebra: 1\r\nhOsT: x\r\nX-Dup: a\r\nX-Dup: b\r\nContent-Length: 5\r\n\r\nhello";
        let server = b"HTTP/1.1 200 OK\r\nB: 2\r\nA: 1\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nT-Last: z\r\n\r\n";
        for decoded in decode_both_ways(client, server) {
            let [Decoded::Message(request), Decoded::Message(response)] = decoded.as_slice() else {
                panic!("two messages: {decoded:?}");
            };
            assert_eq!(names(request), [&b"Zebra"[..], b"hOsT", b"X-Dup", b"X-Dup", b"Content-Length"]);
            assert_eq!(request.body, b"hello");
            assert!(request.complete);
            assert_eq!(response.start_line.as_deref(), Some(&b"HTTP/1.1 200 OK"[..]));
            assert_eq!(names(response), [&b"B"[..], b"A", b"Transfer-Encoding"]);
            assert_eq!(response.body, b"abcde");
            assert_eq!(response.trailers, [Field { name: b"T-Last".to_vec(), value: b"z".to_vec() }]);
            assert!(response.complete);
        }
    }

    #[test]
    fn frames_responses_by_their_request() {
        let client = b"HEAD / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n";
        let server = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\nuntil close";
        for decoded in decode_both_ways(client, server) {
            let bodies: Vec<(&[u8], bool)> = decoded
                .iter()
                .map(|each| match each {
                    Decoded::Message(message) => (message.body.as_slice(), message.complete),
                    other => panic!("only messages: {other:?}"),
                })
                .collect();
            assert_eq!(bodies, [(&b""[..], true), (b"", true), (b"", true), (b"", true), (b"until close", true)]);
        }
    }

    #[test]
    fn passes_bytes_after_a_protocol_switch_through() {
        let client = b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n\x81\x02hi";
        let server = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x02yo";
        for decoded in decode_both_ways(client, server) {
            let unparsed: Vec<u8> = decoded
                .iter()
                .filter_map(|each| match each {
                    Decoded::Unparsed { bytes, .. } => Some(bytes.clone()),
                    _ => None,
                })
                .flatten()
                .collect();
            let mut expected = b"\x81\x02yo".to_vec();
            expected.extend(b"\x81\x02hi");
            let mut sorted = unparsed.clone();
            sorted.sort_unstable();
            expected.sort_unstable();
            assert_eq!(sorted, expected);
        }
    }

    #[test]
    fn marks_a_body_cut_short() {
        for decoded in decode_both_ways(b"PUT / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc", b"") {
            let [Decoded::Message(request)] = decoded.as_slice() else { panic!("one message: {decoded:?}") };
            assert_eq!(request.body, b"abc");
            assert!(!request.complete);
        }
    }
}
