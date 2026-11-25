//! A sink that writes each event to standard output as one line of JSON, its kind under `event`.
//!
//! Bytes that are UTF-8 are a JSON string, and others `{"base64": ".."}`, so nothing is lost or changed.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use simple_httptap_decoder::{Decoded, Direction, Field, Kind, Message};
use simple_httptap_sink::{Event, Sink, Transport};

/// A sink of JSON lines on standard output.
#[derive(Debug, Default)]
pub struct NdJson;

impl Sink for NdJson {
    fn write_event(&self, event: &Event) -> std::io::Result<()> {
        let mut output = std::io::stdout().lock();
        serde_json::to_writer(&mut output, &Line::of(event))?;
        writeln!(output)?;
        output.flush()
    }
}

/// A JSON line with an event's fields and the time it was written, in Unix milliseconds.
#[derive(Serialize)]
struct Line<'a> {
    #[serde(flatten)]
    event: Happening<'a>,
    unix_ms: u128,
}

/// The fields of each kind of event, the kind's name written under `event`.
#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Happening<'a> {
    Listening { address: String },
    Opened { connection: u64, client: String, target: &'a str, transport: Carrier, tls: bool, protocol: Option<&'a str> },
    Request(Exchanged<'a>),
    Response(Exchanged<'a>),
    Unparsed { connection: u64, from: Side, bytes: Bytes<'a> },
    Fault { connection: u64, from: Side, detail: &'a str },
    Refused { connection: u64, detail: &'a str },
    Closed { connection: u64 },
}

/// A request's or response's fields, each field written as a `[name, value]` pair in order.
#[derive(Serialize)]
struct Exchanged<'a> {
    connection: u64,
    stream: Option<u64>,
    start_line: Option<Bytes<'a>>,
    headers: Vec<(Bytes<'a>, Bytes<'a>)>,
    body: Bytes<'a>,
    trailers: Vec<(Bytes<'a>, Bytes<'a>)>,
    complete: bool,
}

/// A JSON string for UTF-8 bytes, or an object with their base64 for others.
#[derive(Serialize)]
#[serde(untagged)]
enum Bytes<'a> {
    Text(&'a str),
    Binary { base64: String },
}

/// The side that sent some bytes, written in lower case.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Side {
    Client,
    Server,
}

impl<'a> Line<'a> {
    /// Returns the line for an event, stamped with the time now.
    fn of(event: &'a Event) -> Self {
        let unix_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(u128::MIN, |since| since.as_millis());
        let event = match event {
            Event::Listening { address } => Happening::Listening { address: address.to_string() },
            Event::Opened(opened) => Happening::Opened {
                connection: opened.id,
                client: opened.client.to_string(),
                target: &opened.target,
                transport: Carrier::of(opened.transport),
                tls: opened.tls,
                protocol: opened.protocol.as_deref(),
            },
            Event::Decoded { connection, decoded: Decoded::Message(message) } => {
                let exchanged = Exchanged::of(*connection, message);
                match message.kind {
                    Kind::Request => Happening::Request(exchanged),
                    Kind::Response => Happening::Response(exchanged),
                }
            }
            Event::Decoded { connection, decoded: Decoded::Unparsed { direction, bytes } } => {
                Happening::Unparsed { connection: *connection, from: Side::of(*direction), bytes: Bytes::of(bytes) }
            }
            Event::Decoded { connection, decoded: Decoded::Fault { direction, detail } } => {
                Happening::Fault { connection: *connection, from: Side::of(*direction), detail }
            }
            Event::Refused { connection, detail } => Happening::Refused { connection: *connection, detail },
            Event::Closed { connection } => Happening::Closed { connection: *connection },
        };
        Self { event, unix_ms }
    }
}

impl<'a> Exchanged<'a> {
    /// Returns the fields written for a message of the connection.
    fn of(connection: u64, message: &'a Message) -> Self {
        Self {
            connection,
            stream: message.stream,
            start_line: message.start_line.as_deref().map(Bytes::of),
            headers: pairs_of(&message.fields),
            body: Bytes::of(&message.body),
            trailers: pairs_of(&message.trailers),
            complete: message.complete,
        }
    }
}

impl<'a> Bytes<'a> {
    /// Returns the bytes as text if they are UTF-8, or else as base64.
    fn of(bytes: &'a [u8]) -> Self {
        std::str::from_utf8(bytes).map_or_else(|_| Self::Binary { base64: STANDARD.encode(bytes) }, Self::Text)
    }
}

/// The transport a connection went over, written in lower case.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Carrier {
    Tcp,
    Udp,
}

impl Carrier {
    /// Returns the name written for a transport.
    fn of(transport: Transport) -> Self {
        match transport {
            Transport::Tcp => Self::Tcp,
            Transport::Udp => Self::Udp,
        }
    }
}

impl Side {
    /// Returns the side a direction comes from.
    fn of(direction: Direction) -> Self {
        match direction {
            Direction::Client => Self::Client,
            Direction::Server => Self::Server,
        }
    }
}

/// Returns each field as a `[name, value]` pair, in order.
fn pairs_of(fields: &[Field]) -> Vec<(Bytes<'_>, Bytes<'_>)> {
    fields.iter().map(|field| (Bytes::of(&field.name), Bytes::of(&field.value))).collect()
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn writes_fields_in_order_and_bytes_without_loss() {
        let message = Message {
            kind: Kind::Response,
            stream: Some(1),
            start_line: None,
            fields: vec![
                Field { name: b"Zebra".to_vec(), value: b"1".to_vec() },
                Field { name: b"apple".to_vec(), value: vec![u8::MAX] },
            ],
            body: b"text".to_vec(),
            trailers: Vec::new(),
            complete: true,
        };
        let event = Event::Decoded { connection: 7, decoded: Decoded::Message(message) };
        let line = serde_json::to_value(Line::of(&event)).expect("a JSON object");
        assert_eq!(line["event"], "response");
        assert_eq!(line["headers"], json!([["Zebra", "1"], ["apple", { "base64": "/w==" }]]));
        assert_eq!(line["body"], "text");
        let keys: Vec<&String> = line.as_object().map(|object| object.keys().collect()).unwrap_or_default();
        assert_eq!(keys.first().map(|key| key.as_str()), Some("event"));
        assert!(matches!(line["unix_ms"], Value::Number(_)));
    }
}
