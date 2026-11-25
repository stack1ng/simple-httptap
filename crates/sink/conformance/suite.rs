//! The tests every implementation of simple-httptap-sink runs, written against its traits alone.

use std::net::{Ipv4Addr, SocketAddr};

use simple_httptap_decoder::{Decoded, Direction, Field, Kind, Message};
use simple_httptap_sink::{Connection, Event, Sink};

/// A start line of a request.
const START_LINE: &[u8] = b"GET / HTTP/1.1";
/// The name of the field every HTTP/1.1 request carries, written in its usual case.
const FIELD_NAME: &[u8] = b"Host";
/// The host that field names in the request.
const FIELD_VALUE: &[u8] = b"example.com";
/// A tunnel's target.
const TARGET: &str = "example.com:443";
/// A protocol TLS agreed on.
const PROTOCOL: &str = "h2";
/// Why something failed, for a person.
const DETAIL: &str = "a fault";

/// Returns one event of every kind, with bytes that are no UTF-8 among them.
fn every_kind_of_event() -> Vec<Event> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, u16::MAX));
    let message = Message {
        kind: Kind::Request,
        stream: None,
        start_line: Some(START_LINE.to_vec()),
        fields: vec![Field { name: FIELD_NAME.to_vec(), value: FIELD_VALUE.to_vec() }],
        body: vec![u8::MAX],
        trailers: Vec::new(),
        complete: true,
    };
    let id = u64::MIN;
    vec![
        Event::Listening { address },
        Event::Opened(Connection {
            id,
            client: address,
            target: TARGET.to_owned(),
            tls: true,
            protocol: Some(PROTOCOL.to_owned()),
        }),
        Event::Decoded { connection: id, decoded: Decoded::Message(message) },
        Event::Decoded { connection: id, decoded: Decoded::Unparsed { direction: Direction::Server, bytes: vec![u8::MAX] } },
        Event::Decoded { connection: id, decoded: Decoded::Fault { direction: Direction::Client, detail: DETAIL.to_owned() } },
        Event::Refused { connection: id, detail: DETAIL.to_owned() },
        Event::Closed { connection: id },
    ]
}

/// Checks that one event of every kind, bytes that are no UTF-8 among them, is written without an error.
pub fn writes_every_kind_of_event<T: Sink>(sink: T) {
    for event in every_kind_of_event() {
        sink.write_event(&event).expect("the sink writes the event");
    }
}

/// Runs each suite function above as its own test on a value made anew for every test.
///
/// List every suite function here, in the order above, and nothing else.
#[macro_export]
macro_rules! tests {
    ($value:expr) => {
        #[test]
        fn writes_every_kind_of_event() {
            $crate::writes_every_kind_of_event($value);
        }
    };
}
