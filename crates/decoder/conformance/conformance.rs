//! The tests every implementation of simple-httptap-decoder runs, written against its traits alone.

use simple_httptap_decoder::{ConnectionDecoder, Decoded, Decoder, Direction};

/// Bytes that are no HTTP message in any version.
const NOT_HTTP: &[u8] = b"\0not http at all\r\n\r\nstill not\r\n\r\n";

/// Checks that no bytes decode to nothing, before and after the connection closes.
pub fn decodes_nothing_from_no_bytes<T: Decoder>(decoder: T) {
    let mut connection = decoder.start_connection();
    assert!(connection.decode(Direction::Client, &[]).is_empty());
    assert!(connection.decode(Direction::Server, &[]).is_empty());
    assert!(connection.finish().is_empty());
}

/// Checks that bytes that are no HTTP come out again whole, unparsed, from the side that sent them.
pub fn returns_every_byte_of_what_is_no_http<T: Decoder>(decoder: T) {
    let mut connection = decoder.start_connection();
    let mut decoded = connection.decode(Direction::Client, NOT_HTTP);
    decoded.extend(connection.finish());
    let mut unparsed = Vec::new();
    for each in decoded {
        match each {
            Decoded::Unparsed { direction, bytes } => {
                assert_eq!(direction, Direction::Client);
                unparsed.extend(bytes);
            }
            Decoded::Fault { direction, .. } => assert_eq!(direction, Direction::Client),
            Decoded::Message(message) => panic!("no HTTP decoded as a message: {message:?}"),
        }
    }
    assert_eq!(unparsed, NOT_HTTP);
}

/// Checks that a second finish returns nothing more than the first.
pub fn finishes_once<T: Decoder>(decoder: T) {
    let mut connection = decoder.start_connection();
    connection.decode(Direction::Client, NOT_HTTP);
    connection.finish();
    assert!(connection.finish().is_empty());
}

/// Runs each suite function above as its own test on a value made anew for every test.
///
/// List every suite function here, in the order above, and nothing else.
#[macro_export]
macro_rules! tests {
    ($value:expr) => {
        #[test]
        fn decodes_nothing_from_no_bytes() {
            $crate::decodes_nothing_from_no_bytes($value);
        }

        #[test]
        fn returns_every_byte_of_what_is_no_http() {
            $crate::returns_every_byte_of_what_is_no_http($value);
        }

        #[test]
        fn finishes_once() {
            $crate::finishes_once($value);
        }
    };
}
