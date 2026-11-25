//! The tests every implementation of simple-httptap-decrypter runs, written against its traits alone.

use simple_httptap_decoder::Direction;
use simple_httptap_decrypter::{ConnectionDecrypter, Decrypted, Decrypter};
use simple_httptap_keylog::{Keylog, Keys};
use simple_httptap_keylog_file::FileKeylog;

/// Bytes that are neither TLS records nor QUIC packets.
const NOT_ENCRYPTED: &[u8] = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
/// The name of the empty key log file in each test's temporary folder.
const FILE_NAME: &str = "keys.log";

/// Returns an empty key log in a new temporary folder, which it keeps.
fn empty_keys() -> impl Keys {
    let file = tempfile::tempdir().expect("a temporary folder").keep().join(FILE_NAME);
    FileKeylog.open(&file).expect("the key log opens")
}

/// Returns every opaque byte the side sent, in order, checking nothing came out decrypted.
fn opaque_bytes(decrypted: Vec<Decrypted>, side: Direction) -> Vec<u8> {
    let mut bytes = Vec::new();
    for each in decrypted {
        match each {
            Decrypted::Opaque { direction, bytes: some } => {
                assert_eq!(direction, side);
                bytes.extend(some);
            }
            Decrypted::Fault { direction, .. } => assert_eq!(direction, side),
            Decrypted::Agreed { .. } => {}
            Decrypted::Plain { .. } => panic!("plaintext out of bytes that were never encrypted: {each:?}"),
        }
    }
    bytes
}

/// Checks that no bytes decrypt to nothing, and that a connection that saw nothing finishes with nothing.
pub fn decrypts_nothing_from_no_bytes<T: Decrypter>(decrypter: T) {
    let keys = empty_keys();
    let mut connection = decrypter.start_connection();
    assert!(connection.retry(&keys).is_empty());
    assert!(!connection.is_waiting());
    let mut decrypted = connection.give_up();
    decrypted.extend(connection.finish());
    assert!(decrypted.iter().all(|each| matches!(each, Decrypted::Agreed { .. })), "{decrypted:?}");
}

/// Checks that bytes of no encryption the decrypter knows come back whole and opaque, from the side that sent them.
pub fn gives_back_what_is_not_its_protocol<T: Decrypter>(decrypter: T) {
    let keys = empty_keys();
    let mut connection = decrypter.start_connection();
    let mut decrypted = connection.decrypt(Direction::Client, NOT_ENCRYPTED, &keys);
    decrypted.extend(connection.retry(&keys));
    decrypted.extend(connection.give_up());
    decrypted.extend(connection.finish());
    assert_eq!(opaque_bytes(decrypted, Direction::Client), NOT_ENCRYPTED);
}

/// Checks that a second finish returns nothing more than the first.
pub fn finishes_once<T: Decrypter>(decrypter: T) {
    let keys = empty_keys();
    let mut connection = decrypter.start_connection();
    connection.decrypt(Direction::Server, NOT_ENCRYPTED, &keys);
    connection.finish();
    assert!(connection.finish().is_empty());
    assert!(!connection.is_waiting());
}

/// Runs each suite function above as its own test on a value made anew for every test.
///
/// List every suite function here, in the order above, and nothing else.
#[macro_export]
macro_rules! tests {
    ($value:expr) => {
        #[test]
        fn decrypts_nothing_from_no_bytes() {
            $crate::decrypts_nothing_from_no_bytes($value);
        }

        #[test]
        fn gives_back_what_is_not_its_protocol() {
            $crate::gives_back_what_is_not_its_protocol($value);
        }

        #[test]
        fn finishes_once() {
            $crate::finishes_once($value);
        }
    };
}
