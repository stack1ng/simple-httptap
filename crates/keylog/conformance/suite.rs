//! The tests every implementation of simple-httptap-keylog runs, written against its traits alone.

use std::io::Write;
use std::path::PathBuf;

use simple_httptap_keylog::{CLIENT_RANDOM, CLIENT_TRAFFIC_SECRET_0, Keylog, Keys};

/// A client random, as a ClientHello carries it.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
const RANDOM: [u8; 32] = [0xA5; 32];
/// Another client random, which nothing logs a secret for.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
const UNKNOWN_RANDOM: [u8; 32] = [0x5A; 32];
/// A secret of the length of a TLS 1.2 master secret.
///
/// https://www.rfc-editor.org/rfc/rfc5246#section-8.1
const SECRET: [u8; 48] = [0x3C; 48];
/// What follows the label on a line another writer appends: hex in upper case, as some clients write it.
const APPENDED_FIELDS: &str = " A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5 0102030405060708091011121314151617181920212223242526272829303132\n";
/// The secret the appended line holds, as long as a SHA-256 TLS 1.3 traffic secret.
///
/// https://www.rfc-editor.org/rfc/rfc8446#section-7.1
const APPENDED_SECRET: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32,
];
/// The name of the key log file in each test's temporary folder.
const FILE_NAME: &str = "keys.log";

/// Returns a key log file path in a new temporary folder, which it keeps.
fn new_file() -> PathBuf {
    tempfile::tempdir().expect("a temporary folder").keep().join(FILE_NAME)
}

/// Checks that a recorded secret comes back under its label and client random, and nothing under others.
pub fn gives_back_what_it_recorded<T: Keylog>(keylog: T) {
    let keys = keylog.open(&new_file()).expect("the key log opens");
    keys.record(CLIENT_RANDOM, &RANDOM, &SECRET).expect("the secret is recorded");
    assert_eq!(keys.secret(CLIENT_RANDOM, &RANDOM), Some(SECRET.to_vec()));
    assert_eq!(keys.secret(CLIENT_RANDOM, &UNKNOWN_RANDOM), None);
    assert_eq!(keys.secret(CLIENT_TRAFFIC_SECRET_0, &RANDOM), None);
}

/// Checks that a line another writer appends to the file, in upper-case hex, is found.
pub fn reads_what_others_append<T: Keylog>(keylog: T) {
    let file = new_file();
    let keys = keylog.open(&file).expect("the key log opens");
    assert_eq!(keys.secret(CLIENT_TRAFFIC_SECRET_0, &RANDOM), None);
    let mut other = std::fs::OpenOptions::new().append(true).open(&file).expect("another writer opens the file");
    let line = [CLIENT_TRAFFIC_SECRET_0.as_bytes(), APPENDED_FIELDS.as_bytes()].concat();
    other.write_all(&line).expect("the line is appended");
    other.flush().expect("the line is flushed");
    assert_eq!(keys.secret(CLIENT_TRAFFIC_SECRET_0, &RANDOM), Some(APPENDED_SECRET.to_vec()));
}

/// Checks that opening the file again gives back the secrets recorded through the first opening.
pub fn keeps_secrets_in_the_file<T: Keylog>(keylog: T) {
    let file = new_file();
    let first = keylog.open(&file).expect("the key log opens");
    first.record(CLIENT_RANDOM, &RANDOM, &SECRET).expect("the secret is recorded");
    let second = keylog.open(&file).expect("the key log opens again");
    assert_eq!(second.secret(CLIENT_RANDOM, &RANDOM), Some(SECRET.to_vec()));
}

/// Runs each suite function above as its own test on a value made anew for every test.
///
/// List every suite function here, in the order above, and nothing else.
#[macro_export]
macro_rules! tests {
    ($value:expr) => {
        #[test]
        fn gives_back_what_it_recorded() {
            $crate::gives_back_what_it_recorded($value);
        }

        #[test]
        fn reads_what_others_append() {
            $crate::reads_what_others_append($value);
        }

        #[test]
        fn keeps_secrets_in_the_file() {
            $crate::keeps_secrets_in_the_file($value);
        }
    };
}
