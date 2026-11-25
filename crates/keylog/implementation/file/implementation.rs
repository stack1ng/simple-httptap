//! A key log kept in a file in the NSS format, read again from where it left off whenever a secret is missing.
//!
//! Reading on a miss, rather than on a timer, means a secret is found as soon as the writer has flushed it.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use simple_httptap_keylog::{Keylog, Keys};

/// The keeper of NSS-format key log files, each read again whenever a secret is missing.
#[derive(Debug, Default)]
pub struct FileKeylog;

impl Keylog for FileKeylog {
    type Keys = FileKeys;

    fn open(&self, file: &Path) -> std::io::Result<FileKeys> {
        let writer = OpenOptions::new().create(true).append(true).open(file)?;
        let reader = File::open(file)?;
        let mut state = State { reader, read: u64::MIN, partial: Vec::new(), secrets: HashMap::new() };
        state.catch_up();
        Ok(FileKeys { state: Mutex::new(state), writer: Mutex::new(writer) })
    }
}

/// An open key log file and every secret read from it so far.
#[derive(Debug)]
pub struct FileKeys {
    state: Mutex<State>,
    writer: Mutex<File>,
}

/// How far the file was read, the start of a line not ended yet, and the secrets of the lines before.
#[derive(Debug)]
struct State {
    reader: File,
    read: u64,
    partial: Vec<u8>,
    secrets: HashMap<(String, Vec<u8>), Vec<u8>>,
}

/// The byte that ends each line of a key log.
///
/// https://datatracker.ietf.org/doc/draft-ietf-tls-keylogfile/
const LINE_END: u8 = b'\n';
/// The byte that starts a comment line.
///
/// https://datatracker.ietf.org/doc/draft-ietf-tls-keylogfile/
const COMMENT: u8 = b'#';
/// The separator between a line's label, client random and secret.
const SEPARATOR: char = ' ';
/// The bits of a hex digit.
///
/// https://www.rfc-editor.org/rfc/rfc4648#section-8
const NIBBLE_BITS: u32 = 4;
/// The base of hex digits.
///
/// https://www.rfc-editor.org/rfc/rfc4648#section-8
const HEX: u32 = 16;
/// The hex digits that spell one byte.
///
/// https://www.rfc-editor.org/rfc/rfc4648#section-8
const DIGITS_PER_BYTE: usize = 2;

impl Keys for FileKeys {
    fn record(&self, label: &str, client_random: &[u8], secret: &[u8]) -> std::io::Result<()> {
        let line = format!("{label}{SEPARATOR}{}{SEPARATOR}{}\n", hex(client_random), hex(secret));
        if let Ok(mut state) = self.state.lock() {
            state.secrets.insert((label.to_owned(), client_random.to_vec()), secret.to_vec());
        }
        let mut writer = self.writer.lock().map_err(|_| std::io::Error::other("the key log's writer panicked"))?;
        writer.write_all(line.as_bytes())?;
        writer.flush()
    }

    fn secret(&self, label: &str, client_random: &[u8]) -> Option<Vec<u8>> {
        let key = (label.to_owned(), client_random.to_vec());
        if let Some(secret) = self.state.lock().ok()?.secrets.get(&key) {
            return Some(secret.clone());
        }
        let mut state = self.state.lock().ok()?;
        state.catch_up();
        state.secrets.get(&key).cloned()
    }
}

impl State {
    /// Reads the lines written to the file since the last read; a file that shrank is read again from its start.
    fn catch_up(&mut self) {
        let State { reader, read, partial, secrets } = self;
        let length = reader.metadata().map_or(*read, |metadata| metadata.len());
        if length < *read {
            *read = u64::MIN;
            partial.clear();
        }
        if length == *read || reader.seek(SeekFrom::Start(*read)).is_err() {
            return;
        }
        let mut appended = Vec::new();
        let Ok(count) = reader.read_to_end(&mut appended) else {
            return;
        };
        *read += count as u64;
        partial.extend(appended);
        let Some(last_end) = partial.iter().rposition(|byte| *byte == LINE_END) else {
            return;
        };
        let rest = partial.split_off(last_end + 1);
        for line in partial.split(|byte| *byte == LINE_END) {
            if let Some((label, client_random, secret)) = parse_line(line) {
                secrets.insert((label, client_random), secret);
            }
        }
        *partial = rest;
    }
}

/// Returns a line's label, client random and secret, or none for a comment, an empty line or a malformed one.
fn parse_line(line: &[u8]) -> Option<(String, Vec<u8>, Vec<u8>)> {
    if line.first() == Some(&COMMENT) {
        return None;
    }
    let line = std::str::from_utf8(line).ok()?.trim();
    let mut parts = line.split(SEPARATOR).filter(|part| !part.is_empty());
    let label = parts.next()?.to_owned();
    let client_random = unhex(parts.next()?)?;
    let secret = unhex(parts.next()?)?;
    parts.next().is_none().then_some((label, client_random, secret))
}

/// Returns the bytes as lower-case hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Returns the bytes hex digits of either case spell, or none if they are no whole bytes of hex.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.chars().map(|digit| digit.to_digit(HEX).and_then(|value| u8::try_from(value).ok())).collect::<Option<_>>()?;
    if digits.len() % DIGITS_PER_BYTE != 0 {
        return None;
    }
    Some(digits.chunks(DIGITS_PER_BYTE).map(|pair| (pair[0] << NIBBLE_BITS) | pair[1]).collect())
}
