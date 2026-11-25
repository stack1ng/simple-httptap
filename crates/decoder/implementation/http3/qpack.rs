//! The field compression of RFC 9204: the static table, the dynamic table an encoder stream builds, and field sections.

use std::collections::VecDeque;
use std::fmt;

use loona_hpack::huffman::HuffmanDecoder;
use simple_httptap_decoder::Field;

/// The name of the pseudo-header field with a response's status.
///
/// https://www.rfc-editor.org/rfc/rfc9114#section-4.3.2
pub(crate) const STATUS_NAME: &str = ":status";
/// The fault for a field section whose bytes end inside a field line or its prefix.
const CUT_SECTION: &str = "a field section cut short";
/// The fields every QPACK peer knows, by index.
///
/// https://www.rfc-editor.org/rfc/rfc9204#appendix-A
const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (STATUS_NAME, "103"),
    (STATUS_NAME, "200"),
    (STATUS_NAME, "304"),
    (STATUS_NAME, "404"),
    (STATUS_NAME, "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (STATUS_NAME, "100"),
    (STATUS_NAME, "204"),
    (STATUS_NAME, "206"),
    (STATUS_NAME, "302"),
    (STATUS_NAME, "400"),
    (STATUS_NAME, "403"),
    (STATUS_NAME, "421"),
    (STATUS_NAME, "425"),
    (STATUS_NAME, "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];
/// The bytes a dynamic table counts for each entry on top of its name and value.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-3.2.1
const ENTRY_OVERHEAD: u64 = 32;
/// The bits of a QUIC variable-length integer's first byte that give its length.
///
/// https://www.rfc-editor.org/rfc/rfc9000#section-16
const VARINT_LENGTH_BITS: u32 = 2;
/// The bit of a prefixed integer's byte that says another byte follows.
///
/// https://www.rfc-editor.org/rfc/rfc7541#section-5.1
const MORE: u8 = 0x80;
/// The bits of a prefixed integer that each byte after its first holds.
///
/// https://www.rfc-editor.org/rfc/rfc7541#section-5.1
const CONTINUATION_BITS: u32 = 7;
/// The prefix of a string's length, and of a field section's Delta Base, whose next higher bit is a flag.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.1.2
const VALUE_PREFIX: u32 = 7;
/// The prefix of the index in Insert With Name Reference and in Indexed Field Line, after a static flag.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.3.2
const INDEX_PREFIX: u32 = 6;
/// The prefix of Set Dynamic Table Capacity, of Duplicate, and of Insert With Literal Name's name.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.3
const INSTRUCTION_PREFIX: u32 = 5;
/// The prefix of the index in Literal Field Line With Name Reference and in Indexed Field Line With Post-Base Index.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.5.4
const REFERENCE_PREFIX: u32 = 4;
/// The prefix of a literal name, and of the index in Literal Field Line With Post-Base Name Reference.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.5.6
const NAME_PREFIX: u32 = 3;
/// The leading zero bits of Insert With Name Reference, and of Indexed Field Line.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.3.2
const NO_ZEROS: u32 = u32::MIN;
/// The leading zero bits of Insert With Literal Name, and of Literal Field Line With Name Reference.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.3.3
const ONE_ZERO: u32 = NO_ZEROS + 1;
/// The leading zero bits of Set Dynamic Table Capacity, and of Literal Field Line With Literal Name.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.3.1
const TWO_ZEROS: u32 = ONE_ZERO + 1;
/// The leading zero bits of Indexed Field Line With Post-Base Index.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.5.3
const THREE_ZEROS: u32 = TWO_ZEROS + 1;

/// Why bytes could not be read.
#[derive(Debug)]
pub(crate) enum Error {
    /// They stop before what they started ends, so more may complete it.
    Short,
    /// They break the format in the way the detail says.
    Malformed(String),
}

impl From<&str> for Error {
    fn from(detail: &str) -> Self {
        Self::Malformed(detail.to_owned())
    }
}

/// A reader that takes bytes off the front of a slice and says when they run out.
pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    /// Starts reading at the first byte.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            at: usize::MIN,
        }
    }

    /// Returns how many bytes have been read.
    pub(crate) fn read(&self) -> usize {
        self.at
    }

    /// Returns the bytes not read yet.
    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at..]
    }

    /// Returns the next byte without reading it.
    fn peek(&self) -> Result<u8, Error> {
        self.rest().first().copied().ok_or(Error::Short)
    }

    /// Reads the next bytes of the length.
    pub(crate) fn take(&mut self, length: u64) -> Result<&'a [u8], Error> {
        let length = usize::try_from(length).map_err(|_| Error::Short)?;
        let taken = self.rest().get(..length).ok_or(Error::Short)?;
        self.at += length;
        Ok(taken)
    }

    /// Reads a QUIC variable-length integer.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9000#section-16
    pub(crate) fn varint(&mut self) -> Result<u64, Error> {
        let first = self.peek()?;
        let length = 1 << (first >> (u8::BITS - VARINT_LENGTH_BITS));
        let (head, tail) = self.take(length)?.split_first().ok_or(Error::Short)?;
        let value = u64::from(head & (u8::MAX >> VARINT_LENGTH_BITS));
        Ok(tail
            .iter()
            .fold(value, |value, byte| value << u8::BITS | u64::from(*byte)))
    }

    /// Reads an integer whose first byte holds it in the prefix's low bits, the bits above being the caller's.
    ///
    /// https://www.rfc-editor.org/rfc/rfc7541#section-5.1
    fn integer(&mut self, prefix: u32) -> Result<u64, Error> {
        let mask = u8::MAX >> (u8::BITS - prefix);
        let first = self.take(1)?[usize::MIN] & mask;
        let mut value = u64::from(first);
        if first < mask {
            return Ok(value);
        }
        let mut shift = u32::MIN;
        loop {
            let byte = self.take(1)?[usize::MIN];
            let part = u64::from(byte & !MORE);
            let shifted = part
                .checked_shl(shift)
                .filter(|shifted| shifted >> shift == part);
            value = shifted
                .and_then(|shifted| value.checked_add(shifted))
                .ok_or("an integer too large")?;
            if byte & MORE == u8::MIN {
                return Ok(value);
            }
            shift += CONTINUATION_BITS;
        }
    }

    /// Reads a string whose length has the prefix, after the flag bit that says it is Huffman-coded.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9204#section-4.1.2
    fn string(&mut self, prefix: u32, huffman: &mut Huffman) -> Result<Vec<u8>, Error> {
        let coded = self.peek()? & flag(prefix) != u8::MIN;
        let length = self.integer(prefix)?;
        let bytes = self.take(length)?;
        if coded {
            huffman.decode(bytes)
        } else {
            Ok(bytes.to_vec())
        }
    }
}

/// Returns the bit just above a prefix, which flags something about what follows.
fn flag(prefix: u32) -> u8 {
    1 << prefix
}

/// A decoder of Huffman-coded strings, made on first use as its table takes some building.
#[derive(Default)]
pub(crate) struct Huffman(Option<HuffmanDecoder>);

impl fmt::Debug for Huffman {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(std::any::type_name::<Self>())
    }
}

impl Huffman {
    /// Returns the bytes a Huffman-coded string stands for.
    ///
    /// https://www.rfc-editor.org/rfc/rfc7541#appendix-B
    fn decode(&mut self, coded: &[u8]) -> Result<Vec<u8>, Error> {
        let decoder = self.0.get_or_insert_with(HuffmanDecoder::new);
        decoder.decode(coded).map_err(|fault| {
            Error::Malformed(format!(
                "a Huffman-coded string that does not decode: {fault}"
            ))
        })
    }
}

/// The dynamic table one peer's encoder stream builds for the field sections it sends.
#[derive(Debug, Default)]
pub(crate) struct Table {
    /// The entries not evicted yet, oldest first.
    entries: VecDeque<Field>,
    /// How many entries were ever inserted, which is one more than the newest's absolute index.
    inserted: u64,
    /// The sum of the entries' sizes.
    size: u64,
    capacity: u64,
}

impl Table {
    /// Returns the entry at the absolute index, if it was inserted and not evicted.
    fn get(&self, absolute: u64) -> Result<&Field, Error> {
        let evicted = self.inserted - self.entries.len() as u64;
        absolute
            .checked_sub(evicted)
            .and_then(|at| self.entries.get(usize::try_from(at).ok()?))
            .ok_or_else(|| {
                Error::Malformed(format!(
                    "a reference to dynamic table entry {absolute}, which it lacks"
                ))
            })
    }

    /// Evicts the oldest entries until the table holds no more than the size.
    fn evict(&mut self, size: u64) {
        while self.size > size {
            let Some(oldest) = self.entries.pop_front() else {
                return;
            };
            self.size -= entry_size(&oldest);
        }
    }

    /// Adds an entry, evicting the oldest ones to make room.
    fn insert(&mut self, field: Field) -> Result<(), Error> {
        let size = entry_size(&field);
        let room = self
            .capacity
            .checked_sub(size)
            .ok_or("an entry larger than the dynamic table's capacity")?;
        self.evict(room);
        self.size += size;
        self.entries.push_back(field);
        self.inserted += 1;
        Ok(())
    }

    /// Reads one encoder instruction off the front of the bytes and applies it, returning how many bytes it took.
    ///
    /// The capacity the decoding peer allows bounds Set Dynamic Table Capacity once its SETTINGS are known.
    /// https://www.rfc-editor.org/rfc/rfc9204#section-4.3
    pub(crate) fn read_instruction(
        &mut self,
        bytes: &[u8],
        allowed: Option<u64>,
        huffman: &mut Huffman,
    ) -> Result<usize, Error> {
        let mut cursor = Cursor::new(bytes);
        let first = cursor.peek()?;
        match first.leading_zeros() {
            NO_ZEROS => {
                let is_static = first & flag(INDEX_PREFIX) != u8::MIN;
                let index = cursor.integer(INDEX_PREFIX)?;
                let value = cursor.string(VALUE_PREFIX, huffman)?;
                let name = match is_static {
                    true => static_field(index)?.name,
                    false => self.get(relative(self.inserted, index)?)?.name.clone(),
                };
                self.insert(Field { name, value })?;
            }
            ONE_ZERO => {
                let name = cursor.string(INSTRUCTION_PREFIX, huffman)?;
                let value = cursor.string(VALUE_PREFIX, huffman)?;
                self.insert(Field { name, value })?;
            }
            TWO_ZEROS => {
                let capacity = cursor.integer(INSTRUCTION_PREFIX)?;
                if allowed.is_some_and(|allowed| capacity > allowed) {
                    return Err(
                        "a dynamic table capacity above SETTINGS_QPACK_MAX_TABLE_CAPACITY".into(),
                    );
                }
                self.capacity = capacity;
                self.evict(capacity);
            }
            _ => {
                let index = cursor.integer(INSTRUCTION_PREFIX)?;
                let field = self.get(relative(self.inserted, index)?)?.clone();
                self.insert(field)?;
            }
        }
        Ok(cursor.read())
    }
}

/// Returns the bytes a dynamic table counts for an entry.
fn entry_size(field: &Field) -> u64 {
    (field.name.len() + field.value.len()) as u64 + ENTRY_OVERHEAD
}

/// Returns the absolute index a relative index stands for, counting back from the base.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-3.2.5
fn relative(base: u64, index: u64) -> Result<u64, Error> {
    base.checked_sub(index)
        .and_then(|after| after.checked_sub(1))
        .ok_or_else(|| "a relative index before the first entry".into())
}

/// Returns the static table's entry at the index.
fn static_field(index: u64) -> Result<Field, Error> {
    let (name, value) = usize::try_from(index)
        .ok()
        .and_then(|index| STATIC_TABLE.get(index))
        .ok_or_else(|| Error::Malformed(format!("static table index {index}, past its end")))?;
    Ok(Field {
        name: name.as_bytes().to_vec(),
        value: value.as_bytes().to_vec(),
    })
}

/// The outcome of decoding a field section: its fields, or a wait for entries or SETTINGS.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Section {
    /// The fields, in the order sent.
    Fields(Vec<Field>),
    /// It waits for dynamic table entries, or for the SETTINGS that say how to read its Required Insert Count.
    Blocked,
}

/// Decodes a field section with the sending peer's dynamic table.
///
/// `allowed` is the decoding peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY, once its SETTINGS came. `required` keeps the
/// Required Insert Count across tries, as more inserts would change how it reads.
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.5
pub(crate) fn decode_section(
    payload: &[u8],
    table: &Table,
    allowed: Option<u64>,
    required: &mut Option<u64>,
    huffman: &mut Huffman,
) -> Result<Section, String> {
    let fault = |error| match error {
        Error::Short => CUT_SECTION.to_owned(),
        Error::Malformed(detail) => detail,
    };
    let mut cursor = Cursor::new(payload);
    let encoded = cursor.integer(u8::BITS).map_err(fault)?;
    let count = match (*required, allowed) {
        (Some(count), _) => count,
        (None, _) if encoded == u64::MIN => u64::MIN,
        (None, None) => return Ok(Section::Blocked),
        (None, Some(allowed)) => *required.insert(decode_required_insert_count(
            encoded,
            allowed / ENTRY_OVERHEAD,
            table.inserted,
        )?),
    };
    if count > table.inserted {
        return Ok(Section::Blocked);
    }
    let negative = cursor.peek().map_err(fault)? & flag(VALUE_PREFIX) != u8::MIN;
    let delta = cursor.integer(VALUE_PREFIX).map_err(fault)?;
    let base = match negative {
        true => count
            .checked_sub(delta)
            .and_then(|base| base.checked_sub(1)),
        false => count.checked_add(delta),
    }
    .ok_or("a field section's base out of range")?;
    let mut fields = Vec::new();
    while !cursor.rest().is_empty() {
        fields.push(field_line(&mut cursor, table, base, count, huffman).map_err(fault)?);
    }
    Ok(Section::Fields(fields))
}

/// Returns the Required Insert Count an encoded one stands for, given the inserts seen so far.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.5.1.1
fn decode_required_insert_count(
    encoded: u64,
    max_entries: u64,
    inserted: u64,
) -> Result<u64, String> {
    let full_range = max_entries * 2;
    if encoded > full_range {
        return Err(format!(
            "an encoded Required Insert Count of {encoded}, past {full_range}"
        ));
    }
    let max_value = inserted + max_entries;
    let max_wrapped = max_value / full_range * full_range;
    let mut count = max_wrapped + encoded - 1;
    if count > max_value {
        if count <= full_range {
            return Err(format!(
                "an encoded Required Insert Count of {encoded}, which no insert count gives"
            ));
        }
        count -= full_range;
    }
    if count == u64::MIN {
        return Err("a Required Insert Count of zero not encoded as zero".to_owned());
    }
    Ok(count)
}

/// Reads one field line, its dynamic references below the Required Insert Count.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-4.5.2
fn field_line(
    cursor: &mut Cursor<'_>,
    table: &Table,
    base: u64,
    count: u64,
    huffman: &mut Huffman,
) -> Result<Field, Error> {
    let dynamic = |absolute: u64| match absolute < count {
        true => table.get(absolute).cloned(),
        false => Err(Error::Malformed(format!(
            "a reference to entry {absolute}, not below the Required Insert Count"
        ))),
    };
    let first = cursor.peek()?;
    let field = match first.leading_zeros() {
        NO_ZEROS => {
            let is_static = first & flag(INDEX_PREFIX) != u8::MIN;
            let index = cursor.integer(INDEX_PREFIX)?;
            match is_static {
                true => static_field(index)?,
                false => dynamic(relative(base, index)?)?,
            }
        }
        ONE_ZERO => {
            let is_static = first & flag(REFERENCE_PREFIX) != u8::MIN;
            let index = cursor.integer(REFERENCE_PREFIX)?;
            let name = match is_static {
                true => static_field(index)?.name,
                false => dynamic(relative(base, index)?)?.name,
            };
            Field {
                name,
                value: cursor.string(VALUE_PREFIX, huffman)?,
            }
        }
        TWO_ZEROS => {
            let name = cursor.string(NAME_PREFIX, huffman)?;
            Field {
                name,
                value: cursor.string(VALUE_PREFIX, huffman)?,
            }
        }
        THREE_ZEROS => {
            let index = cursor.integer(REFERENCE_PREFIX)?;
            dynamic(post_base(base, index)?)?
        }
        _ => {
            let index = cursor.integer(NAME_PREFIX)?;
            let name = dynamic(post_base(base, index)?)?.name;
            Field {
                name,
                value: cursor.string(VALUE_PREFIX, huffman)?,
            }
        }
    };
    Ok(field)
}

/// Returns the absolute index a post-base index stands for, counting on from the base.
///
/// https://www.rfc-editor.org/rfc/rfc9204#section-3.2.6
fn post_base(base: u64, index: u64) -> Result<u64, Error> {
    base.checked_add(index)
        .ok_or_else(|| "a post-base index too large".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capacity the decoder allows in RFC 9204's examples, which sets the table's to it.
    const EXAMPLE_CAPACITY: u64 = 220;

    /// Returns the bytes hexadecimal digits stand for, spaces aside.
    fn hex(digits: &str) -> Vec<u8> {
        let digits: Vec<u8> = digits
            .bytes()
            .filter(|digit| !digit.is_ascii_whitespace())
            .collect();
        digits
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16)
                    .expect("a hex pair")
            })
            .collect()
    }

    /// Returns a field from text.
    fn field(name: &str, value: &str) -> Field {
        Field {
            name: name.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        }
    }

    /// Feeds encoder stream bytes to the table one at a time, as a stream may bring them.
    fn feed(table: &mut Table, digits: &str, huffman: &mut Huffman) {
        let mut buffer = Vec::new();
        for byte in hex(digits) {
            buffer.push(byte);
            match table.read_instruction(&buffer, Some(EXAMPLE_CAPACITY), huffman) {
                Ok(read) => assert_eq!(buffer.drain(..read).count(), read),
                Err(Error::Short) => {}
                Err(Error::Malformed(detail)) => panic!("{detail}"),
            }
        }
        assert!(buffer.is_empty(), "an instruction left unread: {buffer:?}");
    }

    /// Decodes a field section of hexadecimal digits with the table.
    fn decode(table: &Table, digits: &str, huffman: &mut Huffman) -> Result<Section, String> {
        decode_section(
            &hex(digits),
            table,
            Some(EXAMPLE_CAPACITY),
            &mut None,
            huffman,
        )
    }

    #[test]
    fn decodes_the_rfc_7541_huffman_examples() {
        let examples = [
            ("f1e3 c2e5 f23a 6ba0 ab90 f4ff", "www.example.com"),
            ("a8eb 1064 9cbf", "no-cache"),
            ("25a8 49e9 5ba9 7d7f", "custom-key"),
            ("25a8 49e9 5bb8 e8b4 bf", "custom-value"),
            ("6402", "302"),
            ("aec3 771a 4b", "private"),
            (
                "d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff",
                "Mon, 21 Oct 2013 20:13:21 GMT",
            ),
            (
                "9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3",
                "https://www.example.com",
            ),
        ];
        let mut huffman = Huffman::default();
        for (coded, plain) in examples {
            assert_eq!(
                huffman.decode(&hex(coded)).expect("a Huffman example"),
                plain.as_bytes()
            );
        }
        assert!(
            huffman.decode(&[u8::MIN]).is_err(),
            "padding that is not the EOS code is an error"
        );
    }

    #[test]
    fn decodes_the_rfc_9204_appendix_b_examples() {
        let mut huffman = Huffman::default();
        let mut table = Table::default();
        let b1 = decode(
            &table,
            "0000 510b 2f69 6e64 6578 2e68 746d 6c",
            &mut huffman,
        );
        assert_eq!(b1, Ok(Section::Fields(vec![field(":path", "/index.html")])));

        let b2 = "0381 10 11";
        assert_eq!(decode(&table, b2, &mut huffman), Ok(Section::Blocked));
        feed(
            &mut table,
            "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468",
            &mut huffman,
        );
        assert_eq!(
            (table.capacity, table.size, table.inserted),
            (EXAMPLE_CAPACITY, 106, 2)
        );
        let expected = vec![
            field(":authority", "www.example.com"),
            field(":path", "/sample/path"),
        ];
        assert_eq!(
            decode(&table, b2, &mut huffman),
            Ok(Section::Fields(expected))
        );

        feed(
            &mut table,
            "4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565",
            &mut huffman,
        );
        assert_eq!(table.size, 160);

        let b4 = "0500 80 c1 81";
        assert_eq!(decode(&table, b4, &mut huffman), Ok(Section::Blocked));
        feed(&mut table, "02", &mut huffman);
        assert_eq!(table.size, 217);
        let expected = vec![
            field(":authority", "www.example.com"),
            field(":path", "/"),
            field("custom-key", "custom-value"),
        ];
        assert_eq!(
            decode(&table, b4, &mut huffman),
            Ok(Section::Fields(expected))
        );

        feed(
            &mut table,
            "810d 6375 7374 6f6d 2d76 616c 7565 32",
            &mut huffman,
        );
        assert_eq!((table.size, table.inserted), (215, 5));
        let entries = [
            field(":path", "/sample/path"),
            field("custom-key", "custom-value"),
            field(":authority", "www.example.com"),
            field("custom-key", "custom-value2"),
        ];
        assert!(table.entries.iter().eq(entries.iter()));
        assert!(
            decode(&table, "0500 83", &mut huffman).is_err(),
            "entry 0 was evicted"
        );
    }

    #[test]
    fn reads_huffman_coded_literals_and_post_base_references() {
        let mut huffman = Huffman::default();
        let mut table = Table::default();
        feed(
            &mut table,
            "3fbd01 4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565",
            &mut huffman,
        );
        let post_base = "0280 10 0089 25a8 49e9 5bb8 e8b4 bf 2f01 25a8 49e9 5ba9 7d7f 89 25a8 49e9 5bb8 e8b4 bf c1";
        let custom = field("custom-key", "custom-value");
        let expected = vec![
            custom.clone(),
            custom.clone(),
            custom.clone(),
            field(":path", "/"),
        ];
        assert_eq!(
            decode(&table, post_base, &mut huffman),
            Ok(Section::Fields(expected))
        );
        let relative = "0200 80 4089 25a8 49e9 5bb8 e8b4 bf";
        assert_eq!(
            decode(&table, relative, &mut huffman),
            Ok(Section::Fields(vec![custom.clone(), custom]))
        );
    }

    #[test]
    fn wraps_the_required_insert_count() {
        assert_eq!(decode_required_insert_count(9, 6, 20), Ok(20));
        assert_eq!(decode_required_insert_count(10, 6, 20), Ok(21));
        assert_eq!(decode_required_insert_count(3, 6, 2), Ok(2));
        assert!(decode_required_insert_count(13, 6, 20).is_err());
    }

    #[test]
    fn refuses_what_breaks_the_format() {
        let mut huffman = Huffman::default();
        let table = Table::default();
        assert!(
            decode(&table, "0000 ff24", &mut huffman).is_err(),
            "static index 99 is past the table"
        );
        assert!(
            decode(&table, "0000 5f", &mut huffman).is_err(),
            "a field line cut short"
        );
        let mut table = Table::default();
        let too_large = hex("3fe201");
        assert!(matches!(
            table.read_instruction(&too_large, Some(EXAMPLE_CAPACITY), &mut huffman),
            Err(Error::Malformed(_))
        ));
        let mut cursor = Cursor::new(&[
            0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        ]);
        assert!(matches!(
            cursor.integer(INSTRUCTION_PREFIX),
            Err(Error::Malformed(_))
        ));
    }
}
