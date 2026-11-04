//! PDF documents, read the way [`crate::zip`] reads an archive: by walking
//! the file for what is actually there and comparing it against what the
//! document's own index says is there.
//!
//! A PDF is a flat sequence of numbered objects, `N G obj ... endobj`, plus
//! a cross-reference table that maps each object number to its byte offset
//! and a trailer naming which object is the root of the document. Readers
//! follow the trailer and the table; they do not scan the file. That is the
//! opening a competition uses. Editing a PDF rarely rewrites it: the usual
//! tool appends a fresh trailer and cross-reference table at the end and
//! leaves the old bytes in place, which is a legitimate feature (undo,
//! revision history) with an illegitimate use (an object still sitting in
//! the file that the current table no longer points at, invisible to a
//! reader and still readable by a walk).
//!
//! So this walks the whole file for `obj` markers first, independent of any
//! index, and separately reads the cross-reference tables to see what they
//! claim. An object nothing points at any more is reported as such. A
//! stream's own compression is not undone here, the way [`crate::png`] does
//! not inflate a `zTXt` chunk itself: that is a platform call, and this
//! reports where the bytes are so the caller can make it.

use crate::bytes;
use crate::inflate::{Inflated, Wrapper, inflate};
use std::collections::{HashMap, HashSet};

/// Most objects one reading reports. An object header is seven bytes, so a file of
/// nothing else asks for far more text than it holds.
const MAX_OBJECTS: usize = 1 << 18;

/// How far past the next object header a dictionary may run before it is given up on,
/// and how much of that the whole file gets.
///
/// A dictionary stops at the next header, because that is what makes the walk linear:
/// every object's search covers bytes no other object's does, where `1 0 obj<<` over
/// and over has each one searching the rest of the file and keeping all of it. The
/// allowance is for a string inside a dictionary that happens to read like a header,
/// and it runs out long before it could matter on a file built to exhaust it.
const DICT_OVERRUN: usize = 64 * 1024;
const DICT_OVERRUN_TOTAL: usize = 8 << 20;

/// Cross-reference tables followed back through `/Prev`, and entries read across them.
/// A table can start inside another, each then reading through most of the same bytes.
const MAX_REVISIONS_FOLLOWED: usize = 4096;
const MAX_XREF_ENTRIES: usize = 1 << 22;

/// Trailers read from the end of the file, and how far each dictionary is searched.
const TRAILERS_READ: usize = 16;
const TRAILER_SPAN: usize = 1 << 20;

/// Where a byte-string token ends, honouring `\)` and the format's other
/// escapes so a literal string carrying a close paren is not cut short.
fn literal_string_end(data: &[u8], open: usize) -> Option<usize> {
    let mut depth = 1i32;
    let mut at = open + 1;

    while at < data.len() {
        match data[at] {
            b'\\' => at += 2,
            b'(' => {
                depth += 1;
                at += 1;
            }
            b')' => {
                depth -= 1;
                at += 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => at += 1,
        }
    }

    None
}

/// Unescapes a PDF literal string's contents, `\(`, `\)`, `\\`, the newline
/// escapes, and octal escapes up to three digits.
fn unescape_literal(raw: &[u8]) -> String {
    let mut out = String::new();
    let mut at = 0usize;

    while at < raw.len() {
        if raw[at] != b'\\' || at + 1 >= raw.len() {
            out.push(raw[at] as char);
            at += 1;
            continue;
        }

        match raw[at + 1] {
            b'n' => {
                out.push('\n');
                at += 2;
            }
            b'r' => {
                out.push('\r');
                at += 2;
            }
            b't' => {
                out.push('\t');
                at += 2;
            }
            b'(' | b')' | b'\\' => {
                out.push(raw[at + 1] as char);
                at += 2;
            }
            digit @ b'0'..=b'7' => {
                let mut value = (digit - b'0') as u32;
                let mut consumed = 1;
                while consumed < 3 && raw.get(at + 1 + consumed).is_some_and(u8::is_ascii_digit) {
                    value = value * 8 + (raw[at + 1 + consumed] - b'0') as u32;
                    consumed += 1;
                }
                if let Some(byte) = char::from_u32(value) {
                    out.push(byte);
                }
                at += 1 + consumed;
            }
            other => {
                out.push(other as char);
                at += 2;
            }
        }
    }

    out
}

/// Characters that end a name token, whitespace aside.
fn ends_name(byte: u8) -> bool {
    byte.is_ascii_whitespace() || b"()<>[]{}/%".contains(&byte)
}

/// What the format counts as whitespace, which is wider than ASCII's by a NUL.
fn pdf_space(byte: u8) -> bool {
    matches!(byte, 0 | b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

/// A name with its `#xx` escapes undone. `/Fl#61teDecode` is `/FlateDecode` to any reader.
fn unescape_name(raw: &str) -> String {
    if !raw.contains('#') {
        return raw.to_string();
    }

    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0usize;
    while at < bytes.len() {
        let digit = |i: usize| bytes.get(i).and_then(|&b| (b as char).to_digit(16));
        match (bytes[at], digit(at + 1), digit(at + 2)) {
            (b'#', Some(high), Some(low)) => {
                out.push((high * 16 + low) as u8);
                at += 3;
            }
            (byte, ..) => {
                out.push(byte);
                at += 1;
            }
        }
    }
    crate::json::latin1(&out)
}

/// Steps through a dictionary's text one object at a time, the way a reader does.
struct Tokens<'a> {
    bytes: &'a [u8],
    at: usize,
    /// Cleared by an opening that never closes, since searching again from every one that
    /// follows would make a dictionary of them quadratic.
    strings: bool,
    hex: bool,
}

impl Tokens<'_> {
    /// Moves past whitespace and comments.
    fn blank(&mut self) {
        while let Some(&byte) = self.bytes.get(self.at) {
            if byte == b'%' {
                self.at += self.bytes[self.at..]
                    .iter()
                    .position(|&b| b == b'\n' || b == b'\r')
                    .unwrap_or(self.bytes.len() - self.at);
            } else if pdf_space(byte) {
                self.at += 1;
            } else {
                break;
            }
        }
    }

    fn at_pair(&self, pair: &[u8; 2]) -> bool {
        self.bytes.get(self.at..self.at + 2) == Some(pair)
    }

    /// Moves past the name that `at` is on, and says where its text ends.
    fn name(&mut self) -> usize {
        let from = self.at + 1;
        self.at = self.bytes[from..]
            .iter()
            .position(|&b| ends_name(b))
            .map_or(self.bytes.len(), |length| from + length);
        self.at
    }

    /// Moves past a string, or past just its opening if it never closes, and an unmatched
    /// parenthesis must not hide the keys after it.
    fn string(&mut self) {
        let open = self.at;
        self.at += 1;
        if self.strings {
            match literal_string_end(self.bytes, open) {
                Some(end) => self.at = end,
                None => self.strings = false,
            }
        }
    }

    fn hex_string(&mut self) {
        let open = self.at;
        self.at += 1;
        if self.hex {
            match self.bytes[open..].iter().position(|&b| b == b'>') {
                Some(length) => self.at = open + length + 1,
                None => self.hex = false,
            }
        }
    }

    /// Moves past an array or a dictionary, with no recursion, since a file can nest them
    /// as deep as it has bytes.
    fn container(&mut self) {
        let mut depth = 0usize;
        loop {
            self.blank();
            match self.bytes.get(self.at) {
                None => return,
                Some(b'[') => {
                    depth += 1;
                    self.at += 1;
                }
                Some(b']') => {
                    depth = depth.saturating_sub(1);
                    self.at += 1;
                }
                Some(b'<') if self.at_pair(b"<<") => {
                    depth += 1;
                    self.at += 2;
                }
                Some(b'>') if self.at_pair(b">>") => {
                    depth = depth.saturating_sub(1);
                    self.at += 2;
                }
                Some(b'<') => self.hex_string(),
                Some(b'(') => self.string(),
                Some(b'/') => {
                    self.name();
                }
                Some(_) => self.at += 1,
            }
            if depth == 0 {
                return;
            }
        }
    }

    /// Moves past one object: a key's value, or whatever is sitting where a key should be.
    /// A dictionary's closing is left where it is, for a key that has no value.
    fn object(&mut self) {
        self.blank();
        match self.bytes.get(self.at) {
            None => {}
            Some(b'>') if self.at_pair(b">>") => {}
            Some(b'[') => self.container(),
            Some(b'<') if self.at_pair(b"<<") => self.container(),
            Some(b'<') => self.hex_string(),
            Some(b'(') => self.string(),
            Some(b'/') => {
                self.name();
            }
            Some(byte) if byte.is_ascii_digit() => self.number(),
            Some(_) => {
                let from = self.at;
                self.at += 1 + self.bytes[from + 1..]
                    .iter()
                    .position(|&b| ends_name(b))
                    .unwrap_or(self.bytes.len() - from - 1);
            }
        }
    }

    /// Moves past a number, and past ` G R` if that follows, which makes it a reference.
    fn number(&mut self) {
        let bytes = self.bytes;
        let digits = |from: usize| {
            bytes[from.min(bytes.len())..]
                .iter()
                .position(|b| !b.is_ascii_digit())
                .map_or(bytes.len(), |length| from + length)
        };
        let spaces = |from: usize| {
            bytes[from.min(bytes.len())..]
                .iter()
                .position(|&b| !pdf_space(b))
                .map_or(bytes.len(), |length| from + length)
        };

        self.at = digits(self.at);

        let generation = spaces(self.at);
        let after = digits(generation);
        if after > generation {
            let keyword = spaces(after);
            let ends = bytes.get(keyword + 1).is_none_or(|&b| ends_name(b));
            if bytes.get(keyword) == Some(&b'R') && ends {
                self.at = keyword + 1;
            }
        }
    }
}

/// What follows `/Key` at a dictionary's own level.
///
/// A dictionary is pairs, so a name is a key only where a key belongs, and one sitting where
/// a value belongs is that value whatever it spells. A key is a whole name, or `/Length`
/// finds `/Length1`, and it is one of this dictionary's own, or `/Length` finds the one in
/// a `/DecodeParms`. A reader keeps the last of a repeated key, so that is the one taken,
/// or a dictionary could name one filter for whoever stops at the first and another for
/// everyone else.
fn field<'a>(dict: &'a str, key: &str) -> Option<&'a str> {
    let mut tokens = Tokens {
        bytes: dict.as_bytes(),
        at: dict.find("<<")? + 2,
        strings: true,
        hex: true,
    };
    let mut found = None;

    loop {
        tokens.blank();
        match tokens.bytes.get(tokens.at) {
            None => return found,
            Some(b'>') if tokens.at_pair(b">>") => return found,
            Some(b'/') => {
                let start = tokens.at + 1;
                let end = tokens.name();
                if dict.get(start..end).is_some_and(|name| unescape_name(name) == key) {
                    found = dict.get(end..).or(found);
                }
                tokens.object();
            }
            // Not a key, so it is stepped over, with something always consumed.
            Some(_) => {
                let before = tokens.at;
                tokens.object();
                tokens.at = tokens.at.max(before + 1);
            }
        }
    }
}

/// The value of `/Key (literal string)` inside a dictionary's text, if it is
/// there and written as a literal string rather than a hex string or a
/// reference to another object.
fn literal_field(dict: &str, key: &str) -> Option<String> {
    let after = field(dict, key)?.trim_start();
    let bytes = after.as_bytes();

    if bytes.first() != Some(&b'(') {
        return None;
    }

    let end = literal_string_end(bytes, 0)?;
    Some(unescape_literal(&bytes[1..end - 1]))
}

/// The name at the start of a run of text, with its slash.
fn leading_name(text: &str) -> Option<&str> {
    let rest = text.strip_prefix('/')?;
    let end = rest
        .find(|c: char| c.is_ascii() && ends_name(c as u8))
        .unwrap_or(rest.len());
    rest.get(..end)
}

/// The value of `/Key /Name` inside a dictionary's text, the space between
/// them optional: most real PDF writers put one there, and the format
/// permits either.
fn name_field(dict: &str, key: &str) -> Option<String> {
    leading_name(field(dict, key)?.trim_start()).map(unescape_name)
}

/// A filter by the name the format gives it in a stream. The short forms are for inline
/// images, and a reader takes them anywhere.
fn filter_name(raw: &str) -> String {
    match unescape_name(raw).as_str() {
        "Fl" => "FlateDecode".to_string(),
        "AHx" => "ASCIIHexDecode".to_string(),
        "A85" => "ASCII85Decode".to_string(),
        "LZW" => "LZWDecode".to_string(),
        "RL" => "RunLengthDecode".to_string(),
        "DCT" => "DCTDecode".to_string(),
        "CCF" => "CCITTFaxDecode".to_string(),
        name => name.to_string(),
    }
}

/// A dictionary's text with its comments taken out, which a reader skips wherever they
/// fall, between a key and its value as readily as between two keys. A percent sign in a
/// string is only a percent sign. A NUL becomes a space, being whitespace to a reader and
/// the one kind that nothing downstream of this would otherwise step over.
fn without_comments(dict: &str) -> String {
    let mut out = String::with_capacity(dict.len());
    let mut chars = dict.chars();
    let mut in_string = 0usize;

    while let Some(c) = chars.next() {
        match c {
            '%' if in_string == 0 => {
                if let Some(end) = chars.find(|&skipped| skipped == '\n' || skipped == '\r') {
                    out.push(end);
                }
            }
            '\\' if in_string > 0 => {
                out.push(c);
                out.extend(chars.next());
            }
            _ => {
                match c {
                    '(' => in_string += 1,
                    ')' => in_string = in_string.saturating_sub(1),
                    _ => {}
                }
                out.push(if c == '\0' && in_string == 0 { ' ' } else { c });
            }
        }
    }
    out
}

/// What stands in for an element of a filter array that could not be read, which
/// [`decode_stream`] refuses by name, so that it is reported and not skipped.
const UNRESOLVED_FILTER: &str = "UnresolvedFilter";

/// Filter names out of whatever `/Filter` holds: one name, or an array of names and
/// references to names, applied in order. Joined with " then ", so a one-item array reads
/// as that one name.
///
/// @param lookup the filter an object holds, for an element that is a reference to one
fn filter_names(value: &str, lookup: &dyn Fn(u32) -> Option<String>) -> Option<String> {
    let value = value.trim_start();
    let Some(items) = value.strip_prefix('[') else {
        return match parse_number_or_reference(value) {
            Some(Number::Reference(object)) => lookup(object),
            _ => leading_name(value).map(filter_name),
        };
    };

    let items = items.get(..items.find(']')?)?.replace('/', " /");
    let mut tokens = items
        .split(|c: char| u8::try_from(c).is_ok_and(pdf_space))
        .filter(|token| !token.is_empty());

    let mut names = Vec::new();
    while let Some(token) = tokens.next() {
        if let Some(name) = token.strip_prefix('/') {
            names.push(filter_name(name.trim_end()));
            continue;
        }
        let resolved = token
            .parse::<u32>()
            .ok()
            .filter(|_| tokens.next().is_some() && tokens.next() == Some("R"))
            .and_then(lookup);
        names.push(resolved.unwrap_or_else(|| UNRESOLVED_FILTER.to_string()));
    }
    Some(names.join(" then "))
}

/// The value of `/Filter`, under either of the names a reader takes it by, with the last
/// of a repeated key being the one that counts.
fn filter_of(dict: &str, lookup: &dyn Fn(u32) -> Option<String>) -> Option<String> {
    filter_names(field(dict, "Filter").or_else(|| field(dict, "F"))?, lookup)
}



/// The dictionaries `/DecodeParms` holds, one place per filter, either written there or
/// in another object.
fn decode_parms(dict: &str, lookup: &dyn Fn(u32) -> Option<String>) -> Vec<Option<String>> {
    let Some(value) = field(dict, "DecodeParms").or_else(|| field(dict, "DP")) else {
        return Vec::new();
    };
    let value = value.trim_start();
    if !value.starts_with(|c: char| c == '[' || c == '<' || c == 'n' || c.is_ascii_digit()) {
        return Vec::new();
    }

    // One item, or an array of them with a null for a filter that takes none.
    let (items, single) = match value.strip_prefix('[') {
        Some(items) => (items, false),
        None => (value, true),
    };
    let bytes = items.as_bytes();

    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b']' if !single => break,
            b'<' if bytes.get(at + 1) == Some(&b'<') => {
                let Some(end) = dict_end(bytes, at) else {
                    break;
                };
                out.push(items.get(at..end).map(str::to_string));
                at = end;
            }
            b'n' => {
                out.push(None);
                at += 4;
            }
            byte if byte.is_ascii_digit() => {
                let rest = items.get(at..).unwrap_or("");
                let mut parts = rest.split_ascii_whitespace();
                let number = parts.next().and_then(|n| n.parse::<u32>().ok());
                let reference = parts.next().is_some() && parts.next().is_some_and(|r| r.starts_with('R'));
                out.push(number.filter(|_| reference).and_then(lookup));
                at += rest.find('R').filter(|_| reference).map_or(1, |r| r + 1);
            }
            _ => at += 1,
        }
        if single && !out.is_empty() {
            break;
        }
    }
    out
}

/// Filter names with what their parameters say written after each, which is what reaches
/// [`decode_stream`], and what a person reads next to a stream.
fn with_parms(
    filter: String,
    parms: &[Option<String>],
    integer: &dyn Fn(u32) -> Option<usize>,
) -> String {
    if parms.iter().all(Option::is_none) {
        return filter;
    }

    let named = filter.split(" then ").enumerate().map(|(index, name)| {
        let mut out = name.to_string();
        let dict = parms.get(index).and_then(Option::as_ref);
        if let Some(dict) = dict.filter(|_| matches!(name, "FlateDecode" | "LZWDecode")) {
            for (label, key) in [
                ("predictor", "Predictor"),
                ("colors", "Colors"),
                ("bits", "BitsPerComponent"),
                ("columns", "Columns"),
                ("early", "EarlyChange"),
            ] {
                let value = match number_or_reference(dict, key) {
                    Some(Number::Direct(number)) => Some(number),
                    Some(Number::Reference(object)) => integer(object).map(|n| n as u64),
                    None => None,
                };
                if let Some(value) = value {
                    out.push_str(&format!(" {label}={value}"));
                }
            }
        }
        out
    });
    named.collect::<Vec<_>>().join(" then ")
}

/// An integer written directly, or the object an indirect reference names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Number {
    Direct(u64),
    Reference(u32),
}

/// The value of `/Key 123` or `/Key 123 0 R` inside a dictionary's text. Telling the
/// two apart is the whole point: read as a plain number, `/Length 5 0 R` is a stream
/// five bytes long.
fn number_or_reference(dict: &str, key: &str) -> Option<Number> {
    parse_number_or_reference(field(dict, key)?.trim_start())
}

/// A value that starts with an integer, and whether what follows makes it a reference.
fn parse_number_or_reference(after: &str) -> Option<Number> {
    let digits = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
    let number: u64 = after.get(..digits)?.parse().ok()?;

    let rest = after.get(digits..)?.trim_start();
    let generation = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    if generation > 0 {
        let rest = rest.get(generation..)?.trim_start();
        let ends = rest.get(1..).is_none_or(|tail| {
            tail.bytes().next().is_none_or(ends_name)
        });
        if rest.starts_with('R') && ends {
            return u32::try_from(number).ok().map(Number::Reference);
        }
    }

    Some(Number::Direct(number))
}

/// The value of `/Key 123`, when it is written as a plain integer.
fn number_field(dict: &str, key: &str) -> Option<u64> {
    match number_or_reference(dict, key)? {
        Number::Direct(number) => Some(number),
        Number::Reference(_) => None,
    }
}

/// The object number of `/Key N G R` inside a dictionary's text: an
/// indirect reference to another object, which is how a dictionary points at
/// something too large to hold inline.
fn reference_field(dict: &str, key: &str) -> Option<u32> {
    match number_or_reference(dict, key)? {
        Number::Reference(number) => Some(number),
        Number::Direct(_) => None,
    }
}

/// A stream's raw bytes, wherever compression leaves them.
#[derive(Debug, Clone, PartialEq)]
pub struct Stream {
    pub offset: usize,
    pub length: usize,
    /// The names in the stream's own `/Filter`, joined with " then ", empty when
    /// it carries its bytes uncompressed.
    pub filter: String,
}

/// One `N G obj ... endobj` block.
#[derive(Debug, Clone, PartialEq)]
pub struct Object {
    pub number: u32,
    pub generation: u16,
    pub offset: usize,
    /// The dictionary text between `<<` and `>>`, verbatim and unparsed
    /// beyond the handful of fields this module looks up by name.
    pub dict: String,
    pub kind: Option<String>,
    pub subtype: Option<String>,
    pub stream: Option<Stream>,
    /// True when the document's cross-reference tables, followed back through every
    /// revision, do not list this object's offset as live. Only set when they could
    /// all be read; a document using a cross-reference stream instead leaves every
    /// object unmarked rather than guessing.
    pub orphaned: bool,
}

/// A revision boundary: an `%%EOF` and how far into the file it sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revision {
    pub ends_at: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Document {
    /// The version from the file's own header, `%PDF-`, without the prefix.
    pub version: String,
    pub objects: Vec<Object>,
    /// One entry per `%%EOF` found, in file order. More than one means the
    /// document has been incrementally updated at least once.
    pub revisions: Vec<Revision>,
    /// True when a trailer or a cross-reference stream names an `/Encrypt` dictionary.
    pub encrypted: bool,
    /// `/Info` dictionary fields this module knows how to read, in the order
    /// they were found.
    pub info: Vec<(String, String)>,
    /// Object numbers whose `/Type` names them as a file attachment, which is what the
    /// format says it should be, or whose `/Subtype` does, which some writers do.
    pub embedded_files: Vec<u32>,
    /// Bytes after the last `%%EOF`. A reader stops there; anything past it
    /// was appended by something other than the tool that wrote the PDF.
    pub trailing: usize,
    /// True when at least one cross-reference table was a stream rather than
    /// the classic plain-text form, which this module locates but does not
    /// decode: it is itself a compressed, filter-encoded stream, and
    /// [`Object::orphaned`] is left false throughout rather than guessed at.
    pub uses_xref_stream: bool,
    /// True when the file has a classic table, or should, that could not be read, so no
    /// object was checked against it.
    pub xref_unread: bool,
}

fn digits_at(data: &[u8], at: usize) -> Option<(u32, usize)> {
    let start = at;
    let mut end = at;
    while data.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    if end == start {
        return None;
    }
    core::str::from_utf8(&data[start..end])
        .ok()?
        .parse()
        .ok()
        .map(|n| (n, end))
}

/// Finds the matching `>>` for a `<<` already known to start at `open`,
/// respecting nested dictionaries.
///
/// Strings and comments are stepped over, since either can hold a `>>` that closes
/// nothing. One that never ends is taken as ordinary bytes, and no later one is looked
/// for, or a dictionary full of them would search the rest of the file from each.
fn dict_end(data: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut at = open;
    let (mut strings, mut hex) = (true, true);

    while at + 1 < data.len() {
        match (data[at], data[at + 1]) {
            (b'<', b'<') => {
                depth += 1;
                at += 2;
            }
            (b'>', b'>') => {
                depth -= 1;
                at += 2;
                if depth == 0 {
                    return Some(at);
                }
            }
            (b'(', _) if strings => match literal_string_end(data, at) {
                Some(end) => at = end,
                None => {
                    strings = false;
                    at += 1;
                }
            },
            (b'<', _) if hex => match data[at + 1..].iter().position(|&b| b == b'>') {
                Some(length) => at += length + 2,
                None => {
                    hex = false;
                    at += 1;
                }
            },
            (b'%', _) => {
                at += data[at..]
                    .iter()
                    .position(|&b| b == b'\n' || b == b'\r')
                    .unwrap_or(data.len() - at);
            }
            _ => at += 1,
        }
    }

    None
}

/// One `N G obj` header, before anything after it has been read.
struct Header {
    number: u32,
    generation: u16,
    offset: usize,
    body_at: usize,
}

/// Every `N G obj` header in the file, walked independent of any index.
fn headers(data: &[u8]) -> Vec<Header> {
    let mut out = Vec::new();
    let mut at = 0usize;

    while out.len() < MAX_OBJECTS
        && let Some(found) = bytes::find(data, at, b"obj")
    {
        at = found + 3;

        // The keyword on its own, so neither `endobj` nor a word like `object`.
        if data.get(at).is_some_and(|&b| !ends_name(b) && !pdf_space(b)) {
            continue;
        }

        // Walk backwards over the generation and object number that must
        // precede the keyword, rather than forward from a match: the signature
        // is the keyword, and what makes this a real object header is what sits
        // in front of it. Any whitespace can separate the three, and a line break
        // or a tab is as good as a space to every reader.
        let mut gen_end = found;
        while gen_end > 0 && pdf_space(data[gen_end - 1]) {
            gen_end -= 1;
        }
        let mut gen_start = gen_end;
        while gen_start > 0 && data[gen_start - 1].is_ascii_digit() {
            gen_start -= 1;
        }
        if gen_start == gen_end || gen_start == 0 || !pdf_space(data[gen_start - 1]) {
            continue;
        }

        let mut num_end = gen_start;
        while num_end > 0 && pdf_space(data[num_end - 1]) {
            num_end -= 1;
        }
        let mut num_start = num_end;
        while num_start > 0 && data[num_start - 1].is_ascii_digit() {
            num_start -= 1;
        }
        if num_start == num_end {
            continue;
        }

        let (Some(number), Some(generation)) = (
            core::str::from_utf8(&data[num_start..num_end]).ok().and_then(|s| s.parse().ok()),
            core::str::from_utf8(&data[gen_start..gen_end]).ok().and_then(|s| s.parse().ok()),
        ) else {
            continue;
        };

        out.push(Header {
            number,
            generation,
            offset: num_start,
            body_at: at,
        });
    }

    out
}

/// Every occurrence of a keyword, in order, so a later question about the next one
/// is a binary search and not another scan of the rest of the file.
fn occurrences(data: &[u8], keyword: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(found) = bytes::find(data, at, keyword) {
        out.push(found);
        at = found + keyword.len();
    }
    out
}

/// The integer an object holds, for a `/Length` that points at one.
fn integer_object(data: &[u8], body_at: usize) -> Option<usize> {
    let rest = data.get(body_at..)?;
    let offset = rest.iter().take(64).position(|b| !b.is_ascii_whitespace())?;
    let (number, _) = digits_at(rest, offset)?;
    Some(number as usize)
}

/// The filter names an object holds, for a `/Filter` that points at one.
fn filter_object(data: &[u8], body_at: usize) -> Option<String> {
    let rest = data.get(body_at..)?;
    let text = without_comments(&crate::json::latin1(&rest[..rest.len().min(4096)]));
    filter_names(&text, &|_| None)
}

/// Bytes a stream holds, given where it starts and what its dictionary claims.
///
/// A claim is taken when it lands on the `endstream` keyword, give or take the line
/// ending in front of it, whichever `endstream` that is: a stream can hold the keyword
/// itself, and an embedded PDF stored uncompressed holds dozens. A claim that lands
/// nowhere is a mistake or a lie, and what is left is the first `endstream` after the
/// start, less its line ending, which is what an inflate needs to see no junk after
/// the data.
fn stream_length(data: &[u8], start: usize, claimed: Option<usize>, first_end: usize) -> usize {
    if let Some(length) = claimed
        && let Some(after) = start.checked_add(length)
    {
        let landed = data.get(after..).is_some_and(|rest| {
            rest.starts_with(b"endstream")
                || rest.starts_with(b"\nendstream")
                || rest.starts_with(b"\r\nendstream")
                || rest.starts_with(b"\rendstream")
        });
        if landed {
            return length;
        }
    }

    let mut end = first_end;
    if end > start && data[end - 1] == b'\n' {
        end -= 1;
    }
    if end > start && data[end - 1] == b'\r' {
        end -= 1;
    }
    end - start
}

/// Every `N G obj` block in the file, walked independent of any index.
fn objects(data: &[u8]) -> Vec<Object> {
    let headers = headers(data);
    let stream_ends = occurrences(data, b"endstream");
    // By number, for a `/Length` that points elsewhere. The last revision wins.
    let bodies: HashMap<u32, usize> = headers.iter().map(|h| (h.number, h.body_at)).collect();

    let mut out = Vec::with_capacity(headers.len());
    let mut overrun = DICT_OVERRUN_TOTAL;

    for (index, header) in headers.iter().enumerate() {
        let body_at = header.body_at;
        let limit = headers.get(index + 1).map_or(data.len(), |next| next.offset);

        let dict = data.get(body_at..limit).and_then(|rest| {
            let offset = rest.iter().position(|b| !b.is_ascii_whitespace())?;
            if rest.get(offset..offset + 2)? != b"<<" {
                return None;
            }
            let open = body_at + offset;
            let end = dict_end(&data[..limit], open).or_else(|| {
                let further = limit.saturating_add(DICT_OVERRUN.min(overrun)).min(data.len());
                overrun -= (further - limit).min(overrun);
                dict_end(&data[..further], open)
            })?;
            Some((open, end))
        });

        let dict_text = dict
            .map(|(open, end)| crate::json::latin1(&data[open..end]))
            .unwrap_or_default();

        let stream = dict.and_then(|(_, dict_end_at)| {
            let after = &data[dict_end_at..];
            let offset = after.iter().position(|b| !b.is_ascii_whitespace())?;
            if !after[offset..].starts_with(b"stream") {
                return None;
            }
            // The stream's own bytes start right after the keyword and a
            // single CRLF or LF, never a bare CR, which is the format's own
            // rule for where a filter's input actually begins.
            let mut start = dict_end_at + offset + b"stream".len();
            if data.get(start..start + 2) == Some(b"\r\n") {
                start += 2;
            } else if data.get(start) == Some(&b'\n') {
                start += 1;
            }

            let next = stream_ends.partition_point(|&end| end < start);
            let first_end = *stream_ends.get(next)?;

            let parsed = without_comments(&dict_text);

            // Either a number here or a number in another object, which may not
            // come until later in the file.
            let claimed = match number_or_reference(&parsed, "Length") {
                Some(Number::Direct(length)) => usize::try_from(length).ok(),
                Some(Number::Reference(object)) => {
                    bodies.get(&object).and_then(|&at| integer_object(data, at))
                }
                None => None,
            };

            // The filter can live in another object too, and reading that as no filter
            // at all is how a compressed stream gets called uncompressed.
            let lookup = |object: u32| filter_object(data, *bodies.get(&object)?);
            let filter = filter_of(&parsed, &lookup);
            let parms = decode_parms(&parsed, &|object| {
                dict_after(data, *bodies.get(&object)?).map(|dict| without_comments(&dict))
            });
            let integer = |object: u32| integer_object(data, *bodies.get(&object)?);

            Some(Stream {
                offset: start,
                length: stream_length(data, start, claimed, first_end),
                filter: with_parms(filter.unwrap_or_default(), &parms, &integer),
            })
        });

        out.push(Object {
            number: header.number,
            generation: header.generation,
            offset: header.offset,
            kind: name_field(&dict_text, "Type"),
            subtype: name_field(&dict_text, "Subtype"),
            stream,
            dict: dict_text,
            orphaned: false,
        });
    }

    out
}

/// Every `%%EOF` in the file, in order.
fn revisions(data: &[u8]) -> Vec<Revision> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(found) = bytes::find(data, at, b"%%EOF") {
        out.push(Revision {
            ends_at: found + 5,
        });
        at = found + 5;
    }
    out
}

/// Object numbers a table mentions, and where each one lives when it is in use.
type XrefEntries = Vec<(u32, Option<usize>)>;

/// What one classic plain-text cross-reference table lists, reading every subsection
/// it declares, and where it stops.
///
/// `xref` is followed by one or more subsections, each a `start count`
/// header line and then `count` fixed-width entries of the form
/// `nnnnnnnnnn ggggg n` (in use) or `...f` (free). Only `n` entries name a
/// real offset. A free entry still counts: it says this number has no live object,
/// which overrides whatever an older table said.
fn classic_xref(data: &[u8], at: usize) -> Option<(XrefEntries, usize)> {
    let mut cursor = at + 4;
    let mut entries = Vec::new();

    loop {
        while data.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }

        let Some((start, after_start)) = digits_at(data, cursor) else {
            break;
        };
        let mut past = after_start;
        while data.get(past).is_some_and(u8::is_ascii_whitespace) {
            past += 1;
        }
        let Some((count, after_count)) = digits_at(data, past) else {
            break;
        };

        cursor = after_count;
        while data.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }

        for index in 0..count {
            let entry = data.get(cursor..cursor + 20)?;
            let text = core::str::from_utf8(entry).ok()?;
            // Ten digits run past what 32 bits hold, and an offset that big is one that points
            // nowhere, not a table that cannot be read.
            let offset: u64 = text.get(0..10)?.trim().parse().ok()?;
            let offset = usize::try_from(offset).unwrap_or(usize::MAX);
            let live = text.as_bytes().get(17) == Some(&b'n');
            entries.push((start.wrapping_add(index), live.then_some(offset)));
            cursor += 20;
        }
    }

    Some((entries, cursor))
}

/// The dictionary after a keyword, searched only so far, so that a file of nothing
/// but this keyword cannot have each one scan the rest of it.
fn dict_after(data: &[u8], at: usize) -> Option<String> {
    let rest = data.get(at..)?;
    let offset = rest.iter().position(|b| !b.is_ascii_whitespace())?;
    if rest.get(offset..offset + 2)? != b"<<" {
        return None;
    }
    let open = at + offset;
    let limit = open.saturating_add(TRAILER_SPAN).min(data.len());
    let end = dict_end(&data[..limit], open)?;
    Some(crate::json::latin1(&data[open..end]))
}

/// Where the newest cross-reference table sits: the offset the last `startxref` names
/// when it lands on one, or failing that the last `xref` keyword in the file.
fn newest_xref(data: &[u8]) -> Option<usize> {
    let named = data.windows(9).rposition(|w| w == b"startxref").and_then(|at| {
        let mut digits = at + 9;
        while data.get(digits).is_some_and(u8::is_ascii_whitespace) {
            digits += 1;
        }
        let (offset, _) = digits_at(data, digits)?;
        let offset = offset as usize;
        data.get(offset..)?.starts_with(b"xref").then_some(offset)
    });

    named.or_else(|| {
        let mut found = None;
        let mut from = 0usize;
        while let Some(at) = bytes::find(data, from, b"xref") {
            // "xref" alone, not "startxref", which names an offset rather
            // than starting a table.
            if at == 0 || data[at - 1] != b't' {
                found = Some(at);
            }
            from = at + 4;
        }
        found
    })
}

/// The offset of every object the document still reaches, from its cross-reference
/// tables newest first, or nothing when a table in the chain cannot be read.
///
/// An incremental update writes a table of what changed and points back at the one
/// before it with `/Prev`, so the last table alone lists almost nothing. Read that way
/// every object the update left alone looks orphaned. The newest entry for a number is
/// the one that counts, whether it gives that number a new home or frees it.
fn live_offsets(data: &[u8], mut entries_left: usize) -> Option<HashSet<usize>> {
    let mut at = newest_xref(data)?;
    let mut decided: HashSet<u32> = HashSet::new();
    let mut live: HashSet<usize> = HashSet::new();
    let mut visited: HashSet<usize> = HashSet::new();

    // A chain that loops is a doctored file, and a table read twice says nothing new.
    while visited.insert(at) && visited.len() <= MAX_REVISIONS_FOLLOWED {
        let (entries, end) = classic_xref(data, at)?;
        entries_left = entries_left.checked_sub(entries.len())?;
        for (number, offset) in entries {
            if decided.insert(number)
                && let Some(offset) = offset
            {
                // A little leeway, since plenty of writers point at the line ending
                // in front of the object rather than at the object.
                let skip = data
                    .get(offset..)
                    .map_or(0, |rest| rest.iter().take(16).take_while(|b| b.is_ascii_whitespace()).count());
                live.insert(offset + skip);
            }
        }

        let mut trailer = end;
        while data.get(trailer).is_some_and(u8::is_ascii_whitespace) {
            trailer += 1;
        }
        if data.get(trailer..trailer + 7) != Some(b"trailer") {
            break;
        }
        let Some(previous) = dict_after(data, trailer + 7).and_then(|d| number_field(&d, "Prev")) else {
            break;
        };

        let previous = usize::try_from(previous).ok()?;
        if !data.get(previous..)?.starts_with(b"xref") {
            return None;
        }
        at = previous;
    }

    Some(live)
}

/// Trailers from the end of the file, newest first, with what each one says.
fn last_trailers(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut end = data.len();
    for _ in 0..TRAILERS_READ {
        let Some(at) = data[..end].windows(7).rposition(|w| w == b"trailer") else {
            break;
        };
        out.extend(dict_after(data, at + 7));
        end = at;
    }
    out
}

/// Most filters in one stream's chain. A real chain has two.
const MAX_FILTERS: usize = 8;

/// Undoes a stream's filter chain, as far as it can be undone.
///
/// Stops at the first filter that fails or that this cannot read, keeping what came
/// out of the one before, so a chain ending in an image format still gets scanned as
/// far as its text wrappers go.
///
/// @param filter the names as [`Stream::filter`] joins them
pub fn decode_stream(data: &[u8], filter: &str, limit: usize) -> Inflated {
    let names: Vec<&str> = filter.split(" then ").collect();
    let mut found: Option<Inflated> = None;

    for &step in names.iter().take(MAX_FILTERS) {
        let (name, parms) = step.split_once(' ').unwrap_or((step, ""));
        let input = found.as_ref().map_or(data, |so_far| &so_far.output);
        let mut next = match name {
            "FlateDecode" => inflate(input, Wrapper::Zlib, limit),
            "ASCIIHexDecode" => ascii_hex(input, limit),
            "ASCII85Decode" => ascii85(input, limit),
            "RunLengthDecode" => run_length(input, limit),
            "LZWDecode" => lzw(input, limit, parm(parms, "early") != Some(0)),
            other => {
                let mut kept = found.unwrap_or_default();
                kept.error = Some(format!("Trawl does not read {other}, so the chain stopped there"));
                return kept;
            }
        };

        undo_predictor(&mut next, parms);
        next.capped |= found.is_some_and(|so_far| so_far.capped);
        if next.error.is_some() {
            return next;
        }
        found = Some(next);
    }

    let mut found = found.unwrap_or_default();
    if names.len() > MAX_FILTERS {
        found.error = Some(format!(
            "the stream has {} filters, and Trawl undoes the first {MAX_FILTERS}",
            names.len()
        ));
    }
    found
}

/// A number from the parameters [`with_parms`] wrote after a filter's name.
fn parm(parms: &str, key: &str) -> Option<usize> {
    parms.split(' ').find_map(|part| {
        let value: u64 = part.strip_prefix(key)?.strip_prefix('=')?.parse().ok()?;
        Some(usize::try_from(value).unwrap_or(usize::MAX))
    })
}

/// Undoes what `/Predictor` did to the data before it was compressed, which leaves bytes
/// that read as nothing until it is undone. A predictor that cannot be undone leaves the
/// data as it was, and says so.
fn undo_predictor(found: &mut Inflated, parms: &str) {
    let predictor = parm(parms, "predictor").unwrap_or(1);
    if predictor <= 1 || found.output.is_empty() {
        return;
    }

    let colors = parm(parms, "colors").unwrap_or(1);
    let bits = parm(parms, "bits").unwrap_or(8);
    let columns = parm(parms, "columns").unwrap_or(1);

    let stride = columns
        .checked_mul(colors)
        .and_then(|samples| samples.checked_mul(bits))
        .map(|width| width.div_ceil(8))
        .filter(|&stride| stride > 0 && stride <= found.output.len());

    let undone = stride.and_then(|stride| match predictor {
        2 if bits == 8 => {
            let mut output = core::mem::take(&mut found.output);
            for row in output.chunks_mut(stride) {
                for at in colors..row.len() {
                    row[at] = row[at].wrapping_add(row[at - colors]);
                }
            }
            Some(output)
        }
        10..=15 => {
            let row = stride + 1;
            let rows = found.output.len().div_ceil(row);
            let mut padded = found.output.clone();
            padded.resize(rows * row, 0);
            let bpp = (colors * bits / 8).max(1);
            crate::png::unfilter(&padded, stride, bpp, rows).ok()
        }
        _ => None,
    });

    match undone {
        Some(output) => found.output = output,
        None if found.error.is_none() => {
            found.error = Some(format!(
                "Trawl could not undo predictor {predictor} here, so this is the data before that step"
            ));
        }
        None => {}
    }
}

fn ascii_hex(data: &[u8], limit: usize) -> Inflated {
    let mut found = Inflated::default();
    let mut high = None;

    for &byte in data {
        if byte == b'>' {
            break;
        }
        if pdf_space(byte) {
            continue;
        }
        let Some(digit) = (byte as char).to_digit(16) else {
            found.error = Some("the hex data holds something that is not a hex digit".to_string());
            return found;
        };
        match high.take() {
            None => high = Some(digit),
            Some(top) => {
                if found.output.len() >= limit {
                    found.capped = true;
                    return found;
                }
                found.output.push((top * 16 + digit) as u8);
            }
        }
    }

    // A last digit on its own is the high half of a byte, by the format's own rule.
    if let Some(top) = high
        && found.output.len() < limit
    {
        found.output.push((top * 16) as u8);
    }
    found
}

fn ascii85(data: &[u8], limit: usize) -> Inflated {
    // The opening an Adobe encoder writes, which is no part of the data.
    let data = data.trim_ascii_start();
    let data = data.strip_prefix(b"<~").unwrap_or(data);

    let mut found = Inflated::default();
    let mut group = [0u8; 5];
    let mut filled = 0usize;

    for &byte in data {
        match byte {
            b'~' => break,
            b'z' if filled == 0 => {
                if found.output.len() + 4 > limit {
                    found.capped = true;
                    return found;
                }
                found.output.extend_from_slice(&[0; 4]);
            }
            b'!'..=b'u' => {
                group[filled] = byte - b'!';
                filled += 1;
                if filled == 5 {
                    if found.output.len() + 4 > limit {
                        found.capped = true;
                        return found;
                    }
                    let value = group.iter().fold(0u32, |acc, &d| acc.wrapping_mul(85).wrapping_add(d as u32));
                    found.output.extend_from_slice(&value.to_be_bytes());
                    filled = 0;
                }
            }
            _ if pdf_space(byte) => {}
            _ => {
                found.error = Some("the ASCII85 data holds a byte outside its alphabet".to_string());
                return found;
            }
        }
    }

    // A short last group stands for that many bytes less one, padded out with the
    // highest digit to round the way an encoder truncated.
    if filled >= 2 {
        group[filled..].fill(84);
        let value = group.iter().fold(0u32, |acc, &d| acc.wrapping_mul(85).wrapping_add(d as u32));
        let take = (filled - 1).min(limit.saturating_sub(found.output.len()));
        found.output.extend_from_slice(&value.to_be_bytes()[..take]);
    }
    found
}

fn run_length(data: &[u8], limit: usize) -> Inflated {
    let mut found = Inflated::default();
    let mut at = 0usize;

    while let Some(&length) = data.get(at) {
        at += 1;
        let room = limit - found.output.len();
        match length {
            128 => return found,
            0..=127 => {
                let wanted = length as usize + 1;
                let available = data.get(at..).map_or(0, <[u8]>::len).min(wanted);
                let taken = available.min(room);
                found.output.extend_from_slice(&data[at..at + taken]);
                at += wanted;
                if taken < available {
                    found.capped = true;
                    return found;
                }
                if available < wanted {
                    found.error = Some("the stream is cut short".to_string());
                    return found;
                }
            }
            _ => {
                let Some(&byte) = data.get(at) else {
                    found.error = Some("the stream is cut short".to_string());
                    return found;
                };
                at += 1;
                let wanted = 257 - length as usize;
                let taken = wanted.min(room);
                found.output.resize(found.output.len() + taken, byte);
                if taken < wanted {
                    found.capped = true;
                    return found;
                }
            }
        }
    }
    found
}

/// PDF's LZW: codes packed most significant bit first, widening one code earlier than
/// GIF's does unless a stream's parameters say otherwise, which none in the wild do.
fn lzw(data: &[u8], limit: usize, early_change: bool) -> Inflated {
    const CLEAR: usize = 256;
    const END: usize = 257;

    let mut found = Inflated::default();
    // Each entry beyond the single bytes is where in the output it was last written.
    let mut table: Vec<(usize, usize)> = Vec::with_capacity(4096);
    let (mut width, mut hold, mut bits) = (9u32, 0u32, 0u32);
    let mut previous: Option<(usize, usize)> = None;

    for &byte in data {
        hold = (hold << 8) | byte as u32;
        bits += 8;

        while bits >= width {
            bits -= width;
            let code = ((hold >> bits) & ((1 << width) - 1)) as usize;

            match code {
                CLEAR => {
                    table.clear();
                    width = 9;
                    previous = None;
                    continue;
                }
                END => return found,
                _ => {}
            }

            let at = found.output.len();
            let length = if code < 256 {
                found.output.push(code as u8);
                1
            } else if let Some(&(from, length)) = table.get(code - 258) {
                if at + length > limit {
                    found.capped = true;
                    return found;
                }
                found.output.extend_from_within(from..from + length);
                length
            } else if let (Some((from, length)), true) = (previous, code - 258 == table.len()) {
                // The one code an encoder can send in the same step it defines it.
                if at + length + 1 > limit {
                    found.capped = true;
                    return found;
                }
                found.output.extend_from_within(from..from + length);
                let first = found.output[from];
                found.output.push(first);
                length + 1
            } else {
                found.error = Some("the LZW data holds a code that means nothing yet".to_string());
                return found;
            };

            if found.output.len() >= limit {
                found.capped = true;
                return found;
            }

            if let Some((from, previous_length)) = previous
                && table.len() < 4096 - 258
            {
                table.push((from, previous_length + 1));
                width = match table.len() + 258 + usize::from(early_change) {
                    size if size >= 2048 => 12,
                    size if size >= 1024 => 11,
                    size if size >= 512 => 10,
                    _ => 9,
                };
            }
            previous = Some((at, length));
        }
    }
    found
}

/// Reads a PDF, or returns nothing when the file does not open with `%PDF-`.
pub fn read(data: &[u8]) -> Option<Document> {
    if !data.starts_with(b"%PDF-") {
        return None;
    }

    let version_end = data[5..]
        .iter()
        .take(16)
        .position(|b| b.is_ascii_whitespace() || *b == b'\r' || *b == b'\n')
        .map(|p| 5 + p)
        .unwrap_or(data.len().min(9));
    let version = crate::json::latin1(&data[5..version_end]);

    let mut objects = objects(data);
    let revisions = revisions(data);
    let trailing = data.len().saturating_sub(
        revisions.last().map(|r| r.ends_at).unwrap_or(data.len()),
    );

    // The last trailer in the file describes the document as a reader would
    // see it today; an earlier one is a revision that got superseded. A linearized
    // file writes the fuller trailer first, so the older ones are asked in turn. A
    // cross-reference stream has no trailer at all and carries the same entries in
    // its own dictionary.
    let trailers = last_trailers(data);
    let xref_stream = objects.iter().rev().find(|o| o.kind.as_deref() == Some("XRef"));
    let dictionaries: Vec<&str> = trailers
        .iter()
        .map(String::as_str)
        .chain(xref_stream.map(|o| o.dict.as_str()))
        .collect();

    let encrypted = dictionaries.iter().any(|d| field(d, "Encrypt").is_some());
    let info_number = dictionaries.iter().find_map(|d| reference_field(d, "Info"));

    // Where the cross-reference table itself sits: the classic form starts
    // with the bare keyword `xref`; PDF 1.5 and later can carry the same
    // information as a compressed object stream instead, named by an
    // `/XRefStm` hybrid entry or by every object in the file being a stream
    // with `/Type/XRef`. This module reads the first kind and only detects
    // the second.
    let uses_xref_stream = objects.iter().any(|o| o.kind.as_deref() == Some("XRef"));

    let mut xref_unread = false;
    if !uses_xref_stream {
        match live_offsets(data, MAX_XREF_ENTRIES) {
            Some(live) => {
                for object in &mut objects {
                    object.orphaned = !live.contains(&object.offset);
                }
            }
            None => xref_unread = true,
        }
    }

    // The revision a reader would see: the live one, or failing that the last one
    // written, since the first one in the file is the oldest.
    let info = info_number
        .and_then(|number| {
            let holding = |o: &&Object| o.number == number;
            objects
                .iter()
                .rev()
                .filter(holding)
                .find(|o| !o.orphaned)
                .or_else(|| objects.iter().rev().find(holding))
        })
        .map(|info_object| {
            ["Title", "Author", "Subject", "Producer", "Creator", "CreationDate", "ModDate"]
                .iter()
                .filter_map(|&key| literal_field(&info_object.dict, key).map(|v| (key.to_string(), v)))
                .collect()
        })
        .unwrap_or_default();

    let embedded_files = objects
        .iter()
        .filter(|o| {
            o.kind.as_deref() == Some("EmbeddedFile") || o.subtype.as_deref() == Some("EmbeddedFile")
        })
        .map(|o| o.number)
        .collect();

    Some(Document {
        version,
        objects,
        revisions,
        encrypted,
        info,
        embedded_files,
        trailing,
        uses_xref_stream,
        xref_unread,

    })
}

/// Objects that say nothing past the first few thousand, which is what reaches the
/// caller. Seven bytes of file make one and each is a line of JSON twenty times that. A
/// stream is what the caller has to open and an orphan is a finding, so those are not
/// held to it, up to the second limit. The true count is reported alongside.
const MAX_PLAIN_OBJECTS_LISTED: usize = 4096;
const MAX_OBJECTS_LISTED: usize = 1 << 16;

pub fn json(data: &[u8]) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    let Some(doc) = read(data) else {
        return "null".to_string();
    };

    let mut plain_left = MAX_PLAIN_OBJECTS_LISTED;
    let listed: Vec<&Object> = doc
        .objects
        .iter()
        .filter(|object| {
            let say_something = object.stream.is_some() || object.orphaned;
            if !say_something && plain_left == 0 {
                return false;
            }
            plain_left = plain_left.saturating_sub(usize::from(!say_something));
            true
        })
        .take(MAX_OBJECTS_LISTED)
        .collect();

    let mut out = String::from("{");
    push_field(&mut out, "version", &doc.version);
    out.push(',');
    push_number(&mut out, "objectCount", doc.objects.len());
    out.push(',');
    push_number(&mut out, "trailing", doc.trailing);
    out.push(',');
    push_bool(&mut out, "encrypted", doc.encrypted);
    out.push(',');
    push_bool(&mut out, "usesXrefStream", doc.uses_xref_stream);
    out.push(',');
    push_bool(&mut out, "xrefUnread", doc.xref_unread);
    out.push(',');
    push_number(&mut out, "revisions", doc.revisions.len());
    out.push(',');

    push_string(&mut out, "info");
    out.push_str(":[");
    for (i, (key, value)) in doc.info.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "key", key);
        out.push(',');
        push_field(&mut out, "value", value);
        out.push('}');
    }
    out.push_str("],");

    push_string(&mut out, "embeddedFiles");
    out.push_str(":[");
    for (i, number) in doc.embedded_files.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&number.to_string());
    }
    out.push_str("],");

    push_string(&mut out, "objects");
    out.push_str(":[");
    for (i, object) in listed.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_number(&mut out, "number", object.number as usize);
        out.push(',');
        push_number(&mut out, "generation", object.generation as usize);
        out.push(',');
        push_number(&mut out, "offset", object.offset);
        out.push(',');
        push_string(&mut out, "type");
        out.push(':');
        match &object.kind {
            Some(kind) => push_string(&mut out, kind),
            None => out.push_str("null"),
        }
        out.push(',');
        push_string(&mut out, "subtype");
        out.push(':');
        match &object.subtype {
            Some(subtype) => push_string(&mut out, subtype),
            None => out.push_str("null"),
        }
        out.push(',');
        push_bool(&mut out, "orphaned", object.orphaned);
        out.push(',');
        push_string(&mut out, "stream");
        match &object.stream {
            Some(stream) => {
                out.push_str(":{");
                push_number(&mut out, "offset", stream.offset);
                out.push(',');
                push_number(&mut out, "length", stream.length);
                out.push(',');
                push_field(&mut out, "filter", &stream.filter);
                out.push('}');
            }
            None => out.push_str(":null"),
        }
        out.push('}');
    }
    out.push_str("]}");

    out
}

#[cfg(test)]
mod tests;
