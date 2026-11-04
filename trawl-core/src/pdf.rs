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

/// What follows `/Key` at a dictionary's own level.
///
/// A key is a whole name, or `/Length` finds `/Length1`, and it is a key of this
/// dictionary rather than of one nested inside it, or `/Length` finds the one in a
/// `/DecodeParms`. Strings are stepped over, since one can hold anything.
fn field<'a>(dict: &'a str, key: &str) -> Option<&'a str> {
    let bytes = dict.as_bytes();
    let mut depth = 0usize;
    let mut arrays = 0usize;
    let mut at = 0usize;
    let mut strings = true;

    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'<' if bytes.get(at + 1) == Some(&b'<') => {
                depth += 1;
                at += 2;
            }
            b'>' if bytes.get(at + 1) == Some(&b'>') => {
                depth = depth.saturating_sub(1);
                at += 2;
            }
            b'[' => {
                arrays += 1;
                at += 1;
            }
            b']' => {
                arrays = arrays.saturating_sub(1);
                at += 1;
            }
            // An unmatched parenthesis must not hide the keys after it, and searching
            // from every one that follows would make a dictionary of them quadratic.
            b'(' if strings => match literal_string_end(bytes, at) {
                Some(end) => at = end,
                None => {
                    strings = false;
                    at += 1;
                }
            },
            b'/' => {
                let start = at + 1;
                let end = bytes[start..]
                    .iter()
                    .position(|&b| ends_name(b))
                    .map_or(bytes.len(), |length| start + length);
                if depth == 1 && arrays == 0 && dict.get(start..end) == Some(key) {
                    return dict.get(end..);
                }
                at = end;
            }
            _ => at += 1,
        }
    }

    None
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
    leading_name(field(dict, key)?.trim_start()).map(str::to_string)
}

/// The value of `/Filter`, which is a single name or an array of them applied in
/// order. Names joined with " then ", so a one-item array reads as that one name.
fn filter_field(dict: &str) -> Option<String> {
    let after = field(dict, "Filter")?.trim_start();
    let Some(items) = after.strip_prefix('[') else {
        return leading_name(after).map(str::to_string);
    };

    let items = items.get(..items.find(']')?)?;
    let names: Vec<&str> = items
        .split('/')
        .skip(1)
        .map(|name| name.trim_end())
        .filter(|name| !name.is_empty())
        .collect();
    Some(names.join(" then "))
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
    let after = field(dict, key)?.trim_start();
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
fn dict_end(data: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut at = open;

    while at + 1 < data.len() {
        if &data[at..at + 2] == b"<<" {
            depth += 1;
            at += 2;
        } else if &data[at..at + 2] == b">>" {
            depth -= 1;
            at += 2;
            if depth == 0 {
                return Some(at);
            }
        } else {
            at += 1;
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
        && let Some(found) = bytes::find(data, at, b" obj")
    {
        at = found + 4;

        // Walk backwards over the generation and object number that must
        // precede " obj", rather than forward from a match: the signature is
        // the keyword, and what makes this a real object header is what sits
        // in front of it.
        let gen_end = found;
        let mut gen_start = gen_end;
        while gen_start > 0 && data[gen_start - 1].is_ascii_digit() {
            gen_start -= 1;
        }
        if gen_start == gen_end || gen_start == 0 || data[gen_start - 1] != b' ' {
            continue;
        }

        let num_end = gen_start - 1;
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

            // Either a number here or a number in another object, which may not
            // come until later in the file.
            let claimed = match number_or_reference(&dict_text, "Length") {
                Some(Number::Direct(length)) => usize::try_from(length).ok(),
                Some(Number::Reference(object)) => {
                    bodies.get(&object).and_then(|&at| integer_object(data, at))
                }
                None => None,
            };

            Some(Stream {
                offset: start,
                length: stream_length(data, start, claimed, first_end),
                filter: filter_field(&dict_text).unwrap_or_default(),
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
            let offset: usize = text.get(0..10)?.trim().parse().ok()?;
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

    if !uses_xref_stream && let Some(live) = live_offsets(data, MAX_XREF_ENTRIES) {
        for object in &mut objects {
            object.orphaned = !live.contains(&object.offset);
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
    })
}

pub fn json(data: &[u8]) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    let Some(doc) = read(data) else {
        return "null".to_string();
    };

    let mut out = String::from("{");
    push_field(&mut out, "version", &doc.version);
    out.push(',');
    push_number(&mut out, "trailing", doc.trailing);
    out.push(',');
    push_bool(&mut out, "encrypted", doc.encrypted);
    out.push(',');
    push_bool(&mut out, "usesXrefStream", doc.uses_xref_stream);
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
    for (i, object) in doc.objects.iter().enumerate() {
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
