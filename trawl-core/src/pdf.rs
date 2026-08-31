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
//! index, and separately reads the last cross-reference table to see what it
//! claims. An object nothing points at any more is reported as such. A
//! stream's own compression is not undone here, the way [`crate::png`] does
//! not inflate a `zTXt` chunk itself: that is a platform call, and this
//! reports where the bytes are so the caller can make it.

use crate::bytes;

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

/// The value of `/Key (literal string)` inside a dictionary's text, if it is
/// there and written as a literal string rather than a hex string or a
/// reference to another object.
fn literal_field(dict: &str, key: &str) -> Option<String> {
    let needle = format!("/{key}");
    let after = dict[dict.find(&needle)? + needle.len()..].trim_start();
    let bytes = after.as_bytes();

    if bytes.first() != Some(&b'(') {
        return None;
    }

    let end = literal_string_end(bytes, 0)?;
    Some(unescape_literal(&bytes[1..end - 1]))
}

/// The value of `/Key /Name` inside a dictionary's text, the space between
/// them optional: most real PDF writers put one there, and the format
/// permits either.
fn name_field(dict: &str, key: &str) -> Option<String> {
    let needle = format!("/{key}");
    let after = dict[dict.find(&needle)? + needle.len()..].trim_start();
    let rest = after.strip_prefix('/')?;
    let end = rest
        .find(|c: char| c.is_whitespace() || "/<>[]()".contains(c))
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// The value of `/Key 123` inside a dictionary's text, a plain integer
/// rather than a name, a string or a reference.
fn number_field(dict: &str, key: &str) -> Option<u64> {
    let needle = format!("/{key}");
    let after = dict[dict.find(&needle)? + needle.len()..].trim_start();
    let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
    after.get(..end)?.parse().ok()
}

/// The object number of `/Key N G R` inside a dictionary's text: an
/// indirect reference to another object, which is how a dictionary points at
/// something too large to hold inline. The leading digit run is the object
/// number whether what follows is a plain integer or a reference, so this is
/// [`number_field`] under a name that says what the number means here.
fn reference_field(dict: &str, key: &str) -> Option<u32> {
    number_field(dict, key)?.try_into().ok()
}

/// A stream's raw bytes, wherever compression leaves them.
#[derive(Debug, Clone, PartialEq)]
pub struct Stream {
    pub offset: usize,
    pub length: usize,
    /// The name of the stream's own `/Filter`, empty when it carries its
    /// bytes uncompressed or names its filter as an array rather than a
    /// single name, which this does not walk.
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
    /// True when the document's last cross-reference table does not list
    /// this object's offset. Only set when that table could be read at all;
    /// a document using a cross-reference stream instead leaves every object
    /// unmarked rather than guessing.
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
    /// True when a trailer names an `/Encrypt` dictionary.
    pub encrypted: bool,
    /// `/Info` dictionary fields this module knows how to read, in the order
    /// they were found.
    pub info: Vec<(String, String)>,
    /// Object numbers whose `/Subtype` names them as a file attachment.
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

/// Every `N G obj` block in the file, walked independent of any index.
fn objects(data: &[u8]) -> Vec<Object> {
    let mut out = Vec::new();
    let mut at = 0usize;

    while let Some(found) = bytes::find(data, at, b" obj") {
        // Walk backwards over the generation and object number that must
        // precede " obj", rather than forward from a match: the signature is
        // the keyword, and what makes this a real object header is what sits
        // in front of it.
        let Some(gen_end) = Some(found) else { break };
        let mut gen_start = gen_end;
        while gen_start > 0 && data[gen_start - 1].is_ascii_digit() {
            gen_start -= 1;
        }
        if gen_start == gen_end || gen_start == 0 || data[gen_start - 1] != b' ' {
            at = found + 4;
            continue;
        }

        let num_end = gen_start - 1;
        let mut num_start = num_end;
        while num_start > 0 && data[num_start - 1].is_ascii_digit() {
            num_start -= 1;
        }
        if num_start == num_end {
            at = found + 4;
            continue;
        }

        let (Some(number), Some(generation)) = (
            core::str::from_utf8(&data[num_start..num_end]).ok().and_then(|s| s.parse().ok()),
            core::str::from_utf8(&data[gen_start..gen_end]).ok().and_then(|s| s.parse().ok()),
        ) else {
            at = found + 4;
            continue;
        };

        let body_at = found + 4;
        let dict = data.get(body_at..).and_then(|rest| {
            let offset = rest.iter().position(|b| !b.is_ascii_whitespace())?;
            if rest.get(offset..offset + 2)? != b"<<" {
                return None;
            }
            let open = body_at + offset;
            let end = dict_end(data, open)?;
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

            let end = bytes::find(data, start, b"endstream")?;
            let length = number_field(&dict_text, "Length")
                .map(|n| n as usize)
                .unwrap_or(end.saturating_sub(start));

            Some(Stream {
                offset: start,
                length: length.min(end.saturating_sub(start)),
                filter: name_field(&dict_text, "Filter").unwrap_or_default(),
            })
        });

        out.push(Object {
            number,
            generation,
            offset: num_start,
            kind: name_field(&dict_text, "Type"),
            subtype: name_field(&dict_text, "Subtype"),
            stream,
            dict: dict_text,
            orphaned: false,
        });

        at = found + 4;
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

/// The object offsets a classic plain-text cross-reference table lists,
/// reading every subsection it declares.
///
/// `xref` is followed by one or more subsections, each a `start count`
/// header line and then `count` fixed-width entries of the form
/// `nnnnnnnnnn ggggg n` (in use) or `...f` (free). Only `n` entries name a
/// real offset.
fn classic_xref(data: &[u8], at: usize) -> Option<Vec<usize>> {
    let mut cursor = at + 4;
    let mut offsets = Vec::new();

    loop {
        while data.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }

        let Some((_start, after_start)) = digits_at(data, cursor) else {
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

        for _ in 0..count {
            let entry = data.get(cursor..cursor + 20)?;
            let text = core::str::from_utf8(entry).ok()?;
            let offset: usize = text.get(0..10)?.trim().parse().ok()?;
            if text.as_bytes().get(17) == Some(&b'n') {
                offsets.push(offset);
            }
            cursor += 20;
        }
    }

    (!offsets.is_empty()).then_some(offsets)
}

/// Reads a PDF, or returns nothing when the file does not open with `%PDF-`.
pub fn read(data: &[u8]) -> Option<Document> {
    if !data.starts_with(b"%PDF-") {
        return None;
    }

    let version_end = data[5..]
        .iter()
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
    // see it today; an earlier one is a revision that got superseded.
    let last_trailer = {
        let mut found = None;
        let mut from = 0usize;
        while let Some(at) = bytes::find(data, from, b"trailer") {
            found = Some(at);
            from = at + 7;
        }
        found
    };

    let trailer_dict = last_trailer.and_then(|at| {
        let rest = &data[at + 7..];
        let offset = rest.iter().position(|b| !b.is_ascii_whitespace())?;
        if rest.get(offset..offset + 2)? != b"<<" {
            return None;
        }
        let open = at + 7 + offset;
        let end = dict_end(data, open)?;
        Some(crate::json::latin1(&data[open..end]))
    });

    let encrypted = trailer_dict.as_deref().is_some_and(|d| d.contains("/Encrypt"));

    // Where the cross-reference table itself sits: the classic form starts
    // with the bare keyword `xref`; PDF 1.5 and later can carry the same
    // information as a compressed object stream instead, named by an
    // `/XRefStm` hybrid entry or by every object in the file being a stream
    // with `/Type/XRef`. This module reads the first kind and only detects
    // the second.
    let uses_xref_stream = objects.iter().any(|o| o.kind.as_deref() == Some("XRef"));

    if !uses_xref_stream {
        let last_xref = {
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
        };

        if let Some(at) = last_xref
            && let Some(listed) = classic_xref(data, at)
        {
            for object in &mut objects {
                object.orphaned = !listed.contains(&object.offset);
            }
        }
    }

    let info = trailer_dict
        .as_deref()
        .and_then(|d| reference_field(d, "Info"))
        .and_then(|number| objects.iter().find(|o| o.number == number))
        .map(|info_object| {
            ["Title", "Author", "Subject", "Producer", "Creator", "CreationDate", "ModDate"]
                .iter()
                .filter_map(|&key| literal_field(&info_object.dict, key).map(|v| (key.to_string(), v)))
                .collect()
        })
        .unwrap_or_default();

    let embedded_files = objects
        .iter()
        .filter(|o| o.subtype.as_deref() == Some("EmbeddedFile"))
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
