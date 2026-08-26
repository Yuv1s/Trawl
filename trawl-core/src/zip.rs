//! ZIP archives, read twice and compared.
//!
//! A ZIP describes itself in two places that are supposed to agree. Every file
//! is preceded by a local header saying what follows, and the archive ends with
//! a central directory listing every file again, with an offset to each local
//! header. Readers use the directory, because it is one contiguous list and can
//! be found without walking the whole file.
//!
//! That is the weakness. The directory is a claim about the archive rather than
//! the archive itself, and nothing forces the two to match. Delete an entry from
//! the directory and its data is still there, still preceded by a perfectly good
//! local header, and `unzip -l` will not mention it. Change a size in one place
//! and not the other and two tools disagree about what the file holds.
//!
//! So this reads both, separately, and reports where they differ. Everything
//! else it says follows from that: what the directory lists, what is actually
//! there, and what sits in the gaps between them.

use crate::bytes;

const LOCAL: &[u8; 4] = b"PK\x03\x04";
const CENTRAL: &[u8; 4] = b"PK\x01\x02";
const END: &[u8; 4] = b"PK\x05\x06";

/// Bytes a local file header occupies before the name begins.
const LOCAL_HEADER: usize = 30;
/// Bytes a central directory record occupies before the name begins.
const CENTRAL_HEADER: usize = 46;
/// Bytes an end-of-central-directory record occupies before its comment.
const END_RECORD: usize = 22;

/// Longest name worth believing.
///
/// Real names are paths. A length field claiming more than this is a sign the
/// bytes were never a header, which matters because the four byte signature
/// turns up inside compressed data by chance.
const MAX_NAME: usize = 4096;

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*data.get(at)?, *data.get(at + 1)?]))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *data.get(at)?,
        *data.get(at + 1)?,
        *data.get(at + 2)?,
        *data.get(at + 3)?,
    ]))
}

/// How an entry was compressed, in the words the format uses.
fn method_name(code: u16) -> &'static str {
    match code {
        0 => "stored",
        1 => "shrunk",
        6 => "imploded",
        8 => "deflate",
        9 => "deflate64",
        12 => "bzip2",
        14 => "LZMA",
        93 => "zstd",
        95 => "XZ",
        98 => "PPMd",
        99 => "AES",
        _ => "unknown",
    }
}

/// A name as it should be shown: printable, and short enough to read.
///
/// Names are bytes rather than text, and a doctored archive is exactly where one
/// full of control characters turns up. Replacing them keeps a name that hides
/// itself with a carriage return from hiding itself in the report too.
fn readable(raw: &[u8]) -> String {
    const SHOWN: usize = 120;

    raw.iter()
        .take(SHOWN)
        .map(|&byte| {
            if (0x20..0x7f).contains(&byte) {
                byte as char
            } else {
                '·'
            }
        })
        .collect()
}

/// One file in the archive, as both places describe it.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    pub method: &'static str,
    pub compressed: u64,
    pub uncompressed: u64,
    pub crc: u32,
    /// Where the local header sits in the file.
    pub offset: usize,
    /// Where this entry's compressed data begins, past its local header and
    /// name. None for a phantom the directory points at with no header of its
    /// own, since there is no data to point to.
    pub data_offset: Option<usize>,
    /// The archive's own password flag. Trawl does not crack these.
    pub encrypted: bool,
    /// Per-entry comment, which readers rarely show and puzzles sometimes use.
    pub comment: String,
    /// True when only a local header names this, with nothing in the directory.
    ///
    /// The data is in the file and `unzip -l` will not list it, because that
    /// reads the directory. This is the reason the module reads both.
    pub undeclared: bool,
    /// What the local header and the directory disagree about, if anything.
    pub disagreement: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Archive {
    pub entries: Vec<Entry>,
    /// The archive's own trailing comment.
    pub comment: String,
    /// Where the first local header sits.
    ///
    /// Anything before it is not part of the archive. A polyglot puts an image
    /// there, which is how one file can be both a picture and a working zip.
    pub prefix: usize,
    /// Bytes after the end-of-directory record and its comment.
    ///
    /// The archive is finished at that point, so whatever follows was appended
    /// by somebody rather than written by a zip tool.
    pub trailing: usize,
    /// How many files the directory says it holds.
    ///
    /// Compared against what it actually lists, since the count is a separate
    /// field and can be edited on its own.
    pub declared: usize,
}

/// A header read out of a local file record, if the bytes really are one.
///
/// The signature is four bytes and turns up inside compressed data by chance, so
/// a match is a candidate rather than a header. What settles it is whether the
/// rest reads as one: a sane name length, a name that stays inside the file, and
/// a compression method the format defines.
fn local_at(data: &[u8], at: usize) -> Option<Entry> {
    if data.get(at..at + 4)? != LOCAL {
        return None;
    }

    let flags = u16_at(data, at + 6)?;
    let method = u16_at(data, at + 8)?;
    let name_len = u16_at(data, at + 26)? as usize;
    let extra_len = u16_at(data, at + 28)? as usize;

    if name_len == 0 || name_len > MAX_NAME || method_name(method) == "unknown" {
        return None;
    }

    let name_at = at + LOCAL_HEADER;
    let name = data.get(name_at..name_at + name_len)?;

    Some(Entry {
        name: readable(name),
        method: method_name(method),
        crc: u32_at(data, at + 14)?,
        compressed: u32_at(data, at + 18)? as u64,
        uncompressed: u32_at(data, at + 22)? as u64,
        offset: at,
        data_offset: Some(name_at + name_len + extra_len),
        // Bit zero is the archive saying its own data is encrypted.
        encrypted: flags & 1 == 1,
        comment: String::new(),
        undeclared: true,
        disagreement: None,
    })
}

/// Every local header in the file, in the order they appear.
///
/// Walked rather than followed from the directory, so an entry the directory
/// never mentions is still found. That is the whole point.
fn locals(data: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut at = 0usize;

    while let Some(found) = bytes::find(data, at, LOCAL) {
        match local_at(data, found) {
            Some(entry) => {
                at = found + LOCAL_HEADER;
                out.push(entry);
            }
            // A false signature inside compressed data. Step past it rather
            // than past a header that was never there.
            None => at = found + 4,
        }
    }

    out
}

/// One record of the central directory: what it claims, and where it points.
struct Declared {
    name: String,
    method: &'static str,
    compressed: u64,
    uncompressed: u64,
    crc: u32,
    encrypted: bool,
    comment: String,
    points_at: usize,
}

fn central_at(data: &[u8], at: usize) -> Option<(Declared, usize)> {
    if data.get(at..at + 4)? != CENTRAL {
        return None;
    }

    let flags = u16_at(data, at + 8)?;
    let method = u16_at(data, at + 10)?;
    let name_len = u16_at(data, at + 28)? as usize;
    let extra_len = u16_at(data, at + 30)? as usize;
    let comment_len = u16_at(data, at + 32)? as usize;

    if name_len == 0 || name_len > MAX_NAME {
        return None;
    }

    let name_at = at + CENTRAL_HEADER;
    let name = data.get(name_at..name_at + name_len)?;
    let comment_at = name_at + name_len + extra_len;
    let comment = data
        .get(comment_at..comment_at + comment_len)
        .map(readable)
        .unwrap_or_default();

    let record = Declared {
        name: readable(name),
        method: method_name(method),
        crc: u32_at(data, at + 16)?,
        compressed: u32_at(data, at + 20)? as u64,
        uncompressed: u32_at(data, at + 24)? as u64,
        encrypted: flags & 1 == 1,
        comment,
        points_at: u32_at(data, at + 42)? as usize,
    };

    Some((record, comment_at + comment_len))
}

/// Every record of the central directory, walked from its first signature.
fn declared(data: &[u8]) -> Vec<Declared> {
    let mut out = Vec::new();
    let Some(mut at) = bytes::find(data, 0, CENTRAL) else {
        return out;
    };

    while let Some((record, next)) = central_at(data, at) {
        out.push(record);
        at = next;
    }

    out
}

/// The end-of-directory record: its comment, its claimed count, and where it
/// finishes.
fn ending(data: &[u8]) -> Option<(String, usize, usize)> {
    // Searched from the back, because the signature can occur in file data and
    // the real record is the last one.
    let mut at = None;
    let mut from = 0usize;
    while let Some(found) = bytes::find(data, from, END) {
        at = Some(found);
        from = found + 4;
    }

    let at = at?;
    let count = u16_at(data, at + 10)? as usize;
    let comment_len = u16_at(data, at + 20)? as usize;
    let comment_at = at + END_RECORD;
    let comment = data
        .get(comment_at..comment_at + comment_len)
        .map(readable)
        .unwrap_or_default();

    Some((comment, count, comment_at + comment_len))
}

/// What the two descriptions disagree about, in the words a person would use.
fn compare(local: &Entry, record: &Declared) -> Option<String> {
    let mut said = Vec::new();

    if local.compressed != record.compressed {
        said.push(format!(
            "compressed size {} here, {} in the directory",
            local.compressed, record.compressed
        ));
    }
    if local.uncompressed != record.uncompressed {
        said.push(format!(
            "uncompressed size {} here, {} in the directory",
            local.uncompressed, record.uncompressed
        ));
    }
    if local.crc != record.crc {
        said.push(format!(
            "checksum {:08x} here, {:08x} in the directory",
            local.crc, record.crc
        ));
    }
    if local.method != record.method {
        said.push(format!(
            "{} here, {} in the directory",
            local.method, record.method
        ));
    }

    (!said.is_empty()).then(|| said.join("; "))
}

/// Reads an archive, or returns nothing when the file is not one.
///
/// A file with no local headers at all is not a zip, whatever its extension
/// says. One with headers but no directory is a zip somebody truncated or
/// stripped, and it is still worth reporting, so that case comes back.
pub fn read(data: &[u8]) -> Option<Archive> {
    let mut entries = locals(data);
    if entries.is_empty() {
        return None;
    }

    let records = declared(data);
    let (comment, declared_count, ends_at) = ending(data).unwrap_or_default();

    // Matched by where the directory points, since that is the only link the
    // format actually defines. Names are not unique and can be edited freely.
    for record in &records {
        match entries.iter_mut().find(|e| e.offset == record.points_at) {
            Some(entry) => {
                entry.undeclared = false;
                entry.comment = record.comment.clone();
                entry.disagreement = compare(entry, record);
                // The directory's name is the one readers show, so a name that
                // differs between the two is worth saying out loud.
                if entry.name != record.name {
                    let said = format!(
                        "named {:?} here, {:?} in the directory",
                        entry.name, record.name
                    );
                    entry.disagreement = Some(match entry.disagreement.take() {
                        Some(rest) => format!("{said}; {rest}"),
                        None => said,
                    });
                }
            }
            // A directory record pointing at nothing. The offset is wrong, or
            // the data it named has been cut out.
            None => entries.push(Entry {
                name: record.name.clone(),
                method: record.method,
                compressed: record.compressed,
                uncompressed: record.uncompressed,
                crc: record.crc,
                offset: record.points_at,
                data_offset: None,
                encrypted: record.encrypted,
                comment: record.comment.clone(),
                undeclared: false,
                disagreement: Some("the directory points here, but there is no header".into()),
            }),
        }
    }

    let prefix = entries.iter().map(|e| e.offset).min().unwrap_or(0);
    let trailing = data.len().saturating_sub(ends_at);

    Some(Archive {
        entries,
        comment,
        prefix,
        trailing,
        declared: declared_count,
    })
}

pub fn json(data: &[u8]) -> String {
    use crate::json::{push_field, push_number, push_string};

    let Some(archive) = read(data) else {
        return "null".to_string();
    };

    let mut out = String::from("{");
    push_number(&mut out, "prefix", archive.prefix);
    out.push(',');
    push_number(&mut out, "trailing", archive.trailing);
    out.push(',');
    push_number(&mut out, "declared", archive.declared);
    out.push(',');
    push_field(&mut out, "comment", &archive.comment);
    out.push(',');

    push_string(&mut out, "entries");
    out.push_str(":[");
    for (i, entry) in archive.entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "name", &entry.name);
        out.push(',');
        push_field(&mut out, "method", entry.method);
        out.push(',');
        push_number(&mut out, "compressed", entry.compressed as usize);
        out.push(',');
        push_number(&mut out, "uncompressed", entry.uncompressed as usize);
        out.push(',');
        push_number(&mut out, "offset", entry.offset);
        out.push(',');
        push_string(&mut out, "dataOffset");
        match entry.data_offset {
            Some(at) => out.push_str(&format!(":{at},")),
            None => out.push_str(":null,"),
        }
        push_string(&mut out, "crc");
        out.push_str(&format!(":\"{:08x}\",", entry.crc));
        push_string(&mut out, "encrypted");
        out.push_str(if entry.encrypted { ":true," } else { ":false," });
        push_string(&mut out, "undeclared");
        out.push_str(if entry.undeclared {
            ":true,"
        } else {
            ":false,"
        });
        push_field(&mut out, "comment", &entry.comment);
        out.push(',');
        push_string(&mut out, "disagreement");
        match &entry.disagreement {
            Some(said) => {
                out.push(':');
                let mut held = String::new();
                push_string(&mut held, said);
                out.push_str(&held);
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
