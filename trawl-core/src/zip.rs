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
use std::collections::HashMap;

const LOCAL: &[u8; 4] = b"PK\x03\x04";
const CENTRAL: &[u8; 4] = b"PK\x01\x02";
const END: &[u8; 4] = b"PK\x05\x06";
const DESCRIPTOR: &[u8; 4] = b"PK\x07\x08";

/// Most entries read from either place. A header is thirty bytes, so a file of nothing
/// else would report far more text than it holds, and this is the format's own limit
/// without its 64-bit extension. An archive past it is told so.
const MAX_ENTRIES: usize = 1 << 16;

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
    /// What the local header called the method, when the directory calls it otherwise.
    pub local_method: Option<&'static str>,
    /// The directory's numbers when it lists this entry, since those are what every
    /// reader goes by. What the header says instead is in `disagreement`.
    pub compressed: u64,
    pub uncompressed: u64,
    pub crc: u32,
    /// Where the local header sits in the file.
    pub offset: usize,
    /// Where this entry's compressed data begins, past its local header and
    /// name. None for a phantom the directory points at with no header of its
    /// own, since there is no data to point to.
    pub data_offset: Option<usize>,
    /// How many bytes from `data_offset` to read: the longest either description makes
    /// possible, so a size zeroed or inflated in one place does not hide what the other
    /// describes.
    pub read_length: usize,
    /// The archive's own password flag. Trawl does not crack these.
    ///
    /// Set only when both places say so. The two disagreeing is pseudo-encryption,
    /// a flag flipped so tools ask for a password the data was never locked with,
    /// which is reported as a disagreement and leaves the entry worth opening.
    pub encrypted: bool,
    /// True when the local header says its sizes follow the data rather than being in
    /// the header, the way a writer that cannot seek back has to do it.
    pub streamed: bool,
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
    /// True when the walk stopped at [`MAX_ENTRIES`] with more of the file to go.
    pub capped: bool,
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
        local_method: None,
        crc: u32_at(data, at + 14)?,
        compressed: u32_at(data, at + 18)? as u64,
        uncompressed: u32_at(data, at + 22)? as u64,
        offset: at,
        data_offset: Some(name_at + name_len + extra_len),
        read_length: 0,
        // Bit zero is the archive saying its own data is encrypted.
        encrypted: flags & 1 == 1,
        // Bit three says the three fields above are zero here, and come after the data.
        streamed: flags & 8 != 0,
        comment: String::new(),
        undeclared: true,
        disagreement: None,
    })
}

/// Every local header in the file, in the order they appear, and whether the walk
/// stopped at the limit before the end of the file.
///
/// Walked rather than followed from the directory, so an entry the directory
/// never mentions is still found. That is the whole point.
fn locals(data: &[u8]) -> (Vec<Entry>, bool) {
    let mut out = Vec::new();
    let mut at = 0usize;

    while out.len() < MAX_ENTRIES
        && let Some(found) = bytes::find(data, at, LOCAL)
    {
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

    for index in 0..out.len() {
        let bound = out.get(index + 1).map_or(data.len(), |next| next.offset);
        let entry = &mut out[index];
        if entry.streamed {
            read_descriptor(data, entry, bound);
        }
    }

    let capped = out.len() >= MAX_ENTRIES && bytes::find(data, at, LOCAL).is_some();
    (out, capped)
}

/// Fills in a streamed entry's sizes from the descriptor that follows its data.
///
/// The signature is optional in the format and can occur in the data, so what settles
/// it is the compressed size it carries matching how far away it sits. Searched only
/// as far as the next header, so a file of these stays a single pass. A descriptor
/// that cannot be found is no finding: the directory, when there is one, has the same
/// numbers, and an entry only a local header names keeps what the header said.
fn read_descriptor(data: &[u8], entry: &mut Entry, bound: usize) {
    let Some(start) = entry.data_offset else {
        return;
    };
    let region = data.get(start..bound).unwrap_or(&[]);

    let mut from = 0usize;
    while let Some(found) = bytes::find(region, from, DESCRIPTOR) {
        let at = start + found;
        if let (Some(crc), Some(compressed), Some(uncompressed)) = (
            u32_at(data, at + 4),
            u32_at(data, at + 8),
            u32_at(data, at + 12),
        ) && compressed as usize == found
        {
            entry.crc = crc;
            entry.compressed = compressed as u64;
            entry.uncompressed = uncompressed as u64;
            return;
        }
        from = found + 4;
    }
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

/// Whether a signature sits at an offset the file itself gave, which can be anything.
fn signature_at(data: &[u8], at: usize, signature: &[u8]) -> bool {
    at.checked_add(signature.len())
        .and_then(|end| data.get(at..end))
        == Some(signature)
}

/// Where this archive's own directory starts, by what its end record says.
///
/// The first signature in the file is not good enough: a ZIP stored inside this
/// one carries a directory of its own, which comes first. Measured back from the
/// end record, so an archive with bytes in front of it still works, and falling
/// back to the first signature when a doctored end record points at nothing.
fn directory_start(data: &[u8]) -> Option<usize> {
    let is_directory = |at: usize| signature_at(data, at, CENTRAL);

    last_end(data)
        .and_then(|end| {
            let size = u32_at(data, end + 12)? as usize;
            let offset = u32_at(data, end + 16)? as usize;
            end.checked_sub(size)
                .filter(|&at| is_directory(at))
                .or(Some(offset).filter(|&at| is_directory(at)))
        })
        .or_else(|| bytes::find(data, 0, CENTRAL))
}

/// Every record of the central directory, walked from where it starts.
fn declared(data: &[u8]) -> Vec<Declared> {
    let mut out = Vec::new();
    let Some(mut at) = directory_start(data) else {
        return out;
    };

    while out.len() < MAX_ENTRIES
        && let Some((record, next)) = central_at(data, at)
    {
        out.push(record);
        at = next;
    }

    out
}

/// The last end-of-directory signature. The signature can occur in file data,
/// and the real record is the last one.
fn last_end(data: &[u8]) -> Option<usize> {
    let mut at = None;
    let mut from = 0usize;
    while let Some(found) = bytes::find(data, from, END) {
        at = Some(found);
        from = found + 4;
    }
    at
}

/// Bytes after the end-of-directory record, which no zip tool writes.
pub fn trailing(data: &[u8]) -> Option<(usize, usize)> {
    let (_, _, end) = ending(data)?;
    (data.len() > end).then(|| (end, data.len() - end))
}

/// The end-of-directory record: its comment, its claimed count, and where it
/// finishes.
fn ending(data: &[u8]) -> Option<(String, usize, usize)> {
    let at = last_end(data)?;
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
///
/// A streamed header is meant to leave its sizes and checksum as zero, so a zero there
/// says nothing either way. Anything else it says still counts.
fn compare(local: &Entry, record: &Declared) -> Option<String> {
    let mut said = Vec::new();
    let silent = |value: u64| local.streamed && value == 0;

    if local.compressed != record.compressed && !silent(local.compressed) {
        said.push(format!(
            "compressed size {} here, {} in the directory",
            local.compressed, record.compressed
        ));
    }
    if local.uncompressed != record.uncompressed && !silent(local.uncompressed) {
        said.push(format!(
            "uncompressed size {} here, {} in the directory",
            local.uncompressed, record.uncompressed
        ));
    }
    if local.crc != record.crc && !silent(local.crc as u64) {
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
    if local.encrypted != record.encrypted {
        let state = |encrypted: bool| if encrypted { "encrypted" } else { "not encrypted" };
        said.push(format!(
            "{} here, {} in the directory",
            state(local.encrypted),
            state(record.encrypted)
        ));
    }

    (!said.is_empty()).then(|| said.join("; "))
}

/// Whether an offset falls inside any of these spans, which are left sorted and merged
/// so that thousands of entries do not each search thousands of spans.
fn merged(mut spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    spans.sort_unstable();

    let mut out: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

fn covered(spans: &[(usize, usize)], offset: usize) -> bool {
    let after = spans.partition_point(|&(start, _)| start <= offset);
    after > 0 && offset < spans[after - 1].1
}

/// Reads an archive, or returns nothing when the file is not one.
///
/// A file with no local headers at all is not a zip, whatever its extension
/// says. One with headers but no directory is a zip somebody truncated or
/// stripped, and it is still worth reporting, so that case comes back.
pub fn read(data: &[u8]) -> Option<Archive> {
    let (mut entries, capped) = locals(data);
    if entries.is_empty() {
        return None;
    }

    let records = declared(data);
    let (comment, declared_count, ends_at) = ending(data).unwrap_or_default();

    let mut at_offset: HashMap<usize, usize> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.offset, index))
        .collect();

    // What the local header claimed for each entry the directory also lists, for
    // working out what is inside what once the directory's numbers have replaced it.
    let mut local_claims: HashMap<usize, u64> = HashMap::new();

    // Everywhere an entry starts, which is as far as looking for a descriptor has to go.
    let mut starts: Vec<usize> = records
        .iter()
        .map(|record| record.points_at)
        .chain(entries.iter().map(|entry| entry.offset))
        .collect();
    starts.sort_unstable();

    // Matched by where the directory points, since that is the only link the
    // format actually defines. Names are not unique and can be edited freely.
    for record in &records {
        // A header the walk stopped short of, or stepped over, is still a header.
        if !at_offset.contains_key(&record.points_at)
            && let Some(mut entry) = local_at(data, record.points_at)
        {
            if entry.streamed {
                let next = starts.partition_point(|&start| start <= record.points_at);
                let bound = starts.get(next).copied().unwrap_or(data.len());
                read_descriptor(data, &mut entry, bound);
            }
            at_offset.insert(entry.offset, entries.len());
            entries.push(entry);
        }

        match at_offset.get(&record.points_at).map(|&index| &mut entries[index]) {
            Some(entry) => {
                entry.undeclared = false;
                entry.comment = record.comment.clone();
                entry.disagreement = compare(entry, record);
                entry.encrypted &= record.encrypted;
                local_claims.insert(entry.offset, entry.compressed);

                // The directory is what every reader goes by. A header saying nothing
                // or anything else leaves the entry where the directory put it, and
                // the difference has already been written down above.
                entry.compressed = record.compressed;
                entry.uncompressed = record.uncompressed;
                entry.crc = record.crc;
                if entry.method != record.method && record.method != "unknown" {
                    entry.local_method = Some(entry.method);
                    entry.method = record.method;
                }

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
            None => {
                at_offset.insert(record.points_at, entries.len());
                entries.push(Entry {
                    name: record.name.clone(),
                    method: record.method,
                    local_method: None,
                    compressed: record.compressed,
                    uncompressed: record.uncompressed,
                    crc: record.crc,
                    offset: record.points_at,
                    data_offset: None,
                    read_length: 0,
                    encrypted: record.encrypted,
                    streamed: false,
                    comment: record.comment.clone(),
                    undeclared: false,
                    disagreement: Some("the directory points here, but there is no header".into()),
                });
            }
        }
    }

    set_read_lengths(data, &mut entries, &local_claims);

    // A header inside a listed file's stored data belongs to that file, such as a
    // ZIP stored in a ZIP. It is not this archive hiding an entry. Measured by the
    // shorter claim, since a directory stretched over the rest of the file would
    // otherwise swallow whatever it wanted hidden.
    let inside = merged(
        entries
            .iter()
            .filter(|e| !e.undeclared && e.method == "stored")
            .filter_map(|e| {
                let start = e.data_offset?;
                let local = local_claims.get(&e.offset).copied().unwrap_or(e.compressed);
                let claim = match local {
                    0 => e.compressed,
                    local => local.min(e.compressed),
                };
                Some((start, start.saturating_add(claim as usize)))
            })
            .collect(),
    );
    entries.retain(|e| !e.undeclared || !covered(&inside, e.offset));

    let prefix = entries.iter().map(|e| e.offset).min().unwrap_or(0);
    let trailing = data.len().saturating_sub(ends_at);

    Some(Archive {
        entries,
        comment,
        prefix,
        trailing,
        declared: declared_count,
        capped,
    })
}

/// How much of the file each entry's data can be read from.
///
/// A claim running past the end of the file is impossible, and a zero is what a header
/// says when it has been cleared, so the longest claim that fits is the one taken. With
/// nothing that fits, what is there runs to the next header: deflate stops itself, and
/// stored data is better read with a tail than not at all.
fn set_read_lengths(data: &[u8], entries: &mut [Entry], local_claims: &HashMap<usize, u64>) {
    let mut headers: Vec<usize> = entries
        .iter()
        .filter(|e| e.data_offset.is_some())
        .map(|e| e.offset)
        .collect();
    headers.sort_unstable();

    for entry in entries.iter_mut() {
        let Some(start) = entry.data_offset else {
            continue;
        };
        let available = data.len().saturating_sub(start) as u64;
        let local = local_claims.get(&entry.offset).copied().unwrap_or(entry.compressed);

        let longest = [entry.compressed, local].into_iter().filter(|&claim| claim <= available).max();
        let said_something = entry.compressed != 0 || local != 0 || entry.uncompressed != 0;

        entry.read_length = match longest {
            Some(claim) if claim > 0 => claim as usize,
            // Nothing was claimed. That is an empty file, unless the writer promised to
            // say later and never did, or claims to hold something after all.
            Some(_) if !said_something && !entry.streamed => 0,
            _ => to_next_header(data.len(), start, &headers),
        };
    }
}

fn to_next_header(end: usize, start: usize, headers: &[usize]) -> usize {
    let next = headers.partition_point(|&offset| offset < start);
    headers.get(next).copied().unwrap_or(end).min(end).saturating_sub(start)
}

pub fn json(data: &[u8]) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

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
    push_bool(&mut out, "capped", archive.capped);
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
        push_string(&mut out, "localMethod");
        match entry.local_method {
            Some(method) => {
                out.push(':');
                push_string(&mut out, method);
            }
            None => out.push_str(":null"),
        }
        out.push(',');
        push_number(&mut out, "compressed", entry.compressed as usize);
        out.push(',');
        push_number(&mut out, "uncompressed", entry.uncompressed as usize);
        out.push(',');
        push_number(&mut out, "offset", entry.offset);
        out.push(',');
        push_number(&mut out, "readLength", entry.read_length);
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
