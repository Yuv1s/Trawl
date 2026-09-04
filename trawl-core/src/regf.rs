//! Windows registry hives, read as the linked structure they are.
//!
//! Every other format this reads describes itself in a table. A PNG lists
//! its chunks in order, a ZIP writes a directory, an ELF has a section
//! header table, and reading any of them is a matter of walking a list. A
//! hive has no such list. It is a tree of cells that point at each other by
//! byte offset, closer to a heap dumped to disk than to a file format, and
//! the only way to know what is in one is to start at the root and follow
//! the pointers.
//!
//! The layout: a 4096-byte base block naming the root cell, then a run of
//! bins, each holding cells. Every offset in the file is relative to the end
//! of the base block rather than to the file, so [`Hive::cell`] does that
//! translation once and bounds-checks the result. A cell whose size is
//! negative is in use; a positive size means it was freed and its bytes are
//! still sitting there, which is the same leftover-data story
//! [`crate::pdf`] tells about an object the cross-reference table dropped.
//!
//! Keys are `nk` cells, values are `vk` cells, and a key's subkeys are
//! reached through a list cell that is one of four kinds (`lf`, `lh`, `li`,
//! `ri`), the last of which points at more lists rather than at keys. Names
//! are either ASCII or UTF-16, decided by a flag bit, and getting that
//! backwards turns every name into either mojibake or every other letter.
//!
//! What makes a hive worth reading at all is that every key carries the time
//! it was last written. That timestamp is the whole basis of registry
//! forensics: it is not a log of what happened, but it is a record of when
//! something last touched a particular key, and for keys Windows only
//! touches on a specific event, the difference stops mattering much.

use crate::binary::MAX_SYMBOLS;

/// Where the hive bins begin, and the point every offset in the file is
/// measured from.
const BASE_BLOCK: usize = 4096;

/// How many keys a single walk will visit. A real SYSTEM hive holds
/// hundreds of thousands, which no panel can show and no browser should be
/// asked to hold, so the walk stops and says it stopped.
const MAX_KEYS: usize = 20_000;

/// Days between 1601-01-01, where Windows counts from, and 1970-01-01,
/// where the civil-date maths below counts from.
const EPOCH_GAP_DAYS: i64 = 134_774;

/// A Windows FILETIME as an ISO 8601 date, or empty when the field is zero
/// or beyond what a date can express.
///
/// Written out here rather than pulled in, the same as every other
/// conversion in this crate. The civil-date arithmetic is Howard Hinnant's,
/// which is the standard way to get from a day count to a calendar date
/// without a table of month lengths.
pub fn filetime(raw: u64) -> String {
    if raw == 0 {
        return String::new();
    }

    let seconds = (raw / 10_000_000) as i64;
    let days = seconds.div_euclid(86_400) - EPOCH_GAP_DAYS;
    let time = seconds.rem_euclid(86_400);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;

    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);

    if !(1601..=9999).contains(&year) {
        return String::new();
    }

    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// What a value holds, once its type has been applied to its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    pub name: String,
    /// The type as the format names it, `REG_SZ` and the rest.
    pub kind: &'static str,
    /// The data as text where the type is textual or small enough to render
    /// as a number, and a hex preview otherwise.
    pub data: String,
    /// True when the data was too large to render whole and was cut.
    pub clipped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub name: String,
    /// When this key was last written, which is the only timing evidence a
    /// hive carries.
    pub written: String,
    pub subkeys: usize,
    pub values: Vec<Value>,
}

fn value_kind(raw: u32) -> &'static str {
    match raw {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        _ => "an unnamed type",
    }
}

/// UTF-16LE up to the first terminator, which is what a hive stores a name
/// or a single string in unless a flag says otherwise.
fn utf16(bytes: &[u8]) -> String {
    let (pairs, _) = bytes.as_chunks::<2>();
    let units: Vec<u16> = pairs
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .take_while(|&unit| unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Every string in a buffer that holds several, which is what
/// `REG_MULTI_SZ` is: one run of text with a terminator after each entry and
/// an empty one at the end. Stopping at the first terminator, the way a
/// single string is read, would report only the first of them.
fn utf16_multi(bytes: &[u8]) -> Vec<String> {
    let (pairs, _) = bytes.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().map(|&pair| u16::from_le_bytes(pair)).collect();

    units
        .split(|&unit| unit == 0)
        .filter(|part| !part.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

/// A hex preview, for the data that is not text and not a number.
fn hex(bytes: &[u8], limit: usize) -> String {
    bytes
        .iter()
        .take(limit)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub struct Hive<'a> {
    data: &'a [u8],
    /// The root key's cell offset, from the base block.
    root: u32,
    pub version: String,
    /// The path the hive names for itself, which for a user hive is where it
    /// lived on the machine it came from.
    pub file_name: String,
    pub written: String,
}

impl<'a> Hive<'a> {
    pub fn open(data: &'a [u8]) -> Option<Hive<'a>> {
        if !data.starts_with(b"regf") || data.len() < BASE_BLOCK {
            return None;
        }

        let u32_at = |at: usize| -> Option<u32> {
            let raw: [u8; 4] = data.get(at..at + 4)?.try_into().ok()?;
            Some(u32::from_le_bytes(raw))
        };
        let u64_at = |at: usize| -> Option<u64> {
            let raw: [u8; 8] = data.get(at..at + 8)?.try_into().ok()?;
            Some(u64::from_le_bytes(raw))
        };

        let major = u32_at(0x14)?;
        let minor = u32_at(0x18)?;
        let root = u32_at(0x24)?;

        Some(Hive {
            data,
            root,
            version: format!("{major}.{minor}"),
            // The name is a fixed 64-byte field, so it is read to its own
            // length rather than to a terminator.
            file_name: utf16(data.get(0x30..0x30 + 64)?),
            written: filetime(u64_at(0x0c)?),
        })
    }

    /// The bytes of the cell at an offset, or nothing when the offset lands
    /// outside the file or names a cell that was freed.
    ///
    /// A cell's first four bytes are its own size, signed, and negative
    /// means in use. Reading a freed cell as though it were live is how a
    /// walk ends up reporting whatever happened to be in reclaimed space.
    fn cell(&self, offset: u32) -> Option<&'a [u8]> {
        if offset == u32::MAX {
            return None;
        }
        let at = BASE_BLOCK.checked_add(offset as usize)?;
        let raw: [u8; 4] = self.data.get(at..at.checked_add(4)?)?.try_into().ok()?;
        let size = i32::from_le_bytes(raw);
        if size >= 0 {
            return None;
        }
        let len = size.unsigned_abs() as usize;
        self.data.get(at + 4..at.checked_add(len)?)
    }

    /// The root key, which every walk starts from.
    pub fn root(&self) -> Option<Key> {
        self.key_at(self.root)
    }

    fn key_at(&self, offset: u32) -> Option<Key> {
        let cell = self.cell(offset)?;
        if cell.get(..2)? != b"nk" {
            return None;
        }

        let u16_at = |at: usize| -> Option<u16> {
            let raw: [u8; 2] = cell.get(at..at + 2)?.try_into().ok()?;
            Some(u16::from_le_bytes(raw))
        };
        let u32_at = |at: usize| -> Option<u32> {
            let raw: [u8; 4] = cell.get(at..at + 4)?.try_into().ok()?;
            Some(u32::from_le_bytes(raw))
        };
        let u64_at = |at: usize| -> Option<u64> {
            let raw: [u8; 8] = cell.get(at..at + 8)?.try_into().ok()?;
            Some(u64::from_le_bytes(raw))
        };

        let flags = u16_at(2)?;
        let subkeys = u32_at(0x14)? as usize;
        let value_count = u32_at(0x24)? as usize;
        let value_list = u32_at(0x28)?;
        let name_length = u16_at(0x48)? as usize;

        // Bit 5 says the name is one byte per character rather than two.
        // Reading it the wrong way gives either every other letter or a run
        // of replacement characters, and both look like a corrupt hive.
        let raw_name = cell.get(0x4c..0x4c + name_length)?;
        let name = if flags & 0x20 != 0 {
            crate::json::latin1(raw_name)
        } else {
            utf16(raw_name)
        };

        Some(Key {
            name,
            written: filetime(u64_at(4)?),
            subkeys,
            values: self.values(value_list, value_count),
        })
    }

    fn values(&self, list_offset: u32, count: usize) -> Vec<Value> {
        let Some(list) = self.cell(list_offset) else {
            return Vec::new();
        };

        (0..count.min(MAX_SYMBOLS))
            .filter_map(|index| {
                let at = index * 4;
                let raw: [u8; 4] = list.get(at..at + 4)?.try_into().ok()?;
                self.value_at(u32::from_le_bytes(raw))
            })
            .collect()
    }

    fn value_at(&self, offset: u32) -> Option<Value> {
        let cell = self.cell(offset)?;
        if cell.get(..2)? != b"vk" {
            return None;
        }

        let u16_at = |at: usize| -> Option<u16> {
            let raw: [u8; 2] = cell.get(at..at + 2)?.try_into().ok()?;
            Some(u16::from_le_bytes(raw))
        };
        let u32_at = |at: usize| -> Option<u32> {
            let raw: [u8; 4] = cell.get(at..at + 4)?.try_into().ok()?;
            Some(u32::from_le_bytes(raw))
        };

        let name_length = u16_at(2)? as usize;
        let declared = u32_at(4)?;
        let data_offset = u32_at(8)?;
        let kind = value_kind(u32_at(0x0c)?);
        let flags = u16_at(0x10)?;

        let raw_name = cell.get(0x14..0x14 + name_length)?;
        let name = if flags & 0x01 != 0 {
            crate::json::latin1(raw_name)
        } else {
            utf16(raw_name)
        };

        // The top bit of the size means the data is small enough to live in
        // the offset field itself rather than in a cell of its own.
        let inline = declared & 0x8000_0000 != 0;
        let length = (declared & 0x7fff_ffff) as usize;

        let owned;
        let data: &[u8] = if inline {
            owned = data_offset.to_le_bytes();
            owned.get(..length.min(4))?
        } else {
            let cell = self.cell(data_offset)?;
            cell.get(..length.min(cell.len()))?
        };

        const PREVIEW: usize = 512;
        let clipped = data.len() > PREVIEW;
        let shown = &data[..data.len().min(PREVIEW)];

        let rendered = match kind {
            "REG_SZ" | "REG_EXPAND_SZ" | "REG_LINK" => utf16(shown),
            "REG_MULTI_SZ" => utf16_multi(shown).join(", "),
            "REG_DWORD" => shown
                .get(..4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(|b| u32::from_le_bytes(b).to_string())
                .unwrap_or_default(),
            "REG_DWORD_BIG_ENDIAN" => shown
                .get(..4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(|b| u32::from_be_bytes(b).to_string())
                .unwrap_or_default(),
            "REG_QWORD" => shown
                .get(..8)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map(|b| u64::from_le_bytes(b).to_string())
                .unwrap_or_default(),
            _ => hex(shown, 64),
        };

        Some(Value {
            name,
            kind,
            data: rendered,
            clipped,
        })
    }

    /// Every subkey offset a key lists, following whichever of the four list
    /// kinds it uses.
    fn subkey_offsets(&self, key_offset: u32) -> Vec<u32> {
        let Some(cell) = self.cell(key_offset) else {
            return Vec::new();
        };
        if cell.get(..2) != Some(b"nk") {
            return Vec::new();
        }
        let Some(raw) = cell.get(0x1c..0x20).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
            return Vec::new();
        };

        let mut out = Vec::new();
        self.collect_list(u32::from_le_bytes(raw), &mut out, 0);
        out
    }

    /// Reads a subkey list into `out`. An `ri` list holds other lists rather
    /// than keys, so this recurses, bounded in case one points at itself.
    fn collect_list(&self, offset: u32, out: &mut Vec<u32>, depth: usize) {
        if depth > 4 || out.len() >= MAX_KEYS {
            return;
        }
        let Some(cell) = self.cell(offset) else { return };
        let Some(kind) = cell.get(..2) else { return };
        let Some(count) = cell
            .get(2..4)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_le_bytes)
        else {
            return;
        };

        // lf and lh carry a four-byte hint after each offset that this does
        // not need; li carries nothing; ri carries offsets to more lists.
        let stride = match kind {
            b"lf" | b"lh" => 8,
            b"li" | b"ri" => 4,
            _ => return,
        };

        for index in 0..count as usize {
            if out.len() >= MAX_KEYS {
                return;
            }
            let at = 4 + index * stride;
            let Some(raw) = cell.get(at..at + 4).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
                return;
            };
            let entry = u32::from_le_bytes(raw);

            if kind == b"ri" {
                self.collect_list(entry, out, depth + 1);
            } else {
                out.push(entry);
            }
        }
    }

    /// The subkeys of a key, as keys rather than offsets.
    pub fn children(&self, key_offset: u32) -> Vec<(u32, Key)> {
        self.subkey_offsets(key_offset)
            .into_iter()
            .filter_map(|offset| self.key_at(offset).map(|key| (offset, key)))
            .collect()
    }

    /// Walks down a path from the root, matching each part case
    /// insensitively, which is how Windows itself treats a key name.
    pub fn find(&self, path: &str) -> Option<(u32, Key)> {
        let mut offset = self.root;
        let mut key = self.key_at(offset)?;

        for part in path.split('\\').filter(|p| !p.is_empty()) {
            let (next_offset, next) = self
                .children(offset)
                .into_iter()
                .find(|(_, child)| child.name.eq_ignore_ascii_case(part))?;
            offset = next_offset;
            key = next;
        }

        Some((offset, key))
    }

    pub fn root_offset(&self) -> u32 {
        self.root
    }
}

#[cfg(test)]
pub(crate) mod tests;
