//! SQLite databases, read for their tables, their rows, and the rows that were
//! deleted but never left.
//!
//! A raw byte scan already finds a flag sitting in a database, so that is not
//! why this exists. It exists to say what the raw scan cannot: that a run of
//! bytes was a row in a named table, that a table holds so many rows, and, the
//! forensic point, that a row was deleted and is still in the file.
//!
//! SQLite never zeroes a deleted row unless it is told to. The cell is unlinked
//! from the page's list and its bytes are left in the free space between the
//! live cells, to be reused or not. So this walks each table's own pages twice,
//! the way [`crate::zip`] reads an archive twice: once down the cell list for
//! the live rows, and once through the free space for the records that are no
//! longer listed. A record found in the gap is a row a query would never
//! return and the file still remembers, which is the same leftover
//! [`crate::pdf`] finds in an orphaned object and [`crate::regf`] finds in a
//! freed cell.

use crate::bytes;
use std::borrow::Cow;
use std::collections::HashSet;

const HEADER: &[u8] = b"SQLite format 3\0";

/// How many tables, rows, and recovered rows a reading will carry. A real
/// database has more than a person reads at once, and the browser should not be
/// asked to hold all of it, so each is capped and the true count reported apart.
const MAX_TABLES: usize = 64;
const MAX_ROWS: usize = 200;
const MAX_DELETED: usize = 200;

/// Pages one table's walk will visit, which only has to read a page's header once its
/// rows are past the cap, and how deep a walk goes. SQLite's own limit on depth is 20.
const MAX_PAGES_WALKED: usize = 1 << 20;
const MAX_DEPTH: usize = 32;

/// The most columns a record can have, which is SQLite's own hard limit.
const MAX_COLUMNS: usize = 32_767;

/// Longest `CREATE TABLE` kept, and longest record reassembled from overflow pages.
const MAX_SQL_BYTES: usize = 1 << 20;
const MAX_RECORD_BYTES: usize = 8 << 20;

/// What one reading may spend, whichever way the file arranges for it to be spent.
///
/// A page can list the same cell tens of thousands of times, and sixty-four tables can
/// share a root page, so what a walk costs has little to do with the size of the file:
/// 131 KB of database can hold sixty thousand values in a row and show it to every row
/// of every table. A database that exhausts one of these still reads, with the tail of
/// what it reported missing.
struct Budget {
    /// Values decoded, at one each and one more for every [`BYTES_PER_VALUE`] of text
    /// they keep. Sixty-four tables of two hundred rows of thirty short columns is a
    /// third of this.
    values: usize,
    /// Bytes copied into a whole record to read it, from its page and its overflow chain.
    overflow: usize,
    /// Places tried as the start of a deleted row, and the types read trying them.
    carve: usize,
    /// Bytes of live cells read to tell a deleted row from a stale copy of a live one.
    compared: usize,
    /// Bytes of live text and blobs searched for flags.
    scanned: usize,
    /// Pages visited.
    pages: usize,
}

/// See [`Budget::values`]. A cell shows 240 bytes, so a row of them can keep far more
/// than its count of values says, and JSON can take six bytes to write one of those.
const BYTES_PER_VALUE: usize = 32;

impl Budget {
    fn new() -> Self {
        Self {
            values: 1 << 20,
            overflow: 256 << 20,
            carve: 1 << 26,
            compared: 256 << 20,
            scanned: 256 << 20,
            pages: 1 << 22,
        }
    }
}

/// One value in a row, rendered to the short text a person reads in a cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// "integer", "real", "text", "blob", or "null".
    pub kind: &'static str,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub values: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub name: String,
    pub columns: Vec<String>,
    /// The `CREATE TABLE` statement, verbatim from the schema.
    pub sql: String,
    /// Live rows a query would return, capped for display.
    pub rows: Vec<Row>,
    /// The true number of live rows, which `rows` is a capped copy of.
    pub row_count: usize,
    /// Rows recovered from the free space of this table's own pages: deleted,
    /// and still there.
    pub deleted: Vec<Row>,
    /// Flags in the live rows, each value searched whole. A value only shows its first
    /// 240 bytes, and one that spills across pages does not sit together in the file.
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Database {
    pub page_size: usize,
    pub page_count: usize,
    pub encoding: &'static str,
    /// The number of pages the header hands to the freelist: space the database
    /// has released and not yet reused.
    pub freelist_pages: usize,
    pub tables: Vec<Table>,
    /// The true table count, which `tables` is a capped copy of.
    pub table_count: usize,
    /// True when a live cell could not be searched to its end, because a budget ran out,
    /// or its overflow chain was cut or ran past what one record is given.
    pub flags_truncated: bool,
}

/// A SQLite varint: one to nine big-endian bytes, each but the ninth giving
/// seven bits and its top bit saying whether another follows.
fn varint(data: &[u8], at: usize) -> Option<(i64, usize)> {
    let mut result: u64 = 0;
    let mut i = 0;
    while i < 8 {
        let byte = *data.get(at + i)?;
        result = (result << 7) | (byte & 0x7f) as u64;
        i += 1;
        if byte & 0x80 == 0 {
            return Some((result as i64, i));
        }
    }
    // The ninth byte contributes all eight of its bits.
    let byte = *data.get(at + 8)?;
    result = (result << 8) | byte as u64;
    Some((result as i64, 9))
}

fn be_u16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn be_u32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

/// How text is stored in this database, which the file header settles once for
/// everything in it, the schema included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl Encoding {
    fn label(self) -> &'static str {
        match self {
            Encoding::Utf8 => "UTF-8",
            Encoding::Utf16Le => "UTF-16LE",
            Encoding::Utf16Be => "UTF-16BE",
        }
    }

    fn decode(self, bytes: &[u8]) -> String {
        let (pairs, _) = bytes.as_chunks::<2>();
        match self {
            Encoding::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
            Encoding::Utf16Le => {
                let units: Vec<u16> = pairs.iter().map(|&pair| u16::from_le_bytes(pair)).collect();
                String::from_utf16_lossy(&units)
            }
            Encoding::Utf16Be => {
                let units: Vec<u16> = pairs.iter().map(|&pair| u16::from_be_bytes(pair)).collect();
                String::from_utf16_lossy(&units)
            }
        }
    }
}

/// How text values are rendered: which encoding, and how much of one to keep.
#[derive(Debug, Clone, Copy)]
struct Text {
    encoding: Encoding,
    cap: usize,
}

/// A cell decoded to its rowid and record values.
struct Cell {
    rowid: i64,
    values: Vec<Value>,
}

/// Decodes a record: a header of serial types, then the values they describe.
///
/// A record that claims more than `payload` holds is corrupt when the payload is
/// whole, and refused. When it is not, because its overflow chain was cut or ran past
/// what a row is given, the values that fit are returned and the first that does not
/// is shown as far as it goes.
fn decode_record(payload: &[u8], whole: bool, text: Text, budget: &mut usize) -> Option<Vec<Value>> {
    let (header_len, n) = varint(payload, 0)?;
    let header_len = usize::try_from(header_len).ok()?;
    if header_len == 0 || header_len > payload.len() {
        return None;
    }

    let mut types = Vec::new();
    let mut at = n;
    while at < header_len {
        if types.len() >= MAX_COLUMNS || *budget == 0 {
            return None;
        }
        *budget -= 1;

        let (serial, used) = varint(payload, at)?;
        types.push(serial);
        at += used;
    }

    let mut values = Vec::with_capacity(types.len());
    let mut body = header_len;
    for serial in types {
        let rest = payload.get(body..)?;
        match decode_value(serial, rest, text, !whole) {
            Some((value, size)) => {
                *budget = budget.saturating_sub(value.text.len() / BYTES_PER_VALUE);
                values.push(value);
                body += size;
                if serial_len(serial) != Some(size) {
                    break;
                }
            }
            None if whole => return None,
            None => break,
        }
    }
    Some(values)
}

/// How many bytes of body a serial type consumes.
fn serial_len(serial: i64) -> Option<usize> {
    match serial {
        0 | 8 | 9 => Some(0),
        1 => Some(1),
        2 => Some(2),
        3 => Some(3),
        4 => Some(4),
        5 => Some(6),
        6 | 7 => Some(8),
        n if n >= 12 => usize::try_from((n - if n % 2 == 0 { 12 } else { 13 }) / 2).ok(),
        _ => None,
    }
}

/// One serial type applied to the bytes that follow it.
///
/// @param clip return as much of a text or blob as there is, rather than nothing,
///        when there is less than it claims
fn decode_value(serial: i64, rest: &[u8], text: Text, clip: bool) -> Option<(Value, usize)> {
    let integer = |bytes: &[u8]| -> i64 {
        let mut v: i64 = if bytes.first().is_some_and(|b| b & 0x80 != 0) {
            -1
        } else {
            0
        };
        for &b in bytes {
            v = (v << 8) | b as i64;
        }
        v
    };
    let int_value = |n: i64| Value {
        kind: "integer",
        text: n.to_string(),
    };

    match serial {
        0 => Some((
            Value {
                kind: "null",
                text: "NULL".into(),
            },
            0,
        )),
        1 => Some((int_value(integer(rest.get(..1)?)), 1)),
        2 => Some((int_value(integer(rest.get(..2)?)), 2)),
        3 => Some((int_value(integer(rest.get(..3)?)), 3)),
        4 => Some((int_value(integer(rest.get(..4)?)), 4)),
        5 => Some((int_value(integer(rest.get(..6)?)), 6)),
        6 => Some((int_value(integer(rest.get(..8)?)), 8)),
        7 => {
            let raw: [u8; 8] = rest.get(..8)?.try_into().ok()?;
            Some((
                Value {
                    kind: "real",
                    text: format!("{}", f64::from_be_bytes(raw)),
                },
                8,
            ))
        }
        8 => Some((int_value(0), 0)),
        9 => Some((int_value(1), 0)),
        n if n >= 12 => {
            let len = serial_len(n)?;
            let held = if clip { len.min(rest.len()) } else { len };
            let bytes = rest.get(..held)?;
            if n % 2 == 0 {
                Some((
                    Value {
                        kind: "blob",
                        text: blob_preview(bytes, len),
                    },
                    held,
                ))
            } else {
                Some((
                    Value {
                        kind: "text",
                        text: text_preview(bytes, len, text),
                    },
                    held,
                ))
            }
        }
        _ => None,
    }
}

const CELL_TEXT_CAP: usize = 240;

fn text_preview(bytes: &[u8], declared: usize, text: Text) -> String {
    let shown = &bytes[..bytes.len().min(text.cap)];
    let mut out = text.encoding.decode(shown);
    if declared > shown.len() {
        out.push('…');
    }
    out
}

fn blob_preview(bytes: &[u8], declared: usize) -> String {
    let shown = &bytes[..bytes.len().min(24)];
    let hex: String = shown.iter().map(|b| format!("{b:02x}")).collect();
    if declared > 24 {
        format!("{hex}… ({declared} bytes)")
    } else {
        format!("{hex} ({declared} bytes)")
    }
}

/// The bytes of a page, 1-indexed the way SQLite counts them.
fn page_bytes(data: &[u8], page: u32, page_size: usize) -> Option<&[u8]> {
    if page == 0 {
        return None;
    }
    // A 32-bit page number times the page size wraps in WASM, and a wrapped offset is
    // some other page, read as though it were this one.
    let start = (page as usize - 1).checked_mul(page_size)?;
    data.get(start..start.checked_add(page_size)?)
}

/// Where a page's b-tree content begins: after the 100-byte file header on page
/// one, at the very start on every other.
fn header_offset(page: u32) -> usize {
    if page == 1 { 100 } else { 0 }
}

/// What reading any page of this file depends on.
struct Db<'a> {
    data: &'a [u8],
    page_size: usize,
    usable: usize,
    encoding: Encoding,
}

impl Db<'_> {
    /// How much of a payload sits in the cell itself, by the format's own arithmetic.
    /// Whatever is left runs through a chain of overflow pages.
    fn local_size(&self, payload: usize) -> usize {
        let usable = self.usable;
        let most = usable.saturating_sub(35);
        if payload <= most {
            return payload;
        }
        let least = (usable.saturating_sub(12) * 32 / 255).saturating_sub(23);
        let chained = least + (payload - least) % usable.saturating_sub(4).max(1);
        if chained <= most { chained } else { least }
    }

    /// Walks a table's b-tree, calling `visit` on every leaf page it reaches. The
    /// walk is bounded and refuses to revisit a page, so a database whose pointers
    /// form a loop cannot spin it, and it recurses only as deep as a real tree goes,
    /// so one built as a chain thousands of pages long cannot run out the stack.
    fn walk_leaves(
        &self,
        page: u32,
        depth: usize,
        seen: &mut HashSet<u32>,
        pages: &mut usize,
        visit: &mut impl FnMut(&[u8], usize),
    ) {
        if depth > MAX_DEPTH || *pages == 0 || !seen.insert(page) {
            return;
        }
        *pages -= 1;

        let Some(bytes) = page_bytes(self.data, page, self.page_size) else {
            return;
        };
        let head = header_offset(page);
        let Some(&kind) = bytes.get(head) else {
            return;
        };

        match kind {
            // Leaf table page: the rows live here.
            0x0d => visit(bytes, head),
            // Interior table page: pointers to children, then a rightmost pointer.
            0x05 => {
                let Some(cells) = be_u16(bytes, head + 3) else {
                    return;
                };
                let pointer_array = head + 12;
                for i in 0..cells as usize {
                    let Some(off) = be_u16(bytes, pointer_array + i * 2) else {
                        break;
                    };
                    if let Some(child) = be_u32(bytes, off as usize) {
                        self.walk_leaves(child, depth + 1, seen, pages, visit);
                    }
                }
                if let Some(right) = be_u32(bytes, head + 8) {
                    self.walk_leaves(right, depth + 1, seen, pages, visit);
                }
            }
            _ => {}
        }
    }

    /// Follows an overflow chain for up to `wanted` bytes. The chain can loop or end
    /// early, and neither matters, since every page taken brings the count down.
    fn chain(&self, first: u32, wanted: usize, budget: &mut Budget, into: &mut Vec<u8>) {
        let mut page = first;
        let mut left = wanted;
        let room = self.usable.saturating_sub(4);

        while left > 0 && room > 0 {
            let Some(bytes) = page_bytes(self.data, page, self.page_size) else {
                return;
            };
            let take = left.min(room).min(budget.overflow);
            if take == 0 {
                return;
            }
            into.extend_from_slice(&bytes[4..4 + take]);
            budget.overflow -= take;
            left -= take;

            let Some(next) = be_u32(bytes, 0) else {
                return;
            };
            page = next;
        }
    }

    /// Whether the record of the cell at `at` runs on through an overflow chain, which
    /// is what leaves a value in pieces around the file.
    fn spills(&self, page: &[u8], at: usize) -> bool {
        varint(page, at).is_some_and(|(length, _)| {
            let length = usize::try_from(length.max(0)).unwrap_or(usize::MAX);
            length > self.local_size(length)
        })
    }

    /// The record of the table-leaf cell at `at`: a payload length, a rowid, then the
    /// record, with whatever does not fit on the page fetched from its overflow chain.
    ///
    /// @return the rowid, the record, and whether that is all of it
    fn record<'p>(
        &self,
        page: &'p [u8],
        at: usize,
        budget: &mut Budget,
    ) -> Option<(i64, Cow<'p, [u8]>, bool)> {
        let (payload_len, n1) = varint(page, at)?;
        let (rowid, n2) = varint(page, at + n1)?;
        let body_at = at + n1 + n2;
        let payload_len = usize::try_from(payload_len.max(0)).unwrap_or(usize::MAX);

        let local = self.local_size(payload_len);
        let on_page = self.usable.saturating_sub(body_at).min(local);
        let held = page.get(body_at..body_at + on_page)?;

        if payload_len <= on_page {
            return Some((rowid, Cow::Borrowed(held), true));
        }

        budget.overflow = budget.overflow.checked_sub(on_page)?;
            let mut payload = held.to_vec();
            if on_page == local
                && let Some(first) = be_u32(page, body_at + local)
            {
                let wanted = payload_len.min(MAX_RECORD_BYTES).saturating_sub(local);
                self.chain(first, wanted, budget, &mut payload);
            }
            let whole = payload.len() == payload_len;
        Some((rowid, Cow::Owned(payload), whole))
    }

    /// Reads a table-leaf cell at `at`, to the values it shows.
    fn read_cell(&self, page: &[u8], at: usize, text: Text, budget: &mut Budget) -> Option<Cell> {
        let (rowid, payload, whole) = self.record(page, at, budget)?;
        let values = decode_record(&payload, whole, text, &mut budget.values)?;
        Some(Cell { rowid, values })
    }

    /// A cell lying whole in free space, if `at` starts one and it fits before `end`:
    /// its length fields and record all have to account for each other exactly, which
    /// is what stops arbitrary bytes passing for one.
    fn intact_cell(
        &self,
        page: &[u8],
        at: usize,
        end: usize,
        columns: usize,
        budget: &mut Budget,
    ) -> Option<(Cell, usize)> {
        let (payload_len, n1) = varint(page, at)?;
        let (rowid, n2) = varint(page, at + n1)?;
        let payload_len = usize::try_from(payload_len).ok().filter(|&length| length > 0)?;
        let body_at = at + n1 + n2;

        let local = self.local_size(payload_len);
        let spills = payload_len > local;
        let cell_end = body_at.checked_add(local)?.checked_add(if spills { 4 } else { 0 })?;
        if cell_end > end {
            return None;
        }

        let held = page.get(body_at..body_at + local)?;
        let (header_len, used) = varint(held, 0)?;
        let header_len = usize::try_from(header_len).ok()?;
        if header_len < used.max(2) || header_len > local {
            return None;
        }

        let mut count = 0usize;
        let mut claimed = header_len;
        let mut cursor = used;
        while cursor < header_len {
            count += 1;
            budget.carve = budget.carve.saturating_sub(1);
            if count > columns + 1 {
                return None;
            }
            let (serial, width) = varint(held, cursor)?;
            claimed = claimed.saturating_add(serial_len(serial)?);
            cursor += width;
        }
        if cursor != header_len || claimed != payload_len {
            return None;
        }

        let text = Text {
            encoding: self.encoding,
            cap: CELL_TEXT_CAP,
        };
        let values = decode_record(held, !spills, text, &mut budget.values)?;
        plausible(&values, columns).then_some((Cell { rowid, values }, cell_end))
    }

    /// Recovers deleted rows from a leaf page's free space.
    ///
    /// Deleting a row turns its cell into a freeblock: the block's own four-byte
    /// header, a next pointer and a size, is written over the cell's first four
    /// bytes, and the rest of the record is left untouched. So the leading bytes,
    /// the payload length, the rowid and usually the record's header length and
    /// first column type, are gone, but the surviving column types and every value
    /// are still there. Neighbouring free cells are merged into one block, and what
    /// was in the middle of it stays there too.
    ///
    /// Deleting the cell at the very front of the content area does not make a
    /// freeblock at all. The area just starts later, and the cell is left whole in the
    /// gap, which is where a table's most recently inserted row goes when it is the
    /// one deleted.
    fn recover_deleted(
        &self,
        page: &[u8],
        head: usize,
        columns: usize,
        alias: Option<usize>,
        out: &mut Vec<Row>,
        budget: &mut Budget,
    ) {
        let mut carved = Vec::new();

        let mut freeblock = be_u16(page, head + 1).unwrap_or(0) as usize;
        let mut guard = 0;
        while freeblock != 0 && guard < 4096 && budget.carve > 0 {
            guard += 1;
            let (Some(next), Some(size)) = (be_u16(page, freeblock), be_u16(page, freeblock + 2))
            else {
                break;
            };
            let (next, size) = (next as usize, size as usize);

            if size >= 6 && freeblock + size <= page.len() {
                self.carve_block(page, freeblock + 4, freeblock + size, columns, budget, &mut carved);
            }

            // The chain runs strictly forward through the page; anything else is a
            // loop, and a loop is a doctored file, not a database to trust.
            if next <= freeblock {
                break;
            }
            freeblock = next;
        }

        // Between the end of the cell pointers and the start of the content area.
        let cells = be_u16(page, head + 3).unwrap_or(0) as usize;
        let content = match be_u16(page, head + 5) {
            Some(0) => 65536,
            Some(start) => start as usize,
            None => 0,
        };
        let gap_end = content.min(self.usable).min(page.len());
        self.carve_cells(page, head + 8 + cells * 2, gap_end, columns, budget, &mut carved);

        if carved.is_empty() {
            return;
        }

        // Defragmenting a page moves its cells and leaves the old copies behind, and a
        // row a query still returns has not been deleted. With nothing left to check
        // that with, nothing more can be called deleted.
        let Some(live) = self.live_cells(page, head, &mut budget.compared) else {
            return;
        };
        for (raw, cell) in carved {
            if raw.is_some_and(|bytes: &[u8]| live.contains(bytes)) {
                continue;
            }
            let mut values = cell.values;
            if let (Some(rowid), Some(alias)) = (cell.rowid, alias)
                && let Some(value) = values.get_mut(alias)
                && value.kind == "null"
            {
                *value = Value {
                    kind: "integer",
                    text: rowid.to_string(),
                };
            }
            if out.len() < MAX_DELETED {
                out.push(Row { values });
            }
        }
    }

    /// The bytes of every cell this page still lists, or nothing once `budget` runs out,
    /// since a page can list a long cell thousands of times.
    fn live_cells<'p>(&self, page: &'p [u8], head: usize, budget: &mut usize) -> Option<HashSet<&'p [u8]>> {
        let mut out = HashSet::new();
        for at in live_cell_offsets(page, head) {
            let Some((payload_len, n1)) = varint(page, at) else {
                continue;
            };
            let Some((_, n2)) = varint(page, at + n1) else {
                continue;
            };
            let payload_len = usize::try_from(payload_len).unwrap_or(usize::MAX);
            let local = self.local_size(payload_len);
            let spill = if payload_len > local { 4 } else { 0 };
            if let Some(bytes) = page.get(at..at + n1 + n2 + local + spill) {
                *budget = budget.checked_sub(bytes.len())?;
                out.insert(bytes);
            }
        }
        Some(out)
    }

    /// Carves every row out of one freeblock, whose first record lost its opening
    /// bytes to the block's header.
    fn carve_block<'p>(
        &self,
        page: &'p [u8],
        start: usize,
        end: usize,
        columns: usize,
        budget: &mut Budget,
        out: &mut Vec<(Option<&'p [u8]>, Carved)>,
    ) {
        let mut at = start;
        let mut clobbered = true;

        while at < end && budget.carve > 0 {
            budget.carve -= 1;

            if clobbered && let Some((values, next)) = self.carve_record(page, at, end, columns, budget) {
                out.push((
                    None,
                    Carved {
                        rowid: None,
                        values,
                    },
                ));
                at = next;
                clobbered = false;
                continue;
            }
            clobbered = false;

            // What a record leaves behind it: a cell freed after it and merged in, or
            // the header of one freed before it. Up to three stray bytes can sit
            // between two freed cells, which SQLite folds into the block.
            let found = (0..=3).find_map(|skip| {
                let here = at + skip;
                if here >= end {
                    return None;
                }
                if let Some((cell, next)) = self.intact_cell(page, here, end, columns, budget) {
                    return Some(Next::Whole(here, cell, next));
                }
                stale_header(page, here, end).then_some(Next::Header(here + 4))
            });

            match found {
                Some(Next::Whole(from, cell, next)) => {
                    out.push((
                        page.get(from..next),
                        Carved {
                            rowid: Some(cell.rowid),
                            values: cell.values,
                        },
                    ));
                    at = next;
                }
                Some(Next::Header(next)) => {
                    at = next;
                    clobbered = true;
                }
                None => {
                    self.carve_cells(page, at, end, columns, budget, out);
                    return;
                }
            }
        }
    }

    /// Finds whole cells anywhere in a run of free space. Zero is not a payload length,
    /// so an empty stretch costs one comparison a byte.
    fn carve_cells<'p>(
        &self,
        page: &'p [u8],
        start: usize,
        end: usize,
        columns: usize,
        budget: &mut Budget,
        out: &mut Vec<(Option<&'p [u8]>, Carved)>,
    ) {
        let mut at = start;
        while at < end && budget.carve > 0 {
            if page.get(at).is_none_or(|&byte| byte == 0) {
                at += 1;
                continue;
            }
            budget.carve -= 1;

            match self.intact_cell(page, at, end, columns, budget) {
                Some((cell, next)) => {
                    out.push((
                        page.get(at..next),
                        Carved {
                            rowid: Some(cell.rowid),
                            values: cell.values,
                        },
                    ));
                    at = next;
                }
                None => at += 1,
            }
        }
    }

    /// Carves a record out of freed space, by finding the point where the serial types
    /// and their values account for the space exactly or stop at something that plainly
    /// comes next.
    fn carve_record(
        &self,
        page: &[u8],
        start: usize,
        end: usize,
        columns: usize,
        budget: &mut Budget,
    ) -> Option<(Vec<Value>, usize)> {
        let remaining = end.checked_sub(start)?;
        let text = Text {
            encoding: self.encoding,
            cap: CELL_TEXT_CAP,
        };

        // A long rowid or payload length leaves the record's own header in one piece,
        // possibly behind a byte or two of the rowid, and when one is there it checks
        // itself.
        for skip in 0..=5usize.min(remaining) {
            let at = start + skip;
            let Some((header_len, used)) = varint(page, at) else {
                continue;
            };
            let Some(header_len) = usize::try_from(header_len).ok().filter(|&h| h > used) else {
                continue;
            };
            if at.saturating_add(header_len) > end {
                continue;
            }

            let mut count = 0usize;
            let mut claimed = header_len;
            let mut cursor = at + used;
            let mut sound = true;
            while cursor < at + header_len {
                count += 1;
                budget.carve = budget.carve.saturating_sub(1);
                let parsed = varint(page, cursor).and_then(|(serial, width)| {
                    Some((serial_len(serial)?, width))
                });
                let Some((length, width)) = parsed.filter(|_| count <= columns + 1) else {
                    sound = false;
                    break;
                };
                claimed = claimed.saturating_add(length);
                cursor += width;
            }
            if !sound || cursor != at + header_len || at.saturating_add(claimed) > end {
                continue;
            }

            let next = at + claimed;
            if next != end && !self.followed_properly(page, next, end) {
                continue;
            }
            let Some(payload) = page.get(at..next) else {
                continue;
            };
            let Some(values) = decode_record(payload, true, text, &mut budget.values) else {
                continue;
            };
            if plausible(&values, columns) {
                return Some((values, next));
            }
        }

        // Otherwise the header length went too, and the types start straight away.
        let mut types = Vec::new();
        let mut type_bytes = 0usize;
        let mut value_bytes = 0usize;
        let mut at = start;

        while type_bytes.saturating_add(value_bytes) < remaining && types.len() <= columns + 2 {
            budget.carve = budget.carve.saturating_sub(1);
            let (serial, used) = varint(page, at)?;
            let vlen = serial_len(serial)?;
            types.push(serial);
            type_bytes += used;
            value_bytes = value_bytes.saturating_add(vlen);
            at += used;

            let total = type_bytes.saturating_add(value_bytes);
            if total > remaining {
                return None;
            }

            let next = start + total;
            let fits = types.len() + 1 >= columns && types.len() <= columns + 1;
            if total != remaining && !(fits && self.followed_properly(page, next, end)) {
                continue;
            }

            // The types end here and the body begins. Decode the values it names.
            let mut values = Vec::new();
            let mut body = start + type_bytes;
            for &serial in &types {
                budget.values = budget.values.checked_sub(1)?;
                let (value, size) = decode_value(serial, page.get(body..)?, text, false)?;
                budget.values = budget.values.saturating_sub(value.text.len() / BYTES_PER_VALUE);
                values.push(value);
                body += size;
            }

            // A row this table could have held: as many columns as it has, give or
            // take the one the freeblock header ate, and not a run of nothing.
            return plausible(&values, columns).then_some((values, next));
        }

        None
    }

    /// Whether what sits at `at` is something a freed cell could be followed by.
    fn followed_properly(&self, page: &[u8], at: usize, end: usize) -> bool {
        (0..=3).any(|skip| {
            let here = at + skip;
            here == end
                || (here < end
                    && (stale_header(page, here, end) || self.cell_shaped(page, here, end)))
        })
    }

    /// The lengths of a whole cell adding up, without decoding it.
    fn cell_shaped(&self, page: &[u8], at: usize, end: usize) -> bool {
        let Some((payload_len, n1)) = varint(page, at) else {
            return false;
        };
        let Some((_, n2)) = varint(page, at + n1) else {
            return false;
        };
        let Some(payload_len) = usize::try_from(payload_len).ok().filter(|&length| length > 0) else {
            return false;
        };

        let local = self.local_size(payload_len);
        let spill = if payload_len > local { 4 } else { 0 };
        let body_at = at + n1 + n2;
        if body_at.saturating_add(local).saturating_add(spill) > end {
            return false;
        }

        let Some((header_len, _)) = varint(page, body_at) else {
            return false;
        };
        usize::try_from(header_len).is_ok_and(|header| header >= 2 && header <= local)
    }
}

/// What a freed record was found to hold.
struct Carved {
    /// Known only when the cell survived whole, since a freeblock's header is written
    /// over the rowid.
    rowid: Option<i64>,
    values: Vec<Value>,
}

/// What comes next inside a freeblock.
enum Next {
    Whole(usize, Cell, usize),
    Header(usize),
}

/// A row this table could have held: as many columns as it has, give or take the one
/// a freeblock header ate, and not a run of nothing.
fn plausible(values: &[Value], columns: usize) -> bool {
    values.len() + 1 >= columns
        && values.len() <= columns + 1
        && values.iter().any(|value| value.kind != "null")
}

/// The header an earlier freeblock left behind before it was merged into this one: a
/// next pointer that runs forward or ends the chain, and a size that fits what is left.
fn stale_header(page: &[u8], at: usize, end: usize) -> bool {
    let (Some(next), Some(size)) = (be_u16(page, at), be_u16(page, at + 2)) else {
        return false;
    };
    let (next, size) = (next as usize, size as usize);
    (next == 0 || (next > at && next < page.len())) && size >= 4 && at + size <= end
}

/// The cell offsets a leaf page lists as live, in the order it lists them.
fn live_cell_offsets(page: &[u8], head: usize) -> Vec<usize> {
    let Some(cells) = be_u16(page, head + 3) else {
        return Vec::new();
    };
    let interior = matches!(page.get(head), Some(0x05 | 0x02));
    let array = head + if interior { 12 } else { 8 };
    (0..cells as usize)
        .filter_map(|i| be_u16(page, array + i * 2).map(|o| o as usize))
        .collect()
}

/// The text of each definition between a `CREATE TABLE`'s outer parentheses.
fn definitions(sql: &str) -> Vec<&str> {
    let Some(open) = sql.find('(') else {
        return Vec::new();
    };
    // Searched for after the open, or `)(` is a slice that ends before it starts.
    let tail = &sql[open + 1..];
    let inner = &tail[..tail.rfind(')').unwrap_or(tail.len())];

    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    for (i, &b) in inner.as_bytes().iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
                out.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&inner[start..]);
    out
}

/// The column a definition names and what is said about it, or nothing when it is a
/// table constraint.
fn column_of(definition: &str) -> Option<(String, &str)> {
    let trimmed = definition.trim();
    // A quoted name can hold spaces, so it runs to its closing quote rather than
    // to the first space the way a bare name does.
    let (name, rest) = match trimmed.chars().next() {
        Some(quote @ ('"' | '`' | '\'')) => trimmed[1..].split_once(quote)?,
        Some('[') => trimmed[1..].split_once(']')?,
        _ => trimmed
            .split_once(char::is_whitespace)
            .unwrap_or((trimmed, "")),
    };
    // Table constraints, not columns.
    let upper = name.to_ascii_uppercase();
    if name.is_empty()
        || matches!(
            upper.as_str(),
            "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN" | "CONSTRAINT"
        )
    {
        return None;
    }
    Some((name.to_string(), rest))
}

/// The column names, pulled from the `CREATE TABLE` text between its first
/// parentheses. Best effort: enough to head the columns, not a SQL parser.
fn columns_from_sql(sql: &str) -> Vec<String> {
    definitions(sql)
        .into_iter()
        .filter_map(column_of)
        .map(|(name, _)| name)
        .collect()
}

/// Which column, if any, is the rowid under another name.
///
/// A column declared exactly `INTEGER PRIMARY KEY` is not stored in the record at all.
/// The record holds a NULL there and the value is the cell's rowid, so reading only the
/// record reports a NULL for the one column that can never be one. `INT PRIMARY KEY`
/// is an ordinary column, and `DESC` is a historical quirk that makes it one too.
fn rowid_alias(sql: &str) -> Option<usize> {
    let parts = definitions(sql);
    let words = |text: &str| {
        text.split_whitespace()
            .map(str::to_ascii_uppercase)
            .collect::<Vec<_>>()
    };
    let columns: Vec<(String, Vec<String>)> = parts
        .iter()
        .filter_map(|definition| column_of(definition))
        .map(|(name, rest)| (name, words(rest)))
        .collect();
    let is_integer = |said: &[String]| said.first().is_some_and(|word| word == "INTEGER");

    if let Some(at) = columns.iter().position(|(_, said)| {
        is_integer(said)
            && said.windows(2).any(|pair| pair[0] == "PRIMARY" && pair[1] == "KEY")
            && !said.iter().any(|word| word == "DESC")
    }) {
        return Some(at);
    }

    // `PRIMARY KEY (id)` at the end says the same thing of the single column it names.
    let constraint = parts.iter().find(|definition| {
        let upper = definition.to_ascii_uppercase();
        column_of(definition).is_none() && upper.contains("PRIMARY") && upper.contains("KEY")
    })?;
    let open = constraint.find('(')?;
    let close = open + constraint[open..].find(')')?;
    let keyed = constraint[open + 1..close].trim();
    if keyed.contains(',') {
        return None;
    }
    let keyed = keyed.trim_matches(|c| matches!(c, '"' | '`' | '\'' | '[' | ']'));

    columns
        .iter()
        .position(|(name, said)| name.eq_ignore_ascii_case(keyed) && is_integer(said))
}

/// One row of `sqlite_master`, the schema table rooted at page one.
struct SchemaRow {
    name: String,
    rootpage: u32,
    sql: String,
}

/// The tables `sqlite_master` lists, as many as a reading carries, and how many it
/// lists altogether.
fn read_schema(db: &Db, budget: &mut Budget) -> (Vec<SchemaRow>, usize) {
    let mut rows = Vec::new();
    let mut table_count = 0usize;
    let mut seen = HashSet::new();
    let mut pages = MAX_PAGES_WALKED.min(budget.pages);
    let walked = pages;
    let short = Text {
        encoding: db.encoding,
        cap: CELL_TEXT_CAP,
    };
    let long = Text {
        encoding: db.encoding,
        cap: MAX_SQL_BYTES,
    };

    db.walk_leaves(1, 0, &mut seen, &mut pages, &mut |page, head| {
        for off in live_cell_offsets(page, head) {
            let Some(cell) = db.read_cell(page, off, short, budget) else {
                continue;
            };
            // sqlite_master is (type, name, tbl_name, rootpage, sql).
            if cell.values.first().is_none_or(|kind| kind.text != "table") {
                continue;
            }
            table_count += 1;
            if rows.len() >= MAX_TABLES {
                continue;
            }

            // Read again at full length now it is known to be kept. Column names come
            // out of this text, and cut off they miss most of a wide table.
            let Some(cell) = db.read_cell(page, off, long, budget) else {
                continue;
            };
            let text = |i: usize| {
                cell.values
                    .get(i)
                    .map(|v| v.text.clone())
                    .unwrap_or_default()
            };
            let rootpage = cell
                .values
                .get(3)
                .and_then(|v| v.text.parse::<u32>().ok())
                .unwrap_or(0);
            rows.push(SchemaRow {
                name: text(1),
                rootpage,
                sql: text(4),
            });
        }
    });
    budget.pages -= walked - pages;

    (rows, table_count)
}

/// Flags found in a table's live cells.
#[derive(Default)]
struct CellFlags {
    seen: HashSet<String>,
    list: Vec<String>,
    truncated: bool,
}

/// Searches each text and blob in a record for flags, whole and one at a time, since the
/// columns of a row sit side by side and a flag with a word in front of it stops looking
/// like one.
fn record_flags(
    payload: &[u8],
    encoding: Encoding,
    tags: &[String],
    budget: &mut Budget,
    into: &mut CellFlags,
) {
    let Some((header_len, mut at)) = varint(payload, 0) else {
        return;
    };
    let Ok(header_len) = usize::try_from(header_len) else {
        return;
    };

    let mut body = header_len;
    while at < header_len && body < payload.len() {
        let Some((serial, used)) = varint(payload, at) else {
            return;
        };
        at += used;
        let Some(size) = serial_len(serial) else {
            return;
        };

        if serial >= 12 && size > 0 {
            let value = &payload[body..body.saturating_add(size).min(payload.len())];
            if budget.scanned < value.len() {
                into.truncated = true;
                return;
            }
            budget.scanned -= value.len();

            let scan = if serial % 2 == 1 && encoding != Encoding::Utf8 {
                bytes::scan_flags(encoding.decode(value).as_bytes(), tags, true)
            } else {
                bytes::scan_flags(value, tags, true)
            };
            into.truncated |= scan.truncated;

            for flag in scan.found {
                if into.list.len() >= bytes::MAX_FLAGS {
                    into.truncated = true;
                    return;
                }
                if into.seen.insert(flag.text.clone()) {
                    into.list.push(flag.text);
                }
            }
        }
        body = body.saturating_add(size);
    }
}

/// One table's rows, walked out of its b-tree.
fn read_table(db: &Db, row: SchemaRow, tags: &[String], budget: &mut Budget) -> (Table, bool) {
    let columns = columns_from_sql(&row.sql);
    let alias = rowid_alias(&row.sql);
    let width = columns.len().max(1);
    let text = Text {
        encoding: db.encoding,
        cap: CELL_TEXT_CAP,
    };

    let mut rows = Vec::new();
    let mut deleted = Vec::new();
    let mut row_count = 0;
    let mut flags = CellFlags::default();

    if row.rootpage != 0 {
        let mut seen = HashSet::new();
        let mut pages = MAX_PAGES_WALKED.min(budget.pages);
        let walked = pages;
        db.walk_leaves(row.rootpage, 0, &mut seen, &mut pages, &mut |page, head| {
            // Every cell the page lists is a row, whatever else about it can be read.
            // Past the cap nothing is decoded, so counting a large table stays cheap, except
            // what a scan of the raw file cannot read: a record in pieces, and UTF-16BE text,
            // which it reads a byte off, so a closing brace pairs with whatever follows it.
            let listed = be_u16(page, head + 3).unwrap_or(0) as usize;
            row_count += listed;
            let raw_scan_misses = db.encoding == Encoding::Utf16Be;

            for off in live_cell_offsets(page, head) {
                let shown = rows.len() < MAX_ROWS;
                let needs_reading = db.spills(page, off) || raw_scan_misses;
                if !shown && !needs_reading {
                    continue;
                }

                let Some((rowid, payload, whole)) = db.record(page, off, budget) else {
                    flags.truncated |= needs_reading;
                    continue;
                };
                record_flags(&payload, db.encoding, tags, budget, &mut flags);
                flags.truncated |= !whole;
                if !shown {
                    continue;
                }

                let Some(mut values) = decode_record(&payload, whole, text, &mut budget.values)
                else {
                    continue;
                };
                if let Some(value) = alias.and_then(|at| values.get_mut(at))
                    && value.kind == "null"
                {
                    *value = Value {
                        kind: "integer",
                        text: rowid.to_string(),
                    };
                }
                rows.push(Row { values });
            }

            if deleted.len() < MAX_DELETED {
                db.recover_deleted(page, head, width, alias, &mut deleted, budget);
            }
        });
        budget.pages -= walked - pages;
    }

    let table = Table {
        name: row.name,
        columns,
        sql: row.sql,
        rows,
        row_count,
        deleted,
        flags: flags.list,
    };
    (table, flags.truncated)
}

pub fn read(data: &[u8]) -> Option<Database> {
    read_for_tags(data, &[])
}

/// [`read`], for a caller that has said which flag tags it is looking for.
pub fn read_for_tags(data: &[u8], tags: &[String]) -> Option<Database> {
    if !data.starts_with(HEADER) || data.len() < 100 {
        return None;
    }

    let page_size = match be_u16(data, 16)? {
        1 => 65536,
        n => n as usize,
    };
    if page_size < 512 || !page_size.is_power_of_two() {
        return None;
    }

    // The reserved bytes at the end of every page, usually zero, are not part of
    // the usable content and a cell never runs into them.
    let reserved = *data.get(20)? as usize;
    let usable = page_size.saturating_sub(reserved);

    let page_count = be_u32(data, 28)
        .map(|n| n as usize)
        .filter(|&n| {
            n > 0
                && n.checked_mul(page_size)
                    .is_some_and(|bytes| bytes <= data.len().saturating_add(page_size))
        })
        .unwrap_or(data.len() / page_size);
    let freelist_pages = be_u32(data, 36)? as usize;
    let encoding = match be_u32(data, 56)? {
        2 => Encoding::Utf16Le,
        3 => Encoding::Utf16Be,
        _ => Encoding::Utf8,
    };

    let db = Db {
        data,
        page_size,
        usable,
        encoding,
    };
    let mut budget = Budget::new();

    let (schema, table_count) = read_schema(&db, &mut budget);
    let mut flags_truncated = false;
    let tables = schema
        .into_iter()
        .map(|row| {
            let (table, truncated) = read_table(&db, row, tags, &mut budget);
            flags_truncated |= truncated;
            table
        })
        .collect();

    Some(Database {
        page_size,
        page_count,
        encoding: encoding.label(),
        freelist_pages,
        tables, table_count, flags_truncated, }) }

pub fn json(data: &[u8]) -> String {
    json_for_tags(data, &[])
}

/// [`json`], for a caller that has said which flag tags it is looking for.
pub fn json_for_tags(data: &[u8], tags: &[String]) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    let Some(db) = read_for_tags(data, tags) else {
        return "null".to_string();
    };

    let mut out = String::from("{");
    push_number(&mut out, "pageSize", db.page_size);
    out.push(',');
    push_number(&mut out, "pageCount", db.page_count);
    out.push(',');
    push_field(&mut out, "encoding", db.encoding);
    out.push(',');
    push_number(&mut out, "freelistPages", db.freelist_pages);
    out.push(',');
    push_number(&mut out, "tableCount", db.table_count);
    out.push(',');
    push_bool(&mut out, "flagsTruncated", db.flags_truncated);
    out.push(',');

    push_string(&mut out, "tables");
    out.push_str(":[");
    for (i, table) in db.tables.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "name", &table.name);
        out.push(',');
        push_field(&mut out, "sql", &table.sql);
        out.push(',');
        push_number(&mut out, "rowCount", table.row_count);
        out.push(',');

        push_string(&mut out, "columns");
        out.push_str(":[");
        for (j, column) in table.columns.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            push_string(&mut out, column);
        }
        out.push_str("],");

        write_rows(&mut out, "rows", &table.rows);
        out.push(',');
        write_rows(&mut out, "deleted", &table.deleted);
        out.push(',');
        push_string(&mut out, "flags");
        out.push_str(":[");
        for (j, flag) in table.flags.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            push_string(&mut out, flag);
        }
        out.push(']');
        out.push('}');
    }
    out.push_str("]}");
    out
}

fn write_rows(out: &mut String, key: &str, rows: &[Row]) {
    use crate::json::{push_field, push_string};
    push_string(out, key);
    out.push_str(":[");
    for (i, row) in rows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('[');
        for (j, value) in row.values.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push('{');
            push_field(out, "kind", value.kind);
            out.push(',');
            push_field(out, "text", &value.text);
            out.push('}');
        }
        out.push(']');
    }
    out.push(']');
}

#[cfg(test)]
mod tests;
