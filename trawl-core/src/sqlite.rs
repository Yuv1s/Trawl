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

const HEADER: &[u8] = b"SQLite format 3\0";

/// How many tables, rows, and recovered rows a reading will carry. A real
/// database has more than a person reads at once, and the browser should not be
/// asked to hold all of it, so each is capped and the true count reported apart.
const MAX_TABLES: usize = 64;
const MAX_ROWS: usize = 200;
const MAX_DELETED: usize = 200;
const MAX_PAGES_WALKED: usize = 4096;

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

/// A cell decoded to its rowid and record values, and where it ended, so the
/// same decoder serves the live walk and the free-space sweep.
struct Cell {
    values: Vec<Value>,
}

/// Reads a table-leaf cell at `at`: a payload length, a rowid, then the record.
/// Overflow is not chased; a payload longer than what remains on the page is
/// read as far as the page holds, which is enough to show and to scan.
fn read_cell(page: &[u8], at: usize, usable: usize) -> Option<(Cell, usize)> {
    let (payload_len, n1) = varint(page, at)?;
    let (_rowid, n2) = varint(page, at + n1)?;
    let body_at = at + n1 + n2;
    let payload_len = payload_len.max(0) as usize;

    let available = usable.saturating_sub(body_at).min(payload_len);
    let payload = page.get(body_at..body_at + available)?;
    let values = decode_record(payload)?;
    Some((Cell { values }, body_at + available))
}

/// Decodes a record: a header of serial types, then the values they describe.
fn decode_record(payload: &[u8]) -> Option<Vec<Value>> {
    let (header_len, n) = varint(payload, 0)?;
    let header_len = header_len.max(0) as usize;
    if header_len == 0 || header_len > payload.len() {
        return None;
    }

    let mut types = Vec::new();
    let mut at = n;
    while at < header_len {
        let (serial, used) = varint(payload, at)?;
        types.push(serial);
        at += used;
    }

    let mut values = Vec::new();
    let mut body = header_len;
    for serial in types {
        let (value, size) = decode_value(serial, payload.get(body..)?)?;
        values.push(value);
        body += size;
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
        n if n >= 12 => Some(((n - if n % 2 == 0 { 12 } else { 13 }) / 2) as usize),
        _ => None,
    }
}

/// One serial type applied to the bytes that follow it.
fn decode_value(serial: i64, rest: &[u8]) -> Option<(Value, usize)> {
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
            let len = ((n - if n % 2 == 0 { 12 } else { 13 }) / 2) as usize;
            let bytes = rest.get(..len)?;
            if n % 2 == 0 {
                Some((
                    Value {
                        kind: "blob",
                        text: blob_preview(bytes),
                    },
                    len,
                ))
            } else {
                Some((
                    Value {
                        kind: "text",
                        text: text_preview(bytes),
                    },
                    len,
                ))
            }
        }
        _ => None,
    }
}

const CELL_TEXT_CAP: usize = 240;

fn text_preview(bytes: &[u8]) -> String {
    let shown = &bytes[..bytes.len().min(CELL_TEXT_CAP)];
    let mut out = String::from_utf8_lossy(shown).into_owned();
    if bytes.len() > CELL_TEXT_CAP {
        out.push('…');
    }
    out
}

fn blob_preview(bytes: &[u8]) -> String {
    let shown = &bytes[..bytes.len().min(24)];
    let hex: String = shown.iter().map(|b| format!("{b:02x}")).collect();
    if bytes.len() > 24 {
        format!("{hex}… ({} bytes)", bytes.len())
    } else {
        format!("{hex} ({} bytes)", bytes.len())
    }
}

/// The bytes of a page, 1-indexed the way SQLite counts them.
fn page_bytes(data: &[u8], page: u32, page_size: usize) -> Option<&[u8]> {
    if page == 0 {
        return None;
    }
    let start = (page as usize - 1) * page_size;
    data.get(start..start + page_size)
}

/// Where a page's b-tree content begins: after the 100-byte file header on page
/// one, at the very start on every other.
fn header_offset(page: u32) -> usize {
    if page == 1 { 100 } else { 0 }
}

/// Walks a table's b-tree, calling `visit` on every leaf page it reaches. The
/// walk is bounded and refuses to revisit a page, so a database whose pointers
/// form a loop cannot spin it.
fn walk_leaves(
    data: &[u8],
    page: u32,
    page_size: usize,
    seen: &mut Vec<u32>,
    budget: &mut usize,
    visit: &mut impl FnMut(&[u8], usize),
) {
    if *budget == 0 || seen.contains(&page) {
        return;
    }
    seen.push(page);
    *budget -= 1;

    let Some(bytes) = page_bytes(data, page, page_size) else {
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
                    walk_leaves(data, child, page_size, seen, budget, visit);
                }
            }
            if let Some(right) = be_u32(bytes, head + 8) {
                walk_leaves(data, right, page_size, seen, budget, visit);
            }
        }
        _ => {}
    }
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

/// Reads the live rows out of a leaf page.
fn leaf_rows(page: &[u8], head: usize, usable: usize, out: &mut Vec<Row>, total: &mut usize) {
    for off in live_cell_offsets(page, head) {
        if let Some((cell, _)) = read_cell(page, off, usable) {
            *total += 1;
            if out.len() < MAX_ROWS {
                out.push(Row {
                    values: cell.values,
                });
            }
        }
    }
}

/// Recovers deleted rows from a leaf page's freeblock chain.
///
/// Deleting a row turns its cell into a freeblock: the block's own four-byte
/// header, a next pointer and a size, is written over the cell's first four
/// bytes, and the rest of the record is left untouched. So the leading bytes,
/// the payload length, the rowid and usually the record's header length and
/// first column type, are gone, but the surviving column types and every value
/// are still there.
///
/// The freed cell had no slack, so its serial types and the values they
/// describe exactly filled it. That is the handle: read types until the types
/// and their values account for the whole freeblock, and the boundary between
/// header and body falls out. What is recovered is the row minus whatever
/// leading column the header clobbered, which for a rowid-alias id is nothing
/// of value.
fn recover_deleted(
    page: &[u8],
    head: usize,
    columns: usize,
    out: &mut Vec<Row>,
    total: &mut usize,
) {
    let mut freeblock = be_u16(page, head + 1).unwrap_or(0) as usize;
    let mut guard = 0;

    while freeblock != 0 && guard < 4096 {
        guard += 1;
        let (Some(next), Some(size)) = (be_u16(page, freeblock), be_u16(page, freeblock + 2))
        else {
            break;
        };
        let (next, size) = (next as usize, size as usize);

        if size >= 6
            && freeblock + size <= page.len()
            && let Some(values) = carve_record(page, freeblock + 4, size - 4, columns)
        {
            *total += 1;
            if out.len() < MAX_DELETED {
                out.push(Row { values });
            }
        }

        // The chain runs strictly forward through the page; anything else is a
        // loop, and a loop is a doctored file, not a database to trust.
        if next <= freeblock {
            break;
        }
        freeblock = next;
    }
}

/// Carves a record out of freed space of a known length, by finding the point
/// where the serial types and their values exactly fill it.
fn carve_record(page: &[u8], start: usize, remaining: usize, columns: usize) -> Option<Vec<Value>> {
    let mut types = Vec::new();
    let mut type_bytes = 0usize;
    let mut value_bytes = 0usize;
    let mut at = start;

    while type_bytes + value_bytes < remaining && types.len() <= columns + 2 {
        let (serial, used) = varint(page, at)?;
        let vlen = serial_len(serial)?;
        types.push(serial);
        type_bytes += used;
        value_bytes += vlen;
        at += used;

        if type_bytes + value_bytes != remaining {
            continue;
        }

        // The types end here and the body begins. Decode the values it names.
        let mut values = Vec::new();
        let mut body = start + type_bytes;
        for &serial in &types {
            let (value, size) = decode_value(serial, page.get(body..)?)?;
            values.push(value);
            body += size;
        }

        // A row this table could have held: as many columns as it has, give or
        // take the one the freeblock header ate, and not a run of nothing.
        let plausible = values.len() + 1 >= columns
            && values.len() <= columns + 1
            && values.iter().any(|v| v.kind != "null");
        return plausible.then_some(values);
    }

    None
}

/// The column names, pulled from the `CREATE TABLE` text between its first
/// parentheses. Best effort: enough to head the columns, not a SQL parser.
fn columns_from_sql(sql: &str) -> Vec<String> {
    let Some(open) = sql.find('(') else {
        return Vec::new();
    };
    let inner = &sql[open + 1..sql.rfind(')').unwrap_or(sql.len())];

    let mut columns = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let bytes = inner.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
                push_column(&inner[start..i], &mut columns);
                start = i + 1;
            }
            _ => {}
        }
    }
    push_column(&inner[start..], &mut columns);
    columns
}

fn push_column(definition: &str, out: &mut Vec<String>) {
    let trimmed = definition.trim();
    // A quoted name can hold spaces, so it runs to its closing quote rather than
    // to the first space the way a bare name does.
    let name = match trimmed.chars().next() {
        Some(quote @ ('"' | '`' | '\'')) => {
            trimmed[1..].split(quote).next().unwrap_or("").to_string()
        }
        Some('[') => trimmed[1..].split(']').next().unwrap_or("").to_string(),
        _ => trimmed.split_whitespace().next().unwrap_or("").to_string(),
    };
    let name = name.as_str();
    // Table constraints, not columns.
    let upper = name.to_ascii_uppercase();
    if name.is_empty()
        || matches!(
            upper.as_str(),
            "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN" | "CONSTRAINT"
        )
    {
        return;
    }
    out.push(name.to_string());
}

/// One row of `sqlite_master`, the schema table rooted at page one.
struct SchemaRow {
    kind: String,
    name: String,
    rootpage: u32,
    sql: String,
}

fn read_schema(data: &[u8], page_size: usize, usable: usize) -> Vec<SchemaRow> {
    let mut rows = Vec::new();
    let mut seen = Vec::new();
    let mut budget = MAX_PAGES_WALKED;

    walk_leaves(
        data,
        1,
        page_size,
        &mut seen,
        &mut budget,
        &mut |page, head| {
            for off in live_cell_offsets(page, head) {
                let Some((cell, _)) = read_cell(page, off, usable) else {
                    continue;
                };
                // sqlite_master is (type, name, tbl_name, rootpage, sql).
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
                    kind: text(0),
                    name: text(1),
                    rootpage,
                    sql: text(4),
                });
            }
        },
    );

    rows
}

pub fn read(data: &[u8]) -> Option<Database> {
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
        .filter(|&n| n > 0 && n * page_size <= data.len() + page_size)
        .unwrap_or(data.len() / page_size);
    let freelist_pages = be_u32(data, 36)? as usize;
    let encoding = match be_u32(data, 56)? {
        2 => "UTF-16LE",
        3 => "UTF-16BE",
        _ => "UTF-8",
    };

    let schema = read_schema(data, page_size, usable);
    let table_count = schema.iter().filter(|r| r.kind == "table").count();

    let mut tables = Vec::new();
    for row in schema.iter().filter(|r| r.kind == "table") {
        if tables.len() >= MAX_TABLES {
            break;
        }
        let columns = columns_from_sql(&row.sql);
        let mut rows = Vec::new();
        let mut deleted = Vec::new();
        let mut row_count = 0;
        let mut deleted_count = 0;

        if row.rootpage != 0 {
            let mut seen = Vec::new();
            let mut budget = MAX_PAGES_WALKED;
            walk_leaves(
                data,
                row.rootpage,
                page_size,
                &mut seen,
                &mut budget,
                &mut |page, head| {
                    leaf_rows(page, head, usable, &mut rows, &mut row_count);
                    recover_deleted(
                        page,
                        head,
                        columns.len().max(1),
                        &mut deleted,
                        &mut deleted_count,
                    );
                },
            );
        }

        tables.push(Table {
            name: row.name.clone(),
            columns,
            sql: row.sql.clone(),
            rows,
            row_count,
            deleted,
        });
    }

    Some(Database {
        page_size,
        page_count,
        encoding,
        freelist_pages,
        tables,
        table_count,
    })
}

pub fn json(data: &[u8]) -> String {
    use crate::json::{push_field, push_number, push_string};

    let Some(db) = read(data) else {
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
