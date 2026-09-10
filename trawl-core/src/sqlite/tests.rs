use super::*;

/// The values a built row can hold, before they are written to a record.
enum Cell {
    Null,
    Int(i64),
    Text(&'static str),
}

/// SQLite's varint encoder, for building records the reader will decode.
fn varint_of(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let mut groups = Vec::new();
    let mut v = value;
    while v > 0 {
        groups.push((v & 0x7f) as u8);
        v >>= 7;
    }
    groups.reverse();
    let last = groups.len() - 1;
    for (i, g) in groups.iter_mut().enumerate() {
        if i != last {
            *g |= 0x80;
        }
    }
    groups
}

/// Builds a record: a header of serial types, then the values, the way a table
/// b-tree cell carries a row.
fn record(cells: &[Cell]) -> Vec<u8> {
    let mut types = Vec::new();
    let mut body = Vec::new();
    for cell in cells {
        match cell {
            Cell::Null => types.extend_from_slice(&varint_of(0)),
            Cell::Int(n) => {
                types.extend_from_slice(&varint_of(1));
                body.push(*n as u8);
            }
            Cell::Text(s) => {
                // A text serial type is a varint, so a long string spans more
                // than one byte, exactly the case a naive one-byte write breaks.
                types.extend_from_slice(&varint_of((s.len() * 2 + 13) as u64));
                body.extend_from_slice(s.as_bytes());
            }
        }
    }
    // The header length counts itself; these headers stay under 128, so its own
    // varint is one byte.
    let header_len = 1 + types.len();
    let mut out = varint_of(header_len as u64);
    out.extend_from_slice(&types);
    out.extend_from_slice(&body);
    out
}

/// A table-leaf cell: payload length, rowid, then the record.
fn leaf_cell(rowid: u64, cells: &[Cell]) -> Vec<u8> {
    let rec = record(cells);
    let mut out = varint_of(rec.len() as u64);
    out.extend_from_slice(&varint_of(rowid));
    out.extend_from_slice(&rec);
    out
}

const PAGE: usize = 4096;

/// A leaf b-tree page from a set of live cells, packed at the end the way
/// SQLite packs them, with an optional planted freeblock carrying a deleted
/// row. `page_one` leaves room for the 100-byte file header.
fn leaf_page(cells: Vec<Vec<u8>>, deleted: Option<Vec<Cell>>, page_one: bool) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    let head = if page_one { 100 } else { 0 };

    // Cells are laid from the end of the page towards the front.
    let mut content = PAGE;
    let mut offsets = Vec::new();
    for cell in &cells {
        content -= cell.len();
        page[content..content + cell.len()].copy_from_slice(cell);
        offsets.push(content);
    }

    // A freeblock: a freed cell whose first four bytes are the block's own next
    // pointer (zero, last in the chain) and size, the rest the record minus the
    // bytes that overwrote it.
    let mut first_freeblock = 0usize;
    if let Some(cells) = deleted {
        let rec = record(&cells);
        // The freed cell was payload-len(1) + rowid(1) + record; the freeblock
        // header eats the first four of those, so two record bytes go too.
        let freed_size = 2 + rec.len();
        content -= freed_size;
        first_freeblock = content;
        page[content] = 0; // next pointer high
        page[content + 1] = 0; // next pointer low
        page[content + 2] = (freed_size >> 8) as u8;
        page[content + 3] = freed_size as u8;
        // After the 4-byte header, the surviving tail of the record: everything
        // past the two bytes the header clobbered beyond the framing.
        let survived = &rec[2..];
        page[content + 4..content + 4 + survived.len()].copy_from_slice(survived);
    }

    page[head] = 0x0d; // leaf table b-tree
    page[head + 1] = (first_freeblock >> 8) as u8;
    page[head + 2] = first_freeblock as u8;
    page[head + 3] = (cells.len() >> 8) as u8;
    page[head + 4] = cells.len() as u8;
    page[head + 5] = (content >> 8) as u8;
    page[head + 6] = content as u8;

    let array = head + 8;
    for (i, off) in offsets.iter().enumerate() {
        page[array + i * 2] = (off >> 8) as u8;
        page[array + i * 2 + 1] = *off as u8;
    }

    page
}

/// A whole database: a file header, page one holding one table's schema row,
/// and page two holding that table's rows.
fn database(sql: &'static str, rows: Vec<Vec<Cell>>, deleted: Option<Vec<Cell>>) -> Vec<u8> {
    let schema = leaf_page(
        vec![leaf_cell(
            1,
            &[
                Cell::Text("table"),
                Cell::Text("users"),
                Cell::Text("users"),
                Cell::Int(2),
                Cell::Text(sql),
            ],
        )],
        None,
        true,
    );

    let data_cells: Vec<Vec<u8>> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| leaf_cell(i as u64 + 1, r))
        .collect();
    let data = leaf_page(data_cells, deleted, false);

    let mut file = Vec::new();
    file.extend_from_slice(HEADER);
    file.extend_from_slice(&(PAGE as u16).to_be_bytes()); // 16: page size
    file.extend_from_slice(&[1, 1, 0]); // write/read version, reserved
    file.extend_from_slice(&[64, 32, 32]); // payload fractions, standard
    file.extend_from_slice(&[0; 4]); // 24: change counter
    file.extend_from_slice(&2u32.to_be_bytes()); // 28: page count
    file.extend_from_slice(&[0; 4]); // 32: first freelist trunk
    file.extend_from_slice(&[0; 4]); // 36: freelist page count
    file.resize(56, 0);
    file.extend_from_slice(&1u32.to_be_bytes()); // 56: text encoding, UTF-8
    file.resize(100, 0);

    file.extend_from_slice(&schema[100..]); // page 1 body follows the header
    file.extend_from_slice(&data); // page 2
    file
}

#[test]
fn declines_a_file_that_is_not_a_database() {
    assert!(read(b"not a database").is_none());
    assert!(read(&[0u8; 200]).is_none());
    // Right magic, but a page size that is not a power of two.
    let mut bad = HEADER.to_vec();
    bad.extend_from_slice(&1000u16.to_be_bytes());
    bad.resize(4096, 0);
    assert!(read(&bad).is_none());
}

#[test]
fn reads_the_header() {
    let db = read(&database("CREATE TABLE users (id, name)", vec![], None)).unwrap();
    assert_eq!(db.page_size, 4096);
    assert_eq!(db.encoding, "UTF-8");
    assert_eq!(db.table_count, 1);
}

#[test]
fn reads_a_table_its_columns_and_its_rows() {
    let file = database(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)",
        vec![
            vec![Cell::Null, Cell::Text("alice"), Cell::Text("admin")],
            vec![Cell::Null, Cell::Text("bob"), Cell::Text("user")],
        ],
        None,
    );
    let db = read(&file).unwrap();
    let users = &db.tables[0];

    assert_eq!(users.name, "users");
    assert_eq!(users.columns, vec!["id", "name", "role"]);
    assert_eq!(users.row_count, 2);
    assert_eq!(users.rows[0].values[1].text, "alice");
    assert_eq!(users.rows[1].values[2].text, "user");
}

#[test]
fn recovers_a_row_that_was_deleted() {
    // The flag is in a row that is no longer live but still in the page's free
    // space, which is the whole point of reading the file rather than querying
    // it.
    let file = database(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT, secret TEXT)",
        vec![vec![
            Cell::Null,
            Cell::Text("alice"),
            Cell::Text("admin"),
            Cell::Text("nothing"),
        ]],
        Some(vec![
            Cell::Null,
            Cell::Text("carol"),
            Cell::Text("user"),
            Cell::Text("flag{deleted_but_not_gone}"),
        ]),
    );
    let db = read(&file).unwrap();
    let users = &db.tables[0];

    assert_eq!(users.row_count, 1, "one live row");
    assert_eq!(users.deleted.len(), 1, "one recovered row");
    let recovered: Vec<&str> = users.deleted[0]
        .values
        .iter()
        .map(|v| v.text.as_str())
        .collect();
    assert!(
        recovered.contains(&"flag{deleted_but_not_gone}"),
        "recovered {recovered:?}"
    );
    assert!(recovered.contains(&"carol"));
}

#[test]
fn a_varint_reads_the_values_sqlite_writes() {
    assert_eq!(varint(&[0x00], 0), Some((0, 1)));
    assert_eq!(varint(&[0x7f], 0), Some((127, 1)));
    // 128 spans two bytes: 0x81 0x00.
    assert_eq!(varint(&[0x81, 0x00], 0), Some((128, 2)));
    assert_eq!(varint(&varint_of(300_000), 0), Some((300_000, 3)));
}

#[test]
fn a_record_round_trips_through_the_decoder() {
    let bytes = record(&[Cell::Int(42), Cell::Text("hi"), Cell::Null]);
    let values = decode_record(&bytes).unwrap();
    assert_eq!(values.len(), 3);
    assert_eq!((values[0].kind, values[0].text.as_str()), ("integer", "42"));
    assert_eq!((values[1].kind, values[1].text.as_str()), ("text", "hi"));
    assert_eq!(values[2].kind, "null");
}

#[test]
fn columns_come_out_of_the_create_statement() {
    assert_eq!(
        columns_from_sql("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, note TEXT)"),
        vec!["id", "name", "note"]
    );
    // A table-level constraint is not a column.
    assert_eq!(
        columns_from_sql("CREATE TABLE t (a TEXT, b TEXT, PRIMARY KEY (a, b))"),
        vec!["a", "b"]
    );
    // Quoted names are unwrapped.
    assert_eq!(
        columns_from_sql("CREATE TABLE t (\"weird name\" TEXT)"),
        vec!["weird name"]
    );
}

#[test]
fn json_output_is_well_formed() {
    let file = database(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)",
        vec![vec![Cell::Null, Cell::Text("alice")]],
        Some(vec![Cell::Null, Cell::Text("carol")]),
    );
    let out = json(&file);
    assert!(crate::json::is_well_formed(&out), "malformed: {out}");
    assert!(out.contains("\"alice\""));
    assert!(out.contains("\"carol\""));

    assert_eq!(json(b"not a db"), "null");
}
