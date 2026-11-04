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
    let values = decode_record(&bytes, true, UTF8, &mut 100).unwrap();
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

const UTF8: Text = Text {
    encoding: Encoding::Utf8,
    cap: CELL_TEXT_CAP,
};

/// A file header in front of the given pages, the first of which already has room left
/// for it.
fn file_of(page_size: usize, encoding: u32, mut pages: Vec<Vec<u8>>) -> Vec<u8> {
    let count = pages.len() as u32;
    let first = &mut pages[0];
    first[..16].copy_from_slice(HEADER);
    first[16..18].copy_from_slice(&(if page_size == 65536 { 1 } else { page_size as u16 }).to_be_bytes());
    first[18..24].copy_from_slice(&[1, 1, 0, 64, 32, 32]);
    first[28..32].copy_from_slice(&count.to_be_bytes());
    first[56..60].copy_from_slice(&encoding.to_be_bytes());
    pages.concat()
}

/// A leaf page of a given size from whole cells laid in from the end, optionally with
/// bytes placed by hand and the header fields that describe them.
struct Leaf {
    page: Vec<u8>,
    head: usize,
    content: usize,
    offsets: Vec<usize>,
}

impl Leaf {
    fn new(size: usize, head: usize) -> Self {
        Self {
            page: vec![0; size],
            head,
            content: size,
            offsets: Vec::new(),
        }
    }

    /// Adds a cell the page still lists.
    fn live(mut self, cell: &[u8]) -> Self {
        self.content -= cell.len();
        self.page[self.content..self.content + cell.len()].copy_from_slice(cell);
        self.offsets.push(self.content);
        self
    }

    /// Lays bytes below the content area without moving it, the way a row deleted from
    /// the front of the area is left.
    fn left_in_the_gap(mut self, bytes: &[u8]) -> Self {
        let at = self.content - bytes.len();
        self.page[at..self.content].copy_from_slice(bytes);
        self
    }

    /// Lays bytes at the front of the content area and makes them a freeblock.
    fn freed(mut self, body: &[u8]) -> Self {
        let size = body.len() + 4;
        self.content -= size;
        let at = self.content;
        self.page[at..at + 2].copy_from_slice(&[0, 0]);
        self.page[at + 2..at + 4].copy_from_slice(&(size as u16).to_be_bytes());
        self.page[at + 4..at + size].copy_from_slice(body);
        self.page[self.head + 1..self.head + 3].copy_from_slice(&(at as u16).to_be_bytes());
        self
    }

    fn build(mut self) -> Vec<u8> {
        let head = self.head;
        self.page[head] = 0x0d;
        self.page[head + 3..head + 5].copy_from_slice(&(self.offsets.len() as u16).to_be_bytes());
        self.page[head + 5..head + 7].copy_from_slice(&(self.content as u16).to_be_bytes());
        for (i, offset) in self.offsets.iter().enumerate() {
            self.page[head + 8 + i * 2..head + 10 + i * 2].copy_from_slice(&(*offset as u16).to_be_bytes());
        }
        self.page
    }
}

/// A schema row for one table whose rows start at page two.
fn schema_cell(sql: &str) -> Vec<u8> {
    let sql: &'static str = sql.to_string().leak();
    leaf_cell(
        1,
        &[
            Cell::Text("table"),
            Cell::Text("notes"),
            Cell::Text("notes"),
            Cell::Int(2),
            Cell::Text(sql),
        ],
    )
}

/// A database of one table, given its statement and its leaf page.
fn one_table(sql: &str, rows: Vec<u8>) -> Vec<u8> {
    let schema = Leaf::new(PAGE, 100).live(&schema_cell(sql)).build();
    file_of(PAGE, 1, vec![schema, rows])
}

const NOTES: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)";

fn text_of(row: &Row) -> Vec<&str> {
    row.values.iter().map(|value| value.text.as_str()).collect()
}

#[test]
fn a_statement_with_its_parentheses_backwards_does_not_panic() {
    // The last close sits before the first open, which used to slice sql[3..1].
    assert!(columns_from_sql(")(").is_empty());
    let _ = columns_from_sql(")))(((");
    assert_eq!(rowid_alias(")("), None);
    assert!(columns_from_sql("no parentheses at all").is_empty());
    assert_eq!(columns_from_sql("CREATE TABLE t ("), Vec::<String>::new());
    assert_eq!(columns_from_sql("CREATE TABLE t (a, b"), vec!["a", "b"]);

    let file = one_table(")(", Leaf::new(PAGE, 0).build());
    assert_eq!(read(&file).unwrap().tables[0].sql, ")(");
}

#[test]
fn a_rowid_alias_shows_the_rowid() {
    // Stored as NULL by design, and shown as NULL by reading only the record.
    let file = database(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)",
        vec![vec![Cell::Null, Cell::Text("alice")], vec![Cell::Null, Cell::Text("bob")]],
        None,
    );
    let db = read(&file).unwrap();

    assert_eq!(text_of(&db.tables[0].rows[0]), vec!["1", "alice"]);
    assert_eq!(db.tables[0].rows[0].values[0].kind, "integer");
    assert_eq!(text_of(&db.tables[0].rows[1]), vec!["2", "bob"]);
}

#[test]
fn a_real_null_in_an_ordinary_column_stays_null() {
    let file = database(
        "CREATE TABLE users (id TEXT, name TEXT)",
        vec![vec![Cell::Null, Cell::Text("alice")]],
        None,
    );
    assert_eq!(text_of(&read(&file).unwrap().tables[0].rows[0]), vec!["NULL", "alice"]);
}

#[test]
fn only_the_exact_declaration_is_a_rowid_alias() {
    for (sql, alias) in [
        ("CREATE TABLE t (id INTEGER PRIMARY KEY, a)", Some(0)),
        ("create table t (a text, id integer primary key autoincrement)", Some(1)),
        ("CREATE TABLE t (\"my id\" INTEGER PRIMARY KEY, a)", Some(0)),
        ("CREATE TABLE t (a, [id] INTEGER NOT NULL PRIMARY KEY)", Some(1)),
        ("CREATE TABLE t (a, id INTEGER, PRIMARY KEY (id))", Some(1)),
        ("CREATE TABLE t (a, id INTEGER, PRIMARY KEY(\"id\"))", Some(1)),
        ("CREATE TABLE t (id INT PRIMARY KEY, a)", None),
        ("CREATE TABLE t (id TEXT PRIMARY KEY, a)", None),
        ("CREATE TABLE t (id INTEGER PRIMARY KEY DESC, a)", None),
        ("CREATE TABLE t (a INTEGER, b INTEGER, PRIMARY KEY (a, b))", None),
        ("CREATE TABLE t (a TEXT, PRIMARY KEY (a))", None),
        ("CREATE TABLE t (id INTEGER, a)", None),
    ] {
        assert_eq!(rowid_alias(sql), alias, "{sql}");
    }
}

#[test]
fn a_long_create_statement_is_read_whole() {
    // Every text value was cut at 240 bytes on its way out, this one included, so a
    // table of thirty columns reported eleven.
    let columns: Vec<String> = (0..30).map(|i| format!("column_number_{i} TEXT")).collect();
    let sql = format!("CREATE TABLE notes({})", columns.join(", "));
    assert!(sql.len() > 240);

    let db = read(&one_table(&sql, Leaf::new(PAGE, 0).build())).unwrap();
    assert_eq!(db.tables[0].columns.len(), 30);
    assert_eq!(db.tables[0].sql, sql);
}

#[test]
fn a_long_cell_is_still_cut_for_display() {
    let long: &'static str = "x".repeat(1000).leak();
    let file = database("CREATE TABLE users (a TEXT)", vec![vec![Cell::Text(long)]], None);
    let text = &read(&file).unwrap().tables[0].rows[0].values[0].text;
    assert_eq!(text.chars().count(), CELL_TEXT_CAP + 1);
    assert!(text.ends_with('…'));
}

/// A row whose record runs on through a chain of overflow pages, the way SQLite stores
/// anything too long for the leaf: `(rowid, body, tail)` with a body of `length` bytes.
fn overflowing(head: &str, length: usize, tail: &str) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut body = head.as_bytes().to_vec();
    body.resize(length, b'x');

    let mut types = Vec::new();
    types.extend_from_slice(&varint_of(0));
    types.extend_from_slice(&varint_of(length as u64 * 2 + 13));
    types.extend_from_slice(&varint_of(tail.len() as u64 * 2 + 13));
    let mut payload = varint_of(1 + types.len() as u64);
    payload.extend_from_slice(&types);
    payload.extend_from_slice(&body);
    payload.extend_from_slice(tail.as_bytes());

    let db = Db {
        data: &[],
        page_size: PAGE,
        usable: PAGE,
        encoding: Encoding::Utf8,
    };
    let local = db.local_size(payload.len());

    let mut cell = varint_of(payload.len() as u64);
    cell.extend_from_slice(&varint_of(42));
    cell.extend_from_slice(&payload[..local]);
    cell.extend_from_slice(&3u32.to_be_bytes());

    let mut chain = Vec::new();
    let pieces: Vec<&[u8]> = payload[local..].chunks(PAGE - 4).collect();
    for (index, piece) in pieces.iter().enumerate() {
        let mut page = vec![0u8; PAGE];
        let next = if index + 1 == pieces.len() { 0 } else { index as u32 + 4 };
        page[..4].copy_from_slice(&next.to_be_bytes());
        page[4..4 + piece.len()].copy_from_slice(piece);
        chain.push(page);
    }
    (cell, chain)
}

#[test]
fn a_row_that_spills_to_overflow_pages_comes_back() {
    // Too long for its page, so reading it as if it had to fit found a value running
    // past the end and dropped the row, and the row count with it.
    let (cell, chain) = overflowing("flag{long_value_spills}", 9000, "after the long one");
    let rows = Leaf::new(PAGE, 0)
        .live(&leaf_cell(41, &[Cell::Null, Cell::Text("short"), Cell::Text("t")]))
        .live(&cell)
        .build();

    let schema = Leaf::new(PAGE, 100)
        .live(&schema_cell("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, tail TEXT)"))
        .build();
    let mut pages = vec![schema, rows];
    pages.extend(chain);

    let db = read(&file_of(PAGE, 1, pages)).unwrap();
    let table = &db.tables[0];

    assert_eq!(table.row_count, 2);
    assert_eq!(table.rows.len(), 2);
    assert_eq!(text_of(&table.rows[0]), vec!["41", "short", "t"]);

    let spilled = &table.rows[1];
    assert_eq!(spilled.values[0].text, "42");
    assert!(spilled.values[1].text.starts_with("flag{long_value_spills}xxx"), "{}", spilled.values[1].text);
    assert_eq!(spilled.values[2].text, "after the long one", "a column past the overflow");
}

/// A database of one table, with its rows on the page after the schema, which is where
/// [`overflowing`] expects its chain to follow from.
fn spilled_database(rows: Vec<u8>, chain: Vec<Vec<u8>>) -> Vec<u8> {
    let schema = Leaf::new(PAGE, 100)
        .live(&schema_cell("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, tail TEXT)"))
        .build();
    let mut pages = vec![schema, rows];
    pages.extend(chain);
    file_of(PAGE, 1, pages)
}

/// Flags one after another, so that some of them sit across the pages of a chain.
fn run_of_flags() -> (String, Vec<String>) {
    let flags: Vec<String> = (0..1000).map(|i| format!("flag{{piece_{i:04}}}")).collect();
    (flags.join(" "), flags)
}

#[test]
fn a_flag_in_pieces_across_overflow_pages_is_found() {
    let (body, flags) = run_of_flags();
    let (cell, chain) = overflowing(&body, body.len(), "t");
    let file = spilled_database(Leaf::new(PAGE, 0).live(&cell).build(), chain);

    let db = read(&file).unwrap();
    assert_eq!(db.tables[0].flags, flags);
    assert!(!db.flags_truncated);
    assert!(
        bytes::flag_candidates(&file).len() < flags.len(),
        "at least one of them really is in pieces in the file"
    );
}

#[test]
fn a_flag_in_pieces_past_the_rows_shown_is_found() {
    let (body, flags) = run_of_flags();
    // A length that leaves little on the page, so all the rows before it fit there too.
    let (cell, chain) = (body.len()..)
        .map(|length| overflowing(&body, length, "t"))
        .find(|(cell, _)| cell.len() < 1000)
        .unwrap();

    let mut rows = Leaf::new(PAGE, 0);
    for rowid in 1..=MAX_ROWS as u64 {
        rows = rows.live(&leaf_cell(rowid, &[Cell::Null, Cell::Text("s"), Cell::Text("t")]));
    }
    let file = spilled_database(rows.live(&cell).build(), chain);

    let db = read(&file).unwrap();
    assert_eq!(db.tables[0].rows.len(), MAX_ROWS);
    assert_eq!(db.tables[0].row_count, MAX_ROWS + 1);
    assert_eq!(db.tables[0].flags, flags);
}

/// A record of one value, with the serial type given.
fn record_of(serial: u64, value: &[u8]) -> Vec<u8> {
    let types = varint_of(serial);
    let mut payload = varint_of(1 + types.len() as u64);
    payload.extend_from_slice(&types);
    payload.extend_from_slice(value);
    payload
}

fn flags_in(payload: &[u8], encoding: Encoding) -> Vec<String> {
    let mut found = CellFlags::default();
    record_flags(payload, encoding, &[], &mut Budget::new(), &mut found);
    found.list
}

#[test]
fn a_cell_that_could_not_be_read_to_its_end_says_so() {
    let (cell, mut chain) = overflowing("flag{at_the_start}", 9000, "tail");
    chain.truncate(1);
    chain[0][..4].copy_from_slice(&0u32.to_be_bytes());

    let db = read(&spilled_database(Leaf::new(PAGE, 0).live(&cell).build(), chain)).unwrap();

    assert!(db.flags_truncated);
    assert_eq!(db.tables[0].flags, ["flag{at_the_start}"]);
}

#[test]
fn each_value_is_searched_as_what_it_is() {
    let wide: Vec<u8> = "flag{wide_text}".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let text = record_of(wide.len() as u64 * 2 + 13, &wide);
    assert_eq!(flags_in(&text, Encoding::Utf16Le), ["flag{wide_text}"]);

    let blob = b"\x00\x01flag{in_a_blob}\xff";
    let record = record_of(blob.len() as u64 * 2 + 12, blob);
    assert_eq!(flags_in(&record, Encoding::Utf8), ["flag{in_a_blob}"]);
}

#[test]
fn a_search_out_of_budget_says_so() {
    let (cell, _) = overflowing("flag{long}", 9000, "t");
    let mut budget = Budget::new();
    let (_, payload, _) = reader(&[]).record(&cell, 0, &mut budget).unwrap();

    budget.scanned = 1;
    let mut found = CellFlags::default();
    record_flags(&payload, Encoding::Utf8, &[], &mut budget, &mut found);

    assert!(found.truncated);
    assert!(found.list.is_empty());
}

#[test]
fn the_local_part_of_a_payload_follows_the_format() {
    let db = Db {
        data: &[],
        page_size: 4096,
        usable: 4096,
        encoding: Encoding::Utf8,
    };
    // Up to U-35 stays on the page. Past that, M + (P-M) % (U-4), or M if that is too long.
    assert_eq!(db.local_size(4061), 4061);
    let least = (4096 - 12) * 32 / 255 - 23;
    assert_eq!(least, 489);
    assert_eq!(db.local_size(4062), least, "4062 itself would be too long");
    assert_eq!(db.local_size(9037), 853);
    assert!(db.local_size(usize::MAX) <= 4061);
}

#[test]
fn an_overflow_chain_that_loops_or_stops_short_keeps_what_it_has() {
    let (cell, mut chain) = overflowing("flag{chain_cut_short}", 9000, "tail");
    chain[0][..4].copy_from_slice(&3u32.to_be_bytes());

    let rows = Leaf::new(PAGE, 0).live(&cell).build();
    let schema = Leaf::new(PAGE, 100).live(&schema_cell(NOTES)).build();
    let mut pages = vec![schema, rows];
    pages.extend(chain.clone());
    let db = read(&file_of(PAGE, 1, pages)).unwrap();
    assert!(db.tables[0].rows[0].values[1].text.starts_with("flag{chain_cut_short}"));

    // And one that ends at a page that does not exist.
    chain[0][..4].copy_from_slice(&0xffff_fff0u32.to_be_bytes());
    let schema = Leaf::new(PAGE, 100).live(&schema_cell(NOTES)).build();
    let rows = Leaf::new(PAGE, 0).live(&cell).build();
    let mut pages = vec![schema, rows];
    pages.extend(chain);
    let db = read(&file_of(PAGE, 1, pages)).unwrap();
    assert_eq!(db.tables[0].row_count, 1);
}

#[test]
fn the_last_row_inserted_is_recovered_from_the_gap() {
    // Deleting the cell at the front of the content area makes no freeblock: the area
    // just starts later, and the whole cell sits in the gap in front of it.
    let rows = Leaf::new(PAGE, 0)
        .live(&leaf_cell(1, &[Cell::Null, Cell::Text("first row here")]))
        .live(&leaf_cell(2, &[Cell::Null, Cell::Text("second row here")]))
        .left_in_the_gap(&leaf_cell(3, &[Cell::Null, Cell::Text("flag{deleted_last_row}")]))
        .build();

    let table = &read(&one_table(NOTES, rows)).unwrap().tables[0];
    assert_eq!(table.row_count, 2);
    assert_eq!(table.deleted.len(), 1);
    assert_eq!(text_of(&table.deleted[0]), vec!["3", "flag{deleted_last_row}"]);
}

#[test]
fn several_rows_deleted_from_the_front_are_all_recovered() {
    let mut gap = leaf_cell(4, &[Cell::Null, Cell::Text("flag{the_fourth}")]);
    gap.extend_from_slice(&leaf_cell(3, &[Cell::Null, Cell::Text("flag{the_third}")]));
    let rows = Leaf::new(PAGE, 0)
        .live(&leaf_cell(1, &[Cell::Null, Cell::Text("the first")]))
        .left_in_the_gap(&gap)
        .build();

    let table = &read(&one_table(NOTES, rows)).unwrap().tables[0];
    let found: Vec<Vec<&str>> = table.deleted.iter().map(text_of).collect();
    assert_eq!(found, vec![vec!["4", "flag{the_fourth}"], vec!["3", "flag{the_third}"]]);
}

/// What survives of a deleted cell behind its four-byte freeblock header, for a row of a
/// NULL rowid alias and one short text: the type of the text, then the text.
fn clobbered(text: &str) -> Vec<u8> {
    let mut out = varint_of(text.len() as u64 * 2 + 13);
    out.extend_from_slice(text.as_bytes());
    out
}

#[test]
fn neighbouring_rows_merged_into_one_freeblock_are_both_recovered() {
    // Laid out exactly as SQLite leaves it: the block's own header, the first row's
    // remains, the header the second row was given before the two were merged, and its
    // remains. The block is one record too long to fill exactly, so nothing came back.
    let mut body = clobbered("flag{adjacent_two_survives}");
    let second = clobbered("flag{adjacent_one_survives}");
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&((second.len() + 4) as u16).to_be_bytes());
    body.extend_from_slice(&second);

    let rows = Leaf::new(PAGE, 0)
        .live(&leaf_cell(1, &[Cell::Null, Cell::Text("alpha row body")]))
        .freed(&body)
        .build();

    let table = &read(&one_table(NOTES, rows)).unwrap().tables[0];
    assert_eq!(table.row_count, 1);
    let found: Vec<Vec<&str>> = table.deleted.iter().map(text_of).collect();
    assert_eq!(
        found,
        vec![vec!["flag{adjacent_two_survives}"], vec!["flag{adjacent_one_survives}"]]
    );
}

#[test]
fn a_cell_merged_into_a_freeblock_without_a_header_of_its_own_is_recovered() {
    // Deleted the other way round, the later cell is absorbed by size alone and never
    // written to, so it is there whole, rowid and all.
    let mut body = clobbered("flag{freed_first}");
    body.extend_from_slice(&leaf_cell(7, &[Cell::Null, Cell::Text("flag{absorbed_whole}")]));

    let rows = Leaf::new(PAGE, 0)
        .live(&leaf_cell(1, &[Cell::Null, Cell::Text("alpha row body")]))
        .freed(&body)
        .build();

    let table = &read(&one_table(NOTES, rows)).unwrap().tables[0];
    let found: Vec<Vec<&str>> = table.deleted.iter().map(text_of).collect();
    assert_eq!(found, vec![vec!["flag{freed_first}"], vec!["7", "flag{absorbed_whole}"]]);
}

#[test]
fn a_record_whose_own_header_survived_is_recovered() {
    // A long rowid and a long payload use up all four bytes the freeblock writes over,
    // which leaves the record's header length as the first thing left.
    let text = "flag{header_survived}".to_string() + &"y".repeat(150);
    let text: &'static str = text.leak();
    let rec = record(&[Cell::Null, Cell::Text(text)]);

    let rows = Leaf::new(PAGE, 0)
        .live(&leaf_cell(1, &[Cell::Null, Cell::Text("alpha row body")]))
        .freed(&rec)
        .build();

    let table = &read(&one_table(NOTES, rows)).unwrap().tables[0];
    assert_eq!(table.deleted.len(), 1);
    assert_eq!(table.deleted[0].values[0].kind, "null");
    assert!(table.deleted[0].values[1].text.starts_with("flag{header_survived}"));
}

#[test]
fn a_stale_copy_of_a_live_row_is_not_reported_deleted() {
    // Defragmenting moves cells and leaves the old copies in the gap.
    let cell = leaf_cell(1, &[Cell::Null, Cell::Text("still very much alive")]);
    let rows = Leaf::new(PAGE, 0).live(&cell).left_in_the_gap(&cell).build();

    let table = &read(&one_table(NOTES, rows)).unwrap().tables[0];
    assert_eq!(table.row_count, 1);
    assert!(table.deleted.is_empty(), "{:?}", table.deleted);
}

#[test]
fn a_gap_of_zeroes_or_noise_recovers_nothing() {
    let mut state = 0x1234_5678u32;
    let noise: Vec<u8> = (0..3000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();

    let rows = Leaf::new(PAGE, 0)
        .live(&leaf_cell(1, &[Cell::Null, Cell::Text("alive")]))
        .left_in_the_gap(&noise)
        .build();
    let table = &read(&one_table(NOTES, rows)).unwrap().tables[0];
    assert!(table.deleted.is_empty(), "{:?}", table.deleted);

    let rows = Leaf::new(PAGE, 0).live(&leaf_cell(1, &[Cell::Null, Cell::Text("alive")])).build();
    assert!(read(&one_table(NOTES, rows)).unwrap().tables[0].deleted.is_empty());
}

/// A record with `types` NULL columns, and nothing else.
fn record_of_nulls(types: usize) -> Vec<u8> {
    let mut header = varint_of(types as u64 + 3);
    header.resize(3, 0);
    let mut fixed = vec![0x80 | ((types + 3) >> 14) as u8, 0x80 | (((types + 3) >> 7) & 0x7f) as u8, ((types + 3) & 0x7f) as u8];
    fixed.extend(std::iter::repeat_n(0u8, types));
    fixed
}

#[test]
fn a_row_of_too_many_values_is_refused() {
    let payload = record_of_nulls(MAX_COLUMNS + 1);
    assert_eq!(decode_record(&payload, true, UTF8, &mut usize::MAX.clone()), None);

    let payload = record_of_nulls(MAX_COLUMNS);
    assert_eq!(decode_record(&payload, true, UTF8, &mut usize::MAX.clone()).unwrap().len(), MAX_COLUMNS);
}

#[test]
fn a_budget_spent_on_values_stops_the_decoding() {
    let payload = record_of_nulls(100);
    let mut budget = 40;
    assert_eq!(decode_record(&payload, true, UTF8, &mut budget), None);
    assert_eq!(budget, 0);
}

#[test]
fn a_page_listing_one_huge_row_many_times_stays_bounded() {
    // 131 KB of file, sixty tables sharing a page of six hundred pointers to one cell of
    // thirty thousand values. Every row was kept, at thirty bytes a value.
    const LARGE: usize = 65536;
    let payload = record_of_nulls(30_000);
    let mut cell = varint_of(payload.len() as u64);
    cell.extend_from_slice(&varint_of(1));
    cell.extend_from_slice(&payload);

    let mut rows = vec![0u8; LARGE];
    rows[2000..2000 + cell.len()].copy_from_slice(&cell);
    rows[0] = 0x0d;
    rows[3..5].copy_from_slice(&600u16.to_be_bytes());
    for i in 0..600 {
        rows[8 + i * 2..10 + i * 2].copy_from_slice(&2000u16.to_be_bytes());
    }

    let mut schema = Leaf::new(LARGE, 100);
    for _ in 0..64 {
        schema = schema.live(&schema_cell("CREATE TABLE notes (a)"));
    }
    let file = file_of(LARGE, 1, vec![schema.build(), rows]);
    assert!(file.len() < 132 * 1024);

    let started = std::time::Instant::now();
    let db = read(&file).unwrap();
    let kept: usize = db
        .tables
        .iter()
        .flat_map(|table| &table.rows)
        .map(|row| row.values.len())
        .sum();

    assert!(kept <= Budget::new().values, "kept {kept} values");
    assert_eq!(db.tables.len(), 64);
    assert_eq!(db.tables[0].row_count, 600, "every listed row is still counted");
    assert!(started.elapsed().as_secs() < 10, "took {:?}", started.elapsed());
}

#[test]
fn rows_of_long_text_keep_a_bounded_amount_of_it() {
    // The same shape with the longest text a cell shows. Going by the count of values,
    // 130 KB of file holds on to a quarter of a gigabyte and writes six times that.
    const LARGE: usize = 65536;
    let text: &'static str = "\u{1}".repeat(CELL_TEXT_CAP).leak();
    let cells: Vec<Cell> = (0..256).map(|_| Cell::Text(text)).collect();
    let cell = leaf_cell(1, &cells);

    let mut rows = vec![0u8; LARGE];
    rows[2000..2000 + cell.len()].copy_from_slice(&cell);
    rows[0] = 0x0d;
    rows[3..5].copy_from_slice(&600u16.to_be_bytes());
    for i in 0..600 {
        rows[8 + i * 2..10 + i * 2].copy_from_slice(&2000u16.to_be_bytes());
    }

    let mut schema = Leaf::new(LARGE, 100);
    for _ in 0..64 {
        schema = schema.live(&schema_cell("CREATE TABLE notes (a)"));
    }
    let file = file_of(LARGE, 1, vec![schema.build(), rows]);

    let db = read(&file).unwrap();
    let kept: usize = db
        .tables
        .iter()
        .flat_map(|table| &table.rows)
        .flat_map(|row| &row.values)
        .map(|value| value.text.len())
        .sum();

    assert!(kept > 0);
    assert!(kept <= Budget::new().values * BYTES_PER_VALUE, "kept {kept} bytes");
}

/// A database of nothing, to read one page against.
fn reader(data: &[u8]) -> Db<'_> {
    Db {
        data,
        page_size: PAGE,
        usable: PAGE,
        encoding: Encoding::Utf8,
    }
}

#[test]
fn the_part_of_a_spilling_cell_on_its_page_is_charged() {
    // A page can list this tens of thousands of times, and each one copied what it holds
    // into a record of its own, whatever else was left to spend.
    let (cell, _) = overflowing("long", 9000, "tail");
    let db = reader(&[]);

    let mut plenty = Budget::new();
    let spent = plenty.overflow;
    assert!(db.read_cell(&cell, 0, UTF8, &mut plenty).is_some());
    assert!(plenty.overflow < spent);

    let mut none = Budget::new();
    none.overflow = 0;
    assert!(db.read_cell(&cell, 0, UTF8, &mut none).is_none());
}

#[test]
fn walking_a_long_header_is_charged_against_carving() {
    // Every place in a page can open a header running to the end of it, and failing only
    // at the end, so it is the types read that cost and not the places tried.
    let mut page = Vec::new();
    page.extend_from_slice(&varint_of(1000));
    page.extend_from_slice(&varint_of(1));
    page.extend_from_slice(&varint_of(1000));
    page.resize(1003, 1);

    let db = reader(&[]);
    let mut budget = Budget::new();
    let start = budget.carve;
    assert!(db.intact_cell(&page, 0, page.len(), 2000, &mut budget).is_none());
    assert!(start - budget.carve >= 900, "spent {}", start - budget.carve);

    let mut budget = Budget::new();
    let start = budget.carve;
    assert!(db.carve_record(&page, 3, page.len(), 2000, &mut budget).is_none());
    assert!(start - budget.carve >= 900, "spent {}", start - budget.carve);
}

#[test]
fn nothing_is_called_deleted_once_there_is_nothing_left_to_check_it_against() {
    let rows = Leaf::new(PAGE, 0)
        .live(&leaf_cell(1, &[Cell::Null, Cell::Text("alpha row body")]))
        .freed(&clobbered("flag{freed}"))
        .build();
    let db = reader(&[]);

    let mut found = Vec::new();
    db.recover_deleted(&rows, 0, 2, Some(0), &mut found, &mut Budget::new());
    assert_eq!(found.len(), 1);

    let mut spent = Budget::new();
    spent.compared = 0;
    let mut found = Vec::new();
    db.recover_deleted(&rows, 0, 2, Some(0), &mut found, &mut spent);
    assert!(found.is_empty());

    let mut ample = usize::MAX;
    assert_eq!(db.live_cells(&rows, 0, &mut ample).map(|live| live.len()), Some(1));
    assert_eq!(db.live_cells(&rows, 0, &mut 1), None);
}

#[test]
fn a_chain_of_interior_pages_stops_at_a_real_depth() {
    // Each interior page's rightmost pointer is the next page. Recursing all the way
    // down a chain thousands of pages long overflows the stack in WASM.
    let mut pages = vec![Leaf::new(512, 100).live(&schema_cell("CREATE TABLE notes (a)")).build()];
    for index in 0..5000u32 {
        let mut page = vec![0u8; 512];
        page[0] = 0x05;
        page[8..12].copy_from_slice(&(index + 3).to_be_bytes());
        pages.push(page);
    }

    let db = read(&file_of(512, 1, pages)).unwrap();
    assert_eq!(db.tables[0].row_count, 0);
}

#[test]
fn a_page_number_that_wraps_a_32_bit_offset_is_not_some_other_page() {
    let file = vec![0u8; 65536];
    // 65537 pages in at 64 KB each is exactly 2^32, which is zero in 32 bits.
    assert_eq!(page_bytes(&file, 65537, 65536), None);
    assert_eq!(page_bytes(&file, u32::MAX, 65536), None);
    assert_eq!(page_bytes(&file, 0, 65536), None);
    assert!(page_bytes(&file, 1, 65536).is_some());
}

#[test]
fn a_page_count_that_wraps_a_32_bit_size_falls_back_to_the_file() {
    let mut file = database("CREATE TABLE users (a)", vec![], None);
    file[16..18].copy_from_slice(&1u16.to_be_bytes());
    file[28..32].copy_from_slice(&65537u32.to_be_bytes());
    let db = read(&file).unwrap();
    assert_eq!(db.page_count, file.len() / 65536);
}

#[test]
fn a_utf16_database_reads_as_text() {
    // The schema is in the database's encoding too, so `table` read as UTF-8 was not
    // the word `table`, and a database of tables reported none.
    for (encoding, label, encode) in [
        (2u32, "UTF-16LE", u16::to_le_bytes as fn(u16) -> [u8; 2]),
        (3u32, "UTF-16BE", u16::to_be_bytes as fn(u16) -> [u8; 2]),
    ] {
        let wide = |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(encode).collect() };

        let mut schema_record = Vec::new();
        let parts = ["table", "notes", "notes", "", NOTES];
        let mut types = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            if i == 3 {
                types.push(1);
            } else {
                types.extend_from_slice(&varint_of(wide(part).len() as u64 * 2 + 13));
            }
        }
        schema_record.extend_from_slice(&varint_of(1 + types.len() as u64));
        schema_record.extend_from_slice(&types);
        for (i, part) in parts.iter().enumerate() {
            if i == 3 {
                schema_record.push(2);
            } else {
                schema_record.extend_from_slice(&wide(part));
            }
        }
        let mut schema_cell = varint_of(schema_record.len() as u64);
        schema_cell.extend_from_slice(&varint_of(1));
        schema_cell.extend_from_slice(&schema_record);

        let body = wide("flag{utf16_database_row}");
        let mut row = vec![3, 0];
        row.extend_from_slice(&varint_of(body.len() as u64 * 2 + 13));
        row.remove(0);
        let mut rec = varint_of(1 + row.len() as u64);
        rec.extend_from_slice(&row);
        rec.extend_from_slice(&body);
        let mut cell = varint_of(rec.len() as u64);
        cell.extend_from_slice(&varint_of(1));
        cell.extend_from_slice(&rec);

        let file = file_of(
            PAGE,
            encoding,
            vec![
                Leaf::new(PAGE, 100).live(&schema_cell).build(),
                Leaf::new(PAGE, 0).live(&cell).build(),
            ],
        );

        let db = read(&file).unwrap();
        assert_eq!(db.encoding, label);
        assert_eq!(db.table_count, 1);
        assert_eq!(db.tables[0].name, "notes");
        assert_eq!(db.tables[0].columns, vec!["id", "body"]);
        assert_eq!(text_of(&db.tables[0].rows[0]), vec!["1", "flag{utf16_database_row}"]);
    }
}

#[test]
fn a_cut_or_odd_utf16_value_does_not_panic() {
    let text = Text {
        encoding: Encoding::Utf16Le,
        cap: 3,
    };
    assert_eq!(text_preview(b"a\0b\0c\0", 6, text), "a…");
    assert_eq!(text_preview(b"a\0b", 3, text), "a");
    assert_eq!(text_preview(&[0x00, 0xd8], 2, text), "\u{fffd}", "a lone surrogate");
}

#[test]
fn a_blob_says_how_long_it_is_whatever_was_kept() {
    assert_eq!(blob_preview(&[1, 2], 2), "0102 (2 bytes)");
    assert!(blob_preview(&[0; 30], 9000).ends_with("… (9000 bytes)"));
}

#[test]
fn a_serial_type_near_the_top_of_64_bits_does_not_wrap_a_sum() {
    // Written as a type in a freed cell, it claims an impossible length, and adding it
    // up has to stop rather than wrap back to something that fits.
    let mut body = vec![0xff; 8];
    body.push(0x41);
    body.extend_from_slice(b"flag{not_reachable}");
    let rows = Leaf::new(PAGE, 0)
        .live(&leaf_cell(1, &[Cell::Null, Cell::Text("alive")]))
        .freed(&body)
        .build();
    assert!(read(&one_table(NOTES, rows)).is_some());

    assert_eq!(serial_len(-1), None);
    assert_eq!(serial_len(10), None);
    assert_eq!(serial_len(13), Some(0));
    assert_eq!(serial_len(12), Some(0));
}

#[test]
fn every_truncation_of_a_database_reads_without_panicking() {
    let file = database(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)",
        vec![vec![Cell::Null, Cell::Text("alice")]],
        Some(vec![Cell::Null, Cell::Text("carol")]),
    );
    for cut in (0..file.len()).step_by(97) {
        let _ = read(&file[..cut]);
    }
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
