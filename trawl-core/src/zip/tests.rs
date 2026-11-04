use super::*;

/// One file to put in a test archive.
struct Put {
    name: &'static str,
    body: &'static [u8],
    /// Left out of the central directory, which is how a file is hidden from
    /// every reader that only walks the directory.
    listed: bool,
    encrypted: bool,
    /// A size written into the directory that the local header disagrees with.
    lie: Option<u32>,
}

impl Put {
    fn new(name: &'static str, body: &'static [u8]) -> Self {
        Self {
            name,
            body,
            listed: true,
            encrypted: false,
            lie: None,
        }
    }
}

fn push16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Builds a stored-method archive, honestly or otherwise.
fn build(files: &[Put], prefix: &[u8], trailing: &[u8], comment: &[u8]) -> Vec<u8> {
    let mut out = prefix.to_vec();
    let mut offsets = Vec::new();

    for file in files {
        offsets.push(out.len());
        out.extend_from_slice(LOCAL);
        push16(&mut out, 20);
        push16(&mut out, if file.encrypted { 1 } else { 0 });
        push16(&mut out, 0); // stored
        push16(&mut out, 0);
        push16(&mut out, 0);
        push32(&mut out, 0xdead_beef);
        push32(&mut out, file.body.len() as u32);
        push32(&mut out, file.body.len() as u32);
        push16(&mut out, file.name.len() as u16);
        push16(&mut out, 0);
        out.extend_from_slice(file.name.as_bytes());
        out.extend_from_slice(file.body);
    }

    let directory_at = out.len();
    let mut listed = 0u16;

    for (file, &offset) in files.iter().zip(&offsets) {
        if !file.listed {
            continue;
        }
        listed += 1;

        out.extend_from_slice(CENTRAL);
        push16(&mut out, 20);
        push16(&mut out, 20);
        push16(&mut out, if file.encrypted { 1 } else { 0 });
        push16(&mut out, 0);
        push16(&mut out, 0);
        push16(&mut out, 0);
        push32(&mut out, 0xdead_beef);
        push32(&mut out, file.lie.unwrap_or(file.body.len() as u32));
        push32(&mut out, file.body.len() as u32);
        push16(&mut out, file.name.len() as u16);
        push16(&mut out, 0);
        push16(&mut out, 0);
        push16(&mut out, 0);
        push16(&mut out, 0);
        push32(&mut out, 0);
        push32(&mut out, offset as u32);
        out.extend_from_slice(file.name.as_bytes());
    }

    let directory_size = out.len() - directory_at;

    out.extend_from_slice(END);
    push16(&mut out, 0);
    push16(&mut out, 0);
    push16(&mut out, listed);
    push16(&mut out, listed);
    push32(&mut out, directory_size as u32);
    push32(&mut out, directory_at as u32);
    push16(&mut out, comment.len() as u16);
    out.extend_from_slice(comment);
    out.extend_from_slice(trailing);

    out
}

fn plain() -> Vec<u8> {
    build(
        &[
            Put::new("notes.txt", b"nothing here"),
            Put::new("cat.png", b"\x89PNG fake"),
        ],
        b"",
        b"",
        b"",
    )
}

#[test]
fn an_offset_at_the_top_of_the_address_space_is_not_a_signature() {
    let file = [&CENTRAL[..], b"rest"].concat();
    assert!(signature_at(&file, 0, CENTRAL));
    assert!(!signature_at(&file, 2, CENTRAL));
    assert!(!signature_at(&file, usize::MAX - 3, CENTRAL));
    assert!(!signature_at(&file, usize::MAX, CENTRAL));
}

#[test]
fn reads_an_ordinary_archive() {
    let archive = read(&plain()).expect("not read as an archive");

    assert_eq!(archive.entries.len(), 2);
    assert_eq!(archive.entries[0].name, "notes.txt");
    assert_eq!(archive.entries[0].method, "stored");
    assert_eq!(archive.entries[0].uncompressed, 12);
    assert_eq!(archive.entries[1].name, "cat.png");
    assert!(archive.entries.iter().all(|e| !e.undeclared));
    assert!(archive.entries.iter().all(|e| e.disagreement.is_none()));
    assert_eq!(archive.declared, 2);
    assert_eq!(archive.prefix, 0);
    assert_eq!(archive.trailing, 0);
}

#[test]
fn finds_a_file_the_directory_does_not_list() {
    // The trick the module exists for. `unzip -l` reads the directory, so an
    // entry left out of it is invisible there while its data sits in the file.
    let mut hidden = Put::new(".secret", b"flag{under_the_floor}");
    hidden.listed = false;

    let archive = read(&build(
        &[Put::new("notes.txt", b"nothing here"), hidden],
        b"",
        b"",
        b"",
    ))
    .expect("not read as an archive");

    let found = archive
        .entries
        .iter()
        .find(|e| e.name == ".secret")
        .expect("the hidden entry was missed");

    assert!(found.undeclared);
    assert_eq!(archive.declared, 1, "the directory should admit to one");
    assert_eq!(archive.entries.len(), 2, "but there are two");
}

#[test]
fn reports_a_size_the_directory_lies_about() {
    let mut lying = Put::new("payload.bin", b"0123456789");
    lying.lie = Some(4);

    let archive = read(&build(&[lying], b"", b"", b"")).unwrap();
    let said = archive.entries[0]
        .disagreement
        .as_ref()
        .expect("the disagreement was not noticed");

    assert!(
        said.contains("compressed size 10 here, 4 in the directory"),
        "{said}"
    );
}

#[test]
fn reports_bytes_appended_after_the_end() {
    let archive = read(&build(
        &[Put::new("notes.txt", b"nothing here")],
        b"",
        b"flag{stuck_on_the_end}",
        b"",
    ))
    .unwrap();

    assert_eq!(archive.trailing, 22);
}

#[test]
fn reports_an_archive_hiding_behind_something_else() {
    // A polyglot: the file opens as an image and also works as a zip, because
    // the archive simply starts partway in.
    let archive = read(&build(
        &[Put::new("notes.txt", b"nothing here")],
        b"\x89PNG\r\n\x1a\n and a good deal more picture",
        b"",
        b"",
    ))
    .unwrap();

    assert_eq!(archive.prefix, 37);
}

#[test]
fn reads_the_archive_comment() {
    let archive = read(&build(
        &[Put::new("notes.txt", b"nothing here")],
        b"",
        b"",
        b"flag{in_the_comment}",
    ))
    .unwrap();

    assert_eq!(archive.comment, "flag{in_the_comment}");
    assert_eq!(archive.trailing, 0, "the comment is part of the record");
}

#[test]
fn notices_an_encrypted_entry() {
    let mut locked = Put::new("flag.txt", b"unreadable");
    locked.encrypted = true;

    let archive = read(&build(&[locked], b"", b"", b"")).unwrap();
    assert!(archive.entries[0].encrypted);
}

#[test]
fn shows_a_name_that_tried_to_hide_itself() {
    // Control characters in a name are how a listing gets doctored on a
    // terminal. They have to survive into the report as something visible.
    let archive = read(&build(
        &[Put::new("safe.txt\r\x1b[2Kevil.sh", b"x")],
        b"",
        b"",
        b"",
    ))
    .unwrap();

    assert!(archive.entries[0].name.starts_with("safe.txt·"));
    assert!(!archive.entries[0].name.contains('\r'));
}

#[test]
fn declines_things_that_are_not_archives() {
    assert_eq!(read(b""), None);
    assert_eq!(read(b"just some text with no headers in it at all"), None);
    // The signature alone is not a header.
    assert_eq!(read(b"PK\x03\x04"), None);
}

#[test]
fn json_reports_what_it_found() {
    let mut hidden = Put::new(".secret", b"flag{under_the_floor}");
    hidden.listed = false;

    let out = json(&build(
        &[Put::new("a.txt", b"one"), hidden],
        b"",
        b"tail",
        b"hi",
    ));

    assert!(out.contains("\"name\":\".secret\""), "{out}");
    assert!(out.contains("\"undeclared\":true"), "{out}");
    assert!(out.contains("\"trailing\":4"), "{out}");
    assert!(out.contains("\"comment\":\"hi\""), "{out}");
    assert_eq!(json(b"not an archive"), "null");
}

/// One deflated-or-whatever entry written the way a writer that cannot seek writes
/// it: flag bit three set, zeroes in the header, and a descriptor after the data.
fn streamed(name: &str, body: &[u8], in_directory: bool, signature: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(LOCAL);
    push16(&mut out, 20);
    push16(&mut out, 8);
    push16(&mut out, 0);
    push16(&mut out, 0);
    push16(&mut out, 0);
    push32(&mut out, 0);
    push32(&mut out, 0);
    push32(&mut out, 0);
    push16(&mut out, name.len() as u16);
    push16(&mut out, 0);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(body);
    if signature {
        out.extend_from_slice(DESCRIPTOR);
    }
    push32(&mut out, 0xcafe_f00d);
    push32(&mut out, body.len() as u32);
    push32(&mut out, body.len() as u32);

    let directory_at = out.len();
    if in_directory {
        out.extend_from_slice(CENTRAL);
        push16(&mut out, 20);
        push16(&mut out, 20);
        push16(&mut out, 8);
        push16(&mut out, 0);
        push16(&mut out, 0);
        push16(&mut out, 0);
        push32(&mut out, 0xcafe_f00d);
        push32(&mut out, body.len() as u32);
        push32(&mut out, body.len() as u32);
        push16(&mut out, name.len() as u16);
        push16(&mut out, 0);
        push16(&mut out, 0);
        push16(&mut out, 0);
        push16(&mut out, 0);
        push32(&mut out, 0);
        push32(&mut out, 0);
        out.extend_from_slice(name.as_bytes());
    }
    let directory_size = out.len() - directory_at;
    let listed = u16::from(in_directory);

    out.extend_from_slice(END);
    push16(&mut out, 0);
    push16(&mut out, 0);
    push16(&mut out, listed);
    push16(&mut out, listed);
    push32(&mut out, directory_size as u32);
    push32(&mut out, directory_at as u32);
    push16(&mut out, 0);
    out
}

#[test]
fn a_streamed_entry_takes_its_sizes_from_where_they_are() {
    // Zeroes in a header with bit three set are what the format asks for, not a lie,
    // and an entry reported as zero bytes long was never opened.
    let archive = read(&streamed("secret.txt", b"flag{streamed}", true, true)).unwrap();
    let entry = &archive.entries[0];

    assert_eq!(entry.compressed, 14);
    assert_eq!(entry.uncompressed, 14);
    assert_eq!(entry.crc, 0xcafe_f00d);
    assert_eq!(entry.disagreement, None);
    assert!(!entry.undeclared);
}

#[test]
fn a_descriptor_with_no_signature_leaves_the_directory_to_say() {
    let archive = read(&streamed("secret.txt", b"flag{streamed}", true, false)).unwrap();
    let entry = &archive.entries[0];

    assert_eq!(entry.compressed, 14);
    assert_eq!(entry.disagreement, None);
}

#[test]
fn a_streamed_entry_only_a_header_names_finds_its_descriptor() {
    let archive = read(&streamed("hidden.txt", b"flag{no_directory}", false, true)).unwrap();
    let entry = &archive.entries[0];

    assert!(entry.undeclared);
    assert_eq!(entry.compressed, 18);
    assert_eq!(entry.uncompressed, 18);
}

#[test]
fn a_descriptor_signature_inside_the_data_does_not_end_the_entry() {
    // The signature can occur in the data, which is why the size it carries has to
    // match how far away it sits.
    let mut body = b"before ".to_vec();
    body.extend_from_slice(DESCRIPTOR);
    body.extend_from_slice(b" and after the lookalike");
    let body: &'static [u8] = body.leak();

    let archive = read(&streamed("tricky.bin", body, false, true)).unwrap();
    assert_eq!(archive.entries[0].compressed, body.len() as u64);
}

#[test]
fn a_streamed_header_that_does_state_a_size_can_still_be_wrong() {
    let mut file = streamed("secret.txt", b"flag{streamed}", true, false);
    file[18..22].copy_from_slice(&99u32.to_le_bytes());

    let archive = read(&file).unwrap();
    let said = archive.entries[0].disagreement.as_ref().expect("not noticed");
    assert!(said.contains("compressed size 99 here, 14 in the directory"), "{said}");
}

#[test]
fn an_ordinary_header_with_zero_sizes_is_still_a_disagreement() {
    let mut file = plain();
    file[18..22].copy_from_slice(&0u32.to_le_bytes());

    let archive = read(&file).unwrap();
    let said = archive.entries[0].disagreement.as_ref().expect("not noticed");
    assert!(said.contains("compressed size 0 here, 12 in the directory"), "{said}");
}

#[test]
fn pseudo_encryption_is_reported_and_leaves_the_entry_open() {
    // The classic trick: the directory's password flag set over data that was never
    // locked. Tools ask for a password that does not exist.
    let mut file = build(&[Put::new("flag.txt", b"flag{pseudo}")], b"", b"", b"");
    let directory = bytes::find(&file, 0, CENTRAL).unwrap();
    file[directory + 8] |= 1;

    let archive = read(&file).unwrap();
    let entry = &archive.entries[0];
    assert!(!entry.encrypted, "the worker has to be willing to open this");
    let said = entry.disagreement.as_ref().expect("not reported");
    assert!(said.contains("not encrypted here, encrypted in the directory"), "{said}");
}

#[test]
fn pseudo_encryption_the_other_way_round_is_reported_too() {
    let mut file = build(&[Put::new("flag.txt", b"flag{pseudo}")], b"", b"", b"");
    file[6] |= 1;

    let archive = read(&file).unwrap();
    let entry = &archive.entries[0];
    assert!(!entry.encrypted);
    let said = entry.disagreement.as_ref().expect("not reported");
    assert!(said.contains("encrypted here, not encrypted in the directory"), "{said}");
}

#[test]
fn both_places_agreeing_on_a_password_is_no_disagreement() {
    let mut locked = Put::new("flag.txt", b"unreadable");
    locked.encrypted = true;

    let archive = read(&build(&[locked], b"", b"", b"")).unwrap();
    assert!(archive.entries[0].encrypted);
    assert_eq!(archive.entries[0].disagreement, None);
}

#[test]
fn a_compressed_size_that_wraps_a_32_bit_offset_covers_nothing_strange() {
    let mut file = build(&[Put::new("a.txt", b"one")], b"", b"", b"");
    let directory = bytes::find(&file, 0, CENTRAL).unwrap();
    file[directory + 20..directory + 24].copy_from_slice(&0xffff_fff8u32.to_le_bytes());
    assert!(read(&file).is_some());
}

#[test]
fn spans_merge_and_answer_the_way_a_search_would() {
    let spans = merged(vec![(50, 60), (10, 20), (15, 30), (30, 31)]);
    assert_eq!(spans, vec![(10, 31), (50, 60)]);
    for (offset, inside) in [(9, false), (10, true), (30, true), (31, false), (49, false), (59, true), (60, false)] {
        assert_eq!(covered(&spans, offset), inside, "{offset}");
    }
    assert!(!covered(&[], 5));
}

#[test]
fn a_file_of_nothing_but_headers_stays_bounded_and_prompt() {
    let mut header = Vec::new();
    header.extend_from_slice(LOCAL);
    header.extend_from_slice(&[0u8; 22]);
    push16(&mut header, 1);
    push16(&mut header, 0);
    header.push(b'x');
    let file = header.repeat(300_000);

    let started = std::time::Instant::now();
    let archive = read(&file).unwrap();
    assert_eq!(archive.entries.len(), MAX_ENTRIES);
    assert!(started.elapsed().as_secs() < 15, "took {:?}", started.elapsed());
}

#[test]
fn a_zip_stored_in_a_zip_is_not_a_doctored_archive() {
    // The inner archive's headers and directory sit in the outer file's data, ahead
    // of the outer directory. Neither is the outer archive hiding anything.
    let inner: &'static [u8] = plain().leak();
    let outer = build(
        &[Put::new("inner.zip", inner), Put::new("notes.txt", b"hello")],
        b"",
        b"",
        b"",
    );

    let archive = read(&outer).unwrap();

    let names: Vec<&str> = archive.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["inner.zip", "notes.txt"]);
    assert!(archive.entries.iter().all(|e| !e.undeclared));
    assert!(archive.entries.iter().all(|e| e.disagreement.is_none()));
}

#[test]
fn a_size_claimed_for_compressed_data_does_not_hide_what_follows_it() {
    // Whatever inflates a deflated entry stops where the stream ends, so a size padded
    // out past that says nothing about the header sitting behind it.
    let mut file = build(
        &[
            Put::new("cover.txt", b"not really deflate"),
            Put {
                listed: false,
                ..Put::new(".hidden.txt", b"flag{behind_the_claim}")
            },
        ],
        b"",
        b"",
        b"",
    );
    let directory = bytes::find(&file, 0, CENTRAL).unwrap();
    let claim = (directory as u32).to_le_bytes();
    file[8..10].copy_from_slice(&8u16.to_le_bytes());
    file[18..22].copy_from_slice(&claim);
    file[directory + 10..directory + 12].copy_from_slice(&8u16.to_le_bytes());
    file[directory + 20..directory + 24].copy_from_slice(&claim);

    let archive = read(&file).unwrap();
    let hidden = archive.entries.iter().find(|e| e.name == ".hidden.txt");
    assert!(hidden.is_some_and(|e| e.undeclared), "{:?}", archive.entries);
}

#[test]
fn a_hidden_entry_after_a_stored_zip_is_still_found() {
    let inner: &'static [u8] = plain().leak();
    let mut hidden = Put::new("hidden.txt", b"flag{here}");
    hidden.listed = false;
    let outer = build(&[Put::new("inner.zip", inner), hidden], b"", b"", b"");

    let archive = read(&outer).unwrap();

    let found = archive
        .entries
        .iter()
        .find(|e| e.name == "hidden.txt")
        .unwrap();
    assert!(found.undeclared);
}
