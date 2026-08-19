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
