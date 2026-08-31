use super::*;

/// One `N G obj` block to place in a test document.
struct Put {
    number: u32,
    generation: u16,
    body: String,
    /// Left out of the cross-reference table, which is how an object
    /// survives in the file bytes without a reader ever finding it.
    listed: bool,
}

impl Put {
    fn new(number: u32, body: &str) -> Self {
        Self {
            number,
            generation: 0,
            body: body.to_string(),
            listed: true,
        }
    }

    fn unlisted(mut self) -> Self {
        self.listed = false;
        self
    }
}

/// Builds a minimal but genuine PDF: a header, the given objects, a classic
/// cross-reference table listing whichever of them are marked `listed`, and
/// a trailer naming object 1 as the root and object 2 as the info
/// dictionary. Offsets are tracked as the bytes are written rather than
/// computed by hand, the same way `zip::tests::build` tracks local header
/// offsets, since a hand-counted offset is exactly where a fixture goes
/// quietly wrong.
fn build(objects: &[Put]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    let highest = objects.iter().map(|o| o.number).max().unwrap_or(0);

    for object in objects {
        offsets.push((object.number, object.generation, out.len(), object.listed));
        out.extend_from_slice(format!("{} {} obj\n", object.number, object.generation).as_bytes());
        out.extend_from_slice(object.body.as_bytes());
        out.extend_from_slice(b"\nendobj\n");
    }

    let xref_at = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", highest + 1).as_bytes());
    // Each entry is exactly 20 bytes: a 10-digit offset, a space, a 5-digit
    // generation, a space, the keyword, and a 2-byte end-of-line — not a
    // third space before it, which is what `classic_xref`'s fixed-width read
    // actually expects.
    out.extend_from_slice(b"0000000000 65535 f\r\n");
    for number in 1..=highest {
        match offsets.iter().find(|(n, _, _, listed)| *n == number && *listed) {
            Some((_, generation, offset, _)) => {
                out.extend_from_slice(format!("{offset:010} {generation:05} n\r\n").as_bytes());
            }
            None => out.extend_from_slice(b"0000000000 00000 f\r\n"),
        }
    }

    out.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R /Info 2 0 R >>\n", highest + 1).as_bytes(),
    );
    out.extend_from_slice(format!("startxref\n{xref_at}\n%%EOF\n").as_bytes());

    out
}

const CATALOG: &str = "<< /Type/Catalog /Pages 3 0 R >>";
const INFO: &str = "<< /Title (Trawl) /Author (a puzzle setter) >>";

#[test]
fn declines_a_file_that_is_not_a_pdf() {
    assert_eq!(read(b"not a pdf at all"), None);
}

#[test]
fn reads_the_version_from_the_header() {
    let doc = read(&build(&[Put::new(1, CATALOG), Put::new(2, INFO)])).unwrap();
    assert_eq!(doc.version, "1.7");
}

#[test]
fn walks_every_object_regardless_of_the_table() {
    let doc = read(&build(&[
        Put::new(1, CATALOG),
        Put::new(2, INFO),
        Put::new(3, "<< /Type/Pages /Kids [] /Count 0 >>"),
    ]))
    .unwrap();

    assert_eq!(doc.objects.len(), 3);
    assert_eq!(doc.objects[0].kind.as_deref(), Some("Catalog"));
    assert_eq!(doc.objects[2].kind.as_deref(), Some("Pages"));
}

#[test]
fn reads_the_info_dictionary_through_the_trailer() {
    let doc = read(&build(&[Put::new(1, CATALOG), Put::new(2, INFO)])).unwrap();

    assert!(doc.info.contains(&("Title".to_string(), "Trawl".to_string())));
    assert!(doc.info.contains(&("Author".to_string(), "a puzzle setter".to_string())));
}

#[test]
fn unescapes_a_literal_string_with_an_escaped_paren() {
    let dict = "<< /Title (say \\(hello\\) there) >>";
    assert_eq!(literal_field(dict, "Title"), Some("say (hello) there".to_string()));
}

#[test]
fn reports_an_object_the_cross_reference_table_no_longer_lists() {
    let doc = read(&build(&[
        Put::new(1, CATALOG),
        Put::new(2, INFO),
        Put::new(3, "<< /Type/Pages /Kids [] /Count 0 >>").unlisted(),
    ]))
    .unwrap();

    let orphan = doc.objects.iter().find(|o| o.number == 3).unwrap();
    assert!(orphan.orphaned, "object 3 should be unlisted");

    let listed = doc.objects.iter().find(|o| o.number == 1).unwrap();
    assert!(!listed.orphaned, "object 1 is listed and should not be flagged");
}

#[test]
fn counts_more_than_one_eof_as_an_incremental_update() {
    let mut file = build(&[Put::new(1, CATALOG), Put::new(2, INFO)]);
    file.extend_from_slice(&build(&[Put::new(1, CATALOG), Put::new(2, INFO)]));

    let doc = read(&file).unwrap();
    assert_eq!(doc.revisions.len(), 2);
}

#[test]
fn reports_bytes_appended_after_the_last_eof() {
    let mut file = build(&[Put::new(1, CATALOG), Put::new(2, INFO)]);
    // `build` writes its own newline after `%%EOF`, which is a real byte
    // sitting after the marker whatever wrote it, so the count includes it.
    file.extend_from_slice(b"flag{parked_after_the_pdf}");

    let doc = read(&file).unwrap();
    assert_eq!(doc.trailing, 1 + "flag{parked_after_the_pdf}".len());
}

#[test]
fn locates_a_stream_and_its_declared_filter() {
    let body = "<< /Type/XObject /Filter/FlateDecode /Length 4 >>\nstream\nABCD\nendstream";
    let doc = read(&build(&[Put::new(1, CATALOG), Put::new(2, INFO), Put::new(3, body)])).unwrap();

    let object = doc.objects.iter().find(|o| o.number == 3).unwrap();
    let stream = object.stream.as_ref().expect("stream not found");
    assert_eq!(stream.filter, "FlateDecode");
    assert_eq!(stream.length, 4);
}

#[test]
fn finds_an_embedded_file_by_its_subtype() {
    let body = "<< /Type/EmbeddedFile /Subtype/EmbeddedFile /Length 3 >>\nstream\nfoo\nendstream";
    let doc = read(&build(&[Put::new(1, CATALOG), Put::new(2, INFO), Put::new(9, body)])).unwrap();

    assert_eq!(doc.embedded_files, vec![9]);
}

#[test]
fn reports_encryption_from_the_trailer() {
    // Built by hand rather than through `build`, since an /Encrypt entry is a
    // trailer field this fixture generator does not otherwise write.
    let mut file = b"%PDF-1.5\n1 0 obj\n<< /Type/Catalog >>\nendobj\n".to_vec();
    let xref_at = file.len();
    file.extend_from_slice(b"xref\n0 2\n0000000000 65535 f\r\n0000000009 00000 n\r\n");
    file.extend_from_slice(
        b"trailer\n<< /Size 2 /Root 1 0 R /Encrypt 5 0 R /ID [<abc> <abc>] >>\n",
    );
    file.extend_from_slice(format!("startxref\n{xref_at}\n%%EOF\n").as_bytes());

    let doc = read(&file).unwrap();
    assert!(doc.encrypted);
}

#[test]
fn json_output_is_well_formed_with_every_field_populated() {
    // One object of each shape this module reports on: a plain dictionary, a
    // stream with a filter, an unlisted object, and an embedded file, so
    // every optional field in the output is exercised at once rather than
    // trusted by inspection.
    let file = build(&[
        Put::new(1, CATALOG),
        Put::new(2, INFO),
        Put::new(
            3,
            "<< /Type/XObject /Filter/FlateDecode /Length 4 >>\nstream\nABCD\nendstream",
        ),
        Put::new(4, "<< /Type/Pages /Kids [] /Count 0 >>").unlisted(),
        Put::new(
            9,
            "<< /Type/EmbeddedFile /Subtype/EmbeddedFile /Length 3 >>\nstream\nfoo\nendstream",
        ),
    ]);

    let out = json(&file);
    assert!(crate::json::is_well_formed(&out), "malformed JSON: {out}");
}

#[test]
fn json_output_is_well_formed_for_a_file_that_is_not_a_pdf() {
    assert_eq!(json(b"not a pdf"), "null");
    assert!(crate::json::is_well_formed(&json(b"not a pdf")));
}
