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
fn reads_a_type_written_with_a_space_before_the_name() {
    // "/Type/Catalog" with no space is what this file's own fixtures write,
    // but "/Type /Catalog" is what real PDF writers do, and both are valid.
    let doc = read(&build(&[Put::new(1, "<< /Type /Catalog /Pages 2 0 R >>"), Put::new(2, INFO)]))
        .unwrap();

    assert_eq!(doc.objects[0].kind.as_deref(), Some("Catalog"));
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

/// A first revision of three objects, then an incremental update replacing object 3
/// with a table of only what changed, chained back with `/Prev`. Written the way a
/// real incremental save is.
fn incrementally_updated() -> Vec<u8> {
    let entry = |offset: usize, kind: char| format!("{offset:010} 00000 {kind} \n");

    let mut file = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for object in [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n",
        "3 0 obj\n<< /Title (old) >>\nendobj\n",
    ] {
        offsets.push(file.len());
        file.extend_from_slice(object.as_bytes());
    }

    let first_table = file.len();
    file.extend_from_slice(b"xref\n0 4\n");
    file.extend_from_slice(entry(0, 'f').as_bytes());
    for offset in offsets {
        file.extend_from_slice(entry(offset, 'n').as_bytes());
    }
    file.extend_from_slice(
        format!("trailer\n<< /Size 4 /Root 1 0 R /Info 3 0 R >>\nstartxref\n{first_table}\n%%EOF\n")
            .as_bytes(),
    );

    let replaced = file.len();
    file.extend_from_slice(b"3 0 obj\n<< /Title (new) >>\nendobj\n");

    let second_table = file.len();
    file.extend_from_slice(b"xref\n3 1\n");
    file.extend_from_slice(entry(replaced, 'n').as_bytes());
    file.extend_from_slice(
        format!(
            "trailer\n<< /Size 4 /Root 1 0 R /Info 3 0 R /Prev {first_table} >>\nstartxref\n{second_table}\n%%EOF\n"
        )
        .as_bytes(),
    );
    file
}

#[test]
fn an_incremental_update_does_not_orphan_what_it_left_alone() {
    // The last table lists only what changed, so read alone it calls everything else
    // a leftover. Following /Prev says objects 1 and 2 are live, and the old object 3
    // is the only one nothing reaches.
    let doc = read(&incrementally_updated()).unwrap();
    let marks: Vec<(u32, bool)> = doc.objects.iter().map(|o| (o.number, o.orphaned)).collect();
    assert_eq!(marks, vec![(1, false), (2, false), (3, true), (3, false)]);
}

#[test]
fn the_info_dictionary_comes_from_the_live_revision() {
    let doc = read(&incrementally_updated()).unwrap();
    assert!(doc.info.contains(&("Title".to_string(), "new".to_string())), "{:?}", doc.info);
}

#[test]
fn a_prev_chain_that_loops_ends() {
    let mut file = b"%PDF-1.7\n1 0 obj\n<< >>\nendobj\n".to_vec();
    let table = file.len();
    file.extend_from_slice(format!("xref\n1 1\n{:010} 00000 n \n", 9).as_bytes());
    file.extend_from_slice(format!("trailer\n<< /Size 2 /Prev {table} >>\n").as_bytes());
    file.extend_from_slice(format!("startxref\n{table}\n%%EOF\n").as_bytes());

    let doc = read(&file).unwrap();
    assert!(!doc.objects[0].orphaned);
}

#[test]
fn a_prev_pointing_at_nothing_marks_nothing_rather_than_guessing() {
    let mut file = incrementally_updated();
    let text = String::from_utf8_lossy(&file).into_owned();
    let at = text.find("/Prev ").unwrap() + 6;
    file[at] = b'9';
    file[at + 1] = b'9';

    let doc = read(&file).unwrap();
    assert!(doc.objects.iter().all(|o| !o.orphaned));
}

#[test]
fn a_freed_number_stays_freed_whatever_an_older_table_said() {
    let doc = read(&build(&[
        Put::new(1, CATALOG),
        Put::new(2, INFO),
        Put::new(3, "<< /Type/Pages /Kids [] /Count 0 >>").unlisted(),
    ]))
    .unwrap();
    assert!(doc.objects.iter().find(|o| o.number == 3).unwrap().orphaned);
}

#[test]
fn an_offset_pointing_at_the_line_ending_before_an_object_still_counts() {
    let mut file = b"%PDF-1.7\n\n1 0 obj\n<< >>\nendobj\n".to_vec();
    let table = file.len();
    file.extend_from_slice(format!("xref\n1 1\n{:010} 00000 n \n", 9).as_bytes());
    file.extend_from_slice(b"trailer\n<< /Size 2 >>\n");
    file.extend_from_slice(format!("startxref\n{table}\n%%EOF\n").as_bytes());

    assert!(!read(&file).unwrap().objects[0].orphaned);
}

#[test]
fn a_length_in_another_object_is_followed() {
    // Read as a plain number, `/Length 5 0 R` is a stream five bytes long, and inflating
    // that fails.
    let body = "<< /Length 5 0 R /Filter /FlateDecode >>\nstream\nABCDEFGHIJ\nendstream";
    let doc = read(&build(&[Put::new(4, body), Put::new(5, "10")])).unwrap();

    let stream = doc.objects[0].stream.as_ref().unwrap();
    assert_eq!(stream.length, 10);
    assert_eq!(stream.filter, "FlateDecode");
}

#[test]
fn a_length_in_an_earlier_or_later_object_is_found_either_way_round() {
    let body = "<< /Length 5 0 R >>\nstream\nABCDEFGHIJ\nendstream";
    let doc = read(&build(&[Put::new(5, "10"), Put::new(6, body)])).unwrap();
    assert_eq!(doc.objects[1].stream.as_ref().unwrap().length, 10);
}

#[test]
fn a_longer_key_is_not_the_one_asked_for() {
    // /Length1 is a font's own measure, and matching on a prefix gave the stream that.
    let body = "<< /Length1 12 /Length 10 >>\nstream\nABCDEFGHIJ\nendstream";
    let doc = read(&build(&[Put::new(6, body)])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().length, 10);

    assert_eq!(number_field("<< /Length1 12 >>", "Length"), None);
    assert_eq!(name_field("<< /Subtype /Type0 /Type /Font >>", "Type").as_deref(), Some("Font"));
}

#[test]
fn a_key_in_a_nested_dictionary_is_not_this_dictionarys() {
    let body = "<< /DecodeParms << /Length 3 >> /Length 10 >>\nstream\nABCDEFGHIJ\nendstream";
    let doc = read(&build(&[Put::new(6, body)])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().length, 10);
}

#[test]
fn a_key_inside_a_string_or_an_array_is_not_a_key() {
    assert_eq!(number_field("<< /Note (/Length 3) /Length 10 >>", "Length"), Some(10));
    assert_eq!(number_field("<< /Kids [/Length 3] /Length 10 >>", "Length"), Some(10));
}

#[test]
fn a_chain_of_tables_stops_reading_at_a_budget() {
    let file = incrementally_updated();
    let all = live_offsets(&file, usize::MAX).unwrap();
    assert!(!all.is_empty());

    assert_eq!(live_offsets(&file, 1), None);
    assert_eq!(live_offsets(&file, MAX_XREF_ENTRIES), Some(all));
}

#[test]
fn an_unmatched_parenthesis_does_not_hide_the_keys_after_it() {
    assert_eq!(number_field("<< /Note (never closed /Length 10 >>", "Length"), Some(10));

    let dict = format!("<< {} /Length 10 >>", "(".repeat(1 << 18));
    let started = std::time::Instant::now();
    assert_eq!(number_field(&dict, "Length"), Some(10));
    assert!(started.elapsed().as_secs() < 10, "took {:?}", started.elapsed());
}

#[test]
fn a_number_and_a_reference_are_told_apart() {
    assert_eq!(number_or_reference("<< /A 5 0 R >>", "A"), Some(Number::Reference(5)));
    assert_eq!(number_or_reference("<< /A 5 >>", "A"), Some(Number::Direct(5)));
    assert_eq!(number_or_reference("<< /A 5 /B 0 >>", "A"), Some(Number::Direct(5)));
    assert_eq!(number_or_reference("<< /A 5 0 Rx >>", "A"), Some(Number::Direct(5)));
    assert_eq!(number_field("<< /A 5 0 R >>", "A"), None);
    assert_eq!(reference_field("<< /A 5 >>", "A"), None);
    assert_eq!(reference_field("<< /A 99999999999 0 R >>", "A"), None);
}

#[test]
fn a_length_that_lands_nowhere_gives_way_to_the_endstream() {
    // Without the line ending, or an inflate sees junk after the data.
    let body = "<< /Length 5 >>\nstream\nABCDEFGHIJ\r\nendstream";
    let doc = read(&build(&[Put::new(6, body)])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().length, 10);

    let body = "<< >>\nstream\nABCDEFGHIJ\nendstream";
    let doc = read(&build(&[Put::new(6, body)])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().length, 10);

    let body = "<< /Length 0xffff >>\nstream\nABCD\nendstream";
    let doc = read(&build(&[Put::new(6, body)])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().length, 4);
}

#[test]
fn a_length_near_the_top_of_32_bits_is_refused() {
    assert_eq!(stream_length(b"ABCD\nendstream", 0, Some(0xffff_fff8), 5), 4);
    assert_eq!(stream_length(b"ABCD\nendstream", 8, Some(usize::MAX), 8), 0);
}

#[test]
fn a_stream_holding_the_keyword_itself_is_measured_by_its_claim() {
    let inner = "ABendstreamCD";
    let body = format!("<< /Length {} >>\nstream\n{inner}\nendstream", inner.len());
    let doc = read(&build(&[Put::new(6, &body)])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().length, inner.len());
}

#[test]
fn an_array_of_filters_is_read() {
    assert_eq!(filter_field("<< /Filter [/FlateDecode] >>").as_deref(), Some("FlateDecode"));
    assert_eq!(
        filter_field("<< /Filter [ /ASCII85Decode /FlateDecode ] >>").as_deref(),
        Some("ASCII85Decode then FlateDecode")
    );
    assert_eq!(filter_field("<< /Filter /FlateDecode >>").as_deref(), Some("FlateDecode"));
    assert_eq!(filter_field("<< /Length 3 >>"), None);
}

#[test]
fn an_embedded_file_is_found_by_its_type() {
    // The format names one with /Type, and /Subtype holds its MIME type.
    let body = "<< /Type /EmbeddedFile /Subtype /text#2Fplain /Length 3 >>\nstream\nabc\nendstream";
    let doc = read(&build(&[Put::new(7, body)])).unwrap();
    assert_eq!(doc.embedded_files, vec![7]);
}

#[test]
fn a_cross_reference_stream_carries_what_a_trailer_would() {
    // No `trailer` keyword exists in a file like this, so what it would have said was
    // reported as nothing at all.
    let file = b"%PDF-1.7\n9 0 obj\n<< /Type /XRef /Encrypt 8 0 R /Info 3 0 R /Size 10 /W [1 2 1] /Length 1 >>\nstream\na\nendstream\nendobj\n3 0 obj\n<< /Title (secret) >>\nendobj\nstartxref\n9\n%%EOF\n";
    let doc = read(file).unwrap();

    assert!(doc.uses_xref_stream);
    assert!(doc.encrypted);
    assert_eq!(doc.info, vec![("Title".to_string(), "secret".to_string())]);
    assert!(doc.objects.iter().all(|o| !o.orphaned));
}

#[test]
fn a_linearized_trailer_is_asked_when_the_last_says_nothing() {
    let file = b"%PDF-1.5\n1 0 obj\n<< /Title (front) >>\nendobj\ntrailer\n<< /Info 1 0 R >>\ntrailer\n<< /Size 2 >>\n";
    let doc = read(file).unwrap();
    assert_eq!(doc.info, vec![("Title".to_string(), "front".to_string())]);
}

#[test]
fn a_word_mentioning_encrypt_does_not_make_a_document_encrypted() {
    let file = b"%PDF-1.5\n1 0 obj\n<< >>\nendobj\ntrailer\n<< /EncryptNot 1 /Note (/Encrypt) >>\n";
    assert!(!read(file).unwrap().encrypted);
}

#[test]
fn nested_object_headers_do_not_each_keep_the_rest_of_the_file() {
    // Every object's dictionary ran to its matching close, so sixty thousand of them
    // kept twenty gigabytes of text between them.
    let count = 60_000;
    let mut file = b"%PDF-1.7\n".to_vec();
    file.extend_from_slice(&b"1 0 obj<<".repeat(count));
    file.extend_from_slice(&b">>".repeat(count));

    let doc = read(&file).unwrap();
    assert_eq!(doc.objects.len(), count);
    let kept: usize = doc.objects.iter().map(|o| o.dict.len()).sum();
    assert!(kept <= DICT_OVERRUN_TOTAL + file.len(), "kept {kept} bytes");
    assert!(crate::json::is_well_formed(&json(&file)));
}

#[test]
fn unterminated_dictionaries_do_not_each_scan_the_rest_of_the_file() {
    let mut file = b"%PDF-1.7\n".to_vec();
    file.extend_from_slice(&b"1 0 obj<<".repeat(200_000));

    let started = std::time::Instant::now();
    let doc = read(&file).unwrap();
    assert_eq!(doc.objects.len(), 200_000);
    assert!(started.elapsed().as_secs() < 15, "took {:?}", started.elapsed());
}

#[test]
fn streams_with_no_end_do_not_each_scan_the_rest_of_the_file() {
    let mut file = b"%PDF-1.7\n".to_vec();
    file.extend_from_slice(&b"1 0 obj<<>>stream\n".repeat(200_000));

    let started = std::time::Instant::now();
    let doc = read(&file).unwrap();
    assert!(doc.objects.iter().all(|o| o.stream.is_none()));
    assert!(started.elapsed().as_secs() < 15, "took {:?}", started.elapsed());
}

#[test]
fn a_file_of_trailers_does_not_each_scan_the_rest_of_the_file() {
    let mut file = b"%PDF-1.7\n".to_vec();
    file.extend_from_slice(&b"trailer<<".repeat(200_000));

    let started = std::time::Instant::now();
    assert!(read(&file).is_some());
    assert!(started.elapsed().as_secs() < 15, "took {:?}", started.elapsed());
}

#[test]
fn a_file_of_nothing_but_headers_reports_a_bounded_number() {
    let mut file = b"%PDF-1.7\n".to_vec();
    file.extend_from_slice(&b"1 0 obj ".repeat(MAX_OBJECTS + 10));
    assert_eq!(read(&file).unwrap().objects.len(), MAX_OBJECTS);
}

#[test]
fn a_string_reading_like_a_header_does_not_cost_a_real_dictionary() {
    // The allowance past the next header is for exactly this.
    let body = "<< /Title (see 1 0 obj for more) /Length 4 >>\nstream\nABCD\nendstream";
    let doc = read(&build(&[Put::new(5, body)])).unwrap();

    let real = doc.objects.iter().find(|o| o.number == 5).unwrap();
    assert_eq!(real.stream.as_ref().unwrap().length, 4);
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
