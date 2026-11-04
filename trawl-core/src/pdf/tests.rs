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
fn an_object_header_can_be_split_by_any_whitespace() {
    for header in ["1 0\nobj", "1\t0\tobj", "1\r\n0\r\nobj", "1  0  obj", "1\x000 obj", "1 0\x0cobj"] {
        let file = format!("%PDF-1.7\n{header}\n<< /Length 4 >>\nstream\nABCD\nendstream\nendobj\n");
        let doc = read(file.as_bytes()).unwrap();

        assert_eq!(doc.objects.len(), 1, "{header:?}");
        assert_eq!(doc.objects[0].number, 1);
        assert_eq!(doc.objects[0].generation, 0);
        assert_eq!(doc.objects[0].offset, 9);
        assert_eq!(doc.objects[0].stream.as_ref().unwrap().length, 4, "{header:?}");
    }
}

#[test]
fn only_the_keyword_itself_opens_an_object() {
    for text in ["1 0 object", "1 0 objx", "endobj", "x 0 obj", "1 x obj", "obj"] {
        let file = format!("%PDF-1.7\n{text}\n");
        assert!(read(file.as_bytes()).unwrap().objects.is_empty(), "{text:?}");
    }
}

#[test]
fn a_close_inside_a_string_does_not_end_the_dictionary() {
    for dict in [
        "<< /Title (>>) /Filter /FlateDecode /Length 4 >>",
        "<< /Title (a \\) >> b) /Filter /FlateDecode /Length 4 >>",
        "<< /Title (nested (>>) still) /Filter /FlateDecode /Length 4 >>",
        "<< /Note <3E3E> /Filter /FlateDecode /Length 4 >>",
        "<< /Note <AB>/Filter /FlateDecode /Length 4 >>",
        "<< /Note 1 %>> not yet\n/Filter /FlateDecode /Length 4 >>",
    ] {
        let body = format!("{dict}\nstream\nABCD\nendstream");
        let doc = read(&build(&[Put::new(1, &body)])).unwrap();
        let stream = doc.objects[0].stream.as_ref().unwrap_or_else(|| panic!("{dict}"));
        assert_eq!(stream.filter, "FlateDecode", "{dict}");
        assert_eq!(stream.length, 4, "{dict}");
    }
}

#[test]
fn a_hex_string_up_against_the_close_is_read_as_one() {
    let doc = read(&build(&[Put::new(1, "<< /ID <AB>>>\nstream\nABCD\nendstream")])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().length, 4);
}

#[test]
fn a_string_that_never_closes_leaves_the_dictionary_to_be_read_anyway() {
    let doc = read(&build(&[Put::new(1, "<< /Note (open /Length 4 >>\nstream\nABCD\nendstream")])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().length, 4);

    let mut file = b"%PDF-1.7\n1 0 obj<<".to_vec();
    file.extend_from_slice(&b"(".repeat(1 << 20));
    file.extend_from_slice(&b"<".repeat(1 << 20));
    file.extend_from_slice(b">>");
    let started = std::time::Instant::now();
    assert!(read(&file).is_some());
    assert!(started.elapsed().as_secs() < 10, "took {:?}", started.elapsed());
}

#[test]
fn name_escapes_are_undone_wherever_they_turn_up() {
    let doc = read(&build(&[Put::new(
        1,
        "<< /Fil#74er /Fl#61teDecode /Ty#70e /XOb#6Aect /Length 4 >>\nstream\nABCD\nendstream",
    )]))
    .unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().filter, "FlateDecode");
    assert_eq!(doc.objects[0].kind.as_deref(), Some("XObject"));

    assert_eq!(unescape_name("plain"), "plain");
    assert_eq!(unescape_name("a#20b"), "a b");
    assert_eq!(unescape_name("not#zzhex#"), "not#zzhex#");
}

#[test]
fn a_filter_in_another_object_is_followed() {
    let body = "<< /Filter 5 0 R /Length 4 >>\nstream\nABCD\nendstream";
    let doc = read(&build(&[Put::new(4, body), Put::new(5, "/FlateDecode")])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().filter, "FlateDecode");

    let doc = read(&build(&[Put::new(5, "[/AHx /Fl]"), Put::new(6, "<< /Filter 5 0 R >>\nstream\nAB\nendstream")])).unwrap();
    assert_eq!(doc.objects[1].stream.as_ref().unwrap().filter, "ASCIIHexDecode then FlateDecode");
}

#[test]
fn the_short_names_an_inline_image_uses_read_as_the_long_ones() {
    for (short, long) in [
        ("Fl", "FlateDecode"),
        ("AHx", "ASCIIHexDecode"),
        ("A85", "ASCII85Decode"),
        ("LZW", "LZWDecode"),
        ("RL", "RunLengthDecode"),
        ("DCT", "DCTDecode"),
        ("CCF", "CCITTFaxDecode"),
    ] {
        let body = format!("<< /Filter /{short} >>\nstream\nAB\nendstream");
        let doc = read(&build(&[Put::new(4, &body)])).unwrap();
        assert_eq!(doc.objects[0].stream.as_ref().unwrap().filter, long);
    }
}

#[test]
fn a_filter_array_can_point_at_its_names() {
    let body = "<< /Length 4 /Filter [7 0 R /ASCIIHexDecode] >>\nstream\nABCD\nendstream";
    let doc = read(&build(&[Put::new(4, body), Put::new(7, "/FlateDecode")])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().filter, "FlateDecode then ASCIIHexDecode");
}

#[test]
fn a_filter_array_element_that_cannot_be_resolved_is_reported() {
    let body = "<< /Length 4 /Filter [99 0 R] >>\nstream\nABCD\nendstream";
    let doc = read(&build(&[Put::new(4, body)])).unwrap();

    let filter = &doc.objects[0].stream.as_ref().unwrap().filter;
    assert_eq!(filter, UNRESOLVED_FILTER);

    let found = decode_stream(b"ABCD", filter, 1 << 20);
    assert!(found.error.is_some_and(|said| said.contains(UNRESOLVED_FILTER)));
}

#[test]
fn a_comment_does_not_hide_a_filter() {
    for dict in [
        "<< /Filter [%c\n/FlateDecode] /Length 4 >>",
        "<< /Filter [%c ] d\n/FlateDecode] /Length 4 >>",
        "<< /Filter %c d\n/FlateDecode /Length 4 >>",
        "<< /Filter %c\n7 0 R /Length 4 >>",
        "<< /Filter [%c\n7 0 R] /Length 4 >>",
    ] {
        let body = format!("{dict}\nstream\nABCD\nendstream");
        let doc = read(&build(&[Put::new(4, &body), Put::new(7, "/FlateDecode")])).unwrap();
        assert_eq!(doc.objects[0].stream.as_ref().unwrap().filter, "FlateDecode", "{dict}");
    }

    let body = "<< /Filter %c\n/FlateDecode /DecodeParms << /Predictor %c\n12 /Columns 4 >> /Length 4 >>\nstream\nABCD\nendstream";
    let doc = read(&build(&[Put::new(4, body)])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().filter, "FlateDecode predictor=12 columns=4");
}

#[test]
fn a_percent_sign_in_a_string_is_not_a_comment() {
    for dict in [
        "<< /Title (100%) /Filter /FlateDecode /Length 4 >>",
        "<< /Title (a \\) 100%) /Filter /FlateDecode /Length 4 >>",
        "<< /Title (a (b) 100%) /Filter /FlateDecode /Length 4 >>",
    ] {
        let body = format!("{dict}\nstream\nABCD\nendstream");
        let doc = read(&build(&[Put::new(4, &body)])).unwrap();
        assert_eq!(doc.objects[0].stream.as_ref().unwrap().filter, "FlateDecode", "{dict}");
    }
}

#[test]
fn the_last_filter_a_dictionary_gives_is_the_one_read() {
    for dict in [
        "<< /Filter /DCTDecode /Filter /FlateDecode /Length 4 >>",
        "<< /Filter /ASCIIHexDecode /Filter /FlateDecode /Length 4 >>",
        "<< /Foo /Filter /Filter /FlateDecode /Length 4 >>",
        "<< /Length 4 /Filter /FlateDecode /Foo /Filter >>",
        // Names sitting where a value belongs, whatever they spell.
        "<< /Length 4 /Filter /FlateDecode /A /Filter /DCTDecode /B >>",
        "<< /Length 4 /A /Filter /B /F /Filter /FlateDecode >>",
        "<< /Length 4 /Filter /FlateDecode /A [ /Filter /DCTDecode ] >>",
        "<< /Length 4 /Filter /FlateDecode /A << /Filter /DCTDecode >> >>",
        "<< /Length 4 /Filter /FlateDecode /A (/Filter /DCTDecode) >>",
        "<< /Length 4 /Filter /FlateDecode /A <2F46> /B 5 0 R /C true /D null >>",
        // A NUL is whitespace to a reader.
        "<< /Length 4 /Filter\0/FlateDecode >>",
    ] {
        let body = format!("{dict}\nstream\nABCD\nendstream");
        let doc = read(&build(&[Put::new(4, &body)])).unwrap();
        assert_eq!(doc.objects[0].stream.as_ref().unwrap().filter, "FlateDecode", "{dict}");
    }
}

#[test]
fn a_name_where_a_value_belongs_is_not_a_filter() {
    let doc = read(&build(&[Put::new(4, "<< /Length 4 /Foo /Filter /Bar /DCTDecode >>\nstream\nABCD\nendstream")])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().filter, "");
}

#[test]
fn a_value_is_stepped_over_whatever_follows_it() {
    for dict in [
        "<< /A 5 0 R /Filter /FlateDecode >>",
        "<< /A 5 /Filter /FlateDecode >>",
        "<< /A 5 0 /Filter /FlateDecode >>",
        "<< /A 5\n\t0\r\nR/Filter /FlateDecode >>",
        "<< /A 12345678901234567890123456789012345678901234567890 é /Filter /FlateDecode >>",
    ] {
        assert_eq!(filter_field(dict).as_deref(), Some("FlateDecode"), "{dict}");
    }
}

#[test]
fn deep_nesting_does_not_run_out_the_stack() {
    let dict = format!("<< /A {} /Filter /FlateDecode >>", "[".repeat(1 << 20));
    assert_eq!(field(&dict, "Filter"), None, "the array never closes, so to a reader this is all the array");

    let dict = format!("<< /A {}{} /Filter /FlateDecode >>", "[".repeat(1 << 20), "]".repeat(1 << 20));
    assert_eq!(filter_field(&dict).as_deref(), Some("FlateDecode"));
}

#[test]
fn the_last_of_a_repeated_parameter_is_the_one_read() {
    for parms in [
        "/DecodeParms << /Predictor 1 /Predictor 12 /Columns 4 >>",
        "/DecodeParms << /Predictor 3 >> /DecodeParms << /Predictor 12 /Columns 4 >>",
        "/DecodeParms << /Predictor 12 /Columns 4 >> /Foo /DecodeParms /Bar 1",
    ] {
        let body = format!("<< /Filter /FlateDecode {parms} /Length 4 >>\nstream\nABCD\nendstream");
        let doc = read(&build(&[Put::new(4, &body)])).unwrap();
        assert_eq!(
            doc.objects[0].stream.as_ref().unwrap().filter,
            "FlateDecode predictor=12 columns=4",
            "{parms}"
        );
    }
}

#[test]
fn streams_the_caller_is_not_told_about_are_counted() {
    let puts: Vec<Put> = (0..MAX_OBJECTS_LISTED as u32 + 3)
        .map(|number| Put::new(number + 1, "<< /Length 1 >>\nstream\nA\nendstream"))
        .collect();
    let file = build(&puts);

    let reading = json(&file);
    assert!(reading.contains(r#""streamsUnlisted":3,"#), "{}", &reading[..200]);
    assert!(reading.contains(r#""objectsCapped":false"#));

    let small = json(&build(&[Put::new(1, "<< /Length 1 >>\nstream\nA\nendstream")]));
    assert!(small.contains(r#""streamsUnlisted":0,"#));
}

#[test]
fn a_filter_can_go_by_its_short_key() {
    assert_eq!(filter_field("<< /F /FlateDecode >>").as_deref(), Some("FlateDecode"));
    assert_eq!(filter_field("<< /F (a file.bin) >>"), None);
}

fn filter_field(dict: &str) -> Option<String> {
    filter_of(dict, &|_| None)
}

/// Data in a zlib wrapper, in one stored block.
fn stored_zlib(data: &[u8]) -> Vec<u8> {
    let length = data.len() as u16;
    let mut out = vec![0x78, 0x01, 1];
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&(!length).to_le_bytes());
    out.extend_from_slice(data);

    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    out.extend_from_slice(&(b << 16 | a).to_be_bytes());
    out
}

/// Text the way a PNG predictor leaves it, with the Sub filter on every row.
fn png_sub(text: &[u8], columns: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for row in text.chunks(columns) {
        out.push(1);
        let mut left = 0u8;
        for &byte in row {
            out.push(byte.wrapping_sub(left));
            left = byte;
        }
    }
    out
}

#[test]
fn a_png_predictor_is_undone() {
    let text = b"BT (flag{predictor_hides_this}) Tj ET";
    let zlib = stored_zlib(&png_sub(text, 8));

    let found = decode_stream(&zlib, "FlateDecode predictor=11 columns=8", 1 << 20);
    assert_eq!(found.error, None);
    assert!(found.output.starts_with(text), "{:?}", String::from_utf8_lossy(&found.output));

    let plain = decode_stream(&zlib, "FlateDecode", 1 << 20);
    assert!(!plain.output.starts_with(text), "the predictor is what was hiding it");
}

#[test]
fn a_tiff_predictor_is_undone() {
    let text = b"flag{tiff_style}";
    let mut held = text.to_vec();
    for at in (1..held.len()).rev() {
        held[at] = held[at].wrapping_sub(held[at - 1]);
    }

    let found = decode_stream(&stored_zlib(&held), &format!("FlateDecode predictor=2 columns={}", text.len()), 1 << 20);
    assert_eq!(found.error, None);
    assert_eq!(found.output, text);
}

#[test]
fn a_predictor_that_cannot_be_undone_says_so_and_keeps_the_data() {
    for filter in [
        "FlateDecode predictor=7 columns=2",
        "FlateDecode predictor=12 columns=4294967295 colors=4294967295",
        "FlateDecode predictor=2 bits=4 columns=2",
    ] {
        let found = decode_stream(&stored_zlib(b"abcdefgh"), filter, 1 << 20);
        assert!(found.error.is_some_and(|said| said.contains("predictor")), "{filter}");
        assert_eq!(found.output, b"abcdefgh", "{filter}");
    }
}

#[test]
fn decode_parms_reach_the_filter_they_belong_to() {
    let dict = "<< /Filter [/ASCIIHexDecode /FlateDecode] /DecodeParms [null << /Predictor 12 /Columns 4 >>] /Length 4 >>";
    let body = format!("{dict}\nstream\nABCD\nendstream");
    let doc = read(&build(&[Put::new(4, &body)])).unwrap();
    assert_eq!(
        doc.objects[0].stream.as_ref().unwrap().filter,
        "ASCIIHexDecode then FlateDecode predictor=12 columns=4"
    );

    let body = "<< /Filter /FlateDecode /DecodeParms 8 0 R /Length 4 >>\nstream\nABCD\nendstream";
    let held = "<< /Predictor 9 0 R /Columns 3 >>";
    let doc = read(&build(&[Put::new(4, body), Put::new(8, held), Put::new(9, "15")])).unwrap();
    assert_eq!(doc.objects[0].stream.as_ref().unwrap().filter, "FlateDecode predictor=15 columns=3");
}

#[test]
fn an_adobe_opening_on_ascii85_is_no_part_of_the_data() {
    let found = decode_stream(b"<~87cURD]i,\"Ebo80~>", "ASCII85Decode", 1 << 20);
    assert_eq!(found.output, b"Hello World!");
}

#[test]
fn lzw_widens_a_code_later_when_a_stream_says_to() {
    // A clear, then more than 253 literals, the last few at ten bits with early change off.
    let (mut hold, mut bits, mut out) = (0u32, 0u32, Vec::new());
    let mut put = |code: u32, width: u32, out: &mut Vec<u8>| {
        hold = (hold << width) | code;
        bits += width;
        while bits >= 8 {
            bits -= 8;
            out.push((hold >> bits) as u8);
        }
    };

    put(256, 9, &mut out);
    let text: Vec<u8> = (0..260u32).map(|i| b'a' + (i % 26) as u8).collect();
    for (index, &byte) in text.iter().enumerate() {
        // Each code after the first adds an entry, so the next code to be defined is 258
        // plus how many went before, and it widens once that passes 511 with no early change.
        let width = if 258 + index > 512 { 10 } else { 9 };
        put(byte as u32, width, &mut out);
    }
    put(257, 10, &mut out);
    put(0, 7, &mut out);

    let found = decode_stream(&out, "LZWDecode early=0", 1 << 20);
    assert_eq!(found.error, None);
    assert_eq!(found.output, text);
}

#[test]
fn a_table_that_cannot_be_read_says_so() {
    let doc = read(b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer<</Size 2>>\n%%EOF\n").unwrap();
    assert!(doc.xref_unread);
    assert!(!doc.objects[0].orphaned);
}

#[test]
fn an_offset_past_32_bits_does_not_cost_the_rest_of_the_table() {
    let body = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n2 0 obj\n<<>>\nendobj\n";
    let mut file = body.to_vec();
    let xref = file.len();
    file.extend_from_slice(b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n");
    file.extend_from_slice(b"3 1\n9999999999 00000 n \n");
    file.extend_from_slice(format!("trailer<</Size 4>>\nstartxref\n{xref}\n%%EOF\n").as_bytes());

    let doc = read(&file).unwrap();
    assert!(!doc.xref_unread);
    assert!(!doc.objects[0].orphaned, "the table names it");
    assert!(doc.objects[1].orphaned, "the table does not");
}

#[test]
fn a_chain_longer_than_the_limit_says_so() {
    let mut layered = b"flag{under_nine_layers}".to_vec();
    for _ in 0..9 {
        layered = layered.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect();
    }

    let eight = ["ASCIIHexDecode"; 8].join(" then ");
    let found = decode_stream(&layered, &eight, 1 << 20);
    assert_eq!(found.error, None);

    let nine = ["ASCIIHexDecode"; 9].join(" then ");
    let found = decode_stream(&layered, &nine, 1 << 20);
    assert!(found.error.as_deref().is_some_and(|said| said.contains("9 filters")), "{:?}", found.error);
    assert!(!found.output.is_empty(), "what came out of the eight is kept");
}

#[test]
fn every_filter_in_a_chain_is_undone_in_order() {
    let zlib = {
        // A stored block, so the test does not need a compressor.
        let text = b"flag{through_the_chain}";
        let mut out = vec![0x78, 0x01, 0x01];
        out.extend_from_slice(&(text.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(text.len() as u16)).to_le_bytes());
        out.extend_from_slice(text);
        let adler = text
            .iter()
            .fold((1u32, 0u32), |(a, b), &byte| {
                let a = (a + byte as u32) % 65521;
                (a, (b + a) % 65521)
            });
        out.extend_from_slice(&(adler.1 << 16 | adler.0).to_be_bytes());
        out
    };

    let hex: String = zlib.iter().map(|b| format!("{b:02x}")).collect();
    let found = decode_stream(format!("{hex} >").as_bytes(), "ASCIIHexDecode then FlateDecode", 1 << 20);
    assert_eq!(found.error, None);
    assert_eq!(found.output, b"flag{through_the_chain}");

    let found = decode_stream(&zlib, "FlateDecode", 1 << 20);
    assert_eq!(found.output, b"flag{through_the_chain}");
}

#[test]
fn ascii85_reads_the_way_its_definition_says() {
    // "Man " and "sure" are the textbook example, and the tail covers a short group.
    let found = decode_stream(b"9jqo^F*2M7/c~>", "ASCII85Decode", 1 << 20);
    assert_eq!(found.error, None);
    assert_eq!(found.output, b"Man sure.");

    let found = decode_stream(b"z 9jqo^~>", "ASCII85Decode", 1 << 20);
    assert_eq!(found.output, b"\0\0\0\0Man ");

    let found = decode_stream(b"9jqo^\x7f", "ASCII85Decode", 1 << 20);
    assert_eq!(found.output, b"Man ");
    assert!(found.error.is_some());
}

#[test]
fn run_length_reads_the_way_its_definition_says() {
    let found = decode_stream(&[2, b'a', b'b', b'c', 254, b'z', 128, 9, 9], "RunLengthDecode", 1 << 20);
    assert_eq!(found.error, None);
    assert_eq!(found.output, b"abczzz");

    let found = decode_stream(&[129, b'z'], "RunLengthDecode", 10);
    assert_eq!(found.output, vec![b'z'; 10]);
    assert!(found.capped);

    let found = decode_stream(&[5, b'a'], "RunLengthDecode", 10);
    assert_eq!(found.output, b"a");
    assert!(found.error.is_some());
}

#[test]
fn lzw_reads_what_a_pdf_writer_writes() {
    // The worked example from the format's own specification: -----A---B.
    let packed = [0x80, 0x0b, 0x60, 0x50, 0x22, 0x0c, 0x0c, 0x85, 0x01];
    let found = decode_stream(&packed, "LZWDecode", 1 << 20);
    assert_eq!(found.error, None);
    assert_eq!(found.output, [45, 45, 45, 45, 45, 65, 45, 45, 45, 66]);

    let found = decode_stream(&packed, "LZWDecode", 4);
    assert!(found.capped);
    assert!(found.output.len() <= 5);
}

#[test]
fn a_filter_this_cannot_read_stops_the_chain_and_says_which() {
    let found = decode_stream(b"41 42>", "ASCIIHexDecode then DCTDecode", 1 << 20);
    assert_eq!(found.output, b"AB");
    assert!(found.error.unwrap().contains("DCTDecode"));
}

#[test]
fn a_chain_keeps_what_the_failing_filter_managed() {
    // Hex digits, then one that is not.
    let found = decode_stream(b"4142zz", "ASCIIHexDecode then FlateDecode", 1 << 20);
    assert_eq!(found.output, b"AB");
    assert!(found.error.is_some());
}

#[test]
fn objects_that_say_nothing_are_not_all_listed_and_the_rest_are() {
    let mut file = b"%PDF-1.7\n".to_vec();
    file.extend_from_slice(&b"1 0 obj\n".repeat(MAX_PLAIN_OBJECTS_LISTED + 500));
    file.extend_from_slice(b"7 0 obj\n<< /Filter /FlateDecode /Length 4 >>\nstream\nABCD\nendstream\nendobj\n");

    let text = json(&file);
    assert!(crate::json::is_well_formed(&text));
    assert!(text.contains(&format!("\"objectCount\":{}", MAX_PLAIN_OBJECTS_LISTED + 501)));
    assert_eq!(text.matches("\"orphaned\":").count(), MAX_PLAIN_OBJECTS_LISTED + 1);
    assert!(text.contains("\"filter\":\"FlateDecode\""), "the stream past them is still there");
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
