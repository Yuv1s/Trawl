use super::*;

fn seg(marker: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0xff, marker];
    out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A structurally valid JPEG. It will not decode to a picture, which does not
/// matter: this module reads structure and never touches the image.
fn build(extra: &[Vec<u8>], scan: &[u8], trailing: &[u8]) -> Vec<u8> {
    let mut sof = vec![8]; // sample precision
    sof.extend_from_slice(&200u16.to_be_bytes()); // height
    sof.extend_from_slice(&320u16.to_be_bytes()); // width
    sof.push(1);
    sof.extend_from_slice(&[1, 0x11, 0]);

    let mut file = vec![0xff, 0xd8];
    for part in extra {
        file.extend_from_slice(part);
    }
    file.extend_from_slice(&seg(0xdb, &[0u8; 65]));
    file.extend_from_slice(&seg(0xc0, &sof));
    file.extend_from_slice(&seg(0xc4, &[0u8; 29]));
    file.extend_from_slice(&seg(0xda, &[1, 1, 0x00, 0, 63, 0]));
    file.extend_from_slice(scan);
    file.extend_from_slice(&[0xff, 0xd9]);
    file.extend_from_slice(trailing);
    file
}

#[test]
fn has_signature_only_accepts_soi() {
    assert!(has_signature(&[0xff, 0xd8, 0xff, 0xe0]));
    assert!(!has_signature(b"\x89PNG\r\n\x1a\n"));
    assert!(!has_signature(&[]));
}

#[test]
fn segments_walks_a_whole_file_in_order() {
    let file = build(&[seg(0xe0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0")], &[0u8; 64], &[]);
    let found = segments(&file);

    let names: Vec<&str> = found.iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        vec!["SOI", "APP0 JFIF", "DQT", "SOF0 baseline", "DHT", "SOS", "EOI"]
    );
    assert_eq!(found[0].offset, 0);
}

/// Scan data carries no length. A literal 0xFF inside it is stuffed as FF 00,
/// and restart markers appear legitimately; both must be walked past.
#[test]
fn segments_skips_stuffed_bytes_and_restart_markers_in_scan_data() {
    let scan = [0x12, 0xff, 0x00, 0x34, 0xff, 0xd0, 0x56, 0xff, 0x00, 0x78];
    let file = build(&[], &scan, &[]);
    let found = segments(&file);

    assert_eq!(found.last().unwrap().name, "EOI");
    assert_eq!(found.iter().filter(|s| s.name == "EOI").count(), 1);
}

#[test]
fn comments_are_read_as_text() {
    let file = build(&[seg(0xfe, b"flag{in_a_jpeg_comment}")], &[0u8; 16], &[]);
    let found = comments(&file);

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, "flag{in_a_jpeg_comment}");
}

#[test]
fn dimensions_come_from_the_start_of_frame() {
    let file = build(&[], &[0u8; 16], &[]);
    assert_eq!(dimensions(&file), Some((320, 200)));
}

#[test]
fn trailing_finds_bytes_after_the_end_marker() {
    let file = build(&[], &[0u8; 16], b"PK\x03\x04stowaway");
    let (offset, length) = trailing(&file).unwrap();

    assert_eq!(length, 12);
    assert_eq!(&file[offset..offset + 2], b"PK");
    assert_eq!(trailing(&build(&[], &[0u8; 16], &[])), None);
}

#[test]
fn exif_payload_is_the_tiff_block_after_the_app1_prefix() {
    let mut app1 = b"Exif\0\0".to_vec();
    app1.extend_from_slice(b"II\x2a\x00\x08\x00\x00\x00");

    let file = build(&[seg(0xe1, &app1)], &[0u8; 16], &[]);
    assert_eq!(exif_payload(&file), Some(&b"II\x2a\x00\x08\x00\x00\x00"[..]));
}

#[test]
fn exif_payload_ignores_an_app1_that_is_not_exif() {
    let file = build(&[seg(0xe1, b"http://ns.adobe.com/xap/1.0/\0xmp")], &[0u8; 16], &[]);
    assert_eq!(exif_payload(&file), None);
}

#[test]
fn a_length_field_that_overruns_the_file_stops_the_walk_without_panicking() {
    let mut file = vec![0xff, 0xd8, 0xff, 0xe1];
    file.extend_from_slice(&0xffffu16.to_be_bytes());
    file.extend_from_slice(b"short");

    let found = segments(&file);
    assert_eq!(found.len(), 2, "SOI and the liar");
    assert_eq!(found[1].name, "APP1 EXIF or XMP");
}

#[test]
fn segments_returns_nothing_for_a_file_that_is_not_a_jpeg() {
    assert!(segments(b"\x89PNG\r\n\x1a\n").is_empty());
    assert!(segments(&[]).is_empty());
}

#[test]
fn a_truncated_file_does_not_panic() {
    let file = build(&[seg(0xfe, b"comment")], &[0u8; 32], &[]);
    for cut in 0..file.len() {
        let _ = segments(&file[..cut]);
        let _ = dimensions(&file[..cut]);
        let _ = trailing(&file[..cut]);
    }
}
