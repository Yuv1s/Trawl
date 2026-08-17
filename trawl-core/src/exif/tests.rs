use super::*;

/// Builds a TIFF block little-endian, which is what most cameras write.
struct Tiff {
    entries: Vec<(u16, u16, Vec<u8>)>,
    next_ifd: u32,
}

impl Tiff {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_ifd: 0,
        }
    }

    fn ascii(mut self, tag: u16, text: &str) -> Self {
        let mut value = text.as_bytes().to_vec();
        value.push(0);
        self.entries.push((tag, 2, value));
        self
    }

    fn short(mut self, tag: u16, value: u16) -> Self {
        self.entries.push((tag, 3, value.to_le_bytes().to_vec()));
        self
    }

    fn long(mut self, tag: u16, value: u32) -> Self {
        self.entries.push((tag, 4, value.to_le_bytes().to_vec()));
        self
    }

    fn build(self) -> Vec<u8> {
        let mut out = b"II\x2a\x00".to_vec();
        out.extend_from_slice(&8u32.to_le_bytes());

        let count = self.entries.len();
        let mut heap_at = 8 + 2 + count * 12 + 4;
        let mut heap = Vec::new();

        out.extend_from_slice(&(count as u16).to_le_bytes());

        for (tag, kind, value) in &self.entries {
            let unit = type_size(*kind);
            let values = value.len() / unit;

            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&(values as u32).to_le_bytes());

            if value.len() <= 4 {
                let mut padded = value.clone();
                padded.resize(4, 0);
                out.extend_from_slice(&padded);
            } else {
                out.extend_from_slice(&(heap_at as u32).to_le_bytes());
                heap.extend_from_slice(value);
                heap_at += value.len();
            }
        }

        out.extend_from_slice(&self.next_ifd.to_le_bytes());
        out.extend_from_slice(&heap);
        out
    }
}

fn value_of(entries: &[Entry], name: &str) -> Option<String> {
    entries
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.value.clone())
}

#[test]
fn parse_reads_text_fields() {
    let tiff = Tiff::new()
        .ascii(0x010f, "Canon")
        .ascii(0x0110, "EOS 5D")
        .ascii(0x010e, "flag{hidden_in_the_description}")
        .build();

    let entries = parse(&tiff).unwrap();
    assert_eq!(value_of(&entries, "Make").as_deref(), Some("Canon"));
    assert_eq!(value_of(&entries, "Model").as_deref(), Some("EOS 5D"));
    assert_eq!(
        value_of(&entries, "ImageDescription").as_deref(),
        Some("flag{hidden_in_the_description}")
    );
}

#[test]
fn parse_marks_which_values_are_readable_text() {
    let tiff = Tiff::new().ascii(0x013b, "A Photographer").short(0x0112, 6).build();
    let entries = parse(&tiff).unwrap();

    assert!(entries.iter().find(|e| e.name == "Artist").unwrap().textual);
    assert!(!entries.iter().find(|e| e.name == "Orientation").unwrap().textual);
}

#[test]
fn parse_accepts_big_endian_byte_order() {
    let mut tiff = b"MM\x00\x2a".to_vec();
    tiff.extend_from_slice(&8u32.to_be_bytes());
    tiff.extend_from_slice(&1u16.to_be_bytes());
    tiff.extend_from_slice(&0x0110u16.to_be_bytes());
    tiff.extend_from_slice(&3u16.to_be_bytes());
    tiff.extend_from_slice(&1u32.to_be_bytes());
    tiff.extend_from_slice(&[0x01, 0x2c, 0, 0]);
    tiff.extend_from_slice(&0u32.to_be_bytes());

    let entries = parse(&tiff).unwrap();
    assert_eq!(entries[0].value, "300");
}

/// Built byte by byte with absolute offsets, because every offset in this format
/// is relative to the TIFF header rather than to the directory holding it. A
/// sub-directory assembled in isolation and pasted in carries the wrong ones.
#[test]
fn parse_follows_the_pointer_into_the_exif_sub_directory() {
    const SUB: u32 = 26; // after the header, IFD0's single entry, and its next pointer
    const HEAP: u32 = SUB + 2 + 12 + 4;
    let comment = b"flag{in_the_sub_ifd}\0";

    let mut tiff = b"II\x2a\x00".to_vec();
    tiff.extend_from_slice(&8u32.to_le_bytes());

    tiff.extend_from_slice(&1u16.to_le_bytes());
    tiff.extend_from_slice(&0x8769u16.to_le_bytes()); // ExifIFDPointer
    tiff.extend_from_slice(&4u16.to_le_bytes()); // LONG
    tiff.extend_from_slice(&1u32.to_le_bytes());
    tiff.extend_from_slice(&SUB.to_le_bytes());
    tiff.extend_from_slice(&0u32.to_le_bytes());

    assert_eq!(tiff.len(), SUB as usize, "sub-IFD must start where IFD0 says");

    tiff.extend_from_slice(&1u16.to_le_bytes());
    tiff.extend_from_slice(&0x9286u16.to_le_bytes()); // UserComment
    tiff.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    tiff.extend_from_slice(&(comment.len() as u32).to_le_bytes());
    tiff.extend_from_slice(&HEAP.to_le_bytes());
    tiff.extend_from_slice(&0u32.to_le_bytes());

    assert_eq!(tiff.len(), HEAP as usize, "value must start where the entry says");
    tiff.extend_from_slice(comment);

    let entries = parse(&tiff).unwrap();
    let found = entries.iter().find(|e| e.name == "UserComment").unwrap();
    assert_eq!(found.value, "flag{in_the_sub_ifd}");
    assert_eq!(found.ifd, "EXIF");
}

#[test]
fn parse_rejects_a_block_with_no_byte_order_mark() {
    assert_eq!(parse(b"XX\x2a\x00\x08\x00\x00\x00"), Err(ExifError::BadByteOrder));
    assert_eq!(parse(b"II\x00\x00\x08\x00\x00\x00"), Err(ExifError::BadMagic));
    assert_eq!(parse(b"II"), Err(ExifError::NoHeader));
}

/// Every offset in this format is attacker-controlled, so a directory pointing
/// at itself has to terminate rather than recurse forever.
#[test]
fn a_directory_that_points_at_itself_terminates() {
    let mut tiff = b"II\x2a\x00".to_vec();
    tiff.extend_from_slice(&8u32.to_le_bytes());
    tiff.extend_from_slice(&1u16.to_le_bytes());
    tiff.extend_from_slice(&0x0110u16.to_le_bytes());
    tiff.extend_from_slice(&3u16.to_le_bytes());
    tiff.extend_from_slice(&1u32.to_le_bytes());
    tiff.extend_from_slice(&[1, 0, 0, 0]);
    tiff.extend_from_slice(&8u32.to_le_bytes()); // next IFD is this IFD

    let entries = parse(&tiff).unwrap();
    assert_eq!(entries.len(), 1);
}

#[test]
fn an_entry_pointing_past_the_end_is_skipped_not_read() {
    let mut tiff = b"II\x2a\x00".to_vec();
    tiff.extend_from_slice(&8u32.to_le_bytes());
    tiff.extend_from_slice(&1u16.to_le_bytes());
    tiff.extend_from_slice(&0x010eu16.to_le_bytes());
    tiff.extend_from_slice(&2u16.to_le_bytes());
    tiff.extend_from_slice(&1000u32.to_le_bytes());
    tiff.extend_from_slice(&0xffff_0000u32.to_le_bytes());
    tiff.extend_from_slice(&0u32.to_le_bytes());

    assert!(parse(&tiff).unwrap().is_empty());
}

#[test]
fn a_truncated_block_does_not_panic() {
    let tiff = Tiff::new()
        .ascii(0x010e, "a reasonably long description field")
        .long(0x011a, 72)
        .build();

    for cut in 0..tiff.len() {
        let _ = parse(&tiff[..cut]);
    }
}

#[test]
fn json_carries_every_field_the_ui_needs() {
    let tiff = Tiff::new().ascii(0x0131, "Trawl").build();
    let text = json(&parse(&tiff).unwrap());

    assert!(text.starts_with('[') && text.ends_with(']'));
    for key in ["\"ifd\"", "\"tag\"", "\"name\"", "\"value\"", "\"textual\""] {
        assert!(text.contains(key), "{key} missing from {text}");
    }
}
