use super::*;

const UNLIMITED: usize = 1 << 30;

/// What Node's zlib made of `dynamic_text()` at level 9: one dynamic block.
const DYNAMIC: &str = "add74d4ec3301040e13da7f0015878feec84cb54699a96d0b481428182b83b02e50679eb91deea933d338de721e587f4f638a497ebd81fd3f6327f9cd37efe4c4fd7d3f36b9adf87cbff78eabe6e69371feed37eea0edfbbdbb93b8dfd663bcdfd71937feea6bf94ac4fc992d2f5295d52b63e654bcad7a77c49c5fa542ca9b23e559654e530341c8696c32099d320c27110e53c887120c4c1e72138125240131534d180265ace8466ce840a674215fc338c33a1ce99d0e04c68014d54d044039a68391396c145423813a69c0933ce843967c282336105345141130d68a2e54c78e64cb870265c39136e9c0977ce8407787114d044054d34a089963311993311c29908e54c848167a873262238135140131534d180265ac4c42f";

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

fn dynamic_text() -> Vec<u8> {
    (0..60)
        .map(|i| {
            format!(
                "line {i}: the quick brown fox jumps over the lazy dog, flag{{dynamic_block_{}}}\n",
                i % 7
            )
        })
        .collect::<String>()
        .into_bytes()
}

/// A zlib stream around one or more stored blocks, valid in every way, so a test can
/// break exactly one thing about it.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let mut blocks = data.chunks(65_535).peekable();
    if data.is_empty() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    while let Some(block) = blocks.next() {
        out.push(u8::from(blocks.peek().is_none()));
        out.extend_from_slice(&(block.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(block.len() as u16)).to_le_bytes());
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// Writes deflate's own bit order, for hand-built fixed-Huffman blocks.
struct Writer {
    out: Vec<u8>,
    acc: u32,
    bits: u32,
}

impl Writer {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            acc: 0,
            bits: 0,
        }
    }

    fn put(&mut self, value: u32, count: u32) {
        self.acc |= value << self.bits;
        self.bits += count;
        while self.bits >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.bits -= 8;
        }
    }

    /// A Huffman code goes in most significant bit first, unlike everything else.
    fn code(&mut self, code: u32, count: u32) {
        self.put(code.reverse_bits() >> (32 - count), count);
    }

    fn literal(&mut self, byte: u8) {
        match byte {
            0..=143 => self.code(0x30 + byte as u32, 8),
            _ => self.code(0x190 + byte as u32 - 144, 9),
        }
    }

    fn end_of_block(&mut self) {
        self.code(0, 7);
    }

    /// A copy of 258 bytes from one byte back, the longest and shortest there are.
    fn run_of_258(&mut self) {
        self.code(0xc5, 8);
        self.code(0, 5);
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

fn fixed_block(data: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.put(1, 1);
    writer.put(1, 2);
    for &byte in data {
        writer.literal(byte);
    }
    writer.end_of_block();
    writer.finish()
}

#[test]
fn reads_a_block_a_real_compressor_wrote() {
    let found = inflate(&from_hex(DYNAMIC), Wrapper::Raw, UNLIMITED);
    assert_eq!(found.error, None);
    assert!(!found.capped);
    assert_eq!(found.trailing, 0);
    assert_eq!(found.output, dynamic_text());
}

#[test]
fn reads_fixed_codes_for_every_byte_value() {
    let data: Vec<u8> = (0..=255).collect();
    let found = inflate(&fixed_block(&data), Wrapper::Raw, UNLIMITED);
    assert_eq!(found.error, None);
    assert_eq!(found.output, data);
}

#[test]
fn reads_a_copy_that_overlaps_itself() {
    let mut writer = Writer::new();
    writer.put(1, 1);
    writer.put(1, 2);
    writer.literal(b'A');
    writer.run_of_258();
    writer.end_of_block();

    let found = inflate(&writer.finish(), Wrapper::Raw, UNLIMITED);
    assert_eq!(found.error, None);
    assert_eq!(found.output, vec![b'A'; 259]);
}

#[test]
fn reads_stored_blocks_across_the_size_they_are_split_at() {
    let data: Vec<u8> = (0..200_000u32).map(|i| (i * 31 % 251) as u8).collect();
    let found = inflate(&zlib_stored(&data), Wrapper::Zlib, UNLIMITED);
    assert_eq!(found.error, None);
    assert_eq!(found.output, data);
}

#[test]
fn an_empty_stream_is_not_a_damaged_one() {
    let found = inflate(&zlib_stored(b""), Wrapper::Zlib, UNLIMITED);
    assert_eq!(found, Inflated::default());
}

#[test]
fn junk_after_the_stream_costs_nothing_and_is_counted() {
    // The stream that lost all but 128 KB through the platform's inflate.
    let data = vec![0x41u8; 1 << 20];
    let mut file = zlib_stored(&data);
    file.push(b'x');

    let found = inflate(&file, Wrapper::Zlib, UNLIMITED);
    assert_eq!(found.output.len(), 1 << 20);
    assert_eq!(found.error, None, "the data itself is sound");
    assert_eq!(found.trailing, 1);
}

#[test]
fn a_wrong_checksum_keeps_the_data_and_shows_both_numbers() {
    // Nothing at all came back from the platform for this one.
    let mut file = zlib_stored(b"flag{behind_a_bad_checksum}");
    let last = file.len() - 1;
    file[last] ^= 1;

    let found = inflate(&file, Wrapper::Zlib, UNLIMITED);
    assert_eq!(found.output, b"flag{behind_a_bad_checksum}");
    let said = found.error.unwrap();
    assert!(said.contains("Adler-32"), "{said}");
    let right = adler32(b"flag{behind_a_bad_checksum}");
    assert!(said.contains(&format!("{right:08x}")), "{said}");
    assert!(said.contains(&format!("{:08x}", right ^ 1)), "{said}");
}

#[test]
fn a_cut_keeps_what_came_before_it() {
    let file = zlib_stored(b"flag{before_the_cut}");
    for (cut, expected) in [
        (file.len() - 2, "Adler-32"),
        (file.len() - 4, "Adler-32"),
        (file.len() - 5, "cut short"),
        (3, "cut short"),
    ] {
        let found = inflate(&file[..cut], Wrapper::Zlib, UNLIMITED);
        let said = found.error.unwrap_or_default();
        assert!(said.contains(expected), "cut at {cut}: {said}");
    }

    let found = inflate(&file[..file.len() - 5], Wrapper::Zlib, UNLIMITED);
    assert_eq!(found.output, b"flag{before_the_cut"[..]);
}

#[test]
fn a_cut_through_compressed_data_keeps_what_had_decoded() {
    let whole = from_hex(DYNAMIC);
    let found = inflate(&whole[..whole.len() / 2], Wrapper::Raw, UNLIMITED);
    assert!(found.error.unwrap().contains("cut short"));
    assert!(found.output.len() > 100, "got {}", found.output.len());
    assert!(dynamic_text().starts_with(&found.output));
}

#[test]
fn damage_part_way_through_keeps_what_came_before_it() {
    // A reserved block type where the second block should begin.
    let mut writer = Writer::new();
    writer.put(0, 1);
    writer.put(1, 2);
    for &byte in b"flag{first_block}" {
        writer.literal(byte);
    }
    writer.end_of_block();
    writer.put(1, 1);
    writer.put(3, 2);
    let file = writer.finish();

    let found = inflate(&file, Wrapper::Raw, UNLIMITED);
    assert_eq!(found.output, b"flag{first_block}");
    assert!(found.error.unwrap().contains("damaged"));
}

#[test]
fn a_copy_from_before_the_start_stops_and_keeps_the_rest() {
    let mut writer = Writer::new();
    writer.put(1, 1);
    writer.put(1, 2);
    writer.literal(b'A');
    writer.code(0xc5, 8);
    writer.code(3, 5);
    writer.end_of_block();

    let found = inflate(&writer.finish(), Wrapper::Raw, UNLIMITED);
    assert_eq!(found.output, b"A");
    assert!(found.error.unwrap().contains("reaches back"));
}

#[test]
fn the_limit_stops_a_bomb_and_says_there_was_more() {
    // Eight kilobytes of file for two megabytes of output.
    let mut writer = Writer::new();
    writer.put(1, 1);
    writer.put(1, 2);
    writer.literal(b'A');
    for _ in 0..8192 {
        writer.run_of_258();
    }
    writer.end_of_block();
    let file = writer.finish();

    let found = inflate(&file, Wrapper::Raw, 1000);
    assert_eq!(found.output.len(), 1000);
    assert!(found.capped);
    assert_eq!(found.error, None, "the stream is fine, there is just a lot of it");

    let found = inflate(&file, Wrapper::Raw, 1 + 8192 * 258);
    assert!(!found.capped, "stopping exactly at the end is not being stopped");
    assert_eq!(found.output.len(), 1 + 8192 * 258);
}

#[test]
fn the_limit_applies_to_stored_data_too() {
    let found = inflate(&zlib_stored(&[7u8; 5000]), Wrapper::Zlib, 3000);
    assert_eq!(found.output.len(), 3000);
    assert!(found.capped);
}

#[test]
fn a_doctored_header_stops_a_viewer_and_not_this() {
    let mut file = zlib_stored(b"flag{past_the_header}");
    file[1] = 0x02;

    let found = inflate(&file, Wrapper::Zlib, UNLIMITED);
    assert_eq!(found.output, b"flag{past_the_header}");
    assert!(found.error.unwrap().contains("header"));
}

#[test]
fn a_stream_that_cannot_be_inflated_says_why() {
    for (file, expected) in [
        (&[0x78][..], "header"),
        (&[0x01, 0x00, 0x00][..], "not deflate"),
        (&[0x78, 0x20, 0x00][..], "dictionary"),
    ] {
        let found = inflate(file, Wrapper::Zlib, UNLIMITED);
        assert!(found.output.is_empty());
        let said = found.error.unwrap();
        assert!(said.contains(expected), "{said}");
    }
}

#[test]
fn every_prefix_of_every_kind_of_stream_ends_without_a_panic() {
    let dynamic = from_hex(DYNAMIC);
    let stored = zlib_stored(&[9u8; 300]);
    let fixed = fixed_block(b"hello there");

    for (file, wrapper) in [
        (&dynamic, Wrapper::Raw),
        (&stored, Wrapper::Zlib),
        (&fixed, Wrapper::Raw),
    ] {
        for cut in 0..file.len() {
            let found = inflate(&file[..cut], wrapper, UNLIMITED);
            assert!(found.error.is_some(), "cut at {cut} of {}", file.len());
        }
    }
}

#[test]
fn flipping_any_bit_of_a_real_stream_never_panics() {
    let original = from_hex(DYNAMIC);
    for at in 0..original.len() * 8 {
        let mut file = original.clone();
        file[at / 8] ^= 1 << (at % 8);
        let found = inflate(&file, Wrapper::Raw, 1 << 20);
        assert!(found.output.len() <= 1 << 20);
    }
}

/// A dynamic block holding nothing, which is the most tables a byte of file can ask for:
/// a code-length table with one-bit codes for symbols 1 and 18, then two runs of zeroes
/// for the 256 literals, a one-bit end-of-block and a one-bit distance, then the end.
fn empty_dynamic_block(writer: &mut Writer, last: bool) {
    writer.put(u32::from(last), 1);
    writer.put(2, 2);
    writer.put(0, 5);
    writer.put(0, 5);
    writer.put(14, 4);

    for slot in 0..18 {
        // Eighteen entries in the format's own order, where the third is symbol 18 and
        // the last is symbol 1.
        writer.put(u32::from(slot == 2 || slot == 17), 3);
    }

    writer.code(1, 1);
    writer.put(127, 7);
    writer.code(1, 1);
    writer.put(107, 7);
    writer.code(0, 1);
    writer.code(0, 1);

    writer.code(0, 1);
}

#[test]
fn an_empty_dynamic_block_is_read_as_one() {
    let mut writer = Writer::new();
    empty_dynamic_block(&mut writer, false);
    empty_dynamic_block(&mut writer, true);

    let found = inflate(&writer.finish(), Wrapper::Raw, UNLIMITED);
    assert_eq!(found.error, None);
    assert!(found.output.is_empty());
}

#[test]
fn a_stream_of_nothing_but_tables_gives_up_rather_than_building_them_all() {
    let mut writer = Writer::new();
    for _ in 0..MAX_DYNAMIC_BLOCKS + 10 {
        empty_dynamic_block(&mut writer, false);
    }
    let file = writer.finish();

    let started = std::time::Instant::now();
    let found = inflate(&file, Wrapper::Raw, UNLIMITED);
    assert!(found.error.unwrap().contains("more blocks"));
    assert!(started.elapsed().as_secs() < 20, "took {:?}", started.elapsed());
}

#[test]
fn thousands_of_fixed_blocks_do_not_build_a_table_each() {
    let mut writer = Writer::new();
    for _ in 0..1 << 20 {
        writer.put(0, 1);
        writer.put(1, 2);
        writer.end_of_block();
    }
    let file = writer.finish();

    let started = std::time::Instant::now();
    let found = inflate(&file, Wrapper::Raw, UNLIMITED);
    assert!(found.error.unwrap().contains("cut short"));
    assert!(started.elapsed().as_secs() < 10, "took {:?}", started.elapsed());
}

#[test]
fn packed_results_carry_the_json_and_then_the_output() {
    let packed_up = packed(Inflated {
        output: b"payload".to_vec(),
        error: Some("a \"quoted\" reason".to_string()),
        capped: true,
        trailing: 3,
    });

    let length = u32::from_le_bytes(packed_up[..4].try_into().unwrap()) as usize;
    let meta = std::str::from_utf8(&packed_up[4..4 + length]).unwrap();
    assert!(crate::json::is_well_formed(meta), "{meta}");
    assert!(meta.contains("\"capped\":true"));
    assert!(meta.contains("\"trailing\":3"));
    assert_eq!(&packed_up[4 + length..], b"payload");

    let clean = packed(Inflated::default());
    let length = u32::from_le_bytes(clean[..4].try_into().unwrap()) as usize;
    assert!(std::str::from_utf8(&clean[4..4 + length]).unwrap().contains("\"error\":null"));
}
