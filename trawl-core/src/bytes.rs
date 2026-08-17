//! Format-independent scans over raw bytes. Shared by every category.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub offset: usize,
    pub text: String,
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b)
}

/// Runs of printable ASCII at least `min_len` long.
pub fn ascii_strings(data: &[u8], min_len: usize) -> Vec<Found> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut run = 0usize;

    for (i, &b) in data.iter().enumerate() {
        if printable(b) {
            if run == 0 {
                start = i;
            }
            run += 1;
        } else {
            if run >= min_len {
                out.push(Found {
                    offset: start,
                    text: String::from_utf8_lossy(&data[start..i]).into_owned(),
                });
            }
            run = 0;
        }
    }

    if run >= min_len {
        out.push(Found {
            offset: start,
            text: String::from_utf8_lossy(&data[start..]).into_owned(),
        });
    }

    out
}

fn tag_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Scans for the `tag{payload}` shape every competition uses: picoCTF{...},
/// flag{...}, HTB{...}. Deliberately format-agnostic rather than a fixed list,
/// because each event invents its own prefix.
///
/// A match is a candidate, never an assertion. The caller decides what to do
/// with it.
pub fn flag_candidates(data: &[u8]) -> Vec<Found> {
    const MAX_TAG: usize = 24;
    const MAX_BODY: usize = 256;

    let mut out = Vec::new();
    let mut i = 0usize;

    while i < data.len() {
        if data[i] != b'{' {
            i += 1;
            continue;
        }

        let mut tag_start = i;
        while tag_start > 0 && tag_byte(data[tag_start - 1]) && i - tag_start < MAX_TAG {
            tag_start -= 1;
        }

        let Some(close) = data[i + 1..]
            .iter()
            .take(MAX_BODY)
            .position(|&b| b == b'}')
            .map(|p| i + 1 + p)
        else {
            i += 1;
            continue;
        };

        let tag_len = i - tag_start;
        let body_len = close - i - 1;
        let body_printable = data[i + 1..close].iter().all(|&b| printable(b));

        if (2..=MAX_TAG).contains(&tag_len) && body_len >= 3 && body_printable {
            out.push(Found {
                offset: tag_start,
                text: String::from_utf8_lossy(&data[tag_start..=close]).into_owned(),
            });
            i = close + 1;
        } else {
            i += 1;
        }
    }

    out
}

const SIGNATURES: [(&[u8], &str); 12] = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"BM", "BMP image"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "gzip stream"),
    (b"BZh", "bzip2 stream"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"%PDF", "PDF document"),
    (b"\x7fELF", "ELF binary"),
    (b"RIFF", "RIFF container"),
];

/// Names the format a byte run starts with, if any.
pub fn identify(data: &[u8]) -> Option<&'static str> {
    SIGNATURES
        .iter()
        .find(|(magic, _)| data.starts_with(magic))
        .map(|(_, name)| *name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicHit {
    pub offset: usize,
    pub label: &'static str,
}

/// A signature plus whatever extra check keeps it from firing on noise.
///
/// Short magics are the problem. Two bytes match roughly once every 64 KB of
/// random data, so scanning half a megabyte for `BM` alone would report eight
/// imaginary bitmaps. Each short signature therefore carries a validator that
/// tests a field the format actually constrains.
struct Scannable {
    magic: &'static [u8],
    label: &'static str,
    validate: fn(&[u8], usize) -> bool,
}

fn always(_: &[u8], _: usize) -> bool {
    true
}

/// gzip: the only defined compression method is deflate, and the reserved bits
/// of FLG are zero.
fn gzip_flags(data: &[u8], at: usize) -> bool {
    data.get(at + 2) == Some(&0x08) && data.get(at + 3).is_some_and(|&flg| flg & 0xe0 == 0)
}

/// JPEG: the byte after SOI must begin a marker segment we recognise.
fn jpeg_marker(data: &[u8], at: usize) -> bool {
    matches!(
        data.get(at + 3),
        Some(0xe0..=0xef) | Some(0xdb) | Some(0xc0) | Some(0xc4) | Some(0xfe)
    )
}

/// GIF: the version field is either 87a or 89a.
fn gif_version(data: &[u8], at: usize) -> bool {
    matches!(data.get(at + 4), Some(b'7') | Some(b'9')) && data.get(at + 5) == Some(&b'a')
}

/// BMP: the declared file size has to fit in what is left of the buffer.
fn bmp_size(data: &[u8], at: usize) -> bool {
    let Some(field) = data.get(at + 2..at + 6) else {
        return false;
    };
    let declared = u32::from_le_bytes([field[0], field[1], field[2], field[3]]) as usize;
    (26..=data.len() - at).contains(&declared)
}

/// RIFF: the container type at offset 8 is four printable characters.
fn riff_type(data: &[u8], at: usize) -> bool {
    data.get(at + 8..at + 12)
        .is_some_and(|kind| kind.iter().all(|b| b.is_ascii_uppercase() || *b == b' '))
}

/// bzip2: the block-size digit is 1 through 9.
fn bzip_level(data: &[u8], at: usize) -> bool {
    data.get(at + 3).is_some_and(|b| (b'1'..=b'9').contains(b))
}

const SCANNABLE: [Scannable; 12] = [
    Scannable { magic: b"RIFF", label: "RIFF container", validate: riff_type },
    Scannable { magic: b"\x89PNG\r\n\x1a\n", label: "PNG image", validate: always },
    Scannable { magic: b"PK\x03\x04", label: "ZIP archive", validate: always },
    Scannable { magic: b"%PDF", label: "PDF document", validate: always },
    Scannable { magic: b"\x7fELF", label: "ELF binary", validate: always },
    Scannable { magic: b"7z\xbc\xaf\x27\x1c", label: "7-Zip archive", validate: always },
    Scannable { magic: b"Rar!\x1a\x07", label: "RAR archive", validate: always },
    Scannable { magic: b"GIF8", label: "GIF image", validate: gif_version },
    Scannable { magic: b"BZh", label: "bzip2 stream", validate: bzip_level },
    Scannable { magic: b"\xff\xd8\xff", label: "JPEG image", validate: jpeg_marker },
    Scannable { magic: b"\x1f\x8b", label: "gzip stream", validate: gzip_flags },
    Scannable { magic: b"BM", label: "BMP image", validate: bmp_size },
];

/// Every file signature anywhere in the buffer, not only at offset zero.
///
/// This is the binwalk move: a container appended to or embedded inside another
/// file announces itself with its own magic, wherever it happens to sit.
pub fn magic_scan(data: &[u8]) -> Vec<MagicHit> {
    let mut out = Vec::new();

    for at in 0..data.len() {
        for candidate in &SCANNABLE {
            if data[at..].starts_with(candidate.magic) && (candidate.validate)(data, at) {
                out.push(MagicHit {
                    offset: at,
                    label: candidate.label,
                });
                break;
            }
        }
    }

    out
}

/// Shannon entropy of a byte run, in bits per byte, so 8.0 is incompressible.
pub fn shannon_entropy(window: &[u8]) -> f32 {
    if window.is_empty() {
        return 0.0;
    }

    let mut histogram = [0u32; 256];
    for &b in window {
        histogram[b as usize] += 1;
    }

    let total = window.len() as f32;
    let sum = histogram
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f32 / total;
            p * p.log2()
        })
        .sum::<f32>();

    // max(0.0) rather than plain negation: a uniform window sums to zero, and
    // negating that yields -0.0, which formats as "-0.000".
    (-sum).max(0.0)
}

/// Entropy across the file in non-overlapping windows.
///
/// @return the window size and one value per window
pub fn entropy_profile(data: &[u8], points: usize) -> (usize, Vec<f32>) {
    if data.is_empty() || points == 0 {
        return (0, Vec::new());
    }

    let window = (data.len() / points).max(256).min(data.len());
    let values = data.chunks(window).map(shannon_entropy).collect();
    (window, values)
}

/// Entropy of the neighbourhood around an offset.
///
/// Used to judge whether a match there means anything: near 8.0 says the region
/// is compressed or encrypted, where any pattern is as likely as any other.
pub fn local_entropy(data: &[u8], offset: usize, radius: usize) -> f32 {
    let start = offset.saturating_sub(radius);
    let end = (offset + radius).min(data.len());
    shannon_entropy(&data[start..end])
}

/// Above this a region is treated as compressed, and a flag-shaped match inside
/// it as coincidence.
pub const COMPRESSED_ENTROPY: f32 = 7.0;

/// Longest run of printable ASCII, with where it starts. Used to decide whether
/// an extracted bit stream carries text or noise.
pub fn longest_printable_run(data: &[u8]) -> (usize, usize) {
    let mut best = (0usize, 0usize);
    let mut start = 0usize;
    let mut run = 0usize;

    for (i, &b) in data.iter().enumerate() {
        if printable(b) {
            if run == 0 {
                start = i;
            }
            run += 1;
            if run > best.1 {
                best = (start, run);
            }
        } else {
            run = 0;
        }
    }

    best
}

/// How many distinct byte values a slice holds.
///
/// The upper bit planes of a smooth image repeat a short cycle, so extracting
/// them yields runs like `UUUU` (0x55) or `3333` (0x33). Those are printable and
/// long, and they are not a payload. Variety is what separates the two.
pub fn distinct_bytes(data: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut count = 0;
    for &b in data {
        if !seen[b as usize] {
            seen[b as usize] = true;
            count += 1;
        }
    }
    count
}

/// Printable ASCII bytes as a fraction of the first `window` bytes.
pub fn printable_ratio(data: &[u8], window: usize) -> f32 {
    let slice = &data[..data.len().min(window)];
    if slice.is_empty() {
        return 0.0;
    }
    slice.iter().filter(|&&b| printable(b)).count() as f32 / slice.len() as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_names_known_signatures() {
        assert_eq!(identify(b"PK\x03\x04rest"), Some("ZIP archive"));
        assert_eq!(identify(b"%PDF-1.7"), Some("PDF document"));
        assert_eq!(identify(b"nothing here"), None);
        assert_eq!(identify(&[]), None);
    }

    fn noise(len: usize, seed: u32) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 17;
                s ^= s << 5;
                (s & 0xff) as u8
            })
            .collect()
    }

    #[test]
    fn magic_scan_finds_a_container_embedded_part_way_through() {
        let mut data = vec![0u8; 500];
        data.extend_from_slice(b"PK\x03\x04payload");
        data.extend_from_slice(&[0u8; 100]);

        let hits = magic_scan(&data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 500);
        assert_eq!(hits[0].label, "ZIP archive");
    }

    /// The reason every short signature carries a validator. Two bytes match
    /// roughly once per 64 KB of noise, so an unguarded `BM` or gzip magic would
    /// fill the report with imaginary files.
    #[test]
    fn magic_scan_stays_quiet_on_half_a_megabyte_of_noise() {
        for seed in [0x1111u32, 0xbeef, 0x5eed, 0xc0ffee, 0x31337, 0xfeedface] {
            let hits = magic_scan(&noise(512 * 1024, seed));
            assert!(
                hits.is_empty(),
                "seed {seed:#x} produced {} phantom signatures: {:?}",
                hits.len(),
                &hits[..hits.len().min(6)]
            );
        }
    }

    #[test]
    fn magic_scan_rejects_a_bitmap_whose_declared_size_cannot_fit() {
        let mut data = b"BM".to_vec();
        data.extend_from_slice(&u32::MAX.to_le_bytes());
        data.extend_from_slice(&[0u8; 64]);
        assert!(magic_scan(&data).is_empty());
    }

    #[test]
    fn magic_scan_accepts_a_bitmap_with_a_plausible_size() {
        let mut data = b"BM".to_vec();
        data.extend_from_slice(&60u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 64]);
        assert_eq!(magic_scan(&data)[0].label, "BMP image");
    }

    #[test]
    fn magic_scan_rejects_a_gzip_magic_with_reserved_flag_bits_set() {
        let ok = [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0];
        let bad = [0x1f, 0x8b, 0x08, 0xe0, 0, 0, 0, 0];
        assert_eq!(magic_scan(&ok).len(), 1);
        assert!(magic_scan(&bad).is_empty());
    }

    #[test]
    fn shannon_entropy_spans_flat_to_incompressible() {
        assert_eq!(shannon_entropy(&[7u8; 1024]), 0.0);
        assert!(shannon_entropy(&noise(64 * 1024, 0x99)) > 7.9);
        assert_eq!(shannon_entropy(&[]), 0.0);

        let two: Vec<u8> = (0..1024).map(|i| if i % 2 == 0 { 1 } else { 2 }).collect();
        assert!((shannon_entropy(&two) - 1.0).abs() < 1e-5);
    }

    #[test]
    fn entropy_profile_covers_the_file_in_windows() {
        let data = noise(64 * 1024, 0x77);
        let (window, values) = entropy_profile(&data, 64);

        assert_eq!(window, 1024);
        assert_eq!(values.len(), 64);
        assert!(values.iter().all(|&v| v > 7.0));
        assert_eq!(entropy_profile(&[], 64), (0, Vec::new()));
    }

    #[test]
    fn local_entropy_separates_a_text_region_from_a_compressed_one() {
        let mut data = vec![b'a'; 2048];
        data.extend(noise(2048, 0x33));

        assert!(local_entropy(&data, 1024, 512) < 1.0);
        assert!(local_entropy(&data, 3072, 512) > COMPRESSED_ENTROPY);
    }

    #[test]
    fn distinct_bytes_separates_a_repeating_cycle_from_real_text() {
        assert_eq!(distinct_bytes(b"UUUUUUUUUUUUUUUU"), 1);
        assert_eq!(distinct_bytes(b"ababababababab"), 2);
        assert!(distinct_bytes(b"flag{hello} ") >= 6);
        assert_eq!(distinct_bytes(&[]), 0);
    }

    #[test]
    fn longest_printable_run_reports_start_and_length() {
        assert_eq!(longest_printable_run(b"\x00abc\x00defgh\x00"), (5, 5));
        assert_eq!(longest_printable_run(&[0, 1, 2]), (0, 0));
    }

    #[test]
    fn printable_ratio_looks_only_at_the_window() {
        assert_eq!(printable_ratio(b"abcd\x00\x00\x00\x00", 4), 1.0);
        assert_eq!(printable_ratio(b"abcd\x00\x00\x00\x00", 8), 0.5);
        assert_eq!(printable_ratio(&[], 8), 0.0);
    }

    #[test]
    fn ascii_strings_ignores_runs_below_the_threshold() {
        let data = b"ab\x00hello world\x00cd";
        let found = ascii_strings(data, 5);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "hello world");
        assert_eq!(found[0].offset, 3);
    }

    #[test]
    fn ascii_strings_keeps_a_run_that_reaches_the_end() {
        let found = ascii_strings(b"\x00trailing", 4);
        assert_eq!(found[0].text, "trailing");
    }

    #[test]
    fn ascii_strings_returns_nothing_for_binary_noise() {
        assert!(ascii_strings(&[0x00, 0xff, 0x01, 0x80], 4).is_empty());
    }

    #[test]
    fn flag_candidates_finds_the_common_shapes() {
        let data = b"junk picoCTF{n0t_s0_h1dd3n} more flag{a_b_c} end";
        let found = flag_candidates(data);
        let texts: Vec<&str> = found.iter().map(|f| f.text.as_str()).collect();
        assert_eq!(texts, vec!["picoCTF{n0t_s0_h1dd3n}", "flag{a_b_c}"]);
    }

    #[test]
    fn flag_candidates_records_the_offset_of_the_tag_not_the_brace() {
        let found = flag_candidates(b"..HTB{abc}");
        assert_eq!(found[0].offset, 2);
    }

    #[test]
    fn flag_candidates_rejects_braces_with_no_tag() {
        assert!(flag_candidates(b"{just_a_brace}").is_empty());
    }

    #[test]
    fn flag_candidates_rejects_a_body_of_binary() {
        assert!(flag_candidates(b"flag{\x00\x01\x02\x03}").is_empty());
    }

    #[test]
    fn flag_candidates_rejects_an_unterminated_brace() {
        assert!(flag_candidates(b"flag{never_closed").is_empty());
    }

    #[test]
    fn flag_candidates_does_not_run_past_a_reasonable_body_length() {
        let mut data = b"flag{".to_vec();
        data.extend(std::iter::repeat_n(b'a', 400));
        data.push(b'}');
        assert!(flag_candidates(&data).is_empty());
    }
}
