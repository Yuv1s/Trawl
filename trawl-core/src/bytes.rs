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

/// Runs of printable ASCII stored as UTF-16LE, which is how Windows tools write
/// text. Each character occupies two bytes with a zero high byte, so a scan for
/// single bytes walks straight past them.
pub fn utf16le_strings(data: &[u8], min_len: usize) -> Vec<Found> {
    let mut out = Vec::new();

    // Both alignments: the run may start on an even or an odd offset.
    for phase in 0..2usize {
        let mut start = phase;
        let mut run = 0usize;
        let mut at = phase;

        while at + 1 < data.len() {
            let printable = printable(data[at]) && data[at + 1] == 0;

            if printable {
                if run == 0 {
                    start = at;
                }
                run += 1;
            } else {
                if run >= min_len {
                    out.push(Found {
                        offset: start,
                        text: data[start..at]
                            .iter()
                            .step_by(2)
                            .map(|&b| b as char)
                            .collect(),
                    });
                }
                run = 0;
            }

            at += 2;
        }

        if run >= min_len {
            out.push(Found {
                offset: start,
                text: data[start..]
                    .iter()
                    .step_by(2)
                    .map(|&b| b as char)
                    .collect(),
            });
        }
    }

    // A run found on both alignments is the same run; keep the earlier offset.
    out.sort_by_key(|f| f.offset);
    out.dedup_by(|a, b| a.offset.abs_diff(b.offset) <= 1 && a.text.len() == b.text.len());
    out
}

fn tag_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Characters a person would type inside a flag.
fn body_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b' ' | b'.' | b'!' | b'?')
}

/// How much of a body has to look like writing rather than punctuation soup.
///
/// Uncompressed pixel data is not high-entropy enough for the region rule to
/// suppress it, but it is random enough to throw this shape constantly. A run of
/// bytes that happens to sit between braces is not a flag unless it also reads
/// like something a person typed.
const MIN_BODY_WRITTEN: f32 = 0.85;

/// Shortest tag worth trusting.
///
/// Two-character tags are where the noise lives: a bitmap threw two dozen of
/// them per image, `iJ{eHzcJ}` and the like, all pure alphanumeric so no
/// character test separates them. Real prefixes are `flag`, `picoCTF`, `HTB`.
/// A two-letter competition prefix would be missed, and that is the trade.
const MIN_TAG: usize = 3;

const MIN_BODY: usize = 4;

/// How lopsided the letter case has to be.
///
/// People write flags in one case, usually lower with underscores. Bytes pulled
/// out of a photograph alternate case at random, which is the one property that
/// separates `eLwaGqDnYDoZHt` from `bitmaps_hide_things_too`.
const MIN_CASE_AGREEMENT: f32 = 0.75;

fn case_is_consistent(body: &[u8]) -> bool {
    let lower = body.iter().filter(|b| b.is_ascii_lowercase()).count();
    let upper = body.iter().filter(|b| b.is_ascii_uppercase()).count();
    let letters = lower + upper;

    // Digits and underscores carry no case, so a body without letters passes.
    letters < 3 || lower.max(upper) as f32 / letters as f32 >= MIN_CASE_AGREEMENT
}

/// Scans for the `tag{payload}` shape every competition uses: picoCTF{...},
/// flag{...}, HTB{...}. Deliberately format-agnostic rather than a fixed list,
/// because each event invents its own prefix.
///
/// A match is a candidate, never an assertion. The caller decides what to do
/// with it.
/// Tags a capture-the-flag answer is usually wrapped in.
pub const KNOWN_TAGS: [&str; 6] = ["flag", "ctf", "key", "htb", "thm", "pico"];

/// True when a flag candidate is wrapped in a tag anyone would recognise.
///
/// A brace shape on its own proves little: no cipher here enciphers
/// punctuation, so the braces of a flag survive being encrypted and any
/// ciphertext that had them still has them. The tag is what makes it evidence.
///
/// Matched at the end rather than anywhere inside. Tags are built by putting a
/// competition's name in front of a common ending, which is how picoCTF and
/// testCTF are built, so the ending is where the evidence lives. Looking
/// anywhere inside instead calls `ethtBAN` a flag, because it happens to contain
/// the letters of HTB, and on a list of decryptions that is not a rare accident.
pub fn tag_is_known(text: &str) -> bool {
    tag_is_known_for(text, &[])
}

pub fn tag_is_known_for(text: &str, tags: &[String]) -> bool {
    let Some(tag) = text.split('{').next() else {
        return false;
    };
    if tags.is_empty() {
        let lower = tag.to_ascii_lowercase();
        return KNOWN_TAGS.iter().any(|known| lower.ends_with(known));
    }

    tags.iter()
        .any(|known| tag.eq_ignore_ascii_case(known.trim()))
}

pub fn flag_candidates_for_tags(data: &[u8], tags: &[String]) -> Vec<Found> {
    flag_candidates(data)
        .into_iter()
        .filter(|found| tag_is_known_for(&found.text, tags))
        .collect()
}

pub fn flag_candidates(data: &[u8]) -> Vec<Found> {
    // Real prefixes are short: flag, picoCTF, HTB, testCTF. Nothing near twelve.
    const MAX_TAG: usize = 12;
    const MAX_BODY: usize = 256;

    let mut out = Vec::new();
    let mut i = 0usize;

    while i < data.len() {
        if data[i] != b'{' {
            i += 1;
            continue;
        }

        // Take the whole run and reject it if it overruns, rather than trimming
        // it to the limit. Trimming turned any long stretch of alphanumerics
        // into a maximum-length tag, which passed every check by construction.
        let mut tag_start = i;
        while tag_start > 0 && tag_byte(data[tag_start - 1]) {
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
        let body = &data[i + 1..close];
        let body_len = body.len();

        // A real tag starts with a letter: picoCTF, flag, HTB. A run of bytes
        // ending in something tag-shaped by accident usually does not.
        let tag_ok =
            (MIN_TAG..=MAX_TAG).contains(&tag_len) && data[tag_start].is_ascii_alphabetic();

        let written = body.iter().filter(|&&b| body_byte(b)).count();
        let body_ok = body_len >= MIN_BODY
            && body.iter().all(|&b| printable(b))
            // A second opening brace means the match began at the wrong one, so
            // this is a longer run that happens to span a brace rather than a
            // flag. The written-byte allowance alone lets one through.
            && !body.contains(&b'{')
            && written as f32 / body_len as f32 >= MIN_BODY_WRITTEN
            && case_is_consistent(body);

        if tag_ok && body_ok {
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
    /// How many bytes to carve out.
    pub length: usize,
    /// True when a real end marker was found. False means the length is a guess,
    /// running to the next signature or the end of the file, and the carved
    /// result may carry a tail of whatever followed.
    pub bounded: bool,
}

/// First occurrence of `needle` at or after `from`.
pub fn find(data: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    data.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

/// Where an embedded file ends, for the formats that say so.
///
/// Carving without this is guesswork: you get the file plus everything after it.
/// Each of these terminators is defined by the format, so the extraction is
/// exact rather than approximate.
fn extent(data: &[u8], at: usize, label: &str) -> Option<usize> {
    match label {
        // The IEND chunk is the last thing in a PNG: type, then a four-byte CRC.
        "PNG image" => find(data, at, b"IEND").map(|p| p + 8),
        // End of image.
        "JPEG image" => find(data, at + 2, &[0xff, 0xd9]).map(|p| p + 2),
        // End of central directory, then a variable-length comment.
        "ZIP archive" => find(data, at, b"PK\x05\x06").and_then(|p| {
            let comment = data.get(p + 20..p + 22)?;
            Some(p + 22 + u16::from_le_bytes([comment[0], comment[1]]) as usize)
        }),
        "PDF document" => {
            // A PDF may be appended to several times, so the last one wins.
            let mut last = None;
            let mut from = at;
            while let Some(p) = find(data, from, b"%%EOF") {
                last = Some(p + 5);
                from = p + 5;
            }
            last
        }
        _ => None,
    }
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
    Scannable {
        magic: b"RIFF",
        label: "RIFF container",
        validate: riff_type,
    },
    Scannable {
        magic: b"\x89PNG\r\n\x1a\n",
        label: "PNG image",
        validate: always,
    },
    Scannable {
        magic: b"PK\x03\x04",
        label: "ZIP archive",
        validate: always,
    },
    Scannable {
        magic: b"%PDF",
        label: "PDF document",
        validate: always,
    },
    Scannable {
        magic: b"\x7fELF",
        label: "ELF binary",
        validate: always,
    },
    Scannable {
        magic: b"7z\xbc\xaf\x27\x1c",
        label: "7-Zip archive",
        validate: always,
    },
    Scannable {
        magic: b"Rar!\x1a\x07",
        label: "RAR archive",
        validate: always,
    },
    Scannable {
        magic: b"GIF8",
        label: "GIF image",
        validate: gif_version,
    },
    Scannable {
        magic: b"BZh",
        label: "bzip2 stream",
        validate: bzip_level,
    },
    Scannable {
        magic: b"\xff\xd8\xff",
        label: "JPEG image",
        validate: jpeg_marker,
    },
    Scannable {
        magic: b"\x1f\x8b",
        label: "gzip stream",
        validate: gzip_flags,
    },
    Scannable {
        magic: b"BM",
        label: "BMP image",
        validate: bmp_size,
    },
];

/// Every file signature anywhere in the buffer, not only at offset zero.
///
/// This is the binwalk move: a container appended to or embedded inside another
/// file announces itself with its own magic, wherever it happens to sit.
pub fn magic_scan(data: &[u8]) -> Vec<MagicHit> {
    let mut found = Vec::new();

    for at in 0..data.len() {
        for candidate in &SCANNABLE {
            if data[at..].starts_with(candidate.magic) && (candidate.validate)(data, at) {
                found.push((at, candidate.label));
                break;
            }
        }
    }

    // A second pass, because an unbounded file runs until the next one starts.
    found
        .iter()
        .enumerate()
        .map(|(i, &(at, label))| {
            let next = found.get(i + 1).map(|&(o, _)| o).unwrap_or(data.len());
            match extent(data, at, label) {
                Some(end) if end > at && end <= data.len() => MagicHit {
                    offset: at,
                    label,
                    length: end - at,
                    bounded: true,
                },
                _ => MagicHit {
                    offset: at,
                    label,
                    length: next - at,
                    bounded: false,
                },
            }
        })
        .collect()
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

/// Latin-1 with control bytes dropped, for metadata fields that claim to be text.
pub fn latin1_lossy(data: &[u8]) -> String {
    data.iter()
        .filter(|&&b| b >= 0x20 || b == b'\n' || b == b'\t')
        .map(|&b| b as char)
        .collect()
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

    /// Carving without a real terminator gives you the file plus everything that
    /// followed it. These four formats say where they end, so the extraction is
    /// exact rather than approximate.
    #[test]
    fn magic_scan_measures_a_png_to_its_iend_chunk() {
        let mut data = vec![0u8; 100];
        let png_at = data.len();
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        data.extend_from_slice(&[0u8; 40]);
        data.extend_from_slice(b"IEND");
        data.extend_from_slice(&[1, 2, 3, 4]); // CRC
        data.extend_from_slice(b"trailing junk that must not be carved");

        let hit = magic_scan(&data)
            .into_iter()
            .find(|h| h.offset == png_at)
            .unwrap();
        assert!(hit.bounded);
        assert_eq!(hit.length, 8 + 40 + 4 + 4);
    }

    #[test]
    fn magic_scan_measures_a_jpeg_to_its_end_of_image_marker() {
        let mut data = vec![0u8; 32];
        let at = data.len();
        data.extend_from_slice(&[0xff, 0xd8, 0xff, 0xe0]);
        data.extend_from_slice(&[0u8; 20]);
        data.extend_from_slice(&[0xff, 0xd9]);
        data.extend_from_slice(b"after the image");

        let hit = magic_scan(&data)
            .into_iter()
            .find(|h| h.offset == at)
            .unwrap();
        assert!(hit.bounded);
        assert_eq!(hit.length, 4 + 20 + 2);
    }

    #[test]
    fn magic_scan_measures_a_zip_including_its_trailing_comment() {
        let comment = b"a comment";
        let mut data = vec![0u8; 16];
        let at = data.len();
        data.extend_from_slice(b"PK\x03\x04");
        data.extend_from_slice(&[0u8; 30]);
        data.extend_from_slice(b"PK\x05\x06");
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        data.extend_from_slice(comment);
        data.extend_from_slice(b"and then some noise");

        let hit = magic_scan(&data)
            .into_iter()
            .find(|h| h.offset == at)
            .unwrap();
        assert!(hit.bounded);
        assert_eq!(hit.length, 4 + 30 + 22 + comment.len());
    }

    #[test]
    fn magic_scan_takes_the_last_pdf_terminator_because_pdfs_get_appended_to() {
        let mut data = b"%PDF-1.7 first revision %%EOF then an update %%EOF".to_vec();
        let tail = data.len();
        data.extend_from_slice(b" junk");

        let hit = &magic_scan(&data)[0];
        assert!(hit.bounded);
        assert_eq!(hit.length, tail);
    }

    /// A format with no terminator is measured to the next signature, and says so
    /// rather than presenting a guess as exact.
    #[test]
    fn a_format_with_no_terminator_is_marked_as_a_guess() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(b"BZh9");
        data.extend_from_slice(&[0u8; 50]);
        let png_at = data.len();
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        data.extend_from_slice(&[0u8; 10]);

        let hits = magic_scan(&data);
        let bzip = hits.iter().find(|h| h.label == "bzip2 stream").unwrap();

        assert!(!bzip.bounded, "there is no bzip2 end marker to find");
        assert_eq!(
            bzip.offset + bzip.length,
            png_at,
            "runs up to the next file"
        );
    }

    #[test]
    fn the_last_unbounded_file_runs_to_the_end_of_the_buffer() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(b"BZh1");
        data.extend_from_slice(&[0u8; 40]);

        let hit = &magic_scan(&data)[0];
        assert!(!hit.bounded);
        assert_eq!(hit.offset + hit.length, data.len());
    }

    #[test]
    fn a_truncated_container_falls_back_to_a_guess_rather_than_overrunning() {
        // A PNG signature with no IEND anywhere after it.
        let mut data = vec![0u8; 8];
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        data.extend_from_slice(&[0u8; 30]);

        let hit = &magic_scan(&data)[0];
        assert!(!hit.bounded);
        assert!(hit.offset + hit.length <= data.len());
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
    fn utf16le_strings_reads_text_a_single_byte_scan_walks_past() {
        let mut data = vec![0xffu8; 8];
        for c in "flag{wide}".chars() {
            data.push(c as u8);
            data.push(0);
        }
        data.extend_from_slice(&[0xff; 8]);

        let found = utf16le_strings(&data, 6);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "flag{wide}");
        assert_eq!(found[0].offset, 8);

        assert!(
            ascii_strings(&data, 6).is_empty(),
            "the ascii scan misses it"
        );
    }

    #[test]
    fn utf16le_strings_finds_a_run_starting_on_an_odd_offset() {
        let mut data = vec![0xffu8];
        for c in "oddaligned".chars() {
            data.push(c as u8);
            data.push(0);
        }
        assert_eq!(utf16le_strings(&data, 6)[0].text, "oddaligned");
    }

    #[test]
    fn utf16le_strings_ignores_plain_ascii_and_noise() {
        assert!(utf16le_strings(b"just some plain ascii text here", 6).is_empty());
        assert!(utf16le_strings(&noise(4096, 0x1234), 8).is_empty());
    }

    #[test]
    fn ascii_strings_returns_nothing_for_binary_noise() {
        assert!(ascii_strings(&[0x00, 0xff, 0x01, 0x80], 4).is_empty());
    }

    #[test]
    fn flag_candidates_finds_the_common_shapes() {
        let data = b"junk picoCTF{n0t_s0_h1dd3n} more flag{a_b_c_d} end";
        let found = flag_candidates(data);
        let texts: Vec<&str> = found.iter().map(|f| f.text.as_str()).collect();
        assert_eq!(texts, vec!["picoCTF{n0t_s0_h1dd3n}", "flag{a_b_c_d}"]);
    }

    #[test]
    fn flag_candidates_records_the_offset_of_the_tag_not_the_brace() {
        let found = flag_candidates(b"..HTB{abcd}");
        assert_eq!(found[0].offset, 2);
    }

    #[test]
    fn configured_flag_tags_match_the_whole_prefix_without_suffix_guessing() {
        let tags = vec!["picoCTF".to_string(), "event".to_string()];
        let found = flag_candidates_for_tags(
            b"picoCTF{first_flag} testCTF{not_selected} event{second_flag}",
            &tags,
        );
        let texts: Vec<&str> = found.iter().map(|found| found.text.as_str()).collect();

        assert_eq!(texts, vec!["picoCTF{first_flag}", "event{second_flag}"]);
        assert!(tag_is_known_for("PICOctf{case_insensitive}", &tags));
        assert!(!tag_is_known_for("testCTF{not_selected}", &tags));
    }

    #[test]
    fn flag_candidates_rejects_braces_with_no_tag() {
        assert!(flag_candidates(b"{just_a_brace}").is_empty());
    }

    #[test]
    fn flag_candidates_rejects_a_body_of_binary() {
        assert!(flag_candidates(b"flag{\x00\x01\x02\x03}").is_empty());
    }

    /// Regression: uncompressed pixel data threw this shape roughly fifty times
    /// per bitmap, because the region rule only suppresses compressed streams.
    #[test]
    fn flag_candidates_rejects_punctuation_soup() {
        for junk in [
            &b"yW0{X.xV+tR)rP+tR-yV0~Y/}"[..],
            b"wT-{W-zV)uR&pM$mK&pM)wS-}",
            b"cD{_?tY;oT;nT?rWDx]G|`Fz}",
            b"b7{[3uV2sT5vW8{[:}",
        ] {
            assert!(
                flag_candidates(junk).is_empty(),
                "{} was reported as a flag",
                String::from_utf8_lossy(junk)
            );
        }
    }

    /// Regression: the walk-back used to trim an over-long run to the maximum
    /// tag length, so a stretch of random alphanumerics before a brace always
    /// produced a tag that passed.
    #[test]
    fn flag_candidates_rejects_an_over_long_run_rather_than_trimming_it() {
        assert!(flag_candidates(b"uJYxMWvKRqGNlCLkBPoEUuJZ{NZOWyLTtIStHVwKZ}").is_empty());
        assert!(flag_candidates(b"abcdefghijklmnopqrstuvwxyz{payload}").is_empty());
        assert_eq!(flag_candidates(b"a picoCTF{payload} b").len(), 1);
    }

    #[test]
    fn flag_candidates_requires_a_tag_that_starts_with_a_letter() {
        assert!(flag_candidates(b"7fx{abcdef}").is_empty());
        assert!(flag_candidates(b"_xy{abcdef}").is_empty());
        assert_eq!(flag_candidates(b"f7x{abcdef}").len(), 1);
    }

    #[test]
    fn flag_candidates_still_accepts_the_shapes_competitions_use() {
        for real in [
            &b"flag{bitmaps_hide_things_too}"[..],
            b"picoCTF{n0t_s0_h1dd3n}",
            b"HTB{a-b-c-d}",
            b"testCTF{rgb msb first}",
            b"CTF{what_now?}",
        ] {
            assert_eq!(
                flag_candidates(real).len(),
                1,
                "{} was rejected",
                String::from_utf8_lossy(real)
            );
        }
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
