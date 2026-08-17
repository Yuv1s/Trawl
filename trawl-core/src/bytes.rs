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
