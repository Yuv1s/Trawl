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

/// Most flag shapes one scan reports.
///
/// Ten bytes of file make one, so a file of nothing else asks for more text than it
/// holds and a lookup per match behind it. No real file has this many flags, and the
/// first few thousand already say what such a file is.
pub const MAX_FLAGS: usize = 10_000;

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
/// A two-letter competition prefix is found only by naming it in the flag tags.
const MIN_TAG: usize = 3;

/// Longest tag trusted without being named. Real prefixes are short: flag, picoCTF,
/// HTB, testCTF. An event with a longer one names it in the flag tags.
const MAX_TAG: usize = 12;

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

    let lower = tag.to_ascii_lowercase();
    tags.iter().any(|known| {
        let known = known.trim().to_ascii_lowercase();
        !known.is_empty() && lower.ends_with(&known)
    })
}

/// How many bytes of a tag run a configured tag accounts for, if any of them does.
///
/// Matched on the ending, the same rule [`tag_is_known_for`] applies.
fn named_tag(run: &[u8], tags: &[String]) -> Option<usize> {
    tags.iter()
        .map(|tag| tag.trim().as_bytes())
        .filter(|tag| !tag.is_empty() && tag.len() <= run.len())
        .filter(|tag| run[run.len() - tag.len()..].eq_ignore_ascii_case(tag))
        .map(<[u8]>::len)
        .max()
}

/// True for a run ending in a tag anyone would recognise.
fn recognised_tag(run: &[u8]) -> bool {
    KNOWN_TAGS.iter().any(|known| {
        known.len() <= run.len() && run[run.len() - known.len()..].eq_ignore_ascii_case(known.as_bytes())
    })
}

pub fn flag_candidates_for_tags(data: &[u8], tags: &[String]) -> Vec<Found> {
    flag_candidates_naming(data, tags)
        .into_iter()
        .filter(|found| tag_is_known_for(&found.text, tags))
        .collect()
}

pub fn flag_candidates(data: &[u8]) -> Vec<Found> {
    flag_candidates_naming(data, &[])
}

/// Every flag shape, with the configured tags let past the checks that exist to
/// reject noise.
///
/// Those checks guess at what a tag and a body look like when nobody has said. A
/// named tag is not a guess: `HV` and `cyberapocalypse` are outside the length limits
/// because the limits are about unnamed runs. A tag anyone would recognise settles
/// the case check the same way, since `HTB{Y0u_F0uNd_1T}` is written like that on
/// purpose and the alternating case that marks noise does not come with a tag on it.
pub fn flag_candidates_naming(data: &[u8], tags: &[String]) -> Vec<Found> {
    const MAX_BODY: usize = 256;

    let mut out = Vec::new();
    let mut i = 0usize;

    while i < data.len() && out.len() < MAX_FLAGS {
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
        let shaped =
            (MIN_TAG..=MAX_TAG).contains(&tag_len) && data[tag_start].is_ascii_alphabetic();

        // A named tag outside the shape is reported as itself, not with whatever
        // run of alphanumerics happens to sit in front of it.
        let named = named_tag(&data[tag_start..i], tags);
        let start = match named {
            Some(len) if !shaped => i - len,
            _ => tag_start,
        };
        let tag_ok = shaped || named.is_some();

        let written = body.iter().filter(|&&b| body_byte(b)).count();
        let body_ok = body_len >= MIN_BODY
            && body.iter().all(|&b| printable(b))
            // A second opening brace means the match began at the wrong one, so
            // this is a longer run that happens to span a brace rather than a
            // flag. The written-byte allowance alone lets one through.
            && !body.contains(&b'{')
            && written as f32 / body_len as f32 >= MIN_BODY_WRITTEN
            && (named.is_some() || recognised_tag(&data[tag_start..i]) || case_is_consistent(body));

        if tag_ok && body_ok {
            out.push(Found {
                offset: start,
                text: String::from_utf8_lossy(&data[start..=close]).into_owned(),
            });
            i = close + 1;
        } else {
            i += 1;
        }
    }

    out
}

/// Accepts whatever follows the magic. For signatures long or odd enough that
/// finding one is already the evidence.
fn always(_: &[u8], _: usize) -> bool {
    true
}

/// gzip: the only defined compression method is deflate, and the reserved bits
/// of FLG are zero.
fn gzip_flags(data: &[u8], at: usize) -> bool {
    data.get(at + 2) == Some(&0x08) && data.get(at + 3).is_some_and(|&flg| flg & 0xe0 == 0)
}

/// JPEG at the start of a file: the byte after SOI names a marker. Enough there, where
/// nothing has to be found by chance, and an encoder can open with any of them.
fn jpeg_opening(data: &[u8], at: usize) -> bool {
    matches!(data.get(at + 3), Some(0xc0..=0xfe))
}

/// JPEG part way through a file: the byte after SOI begins a segment a file usually
/// opens with, and that segment's length lands on the next marker. Three bytes and a
/// marker class alone turn up by chance in any file of a few megabytes.
fn jpeg_segment(data: &[u8], at: usize) -> bool {
    if !matches!(
        data.get(at + 3),
        Some(0xe0..=0xef) | Some(0xdb) | Some(0xc0) | Some(0xc4) | Some(0xfe)
    ) {
        return false;
    }
    let Some(field) = data.get(at + 4..at + 6) else {
        return false;
    };
    let length = u16::from_be_bytes([field[0], field[1]]) as usize;
    length >= 2 && data.get(at + 4 + length) == Some(&0xff)
}

/// GIF: the version field is either 87a or 89a.
fn gif_version(data: &[u8], at: usize) -> bool {
    matches!(data.get(at + 4), Some(b'7') | Some(b'9')) && data.get(at + 5) == Some(&b'a')
}

/// BMP: the declared file size has to fit in what is left of the buffer, the
/// reserved field is zero, and the info header is one of the sizes the format
/// defines. Two magic bytes alone turn up constantly by chance.
fn bmp_size(data: &[u8], at: usize) -> bool {
    let Some(header) = data.get(at..at + 18) else {
        return false;
    };
    let declared = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
    let info = u32::from_le_bytes([header[14], header[15], header[16], header[17]]);
    (26..=data.len() - at).contains(&declared)
        && header[6..10] == [0, 0, 0, 0]
        && matches!(info, 12 | 16 | 40 | 52 | 56 | 64 | 108 | 124)
}

/// BMP at the start of a file: the info header is one of the sizes the format defines.
/// That is three zero bytes in a row, which no readable text has, and it is all that
/// is asked here. The size can be wrong and the reserved bytes can hold something on a
/// doctored bitmap, which is still a bitmap.
fn bmp_info(data: &[u8], at: usize) -> bool {
    data.get(at + 14..at + 18).is_some_and(|field| {
        matches!(
            u32::from_le_bytes([field[0], field[1], field[2], field[3]]),
            12 | 16 | 40 | 52 | 56 | 64 | 108 | 124
        )
    })
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

/// Registry hive: the base block's major version, which has only ever been 1. The
/// magic alone is four lowercase letters, and a rotation of ordinary text reaches
/// those as easily as any others.
fn hive_version(data: &[u8], at: usize) -> bool {
    data.get(at + 0x14..at + 0x18) == Some(&[1, 0, 0, 0])
}

/// pcapng: the byte-order magic a Section Header Block carries. The block type alone
/// is a pair of line endings.
fn pcapng_order(data: &[u8], at: usize) -> bool {
    matches!(
        data.get(at + 8..at + 12),
        Some([0x4d, 0x3c, 0x2b, 0x1a]) | Some([0x1a, 0x2b, 0x3c, 0x4d])
    )
}

/// A signature plus whatever extra check keeps it from firing on noise.
///
/// Short magics are the problem. Two bytes match roughly once every 64 KB of
/// random data, so scanning half a megabyte for `BM` alone would report eight
/// imaginary bitmaps. Each short signature therefore carries a validator that
/// tests a field the format actually constrains.
///
/// Readable text has the same problem at offset zero: `TELL ME` rotates to `BMTT UM`,
/// and calling that a bitmap makes it the answer. So naming a format asks the same
/// question scanning for one does.
struct Signature {
    magic: &'static [u8],
    label: &'static str,
    /// What has to hold for a file to open with this format.
    opening: fn(&[u8], usize) -> bool,
    /// What has to hold for this format to be reported part way through a file.
    /// None for the ones not worth carving out.
    embedded: Option<fn(&[u8], usize) -> bool>,
}

const fn signature(
    magic: &'static [u8],
    label: &'static str,
    opening: fn(&[u8], usize) -> bool,
    embedded: Option<fn(&[u8], usize) -> bool>,
) -> Signature {
    Signature {
        magic,
        label,
        opening,
        embedded,
    }
}

const SIGNATURES: [Signature; 19] = [
    signature(b"\x89PNG\r\n\x1a\n", "PNG image", always, Some(always)),
    signature(b"\xff\xd8\xff", "JPEG image", jpeg_opening, Some(jpeg_segment)),
    signature(b"GIF8", "GIF image", gif_version, Some(gif_version)),
    signature(b"BM", "BMP image", bmp_info, Some(bmp_size)),
    signature(b"PK\x03\x04", "ZIP archive", always, Some(always)),
    signature(b"\x1f\x8b", "gzip stream", gzip_flags, Some(gzip_flags)),
    signature(b"BZh", "bzip2 stream", bzip_level, Some(bzip_level)),
    signature(b"7z\xbc\xaf\x27\x1c", "7-Zip archive", always, Some(always)),
    signature(b"Rar!\x1a\x07", "RAR archive", always, Some(always)),
    signature(b"%PDF", "PDF document", always, Some(always)),
    signature(b"regf", "Windows registry hive", hive_version, None),
    signature(b"\x7fELF", "ELF binary", always, Some(always)),
    signature(b"RIFF", "RIFF container", riff_type, Some(riff_type)),
    // Classic libpcap, all four byte orders and both timestamp resolutions.
    signature(b"\xd4\xc3\xb2\xa1", "packet capture", always, None),
    signature(b"\xa1\xb2\xc3\xd4", "packet capture", always, None),
    signature(b"\x4d\x3c\xb2\xa1", "packet capture", always, None),
    signature(b"\xa1\xb2\x3c\x4d", "packet capture", always, None),
    // pcapng, whose first block is always a Section Header Block.
    signature(b"\x0a\x0d\x0d\x0a", "packet capture", pcapng_order, None),
    // SQLite, so the header line names one before the database reader runs.
    signature(b"SQLite format 3\x00", "SQLite database", always, None),
];

/// Names the format a byte run starts with, if any.
pub fn identify(data: &[u8]) -> Option<&'static str> {
    SIGNATURES
        .iter()
        .find(|signature| data.starts_with(signature.magic) && (signature.opening)(data, 0))
        .map(|signature| signature.label)
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

/// The next place one terminator occurs, remembered between questions.
///
/// Questions arrive in file order, so an answer stays good until the scan passes it,
/// and "none" stays good for the rest of the file. Asking afresh each time rescans to
/// the end of the file for every signature, which is quadratic on a file made of
/// nothing but signatures.
struct Ahead<'a> {
    data: &'a [u8],
    needle: &'static [u8],
    next: Option<usize>,
    exhausted: bool,
}

impl<'a> Ahead<'a> {
    fn new(data: &'a [u8], needle: &'static [u8]) -> Self {
        Self {
            data,
            needle,
            next: None,
            exhausted: false,
        }
    }

    fn at_or_after(&mut self, at: usize) -> Option<usize> {
        if self.exhausted {
            return None;
        }
        if self.next.is_none_or(|next| next < at) {
            self.next = find(self.data, at, self.needle);
            self.exhausted = self.next.is_none();
        }
        self.next
    }
}

/// Where embedded files end, for the formats that say so.
///
/// Carving without this is guesswork: you get the file plus everything after it.
/// Each of these terminators is defined by the format, so the extraction is
/// exact rather than approximate.
struct Extents<'a> {
    data: &'a [u8],
    iend: Ahead<'a>,
    eoi: Ahead<'a>,
    end_of_directory: Ahead<'a>,
    /// The last `%%EOF` in the file, since a PDF may be appended to several times.
    pdf_end: Option<usize>,
}

impl<'a> Extents<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            iend: Ahead::new(data, b"IEND"),
            eoi: Ahead::new(data, &[0xff, 0xd9]),
            end_of_directory: Ahead::new(data, b"PK\x05\x06"),
            pdf_end: data.windows(5).rposition(|w| w == b"%%EOF"),
        }
    }

    fn of(&mut self, at: usize, label: &str) -> Option<usize> {
        match label {
            // The IEND chunk is the last thing in a PNG: type, then a four-byte CRC.
            "PNG image" => self.iend.at_or_after(at).map(|p| p + 8),
            // End of image.
            "JPEG image" => self.eoi.at_or_after(at + 2).map(|p| p + 2),
            // End of central directory, then a variable-length comment.
            "ZIP archive" => self.end_of_directory.at_or_after(at).and_then(|p| {
                let comment = self.data.get(p + 20..p + 22)?;
                Some(p + 22 + u16::from_le_bytes([comment[0], comment[1]]) as usize)
            }),
            "PDF document" => self.pdf_end.filter(|&p| p >= at).map(|p| p + 5),
            _ => None,
        }
    }
}

/// Most signatures one scan reports. Each is four bytes of file and a line of JSON,
/// so a file of nothing else would ask for twenty times its own size.
const MAX_HITS: usize = 4096;

/// Which bytes can begin a signature the scan looks for, so most of a file is one
/// table lookup rather than a comparison per signature.
const SCAN_STARTS: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < SIGNATURES.len() {
        if SIGNATURES[i].embedded.is_some() {
            table[SIGNATURES[i].magic[0] as usize] = true;
        }
        i += 1;
    }
    table
};

/// Every file signature anywhere in the buffer, not only at offset zero.
///
/// This is the binwalk move: a container appended to or embedded inside another
/// file announces itself with its own magic, wherever it happens to sit.
pub fn magic_scan(data: &[u8]) -> Vec<MagicHit> {
    let mut found = Vec::new();

    'scan: for at in 0..data.len() {
        if !SCAN_STARTS[data[at] as usize] {
            continue;
        }
        for candidate in &SIGNATURES {
            let Some(validate) = candidate.embedded else {
                continue;
            };
            if data[at..].starts_with(candidate.magic) && validate(data, at) {
                found.push((at, candidate.label));
                if found.len() >= MAX_HITS {
                    break 'scan;
                }
                break;
            }
        }
    }

    let mut extents = Extents::new(data);

    // A second pass, because an unbounded file runs until the next one starts.
    found
        .iter()
        .enumerate()
        .map(|(i, &(at, label))| {
            let next = found.get(i + 1).map(|&(o, _)| o).unwrap_or(data.len());
            match extents.of(at, label) {
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
    fn magic_scan_ignores_a_jpeg_signature_with_no_next_segment() {
        // The opening bytes alone, as they turn up by chance in audio samples.
        let mut data = vec![0x11u8; 64];
        data[20..26].copy_from_slice(&[0xff, 0xd8, 0xff, 0xe0, 0x00, 0x05]);
        assert!(!magic_scan(&data).iter().any(|hit| hit.label == "JPEG image"));
    }

    #[test]
    fn magic_scan_ignores_a_bmp_signature_with_no_real_header() {
        let mut data = vec![0x11u8; 64];
        data[20..26].copy_from_slice(&[b'B', b'M', 30, 0, 0, 0]);
        assert!(!magic_scan(&data).iter().any(|hit| hit.label == "BMP image"));
    }

    #[test]
    fn magic_scan_measures_a_jpeg_to_its_end_of_image_marker() {
        let mut data = vec![0u8; 32];
        let at = data.len();
        data.extend_from_slice(&[0xff, 0xd8, 0xff, 0xe0, 0x00, 0x14]);
        data.extend_from_slice(&[0u8; 18]);
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
        data[14] = 40;
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
    fn configured_flag_tags_match_on_the_ending_of_the_tag() {
        let tags = vec!["picoCTF".to_string(), "event".to_string()];
        let found = flag_candidates_for_tags(
            b"picoCTF{first_flag} testCTF{not_selected} event{second_flag}",
            &tags,
        );
        let texts: Vec<&str> = found.iter().map(|found| found.text.as_str()).collect();

        assert_eq!(texts, vec!["picoCTF{first_flag}", "event{second_flag}"]);
        assert!(tag_is_known_for("PICOctf{case_insensitive}", &tags));
        assert!(!tag_is_known_for("testCTF{not_selected}", &tags));
        assert!(tag_is_known_for("testCTF{event_name_in_front}", &["CTF".to_string()]));
        assert!(!tag_is_known_for("CTFtest{ending_differs}", &["CTF".to_string()]));
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

    /// `TELL ME` rotates to `BMTT UM`, and calling that a bitmap made a readable
    /// sentence lose to its own ciphertext.
    #[test]
    fn identify_asks_more_of_a_signature_than_its_first_bytes() {
        assert_eq!(identify(b"BMTT UM ALPE LOP VPJZPE KPZZHNP"), None);
        assert_eq!(identify(b"BM not a bitmap, just text"), None);
        assert_eq!(identify(b"BZhello there"), None);
        assert_eq!(identify(b"GIF8 is not a version"), None);
        assert_eq!(identify(b"RIFF raff and other riff raff"), None);
        assert_eq!(identify(b"regf is four letters"), None);
        assert_eq!(identify(b"\x0a\x0d\x0d\x0ajust some line endings"), None);
        assert_eq!(identify(&[0x1f, 0x8b, 0x41, 0x41]), None);
        assert_eq!(identify(&[0xff, 0xd8, 0xff, 0x41]), None);

        assert_eq!(identify(b"BZh91AY&SY"), Some("bzip2 stream"));
        assert_eq!(identify(b"GIF89a"), Some("GIF image"));
        assert_eq!(identify(b"RIFF\0\0\0\0WAVE"), Some("RIFF container"));
        assert_eq!(identify(&[0x1f, 0x8b, 0x08, 0x00]), Some("gzip stream"));
        assert_eq!(identify(&[0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]), Some("JPEG image"));
        assert_eq!(identify(&[0xff, 0xd8, 0xff, 0xc2, 0x00, 0x11]), Some("JPEG image"));

        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&60u32.to_le_bytes());
        bmp.extend_from_slice(&[0u8; 64]);
        bmp[14] = 40;
        assert_eq!(identify(&bmp), Some("BMP image"));

        // A size that lies and reserved bytes holding something are what a doctored
        // bitmap looks like, and it is still one. Only the scan asks more of it.
        bmp[2..6].copy_from_slice(&u32::MAX.to_le_bytes());
        bmp[6..10].copy_from_slice(b"flag");
        assert_eq!(identify(&bmp), Some("BMP image"));
        assert!(magic_scan(&bmp).iter().all(|hit| hit.label != "BMP image"));

        let mut hive = b"regf".to_vec();
        hive.resize(4096, 0);
        hive[0x14] = 1;
        assert_eq!(identify(&hive), Some("Windows registry hive"));

        let mut capture = b"\x0a\x0d\x0d\x0a".to_vec();
        capture.extend_from_slice(&28u32.to_le_bytes());
        capture.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        assert_eq!(identify(&capture), Some("packet capture"));
    }

    /// Each signature rescanning to the end of the file for its terminator makes 800 KB
    /// of `PK\x03\x04` a minute and a half of work.
    #[test]
    fn a_file_of_nothing_but_signatures_scans_in_linear_time() {
        for magic in [&b"PK\x03\x04"[..], b"\x89PNG\r\n\x1a\n", b"%PDF", b"BZh9"] {
            let data = magic.repeat(8_000_000 / magic.len());

            let started = std::time::Instant::now();
            let hits = magic_scan(&data);

            assert_eq!(hits.len(), MAX_HITS, "the report has to stay bounded");
            assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
        }
    }

    #[test]
    fn a_remembered_terminator_is_still_the_right_one() {
        // Two archives and one terminator after each: the first must not be measured
        // to the second's end, and neither to one that sits before it.
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(b"PK\x05\x06");
        data.extend_from_slice(&[0u8; 18]);
        let second = data.len();
        data.extend_from_slice(b"PK\x03\x04");
        data.extend_from_slice(&[1u8; 8]);
        data.extend_from_slice(b"PK\x05\x06");
        data.extend_from_slice(&[0u8; 18]);

        let hits = magic_scan(&data);
        assert_eq!(hits.len(), 2);
        assert_eq!((hits[0].offset, hits[0].length), (0, 26));
        assert_eq!((hits[1].offset, hits[1].length), (second, 34));

        // No terminator after the last signature, though one sits before it.
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(b"PK\x05\x06");
        data.extend_from_slice(&[0u8; 18]);
        data.extend_from_slice(b"PK\x03\x04");
        let hits = magic_scan(&data);
        assert!(hits[0].bounded);
        assert!(!hits[1].bounded);
    }

    #[test]
    fn a_tag_anyone_would_recognise_settles_the_case_check() {
        for real in [&b"HTB{Y0u_F0uNd_1T}"[..], b"picoCTF{mIxEd_CaSe_FlAg}", b"flag{tHiS_iS_fInE}"] {
            assert_eq!(
                flag_candidates(real).len(),
                1,
                "{} was rejected",
                String::from_utf8_lossy(real)
            );
        }

        // The noise the check exists for has no such tag on it.
        assert!(flag_candidates(b"qWx{eLwaGqDnYDoZHt}").is_empty());
    }

    #[test]
    fn a_configured_tag_is_trusted_past_the_length_limits() {
        let short = vec!["HV".to_string()];
        let found = flag_candidates_for_tags(b"HV{some_flag_here}", &short);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "HV{some_flag_here}");

        let long = vec!["cyberapocalypse".to_string()];
        let found = flag_candidates_for_tags(b"..cyberapocalypse{some_flag_here}", &long);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "cyberapocalypse{some_flag_here}");
        assert_eq!(found[0].offset, 2);

        // Neither passes unnamed, which is what the limits are for.
        assert!(flag_candidates(b"HV{some_flag_here}").is_empty());
        assert!(flag_candidates(b"cyberapocalypse{some_flag_here}").is_empty());
    }

    #[test]
    fn a_configured_tag_is_trusted_past_the_case_check() {
        let tags = vec!["event".to_string()];
        let found = flag_candidates_for_tags(b"event{mIxEd_CaSe_BoDy}", &tags);
        assert_eq!(found[0].text, "event{mIxEd_CaSe_BoDy}");

        // Named or not, the body still has to look like a body.
        assert!(flag_candidates_for_tags(b"event{\x00\x01\x02\x03}", &tags).is_empty());
        assert!(flag_candidates_for_tags(b"event{ab}", &tags).is_empty());
        assert!(flag_candidates_for_tags(b"event{{{{{{{{}", &tags).is_empty());
    }

    #[test]
    fn a_configured_tag_at_the_end_of_a_long_run_is_reported_as_itself() {
        // Whatever precedes it is not part of the flag, and a run of a megabyte of
        // alphanumerics must not come back as one.
        let mut data = vec![b'x'; 1 << 20];
        data.extend_from_slice(b"HV{some_flag_here}");
        let found = flag_candidates_for_tags(&data, &["HV".to_string()]);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "HV{some_flag_here}");
        assert_eq!(found[0].offset, 1 << 20);
    }

    #[test]
    fn a_name_the_filter_never_asked_for_stays_filtered_out() {
        let tags = vec!["HV".to_string()];
        assert!(flag_candidates_for_tags(b"flag{not_configured}", &tags).is_empty());
        assert_eq!(flag_candidates_naming(b"flag{shaped_anyway}", &tags).len(), 1);
    }

    #[test]
    fn a_blank_configured_tag_names_nothing() {
        assert!(flag_candidates_naming(b"no{body_here}", &[String::new(), " ".to_string()]).is_empty());
    }

    #[test]
    fn a_file_of_flags_reports_a_bounded_number() {
        let found = flag_candidates(&b"flag{abcd}".repeat(MAX_FLAGS + 50));
        assert_eq!(found.len(), MAX_FLAGS);
    }
}
