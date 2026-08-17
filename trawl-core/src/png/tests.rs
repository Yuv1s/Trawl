use super::*;

/// Forward row filter, the exact inverse of `unfilter`. Test-only: real PNGs are
/// filtered by the encoder that produced them, never by us.
fn filter_rows(raw: &[u8], stride: usize, bpp: usize, height: usize, filter_type: u8) -> Vec<u8> {
    let mut out = vec![0u8; (stride + 1) * height];

    for y in 0..height {
        out[y * (stride + 1)] = filter_type;
        for i in 0..stride {
            let cur = raw[y * stride + i];
            let a = if i >= bpp { raw[y * stride + i - bpp] } else { 0 };
            let b = if y > 0 { raw[(y - 1) * stride + i] } else { 0 };
            let c = if y > 0 && i >= bpp {
                raw[(y - 1) * stride + i - bpp]
            } else {
                0
            };

            let predictor = match filter_type {
                0 => 0,
                1 => a,
                2 => b,
                3 => ((a as u16 + b as u16) / 2) as u8,
                4 => paeth(a, b, c),
                _ => unreachable!(),
            };
            out[y * (stride + 1) + 1 + i] = cur.wrapping_sub(predictor);
        }
    }

    out
}

fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc32(&out[4..]).to_be_bytes());
    out
}

fn ihdr(width: u32, height: u32, bit_depth: u8, color_type: u8, interlace: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(13);
    data.extend_from_slice(&width.to_be_bytes());
    data.extend_from_slice(&height.to_be_bytes());
    data.extend_from_slice(&[bit_depth, color_type, 0, 0, interlace]);
    chunk(b"IHDR", &data)
}

/// A PNG carrying an empty IDAT. Pixel data is passed to `decode` separately, so
/// nothing here needs a deflate implementation.
fn png(width: u32, height: u32, bit_depth: u8, color_type: u8, extra: &[Vec<u8>]) -> Vec<u8> {
    let mut file = Vec::new();
    file.extend_from_slice(&SIGNATURE);
    file.extend_from_slice(&ihdr(width, height, bit_depth, color_type, 0));
    for part in extra {
        file.extend_from_slice(part);
    }
    file.extend_from_slice(&chunk(b"IDAT", &[]));
    file.extend_from_slice(&chunk(b"IEND", &[]));
    file
}

/// Deterministic, so a failure names one specific byte rather than a flaky run.
fn xorshift32(seed: u32) -> impl FnMut() -> u32 {
    let mut s = seed;
    move || {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        s
    }
}

fn payload(len: usize, base: u8) -> Vec<u8> {
    let mut next = xorshift32(0x5eed);
    (0..len).map(|_| (base & 0xfe) | (next() & 1) as u8).collect()
}

#[test]
fn paeth_picks_the_predictor_nearest_the_estimate() {
    assert_eq!(paeth(0, 0, 0), 0);
    assert_eq!(paeth(10, 20, 30), 10, "p=0, a is nearest");
    assert_eq!(paeth(20, 10, 30), 10, "p=0, b is nearest");
    assert_eq!(paeth(200, 100, 150), 150, "p=150 lands on c exactly");
    assert_eq!(paeth(100, 200, 150), 150, "a and b tie, c is closer");
    assert_eq!(paeth(10, 10, 0), 10, "ties resolve toward a");
    assert_eq!(paeth(255, 255, 0), 255, "p=510 does not overflow u8");
}

#[test]
fn unfilter_inverts_every_filter_type() {
    let (stride, bpp, height) = (12usize, 3usize, 5usize);
    let raw = payload(stride * height, 0x80);

    for filter_type in 0..=4u8 {
        let filtered = filter_rows(&raw, stride, bpp, height, filter_type);
        let restored = unfilter(&filtered, stride, bpp, height).unwrap();
        assert_eq!(restored, raw, "filter type {filter_type} did not round-trip");
    }
}

#[test]
fn unfilter_rejects_an_unknown_filter_type() {
    let filtered = vec![9u8; 4];
    assert_eq!(
        unfilter(&filtered, 3, 1, 1),
        Err(PngError::BadFilterType(9))
    );
}

#[test]
fn unfilter_rejects_short_input_instead_of_reading_past_the_end() {
    assert_eq!(
        unfilter(&[0, 1, 2], 3, 1, 2),
        Err(PngError::ShortPixelData {
            expected: 8,
            actual: 3
        })
    );
}

#[test]
fn header_reads_ihdr() {
    let file = png(7, 3, 8, 6, &[]);
    assert_eq!(
        header(&file).unwrap(),
        Header {
            width: 7,
            height: 3,
            bit_depth: 8,
            color_type: 6,
            interlace: 0
        }
    );
}

#[test]
fn header_rejects_files_that_are_not_png() {
    assert_eq!(header(b"\xff\xd8\xff\xe0JFIF"), Err(PngError::NotPng));
}

#[test]
fn header_accepts_sixteen_bit_truecolour() {
    let file = png(4, 4, 16, 2, &[]);
    assert_eq!(header(&file).unwrap().bit_depth, 16);
}

#[test]
fn header_rejects_depth_and_colour_combinations_the_spec_forbids() {
    // A palette cannot be 16 bits deep; indices are at most 8.
    assert_eq!(
        header(&png(4, 4, 16, 3, &[])),
        Err(PngError::UnsupportedBitDepth {
            color_type: 3,
            bit_depth: 16
        })
    );
    // Truecolour has no sub-byte form.
    assert_eq!(
        header(&png(4, 4, 4, 2, &[])),
        Err(PngError::UnsupportedBitDepth {
            color_type: 2,
            bit_depth: 4
        })
    );
}

#[test]
fn decode_takes_the_high_byte_of_a_sixteen_bit_sample() {
    let file = png(2, 1, 16, 2, &[]);
    // Two pixels, three channels, big-endian pairs.
    let raw = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44];
    let inflated = filter_rows(&raw, 12, 6, 1, 0);

    let rgba = decode(&file, &inflated).unwrap();
    assert_eq!(&rgba[0..4], &[0x12, 0x56, 0x9a, 255]);
    assert_eq!(&rgba[4..8], &[0xde, 0x11, 0x33, 255]);
}

#[test]
fn chunks_walks_the_file_and_checks_crcs() {
    let file = png(2, 2, 8, 2, &[]);
    let found = chunks(&file);

    let kinds: Vec<&[u8]> = found.iter().map(|c| &c.kind[..]).collect();
    assert_eq!(kinds, vec![&b"IHDR"[..], &b"IDAT"[..], &b"IEND"[..]]);
    assert!(found.iter().all(|c| c.crc_ok));
    assert_eq!(found[0].offset, SIGNATURE.len());
    assert_eq!(found[0].length, 13);
}

#[test]
fn chunks_flags_a_corrupt_crc_without_refusing_the_file() {
    let mut file = png(2, 2, 8, 2, &[]);
    let ihdr_crc = SIGNATURE.len() + 8 + 13;
    file[ihdr_crc] ^= 0xff;

    let found = chunks(&file);
    assert_eq!(found.len(), 3, "walk continues past the bad chunk");
    assert!(!found[0].crc_ok);
    assert!(found[1].crc_ok);
}

#[test]
fn chunks_stops_cleanly_on_a_length_field_that_overruns_the_file() {
    let mut file = Vec::new();
    file.extend_from_slice(&SIGNATURE);
    file.extend_from_slice(&ihdr(2, 2, 8, 2, 0));
    file.extend_from_slice(&0xffff_ffffu32.to_be_bytes());
    file.extend_from_slice(b"IDAT");

    let found = chunks(&file);
    assert_eq!(found.len(), 1, "IHDR parsed, the liar dropped");
    assert!(found[0].is(b"IHDR"));
}

#[test]
fn decode_preserves_every_bit_of_rgb() {
    let (width, height) = (16usize, 4usize);
    let raw = payload(width * height * 3, 0x80);
    let file = png(width as u32, height as u32, 8, 2, &[]);
    let inflated = filter_rows(&raw, width * 3, 3, height, 4);

    let rgba = decode(&file, &inflated).unwrap();

    for i in 0..width * height {
        assert_eq!(&rgba[i * 4..i * 4 + 3], &raw[i * 3..i * 3 + 3]);
        assert_eq!(rgba[i * 4 + 3], 255);
    }
}

/// The case the browser path corrupts: alpha below 255 with a payload in bit 0.
#[test]
fn decode_preserves_every_bit_of_translucent_rgba() {
    let (width, height) = (16usize, 4usize);
    let mut raw = payload(width * height * 4, 0x80);
    for i in 0..width * height {
        raw[i * 4 + 3] = 128;
    }

    let file = png(width as u32, height as u32, 8, 6, &[]);
    let inflated = filter_rows(&raw, width * 4, 4, height, 4);

    let rgba = decode(&file, &inflated).unwrap();
    assert_eq!(rgba, raw, "premultiplication must not touch these samples");
}

#[test]
fn decode_expands_a_palette_with_transparency() {
    let plte = chunk(b"PLTE", &[0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff]);
    let trns = chunk(b"tRNS", &[0x40, 0x80]);
    let file = png(4, 1, 8, 3, &[plte, trns]);
    let inflated = filter_rows(&[0, 1, 2, 1], 4, 1, 1, 0);

    let rgba = decode(&file, &inflated).unwrap();

    assert_eq!(&rgba[0..4], &[0xff, 0x00, 0x00, 0x40]);
    assert_eq!(&rgba[4..8], &[0x00, 0xff, 0x00, 0x80]);
    assert_eq!(&rgba[8..12], &[0x00, 0x00, 0xff, 0xff], "no tRNS entry, opaque");
    assert_eq!(&rgba[12..16], &[0x00, 0xff, 0x00, 0x80]);
}

#[test]
fn decode_unpacks_sub_byte_grayscale() {
    let file = png(8, 1, 1, 0, &[]);
    let inflated = filter_rows(&[0b1010_0110], 1, 1, 1, 0);

    let rgba = decode(&file, &inflated).unwrap();
    let levels: Vec<u8> = (0..8).map(|x| rgba[x * 4]).collect();

    assert_eq!(levels, vec![255, 0, 255, 0, 0, 255, 255, 0]);
}

#[test]
fn decode_keeps_gray_alpha_channels_separate() {
    let file = png(2, 1, 8, 4, &[]);
    let inflated = filter_rows(&[0x11, 0x22, 0x33, 0x44], 4, 2, 1, 0);

    let rgba = decode(&file, &inflated).unwrap();
    assert_eq!(&rgba[0..4], &[0x11, 0x11, 0x11, 0x22]);
    assert_eq!(&rgba[4..8], &[0x33, 0x33, 0x33, 0x44]);
}

/// Adam7 splits the image into seven passes, each filtered independently with
/// its own width. This builds one the way an encoder would, then checks every
/// pixel lands back where it started.
#[test]
fn decode_reassembles_an_adam7_interlaced_image() {
    const W: usize = 8;
    const H: usize = 8;

    // Each pixel gets a value derived from its position, so a misplacement shows.
    let colour = |x: usize, y: usize| [(x * 16 + 8) as u8, (y * 16 + 8) as u8, ((x ^ y) * 8) as u8];

    let mut interlaced = Vec::new();
    for (x0, y0, dx, dy) in ADAM7 {
        let pw = W.saturating_sub(x0).div_ceil(dx);
        let ph = H.saturating_sub(y0).div_ceil(dy);
        if pw == 0 || ph == 0 {
            continue;
        }

        let mut raw = Vec::with_capacity(pw * ph * 3);
        for row in 0..ph {
            for col in 0..pw {
                raw.extend_from_slice(&colour(x0 + col * dx, y0 + row * dy));
            }
        }
        interlaced.extend_from_slice(&filter_rows(&raw, pw * 3, 3, ph, 0));
    }

    let mut file = Vec::new();
    file.extend_from_slice(&SIGNATURE);
    file.extend_from_slice(&ihdr(W as u32, H as u32, 8, 2, 1));
    file.extend_from_slice(&chunk(b"IEND", &[]));

    let rgba = decode(&file, &interlaced).unwrap();

    for y in 0..H {
        for x in 0..W {
            let at = (y * W + x) * 4;
            assert_eq!(
                &rgba[at..at + 3],
                &colour(x, y),
                "pixel ({x}, {y}) landed in the wrong place"
            );
            assert_eq!(rgba[at + 3], 255);
        }
    }
}

#[test]
fn decode_rejects_an_unknown_interlace_method() {
    let mut file = Vec::new();
    file.extend_from_slice(&SIGNATURE);
    file.extend_from_slice(&ihdr(4, 4, 8, 2, 7));
    file.extend_from_slice(&chunk(b"IEND", &[]));

    assert_eq!(decode(&file, &[]), Err(PngError::Interlaced));
}

#[test]
fn an_interlaced_image_with_too_little_data_reports_it() {
    let mut file = Vec::new();
    file.extend_from_slice(&SIGNATURE);
    file.extend_from_slice(&ihdr(16, 16, 8, 2, 1));
    file.extend_from_slice(&chunk(b"IEND", &[]));

    assert!(matches!(
        decode(&file, &[0u8; 8]),
        Err(PngError::ShortPixelData { .. })
    ));
}

#[test]
fn decode_refuses_an_indexed_image_with_no_palette() {
    let file = png(2, 1, 8, 3, &[]);
    assert_eq!(decode(&file, &[0, 0, 1]), Err(PngError::MissingPalette));
}

#[test]
fn text_chunks_reads_text_and_reports_compressed_ones_as_unread() {
    let mut plain = b"Comment".to_vec();
    plain.push(0);
    plain.extend_from_slice(b"flag{not_hidden_very_well}");

    let mut compressed = b"Secret".to_vec();
    compressed.push(0);
    compressed.push(0);
    compressed.extend_from_slice(&[0x78, 0x9c, 0xff]);

    let file = png(2, 2, 8, 2, &[chunk(b"tEXt", &plain), chunk(b"zTXt", &compressed)]);
    let found = text_chunks(&file);

    assert_eq!(found.len(), 2);
    assert_eq!(found[0].keyword, "Comment");
    assert_eq!(found[0].text, "flag{not_hidden_very_well}");
    assert!(!found[0].compressed);

    assert_eq!(found[1].keyword, "Secret");
    assert_eq!(found[1].text, "", "not inflated here, so not claimed");
    assert!(found[1].compressed);
}

#[test]
fn text_chunks_reads_uncompressed_itxt_past_its_language_fields() {
    let mut data = b"Title".to_vec();
    data.extend_from_slice(&[0, 0, 0]);
    data.extend_from_slice(b"en");
    data.push(0);
    data.extend_from_slice(b"Titre");
    data.push(0);
    data.extend_from_slice("payload \u{e9}".as_bytes());

    let file = png(2, 2, 8, 2, &[chunk(b"iTXt", &data)]);
    let found = text_chunks(&file);

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].keyword, "Title");
    assert_eq!(found[0].text, "payload \u{e9}");
}

#[test]
fn located_flags_credits_a_match_in_a_text_chunk() {
    let mut text = b"Comment".to_vec();
    text.push(0);
    text.extend_from_slice(b"flag{in_the_open}");

    let file = png(2, 2, 8, 2, &[chunk(b"tEXt", &text)]);
    let found = located_flags(&file);

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].text, "flag{in_the_open}");
    assert_eq!(found[0].region, "inside tEXt");
    assert!(found[0].credible);
}

#[test]
fn located_flags_credits_a_match_after_iend() {
    let mut file = png(2, 2, 8, 2, &[]);
    file.extend_from_slice(b"flag{appended}");

    let found = located_flags(&file);
    assert_eq!(found[0].region, "after IEND");
    assert!(found[0].credible);
}

/// The CacheSleuth false positive: compressed bytes are near-uniform, so the
/// tag{payload} shape turns up by chance. Reporting it as a find is worse than
/// reporting nothing.
#[test]
fn located_flags_does_not_credit_a_match_inside_idat() {
    let mut file = Vec::new();
    file.extend_from_slice(&SIGNATURE);
    file.extend_from_slice(&ihdr(2, 2, 8, 2, 0));
    file.extend_from_slice(&chunk(b"IDAT", b"\x78\x01noise BM{GEBF} more noise"));
    file.extend_from_slice(&chunk(b"IEND", &[]));

    let found = located_flags(&file);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].text, "BM{GEBF}");
    assert_eq!(found[0].region, "inside IDAT");
    assert!(!found[0].credible, "a match in a deflate stream is a coincidence");
}

#[test]
fn located_flags_does_not_credit_a_match_inside_ztxt() {
    let mut data = b"Secret".to_vec();
    data.extend_from_slice(&[0, 0]);
    data.extend_from_slice(b"zz{abcd}");

    let file = png(2, 2, 8, 2, &[chunk(b"zTXt", &data)]);
    let found = located_flags(&file);

    assert_eq!(found[0].region, "inside zTXt");
    assert!(!found[0].credible);
}

#[test]
fn located_flags_credits_uncompressed_itxt_but_not_compressed_itxt() {
    let build = |compression_flag: u8| {
        let mut data = b"Title".to_vec();
        data.extend_from_slice(&[0, compression_flag, 0]);
        data.extend_from_slice(b"en");
        data.push(0);
        data.push(0);
        data.extend_from_slice(b"flag{itxt}");
        png(2, 2, 8, 2, &[chunk(b"iTXt", &data)])
    };

    assert!(located_flags(&build(0))[0].credible);
    assert!(!located_flags(&build(1))[0].credible);
}

#[test]
fn trailing_data_finds_bytes_parked_after_iend() {
    let mut file = png(2, 2, 8, 2, &[]);
    let end = file.len();
    file.extend_from_slice(b"PK\x03\x04stowaway");

    assert_eq!(trailing_data(&file), Some((end, 12)));
}

#[test]
fn trailing_data_is_absent_on_a_well_formed_file() {
    assert_eq!(trailing_data(&png(2, 2, 8, 2, &[])), None);
}

#[test]
fn ancillary_chunks_are_the_lowercase_ones() {
    assert!(is_ancillary(b"tEXt"));
    assert!(is_ancillary(b"sRGB"));
    assert!(!is_ancillary(b"IHDR"));
    assert!(!is_ancillary(b"IDAT"));
}

#[test]
fn structure_json_is_parseable_and_reports_the_walk() {
    let mut text = b"Comment".to_vec();
    text.push(0);
    text.extend_from_slice(b"quoted \" and \\ backslash");

    let mut file = png(3, 2, 8, 6, &[chunk(b"tEXt", &text)]);
    file.extend_from_slice(b"trailing");

    let json = structure_json(&file);

    assert!(json.starts_with('{') && json.ends_with('}'));
    assert!(json.contains("\"signature\":true"));
    assert!(json.contains("\"width\":3"));
    assert!(json.contains("\"colorType\":6"));
    assert!(json.contains("\"kind\":\"IHDR\""));
    assert!(json.contains("\"ancillary\":true"));
    assert!(json.contains("\"trailing\":{"));
    assert!(
        json.contains("quoted \\\" and \\\\ backslash"),
        "text payloads must be escaped, not concatenated raw"
    );
}

#[test]
fn structure_json_reports_the_header_error_rather_than_omitting_it() {
    let file = png(4, 4, 16, 3, &[]);
    let json = structure_json(&file);

    assert!(json.contains("\"error\":\"bit depth 16 unsupported for colour type 3\""));
    assert!(json.contains("\"kind\":\"IHDR\""), "the walk still happens");
}

#[test]
fn idat_concatenates_split_chunks_in_order() {
    let mut file = Vec::new();
    file.extend_from_slice(&SIGNATURE);
    file.extend_from_slice(&ihdr(2, 2, 8, 2, 0));
    file.extend_from_slice(&chunk(b"IDAT", &[1, 2, 3]));
    file.extend_from_slice(&chunk(b"IDAT", &[4, 5]));
    file.extend_from_slice(&chunk(b"IEND", &[]));

    assert_eq!(idat(&file), vec![1, 2, 3, 4, 5]);
}
