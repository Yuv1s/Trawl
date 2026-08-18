use super::*;

/// The LZW encoder GIF expects, written only so the tests can produce input the
/// decoder has to get right. Nothing outside tests uses it.
fn lzw_encode(min_code_size: u8, indices: &[u8]) -> Vec<u8> {
    let clear = 1u16 << min_code_size;
    let end = clear + 1;

    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut held = 0u8;
    let mut width = min_code_size + 1;

    let emit = |code: u16, width: u8, acc: &mut u32, held: &mut u8, out: &mut Vec<u8>| {
        *acc |= (code as u32) << *held;
        *held += width;
        while *held >= 8 {
            out.push((*acc & 0xff) as u8);
            *acc >>= 8;
            *held -= 8;
        }
    };

    // A dictionary keyed by the string it represents, which is slow and clear.
    let mut dict: Vec<Vec<u8>> = (0..clear).map(|i| vec![i as u8]).collect();
    dict.push(Vec::new()); // clear
    dict.push(Vec::new()); // end
    let mut next = end + 1;

    emit(clear, width, &mut acc, &mut held, &mut out);

    let mut current: Vec<u8> = Vec::new();
    for &value in indices {
        let mut candidate = current.clone();
        candidate.push(value);

        if dict.contains(&candidate) {
            current = candidate;
            continue;
        }

        let code = dict.iter().position(|e| *e == current).unwrap() as u16;
        emit(code, width, &mut acc, &mut held, &mut out);

        if next < 4096 {
            dict.push(candidate);
            next += 1;
            if next == (1 << width) + 1 && width < 12 {
                width += 1;
            }
        }
        current = vec![value];
    }

    if !current.is_empty() {
        let code = dict.iter().position(|e| *e == current).unwrap() as u16;
        emit(code, width, &mut acc, &mut held, &mut out);
    }
    emit(end, width, &mut acc, &mut held, &mut out);

    if held > 0 {
        out.push((acc & 0xff) as u8);
    }
    out
}

fn chunked(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for block in data.chunks(255) {
        out.push(block.len() as u8);
        out.extend_from_slice(block);
    }
    out.push(0);
    out
}

struct Build {
    width: usize,
    height: usize,
    table: Vec<[u8; 3]>,
    indices: Vec<u8>,
    interlaced: bool,
    comment: Option<&'static str>,
    transparent: Option<u8>,
}

fn build(b: Build) -> Vec<u8> {
    let bits = (b.table.len().max(2).next_power_of_two().trailing_zeros().max(1) - 1) as u8;
    let entries = 2usize << bits;

    let mut out = b"GIF89a".to_vec();
    out.extend_from_slice(&(b.width as u16).to_le_bytes());
    out.extend_from_slice(&(b.height as u16).to_le_bytes());
    out.push(0x80 | bits);
    out.push(0);
    out.push(0);

    for i in 0..entries {
        let [r, g, bl] = b.table.get(i).copied().unwrap_or([0, 0, 0]);
        out.extend_from_slice(&[r, g, bl]);
    }

    if let Some(index) = b.transparent {
        out.extend_from_slice(&[0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, index, 0x00]);
    }
    if let Some(text) = b.comment {
        out.extend_from_slice(&[0x21, 0xfe]);
        out.extend_from_slice(&chunked(text.as_bytes()));
    }

    out.push(0x2c);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(b.width as u16).to_le_bytes());
    out.extend_from_slice(&(b.height as u16).to_le_bytes());
    out.push(if b.interlaced { 0x40 } else { 0x00 });

    let min_code_size = bits.max(1) + 1;
    out.push(min_code_size);
    out.extend_from_slice(&chunked(&lzw_encode(min_code_size, &b.indices)));

    out.push(0x3b);
    out
}

fn simple(width: usize, height: usize, indices: Vec<u8>) -> Build {
    Build {
        width,
        height,
        table: vec![[255, 0, 0], [0, 255, 0], [0, 0, 255], [255, 255, 0]],
        indices,
        interlaced: false,
        comment: None,
        transparent: None,
    }
}

fn pixel(rgba: &[u8], width: usize, x: usize, y: usize) -> [u8; 4] {
    let at = (y * width + x) * 4;
    [rgba[at], rgba[at + 1], rgba[at + 2], rgba[at + 3]]
}

#[test]
fn has_signature_accepts_both_versions() {
    assert!(has_signature(b"GIF87a"));
    assert!(has_signature(b"GIF89a"));
    assert!(!has_signature(b"GIF88a"));
    assert!(!has_signature(b"\x89PNG\r\n\x1a\n"));
}

/// The whole point of the module: LZW has to come back out exactly as it went in.
#[test]
fn lzw_round_trips_every_index() {
    let indices: Vec<u8> = (0..600).map(|i| (i * 7 % 4) as u8).collect();
    let file = build(simple(20, 30, indices.clone()));

    let (header, rgba) = decode(&file).unwrap();
    assert_eq!((header.width, header.height), (20, 30));

    let table = [[255u8, 0, 0], [0, 255, 0], [0, 0, 255], [255, 255, 0]];
    for (i, &index) in indices.iter().enumerate() {
        let [r, g, b] = table[index as usize];
        assert_eq!(
            pixel(&rgba, 20, i % 20, i / 20),
            [r, g, b, 255],
            "pixel {i} decoded wrong"
        );
    }
}

#[test]
fn lzw_handles_a_long_run_of_one_value() {
    let indices = vec![2u8; 4000];
    let file = build(simple(80, 50, indices));

    let (_, rgba) = decode(&file).unwrap();
    for i in 0..4000 {
        assert_eq!(pixel(&rgba, 80, i % 80, i / 80), [0, 0, 255, 255]);
    }
}

#[test]
fn the_dictionary_resets_and_keeps_decoding() {
    // Enough distinct runs to grow the code width more than once.
    let indices: Vec<u8> = (0..3000).map(|i| ((i / 3) % 4) as u8).collect();
    let file = build(simple(60, 50, indices.clone()));

    let (_, rgba) = decode(&file).unwrap();
    let table = [[255u8, 0, 0], [0, 255, 0], [0, 0, 255], [255, 255, 0]];
    for (i, &index) in indices.iter().enumerate() {
        let [r, g, b] = table[index as usize];
        assert_eq!(pixel(&rgba, 60, i % 60, i / 60), [r, g, b, 255]);
    }
}

#[test]
fn an_interlaced_gif_lands_its_rows_in_the_right_order() {
    let (w, h) = (8usize, 8usize);
    // Row n is painted entirely with index n % 4.
    let stored: Vec<u8> = {
        let mut rows: Vec<usize> = Vec::new();
        for (start, step) in PASSES {
            let mut y = start;
            while y < h {
                rows.push(y);
                y += step;
            }
        }
        rows.iter().flat_map(|&y| vec![(y % 4) as u8; w]).collect()
    };

    let mut b = simple(w, h, stored);
    b.interlaced = true;
    let file = build(b);

    let (_, rgba) = decode(&file).unwrap();
    let table = [[255u8, 0, 0], [0, 255, 0], [0, 0, 255], [255, 255, 0]];
    for y in 0..h {
        let [r, g, bl] = table[y % 4];
        assert_eq!(pixel(&rgba, w, 0, y), [r, g, bl, 255], "row {y}");
    }
}

#[test]
fn comments_are_read_as_text() {
    let mut b = simple(4, 4, vec![0u8; 16]);
    b.comment = Some("flag{in_a_gif_comment}");
    let file = build(b);

    let found = comments(&file);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, "flag{in_a_gif_comment}");
}

#[test]
fn the_transparent_index_becomes_zero_alpha() {
    let mut b = simple(2, 1, vec![0, 1]);
    b.transparent = Some(0);
    let file = build(b);

    let (_, rgba) = decode(&file).unwrap();
    assert_eq!(pixel(&rgba, 2, 0, 0)[3], 0, "index 0 is transparent");
    assert_eq!(pixel(&rgba, 2, 1, 0)[3], 255);
}

#[test]
fn the_frame_count_is_reported() {
    let file = build(simple(4, 4, vec![0u8; 16]));
    assert_eq!(decode(&file).unwrap().0.frames, 1);
}

#[test]
fn something_that_is_not_a_gif_is_refused() {
    assert_eq!(decode(b"\x89PNG\r\n\x1a\n"), Err(GifError::NotGif));
    assert_eq!(decode(&[]), Err(GifError::NotGif));
}

#[test]
fn a_truncated_file_does_not_panic() {
    let mut b = simple(8, 8, (0..64).map(|i| (i % 4) as u8).collect());
    b.comment = Some("something");
    let file = build(b);

    for cut in 0..file.len() {
        let _ = decode(&file[..cut]);
        let _ = comments(&file[..cut]);
    }
}
