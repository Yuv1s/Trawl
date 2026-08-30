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
fn the_transparent_index_leaves_the_background_colour() {
    let mut b = simple(2, 1, vec![0, 1]);
    b.transparent = Some(0);
    // Make the logical background index 0, which paints red.
    let file = build(b);

    let (_, rgba) = decode(&file).unwrap();
    // Index 0 is transparent, so the logical background (index 0) shows through.
    assert_eq!(pixel(&rgba, 2, 0, 0), [255, 0, 0, 255], "transparent shows background");
    assert_eq!(pixel(&rgba, 2, 1, 0), [0, 255, 0, 255], "index 1 paints green");
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

/// One frame for the multi-frame builder: a sub-rectangle, an optional local
/// palette, interlace, transparency, delay, and disposal.
struct Frame {
    left: usize,
    top: usize,
    width: usize,
    height: usize,
    table: Option<Vec<[u8; 3]>>,
    indices: Vec<u8>,
    interlaced: bool,
    transparent: Option<u8>,
    delay: u16,
    disposal: u8,
}

impl Frame {
    fn full(width: usize, height: usize, indices: Vec<u8>) -> Self {
        Self {
            left: 0,
            top: 0,
            width,
            height,
            table: None,
            indices,
            interlaced: false,
            transparent: None,
            delay: 0,
            disposal: 1,
        }
    }
}

/// Builds a GIF with a shared global palette and several frames, each carrying
/// its own Graphic Control Extension so disposal and transparency are exercised.
fn build_multi(global: &[[u8; 3]], background: u8, frames: Vec<Frame>) -> Vec<u8> {
    let bits = (global.len().max(2).next_power_of_two().trailing_zeros().max(1) - 1) as u8;
    let entries = 2usize << bits;

    // Logical screen: wide enough for any frame with its left/top taken into account.
    let mut width = 0usize;
    let mut height = 0usize;
    for f in &frames {
        width = width.max(f.left + f.width);
        height = height.max(f.top + f.height);
    }

    let mut out = b"GIF89a".to_vec();
    out.extend_from_slice(&(width as u16).to_le_bytes());
    out.extend_from_slice(&(height as u16).to_le_bytes());
    out.push(0x80 | bits);
    out.push(background);
    out.push(0);
    for i in 0..entries {
        let [r, g, b] = global.get(i).copied().unwrap_or([0, 0, 0]);
        out.extend_from_slice(&[r, g, b]);
    }

    for f in &frames {
        // Graphic Control Extension: transparent flag, two zero delay bytes, then
        // disposal in bits 2-4 and the pack byte 0.
        let transparent_flag = if f.transparent.is_some() { 1 } else { 0 };
        out.extend_from_slice(&[
            0x21,
            0xf9,
            0x04,
            transparent_flag | (f.disposal << 2),
            f.delay.to_le_bytes()[0],
            f.delay.to_le_bytes()[1],
            f.transparent.unwrap_or(0),
            0x00,
        ]);

        out.push(0x2c);
        out.extend_from_slice(&(f.left as u16).to_le_bytes());
        out.extend_from_slice(&(f.top as u16).to_le_bytes());
        out.extend_from_slice(&(f.width as u16).to_le_bytes());
        out.extend_from_slice(&(f.height as u16).to_le_bytes());

        match &f.table {
            Some(t) => {
                let ft = (t.len().max(2).next_power_of_two().trailing_zeros().max(1) - 1) as u8;
                out.push(0x80 | if f.interlaced { 0x40 } else { 0 } | ft);
                for i in 0..(2usize << ft) {
                    let [r, g, b] = t.get(i).copied().unwrap_or([0, 0, 0]);
                    out.extend_from_slice(&[r, g, b]);
                }
            }
            None => out.push(if f.interlaced { 0x40 } else { 0 }),
        }

        // Smallest power of two that holds the palette index range, matching the
        // single-frame builder so the decoder's 2..=11 minimum is always met.
        let table_len = match &f.table {
            Some(t) => t.len(),
            None => global.len(),
        };
        let bits = (table_len.max(2).next_power_of_two().trailing_zeros().max(1) - 1) as u8;
        let ms = bits.max(1) + 1;
        out.push(ms);
        out.extend_from_slice(&chunked(&lzw_encode(ms, &f.indices)));
    }

    out.push(0x3b);
    out
}

/// Global palette with a distinct colour per index, plus a clear background.
const GLOBAL: [[u8; 3]; 4] = [
    [255, 0, 0],   // 0 red, also the background
    [0, 255, 0],   // 1 green
    [0, 0, 255],   // 2 blue
    [255, 255, 0], // 3 yellow
];

#[test]
fn consecutive_frames_composite_and_differ() {
    // Canvas is 2 wide. Frame 1 paints both pixels red; frame 2 recolours one.
    let file = build_multi(
        &GLOBAL,
        0,
        vec![
            Frame::full(2, 1, vec![0, 1]),
            Frame::full(2, 1, vec![0, 2]),
        ],
    );

    let (header, displayed, differences, capped) = decode_frames(&file).unwrap();
    assert_eq!((header.width, header.height), (2, 1));
    assert_eq!(header.frames, 2);
    assert!(!capped);

    assert_eq!(pixel(&displayed[0], 2, 0, 0), [255, 0, 0, 255]);
    assert_eq!(pixel(&displayed[0], 2, 1, 0), [0, 255, 0, 255]);
    assert_eq!(pixel(&displayed[1], 2, 1, 0), [0, 0, 255, 255]);

    // Only the second pixel changed between the frames.
    assert_eq!(differences.len(), 1);
    assert_eq!(pixel(&differences[0], 2, 0, 0), [0, 0, 0, 0]);
    assert_eq!(pixel(&differences[0], 2, 1, 0), [0, 255, 255, 0]);
}

#[test]
fn disposal_2_restores_the_background_for_later_frames() {
    // Frame 1 paints red + green. Frame 2 paints its whole band blue, then
    // disposes to background so frame 3 starts from red there. Frame 3 paints
    // green only on the right pixel, leaving the restored pixel as red.
    let file = build_multi(
        &GLOBAL,
        0,
        vec![
            Frame::full(2, 1, vec![0, 1]),
            Frame {
                disposal: 2,
                ..Frame::full(2, 1, vec![2, 2])
            },
            Frame {
                transparent: Some(0),
                ..Frame::full(2, 1, vec![0, 1])
            },
        ],
    );

    let (header, displayed, ..) = decode_frames(&file).unwrap();
    assert_eq!(header.frames, 3);
    assert_eq!(pixel(&displayed[1], 2, 0, 0), [0, 0, 255, 255], "frame 2 paints blue");
    // Frame 3: left pixel restored to background red, right pixel painted green.
    assert_eq!(pixel(&displayed[2], 2, 0, 0), [255, 0, 0, 255], "disposal to background");
    assert_eq!(pixel(&displayed[2], 2, 1, 0), [0, 255, 0, 255]);
}

#[test]
fn disposal_3_restores_the_pre_frame_canvas_for_later_frames() {
    // Frame 1: red + green. Frame 2 paints blue over both, then restores the
    // canvas to frame 1's snapshot so frame 3's left pixel starts red again.
    let file = build_multi(
        &GLOBAL,
        0,
        vec![
            Frame::full(2, 1, vec![0, 1]),
            Frame {
                disposal: 3,
                ..Frame::full(2, 1, vec![2, 2])
            },
            Frame {
                transparent: Some(0),
                ..Frame::full(2, 1, vec![0, 1])
            },
        ],
    );

    let (_, displayed, ..) = decode_frames(&file).unwrap();
    assert_eq!(pixel(&displayed[1], 2, 0, 0), [0, 0, 255, 255], "frame 2 paints blue");
    // Frame 3: left pixel restored to frame 1's red, right pixel painted green.
    assert_eq!(pixel(&displayed[2], 2, 0, 0), [255, 0, 0, 255], "disposal to previous");
    assert_eq!(pixel(&displayed[2], 2, 1, 0), [0, 255, 0, 255]);
}

#[test]
fn offsets_and_a_local_palette_paint_in_place() {
    // 2x2 canvas. Frame 1 fills it red. Frame 2 is a 1x1 rectangle at (1,1)
    // with its own palette so index 0 means white, not red.
    let file = build_multi(
        &GLOBAL,
        0,
        vec![
            Frame::full(2, 2, vec![0, 0, 0, 0]),
            Frame {
                left: 1,
                top: 1,
                width: 1,
                height: 1,
                table: Some(vec![[10, 20, 30]]),
                indices: vec![0],
                interlaced: false,
                transparent: None,
                delay: 0,
                disposal: 1,
            },
        ],
    );

    let (_, displayed, ..) = decode_frames(&file).unwrap();
    assert_eq!(pixel(&displayed[0], 2, 0, 0), [255, 0, 0, 255]);
    assert_eq!(pixel(&displayed[1], 2, 1, 1), [10, 20, 30, 255]);
    assert_eq!(pixel(&displayed[1], 2, 0, 0), [255, 0, 0, 255], "outside the local band");
}

#[test]
fn a_later_frame_can_be_interlaced() {
    // 2x4 canvas, interlaced frame paints every other row green over red.
    let indices = {
        let mut rows: Vec<usize> = Vec::new();
        for (start, step) in PASSES {
            let mut y = start;
            while y < 4 {
                rows.push(y);
                y += step;
            }
        }
        rows.iter().flat_map(|&_| vec![1u8; 2]).collect()
    };
    let file = build_multi(
        &GLOBAL,
        0,
        vec![
            Frame::full(2, 4, vec![0u8; 8]),
            Frame {
                interlaced: true,
                ..Frame::full(2, 4, indices)
            },
        ],
    );

    let (_, displayed, ..) = decode_frames(&file).unwrap();
    for y in 0..4 {
        assert_eq!(pixel(&displayed[1], 2, 0, y), [0, 255, 0, 255], "row {y}");
    }
}

#[test]
fn transparency_preserves_the_underlying_frame() {
    // Frame 1 fills red. Frame 2 is a 2x1 strip, index 0 of which is
    // transparent, so it leaves the red underneath.
    let file = build_multi(
        &GLOBAL,
        0,
        vec![
            Frame::full(2, 1, vec![0, 0]),
            Frame {
                transparent: Some(0),
                ..Frame::full(2, 1, vec![0, 2])
            },
        ],
    );

    let (_, displayed, ..) = decode_frames(&file).unwrap();
    assert_eq!(pixel(&displayed[1], 2, 0, 0), [255, 0, 0, 255], "transparent");
    assert_eq!(pixel(&displayed[1], 2, 1, 0), [0, 0, 255, 255]);
}

#[test]
fn a_frame_outside_the_canvas_is_refused() {
    // Hand-built: a 2x1 logical screen, then a frame at left 1 width 2 that would
    // reach column 3, one past the screen edge. build_multi sizes the screen to
    // fit, so this path needs a fixed screen.
    let bits = 1u8;
    let entries = 2usize << bits;
    let mut out = b"GIF89a".to_vec();
    out.extend_from_slice(&(2u16).to_le_bytes()); // screen width 2
    out.extend_from_slice(&(1u16).to_le_bytes()); // screen height 1
    out.push(0x80 | bits);
    out.push(0);
    out.push(0);
    for _ in 0..entries {
        out.extend_from_slice(&[0, 0, 0]);
    }
    out.push(0x2c);
    out.extend_from_slice(&(1u16).to_le_bytes()); // left 1
    out.extend_from_slice(&(0u16).to_le_bytes());
    out.extend_from_slice(&(2u16).to_le_bytes()); // width 2 -> reaches column 3
    out.extend_from_slice(&(1u16).to_le_bytes());
    out.push(0x00);
    let ms = 3u8;
    out.push(ms);
    out.extend_from_slice(&chunked(&lzw_encode(ms, &[1, 1])));
    out.push(0x3b);

    assert_eq!(decode(&out), Err(GifError::DimensionOverflow));
}

#[test]
fn empty_global_palette_reads_as_black_opaque() {
    // No global palette and no background: an index into the missing table falls
    // back to black, opaque, the documented safe default.
    let file = build_multi(&[], 0, vec![Frame::full(2, 1, vec![0, 1])]);
    let (_, rgba) = decode(&file).unwrap();
    assert_eq!(pixel(&rgba, 2, 0, 0), [0, 0, 0, 255]);
    assert_eq!(pixel(&rgba, 2, 1, 0), [0, 0, 0, 255]);
}

#[test]
fn over_the_frame_budget_reports_capped() {
    // The frame budget is 128; 200 declared frames trip the work cap so the
    // analysis reports capped, not malformed.
    let mut frames = Vec::new();
    for _ in 0..200 {
        frames.push(Frame::full(1, 1, vec![1]));
    }
    let file = build_multi(&GLOBAL, 0, frames);
    let (header, displayed, differences, capped) = decode_frames(&file).unwrap();
    assert!(capped);
    assert_eq!(displayed.len(), 128);
    assert_eq!(differences.len(), 127);
    assert_eq!(header.frames, 128);
}
