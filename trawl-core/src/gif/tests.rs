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

/// A screen of any size carrying `frames` copies of a 1x1 frame, which is how little
/// file a big canvas takes.
fn tiny_frames_on(width: u16, height: u16, frames: usize) -> Vec<u8> {
    let mut out = b"GIF89a".to_vec();
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0]);
    for _ in 0..frames {
        out.push(0x2c);
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.push(0);
        out.push(2);
        out.extend_from_slice(&[2, 0x44, 0x01, 0]);
    }
    out.push(0x3b);
    out
}

#[test]
fn a_canvas_too_large_to_composite_is_refused_before_it_is_allocated() {
    // 29 bytes declaring 65535 x 65535. Times four it wraps a 32-bit usize, and it
    // was sixteen gigabytes of canvas on anything else.
    let file = tiny_frames_on(65_535, 65_535, 1);
    assert_eq!(file.len(), 29);
    assert_eq!(decode_frames(&file).unwrap_err(), GifError::WorkLimit);
    assert_eq!(decode(&file).unwrap_err(), GifError::WorkLimit);
}

#[test]
fn the_budget_counts_the_canvas_and_not_the_little_a_frame_paints() {
    // Two kilobytes of file. Counted by what each frame painted this was 128 pixels
    // and 16 gigabytes of canvases, so most of it has to stay undecoded.
    let file = tiny_frames_on(4000, 4000, 128);
    assert!(file.len() < 2048);

    let (header, displayed, differences, capped) = decode_frames(&file).unwrap();
    assert!(capped);
    assert_eq!(displayed.len(), MAX_COMPOSITED_PIXELS / (4000 * 4000));
    assert_eq!(differences.len(), displayed.len() - 1);
    assert_eq!(header.frames, displayed.len());
    assert_eq!(header.declared_frames, 128);
}

#[test]
fn the_first_frame_alone_does_not_decode_the_rest() {
    // A pixel tool wants one picture. A broken later frame is no reason to refuse it,
    // and building every canvas first is no way to get it.
    let mut file = tiny_frames_on(2, 2, 2);
    let last_code_size = file.len() - 6;
    file[last_code_size] = 1;

    assert!(decode_frames(&file).is_err(), "the fixture should break frame two");
    assert_eq!(decode(&file).unwrap().1.len(), 2 * 2 * 4);
}

#[test]
fn a_zero_sized_screen_is_refused() {
    let file = tiny_frames_on(0, 5, 0);
    assert_eq!(decode(&file).unwrap_err(), GifError::ZeroDimension);
    assert_eq!(decode_frames(&tiny_frames_on(5, 0, 0)).unwrap_err(), GifError::ZeroDimension);
    assert_eq!(decode(&tiny_frames_on(0, 0, 1)).unwrap_err(), GifError::ZeroDimension);
}

#[test]
fn frame_timing_is_carried_through() {
    let file = build_multi(
        &GLOBAL,
        0,
        vec![
            Frame {
                delay: 7,
                disposal: 2,
                ..Frame::full(2, 1, vec![0, 1])
            },
            Frame {
                delay: 250,
                disposal: 3,
                ..Frame::full(2, 1, vec![0, 2])
            },
        ],
    );

    let (header, ..) = decode_frames(&file).unwrap();
    assert_eq!(header.timings[0], Timing { delay: 7, disposal: 2 });
    assert_eq!(header.timings[1].delay, 250);
    assert_eq!(header.timings[1].disposal_name(), "previous");

    let json = analysis_json(&file, &[], 256, 4);
    assert!(crate::json::is_well_formed(&json), "{json}");
    assert!(json.contains("\"delay\":7"), "{json}");
    assert!(json.contains("\"disposal\":\"background\""), "{json}");
    assert!(json.contains("\"delay\":250"), "{json}");
    assert!(json.contains("\"kind\":\"difference\""), "{json}");
    assert!(json.contains("\"to\":2,\"delay\":null,\"disposal\":null"), "{json}");
}

#[test]
fn a_gif_this_reader_refuses_says_why() {
    let json = analysis_json(&tiny_frames_on(65_535, 65_535, 1), &[], 256, 4);
    assert!(crate::json::is_well_formed(&json), "{json}");
    assert!(json.contains("\"error\":\"the canvas is larger"), "{json}");
    assert!(json.contains("\"width\":65535"), "{json}");
    assert!(json.contains("\"sources\":[]"), "{json}");

    assert_eq!(analysis_json(b"not a gif", &[], 256, 4), "null");
}

#[test]
fn configured_tags_reach_the_frame_sweep() {
    // A two-letter tag is outside what an unnamed shape may be. The tags were accepted
    // and thrown away, so no frame could ever report one.
    let message = b"HV{hidden_in_a_frame}";
    let bits: Vec<u8> = message
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1))
        .collect();
    let width = 16usize;
    let height = bits.len().div_ceil(3).div_ceil(width);

    let mut indices = vec![0u8; width * height];
    for (i, chunk) in bits.chunks(3).enumerate() {
        // Colours whose low bits spell the three bits this pixel carries.
        indices[i] = chunk.iter().fold(0, |acc, bit| (acc << 1) | bit) << (3 - chunk.len());
    }
    let table: Vec<[u8; 3]> = (0..8)
        .map(|i| [((i >> 2) & 1) as u8, ((i >> 1) & 1) as u8, (i & 1) as u8])
        .collect();
    let file = build_multi(&table, 0, vec![Frame::full(width, height, indices)]);

    let named = analysis_json(&file, &["HV".to_string()], 256, 4);
    assert!(named.contains("\"flags\":[\"HV{hidden_in_a_frame}\"]"), "{named}");
    assert!(crate::json::is_well_formed(&named), "{named}");

    let unnamed = analysis_json(&file, &[], 256, 4);
    assert!(!unnamed.contains("\"flags\":[\"HV{hidden_in_a_frame}\"]"), "{unnamed}");
}

#[test]
fn bytes_after_the_trailer_are_found() {
    let mut file = build(simple(4, 4, vec![0u8; 16]));
    assert_eq!(trailing(&file), None);

    let end = file.len();
    file.extend_from_slice(b"appended");
    assert_eq!(trailing(&file), Some((end, 8)));

    assert_eq!(trailing(b"not a gif"), None);
    for cut in 0..end {
        assert_eq!(trailing(&file[..cut]), None, "cut at {cut}");
    }
}

/// One frame whose pixels carry a message in their low bits, then `more` single-pixel
/// frames: an ordinary long animation with something hidden in its first picture.
fn message_then_frames(message: &[u8], more: usize) -> Vec<u8> {
    let bits: Vec<u8> = message
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1))
        .collect();
    let width = 16usize;
    let height = bits.len().div_ceil(3).div_ceil(width);

    let mut indices = vec![0u8; width * height];
    for (i, chunk) in bits.chunks(3).enumerate() {
        indices[i] = chunk.iter().fold(0, |acc, bit| (acc << 1) | bit) << (3 - chunk.len());
    }
    let table: Vec<[u8; 3]> = (0..8)
        .map(|i| [((i >> 2) & 1) as u8, ((i >> 1) & 1) as u8, (i & 1) as u8])
        .collect();

    let mut frames = vec![Frame::full(width, height, indices)];
    frames.extend((0..more).map(|_| Frame::full(1, 1, vec![0])));
    build_multi(&table, 0, frames)
}

#[test]
fn more_frames_than_are_kept_does_not_cost_the_ones_that_are() {
    // Two hundred and fifty-seven frames in seven kilobytes used to refuse the file, and
    // the flag in the first frame went with it.
    for more in [256, 300, 1000] {
        let file = message_then_frames(b"flag{in_the_first_frame}", more);

        let (header, displayed, _, capped) = decode_frames(&file).unwrap();
        assert!(capped);
        assert_eq!(displayed.len(), MAX_FRAMES);
        assert_eq!(header.declared_frames, more + 1, "the rest are still counted");

        let json = analysis_json(&file, &[], 256, 4);
        assert!(crate::json::is_well_formed(&json), "{json}");
        assert!(json.contains("flag{in_the_first_frame}"), "more={more}");
        assert!(json.contains("\"capped\":true"));
        assert!(json.contains("\"error\":null"));

        assert!(decode(&file).is_ok(), "the pixel tools read this one too");
    }
}

#[test]
fn a_file_cut_off_after_a_frame_still_shows_that_frame() {
    let file = message_then_frames(b"flag{before_the_cut}", 3);
    let (_, whole) = decode(&file).unwrap();

    // Through the last frame's image data, then a marker that means nothing.
    let cut = &file[..file.len() - 4];
    let (_, first) = decode(cut).unwrap();
    assert_eq!(first, whole);

    let json = analysis_json(cut, &[], 256, 4);
    assert!(json.contains("flag{before_the_cut}"), "{json}");
    assert!(json.contains("\"stopped\":\"the file ends part way through a block\""), "{json}");

    let mut junk = file[..file.len() - 1].to_vec();
    junk.extend_from_slice(b"\x55\x55\x55");
    assert_eq!(decode(&junk).unwrap().1, whole);
}

#[test]
fn a_broken_frame_costs_the_frames_after_it_and_no_others() {
    let mut file = tiny_frames_on(2, 2, 3);
    let last_code_size = file.len() - 6;
    file[last_code_size] = 1;

    let json = analysis_json(&file, &[], 256, 4);
    assert!(crate::json::is_well_formed(&json), "{json}");
    assert!(json.contains("\"analysedFrames\":2"), "{json}");
    assert!(json.contains("\"stopped\":\"the compressed data contains an impossible code\""), "{json}");
    assert!(json.contains("\"error\":null"), "{json}");
}

#[test]
fn a_file_with_no_frame_to_show_is_still_refused() {
    let mut file = tiny_frames_on(2, 2, 1);
    file.truncate(file.len() - 3);
    assert_eq!(decode(&file).unwrap_err(), GifError::Truncated);

    let json = analysis_json(&file, &[], 256, 4);
    assert!(crate::json::is_well_formed(&json), "{json}");
    assert!(json.contains("\"error\":\"the file ends"), "{json}");
    assert!(json.contains("\"sources\":[]"), "{json}");

    assert_eq!(decode(&tiny_frames_on(2, 2, 0)).unwrap_err(), GifError::NoImage);
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
