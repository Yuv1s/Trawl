use super::*;
use crate::jpeg::fixture::{block, build, build_progressive, Pass, Spec};

#[test]
fn recovers_the_exact_coefficients_of_one_block() {
    let planted = block(&[(0, -37), (1, 12), (2, -1), (5, 3), (40, 1)]);
    let file = build(&Spec::grayscale(8, 8), &[vec![planted]]);

    let found = coefficients(&file).unwrap();
    assert_eq!(found.blocks.len(), 1);
    assert_eq!(found.blocks[0].len(), 1);
    assert_eq!(found.blocks[0][0], planted);
}

#[test]
fn a_block_of_nothing_but_dc_round_trips() {
    let planted = block(&[(0, 5)]);
    let file = build(&Spec::grayscale(8, 8), &[vec![planted]]);
    assert_eq!(coefficients(&file).unwrap().blocks[0][0], planted);
}

#[test]
fn an_entirely_empty_block_round_trips() {
    let file = build(&Spec::grayscale(8, 8), &[vec![[0i32; 64]]]);
    assert_eq!(coefficients(&file).unwrap().blocks[0][0], [0i32; 64]);
}

#[test]
fn carries_the_dc_predictor_across_blocks() {
    // DC is coded as a difference from the previous block, so getting the
    // running total wrong shifts every block after the first.
    let planted: Vec<Block> = vec![
        block(&[(0, 100)]),
        block(&[(0, 100)]),
        block(&[(0, -50)]),
        block(&[(0, 0)]),
    ];
    let file = build(&Spec::grayscale(32, 8), std::slice::from_ref(&planted));

    let found = coefficients(&file).unwrap();
    assert_eq!(found.blocks[0], planted);
}

#[test]
fn skips_a_run_of_sixteen_zeroes() {
    // Anything past a 15-zero gap needs a ZRL symbol, which is the one AC code
    // that carries no value with it.
    let planted = block(&[(0, 1), (1, 4), (30, -2)]);
    let file = build(&Spec::grayscale(8, 8), &[vec![planted]]);
    assert_eq!(coefficients(&file).unwrap().blocks[0][0], planted);
}

#[test]
fn reads_a_coefficient_in_the_last_position() {
    // Index 63 means no end-of-block symbol is written at all.
    let mut planted = [0i32; 64];
    planted[0] = 3;
    planted[63] = -1;
    let file = build(&Spec::grayscale(8, 8), &[vec![planted]]);
    assert_eq!(coefficients(&file).unwrap().blocks[0][0], planted);
}

#[test]
fn steps_over_a_stuffed_zero_byte() {
    // A literal 0xFF in the entropy stream is written 0xFF 0x00. Reading the
    // stuffed byte as data corrupts everything after it, so plant enough blocks
    // that one is certain to occur and check the tail is still exact.
    // Constructed rather than stumbled on. A DC of 12 is category 4, so its
    // code and its magnitude bits fill exactly one byte. The next AC code is
    // another eight bits. That leaves the following magnitude field starting on
    // a byte boundary, so a coefficient of 255, whose eight magnitude bits are
    // all ones, writes a literal 0xFF.
    let mut planted: Vec<Block> = vec![block(&[(0, 12), (1, 255)])];
    planted.extend((0..8).map(|i| block(&[(0, i * 3 - 9), (1, 6), (9, -4)])));

    let file = build(&Spec::grayscale(8 * 9, 8), std::slice::from_ref(&planted));
    assert!(
        file.windows(2).any(|w| w == [0xff, 0x00]),
        "the fixture never produced a stuffed byte, so this proves nothing"
    );

    assert_eq!(coefficients(&file).unwrap().blocks[0], planted);
}

#[test]
fn resets_the_predictor_at_a_restart_marker() {
    let planted: Vec<Block> = (0..8).map(|i| block(&[(0, 40 * (i + 1))])).collect();
    let spec = Spec {
        restart_interval: 2,
        ..Spec::grayscale(64, 8)
    };

    let file = build(&spec, std::slice::from_ref(&planted));
    let found = coefficients(&file).unwrap();

    assert_eq!(found.restart_interval, 2);
    assert_eq!(found.blocks[0], planted);
}

#[test]
fn interleaves_a_subsampled_colour_image() {
    // 4:2:0. Each MCU is four luma blocks then one of each chroma, and reading
    // that order wrong scrambles which component every block belongs to.
    let spec = Spec {
        width: 16,
        height: 16,
        components: vec![(1, 2, 2), (2, 1, 1), (3, 1, 1)],
        restart_interval: 0,
        progressive: false,
    };

    let luma: Vec<Block> = (0..4).map(|i| block(&[(0, i + 1), (1, 2)])).collect();
    let cb = vec![block(&[(0, -9)])];
    let cr = vec![block(&[(0, 21), (5, -3)])];

    let file = build(&spec, &[luma.clone(), cb.clone(), cr.clone()]);
    let found = coefficients(&file).unwrap();

    assert_eq!(found.frame.components.len(), 3);
    assert_eq!(found.blocks[0], luma);
    assert_eq!(found.blocks[1], cb);
    assert_eq!(found.blocks[2], cr);
    assert_eq!(found.total_blocks(), 6);
}

#[test]
fn reports_the_frame_the_header_declared() {
    let file = build(&Spec::grayscale(24, 16), &[vec![[0i32; 64]; 6]]);
    let found = coefficients(&file).unwrap();

    assert_eq!(found.frame.width, 24);
    assert_eq!(found.frame.height, 16);
    assert_eq!(found.frame.precision, 8);
    assert!(!found.frame.progressive);
    assert_eq!(found.frame.components[0].horizontal, 1);
}

#[test]
fn covers_a_partial_block_at_the_edge() {
    // 12 pixels wide is a block and a half, and JPEG pads to whole blocks, so
    // the decoder must expect two.
    let planted: Vec<Block> = vec![block(&[(0, 1)]), block(&[(0, 2)])];
    let file = build(&Spec::grayscale(12, 8), std::slice::from_ref(&planted));
    assert_eq!(coefficients(&file).unwrap().blocks[0], planted);
}

#[test]
fn keeps_the_quantization_table_it_was_given() {
    let file = build(&Spec::grayscale(8, 8), &[vec![[0i32; 64]]]);
    let found = coefficients(&file).unwrap();
    assert_eq!(found.quant[0], [1u16; 64]);
}

#[test]
fn refuses_a_progressive_scan_that_mixes_dc_and_ac() {
    // A SOF2 header over baseline-shaped scan data. The band covers 0 to 63,
    // which progressive never allows, and reading it as a DC scan would return
    // one coefficient per block and call the rest zero.
    let spec = Spec {
        progressive: true,
        ..Spec::grayscale(8, 8)
    };
    let file = build(&spec, &[vec![block(&[(0, 1)])]]);

    assert_eq!(
        coefficients(&file).unwrap_err(),
        DctError::Unsupported("a progressive scan mixing DC and AC coefficients")
    );
}

#[test]
fn says_so_when_the_file_is_not_a_jpeg() {
    assert_eq!(
        coefficients(b"\x89PNG\r\n\x1a\n").unwrap_err(),
        DctError::NotJpeg
    );
}

#[test]
fn says_so_when_there_is_no_frame_header() {
    let file = vec![0xff, 0xd8, 0xff, 0xd9];
    assert_eq!(coefficients(&file).unwrap_err(), DctError::NoFrame);
}

#[test]
fn returns_what_it_read_when_the_scan_is_cut_short() {
    let planted: Vec<Block> = (0..40).map(|i| block(&[(0, i), (1, 3)])).collect();
    let mut file = build(&Spec::grayscale(8 * 40, 8), &[planted]);

    // Lop off the tail of the entropy data, leaving the headers intact.
    file.truncate(file.len() - 40);

    let found = coefficients(&file).unwrap();

    // The buffer stays the size of the image, so the tail reads as zero. That is
    // only honest if the file says so, which is what the flag is for.
    assert_eq!(found.blocks[0].len(), 40);
    assert!(found.truncated);

    let carrying = found.blocks[0].iter().filter(|b| b[0] != 0).count();
    assert!(carrying > 0, "nothing decoded at all");
    assert!(carrying < 40, "the cut should have cost some blocks");
}

#[test]
fn a_whole_file_is_not_reported_as_truncated() {
    let planted: Vec<Block> = (0..8).map(|i| block(&[(0, i + 1), (1, 2)])).collect();
    let file = build(&Spec::grayscale(8 * 8, 8), std::slice::from_ref(&planted));

    let found = coefficients(&file).unwrap();
    assert!(!found.truncated);
    assert_eq!(found.blocks[0], planted);
    assert_eq!(found.scans, 1);
}

#[test]
fn sign_extends_the_way_the_specification_says() {
    // A leading one is positive, a leading zero negative.
    assert_eq!(extend(0b1, 1), 1);
    assert_eq!(extend(0b0, 1), -1);
    assert_eq!(extend(0b11, 2), 3);
    assert_eq!(extend(0b10, 2), 2);
    assert_eq!(extend(0b01, 2), -2);
    assert_eq!(extend(0b00, 2), -3);
    assert_eq!(extend(0, 0), 0);
    assert_eq!(extend(0b1000, 4), 8);
    assert_eq!(extend(0b0111, 4), -8);
}

#[test]
fn builds_canonical_codes_the_way_the_specification_says() {
    // Two codes of length 2 and one of length 3: 00, 01, then 100.
    let mut counts = [0u8; 16];
    counts[1] = 2;
    counts[2] = 1;
    let table = Huffman::build(&counts, vec![b'a', b'b', b'c']);

    assert_eq!(table.min_code[2], 0b00);
    assert_eq!(table.max_code[2], 0b01);
    assert_eq!(table.min_code[3], 0b100);
    assert_eq!(table.max_code[3], 0b100);
    assert_eq!(table.max_code[1], -1, "no codes of length 1 were assigned");
}

#[test]
fn the_zigzag_table_is_a_permutation() {
    let mut seen = [false; 64];
    for &i in &ZIGZAG {
        assert!(!seen[i], "index {i} appears twice");
        seen[i] = true;
    }
    assert!(seen.iter().all(|&s| s));
    assert_eq!(ZIGZAG[0], 0, "the DC term leads");
    assert_eq!(ZIGZAG[63], 63);
}

// Progressive JPEG.
//
// Every test here checks the progressive decode against the baseline decode of
// the same coefficients. A round trip through the progressive encoder alone
// would pass with a matching pair of bugs in the encoder and decoder; the
// baseline path has its own tests above, so comparing against it is a fixed
// reference rather than a second opinion.

/// Decodes the same blocks both ways and asserts they agree with each other and
/// with what was planted.
fn both_ways(spec: &Spec, blocks: &[Vec<Block>], passes: &[Pass]) -> Coefficients {
    let baseline = coefficients(&build(spec, blocks)).unwrap();

    let progressive_spec = Spec {
        progressive: true,
        width: spec.width,
        height: spec.height,
        components: spec.components.clone(),
        restart_interval: spec.restart_interval,
    };
    let progressive = coefficients(&build_progressive(&progressive_spec, blocks, passes)).unwrap();

    assert!(progressive.frame.progressive);
    assert!(!progressive.truncated, "the progressive file ran out of data");
    assert_eq!(
        progressive.blocks, baseline.blocks,
        "progressive and baseline disagree"
    );

    for (c, planted) in blocks.iter().enumerate() {
        assert_eq!(&progressive.blocks[c], planted, "component {c} came back wrong");
    }

    progressive
}

fn spectral_passes() -> Vec<Pass> {
    vec![
        Pass::dc(vec![0], 0, 0),
        Pass::ac(0, 1, 5, 0, 0),
        Pass::ac(0, 6, 63, 0, 0),
    ]
}

#[test]
fn reads_a_file_split_into_frequency_bands() {
    let planted: Vec<Block> = vec![
        block(&[(0, 40), (1, -3), (2, 7), (9, 1), (30, -2)]),
        block(&[(0, 12), (3, 4), (44, 1)]),
        block(&[(0, -8)]),
        block(&[(0, 0), (1, 1), (63, -1)]),
    ];

    let found = both_ways(
        &Spec::grayscale(32, 8),
        std::slice::from_ref(&planted),
        &spectral_passes(),
    );
    assert_eq!(found.scans, 3);
}

#[test]
fn reads_a_file_sent_one_bit_at_a_time() {
    // Successive approximation: each scan carries a lower bit of the same value.
    let planted: Vec<Block> = (0..12)
        .map(|i| block(&[(0, i * 9 - 40), (1, 13), (2, -6), (8, 3), (20, -11)]))
        .collect();

    let passes = vec![
        Pass::dc(vec![0], 0, 1),
        Pass::dc(vec![0], 1, 0),
        Pass::ac(0, 1, 63, 0, 1),
        Pass::ac(0, 1, 63, 1, 0),
    ];

    let found = both_ways(
        &Spec::grayscale(8 * 12, 8),
        std::slice::from_ref(&planted),
        &passes,
    );
    assert_eq!(found.scans, 4);
}

#[test]
fn reads_a_file_using_both_bands_and_bit_passes() {
    // What a real encoder emits: several bands, each refined afterwards.
    let planted: Vec<Block> = (0..16)
        .map(|i| {
            block(&[
                (0, 30 - i * 4),
                (1, 9),
                (2, -5),
                (4, 2),
                (11, -3),
                (28, 1),
                (55, -1),
            ])
        })
        .collect();

    let passes = vec![
        Pass::dc(vec![0], 0, 1),
        Pass::ac(0, 1, 5, 0, 2),
        Pass::ac(0, 6, 63, 0, 2),
        Pass::dc(vec![0], 1, 0),
        Pass::ac(0, 1, 63, 2, 1),
        Pass::ac(0, 1, 63, 1, 0),
    ];

    both_ways(
        &Spec::grayscale(8 * 16, 8),
        std::slice::from_ref(&planted),
        &passes,
    );
}

#[test]
fn reads_a_progressive_colour_image() {
    // Subsampled chroma, so the DC scan interleaves four luma blocks with one of
    // each chroma while the AC scans walk one component at a time.
    let spec = Spec {
        width: 32,
        height: 16,
        components: vec![(1, 2, 2), (2, 1, 1), (3, 1, 1)],
        restart_interval: 0,
        progressive: false,
    };

    let luma: Vec<Block> = (0..8)
        .map(|i| block(&[(0, i * 5 - 10), (1, 4), (17, -2)]))
        .collect();
    let cb: Vec<Block> = (0..2).map(|i| block(&[(0, i - 6), (2, 3)])).collect();
    let cr: Vec<Block> = (0..2).map(|i| block(&[(0, i + 9), (5, -4)])).collect();

    let passes = vec![
        Pass::dc(vec![0, 1, 2], 0, 0),
        Pass::ac(0, 1, 63, 0, 0),
        Pass::ac(1, 1, 63, 0, 0),
        Pass::ac(2, 1, 63, 0, 0),
    ];

    let found = both_ways(&spec, &[luma, cb, cr], &passes);

    assert_eq!(found.blocks[0].len(), 8);
    assert_eq!(found.blocks[1].len(), 2);
    assert_eq!(found.blocks[2].len(), 2);
}

#[test]
fn folds_long_runs_of_empty_blocks_into_one_symbol() {
    // Most blocks carry nothing above DC, which is what end-of-band runs exist
    // for. Getting the run accounting wrong shifts everything after it.
    let mut planted: Vec<Block> = (0..40).map(|i| block(&[(0, i)])).collect();
    planted[7] = block(&[(0, 7), (3, 5)]);
    planted[33] = block(&[(0, 33), (1, -2), (40, 1)]);

    both_ways(
        &Spec::grayscale(8 * 40, 8),
        std::slice::from_ref(&planted),
        &spectral_passes(),
    );
}

#[test]
fn walks_a_component_in_raster_order_not_mcu_order() {
    // A single-component AC scan addresses blocks row by row across the whole
    // component. On a subsampled image that is a different traversal from the
    // MCU order the DC scan used, and mixing them up scrambles the result.
    let spec = Spec {
        width: 64,
        height: 32,
        components: vec![(1, 2, 2), (2, 1, 1), (3, 1, 1)],
        restart_interval: 0,
        progressive: false,
    };

    let luma: Vec<Block> = (0..32).map(|i| block(&[(0, i - 16), (1, (i % 7) - 3)])).collect();
    let cb: Vec<Block> = (0..8).map(|i| block(&[(0, i), (2, 1)])).collect();
    let cr: Vec<Block> = (0..8).map(|i| block(&[(0, -i), (3, -1)])).collect();

    let passes = vec![
        Pass::dc(vec![0, 1, 2], 0, 0),
        Pass::ac(0, 1, 63, 0, 0),
        Pass::ac(1, 1, 63, 0, 0),
        Pass::ac(2, 1, 63, 0, 0),
    ];

    both_ways(&spec, &[luma, cb, cr], &passes);
}

#[test]
fn the_traversal_order_covers_every_block_exactly_once() {
    // Refinement scans revisit blocks the first scan already walked. Recording
    // those again would count every coefficient several times over, which would
    // quietly corrupt anything read out of the stream.
    let planted: Vec<Block> = (0..10).map(|i| block(&[(0, i), (1, 2), (9, -1)])).collect();

    let passes = vec![
        Pass::dc(vec![0], 0, 1),
        Pass::dc(vec![0], 1, 0),
        Pass::ac(0, 1, 63, 0, 1),
        Pass::ac(0, 1, 63, 1, 0),
    ];

    let found = both_ways(
        &Spec::grayscale(8 * 10, 8),
        std::slice::from_ref(&planted),
        &passes,
    );

    assert_eq!(found.order.len(), 10);
    let mut seen: Vec<usize> = found.order.iter().map(|&(_, at)| at).collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..10).collect::<Vec<_>>());
}

#[test]
fn refuses_a_progressive_ac_scan_covering_several_components() {
    let spec = Spec {
        width: 16,
        height: 8,
        components: vec![(1, 1, 1), (2, 1, 1)],
        restart_interval: 0,
        progressive: true,
    };

    let a = vec![block(&[(0, 1), (1, 2)]), block(&[(0, 3)])];
    let b = vec![block(&[(0, 4)]), block(&[(0, 5)])];

    let passes = vec![
        Pass::dc(vec![0, 1], 0, 0),
        Pass {
            components: vec![0, 1],
            spectral_start: 1,
            spectral_end: 63,
            approx_high: 0,
            approx_low: 0,
        },
    ];

    let file = build_progressive(&spec, &[a, b], &passes);
    assert_eq!(
        coefficients(&file).unwrap_err(),
        DctError::Unsupported("a progressive AC scan covering several components")
    );
}
