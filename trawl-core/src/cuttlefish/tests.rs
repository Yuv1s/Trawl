use super::*;

fn xorshift32(seed: u32) -> impl FnMut() -> u32 {
    let mut s = seed;
    move || {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        s
    }
}

/// A cover whose low bits are random, which is the honest control: natural image
/// LSBs are close to uniform, so anything the sweep reports here is a false alarm.
fn clean_cover(pixels: usize, seed: u32) -> Vec<u8> {
    let mut next = xorshift32(seed);
    (0..pixels * 4).map(|_| (next() & 0xff) as u8).collect()
}

/// The inverse of `extract`, so a test can plant a payload at known parameters.
fn embed(rgba: &mut [u8], channels: &[usize], bit: u8, msb_first: bool, payload: &[u8]) {
    let mut bits = payload.iter().flat_map(|&byte| {
        (0..8).map(move |i| {
            if msb_first {
                (byte >> (7 - i)) & 1
            } else {
                (byte >> i) & 1
            }
        })
    });

    'pixels: for pixel in 0..rgba.len() / 4 {
        for &c in channels {
            let Some(value) = bits.next() else { break 'pixels };
            let at = pixel * 4 + c;
            rgba[at] = (rgba[at] & !(1 << bit)) | (value << bit);
        }
    }
}

#[test]
fn extract_inverts_embed_for_every_parameter_combination() {
    let payload = b"the quick brown fox";

    for (label, channels) in CHANNEL_SETS {
        for bit in 0..3u8 {
            for msb_first in [true, false] {
                let mut cover = clean_cover(2048, 0x1234);
                embed(&mut cover, channels, bit, msb_first, payload);

                let got = extract(&cover, channels, bit, msb_first, payload.len());
                assert_eq!(
                    got,
                    payload,
                    "{label} bit {bit} msb_first {msb_first} did not round-trip"
                );
            }
        }
    }
}

#[test]
fn extract_stops_at_the_byte_limit() {
    let cover = clean_cover(4096, 0x99);
    assert_eq!(extract(&cover, &[0, 1, 2], 0, true, 32).len(), 32);
}

#[test]
fn extract_reading_the_wrong_bit_plane_returns_something_else() {
    let mut cover = clean_cover(1024, 0x55);
    embed(&mut cover, &[0, 1, 2], 0, true, b"payload in plane zero");

    let wrong = extract(&cover, &[0, 1, 2], 1, true, 21);
    assert_ne!(wrong, b"payload in plane zero");
}

#[test]
fn sweep_finds_a_planted_flag_and_names_the_parameters() {
    let mut cover = clean_cover(40_000, 0xabcd);
    embed(&mut cover, &[0, 1, 2], 0, true, b"flag{hello}\x00");

    let found = sweep(&cover, false, 4096);
    let hit = found
        .iter()
        .find(|c| c.flags.iter().any(|f| f == "flag{hello}"))
        .expect("planted flag not recovered");

    assert_eq!(hit.params.channels, "rgb");
    assert_eq!(hit.params.bit, 0);
    assert!(hit.params.msb_first);
}

#[test]
fn sweep_finds_a_planted_file_signature() {
    let mut cover = clean_cover(40_000, 0x4242);
    embed(&mut cover, &[2, 1, 0], 0, true, b"PK\x03\x04and then some archive");

    let found = sweep(&cover, false, 4096);
    assert!(
        found
            .iter()
            .any(|c| c.params.channels == "bgr" && c.reason.contains("ZIP archive")),
        "signature in the bgr stream was missed"
    );
}

#[test]
fn sweep_finds_plain_text_with_no_flag_shape() {
    let mut cover = clean_cover(40_000, 0x7777);
    embed(
        &mut cover,
        &[0],
        0,
        true,
        b"meet me behind the bike sheds at midnight",
    );

    let found = sweep(&cover, false, 4096);
    assert!(found.iter().any(|c| c.params.channels == "r"));
}

/// A smooth image with random low bits. Its *upper* bit planes are highly ordered,
/// which is the case random noise does not exercise: extracting bit 1 of a gradient
/// yields long printable runs of 0x55, and bit 2 yields 0x33.
fn gradient_cover(width: usize, height: usize, seed: u32) -> Vec<u8> {
    let mut next = xorshift32(seed);
    let mut out = vec![0u8; width * height * 4];

    for y in 0..height {
        for x in 0..width {
            let o = (y * width + x) * 4;
            out[o] = ((x * 255 / width) as u8 & 0xfe) | (next() & 1) as u8;
            out[o + 1] = ((y * 255 / height) as u8 & 0xfe) | (next() & 1) as u8;
            out[o + 2] = (((x + y) * 255 / (width + height)) as u8 & 0xfe) | (next() & 1) as u8;
            out[o + 3] = 255;
        }
    }

    out
}

/// The single most important assertion in this module.
#[test]
fn sweep_reports_nothing_on_a_clean_random_cover() {
    for seed in [0x1111u32, 0x2222, 0x3333, 0x4444, 0x5555, 0xfeed, 0xbeef] {
        let cover = clean_cover(40_000, seed);
        let found = sweep(&cover, true, 4096);
        assert!(
            found.is_empty(),
            "false positive on clean cover seed {seed:#x}: {found:?}"
        );
    }
}

/// Regression: an earlier build reported eighteen hits on a gradient, every one of
/// them a repeated character out of an upper bit plane.
#[test]
fn sweep_reports_nothing_on_a_clean_gradient_cover() {
    for (w, h, seed) in [(200usize, 150usize, 0xaaaa_u32), (96, 96, 0x5eed), (320, 40, 0x1)] {
        let cover = gradient_cover(w, h, seed);
        let found = sweep(&cover, true, 4096);
        assert!(
            found.is_empty(),
            "false positive on a {w}x{h} gradient: {found:?}"
        );
    }
}

#[test]
fn sweep_still_finds_a_payload_hidden_in_a_gradient() {
    let mut cover = gradient_cover(200, 150, 0xaaaa);
    embed(&mut cover, &[0, 1, 2], 0, true, b"testCTF{hello}\x00");

    let found = sweep(&cover, true, 4096);
    assert!(
        found
            .iter()
            .any(|c| c.flags.iter().any(|f| f == "testCTF{hello}")),
        "variety filter must not eat a real payload"
    );
}

#[test]
fn a_long_run_of_one_repeated_character_is_not_a_payload() {
    let mut cover = gradient_cover(200, 150, 0x77);
    embed(&mut cover, &[0, 1, 2], 0, true, &[b'U'; 64]);

    let found = sweep(&cover, true, 4096);
    assert!(found.is_empty(), "structure was reported as a find: {found:?}");
}

#[test]
fn sweep_skips_alpha_combinations_when_there_is_no_alpha_channel() {
    let cover = clean_cover(4_000, 0x31337);
    assert_eq!(combination_count(false), 5 * 3 * 2);
    assert_eq!(combination_count(true), 7 * 3 * 2);
    assert!(sweep(&cover, false, 512).iter().all(|c| {
        c.params.channels != "a" && c.params.channels != "rgba"
    }));
}

#[test]
fn sweep_json_is_shaped_for_the_worker() {
    let mut cover = clean_cover(40_000, 0xc0ffee);
    embed(&mut cover, &[0, 1, 2], 0, true, b"flag{json}\x00");

    let json = sweep_json(&cover, false, 4096);
    assert!(json.starts_with('{') && json.ends_with('}'));
    assert!(json.contains("\"channels\":\"rgb\""));
    assert!(json.contains("\"msbFirst\":true"));
    assert!(json.contains("flag{json}"));
    assert!(json.contains("\"combinations\":30"));
}

#[test]
fn extract_named_rejects_a_channel_set_that_does_not_exist() {
    let cover = clean_cover(64, 1);
    assert!(extract_named(&cover, "xyz", 0, true, 16).is_none());
    assert!(extract_named(&cover, "rgb", 0, true, 16).is_some());
}
