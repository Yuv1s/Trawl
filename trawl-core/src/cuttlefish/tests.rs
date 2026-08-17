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

/// Sweeps a buffer with no meaningful geometry. Height one makes column-major
/// identical to row-major, which is what these tests want.
fn sweep_flat(cover: &[u8], has_alpha: bool, max_bytes: usize) -> Vec<Candidate> {
    sweep(cover, cover.len() / 4, 1, has_alpha, max_bytes)
}

fn sweep_json_flat(cover: &[u8], has_alpha: bool, max_bytes: usize) -> String {
    sweep_json(cover, cover.len() / 4, 1, has_alpha, max_bytes)
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

    let found = sweep_flat(&cover, false, 4096);
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

    let found = sweep_flat(&cover, false, 4096);
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

    let found = sweep_flat(&cover, false, 4096);
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
        let found = sweep_flat(&cover, true, 4096);
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
        // Real geometry, so column-major traversal is exercised too. A gradient
        // read down its columns is just as ordered as one read along its rows.
        let found = sweep(&cover, w, h, true, 4096);
        assert!(
            found.is_empty(),
            "false positive on a {w}x{h} gradient: {found:?}"
        );
    }
}

#[test]
fn extract_columns_inverts_a_column_major_payload() {
    let (w, h) = (64usize, 48usize);
    let mut cover = gradient_cover(w, h, 0x2468);
    let payload = b"written down the columns";

    let mut bits = payload.iter().flat_map(|&byte| (0..8).map(move |i| (byte >> (7 - i)) & 1));
    'outer: for step in 0..w * h {
        let pixel = (step % h) * w + step / h;
        for c in 0..3 {
            let Some(bit) = bits.next() else { break 'outer };
            cover[pixel * 4 + c] = (cover[pixel * 4 + c] & 0xfe) | bit;
        }
    }

    let read = extract_columns(&cover, w, h, &[0, 1, 2], 0, true, payload.len());
    assert_eq!(read, payload);

    let row_major = extract(&cover, &[0, 1, 2], 0, true, payload.len());
    assert_ne!(row_major, payload, "the two orders must not agree");
}

/// The parameter BUILD_PLAN names and the sweep skipped until now.
#[test]
fn the_sweep_finds_a_payload_written_down_the_columns() {
    let (w, h) = (200usize, 150usize);
    let mut cover = gradient_cover(w, h, 0x1357);

    let payload = b"flag{column_major}\x00";
    let mut bits = payload.iter().flat_map(|&byte| (0..8).map(move |i| (byte >> (7 - i)) & 1));
    'outer: for step in 0..w * h {
        let pixel = (step % h) * w + step / h;
        for c in 0..3 {
            let Some(bit) = bits.next() else { break 'outer };
            cover[pixel * 4 + c] = (cover[pixel * 4 + c] & 0xfe) | bit;
        }
    }

    let hit = sweep(&cover, w, h, true, 4096)
        .into_iter()
        .find(|c| c.flags.iter().any(|f| f == "flag{column_major}"))
        .expect("column-major payload not recovered");

    assert!(hit.params.column_major);
    assert_eq!(hit.params.channels, "rgb");
}

#[test]
fn sweep_still_finds_a_payload_hidden_in_a_gradient() {
    let mut cover = gradient_cover(200, 150, 0xaaaa);
    embed(&mut cover, &[0, 1, 2], 0, true, b"testCTF{hello}\x00");

    let found = sweep_flat(&cover, true, 4096);
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

    let found = sweep_flat(&cover, true, 4096);
    assert!(found.is_empty(), "structure was reported as a find: {found:?}");
}

#[test]
fn sweep_skips_alpha_combinations_when_there_is_no_alpha_channel() {
    let cover = clean_cover(4_000, 0x31337);
    assert_eq!(combination_count(false), 5 * 3 * 2 * 2);
    assert_eq!(combination_count(true), 7 * 3 * 2 * 2);
    assert!(sweep_flat(&cover, false, 512).iter().all(|c| {
        c.params.channels != "a" && c.params.channels != "rgba"
    }));
}

#[test]
fn sweep_json_is_shaped_for_the_worker() {
    let mut cover = clean_cover(40_000, 0xc0ffee);
    embed(&mut cover, &[0, 1, 2], 0, true, b"flag{json}\x00");

    let json = sweep_json_flat(&cover, false, 4096);
    assert!(json.starts_with('{') && json.ends_with('}'));
    assert!(json.contains("\"channels\":\"rgb\""));
    assert!(json.contains("\"msbFirst\":true"));
    assert!(json.contains("flag{json}"));
    assert!(json.contains("\"combinations\":60"));
    assert!(json.contains("\"columnMajor\":false"));
}

/// Regression: the preview was capped at 96 characters with nothing saying so,
/// which presented a clipped message as if it were the whole thing.
#[test]
fn a_long_message_reports_its_true_length_even_when_the_preview_clips() {
    let message: String = std::iter::repeat_n("the quick brown fox jumps. ", 40).collect();
    let mut cover = clean_cover(200_000, 0x2024);
    embed(&mut cover, &[0, 1, 2], 0, true, message.as_bytes());

    let found = sweep_flat(&cover, false, 4096);
    let hit = found
        .iter()
        .find(|c| c.params.channels == "rgb" && c.params.bit == 0 && c.params.msb_first)
        .expect("planted message not found");

    assert!(hit.readable >= message.len(), "readable {} vs {}", hit.readable, message.len());
    assert!(hit.preview.chars().count() > 96, "preview still clipped short");
    assert!(hit.reason.contains("characters"), "length missing from the reason");
}

#[test]
fn a_short_message_is_previewed_whole() {
    let mut cover = clean_cover(40_000, 0x2025);
    embed(&mut cover, &[0, 1, 2], 0, true, b"short and complete\x00");

    let hit = sweep_flat(&cover, false, 4096)
        .into_iter()
        .find(|c| c.preview.starts_with("short and complete"))
        .expect("message not found");

    assert_eq!(hit.preview.chars().count(), hit.readable);
}

#[test]
fn plane_full_is_one_byte_per_pixel_and_only_ever_black_or_white() {
    let cover = gradient_cover(8, 4, 0x11);
    let plane = plane_full(&cover, 1, 3);

    assert_eq!(plane.len(), 32);
    assert!(plane.iter().all(|&v| v == 0 || v == 255));
}

#[test]
fn plane_wall_sizes_the_thumbnails_to_the_target_width() {
    let cover = gradient_cover(400, 200, 0x22);
    let (json, tw, th, thumbnails) = plane_wall(&cover, 400, 200, 3, 100);

    assert_eq!((tw, th), (100, 50));
    assert_eq!(thumbnails.len(), 3 * 8 * 100 * 50);
    assert!(json.contains("\"thumbWidth\":100"));
    assert!(json.contains("\"channels\":3"));
}

#[test]
fn plane_wall_never_upscales_past_the_source_width() {
    let cover = gradient_cover(16, 16, 0x33);
    let (_, tw, _, _) = plane_wall(&cover, 16, 16, 3, 512);
    assert_eq!(tw, 16);
}

fn rate(json: &str, channel: usize, bit: usize) -> f32 {
    let key = format!("\"channel\":{channel},\"bit\":{bit},\"transitionRate\":");
    let start = json.find(&key).expect("plane missing from report") + key.len();
    let rest = &json[start..];
    let end = rest.find(['}', ',']).unwrap();
    rest[..end].parse().unwrap()
}

#[test]
fn the_wall_reports_a_rate_for_every_plane_of_every_channel() {
    let cover = gradient_cover(120, 90, 0x44);
    let (json, _, _, _) = plane_wall(&cover, 120, 90, 3, 60);

    assert_eq!(json.matches("\"transitionRate\"").count(), 24);
    assert!((0.0..=1.0).contains(&rate(&json, 0, 0)));
}

/// Regression: counting only horizontal neighbours reported every plane of a
/// vertical gradient as perfectly flat, which is a measurement bug, not a finding.
#[test]
fn a_vertical_gradient_does_not_read_as_flat() {
    let cover = gradient_cover(200, 150, 0x99);
    let (json, _, _, _) = plane_wall(&cover, 200, 150, 3, 64);

    // Channel 1 varies only down the image.
    assert!(
        rate(&json, 1, 7) > 0.0,
        "vertical structure was invisible: {json}"
    );
}

#[test]
fn the_lowest_plane_of_a_clean_image_reads_close_to_noise() {
    let cover = clean_cover(200 * 150, 0x55);
    let (json, _, _, _) = plane_wall(&cover, 200, 150, 4, 64);

    for channel in 0..3 {
        let r = rate(&json, channel, 0);
        assert!((0.45..=0.55).contains(&r), "channel {channel} bit 0 was {r}");
    }
}

/// The wall's real job: a plane carrying a payload stops looking like the picture
/// and starts looking like noise, and the rate is what makes that comparable.
#[test]
fn embedding_pushes_a_structured_plane_towards_noise() {
    let clean = gradient_cover(200, 150, 0x66);
    let (before, _, _, _) = plane_wall(&clean, 200, 150, 3, 64);

    let mut stego = clean.clone();
    let payload: Vec<u8> = (0..30_000).map(|i| (i * 37 % 251) as u8).collect();
    embed(&mut stego, &[0, 1, 2], 4, true, &payload);
    let (after, _, _, _) = plane_wall(&stego, 200, 150, 3, 64);

    assert!(rate(&before, 0, 4) < 0.2, "plane 4 should start structured");
    assert!(
        rate(&after, 0, 4) > rate(&before, 0, 4) + 0.2,
        "embedding did not move the rate: {} to {}",
        rate(&before, 0, 4),
        rate(&after, 0, 4)
    );
}

#[test]
fn the_wall_makes_no_claim_about_which_plane_is_suspicious() {
    let cover = gradient_cover(120, 90, 0x77);
    let (json, _, _, _) = plane_wall(&cover, 120, 90, 3, 60);
    assert!(
        !json.contains("anomalous"),
        "the wall reports measurements; chi-square and RS do the judging"
    );
}

/// A cover with a genuinely lumpy histogram. Chi-square asks whether value pairs
/// are equal, so a flat histogram is already indistinguishable from embedding and
/// would make the test meaningless.
fn photo_like_cover(width: usize, height: usize) -> Vec<u8> {
    let mut out = vec![0u8; width * height * 4];

    for y in 0..height {
        for x in 0..width {
            let o = (y * width + x) * 4;
            let fx = x as f32 / width as f32;
            let fy = y as f32 / height as f32;
            let r = ((fx - 0.5).powi(2) + (fy - 0.5).powi(2)).sqrt();

            out[o] = (190.0 - 110.0 * r) as u8;
            out[o + 1] = (140.0 + 60.0 * (fx * 3.0).sin()) as u8;
            out[o + 2] = (95.0 + 55.0 * (fy * 2.0).cos()) as u8;
            out[o + 3] = 255;
        }
    }

    out
}

fn histogram_is_lumpy(rgba: &[u8]) -> bool {
    let samples = traversal_samples(rgba);
    let mut histogram = [0u64; 256];
    for &s in &samples {
        histogram[s as usize] += 1;
    }
    // At least one pair whose members differ by more than a fifth of their total.
    (0..128).any(|k| {
        let (a, b) = (histogram[k * 2] as f64, histogram[k * 2 + 1] as f64);
        a + b > 100.0 && (a - b).abs() / (a + b) > 0.2
    })
}

#[test]
fn chi_square_stays_quiet_on_a_cover_with_a_lumpy_histogram() {
    let cover = photo_like_cover(300, 220);
    assert!(histogram_is_lumpy(&cover), "the control must be testable");

    let json = chi_square_json(&cover, 32);
    assert!(
        json.contains("\"detected\":false"),
        "clean cover read as embedded: {json}"
    );
}

#[test]
fn chi_square_detects_a_payload_written_into_the_low_bits() {
    let mut cover = photo_like_cover(300, 220);
    let payload: Vec<u8> = (0..20_000).map(|i| (i * 61 % 251) as u8).collect();
    embed(&mut cover, &[0, 1, 2], 0, true, &payload);

    let json = chi_square_json(&cover, 32);
    assert!(
        json.contains("\"detected\":true"),
        "payload went unnoticed: {json}"
    );
}

#[test]
fn chi_square_json_carries_the_whole_curve() {
    let cover = photo_like_cover(120, 90);
    let json = chi_square_json(&cover, 16);

    assert!(json.starts_with('{') && json.ends_with('}'));
    assert_eq!(json.matches("\"fraction\"").count(), 16);
    assert!(json.contains("\"peakProbability\""));
    assert!(json.contains("\"samples\":32400"));
}

#[test]
fn traversal_samples_drops_alpha_and_keeps_pixel_order() {
    let rgba = [1, 2, 3, 255, 4, 5, 6, 128];
    assert_eq!(traversal_samples(&rgba), vec![1, 2, 3, 4, 5, 6]);
}

#[test]
fn extract_named_rejects_a_channel_set_that_does_not_exist() {
    let cover = clean_cover(64, 1);
    assert!(extract_named(&cover, "xyz", 0, true, 16).is_none());
    assert!(extract_named(&cover, "rgb", 0, true, 16).is_some());
}
