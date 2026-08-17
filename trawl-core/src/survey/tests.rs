use super::*;

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
fn a_flag_in_readable_data_is_credited() {
    let mut data = vec![b' '; 4096];
    data[2000..2020].copy_from_slice(b"flag{plain_as_day}  ");

    let text = json(&data);
    assert!(text.contains("flag{plain_as_day}"));
    assert!(text.contains("\"credible\":true"));
}

/// The general form of the CacheSleuth false positive: the shape appears by
/// chance in compressed bytes, and reporting it as a find would be a lie.
#[test]
fn a_flag_shape_inside_compressed_bytes_is_not_credited() {
    let mut data = noise(64 * 1024, 0x1234);
    data[30_000..30_011].copy_from_slice(b"zz{abcdefg}");

    let text = json(&data);
    assert!(text.contains("zz{abcdefg}"));
    assert!(text.contains("\"credible\":false"));
    assert!(text.contains("high-entropy region"));
}

#[test]
fn the_survey_names_the_format_when_it_recognises_one() {
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&[0u8; 64]);
    assert!(json(&png).contains("\"format\":\"PNG image\""));

    assert!(json(&[0u8; 64]).contains("\"format\":null"));
}

#[test]
fn an_embedded_archive_is_reported_with_its_offset() {
    let mut data = vec![0u8; 1024];
    data.extend_from_slice(b"PK\x03\x04here is a zip");
    data.extend_from_slice(&[0u8; 512]);

    let text = json(&data);
    assert!(text.contains("\"label\":\"ZIP archive\""));
    assert!(text.contains("\"offset\":1024"));
    assert!(text.contains("\"embedded\":true"));
}

#[test]
fn a_signature_at_offset_zero_is_the_format_not_an_embedded_file() {
    let mut data = b"%PDF-1.7\n".to_vec();
    data.extend_from_slice(&[0u8; 256]);

    let text = json(&data);
    assert!(text.contains("\"offset\":0"));
    assert!(text.contains("\"embedded\":false"));
}

#[test]
fn the_survey_runs_on_a_format_it_cannot_walk() {
    let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10];
    jpeg.extend_from_slice(b"JFIF\0");
    jpeg.extend_from_slice(&[b' '; 200]);
    jpeg.extend_from_slice(b"picoCTF{not_a_png_but_still_read}");
    jpeg.extend_from_slice(&[0xff, 0xd9]);

    let text = json(&jpeg);
    assert!(text.contains("\"format\":\"JPEG image\""));
    assert!(text.contains("picoCTF{not_a_png_but_still_read}"));
    assert!(text.contains("\"credible\":true"));
}

fn entropy_values(text: &str) -> Vec<f32> {
    let start = text.find("\"values\":[").unwrap() + 10;
    let end = start + text[start..].find(']').unwrap();
    text[start..end]
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap())
        .collect()
}

#[test]
fn entropy_is_reported_across_the_whole_file() {
    let mut data = vec![0u8; 32 * 1024];
    data.extend(noise(32 * 1024, 0x55));

    let text = json(&data);
    assert!(text.contains("\"window\":256"));

    let values = entropy_values(&text);
    assert_eq!(values.len(), 256);

    let (flat, noisy) = values.split_at(128);
    assert!(flat.iter().all(|&v| v == 0.0), "a constant region is zero entropy");
    assert!(
        noisy.iter().all(|&v| v > 6.5),
        "256 random bytes over 256 values cannot reach 8.0, but should be close"
    );
}

#[test]
fn a_uniform_region_never_reports_negative_zero() {
    let text = json(&vec![0u8; 8192]);
    assert!(!text.contains("-0.000"), "negated zero must be normalised");
}

#[test]
fn the_survey_is_valid_json_for_an_empty_file() {
    let text = json(&[]);
    assert!(text.starts_with('{') && text.ends_with('}'));
    assert!(text.contains("\"size\":0"));
    assert!(text.contains("\"format\":null"));
    assert!(text.contains("\"values\":[]"));
}
