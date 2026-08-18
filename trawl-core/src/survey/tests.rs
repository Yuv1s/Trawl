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
    data[30_000..30_011].copy_from_slice(b"flag{abcde}");

    let text = json(&data);
    assert!(text.contains("flag{abcde}"));
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

/// Builds a JPEG carrying EXIF, so the survey has both layers to walk.
fn jpeg_with_exif(description: &str) -> Vec<u8> {
    let mut value = description.as_bytes().to_vec();
    value.push(0);

    let heap = 8 + 2 + 12 + 4;
    let mut tiff = b"II\x2a\x00".to_vec();
    tiff.extend_from_slice(&8u32.to_le_bytes());
    tiff.extend_from_slice(&1u16.to_le_bytes());
    tiff.extend_from_slice(&0x010eu16.to_le_bytes()); // ImageDescription
    tiff.extend_from_slice(&2u16.to_le_bytes());
    tiff.extend_from_slice(&(value.len() as u32).to_le_bytes());
    tiff.extend_from_slice(&(heap as u32).to_le_bytes());
    tiff.extend_from_slice(&0u32.to_le_bytes());
    tiff.extend_from_slice(&value);

    let mut app1 = b"Exif\0\0".to_vec();
    app1.extend_from_slice(&tiff);

    let mut file = vec![0xff, 0xd8, 0xff, 0xe1];
    file.extend_from_slice(&((app1.len() + 2) as u16).to_be_bytes());
    file.extend_from_slice(&app1);
    file.extend_from_slice(&[0xff, 0xd9]);
    file
}

#[test]
fn the_survey_reads_exif_out_of_a_jpeg() {
    let text = json(&jpeg_with_exif("flag{in_the_metadata}"));

    assert!(text.contains("\"name\":\"ImageDescription\""));
    assert!(text.contains("flag{in_the_metadata}"));
    assert!(text.contains("\"textual\":true"));
    assert!(text.contains("\"name\":\"APP1 EXIF or XMP\""));
}

#[test]
fn the_survey_reads_the_same_exif_block_out_of_a_png() {
    let tiff = {
        let jpeg = jpeg_with_exif("flag{png_exif_chunk}");
        crate::jpeg::exif_payload(&jpeg).unwrap().to_vec()
    };

    let crc = |kind: &[u8; 4], data: &[u8]| {
        let mut body = kind.to_vec();
        body.extend_from_slice(data);
        let mut out = (data.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out.extend_from_slice(&crate::png::crc_of(&body).to_be_bytes());
        out
    };

    let mut ihdr = 4u32.to_be_bytes().to_vec();
    ihdr.extend_from_slice(&4u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);

    let mut file = crate::png::SIGNATURE.to_vec();
    file.extend_from_slice(&crc(b"IHDR", &ihdr));
    file.extend_from_slice(&crc(b"eXIf", &tiff));
    file.extend_from_slice(&crc(b"IEND", &[]));

    let text = json(&file);
    assert!(text.contains("flag{png_exif_chunk}"), "eXIf chunk was not read");
}

#[test]
fn the_survey_reads_utf16le_text_alongside_ascii() {
    let mut data = vec![0xffu8; 64];
    data.extend_from_slice(b"plain ascii here");
    data.extend_from_slice(&[0xff; 16]);
    for c in "flag{wide_text}".chars() {
        data.push(c as u8);
        data.push(0);
    }
    data.extend_from_slice(&[0xff; 16]);

    let text = json(&data);
    assert!(text.contains("plain ascii here"));
    assert!(text.contains("flag{wide_text}"), "wide text was missed");
    assert!(text.contains("\"wide\":1"));
}

/// Regression: the byte-level flag scan cannot see a wide flag, because every
/// character has a null after it. The decoded text has to be searched too.
#[test]
fn a_flag_written_as_utf16le_is_recovered() {
    let mut data = vec![0xffu8; 32];
    for c in "picoCTF{wide_and_hidden}".chars() {
        data.push(c as u8);
        data.push(0);
    }
    data.extend_from_slice(&[0xff; 32]);

    let text = json(&data);
    assert!(text.contains("\"text\":\"picoCTF{wide_and_hidden}\""));
    assert!(text.contains("\"region\":\"UTF-16LE text\""));
    assert!(text.contains("\"credible\":true"));
}

#[test]
fn a_file_with_no_metadata_reports_null_rather_than_an_empty_list() {
    assert!(json(&[0u8; 512]).contains("\"exif\":null"));
}

#[test]
fn jpeg_comments_and_trailing_bytes_are_reported() {
    let mut file = vec![0xff, 0xd8, 0xff, 0xfe];
    let comment = b"flag{jpeg_comment}";
    file.extend_from_slice(&((comment.len() + 2) as u16).to_be_bytes());
    file.extend_from_slice(comment);
    file.extend_from_slice(&[0xff, 0xd9]);
    file.extend_from_slice(b"appended");

    let text = json(&file);
    assert!(text.contains("flag{jpeg_comment}"));
    assert!(text.contains("\"jpegTrailing\":{"));
}

#[test]
fn the_survey_is_valid_json_for_an_empty_file() {
    let text = json(&[]);
    assert!(text.starts_with('{') && text.ends_with('}'));
    assert!(text.contains("\"size\":0"));
    assert!(text.contains("\"format\":null"));
    assert!(text.contains("\"values\":[]"));
}
