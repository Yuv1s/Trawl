use super::*;

/// A 2x2 BMP with four known colours, bottom-up as the format stores them.
fn bmp_file() -> Vec<u8> {
    let mut out = b"BM".to_vec();
    out.extend_from_slice(&(54u32 + 16).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&54u32.to_le_bytes());
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&2i32.to_le_bytes());
    out.extend_from_slice(&2i32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&24u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    // Bottom row first: blue, green. Then top row: red, white.
    out.extend_from_slice(&[255, 0, 0, 0, 255, 0]);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&[0, 0, 255, 255, 255, 255]);
    out.extend_from_slice(&[0, 0]);
    out
}

#[test]
fn decode_routes_a_bmp_to_the_bitmap_reader() {
    let raster = decode(&bmp_file(), &[]).unwrap();

    assert_eq!(raster.format, "BMP");
    assert_eq!((raster.width, raster.height), (2, 2));
    assert_eq!(raster.rgba.len(), 2 * 2 * 4);
    assert_eq!(&raster.rgba[0..4], &[255, 0, 0, 255], "top left is red");
}

#[test]
fn decode_names_the_format_it_used() {
    assert_eq!(decode(&bmp_file(), &[]).unwrap().format, "BMP");
}

/// A format with no decoder says so rather than returning something wrong.
#[test]
fn decode_refuses_a_format_it_cannot_read() {
    let jpeg = [0xff, 0xd8, 0xff, 0xe0, 0, 16];
    let error = decode(&jpeg, &[]).unwrap_err();
    assert!(error.contains("can't decode"), "{error}");

    assert!(decode(&[], &[]).is_err());
}

#[test]
fn a_bitmap_error_is_passed_through_rather_than_swallowed() {
    let mut file = bmp_file();
    file[30] = 1; // BI_RLE8
    let error = decode(&file, &[]).unwrap_err();
    assert!(error.contains("compression"), "{error}");
}

#[test]
fn a_png_cut_short_is_as_tall_as_the_rows_it_has() {
    let mut ihdr = 2u32.to_be_bytes().to_vec();
    ihdr.extend_from_slice(&3u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);

    let mut body = b"IHDR".to_vec();
    body.extend_from_slice(&ihdr);
    let mut file = png::SIGNATURE.to_vec();
    file.extend_from_slice(&13u32.to_be_bytes());
    file.extend_from_slice(&body);
    file.extend_from_slice(&png::crc_of(&body).to_be_bytes());

    let raster = decode(&file, &[0, 1, 2, 3, 4, 5, 6]).unwrap();
    assert_eq!(raster.height, 1);
    assert_eq!(raster.declared_height, 3);
    assert_eq!(raster.rgba.len(), 2 * 4);

    let error = decode(&file, &[]).unwrap_err();
    assert!(error.contains("expected"), "{error}");
}

#[test]
fn alpha_is_only_claimed_when_the_format_carries_it() {
    assert!(!decode(&bmp_file(), &[]).unwrap().has_alpha, "24-bit BMP has none");
}
