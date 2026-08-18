//! trawl-core — the analysis engine.
//!
//! Everything here is a pure function over `&[u8]` or over decoded pixel data:
//! slice in, struct out. No async, no I/O, no global state.

use wasm_bindgen::prelude::*;

pub mod bmp;
pub mod bytes;
pub mod cuttlefish;
pub mod exif;
pub mod gif;
pub mod jpeg;
pub mod json;
pub mod mantis;
pub mod pixels;
pub mod png;
pub mod spectrogram;
pub mod survey;
pub mod wav;

/// Everything that can be said about a file without knowing its format: flag
/// shapes, strings, embedded signatures and entropy.
#[wasm_bindgen]
pub fn file_survey(file: &[u8]) -> String {
    survey::json(file)
}

/// Sweeps LSB parameters and reports combinations that produced something.
///
/// Decoding happens inside this call so a 12-megapixel RGBA buffer never crosses
/// the WASM boundary.
#[wasm_bindgen]
pub fn lsb_sweep(file: &[u8], inflated: &[u8], max_bytes: usize) -> Result<String, JsError> {
    let raster = pixels::decode(file, inflated).map_err(|e| JsError::new(&e))?;

    Ok(cuttlefish::sweep_json(
        &raster.rgba,
        raster.width,
        raster.height,
        raster.has_alpha,
        max_bytes,
    ))
}

/// Every bit plane downsampled for the wall.
///
/// Returns one buffer rather than a struct: a u32 length, then that many bytes of
/// JSON metadata, then the grayscale thumbnails ordered channel-major and bit
/// ascending. One call means one decode of a buffer that can reach 20 MB.
#[wasm_bindgen]
pub fn plane_wall(file: &[u8], inflated: &[u8], target_width: usize) -> Result<Vec<u8>, JsError> {
    let raster = pixels::decode(file, inflated).map_err(|e| JsError::new(&e))?;
    let channels = if raster.has_alpha { 4 } else { 3 };

    let (json, _, _, thumbnails) = cuttlefish::plane_wall(
        &raster.rgba,
        raster.width,
        raster.height,
        channels,
        target_width,
    );

    let mut out = Vec::with_capacity(4 + json.len() + thumbnails.len());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(json.as_bytes());
    out.extend_from_slice(&thumbnails);
    Ok(out)
}

/// Chi-square attack over increasing prefixes (Westfeld & Pfitzmann, 1999).
#[wasm_bindgen]
pub fn chi_square(file: &[u8], inflated: &[u8], steps: usize) -> Result<String, JsError> {
    let raster = pixels::decode(file, inflated).map_err(|e| JsError::new(&e))?;
    Ok(cuttlefish::chi_square_json(&raster.rgba, steps))
}

/// Flag-shaped matches in a byte run, as JSON.
///
/// Exposed so the worker can re-scan text it decompressed itself, using the same
/// matcher as everything else rather than a second implementation in JS.
#[wasm_bindgen]
pub fn find_flags(data: &[u8]) -> String {
    use json::{push_field, push_number};

    let mut out = String::from("[");
    for (i, found) in bytes::flag_candidates(data).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_number(&mut out, "offset", found.offset);
        out.push(',');
        push_field(&mut out, "text", &found.text);
        out.push('}');
    }
    out.push(']');
    out
}

/// Palette findings for an indexed image, as JSON. Null when there is no PLTE.
#[wasm_bindgen]
pub fn png_palette(file: &[u8], inflated: &[u8]) -> String {
    use json::{push_number, push_string};

    let indices = png::palette_indices(file, inflated);
    let Some(palette) = png::palette(file, indices.as_deref()) else {
        return "null".to_string();
    };

    let mut out = String::from("{");
    push_number(&mut out, "entries", palette.entries);
    out.push(',');
    push_number(&mut out, "unused", palette.unused);
    out.push(',');
    push_number(&mut out, "capacityBits", palette.capacity_bits);
    out.push(',');
    push_string(&mut out, "duplicates");
    out.push_str(":[");
    for (i, (colour, count)) in palette.duplicates.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_string(&mut out, "colour");
        out.push(':');
        push_string(&mut out, colour);
        out.push(',');
        push_number(&mut out, "count", *count);
        out.push('}');
    }
    out.push_str("]}");
    out
}

/// RS analysis, estimating the embedding rate (Fridrich, Goljan & Du, 2001).
#[wasm_bindgen]
pub fn rs_analysis(file: &[u8], inflated: &[u8]) -> Result<String, JsError> {
    let raster = pixels::decode(file, inflated).map_err(|e| JsError::new(&e))?;
    let estimate = cuttlefish::rs::analyse(&raster.rgba, raster.width, raster.height, 3);
    Ok(cuttlefish::rs::json(&estimate))
}

/// One plane at full resolution, 0 or 255 per pixel.
#[wasm_bindgen]
pub fn plane(file: &[u8], inflated: &[u8], channel: usize, bit: u8) -> Result<Vec<u8>, JsError> {
    if channel > 3 || bit > 7 {
        return Err(JsError::new("channel must be 0-3 and bit 0-7"));
    }

    let raster = pixels::decode(file, inflated).map_err(|e| JsError::new(&e))?;
    Ok(cuttlefish::plane_full(&raster.rgba, channel, bit))
}

/// Full extraction for one chosen combination.
#[wasm_bindgen]
pub fn lsb_extract(
    file: &[u8],
    inflated: &[u8],
    channels: &str,
    bit: u8,
    msb_first: bool,
    max_bytes: usize,
) -> Result<Vec<u8>, JsError> {
    let raster = pixels::decode(file, inflated).map_err(|e| JsError::new(&e))?;

    cuttlefish::extract_named(&raster.rgba, channels, bit, msb_first, max_bytes)
        .ok_or_else(|| JsError::new(&format!("unknown channel set {channels}")))
}

/// The container walk as a JSON string: header, every chunk, text chunks, and any
/// bytes past IEND.
#[wasm_bindgen]
pub fn png_structure(file: &[u8]) -> String {
    png::structure_json(file)
}

/// Concatenated IDAT payloads, to be inflated by `DecompressionStream` on the JS
/// side and handed straight back to [`png_decode`].
#[wasm_bindgen]
pub fn png_idat(file: &[u8]) -> Vec<u8> {
    png::idat(file)
}

/// Decodes to non-premultiplied RGBA8, four bytes per pixel.
#[wasm_bindgen]
pub fn png_decode(file: &[u8], inflated: &[u8]) -> Result<Vec<u8>, JsError> {
    png::decode(file, inflated).map_err(|e| JsError::new(&e.to_string()))
}

/// Width and height as a two-element array, so callers can size a buffer before
/// decoding.
#[wasm_bindgen]
pub fn png_dimensions(file: &[u8]) -> Result<Vec<u32>, JsError> {
    png::header(file)
        .map(|h| vec![h.width, h.height])
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Peels encoding layers off a pasted string, as JSON.
///
/// Reports the chain it followed and what fell out at the end, or an empty chain
/// when nothing it tried made the input more readable than it already was.
#[wasm_bindgen]
pub fn peel_encodings(data: &[u8]) -> String {
    mantis::json(data)
}

/// JPEG coefficient analysis as JSON: the chi-square attack, the coefficient
/// histogram, and any JSteg extraction that produced something readable.
///
/// Null for a file that is not a JPEG, and an object carrying `error` for one
/// this decoder will not read, such as a progressive JPEG.
#[wasm_bindgen]
pub fn jpeg_stego(file: &[u8], max_bytes: usize, steps: usize) -> String {
    jpeg::stego::json(file, max_bytes, steps)
}

/// One JSteg combination in full, for the reader pane.
#[wasm_bindgen]
pub fn jpeg_stego_extract(
    file: &[u8],
    include_dc: bool,
    msb_first: bool,
    max_bytes: usize,
) -> Result<Vec<u8>, JsError> {
    let coefficients = jpeg::dct::coefficients(file).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(jpeg::stego::extract(
        &coefficients,
        include_dc,
        msb_first,
        max_bytes,
    ))
}

/// Payloads hidden in the choice between identical palette entries, as JSON.
///
/// Null unless the file is an indexed image whose pixel data could be read.
#[wasm_bindgen]
pub fn palette_stego(file: &[u8], inflated: &[u8], max_bytes: usize) -> String {
    let Some(indices) = png::palette_indices(file, inflated) else {
        return "null".to_string();
    };
    let Some(plte) = png::chunk_payload(file, b"PLTE") else {
        return "null".to_string();
    };

    cuttlefish::palette::json(plte, &indices, max_bytes)
}

/// One palette combination in full, for the reader pane.
#[wasm_bindgen]
pub fn palette_extract(
    file: &[u8],
    inflated: &[u8],
    msb_first: bool,
    max_bytes: usize,
) -> Result<Vec<u8>, JsError> {
    let indices = png::palette_indices(file, inflated)
        .ok_or_else(|| JsError::new("this file is not an indexed image"))?;
    let plte = png::chunk_payload(file, b"PLTE")
        .ok_or_else(|| JsError::new("this file has no palette"))?;

    Ok(cuttlefish::palette::extract(
        plte, &indices, msb_first, max_bytes,
    ))
}

/// The RIFF walk as JSON: format, every chunk, text in the chunks a player
/// skips, and any bytes past the length the header declares. Null for a file
/// that is not a WAV, so the audio tools stand down rather than erroring.
#[wasm_bindgen]
pub fn wav_structure(file: &[u8]) -> String {
    wav::structure_json(file)
}

/// Sweeps LSB parameters over the samples and reports what carried data.
#[wasm_bindgen]
pub fn wav_lsb_sweep(file: &[u8], max_bytes: usize) -> Result<String, JsError> {
    let parsed = wav::parse(file).map_err(|e| JsError::new(&e.to_string()))?;
    let samples = wav::integer_samples(file, &parsed).map_err(|e| JsError::new(&e.to_string()))?;

    Ok(cuttlefish::audio::sweep_json(
        &samples,
        parsed.format.channels,
        max_bytes,
    ))
}

/// One LSB combination in full, for the reader pane.
///
/// @param channel_index negative reads every channel interleaved
#[wasm_bindgen]
pub fn wav_lsb_extract(
    file: &[u8],
    channel_index: i32,
    bit: u8,
    msb_first: bool,
    max_bytes: usize,
) -> Result<Vec<u8>, JsError> {
    let parsed = wav::parse(file).map_err(|e| JsError::new(&e.to_string()))?;
    let samples = wav::integer_samples(file, &parsed).map_err(|e| JsError::new(&e.to_string()))?;

    let channel = if channel_index < 0 {
        None
    } else {
        Some(channel_index as usize)
    };

    Ok(cuttlefish::audio::extract(
        &samples,
        parsed.format.channels,
        channel,
        bit,
        msb_first,
        max_bytes,
    ))
}

/// The spectrogram image.
///
/// Packed the same way as [`plane_wall`]: a u32 length, that many bytes of JSON,
/// then one grayscale byte per pixel with row 0 at the top.
#[wasm_bindgen]
pub fn wav_spectrogram(file: &[u8], window: usize, target_width: usize) -> Result<Vec<u8>, JsError> {
    let parsed = wav::parse(file).map_err(|e| JsError::new(&e.to_string()))?;
    let samples = wav::mono(file, &parsed).map_err(|e| JsError::new(&e.to_string()))?;

    let spec = spectrogram::analyse(&samples, parsed.format.sample_rate, window, target_width)
        .ok_or_else(|| JsError::new("the clip is shorter than one analysis window"))?;

    let json = spectrogram::json(&spec);
    let mut out = Vec::with_capacity(4 + json.len() + spec.pixels.len());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(json.as_bytes());
    out.extend_from_slice(&spec.pixels);
    Ok(out)
}
