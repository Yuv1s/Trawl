//! trawl-core — the analysis engine.
//!
//! Everything here is a pure function over `&[u8]` or over decoded pixel data:
//! slice in, struct out. No async, no I/O, no global state.

use wasm_bindgen::prelude::*;

pub mod aes;
pub mod bmp;
pub mod bytes;
pub mod cuttlefish;
pub mod exif;
pub mod gif;
pub mod jpeg;
pub mod json;
pub mod mantis;
pub mod pdf;
pub mod pixels;
pub mod png;
pub mod spectrogram;
pub mod survey;
pub mod wav;
pub mod zip;

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
fn flags_json(found: &[bytes::Found]) -> String {
    use json::{push_field, push_number};

    let mut out = String::from("[");
    for (i, found) in found.iter().enumerate() {
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

#[wasm_bindgen]
pub fn find_flags(data: &[u8]) -> String {
    flags_json(&bytes::flag_candidates(data))
}

#[wasm_bindgen]
pub fn find_flags_for_tags(data: &[u8], tags: &str) -> String {
    let tags: Vec<String> = tags
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
        .collect();
    flags_json(&bytes::flag_candidates_for_tags(data, &tags))
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

#[wasm_bindgen]
pub fn png_patch_ihdr(file: &[u8], width: u32, height: u32) -> Result<Vec<u8>, JsError> {
    png::patch_ihdr(file, width, height)
        .ok_or_else(|| JsError::new("PNG has no complete IHDR chunk"))
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

/// `peel_encodings`, with the caller's configured flag tags steering the cribs
/// that recover keys underneath an enciphered flag.
#[wasm_bindgen]
pub fn peel_encodings_for_tags(data: &[u8], tags: &str) -> String {
    let tags: Vec<String> = tags
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
        .collect();
    mantis::json_for_tags(data, &tags)
}

/// Packed Mantis pass for the worker's alternating loop.
///
/// Returns a single buffer: u32 little-endian JSON length, then that many bytes
/// of JSON metadata (the `PeelResult` shape), then the exact final result bytes.
/// The binary tail is authoritative for compression detection and the next pass;
/// the JSON is for the panel. Accepts a remaining depth so the worker and Rust
/// share one six-layer budget.
#[wasm_bindgen]
pub fn mantis_packed_pass(data: &[u8], tags: &str, remaining_depth: usize) -> Vec<u8> {
    let tags: Vec<String> = tags
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
        .collect();

    let peel = mantis::peel_with_depth(data, &tags, remaining_depth);
    let json = mantis::json_from_peel(&peel);
    let json_bytes = json.as_bytes();
    let result_bytes = &peel.result;

    let mut out = Vec::with_capacity(4 + json_bytes.len() + result_bytes.len());
    out.extend_from_slice(&(json_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(json_bytes);
    out.extend_from_slice(result_bytes);
    out
}

/// AES-CBC decryptions the file decrypts to readable text, as JSON.
///
/// A file that carries its own key, IV and ciphertext is decrypted here rather
/// than by hand. The array is empty when nothing in the file forms a set that
/// decrypts to anything a person could read, which is every ordinary file.
#[wasm_bindgen]
pub fn aes_probe(file: &[u8]) -> String {
    aes::json(file)
}

/// What a ZIP archive holds, as JSON, or null when the file is not one.
///
/// Reports the local headers and the central directory separately, because a
/// doctored archive is one where they disagree and every ordinary reader only
/// consults the directory.
#[wasm_bindgen]
pub fn zip_structure(file: &[u8]) -> String {
    zip::json(file)
}

/// What a PDF document holds, as JSON, or null when the file is not one.
///
/// Walks the file for every object header independent of the cross-reference
/// table, then reads the table separately, the same split [`zip_structure`]
/// makes between local headers and the central directory. An object the
/// table no longer lists is a leftover from an earlier revision that a
/// reader will never show.
#[wasm_bindgen]
pub fn pdf_structure(file: &[u8]) -> String {
    pdf::json(file)
}

/// Applies a key somebody already has, across every cipher that takes one.
///
/// Separate from `peel_encodings` because it answers a different question.
/// That one asks what the text is; this one is told, and reports what each
/// cipher makes of the key without judging any of it. Recovering a key needs
/// enough text to count letters in, and plenty of puzzles have neither that nor
/// an answer a scorer could recognise.
#[wasm_bindgen]
pub fn mantis_with_key(data: &[u8], key: &str) -> String {
    mantis::keyed::json(&mantis::keyed::with_key(data, key))
}

/// `mantis_with_key`, with the caller's configured flag tags steering the cribs.
#[wasm_bindgen]
pub fn mantis_with_key_for_tags(data: &[u8], key: &str, tags: &str) -> String {
    let tags: Vec<String> = tags
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
        .collect();
    mantis::keyed::json(&mantis::keyed::with_key_for_tags(data, key, &tags))
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
        parsed.format.sample_rate,
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
pub fn wav_spectrogram(
    file: &[u8],
    window: usize,
    target_width: usize,
) -> Result<Vec<u8>, JsError> {
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

/// Automatic GIF frame and difference analysis.
///
/// For each displayed frame and each consecutive difference, runs the existing
/// Cuttlefish detectors (sweep, chi-square, RS) on the RGBA pixels. Returns a
/// compact JSON summary with findings; the raw pixels and plane walls stay behind.
/// The packed binary tail is unnecessary — we only need metadata and detector results.
#[wasm_bindgen]
pub fn gif_frame_analysis(
	file: &[u8],
	_tags: &str,
	max_bytes: usize,
	chi_steps: usize,
) -> Result<String, JsError> {
	if !gif::has_signature(file) {
		return Ok("null".to_string());
	}

	let (header, frames, differences, capped) = gif::decode_frames(file)
		.map_err(|e| JsError::new(&e.to_string()))?;

	use crate::json::{push_bool, push_field, push_number, push_string};

	let mut out = String::from("{");
	push_number(&mut out, "width", header.width);
	out.push(',');
	push_number(&mut out, "height", header.height);
	out.push(',');
	push_number(&mut out, "declaredFrames", header.declared_frames);
	out.push(',');
	push_number(&mut out, "analysedFrames", frames.len());
	out.push(',');
	push_bool(&mut out, "capped", capped);
	out.push(',');
	push_string(&mut out, "error");
	out.push_str(":null");
	out.push(',');
	push_string(&mut out, "sources");
	out.push_str(":[");

	let mut source_index = 0;

	// Analyze each displayed frame
	for (frame_idx, frame) in frames.iter().enumerate() {
		if source_index > 0 {
			out.push(',');
		}
		source_index += 1;

		out.push('{');
		push_field(&mut out, "kind", "frame");
		out.push(',');
		push_number(&mut out, "from", frame_idx + 1); // one-based
		out.push(',');
		push_string(&mut out, "to");
		out.push_str(":null");
		out.push(',');
		push_number(&mut out, "delay", 0);
		out.push(',');
		push_string(&mut out, "disposal");
		out.push_str(":null");
		out.push(',');

		// Run detectors on this frame
		let sweep_json = cuttlefish::sweep_json(frame, header.width, header.height, false, max_bytes);
		let chi_json = cuttlefish::chi_square_json(frame, chi_steps);
		let rs_json = cuttlefish::rs::analyse(frame, header.width, header.height, 3);
		let rs_json_str = cuttlefish::rs::json(&rs_json);

		push_string(&mut out, "lsb");
		out.push(':');
		out.push_str(&sweep_json);
		out.push(',');

		push_string(&mut out, "chi");
		out.push(':');
		// Parse chi JSON and extract just detected/embeddedFraction
		// For simplicity, include the full chi result
		out.push_str(&chi_json);
		out.push(',');

		push_string(&mut out, "rs");
		out.push(':');
		out.push_str(&rs_json_str);

		out.push('}');
	}

	// Analyze each consecutive difference
	for (diff_idx, diff) in differences.iter().enumerate() {
		if source_index > 0 {
			out.push(',');
		}
		source_index += 1;

		out.push('{');
		push_field(&mut out, "kind", "difference");
		out.push(',');
		push_number(&mut out, "from", diff_idx + 1); // one-based
		out.push(',');
		push_number(&mut out, "to", diff_idx + 2); // the later frame
		out.push(',');
		push_number(&mut out, "delay", 0);
		out.push(',');
		push_string(&mut out, "disposal");
		out.push_str(":null");
		out.push(',');

		// Run detectors on this difference
		let sweep_json = cuttlefish::sweep_json(diff, header.width, header.height, false, max_bytes);
		let chi_json = cuttlefish::chi_square_json(diff, chi_steps);
		let rs_json = cuttlefish::rs::analyse(diff, header.width, header.height, 3);
		let rs_json_str = cuttlefish::rs::json(&rs_json);

		push_string(&mut out, "lsb");
		out.push(':');
		out.push_str(&sweep_json);
		out.push(',');

		push_string(&mut out, "chi");
		out.push(':');
		out.push_str(&chi_json);
		out.push(',');

		push_string(&mut out, "rs");
		out.push(':');
		out.push_str(&rs_json_str);

		out.push('}');
	}

	out.push_str("]}");
	Ok(out)
}
