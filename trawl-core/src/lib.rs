//! trawl-core — the analysis engine.
//!
//! Everything here is a pure function over `&[u8]` or over decoded pixel data:
//! slice in, struct out. No async, no I/O, no global state.

use wasm_bindgen::prelude::*;

pub mod bytes;
pub mod cuttlefish;
pub mod json;
pub mod png;

/// Sweeps LSB parameters and reports combinations that produced something.
///
/// Decoding happens inside this call so a 12-megapixel RGBA buffer never crosses
/// the WASM boundary.
#[wasm_bindgen]
pub fn png_lsb_sweep(file: &[u8], inflated: &[u8], max_bytes: usize) -> Result<String, JsError> {
    let header = png::header(file).map_err(|e| JsError::new(&e.to_string()))?;
    let rgba = png::decode(file, inflated).map_err(|e| JsError::new(&e.to_string()))?;
    let has_alpha = matches!(header.color_type, 4 | 6);

    Ok(cuttlefish::sweep_json(&rgba, has_alpha, max_bytes))
}

/// Full extraction for one chosen combination.
#[wasm_bindgen]
pub fn png_lsb_extract(
    file: &[u8],
    inflated: &[u8],
    channels: &str,
    bit: u8,
    msb_first: bool,
    max_bytes: usize,
) -> Result<Vec<u8>, JsError> {
    let rgba = png::decode(file, inflated).map_err(|e| JsError::new(&e.to_string()))?;

    cuttlefish::extract_named(&rgba, channels, bit, msb_first, max_bytes)
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
