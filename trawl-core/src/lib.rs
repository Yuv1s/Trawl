//! trawl-core — the analysis engine.
//!
//! Everything here is a pure function over `&[u8]` or over decoded pixel data:
//! slice in, struct out. No async, no I/O, no global state.

use wasm_bindgen::prelude::*;

pub mod aes;
pub mod binary;
pub mod bmp;
pub mod bytes;
pub mod cuttlefish;
pub mod elf;
pub mod exif;
pub mod gif;
pub mod inflate;
pub mod jpeg;
pub mod json;
pub mod mantis;
pub mod pcap;
pub mod pdf;
pub mod pe;
pub mod pixels;
pub mod png;
pub mod regf;
pub mod registry;
pub mod spectrogram;
pub mod sqlite;
pub mod survey;
pub mod wav;
pub mod zip;

/// Everything that can be said about a file without knowing its format: flag
/// shapes, strings, embedded signatures and entropy. The caller's flag tags decide
/// what counts as a flag and which of them are credible wherever they sit.
#[wasm_bindgen]
pub fn file_survey(file: &[u8], tags: &str) -> String {
    survey::json_for_tags(file, &tag_list(tags))
}

/// One image, decoded once, for every pixel tool to read.
///
/// At the largest image allowed a decode is half a gigabyte of pixels, which no tool should
/// have to make for itself. The raster stays behind in WASM memory, so a 12-megapixel RGBA
/// buffer never crosses the boundary, until the worker frees it.
#[wasm_bindgen]
pub struct DecodedPixels {
    raster: pixels::Raster,
}

#[wasm_bindgen]
impl DecodedPixels {
    #[wasm_bindgen(constructor)]
    pub fn new(file: &[u8], inflated: &[u8]) -> Result<DecodedPixels, JsError> {
        let raster = pixels::decode(file, inflated).map_err(|e| JsError::new(&e))?;
        Ok(Self { raster })
    }

    /// Rows that could be decoded, which a damaged file can leave short of `declared_rows`.
    pub fn rows(&self) -> usize {
        self.raster.height
    }

    pub fn declared_rows(&self) -> usize {
        self.raster.declared_height
    }

    /// Sweeps LSB parameters and reports combinations that produced something.
    pub fn lsb_sweep(&self, max_bytes: usize, tags: &str) -> String {
        cuttlefish::sweep_json_naming(
            &self.raster.rgba,
            self.raster.width,
            self.raster.height,
            self.raster.has_alpha,
            max_bytes,
            &tag_list(tags),
        )
    }

    /// Every bit plane downsampled for the wall.
    ///
    /// Returns one buffer rather than a struct: a u32 length, then that many bytes of
    /// JSON metadata, then the grayscale thumbnails ordered channel-major and bit
    /// ascending.
    pub fn plane_wall(&self, target_width: usize) -> Vec<u8> {
        let channels = if self.raster.has_alpha { 4 } else { 3 };

        let (json, _, _, thumbnails) = cuttlefish::plane_wall(
            &self.raster.rgba,
            self.raster.width,
            self.raster.height,
            channels,
            target_width,
        );

        let mut out = Vec::with_capacity(4 + json.len() + thumbnails.len());
        out.extend_from_slice(&(json.len() as u32).to_le_bytes());
        out.extend_from_slice(json.as_bytes());
        out.extend_from_slice(&thumbnails);
        out
    }

    /// Chi-square attack over increasing prefixes (Westfeld & Pfitzmann, 1999).
    pub fn chi_square(&self, steps: usize) -> String {
        cuttlefish::chi_square_json(&self.raster.rgba, steps)
    }

    /// RS analysis, estimating the embedding rate (Fridrich, Goljan & Du, 2001).
    pub fn rs_analysis(&self) -> String {
        let estimate = cuttlefish::rs::analyse(
            &self.raster.rgba,
            self.raster.width,
            self.raster.height,
            3,
        );
        cuttlefish::rs::json(&estimate)
    }

    /// One plane at full resolution, 0 or 255 per pixel.
    pub fn plane(&self, channel: usize, bit: u8) -> Result<Vec<u8>, JsError> {
        if channel > 3 || bit > 7 {
            return Err(JsError::new("channel must be 0-3 and bit 0-7"));
        }
        Ok(cuttlefish::plane_full(&self.raster.rgba, channel, bit))
    }

    /// Full extraction for one chosen combination.
    pub fn lsb_extract(
        &self,
        channels: &str,
        bit: u8,
        msb_first: bool,
        column_major: bool,
        max_bytes: usize,
    ) -> Result<Vec<u8>, JsError> {
        let rgba = &self.raster.rgba;
        let size = (self.raster.width, self.raster.height);

        if column_major {
            cuttlefish::extract_named_columns(rgba, size, channels, bit, msb_first, max_bytes)
        } else {
            cuttlefish::extract_named(rgba, channels, bit, msb_first, max_bytes)
        }
        .ok_or_else(|| JsError::new(&format!("unknown channel set {channels}")))
    }
}

/// The comma-separated flag tags the worker passes across the boundary.
fn tag_list(tags: &str) -> Vec<String> {
    tags.split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
        .collect()
}

/// As much of a deflate stream as can be read, keeping what came before any damage.
///
/// Packed the same way as the wall: a u32 length, that many bytes of JSON saying what
/// went wrong if anything did, then the output.
///
/// @param wrapper "zlib" for a two-byte header and a checksum, anything else for none
#[wasm_bindgen]
pub fn inflate_stream(data: &[u8], wrapper: &str, limit: usize) -> Vec<u8> {
    let wrapper = if wrapper == "zlib" {
        inflate::Wrapper::Zlib
    } else {
        inflate::Wrapper::Raw
    };
    inflate::packed(inflate::inflate(data, wrapper, limit))
}

/// A PDF stream with its filter chain undone, packed like [`inflate_stream`].
#[wasm_bindgen]
pub fn pdf_stream(data: &[u8], filter: &str, limit: usize) -> Vec<u8> {
    inflate::packed(pdf::decode_stream(data, filter, limit))
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

/// The flags with the caller's tags in a byte run, and whether there were more than fit.
#[wasm_bindgen]
pub fn find_flags_for_tags(data: &[u8], tags: &str) -> String {
    let scan = bytes::scan_flags(data, &tag_list(tags), true);

    let mut out = String::from("{");
    json::push_string(&mut out, "flags");
    out.push(':');
    out.push_str(&flags_json(&scan.found));
    out.push(',');
    json::push_bool(&mut out, "truncated", scan.truncated);
    out.push('}');
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

/// The container walk as a JSON string: header, every chunk, text chunks, and any
/// bytes past IEND. The caller's flag tags steer what the walk calls a flag.
#[wasm_bindgen]
pub fn png_structure(file: &[u8], tags: &str) -> String {
    png::structure_json_for_tags(file, &tag_list(tags))
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
    mantis::json_for_tags(data, &tag_list(tags))
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
    let peel = mantis::peel_with_depth(data, &tag_list(tags), remaining_depth);
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
pub fn aes_probe(file: &[u8], tags: &str) -> String {
    aes::json_naming(file, &tag_list(tags))
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

/// What an executable declares about itself, as JSON, or null when the file
/// is neither an ELF nor a PE.
///
/// The header, the section table, the libraries needed, the symbols passing
/// in and out, and the protections the file says it was built with, each
/// read and reported. Nothing here decodes an instruction: the question this
/// answers is what the file says it is, which the format states outright,
/// rather than what its code does, which it does not.
#[wasm_bindgen]
pub fn binary_structure(file: &[u8]) -> String {
    binary::json(file)
}

/// What a Windows registry hive remembers about the USB devices plugged
/// into the machine it came from, as JSON, or null when the file is not one.
///
/// A hive is a tree of cells pointing at each other by offset rather than a
/// table, so this walks it from the root. Every key carries the time it was
/// last written, and for the keys Windows only touches when a device is
/// connected, that timestamp is the evidence.
#[wasm_bindgen]
pub fn registry_hive(file: &[u8]) -> String {
    registry::json(file)
}

/// What a SQLite database holds, as JSON, or null when the file is not one.
///
/// The tables and their rows, and the rows recovered from each page's free
/// space: deleted, and still in the file. A raw scan already finds a flag
/// sitting in a database; this says which table a row was in and whether it
/// was one a query would still return.
#[wasm_bindgen]
pub fn sqlite_database(file: &[u8], tags: &str) -> String {
    sqlite::json_for_tags(file, &tag_list(tags))
}

/// What a packet capture carried, as JSON, or null when the file is neither a
/// classic pcap nor a pcapng.
///
/// The header, the protocol breakdown, the conversations, the DNS questions
/// asked, and the reassembled TCP streams. The streams are the point: a raw
/// scan already finds a flag that sits whole inside one packet, but a flag
/// broken across two TCP segments is interrupted in the file by the headers of
/// the packet that carried the second half, so only putting the connection
/// back together reveals it. The caller's flag tags steer that scan.
#[wasm_bindgen]
pub fn pcap_capture(file: &[u8], tags: &str) -> String {
    pcap::json(file, &tag_list(tags))
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
    mantis::keyed::json(&mantis::keyed::with_key_for_tags(data, key, &tag_list(tags)))
}

/// JPEG coefficient analysis as JSON: the chi-square attack, the coefficient
/// histogram, and any JSteg extraction that produced something readable.
///
/// Null for a file that is not a JPEG, and an object carrying `error` for one
/// this decoder will not read, such as a progressive JPEG.
#[wasm_bindgen]
pub fn jpeg_stego(file: &[u8], max_bytes: usize, steps: usize, tags: &str) -> String {
    jpeg::stego::json_naming(file, max_bytes, steps, &tag_list(tags))
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
pub fn palette_stego(file: &[u8], inflated: &[u8], max_bytes: usize, tags: &str) -> String {
    let Some(indices) = png::palette_indices(file, inflated) else {
        return "null".to_string();
    };
    let Some(plte) = png::chunk_payload(file, b"PLTE") else {
        return "null".to_string();
    };

    cuttlefish::palette::json_naming(plte, &indices, max_bytes, &tag_list(tags))
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
pub fn wav_lsb_sweep(file: &[u8], max_bytes: usize, tags: &str) -> Result<String, JsError> {
    let parsed = wav::parse(file).map_err(|e| JsError::new(&e.to_string()))?;
    let samples = wav::integer_samples(file, &parsed).map_err(|e| JsError::new(&e.to_string()))?;

    Ok(cuttlefish::audio::sweep_json_naming(
        &samples,
        parsed.format.channels,
        parsed.format.sample_rate,
        max_bytes,
        &tag_list(tags),
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
/// The packed binary tail is unnecessary, since only metadata and detector results
/// are wanted. The caller's flag tags steer what the sweep calls a flag.
#[wasm_bindgen]
pub fn gif_frame_analysis(file: &[u8], tags: &str, max_bytes: usize, chi_steps: usize) -> String {
    gif::analysis_json(file, &tag_list(tags), max_bytes, chi_steps)
}
