//! One way in to pixel data, whatever the container was.
//!
//! Every pixel tool wants the same thing: non-premultiplied RGBA8 and the
//! dimensions to walk it by. Once a format can produce that, the bit-plane wall,
//! the LSB sweep, chi-square and RS analysis all work on it with no new code.

use crate::{bmp, gif, png};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raster {
    pub width: usize,
    pub height: usize,
    pub rgba: Vec<u8>,
    /// False when the alpha channel is a synthesised 255, so the sweep can skip
    /// combinations that would only ever read a constant.
    pub has_alpha: bool,
    pub format: &'static str,
}

/// Decodes to RGBA8.
///
/// @param inflated the already-inflated IDAT stream, which only PNG needs.
///        `DecompressionStream` does that on the JS side; BMP is uncompressed
///        and GIF carries its own LZW, so both ignore this.
pub fn decode(file: &[u8], inflated: &[u8]) -> Result<Raster, String> {
    if png::has_signature(file) {
        let header = png::header(file).map_err(|e| e.to_string())?;
        let rgba = png::decode(file, inflated).map_err(|e| e.to_string())?;
        return Ok(Raster {
            width: header.width as usize,
            height: header.height as usize,
            rgba,
            has_alpha: matches!(header.color_type, 4 | 6),
            format: "PNG",
        });
    }

    if bmp::has_signature(file) {
        let (header, rgba) = bmp::decode(file).map_err(|e| e.to_string())?;
        return Ok(Raster {
            width: header.width,
            height: header.height,
            rgba,
            has_alpha: header.bits_per_pixel == 32,
            format: "BMP",
        });
    }

    if gif::has_signature(file) {
        let (header, rgba) = gif::decode(file).map_err(|e| e.to_string())?;
        return Ok(Raster {
            width: header.width,
            height: header.height,
            rgba,
            // GIF alpha is a single fully transparent index rather than a
            // channel, so sweeping it would read one bit of nothing.
            has_alpha: false,
            format: "GIF",
        });
    }

    Err("no decoder for this format yet".to_string())
}

#[cfg(test)]
mod tests;
