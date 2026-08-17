//! trawl-core — the analysis engine.
//!
//! Everything here is a pure function over `&[u8]` or over decoded pixel data:
//! slice in, struct out. No async, no I/O, no global state.

use wasm_bindgen::prelude::*;

/// Scaffold smoke test: proves the byte-slice marshalling path works end to end.
///
/// A `&[u8]` cannot cross the WASM boundary directly — wasm-bindgen copies the
/// caller's `Uint8Array` into linear memory and passes this function a pointer and
/// a length. If this returns the right number for a file read in the browser, the
/// bytes arrived intact.
///
/// Delete this once the first real detector lands.
#[wasm_bindgen]
pub fn byte_len(bytes: &[u8]) -> usize {
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_len_counts_the_whole_slice() {
        assert_eq!(byte_len(&[0x89, b'P', b'N', b'G']), 4);
        assert_eq!(byte_len(&[]), 0);
    }
}
