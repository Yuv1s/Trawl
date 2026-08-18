//! A JPEG assembler for tests, writing coefficients straight into the entropy
//! stream so every expected value is known by construction rather than by
//! trusting a third-party encoder.
//!
//! `dct::tests` validates this builder before `stego::tests` relies on it.

use super::dct::Block;

/// Writes entropy-coded bits the way a JPEG encoder does, stuffing a zero after
/// every literal 0xFF.
#[derive(Default)]
pub(crate) struct BitWriter {
    out: Vec<u8>,
    byte: u8,
    filled: u8,
}

impl BitWriter {
    fn push(&mut self, bit: u32) {
        self.byte = (self.byte << 1) | (bit & 1) as u8;
        self.filled += 1;

        if self.filled == 8 {
            self.out.push(self.byte);
            if self.byte == 0xff {
                self.out.push(0x00);
            }
            self.byte = 0;
            self.filled = 0;
        }
    }

    fn write(&mut self, value: u32, length: u32) {
        for i in (0..length).rev() {
            self.push((value >> i) & 1);
        }
    }

    /// The encoder pads the final byte with ones, never zeroes: a run of zeroes
    /// could decode as another symbol.
    fn flush(&mut self) {
        while self.filled != 0 {
            self.push(1);
        }
    }
}

/// Every AC symbol that can occur, at one code length, so a code is just its
/// index and nothing about these tests depends on a clever table. Curating a
/// shorter list only meant the fixture builder ran out of symbols on the cases
/// worth testing. The decoder's canonical builder is exercised separately.
pub(crate) fn ac_symbols() -> Vec<u8> {
    let mut out = vec![0x00, 0xf0];

    // End-of-band runs, which only progressive uses. A run of 0 is 0x00 and a
    // run of 15 with no value is ZRL, so the middle fourteen are what is left.
    for run in 1..15u8 {
        out.push(run << 4);
    }

    for run in 0..16u8 {
        for size in 1..=10u8 {
            out.push((run << 4) | size);
        }
    }

    out
}

pub(crate) fn dc_code(category: u8) -> (u32, u32) {
    (category as u32, 4)
}

pub(crate) fn ac_code(symbol: u8) -> (u32, u32) {
    let index = ac_symbols()
        .iter()
        .position(|&s| s == symbol)
        .unwrap_or_else(|| panic!("test table has no AC symbol 0x{symbol:02x}"));
    (index as u32, 8)
}

/// Magnitude category and the bits JPEG writes for a coefficient value.
pub(crate) fn magnitude(value: i32) -> (u32, u32) {
    if value == 0 {
        return (0, 0);
    }
    let size = 32 - value.unsigned_abs().leading_zeros();
    let bits = if value > 0 {
        value as u32
    } else {
        (value + (1 << size) - 1) as u32
    };
    (size, bits)
}

pub(crate) fn encode_block(w: &mut BitWriter, block: &Block, predictor: &mut i32) {
    let diff = block[0] - *predictor;
    *predictor = block[0];

    let (size, bits) = magnitude(diff);
    let (code, length) = dc_code(size as u8);
    w.write(code, length);
    w.write(bits, size);

    let last = (1..64).rev().find(|&k| block[k] != 0);

    let mut run = 0usize;
    for (k, &value) in block.iter().enumerate().take(64).skip(1) {
        if Some(k) > last {
            break;
        }
        if value == 0 {
            run += 1;
            continue;
        }

        while run >= 16 {
            let (code, length) = ac_code(0xf0);
            w.write(code, length);
            run -= 16;
        }

        let (size, bits) = magnitude(value);
        let (code, length) = ac_code(((run as u8) << 4) | size as u8);
        w.write(code, length);
        w.write(bits, size);
        run = 0;
    }

    if last.is_none() || last.unwrap() < 63 {
        let (code, length) = ac_code(0x00);
        w.write(code, length);
    }
}

pub(crate) fn marker(out: &mut Vec<u8>, code: u8, payload: &[u8]) {
    out.push(0xff);
    out.push(code);
    out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

pub(crate) fn huffman_tables() -> Vec<u8> {
    let mut out = Vec::new();

    // DC slot 0: twelve categories, all four bits long.
    out.push(0x00);
    let mut counts = [0u8; 16];
    counts[3] = 12;
    out.extend_from_slice(&counts);
    out.extend((0..12u8).collect::<Vec<_>>());

    // AC slot 0: every symbol, all eight bits long.
    let symbols = ac_symbols();
    out.push(0x10);
    let mut counts = [0u8; 16];
    counts[7] = symbols.len() as u8;
    out.extend_from_slice(&counts);
    out.extend_from_slice(&symbols);

    out
}

#[derive(Clone)]
pub(crate) struct Spec {
    pub(crate) width: usize,
    pub(crate) height: usize,
    /// One entry per component: (id, horizontal, vertical).
    pub(crate) components: Vec<(u8, usize, usize)>,
    pub(crate) restart_interval: usize,
    pub(crate) progressive: bool,
}

impl Spec {
    pub(crate) fn grayscale(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            components: vec![(1, 1, 1)],
            restart_interval: 0,
            progressive: false,
        }
    }
}

/// Where a block sits in its component, given its position in the MCU grid.
///
/// The decoder returns blocks in raster order, so the builders have to lay them
/// out that way too. Feeding them in MCU order instead only agrees when the
/// image is one MCU wide, which is exactly the case a small test uses.
fn raster_index(
    blocks: &[Block],
    across: usize,
    down: usize,
    row: usize,
    col: usize,
) -> Option<usize> {
    if row >= down || col >= across {
        // MCU overhang: the grid reaches past the image, and those blocks carry
        // nothing the image keeps.
        return None;
    }
    let at = row * across + col;
    (at < blocks.len()).then_some(at)
}

/// Blocks a component covers, across and down.
fn component_extent(spec: &Spec, c: usize) -> (usize, usize) {
    let (_, h, v) = spec.components[c];
    let h_max = spec.components.iter().map(|x| x.1).max().unwrap();
    let v_max = spec.components.iter().map(|x| x.2).max().unwrap();
    (
        (spec.width * h).div_ceil(8 * h_max),
        (spec.height * v).div_ceil(8 * v_max),
    )
}

/// Assembles a JPEG carrying exactly the coefficients given, one Vec per
/// component in MCU order.
pub(crate) fn build(spec: &Spec, blocks: &[Vec<Block>]) -> Vec<u8> {
    let mut file = vec![0xff, 0xd8];

    // A flat quantization table. Nothing here dequantizes, but a real file has
    // one and the walker reports it.
    let mut dqt = vec![0x00];
    dqt.extend(std::iter::repeat_n(1u8, 64));
    marker(&mut file, 0xdb, &dqt);

    let mut sof = vec![8];
    sof.extend_from_slice(&(spec.height as u16).to_be_bytes());
    sof.extend_from_slice(&(spec.width as u16).to_be_bytes());
    sof.push(spec.components.len() as u8);
    for &(id, h, v) in &spec.components {
        sof.push(id);
        sof.push(((h as u8) << 4) | v as u8);
        sof.push(0);
    }
    marker(&mut file, if spec.progressive { 0xc2 } else { 0xc0 }, &sof);

    marker(&mut file, 0xc4, &huffman_tables());

    if spec.restart_interval > 0 {
        marker(
            &mut file,
            0xdd,
            &(spec.restart_interval as u16).to_be_bytes(),
        );
    }

    let mut sos = vec![spec.components.len() as u8];
    for &(id, _, _) in &spec.components {
        sos.push(id);
        sos.push(0x00);
    }
    sos.extend_from_slice(&[0, 63, 0]);
    marker(&mut file, 0xda, &sos);

    let h_max = spec.components.iter().map(|c| c.1).max().unwrap();
    let v_max = spec.components.iter().map(|c| c.2).max().unwrap();
    let mcus = spec.width.div_ceil(8 * h_max) * spec.height.div_ceil(8 * v_max);

    let mcus_across = spec.width.div_ceil(8 * h_max);
    let empty = [0i32; 64];

    let mut w = BitWriter::default();
    let mut predictors = vec![0i32; spec.components.len()];

    for mcu in 0..mcus {
        if spec.restart_interval > 0 && mcu > 0 && mcu % spec.restart_interval == 0 {
            w.flush();
            w.out.push(0xff);
            w.out.push(0xd0 + ((mcu / spec.restart_interval - 1) % 8) as u8);
            predictors.iter_mut().for_each(|p| *p = 0);
        }

        let mcu_row = mcu / mcus_across;
        let mcu_col = mcu % mcus_across;

        for (c, &(_, h, v)) in spec.components.iter().enumerate() {
            let (across, down) = component_extent(spec, c);
            for y in 0..v {
                for x in 0..h {
                    let row = mcu_row * v + y;
                    let col = mcu_col * h + x;
                    let block = raster_index(&blocks[c], across, down, row, col)
                        .map(|at| blocks[c][at])
                        .unwrap_or(empty);
                    encode_block(&mut w, &block, &mut predictors[c]);
                }
            }
        }
    }

    w.flush();
    file.extend_from_slice(&w.out);
    file.extend_from_slice(&[0xff, 0xd9]);
    file
}

pub(crate) fn block(pairs: &[(usize, i32)]) -> Block {
    let mut out = [0i32; 64];
    for &(k, v) in pairs {
        out[k] = v;
    }
    out
}


// A progressive encoder, for testing the progressive decoder.
//
// Deliberately honest about what it proves. A round trip through one
// implementation only shows its two halves agree, so the tests also encode the
// same coefficients as baseline and compare the results. The baseline path has
// its own tests, which makes it a fixed reference rather than a second guess.

/// One progressive scan: which components, which band, and which bit.
pub(crate) struct Pass {
    /// Frame component indices this scan covers.
    pub components: Vec<usize>,
    pub spectral_start: usize,
    pub spectral_end: usize,
    /// The bit an earlier scan already sent. Zero on a first pass.
    pub approx_high: u32,
    /// The bit this scan carries.
    pub approx_low: u32,
}

impl Pass {
    pub(crate) fn dc(components: Vec<usize>, high: u32, low: u32) -> Self {
        Self {
            components,
            spectral_start: 0,
            spectral_end: 0,
            approx_high: high,
            approx_low: low,
        }
    }

    pub(crate) fn ac(component: usize, start: usize, end: usize, high: u32, low: u32) -> Self {
        Self {
            components: vec![component],
            spectral_start: start,
            spectral_end: end,
            approx_high: high,
            approx_low: low,
        }
    }
}

/// JPEG's point transform: divide by a power of two, truncating toward zero.
///
/// An arithmetic shift rounds negatives toward minus infinity instead, which
/// turns -5 at Al=2 into -2 where the format says -1. That is a different
/// coefficient, and every later refinement builds on the wrong number.
fn point_transform(value: i32, low: u32) -> i32 {
    let magnitude = (value.unsigned_abs() >> low) as i32;
    if value < 0 {
        -magnitude
    } else {
        magnitude
    }
}

fn encode_dc_first(w: &mut BitWriter, block: &Block, predictor: &mut i32, low: u32) {
    let value = block[0] >> low;
    let (size, bits) = magnitude(value - *predictor);
    *predictor = value;

    let (code, length) = dc_code(size as u8);
    w.write(code, length);
    w.write(bits, size);
}

fn encode_dc_refine(w: &mut BitWriter, block: &Block, low: u32) {
    w.push(((block[0] >> low) & 1) as u32);
}

/// Writes an end-of-band run, then any correction bits it was holding.
fn flush_eob(w: &mut BitWriter, eob_run: &mut u32, pending: &mut Vec<u32>) {
    if *eob_run == 0 && pending.is_empty() {
        return;
    }

    // The run is coded as a magnitude category plus that many extra bits.
    let r = if *eob_run == 0 {
        0
    } else {
        31 - (*eob_run).leading_zeros()
    };

    let (code, length) = ac_code((r as u8) << 4);
    w.write(code, length);
    if r > 0 {
        w.write(*eob_run - (1 << r), r);
    }

    for bit in pending.drain(..) {
        w.push(bit);
    }
    *eob_run = 0;
}

/// The first scan over a band, at reduced precision. Blocks with nothing in the
/// band fold into an end-of-band run.
fn encode_ac_first(w: &mut BitWriter, blocks: &[&Block], pass: &Pass) {
    let low = pass.approx_low;
    let mut eob_run = 0u32;
    let mut nothing: Vec<u32> = Vec::new();

    for block in blocks {
        let band: Vec<i32> = (pass.spectral_start..=pass.spectral_end)
            .map(|k| point_transform(block[k], low))
            .collect();

        let last = band.iter().rposition(|&v| v != 0);

        let Some(last) = last else {
            eob_run += 1;
            if eob_run == (1 << 14) - 1 {
                flush_eob(w, &mut eob_run, &mut nothing);
            }
            continue;
        };

        flush_eob(w, &mut eob_run, &mut nothing);

        let mut run = 0usize;
        for &value in band.iter().take(last + 1) {
            if value == 0 {
                run += 1;
                continue;
            }

            while run >= 16 {
                let (code, length) = ac_code(0xf0);
                w.write(code, length);
                run -= 16;
            }

            let (size, bits) = magnitude(value);
            let (code, length) = ac_code(((run as u8) << 4) | size as u8);
            w.write(code, length);
            w.write(bits, size);
            run = 0;
        }

        if last < band.len() - 1 {
            eob_run = 1;
        }
    }

    flush_eob(w, &mut eob_run, &mut nothing);
}

/// A refinement scan, adding one bit to the band.
///
/// Coefficients already non-zero take a single correction bit. Ones reaching the
/// threshold for the first time are run-length coded, with the correction bits
/// of everything in between woven through the run rather than sent separately.
fn encode_ac_refine(w: &mut BitWriter, blocks: &[&Block], pass: &Pass) {
    let low = pass.approx_low;
    let mut eob_run = 0u32;
    let mut pending: Vec<u32> = Vec::new();

    for block in blocks {
        // What this scan reveals, against what an earlier scan already sent.
        let now: Vec<i32> = (pass.spectral_start..=pass.spectral_end)
            .map(|k| point_transform(block[k], low))
            .collect();
        let before: Vec<i32> = (pass.spectral_start..=pass.spectral_end)
            .map(|k| point_transform(block[k], low + 1) * 2)
            .collect();

        let last_new = (0..now.len()).rfind(|&i| before[i] == 0 && now[i] != 0);

        let Some(last_new) = last_new else {
            // Nothing new here, so the band folds into a run and carries only
            // correction bits.
            eob_run += 1;
            for i in 0..now.len() {
                if before[i] != 0 {
                    pending.push(now[i].unsigned_abs() & 1);
                }
            }
            if eob_run == (1 << 14) - 1 {
                flush_eob(w, &mut eob_run, &mut pending);
            }
            continue;
        };

        flush_eob(w, &mut eob_run, &mut pending);

        let mut run = 0usize;
        let mut corrections: Vec<u32> = Vec::new();

        for i in 0..=last_new {
            if before[i] != 0 {
                corrections.push(now[i].unsigned_abs() & 1);
                continue;
            }

            if now[i] == 0 {
                run += 1;
                if run == 16 {
                    let (code, length) = ac_code(0xf0);
                    w.write(code, length);
                    for bit in corrections.drain(..) {
                        w.push(bit);
                    }
                    run = 0;
                }
                continue;
            }

            let (code, length) = ac_code(((run as u8) << 4) | 1);
            w.write(code, length);
            w.push(if now[i] > 0 { 1 } else { 0 });
            for bit in corrections.drain(..) {
                w.push(bit);
            }
            run = 0;
        }

        // Anything past the last new coefficient still owes its correction bits.
        for i in last_new + 1..now.len() {
            if before[i] != 0 {
                corrections.push(now[i].unsigned_abs() & 1);
            }
        }

        if last_new < now.len() - 1 {
            eob_run = 1;
            pending = corrections;
        } else {
            for bit in corrections.drain(..) {
                w.push(bit);
            }
        }
    }

    flush_eob(w, &mut eob_run, &mut pending);
}

/// Assembles a progressive JPEG carrying exactly these coefficients.
pub(crate) fn build_progressive(spec: &Spec, blocks: &[Vec<Block>], passes: &[Pass]) -> Vec<u8> {
    let mut file = vec![0xff, 0xd8];

    let mut dqt = vec![0x00];
    dqt.extend(std::iter::repeat_n(1u8, 64));
    marker(&mut file, 0xdb, &dqt);

    let mut sof = vec![8];
    sof.extend_from_slice(&(spec.height as u16).to_be_bytes());
    sof.extend_from_slice(&(spec.width as u16).to_be_bytes());
    sof.push(spec.components.len() as u8);
    for &(id, h, v) in &spec.components {
        sof.push(id);
        sof.push(((h as u8) << 4) | v as u8);
        sof.push(0);
    }
    marker(&mut file, 0xc2, &sof);
    marker(&mut file, 0xc4, &huffman_tables());

    let h_max = spec.components.iter().map(|c| c.1).max().unwrap();
    let v_max = spec.components.iter().map(|c| c.2).max().unwrap();
    let mcus_across = spec.width.div_ceil(8 * h_max);
    let mcus = mcus_across * spec.height.div_ceil(8 * v_max);

    for pass in passes {
        let mut sos = vec![pass.components.len() as u8];
        for &c in &pass.components {
            sos.push(spec.components[c].0);
            sos.push(0x00);
        }
        sos.push(pass.spectral_start as u8);
        sos.push(pass.spectral_end as u8);
        sos.push(((pass.approx_high as u8) << 4) | pass.approx_low as u8);
        marker(&mut file, 0xda, &sos);

        let mut w = BitWriter::default();

        if pass.spectral_start == 0 {
            // DC scans interleave every component they name, in MCU order.
            let mut predictors = vec![0i32; spec.components.len()];
            let empty = [0i32; 64];

            for mcu in 0..mcus {
                let mcu_row = mcu / mcus_across;
                let mcu_col = mcu % mcus_across;

                for &c in &pass.components {
                    let (_, h, v) = spec.components[c];
                    let (across, down) = component_extent(spec, c);

                    for y in 0..v {
                        for x in 0..h {
                            let row = mcu_row * v + y;
                            let col = mcu_col * h + x;
                            let block = raster_index(&blocks[c], across, down, row, col)
                                .map(|at| blocks[c][at])
                                .unwrap_or(empty);

                            if pass.approx_high == 0 {
                                encode_dc_first(&mut w, &block, &mut predictors[c], pass.approx_low);
                            } else {
                                encode_dc_refine(&mut w, &block, pass.approx_low);
                            }
                        }
                    }
                }
            }
        } else {
            // An AC scan covers one component, in that component's raster order.
            let c = pass.components[0];
            let refs: Vec<&Block> = blocks[c].iter().collect();

            if pass.approx_high == 0 {
                encode_ac_first(&mut w, &refs, pass);
            } else {
                encode_ac_refine(&mut w, &refs, pass);
            }
        }

        w.flush();
        file.extend_from_slice(&w.out);
    }

    file.extend_from_slice(&[0xff, 0xd9]);
    file
}
