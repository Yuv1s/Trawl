//! Quantized DCT coefficients, recovered from a JPEG's scans.
//!
//! Every other pixel tool in Trawl works on decoded samples. This one must not.
//! JSteg, F5 and OutGuess all write into the *quantized* coefficients, which is
//! the last representation before entropy coding, so dequantizing and running an
//! inverse DCT would destroy the exact numbers the attacks live in. The decode
//! therefore stops one step early: Huffman out, coefficients in hand, no IDCT.
//!
//! Baseline and progressive are both read. A progressive file sends the same
//! coefficients across several scans: a band of frequencies at reduced
//! precision, then further scans filling in lower bits. Nothing can be judged
//! until the last scan lands, so the coefficient buffer persists and every scan
//! writes into it.

use core::fmt;

use super::{segments, Segment};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DctError {
    NotJpeg,
    NoFrame,
    NoScan,
    Unsupported(&'static str),
    Truncated,
    BadHuffmanCode,
    MissingTable,
}

impl fmt::Display for DctError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJpeg => write!(f, "not a JPEG"),
            Self::NoFrame => write!(f, "no frame header, so there are no coefficients to read"),
            Self::NoScan => write!(f, "no scan, so the file carries no coefficient data"),
            Self::Unsupported(what) => write!(f, "unsupported JPEG feature: {what}"),
            Self::Truncated => write!(f, "the scan data ends before the last block"),
            Self::BadHuffmanCode => write!(f, "a Huffman code in the scan does not decode"),
            Self::MissingTable => write!(f, "the scan refers to a table the file does not define"),
        }
    }
}

/// Zig-zag order. Coefficients are stored along this path, low frequency first,
/// so index 0 is DC and 63 is the highest frequency.
pub const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Component {
    pub id: u8,
    pub horizontal: usize,
    pub vertical: usize,
    pub quant_table: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub width: usize,
    pub height: usize,
    pub precision: u8,
    pub progressive: bool,
    pub components: Vec<Component>,
}

/// One 8x8 block of quantized coefficients, in zig-zag order.
pub type Block = [i32; 64];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coefficients {
    pub frame: Frame,
    /// Blocks per component in raster order, left to right then top to bottom.
    pub blocks: Vec<Vec<Block>>,
    /// (component, index within that component) in entropy-stream order.
    ///
    /// An embedder walks the coefficients in the order they were coded, which on
    /// a subsampled colour image interleaves the components inside each MCU.
    /// Raster order loses that, and reading a payload in the wrong order returns
    /// noise, so the traversal is kept alongside.
    pub order: Vec<(usize, usize)>,
    /// Quantization table per slot, so the caller can report quality without
    /// this module having to define what quality means.
    pub quant: Vec<[u16; 64]>,
    pub restart_interval: usize,
    /// How many scans the file needed. One for baseline, several for progressive.
    pub scans: usize,
    /// True when a scan ran out of data before covering every block.
    ///
    /// The buffer is still the image's full size, so the blocks past that point
    /// read as zero. They are not measurements, and nothing should present them
    /// as one.
    pub truncated: bool,
}

impl Coefficients {
    pub fn total_blocks(&self) -> usize {
        self.blocks.iter().map(|c| c.len()).sum()
    }
}

/// A canonical JPEG Huffman table, expanded for decoding.
#[derive(Debug, Clone, Default)]
struct Huffman {
    /// Smallest code of each length, and the index into `values` it starts at.
    min_code: [i32; 17],
    max_code: [i32; 17],
    first_index: [i32; 17],
    values: Vec<u8>,
}

impl Huffman {
    /// Builds the canonical code assignment from the 16 length counts.
    fn build(counts: &[u8; 16], values: Vec<u8>) -> Self {
        let mut table = Self {
            values,
            ..Default::default()
        };

        let mut code = 0i32;
        let mut index = 0i32;

        for length in 1..=16usize {
            table.first_index[length] = index;
            table.min_code[length] = code;
            code += counts[length - 1] as i32;
            index += counts[length - 1] as i32;
            table.max_code[length] = if counts[length - 1] == 0 { -1 } else { code - 1 };
            code <<= 1;
        }

        table
    }
}

/// Reads one scan's entropy data a bit at a time, hiding JPEG's byte stuffing.
struct BitReader<'a> {
    data: &'a [u8],
    at: usize,
    end: usize,
    bits: u32,
    count: u32,
    /// Set once the reader runs past this scan. Further reads return zero.
    spent: bool,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8], at: usize, end: usize) -> Self {
        Self {
            data,
            at,
            end: end.min(data.len()),
            bits: 0,
            count: 0,
            spent: false,
        }
    }

    /// One bit, MSB first.
    ///
    /// A literal 0xFF in the entropy stream is written as 0xFF 0x00, so the
    /// stuffed zero is dropped here. Anything else after 0xFF is a marker, which
    /// means this scan is over.
    ///
    /// Running out returns zeroes rather than failing. A truncated file should
    /// give back the blocks it did contain, and on a progressive file a later
    /// scan may still be intact.
    fn bit(&mut self) -> u32 {
        if self.count == 0 {
            if self.at >= self.end {
                self.spent = true;
                return 0;
            }

            let byte = self.data[self.at];
            self.at += 1;

            if byte == 0xff {
                match self.data.get(self.at) {
                    Some(0x00) => self.at += 1,
                    _ => {
                        self.spent = true;
                        return 0;
                    }
                }
            }

            self.bits = byte as u32;
            self.count = 8;
        }

        self.count -= 1;
        (self.bits >> self.count) & 1
    }

    fn receive(&mut self, n: u32) -> u32 {
        let mut out = 0u32;
        for _ in 0..n {
            out = (out << 1) | self.bit();
        }
        out
    }

    fn decode(&mut self, table: &Huffman) -> Result<u8, DctError> {
        let mut code = self.bit() as i32;

        for length in 1..=16usize {
            if table.max_code[length] >= 0 && code <= table.max_code[length] {
                let index = table.first_index[length] + (code - table.min_code[length]);
                return table
                    .values
                    .get(index as usize)
                    .copied()
                    .ok_or(DctError::BadHuffmanCode);
            }
            code = (code << 1) | self.bit() as i32;
        }

        Err(DctError::BadHuffmanCode)
    }

    /// Restart markers reset the bit position and the DC predictors.
    fn restart(&mut self) -> bool {
        self.count = 0;

        // The encoder pads to a byte boundary before the marker.
        while self.at + 1 < self.end {
            if self.data[self.at] == 0xff && matches!(self.data[self.at + 1], 0xd0..=0xd7) {
                self.at += 2;
                return true;
            }
            self.at += 1;
        }

        false
    }
}

/// Sign-extends a JPEG variable-length integer.
///
/// The magnitude category says how many bits follow; a leading zero means the
/// value is negative and needs the offset applied.
fn extend(value: u32, length: u32) -> i32 {
    if length == 0 {
        return 0;
    }
    if value < (1 << (length - 1)) {
        value as i32 - (1 << length) + 1
    } else {
        value as i32
    }
}

fn u16_at(file: &[u8], at: usize) -> Option<usize> {
    let b = file.get(at..at + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]) as usize)
}

fn read_frame(file: &[u8], segment: Segment) -> Result<Frame, DctError> {
    let at = segment.data_offset;
    let precision = *file.get(at).ok_or(DctError::Truncated)?;
    let height = u16_at(file, at + 1).ok_or(DctError::Truncated)?;
    let width = u16_at(file, at + 3).ok_or(DctError::Truncated)?;
    let count = *file.get(at + 5).ok_or(DctError::Truncated)? as usize;

    let mut components = Vec::with_capacity(count);
    for i in 0..count {
        let base = at + 6 + i * 3;
        let spec = file.get(base..base + 3).ok_or(DctError::Truncated)?;
        components.push(Component {
            id: spec[0],
            horizontal: (spec[1] >> 4) as usize,
            vertical: (spec[1] & 0x0f) as usize,
            quant_table: spec[2] as usize,
        });
    }

    if components.is_empty() {
        return Err(DctError::NoFrame);
    }
    if components
        .iter()
        .any(|c| c.horizontal == 0 || c.vertical == 0)
    {
        return Err(DctError::Unsupported("a component declaring zero sampling"));
    }
    if width == 0 || height == 0 {
        return Err(DctError::Unsupported("a zero dimension"));
    }

    Ok(Frame {
        width,
        height,
        precision,
        progressive: segment.marker == 0xc2,
        components,
    })
}

/// Reads every quantization table a DQT segment carries. One segment may hold
/// several, each prefixed by its precision and slot.
fn read_quant(file: &[u8], segment: Segment, tables: &mut [[u16; 64]; 4]) {
    let mut at = segment.data_offset;
    // `length` already excludes the two-byte length field.
    let end = segment.data_offset + segment.length;

    while at < end {
        let Some(&spec) = file.get(at) else { return };
        let wide = spec >> 4 == 1;
        let slot = (spec & 0x0f) as usize;
        at += 1;

        if slot >= 4 {
            return;
        }

        for slot_value in tables[slot].iter_mut() {
            let value = if wide {
                let Some(pair) = file.get(at..at + 2) else {
                    return;
                };
                at += 2;
                u16::from_be_bytes([pair[0], pair[1]])
            } else {
                let Some(&byte) = file.get(at) else { return };
                at += 1;
                byte as u16
            };
            *slot_value = value;
        }
    }
}

fn read_huffman(
    file: &[u8],
    segment: Segment,
    dc: &mut [Option<Huffman>; 4],
    ac: &mut [Option<Huffman>; 4],
) {
    let mut at = segment.data_offset;
    let end = segment.data_offset + segment.length;

    while at < end {
        let Some(&spec) = file.get(at) else { return };
        let is_ac = spec >> 4 == 1;
        let slot = (spec & 0x0f) as usize;
        at += 1;

        let Some(counts) = file.get(at..at + 16) else {
            return;
        };
        at += 16;

        let mut lengths = [0u8; 16];
        lengths.copy_from_slice(counts);
        let total: usize = lengths.iter().map(|&c| c as usize).sum();

        let Some(values) = file.get(at..at + total) else {
            return;
        };
        at += total;

        if slot >= 4 {
            continue;
        }

        let table = Huffman::build(&lengths, values.to_vec());
        if is_ac {
            ac[slot] = Some(table);
        } else {
            dc[slot] = Some(table);
        }
    }
}

/// Per-component block storage.
///
/// Sized to whole MCUs, because an interleaved scan addresses blocks the image
/// itself does not reach when its dimensions do not divide evenly. Those
/// overhang blocks are decoded and then dropped.
struct Plane {
    /// Stored width in blocks, rounded up to whole MCUs.
    stride: usize,
    /// Blocks the image actually covers, which is what a single-component scan
    /// walks and what survives into the result.
    across: usize,
    down: usize,
    blocks: Vec<Block>,
}

/// What one SOS header declares.
struct ScanHeader {
    /// Frame component index, DC table slot, AC table slot.
    components: Vec<(usize, usize, usize)>,
    spectral_start: usize,
    spectral_end: usize,
    approx_high: u32,
    approx_low: u32,
}

fn read_scan_header(file: &[u8], scan: Segment, frame: &Frame) -> Result<ScanHeader, DctError> {
    let at = scan.data_offset;
    let count = *file.get(at).ok_or(DctError::Truncated)? as usize;
    if count == 0 || count > 4 {
        return Err(DctError::Unsupported("a scan naming no components"));
    }

    let mut components = Vec::with_capacity(count);
    for i in 0..count {
        let spec = file
            .get(at + 1 + i * 2..at + 3 + i * 2)
            .ok_or(DctError::Truncated)?;

        let index = frame
            .components
            .iter()
            .position(|c| c.id == spec[0])
            .ok_or(DctError::MissingTable)?;

        components.push((index, (spec[1] >> 4) as usize, (spec[1] & 0x0f) as usize));
    }

    let tail = file
        .get(at + 1 + count * 2..at + 4 + count * 2)
        .ok_or(DctError::Truncated)?;

    let spectral_start = tail[0] as usize;
    let spectral_end = tail[1] as usize;

    if spectral_start > 63 || spectral_end > 63 || spectral_start > spectral_end {
        return Err(DctError::Unsupported("a scan with an impossible band"));
    }

    Ok(ScanHeader {
        components,
        spectral_start,
        spectral_end,
        approx_high: (tail[2] >> 4) as u32,
        approx_low: (tail[2] & 0x0f) as u32,
    })
}

/// Every block one interleaved MCU covers, as (component index, storage index,
/// position in the scan's component list).
fn mcu_targets(
    frame: &Frame,
    header: &ScanHeader,
    planes: &[Plane],
    mcus_across: usize,
    mcu: usize,
) -> Vec<(usize, usize, usize)> {
    let mcu_row = mcu / mcus_across;
    let mcu_col = mcu % mcus_across;
    let mut out = Vec::new();

    for (slot, &(index, _, _)) in header.components.iter().enumerate() {
        let component = frame.components[index];
        for y in 0..component.vertical {
            for x in 0..component.horizontal {
                let row = mcu_row * component.vertical + y;
                let col = mcu_col * component.horizontal + x;
                out.push((index, row * planes[index].stride + col, slot));
            }
        }
    }

    out
}

/// Runs one scan over the coefficient buffer.
///
/// Baseline files have a single scan covering everything. A progressive file has
/// several, each filling in part of the same buffer, so this is called in turn
/// and never resets what earlier scans wrote.
#[allow(clippy::too_many_arguments)]
fn decode_scan(
    reader: &mut BitReader,
    frame: &Frame,
    header: &ScanHeader,
    planes: &mut [Plane],
    dc_tables: &[Option<Huffman>; 4],
    ac_tables: &[Option<Huffman>; 4],
    restart_interval: usize,
    order: &mut Vec<(usize, usize)>,
    record_order: bool,
) -> Result<bool, DctError> {
    let interleaved = header.components.len() > 1;

    let h_max = frame.components.iter().map(|c| c.horizontal).max().unwrap();
    let v_max = frame.components.iter().map(|c| c.vertical).max().unwrap();
    let mcus_across = frame.width.div_ceil(8 * h_max);
    let mcus_down = frame.height.div_ceil(8 * v_max);

    let mut predictor = vec![0i32; frame.components.len()];
    let mut eob_run = 0u32;

    // Interleaved scans walk MCUs. A single-component scan walks that
    // component's own blocks in raster order, which is a different traversal and
    // a classic place to go wrong.
    let units = if interleaved {
        mcus_across * mcus_down
    } else {
        let (index, _, _) = header.components[0];
        planes[index].across * planes[index].down
    };

    let mut since_restart = 0usize;

    for unit in 0..units {
        if restart_interval > 0 && unit > 0 && since_restart == restart_interval {
            if !reader.restart() {
                return Ok(true);
            }
            predictor.iter_mut().for_each(|p| *p = 0);
            eob_run = 0;
            since_restart = 0;
        }
        since_restart += 1;

        let targets = if interleaved {
            mcu_targets(frame, header, planes, mcus_across, unit)
        } else {
            let (index, _, _) = header.components[0];
            let row = unit / planes[index].across;
            let col = unit % planes[index].across;
            vec![(index, row * planes[index].stride + col, 0usize)]
        };

        for (index, at, slot) in targets {
            if at >= planes[index].blocks.len() {
                continue;
            }

            let (_, dc_slot, ac_slot) = header.components[slot];

            if record_order {
                order.push((index, at));
            }

            let block = &mut planes[index].blocks[at];

            if !frame.progressive {
                let dc = dc_tables[dc_slot].as_ref().ok_or(DctError::MissingTable)?;
                let ac = ac_tables[ac_slot].as_ref().ok_or(DctError::MissingTable)?;
                decode_baseline_block(reader, block, dc, ac, &mut predictor[index])?;
            } else if header.spectral_start == 0 {
                let dc = dc_tables[dc_slot].as_ref().ok_or(DctError::MissingTable)?;
                if header.approx_high == 0 {
                    decode_dc_first(reader, block, dc, &mut predictor[index], header.approx_low)?;
                } else {
                    decode_dc_refine(reader, block, header.approx_low);
                }
            } else {
                let ac = ac_tables[ac_slot].as_ref().ok_or(DctError::MissingTable)?;
                if header.approx_high == 0 {
                    decode_ac_first(reader, block, ac, header, &mut eob_run)?;
                } else {
                    decode_ac_refine(reader, block, ac, header, &mut eob_run)?;
                }
            }
        }

        if reader.spent {
            // Everything from here on stays zero, which is not the same as
            // having measured a zero.
            return Ok(true);
        }
    }

    Ok(false)
}

fn decode_baseline_block(
    reader: &mut BitReader,
    block: &mut Block,
    dc: &Huffman,
    ac: &Huffman,
    predictor: &mut i32,
) -> Result<(), DctError> {
    let category = reader.decode(dc)? as u32;
    *predictor += extend(reader.receive(category), category);
    block[0] = *predictor;

    let mut k = 1usize;
    while k < 64 {
        let symbol = reader.decode(ac)?;
        let run = (symbol >> 4) as usize;
        let size = (symbol & 0x0f) as u32;

        if size == 0 {
            // 0x00 ends the block, 0xF0 skips sixteen zeroes.
            if run != 15 {
                break;
            }
            k += 16;
            continue;
        }

        k += run;
        if k >= 64 {
            break;
        }

        block[k] = extend(reader.receive(size), size);
        k += 1;
    }

    Ok(())
}

/// The first scan to carry DC, at reduced precision.
fn decode_dc_first(
    reader: &mut BitReader,
    block: &mut Block,
    dc: &Huffman,
    predictor: &mut i32,
    low: u32,
) -> Result<(), DctError> {
    let category = reader.decode(dc)? as u32;
    *predictor += extend(reader.receive(category), category);
    block[0] = *predictor << low;
    Ok(())
}

/// A later DC scan, contributing one more bit per block.
fn decode_dc_refine(reader: &mut BitReader, block: &mut Block, low: u32) {
    if reader.bit() == 1 {
        block[0] |= 1 << low;
    }
}

/// The first scan to carry a band of AC coefficients.
fn decode_ac_first(
    reader: &mut BitReader,
    block: &mut Block,
    ac: &Huffman,
    header: &ScanHeader,
    eob_run: &mut u32,
) -> Result<(), DctError> {
    if *eob_run > 0 {
        *eob_run -= 1;
        return Ok(());
    }

    let mut k = header.spectral_start;
    while k <= header.spectral_end {
        let symbol = reader.decode(ac)?;
        let run = (symbol >> 4) as u32;
        let size = (symbol & 0x0f) as u32;

        if size == 0 {
            if run < 15 {
                // An end-of-band run: this block and the next few are finished.
                *eob_run = (1 << run) - 1;
                if run > 0 {
                    *eob_run += reader.receive(run);
                }
                break;
            }
            k += 16;
            continue;
        }

        k += run as usize;
        if k > header.spectral_end {
            break;
        }

        block[k] = extend(reader.receive(size), size) << header.approx_low;
        k += 1;
    }

    Ok(())
}

/// A later AC scan, adding one bit to coefficients already present and inserting
/// ones that reach the threshold for the first time.
///
/// The awkward part of progressive JPEG. Correction bits for coefficients that
/// are already non-zero are interleaved with the run-length coding of new ones,
/// so the two have to be walked together rather than in separate passes.
fn decode_ac_refine(
    reader: &mut BitReader,
    block: &mut Block,
    ac: &Huffman,
    header: &ScanHeader,
    eob_run: &mut u32,
) -> Result<(), DctError> {
    let plus = 1i32 << header.approx_low;
    let minus = -(1i32 << header.approx_low);

    let mut k = header.spectral_start;

    if *eob_run == 0 {
        while k <= header.spectral_end {
            let symbol = reader.decode(ac)?;
            let mut run = (symbol >> 4) as i32;
            let size = (symbol & 0x0f) as u32;
            let mut value = 0i32;

            if size == 0 {
                if run < 15 {
                    *eob_run = 1 << run;
                    if run > 0 {
                        *eob_run += reader.receive(run as u32);
                    }
                    break;
                }
                // Run of 15 with no value: skip sixteen zero-history slots.
            } else {
                value = if reader.bit() == 1 { plus } else { minus };
            }

            while k <= header.spectral_end {
                if block[k] != 0 {
                    // Already non-zero, so this scan only says whether to nudge
                    // it. Zero-history slots are what the run counts.
                    if reader.bit() == 1 && (block[k] & plus) == 0 {
                        block[k] += if block[k] >= 0 { plus } else { minus };
                    }
                } else {
                    if run == 0 {
                        if value != 0 {
                            block[k] = value;
                        }
                        break;
                    }
                    run -= 1;
                }
                k += 1;
            }

            k += 1;
        }
    }

    if *eob_run > 0 {
        // Inside an end-of-band run no new coefficients appear, but the ones
        // already there still take their correction bits.
        while k <= header.spectral_end {
            if block[k] != 0 && reader.bit() == 1 && (block[k] & plus) == 0 {
                block[k] += if block[k] >= 0 { plus } else { minus };
            }
            k += 1;
        }
        *eob_run -= 1;
    }

    Ok(())
}

/// Decodes every scan into quantized coefficients.
pub fn coefficients(file: &[u8]) -> Result<Coefficients, DctError> {
    if !super::has_signature(file) {
        return Err(DctError::NotJpeg);
    }

    let walked = segments(file);

    let mut quant = [[0u16; 64]; 4];
    let mut dc_tables: [Option<Huffman>; 4] = Default::default();
    let mut ac_tables: [Option<Huffman>; 4] = Default::default();
    let mut restart_interval = 0usize;
    let mut frame: Option<Frame> = None;
    let mut planes: Vec<Plane> = Vec::new();
    let mut order: Vec<(usize, usize)> = Vec::new();
    let mut scans = 0usize;
    let mut truncated = false;

    for (i, segment) in walked.iter().enumerate() {
        match segment.marker {
            0xdb => read_quant(file, *segment, &mut quant),
            0xc4 => read_huffman(file, *segment, &mut dc_tables, &mut ac_tables),
            0xdd => restart_interval = u16_at(file, segment.data_offset).unwrap_or(0),
            0xc0..=0xc2 if frame.is_none() => {
                let read = read_frame(file, *segment)?;

                let h_max = read.components.iter().map(|c| c.horizontal).max().unwrap();
                let v_max = read.components.iter().map(|c| c.vertical).max().unwrap();
                let mcus_across = read.width.div_ceil(8 * h_max);
                let mcus_down = read.height.div_ceil(8 * v_max);

                planes = read
                    .components
                    .iter()
                    .map(|c| {
                        let stride = mcus_across * c.horizontal;
                        let rows = mcus_down * c.vertical;
                        Plane {
                            stride,
                            across: (read.width * c.horizontal).div_ceil(8 * h_max),
                            down: (read.height * c.vertical).div_ceil(8 * v_max),
                            blocks: vec![[0i32; 64]; stride * rows],
                        }
                    })
                    .collect();

                frame = Some(read);
            }
            0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf => {
                return Err(DctError::Unsupported("arithmetic or lossless coding"));
            }
            0xda => {
                let Some(ref frame) = frame else {
                    return Err(DctError::NoFrame);
                };

                let header = read_scan_header(file, *segment, frame)?;

                // A progressive DC scan covers index 0 and nothing else, and an
                // AC scan covers one component at a time. Reading a scan that
                // breaks either rule as though it were well formed produces
                // numbers that look like coefficients and are not.
                if frame.progressive {
                    if header.spectral_start == 0 && header.spectral_end != 0 {
                        return Err(DctError::Unsupported(
                            "a progressive scan mixing DC and AC coefficients",
                        ));
                    }
                    if header.spectral_start > 0 && header.components.len() != 1 {
                        return Err(DctError::Unsupported(
                            "a progressive AC scan covering several components",
                        ));
                    }
                }

                // Entropy data runs from the end of the SOS header to whatever
                // marker the segment walk found next.
                let start = segment.data_offset + segment.length;
                let end = walked
                    .get(i + 1)
                    .map(|next| next.offset)
                    .unwrap_or(file.len());

                let mut reader = BitReader::new(file, start, end);

                // Record the traversal from the first scan that covers every
                // component, since that is the order an embedder walked. Later
                // refinement scans revisit the same blocks, and recording those
                // too would count every coefficient several times.
                let record = order.is_empty() && header.components.len() == frame.components.len();

                truncated |= decode_scan(
                    &mut reader,
                    frame,
                    &header,
                    &mut planes,
                    &dc_tables,
                    &ac_tables,
                    restart_interval,
                    &mut order,
                    record,
                )?;

                scans += 1;
            }
            _ => {}
        }
    }

    let frame = frame.ok_or(DctError::NoFrame)?;
    if scans == 0 {
        return Err(DctError::NoScan);
    }
    if frame.precision != 8 {
        return Err(DctError::Unsupported("sample precision other than 8 bits"));
    }

    // Drop the MCU overhang, so what comes out is exactly the image's blocks.
    let mut trimmed: Vec<Vec<Block>> = Vec::with_capacity(planes.len());
    let mut remap: Vec<Vec<usize>> = Vec::with_capacity(planes.len());

    for plane in &planes {
        let mut blocks = Vec::with_capacity(plane.across * plane.down);
        let mut indices = vec![usize::MAX; plane.blocks.len()];

        for row in 0..plane.down {
            for col in 0..plane.across {
                let at = row * plane.stride + col;
                indices[at] = blocks.len();
                blocks.push(plane.blocks[at]);
            }
        }

        trimmed.push(blocks);
        remap.push(indices);
    }

    let order = order
        .into_iter()
        .filter_map(|(component, at)| {
            let mapped = *remap[component].get(at)?;
            (mapped != usize::MAX).then_some((component, mapped))
        })
        .collect();

    Ok(Coefficients {
        frame,
        blocks: trimmed,
        order,
        quant: quant.to_vec(),
        restart_interval,
        scans,
        truncated,
    })
}

#[cfg(test)]
mod tests;
