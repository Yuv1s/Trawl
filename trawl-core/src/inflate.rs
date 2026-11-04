//! Inflate, written out here for the one thing the platform's will not do: hand back
//! what it had when something went wrong.
//!
//! `DecompressionStream` errors the moment a checksum fails or junk follows the data, and
//! the Streams specification has an errored stream discard every chunk not yet read. In
//! Chromium a three-kilobyte stream with a wrong Adler-32 gives back nothing, and a
//! megabyte with one byte after it gives back 128 KB. A browser showing the same image has
//! no such trouble, so a flag in those pixels was there for everyone but Trawl.
//!
//! So this stops where the stream stops making sense, keeps everything before that, and
//! says what went wrong. Nothing here is an error to the caller: a damaged stream is a
//! finding, and most of what it held is usually still there.

use crate::json::{push_bool, push_field, push_number, push_string};

/// Most dynamic blocks read from one stream. Each builds three tables out of eight bytes
/// of input, and a compressor writes one for every few tens of kilobytes it produces.
const MAX_DYNAMIC_BLOCKS: usize = 1 << 18;

/// What a stream is wrapped in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrapper {
    /// Two header bytes and an Adler-32 after the data, which is what PNG and PDF use.
    Zlib,
    /// Nothing at all, which is how a ZIP stores each entry.
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Inflated {
    pub output: Vec<u8>,
    /// What stopped it or what was wrong, in words. The output is everything read before.
    pub error: Option<String>,
    /// True when `limit` stopped it, so the stream holds more than `output` does.
    pub capped: bool,
    /// Bytes after the end of the stream, which no compressor writes.
    pub trailing: usize,
}

/// Why a block could not be read any further.
enum Stop {
    /// The limit was reached, with more still to come.
    Limit,
    /// The input ended part way through a block.
    Truncated,
    Invalid(&'static str),
}

/// Reads bits least significant first, which is the one order deflate has.
struct Bits<'a> {
    data: &'a [u8],
    at: usize,
    hold: u64,
    count: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            at: 0,
            hold: 0,
            count: 0,
        }
    }

    fn refill(&mut self) {
        while self.count <= 56 && self.at < self.data.len() {
            self.hold |= (self.data[self.at] as u64) << self.count;
            self.at += 1;
            self.count += 8;
        }
    }

    fn take(&mut self, n: u32) -> Result<u32, Stop> {
        if self.count < n {
            self.refill();
            if self.count < n {
                return Err(Stop::Truncated);
            }
        }
        let value = (self.hold & ((1u64 << n) - 1)) as u32;
        self.hold >>= n;
        self.count -= n;
        Ok(value)
    }

    /// Hands unused whole bytes back and drops what is left of the current one, so the
    /// position is a byte boundary again.
    fn align(&mut self) {
        self.at -= (self.count / 8) as usize;
        self.hold = 0;
        self.count = 0;
    }
}

/// Bits looked up in one go. Longer codes take the slow walk below, and they are rare by
/// construction, since a long code is what a rare symbol gets.
const FAST_BITS: u32 = 10;
const MAX_CODE_BITS: usize = 15;

/// A canonical Huffman code, as deflate defines one.
struct Code {
    /// `symbol << 4 | length` for every code that fits, indexed by the next bits.
    fast: Vec<u16>,
    counts: [u16; MAX_CODE_BITS + 1],
    symbols: Vec<u16>,
}

impl Code {
    /// A code no bit pattern could decode has more codes of some length than that
    /// length can hold. One that merely leaves patterns unused is left to fail if a
    /// stream ever sends one, since a real compressor writes those for a single distance.
    fn build(lengths: &[u8]) -> Option<Self> {
        let mut counts = [0u16; MAX_CODE_BITS + 1];
        for &length in lengths {
            counts[length as usize] += 1;
        }
        counts[0] = 0;

        let mut left = 1i32;
        let mut next = [0u16; MAX_CODE_BITS + 2];
        let mut offsets = [0u16; MAX_CODE_BITS + 2];
        for length in 1..=MAX_CODE_BITS {
            left = left * 2 - counts[length] as i32;
            if left < 0 {
                return None;
            }
            next[length + 1] = (next[length] + counts[length]) << 1;
            offsets[length + 1] = offsets[length] + counts[length];
        }

        let mut symbols = vec![0u16; lengths.len()];
        let mut fast = vec![0u16; 1 << FAST_BITS];
        for (symbol, &length) in lengths.iter().enumerate() {
            let length = length as usize;
            if length == 0 {
                continue;
            }
            symbols[offsets[length] as usize] = symbol as u16;
            offsets[length] += 1;

            let code = next[length];
            next[length] += 1;
            if length <= FAST_BITS as usize {
                // The bits arrive in the opposite order to the one a code is written in.
                let reversed = (code.reverse_bits() >> (16 - length)) as usize;
                let entry = (symbol as u16) << 4 | length as u16;
                for slot in (reversed..1 << FAST_BITS).step_by(1 << length) {
                    fast[slot] = entry;
                }
            }
        }

        Some(Self {
            fast,
            counts,
            symbols,
        })
    }

    fn decode(&self, bits: &mut Bits) -> Result<u16, Stop> {
        if bits.count < MAX_CODE_BITS as u32 {
            bits.refill();
        }

        let entry = self.fast[(bits.hold & ((1 << FAST_BITS) - 1)) as usize];
        if entry != 0 {
            let length = (entry & 0xf) as u32;
            if length > bits.count {
                return Err(Stop::Truncated);
            }
            bits.hold >>= length;
            bits.count -= length;
            return Ok(entry >> 4);
        }

        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for length in 1..=MAX_CODE_BITS {
            code |= bits.take(1)? as i32;
            let count = self.counts[length] as i32;
            if code - count < first {
                return Ok(self.symbols[(index + code - first) as usize]);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }

        Err(Stop::Invalid("a code in the stream means nothing in its table"))
    }
}

/// Extra bits and base value of each length and distance code.
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049,
    3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];

/// One block's worth of literals and copies, written straight onto the output, which is
/// also the only window a copy needs.
fn codes(
    bits: &mut Bits,
    output: &mut Vec<u8>,
    limit: usize,
    literals: &Code,
    distances: &Code,
) -> Result<(), Stop> {
    loop {
        let symbol = literals.decode(bits)? as usize;

        if symbol < 256 {
            if output.len() >= limit {
                return Err(Stop::Limit);
            }
            output.push(symbol as u8);
            continue;
        }
        if symbol == 256 {
            return Ok(());
        }

        let slot = symbol - 257;
        let (Some(&base), Some(&extra)) = (LENGTH_BASE.get(slot), LENGTH_EXTRA.get(slot)) else {
            return Err(Stop::Invalid("a length code past the end of the table"));
        };
        let length = base as usize + bits.take(extra as u32)? as usize;

        let slot = distances.decode(bits)? as usize;
        let (Some(&base), Some(&extra)) = (DISTANCE_BASE.get(slot), DISTANCE_EXTRA.get(slot))
        else {
            return Err(Stop::Invalid("a distance code past the end of the table"));
        };
        let distance = base as usize + bits.take(extra as u32)? as usize;

        if distance > output.len() {
            return Err(Stop::Invalid("a copy reaches back before the start of the data"));
        }

        let room = limit - output.len().min(limit);
        let copied = length.min(room);
        let from = output.len() - distance;

        // Overlapping is how a run is written: each byte reads what the copy has just
        // laid down, so what is available to copy doubles every time round.
        let mut left = copied;
        while left > 0 {
            let step = left.min(output.len() - from);
            output.extend_from_within(from..from + step);
            left -= step;
        }
        if copied < length {
            return Err(Stop::Limit);
        }
    }
}

fn stored(bits: &mut Bits, output: &mut Vec<u8>, limit: usize) -> Result<(), Stop> {
    bits.align();

    let header = bits.data.get(bits.at..bits.at + 4).ok_or(Stop::Truncated)?;
    let length = u16::from_le_bytes([header[0], header[1]]);
    let check = u16::from_le_bytes([header[2], header[3]]);
    if length != !check {
        return Err(Stop::Invalid("a stored block's length fails its own check"));
    }
    bits.at += 4;

    let wanted = length as usize;
    let available = wanted.min(bits.data.len() - bits.at);
    let room = limit - output.len().min(limit);
    let taken = available.min(room);
    output.extend_from_slice(&bits.data[bits.at..bits.at + taken]);
    bits.at += taken;

    if taken < available {
        Err(Stop::Limit)
    } else if available < wanted {
        Err(Stop::Truncated)
    } else {
        Ok(())
    }
}

/// Reads the code lengths a dynamic block sends, which are themselves Huffman coded, and
/// builds the two tables they describe.
fn dynamic_tables(bits: &mut Bits) -> Result<(Code, Code), Stop> {
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];

    let literal_count = bits.take(5)? as usize + 257;
    let distance_count = bits.take(5)? as usize + 1;
    let length_count = bits.take(4)? as usize + 4;

    let mut lengths = [0u8; 19];
    for &slot in &ORDER[..length_count] {
        lengths[slot] = bits.take(3)? as u8;
    }
    let meta = Code::build(&lengths).ok_or(Stop::Invalid("a table of code lengths that cannot be"))?;

    let total = literal_count + distance_count;
    let mut lengths = vec![0u8; total];
    let mut at = 0usize;
    while at < total {
        let symbol = meta.decode(bits)?;
        let (value, repeat) = match symbol {
            0..=15 => {
                lengths[at] = symbol as u8;
                at += 1;
                continue;
            }
            16 => {
                let previous = at
                    .checked_sub(1)
                    .map(|p| lengths[p])
                    .ok_or(Stop::Invalid("a repeat with nothing before it to repeat"))?;
                (previous, 3 + bits.take(2)? as usize)
            }
            17 => (0, 3 + bits.take(3)? as usize),
            _ => (0, 11 + bits.take(7)? as usize),
        };
        if at + repeat > total {
            return Err(Stop::Invalid("a repeat running past the end of the table"));
        }
        lengths[at..at + repeat].fill(value);
        at += repeat;
    }

    let literals = Code::build(&lengths[..literal_count])
        .ok_or(Stop::Invalid("a literal table with too many codes"))?;
    let distances = Code::build(&lengths[literal_count..])
        .ok_or(Stop::Invalid("a distance table with too many codes"))?;
    Ok((literals, distances))
}

fn fixed_tables() -> (Code, Code) {
    let mut lengths = [8u8; 288];
    lengths[144..256].fill(9);
    lengths[256..280].fill(7);

    // Both tables are complete, so neither can be refused.
    let literals = Code::build(&lengths).expect("the fixed literal table is valid");
    let distances = Code::build(&[5u8; 30]).expect("the fixed distance table is valid");
    (literals, distances)
}

/// Reads blocks until the last one ends.
fn blocks(bits: &mut Bits, output: &mut Vec<u8>, limit: usize) -> Result<(), Stop> {
    let mut fixed = None;
    let mut dynamic_left = MAX_DYNAMIC_BLOCKS;

    loop {
        let last = bits.take(1)? == 1;
        match bits.take(2)? {
            0 => stored(bits, output, limit)?,
            1 => {
                let (literals, distances) = fixed.get_or_insert_with(fixed_tables);
                codes(bits, output, limit, literals, distances)?;
            }
            2 => {
                dynamic_left = dynamic_left
                    .checked_sub(1)
                    .ok_or(Stop::Invalid("more blocks than any compressor writes"))?;
                let (literals, distances) = dynamic_tables(bits)?;
                codes(bits, output, limit, &literals, &distances)?;
            }
            _ => return Err(Stop::Invalid("a block of a kind that does not exist")),
        }
        if last {
            return Ok(());
        }
    }
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    // The most bytes that cannot overflow 32 bits between reductions.
    for run in data.chunks(5552) {
        for &byte in run {
            a += byte as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    b << 16 | a
}

/// Inflates as much as can be read, up to `limit` bytes of output.
pub fn inflate(data: &[u8], wrapper: Wrapper, limit: usize) -> Inflated {
    let mut found = Inflated::default();
    let mut body = data;
    let mut complaint = None;

    if wrapper == Wrapper::Zlib {
        let &[cmf, flg, ..] = data else {
            found.error = Some("the stream ends before its zlib header does".to_string());
            return found;
        };
        if cmf & 0x0f != 8 {
            found.error = Some("the zlib header names a compression method that is not deflate".to_string());
            return found;
        }
        if flg & 0x20 != 0 {
            found.error = Some("the stream needs a preset dictionary, which it does not carry".to_string());
            return found;
        }
        // Read anyway. A doctored header stops a viewer and leaves the data where it was.
        if !(cmf as u32 * 256 + flg as u32).is_multiple_of(31) {
            complaint = Some("the zlib header fails its own check".to_string());
        }
        body = &data[2..];
    }

    found.output = Vec::with_capacity(limit.min(body.len().saturating_mul(3)).min(1 << 24));
    let mut bits = Bits::new(body);

    let result = blocks(&mut bits, &mut found.output, limit);
    match result {
        Ok(()) => {
            bits.align();
            let mut rest = &body[bits.at..];

            if wrapper == Wrapper::Zlib {
                match rest.first_chunk::<4>() {
                    Some(stored) => {
                        let stored = u32::from_be_bytes(*stored);
                        let actual = adler32(&found.output);
                        if stored != actual {
                            complaint = Some(format!(
                                "the Adler-32 checksum is wrong: the stream says {stored:08x}, the data gives {actual:08x}"
                            ));
                        }
                        rest = &rest[4..];
                    }
                    None => {
                        complaint = Some("the stream ends before its Adler-32 checksum".to_string());
                        rest = &[];
                    }
                }
            }
            found.trailing = rest.len();
        }
        Err(Stop::Limit) => found.capped = true,
        Err(Stop::Truncated) => {
            complaint = Some("the stream is cut short".to_string());
        }
        Err(Stop::Invalid(why)) => complaint = Some(format!("the stream is damaged: {why}")),
    }

    found.error = complaint;
    found
}

/// A packed result: a u32 length, that many bytes of JSON, then the output.
///
/// Laid out over the output's own buffer rather than beside it, since at the sizes a
/// bitmap reaches a second copy is most of what the call would cost.
pub fn packed(found: Inflated) -> Vec<u8> {
    let mut meta = String::from("{");
    match &found.error {
        Some(error) => push_field(&mut meta, "error", error),
        None => {
            push_string(&mut meta, "error");
            meta.push_str(":null");
        }
    }
    meta.push(',');
    push_bool(&mut meta, "capped", found.capped);
    meta.push(',');
    push_number(&mut meta, "trailing", found.trailing);
    meta.push('}');

    let mut out = found.output;
    let head = 4 + meta.len();
    let length = out.len();
    out.resize(length + head, 0);
    out.copy_within(0..length, head);
    out[..4].copy_from_slice(&(meta.len() as u32).to_le_bytes());
    out[4..head].copy_from_slice(meta.as_bytes());
    out
}

#[cfg(test)]
mod tests;
