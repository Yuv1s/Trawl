//! Payloads hidden in the choice between identical palette entries.
//!
//! An indexed image paints each pixel by number rather than by colour. If the
//! palette holds the same colour twice, a pixel using either index looks exactly
//! the same, so the choice is free and carries a bit. The picture is untouched,
//! nothing statistical fires, and a viewer shows no difference at all.
//!
//! The palette panel already reports that the opportunity exists. This reads it.
//!
//! Two entries carry one bit each, four carry two, and so on. Anything that is
//! not a power of two is rounded down, because an encoder cannot use a fraction
//! of a bit and guessing at the leftovers would put noise into the stream.

use crate::bytes;

use super::assess;

/// A set of palette entries painting the same colour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Palette indices sharing this colour, in ascending order.
    pub indices: Vec<u8>,
    pub colour: [u8; 3],
    /// Bits a pixel using this colour can carry.
    pub bits: u32,
}

/// Groups palette entries by colour, keeping only those a payload could use.
///
/// @param palette RGB triples, as PLTE stores them
pub fn groups(palette: &[u8]) -> Vec<Group> {
    let entries = palette.len() / 3;
    let mut seen: Vec<Group> = Vec::new();

    for i in 0..entries {
        let colour = [palette[i * 3], palette[i * 3 + 1], palette[i * 3 + 2]];

        match seen.iter_mut().find(|g| g.colour == colour) {
            Some(group) => group.indices.push(i as u8),
            None => seen.push(Group {
                indices: vec![i as u8],
                colour,
                bits: 0,
            }),
        }
    }

    seen.retain(|g| g.indices.len() > 1);

    for group in &mut seen {
        // Round down to a whole power of two. Three copies carry one reliable
        // bit, not one and a half.
        group.bits = (usize::BITS - group.indices.len().leading_zeros()) - 1;
    }

    seen
}

/// Total bits the duplicate entries carry across this image.
pub fn capacity(palette: &[u8], indices: &[u8]) -> usize {
    let found = groups(palette);

    indices
        .iter()
        .filter_map(|&i| {
            found
                .iter()
                .find(|g| g.indices.contains(&i))
                .map(|g| g.bits as usize)
        })
        .sum()
}

/// Reads the payload out of the index choices.
///
/// @param msb_first pack the recovered bits high end first
pub fn extract(palette: &[u8], indices: &[u8], msb_first: bool, max_bytes: usize) -> Vec<u8> {
    let found = groups(palette);
    if found.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut byte = 0u8;
    let mut filled = 0u8;

    for &index in indices {
        let Some(group) = found.iter().find(|g| g.indices.contains(&index)) else {
            continue;
        };
        if group.bits == 0 {
            continue;
        }

        // Which copy this pixel chose, which is the value the encoder wrote.
        let choice = group.indices.iter().position(|&i| i == index).unwrap() as u32;

        for shift in (0..group.bits).rev() {
            let bit = ((choice >> shift) & 1) as u8;

            byte = if msb_first {
                (byte << 1) | bit
            } else {
                byte | (bit << filled)
            };
            filled += 1;

            if filled == 8 {
                out.push(byte);
                byte = 0;
                filled = 0;

                if out.len() >= max_bytes {
                    return out;
                }
            }
        }
    }

    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub msb_first: bool,
    pub reason: String,
    pub preview: String,
    pub readable: usize,
    pub flags: Vec<String>,
    pub bytes_read: usize,
}

/// Both bit orders. There is no channel or bit-plane choice here: the palette
/// decides how many bits each pixel carries, so the only free parameter is how
/// they were packed.
pub const COMBINATIONS: usize = 2;

pub fn sweep(palette: &[u8], indices: &[u8], max_bytes: usize) -> Vec<Candidate> {
    let mut out = Vec::new();

    for msb_first in [true, false] {
        let stream = extract(palette, indices, msb_first, max_bytes);
        if stream.is_empty() {
            continue;
        }

        let flags: Vec<String> = bytes::flag_candidates(&stream)
            .into_iter()
            .map(|f| f.text)
            .collect();

        let assessed = assess(&stream);
        if flags.is_empty() && assessed.is_none() {
            continue;
        }

        let (reason, preview, readable) = assessed.unwrap_or_else(|| {
            let joined = flags.join("  ");
            let shown = joined.chars().count();
            (
                "flag-shaped string in the extracted stream".to_string(),
                joined,
                shown,
            )
        });

        out.push(Candidate {
            msb_first,
            reason,
            preview,
            readable,
            flags,
            bytes_read: stream.len(),
        });
    }

    out
}

pub fn json(palette: &[u8], indices: &[u8], max_bytes: usize) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    let found = groups(palette);
    let mut out = String::from("{");

    push_number(&mut out, "combinations", COMBINATIONS);
    out.push(',');
    push_number(&mut out, "capacityBits", capacity(palette, indices));
    out.push(',');
    push_string(&mut out, "groups");
    out.push_str(":[");
    for (i, group) in found.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(
            &mut out,
            "colour",
            &format!(
                "#{:02x}{:02x}{:02x}",
                group.colour[0], group.colour[1], group.colour[2]
            ),
        );
        out.push(',');
        push_number(&mut out, "copies", group.indices.len());
        out.push(',');
        push_number(&mut out, "bits", group.bits as usize);
        out.push('}');
    }
    out.push_str("],");

    push_string(&mut out, "candidates");
    out.push_str(":[");
    for (i, candidate) in sweep(palette, indices, max_bytes).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_bool(&mut out, "msbFirst", candidate.msb_first);
        out.push(',');
        push_field(&mut out, "reason", &candidate.reason);
        out.push(',');
        push_field(&mut out, "preview", &candidate.preview);
        out.push(',');
        push_number(&mut out, "readable", candidate.readable);
        out.push(',');
        push_number(&mut out, "bytesRead", candidate.bytes_read);
        out.push(',');
        push_string(&mut out, "flags");
        out.push_str(":[");
        for (j, flag) in candidate.flags.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            push_string(&mut out, flag);
        }
        out.push_str("]}");
    }
    out.push_str("]}");

    out
}

#[cfg(test)]
mod tests;
