//! Packet captures, read for what crossed the wire, and for the one thing a raw
//! byte scan of the file cannot see: a flag split across TCP segments.
//!
//! A capture is a list of frames, each a copy of what a network card saw. A flag
//! sitting whole inside one packet is already found by [`crate::survey`], so that
//! is not why this exists. It exists for the flag that does not sit whole in any
//! packet. TCP breaks a stream into segments, and between two segments' payloads
//! sit the headers of the packets that carried them, so a message spanning a
//! segment boundary is interrupted by bytes that are not part of it. A scan of
//! the file walks straight past it. Reassembly, following each connection's
//! sequence numbers and laying the payloads back down in order, is the only way
//! the message becomes readable again. That reassembly is the same recovery
//! [`crate::sqlite`] does for a deleted row and [`crate::pdf`] does for a
//! compressed stream: the bytes were always in the file, arranged so nothing
//! that reads it plainly would find them.
//!
//! Two container formats hold the frames: classic libpcap, a global header then
//! fixed-size records, and pcapng, a chain of typed blocks. Both are parsed here.
//! Inside each frame the link, network and transport layers are peeled to reach
//! the payload, and the connections are put back together.

use crate::bytes;
use std::collections::{HashMap, HashSet};

/// Ceilings on what one reading carries, so a large capture cannot ask the
/// browser to hold all of it. The true counts are reported alongside the capped
/// lists.
const MAX_PACKETS: usize = 500_000;
const MAX_STREAMS: usize = 48;
const MAX_STREAM_BYTES: usize = 256 * 1024;
/// Bytes laid out for showing a stream, across every stream. A two-packet connection can
/// claim a whole stream's worth of gap between its segments, so a capture of many such
/// connections would otherwise ask for far more than it holds.
const MAX_REASSEMBLED: usize = 64 << 20;
/// What a stream gets to show however little of that is left, so the biggest flows cannot
/// use it all up. Searching a stream for flags costs what it carries and takes none of it.
const FLOW_ALLOWANCE: usize = 16 * 1024;
const MAX_CONVERSATIONS: usize = 40;
const MAX_DNS: usize = 120;
const PREVIEW_BYTES: usize = 4096;
/// Streams carrying a flag or a file, which are not held to [`MAX_STREAMS`], since those
/// are the ones a person came for. They get a shorter preview past it.
const MAX_FINDING_STREAMS: usize = 1024;
const SHORT_PREVIEW_BYTES: usize = 256;
/// Bytes either side of a disagreeing segment searched for a flag it completes. A body
/// runs to 256 bytes, and a tag somebody named a little past that.
const OVERLAY_MARGIN: usize = 512;
/// Disagreeing segments read against their surroundings, across the whole capture.
const MAX_OVERLAYS: usize = 1 << 16;

#[derive(Debug, Clone, PartialEq)]
pub struct Protocol {
    /// The highest layer named: an application by well-known port where one is
    /// obvious, otherwise the transport.
    pub name: String,
    pub packets: usize,
    pub bytes: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Conversation {
    pub a: String,
    pub b: String,
    pub protocol: String,
    pub packets: usize,
    pub bytes: usize,
}

/// One direction of a TCP connection, reassembled from its segments.
#[derive(Debug, Clone, PartialEq)]
pub struct Stream {
    pub src: String,
    pub dst: String,
    pub bytes: usize,
    /// Payload bytes the direction carried, counting a retransmission once, of which
    /// `bytes` is the window laid out. All of them were searched for flags.
    pub carried: usize,
    /// Bytes two segments of this stream gave different values for. A retransmission
    /// repeats itself, so this is a capture telling two stories about one stream, and
    /// `flags` holds what each reading of it said.
    pub conflicting: usize,
    /// A printable rendering of the reassembled bytes, control characters shown
    /// as dots, capped for display.
    pub text: String,
    /// How much of the stream is printable, to tell a transcript from a file.
    pub printable: f32,
    /// A file signature at the very start of the stream, when the connection
    /// carried a whole file rather than a conversation. The raw scan cannot see
    /// it because the file's magic sits mid-packet, after a header.
    pub embedded_file: Option<&'static str>,
    /// Flag shapes found in the reassembled bytes: the payoff, and invisible to
    /// any scan of the file as it sits on disk.
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Capture {
    /// "pcap" or "pcapng".
    pub format: &'static str,
    pub link_type: String,
    pub packet_count: usize,
    /// Sum of the original on-the-wire lengths, which exceeds the file when the
    /// capture was snapped short.
    pub capture_bytes: usize,
    /// True when any frame was captured with fewer bytes than it carried.
    pub truncated: bool,
    /// The span first frame to last, worded, or empty when the timestamps say
    /// nothing.
    pub duration: String,
    pub protocols: Vec<Protocol>,
    pub conversations: Vec<Conversation>,
    /// True number of conversations, which `conversations` is a capped copy of.
    pub conversation_count: usize,
    pub streams: Vec<Stream>,
    /// True number of reassembled streams that carried payload.
    pub stream_count: usize,
    pub dns: Vec<DnsQuery>,
    /// True when the reader stopped at [`MAX_PACKETS`] with more of the file to go.
    pub packets_capped: bool,
    /// True when the streams held more flags than are reported.
    pub flags_truncated: bool,
}

// Big-endian network-order readers, for the protocol fields inside a frame.
fn be16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn be32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

// Container fields carry the capture writer's own byte order.
fn u16_at(data: &[u8], at: usize, le: bool) -> Option<u16> {
    let raw: [u8; 2] = data.get(at..at + 2)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    })
}

fn u32_at(data: &[u8], at: usize, le: bool) -> Option<u32> {
    let raw: [u8; 4] = data.get(at..at + 4)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

/// A frame located in the file: which interface's link type it uses, where its
/// bytes are, and when it was captured.
struct Frame {
    link_type: u16,
    offset: usize,
    len: usize,
    timestamp: f64,
}

/// The name a link type goes by, for the header line.
fn link_name(link_type: u16) -> &'static str {
    match link_type {
        0 => "BSD loopback",
        1 => "Ethernet",
        101 => "raw IP",
        113 => "Linux cooked",
        127 => "802.11 radiotap",
        276 => "Linux cooked v2",
        _ => "other",
    }
}

/// Reads the frames out of a classic libpcap file: a 24-byte global header, then
/// records of a 16-byte header and that many captured bytes.
fn parse_pcap(data: &[u8]) -> Option<(Vec<Frame>, u16, usize, bool, bool)> {
    let magic = data.get(0..4)?;
    let (le, nanos) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return None,
    };

    let link_type = u32_at(data, 20, le)? as u16;

    let mut frames = Vec::new();
    let mut capture_bytes = 0usize;
    let mut truncated = false;
    let mut at = 24;

    while at + 16 <= data.len() && frames.len() < MAX_PACKETS {
        let ts_sec = u32_at(data, at, le)? as f64;
        let ts_frac = u32_at(data, at + 4, le)? as f64;
        let incl = u32_at(data, at + 8, le)? as usize;
        let orig = u32_at(data, at + 12, le)? as usize;
        let body = at + 16;

        // A record claiming more than the file holds is a corrupt or partial
        // capture; stop rather than reading into whatever follows.
        if incl > data.len() - body {
            break;
        }

        capture_bytes = capture_bytes.saturating_add(orig);
        truncated |= orig > incl;
        frames.push(Frame {
            link_type,
            offset: body,
            len: incl,
            timestamp: ts_sec + ts_frac / if nanos { 1e9 } else { 1e6 },
        });
        at = body + incl;
    }

    let capped = frames.len() >= MAX_PACKETS && at + 16 <= data.len();
    Some((frames, link_type, capture_bytes, truncated, capped))
}

/// How many timestamp ticks an interface counts per second.
///
/// The `if_tsresol` option says, in one byte: a power of ten when the top bit is
/// clear, a power of two when it is set. Microseconds when it is absent, which is
/// the format's default and the wrong answer for the nanosecond captures tcpdump
/// and Wireshark often write, where a second would read as a quarter of an hour.
fn ticks_per_second(data: &[u8], options: usize, end: usize, le: bool) -> f64 {
    const END_OF_OPTIONS: u16 = 0;
    const IF_TSRESOL: u16 = 9;

    let mut at = options;
    while at + 4 <= end {
        let (Some(code), Some(length)) = (u16_at(data, at, le), u16_at(data, at + 2, le)) else {
            break;
        };
        if code == END_OF_OPTIONS {
            break;
        }
        if code == IF_TSRESOL
            && length == 1
            && let Some(&raw) = data.get(at + 4)
        {
            let exponent = (raw & 0x7f) as i32;
            return if raw & 0x80 != 0 {
                2f64.powi(exponent)
            } else {
                10f64.powi(exponent)
            };
        }
        // Option values are padded to a four-byte boundary.
        at += 4 + (length as usize).next_multiple_of(4);
    }

    1e6
}

/// The frame an Enhanced Packet Block holds, and its original length, or nothing
/// when the block is too short to hold what it claims.
fn enhanced_packet(
    data: &[u8],
    body: usize,
    block_end: usize,
    le: bool,
    interfaces: &[(u16, f64)],
) -> Option<(Frame, usize)> {
    let interface = u32_at(data, body, le)? as usize;
    let ts_high = u32_at(data, body + 4, le)? as u64;
    let ts_low = u32_at(data, body + 8, le)? as u64;
    let incl = u32_at(data, body + 12, le)? as usize;
    let orig = u32_at(data, body + 16, le)? as usize;
    let frame_at = body + 20;
    if frame_at.checked_add(incl)? > block_end {
        return None;
    }

    let (link_type, ticks) = interfaces.get(interface).copied().unwrap_or((1, 1e6));
    let frame = Frame {
        link_type,
        offset: frame_at,
        len: incl,
        timestamp: ((ts_high << 32) | ts_low) as f64 / ticks,
    };
    Some((frame, orig))
}

/// Reads the frames out of a pcapng file: a chain of typed blocks, each a type,
/// a total length, a body, and the total length again. Only the interface and
/// packet blocks carry frames; the rest are skipped by their length.
fn parse_pcapng(data: &[u8]) -> Option<(Vec<Frame>, u16, usize, bool, bool)> {
    if data.get(0..4)? != [0x0a, 0x0d, 0x0d, 0x0a] {
        return None;
    }
    // The Section Header Block's byte-order magic settles the whole section's
    // endianness. A value that reads neither way round is not this format.
    let le = match u32_at(data, 8, true)? {
        0x1a2b_3c4d => true,
        0x4d3c_2b1a => false,
        _ => return None,
    };

    let mut frames = Vec::new();
    let mut interfaces: Vec<(u16, f64)> = Vec::new();
    let mut capture_bytes = 0usize;
    let mut truncated = false;
    let mut at = 0usize;

    while at + 12 <= data.len() && frames.len() < MAX_PACKETS {
        let Some(block_type) = u32_at(data, at, le) else { break };
        let Some(total) = u32_at(data, at + 4, le) else { break };
        let total = total as usize;
        // Every block is at least the two lengths plus a type, and padded to a
        // four-byte boundary. Anything else is a desync; stop. The sum wraps in
        // WASM, and a wrapped end sends the walk back round the same blocks forever.
        let Some(next) = at.checked_add(total).filter(|&next| next <= data.len()) else {
            break;
        };
        if total < 12 || !total.is_multiple_of(4) {
            break;
        }
        let body = at + 8;
        // The total length is repeated in the block's last four bytes.
        let block_end = next - 4;

        match block_type {
            // Interface Description Block: link type, a reserved field, a snap
            // length, then options.
            0x0000_0001 => {
                if let Some(link_type) = u16_at(data, body, le) {
                    interfaces.push((link_type, ticks_per_second(data, body + 8, block_end, le)));
                }
            }
            // Enhanced Packet Block: interface id, timestamp, captured len,
            // original len, then the frame.
            0x0000_0006 => {
                if let Some((frame, orig)) = enhanced_packet(data, body, block_end, le, &interfaces) {
                    capture_bytes = capture_bytes.saturating_add(orig);
                    truncated |= orig > frame.len;
                    frames.push(frame);
                }
            }
            // Simple Packet Block: an original length, then the frame filling the
            // rest of the block.
            0x0000_0003 => {
                let Some(orig) = u32_at(data, body, le) else { break };
                let orig = orig as usize;
                let frame_at = body + 4;
                // Block bytes minus type, both lengths and the original-length
                // field give what was captured.
                let incl = total.saturating_sub(16).min(orig);
                if frame_at + incl <= block_end {
                    capture_bytes = capture_bytes.saturating_add(orig);
                    truncated |= orig > incl;
                    frames.push(Frame {
                        link_type: interfaces.first().map_or(1, |&(link_type, _)| link_type),
                        offset: frame_at,
                        len: incl,
                        timestamp: 0.0,
                    });
                }
            }
            _ => {}
        }

        at = next;
    }

    let link_type = interfaces.first().map_or(1, |&(link_type, _)| link_type);
    let capped = frames.len() >= MAX_PACKETS && at + 12 <= data.len();
    Some((frames, link_type, capture_bytes, truncated, capped))
}

/// What one frame decoded to: its endpoints, the highest layer named, and where
/// its transport payload sits in the file.
struct Decoded {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    /// "TCP", "UDP", "ICMP", "ICMPv6", "ARP" or "other".
    transport: &'static str,
    payload_at: usize,
    payload_len: usize,
    /// Present only for TCP: the sequence number of the first payload byte.
    seq: Option<u32>,
}

fn ipv4(bytes: &[u8], at: usize) -> String {
    format!(
        "{}.{}.{}.{}",
        bytes.get(at).copied().unwrap_or(0),
        bytes.get(at + 1).copied().unwrap_or(0),
        bytes.get(at + 2).copied().unwrap_or(0),
        bytes.get(at + 3).copied().unwrap_or(0)
    )
}

/// IPv6 in the usual colon form, with the longest run of zero groups collapsed
/// to `::`.
fn ipv6(bytes: &[u8], at: usize) -> String {
    let Some(raw) = bytes.get(at..at + 16) else {
        return "::".into();
    };
    let groups: [u16; 8] =
        std::array::from_fn(|i| u16::from_be_bytes([raw[i * 2], raw[i * 2 + 1]]));

    // The longest zero run, which is the one `::` is allowed to replace.
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let (mut run_start, mut run_len) = (0usize, 0usize);
    for (i, &g) in groups.iter().enumerate() {
        if g == 0 {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
            if run_len > best_len {
                best_len = run_len;
                best_start = run_start;
            }
        } else {
            run_len = 0;
        }
    }

    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if best_len > 1 && i == best_start {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", groups[i]));
        i += 1;
    }
    if out.is_empty() { "::".into() } else { out }
}

/// The transport header sitting on top of an IP payload, given the protocol
/// number and where layer four begins.
fn transport(frame: &[u8], proto: u8, l4: usize) -> (&'static str, u16, u16, usize, Option<u32>) {
    match proto {
        6 => {
            // TCP: ports, a sequence number, then a data offset that says where
            // the payload begins.
            let sport = be16(frame, l4).unwrap_or(0);
            let dport = be16(frame, l4 + 2).unwrap_or(0);
            let seq = be32(frame, l4 + 4);
            let data_off = frame
                .get(l4 + 12)
                .map(|b| (b >> 4) as usize * 4)
                .unwrap_or(20);
            ("TCP", sport, dport, l4 + data_off.max(20), seq)
        }
        17 => {
            let sport = be16(frame, l4).unwrap_or(0);
            let dport = be16(frame, l4 + 2).unwrap_or(0);
            ("UDP", sport, dport, l4 + 8, None)
        }
        1 => ("ICMP", 0, 0, l4, None),
        58 => ("ICMPv6", 0, 0, l4, None),
        _ => ("other", 0, 0, l4, None),
    }
}

/// Peels one frame's link, network and transport layers to its payload.
fn decode(file: &[u8], frame: &Frame) -> Option<Decoded> {
    let bytes = file.get(frame.offset..frame.offset + frame.len)?;

    // Reach the network layer past whatever link layer wraps it.
    let (l3, ethertype) = match frame.link_type {
        1 => {
            // Ethernet II: two addresses then a type, with one optional VLAN tag.
            let mut kind = be16(bytes, 12)?;
            let mut l3 = 14;
            if matches!(kind, 0x8100 | 0x88a8) {
                kind = be16(bytes, 16)?;
                l3 = 18;
            }
            (l3, kind)
        }
        // BSD loopback: a four-byte address family, 2 for IPv4.
        0 => (
            4,
            if bytes.first().copied().unwrap_or(0) == 2 {
                0x0800
            } else {
                0x86dd
            },
        ),
        // Raw IP: the version nibble of the first byte decides.
        101 => (
            0,
            if bytes.first().map(|b| b >> 4) == Some(6) {
                0x86dd
            } else {
                0x0800
            },
        ),
        // Linux cooked capture: a 16-byte header ending in the ethertype.
        113 => (16, be16(bytes, 14)?),
        276 => (20, be16(bytes, 0)?),
        _ => return None,
    };

    match ethertype {
        0x0806 => Some(Decoded {
            src_ip: String::new(),
            dst_ip: String::new(),
            src_port: 0,
            dst_port: 0,
            transport: "ARP",
            payload_at: 0,
            payload_len: 0,
            seq: None,
        }),
        0x0800 => {
            let ihl = (bytes.get(l3)? & 0x0f) as usize * 4;
            if ihl < 20 {
                return None;
            }
            let proto = *bytes.get(l3 + 9)?;
            let src = ipv4(bytes, l3 + 12);
            let dst = ipv4(bytes, l3 + 16);
            let (t, sp, dp, pay, seq) = transport(bytes, proto, l3 + ihl);
            let end = packet_end(bytes.len(), l3, be16(bytes, l3 + 2));
            Some(Decoded {
                src_ip: src,
                dst_ip: dst,
                src_port: sp,
                dst_port: dp,
                transport: t,
                payload_at: frame.offset + pay,
                payload_len: end.saturating_sub(pay),
                seq,
            })
        }
        0x86dd => {
            let proto = *bytes.get(l3 + 6)?;
            let src = ipv6(bytes, l3 + 8);
            let dst = ipv6(bytes, l3 + 24);
            let (t, sp, dp, pay, seq) = transport(bytes, proto, l3 + 40);
            // IPv6 counts its payload alone, leaving out the fixed header.
            let end = packet_end(bytes.len(), l3 + 40, be16(bytes, l3 + 4));
            Some(Decoded {
                src_ip: src,
                dst_ip: dst,
                src_port: sp,
                dst_port: dp,
                transport: t,
                payload_at: frame.offset + pay,
                payload_len: end.saturating_sub(pay),
                seq,
            })
        }
        _ => None,
    }
}

/// Where a packet stops inside its frame, by its own length field.
///
/// Ethernet pads a short frame to sixty bytes, so whatever follows the packet is not
/// part of it. Read as payload, the padding on a keep-alive becomes data, and since a
/// keep-alive deliberately carries a sequence number one behind, that data lands on
/// the end of what came before. A length of zero is what a capture shows when the
/// card was left to fill it in, and says nothing.
fn packet_end(frame_len: usize, from: usize, declared: Option<u16>) -> usize {
    match declared {
        Some(length) if length != 0 => from.saturating_add(length as usize).min(frame_len),
        _ => frame_len,
    }
}

/// The application a well-known port belongs to, for the protocol breakdown.
fn app_name(sport: u16, dport: u16) -> Option<&'static str> {
    let named = |p: u16| -> Option<&'static str> {
        Some(match p {
            20 | 21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 | 587 => "SMTP",
            53 => "DNS",
            67 | 68 => "DHCP",
            69 => "TFTP",
            80 | 8080 | 8000 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 | 8443 => "TLS",
            445 => "SMB",
            1883 => "MQTT",
            3306 => "MySQL",
            3389 => "RDP",
            5432 => "PostgreSQL",
            6379 => "Redis",
            _ => return None,
        })
    };
    // The lower port is the server's, which is the one that names the protocol.
    named(sport.min(dport)).or_else(|| named(sport.max(dport)))
}

fn endpoint(ip: &str, port: u16) -> String {
    if port == 0 {
        ip.to_string()
    } else if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

/// One directional TCP flow's segments, before reassembly.
#[derive(Default)]
struct Segments {
    parts: Vec<(u32, usize, usize)>,
}

/// Renders reassembled bytes to a short printable preview, control characters
/// shown as dots so a binary payload reads as a shape rather than filling the
/// pane with noise.
fn preview(data: &[u8], length: usize) -> String {
    data.iter()
        .take(length)
        .map(|&b| match b {
            b'\n' | b'\t' => b as char,
            0x20..=0x7e => b as char,
            _ => '.',
        })
        .collect()
}

fn printable_fraction(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let readable = data
        .iter()
        .filter(|&&b| (0x20..0x7f).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'))
        .count();
    readable as f32 / data.len() as f32
}

/// One stretch of a direction with no hole in it, by distance from the first segment seen.
struct Run {
    start: i64,
    end: i64,
    /// Indices into the segments, in the order they arrived.
    parts: Vec<usize>,
}

/// A direction's segments, sorted out into the runs they join up into.
///
/// Sequence numbers are modular, so "lowest" is only meaningful as a signed distance:
/// a stream that crosses zero has its start at 0xfffffff8 and its end at 16, and the
/// plain minimum would call the end the start and drop everything before it. So each
/// is measured from the first segment seen, either way round.
fn runs(segments: &Segments) -> Vec<Run> {
    let Some(&(first, _, _)) = segments.parts.first() else {
        return Vec::new();
    };

    let mut spans: Vec<(i64, i64, usize)> = segments
        .parts
        .iter()
        .enumerate()
        .map(|(index, &(seq, _, len))| {
            let start = seq.wrapping_sub(first) as i32 as i64;
            (start, start + len as i64, index)
        })
        .collect();
    spans.sort_unstable();

    let mut out: Vec<Run> = Vec::new();
    for (start, end, index) in spans {
        match out.last_mut() {
            Some(run) if start <= run.end => {
                run.end = run.end.max(end);
                run.parts.push(index);
            }
            _ => out.push(Run {
                start,
                end,
                parts: vec![index],
            }),
        }
    }
    for run in &mut out {
        run.parts.sort_unstable();
    }
    out
}

/// Where a window of `limit` bytes should start.
///
/// On the longest run, which is the conversation: anything a single stray segment says
/// about where a stream starts is one byte's word against all of the rest. Earlier runs
/// come in with it when they fit, so a stream with one lost packet reads as one stream.
fn window_start(runs: &[Run], limit: usize) -> Option<i64> {
    let anchor = runs
        .iter()
        .enumerate()
        .max_by_key(|&(index, run)| (run.end - run.start, std::cmp::Reverse(index)))
        .map(|(_, run)| run)?;

    let earliest = runs
        .iter()
        .find(|run| anchor.end - run.start <= limit as i64)
        .map_or(anchor.start, |run| run.start.min(anchor.start));
    Some(earliest)
}

/// Lays one direction's segments back down in sequence order, in a window around its
/// longest run.
///
/// Every segment is placed at its distance from the start of the window, so an
/// out-of-order segment lands where it belongs. The first copy of a byte is the one
/// shown: a retransmission carries the same bytes anyway, and a keep-alive probe carries
/// one junk byte a position behind the data it follows, which must not overwrite it.
/// Anything outside the window is dropped from this, and not from the search for flags.
fn reassemble(file: &[u8], segments: &Segments, limit: usize) -> Vec<u8> {
    let Some(base) = window_start(&runs(segments), limit) else {
        return Vec::new();
    };
    let Some(&(first, _, _)) = segments.parts.first() else {
        return Vec::new();
    };

    let mut buf: Vec<u8> = Vec::new();
    let mut written: Vec<bool> = Vec::new();
    for &(seq, at, len) in &segments.parts {
        let start = seq.wrapping_sub(first) as i32 as i64 - base;
        let Ok(offset) = usize::try_from(start) else {
            continue;
        };
        if offset >= limit {
            continue;
        }
        let take = len.min(limit - offset);
        let Some(bytes) = file.get(at..at + take) else {
            continue;
        };
        if offset + take > buf.len() {
            buf.resize(offset + take, 0);
            written.resize(offset + take, false);
        }
        for (i, &byte) in bytes.iter().enumerate() {
            if !written[offset + i] {
                buf[offset + i] = byte;
                written[offset + i] = true;
            }
        }
    }
    buf
}

/// What a search of one direction for flags turned up, across every run it has.
struct FlowFlags {
    flags: Vec<String>,
    truncated: bool,
    /// Bytes of payload, counting each position once.
    carried: usize,
    /// Bytes two segments gave different values for.
    conflicting: usize,
}

/// Searches every run of a direction for flags, each reading of it where segments disagree.
///
/// Nothing in TCP says which of two copies of a byte is the true one. A stack keeps the
/// first and a capture tool can be made to show either, so an author who wants a flag
/// missed sends a forged copy first and lets the real one lose. Where copies disagree the
/// first of each byte is read, then the last, then each disagreeing segment laid over the
/// first reading in turn, so a flag sitting in the middle of three copies is found too.
/// Every reading's flags are reported, and which is the answer is the person's call.
fn search_flow(
    file: &[u8],
    segments: &Segments,
    tags: &[String],
    flags_left: &mut usize,
    overlays_left: &mut usize,
) -> FlowFlags {
    let first_seq = segments.parts.first().map_or(0, |part| part.0);
    let mut found = FlowFlags {
        flags: Vec::new(),
        truncated: false,
        carried: 0,
        conflicting: 0,
    };
    let mut seen: HashSet<String> = HashSet::new();

    let mut scan = |bytes: &[u8], found: &mut FlowFlags| {
        let scan = bytes::scan_flags(bytes, tags, true);
        found.truncated |= scan.truncated;
        for flag in scan.found {
            if seen.contains(&flag.text) {
                continue;
            }
            if *flags_left == 0 {
                found.truncated = true;
                continue;
            }
            *flags_left -= 1;
            seen.insert(flag.text.clone());
            found.flags.push(flag.text);
        }
    };

    for run in runs(segments) {
        let length = (run.end - run.start) as usize;
        found.carried += length;

        // Each position's first value, and any segment that went on to contradict it.
        let mut reading = vec![0u8; length];
        let mut written = vec![false; length];
        let mut disagreeing: Vec<(usize, usize)> = Vec::new();
        let mut high_water = 0usize;

        for &index in &run.parts {
            let (seq, at, len) = segments.parts[index];
            let offset = (seq.wrapping_sub(first_seq) as i32 as i64 - run.start) as usize;
            let Some(payload) = file.get(at..at + len) else {
                continue;
            };

            let mut differing = 0usize;
            for (i, &byte) in payload.iter().enumerate() {
                if !written[offset + i] {
                    reading[offset + i] = byte;
                    written[offset + i] = true;
                } else if reading[offset + i] != byte {
                    differing += 1;
                }
            }

            if differing > 0 {
                disagreeing.push((index, offset));
                // One byte, one place behind everything sent so far, is a keep-alive
                // probe, and some stacks put junk in them. That is no story of its own.
                if len > 1 || offset + 1 != high_water {
                    found.conflicting += differing;
                }
            }
            high_water = high_water.max(offset + len);
        }

        scan(&reading, &mut found);
        if disagreeing.is_empty() {
            continue;
        }

        // The other end of the argument: whichever copy of each byte came last.
        let mut last = reading.clone();
        for &index in &run.parts {
            let (seq, at, len) = segments.parts[index];
            let offset = (seq.wrapping_sub(first_seq) as i32 as i64 - run.start) as usize;
            if let Some(payload) = file.get(at..at + len) {
                last[offset..offset + len].copy_from_slice(payload);
            }
        }
        scan(&last, &mut found);

        for (index, offset) in disagreeing {
            if *overlays_left == 0 {
                break;
            }
            *overlays_left -= 1;

            let (_, at, len) = segments.parts[index];
            let Some(payload) = file.get(at..at + len) else {
                continue;
            };
            let from = offset.saturating_sub(OVERLAY_MARGIN);
            let to = (offset + len + OVERLAY_MARGIN).min(length);
            let mut window = reading[from..to].to_vec();
            window[offset - from..offset - from + len].copy_from_slice(payload);
            scan(&window, &mut found);
        }
    }

    found
}

/// Reads the query names out of a DNS message's question section. Compression
/// pointers, which questions rarely use, end the read rather than being chased.
fn dns_questions(payload: &[u8], out: &mut Vec<DnsQuery>) {
    let Some(qdcount) = be16(payload, 4) else {
        return;
    };
    let mut at = 12;
    for _ in 0..qdcount.min(16) {
        let mut labels = Vec::new();
        loop {
            let Some(&len) = payload.get(at) else {
                return;
            };
            if len == 0 {
                at += 1;
                break;
            }
            if len & 0xc0 != 0 {
                // A pointer, or a length this reader does not follow.
                return;
            }
            let from = at + 1;
            let Some(label) = payload.get(from..from + len as usize) else {
                return;
            };
            labels.push(String::from_utf8_lossy(label).into_owned());
            at = from + len as usize;
        }
        let name = labels.join(".");
        let kind = match be16(payload, at) {
            Some(1) => "A",
            Some(28) => "AAAA",
            Some(5) => "CNAME",
            Some(15) => "MX",
            Some(16) => "TXT",
            Some(255) => "ANY",
            _ => "?",
        };
        if !name.is_empty() && out.len() < MAX_DNS && !out.iter().any(|q| q.name == name) {
            out.push(DnsQuery {
                name,
                kind: kind.to_string(),
            });
        }
        at += 4;
    }
}

fn worded_duration(seconds: f64) -> String {
    if !seconds.is_finite() || seconds <= 0.0 {
        return String::new();
    }
    if seconds < 1.0 {
        format!("{:.0} ms", seconds * 1000.0)
    } else if seconds < 120.0 {
        format!("{seconds:.2} s")
    } else {
        format!("{:.1} min", seconds / 60.0)
    }
}

pub fn read(data: &[u8], tags: &[String]) -> Option<Capture> {
    let (frames, link_type, capture_bytes, truncated, packets_capped, format) =
        if let Some((f, lt, cb, tr, pc)) = parse_pcap(data) {
            (f, lt, cb, tr, pc, "pcap")
        } else if let Some((f, lt, cb, tr, pc)) = parse_pcapng(data) {
            (f, lt, cb, tr, pc, "pcapng")
        } else {
            return None;
        };

    let packet_count = frames.len();

    let mut protocols: HashMap<String, (usize, usize)> = HashMap::new();
    let mut conversations: HashMap<(String, String, &'static str), (usize, usize)> = HashMap::new();
    let mut tcp: HashMap<(String, u16, String, u16), Segments> = HashMap::new();
    let mut dns = Vec::new();

    // Timestamps that are all zero (a Simple Packet Block capture) say nothing.
    let first_ts = frames.first().map(|f| f.timestamp).unwrap_or(0.0);
    let mut last_ts = first_ts;

    for frame in &frames {
        last_ts = frame.timestamp;
        let Some(d) = decode(data, frame) else {
            let entry = protocols.entry("other".into()).or_default();
            entry.0 += 1;
            entry.1 += frame.len;
            continue;
        };

        let name = app_name(d.src_port, d.dst_port)
            .unwrap_or(d.transport)
            .to_string();
        let entry = protocols.entry(name.clone()).or_default();
        entry.0 += 1;
        entry.1 += frame.len;

        if d.transport == "ARP" {
            continue;
        }

        // A conversation is undirected: the same pair however the packets flow.
        let a = endpoint(&d.src_ip, d.src_port);
        let b = endpoint(&d.dst_ip, d.dst_port);
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        let conv = conversations.entry((a, b, d.transport)).or_default();
        conv.0 += 1;
        conv.1 += frame.len;

        if d.transport == "TCP"
            && d.payload_len > 0
            && let Some(seq) = d.seq
        {
            let key = (d.src_ip.clone(), d.src_port, d.dst_ip.clone(), d.dst_port);
            tcp.entry(key)
                .or_default()
                .parts
                .push((seq, d.payload_at, d.payload_len));
        }

        if name == "DNS"
            && d.transport == "UDP"
            && let Some(payload) = data.get(d.payload_at..d.payload_at + d.payload_len)
        {
            dns_questions(payload, &mut dns);
        }
    }

    // Every directional flow here carried payload, whether or not it gets read.
    let stream_count = tcp.len();

    // Biggest first, so the budget goes on the streams with the most in them, and in
    // a fixed order, so the same file reads the same way twice.
    let mut flows: Vec<_> = tcp
        .into_iter()
        .map(|(key, segments)| {
            let carried: usize = segments.parts.iter().map(|&(_, _, len)| len).sum();
            (carried, key, segments)
        })
        .collect();
    flows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

    let mut budget = MAX_REASSEMBLED;
    let mut flags_left = bytes::MAX_FLAGS;
    let mut overlays_left = MAX_OVERLAYS;
    let mut flags_truncated = false;
    let mut streams: Vec<Stream> = Vec::new();
    for (_, (src_ip, sp, dst_ip, dp), segments) in flows {
        let limit = MAX_STREAM_BYTES.min(budget.max(FLOW_ALLOWANCE));
        let buf = reassemble(data, &segments, limit);
        if buf.is_empty() {
            continue;
        }
        budget = budget.saturating_sub(buf.len());

        let searched = search_flow(data, &segments, tags, &mut flags_left, &mut overlays_left);
        flags_truncated |= searched.truncated;

        let embedded_file = (buf.len() >= 8).then(|| bytes::identify(&buf)).flatten();
        streams.push(Stream {
            src: endpoint(&src_ip, sp),
            dst: endpoint(&dst_ip, dp),
            bytes: buf.len(),
            carried: searched.carried,
            conflicting: searched.conflicting,
            text: preview(&buf, PREVIEW_BYTES),
            printable: printable_fraction(&buf),
            embedded_file,
            flags: searched.flags,
        });
    }

    // A stream carrying a flag or a whole file leads; then the largest.
    let finding = |s: &Stream| !s.flags.is_empty() || s.embedded_file.is_some();
    streams.sort_by_key(|s| std::cmp::Reverse((finding(s), s.bytes)));

    let findings = streams.iter().take_while(|s| finding(s)).count();
    streams.truncate(findings.clamp(MAX_STREAMS, MAX_FINDING_STREAMS));
    for stream in streams.iter_mut().skip(MAX_STREAMS) {
        stream.text.truncate(SHORT_PREVIEW_BYTES);
    }
    flags_truncated |= findings > MAX_FINDING_STREAMS;

    let mut protocols: Vec<Protocol> = protocols
        .into_iter()
        .map(|(name, (packets, bytes))| Protocol {
            name,
            packets,
            bytes,
        })
        .collect();
    protocols.sort_by(|a, b| b.packets.cmp(&a.packets).then(a.name.cmp(&b.name)));

    let conversation_count = conversations.len();
    let mut conversations: Vec<Conversation> = conversations
        .into_iter()
        .map(|((a, b, protocol), (packets, bytes))| Conversation {
            a,
            b,
            protocol: protocol.to_string(),
            packets,
            bytes,
        })
        .collect();
    conversations.sort_by_key(|x| std::cmp::Reverse(x.bytes));
    conversations.truncate(MAX_CONVERSATIONS);

    Some(Capture {
        format,
        link_type: link_name(link_type).to_string(),
        packet_count,
        capture_bytes,
        truncated,
        duration: worded_duration(last_ts - first_ts),
        protocols,
        conversations,
        conversation_count,
        streams,
        stream_count,
        dns,
        packets_capped,
        flags_truncated,
    })
}

pub fn json(data: &[u8], tags: &[String]) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    let Some(cap) = read(data, tags) else {
        return "null".to_string();
    };

    let mut out = String::from("{");
    push_field(&mut out, "format", cap.format);
    out.push(',');
    push_field(&mut out, "linkType", &cap.link_type);
    out.push(',');
    push_number(&mut out, "packetCount", cap.packet_count);
    out.push(',');
    push_number(&mut out, "captureBytes", cap.capture_bytes);
    out.push(',');
    push_bool(&mut out, "truncated", cap.truncated);
    out.push(',');
    push_field(&mut out, "duration", &cap.duration);
    out.push(',');
    push_number(&mut out, "streamCount", cap.stream_count);
    out.push(',');
    push_number(&mut out, "conversationCount", cap.conversation_count);
    out.push(',');
    push_bool(&mut out, "packetsCapped", cap.packets_capped);
    out.push(',');
    push_bool(&mut out, "flagsTruncated", cap.flags_truncated);
    out.push(',');

    push_string(&mut out, "protocols");
    out.push_str(":[");
    for (i, p) in cap.protocols.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "name", &p.name);
        out.push(',');
        push_number(&mut out, "packets", p.packets);
        out.push(',');
        push_number(&mut out, "bytes", p.bytes);
        out.push('}');
    }
    out.push_str("],");

    push_string(&mut out, "conversations");
    out.push_str(":[");
    for (i, c) in cap.conversations.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "a", &c.a);
        out.push(',');
        push_field(&mut out, "b", &c.b);
        out.push(',');
        push_field(&mut out, "protocol", &c.protocol);
        out.push(',');
        push_number(&mut out, "packets", c.packets);
        out.push(',');
        push_number(&mut out, "bytes", c.bytes);
        out.push('}');
    }
    out.push_str("],");

    push_string(&mut out, "streams");
    out.push_str(":[");
    for (i, s) in cap.streams.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "src", &s.src);
        out.push(',');
        push_field(&mut out, "dst", &s.dst);
        out.push(',');
        push_number(&mut out, "bytes", s.bytes);
        out.push(',');
        push_number(&mut out, "carried", s.carried);
        out.push(',');
        push_number(&mut out, "conflicting", s.conflicting);
        out.push(',');
        push_field(&mut out, "text", &s.text);
        out.push(',');
        push_string(&mut out, "printable");
        out.push(':');
        out.push_str(&format!("{:.2}", s.printable));
        out.push(',');
        push_string(&mut out, "embeddedFile");
        out.push(':');
        match s.embedded_file {
            Some(label) => push_string(&mut out, label),
            None => out.push_str("null"),
        }
        out.push(',');
        push_string(&mut out, "flags");
        out.push_str(":[");
        for (j, flag) in s.flags.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            push_string(&mut out, flag);
        }
        out.push_str("]}");
    }
    out.push_str("],");

    push_string(&mut out, "dns");
    out.push_str(":[");
    for (i, q) in cap.dns.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "name", &q.name);
        out.push(',');
        push_field(&mut out, "type", &q.kind);
        out.push('}');
    }
    out.push_str("]}");
    out
}

#[cfg(test)]
mod tests;
