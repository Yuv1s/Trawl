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
use std::collections::HashMap;

/// Ceilings on what one reading carries, so a large capture cannot ask the
/// browser to hold all of it. The true counts are reported alongside the capped
/// lists.
const MAX_PACKETS: usize = 500_000;
const MAX_SEGMENTS: usize = 200_000;
const MAX_STREAMS: usize = 48;
const MAX_STREAM_BYTES: usize = 256 * 1024;
const MAX_CONVERSATIONS: usize = 40;
const MAX_DNS: usize = 120;
const PREVIEW_BYTES: usize = 4096;

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
fn parse_pcap(data: &[u8]) -> Option<(Vec<Frame>, u16, usize, bool)> {
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

        capture_bytes += orig;
        truncated |= orig > incl;
        frames.push(Frame {
            link_type,
            offset: body,
            len: incl,
            timestamp: ts_sec + ts_frac / if nanos { 1e9 } else { 1e6 },
        });
        at = body + incl;
    }

    Some((frames, link_type, capture_bytes, truncated))
}

/// Reads the frames out of a pcapng file: a chain of typed blocks, each a type,
/// a total length, a body, and the total length again. Only the interface and
/// packet blocks carry frames; the rest are skipped by their length.
fn parse_pcapng(data: &[u8]) -> Option<(Vec<Frame>, u16, usize, bool)> {
    if data.get(0..4)? != [0x0a, 0x0d, 0x0d, 0x0a] {
        return None;
    }
    // The Section Header Block's byte-order magic settles the whole section's
    // endianness. Read at offset 8; little-endian if it comes back as expected.
    let le = u32_at(data, 8, true)? == 0x1a2b3c4d;

    let mut frames = Vec::new();
    let mut link_types: Vec<u16> = Vec::new();
    let mut capture_bytes = 0usize;
    let mut truncated = false;
    let mut at = 0usize;

    while at + 12 <= data.len() && frames.len() < MAX_PACKETS {
        let block_type = u32_at(data, at, le)?;
        let total = u32_at(data, at + 4, le)? as usize;
        // Every block is at least the two lengths plus a type, and padded to a
        // four-byte boundary. Anything else is a desync; stop.
        if total < 12 || !total.is_multiple_of(4) || at + total > data.len() {
            break;
        }
        let body = at + 8;

        match block_type {
            // Interface Description Block: link type, then a snap length.
            0x0000_0001 => {
                if let Some(lt) = u16_at(data, body, le) {
                    link_types.push(lt);
                }
            }
            // Enhanced Packet Block: interface id, timestamp, captured len,
            // original len, then the frame.
            0x0000_0006 => {
                let interface = u32_at(data, body, le)? as usize;
                let ts_high = u32_at(data, body + 4, le)? as u64;
                let ts_low = u32_at(data, body + 8, le)? as u64;
                let incl = u32_at(data, body + 12, le)? as usize;
                let orig = u32_at(data, body + 16, le)? as usize;
                let frame_at = body + 20;
                if frame_at + incl <= at + total {
                    capture_bytes += orig;
                    truncated |= orig > incl;
                    frames.push(Frame {
                        link_type: link_types.get(interface).copied().unwrap_or(1),
                        offset: frame_at,
                        len: incl,
                        // Microsecond units, the default when no resolution
                        // option is read.
                        timestamp: ((ts_high << 32) | ts_low) as f64 / 1e6,
                    });
                }
            }
            // Simple Packet Block: an original length, then the frame filling the
            // rest of the block.
            0x0000_0003 => {
                let orig = u32_at(data, body, le)? as usize;
                let frame_at = body + 4;
                // Block bytes minus type, both lengths and the original-length
                // field give what was captured.
                let incl = total.saturating_sub(16).min(orig);
                if frame_at + incl <= at + total {
                    capture_bytes += orig;
                    truncated |= orig > incl;
                    frames.push(Frame {
                        link_type: link_types.first().copied().unwrap_or(1),
                        offset: frame_at,
                        len: incl,
                        timestamp: 0.0,
                    });
                }
            }
            _ => {}
        }

        at += total;
    }

    let link_type = link_types.first().copied().unwrap_or(1);
    Some((frames, link_type, capture_bytes, truncated))
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
            Some(Decoded {
                src_ip: src,
                dst_ip: dst,
                src_port: sp,
                dst_port: dp,
                transport: t,
                payload_at: frame.offset + pay,
                payload_len: bytes.len().saturating_sub(pay),
                seq,
            })
        }
        0x86dd => {
            let proto = *bytes.get(l3 + 6)?;
            let src = ipv6(bytes, l3 + 8);
            let dst = ipv6(bytes, l3 + 24);
            let (t, sp, dp, pay, seq) = transport(bytes, proto, l3 + 40);
            Some(Decoded {
                src_ip: src,
                dst_ip: dst,
                src_port: sp,
                dst_port: dp,
                transport: t,
                payload_at: frame.offset + pay,
                payload_len: bytes.len().saturating_sub(pay),
                seq,
            })
        }
        _ => None,
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
fn preview(data: &[u8]) -> String {
    data.iter()
        .take(PREVIEW_BYTES)
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

/// Lays one direction's segments back down in sequence order.
///
/// The lowest sequence number is the start of the direction's data. Every
/// segment is placed at its distance from that start, so a retransmission lands
/// where it already sits and an out-of-order segment lands where it belongs.
/// Anything beyond the display cap, including a segment left far away by
/// sequence-number wrap, is dropped.
fn reassemble(file: &[u8], segments: &Segments) -> Vec<u8> {
    let Some(base) = segments.parts.iter().map(|&(seq, _, _)| seq).min() else {
        return Vec::new();
    };

    let mut buf: Vec<u8> = Vec::new();
    for &(seq, at, len) in &segments.parts {
        let offset = seq.wrapping_sub(base) as usize;
        if offset > MAX_STREAM_BYTES {
            continue;
        }
        let take = len.min(MAX_STREAM_BYTES - offset);
        let Some(bytes) = file.get(at..at + take) else {
            continue;
        };
        if offset + take > buf.len() {
            buf.resize(offset + take, 0);
        }
        buf[offset..offset + take].copy_from_slice(bytes);
    }
    buf
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
    let (frames, link_type, capture_bytes, truncated, format) =
        if let Some((f, lt, cb, tr)) = parse_pcap(data) {
            (f, lt, cb, tr, "pcap")
        } else if let Some((f, lt, cb, tr)) = parse_pcapng(data) {
            (f, lt, cb, tr, "pcapng")
        } else {
            return None;
        };

    let packet_count = frames.len();

    let mut protocols: HashMap<String, (usize, usize)> = HashMap::new();
    let mut conversations: HashMap<(String, String, &'static str), (usize, usize)> = HashMap::new();
    let mut tcp: HashMap<(String, u16, String, u16), Segments> = HashMap::new();
    let mut segment_total = 0usize;
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
            && segment_total < MAX_SEGMENTS
            && let Some(seq) = d.seq
        {
            let key = (d.src_ip.clone(), d.src_port, d.dst_ip.clone(), d.dst_port);
            tcp.entry(key)
                .or_default()
                .parts
                .push((seq, d.payload_at, d.payload_len));
            segment_total += 1;
        }

        if name == "DNS"
            && d.transport == "UDP"
            && let Some(payload) = data.get(d.payload_at..d.payload_at + d.payload_len)
        {
            dns_questions(payload, &mut dns);
        }
    }

    // Reassemble every directional flow, keep the ones that carried payload.
    let mut streams: Vec<Stream> = tcp
        .into_iter()
        .filter_map(|((src_ip, sp, dst_ip, dp), segments)| {
            let buf = reassemble(data, &segments);
            if buf.is_empty() {
                return None;
            }
            let flags = bytes::flag_candidates_for_tags(&buf, tags)
                .into_iter()
                .map(|f| f.text)
                .collect();
            let embedded_file = (buf.len() >= 8).then(|| bytes::identify(&buf)).flatten();
            Some(Stream {
                src: endpoint(&src_ip, sp),
                dst: endpoint(&dst_ip, dp),
                bytes: buf.len(),
                text: preview(&buf),
                printable: printable_fraction(&buf),
                embedded_file,
                flags,
            })
        })
        .collect();
    let stream_count = streams.len();

    // A stream carrying a flag or a whole file leads; then the largest.
    streams.sort_by(|a, b| {
        let weight = |s: &Stream| (!s.flags.is_empty() || s.embedded_file.is_some(), s.bytes);
        weight(b).cmp(&weight(a))
    });
    streams.truncate(MAX_STREAMS);

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
