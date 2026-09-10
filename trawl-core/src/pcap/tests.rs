use super::*;

/// An Ethernet + IPv4 + TCP frame carrying `payload`, with a sequence number so
/// segments of one connection can be ordered.
fn tcp_frame(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x02; 6]); // dst MAC
    f.extend_from_slice(&[0x01; 6]); // src MAC
    f.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    let total = 20 + 20 + payload.len();
    f.push(0x45); // version 4, IHL 5
    f.push(0);
    f.extend_from_slice(&(total as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]); // id, flags/frag
    f.push(64); // TTL
    f.push(6); // TCP
    f.extend_from_slice(&[0, 0]); // checksum, unread
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);

    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes()); // ack
    f.push(0x50); // data offset 5 words
    f.push(0x18); // PSH | ACK
    f.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // window, checksum, urgent
    f.extend_from_slice(payload);
    f
}

/// An Ethernet + IPv4 + UDP frame carrying `payload`.
fn udp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x02; 6]);
    f.extend_from_slice(&[0x01; 6]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());

    let total = 20 + 8 + payload.len();
    f.push(0x45);
    f.push(0);
    f.extend_from_slice(&(total as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.push(64);
    f.push(17); // UDP
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);

    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    f
}

/// A DNS query message for one name, question section only.
fn dns_query(name: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    m.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query
    m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    m.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an, ns, ar counts
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0); // root
    m.extend_from_slice(&1u16.to_be_bytes()); // type A
    m.extend_from_slice(&1u16.to_be_bytes()); // class IN
    m
}

/// Classic little-endian microsecond pcap around a set of frames.
fn pcap_file(link_type: u32, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0u32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&link_type.to_le_bytes());

    for (i, frame) in frames.iter().enumerate() {
        out.extend_from_slice(&(i as u32).to_le_bytes()); // ts sec, one apart
        out.extend_from_slice(&0u32.to_le_bytes()); // ts usec
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // incl
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // orig
        out.extend_from_slice(frame);
    }
    out
}

/// pcapng around a set of frames: a section header, one interface, then an
/// enhanced packet block per frame.
fn pcapng_file(link_type: u16, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();

    // Section Header Block.
    out.extend_from_slice(&0x0a0d0d0au32.to_le_bytes());
    out.extend_from_slice(&28u32.to_le_bytes());
    out.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(-1i64).to_le_bytes());
    out.extend_from_slice(&28u32.to_le_bytes());

    // Interface Description Block.
    out.extend_from_slice(&0x00000001u32.to_le_bytes());
    out.extend_from_slice(&20u32.to_le_bytes());
    out.extend_from_slice(&link_type.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&20u32.to_le_bytes());

    for frame in frames {
        let padded = (frame.len() + 3) & !3;
        let total = 32 + padded;
        out.extend_from_slice(&0x00000006u32.to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // interface id
        out.extend_from_slice(&0u32.to_le_bytes()); // ts high
        out.extend_from_slice(&0u32.to_le_bytes()); // ts low
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // captured
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // original
        out.extend_from_slice(frame);
        out.extend(std::iter::repeat_n(0u8, padded - frame.len()));
        out.extend_from_slice(&(total as u32).to_le_bytes());
    }
    out
}

const SRV: [u8; 4] = [10, 0, 0, 1];
const CLI: [u8; 4] = [10, 0, 0, 9];

#[test]
fn reads_a_classic_pcap_header() {
    let file = pcap_file(
        1,
        &[tcp_frame(CLI, SRV, 5000, 80, 1, b"GET / HTTP/1.1\r\n")],
    );
    let cap = read(&file, &[]).unwrap();
    assert_eq!(cap.format, "pcap");
    assert_eq!(cap.link_type, "Ethernet");
    assert_eq!(cap.packet_count, 1);
}

#[test]
fn reassembles_a_flag_split_across_two_tcp_segments() {
    // The flag is broken across two segments of one connection. Between the two
    // payloads in the file sit the second packet's Ethernet, IP and TCP headers.
    let first = b"here it comes: flag{split_ac";
    let second = b"ross_two_segments}, done";
    let file = pcap_file(
        1,
        &[
            tcp_frame(SRV, CLI, 80, 5000, 100, first),
            tcp_frame(SRV, CLI, 80, 5000, 100 + first.len() as u32, second),
        ],
    );

    // The point of the reader: the file itself does not contain the flag as a
    // contiguous run, so a raw byte scan cannot find it.
    assert!(
        bytes::flag_candidates(&file).is_empty(),
        "the flag must not appear whole anywhere in the file"
    );

    let cap = read(&file, &[]).unwrap();
    let stream = cap
        .streams
        .iter()
        .find(|s| !s.flags.is_empty())
        .expect("a stream should carry the reassembled flag");
    assert_eq!(stream.flags, vec!["flag{split_across_two_segments}"]);
    assert_eq!(stream.src, "10.0.0.1:80");
    assert_eq!(stream.dst, "10.0.0.9:5000");
}

#[test]
fn orders_segments_that_arrive_out_of_order() {
    let first = b"noise flag{seq_";
    let second = b"orders_hold} more";
    // The later segment is written to the file first.
    let file = pcap_file(
        1,
        &[
            tcp_frame(SRV, CLI, 80, 5000, 500 + first.len() as u32, second),
            tcp_frame(SRV, CLI, 80, 5000, 500, first),
        ],
    );
    let cap = read(&file, &[]).unwrap();
    let stream = cap.streams.iter().find(|s| !s.flags.is_empty()).unwrap();
    assert_eq!(stream.flags, vec!["flag{seq_orders_hold}"]);
}

#[test]
fn reads_dns_query_names() {
    let file = pcap_file(
        1,
        &[udp_frame(
            CLI,
            SRV,
            40000,
            53,
            &dns_query("secret.data.example.com"),
        )],
    );
    let cap = read(&file, &[]).unwrap();
    assert_eq!(cap.dns.len(), 1);
    assert_eq!(cap.dns[0].name, "secret.data.example.com");
    assert_eq!(cap.dns[0].kind, "A");
    assert!(cap.protocols.iter().any(|p| p.name == "DNS"));
}

#[test]
fn names_a_file_transferred_whole_over_tcp() {
    // A PNG sent down a raw connection: its magic sits after the packet header,
    // so the file scan cannot see it, but the reassembled stream begins with it.
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&[0u8; 32]);
    let file = pcap_file(1, &[tcp_frame(SRV, CLI, 1337, 44000, 1, &png)]);

    let cap = read(&file, &[]).unwrap();
    let stream = cap
        .streams
        .iter()
        .find(|s| s.embedded_file.is_some())
        .unwrap();
    assert_eq!(stream.embedded_file, Some("PNG image"));
}

#[test]
fn counts_protocols_by_application() {
    let file = pcap_file(
        1,
        &[
            tcp_frame(CLI, SRV, 5000, 80, 1, b"GET / HTTP/1.1\r\n"),
            tcp_frame(SRV, CLI, 80, 5000, 1, b"HTTP/1.1 200 OK\r\n"),
            udp_frame(CLI, SRV, 40000, 53, &dns_query("example.com")),
        ],
    );
    let cap = read(&file, &[]).unwrap();
    let http = cap.protocols.iter().find(|p| p.name == "HTTP").unwrap();
    assert_eq!(http.packets, 2);
    assert!(cap.protocols.iter().any(|p| p.name == "DNS"));
}

#[test]
fn reads_a_pcapng_capture() {
    let file = pcapng_file(
        1,
        &[
            tcp_frame(SRV, CLI, 80, 5000, 1, b"flag{pcapng"),
            tcp_frame(SRV, CLI, 80, 5000, 12, b"_reads_too}"),
        ],
    );
    let cap = read(&file, &[]).unwrap();
    assert_eq!(cap.format, "pcapng");
    assert_eq!(cap.packet_count, 2);
    let stream = cap.streams.iter().find(|s| !s.flags.is_empty()).unwrap();
    assert_eq!(stream.flags, vec!["flag{pcapng_reads_too}"]);
}

#[test]
fn configured_tags_steer_the_stream_scan() {
    let file = pcap_file(
        1,
        &[
            tcp_frame(SRV, CLI, 80, 5000, 1, b"event{cust"),
            tcp_frame(SRV, CLI, 80, 5000, 11, b"om_tag}"),
        ],
    );
    let none = read(&file, &[]).unwrap();
    assert!(none.streams.iter().all(|s| s.flags.is_empty()));

    let tagged = read(&file, &["event".to_string()]).unwrap();
    let stream = tagged.streams.iter().find(|s| !s.flags.is_empty()).unwrap();
    assert_eq!(stream.flags, vec!["event{custom_tag}"]);
}

#[test]
fn is_not_a_capture() {
    assert!(read(b"not a capture at all, just text", &[]).is_none());
    assert!(read(&[0u8; 64], &[]).is_none());
    assert_eq!(json(b"plain text", &[]), "null");
}

#[test]
fn json_is_well_formed() {
    let file = pcap_file(
        1,
        &[
            tcp_frame(SRV, CLI, 80, 5000, 1, b"flag{well"),
            tcp_frame(SRV, CLI, 80, 5000, 10, b"_formed}"),
            udp_frame(CLI, SRV, 40000, 53, &dns_query("q.example.com")),
        ],
    );
    assert!(crate::json::is_well_formed(&json(&file, &[])));
}
