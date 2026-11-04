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

/// A section header then one block claiming whatever total length a test wants.
fn pcapng_with_block_total(total: u32) -> Vec<u8> {
    let mut out = pcapng_file(1, &[]);
    out.extend_from_slice(&0xdeadu32.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

#[test]
fn a_block_total_that_wraps_a_32_bit_offset_ends_the_walk() {
    // In WASM 48 + 0xffffffd0 wraps to zero, which reads as a block that fits and
    // sends the walk back to the start of the file, forever.
    for total in [0xffff_ffd0u32, 0xffff_ffe4, 0xffff_fffc, 0xffff_fff8] {
        let cap = read(&pcapng_with_block_total(total), &[]).unwrap();
        assert_eq!(cap.format, "pcapng");
        assert_eq!(cap.packet_count, 0, "total {total:#x}");
    }
}

#[test]
fn a_packet_length_that_wraps_a_32_bit_offset_is_not_a_frame() {
    let mut file = pcapng_file(1, &[tcp_frame(SRV, CLI, 80, 5000, 1, b"flag{real_one}")]);
    // Point the captured length of the only packet near the top of 32 bits: past the
    // section and interface blocks, then a type, a total, an interface and a timestamp.
    let incl = 28 + 20 + 8 + 4 + 8;
    file[incl..incl + 4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());

    let cap = read(&file, &[]).unwrap();
    assert_eq!(cap.packet_count, 0);
}

#[test]
fn a_classic_record_claiming_more_than_the_file_ends_the_walk() {
    let mut file = pcap_file(1, &[tcp_frame(SRV, CLI, 80, 5000, 1, b"abcd")]);
    file[24 + 8..24 + 12].copy_from_slice(&0xffff_fff8u32.to_le_bytes());
    assert_eq!(read(&file, &[]).unwrap().packet_count, 0);
}

#[test]
fn original_lengths_summed_past_the_top_of_32_bits_do_not_wrap() {
    let frame = tcp_frame(SRV, CLI, 80, 5000, 1, b"abcd");
    let mut file = pcap_file(1, &[frame.clone(), frame]);
    let second = 24 + 16 + 58;
    file[24 + 12..24 + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    file[second + 12..second + 16].copy_from_slice(&u32::MAX.to_le_bytes());

    let cap = read(&file, &[]).unwrap();
    assert!(cap.capture_bytes >= u32::MAX as usize);
    assert!(cap.truncated);
}

#[test]
fn an_impossible_byte_order_is_not_a_pcapng() {
    let mut file = pcapng_file(1, &[]);
    file[8..12].copy_from_slice(&[1, 2, 3, 4]);
    assert!(read(&file, &[]).is_none());
}

/// A TCP frame carrying `pad` bytes past what the IP length covers, the way Ethernet
/// pads anything under sixty bytes.
fn padded(mut frame: Vec<u8>, pad: usize) -> Vec<u8> {
    frame.extend(std::iter::repeat_n(0u8, pad));
    frame
}

#[test]
fn ethernet_padding_on_a_keep_alive_does_not_overwrite_the_stream() {
    // A keep-alive is empty and one sequence number behind, padded to the Ethernet
    // minimum. Read as payload, its six zeroes landed on the closing brace.
    let data = b"flag{padding_must_not_corrupt_this}";
    let seq = 5000 + data.len() as u32 - 1;
    let file = pcap_file(
        1,
        &[
            tcp_frame(SRV, CLI, 80, 5000, 5000, data),
            padded(tcp_frame(SRV, CLI, 80, 5000, seq, b""), 6),
        ],
    );

    let cap = read(&file, &[]).unwrap();
    assert_eq!(cap.streams[0].bytes, data.len());
    assert_eq!(cap.streams[0].flags, vec!["flag{padding_must_not_corrupt_this}"]);
}

#[test]
fn a_keep_alive_carrying_a_junk_byte_does_not_overwrite_the_stream() {
    // Some stacks send one byte with the probe rather than none. It is inside the IP
    // length, so only keeping the first copy of a byte protects what it lands on.
    let data = b"flag{keep_the_first_copy}";
    let seq = 100 + data.len() as u32 - 1;
    let file = pcap_file(
        1,
        &[
            tcp_frame(SRV, CLI, 80, 5000, 100, data),
            tcp_frame(SRV, CLI, 80, 5000, seq, &[0]),
        ],
    );

    let cap = read(&file, &[]).unwrap();
    assert_eq!(cap.streams[0].flags, vec!["flag{keep_the_first_copy}"]);
}

#[test]
fn a_retransmission_lands_where_it_already_sits() {
    let first = b"flag{once_";
    let second = b"only_please}";
    let file = pcap_file(
        1,
        &[
            tcp_frame(SRV, CLI, 80, 5000, 10, first),
            tcp_frame(SRV, CLI, 80, 5000, 10, first),
            tcp_frame(SRV, CLI, 80, 5000, 10 + first.len() as u32, second),
            tcp_frame(SRV, CLI, 80, 5000, 10 + first.len() as u32, second),
        ],
    );

    let cap = read(&file, &[]).unwrap();
    assert_eq!(cap.streams[0].bytes, first.len() + second.len());
    assert_eq!(cap.streams[0].flags, vec!["flag{once_only_please}"]);
}

#[test]
fn a_length_of_zero_in_the_ip_header_leaves_the_frame_in_charge() {
    // What a capture shows when the card fills the length in after the tap.
    let mut frame = tcp_frame(SRV, CLI, 80, 5000, 1, b"flag{checksum_offload}");
    frame[14 + 2..14 + 4].copy_from_slice(&[0, 0]);
    let cap = read(&pcap_file(1, &[frame]), &[]).unwrap();
    assert_eq!(cap.streams[0].flags, vec!["flag{checksum_offload}"]);
}

#[test]
fn an_ipv6_payload_length_excludes_the_padding_too() {
    let payload = b"flag{v6_padded}";
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02; 6]);
    frame.extend_from_slice(&[0x01; 6]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    frame.push(6); // TCP
    frame.push(64);
    frame.extend_from_slice(&[0x20; 16]);
    frame.extend_from_slice(&[0x21; 16]);
    frame.extend_from_slice(&80u16.to_be_bytes());
    frame.extend_from_slice(&5000u16.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.push(0x50);
    frame.push(0x18);
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&[0xee; 9]);

    let cap = read(&pcap_file(1, &[frame]), &[]).unwrap();
    assert_eq!(cap.streams[0].bytes, payload.len());
    assert_eq!(cap.streams[0].flags, vec!["flag{v6_padded}"]);
}

#[test]
fn a_stream_crossing_the_sequence_wrap_keeps_both_halves() {
    // The plain minimum of 0xfffffff8 and 0 is 0, which put the first half four
    // billion bytes away, past the cap, and dropped it.
    let file = pcap_file(
        1,
        &[
            tcp_frame(SRV, CLI, 80, 5000, 0xffff_fff8, b"flag{spl"),
            tcp_frame(SRV, CLI, 80, 5000, 0, b"it_across_wrap}"),
        ],
    );

    let cap = read(&file, &[]).unwrap();
    assert_eq!(cap.streams[0].flags, vec!["flag{split_across_wrap}"]);
}

#[test]
fn a_wrapped_stream_arriving_out_of_order_keeps_both_halves() {
    let file = pcap_file(
        1,
        &[
            tcp_frame(SRV, CLI, 80, 5000, 0, b"it_across_wrap}"),
            tcp_frame(SRV, CLI, 80, 5000, 0xffff_fff8, b"flag{spl"),
        ],
    );

    let cap = read(&file, &[]).unwrap();
    assert_eq!(cap.streams[0].flags, vec!["flag{split_across_wrap}"]);
}

#[test]
fn a_segment_past_the_limit_is_dropped_rather_than_allocated_for() {
    let file = pcap_file(
        1,
        &[
            tcp_frame(SRV, CLI, 80, 5000, 1000, b"flag{near_part}"),
            tcp_frame(SRV, CLI, 80, 5000, 1000 + 0x7000_0000, b"far away"),
        ],
    );

    let cap = read(&file, &[]).unwrap();
    assert_eq!(cap.streams[0].bytes, "flag{near_part}".len());
}

#[test]
fn gaps_across_many_connections_stay_inside_the_budget() {
    // Two packets a connection, each claiming a whole stream's worth of gap. A dozen
    // megabytes of capture would otherwise ask for tens of gigabytes of buffers.
    let mut frames = Vec::new();
    for port in 0..4000u16 {
        frames.push(tcp_frame(SRV, CLI, 80, port + 1, 0, b"x"));
        frames.push(tcp_frame(SRV, CLI, 80, port + 1, MAX_STREAM_BYTES as u32 - 1, b"y"));
    }

    let cap = read(&pcap_file(1, &frames), &[]).unwrap();
    assert_eq!(cap.stream_count, 4000, "every stream is still counted");
    assert_eq!(cap.streams.len(), MAX_STREAMS);

    let segments = Segments {
        parts: vec![(0, 0, 1), (MAX_STREAM_BYTES as u32 - 1, 1, 1)],
    };
    assert_eq!(reassemble(b"xy", &segments, MAX_STREAM_BYTES).len(), MAX_STREAM_BYTES);
    assert_eq!(reassemble(b"xy", &segments, 1).len(), 1);
    assert!(reassemble(b"xy", &segments, 0).is_empty());
}

/// A pcapng whose interface declares a timestamp resolution, with two packets a
/// given number of ticks apart.
fn pcapng_with_resolution(tsresol: u8, ticks: u64) -> Vec<u8> {
    let mut out = pcapng_file(1, &[]);
    // Replace the interface block with one carrying an option.
    out.truncate(28);

    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&65535u32.to_le_bytes());
    body.extend_from_slice(&9u16.to_le_bytes()); // if_tsresol
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&[tsresol, 0, 0, 0]);
    body.extend_from_slice(&0u16.to_le_bytes()); // end of options
    body.extend_from_slice(&0u16.to_le_bytes());

    let total = (body.len() + 12) as u32;
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&total.to_le_bytes());

    let frame = tcp_frame(SRV, CLI, 80, 5000, 1, b"abcd");
    for stamp in [ticks, ticks * 2] {
        let padded = (frame.len() + 3) & !3;
        let total = (32 + padded) as u32;
        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&((stamp >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&(stamp as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&frame);
        out.extend(std::iter::repeat_n(0u8, padded - frame.len()));
        out.extend_from_slice(&total.to_le_bytes());
    }
    out
}

#[test]
fn a_nanosecond_capture_times_a_second_as_a_second() {
    // Read as microseconds, this was sixteen and a half minutes.
    let cap = read(&pcapng_with_resolution(9, 1_000_000_000), &[]).unwrap();
    assert_eq!(cap.duration, "1.00 s");
}

#[test]
fn a_binary_timestamp_resolution_is_a_power_of_two() {
    let cap = read(&pcapng_with_resolution(0x80 | 10, 1024), &[]).unwrap();
    assert_eq!(cap.duration, "1.00 s");
}

#[test]
fn no_resolution_option_means_microseconds() {
    assert_eq!(ticks_per_second(&[], 0, 0, true), 1e6);
    // An option that is not the one asked for is stepped over, padding and all.
    let mut options = 2u16.to_le_bytes().to_vec();
    options.extend_from_slice(&5u16.to_le_bytes());
    options.extend_from_slice(b"hello\0\0\0");
    options.extend_from_slice(&9u16.to_le_bytes());
    options.extend_from_slice(&1u16.to_le_bytes());
    options.extend_from_slice(&[3, 0, 0, 0]);
    assert_eq!(ticks_per_second(&options, 0, options.len(), true), 1e3);
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
