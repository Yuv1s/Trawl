use super::*;

fn found(text: &[u8]) -> Vec<String> {
    harvest(text).into_iter().map(|h| h.value).collect()
}

fn base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut packed = 0u32;
        for (i, &byte) in chunk.iter().enumerate() {
            packed |= (byte as u32) << (16 - 8 * i);
        }
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                B64[((packed >> (18 - 6 * i)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn css_escapes(text: &str) -> String {
    text.bytes().map(|b| format!("\\{b:02x} ")).collect()
}

fn xor_array(text: &str, key: u8) -> String {
    let parts: Vec<String> = text.bytes().map(|b| (b ^ key).to_string()).collect();
    format!("[{}]", parts.join(", "))
}

#[test]
fn reads_a_base64_variable_out_of_source() {
    let value = base64(b"flag{base64_below_the_waterline}");
    let js = format!("const navCache = \"{value}\";");
    assert!(found(js.as_bytes()).contains(&"flag{base64_below_the_waterline}".to_string()));
}

#[test]
fn reads_a_hex_variable_out_of_source() {
    let js =
        b"var channelFingerprint = \"666c61677b6865785f6d61726b735f7468655f68696464656e5f6368616e6e656c7d\";";
    assert!(found(js).contains(&"flag{hex_marks_the_hidden_channel}".to_string()));
}

#[test]
fn reads_a_rot13_comment() {
    let html = b"<!-- legacy bearing synt{ebg13_gheaf_gur_gvqr} -->";
    let result = harvest(html);
    assert!(
        result
            .iter()
            .any(|h| h.value == "flag{rot13_turns_the_tide}" && h.how == "ROT13")
    );
}

#[test]
fn reads_css_hex_escapes() {
    let css = format!(".x::after {{ content: \"{}\"; }}", css_escapes("flag{css_escapes}"));
    assert!(found(css.as_bytes()).contains(&"flag{css_escapes}".to_string()));
}

#[test]
fn reverses_an_etag_before_decoding_it() {
    // The header value backwards is standard base64 of the flag.
    let forward: String = base64(b"flag{etag_reverse_base64_current}")
        .chars()
        .rev()
        .collect();
    let header = format!("ETag: \"{forward}\"");
    let result = harvest(header.as_bytes());
    assert!(
        result
            .iter()
            .any(|h| h.value == "flag{etag_reverse_base64_current}" && h.how == "reversed base64")
    );
}

#[test]
fn xors_an_integer_array_against_the_right_byte() {
    let js = format!("const driftVector = {};", xor_array("flag{xored_vectors}", 0x2d));
    let result = harvest(js.as_bytes());
    assert!(
        result
            .iter()
            .any(|h| h.value == "flag{xored_vectors}" && h.how == "XOR 0x2d")
    );
}

#[test]
fn a_base64_cookie_value_decodes() {
    let value = base64(b"flag{cookie_cargo_decoded}");
    let header = format!("session={value}; Path=/");
    assert!(found(header.as_bytes()).contains(&"flag{cookie_cargo_decoded}".to_string()));
}

#[test]
fn stays_quiet_on_ordinary_text() {
    let html = br#"<html><body><h1>Welcome to the harbour</h1>
        <p>The tide comes in at 0600 and 1800. Numbers: [1, 2, 3, 4, 5].</p>
        <a href="/about">About</a> <script>const total = 42;</script></body></html>"#;
    assert!(
        harvest(html).is_empty(),
        "harvest was not quiet: {:?}",
        harvest(html)
    );
}

#[test]
fn one_flag_is_reported_once_even_if_two_readings_find_it() {
    let value = base64(b"flag{seen_only_once}");
    let js = format!("x = \"{value}\";");
    let values = found(js.as_bytes());
    assert_eq!(
        values.iter().filter(|v| *v == "flag{seen_only_once}").count(),
        1
    );
}
