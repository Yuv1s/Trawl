//! Just enough JSON to get analysis results across the WASM boundary.
//!
//! wasm-bindgen structs are handles into linear memory, so they cannot survive a
//! `postMessage` out of the worker. A string can. serde would do this too, but it
//! is a dependency and this is thirty lines.

pub fn push_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str("\\u");
                for shift in [12, 8, 4, 0] {
                    out.push(char::from_digit((c as u32 >> shift) & 0xf, 16).unwrap());
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn push_field(out: &mut String, key: &str, value: &str) {
    push_string(out, key);
    out.push(':');
    push_string(out, value);
}

pub fn push_number(out: &mut String, key: &str, value: usize) {
    push_string(out, key);
    out.push(':');
    out.push_str(&value.to_string());
}

/// For a number that is 64 bits wide in the file, which a WASM `usize` would cut down
/// to its low half.
pub fn push_u64(out: &mut String, key: &str, value: u64) {
    push_string(out, key);
    out.push(':');
    out.push_str(&value.to_string());
}

pub fn push_bool(out: &mut String, key: &str, value: bool) {
    push_string(out, key);
    out.push(':');
    out.push_str(if value { "true" } else { "false" });
}

/// Latin-1, which is what PNG text chunks and most legacy metadata actually hold.
/// Decoding those as UTF-8 turns a valid 0xE9 into a replacement character.
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// A JSON syntax check for tests, so a module's own `json()` test can prove
/// its output actually parses rather than merely containing the right
/// substrings.
///
/// Not a deserialiser: nothing here is kept, only whether the grammar holds
/// together — braces and brackets close, every key is followed by a colon,
/// every element is separated by a comma, and strings escape correctly. That
/// is enough to catch what a substring check cannot: a key written twice
/// with nothing between them still contains every substring a hand-written
/// assertion would look for.
#[cfg(test)]
pub fn is_well_formed(text: &str) -> bool {
    struct Parser<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl Parser<'_> {
        fn skip_ws(&mut self) {
            while matches!(self.bytes.get(self.at), Some(b' ' | b'\n' | b'\r' | b'\t')) {
                self.at += 1;
            }
        }

        fn eat(&mut self, byte: u8) -> bool {
            if self.bytes.get(self.at) == Some(&byte) {
                self.at += 1;
                true
            } else {
                false
            }
        }

        fn literal(&mut self, word: &str) -> bool {
            let bytes = word.as_bytes();
            if self.bytes.get(self.at..self.at + bytes.len()) == Some(bytes) {
                self.at += bytes.len();
                true
            } else {
                false
            }
        }

        fn string(&mut self) -> bool {
            if !self.eat(b'"') {
                return false;
            }
            loop {
                match self.bytes.get(self.at) {
                    None => return false,
                    Some(b'"') => {
                        self.at += 1;
                        return true;
                    }
                    Some(b'\\') => {
                        self.at += 1;
                        match self.bytes.get(self.at) {
                            Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                                self.at += 1;
                            }
                            Some(b'u') => {
                                let digits = self.bytes.get(self.at + 1..self.at + 5);
                                if !digits.is_some_and(|d| d.iter().all(u8::is_ascii_hexdigit)) {
                                    return false;
                                }
                                self.at += 5;
                            }
                            _ => return false,
                        }
                    }
                    // A raw control character is the one thing a JSON string cannot
                    // hold, and what a missed escape looks like.
                    Some(0x00..=0x1f) => return false,
                    Some(_) => self.at += 1,
                }
            }
        }

        fn digits(&mut self) -> bool {
            let start = self.at;
            while self.bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
                self.at += 1;
            }
            self.at > start
        }

        fn number(&mut self) -> bool {
            self.eat(b'-');
            // A lone zero, or digits that do not begin with one.
            if !self.eat(b'0') && !(self.bytes.get(self.at).is_some_and(|b| *b != b'0') && self.digits()) {
                return false;
            }
            if self.eat(b'.') && !self.digits() {
                return false;
            }
            if self.eat(b'e') || self.eat(b'E') {
                if !self.eat(b'+') {
                    self.eat(b'-');
                }
                return self.digits();
            }
            true
        }

        fn value(&mut self) -> bool {
            self.skip_ws();
            let ok = match self.bytes.get(self.at) {
                Some(b'{') => self.object(),
                Some(b'[') => self.array(),
                Some(b'"') => self.string(),
                Some(b't') => self.literal("true"),
                Some(b'f') => self.literal("false"),
                Some(b'n') => self.literal("null"),
                Some(b'-') | Some(b'0'..=b'9') => self.number(),
                _ => false,
            };
            self.skip_ws();
            ok
        }

        fn object(&mut self) -> bool {
            if !self.eat(b'{') {
                return false;
            }
            self.skip_ws();
            if self.eat(b'}') {
                return true;
            }
            loop {
                self.skip_ws();
                if !self.string() {
                    return false;
                }
                self.skip_ws();
                if !self.eat(b':') {
                    return false;
                }
                if !self.value() {
                    return false;
                }
                if self.eat(b',') {
                    continue;
                }
                return self.eat(b'}');
            }
        }

        fn array(&mut self) -> bool {
            if !self.eat(b'[') {
                return false;
            }
            self.skip_ws();
            if self.eat(b']') {
                return true;
            }
            loop {
                if !self.value() {
                    return false;
                }
                if self.eat(b',') {
                    continue;
                }
                return self.eat(b']');
            }
        }
    }

    let mut parser = Parser {
        bytes: text.as_bytes(),
        at: 0,
    };
    parser.value() && parser.at == parser.bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_the_characters_json_cannot_hold_raw() {
        let mut out = String::new();
        push_string(&mut out, "a\"b\\c\nd\te");
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\\te\"");
    }

    #[test]
    fn escapes_control_bytes_as_four_digit_hex() {
        let mut out = String::new();
        push_string(&mut out, "\u{1}\u{1f}\u{7f}");
        assert_eq!(out, "\"\\u0001\\u001f\\u007f\"");
    }

    #[test]
    fn latin1_maps_high_bytes_without_replacement_characters() {
        assert_eq!(latin1(&[0x41, 0xe9, 0xff]), "A\u{e9}\u{ff}");
        assert_eq!(latin1(&[0x80]).chars().next(), Some('\u{80}'));
    }

    #[test]
    fn accepts_ordinary_json() {
        assert!(is_well_formed(
            r#"{"a":1,"b":[1,2,"three"],"c":null,"d":true,"e":{"nested":false}}"#
        ));
        assert!(is_well_formed("[]"));
        assert!(is_well_formed("null"));
    }

    #[test]
    fn rejects_a_key_written_twice_with_nothing_between() {
        // The exact shape a `push_string` call followed by a `push_field` call
        // for the same key produces: the value is there, and so is every
        // substring an assertion might look for, but the key appears twice
        // with no colon after the first one.
        assert!(!is_well_formed(r#"{"type""type":"Catalog"}"#));
    }

    #[test]
    fn rejects_a_raw_control_character_in_a_string() {
        assert!(!is_well_formed("\"a\nb\""));
        assert!(!is_well_formed("\"a\tb\""));
        assert!(!is_well_formed("\"a\u{1}b\""));
        assert!(is_well_formed("\"a\\nb\""));
        assert!(is_well_formed("\"caf\u{e9} \u{7f}\""));
    }

    #[test]
    fn rejects_an_escape_json_does_not_have() {
        for bad in [r#""\q""#, r#""\u12""#, r#""\u12g4""#, r#""\x41""#, r#""\"#, r#""\u"#] {
            assert!(!is_well_formed(bad), "{bad}");
        }
        for good in [r#""\"""#, r#""\\""#, r#""\/""#, r#""\b\f\n\r\t""#, r#""\u00e9""#, r#""\uABCD""#] {
            assert!(is_well_formed(good), "{good}");
        }
    }

    #[test]
    fn rejects_a_number_json_does_not_have() {
        for bad in ["-", "1.", ".5", "01", "-01", "1e", "1e+", "--1", "+1", "NaN", "inf"] {
            assert!(!is_well_formed(bad), "{bad}");
        }
        for good in ["0", "-0", "10", "1.5", "-1.25", "0.5", "1e5", "1E-5", "1.5e+3"] {
            assert!(is_well_formed(good), "{good}");
        }
    }

    #[test]
    fn rejects_whitespace_json_does_not_have() {
        assert!(!is_well_formed("\u{c}1"));
        assert!(is_well_formed(" \r\n\t1 "));
    }

    #[test]
    fn a_wide_number_is_written_in_full() {
        let mut out = String::new();
        push_u64(&mut out, "size", 0x1_0000_0000);
        assert_eq!(out, "\"size\":4294967296");
    }

    #[test]
    fn rejects_unbalanced_and_trailing_garbage() {
        assert!(!is_well_formed(r#"{"a":1"#));
        assert!(!is_well_formed(r#"{"a":1}}"#));
        assert!(!is_well_formed(r#"{"a":1,}"#));
    }
}
