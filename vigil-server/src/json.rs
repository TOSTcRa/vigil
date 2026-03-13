// zero-dep json serializer/deserializer
// only uses std, no serde, no external crates

use std::fmt;

// represents any json value
#[derive(Debug)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>), // preserves insertion order
}

// parser state - tracks position for error messages
struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn new(input: &str) -> Self {
        Parser {
            chars: input.chars().collect(),
            pos: 0,
        }
    }

    // where we are in the input, for error messages
    fn location(&self) -> String {
        let consumed = &self.chars[..self.pos];
        let line = consumed.iter().filter(|&&c| c == '\n').count() + 1;
        let col = consumed.iter().rev().take_while(|&&c| c != '\n').count() + 1;
        format!("line {}, col {}", line, col)
    }

    fn err<T>(&self, msg: &str) -> Result<T, String> {
        Err(format!("{} at {}", msg, self.location()))
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let ch = self.chars.get(self.pos).copied();
        if ch.is_some() {
            self.pos += 1;
        }
        ch
    }

    fn skip_ws(&mut self) {
        while let Some(ch) = self.peek() {
            if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    // expect a specific character, error if not found
    fn expect(&mut self, expected: char) -> Result<(), String> {
        self.skip_ws();
        match self.next() {
            Some(ch) if ch == expected => Ok(()),
            Some(ch) => self.err(&format!("expected '{}', got '{}'", expected, ch)),
            None => self.err(&format!("expected '{}', got end of input", expected)),
        }
    }

    // try to consume a specific string literal (like "true", "false", "null")
    fn expect_str(&mut self, s: &str) -> Result<(), String> {
        for expected in s.chars() {
            match self.next() {
                Some(ch) if ch == expected => {}
                Some(ch) => return self.err(&format!("expected '{}' in '{}', got '{}'", expected, s, ch)),
                None => return self.err(&format!("unexpected end of input while parsing '{}'", s)),
            }
        }
        Ok(())
    }

    // main entry - parse a single json value
    fn parse_value(&mut self) -> Result<JsonValue, String> {
        self.skip_ws();
        match self.peek() {
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('t') => {
                self.expect_str("true")?;
                Ok(JsonValue::Bool(true))
            }
            Some('f') => {
                self.expect_str("false")?;
                Ok(JsonValue::Bool(false))
            }
            Some('n') => {
                self.expect_str("null")?;
                Ok(JsonValue::Null)
            }
            Some(ch) if ch == '-' || ch.is_ascii_digit() => self.parse_number(),
            Some(ch) => self.err(&format!("unexpected character '{}'", ch)),
            None => self.err("unexpected end of input"),
        }
    }

    // parse a json string (consumes opening and closing quotes)
    fn parse_string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut res = String::new();

        loop {
            match self.next() {
                Some('"') => return Ok(res),
                Some('\\') => {
                    // escape sequence
                    match self.next() {
                        Some('"') => res.push('"'),
                        Some('\\') => res.push('\\'),
                        Some('/') => res.push('/'),
                        Some('n') => res.push('\n'),
                        Some('t') => res.push('\t'),
                        Some('r') => res.push('\r'),
                        Some('b') => res.push('\u{0008}'),
                        Some('f') => res.push('\u{000C}'),
                        Some('u') => {
                            let cp = self.parse_unicode_escape()?;
                            // handle surrogate pairs
                            if (0xD800..=0xDBFF).contains(&cp) {
                                // high surrogate - expect \uXXXX low surrogate
                                match (self.next(), self.next()) {
                                    (Some('\\'), Some('u')) => {
                                        let low = self.parse_unicode_escape()?;
                                        if !(0xDC00..=0xDFFF).contains(&low) {
                                            return self.err("expected low surrogate after high surrogate");
                                        }
                                        let full = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                                        match char::from_u32(full as u32) {
                                            Some(c) => res.push(c),
                                            None => return self.err("invalid surrogate pair"),
                                        }
                                    }
                                    _ => return self.err("expected low surrogate pair (\\uXXXX) after high surrogate"),
                                }
                            } else {
                                match char::from_u32(cp as u32) {
                                    Some(c) => res.push(c),
                                    None => return self.err(&format!("invalid unicode codepoint: {:04X}", cp)),
                                }
                            }
                        }
                        Some(ch) => return self.err(&format!("invalid escape sequence '\\{}'", ch)),
                        None => return self.err("unexpected end of input in escape sequence"),
                    }
                }
                Some(ch) => {
                    // control characters (U+0000 through U+001F) must be escaped per spec
                    if ch < '\u{0020}' {
                        return self.err(&format!("unescaped control character U+{:04X} in string", ch as u32));
                    }
                    res.push(ch);
                }
                None => return self.err("unterminated string"),
            }
        }
    }

    // parse 4 hex digits for \uXXXX escapes, returns the codepoint as usize
    fn parse_unicode_escape(&mut self) -> Result<usize, String> {
        let mut val = 0usize;
        for _ in 0..4 {
            match self.next() {
                Some(ch) => {
                    let digit = match ch {
                        '0'..='9' => ch as usize - '0' as usize,
                        'a'..='f' => ch as usize - 'a' as usize + 10,
                        'A'..='F' => ch as usize - 'A' as usize + 10,
                        _ => return self.err(&format!("invalid hex digit '{}' in \\u escape", ch)),
                    };
                    val = val * 16 + digit;
                }
                None => return self.err("unexpected end of input in \\u escape"),
            }
        }
        Ok(val)
    }

    // parse a json number
    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;

        // optional minus
        if self.peek() == Some('-') {
            self.pos += 1;
        }

        // integer part
        match self.peek() {
            Some('0') => {
                self.pos += 1;
                // after leading 0, next char must not be a digit (no 007 style)
            }
            Some(ch) if ch.is_ascii_digit() => {
                while let Some(ch) = self.peek() {
                    if ch.is_ascii_digit() {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
            }
            _ => return self.err("expected digit in number"),
        }

        // fractional part
        if self.peek() == Some('.') {
            self.pos += 1;
            let frac_start = self.pos;
            while let Some(ch) = self.peek() {
                if ch.is_ascii_digit() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if self.pos == frac_start {
                return self.err("expected digit after decimal point");
            }
        }

        // exponent part
        if let Some('e' | 'E') = self.peek() {
            self.pos += 1;
            // optional sign
            if let Some('+' | '-') = self.peek() {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while let Some(ch) = self.peek() {
                if ch.is_ascii_digit() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if self.pos == exp_start {
                return self.err("expected digit in exponent");
            }
        }

        let num_str: String = self.chars[start..self.pos].iter().collect();
        match num_str.parse::<f64>() {
            Ok(n) => Ok(JsonValue::Number(n)),
            Err(_) => self.err(&format!("invalid number '{}'", num_str)),
        }
    }

    // parse a json object: { "key": value, ... }
    fn parse_object(&mut self) -> Result<JsonValue, String> {
        self.expect('{')?;
        let mut pairs: Vec<(String, JsonValue)> = Vec::new();

        self.skip_ws();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Ok(JsonValue::Object(pairs));
        }

        loop {
            self.skip_ws();
            // key must be a string
            if self.peek() != Some('"') {
                return self.err("expected string key in object");
            }
            let key = self.parse_string()?;
            self.expect(':')?;
            let val = self.parse_value()?;
            pairs.push((key, val));

            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                }
                Some('}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(pairs));
                }
                _ => return self.err("expected ',' or '}' in object"),
            }
        }
    }

    // parse a json array: [ value, ... ]
    fn parse_array(&mut self) -> Result<JsonValue, String> {
        self.expect('[')?;
        let mut items: Vec<JsonValue> = Vec::new();

        self.skip_ws();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }

        loop {
            let val = self.parse_value()?;
            items.push(val);

            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                }
                Some(']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return self.err("expected ',' or ']' in array"),
            }
        }
    }
}

// parse a json string into a JsonValue
pub fn parse(input: &str) -> Result<JsonValue, String> {
    let mut parser = Parser::new(input);
    let val = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos != parser.chars.len() {
        return parser.err("trailing data after json value");
    }
    Ok(val)
}

// serialize a JsonValue to a compact json string
pub fn stringify(val: &JsonValue) -> String {
    let mut out = String::new();
    write_value(val, &mut out);
    out
}

// recursive serializer
fn write_value(val: &JsonValue, out: &mut String) {
    match val {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Number(n) => {
            // if the number is a whole integer, skip the decimal point
            if n.fract() == 0.0 && n.is_finite() && n.abs() < (i64::MAX as f64) {
                out.push_str(&(*n as i64).to_string());
            } else {
                out.push_str(&n.to_string());
            }
        }
        JsonValue::String(s) => {
            out.push('"');
            write_escaped(s, out);
            out.push('"');
        }
        JsonValue::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        JsonValue::Object(pairs) => {
            out.push('{');
            for (i, (key, val)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                write_escaped(key, out);
                out.push('"');
                out.push(':');
                write_value(val, out);
            }
            out.push('}');
        }
    }
}

// escape a string for json output
fn write_escaped(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if c < '\u{0020}' => {
                // other control chars get \u00XX treatment
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

// helper methods on JsonValue
impl JsonValue {
    // look up a key in an object
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(pairs) => {
                pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
            }
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    // truncates f64 to i64
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonValue::Number(n) => Some(*n as i64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<JsonValue>> {
        match self {
            JsonValue::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Vec<(String, JsonValue)>> {
        match self {
            JsonValue::Object(pairs) => Some(pairs),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, JsonValue::Null)
    }
}

// builder helpers - shortcuts for constructing json values

pub fn json_obj(pairs: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
    )
}

pub fn json_arr(items: Vec<JsonValue>) -> JsonValue {
    JsonValue::Array(items)
}

pub fn json_str(s: &str) -> JsonValue {
    JsonValue::String(s.to_string())
}

pub fn json_num(n: f64) -> JsonValue {
    JsonValue::Number(n)
}

pub fn json_bool(b: bool) -> JsonValue {
    JsonValue::Bool(b)
}

pub fn json_null() -> JsonValue {
    JsonValue::Null
}

// Display just calls stringify
impl fmt::Display for JsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", stringify(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitives() {
        assert!(parse("null").unwrap().is_null());
        assert_eq!(parse("true").unwrap().as_bool(), Some(true));
        assert_eq!(parse("false").unwrap().as_bool(), Some(false));
        assert_eq!(parse("42").unwrap().as_f64(), Some(42.0));
        assert_eq!(parse("-3.14").unwrap().as_f64(), Some(-3.14));
        assert_eq!(parse("1e10").unwrap().as_f64(), Some(1e10));
        assert_eq!(parse("\"hello\"").unwrap().as_str(), Some("hello"));
    }

    #[test]
    fn test_string_escapes() {
        let val = parse(r#""hello\nworld""#).unwrap();
        assert_eq!(val.as_str(), Some("hello\nworld"));

        let val = parse(r#""tab\there""#).unwrap();
        assert_eq!(val.as_str(), Some("tab\there"));

        let val = parse(r#""quote\"inside""#).unwrap();
        assert_eq!(val.as_str(), Some("quote\"inside"));

        let val = parse(r#""back\\slash""#).unwrap();
        assert_eq!(val.as_str(), Some("back\\slash"));

        let val = parse(r#""slash\/ok""#).unwrap();
        assert_eq!(val.as_str(), Some("slash/ok"));
    }

    #[test]
    fn test_unicode_escape() {
        // basic unicode
        let val = parse(r#""\u0041""#).unwrap();
        assert_eq!(val.as_str(), Some("A"));

        // surrogate pair for emoji (U+1F600 = grinning face)
        let val = parse(r#""\uD83D\uDE00""#).unwrap();
        assert_eq!(val.as_str(), Some("\u{1F600}"));
    }

    #[test]
    fn test_array() {
        let val = parse("[1, 2, 3]").unwrap();
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0].as_f64(), Some(1.0));
        assert_eq!(arr[2].as_f64(), Some(3.0));

        // empty array
        let val = parse("[]").unwrap();
        assert_eq!(val.as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_object() {
        let val = parse(r#"{"name": "vigil", "version": 1}"#).unwrap();
        assert_eq!(val.get("name").unwrap().as_str(), Some("vigil"));
        assert_eq!(val.get("version").unwrap().as_f64(), Some(1.0));
        assert!(val.get("missing").is_none());

        // empty object
        let val = parse("{}").unwrap();
        assert_eq!(val.as_object().unwrap().len(), 0);
    }

    #[test]
    fn test_nested() {
        let input = r#"{"players": [{"id": 1, "name": "test"}], "count": 1}"#;
        let val = parse(input).unwrap();
        let players = val.get("players").unwrap().as_array().unwrap();
        assert_eq!(players.len(), 1);
        assert_eq!(players[0].get("name").unwrap().as_str(), Some("test"));
    }

    #[test]
    fn test_stringify_roundtrip() {
        let input = r#"{"a":1,"b":"hello","c":[true,null,3.14],"d":{"nested":false}}"#;
        let val = parse(input).unwrap();
        let output = stringify(&val);
        assert_eq!(output, input);
    }

    #[test]
    fn test_builder_helpers() {
        let val = json_obj(vec![
            ("status", json_str("ok")),
            ("code", json_num(200.0)),
            ("data", json_arr(vec![json_bool(true), json_null()])),
        ]);
        let s = stringify(&val);
        assert_eq!(s, r#"{"status":"ok","code":200,"data":[true,null]}"#);
    }

    #[test]
    fn test_display() {
        let val = json_str("test");
        assert_eq!(format!("{}", val), "\"test\"");
    }

    #[test]
    fn test_as_i64() {
        let val = parse("42").unwrap();
        assert_eq!(val.as_i64(), Some(42));

        let val = parse("3.9").unwrap();
        assert_eq!(val.as_i64(), Some(3)); // truncates
    }

    #[test]
    fn test_error_messages() {
        let res = parse("{bad}");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("line"));

        let res = parse("[1, 2,]");
        assert!(res.is_err());

        let res = parse("");
        assert!(res.is_err());
    }

    #[test]
    fn test_whitespace_handling() {
        let val = parse("  {  \"a\"  :  1  }  ").unwrap();
        assert_eq!(val.get("a").unwrap().as_f64(), Some(1.0));
    }

    #[test]
    fn test_string_escape_output() {
        let val = JsonValue::String("line1\nline2\ttab".to_string());
        assert_eq!(stringify(&val), r#""line1\nline2\ttab""#);
    }

    #[test]
    fn test_number_formats() {
        // leading zero not allowed for multi-digit
        assert_eq!(parse("0").unwrap().as_f64(), Some(0.0));
        assert_eq!(parse("-0").unwrap().as_f64(), Some(-0.0));
        assert_eq!(parse("1.5e2").unwrap().as_f64(), Some(150.0));
        assert_eq!(parse("1.5E-2").unwrap().as_f64(), Some(0.015));
        assert_eq!(parse("1e+3").unwrap().as_f64(), Some(1000.0));
    }

    #[test]
    fn test_insertion_order_preserved() {
        let input = r#"{"z":1,"a":2,"m":3}"#;
        let val = parse(input).unwrap();
        let pairs = val.as_object().unwrap();
        assert_eq!(pairs[0].0, "z");
        assert_eq!(pairs[1].0, "a");
        assert_eq!(pairs[2].0, "m");
    }
}
