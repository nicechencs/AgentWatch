//! Compact JSON writer and a checker for stored JSON columns.
//!
//! Stored JSON (`collectors`, `field_evidence`, `answers`, `domain_alts`,
//! `affects`) is embedded only when it is exactly one JSON value. The bytes
//! are copied through unchanged, so key order inside those values is whatever
//! was stored. This crate does not take a serde dependency for that check.

use std::io::Write;

use crate::export::{io_err, ExportError};

pub(crate) struct JsonWrite<'a, W> {
    out: &'a mut W,
    /// Whether the next object or array element needs a comma in front.
    needs_comma: Vec<bool>,
}

impl<'a, W: Write> JsonWrite<'a, W> {
    pub(crate) fn new(out: &'a mut W) -> Self {
        Self {
            out,
            needs_comma: Vec::new(),
        }
    }

    pub(crate) fn begin_object(&mut self) -> Result<(), ExportError> {
        self.comma()?;
        self.out
            .write_all(b"{")
            .map_err(|err| io_err("write_jsonl", err))?;
        self.needs_comma.push(false);
        Ok(())
    }

    pub(crate) fn end_object(&mut self) -> Result<(), ExportError> {
        self.needs_comma.pop();
        self.out
            .write_all(b"}")
            .map_err(|err| io_err("write_jsonl", err))
    }

    pub(crate) fn begin_array(&mut self) -> Result<(), ExportError> {
        self.comma()?;
        self.out
            .write_all(b"[")
            .map_err(|err| io_err("write_jsonl", err))?;
        self.needs_comma.push(false);
        Ok(())
    }

    pub(crate) fn end_array(&mut self) -> Result<(), ExportError> {
        self.needs_comma.pop();
        self.out
            .write_all(b"]")
            .map_err(|err| io_err("write_jsonl", err))
    }

    pub(crate) fn key(&mut self, name: &str) -> Result<(), ExportError> {
        self.comma()?;
        // The key took the comma slot. The following value must not write one,
        // and the value's own comma() must leave the flag set for the next key.
        if let Some(flag) = self.needs_comma.last_mut() {
            *flag = false;
        }
        self.needs_comma.push(false);
        write_string(self.out, name)?;
        self.out
            .write_all(b":")
            .map_err(|err| io_err("write_jsonl", err))?;
        self.needs_comma.pop();
        Ok(())
    }

    pub(crate) fn string(&mut self, value: &str) -> Result<(), ExportError> {
        self.comma()?;
        write_string(self.out, value)
    }

    pub(crate) fn opt_string(&mut self, value: Option<&str>) -> Result<(), ExportError> {
        match value {
            Some(value) => self.string(value),
            None => self.null(),
        }
    }

    pub(crate) fn i64(&mut self, value: i64) -> Result<(), ExportError> {
        self.comma()?;
        write!(self.out, "{value}").map_err(|err| io_err("write_jsonl", err))
    }

    pub(crate) fn opt_i64(&mut self, value: Option<i64>) -> Result<(), ExportError> {
        match value {
            Some(value) => self.i64(value),
            None => self.null(),
        }
    }

    pub(crate) fn null(&mut self) -> Result<(), ExportError> {
        self.comma()?;
        self.out
            .write_all(b"null")
            .map_err(|err| io_err("write_jsonl", err))
    }

    /// Embed one already-validated JSON value. `comma` runs first so the next
    /// key still gets a separator; `write_embedded` itself does not.
    pub(crate) fn embed(&mut self, column: &'static str, text: &str) -> Result<(), ExportError> {
        self.comma()?;
        write_embedded(self.out, column, text)
    }

    fn comma(&mut self) -> Result<(), ExportError> {
        if let Some(flag) = self.needs_comma.last_mut() {
            if *flag {
                self.out
                    .write_all(b",")
                    .map_err(|err| io_err("write_jsonl", err))?;
            }
            *flag = true;
        }
        Ok(())
    }
}

pub(crate) fn write_embedded<W: Write>(
    out: &mut W,
    column: &'static str,
    text: &str,
) -> Result<(), ExportError> {
    if !is_json_value(text) {
        return Err(ExportError::BadStoredJson { column });
    }
    out.write_all(text.trim().as_bytes())
        .map_err(|err| io_err("write_jsonl", err))
}

fn write_string<W: Write>(out: &mut W, value: &str) -> Result<(), ExportError> {
    out.write_all(b"\"")
        .map_err(|err| io_err("write_jsonl", err))?;
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let escape: &[u8] = match b {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            0x08 => b"\\b",
            0x0c => b"\\f",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0x00..=0x1f => {
                let hex = format!("\\u{b:04x}");
                out.write_all(hex.as_bytes())
                    .map_err(|err| io_err("write_jsonl", err))?;
                i += 1;
                continue;
            }
            _ => {
                let ch = value[i..].chars().next().unwrap_or('\u{FFFD}');
                let len = ch.len_utf8();
                out.write_all(&bytes[i..i + len])
                    .map_err(|err| io_err("write_jsonl", err))?;
                i += len;
                continue;
            }
        };
        out.write_all(escape)
            .map_err(|err| io_err("write_jsonl", err))?;
        i += 1;
    }
    out.write_all(b"\"")
        .map_err(|err| io_err("write_jsonl", err))
}

fn is_json_value(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = skip_ws(bytes, 0);
    if !parse_value(bytes, &mut i) {
        return false;
    }
    i = skip_ws(bytes, i);
    i == bytes.len()
}

fn parse_value(bytes: &[u8], i: &mut usize) -> bool {
    if *i >= bytes.len() {
        return false;
    }
    match bytes[*i] {
        b'n' => eat(bytes, i, b"null"),
        b't' => eat(bytes, i, b"true"),
        b'f' => eat(bytes, i, b"false"),
        b'"' => parse_string(bytes, i),
        b'{' => parse_object(bytes, i),
        b'[' => parse_array(bytes, i),
        b'-' | b'0'..=b'9' => parse_number(bytes, i),
        _ => false,
    }
}

fn eat(bytes: &[u8], i: &mut usize, lit: &[u8]) -> bool {
    if bytes[*i..].starts_with(lit) {
        *i += lit.len();
        true
    } else {
        false
    }
}

fn parse_object(bytes: &[u8], i: &mut usize) -> bool {
    *i += 1;
    *i = skip_ws(bytes, *i);
    if *i < bytes.len() && bytes[*i] == b'}' {
        *i += 1;
        return true;
    }
    loop {
        if !parse_string(bytes, i) {
            return false;
        }
        *i = skip_ws(bytes, *i);
        if *i >= bytes.len() || bytes[*i] != b':' {
            return false;
        }
        *i += 1;
        *i = skip_ws(bytes, *i);
        if !parse_value(bytes, i) {
            return false;
        }
        *i = skip_ws(bytes, *i);
        if *i >= bytes.len() {
            return false;
        }
        match bytes[*i] {
            b',' => {
                *i += 1;
                *i = skip_ws(bytes, *i);
            }
            b'}' => {
                *i += 1;
                return true;
            }
            _ => return false,
        }
    }
}

fn parse_array(bytes: &[u8], i: &mut usize) -> bool {
    *i += 1;
    *i = skip_ws(bytes, *i);
    if *i < bytes.len() && bytes[*i] == b']' {
        *i += 1;
        return true;
    }
    loop {
        if !parse_value(bytes, i) {
            return false;
        }
        *i = skip_ws(bytes, *i);
        if *i >= bytes.len() {
            return false;
        }
        match bytes[*i] {
            b',' => {
                *i += 1;
                *i = skip_ws(bytes, *i);
            }
            b']' => {
                *i += 1;
                return true;
            }
            _ => return false,
        }
    }
}

fn parse_string(bytes: &[u8], i: &mut usize) -> bool {
    if *i >= bytes.len() || bytes[*i] != b'"' {
        return false;
    }
    *i += 1;
    while *i < bytes.len() {
        match bytes[*i] {
            b'"' => {
                *i += 1;
                return true;
            }
            b'\\' => {
                *i += 1;
                if *i >= bytes.len() {
                    return false;
                }
                match bytes[*i] {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => *i += 1,
                    b'u' => {
                        *i += 1;
                        if *i + 4 > bytes.len() {
                            return false;
                        }
                        if !bytes[*i..*i + 4].iter().all(u8::is_ascii_hexdigit) {
                            return false;
                        }
                        *i += 4;
                    }
                    _ => return false,
                }
            }
            0x00..=0x1f => return false,
            _ => {
                // Advance one UTF-8 scalar. Invalid UTF-8 is not stored JSON we embed.
                let rest = &bytes[*i..];
                let Ok(text) = std::str::from_utf8(rest) else {
                    return false;
                };
                let Some(ch) = text.chars().next() else {
                    return false;
                };
                *i += ch.len_utf8();
            }
        }
    }
    false
}

fn parse_number(bytes: &[u8], i: &mut usize) -> bool {
    if *i < bytes.len() && bytes[*i] == b'-' {
        *i += 1;
    }
    if *i >= bytes.len() || !bytes[*i].is_ascii_digit() {
        return false;
    }
    if bytes[*i] == b'0' {
        *i += 1;
    } else {
        while *i < bytes.len() && bytes[*i].is_ascii_digit() {
            *i += 1;
        }
    }
    if *i < bytes.len() && bytes[*i] == b'.' {
        *i += 1;
        if *i >= bytes.len() || !bytes[*i].is_ascii_digit() {
            return false;
        }
        while *i < bytes.len() && bytes[*i].is_ascii_digit() {
            *i += 1;
        }
    }
    if *i < bytes.len() && (bytes[*i] == b'e' || bytes[*i] == b'E') {
        *i += 1;
        if *i < bytes.len() && (bytes[*i] == b'+' || bytes[*i] == b'-') {
            *i += 1;
        }
        if *i >= bytes.len() || !bytes[*i].is_ascii_digit() {
            return false;
        }
        while *i < bytes.len() && bytes[*i].is_ascii_digit() {
            *i += 1;
        }
    }
    true
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\n' | b'\r' | b'\t') {
        i += 1;
    }
    i
}
