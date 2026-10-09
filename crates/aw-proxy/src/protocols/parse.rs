//! JSON-RPC object walk and SSE frame count.
//!
//! The JSON walk uses `serde_json`, which `aw-proxy` already depends on. Only
//! the first object is read. Argument values are counted and dropped. They are
//! not stored, not hashed, and not formatted.
//!
//! SSE counting follows the WHATWG HTML living standard (event stream format):
//! a frame is separated by a blank line, and a `data:` field is one data line.
//! This module counts frames that contain at least one `data:` field. It does
//! not keep the data, the event type, or the id.

use serde_json::{Map, Value};

use super::{ParseGap, MAX_KEY_SCALARS};

/// `data:` frames in one buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseCount {
    /// Frames that had at least one `data:` field.
    pub frames: u64,
    /// `true` only when the last line has no newline, so the buffer was cut.
    /// A complete buffer with zero `data:` frames has `frames == 0` and
    /// `truncated == false`. A finished frame that has no trailing blank line
    /// is still complete.
    pub truncated: bool,
}

/// Count `data:` frames in `input`.
///
/// Returns `None` when `input` is empty: an empty buffer was not observed, so
/// a count of zero would invent "a complete stream with no frames". `Some(0)`
/// is returned only for a non-empty buffer whose last line ends in a newline
/// and that contained no `data:` field (a comment, an `event:` with no
/// `data:`, a heartbeat). A stream that ends on its last field line, without
/// the blank line the HTML spec uses as a separator, is still complete: the
/// open frame is counted and `truncated` is false.
///
/// `truncated` is true only when the last line has no newline. The bytes of
/// that line were cut, so a `data:` field there may be a partial name and is
/// not counted. `data:` fields in earlier, newline-terminated lines are
/// counted. The payload after `data:` is discarded either way.
#[must_use]
pub fn count_sse(input: &[u8]) -> Option<SseCount> {
    if input.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(input);
    let mut frames: u64 = 0;
    let mut data_in_frame = false;
    let mut ended_with_newline = false;

    for line in text.split_inclusive('\n') {
        let Some(bare) = line.strip_suffix('\n') else {
            // Cut mid-line. Do not treat a partial `data` prefix as a field.
            break;
        };
        let bare = bare.strip_suffix('\r').unwrap_or(bare);
        ended_with_newline = true;
        if bare.is_empty() {
            if data_in_frame {
                frames = frames.saturating_add(1);
                data_in_frame = false;
            }
            continue;
        }
        if is_data_field(bare) {
            data_in_frame = true;
        }
    }

    if data_in_frame {
        frames = frames.saturating_add(1);
    }
    Some(SseCount {
        frames,
        truncated: !ended_with_newline,
    })
}

/// `data:` field, per the HTML event-stream grammar.
///
/// `strip_prefix("data:")` rejects a longer name such as `data-extra:`. One
/// optional space after the colon is the payload; it is not inspected.
fn is_data_field(line: &str) -> bool {
    line.starts_with("data:")
}

/// Fields kept from one JSON object. No values.
pub struct ParsedObject {
    pub method: Option<String>,
    pub target: Option<String>,
    pub arg_shape: Option<Value>,
    pub is_error: bool,
}

/// Parse one JSON object from `prefix`.
///
/// `prefix` is whatever the caller capped. [`serde_json::from_slice`] requires
/// the slice to be one JSON value and nothing after it, so a prefix that was
/// cut mid-value, or that still has the next byte past the cap, is
/// [`ParseGap::NotJson`]. The caller sets [`ParseGap::Truncated`] when it
/// knows the body continued. A complete value that is not an object is
/// [`ParseGap::NotObject`]. Neither gap carries the bytes.
///
/// `serde` itself is not a direct dependency of this crate. `serde_json` is,
/// and that is the only parser used here.
pub fn parse_object(prefix: &[u8]) -> Result<ParsedObject, ParseGap> {
    let value: Value = serde_json::from_slice(prefix).map_err(|_| ParseGap::NotJson)?;
    let Some(obj) = value.as_object() else {
        return Err(ParseGap::NotObject);
    };
    Ok(walk_object(obj))
}

fn walk_object(obj: &Map<String, Value>) -> ParsedObject {
    let method = obj
        .get("method")
        .and_then(Value::as_str)
        .map(truncate_scalars);
    let target = obj
        .get("params")
        .and_then(Value::as_object)
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
        .map(truncate_scalars);
    let arg_shape = obj.get("params").and_then(arg_shape_of);
    let is_error = obj.contains_key("error");
    ParsedObject {
        method,
        target,
        arg_shape,
        is_error,
    }
}

/// `{key: {"type": <json type>, "len": <byte length>}}` for `params.arguments`.
///
/// `None` when `params` is not an object or `arguments` is not an object.
/// Keys are truncated to [`MAX_KEY_SCALARS`] Unicode scalars. Length is the
/// UTF-8 length of the value's JSON encoding, not the length of the body.
/// The value itself is not inserted.
#[must_use]
pub fn arg_shape_of(params: &Value) -> Option<Value> {
    let arguments = params
        .as_object()
        .and_then(|params| params.get("arguments"))
        .and_then(Value::as_object)?;
    let mut shape = Map::new();
    for (key, value) in arguments {
        let key = truncate_scalars(key);
        let entry = serde_json::json!({
            "type": json_type_name(value),
            "len": json_byte_len(value),
        });
        shape.insert(key, entry);
    }
    Some(Value::Object(shape))
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn json_byte_len(value: &Value) -> u64 {
    // A value that came from the parser re-encodes. Failure is not a measured
    // length, so it is not reported as 0 (an empty string is the only value
    // whose encoding is empty, and that path returns Ok).
    match serde_json::to_vec(value) {
        Ok(bytes) => u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        Err(_) => u64::MAX,
    }
}

fn truncate_scalars(text: &str) -> String {
    let mut out = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index >= MAX_KEY_SCALARS {
            break;
        }
        out.push(ch);
    }
    out
}
