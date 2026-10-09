//! JSON-RPC shape extraction. Labels and lengths only.
//!
//! Kept: `method`, `params.name` (tool name), `id` rendered as text, the frame
//! length the caller measured, the direction the caller observed, whether an
//! `error` key exists, and for `params.arguments` the key names, JSON types,
//! and value byte lengths.
//!
//! Not kept: argument values, `result` content, `error.message`, the raw JSON,
//! and any content hash of a value. A chunk hash would require holding the
//! value; this function does not.

use std::fmt;

use serde_json::Value;

use super::frame::MAX_FRAME_BYTES;

/// Key names longer than this many Unicode scalars are truncated.
pub const MAX_KEY_SCALARS: usize = 64;

/// JSON types recorded for an argument value. The value itself is not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgType {
    /// JSON string.
    String,
    /// JSON number.
    Number,
    /// JSON bool.
    Bool,
    /// JSON object.
    Object,
    /// JSON array.
    Array,
    /// JSON null.
    Null,
}

impl ArgType {
    fn label(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Bool => "bool",
            Self::Object => "object",
            Self::Array => "array",
            Self::Null => "null",
        }
    }

    fn from_value(value: &Value) -> Self {
        match value {
            Value::String(_) => Self::String,
            Value::Number(_) => Self::Number,
            Value::Bool(_) => Self::Bool,
            Value::Object(_) => Self::Object,
            Value::Array(_) => Self::Array,
            Value::Null => Self::Null,
        }
    }
}

impl fmt::Display for ArgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Why a frame produced no [`RpcExtract`].
///
/// Display and Debug print the label only. They never include the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractGap {
    /// The frame was empty or only whitespace.
    Empty,
    /// The frame was longer than [`MAX_FRAME_BYTES`] and was not parsed.
    Oversize,
    /// `serde_json` rejected the frame.
    NotJson,
    /// The frame was JSON but not an object.
    NotObject,
}

impl ExtractGap {
    /// Stable token used in the wrapper's one-line gap notice.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Oversize => "oversize",
            Self::NotJson => "not_json",
            Self::NotObject => "not_object",
        }
    }
}

impl fmt::Display for ExtractGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metadata of one JSON-RPC line. No argument values and no result content.
///
/// `Debug` prints method, tool name, id, lengths, direction, the error flag,
/// and argument key names. It does not print argument values because this
/// struct does not store them.
#[derive(Clone, PartialEq, Eq)]
pub struct RpcExtract {
    /// JSON-RPC `method`. Empty string when the object has no string method
    /// (a response has none). The key's absence is not a gap: the frame was
    /// still an object.
    pub method: String,
    /// `params.name` when that field is a string. Not `params` itself.
    pub tool_name: Option<String>,
    /// `id` as a string, or a number rendered in decimal. Other id types are
    /// omitted (`None`), not stringified via `Debug`.
    pub id: Option<String>,
    /// Frame length in bytes, measured by the caller (usually the raw line).
    pub req_bytes: u64,
    /// `"c2s"` or `"s2c"`, supplied by the caller. Not inferred.
    pub direction: String,
    /// `true` when the object has an `error` key. `error.message` is not copied.
    pub error_present: bool,
    /// Names of keys in `params.arguments`, when that value is an object.
    /// Each name is at most [`MAX_KEY_SCALARS`] Unicode scalars.
    pub arg_keys: Vec<String>,
    /// JSON type of each argument value, parallel to [`Self::arg_keys`].
    pub arg_types: Vec<ArgType>,
    /// UTF-8 byte length of each argument value's JSON encoding, parallel to
    /// [`Self::arg_keys`]. Not the length of the whole frame.
    pub arg_lengths: Vec<u64>,
}

impl fmt::Debug for RpcExtract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcExtract")
            .field("method", &self.method)
            .field("tool_name", &self.tool_name)
            .field("id", &self.id)
            .field("req_bytes", &self.req_bytes)
            .field("direction", &self.direction)
            .field("error_present", &self.error_present)
            .field("arg_keys", &self.arg_keys)
            .field("arg_types", &self.arg_types)
            .field("arg_lengths", &self.arg_lengths)
            .finish()
    }
}

impl fmt::Display for RpcExtract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "method={} direction={} bytes={} error={}",
            self.method, self.direction, self.req_bytes, self.error_present
        )
    }
}

/// Extract labels from one frame.
///
/// `direction` is recorded as given (`"c2s"` or `"s2c"`). `req_bytes` is the
/// caller's length of the raw frame. This function does not re-measure the
/// string if the caller already counted bytes, but it does refuse a frame
/// whose byte length exceeds [`MAX_FRAME_BYTES`].
///
/// # Errors
///
/// [`ExtractGap::Empty`], [`ExtractGap::Oversize`], [`ExtractGap::NotJson`],
/// or [`ExtractGap::NotObject`]. The error does not contain the frame.
pub fn extract(frame: &str, direction: &str, req_bytes: u64) -> Result<RpcExtract, ExtractGap> {
    if frame.trim().is_empty() {
        return Err(ExtractGap::Empty);
    }
    if frame.len() > MAX_FRAME_BYTES || req_bytes > u64::try_from(MAX_FRAME_BYTES).unwrap_or(u64::MAX)
    {
        return Err(ExtractGap::Oversize);
    }
    let value: Value = serde_json::from_str(frame).map_err(|_| ExtractGap::NotJson)?;
    let Some(obj) = value.as_object() else {
        return Err(ExtractGap::NotObject);
    };

    let method = obj
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let tool_name = obj
        .get("params")
        .and_then(Value::as_object)
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
        .map(truncate_scalars);
    let id = obj.get("id").and_then(render_id);
    let error_present = obj.contains_key("error");
    let (arg_keys, arg_types, arg_lengths) = argument_shape(obj.get("params"));

    Ok(RpcExtract {
        method,
        tool_name,
        id,
        req_bytes,
        direction: direction.to_owned(),
        error_present,
        arg_keys,
        arg_types,
        arg_lengths,
    })
}

fn render_id(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(truncate_scalars(text)),
        Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                Some(unsigned.to_string())
            } else {
                number.as_i64().map(|signed| signed.to_string())
            }
        }
        _ => None,
    }
}

fn argument_shape(params: Option<&Value>) -> (Vec<String>, Vec<ArgType>, Vec<u64>) {
    let Some(arguments) = params
        .and_then(Value::as_object)
        .and_then(|params| params.get("arguments"))
        .and_then(Value::as_object)
    else {
        return (Vec::new(), Vec::new(), Vec::new());
    };
    let mut keys = Vec::with_capacity(arguments.len());
    let mut types = Vec::with_capacity(arguments.len());
    let mut lengths = Vec::with_capacity(arguments.len());
    for (key, value) in arguments {
        keys.push(truncate_scalars(key));
        types.push(ArgType::from_value(value));
        lengths.push(json_byte_len(value));
    }
    (keys, types, lengths)
}

/// Byte length of the JSON encoding of `value`. A value that cannot be
/// re-encoded (it came from the parser, so this does not happen) is `0` only
/// as a last resort: the length is then unknown and is not invented as the
/// source length. Callers treat `0` as "this value encoded to nothing", which
/// only `Null` does not — null encodes to `null` (4). Encoding failure is the
/// only path to a real zero here besides an empty string.
fn json_byte_len(value: &Value) -> u64 {
    match serde_json::to_vec(value) {
        Ok(bytes) => u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        Err(_) => 0,
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
