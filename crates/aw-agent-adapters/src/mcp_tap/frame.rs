//! Newline-delimited frame splitter for MCP stdio (JSON-RPC lines).
//!
//! A frame is the bytes between `\n` delimiters, without the delimiter.
//! A trailing `\r` before `\n` is stripped (MCP clients send CRLF). The `\n`
//! itself is not part of the frame the parser sees; the wrapper still forwards
//! the original bytes, delimiter included.
//!
//! A frame whose length exceeds [`MAX_FRAME_BYTES`] is not parsed. The outcome
//! carries the reason `oversize` and the raw length, not the bytes.

use super::extract::ExtractGap;

/// 1 MiB. Larger than any MCP metadata frame this tool records, small enough
/// that one line cannot pin an unbounded buffer.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Why a completed line was not handed to the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The line was longer than [`MAX_FRAME_BYTES`].
    Oversize { len: u64 },
}

impl FrameError {
    /// Stable gap label. Not a payload.
    #[must_use]
    pub fn reason(self) -> ExtractGap {
        ExtractGap::Oversize
    }

    /// Raw frame length in bytes, delimiter excluded.
    #[must_use]
    pub fn len(self) -> u64 {
        match self {
            Self::Oversize { len } => len,
        }
    }

    /// True when the refused frame had no bytes. An oversize frame is never empty.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

/// One completed line, or a refusal to parse it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameOutcome {
    /// A line at or under the cap. Bytes are the frame without the newline.
    Frame(Vec<u8>),
    /// Not parsed. Length only.
    Gap(FrameError),
}

/// Incremental splitter. Feed socket or pipe chunks; it yields completed lines.
///
/// Incomplete trailing bytes stay in the buffer until [`Splitter::finish`] or
/// the next `\n`. [`Splitter::finish`] emits the tail as a frame when the
/// stream ends without a newline (a last JSON line with no terminator).
#[derive(Debug, Default)]
pub struct Splitter {
    buf: Vec<u8>,
    /// Once the current line has already passed the cap, further bytes are
    /// counted and discarded until `\n`. The payload is not retained.
    skipping: bool,
    skipped: u64,
}

impl Splitter {
    /// Empty splitter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes held for a line that has not ended. Not the skipped-oversize count.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    /// Push `input` and return every completed line.
    pub fn push(&mut self, input: &[u8]) -> Vec<FrameOutcome> {
        let mut out = Vec::new();
        for &byte in input {
            if byte == b'\n' {
                out.push(self.take_line());
                continue;
            }
            if self.skipping {
                self.skipped = self.skipped.saturating_add(1);
                continue;
            }
            if self.buf.len() >= MAX_FRAME_BYTES {
                // The cap is exceeded by this byte. Drop what was buffered and
                // count it, plus this byte. Do not keep the content.
                self.skipped = u64::try_from(self.buf.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1);
                self.buf.clear();
                self.skipping = true;
                continue;
            }
            self.buf.push(byte);
        }
        out
    }

    /// Emit a trailing line that had no newline, if any bytes remain.
    ///
    /// An empty tail (the stream ended on `\n`, or nothing was fed) emits nothing.
    pub fn finish(&mut self) -> Option<FrameOutcome> {
        if self.skipping {
            return Some(self.take_line());
        }
        if self.buf.is_empty() {
            return None;
        }
        Some(self.take_line())
    }

    fn take_line(&mut self) -> FrameOutcome {
        if self.skipping {
            let len = self.skipped;
            self.skipping = false;
            self.skipped = 0;
            self.buf.clear();
            return FrameOutcome::Gap(FrameError::Oversize { len });
        }
        if !self.buf.is_empty() && self.buf.last() == Some(&b'\r') {
            self.buf.pop();
        }
        let frame = std::mem::take(&mut self.buf);
        FrameOutcome::Frame(frame)
    }
}

/// Split a complete buffer the same way [`Splitter`] would, including a trailing
/// line with no newline. Convenience for tests and one-shot callers.
#[must_use]
pub fn push_frames(input: &[u8]) -> Vec<FrameOutcome> {
    let mut splitter = Splitter::new();
    let mut out = splitter.push(input);
    if let Some(tail) = splitter.finish() {
        out.push(tail);
    }
    out
}
