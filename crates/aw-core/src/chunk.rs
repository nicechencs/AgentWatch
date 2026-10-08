//! Content-defined chunking shared by the file side and the request side.
//!
//! This is a FastCDC-style chunker written in this crate. The `fastcdc` crate is
//! not in `Cargo.lock`, and this task must not add a dependency. Parameters match
//! the task card and evidence-model §6.2:
//!
//! - average chunk length about 256 B (`MASK_BITS = 8`, so a hit is expected once
//!   per 256 scanned bytes);
//! - minimum chunk length 64 B (the hash is not tested before that);
//! - maximum chunk length 1024 B (a hard cut when the mask never hits);
//! - an input shorter than 64 B is one whole chunk.
//!
//! A cut falls where a 64-byte sliding-window hash has its low 8 bits clear. The
//! window hash is a Gear rolling hash (one byte in, one byte out), which is the
//! content-defined cut FastCDC is built on. It is **not** [`crate::xxh3`]. That
//! function is one-shot, returns `None` above 240 bytes, and cannot roll a
//! window, so it cannot be the cut hash. The table below is still derived from
//! it: each Gear entry is `xxh3_64` of a 2-byte index, so the cut points are
//! pinned by code this crate already owns.
//!
//! Chunk bytes are then hashed with SHA-256 (`sha2 0.11.0`, already in the
//! lockfile). The task card names BLAKE3. BLAKE3 is not in the lockfile, so both
//! sides use SHA-256 instead. A match only means "these two sets were produced
//! by this module".
//!
//! # Streaming
//!
//! [`Chunker::push`] accepts any sequence of slices. Slices are appended to an
//! internal buffer and chunked only as a contiguous byte string, so the cut
//! points and the digest set match chunking the whole input at once. The buffer
//! is wiped with `zeroize` after each emitted chunk and when the chunker drops.
//!
//! # What this is not
//!
//! Gear tables differ between FastCDC implementations, so these cut points will
//! not match another library's. Do not compare these digests with hashes from
//! anywhere else.
//!
//! Digests are not file contents, but they confirm that a file's bytes appeared
//! in a request. [`Chunked`]'s `Debug` prints the count only.

use std::collections::BTreeSet;
use std::io::{self, Read};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::xxh3::xxh3_64;

/// Smallest chunk emitted, other than a final short tail.
pub const MIN_CHUNK: usize = 64;

/// Target chunk length. A boundary is expected about once per this many bytes.
pub const AVG_CHUNK: usize = 256;

/// Largest chunk. The chunker cuts here even when the mask never hit.
pub const MAX_CHUNK: usize = 1024;

/// Gear window, in bytes. Equal to [`MIN_CHUNK`].
const WINDOW: usize = 64;

/// Low bits that must be clear. `1 << 8 == 256`, which is [`AVG_CHUNK`].
const MASK_BITS: u32 = 8;

const MASK: u64 = (1u64 << MASK_BITS) - 1;

/// SHA-256 of one chunk's raw bytes.
pub type ChunkDigest = [u8; 32];

/// Ordered digest set. `BTreeSet` so two equal inputs always compare equal.
pub type ChunkSet = BTreeSet<ChunkDigest>;

/// How many chunks were cut, and their digests.
#[derive(Clone, PartialEq, Eq)]
pub struct Chunked {
    /// Chunks emitted. Duplicate chunk bytes share one digest, so this can be
    /// larger than `digests.len()`.
    pub chunk_count: u32,
    /// SHA-256 of each distinct chunk.
    pub digests: ChunkSet,
}

impl std::fmt::Debug for Chunked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chunked")
            .field("chunk_count", &self.chunk_count)
            .field("distinct", &self.digests.len())
            .finish_non_exhaustive()
    }
}

/// Streaming chunker. [`Self::push`] slices, then [`Self::finish`].
pub struct Chunker {
    /// Bytes not yet emitted as a finished chunk.
    pending: Vec<u8>,
    digests: ChunkSet,
    chunk_count: u32,
}

impl Default for Chunker {
    fn default() -> Self {
        Self::new()
    }
}

impl Chunker {
    /// Empty chunker. Nothing is retained.
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            digests: ChunkSet::new(),
            chunk_count: 0,
        }
    }

    /// Append `input`. Chunks whose end is no longer inside the trailing window
    /// are hashed and wiped.
    pub fn push(&mut self, input: &[u8]) {
        self.pending.extend_from_slice(input);
        self.drain_ready();
    }

    /// Hash the remaining tail, wipe the buffer, and return the set.
    ///
    /// An empty input yields `chunk_count == 0` and an empty set. That is "no
    /// bytes", not a hash of the empty string.
    pub fn finish(mut self) -> Chunked {
        if !self.pending.is_empty() {
            self.emit_chunk(self.pending.len());
        }
        self.pending.zeroize();
        Chunked {
            chunk_count: self.chunk_count,
            digests: std::mem::take(&mut self.digests),
        }
    }

    /// Emit every chunk that can no longer grow.
    ///
    /// A full window of bytes is kept past the searched region, so a later
    /// `push` extends the tail instead of being glued on after a premature cut.
    fn drain_ready(&mut self) {
        loop {
            if self.pending.len() <= MAX_CHUNK {
                // The tail may still grow into a longer chunk. Wait for more
                // bytes, or for `finish`.
                return;
            }
            let cut = find_cut(&self.pending[..MAX_CHUNK]).unwrap_or(MAX_CHUNK);
            self.emit_chunk(cut);
        }
    }

    fn emit_chunk(&mut self, len: usize) {
        debug_assert!(len > 0 && len <= self.pending.len());
        self.digests.insert(sha256(&self.pending[..len]));
        self.chunk_count = self.chunk_count.saturating_add(1);
        self.pending[..len].zeroize();
        self.pending.drain(..len);
    }
}

impl Drop for Chunker {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

/// Chunk a complete buffer. Same cuts and digests as any slicing of it.
pub fn chunk_bytes(input: &[u8]) -> Chunked {
    let mut chunker = Chunker::new();
    chunker.push(input);
    chunker.finish()
}

/// Read `reader` to the end and chunk it.
///
/// The read buffer is wiped before it is reused and before this returns. An
/// I/O error still wipes what was read. This function has no size cap; the
/// file hasher and the proxy apply their own.
pub fn chunk_reader(reader: &mut dyn Read) -> io::Result<Chunked> {
    let mut chunker = Chunker::new();
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                buf.zeroize();
                return Err(err);
            }
        };
        chunker.push(&buf[..n]);
        buf[..n].zeroize();
    }
    buf.zeroize();
    Ok(chunker.finish())
}

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> ChunkDigest {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// First cut in `bytes`, or `None` when `bytes` is shorter than [`MAX_CHUNK`]
/// and the mask never hit.
///
/// The caller passes at most [`MAX_CHUNK`] bytes. A hit returns the index just
/// past the matching window. No hit on a full [`MAX_CHUNK`] slice returns
/// [`MAX_CHUNK`].
fn find_cut(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < MIN_CHUNK {
        return None;
    }
    let gear = gear_table();
    let mut hash = gear_init(gear, &bytes[..WINDOW]);
    let mut pos = WINDOW;
    while pos < MIN_CHUNK {
        hash = gear_roll(gear, hash, bytes[pos - WINDOW], bytes[pos]);
        pos += 1;
    }
    let limit = bytes.len().min(MAX_CHUNK);
    while pos < limit {
        hash = gear_roll(gear, hash, bytes[pos - WINDOW], bytes[pos]);
        pos += 1;
        if hash & MASK == 0 {
            return Some(pos);
        }
    }
    if bytes.len() >= MAX_CHUNK {
        Some(MAX_CHUNK)
    } else {
        None
    }
}

fn gear_init(gear: &[u64; 256], window: &[u8]) -> u64 {
    debug_assert_eq!(window.len(), WINDOW);
    let mut hash = 0u64;
    for byte in window {
        hash = hash.wrapping_add(gear[usize::from(*byte)]);
    }
    hash
}

fn gear_roll(gear: &[u64; 256], hash: u64, outgoing: u8, incoming: u8) -> u64 {
    hash.wrapping_sub(gear[usize::from(outgoing)])
        .wrapping_add(gear[usize::from(incoming)])
}

fn gear_table() -> &'static [u64; 256] {
    GEAR.get_or_init(build_gear)
}

/// Built once. Each entry is `xxh3_64` of a 2-byte little-endian index, which
/// is well under that function's 240-byte limit, so every entry is `Some`.
static GEAR: OnceLock<[u64; 256]> = OnceLock::new();

fn build_gear() -> [u64; 256] {
    let mut out = [0u64; 256];
    for (i, slot) in out.iter_mut().enumerate() {
        let index = u16::try_from(i).unwrap_or(0);
        let bytes = index.to_le_bytes();
        // 2 bytes is inside the implemented range. A missing digest would make
        // every cut depend on a zero entry, so fall back to the index itself
        // rather than panic (this crate forbids unwrap in non-test code).
        *slot = xxh3_64(&bytes).unwrap_or(u64::from(index));
    }
    out
}
