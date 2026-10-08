//! Read one file and chunk-hash it (P3-PIPE-06).
//!
//! This is the only place the daemon reads file contents on purpose. The bytes
//! stay inside [`hash_file`]: they are fed to [`aw_core::chunk_reader`] and the
//! read buffer there is wiped before it returns. Nothing is logged. Nothing is
//! written to SQL; this module has no database types.
//!
//! Opening is a plain read-only `File::open`.
//!
//! `O_NOATIME` is **not** set. On Unix it needs a `libc` open flag (`O_NOATIME`)
//! and usually `CAP_FOWNER` unless the daemon owns the file; this crate does not
//! depend on `libc`, and a failed `O_NOATIME` open would hide a permission
//! error behind a retry. `FILE_FLAG_SEQUENTIAL_SCAN` is likewise not set: it is
//! a Windows `CreateFile` flag, and going through `OpenOptionsExt` for one hint
//! is not worth a platform branch in this file. The read is sequential anyway.
//!
//! Before reading, size and mtime are recorded. After reading they are recorded
//! again. A mismatch returns [`HashSkip::FileChanged`] and the chunks computed
//! along the way are dropped, not returned. A file larger than
//! [`HashFileLimits::max_bytes`] (default 10 MB) returns [`HashSkip::TooLarge`]
//! without a `read` call.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::time::SystemTime;

use aw_core::{ChunkSet, Chunked};

/// Default `correlation.max_hash_file_size`: 10 MB.
///
/// The session correlator is not in this crate yet, so nothing here calls
/// [`hash_file`]. `main` names this constant to keep the module linked.
pub const DEFAULT_MAX_HASH_FILE: u64 = 10 * 1024 * 1024;

/// Caps for one file hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashFileLimits {
    /// Files strictly larger than this are not read.
    pub max_bytes: u64,
}

impl Default for HashFileLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_HASH_FILE,
        }
    }
}

/// Digests of one file, plus the size that was hashed.
#[derive(Clone, PartialEq, Eq)]
pub struct FileChunks {
    /// Chunks emitted, counting duplicate chunk bytes.
    pub chunk_count: u32,
    /// Distinct chunk digests.
    pub digests: ChunkSet,
    /// Size in bytes at the moment hashing started. The second stat matched it.
    pub size: u64,
}

impl std::fmt::Debug for FileChunks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileChunks")
            .field("chunk_count", &self.chunk_count)
            .field("distinct", &self.digests.len())
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// The file was not hashed. Maps onto [`aw_pipeline::SkipReason`] at the call
/// site; this module does not depend on the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashSkip {
    /// `len` is over the cap. The file was not read.
    TooLarge {
        /// Size reported by the first stat.
        size: u64,
    },
    /// Size or mtime differed between the stat before the read and the stat
    /// after it, or the file disappeared mid-read.
    FileChanged,
    /// `open` failed. `kind` is the I/O kind, not the path and not the message
    /// (messages can embed the path).
    PermissionDenied {
        /// `std::io::ErrorKind` from the open.
        kind: io::ErrorKind,
    },
}

/// Why [`hash_file`] did not return chunks.
#[derive(Debug)]
pub enum FileHashError {
    /// A precondition failed. No digest is available.
    Skipped(HashSkip),
    /// The read itself failed, after the size check passed.
    Read(io::Error),
}

impl std::fmt::Display for FileHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Skipped(HashSkip::TooLarge { size }) => {
                write!(f, "file is {size} bytes, over the hash size cap")
            }
            Self::Skipped(HashSkip::FileChanged) => {
                write!(f, "file size or mtime changed while hashing")
            }
            Self::Skipped(HashSkip::PermissionDenied { kind }) => {
                write!(f, "opening file for hashing failed: {kind:?}")
            }
            Self::Read(err) => write!(f, "reading file for hashing: {err}"),
        }
    }
}

impl std::error::Error for FileHashError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(err) => Some(err),
            Self::Skipped(_) => None,
        }
    }
}

/// Stat, size-check, read, chunk, stat again.
///
/// `path` is not copied into the error. Callers that record a path already have
/// it from the file event. `main` holds a function pointer to this so the binary
/// links it before the session correlator exists.
pub fn hash_file(path: &Path, limits: &HashFileLimits) -> Result<FileChunks, FileHashError> {
    let before = stat_signature(path)?;
    if before.size > limits.max_bytes {
        return Err(FileHashError::Skipped(HashSkip::TooLarge {
            size: before.size,
        }));
    }

    let mut file = File::open(path)
        .map_err(|err| FileHashError::Skipped(HashSkip::PermissionDenied { kind: err.kind() }))?;
    // Cap the read as well as the stat. A file that grows past the cap between
    // the two is `FileChanged` below; we still must not pull it all in.
    let mut limited = file.by_ref().take(limits.max_bytes.saturating_add(1));
    let chunked = aw_core::chunk_reader(&mut limited).map_err(FileHashError::Read)?;
    // `chunk_reader` wipes its own buffer. Drop our handle before the second stat
    // so Windows can observe a concurrent replace.
    drop(file);

    let after = stat_signature(path)?;
    if after != before {
        return Err(FileHashError::Skipped(HashSkip::FileChanged));
    }
    // The size cap was checked before reading. A `take` that ended early would
    // mean the file shrank or the cap raced; the second stat catches the shrink.
    Ok(into_chunks(chunked, before.size))
}

fn into_chunks(chunked: Chunked, size: u64) -> FileChunks {
    FileChunks {
        chunk_count: chunked.chunk_count,
        digests: chunked.digests,
        size,
    }
}

#[derive(PartialEq, Eq)]
struct Signature {
    size: u64,
    mtime: Option<SystemTime>,
}

fn stat_signature(path: &Path) -> Result<Signature, FileHashError> {
    let meta = fs::metadata(path).map_err(|err| {
        // A missing file on the second stat is "changed", not "denied": the
        // open already succeeded. Callers of the first stat get the same
        // variant; the pipeline treats both as not-hashed-and-say-why.
        if err.kind() == io::ErrorKind::NotFound {
            FileHashError::Skipped(HashSkip::FileChanged)
        } else {
            FileHashError::Skipped(HashSkip::PermissionDenied { kind: err.kind() })
        }
    })?;
    Ok(Signature {
        size: meta.len(),
        mtime: meta.modified().ok(),
    })
}
