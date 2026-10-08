//! Content-match decision (P3-PIPE-06).
//!
//! Pure comparison. No I/O, no file reads, no wording. The file side and the
//! request side each hand in a [`aw_core::ChunkSet`] produced by
//! [`aw_core::chunk`]. This module counts the overlap and applies the
//! thresholds from evidence-model §6.2.
//!
//! A match is `overlap >= min_chunks` (default 3) **and** `coverage >= min_coverage`
//! (default 0.2, meaning 20% of the file's chunks). Both are required. A file
//! with fewer than `min_chunks` chunks can still match when every one of its
//! chunks is in the request: that is the "small file, whole hit" case, and it
//! is reported as [`Verdict::Match`] only when coverage is 1.0 and the overlap
//! equals the file's chunk count. Below that it is a miss, not a match on a
//! single shared block.
//!
//! Nothing here renders a sentence. The caller picks `evidence.content_match`
//! or `infer.temporal_hash_miss`; those templates live elsewhere.

use aw_core::ChunkSet;

/// Default minimum overlapping chunks for a file that has at least this many.
pub const DEFAULT_MIN_CHUNKS: u32 = 3;

/// Default minimum fraction of the file's chunks that must overlap.
pub const DEFAULT_MIN_COVERAGE: f64 = 0.2;

/// Thresholds for one comparison.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MatchConfig {
    /// Overlap required when the file has at least this many chunks.
    pub min_chunks: u32,
    /// Required `overlap / file_chunks`. Range 0.0 to 1.0.
    pub min_coverage: f64,
}

impl Default for MatchConfig {
    fn default() -> Self {
        Self {
            min_chunks: DEFAULT_MIN_CHUNKS,
            min_coverage: DEFAULT_MIN_COVERAGE,
        }
    }
}

/// Why two sets were not compared.
///
/// These are structured reasons, not display strings. The pipeline maps them
/// onto `NA(too_large)`, `NA(file_changed)`, and the gap log; this module does
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// File or body was over the size cap. Nothing was read or hashed.
    TooLarge,
    /// Size or mtime changed between the two stat calls, so the bytes hashed
    /// would not be the bytes that were read.
    FileChanged,
    /// The file could not be opened.
    PermissionDenied,
    /// Degrade level is L2 or higher. Hashing is off.
    DegradeL2OrHigher,
    /// No process in this session read the file. It is not hashed.
    NotReadBySession,
    /// The request body used an encoding this build does not inflate (`br`,
    /// `zstd`, or a stacked encoding).
    UnsupportedEncoding,
}

/// Outcome of one file-against-request comparison.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Verdict {
    /// Both thresholds held (or the whole small file was present).
    Match {
        /// Chunks present on both sides.
        overlap: u32,
        /// `overlap / file_chunks`, in `0.0..=1.0`.
        coverage: f64,
    },
    /// Compared, and at least one threshold failed.
    Miss {
        /// Chunks present on both sides. Zero when the sets are disjoint.
        overlap: u32,
        /// `overlap / file_chunks`. `0.0` when the file had no chunks.
        coverage: f64,
    },
    /// Not compared. `reason` says which precondition failed.
    NotCompared {
        /// Why.
        reason: SkipReason,
    },
}

impl Verdict {
    /// `true` only for [`Verdict::Match`].
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match { .. })
    }
}

/// Compare a file's chunks with a request body's chunks.
///
/// `file_chunks` is the file's chunk count **before** de-duplication (repeated
/// identical chunks still count toward the file's length). `file` and `request`
/// are the distinct digests. Overlap is the size of the intersection.
///
/// A `file_chunks` of 0 is a miss with zero coverage, not a match: there was
/// nothing to cover. Pass [`SkipReason`] through [`Verdict::NotCompared`]
/// instead of calling this when the file was never hashed.
pub fn decide(file: &ChunkSet, request: &ChunkSet, file_chunks: u32, cfg: &MatchConfig) -> Verdict {
    if file_chunks == 0 || file.is_empty() {
        return Verdict::Miss {
            overlap: 0,
            coverage: 0.0,
        };
    }
    let overlap = intersection_len(file, request);
    let coverage = f64::from(overlap) / f64::from(file_chunks);
    let coverage = coverage.clamp(0.0, 1.0);

    let small_file = file_chunks < cfg.min_chunks;
    let whole_hit = small_file && overlap == file_chunks && (coverage - 1.0).abs() < f64::EPSILON;
    let thresholds = overlap >= cfg.min_chunks && coverage + f64::EPSILON >= cfg.min_coverage;

    if whole_hit || thresholds {
        Verdict::Match { overlap, coverage }
    } else {
        Verdict::Miss { overlap, coverage }
    }
}

fn intersection_len(a: &ChunkSet, b: &ChunkSet) -> u32 {
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let n = small.iter().filter(|d| large.contains(*d)).count();
    u32::try_from(n).unwrap_or(u32::MAX)
}
