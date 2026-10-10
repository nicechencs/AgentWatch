//! P3-PIPE-06: content-match thresholds on synthetic digests.
//! These are not file contents. A match only means the digest sets overlap.

#![allow(clippy::expect_used)]

use aw_core::{chunk_bytes, ChunkSet};
use aw_pipeline::content_match::{decide, MatchConfig, SkipReason, Verdict};

fn digests(count: u8) -> ChunkSet {
    (0..count)
        .map(|index| {
            let mut digest = [index; 32];
            digest[1] = index.wrapping_mul(3);
            digest
        })
        .collect()
}

#[test]
fn three_shared_chunks_covering_the_file_match() {
    let file = digests(4);
    let mut request = file.clone();
    request.extend(digests(2).into_iter().map(|mut digest| {
        digest[0] = digest[0].wrapping_add(100);
        digest
    }));
    let verdict = decide(&file, &request, 4, &MatchConfig::default());
    assert!(
        matches!(verdict, Verdict::Match { overlap: 4, .. }),
        "{verdict:?}"
    );
}

#[test]
fn one_shared_chunk_of_a_larger_file_is_a_miss() {
    let file = digests(5);
    let shared = file.iter().next().copied().expect("chunk");
    let mut request = ChunkSet::new();
    request.insert([9_u8; 32]);
    request.insert([10_u8; 32]);
    request.insert(shared);
    let verdict = decide(&file, &request, 5, &MatchConfig::default());
    assert!(
        matches!(verdict, Verdict::Miss { overlap: 1, .. }),
        "{verdict:?}"
    );
}

#[test]
fn a_whole_small_file_matches_and_a_partial_one_does_not() {
    let file = digests(2);
    let whole = decide(&file, &file, 2, &MatchConfig::default());
    assert!(
        matches!(whole, Verdict::Match { overlap: 2, .. }),
        "{whole:?}"
    );
    let shared = file.iter().next().copied().expect("chunk");
    let mut request = ChunkSet::new();
    request.insert(shared);
    let partial = decide(&file, &request, 2, &MatchConfig::default());
    assert!(
        matches!(partial, Verdict::Miss { overlap: 1, .. }),
        "{partial:?}"
    );
}

#[test]
fn an_empty_file_is_a_miss_and_a_skip_is_not_a_match() {
    let empty = chunk_bytes(b"").digests;
    let other = digests(3);
    let verdict = decide(&empty, &other, 0, &MatchConfig::default());
    assert_eq!(
        verdict,
        Verdict::Miss {
            overlap: 0,
            coverage: 0.0,
        }
    );
    let skipped = Verdict::NotCompared {
        reason: SkipReason::TooLarge,
    };
    assert!(!skipped.is_match());
}
