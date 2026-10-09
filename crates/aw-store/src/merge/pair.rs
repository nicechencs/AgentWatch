//! Mirror pairing and clock-skew estimate.
//!
//! A flow on side A pairs with a flow on side B when, after NAT rewrite:
//!
//! - `proto` is the same (`tcp` or `udp`);
//! - A's local endpoint equals B's remote endpoint;
//! - A's remote endpoint equals B's local endpoint.
//!
//! Each flow is used at most once. When several mirrors exist, the one with
//! the smallest absolute start-time difference wins; a side with no start
//! time sorts after every timed candidate and can still pair.
//!
//! The skew estimate is the median of `B.start_ns - A.start_ns` over pairs
//! that have both times. It is [`None`] when that set is empty. Zero is a
//! real median (clocks agree), not a stand-in for "unknown".

use std::collections::BTreeMap;

use super::nat::NatMap;
use super::read::FlowFields;

/// Which export a flow came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The first file.
    A,
    /// The second file.
    B,
}

impl Side {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }
}

/// Median clock difference. `b_minus_a_ns` is side B's establish time minus
/// side A's. Positive means B's clock is ahead of A.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockSkew {
    /// Nanoseconds. Never used as "unknown".
    pub b_minus_a_ns: i64,
}

/// One paired connection. Evidence of the pair itself is always `I`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemotePair {
    /// Side A flow index in the loaded file.
    pub a_index: usize,
    /// Side B flow index in the loaded file.
    pub b_index: usize,
    /// Session id the B-side process lives in.
    pub to_session: i64,
    /// Process on side A.
    pub from_proc: i64,
    /// Process on side B.
    pub to_proc: i64,
    /// A's address after NAT, as text.
    pub a_ip: String,
    /// A's port after NAT.
    pub a_port: u16,
    /// B's address after NAT, as text.
    pub b_ip: String,
    /// B's port after NAT.
    pub b_port: u16,
    /// Bytes from A toward B, when both directions were observed. `None` if
    /// either side did not report the count. Not zero.
    pub bytes_a_to_b: Option<i64>,
    /// Bytes from B toward A. Same rule.
    pub bytes_b_to_a: Option<i64>,
    /// `B.start - A.start` when both times exist. Not part of the median by
    /// itself; the median is [`Paired::skew`].
    pub delta_ns: Option<i64>,
}

/// Result of one pairing pass. Unpaired counts include flows that had no tuple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paired {
    /// Matched mirrors.
    pub pairs: Vec<RemotePair>,
    /// Side A flows with no match.
    pub unpaired_a: u64,
    /// Side B flows with no match.
    pub unpaired_b: u64,
    /// Median of the timed deltas. `None` when no pair had both timestamps.
    pub skew: Option<ClockSkew>,
}

/// Pair `a` against `b`. Flows that cannot form a five-tuple stay unpaired.
pub fn pair_flows(a: &[FlowFields], b: &[FlowFields], nat: &NatMap) -> Paired {
    let mut b_by_key: BTreeMap<MirrorKey, Vec<usize>> = BTreeMap::new();
    let mut b_incomplete = 0_u64;
    for (idx, flow) in b.iter().enumerate() {
        match flow.mirror_key(nat) {
            Some(key) => b_by_key.entry(key).or_default().push(idx),
            None => b_incomplete += 1,
        }
    }

    let mut used_b = vec![false; b.len()];
    let mut pairs = Vec::new();
    let mut unpaired_a = 0_u64;

    // Timed candidates first would change which flow is left over when one
    // side has two flows to the same tuple. We walk A in file order and pick
    // the closest unused B, so the result does not depend on HashMap order.
    for (a_idx, flow) in a.iter().enumerate() {
        let Some(key) = flow.mirror_key(nat) else {
            unpaired_a += 1;
            continue;
        };
        let Some(candidates) = b_by_key.get(&key) else {
            unpaired_a += 1;
            continue;
        };
        let mut best: Option<(usize, Option<i64>)> = None;
        for &b_idx in candidates {
            if used_b[b_idx] {
                continue;
            }
            let delta = delta_ns(flow.start_ns, b[b_idx].start_ns);
            let better = match best {
                None => true,
                Some((_, best_delta)) => closer(delta, best_delta),
            };
            if better {
                best = Some((b_idx, delta));
            }
        }
        let Some((b_idx, delta)) = best else {
            unpaired_a += 1;
            continue;
        };
        used_b[b_idx] = true;
        let other = &b[b_idx];
        let (a_ip, a_port) = flow.local_after(nat);
        let (b_ip, b_port) = other.local_after(nat);
        pairs.push(RemotePair {
            a_index: a_idx,
            b_index: b_idx,
            to_session: other.session_id,
            from_proc: flow.proc_uid,
            to_proc: other.proc_uid,
            a_ip: a_ip.to_owned(),
            a_port,
            b_ip: b_ip.to_owned(),
            b_port,
            bytes_a_to_b: add_dir(flow.bytes_up, other.bytes_down),
            bytes_b_to_a: add_dir(flow.bytes_down, other.bytes_up),
            delta_ns: delta,
        });
    }

    let unpaired_b = used_b.iter().filter(|used| !**used).count() as u64;
    // Incomplete B flows were never inserted into the map, so they are already
    // inside `unpaired_b` via `used_b`. `b_incomplete` is only a cross-check.
    let _ = b_incomplete;
    debug_assert_eq!(
        unpaired_b,
        (b.len() as u64).saturating_sub(pairs.len() as u64)
    );

    let skew = median_skew(&pairs);
    Paired {
        pairs,
        unpaired_a,
        unpaired_b,
        skew,
    }
}

/// `Some` is closer than `None`. Smaller absolute delta wins. A tie keeps the
/// earlier candidate (file order), so this returns false on equal distance.
fn closer(candidate: Option<i64>, best: Option<i64>) -> bool {
    match (candidate, best) {
        (Some(next), Some(prev)) => next.unsigned_abs() < prev.unsigned_abs(),
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn delta_ns(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(b.saturating_sub(a)),
        _ => None,
    }
}

/// Prefer the side that observed a count. If both did and they differ, keep
/// `None`: the merge does not pick a winner and does not store 0.
fn add_dir(from_sender: Option<i64>, from_receiver: Option<i64>) -> Option<i64> {
    match (from_sender, from_receiver) {
        (Some(a), Some(b)) if a == b => Some(a),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        _ => None,
    }
}

fn median_skew(pairs: &[RemotePair]) -> Option<ClockSkew> {
    let mut deltas: Vec<i64> = pairs.iter().filter_map(|pair| pair.delta_ns).collect();
    if deltas.is_empty() {
        return None;
    }
    deltas.sort_unstable();
    let mid = deltas.len() / 2;
    let value = if deltas.len() % 2 == 1 {
        deltas[mid]
    } else {
        // Even count: average the two central values. Truncation toward zero
        // is at most 0.5 ns, far under the 50 ms acceptance bound.
        let left = deltas[mid - 1];
        let right = deltas[mid];
        left.saturating_add(right) / 2
    };
    Some(ClockSkew {
        b_minus_a_ns: value,
    })
}

/// Canonical mirror key: protocol plus the two endpoints ordered so that
/// (local, remote) and (remote, local) land on the same key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MirrorKey {
    proto: String,
    lo_ip: String,
    lo_port: u16,
    hi_ip: String,
    hi_port: u16,
}

impl FlowFields {
    fn mirror_key(&self, nat: &NatMap) -> Option<MirrorKey> {
        if !self.tuple_complete() {
            return None;
        }
        let proto = self.proto.to_ascii_lowercase();
        if proto != "tcp" && proto != "udp" {
            return None;
        }
        let (local_ip, local_port) = self.local_after(nat);
        let (remote_ip, remote_port) = self.remote_after(nat);
        let local = (local_ip, local_port);
        let remote = (remote_ip, remote_port);
        let (lo, hi) = if endpoint_ord(local) <= endpoint_ord(remote) {
            (local, remote)
        } else {
            (remote, local)
        };
        Some(MirrorKey {
            proto,
            lo_ip: lo.0.to_owned(),
            lo_port: lo.1,
            hi_ip: hi.0.to_owned(),
            hi_port: hi.1,
        })
    }

    pub(crate) fn local_after<'a>(&'a self, nat: &'a NatMap) -> (&'a str, u16) {
        match (self.local_ip.as_deref(), self.local_port) {
            (Some(ip), Some(port)) => nat.rewrite(ip, port),
            _ => ("", 0),
        }
    }

    fn remote_after<'a>(&'a self, nat: &'a NatMap) -> (&'a str, u16) {
        match (self.remote_ip.as_deref(), self.remote_port) {
            (Some(ip), Some(port)) => nat.rewrite(ip, port),
            _ => ("", 0),
        }
    }
}

fn endpoint_ord(endpoint: (&str, u16)) -> (&str, u16) {
    endpoint
}
