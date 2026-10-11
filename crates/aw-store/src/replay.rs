//! Deterministic replay markers for bounded writer transactions.
//!
//! The marker is derived only from the already-redacted row content.  It is
//! not a database write time, a random value, or an in-process address: a
//! delivery retried after another 500-row chunk committed produces the same
//! marker on every platform and process.

use rusqlite::{params, Connection};

use crate::error::StoreError;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x100_0000_01b3;

/// Incrementally encode fields without retaining their text.
///
/// Length prefixes make `("ab", "c")` distinct from `("a", "bc")`.
pub(crate) struct KeyBuilder {
    hash: u64,
}

impl KeyBuilder {
    pub(crate) fn new(table: &str) -> Self {
        let mut out = Self { hash: FNV_OFFSET };
        out.text(table);
        out
    }

    pub(crate) fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    pub(crate) fn opt_text(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.text(value);
            }
            None => self.byte(0),
        }
    }

    pub(crate) fn i64(&mut self, value: i64) {
        self.bytes(&value.to_le_bytes());
    }

    pub(crate) fn opt_i64(&mut self, value: Option<i64>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.i64(value);
            }
            None => self.byte(0),
        }
    }

    pub(crate) fn finish(self) -> String {
        format!("{:016x}", self.hash)
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.mix(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
        self.mix(bytes);
    }

    fn byte(&mut self, byte: u8) {
        self.mix(&[byte]);
    }

    fn mix(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.hash ^= u64::from(*byte);
            self.hash = self.hash.wrapping_mul(FNV_PRIME);
        }
    }
}

/// A deterministic negative SQLite id for rows whose legacy caller left `id`
/// to SQLite.  Negative ids cannot collide with SQLite's normal positive rowid
/// allocation.  The caller has already included its table name in `key`.
pub(crate) fn deterministic_id(key: &str) -> i64 {
    let mut hash = FNV_OFFSET;
    for byte in key.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    i64::from_ne_bytes((hash | (1_u64 << 63)).to_ne_bytes())
}

/// Claim a content-derived row marker in the same transaction as the write.
///
/// `false` means this exact row was committed by an earlier chunk, so callers
/// must leave their table untouched.  The table contains only the short hash,
/// never paths, argv, URLs, headers, or any other source text.
pub(crate) fn claim(
    conn: &Connection,
    table: &'static str,
    key: &str,
    session_id: Option<i64>,
) -> Result<bool, StoreError> {
    let changed = conn
        .execute(
            "INSERT INTO replay_writes (table_name, row_key, session_id) VALUES (?1, ?2, ?3)
             ON CONFLICT(table_name, row_key) DO NOTHING",
            params![table, key, session_id],
        )
        .map_err(|err| StoreError::sqlite("claim_replay_row", err))?;
    Ok(changed != 0)
}
