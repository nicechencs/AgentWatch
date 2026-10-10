//! `sim scan-secrets <db>` — byte-level scan of a SQLite database (and its
//! WAL / export files) for plaintext tokens that the redaction pipeline should
//! have removed.
//!
//! # Token corpus
//!
//! Patterns are taken from the same source as
//! `crates/aw-pipeline/src/redact/engine.rs` so the two stay in sync.  The
//! scan does NOT load the engine crate (sim must not depend on aw-*) — instead
//! it embeds a minimal replica of the regexes as byte-search patterns.
//!
//! To keep the scan fast we first check for a short fixed prefix before
//! running the regex, so most windows are discarded in one comparison.
//!
//! # Usage
//!
//!   sim scan-secrets <path/to/db>
//!
//! Exits 0 with "no tokens found" or prints matches and exits 1.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One detected token occurrence.
#[derive(Debug)]
pub struct Hit {
    pub file: PathBuf,
    pub rule: &'static str,
    /// Byte offset of the first character of the token.
    pub offset: usize,
    /// The matched bytes (truncated for safety).
    pub snippet: String,
}

/// Run `sim scan-secrets` from parsed CLI arguments.
pub fn run(args: Vec<String>) -> Result<(), String> {
    let opts = parse_args(args)?;
    let mut all_hits: Vec<Hit> = Vec::new();

    // Always scan the main db file plus WAL and SHM siblings if present.
    let paths = sibling_paths(&opts.db_path);
    for path in &paths {
        if path.exists() {
            let hits = scan_file(path)?;
            all_hits.extend(hits);
        }
    }

    // Also scan any extra paths the user passed.
    for extra in &opts.extra_paths {
        if extra.exists() {
            let hits = scan_file(extra)?;
            all_hits.extend(hits);
        }
    }

    if all_hits.is_empty() {
        println!(
            "scan-secrets: no plaintext tokens found in {} file(s) scanned",
            paths.len()
        );
        return Ok(());
    }

    // Group by rule.
    let mut by_rule: BTreeMap<&str, Vec<&Hit>> = BTreeMap::new();
    for hit in &all_hits {
        by_rule.entry(hit.rule).or_default().push(hit);
    }

    eprintln!(
        "FAIL: scan-secrets found {} plaintext token(s):",
        all_hits.len()
    );
    for (rule, hits) in &by_rule {
        eprintln!("  rule {rule}: {} occurrence(s)", hits.len());
        for h in hits.iter().take(3) {
            eprintln!(
                "    {} @ offset {} : {:?}",
                h.file.display(),
                h.offset,
                h.snippet
            );
        }
    }
    Err(format!("{} plaintext token(s) found", all_hits.len()))
}

fn parse_args(args: Vec<String>) -> Result<Opts, String> {
    let mut db_path = None;
    let mut extra_paths: Vec<PathBuf> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => {
                return Err("usage: sim scan-secrets <db_path> [<extra_file> ...]".to_string())
            }
            other if other.starts_with('-') => return Err(format!("unknown flag `{other}`")),
            other => {
                if db_path.is_none() {
                    db_path = Some(PathBuf::from(other));
                } else {
                    extra_paths.push(PathBuf::from(other));
                }
            }
        }
    }
    Ok(Opts {
        db_path: db_path.ok_or("scan-secrets requires a db path")?,
        extra_paths,
    })
}

struct Opts {
    db_path: PathBuf,
    extra_paths: Vec<PathBuf>,
}

fn sibling_paths(db: &Path) -> Vec<PathBuf> {
    let mut v = vec![db.to_path_buf()];
    let mut wal = db.to_path_buf();
    wal.set_extension("db-wal");
    v.push(wal);
    let mut shm = db.to_path_buf();
    shm.set_extension("db-shm");
    v.push(shm);
    v
}

/// Scan one file and return all hits.
pub fn scan_file(path: &Path) -> Result<Vec<Hit>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(scan_bytes(path, &bytes))
}

/// Scan a byte buffer for known token patterns.  Used directly in tests.
pub fn scan_bytes(path: &Path, bytes: &[u8]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for rule in RULES {
        for (offset, snippet) in find_pattern(bytes, rule) {
            hits.push(Hit {
                file: path.to_path_buf(),
                rule: rule.name,
                offset,
                snippet,
            });
        }
    }
    hits
}

/// One scanning rule: a fixed prefix (ASCII, for fast pre-filter) plus a
/// simple length constraint and character-class check.
struct ScanRule {
    name: &'static str,
    /// ASCII prefix that must be present for a match.
    prefix: &'static [u8],
    /// Minimum total token length (including prefix).
    min_len: usize,
    /// Maximum total token length (0 = unlimited up to 256).
    max_len: usize,
    /// Characters that extend the token after the prefix.
    char_class: CharClass,
}

#[derive(Clone, Copy)]
enum CharClass {
    UpperAlphaNum,     // A-Z 0-9
    AlphaNum,          // A-Za-z0-9
    AlphaNumDash,      // A-Za-z0-9-
    AlphaNumUnderDash, // A-Za-z0-9_-
    AlphaNumPlus,      // A-Za-z0-9_-+./=
}

impl CharClass {
    fn matches(self, b: u8) -> bool {
        match self {
            Self::UpperAlphaNum => b.is_ascii_uppercase() || b.is_ascii_digit(),
            Self::AlphaNum => b.is_ascii_alphanumeric(),
            Self::AlphaNumDash => b.is_ascii_alphanumeric() || b == b'-',
            Self::AlphaNumUnderDash => b.is_ascii_alphanumeric() || b == b'_' || b == b'-',
            Self::AlphaNumPlus => {
                b.is_ascii_alphanumeric()
                    || b == b'_'
                    || b == b'-'
                    || b == b'+'
                    || b == b'.'
                    || b == b'/'
                    || b == b'='
            }
        }
    }
}

static RULES: &[ScanRule] = &[
    ScanRule {
        name: "tok.aws_akid",
        prefix: b"AKIA",
        min_len: 20,
        max_len: 20,
        char_class: CharClass::UpperAlphaNum,
    },
    ScanRule {
        name: "tok.aws_akid_asia",
        prefix: b"ASIA",
        min_len: 20,
        max_len: 20,
        char_class: CharClass::UpperAlphaNum,
    },
    ScanRule {
        name: "tok.github",
        prefix: b"ghp_",
        min_len: 40,
        max_len: 260,
        char_class: CharClass::AlphaNum,
    },
    ScanRule {
        name: "tok.github_gho",
        prefix: b"gho_",
        min_len: 40,
        max_len: 260,
        char_class: CharClass::AlphaNum,
    },
    ScanRule {
        name: "tok.github_pat",
        prefix: b"github_pat_",
        min_len: 33,
        max_len: 270,
        char_class: CharClass::AlphaNumUnderDash,
    },
    ScanRule {
        name: "tok.anthropic",
        prefix: b"sk-ant-",
        min_len: 27,
        max_len: 200,
        char_class: CharClass::AlphaNumUnderDash,
    },
    ScanRule {
        name: "tok.openai",
        prefix: b"sk-proj-",
        min_len: 28,
        max_len: 200,
        char_class: CharClass::AlphaNumUnderDash,
    },
    ScanRule {
        name: "tok.openai_old",
        prefix: b"sk-",
        min_len: 23,
        max_len: 200,
        char_class: CharClass::AlphaNumUnderDash,
    },
    ScanRule {
        name: "tok.slack_bot",
        prefix: b"xoxb-",
        min_len: 15,
        max_len: 100,
        char_class: CharClass::AlphaNumDash,
    },
    ScanRule {
        name: "tok.slack_app",
        prefix: b"xoxa-",
        min_len: 15,
        max_len: 100,
        char_class: CharClass::AlphaNumDash,
    },
    ScanRule {
        name: "tok.google_api",
        prefix: b"AIza",
        min_len: 39,
        max_len: 39,
        char_class: CharClass::AlphaNumUnderDash,
    },
    ScanRule {
        name: "tok.stripe_test",
        prefix: b"sk_test_",
        min_len: 24,
        max_len: 100,
        char_class: CharClass::AlphaNum,
    },
    ScanRule {
        name: "tok.stripe_live",
        prefix: b"sk_live_",
        min_len: 24,
        max_len: 100,
        char_class: CharClass::AlphaNum,
    },
    // JWT: eyJ header.payload.signature — ASCII-safe portion only.
    ScanRule {
        name: "tok.jwt",
        prefix: b"eyJ",
        min_len: 36,
        max_len: 0, // unlimited (cap at 2048 in find_pattern)
        char_class: CharClass::AlphaNumPlus,
    },
];

/// Find all non-overlapping occurrences of `rule` in `bytes`.
fn find_pattern(bytes: &[u8], rule: &ScanRule) -> Vec<(usize, String)> {
    let max_len = if rule.max_len == 0 {
        2048
    } else {
        rule.max_len
    };
    let mut hits = Vec::new();
    let mut i = 0usize;
    while i + rule.prefix.len() <= bytes.len() {
        // Fast prefix scan.
        if bytes[i..].starts_with(rule.prefix) {
            // Extend with the continuation character class.
            let start = i;
            let mut end = i + rule.prefix.len();
            while end < bytes.len() && end - start < max_len && rule.char_class.matches(bytes[end])
            {
                end += 1;
            }
            let total = end - start;
            if total >= rule.min_len {
                // For JWT require a dot inside the token.
                let token = &bytes[start..end];
                if rule.name.starts_with("tok.jwt") && !token.contains(&b'.') {
                    i += rule.prefix.len();
                    continue;
                }
                let snippet = String::from_utf8_lossy(&token[..token.len().min(80)])
                    .chars()
                    .take(60)
                    .collect();
                hits.push((start, snippet));
                i = end; // skip past this token
                continue;
            }
        }
        i += 1;
    }
    hits
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod tests {
    use super::*;

    /// Canary token embedded in a SQLite-like byte stream.  The bytes around
    /// it are random-looking binary to simulate a real database page.
    fn make_test_db(token: &[u8]) -> Vec<u8> {
        // Realistic SQLite header magic + padding + token + trailing garbage.
        let mut buf = b"SQLite format 3\x00".to_vec();
        buf.extend_from_slice(&[0u8; 96]); // page-size bytes
        buf.extend_from_slice(b"INSERT INTO sessions VALUES('");
        buf.extend_from_slice(token);
        buf.extend_from_slice(b"');\x00\xff\xfe\xfd");
        buf
    }

    #[test]
    fn detects_aws_akid() {
        let token = b"AKIAIOSFODNN7EXAMPLE";
        let buf = make_test_db(token);
        let hits = scan_bytes(Path::new("test.db"), &buf);
        assert!(
            hits.iter().any(|h| h.rule.contains("aws_akid")),
            "expected aws_akid hit, got: {hits:?}"
        );
    }

    #[test]
    fn detects_anthropic_key() {
        let token = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let buf = make_test_db(token);
        let hits = scan_bytes(Path::new("test.db"), &buf);
        assert!(
            hits.iter().any(|h| h.rule == "tok.anthropic"),
            "expected tok.anthropic hit"
        );
    }

    #[test]
    fn detects_github_pat() {
        let token = b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let buf = make_test_db(token);
        let hits = scan_bytes(Path::new("test.db"), &buf);
        assert!(
            hits.iter().any(|h| h.rule.contains("github")),
            "expected github hit"
        );
    }

    #[test]
    fn detects_stripe_test_key() {
        let token = b"sk_test_AAAAAAAAAAAAAAAA";
        let buf = make_test_db(token);
        let hits = scan_bytes(Path::new("test.db"), &buf);
        assert!(
            hits.iter().any(|h| h.rule.contains("stripe")),
            "expected stripe hit"
        );
    }

    #[test]
    fn detects_jwt() {
        // Minimal JWT: header.payload.signature (each part base64url, no padding).
        let token = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let buf = make_test_db(token);
        let hits = scan_bytes(Path::new("test.db"), &buf);
        assert!(
            hits.iter().any(|h| h.rule.contains("jwt")),
            "expected jwt hit"
        );
    }

    #[test]
    fn no_false_positives_on_simbait() {
        // The SIMBAIT pattern used in bait_bytes must not trigger any rule.
        let buf = b"SIMBAIT-not-a-secret-SIMBAIT-not-a-secret-SIMBAIT-not-a-secret-".to_vec();
        let hits = scan_bytes(Path::new("test.db"), &buf);
        assert!(hits.is_empty(), "SIMBAIT triggered a rule: {hits:?}");
    }

    #[test]
    fn scan_file_on_temp_file() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "sim-scan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.db");
        let token = b"AKIAIOSFODNN7EXAMPLE";
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"garbage before ").unwrap();
        f.write_all(token).unwrap();
        f.write_all(b" garbage after").unwrap();
        drop(f);

        let hits = scan_file(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!hits.is_empty(), "expected a hit in temp file");
    }

    #[test]
    fn clean_file_returns_no_hits() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "sim-scan-clean-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clean.db");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"normal log output without any secrets here")
            .unwrap();
        drop(f);

        let hits = scan_file(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(hits.is_empty(), "unexpected hits: {hits:?}");
    }
}
