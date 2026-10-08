//! `aw ps` (P1-CLI-02).
//!
//! Lists processes the caller could attach to, as a tree. Rows come from a
//! [`ProcessTable`]. The production table is a stub and returns
//! [`PsError::Unavailable`]: this CLI does not read the operating system's
//! process list. Tests inject rows.
//!
//! `--agents-only` keeps rows whose executable base name is on
//! [`AGENT_NAMES`]. That list is a name match only. Full agent recognition is
//! P5; a hit here is not evidence that the process is an agent.

use std::io;

use serde_json::{json, Value};

use aw_core::Evidence;

use crate::exit;
use crate::output::{evidence_badge, evidence_code, OutputMode, Row, Table};

use super::render;
use super::Outcome;

/// Name stems treated as agents for `--agents-only`.
///
/// Comparison is on the executable base name, without a directory and without
/// `.exe`, case-insensitive. This is not agent detection: P5 owns that.
pub(crate) const AGENT_NAMES: [&str; 8] = [
    "claude", "codex", "cursor", "aider", "continue", "windsurf", "gemini", "copilot",
];

/// One process the table is willing to show. No command line: argv is not a
/// field here, so it cannot be printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessRow {
    /// Process id.
    pub pid: u32,
    /// Parent process id. `None` when the table does not know it (not `0`).
    pub parent: Option<u32>,
    /// Executable base name. Not a path.
    pub name: String,
    /// How this row was observed.
    pub evidence: Evidence,
}

/// Why the table produced no rows.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum PsError {
    /// No process source is wired.
    Unavailable { detail: String },
    /// `--filter` was rejected.
    BadFilter { detail: String },
}

impl std::fmt::Display for PsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable { detail } | Self::BadFilter { detail } => write!(f, "{detail}"),
        }
    }
}

/// Process list. Production returns [`PsError::Unavailable`].
pub(crate) trait ProcessTable {
    /// Processes visible to the caller.
    ///
    /// # Errors
    ///
    /// [`PsError::Unavailable`] when no source is wired, or [`PsError::BadFilter`].
    fn list(&mut self) -> Result<Vec<ProcessRow>, PsError>;
}

/// Production table. Does not call an OS process API.
#[derive(Debug, Default)]
pub(crate) struct UnwiredTable;

impl ProcessTable for UnwiredTable {
    fn list(&mut self) -> Result<Vec<ProcessRow>, PsError> {
        Err(PsError::Unavailable {
            detail: "process table is not available; the daemon process API is not connected. Run `aw daemon start`, or use `aw run --no-daemon` for launch mode (进程表不可用)".to_owned(),
        })
    }
}

/// Run `aw ps`.
pub(crate) fn run(
    agents_only: bool,
    filter: Option<&str>,
    json: bool,
    table: &mut dyn ProcessTable,
) -> Outcome {
    if let Some(text) = filter {
        if text.trim().is_empty() {
            return super::error_outcome(exit::USAGE, "usage", "--filter is empty", json);
        }
    }
    let rows = match table.list() {
        Ok(rows) => rows,
        Err(PsError::Unavailable { detail }) => {
            return super::error_outcome(exit::UNREACHABLE, "unreachable", &detail, json);
        }
        Err(PsError::BadFilter { detail }) => {
            return super::error_outcome(exit::USAGE, "usage", &detail, json);
        }
    };
    let filtered = select(&rows, agents_only, filter);
    let mode = OutputMode::from_json_flag(json);
    match write_ps(mode, &filtered, agents_only) {
        Ok(stdout) => Outcome {
            code: exit::OK,
            stdout,
            stderr: Vec::new(),
        },
        Err(err) => super::error_outcome(exit::GENERAL, "ps", &err.to_string(), json),
    }
}

/// Keep rows the flags ask for.
///
/// `--agents-only` matches [`AGENT_NAMES`] against the base name. `--filter` is
/// a case-insensitive substring of that same base name. Neither inspects argv.
fn select(rows: &[ProcessRow], agents_only: bool, filter: Option<&str>) -> Vec<ProcessRow> {
    let needle = filter.map(str::to_ascii_lowercase);
    rows.iter()
        .filter(|row| {
            if agents_only && !is_agent_name(&row.name) {
                return false;
            }
            if let Some(needle) = &needle {
                if !row.name.to_ascii_lowercase().contains(needle) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect()
}

/// `true` when `name` is on [`AGENT_NAMES`].
///
/// Strips one trailing `.exe` and ignores ASCII case. A path is reduced to its
/// last segment so a caller that passed a full path still matches the base
/// name. The match is the whole base name, not a substring, so `claude-helper`
/// is not `claude`.
pub(crate) fn is_agent_name(name: &str) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let base = base
        .strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".EXE"))
        .unwrap_or(base);
    let folded = base.to_ascii_lowercase();
    AGENT_NAMES.iter().any(|agent| folded == *agent)
}

fn write_ps(mode: OutputMode, rows: &[ProcessRow], agents_only: bool) -> io::Result<Vec<u8>> {
    let ordered = tree_order(rows);
    let rendered = Table {
        headers: vec!["tree".to_owned(), "pid".to_owned(), "name".to_owned()],
        rows: ordered
            .iter()
            .map(|(depth, row)| Row {
                cells: vec![
                    tree_cell(*depth, &row.name),
                    row.pid.to_string(),
                    row.name.clone(),
                ],
                evidence: row.evidence.clone(),
            })
            .collect(),
    };
    let doc = ps_json(&ordered, agents_only);
    let mut buf = Vec::new();
    render::write_out(&mut buf, mode, &rendered, &doc)?;
    Ok(buf)
}

fn tree_cell(depth: usize, name: &str) -> String {
    let mut cell = String::new();
    for _ in 0..depth {
        cell.push_str("  ");
    }
    if depth > 0 {
        cell.push_str("└ ");
    }
    cell.push_str(name);
    cell
}

/// Parents before children. A row whose parent is not in `rows` is a root.
/// Depth is the number of selected ancestors, so a filtered list does not
/// pretend a missing parent is pid 0.
fn tree_order(rows: &[ProcessRow]) -> Vec<(usize, ProcessRow)> {
    let mut remaining: Vec<ProcessRow> = rows.to_vec();
    let mut ordered: Vec<(usize, ProcessRow)> = Vec::with_capacity(rows.len());
    let mut guard = rows.len().saturating_add(1);
    while !remaining.is_empty() && guard > 0 {
        guard -= 1;
        let before = remaining.len();
        let mut index = 0;
        while index < remaining.len() {
            let parent = remaining[index].parent;
            let depth = match parent {
                Some(pid) => ordered
                    .iter()
                    .find(|(_, row)| row.pid == pid)
                    .map(|(depth, _)| depth + 1),
                None => Some(0),
            };
            let ready = depth.is_some() || !remaining.iter().any(|row| Some(row.pid) == parent);
            if ready {
                let row = remaining.remove(index);
                let depth = depth.unwrap_or(0);
                ordered.push((depth, row));
            } else {
                index += 1;
            }
        }
        if remaining.len() == before {
            // A cycle, or parents that only point at each other. Emit the rest
            // as roots rather than dropping them.
            for row in remaining.drain(..) {
                ordered.push((0, row));
            }
        }
    }
    ordered
}

fn ps_json(rows: &[(usize, ProcessRow)], agents_only: bool) -> Value {
    json!({
        "agents_only": agents_only,
        "agent_match": "name list; full recognition is P5",
        "rows": rows.iter().map(|(depth, row)| json!({
            "depth": depth,
            "pid": row.pid,
            "parent": row.parent,
            "name": row.name,
            "evidence": evidence_code(&row.evidence),
            "badge": evidence_badge(&row.evidence),
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{is_agent_name, run, ProcessRow, ProcessTable, PsError, AGENT_NAMES};
    use crate::exit;
    use aw_core::Evidence;

    struct Fixed(Vec<ProcessRow>);

    impl ProcessTable for Fixed {
        fn list(&mut self) -> Result<Vec<ProcessRow>, PsError> {
            Ok(self.0.clone())
        }
    }

    fn row(pid: u32, parent: Option<u32>, name: &str) -> ProcessRow {
        ProcessRow {
            pid,
            parent,
            name: name.to_owned(),
            evidence: Evidence::S,
        }
    }

    #[test]
    fn agents_only_keeps_name_matches() {
        let mut table = Fixed(vec![
            row(1, None, "claude"),
            row(2, Some(1), "node"),
            row(3, None, "codex.exe"),
            row(4, None, "Cursor"),
            row(5, None, "claude-helper"),
        ]);
        let outcome = run(true, None, false, &mut table);
        assert_eq!(outcome.code, exit::OK);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(text.contains("claude"), "{text}");
        assert!(text.contains("codex.exe"), "{text}");
        assert!(text.contains("Cursor"), "{text}");
        assert!(!text.contains("node"), "{text}");
        assert!(!text.contains("claude-helper"), "{text}");
        assert!(text.contains("S 采样"), "{text}");
        for name in AGENT_NAMES {
            assert!(is_agent_name(name));
        }
    }

    #[test]
    fn tree_indents_a_child() {
        let mut table = Fixed(vec![row(2, Some(1), "aider"), row(1, None, "claude")]);
        let outcome = run(false, None, false, &mut table);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        let claude = text
            .lines()
            .find(|line| line.contains("claude"))
            .expect("root");
        let aider = text
            .lines()
            .find(|line| line.contains("aider"))
            .expect("child");
        assert!(
            aider.find('a') > claude.find('c'),
            "child should be indented:\n{text}"
        );
    }
}
