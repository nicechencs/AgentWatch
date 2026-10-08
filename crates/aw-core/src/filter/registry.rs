//! Field registry: name to type to the record kinds it applies to.
//!
//! Unknown names are rejected by the parser. A known field used with a `kind`
//! it does not apply to is still parsed; the SQL compiler (P2-STORE-03) turns
//! that combination into an empty result plus a warning.

/// What a field's values look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// Free text. `:` is a glob, `~` is a substring.
    String,
    /// A path or name glob. `*` does not cross a separator, `**` does.
    Glob,
    /// An integer.
    Number,
    /// A byte count. Accepts `B`, `KB`/`MB`/`GB` (1000) and `KiB`/`MiB`/`GiB` (1024).
    Bytes,
    /// A span of time (`ms`, `s`, `m`, `h`, `d`), stored as nanoseconds.
    Duration,
    /// An instant. Accepts `+5m` (from session start) and `-10m` (from now).
    Time,
    /// `true` or `false`.
    Bool,
    /// One of a fixed set of tokens.
    Enum,
}

/// Which record category a field belongs to. `None` means every category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// Usable with any `kind`.
    Any,
    /// `proc`.
    Proc,
    /// `file`.
    File,
    /// `net`.
    Net,
    /// `dns`.
    Dns,
    /// `http`.
    Http,
    /// `agent`.
    Agent,
    /// `ipc`.
    Ipc,
    /// `rpc`.
    Rpc,
    /// `finding`.
    Finding,
}

/// One registered field.
#[derive(Debug, Clone, Copy)]
pub struct FieldInfo {
    /// Canonical name, including dots (`remote.ip`).
    pub name: &'static str,
    /// How its values parse.
    pub ty: FieldType,
    /// The record category it applies to.
    pub kind: FieldKind,
}

/// Every field in api-and-cli §4.3.
pub const FIELDS: &[FieldInfo] = &[
    FieldInfo {
        name: "kind",
        ty: FieldType::Enum,
        kind: FieldKind::Any,
    },
    FieldInfo {
        name: "time",
        ty: FieldType::Time,
        kind: FieldKind::Any,
    },
    FieldInfo {
        name: "evidence",
        ty: FieldType::Enum,
        kind: FieldKind::Any,
    },
    FieldInfo {
        name: "source",
        ty: FieldType::String,
        kind: FieldKind::Any,
    },
    FieldInfo {
        name: "proc",
        ty: FieldType::Glob,
        kind: FieldKind::Any,
    },
    FieldInfo {
        name: "pid",
        ty: FieldType::Number,
        kind: FieldKind::Any,
    },
    FieldInfo {
        name: "proc_uid",
        ty: FieldType::String,
        kind: FieldKind::Any,
    },
    FieldInfo {
        name: "subtree",
        ty: FieldType::String,
        kind: FieldKind::Any,
    },
    FieldInfo {
        name: "tag",
        ty: FieldType::String,
        kind: FieldKind::Any,
    },
    FieldInfo {
        name: "exe",
        ty: FieldType::Glob,
        kind: FieldKind::Proc,
    },
    FieldInfo {
        name: "argv",
        ty: FieldType::String,
        kind: FieldKind::Proc,
    },
    FieldInfo {
        name: "cwd",
        ty: FieldType::Glob,
        kind: FieldKind::Proc,
    },
    FieldInfo {
        name: "path",
        ty: FieldType::Glob,
        kind: FieldKind::File,
    },
    FieldInfo {
        name: "dir",
        ty: FieldType::Glob,
        kind: FieldKind::File,
    },
    FieldInfo {
        name: "op",
        ty: FieldType::Enum,
        kind: FieldKind::File,
    },
    FieldInfo {
        name: "access",
        ty: FieldType::Enum,
        kind: FieldKind::File,
    },
    FieldInfo {
        name: "bytes_read",
        ty: FieldType::Bytes,
        kind: FieldKind::File,
    },
    FieldInfo {
        name: "bytes_written",
        ty: FieldType::Bytes,
        kind: FieldKind::File,
    },
    FieldInfo {
        name: "domain",
        ty: FieldType::Glob,
        kind: FieldKind::Net,
    },
    FieldInfo {
        name: "ip",
        ty: FieldType::String,
        kind: FieldKind::Net,
    },
    FieldInfo {
        name: "port",
        ty: FieldType::Number,
        kind: FieldKind::Net,
    },
    FieldInfo {
        name: "remote.ip",
        ty: FieldType::String,
        kind: FieldKind::Net,
    },
    FieldInfo {
        name: "remote.port",
        ty: FieldType::Number,
        kind: FieldKind::Net,
    },
    FieldInfo {
        name: "local.port",
        ty: FieldType::Number,
        kind: FieldKind::Net,
    },
    FieldInfo {
        name: "proto",
        ty: FieldType::Enum,
        kind: FieldKind::Net,
    },
    FieldInfo {
        name: "bytes_up",
        ty: FieldType::Bytes,
        kind: FieldKind::Net,
    },
    FieldInfo {
        name: "bytes_down",
        ty: FieldType::Bytes,
        kind: FieldKind::Net,
    },
    FieldInfo {
        name: "direct",
        ty: FieldType::Bool,
        kind: FieldKind::Net,
    },
    FieldInfo {
        name: "via_proxy",
        ty: FieldType::Bool,
        kind: FieldKind::Net,
    },
    FieldInfo {
        name: "qname",
        ty: FieldType::Glob,
        kind: FieldKind::Dns,
    },
    FieldInfo {
        name: "qtype",
        ty: FieldType::String,
        kind: FieldKind::Dns,
    },
    FieldInfo {
        name: "rcode",
        ty: FieldType::Number,
        kind: FieldKind::Dns,
    },
    FieldInfo {
        name: "method",
        ty: FieldType::Enum,
        kind: FieldKind::Http,
    },
    FieldInfo {
        name: "url",
        ty: FieldType::String,
        kind: FieldKind::Http,
    },
    FieldInfo {
        name: "host",
        ty: FieldType::Glob,
        kind: FieldKind::Http,
    },
    FieldInfo {
        name: "status",
        ty: FieldType::Number,
        kind: FieldKind::Http,
    },
    FieldInfo {
        name: "req_bytes",
        ty: FieldType::Bytes,
        kind: FieldKind::Http,
    },
    FieldInfo {
        name: "resp_bytes",
        ty: FieldType::Bytes,
        kind: FieldKind::Http,
    },
    FieldInfo {
        name: "tool",
        ty: FieldType::String,
        kind: FieldKind::Agent,
    },
    FieldInfo {
        name: "agent",
        ty: FieldType::String,
        kind: FieldKind::Agent,
    },
    FieldInfo {
        name: "ipc_kind",
        ty: FieldType::Enum,
        kind: FieldKind::Ipc,
    },
    FieldInfo {
        name: "peer",
        ty: FieldType::String,
        kind: FieldKind::Ipc,
    },
    FieldInfo {
        name: "channel",
        ty: FieldType::String,
        kind: FieldKind::Ipc,
    },
    FieldInfo {
        name: "target",
        ty: FieldType::String,
        kind: FieldKind::Rpc,
    },
    FieldInfo {
        name: "rule",
        ty: FieldType::String,
        kind: FieldKind::Finding,
    },
    FieldInfo {
        name: "severity",
        ty: FieldType::Enum,
        kind: FieldKind::Finding,
    },
];

/// Look up a field by its exact name.
pub fn lookup(name: &str) -> Option<&'static FieldInfo> {
    FIELDS.iter().find(|f| f.name == name)
}

/// The registered name with the smallest edit distance, when it is close enough
/// to be worth suggesting. `None` when nothing is close.
pub fn suggest(name: &str) -> Option<&'static str> {
    let mut best: Option<(&str, usize)> = None;
    for field in FIELDS {
        let distance = edit_distance(name, field.name);
        if distance > 0 && distance <= 2 && best.is_none_or(|(_, d)| distance < d) {
            best = Some((field.name, distance));
        }
    }
    best.map(|(name, _)| name)
}

/// Levenshtein distance over bytes. Field names are short ASCII identifiers.
fn edit_distance(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}
