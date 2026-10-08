//! `cargo xtask wording-lint [paths...]` (P3-CI-01).
//!
//! Checks product text against the banned-phrase table of evidence-model §7:
//! - `ui/src/i18n/**/*.json`: every line;
//! - `crates/aw-cli/src/**/*.rs`: string literals only;
//! - `crates/aw-pipeline/rules/*.toml`: every line, `#` comments excluded.
//!
//! `docs/` is never scanned: the docs quote the banned phrases as examples.
//!
//! Exemption: `// wording-lint: allow <reason>` (`# ...` in TOML) on the same
//! line, or alone on the line directly above. The reason is required; a bare
//! marker is itself an error. JSON has no comments, so i18n files have no
//! exemption: fix the text instead.
//!
//! Why this does not call `aw_pipeline::wording::lint`: that function exists
//! (`fn lint(&str) -> Vec<Violation>`), but its `UnprovableNegative` pattern
//! uses a look-behind `(?<!不)安全` that the `regex` crate rejects, so the first
//! call panics. aw-pipeline is outside this card's file scope, and depending on
//! it would also mean editing `xtask/Cargo.toml`. The matcher below mirrors the
//! same §7 rows and rule ids with plain substring search and no dependencies.
//! Once the pipeline pattern is fixed, swap `lint` for the pipeline one.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// One row of evidence-model §7. Same names as `aw_pipeline::wording::RuleId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleId {
    UploadedFile,
    Intent,
    BareEvilDomain,
    AgentRead,
    UnprovableNegative,
    ZeroBytes,
    AllTraffic,
    InstructedSteal,
    UploadedVia,
    ContentMatchPhrase,
}

/// One hit. `offset` is a byte index into the scanned text.
struct Violation {
    rule: RuleId,
    offset: usize,
    suggestion: &'static str,
}

/// Every occurrence of `needle`. ASCII needles match case-insensitively and
/// only on word boundaries, so `stole` does not fire inside `stolen`.
fn find_all(text: &str, needle: &str) -> Vec<usize> {
    let ascii = needle.is_ascii();
    let hay = if ascii {
        text.to_ascii_lowercase()
    } else {
        text.to_string()
    };
    let bytes = hay.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = hay[from..].find(needle) {
        let at = from + pos;
        let end = at + needle.len();
        let left_ok = !ascii || at == 0 || !is_ident(bytes[at - 1]);
        let right_ok = !ascii || end >= bytes.len() || !is_ident(bytes[end]);
        if left_ok && right_ok {
            out.push(at);
        }
        from = at + needle.len().max(1);
        while !hay.is_char_boundary(from) {
            from += 1;
        }
    }
    out
}

/// `first`, then within `gap` chars `second`. Offset is that of `first`.
fn find_pair(text: &str, first: &str, second: &str, min_gap: usize, gap: usize) -> Vec<usize> {
    let mut out = Vec::new();
    for at in find_all(text, first) {
        let rest = &text[at + first.len()..];
        let ascii = second.is_ascii();
        let rest_cmp = if ascii {
            rest.to_ascii_lowercase()
        } else {
            rest.to_string()
        };
        for (n, (i, _)) in rest_cmp.char_indices().enumerate() {
            if n > gap {
                break;
            }
            if n >= min_gap && rest_cmp[i..].starts_with(second) {
                out.push(at);
                break;
            }
        }
    }
    out
}

/// Scan `text` against every §7 row.
fn lint(text: &str) -> Vec<Violation> {
    let mut hits: Vec<(RuleId, usize)> = Vec::new();
    let mut add = |rule: RuleId, offsets: Vec<usize>| {
        hits.extend(offsets.into_iter().map(|o| (rule, o)));
    };
    // “已上传文件” asserts the same completed upload as “上传了文件” without
    // content evidence, so it is the same §7 row. (The pipeline regex misses it.)
    for n in ["上传了文件", "已上传文件", "uploaded file"] {
        add(RuleId::UploadedFile, find_all(text, n));
    }
    for n in ["泄露", "窃取", "外泄", "exfiltrated", "leaked", "stole"] {
        add(RuleId::Intent, find_all(text, n));
    }
    add(
        RuleId::BareEvilDomain,
        find_pair(text, "访问了", "evil.com", 0, 4),
    );
    for n in ["Agent 读取了", "agent read"] {
        add(RuleId::AgentRead, find_all(text, n));
    }
    for n in ["没有上传任何文件", "no data leaked"] {
        add(RuleId::UnprovableNegative, find_all(text, n));
    }
    // “安全” is banned; “不安全” is not (same carve-out as the pipeline rule).
    let safe: Vec<usize> = find_all(text, "安全")
        .into_iter()
        .filter(|&at| !text[..at].ends_with('不'))
        .collect();
    add(RuleId::UnprovableNegative, safe);
    let zero: Vec<usize> = find_all(text, "读取了")
        .into_iter()
        .filter(|&at| {
            let rest = text[at + "读取了".len()..].trim_start();
            rest.strip_prefix('0')
                .is_some_and(|r| r.trim_start().starts_with("字节"))
        })
        .collect();
    add(RuleId::ZeroBytes, zero);
    add(RuleId::ZeroBytes, find_all(text, "read 0 bytes"));
    for n in ["所有流量", "all traffic"] {
        add(RuleId::AllTraffic, find_all(text, n));
    }
    add(
        RuleId::InstructedSteal,
        find_pair(text, "让", "窃取了", 1, 40),
    );
    add(
        RuleId::InstructedSteal,
        find_pair(text, "instructed", "to steal", 1, 40),
    );
    add(
        RuleId::UploadedVia,
        find_pair(text, "通过", "上传了", 1, 40),
    );
    add(
        RuleId::UploadedVia,
        find_pair(text, "uploaded", " via", 1, 40),
    );
    add(
        RuleId::ContentMatchPhrase,
        find_pair(text, "内容与", "匹配", 0, 80),
    );
    for n in ["chunks identical to", "content matches"] {
        add(RuleId::ContentMatchPhrase, find_all(text, n));
    }
    hits.sort_by_key(|&(rule, offset)| (offset, rule as u8));
    hits.into_iter()
        .map(|(rule, offset)| Violation {
            rule,
            offset,
            suggestion: suggestion(rule),
        })
        .collect()
}

/// Template id named in the rewrite column (same as the pipeline table).
fn suggestion(rule: RuleId) -> &'static str {
    match rule {
        RuleId::UploadedFile => "infer.temporal",
        RuleId::Intent | RuleId::BareEvilDomain | RuleId::AllTraffic => "fact.net_send",
        RuleId::AgentRead => "fact.file_read",
        RuleId::UnprovableNegative => "gap.generic",
        RuleId::ZeroBytes => "fact.file_opened_read",
        RuleId::InstructedSteal => "delegation.chain",
        RuleId::UploadedVia => "ipc.channel",
        RuleId::ContentMatchPhrase => "evidence.content_match",
    }
}

const MARKER: &str = "wording-lint: allow";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Json,
    Rust,
    Toml,
}

impl Kind {
    fn of(path: &Path) -> Option<Kind> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("json") => Some(Kind::Json),
            Some("rs") => Some(Kind::Rust),
            Some("toml") => Some(Kind::Toml),
            _ => None,
        }
    }

    fn comment(self) -> Option<&'static str> {
        match self {
            Kind::Json => None,
            Kind::Rust => Some("//"),
            Kind::Toml => Some("#"),
        }
    }
}

/// A finding printed to the CI log. `line`/`col` are 1-based.
struct Hit {
    file: String,
    line: usize,
    col: usize,
    rule: RuleId,
    phrase: String,
    suggestion: &'static str,
}

struct Exemption {
    file: String,
    line: usize,
    reason: String,
    used: bool,
}

#[derive(Default)]
struct Report {
    files: usize,
    hits: Vec<Hit>,
    exemptions: Vec<Exemption>,
    /// Markers with no reason: `file:line`.
    bare_markers: Vec<String>,
}

pub fn run(args: &[String]) -> ExitCode {
    let root = repo_root();
    let targets: Vec<PathBuf> = if args.is_empty() {
        default_targets(&root)
    } else {
        let mut out = Vec::new();
        for arg in args {
            let path = PathBuf::from(arg);
            let path = if path.is_absolute() {
                path
            } else {
                root.join(path)
            };
            if !path.exists() {
                eprintln!("wording-lint: 路径不存在：{arg}");
                return ExitCode::from(2);
            }
            collect(&path, true, &mut out);
        }
        out
    };

    let mut files: Vec<PathBuf> = targets.into_iter().filter(|p| !is_docs(&root, p)).collect();
    files.sort();
    files.dedup();

    let mut report = Report::default();
    for path in &files {
        let Some(kind) = Kind::of(path) else { continue };
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) => {
                eprintln!("wording-lint: 无法读取 {}：{err}", display(&root, path));
                return ExitCode::from(2);
            }
        };
        report.files += 1;
        scan_file(&display(&root, path), kind, &text, &mut report);
    }

    print_report(&report);
    if report.hits.is_empty() && report.bare_markers.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn repo_root() -> PathBuf {
    // xtask/ sits directly under the workspace root.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap_or(manifest).to_path_buf()
}

fn default_targets(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_ext(&root.join("ui/src/i18n"), "json", true, &mut out);
    collect_ext(&root.join("crates/aw-cli/src"), "rs", true, &mut out);
    collect_ext(
        &root.join("crates/aw-pipeline/rules"),
        "toml",
        false,
        &mut out,
    );
    out
}

fn collect(path: &Path, recursive: bool, out: &mut Vec<PathBuf>) {
    if path.is_file() {
        if Kind::of(path).is_some() {
            out.push(path.to_path_buf());
        }
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let name = entry.file_name();
            if recursive && name != "target" && name != "node_modules" && name != ".git" {
                collect(&p, recursive, out);
            }
        } else if Kind::of(&p).is_some() {
            out.push(p);
        }
    }
}

fn collect_ext(dir: &Path, ext: &str, recursive: bool, out: &mut Vec<PathBuf>) {
    let mut all = Vec::new();
    collect(dir, recursive, &mut all);
    out.extend(
        all.into_iter()
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some(ext)),
    );
}

fn is_docs(root: &Path, path: &Path) -> bool {
    path.strip_prefix(root)
        .ok()
        .and_then(|rel| rel.components().next())
        .is_some_and(|first| first.as_os_str() == "docs")
}

fn display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
/// A run of text to lint and its byte offset in the file.
struct Segment<'a> {
    start: usize,
    text: &'a str,
}

fn scan_file(name: &str, kind: Kind, text: &str, report: &mut Report) {
    let line_starts = line_starts(text);
    let lines: Vec<&str> = text.lines().collect();

    // Exemption markers, keyed by 1-based line.
    let mut exempt: Vec<(usize, usize)> = Vec::new(); // (line, index into report.exemptions)
    if let Some(comment) = kind.comment() {
        for (idx, line) in lines.iter().enumerate() {
            let Some(reason) = marker_reason(line, comment) else {
                continue;
            };
            let lineno = idx + 1;
            if reason.is_empty() {
                report.bare_markers.push(format!("{name}:{lineno}"));
                continue;
            }
            report.exemptions.push(Exemption {
                file: name.to_string(),
                line: lineno,
                reason,
                used: false,
            });
            exempt.push((lineno, report.exemptions.len() - 1));
        }
    }

    let segments = match kind {
        Kind::Json => line_segments(text, &line_starts, None),
        Kind::Toml => line_segments(text, &line_starts, Some('#')),
        Kind::Rust => rust_string_literals(text),
    };

    for seg in segments {
        for v in lint(seg.text) {
            let at = seg.start + v.offset;
            let (line, col) = line_col(text, &line_starts, at);
            if let Some(slot) = exemption_for(&exempt, &lines, kind, line) {
                report.exemptions[slot].used = true;
                continue;
            }
            report.hits.push(hit(name, line, col, &v, &text[at..]));
        }
    }
}

/// Text after `<comment> wording-lint: allow`, trimmed. `None` if no marker.
fn marker_reason(line: &str, comment: &str) -> Option<String> {
    let mut search = line;
    while let Some(pos) = search.find(comment) {
        let rest = search[pos + comment.len()..].trim_start();
        if let Some(reason) = rest.strip_prefix(MARKER) {
            return Some(reason.trim().to_string());
        }
        search = &search[pos + comment.len()..];
    }
    None
}

/// The marker covers its own line, and the next line when it stands alone.
fn exemption_for(
    exempt: &[(usize, usize)],
    lines: &[&str],
    kind: Kind,
    line: usize,
) -> Option<usize> {
    let comment = kind.comment()?;
    for &(marker_line, slot) in exempt {
        if marker_line == line {
            return Some(slot);
        }
        if marker_line + 1 == line {
            let own = lines.get(marker_line - 1).map_or("", |l| l.trim_start());
            if own.starts_with(comment) {
                return Some(slot);
            }
        }
    }
    None
}

fn hit(file: &str, line: usize, col: usize, v: &Violation, from: &str) -> Hit {
    // Violation carries no match length. Show up to 16 chars from the match
    // start, cut at end of line, so the log points at the phrase.
    let phrase: String = from
        .chars()
        .take_while(|c| *c != '\n' && *c != '\r' && *c != '"')
        .take(16)
        .collect();
    Hit {
        file: file.to_string(),
        line,
        col,
        rule: v.rule,
        phrase,
        suggestion: v.suggestion,
    }
}

fn line_starts(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
    starts
}

fn line_col(text: &str, starts: &[usize], at: usize) -> (usize, usize) {
    let idx = match starts.binary_search(&at) {
        Ok(i) => i,
        Err(i) => i - 1,
    };
    let col = text[starts[idx]..at].chars().count() + 1;
    (idx + 1, col)
}

/// One segment per line. With `comment`, text from an unquoted `comment`
/// char onward is dropped (TOML comments explain rules, they are not output).
fn line_segments<'a>(text: &'a str, starts: &[usize], comment: Option<char>) -> Vec<Segment<'a>> {
    let mut out = Vec::new();
    for (i, &start) in starts.iter().enumerate() {
        let end = starts.get(i + 1).map_or(text.len(), |&n| n);
        let mut line = &text[start..end];
        if let Some(c) = comment {
            line = strip_comment(line, c);
        }
        out.push(Segment { start, text: line });
    }
    out
}

fn strip_comment(line: &str, comment: char) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == comment => return &line[..i],
            None => {}
        }
    }
    line
}

/// Contents of every string literal in Rust source: `"…"`, `b"…"`, `r#"…"#`.
/// Comments and char literals are skipped. Escapes are left as written.
fn rust_string_literals(src: &str) -> Vec<Segment<'_>> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let prev_ident = i > 0 && is_ident(bytes[i - 1]);
        match b {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let mut depth = 1;
                i += 2;
                while i < bytes.len() && depth > 0 {
                    if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            b'r' if !prev_ident
                || (i > 0 && bytes[i - 1] == b'b' && (i < 2 || !is_ident(bytes[i - 2]))) =>
            {
                let mut j = i + 1;
                while bytes.get(j) == Some(&b'#') {
                    j += 1;
                }
                if bytes.get(j) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let hashes = j - i - 1;
                let start = j + 1;
                let mut k = start;
                let end = loop {
                    if k >= bytes.len() {
                        break bytes.len();
                    }
                    if bytes[k] == b'"'
                        && bytes[k + 1..]
                            .iter()
                            .take(hashes)
                            .filter(|c| **c == b'#')
                            .count()
                            == hashes
                    {
                        break k;
                    }
                    k += 1;
                };
                out.push(Segment {
                    start,
                    text: &src[start..end],
                });
                i = (end + 1 + hashes).min(bytes.len());
            }
            b'"' => {
                let start = i + 1;
                let mut k = start;
                while k < bytes.len() && bytes[k] != b'"' {
                    k += if bytes[k] == b'\\' { 2 } else { 1 };
                }
                let end = k.min(bytes.len());
                out.push(Segment {
                    start,
                    text: &src[start..end],
                });
                i = end + 1;
            }
            b'\'' => i = skip_char_literal(bytes, i),
            _ => i += 1,
        }
    }
    out
}

/// Past a char literal (`'x'`, `'\n'`, `'\u{..}'`, `'中'`), or one byte for a
/// lifetime / label.
fn skip_char_literal(bytes: &[u8], i: usize) -> usize {
    if bytes.get(i + 1) == Some(&b'\\') {
        let mut k = i + 2;
        while k < bytes.len() && bytes[k] != b'\'' && bytes[k] != b'\n' {
            k += 1;
        }
        return k + 1;
    }
    // One UTF-8 scalar then a closing quote.
    let mut k = i + 1;
    if k < bytes.len() {
        k += 1;
        while k < bytes.len() && (bytes[k] & 0xC0) == 0x80 {
            k += 1;
        }
        if bytes.get(k) == Some(&b'\'') {
            return k + 1;
        }
    }
    i + 1
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Banned phrase as written in evidence-model §7.
fn banned(rule: RuleId) -> &'static str {
    match rule {
        RuleId::UploadedFile => "“上传了文件” / “uploaded file”",
        RuleId::Intent => "“泄露”“窃取”“外泄”“exfiltrated”“leaked”“stole”",
        RuleId::BareEvilDomain => "“访问了 evil.com”（仅凭 IP 反查）",
        RuleId::AgentRead => "“Agent 读取了 X”（实际是子进程）",
        RuleId::UnprovableNegative => "“没有上传任何文件”“安全”“no data leaked”",
        RuleId::ZeroBytes => "“读取了 0 字节”（实际是 NA）",
        RuleId::AllTraffic => "“所有流量” / “all traffic”",
        RuleId::InstructedSteal => "“A 让 B 窃取了 …”",
        RuleId::UploadedVia => "“A 通过 B 上传了 …”",
        RuleId::ContentMatchPhrase => "“内容与……匹配”（仅限 evidence.content_match）",
    }
}

/// Rewrite column of evidence-model §7.
fn rewrite(rule: RuleId) -> &'static str {
    match rule {
        RuleId::UploadedFile => "使用 infer.temporal 模板",
        RuleId::Intent => "“发送了 N 字节”",
        RuleId::BareEvilDomain => "“连接了 1.2.3.4（推测域名：evil.com）”",
        RuleId::AgentRead => "写出具体进程和它与根进程的关系",
        RuleId::UnprovableNegative => "“在已观测范围内未发现 …”，并列出缺口",
        RuleId::ZeroBytes => "“读取字节数不可得”",
        RuleId::AllTraffic => "“已观测的流量”",
        RuleId::InstructedSteal => "使用 delegation.chain：逐跳陈述通道、调用与字节",
        RuleId::UploadedVia => "使用 ipc.channel + fact.net_send，或 delegation.chain",
        RuleId::ContentMatchPhrase => "只能由 evidence.content_match 模板渲染",
    }
}

fn print_report(report: &Report) {
    let mut out = String::new();
    for h in &report.hits {
        let _ = writeln!(
            out,
            "{}:{}:{}: 违规词 {}，命中片段「{}」；建议改写：{}（模板 {}）",
            h.file,
            h.line,
            h.col,
            banned(h.rule),
            h.phrase,
            rewrite(h.rule),
            h.suggestion,
        );
        // GitHub Actions annotation so the PR diff shows the line.
        let _ = writeln!(
            out,
            "::error file={},line={},col={}::wording-lint: {}，建议：{}",
            h.file,
            h.line,
            h.col,
            banned(h.rule),
            rewrite(h.rule),
        );
    }
    for m in &report.bare_markers {
        let _ = writeln!(out, "{m}: 豁免缺少原因，格式为 `// {MARKER} <原因>`");
        let _ = writeln!(out, "::error::wording-lint: {m} 豁免缺少原因");
    }

    let used = report.exemptions.iter().filter(|e| e.used).count();
    let _ = writeln!(
        out,
        "wording-lint: 扫描 {} 个文件，违规 {} 处，豁免 {} 条（生效 {} 条，未命中 {} 条），缺少原因的豁免 {} 条",
        report.files,
        report.hits.len(),
        report.exemptions.len(),
        used,
        report.exemptions.len() - used,
        report.bare_markers.len(),
    );
    for e in &report.exemptions {
        let state = if e.used { "生效" } else { "未命中" };
        let _ = writeln!(out, "  豁免 {}:{}（{state}）：{}", e.file, e.line, e.reason);
    }

    if report.hits.is_empty() && report.bare_markers.is_empty() {
        print!("{out}");
    } else {
        eprint!("{out}");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn scan(kind: Kind, text: &str) -> Report {
        let mut r = Report::default();
        scan_file("t", kind, text, &mut r);
        r
    }

    #[test]
    fn json_line_number() {
        let r = scan(
            Kind::Json,
            "{\n  \"a\": \"ok\",\n  \"b\": \"已上传文件\"\n}\n",
        );
        assert_eq!(r.hits.len(), 1);
        assert_eq!(r.hits[0].line, 3);
        assert_eq!(r.hits[0].rule, RuleId::UploadedFile);
    }

    #[test]
    fn rust_only_literals() {
        let src = "// 泄露 in a comment\nfn f() { let _ = 'x'; let s = \"数据泄露\"; }\n";
        let r = scan(Kind::Rust, src);
        assert_eq!(r.hits.len(), 1);
        assert_eq!(r.hits[0].line, 2);
    }

    #[test]
    fn rust_raw_string() {
        let r = scan(Kind::Rust, "const A: &str = r#\"all traffic\"#;\n");
        assert_eq!(r.hits.len(), 1);
    }

    #[test]
    fn allow_with_reason() {
        let src = "let s = \"泄露\"; // wording-lint: allow 测试反例\n// wording-lint: allow 下一行\nlet t = \"窃取\";\n";
        let r = scan(Kind::Rust, src);
        assert!(r.hits.is_empty());
        assert_eq!(r.exemptions.len(), 2);
        assert!(r.exemptions.iter().all(|e| e.used));
    }

    #[test]
    fn allow_without_reason_fails() {
        let r = scan(Kind::Rust, "let s = \"泄露\"; // wording-lint: allow\n");
        assert_eq!(r.hits.len(), 1);
        assert_eq!(r.bare_markers.len(), 1);
    }

    #[test]
    fn toml_comments_skipped() {
        let r = scan(
            Kind::Toml,
            "# 泄露 说明\nwording = \"fact.net_send\" # 窃取\nx = \"所有流量\"\n",
        );
        assert_eq!(r.hits.len(), 1);
        assert_eq!(r.hits[0].line, 3);
    }

    #[test]
    fn docs_excluded() {
        let root = Path::new("/repo");
        assert!(is_docs(root, Path::new("/repo/docs/a.md")));
        assert!(!is_docs(root, Path::new("/repo/ui/src/i18n/zh.json")));
    }
}
