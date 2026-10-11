//! `aw config rules list` and `aw config rules test` (P3-CLI-01).
//!
//! `list` loads the compiled-in rules and, when `AW_RULES_DIR` names a
//! directory, the user `*.toml` files in it. That is the `rules.d/` overlay
//! from pipeline.md §3.6. A missing variable lists the built-in rules only.
//! This command does not open the daemon config file and does not open a
//! session database.
//!
//! `test` copies one rule file into a fresh temporary directory and loads it
//! with [`aw_pipeline::rules::load_with_user`]. The parent directory is not
//! scanned, so sibling rules are not loaded. The fixture is replayed through
//! [`aw_pipeline::rules::Engine`] on a [`VirtualClock`]. Findings that belong
//! to a built-in rule are dropped, so the output is the file under test.
//! This command does not resolve an endpoint, does not open a socket, and does
//! not read `agentwatch.db`. The clock moves to each record's own timestamp.
//! `--expect` compares the printed findings; a mismatch exits 1. A rule that
//! fails to load exits 1 and the message includes the 1-based line from
//! [`RuleError`].

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use aw_pipeline::rules::{
    Engine, EngineConfig, FindingDraft, ProcNode, RuleError, RuleRecord, RuleSet, VirtualClock,
};
use aw_pipeline::wording::{self, Lang};
use serde_json::{json, Map, Value};

use crate::exit;

use super::Outcome;

/// `aw config rules list`.
pub(crate) fn list(json_mode: bool) -> Outcome {
    let dir = std::env::var_os("AW_RULES_DIR").map(PathBuf::from);
    match aw_pipeline::rules::load_with_user(dir.as_deref()) {
        Ok(set) => list_outcome(&set, json_mode),
        Err(err) => load_outcome(err, json_mode),
    }
}

/// `aw config rules test <rule.toml> <fixture.jsonl> [--expect]`.
///
/// `lang` selects the wording table. `None` is `zh`.
pub(crate) fn test(
    rule_path: &str,
    fixture_path: &str,
    expect_path: Option<&str>,
    lang: Option<&str>,
    json_mode: bool,
) -> Outcome {
    let lang = match parse_lang(lang) {
        Ok(lang) => lang,
        Err(detail) => return super::error_outcome(exit::USAGE, "usage", &detail, json_mode),
    };
    let rule_path = Path::new(rule_path);
    if let Err(detail) = require_file(rule_path) {
        return super::error_outcome(exit::GENERAL, "rule", &detail, json_mode);
    }
    let loaded = match load_one(rule_path) {
        Ok(loaded) => loaded,
        Err(err) => return load_outcome(err, json_mode),
    };
    let records = match read_fixture(Path::new(fixture_path)) {
        Ok(records) => records,
        Err(detail) => {
            return super::error_outcome(exit::GENERAL, "fixture", &detail, json_mode);
        }
    };
    let findings = replay(&loaded.set, &loaded.rule_id, &records);
    let actual = findings_value(&findings, lang);
    if let Some(expect) = expect_path {
        match read_expect(Path::new(expect)) {
            Ok(expected) => {
                if canonical(&actual) != canonical(&expected) {
                    let detail = format!("发现结果与 {} 不匹配", Path::new(expect).display());
                    let mut outcome =
                        super::error_outcome(exit::GENERAL, "expect_mismatch", &detail, json_mode);
                    // The actual findings stay on stdout so the difference is visible
                    // without printing the fixture body.
                    let body = format!("{}\n", actual);
                    outcome.stdout = body.into_bytes();
                    return outcome;
                }
            }
            Err(detail) => {
                return super::error_outcome(exit::GENERAL, "expect", &detail, json_mode);
            }
        }
    }
    let text = if json_mode {
        format!("{actual}\n")
    } else {
        findings_text(&findings, lang)
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn parse_lang(lang: Option<&str>) -> Result<Lang, String> {
    match lang {
        None | Some("zh") => Ok(Lang::Zh),
        Some("en") => Ok(Lang::En),
        Some(other) => Err(format!("--lang `{other}` 不是 zh 或 en")),
    }
}

/// The loaded set plus the id of the file under test.
struct LoadedRule {
    set: RuleSet,
    /// Id of the rule the named file contributed. Built-in findings are dropped.
    rule_id: String,
}

/// One rule file, checked by the same loader the engine uses.
///
/// `parse_rule` is not re-exported and `RuleSet` has no public constructor, so
/// the file is copied into an empty temporary directory and loaded with
/// [`aw_pipeline::rules::load_with_user`]. Only that copy is read. The parent
/// of the named file is not scanned. The temporary directory is removed before
/// this function returns; the original file is not.
fn load_one(path: &Path) -> Result<LoadedRule, RuleError> {
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| RuleError::Io {
            path: path.to_path_buf(),
            detail: "规则路径没有文件名".to_owned(),
        })?;
    let scratch = TempDir::create().map_err(|err| RuleError::Io {
        path: path.to_path_buf(),
        detail: err,
    })?;
    let dest = scratch.path.join(name);
    fs::copy(path, &dest).map_err(|err| RuleError::Io {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })?;
    let set = aw_pipeline::rules::load_with_user(Some(scratch.path()))?;
    let rule_id = tested_rule_id(&set).ok_or_else(|| RuleError::Io {
        path: path.to_path_buf(),
        detail: "该文件没有加载为规则".to_owned(),
    })?;
    Ok(LoadedRule { set, rule_id })
}

/// The rule this file added.
///
/// A file that replaces a built-in rule is the one `overrides` records. A file
/// with a new id is the rule that is not in the compiled-in set. The directory
/// holds exactly one file, so at most one of those is true.
fn tested_rule_id(set: &RuleSet) -> Option<String> {
    if let Some(over) = set.overrides().last() {
        return Some(over.rule_id.clone());
    }
    let builtin = aw_pipeline::rules::load_builtin().ok()?;
    set.rules()
        .iter()
        .find(|rule| builtin.get(&rule.id).is_none())
        .map(|rule| rule.id.clone())
}

/// Replay `records` and keep findings of `rule_id` only.
///
/// The engine still sees the compiled-in rules, because that is the only set
/// `Engine::new` accepts. Their findings are not part of this file's result.
fn replay(set: &RuleSet, rule_id: &str, records: &[FixtureRecord]) -> Vec<FindingDraft> {
    let mut engine = Engine::new(set.clone(), EngineConfig::default());
    let mut clock = VirtualClock::new();
    let mut findings = Vec::new();
    for record in records {
        if let Some(node) = record.process {
            engine.observe_process(node);
        }
        if let Some(row) = &record.row {
            clock.advance_to(row.ts_ns());
            let step = engine.push(&clock, row);
            findings.extend(
                step.findings
                    .into_iter()
                    .filter(|finding| finding.rule_id == rule_id),
            );
        }
    }
    let tail = engine.finish(&clock);
    findings.extend(
        tail.findings
            .into_iter()
            .filter(|finding| finding.rule_id == rule_id),
    );
    findings
}

/// A directory under the system temp path, removed when dropped.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn create() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "aw-rules-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir(&path).map_err(|err| format!("创建 {} 失败：{err}", path.display()))?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// One fixture line. A process observation and a record may share a line.
struct FixtureRecord {
    process: Option<ProcNode>,
    row: Option<RuleRecord>,
}

fn read_fixture(path: &Path) -> Result<Vec<FixtureRecord>, String> {
    let text = fs::read_to_string(path).map_err(|err| file_read_error(path, "fixture", err))?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_no = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed)
            .map_err(|_| format!("{}:{line_no}：fixture 行不是 JSON", path.display()))?;
        records.push(
            fixture_record(&value)
                .map_err(|detail| format!("{}:{line_no}：{detail}", path.display()))?,
        );
    }
    Ok(records)
}

fn fixture_record(value: &Value) -> Result<FixtureRecord, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "fixture 行不是对象".to_owned())?;
    let process = match object.get("process") {
        Some(node) => Some(proc_node(node)?),
        None => None,
    };
    let row = if object.contains_key("record") || object.contains_key("record_type") {
        Some(rule_record(object)?)
    } else if process.is_some() {
        None
    } else {
        return Err("fixture 行既没有 record 也没有 process".to_owned());
    };
    Ok(FixtureRecord { process, row })
}

fn proc_node(value: &Value) -> Result<ProcNode, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "process 不是对象".to_owned())?;
    let proc_uid = required_u64(object, "proc_uid")?;
    let parent = optional_u64(object, "parent")?;
    Ok(ProcNode { proc_uid, parent })
}

fn rule_record(object: &Map<String, Value>) -> Result<RuleRecord, String> {
    let record_type =
        required_str(object, "record").or_else(|_| required_str(object, "record_type"))?;
    let id =
        optional_u64(object, "id")?.or_else(|| optional_u64(object, "record_id").ok().flatten());
    let id = id.ok_or_else(|| "record 缺少 id".to_owned())?;
    let ts_ns = required_u64(object, "ts_ns")?;
    let mut record = RuleRecord::new(record_type, id, ts_ns);
    if let Some(session) = optional_u64(object, "session")? {
        record = record.with_session(session);
    }
    if let Some(proc_uid) = optional_u64(object, "proc_uid")? {
        record = record.with_proc(proc_uid);
    }
    if let Some(fields) = object.get("fields") {
        for (key, value) in string_map(fields, "fields")? {
            record = record.text_field(&key, &value);
        }
    }
    if let Some(numbers) = object.get("numbers") {
        for (key, value) in number_map(numbers, "numbers")? {
            record = record.number_field(&key, value);
        }
    }
    if let Some(bools) = object.get("bools") {
        for (key, value) in bool_map(bools, "bools")? {
            record = record.bool_field(&key, value);
        }
    }
    if let Some(params) = object.get("params") {
        for (key, value) in string_map(params, "params")? {
            record = record.param(&key, &value);
        }
    }
    if let Some(tags) = object.get("tags") {
        let list = tags.as_array().ok_or_else(|| "tags 不是列表".to_owned())?;
        for tag in list {
            let tag = tag.as_str().ok_or_else(|| "tag 不是字符串".to_owned())?;
            record = record.tag(tag);
        }
    }
    Ok(record)
}

fn string_map(value: &Value, name: &str) -> Result<BTreeMap<String, String>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{name} 不是对象"))?;
    let mut out = BTreeMap::new();
    for (key, entry) in object {
        let text = entry
            .as_str()
            .ok_or_else(|| format!("{name}.{key} 不是字符串"))?;
        out.insert(key.clone(), text.to_owned());
    }
    Ok(out)
}

fn number_map(value: &Value, name: &str) -> Result<BTreeMap<String, i64>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{name} 不是对象"))?;
    let mut out = BTreeMap::new();
    for (key, entry) in object {
        let number = entry
            .as_i64()
            .ok_or_else(|| format!("{name}.{key} 不是整数"))?;
        out.insert(key.clone(), number);
    }
    Ok(out)
}

fn bool_map(value: &Value, name: &str) -> Result<BTreeMap<String, bool>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{name} 不是对象"))?;
    let mut out = BTreeMap::new();
    for (key, entry) in object {
        let flag = entry
            .as_bool()
            .ok_or_else(|| format!("{name}.{key} 不是布尔值"))?;
        out.insert(key.clone(), flag);
    }
    Ok(out)
}

fn required_str<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("缺少 {key}"))
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, String> {
    optional_u64(object, key)?.ok_or_else(|| format!("缺少 {key}"))
}

fn optional_u64(object: &Map<String, Value>, key: &str) -> Result<Option<u64>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let number = value
                .as_u64()
                .or_else(|| value.as_i64().and_then(|n| u64::try_from(n).ok()))
                .ok_or_else(|| format!("{key} 不是无符号整数"))?;
            Ok(Some(number))
        }
    }
}

fn read_expect(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|err| file_read_error(path, "expect", err))?;
    serde_json::from_str(&text).map_err(|_| format!("{} 不是 JSON", path.display()))
}

fn require_file(path: &Path) -> Result<(), String> {
    fs::metadata(path)
        .map(|_| ())
        .map_err(|err| file_read_error(path, "规则", err))
}

fn file_read_error(path: &Path, what: &str, err: std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::NotFound {
        format!("找不到文件：{}", path.display())
    } else {
        format!("读取 {what} {} 失败：{err}", path.display())
    }
}

/// Compare objects independent of key order. Arrays keep their order.
fn canonical(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned())
}

fn findings_value(findings: &[FindingDraft], lang: Lang) -> Value {
    json!({
        "findings": findings.iter().map(|finding| one_finding(finding, lang)).collect::<Vec<_>>(),
    })
}

fn one_finding(finding: &FindingDraft, lang: Lang) -> Value {
    let params: Vec<(&str, &str)> = finding
        .params
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let (text, error) = match wording::render(&finding.wording_id, &params, lang) {
        Ok(text) => (Some(text), None),
        Err(err) => (None, Some(err.to_string())),
    };
    json!({
        "rule_id": finding.rule_id,
        "rule_version": finding.rule_version,
        "kind": finding.kind,
        "evidence": finding.evidence,
        "severity": finding.severity,
        "wording_id": finding.wording_id,
        "text": text,
        "error": error,
        "count": finding.count,
        "first_ns": finding.ts_ns,
        "last_ns": finding.ts_ns,
        "refs": finding.refs.iter().map(|item| json!({
            "table": item.table,
            "id": item.id,
        })).collect::<Vec<_>>(),
    })
}

fn findings_text(findings: &[FindingDraft], lang: Lang) -> String {
    if findings.is_empty() {
        return "no findings\n".to_owned();
    }
    let mut lines = String::new();
    for finding in findings {
        let params: Vec<(&str, &str)> = finding
            .params
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let text = match wording::render(&finding.wording_id, &params, lang) {
            Ok(text) => text,
            Err(_) => "不可得".to_owned(),
        };
        lines.push_str(&format!(
            "{text}  {}  {}  {}  {}\n",
            finding.evidence, finding.count, finding.ts_ns, finding.ts_ns
        ));
    }
    lines
}

fn list_outcome(set: &RuleSet, json_mode: bool) -> Outcome {
    let text = if json_mode {
        format!("{}\n", list_json(set))
    } else {
        list_text(set)
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn list_text(set: &RuleSet) -> String {
    let mut lines = String::new();
    for rule in set.rules() {
        let kind = if rule.user_override {
            "user"
        } else {
            "builtin"
        };
        lines.push_str(&format!("{kind} {} v{}\n", rule.id, rule.version));
        if let Some(over) = set.overrides().iter().find(|item| item.rule_id == rule.id) {
            lines.push_str(&format!(
                "  overrides builtin v{} with {}\n",
                over.builtin_version,
                over.file.display()
            ));
        }
    }
    if lines.is_empty() {
        lines.push_str("no rules loaded\n");
    }
    lines
}

fn list_json(set: &RuleSet) -> Value {
    json!({
        "rules": set.rules().iter().map(|rule| {
            let over = set.overrides().iter().find(|item| item.rule_id == rule.id);
            json!({
                "id": rule.id,
                "version": rule.version,
                "builtin": !rule.user_override,
                "overrides": over.map(|item| json!({
                    "builtin_version": item.builtin_version,
                    "user_version": item.user_version,
                    "file": item.file.display().to_string(),
                })),
            })
        }).collect::<Vec<_>>(),
    })
}

fn load_outcome(err: RuleError, json_mode: bool) -> Outcome {
    let mut message = err.to_string();
    if let Some(line) = err.line() {
        if !message.contains(&format!(":{line}:")) {
            message = format!("{message}（第 {line} 行）");
        }
    }
    super::error_outcome(exit::GENERAL, "rule", &message, json_mode)
}
