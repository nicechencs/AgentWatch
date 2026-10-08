//! TOML to [`Rule`](super::Rule).
//!
//! Validation happens here, before a rule can run:
//! - a rule with two or more steps must say `evidence = "I"`, unless it declares
//!   `kind = "fact_conjunction"`;
//! - `severity` is `info`, `notice`, or `warn`;
//! - `wording` is a key the wording catalog actually has, and every placeholder
//!   in that template is named by `emit.params`;
//! - `within` is at most [`MAX_WITHIN_NS`](super::MAX_WITHIN_NS) (10 minutes);
//! - `where` goes through [`aw_core::filter::parse`], not a second grammar.
//!
//! A failure names the file and the 1-based line of the offending field.

use std::path::Path;

use aw_core::filter::{self, FieldKind, FieldRef};

use super::ast::{
    EvidenceLevel, KeyField, MatchStep, Rule, Same, Severity, UpgradeIf, MAX_WITHIN_NS,
};
use super::error::RuleError;
use crate::wording::{self, Lang};

/// Record types a step may name, and the filter category their fields belong to.
const RECORD_TYPES: &[(&str, FieldKind)] = &[
    ("file_access", FieldKind::File),
    ("net_flow", FieldKind::Net),
    ("net_flow_bucket", FieldKind::Net),
    ("dns", FieldKind::Dns),
    ("http", FieldKind::Http),
    ("process", FieldKind::Proc),
    ("agent_event", FieldKind::Agent),
    ("content_match", FieldKind::Http),
    ("attribution_break", FieldKind::Any),
    ("self_report_mismatch", FieldKind::File),
];

/// Parse one rule file.
///
/// `file` is only used in error text. `None` marks a compiled-in rule.
pub fn parse_rule(source: &str, file: Option<&Path>) -> Result<Rule, RuleError> {
    let value: toml::Value = toml::from_str(source).map_err(|err| RuleError::Syntax {
        file: file.map(Path::to_path_buf),
        line: 1,
        detail: format!("the file is not valid TOML: {err}"),
    })?;
    let root = value
        .as_table()
        .ok_or_else(|| syntax(source, file, 0, "the file is not a table"))?;
    let rule = root
        .get("rule")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| syntax(source, file, 0, "missing [rule]"))?;

    let id = required_str(source, file, rule, "id")?;
    let version = required_int(source, file, &id, rule, "version")?;
    let title = required_str(source, file, rule, "title")?;
    let evidence_text = required_str(source, file, rule, "evidence")?;
    let wording_id = required_str(source, file, rule, "wording")?;
    let severity_text = required_str(source, file, rule, "severity")?;
    let kind_text = optional_str(rule, "kind");

    let evidence = parse_evidence(&evidence_text).ok_or_else(|| {
        invalid(
            source,
            file,
            &id,
            rule,
            "evidence",
            "evidence must be \"E1\", \"I\", or \"content_match\"",
        )
    })?;
    let severity = parse_severity(&severity_text).ok_or_else(|| {
        invalid(
            source,
            file,
            &id,
            rule,
            "severity",
            "severity must be \"info\", \"notice\", or \"warn\"",
        )
    })?;

    // `[[rule.match]]` is an array of tables nested inside the `rule` table.
    let matches = rule
        .get("match")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| invalid(source, file, &id, rule, "id", "missing [[rule.match]]"))?;
    if matches.is_empty() {
        return Err(invalid(
            source,
            file,
            &id,
            rule,
            "id",
            "a rule needs at least one match step",
        ));
    }
    let steps = parse_steps(source, file, &id, matches)?;

    check_wording(source, file, &id, rule, &wording_id)?;
    let kind = resolve_kind(
        &id,
        evidence,
        kind_text.as_deref(),
        steps.len(),
        source,
        file,
        rule,
    )?;

    let emit = rule
        .get("emit")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| invalid(source, file, &id, rule, "id", "missing [rule.emit]"))?;
    let key = parse_key(source, file, &id, emit, &steps)?;
    let upgrade_if = parse_upgrade(source, file, &id, emit, &steps)?;
    let params = parse_params(source, file, &id, emit)?;
    check_params_cover_template(source, file, &id, emit, &wording_id, &params)?;

    Ok(Rule {
        id,
        version,
        title,
        evidence,
        kind,
        wording: wording_id,
        severity,
        steps,
        key,
        upgrade_if,
        params,
        user_override: false,
    })
}

fn parse_steps(
    source: &str,
    file: Option<&Path>,
    id: &str,
    matches: &[toml::Value],
) -> Result<Vec<MatchStep>, RuleError> {
    let mut steps = Vec::with_capacity(matches.len());
    let mut seen_alias = Vec::new();
    for (index, entry) in matches.iter().enumerate() {
        let table = entry.as_table().ok_or_else(|| RuleError::Invalid {
            file: file.map(Path::to_path_buf),
            line: super::error::line_of(source, 0),
            rule_id: id.to_owned(),
            detail: "a match step must be a table".to_owned(),
        })?;
        let alias = required_str(source, file, table, "as")?;
        if !is_ident(&alias) {
            return Err(invalid(
                source,
                file,
                id,
                table,
                "as",
                "a step alias must be an identifier",
            ));
        }
        if seen_alias.iter().any(|have: &String| have == &alias) {
            return Err(invalid(
                source,
                file,
                id,
                table,
                "as",
                "a step alias is used twice",
            ));
        }
        let record = required_str(source, file, table, "record")?;
        let category = record_category(&record)
            .ok_or_else(|| invalid(source, file, id, table, "record", "unknown record type"))?;
        let where_raw = tighten_ops(&optional_str(table, "where").unwrap_or_default());
        let where_text = alias_fields(&where_raw);
        let pred = filter::parse(&where_text)
            .map(|expr| rewrite_tag_prefix(mark_aliases(expr, &where_raw)))
            .map_err(|err| RuleError::Where {
                file: file.map(Path::to_path_buf),
                line: field_line(source, table, "where"),
                rule_id: id.to_owned(),
                step: alias.clone(),
                detail: err.to_string(),
            })?;
        check_fields(
            &CheckCtx {
                source,
                file,
                id,
                table,
                step: &alias,
                earlier: &seen_alias,
            },
            &pred,
            category,
        )?;

        let within_ns = match optional_str(table, "within") {
            Some(text) => Some(parse_within(source, file, id, table, &text)?),
            None => None,
        };
        let same = match optional_str(table, "same") {
            Some(text) => Some(parse_same(&text).ok_or_else(|| {
                invalid(
                    source,
                    file,
                    id,
                    table,
                    "same",
                    "same must be \"session\", \"process\", or \"process_tree\"",
                )
            })?),
            None => None,
        };
        let threshold = match table.get("threshold") {
            Some(value) => Some(positive_int(value).ok_or_else(|| {
                invalid(
                    source,
                    file,
                    id,
                    table,
                    "threshold",
                    "threshold must be a positive integer",
                )
            })?),
            None => None,
        };

        if index == 0 && threshold.is_none() && (within_ns.is_some() || same.is_some()) {
            return Err(invalid(
                source,
                file,
                id,
                table,
                "within",
                "the first step has no earlier record to relate to",
            ));
        }
        if index > 0 && within_ns.is_none() {
            return Err(invalid(
                source,
                file,
                id,
                table,
                "within",
                "a later step needs within",
            ));
        }
        seen_alias.push(alias.clone());
        steps.push(MatchStep {
            alias,
            record,
            pred,
            within_ns,
            same,
            threshold,
        });
    }
    Ok(steps)
}

/// Everything [`check_fields`] reports an error with.
struct CheckCtx<'a> {
    source: &'a str,
    file: Option<&'a Path>,
    id: &'a str,
    table: &'a toml::Table,
    step: &'a str,
    earlier: &'a [String],
}

/// A field must belong to the step's record category, or be one of the generic
/// fields. `alias.field` references an earlier step and is checked separately.
fn check_fields(
    ctx: &CheckCtx<'_>,
    expr: &aw_core::filter::Expr,
    category: FieldKind,
) -> Result<(), RuleError> {
    let mut bad: Option<String> = None;
    walk(expr, &mut |term| {
        if bad.is_some() {
            return;
        }
        if let FieldRef::Named(info) = &term.field {
            if info.kind != FieldKind::Any && info.kind != category && category != FieldKind::Any {
                bad = Some(format!(
                    "field `{}` does not apply to this record",
                    info.name
                ));
            }
        }
        for value in &term.values {
            if let aw_core::filter::Value::Text(text) = value {
                if let Some((alias, field)) = split_ref(text) {
                    if !ctx.earlier.iter().any(|have| have == alias) || !is_ident(field) {
                        bad = Some(format!("`{text}` does not name an earlier step"));
                    }
                }
            }
        }
    });
    match bad {
        Some(detail) => Err(RuleError::Where {
            file: ctx.file.map(Path::to_path_buf),
            line: field_line(ctx.source, ctx.table, "where"),
            rule_id: ctx.id.to_owned(),
            step: ctx.step.to_owned(),
            detail,
        }),
        None => Ok(()),
    }
}

/// Fields a rule may name that the shared registry does not have, and the
/// registered field they are parsed as.
///
/// `is_loopback` is a real column of `net_flows` (storage.md) but not a filter
/// field. It is parsed as `direct`, which has the same boolean type, and the
/// engine maps it back before evaluation. The registry itself is not modified.
const FIELD_ALIASES: &[(&str, &str)] = &[("is_loopback", "direct")];

/// Marker prefixed to a value whose field was aliased, so the engine can tell
/// `is_loopback:true` from a real `direct:true` after parsing.
const ALIAS_MARK: &str = "\u{0}alias";

/// Rewrite alias fields onto the registered field they parse as.
fn alias_fields(input: &str) -> String {
    let mut out = input.to_owned();
    for (from, to) in FIELD_ALIASES {
        out = out.replace(from, to);
    }
    out
}

/// Mark terms whose field was rewritten, by prefixing their first value.
///
/// The mark survives parsing and is read back by the engine. It is only added
/// when the source text named the alias, so a genuine `direct` term is not
/// marked.
fn mark_aliases(expr: aw_core::filter::Expr, source: &str) -> aw_core::filter::Expr {
    use aw_core::filter::{Expr, Value};
    let used_alias = FIELD_ALIASES.iter().any(|(from, _)| source.contains(from));
    if !used_alias {
        return expr;
    }
    match expr {
        Expr::And(left, right) => Expr::And(
            Box::new(mark_aliases(*left, source)),
            Box::new(mark_aliases(*right, source)),
        ),
        Expr::Or(left, right) => Expr::Or(
            Box::new(mark_aliases(*left, source)),
            Box::new(mark_aliases(*right, source)),
        ),
        Expr::Not(inner) => Expr::Not(Box::new(mark_aliases(*inner, source))),
        Expr::Term(mut term) => {
            let aliased = FIELD_ALIASES.iter().any(|(_, to)| term.field.name() == *to);
            if aliased {
                if let Some(Value::Bool(value)) = term.values.first().cloned() {
                    term.values
                        .insert(0, Value::Text(format!("{ALIAS_MARK}:{value}")));
                }
            }
            Expr::Term(term)
        }
        other => other,
    }
}

/// Remove the spaces around operators.
///
/// The shared grammar allows no whitespace between a field and its operator, but
/// the rule examples write `op = "access"`. Only the spaces touching an operator
/// are removed, so the space that means `and` stays.
fn tighten_ops(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let start = index;
            index += 1;
            while index < bytes.len() && bytes[index] != b'"' {
                if bytes[index] == b'\\' {
                    index += 1;
                }
                index += 1;
            }
            index = (index + 1).min(bytes.len());
            out.push_str(&input[start..index]);
            continue;
        }
        if bytes[index].is_ascii_whitespace() && operator_near(bytes, index) {
            index += 1;
            continue;
        }
        out.push(bytes[index] as char);
        index += 1;
    }
    out
}

/// `true` when the whitespace at `index` touches an operator on either side.
fn operator_near(bytes: &[u8], index: usize) -> bool {
    let prev = (0..index)
        .rev()
        .find(|at| !bytes[*at].is_ascii_whitespace());
    let next = (index + 1..bytes.len()).find(|at| !bytes[*at].is_ascii_whitespace());
    prev.is_some_and(|at| is_operator_byte(bytes[at]))
        || next.is_some_and(|at| is_operator_byte(bytes[at]))
}

fn is_operator_byte(byte: u8) -> bool {
    matches!(byte, b'=' | b'!' | b'<' | b'>' | b'~' | b':')
}

/// `tag:sensitive` means the `sensitive` tag or any `sensitive.<rule>` tag.
///
/// The shared grammar matches `tag` as a whole string, so a row tagged
/// `sensitive.ssh-key` would not hit. The engine rewrites that one term to a
/// boolean field it computes itself. Every other term is left untouched.
fn rewrite_tag_prefix(expr: aw_core::filter::Expr) -> aw_core::filter::Expr {
    use aw_core::filter::{Expr, Op, Value};
    match expr {
        Expr::And(left, right) => Expr::And(
            Box::new(rewrite_tag_prefix(*left)),
            Box::new(rewrite_tag_prefix(*right)),
        ),
        Expr::Or(left, right) => Expr::Or(
            Box::new(rewrite_tag_prefix(*left)),
            Box::new(rewrite_tag_prefix(*right)),
        ),
        Expr::Not(inner) => Expr::Not(Box::new(rewrite_tag_prefix(*inner))),
        Expr::Term(term)
            if term.field.name() == "tag"
                && matches!(term.op, Op::Match | Op::Eq | Op::In)
                && term
                    .values
                    .iter()
                    .any(|value| matches!(value, Value::Text(text) if text == "sensitive")) =>
        {
            Expr::Term(aw_core::filter::Term {
                field: FieldRef::Named(sensitive_tag_field()),
                op: Op::Eq,
                values: vec![Value::Bool(true)],
                offset: term.offset,
            })
        }
        other => other,
    }
}

/// A stand-in field for the rewritten tag test.
///
/// Registered fields are `&'static`, and `tag` itself is a string field, so the
/// rewrite points at this one. Its name is what [`super::record::RuleRecord`]
/// answers `bool_value` with.
fn sensitive_tag_field() -> &'static aw_core::filter::FieldInfo {
    use aw_core::filter::{FieldInfo, FieldType};
    static FIELD: FieldInfo = FieldInfo {
        name: "tag_sensitive",
        ty: FieldType::Bool,
        kind: FieldKind::Any,
    };
    &FIELD
}

fn walk(expr: &aw_core::filter::Expr, visit: &mut dyn FnMut(&aw_core::filter::Term)) {
    match expr {
        aw_core::filter::Expr::True => {}
        aw_core::filter::Expr::Term(term) => visit(term),
        aw_core::filter::Expr::And(left, right) | aw_core::filter::Expr::Or(left, right) => {
            walk(left, visit);
            walk(right, visit);
        }
        aw_core::filter::Expr::Not(inner) => walk(inner, visit),
    }
}

fn resolve_kind(
    id: &str,
    evidence: EvidenceLevel,
    declared: Option<&str>,
    steps: usize,
    source: &str,
    file: Option<&Path>,
    rule: &toml::Table,
) -> Result<String, RuleError> {
    let multi = steps >= 2;
    match (evidence, declared, multi) {
        (EvidenceLevel::I, None, true) => Ok("inference".to_owned()),
        (EvidenceLevel::I, Some("inference") | None, false) => Ok("inference".to_owned()),
        (EvidenceLevel::E1, None, false) => Ok("fact".to_owned()),
        (EvidenceLevel::E1, Some("fact_conjunction"), true) => Ok("fact_conjunction".to_owned()),
        (EvidenceLevel::ContentMatch, Some("content_match"), false) => Ok("content_match".to_owned()),
        (EvidenceLevel::E1, _, true) => Err(invalid(
            source,
            file,
            id,
            rule,
            "evidence",
            "a rule with two or more steps must use evidence \"I\" unless it declares kind = \"fact_conjunction\"",
        )),
        (EvidenceLevel::ContentMatch, _, _) => Err(invalid(
            source,
            file,
            id,
            rule,
            "kind",
            "evidence \"content_match\" requires kind = \"content_match\" and exactly one step",
        )),
        (_, Some("fact_conjunction"), false) => Err(invalid(
            source,
            file,
            id,
            rule,
            "kind",
            "fact_conjunction needs two or more steps",
        )),
        _ => Err(invalid(
            source,
            file,
            id,
            rule,
            "kind",
            "kind must be \"fact_conjunction\" or \"content_match\"; other kinds are derived from evidence",
        )),
    }
}

fn check_wording(
    source: &str,
    file: Option<&Path>,
    id: &str,
    rule: &toml::Table,
    wording_id: &str,
) -> Result<(), RuleError> {
    // Probe the catalog with an empty parameter list. UnknownTemplate means the
    // key is absent; MissingParam means the key exists and needs parameters.
    match wording::render(wording_id, &[], Lang::Zh) {
        Ok(_) => Ok(()),
        Err(wording::WordingError::MissingParam { .. }) => Ok(()),
        Err(wording::WordingError::UnknownTemplate { .. }) => Err(invalid(
            source,
            file,
            id,
            rule,
            "wording",
            "wording is not a template in the wording catalog",
        )),
        Err(other) => Err(invalid(
            source,
            file,
            id,
            rule,
            "wording",
            &other.to_string(),
        )),
    }
}

/// Every `{name}` the template uses must be listed in `emit.params`, so a rule
/// cannot load when it could not fill its own sentence.
fn check_params_cover_template(
    source: &str,
    file: Option<&Path>,
    id: &str,
    emit: &toml::Table,
    wording_id: &str,
    params: &[String],
) -> Result<(), RuleError> {
    let supplied: Vec<(&str, &str)> = params.iter().map(|name| (name.as_str(), "")).collect();
    match wording::render(wording_id, &supplied, Lang::Zh) {
        Ok(_) => Ok(()),
        Err(wording::WordingError::MissingParam { param, .. }) => Err(invalid(
            source,
            file,
            id,
            emit,
            "params",
            &format!("wording template `{wording_id}` needs parameter `{param}`, which emit.params does not name"),
        )),
        Err(wording::WordingError::UnknownTemplate { .. }) => Err(invalid(
            source,
            file,
            id,
            emit,
            "wording",
            "wording is not a template in the wording catalog",
        )),
        Err(other) => Err(invalid(source, file, id, emit, "params", &other.to_string())),
    }
}

fn parse_key(
    source: &str,
    file: Option<&Path>,
    id: &str,
    emit: &toml::Table,
    steps: &[MatchStep],
) -> Result<Vec<KeyField>, RuleError> {
    let values = emit
        .get("key")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| invalid(source, file, id, emit, "key", "emit.key must be an array"))?;
    if values.is_empty() {
        return Err(invalid(
            source,
            file,
            id,
            emit,
            "key",
            "emit.key must name at least one field",
        ));
    }
    let mut key = Vec::with_capacity(values.len());
    for value in values {
        let text = value.as_str().ok_or_else(|| {
            invalid(
                source,
                file,
                id,
                emit,
                "key",
                "an emit.key entry must be a string",
            )
        })?;
        let (alias, field) = split_ref(text).ok_or_else(|| {
            invalid(
                source,
                file,
                id,
                emit,
                "key",
                "an emit.key entry must be alias.field",
            )
        })?;
        if !steps.iter().any(|step| step.alias == alias) {
            return Err(invalid(
                source,
                file,
                id,
                emit,
                "key",
                "emit.key names a step the rule does not have",
            ));
        }
        key.push(KeyField {
            alias: alias.to_owned(),
            field: field.to_owned(),
        });
    }
    Ok(key)
}

fn parse_upgrade(
    source: &str,
    file: Option<&Path>,
    id: &str,
    emit: &toml::Table,
    steps: &[MatchStep],
) -> Result<UpgradeIf, RuleError> {
    let Some(text) = optional_str(emit, "upgrade_if") else {
        return Ok(UpgradeIf::None);
    };
    let inner = text
        .strip_prefix("content_match(")
        .and_then(|rest| rest.strip_suffix(')'))
        .ok_or_else(|| {
            invalid(
                source,
                file,
                id,
                emit,
                "upgrade_if",
                "upgrade_if must be content_match(step.path, step.flow)",
            )
        })?;
    let mut parts = inner.split(',').map(str::trim);
    let (path_step, flow_step) = match (parts.next(), parts.next(), parts.next()) {
        (Some(path), Some(flow), None) => (path, flow),
        _ => {
            return Err(invalid(
                source,
                file,
                id,
                emit,
                "upgrade_if",
                "upgrade_if must be content_match(step.path, step.flow)",
            ))
        }
    };
    let path_step = path_step.strip_suffix(".path").ok_or_else(|| {
        invalid(
            source,
            file,
            id,
            emit,
            "upgrade_if",
            "the first argument must be a step's path",
        )
    })?;
    let flow_step = flow_step.strip_suffix(".flow").ok_or_else(|| {
        invalid(
            source,
            file,
            id,
            emit,
            "upgrade_if",
            "the second argument must be a step's flow",
        )
    })?;
    if !steps.iter().any(|step| step.alias == path_step)
        || !steps.iter().any(|step| step.alias == flow_step)
    {
        return Err(invalid(
            source,
            file,
            id,
            emit,
            "upgrade_if",
            "upgrade_if names a step the rule does not have",
        ));
    }
    Ok(UpgradeIf::ContentMatch {
        path_step: path_step.to_owned(),
        flow_step: flow_step.to_owned(),
    })
}

fn parse_params(
    source: &str,
    file: Option<&Path>,
    id: &str,
    emit: &toml::Table,
) -> Result<Vec<String>, RuleError> {
    let Some(values) = emit.get("params") else {
        return Ok(Vec::new());
    };
    let values = values.as_array().ok_or_else(|| {
        invalid(
            source,
            file,
            id,
            emit,
            "params",
            "emit.params must be an array of names",
        )
    })?;
    let mut names = Vec::with_capacity(values.len());
    for value in values {
        let name = value.as_str().ok_or_else(|| {
            invalid(
                source,
                file,
                id,
                emit,
                "params",
                "a parameter name must be a string",
            )
        })?;
        if !is_ident(name) {
            return Err(invalid(
                source,
                file,
                id,
                emit,
                "params",
                "a parameter name must be an identifier",
            ));
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

fn parse_within(
    source: &str,
    file: Option<&Path>,
    id: &str,
    table: &toml::Table,
    text: &str,
) -> Result<u64, RuleError> {
    let nanos = duration_ns(text).ok_or_else(|| {
        invalid(
            source,
            file,
            id,
            table,
            "within",
            "within must be a duration like \"10s\" or \"5m\"",
        )
    })?;
    if nanos == 0 || nanos > MAX_WITHIN_NS {
        return Err(invalid(
            source,
            file,
            id,
            table,
            "within",
            "within must be greater than 0 and at most 600s",
        ));
    }
    Ok(nanos)
}

fn duration_ns(text: &str) -> Option<u64> {
    const UNITS: &[(&str, u64)] = &[
        ("ms", 1_000_000),
        ("s", 1_000_000_000),
        ("m", 60_000_000_000),
        ("h", 3_600_000_000_000),
    ];
    for (suffix, factor) in UNITS {
        if let Some(number) = text.strip_suffix(suffix) {
            if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let value: u64 = number.parse().ok()?;
            return value.checked_mul(*factor);
        }
    }
    None
}

fn parse_evidence(text: &str) -> Option<EvidenceLevel> {
    match text {
        "E1" => Some(EvidenceLevel::E1),
        "I" => Some(EvidenceLevel::I),
        "content_match" => Some(EvidenceLevel::ContentMatch),
        _ => None,
    }
}

fn parse_severity(text: &str) -> Option<Severity> {
    match text {
        "info" => Some(Severity::Info),
        "notice" => Some(Severity::Notice),
        "warn" => Some(Severity::Warn),
        _ => None,
    }
}

fn parse_same(text: &str) -> Option<Same> {
    match text {
        "session" => Some(Same::Session),
        "process" => Some(Same::Process),
        "process_tree" => Some(Same::ProcessTree),
        _ => None,
    }
}

fn record_category(record: &str) -> Option<FieldKind> {
    RECORD_TYPES
        .iter()
        .find(|(name, _)| *name == record)
        .map(|(_, kind)| *kind)
}

/// `alias.field` inside a value or a key.
///
/// The alias is a single identifier. The field may itself contain dots
/// (`remote.ip`), because that is how the filter registry spells nested fields.
fn split_ref(text: &str) -> Option<(&str, &str)> {
    let (alias, field) = text.split_once('.')?;
    if is_ident(alias) && !field.is_empty() && field.chars().all(is_field_char) {
        Some((alias, field))
    } else {
        None
    }
}

fn is_field_char(ch: char) -> bool {
    ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '.'
}

fn is_ident(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() || first == '_' => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

fn required_str(
    source: &str,
    file: Option<&Path>,
    table: &toml::Table,
    key: &str,
) -> Result<String, RuleError> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            syntax(
                source,
                file,
                table_origin(source, table),
                &format!("missing or empty `{key}`"),
            )
        })
}

fn optional_str(table: &toml::Table, key: &str) -> Option<String> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
}

fn required_int(
    source: &str,
    file: Option<&Path>,
    id: &str,
    table: &toml::Table,
    key: &str,
) -> Result<u32, RuleError> {
    let value = table
        .get(key)
        .ok_or_else(|| invalid(source, file, id, table, key, &format!("missing `{key}`")))?;
    let number = value.as_integer().ok_or_else(|| {
        invalid(
            source,
            file,
            id,
            table,
            key,
            &format!("`{key}` must be an integer"),
        )
    })?;
    u32::try_from(number).map_err(|_| {
        invalid(
            source,
            file,
            id,
            table,
            key,
            &format!("`{key}` is out of range"),
        )
    })
}

fn positive_int(value: &toml::Value) -> Option<u64> {
    let number = value.as_integer()?;
    u64::try_from(number).ok().filter(|n| *n > 0)
}

/// 1-based line of the assignment to `key` inside the table that starts at
/// `table_at`. `toml::Value` carries no span in this build, so the line is found
/// by scanning the source. A key that never appears reports the table's line.
fn field_line(source: &str, table: &toml::Table, key: &str) -> u32 {
    let origin = table_origin(source, table);
    super::error::line_of(source, key_offset(source, origin, key).unwrap_or(origin))
}

/// Byte offset where the table literal that produced `table` begins.
///
/// Matched by content, not by position: the first key of the table must occur
/// as an assignment, and the following keys must occur before the table closes.
/// Good enough for the one-rule-per-file layout every rule here uses.
fn table_origin(source: &str, table: &toml::Table) -> usize {
    let Some(first) = table.keys().next() else {
        return 0;
    };
    let mut search_from = 0;
    while let Some(found) = find_key(source, search_from, first) {
        if table
            .keys()
            .skip(1)
            .all(|key| find_key(source, found, key).is_some())
        {
            return found;
        }
        search_from = found.saturating_add(first.len());
    }
    0
}

fn key_offset(source: &str, from: usize, key: &str) -> Option<usize> {
    find_key(source, from, key)
}

fn find_key(source: &str, from: usize, key: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let key_bytes = key.as_bytes();
    let mut index = from;
    while index + key_bytes.len() <= bytes.len() {
        if &bytes[index..index + key_bytes.len()] == key_bytes
            && bounded(bytes, index, key_bytes.len())
        {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// `true` when `key` sits where a TOML key sits: not inside a longer identifier,
/// and followed by `=` once whitespace is skipped.
fn bounded(bytes: &[u8], at: usize, len: usize) -> bool {
    if at > 0 && is_key_byte(bytes[at - 1]) {
        return false;
    }
    let mut after = at + len;
    while after < bytes.len() && bytes[after].is_ascii_whitespace() {
        after += 1;
    }
    after < bytes.len() && bytes[after] == b'='
}

fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn syntax(source: &str, file: Option<&Path>, offset: usize, detail: &str) -> RuleError {
    RuleError::Syntax {
        file: file.map(Path::to_path_buf),
        line: super::error::line_of(source, offset),
        detail: detail.to_owned(),
    }
}

fn invalid(
    source: &str,
    file: Option<&Path>,
    id: &str,
    table: &toml::Table,
    key: &str,
    detail: &str,
) -> RuleError {
    RuleError::Invalid {
        file: file.map(Path::to_path_buf),
        line: field_line(source, table, key),
        rule_id: id.to_owned(),
        detail: detail.to_owned(),
    }
}
