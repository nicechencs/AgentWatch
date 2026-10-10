//! Default redaction rules from security-privacy §3.2.
//!
//! Every pattern uses the `regex` crate, which guarantees linear time, so a
//! hostile value cannot stall the pipeline. A rule that fails to compile stops
//! the process at startup and names only the rule id, never a value.
//!
//! The text before replacement is never logged and never put in an error.

use std::sync::OnceLock;

use aw_core::{
    AgentRpc, AgentToolCall, Arg, EnvMap, EventKind, HeaderList, HttpRequest, HttpResponse,
    IpcOpen, ProcessStart, RawEvent,
};
use regex::{Regex, RegexSet};

use crate::config::RedactionConfig;

/// Written onto the session when redaction was switched off for the whole run.
pub const UNSAFE_NO_REDACT_FLAG: &str = "unsafe_no_redact";

const MARK_OPEN: &str = "\u{00ab}redacted:";
const MARK_CLOSE: &str = "\u{00bb}";

/// Applies the built-in rules. One instance per session, so the salt differs.
pub struct Redactor {
    /// Hex of the session salt, mixed into the marker. Not persisted.
    salt: String,
    /// `true` only for `--unsafe-no-redact`, which disables every built-in rule.
    disabled: bool,
}

impl Redactor {
    /// A redactor for one session.
    pub fn new(config: &RedactionConfig) -> Self {
        let salt = if config.salt.is_empty() {
            String::new()
        } else {
            bytes_to_hex(&config.salt)
        };
        Self {
            salt,
            disabled: config.unsafe_no_redact,
        }
    }

    /// Whether this session runs with the built-in rules switched off.
    pub fn disabled(&self) -> bool {
        self.disabled
    }

    /// Rewrite the sensitive fields of one event.
    ///
    /// `exe_base` is the process executable name, needed only for `argv.mysql_p`.
    pub fn apply(&self, event: &mut RawEvent, exe_base: Option<&str>) {
        if self.disabled {
            return;
        }
        match &mut event.kind {
            EventKind::ProcessStart(start) => self.redact_process(start, exe_base),
            EventKind::HttpRequest(req) => self.redact_http(req),
            EventKind::HttpResponse(resp) => self.redact_response(resp),
            EventKind::AgentToolCall(call) => self.redact_tool(call),
            EventKind::IpcOpen(ipc) => self.redact_ipc(ipc),
            EventKind::AgentRpc(rpc) => self.redact_rpc(rpc),
            _ => {}
        }
    }

    /// The argv rules [`Self::apply`] runs on a `ProcessStart`, for a command
    /// line that is not an event (the `sessions.argv` of `aw run`).
    pub fn redact_args(&self, argv: &[String]) -> Vec<String> {
        if self.disabled {
            return argv.to_vec();
        }
        let mut args: Vec<Arg> = argv.iter().map(|arg| Arg::new(arg.clone())).collect();
        let exe_base = argv
            .first()
            .map(|exe| exe.rsplit(['/', '\\']).next().unwrap_or(exe).to_owned());
        self.redact_argv(&mut args, exe_base.as_deref());
        args.iter().map(|arg| arg.as_str().to_owned()).collect()
    }

    /// Run B-class token rules over free text. Used for URLs and summaries.
    pub fn scrub_text(&self, text: &str) -> String {
        self.replace_tokens(text)
    }

    fn redact_process(&self, start: &mut ProcessStart, exe_base: Option<&str>) {
        if let Some(argv) = &mut start.argv {
            self.redact_argv(argv, exe_base);
        }
        if let Some(env) = &mut start.env {
            self.redact_env(env);
        }
    }

    fn redact_argv(&self, argv: &mut [Arg], exe_base: Option<&str>) {
        let mut index = 0;
        while index < argv.len() {
            let current = argv[index].as_str().to_owned();
            if secret_flag(&current) {
                if let Some(next) = argv.get_mut(index + 1) {
                    *next = Arg::new(self.mark("argv.flag_secret"));
                }
                index += 2;
                continue;
            }
            if let Some(replaced) = flag_equals(&current) {
                argv[index] = Arg::new(replaced);
                index += 1;
                continue;
            }
            if index > 0 && header_flag(argv.get(index - 1).map(Arg::as_str)) {
                if let Some(replaced) = header_value(&current) {
                    argv[index] = Arg::new(replaced);
                }
            }
            if index > 0 && basic_auth_flag(argv.get(index - 1).map(Arg::as_str), exe_base) {
                if let Some(replaced) = after_colon(&current, "argv.basic_auth") {
                    argv[index] = Arg::new(replaced);
                }
            }
            if mysql_client(exe_base) {
                if let Some(replaced) = mysql_password(&current) {
                    argv[index] = Arg::new(replaced);
                }
            }
            if let Some((key, value)) = split_assign(&current) {
                if env_name_is_secret(key) {
                    argv[index] = Arg::new(format!("{key}={}", self.mark("argv.env_assign")));
                    index += 1;
                    continue;
                }
                let scrubbed = self.replace_tokens(value);
                if scrubbed != value {
                    argv[index] = Arg::new(format!("{key}={scrubbed}"));
                }
            }
            let scrubbed = self.replace_tokens(argv[index].as_str());
            if scrubbed != argv[index].as_str() {
                argv[index] = Arg::new(scrubbed);
            }
            index += 1;
        }
    }

    /// Keep only the whitelist. A name that looks like a credential loses its
    /// value even when the name is whitelisted.
    fn redact_env(&self, env: &mut EnvMap) {
        env.0.retain(|name, _| env_name_kept(name));
        for (name, value) in &mut env.0 {
            if env_name_is_secret(name) {
                *value = self.mark("env.secret_name");
            } else {
                *value = self.replace_tokens(value);
            }
        }
    }

    fn redact_http(&self, req: &mut HttpRequest) {
        let scrubbed = self.scrub_url(req.url.as_str());
        req.url = aw_core::Redacted::new(scrubbed);
        self.redact_headers(&mut req.headers);
    }

    fn redact_response(&self, resp: &mut HttpResponse) {
        self.redact_headers(&mut resp.headers);
    }

    fn redact_headers(&self, headers: &mut HeaderList) {
        for (name, value) in &mut headers.0 {
            if header_blacklisted(name) {
                *value = self.mark("header.blocked");
            } else if header_whitelisted(name) {
                *value = self.scrub_url(value);
            } else {
                value.clear();
            }
        }
    }

    fn redact_tool(&self, call: &mut AgentToolCall) {
        let rendered = call.summary.to_string();
        let scrubbed = self.replace_tokens(&rendered);
        if scrubbed != rendered {
            call.summary = serde_json::Value::String(scrubbed);
        }
    }

    /// Socket path or pipe name. Tokens only; the path itself stays, since the
    /// sensitive-path rules label it rather than hide it.
    fn redact_ipc(&self, ipc: &mut IpcOpen) {
        if let Some(name) = &mut ipc.name {
            let scrubbed = self.replace_tokens(name);
            if scrubbed != *name {
                *name = scrubbed;
            }
        }
    }

    /// `arg_shape` holds `{type, len}` only, but a collector could still have put
    /// a value in it. Scrub the rendered form; the method name is not a secret.
    fn redact_rpc(&self, rpc: &mut AgentRpc) {
        let Some(shape) = &rpc.arg_shape else {
            return;
        };
        let rendered = shape.to_string();
        let scrubbed = self.replace_tokens(&rendered);
        if scrubbed != rendered {
            rpc.arg_shape = Some(serde_json::Value::String(scrubbed));
        }
    }

    /// Query secrets, the fragment, and any path segment that is a token.
    fn scrub_url(&self, url: &str) -> String {
        let (base, fragment) = match url.split_once('#') {
            Some((base, _)) => (base, true),
            None => (url, false),
        };
        let (path, query) = match base.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (base, None),
        };
        let mut out = self.replace_tokens(path);
        if let Some(query) = query {
            out.push('?');
            out.push_str(&self.scrub_query(query));
        }
        if fragment {
            out.push('#');
            out.push_str(&self.mark("url.fragment"));
        }
        out
    }

    fn scrub_query(&self, query: &str) -> String {
        query
            .split('&')
            .map(|pair| match pair.split_once('=') {
                Some((name, _value)) if query_name_secret(name) => {
                    format!("{name}={}", self.mark("url.query_secret"))
                }
                Some((name, value)) => format!("{name}={}", self.replace_tokens(value)),
                None => self.replace_tokens(pair),
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    fn replace_tokens(&self, text: &str) -> String {
        let patterns = patterns();
        let mut out = text.to_owned();
        for index in patterns.set.matches(&out).into_iter() {
            let rule = &patterns.rules[index];
            let replacement = self.mark(rule.id);
            out = rule
                .regex
                .replace_all(&out, replacement.as_str())
                .into_owned();
        }
        out
    }

    /// `tok.high_entropy`. Off by default (security-privacy §3.2 B); the config
    /// has no switch for it yet, so nothing here calls it.
    #[allow(dead_code)]
    fn replace_high_entropy(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let bytes = text.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if entropy_char(bytes[index]) {
                let start = index;
                while index < bytes.len() && entropy_char(bytes[index]) {
                    index += 1;
                }
                let token = &text[start..index];
                if high_entropy(token) {
                    out.push_str(&self.mark("tok.high_entropy"));
                } else {
                    out.push_str(token);
                }
            } else {
                out.push(bytes[index] as char);
                index += 1;
            }
        }
        out
    }

    fn mark(&self, rule: &str) -> String {
        if self.salt.is_empty() {
            format!("{MARK_OPEN}{rule}{MARK_CLOSE}")
        } else {
            let salt = &self.salt[..self.salt.len().min(8)];
            format!("{MARK_OPEN}{rule}:{salt}{MARK_CLOSE}")
        }
    }
}

struct Rule {
    id: &'static str,
    regex: Regex,
}

struct Patterns {
    set: RegexSet,
    rules: Vec<Rule>,
}

/// Token patterns, by rule id. Also listed by [`builtin_rules`].
const TOKEN_SOURCES: &[(&str, &str)] = &[
    ("tok.aws_akid", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("tok.github", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    ("tok.github_pat", r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
    ("tok.anthropic", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    ("tok.openai", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
    ("tok.slack", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    ("tok.google_api", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    (
        "tok.stripe",
        r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
    ),
    (
        "tok.jwt",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    ),
    ("tok.bearer", r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]+=*"),
    (
        "tok.url_userinfo",
        r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@",
    ),
];

/// One built-in redaction rule, for display (`GET /api/v1/config`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltinRule {
    /// Rule id, the same text that appears in `«redacted:<id>»`.
    pub id: &'static str,
    /// Where it applies: `text` (any captured text), `argv`, `env`, `url`, `header`.
    pub scope: &'static str,
    /// The regular expression, for token rules. Structural rules have none.
    pub pattern: Option<&'static str>,
}

/// Every rule the engine applies without configuration. Token rules come
/// from the same table the matcher compiles, so the list cannot drift from
/// what runs; the structural rules are the `mark(...)` ids in this file.
pub fn builtin_rules() -> Vec<BuiltinRule> {
    let mut rules: Vec<BuiltinRule> = TOKEN_SOURCES
        .iter()
        .map(|(id, source)| BuiltinRule {
            id,
            scope: "text",
            pattern: Some(source),
        })
        .collect();
    for (id, scope) in [
        ("argv.flag_secret", "argv"),
        ("argv.flag_secret_eq", "argv"),
        ("argv.header", "argv"),
        ("argv.basic_auth", "argv"),
        ("argv.env_assign", "argv"),
        ("argv.mysql_p", "argv"),
        ("env.secret_name", "env"),
        ("url.fragment", "url"),
        ("url.query_secret", "url"),
        ("header.blocked", "header"),
    ] {
        rules.push(BuiltinRule {
            id,
            scope,
            pattern: None,
        });
    }
    rules
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let sources: &[(&str, &str)] = TOKEN_SOURCES;
        let set = RegexSet::new(sources.iter().map(|(_, source)| *source))
            .unwrap_or_else(|_| panic!("redaction RegexSet failed to compile"));
        let rules = sources
            .iter()
            .map(|(id, source)| Rule {
                id,
                regex: Regex::new(source)
                    .unwrap_or_else(|_| panic!("redaction rule {id} failed to compile")),
            })
            .collect();
        Patterns { set, rules }
    })
}

fn flag_equals(arg: &str) -> Option<String> {
    static RULE: OnceLock<Regex> = OnceLock::new();
    let rule = RULE.get_or_init(|| {
        Regex::new(
            r"(?i)^(--?(?:[a-z0-9-]*[-_])?(?:password|passwd|token|secret|api[-_]?key|auth|credential))=(.+)$",
        )
        .unwrap_or_else(|_| panic!("redaction rule argv.flag_secret_eq failed to compile"))
    });
    rule.captures(arg)
        .map(|caps| format!("{}=\u{00ab}redacted:argv.flag_secret_eq\u{00bb}", &caps[1]))
}

fn secret_flag(arg: &str) -> bool {
    static RULE: OnceLock<Regex> = OnceLock::new();
    RULE.get_or_init(|| {
        Regex::new(
            r"(?i)^--?(?:[a-z0-9-]*[-_])?(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|auth|credential|private[-_]?key)$",
        )
        .unwrap_or_else(|_| panic!("redaction rule argv.flag_secret failed to compile"))
    })
    .is_match(arg)
}

fn header_flag(previous: Option<&str>) -> bool {
    matches!(previous, Some("-H" | "--header"))
}

fn header_value(arg: &str) -> Option<String> {
    static RULE: OnceLock<Regex> = OnceLock::new();
    let rule = RULE.get_or_init(|| {
        Regex::new(r"(?i)^(authorization|cookie|x-api-key|proxy-authorization)\s*:(.*)$")
            .unwrap_or_else(|_| panic!("redaction rule argv.header failed to compile"))
    });
    rule.captures(arg)
        .map(|caps| format!("{}: \u{00ab}redacted:argv.header\u{00bb}", &caps[1]))
}

fn basic_auth_flag(previous: Option<&str>, exe: Option<&str>) -> bool {
    matches!(previous, Some("-u" | "--user")) && curl_client(exe)
}

fn curl_client(exe: Option<&str>) -> bool {
    matches!(exe, Some("curl" | "curl.exe"))
}

fn mysql_client(exe: Option<&str>) -> bool {
    matches!(
        exe,
        Some("mysql" | "mysql.exe" | "mysqldump" | "mysqldump.exe")
    )
}

fn mysql_password(arg: &str) -> Option<String> {
    arg.strip_prefix("-p")
        .filter(|rest| !rest.is_empty())
        .map(|_| "-p\u{00ab}redacted:argv.mysql_p\u{00bb}".to_owned())
}

fn after_colon(arg: &str, rule: &str) -> Option<String> {
    arg.split_once(':')
        .map(|(name, _)| format!("{name}:\u{00ab}redacted:{rule}\u{00bb}"))
}

fn split_assign(arg: &str) -> Option<(&str, &str)> {
    let (key, value) = arg.split_once('=')?;
    if key.is_empty() || key.contains('/') || key.starts_with('-') {
        return None;
    }
    Some((key, value))
}

fn env_name_kept(name: &str) -> bool {
    const KEEP: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "PWD",
        "LANG",
        "TERM",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "NODE_OPTIONS",
        "VIRTUAL_ENV",
        "CI",
    ];
    KEEP.iter().any(|kept| kept.eq_ignore_ascii_case(name))
}

fn env_name_is_secret(name: &str) -> bool {
    const WORDS: &[&str] = &[
        "token",
        "secret",
        "key",
        "password",
        "passwd",
        "credential",
        "auth",
        "cookie",
        "session",
    ];
    let lower = name.to_ascii_lowercase();
    WORDS.iter().any(|word| lower.contains(word))
}

fn header_whitelisted(name: &str) -> bool {
    const KEEP: &[&str] = &[
        "host",
        "user-agent",
        "content-type",
        "content-length",
        "content-encoding",
        "accept",
        "accept-encoding",
        "referer",
        "origin",
        "x-request-id",
        "server",
        "location",
    ];
    KEEP.iter().any(|kept| kept.eq_ignore_ascii_case(name))
}

fn header_blacklisted(name: &str) -> bool {
    const BLOCK: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-amz-security-token",
    ];
    BLOCK
        .iter()
        .any(|blocked| blocked.eq_ignore_ascii_case(name))
        || env_name_is_secret(name)
}

fn query_name_secret(name: &str) -> bool {
    static RULE: OnceLock<Regex> = OnceLock::new();
    RULE.get_or_init(|| {
        Regex::new(
            r"(?i)^(?:.*[-_])?(?:token|key|apikey|api_key|secret|password|passwd|pwd|sig|signature|auth|code|session|sid|access_token|refresh_token|client_secret|x-amz-[a-z-]+)$",
        )
        .unwrap_or_else(|_| panic!("redaction rule url.query_secret failed to compile"))
    })
    .is_match(name)
}

fn entropy_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'=' | b'-')
}

/// Shannon entropy over the alphabet, in bits. Hex hashes of 40 or 64 chars are
/// excluded because they are usually commit ids, not credentials.
fn high_entropy(token: &str) -> bool {
    if token.len() < 32 {
        return false;
    }
    if (token.len() == 40 || token.len() == 64) && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let mut counts = [0u32; 256];
    for byte in token.bytes() {
        counts[byte as usize] += 1;
    }
    let len = token.len() as f64;
    let entropy: f64 = counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let p = f64::from(count) / len;
            -p * p.log2()
        })
        .sum();
    entropy >= 4.0
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{builtin_rules, patterns};

    /// The Settings page listed no built-in rule (UI review #143, detail 9).
    /// The list must name every token rule the matcher runs, with no repeats.
    #[test]
    fn builtin_rules_cover_the_compiled_token_rules() {
        let listed = builtin_rules();
        let ids: Vec<&str> = listed.iter().map(|rule| rule.id).collect();
        for rule in &patterns().rules {
            assert!(ids.contains(&rule.id), "{} not listed", rule.id);
        }
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), ids.len());
        assert!(ids.contains(&"env.secret_name"));
        assert!(listed
            .iter()
            .all(|rule| (rule.scope == "text") == rule.pattern.is_some()));
        // Every structural id is a marker this file actually writes.
        let source = include_str!("engine.rs");
        for rule in listed.iter().filter(|rule| rule.pattern.is_none()) {
            assert!(
                source.contains(&format!("\"{}\"", rule.id))
                    || source.contains(&format!("redacted:{}", rule.id)),
                "{}",
                rule.id
            );
        }
    }
}
