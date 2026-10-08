//! Template loading and rendering.
//!
//! Both language tables are `include_str!`'d and parsed on first use into a
//! [`std::sync::OnceLock`]. Keys must be identical across languages. When they
//! are not, [`render`] returns [`WordingError::KeyMismatch`] and
//! [`template_key_mismatch`] lists the difference. Parameter values never
//! appear in error text.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use regex::Regex;

const ZH_TOML: &str = include_str!("zh.toml");
const EN_TOML: &str = include_str!("en.toml");

/// Fixed marker written over a home-directory user segment.
const PATH_MARK: &str = "«redacted:path»";

/// Which compiled-in table to render from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// `zh.toml`.
    Zh,
    /// `en.toml`.
    En,
}

/// Why [`render`] refused to produce a string.
///
/// `Display` never includes a parameter value. A missing parameter is named by
/// its placeholder, not by whatever the caller passed for the others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordingError {
    /// `id` is not a key in the selected language table.
    UnknownTemplate {
        /// The template id that was requested.
        id: String,
    },
    /// The template needs `param` and `params` did not provide it.
    ///
    /// Nothing is rendered. An absent value is not replaced with `""`.
    MissingParam {
        /// The template id that was requested.
        id: String,
        /// The placeholder name that was not supplied.
        param: String,
    },
    /// `zh.toml` and `en.toml` do not have the same key set.
    ///
    /// [`template_key_mismatch`] lists every key present in only one table.
    KeyMismatch,
    /// A compiled-in table could not be parsed. The detail is the parser
    /// message only; template bodies are not copied into it.
    Catalog {
        /// `toml` error text.
        detail: String,
    },
}

impl std::fmt::Display for WordingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTemplate { id } => write!(f, "unknown wording template `{id}`"),
            Self::MissingParam { id, param } => {
                write!(f, "wording template `{id}` is missing parameter `{param}`")
            }
            Self::KeyMismatch => write!(
                f,
                "zh.toml and en.toml wording keys differ; see wording::template_key_mismatch"
            ),
            Self::Catalog { detail } => write!(f, "wording catalog failed to parse: {detail}"),
        }
    }
}

impl std::error::Error for WordingError {}

struct Catalog {
    zh: BTreeMap<String, String>,
    en: BTreeMap<String, String>,
    /// Keys present in exactly one language, sorted. Empty when the tables agree.
    mismatch: Vec<String>,
}

fn catalog() -> Result<&'static Catalog, WordingError> {
    static CATALOG: OnceLock<Result<Catalog, String>> = OnceLock::new();
    match CATALOG.get_or_init(load_catalog) {
        Ok(loaded) => Ok(loaded),
        Err(detail) => Err(WordingError::Catalog {
            detail: detail.clone(),
        }),
    }
}

fn load_catalog() -> Result<Catalog, String> {
    let zh = parse_table(ZH_TOML)?;
    let en = parse_table(EN_TOML)?;
    let zh_keys: BTreeSet<&str> = zh.keys().map(String::as_str).collect();
    let en_keys: BTreeSet<&str> = en.keys().map(String::as_str).collect();
    let mut mismatch: Vec<String> = zh_keys
        .symmetric_difference(&en_keys)
        .map(|key| (*key).to_owned())
        .collect();
    mismatch.sort();
    Ok(Catalog { zh, en, mismatch })
}

fn parse_table(source: &str) -> Result<BTreeMap<String, String>, String> {
    let value: toml::Value = toml::from_str(source).map_err(|err| err.to_string())?;
    let table = value
        .as_table()
        .ok_or_else(|| "wording file is not a table".to_owned())?;
    let mut out = BTreeMap::new();
    for (key, entry) in table {
        let text = entry
            .as_str()
            .ok_or_else(|| format!("wording template `{key}` is not a string"))?;
        out.insert(key.clone(), text.to_owned());
    }
    Ok(out)
}

/// Keys present in exactly one of `zh.toml` and `en.toml`, sorted.
///
/// Empty when the two tables agree. A parse failure yields one entry,
/// `catalog:<detail>`, so a caller can still see why the tables could not be
/// compared. The detail comes from the parser, never from a parameter value.
pub fn template_key_mismatch() -> Vec<String> {
    match catalog() {
        Ok(loaded) => loaded.mismatch.clone(),
        Err(WordingError::Catalog { detail }) => vec![format!("catalog:{detail}")],
        Err(_) => Vec::new(),
    }
}

/// Render template `id` in `lang`.
///
/// Every `{name}` in the template must appear in `params`. The first missing
/// name is [`WordingError::MissingParam`]; the function does not emit a partial
/// sentence and does not fill the hole with an empty string. Parameter values
/// that look like a path (`/` or `\`) or a domain have `/home/<name>` and
/// `C:\Users\<name>` rewritten so `<name>` becomes the fixed marker
/// `«redacted:path»`. Other text is copied unchanged.
///
/// # Errors
///
/// [`WordingError::UnknownTemplate`] when `id` is not in the table,
/// [`WordingError::MissingParam`] when a placeholder has no value,
/// [`WordingError::KeyMismatch`] when the two language files disagree, and
/// [`WordingError::Catalog`] when a compiled-in file fails to parse.
pub fn render(id: &str, params: &[(&str, &str)], lang: Lang) -> Result<String, WordingError> {
    let loaded = catalog()?;
    if !loaded.mismatch.is_empty() {
        return Err(WordingError::KeyMismatch);
    }
    let table = match lang {
        Lang::Zh => &loaded.zh,
        Lang::En => &loaded.en,
    };
    let template = table
        .get(id)
        .ok_or_else(|| WordingError::UnknownTemplate { id: id.to_owned() })?;
    let placeholders = placeholder_names(template);
    for name in &placeholders {
        if !params.iter().any(|(key, _)| key == name) {
            return Err(WordingError::MissingParam {
                id: id.to_owned(),
                param: name.clone(),
            });
        }
    }
    Ok(fill(template, params))
}

/// `{name}` occurrences, in order, including duplicates.
///
/// A `{` that is not followed by a name and a closing `}` is literal text, not
/// a placeholder, so a template can mention braces without becoming a parameter.
fn placeholder_names(template: &str) -> Vec<String> {
    let mut names = Vec::new();
    let bytes = template.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'{' {
            index += 1;
            continue;
        }
        let start = index + 1;
        let Some(end) = template[start..].find('}') else {
            break;
        };
        let name = &template[start..start + end];
        if is_placeholder_name(name) {
            names.push(name.to_owned());
            index = start + end + 1;
        } else {
            index += 1;
        }
    }
    names
}

fn is_placeholder_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn fill(template: &str, params: &[(&str, &str)]) -> String {
    let mut out = template.to_owned();
    // Longer names first, so `{bytes_up}` is not partly eaten by `{bytes}`.
    let mut ordered: Vec<(&str, &str)> = params.to_vec();
    ordered.sort_by(|left, right| right.0.len().cmp(&left.0.len()).then(left.0.cmp(right.0)));
    for (name, value) in ordered {
        let needle = format!("{{{name}}}");
        if !out.contains(&needle) {
            continue;
        }
        let redacted = redact_param(value);
        out = out.replace(&needle, &redacted);
    }
    out
}

/// Replace the user segment of `/home/<name>` and `C:\Users\<name>`.
///
/// Applied to values that contain `/` or `\`, which is how a path is
/// recognized, and to values that contain a domain. The marker is fixed. A
/// bare domain has no user segment, so the home-prefix pass leaves it as-is.
fn redact_param(value: &str) -> String {
    if !value.contains('/') && !value.contains('\\') && !looks_like_domain(value) {
        return value.to_owned();
    }
    let with_unix = match unix_home() {
        Some(rule) => rule.replace_all(value, &format!("/home/{PATH_MARK}")),
        None => std::borrow::Cow::Borrowed(value),
    };
    match windows_users() {
        Some(rule) => rule
            .replace_all(&with_unix, &format!("C:\\Users\\{PATH_MARK}"))
            .into_owned(),
        None => with_unix.into_owned(),
    }
}

fn looks_like_domain(value: &str) -> bool {
    // A host label, a dot, another host label. Paths that also contain a host
    // are already selected by `/` or `\`.
    domain_shape().is_some_and(|rule| rule.is_match(value))
}

fn unix_home() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"/home/[^/\\]+").ok())
        .as_ref()
}

fn windows_users() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)C:\\Users\\[^\\/]+").ok())
        .as_ref()
}

fn domain_shape() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|[\s`])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}").ok())
        .as_ref()
}
