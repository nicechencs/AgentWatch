//! The record shape the matcher reads.
//!
//! Pipeline stages own the real rows (`FileAccessRec`, `NetFlowRec`, ...). The
//! engine never depends on those structs, so it can be called without being
//! wired into the stage chain. A caller projects a row onto [`RuleRecord`] and
//! hands it to [`super::Engine::push`].
//!
//! An unknown field is `None`. This projection does not turn "not observed"
//! into `0` or `""`, because the filter treats an absent value as not equal to
//! anything.

use std::collections::BTreeMap;

/// One record offered to the matcher.
///
/// `record_type` selects which rule steps can see it (`file_access`,
/// `net_flow`, ...). `fields` holds the text the filter compares, `numbers` the
/// integers, `bools` the flags. `params` holds template values that are not
/// filter fields, such as a rendered byte count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRecord {
    /// Record type. Matches a step's `record`.
    pub record_type: String,
    /// Row id. Copied into a finding's `refs`.
    pub record_id: u64,
    /// Monotonic timestamp the window is measured against.
    pub ts_ns: u64,
    /// Session, when the record has one.
    pub session: Option<u64>,
    /// Subject process, when the record has one.
    pub proc_uid: Option<u64>,
    /// Text fields, keyed by the filter field name (`path`, `op`, `domain`).
    pub fields: BTreeMap<String, String>,
    /// Integer fields (`bytes_up`, `pid`).
    pub numbers: BTreeMap<String, i64>,
    /// Boolean fields (`direct`, `is_loopback`).
    pub bools: BTreeMap<String, bool>,
    /// Template parameter values this record can fill (`proc`, `path`, ...).
    pub params: BTreeMap<String, String>,
    /// Tags. `tag:sensitive` matches any tag that is `sensitive` or starts with
    /// `sensitive.`.
    pub tags: Vec<String>,
}

impl RuleRecord {
    /// A record with no fields. The caller fills in what it actually observed.
    pub fn new(record_type: &str, record_id: u64, ts_ns: u64) -> Self {
        Self {
            record_type: record_type.to_owned(),
            record_id,
            ts_ns,
            session: None,
            proc_uid: None,
            fields: BTreeMap::new(),
            numbers: BTreeMap::new(),
            bools: BTreeMap::new(),
            params: BTreeMap::new(),
            tags: Vec::new(),
        }
    }

    /// The record type.
    pub fn record_type(&self) -> &str {
        &self.record_type
    }

    /// Row id.
    pub fn record_id(&self) -> u64 {
        self.record_id
    }

    /// Timestamp.
    pub fn ts_ns(&self) -> u64 {
        self.ts_ns
    }

    /// Session.
    pub fn session(&self) -> Option<u64> {
        self.session
    }

    /// Process.
    pub fn proc_uid(&self) -> Option<u64> {
        self.proc_uid
    }

    /// Attach a session.
    pub fn with_session(mut self, session: u64) -> Self {
        self.session = Some(session);
        self
    }

    /// Attach a process.
    pub fn with_proc(mut self, proc_uid: u64) -> Self {
        self.proc_uid = Some(proc_uid);
        self
    }

    /// Set a text field.
    pub fn text_field(mut self, name: &str, value: &str) -> Self {
        self.fields.insert(name.to_owned(), value.to_owned());
        self
    }

    /// Set an integer field.
    pub fn number_field(mut self, name: &str, value: i64) -> Self {
        self.numbers.insert(name.to_owned(), value);
        self
    }

    /// Set a boolean field.
    pub fn bool_field(mut self, name: &str, value: bool) -> Self {
        self.bools.insert(name.to_owned(), value);
        self
    }

    /// Set a template parameter.
    pub fn param(mut self, name: &str, value: &str) -> Self {
        self.params.insert(name.to_owned(), value.to_owned());
        self
    }

    /// Add a tag.
    pub fn tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_owned());
        self
    }

    pub(crate) fn text(&self, field: &str) -> Option<&str> {
        if field == "tag" {
            return self.tags.first().map(String::as_str);
        }
        self.fields.get(field).map(String::as_str)
    }

    pub(crate) fn number(&self, field: &str) -> Option<i64> {
        self.numbers.get(field).copied()
    }

    pub(crate) fn bool_value(&self, field: &str) -> Option<bool> {
        if field == "tag_sensitive" {
            return Some(has_sensitive_tag(&self.tags));
        }
        self.bools.get(field).copied()
    }

    pub(crate) fn in_subtree(&self, proc_uid: &str) -> bool {
        self.proc_uid.is_some_and(|uid| uid.to_string() == proc_uid)
    }

    pub(crate) fn facts(&self) -> StepFacts {
        StepFacts {
            alias: String::new(),
            record: self.record_type.clone(),
            record_id: self.record_id,
            ts_ns: self.ts_ns,
            fields: self.fields.clone(),
            params: self.params.clone(),
            flags: self.bools.clone(),
        }
    }
}

/// The parts of one matched record a later step or a finding needs.
///
/// Kept by value, because the caller's record is gone by the time a later
/// record completes the match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepFacts {
    /// Step alias. Filled in by the engine once it knows which step matched.
    pub alias: String,
    /// Record type.
    pub record: String,
    /// Row id.
    pub record_id: u64,
    /// Timestamp.
    pub ts_ns: u64,
    /// Text fields.
    pub fields: BTreeMap<String, String>,
    /// Template parameters.
    pub params: BTreeMap<String, String>,
    /// Flags (`proxy_enabled`, `hash_compared`).
    pub flags: BTreeMap<String, bool>,
}

impl StepFacts {
    pub(crate) fn text(&self, field: &str) -> Option<&String> {
        self.fields.get(field).or_else(|| self.params.get(field))
    }

    pub(crate) fn param(&self, name: &str) -> Option<String> {
        self.params.get(name).cloned().or_else(|| self.fields.get(name).cloned())
    }

    pub(crate) fn flag(&self, name: &str) -> Option<bool> {
        self.flags.get(name).copied()
    }
}

/// `tag:sensitive` holds when any tag is exactly `sensitive` or starts with
/// `sensitive.`. The filter grammar has no prefix operator, so the projection
/// answers it as a boolean field named `tag` compared against the text
/// `sensitive` — see [`RuleRecord`]'s `RecordView`.
pub fn has_sensitive_tag(tags: &[String]) -> bool {
    tags.iter().any(|tag| tag == "sensitive" || tag.starts_with("sensitive."))
}
