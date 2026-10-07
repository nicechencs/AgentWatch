//! Errors returned when a [`crate::RawEvent`] cannot be built or decoded.

use thiserror::Error;

use crate::event::SCHEMA_VERSION;

/// Failure to construct or validate a [`crate::RawEvent`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EventError {
    /// `v` is outside the major schema this crate can read.
    #[error(
        "schema version {found} is not supported (this build reads major version {SCHEMA_VERSION})"
    )]
    UnsupportedSchema { found: u16 },

    /// A field that the schema treats as required is `None` and has no `NA` entry.
    #[error(
        "field `{field}` on `{kind}` is None without an NA entry in field_evidence; \
         semantically required fields must be marked unavailable"
    )]
    MissingRequired {
        /// Event kind name, snake_case, matching the JSON `kind` tag.
        kind: &'static str,
        /// Field path inside that kind.
        field: &'static str,
    },

    /// JSON could not be decoded as an event (unknown variant, type mismatch, …).
    #[error("failed to decode event JSON: {0}")]
    Decode(String),
}

/// Alias kept for call sites that talk about the schema version check specifically.
pub type SchemaError = EventError;
