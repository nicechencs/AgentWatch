//! Filter query parser shared by the CLI, the API, the UI, and the rule engine.
//!
//! The grammar is api-and-cli §4.2. [`parse`] returns an [`Expr`]; [`Expr::to_predicate`]
//! evaluates it against an in-memory record. Compiling the same AST to SQL is
//! `aw-store`'s job (P2-STORE-03) and is deliberately not here.
//!
//! `~` is a substring operator and never a regular expression.

mod ast;
mod error;
mod parse;
mod registry;

pub use ast::{EvalCtx, Expr, FieldRef, Op, RecordView, Term, Value};
pub use error::FilterError;
pub use parse::parse;
pub use registry::{FieldInfo, FieldKind, FieldType, FIELDS};
