//! Write an empty migrated database. Schema only; no sessions or events.
//!
//! `cargo run -p aw-store --example init_empty --offline -- fixtures/db/v1.db`

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use aw_store::Store;

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: init_empty <path.db>");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("usage: init_empty <path.db>");
        return ExitCode::from(2);
    }
    match Store::open(PathBuf::from(path)) {
        Ok(store) => match store.schema_version() {
            Ok(version) => {
                println!("schema_version={version}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("schema_version: {err}");
                ExitCode::from(1)
            }
        },
        Err(err) => {
            eprintln!("open: {err}");
            ExitCode::from(1)
        }
    }
}
