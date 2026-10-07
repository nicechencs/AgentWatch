//! SPIKE-02 ETW subscription sketch (P0-WIN-01).
//!
//! An elevated process can open one real-time user-mode ETW session and enable
//! the four providers listed in `docs/02-platforms/windows.md`:
//!
//! - Microsoft-Windows-Kernel-Process `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`
//! - Microsoft-Windows-Kernel-File `{EDD08927-9CC4-4E65-B970-C2560FB5C289}`
//! - Microsoft-Windows-Kernel-Network `{7DD42A49-5329-4832-8DFD-43D979153A88}`
//! - Microsoft-Windows-DNS-Client `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`
//!
//! Each event is one JSON object on stdout. `--pid` keeps events whose ETW
//! header process id matches. It does not walk a process tree: parent linkage
//! is still unverified. GUIDs, event ids, keyword bits, and property names are
//! copied from windows.md and are all 【待验证】.
//!
//! Privilege: this process never relaunches itself, never calls ShellExecute,
//! and never requests a UAC prompt. `UserTrace::start_and_process` is the only
//! call that opens the session. If ETW returns access denied (Win32 error 5),
//! the example prints that an elevated token is required and exits 2. It does
//! not try again and does not spawn another process.
//!
//! `cargo test -p aw-collector-windows` does not build examples. `cargo check
//! --all-targets` type-checks this file and does not execute `main`. This file
//! has no `#[cfg(test)]` module, so `cargo test --all-targets` has nothing here
//! that could call `UserTrace`. Argument parsing and the access-denied check
//! are plain functions; they do not open a session.
//!
//! NT Kernel Logger is not started. Only one such session may exist on older
//! Windows, and this spike must not take it. No WinDivert. No driver.
//!
//! ```text
//! cargo run -p aw-collector-windows --example poc -- --pid <pid>
//! ```
//!
//! As of 2026-10-07 this binary has not been run elevated, and it has not been
//! run in a way that opens a system ETW session. There are no measurements.

#![cfg(windows)]

use std::io::{self, ErrorKind, Write};
use std::process::ExitCode;

use ferrisetw::native::EvntraceNativeError;
use ferrisetw::parser::{Parser, ParserError};
use ferrisetw::provider::Provider;
use ferrisetw::schema::Schema;
use ferrisetw::schema_locator::{SchemaError, SchemaLocator};
use ferrisetw::trace::{TraceError, UserTrace};
use ferrisetw::{EventRecord, GUID};

const SESSION_NAME: &str = "AgentWatch-SPIKE-02";

/// Keyword bits copied from windows.md §2.1 and §2.2. Not confirmed here.
const PROCESS_KEYWORD_PROCESS: u64 = 0x10;
const PROCESS_KEYWORD_IMAGE: u64 = 0x40;
const FILE_KEYWORDS: u64 = 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000;

const GUID_KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
const GUID_KERNEL_FILE: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";
const GUID_KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
const GUID_DNS_CLIENT: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";

const NOT_ELEVATED: &str = "\
poc: not allowed to create a real-time ETW session (access denied).\n\
\n\
An elevated token is required (Administrator, Performance Log Users, or SYSTEM).\n\
This example does not relaunch itself, does not call ShellExecute, and does not request a UAC prompt.\n\
Start it yourself from an already-elevated shell:\n\
\n\
    cargo run -p aw-collector-windows --example poc -- --pid <pid>\n\
\n\
No second attempt was made.\
";

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };

    match subscribe(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) if access_denied(&err) => {
            eprintln!("{NOT_ELEVATED}");
            eprintln!("poc: ferrisetw reported: {err:?}");
            ExitCode::from(2)
        }
        Err(err) => {
            eprintln!("poc: {err:?}");
            ExitCode::from(1)
        }
    }
}

fn subscribe(args: Args) -> Result<(), TraceError> {
    let filter_pid = args.pid;
    // ferrisetw callbacks are `FnMut + Send + Sync` and are not cloned, so the
    // four providers cannot share one closure. `Option<u32>` is `Copy`, so each
    // closure captures the same header-PID filter. This is not a process tree:
    // parent linkage is still unverified. Process events try the property names
    // from windows.md, including CommandLine, which may be absent.
    let on_process = filtered(filter_pid);
    let on_file = filtered(filter_pid);
    let on_network = filtered(filter_pid);
    let on_dns = filtered(filter_pid);

    let process = Provider::by_guid(GUID_KERNEL_PROCESS)
        .any(PROCESS_KEYWORD_PROCESS | PROCESS_KEYWORD_IMAGE)
        .add_callback(on_process)
        .build();
    let file = Provider::by_guid(GUID_KERNEL_FILE)
        .any(FILE_KEYWORDS)
        .add_callback(on_file)
        .build();
    let network = Provider::by_guid(GUID_KERNEL_NETWORK)
        .add_callback(on_network)
        .build();
    let dns = Provider::by_guid(GUID_DNS_CLIENT)
        .add_callback(on_dns)
        .build();

    let trace = UserTrace::new()
        .named(String::from(SESSION_NAME))
        .enable(process)
        .enable(file)
        .enable(network)
        .enable(dns)
        .start_and_process()?;

    eprintln!(
        "poc: session {SESSION_NAME} is running (user trace, not NT Kernel Logger). Press Enter to stop."
    );
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    trace.stop()?;
    Ok(())
}

fn filtered(
    filter_pid: Option<u32>,
) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |record: &EventRecord, locator: &SchemaLocator| {
        if let Some(pid) = filter_pid {
            if record.process_id() != pid {
                return;
            }
        }
        emit(record, locator);
    }
}

fn emit(record: &EventRecord, locator: &SchemaLocator) {
    let line = json_line(record, locator);
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{line}");
}

fn json_line(record: &EventRecord, locator: &SchemaLocator) -> String {
    let provider = guid_string(&record.provider_id());
    let mut line = format!(
        "{{\"provider\":\"{}\",\"event_id\":{},\"opcode\":{},\"pid\":{},\"tid\":{},\"timestamp\":{}",
        json_escape(&provider),
        record.event_id(),
        record.opcode(),
        record.process_id(),
        record.thread_id(),
        record.raw_timestamp(),
    );

    match locator.event_schema(record) {
        Ok(schema) => {
            line.push_str(&format!(
                ",\"provider_name\":\"{}\"",
                json_escape(&schema.provider_name())
            ));
            line.push_str(&format_named_fields(record, &schema, &provider));
        }
        Err(err) => {
            line.push_str(&format!(
                ",\"schema\":null,\"schema_error\":\"{}\"",
                json_escape(&schema_error_text(&err))
            ));
        }
    }
    line.push('}');
    line
}

/// Property names are the ones windows.md lists as 【待验证】.
/// A name the manifest does not have becomes JSON null. That is not a measurement.
fn format_named_fields(record: &EventRecord, schema: &Schema, provider: &str) -> String {
    let parser = Parser::create(record, schema);
    let mut out = String::from(",\"fields\":{");
    let mut first = true;
    for name in field_names(provider, record.event_id()) {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        out.push_str(&json_escape(name));
        out.push_str("\":");
        out.push_str(&parse_loose(&parser, name));
    }
    out.push('}');
    out
}

fn field_names(provider: &str, event_id: u16) -> &'static [&'static str] {
    if guid_eq(provider, GUID_KERNEL_PROCESS) {
        return match event_id {
            1 => &[
                "ProcessID",
                "CreateTime",
                "ParentProcessID",
                "SessionID",
                "ImageName",
                "CommandLine",
            ],
            2 => &[
                "ProcessID",
                "CreateTime",
                "ExitTime",
                "ExitCode",
                "ImageName",
            ],
            _ => &[],
        };
    }
    if guid_eq(provider, GUID_KERNEL_FILE) {
        return match event_id {
            12 | 30 => &["FileObject", "FileName"],
            15 | 16 => &["ByteOffset", "FileObject", "FileKey", "IOSize", "IOFlags"],
            26 | 27 => &["FileObject", "FileKey", "FilePath"],
            _ => &[],
        };
    }
    if guid_eq(provider, GUID_KERNEL_NETWORK) {
        return match event_id {
            10 | 11 | 12 | 13 | 15 | 26 | 27 | 28 | 29 | 31 | 42 | 43 | 58 | 59 => {
                &["PID", "size", "daddr", "saddr", "dport", "sport", "connid"]
            }
            _ => &[],
        };
    }
    if guid_eq(provider, GUID_DNS_CLIENT) {
        return match event_id {
            3006 | 3008 | 3020 => &["QueryName", "QueryType", "QueryStatus", "QueryResults"],
            _ => &[],
        };
    }
    &[]
}

fn parse_loose(parser: &Parser, name: &str) -> String {
    match parser.try_parse::<String>(name) {
        Ok(value) => format!("\"{}\"", json_escape(&value)),
        Err(ParserError::InvalidType) => match parser.try_parse::<u64>(name) {
            Ok(value) => value.to_string(),
            Err(_) => match parser.try_parse::<u32>(name) {
                Ok(value) => value.to_string(),
                Err(_) => "null".to_string(),
            },
        },
        Err(_) => "null".to_string(),
    }
}

fn guid_eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn schema_error_text(err: &SchemaError) -> String {
    match err {
        SchemaError::TdhNativeError(inner) => format!("TdhNativeError({inner:?})"),
    }
}

fn guid_string(guid: &GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    )
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

/// Win32 `ERROR_ACCESS_DENIED` is 5. ferrisetw wraps that as `io::Error`.
/// Classifying the error does not open a session and does not relaunch.
fn access_denied(err: &TraceError) -> bool {
    match err {
        TraceError::EtwNativeError(EvntraceNativeError::IoError(io)) => {
            io.kind() == ErrorKind::PermissionDenied || io.raw_os_error() == Some(5)
        }
        TraceError::InvalidTraceName => false,
        TraceError::EtwNativeError(_) => false,
    }
}

struct Args {
    pid: Option<u32>,
}

impl Args {
    fn usage() -> &'static str {
        "usage: poc [--pid <pid>]\n\
         \n\
         When already elevated, subscribes to Kernel-Process, Kernel-File,\n\
         Kernel-Network and DNS-Client and prints one JSON object per event.\n\
         --pid keeps events whose ETW header process id equals <pid>.\n\
         Does not build a process tree and does not elevate itself.\n\
         Without an elevated token the process exits before any retry."
    }

    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, &'static str> {
        let mut pid = None;
        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "-h" | "--help" => return Err(Self::usage()),
                "--pid" => {
                    let Some(value) = iter.next() else {
                        return Err("poc: --pid needs a process id");
                    };
                    let Ok(parsed) = value.parse::<u32>() else {
                        return Err("poc: --pid must be a decimal u32");
                    };
                    if parsed == 0 {
                        return Err("poc: --pid 0 is not a process");
                    }
                    pid = Some(parsed);
                }
                _ if arg.starts_with('-') => return Err("poc: unknown argument (see --help)"),
                _ => return Err("poc: unexpected argument (see --help)"),
            }
        }
        Ok(Self { pid })
    }
}
