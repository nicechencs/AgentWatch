//! P2-PIPE-03: built-in redaction against synthetic values.
//! The original secrets below are fixtures. The assertions require them to be gone.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};

use aw_core::{
    Arg, EnvMap, EventKind, Evidence, HeaderList, HttpRequest, ProcRef, ProcUid, RawEvent,
    Redacted, SessionId, Source, StartHow, UserRef, SCHEMA_VERSION,
};
use aw_pipeline::{RedactionConfig, Redactor};

const SECRET: &str = "fixture-secret-value";
const AKID: &str = "AKIAIOSFODNN7EXAMPLE";

fn process(argv: Vec<&str>, env: Vec<(&str, &str)>, exe: &str) -> RawEvent {
    let mut map = BTreeMap::new();
    for (key, value) in env {
        map.insert(key.to_owned(), value.to_owned());
    }
    let event = RawEvent {
        v: SCHEMA_VERSION,
        seq: 1,
        ts_mono_ns: 1,
        ts_wall_ns: 1_700_000_000_000_000_000,
        session_id: Some(SessionId(1)),
        proc: Some(ProcRef {
            uid: ProcUid(1),
            pid: 10,
            tid: None,
        }),
        source: Source::new("synthetic/process_start"),
        evidence: Evidence::E1,
        field_evidence: BTreeMap::new(),
        kind: EventKind::ProcessStart(aw_core::ProcessStart::new(
            1,
            None,
            1,
            Some(exe.to_owned()),
            Some(argv.into_iter().map(Arg::new).collect()),
            None,
            Some(UserRef {
                id: "1".to_owned(),
                name: None,
            }),
            StartHow::Exec,
            Some(EnvMap(map)),
            None,
        )),
    };
    event.check().expect("process event");
    event
}

fn argv_of(event: &RawEvent) -> Vec<String> {
    match &event.kind {
        EventKind::ProcessStart(start) => start
            .argv
            .as_ref()
            .expect("argv")
            .iter()
            .map(|arg| arg.as_str().to_owned())
            .collect(),
        _ => panic!("process start"),
    }
}

fn env_of(event: &RawEvent) -> BTreeMap<String, String> {
    match &event.kind {
        EventKind::ProcessStart(start) => start.env.as_ref().expect("env").0.clone(),
        _ => panic!("process start"),
    }
}

fn redactor() -> Redactor {
    Redactor::new(&RedactionConfig::default())
}

#[test]
fn argv_secrets_are_replaced_and_ordinary_words_stay() {
    let mut event = process(
        vec![
            "tool",
            "--password",
            SECRET,
            "--token=fixture-token",
            "-H",
            "Authorization: Bearer fixture",
            "note=hello",
        ],
        vec![("PATH", "/usr/bin"), ("API_TOKEN", SECRET)],
        "tool",
    );
    redactor().apply(&mut event, Some("tool"));
    let argv = argv_of(&event);
    assert!(!argv.iter().any(|arg| arg.contains(SECRET)));
    assert!(argv[2].contains("argv.flag_secret"));
    assert!(argv[3].contains("argv.flag_secret_eq"));
    assert!(argv[5].contains("header.blocked") || argv[5].contains("argv.header"));
    assert_eq!(argv[6], "note=hello");
    let env = env_of(&event);
    assert!(env.contains_key("PATH"));
    assert!(!env.contains_key("API_TOKEN"));
    assert!(!env.values().any(|value| value.contains(SECRET)));
}

#[test]
fn a_known_token_shape_is_replaced_inside_free_text() {
    let mut event = process(
        vec!["tool", &format!("prefix {AKID} suffix")],
        Vec::new(),
        "tool",
    );
    redactor().apply(&mut event, Some("tool"));
    let argv = argv_of(&event);
    assert!(!argv[1].contains(AKID));
    assert!(argv[1].contains("tok.aws_akid"));
    assert!(argv[1].contains("prefix"));
    assert!(argv[1].contains("suffix"));
}

#[test]
fn url_query_secrets_and_fragments_are_removed() {
    let url = format!("https://example.test/path?token={SECRET}&q=keep#{SECRET}");
    let mut event = RawEvent {
        v: SCHEMA_VERSION,
        seq: 2,
        ts_mono_ns: 2,
        ts_wall_ns: 1_700_000_000_000_000_000,
        session_id: Some(SessionId(1)),
        proc: None,
        source: Source::new("synthetic/http_request"),
        evidence: Evidence::E2,
        field_evidence: BTreeMap::new(),
        kind: EventKind::HttpRequest(HttpRequest::new(
            1,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
            None,
            "GET",
            Redacted::new(url),
            "HTTP/1.1",
            HeaderList(vec![
                ("Host".to_owned(), "example.test".to_owned()),
                ("Authorization".to_owned(), format!("Bearer {SECRET}")),
            ]),
            0,
            None,
        )),
    };
    event.check().expect("http event");
    redactor().apply(&mut event, None);
    match &event.kind {
        EventKind::HttpRequest(req) => {
            let url = req.url.as_str();
            assert!(!url.contains(SECRET));
            assert!(url.contains("url.query_secret"));
            assert!(url.contains("q=keep"));
            assert!(url.contains("url.fragment"));
            assert_eq!(req.headers.0[0].1, "example.test");
            assert!(req.headers.0[1].1.contains("header.blocked"));
            assert!(!req.headers.0[1].1.contains(SECRET));
        }
        _ => panic!("http request"),
    }
}

#[test]
fn disabling_redaction_keeps_the_original_and_marks_the_session() {
    let mut event = process(vec!["tool", "--password", SECRET], Vec::new(), "tool");
    let off = Redactor::new(&RedactionConfig {
        unsafe_no_redact: true,
        ..RedactionConfig::default()
    });
    off.apply(&mut event, Some("tool"));
    assert!(argv_of(&event).iter().any(|arg| arg == SECRET));
    assert!(off.disabled());
}
