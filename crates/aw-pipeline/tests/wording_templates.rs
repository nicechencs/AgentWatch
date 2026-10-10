//! P3-PIPE-03: compiled-in wording templates.
//! Values are fixtures. A missing parameter is an error, not an empty string.

#![allow(clippy::expect_used)]

use aw_pipeline::{lint, lint_allowing, render, template_key_mismatch, Lang, RuleId, WordingError};

const FILE_READ: &[(&str, &str)] = &[
    ("proc", "fixture-tool"),
    ("path", "/opt/fixture/notes.txt"),
    ("bytes", "12 B"),
];

#[test]
fn the_two_languages_have_the_same_keys() {
    assert_eq!(template_key_mismatch(), Vec::<String>::new());
}

#[test]
fn a_missing_parameter_is_an_error_and_names_only_the_placeholder() {
    let err = render(
        "fact.file_read",
        &[
            ("proc", "fixture-tool"),
            ("path", "/opt/fixture/secret.txt"),
        ],
        Lang::Zh,
    )
    .expect_err("bytes is required");
    assert_eq!(
        err,
        WordingError::MissingParam {
            id: "fact.file_read".to_owned(),
            param: "bytes".to_owned(),
        }
    );
    let shown = err.to_string();
    assert!(shown.contains("bytes"));
    assert!(
        !shown.contains("secret.txt"),
        "the error must not repeat a supplied value"
    );
    assert!(render("no.such.template", &[], Lang::En).is_err());
}

struct Case {
    id: &'static str,
    params: &'static [(&'static str, &'static str)],
    allow: Option<RuleId>,
}

#[test]
fn every_template_renders_in_both_languages_and_passes_lint() {
    let cases = [
        Case {
            id: "fact.file_read",
            params: FILE_READ,
            allow: None,
        },
        Case {
            id: "fact.file_opened_read",
            params: &[
                ("proc", "fixture-tool"),
                ("path", "/opt/fixture/notes.txt"),
                ("na_reason", "es_no_read_event"),
            ],
            allow: None,
        },
        Case {
            id: "fact.net_send",
            params: &[
                ("ev", "E1"),
                ("proc", "fixture-tool"),
                ("dest", "203.0.113.10:443"),
                ("bytes_up", "20 B"),
                ("bytes_down", "8 B"),
            ],
            allow: None,
        },
        Case {
            id: "evidence.content_match",
            params: &[
                ("proc", "fixture-tool"),
                ("url", "https://example.test/path"),
                ("t", "t0"),
                ("matched", "2"),
                ("total", "4"),
                ("path", "/opt/fixture/notes.txt"),
                ("pct", "50"),
            ],
            allow: Some(RuleId::ContentMatchPhrase),
        },
        Case {
            id: "gap.generic",
            params: &[
                ("from", "t0"),
                ("to", "t1"),
                ("collector", "synthetic"),
                ("kinds", "file"),
                ("reason", "queue full"),
            ],
            allow: None,
        },
        Case {
            id: "attr.break",
            params: &[("proc", "fixture-tool"), ("via", "sudo")],
            allow: None,
        },
    ];
    for case in cases {
        let Case { id, params, allow } = case;
        for lang in [Lang::Zh, Lang::En] {
            let text =
                render(id, params, lang).unwrap_or_else(|err| panic!("{id} {lang:?}: {err}"));
            assert!(!text.is_empty(), "{id} rendered empty");
            let hits = match allow {
                Some(rule) => lint_allowing(&text, &[rule]),
                None => lint(&text),
            };
            assert!(
                hits.is_empty(),
                "{id} {lang:?} failed lint: {text} -> {hits:?}"
            );
        }
    }
}

#[test]
fn a_home_segment_in_a_path_parameter_is_replaced() {
    let text = render(
        "fact.file_read",
        &[
            ("proc", "fixture-tool"),
            ("path", "/home/fixture-user/notes.txt"),
            ("bytes", "1 B"),
        ],
        Lang::En,
    )
    .expect("render");
    assert!(!text.contains("fixture-user"));
    assert!(text.contains("«redacted:path»"));
}
