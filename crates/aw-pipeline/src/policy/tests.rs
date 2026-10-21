//! Policy decisions from the design's acceptance list (P5-SEC-01).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{decide, downgrade_codex_ask, load_str, Action, Layer, Phase, PolicyState, Subject};

const SAMPLE: &str = r#"
version = 1
enabled = true
on_error = "deny"

[[rule]]
id = "no-rm-rf"
layer = ["hook"]
agent = ["claude-code", "codex"]
tool = ["Bash"]
match.command = { regex = '\brm\s+-rf\b' }
action = "deny"
reason = "不允许递归删除"

[[rule]]
id = "force-dry-run"
layer = ["hook"]
tool = ["Bash"]
match.command = { prefix = "terraform apply" }
action = "rewrite"
rewrite.command = { replace = ["terraform apply", "terraform plan"] }
reason = "只允许 plan"

[[rule]]
id = "ask-before-push"
layer = ["hook"]
tool = ["Bash"]
match.command = { regex = '^git push' }
action = "ask"

[[rule]]
id = "block-paste-sites"
layer = ["proxy"]
match.host = { glob = "*.pastebin.com" }
action = "deny"
reason = "不允许连这个网站"

[[rule]]
id = "also-allow-push"
layer = ["hook"]
tool = ["Bash"]
match.command = { prefix = "git push" }
action = "allow"
"#;

fn policy() -> super::Policy {
    match load_str(SAMPLE).expect("sample") {
        PolicyState::On(policy) => policy,
        PolicyState::Off => panic!("sample is enabled"),
    }
}

fn bash(command: &str) -> Subject {
    Subject {
        layer: Layer::Hook,
        agent: Some("claude-code".to_owned()),
        tool: Some("Bash".to_owned()),
        event: Some("PreToolUse".to_owned()),
        command: Some(command.to_owned()),
        phase: Phase::Pre,
        ..Subject::default()
    }
}

#[test]
fn disabled_or_absent_enabled_is_off() {
    assert!(matches!(
        load_str("version = 1\nenabled = false\n").unwrap(),
        PolicyState::Off
    ));
    assert!(matches!(
        load_str("version = 1\n").unwrap(),
        PolicyState::Off
    ));
    // An empty document is not a policy. toml accepts it as an empty table,
    // which has no `enabled`, so it is off rather than a parse error.
    assert!(matches!(load_str("").unwrap(), PolicyState::Off));
}

#[test]
fn broken_file_is_an_error_not_off() {
    let err = load_str("enabled = true\n[[rule]]\naction = \"nope\"\n").unwrap_err();
    let text = err.to_string();
    assert!(text.contains("rule"));
    assert!(!text.contains("nope") || text.contains("action"));
}

#[test]
fn rm_is_deny_and_terraform_rewrites_and_push_asks() {
    let policy = policy();
    let rm = decide(&policy, &bash("rm -rf /tmp/x")).unwrap();
    assert_eq!(rm.effective, Action::Deny);
    assert_eq!(rm.rule_id.as_deref(), Some("no-rm-rf"));
    assert_eq!(rm.reason.as_deref(), Some("不允许递归删除"));

    let plan = decide(&policy, &bash("terraform apply -auto-approve")).unwrap();
    assert_eq!(plan.effective, Action::Rewrite);
    assert_eq!(
        plan.fields,
        vec![(
            "command".to_owned(),
            "terraform plan -auto-approve".to_owned()
        )]
    );

    let push = decide(&policy, &bash("git push origin main")).unwrap();
    assert_eq!(push.action, Action::Ask);
    assert_eq!(push.effective, Action::Ask);
    assert_eq!(push.rule_id.as_deref(), Some("ask-before-push"));
}

#[test]
fn two_hits_keep_the_stricter_one() {
    let policy = policy();
    let push = decide(&policy, &bash("git push")).unwrap();
    assert_eq!(push.action, Action::Ask);
    assert_eq!(push.rule_id.as_deref(), Some("ask-before-push"));
}

#[test]
fn rewrite_that_lands_on_deny_becomes_deny() {
    let text = r#"
enabled = true
[[rule]]
id = "edit"
tool = ["Bash"]
layer = ["hook"]
match.command = { prefix = "echo " }
action = "rewrite"
rewrite.command = { replace = ["echo ", "rm -rf "] }

[[rule]]
id = "no-rm"
tool = ["Bash"]
layer = ["hook"]
match.command = { regex = '\brm\s+-rf\b' }
action = "deny"
reason = "不允许递归删除"
"#;
    let PolicyState::On(policy) = load_str(text).unwrap() else {
        panic!("on");
    };
    let decision = decide(&policy, &bash("echo /tmp/x")).unwrap();
    assert_eq!(decision.effective, Action::Deny);
    assert_eq!(decision.rule_id.as_deref(), Some("no-rm"));
    assert!(decision.fields.is_empty());
}

#[test]
fn codex_ask_downgrades_to_deny() {
    let policy = policy();
    let mut subject = bash("git push");
    subject.agent = Some("codex".to_owned());
    let decision = downgrade_codex_ask(&decide(&policy, &subject).unwrap());
    assert_eq!(decision.action, Action::Ask);
    assert_eq!(decision.effective, Action::Deny);
    assert!(decision.downgraded);
    assert!(decision.reason.unwrap().contains("确认"));
}

#[test]
fn proxy_rewrite_and_ask_downgrade_to_deny() {
    let text = r#"
enabled = true
[[rule]]
id = "rw"
layer = ["proxy"]
match.host = { exact = "example.test" }
action = "rewrite"
rewrite.host = { replace = ["example.test", "other.test"] }
"#;
    let PolicyState::On(policy) = load_str(text).unwrap() else {
        panic!("on");
    };
    let subject = Subject {
        layer: Layer::Proxy,
        host: Some("example.test".to_owned()),
        ..Subject::default()
    };
    let decision = decide(&policy, &subject).unwrap();
    assert_eq!(decision.action, Action::Rewrite);
    assert_eq!(decision.effective, Action::Deny);
    assert!(decision.downgraded);
    assert!(decision.fields.is_empty());
}

#[test]
fn glob_host_and_other_agent_do_not_cross() {
    let policy = policy();
    let host = Subject {
        layer: Layer::Proxy,
        host: Some("x.pastebin.com".to_owned()),
        ..Subject::default()
    };
    assert_eq!(decide(&policy, &host).unwrap().effective, Action::Deny);
    let other = Subject {
        layer: Layer::Proxy,
        host: Some("pastebin.com".to_owned()),
        ..Subject::default()
    };
    assert_eq!(decide(&policy, &other).unwrap().effective, Action::Allow);

    let mut aider = bash("rm -rf /tmp/x");
    aider.agent = Some("aider".to_owned());
    assert_eq!(decide(&policy, &aider).unwrap().rule_id, None);
}

#[test]
fn arg_exact_and_prefix() {
    let text = r#"
enabled = true
[[rule]]
id = "arg"
layer = ["mcp"]
match.mcp_method = { exact = "tools/call" }
match.arg.command = { prefix = "sudo " }
action = "deny"
reason = "不允许"
"#;
    let PolicyState::On(policy) = load_str(text).unwrap() else {
        panic!("on");
    };
    let subject = Subject {
        layer: Layer::Mcp,
        method: Some("tools/call".to_owned()),
        mcp_method: Some("tools/call".to_owned()),
        args: vec![("command".to_owned(), "sudo rm".to_owned())],
        ..Subject::default()
    };
    assert_eq!(decide(&policy, &subject).unwrap().effective, Action::Deny);
}

#[test]
fn on_error_tokens_parse() {
    let PolicyState::On(deny) = load_str("enabled = true\n").unwrap() else {
        panic!("on");
    };
    assert_eq!(deny.on_error(), super::OnError::Deny);
    let PolicyState::On(allow) = load_str("enabled = true\non_error = \"allow\"\n").unwrap() else {
        panic!("on");
    };
    assert_eq!(allow.on_error(), super::OnError::Allow);
    assert!(load_str("enabled = true\non_error = \"drop\"\n").is_err());
}
