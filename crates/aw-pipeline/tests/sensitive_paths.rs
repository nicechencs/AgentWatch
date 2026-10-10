//! P2-PIPE-02: built-in sensitive-path rules against synthetic paths.
//! The matcher labels a path. It does not open the file or emit a finding.

#![allow(clippy::expect_used)]

use aw_pipeline::{SensitiveConfig, SensitiveRuleConfig, SensitiveRules};

const HOME: &str = "/home/fixture";
const WIN_HOME: &str = "C:\\Users\\fixture";

fn unix() -> SensitiveRules {
    SensitiveRules::load(&SensitiveConfig {
        home: Some(HOME.to_owned()),
        case_insensitive: false,
        extra: Vec::new(),
    })
}

fn windows() -> SensitiveRules {
    SensitiveRules::load(&SensitiveConfig {
        home: Some(WIN_HOME.to_owned()),
        case_insensitive: true,
        extra: Vec::new(),
    })
}

fn rule(rules: &SensitiveRules, path: &str) -> Option<String> {
    rules.hit(path, None).map(|hit| hit.rule_id)
}

#[test]
fn every_builtin_rule_has_a_hit_and_a_miss_on_each_path_style() {
    let cases: &[(&str, &str, &str, &str)] = &[
        ("ssh-keys", "/home/fixture/.ssh/id_ed25519", "/home/fixture/.ssh/id_ed25519.pub", "C:\\Users\\fixture\\.ssh\\id_ed25519"),
        ("gpg", "/home/fixture/.gnupg/private-keys-v1.d/key", "/home/fixture/notes/gnupg.txt", "C:\\Users\\fixture\\AppData\\Roaming\\gnupg\\key"),
        ("cloud-aws", "/home/fixture/.aws/credentials", "/home/fixture/notes/aws.txt", "C:\\Users\\fixture\\.aws\\credentials"),
        ("cloud-gcp", "/home/fixture/.config/gcloud/application_default_credentials.json", "/home/fixture/notes/gcloud.txt", "C:\\Users\\fixture\\AppData\\Roaming\\gcloud\\credentials.json"),
        ("cloud-azure", "/home/fixture/.azure/accessTokens.json", "/home/fixture/notes/azure.txt", "C:\\Users\\fixture\\.azure\\accessTokens.json"),
        ("kube", "/home/fixture/.kube/config", "/home/fixture/notes/kube.txt", "C:\\Users\\fixture\\.kube\\config"),
        ("docker-auth", "/home/fixture/.docker/config.json", "/home/fixture/.docker/contexts/meta.json", "C:\\Users\\fixture\\.docker\\config.json"),
        ("git-cred", "/home/fixture/.git-credentials", "/home/fixture/.gitconfig", "C:\\Users\\fixture\\.git-credentials"),
        ("pkg-tokens", "/home/fixture/.npmrc", "/home/fixture/.npm/note", "C:\\Users\\fixture\\.npmrc"),
        ("netrc", "/home/fixture/.netrc", "/home/fixture/.netrc.bak", "C:\\Users\\fixture\\_netrc"),
        ("dotenv", "/fixture/app/.env", "/fixture/app/.env.example", "C:\\fixture\\app\\.env"),
        ("key-files", "/fixture/certs/server.pem", "/fixture/certs/server.pem.txt", "C:\\fixture\\certs\\server.pem"),
        ("browser-profile", "/home/fixture/.mozilla/firefox/profile/logins.json", "/home/fixture/notes/browser.txt", "C:\\Users\\fixture\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"),
        ("os-keystore", "/home/fixture/.local/share/keyrings/login.keyring", "/home/fixture/notes/keyring.txt", "C:\\Users\\fixture\\AppData\\Roaming\\Microsoft\\Credentials\\secret"),
        ("shell-history", "/home/fixture/.bash_history", "/home/fixture/notes/history.txt", "C:\\Users\\fixture\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"),
        ("agent-config", "/home/fixture/.claude/settings.json", "/home/fixture/notes/claude.txt", "C:\\Users\\fixture\\.claude\\settings.json"),
        ("system-secrets", "/etc/shadow", "/etc/shadow.bak", "C:\\Windows\\System32\\config\\SAM"),
    ];
    let posix = unix();
    let win = windows();
    for (id, hit, miss, windows_hit) in cases {
        assert_eq!(
            rule(&posix, hit).as_deref(),
            Some(*id),
            "{id} should match {hit}"
        );
        assert_ne!(
            rule(&posix, miss).as_deref(),
            Some(*id),
            "{id} should not match {miss}"
        );
        assert_eq!(
            rule(&win, windows_hit).as_deref(),
            Some(*id),
            "{id} should match {windows_hit}"
        );
    }
}

#[test]
fn documented_public_and_sample_paths_are_not_labelled() {
    let rules = unix();
    for path in [
        "/home/fixture/.ssh/id_rsa.pub",
        "/home/fixture/.ssh/known_hosts",
        "/home/fixture/.ssh/known_hosts.old",
        "/fixture/app/.env.example",
        "/fixture/app/.env.sample",
        "/fixture/certs/id_rsa.pub",
        "/etc/ssh/ssh_host_ed25519_key.pub",
    ] {
        assert_eq!(rule(&rules, path).as_deref(), None, "{path} is excluded");
    }
    assert_eq!(
        rule(&rules, "/etc/ssh/ssh_host_ed25519_key").as_deref(),
        Some("system-secrets")
    );
}

#[test]
fn windows_matching_ignores_ascii_case() {
    let rules = windows();
    assert_eq!(
        rule(&rules, "c:\\users\\fixture\\.ssh\\id_ed25519").as_deref(),
        Some("ssh-keys")
    );
    assert_eq!(
        rule(&rules, "C:\\WINDOWS\\SYSTEM32\\CONFIG\\sam").as_deref(),
        Some("system-secrets")
    );
}

#[test]
fn tilde_uses_the_session_home_and_matches_nothing_without_one() {
    let with_home = unix();
    assert_eq!(
        rule(&with_home, "~/.ssh/id_ed25519").as_deref(),
        Some("ssh-keys")
    );
    assert_eq!(rule(&with_home, "~/.netrc").as_deref(), Some("netrc"));
    let no_home = SensitiveRules::load(&SensitiveConfig::default());
    assert_eq!(
        rule(&no_home, "~/.netrc").as_deref(),
        None,
        "a home-only rule is not expanded without a session home"
    );
    assert_eq!(
        rule(&no_home, "/home/fixture/.ssh/id_ed25519").as_deref(),
        Some("key-files"),
        "a concrete private-key path still matches without a session home"
    );
    assert_eq!(rule(&no_home, "/home/fixture/.netrc").as_deref(), None);
}

#[test]
fn an_agent_reading_its_own_config_is_info_only() {
    let rules = unix();
    let own = rules
        .hit("/home/fixture/.claude/settings.json", Some("claude"))
        .expect("hit");
    assert!(own.info_only);
    assert_eq!(own.rule_id, "agent-config");
    let other = rules
        .hit("/home/fixture/.claude/settings.json", Some("codex"))
        .expect("hit");
    assert!(
        !other.info_only,
        "another agent reading this directory is not the exception"
    );
    let ssh = rules
        .hit("/home/fixture/.ssh/id_ed25519", Some("claude"))
        .expect("hit");
    assert!(
        !ssh.info_only,
        "the exception does not cover a different rule"
    );
}

#[test]
fn a_user_rule_can_be_added_but_cannot_replace_a_builtin() {
    let rules = SensitiveRules::load(&SensitiveConfig {
        home: Some(HOME.to_owned()),
        case_insensitive: false,
        extra: vec![
            SensitiveRuleConfig {
                id: "ssh-keys".to_owned(),
                platform: "any".to_owned(),
                glob: "/tmp/not-a-key".to_owned(),
                exclude: Vec::new(),
            },
            SensitiveRuleConfig {
                id: "project-secret".to_owned(),
                platform: "any".to_owned(),
                glob: "/fixture/project/secret.txt".to_owned(),
                exclude: Vec::new(),
            },
        ],
    });
    assert_eq!(
        rule(&rules, "/tmp/not-a-key").as_deref(),
        None,
        "a colliding user id is ignored"
    );
    assert_eq!(
        rule(&rules, "/fixture/project/secret.txt").as_deref(),
        Some("project-secret")
    );
    assert_eq!(
        rule(&rules, "/home/fixture/.ssh/id_ed25519").as_deref(),
        Some("ssh-keys")
    );
}
