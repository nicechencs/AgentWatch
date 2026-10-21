//! `aw hook` through the built binary (P5-SEC-02).
//!
//! Unit tests call `run` with a payload already in memory, so they never see
//! `run_from_stdio` return before the policy is read. A bad `--http` used to
//! do exactly that: exit 0, empty stdout, rule never opened.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

/// Policy files live under the crate's `target/` directory, not `/tmp`.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("hook-cli")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// Clears every address and policy variable, and points the home directories
/// at `dir` so a developer's real `policy.toml` cannot decide the run.
fn hook(
    dir: &Path,
    policy: &Path,
    audit: &Path,
    args: &[&str],
    stdin_bytes: &[u8],
) -> (i32, Vec<u8>, Vec<u8>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aw"));
    command
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("AW_POLICY", policy)
        .env("AW_INTERCEPT_AUDIT", audit)
        .env("XDG_CONFIG_HOME", dir)
        .env("HOME", dir)
        .env("APPDATA", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn aw");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin_bytes)
        .expect("write stdin");
    let output = child.wait_with_output().expect("wait aw");
    (
        output.status.code().unwrap_or(1),
        output.stdout,
        output.stderr,
    )
}

/// A bad `--http` is not a reason to skip the decision. The audit then has
/// nowhere to go, so a rewrite is printed as a deny.
#[test]
fn bad_endpoint_still_denies_and_downgrades_a_rewrite() {
    let dir = scratch("bad-endpoint");
    let policy = dir.join("policy.toml");
    std::fs::write(
        &policy,
        "enabled = true\n[[rule]]\nid = \"no-rm\"\nlayer = [\"hook\"]\n\
         tool = [\"Bash\"]\nmatch.command = { prefix = \"rm \" }\n\
         action = \"deny\"\nreason = \"no rm\"\n\
         [[rule]]\nid = \"force-dry-run\"\nlayer = [\"hook\"]\ntool = [\"Bash\"]\n\
         match.command = { prefix = \"terraform apply\" }\naction = \"rewrite\"\n\
         rewrite.command = { replace = [\"terraform apply\", \"terraform plan\"] }\n\
         reason = \"只允许 plan\"\n",
    )
    .unwrap();
    // A directory, not a file: the backup append fails (the parent of a missing
    // file would just be created). Together with the dead socket, the audit has
    // nowhere to go.
    let audit = dir.clone();
    // `--socket` wins over `--http` and over the platform default, which on a
    // shared machine can be another worktree's live daemon. The path does not
    // exist, so the audit post fails; the backup path's parent does not exist
    // either. A rewrite then has nowhere to be recorded.
    let args = [
        "--socket",
        "aw-hook-missing.sock",
        "--http",
        "ftp://nope",
        "hook",
        "claude-code",
    ];

    let deny_payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf x"}}"#;
    let (code, stdout, stderr) = hook(&dir, &policy, &audit, &args, deny_payload);
    assert_eq!(code, 0, "stderr {}", String::from_utf8_lossy(&stderr));
    let body: Value = serde_json::from_slice(&stdout).unwrap_or_else(|_| {
        panic!(
            "bad endpoint allowed the command: {}",
            String::from_utf8_lossy(&stdout)
        )
    });
    assert_eq!(body["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        body["hookSpecificOutput"]["permissionDecisionReason"],
        "no rm"
    );

    let rewrite_payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"terraform apply"}}"#;
    let (code, stdout, stderr) = hook(&dir, &policy, &audit, &args, rewrite_payload);
    assert_eq!(code, 0, "stderr {}", String::from_utf8_lossy(&stderr));
    let body: Value = serde_json::from_slice(&stdout).unwrap_or_else(|_| {
        panic!(
            "rewrite survived a bad endpoint: {}",
            String::from_utf8_lossy(&stdout)
        )
    });
    assert_eq!(
        body["hookSpecificOutput"]["permissionDecision"], "deny",
        "{body}"
    );
    assert!(
        body["hookSpecificOutput"].get("updatedInput").is_none(),
        "{body}"
    );
    let reason = body["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    assert!(reason.contains("审计写不进去"), "{reason}");
    assert!(reason.contains("只允许 plan"), "{reason}");
    let _ = std::fs::remove_dir_all(&dir);
}
