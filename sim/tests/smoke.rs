//! Integration coverage for `sim run`: scenario parse, path jail, and the
//! 3-level process tree written by `scenarios/smoke.toml`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sim_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sim"))
}

fn read_lines(path: &Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(path).expect("truth log");
    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).expect("json line"))
        .collect()
}

#[test]
fn smoke_scenario_parses() {
    let path = manifest_dir().join("scenarios/smoke.toml");
    let text = std::fs::read_to_string(path).expect("smoke.toml");
    let value: toml::Value = toml::from_str(&text).expect("parse");
    assert_eq!(value["name"].as_str(), Some("smoke"));
    let steps = value["step"].as_array().expect("steps");
    let actions: Vec<&str> = steps
        .iter()
        .map(|step| step["action"].as_str().unwrap_or(""))
        .collect();
    assert!(actions.contains(&"spawn"));
    assert!(actions.contains(&"write_file"));
    assert!(actions.contains(&"rename"));
    assert!(actions.contains(&"delete"));
    assert!(actions.contains(&"dns_lookup"));
    assert!(actions.contains(&"sleep"));
    assert!(actions.contains(&"http_download"));
}

#[test]
fn smoke_run_records_three_process_levels() {
    let scenario = manifest_dir().join("scenarios/smoke.toml");
    let scratch = std::env::temp_dir().join(format!("sim-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).expect("scratch");
    let truth = scratch.join("truth.jsonl");
    let root = scratch.join("root");

    let output = Command::new(sim_bin())
        .arg("run")
        .arg(&scenario)
        .arg("--truth")
        .arg(&truth)
        .arg("--root")
        .arg(&root)
        .output()
        .expect("spawn sim");
    assert!(
        output.status.success(),
        "sim run failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = read_lines(&truth);
    let enters: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|line| line["action"] == "spawn_enter")
        .collect();
    assert!(
        enters
            .iter()
            .any(|line| line["depth"] == 1 && line["id"] == "child"),
        "missing child spawn_enter: {lines:?}"
    );
    assert!(
        enters
            .iter()
            .any(|line| line["depth"] == 2 && line["id"] == "grandchild"),
        "missing grandchild spawn_enter: {lines:?}"
    );

    let child = enters
        .iter()
        .find(|line| line["id"] == "child")
        .expect("child");
    let grand = enters
        .iter()
        .find(|line| line["id"] == "grandchild")
        .expect("grandchild");
    let root_pid = lines
        .iter()
        .find(|line| line["action"] == "run")
        .expect("run")["pid"]
        .as_u64()
        .expect("root pid");
    let child_pid = child["pid"].as_u64().expect("child pid");
    let grand_pid = grand["pid"].as_u64().expect("grand pid");
    assert_ne!(root_pid, child_pid);
    assert_ne!(child_pid, grand_pid);
    assert_eq!(child["ppid"].as_u64(), Some(root_pid));
    assert_eq!(grand["ppid"].as_u64(), Some(child_pid));

    let spawn_child = lines
        .iter()
        .find(|line| line["action"] == "spawn" && line["id"] == "child")
        .expect("parent spawn row");
    assert_eq!(spawn_child["spawned_pid"].as_u64(), Some(child_pid));
    assert_eq!(spawn_child["pid"].as_u64(), Some(root_pid));

    let read = lines
        .iter()
        .find(|line| line["action"] == "read_file")
        .expect("read_file");
    assert_eq!(read["ok"], true);
    assert_eq!(read["bytes"], 412);
    assert_eq!(read["pid"].as_u64(), Some(grand_pid));
    let read_path = read["path"].as_str().unwrap_or("");
    assert!(read_path.contains("home"));
    assert!(read_path.contains(".ssh"));
    assert!(!read_path.contains("C:\\Users") || read_path.contains("root"));

    assert!(!root.join("home").join(".ssh").join("id_rsa").exists());
    assert!(
        !root.exists(),
        "temp root should be removed: {}",
        root.display()
    );

    let upload = lines
        .iter()
        .find(|line| line["action"] == "http_upload")
        .expect("http_upload");
    // The scenario starts its own loopback server, so the upload now succeeds
    // and the byte count is the one the scenario asked for. A refused connection
    // is still only a recorded failure: it must not fail the run.
    if upload["ok"] == true {
        assert_eq!(upload["app_bytes"].as_u64(), Some(5120));
        let remote = upload["remote"].as_str().unwrap_or("");
        assert!(remote.starts_with("127.0.0.1"), "{remote}");
    } else {
        assert!(upload["error"].as_str().is_some());
    }

    let _ = std::fs::remove_dir_all(&scratch);
}

/// P1-SIM-01. The two scenarios parse, and a shortened basic_proc_net run
/// records matching client and server byte counts without touching the network
/// outside 127.0.0.1. `--duration 1000` stands in for the 30 s hold.
#[test]
fn basic_proc_net_bytes_match_and_stay_local() {
    let scenario = manifest_dir().join("scenarios/basic_proc_net.toml");
    let scratch = std::env::temp_dir().join(format!(
        "sim-basic-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&scratch).expect("scratch");
    let truth = scratch.join("truth.jsonl");

    let output = Command::new(sim_bin())
        .arg("run")
        .arg(&scenario)
        .arg("--truth")
        .arg(&truth)
        .arg("--duration")
        .arg("1000")
        .output()
        .expect("spawn sim");
    assert!(
        output.status.success(),
        "sim run failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = read_lines(&truth);
    let text = std::fs::read_to_string(&truth).expect("truth text");
    assert!(
        !text.contains("http://") || text.contains("127.0.0.1"),
        "truth log left the loopback"
    );
    for line in &lines {
        if let Some(url) = line["url"].as_str() {
            assert!(url.contains("127.0.0.1"), "non-local url: {url}");
        }
        if let Some(remote) = line["remote"].as_str() {
            assert!(
                remote.starts_with("127.0.0.1"),
                "non-local remote: {remote}"
            );
        }
    }

    let uploads: Vec<u64> = lines
        .iter()
        .filter(|line| line["action"] == "http_upload")
        .map(|line| line["app_bytes"].as_u64().expect("upload bytes"))
        .collect();
    assert_eq!(uploads, vec![1_048_576, 10_485_760]);
    let download = lines
        .iter()
        .find(|line| line["action"] == "http_download")
        .expect("download");
    assert_eq!(download["app_bytes"].as_u64(), Some(5_242_880));
    assert_eq!(download["ok"], true);

    let server = read_lines(&scratch.join("server.jsonl"));
    let server_uploads: Vec<u64> = server
        .iter()
        .filter(|line| line["direction"] == "upload")
        .map(|line| line["app_bytes"].as_u64().expect("server upload"))
        .collect();
    assert_eq!(server_uploads, uploads);
    let server_download = server
        .iter()
        .find(|line| line["direction"] == "download")
        .expect("server download");
    assert_eq!(server_download["app_bytes"].as_u64(), Some(5_242_880));

    let dns: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|line| line["action"] == "dns_lookup")
        .collect();
    assert_eq!(dns.len(), 5);
    assert!(dns.iter().any(|line| line["answers"] == 0));
    assert!(dns.iter().all(|line| line["ok"] == true));

    let execs: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|line| line["action"] == "exec")
        .collect();
    assert!(execs.iter().any(|line| {
        line["argv"]
            .as_array()
            .is_some_and(|argv| argv.iter().any(|arg| arg.as_str() == Some("my file.txt")))
    }));
    assert!(execs.iter().any(|line| {
        line["argv"].as_array().is_some_and(|argv| {
            argv.iter()
                .any(|arg| arg.as_str().is_some_and(|s| s.contains('β')))
        })
    }));

    assert!(lines.iter().any(|line| line["action"] == "short_lived"));
    assert!(lines.iter().any(|line| line["depth"] == 2));
    let udp = lines
        .iter()
        .find(|line| line["action"] == "udp_send")
        .expect("udp");
    assert_eq!(udp["ok"], true);
    let server_udp = server
        .iter()
        .find(|line| line["direction"] == "udp")
        .expect("server udp");
    assert_eq!(server_udp["app_bytes"], udp["app_bytes"]);

    let _ = std::fs::remove_dir_all(&scratch);
}

/// The 10-minute load must shrink with `--duration` instead of running for real.
#[test]
fn typical_agent_duration_override_shrinks_the_load() {
    let scenario = manifest_dir().join("scenarios/typical_agent.toml");
    let text = std::fs::read_to_string(&scenario).expect("scenario");
    let value: toml::Value = toml::from_str(&text).expect("parse");
    assert_eq!(value["name"].as_str(), Some("typical_agent"));
    let repeats = value["step"].as_array().expect("steps");
    assert!(repeats
        .iter()
        .any(|step| step["times"].as_integer() == Some(12_000)));
    assert!(repeats
        .iter()
        .any(|step| step["duration_ms"].as_integer() == Some(600_000)));

    let scratch = std::env::temp_dir().join(format!(
        "sim-typical-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&scratch).expect("scratch");
    let truth = scratch.join("truth.jsonl");
    let started = std::time::Instant::now();
    let output = Command::new(sim_bin())
        .arg("run")
        .arg(&scenario)
        .arg("--truth")
        .arg(&truth)
        .arg("--duration")
        .arg("1000")
        .output()
        .expect("spawn sim");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        started.elapsed().as_secs() < 30,
        "override did not shorten the run"
    );

    let lines = read_lines(&truth);
    let execs = lines.iter().filter(|line| line["action"] == "exec").count();
    let downloads = lines
        .iter()
        .filter(|line| line["action"] == "http_download")
        .count();
    // 12000 and 6000 over 600 s, scaled to 1 s, is 20 and 10.
    assert_eq!(execs, 20);
    assert_eq!(downloads, 10);
    assert!(lines
        .iter()
        .filter(|line| line["action"] == "http_download")
        .all(|line| line["ok"] == true));

    let _ = std::fs::remove_dir_all(&scratch);
}
