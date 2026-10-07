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
    // No sim serve yet (P0-SIM-03). The step must be recorded, not crash the run.
    assert_eq!(upload["ok"], false);
    assert!(upload["error"].as_str().is_some());

    let _ = std::fs::remove_dir_all(&scratch);
}
