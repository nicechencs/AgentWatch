//! TOML scenario model. Nested `steps` are the same shape at every depth.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Scenario {
    pub name: String,
    #[serde(default)]
    #[allow(dead_code)] // kept so smoke.toml matches testing.md §4.2
    pub description: String,
    #[serde(default)]
    pub setup: Setup,
    #[serde(default)]
    pub step: Vec<Step>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Setup {
    #[serde(default)]
    pub files: Vec<SetupFile>,
    /// Declared for the documented smoke shape. The local server itself is
    /// P0-SIM-03 (`sim serve`); this runner does not start one.
    /// Hint only. Starting the listener is P0-SIM-03 (`sim serve`).
    #[serde(default)]
    #[allow(dead_code)]
    pub server: Option<ServerHint>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // parsed so the documented `[setup].server` table is accepted
pub struct ServerHint {
    #[serde(default)]
    pub http: bool,
    #[serde(default)]
    pub https: bool,
    #[serde(default)]
    pub http_port: Option<u16>,
    #[serde(default)]
    pub https_port: Option<u16>,
    /// Bind a UDP echo on 127.0.0.1. Off unless the scenario asks.
    #[serde(default)]
    pub udp: bool,
    /// Bind the `*.agentwatch.test` stub. A bind failure becomes `skip` on the
    /// DNS steps rather than a failed run.
    #[serde(default)]
    pub dns: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetupFile {
    pub path: String,
    #[serde(default)]
    pub size: u64,
    /// `"random"` fills `size` bytes with a recognizable pattern. A literal
    /// string is written as-is (still only under the temp root).
    #[serde(default = "default_content")]
    pub content: String,
}

fn default_content() -> String {
    "random".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub action: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub steps: Vec<Step>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub ms: Option<u64>,
    /// `"read"` or `"mmap"`. Both read the whole file; mmap is recorded so
    /// later collectors can tell the intended access mode apart.
    #[serde(default)]
    pub mode: Option<String>,
    /// Arguments of an `exec` step. Stored as the process argv, not logged raw
    /// beyond the truth line's `argv` array (the scenario author wrote them).
    #[serde(default)]
    pub argv: Vec<String>,
    /// `repeat` count. `SIM_DURATION_MS` / `--duration` scales a step that also
    /// sets `duration_ms` down so a 10-minute load can finish in tests.
    #[serde(default)]
    pub times: Option<u64>,
    /// Nominal length of a `repeat` block, in milliseconds. With `times`, the
    /// runner derives the per-second rate and applies a shorter duration.
    #[serde(default)]
    pub duration_ms: Option<u64>,
    /// `udp_send` destination, `host:port`. Only `127.0.0.1` is accepted.
    #[serde(default)]
    pub dest: Option<String>,
    /// `long_conn` hold time. Scaled by the same duration override as `repeat`.
    #[serde(default)]
    pub hold_ms: Option<u64>,
    /// Exit after this many milliseconds. Used for the short-lived process.
    #[serde(default)]
    pub lifetime_ms: Option<u64>,
}

impl Scenario {
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}
