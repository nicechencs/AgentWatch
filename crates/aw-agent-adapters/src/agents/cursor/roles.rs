//! Child-process role labels for a process the caller already attributes to Cursor.
//!
//! Labels come from argv shape (`--type=` and a shell file name). They are not a
//! claim that the binary was observed on a machine. `identify` does not read
//! these roles; a helper with `--type=` is not itself the agent root.

use crate::{ProcInfo, ProfileSet};

/// Profile id. Matches `profiles/cursor.toml`.
pub const PROFILE_ID: &str = "cursor";

/// Electron / terminal role under a Cursor tree.
///
/// The names follow the task card. They are inferences about argv, not a
/// measured process tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorRole {
    /// `--type=renderer`.
    Renderer,
    /// `--type=utility`.
    Utility,
    /// `--type=extensionHost`.
    ExtensionHost,
    /// A shell binary name on argv (`bash`, `zsh`, `fish`, `sh`, `pwsh`,
    /// `powershell`, `cmd`). Whether Cursor's terminal actually uses that name
    /// is 【待验证】 (SPIKE-07 §5.3 does not record the OS process).
    TerminalShell,
    /// An argv shape that looks like an MCP server command. Not proof that the
    /// process is an MCP server.
    McpServer,
}

impl CursorRole {
    /// Stable role string stored beside the process. Matches the profile.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Renderer => "renderer",
            Self::Utility => "utility",
            Self::ExtensionHost => "extension-host",
            Self::TerminalShell => "terminal-shell",
            Self::McpServer => "mcp_server",
        }
    }

    fn from_label(label: &str) -> Option<Self> {
        match label {
            "renderer" => Some(Self::Renderer),
            "utility" => Some(Self::Utility),
            "extension-host" => Some(Self::ExtensionHost),
            "terminal-shell" => Some(Self::TerminalShell),
            "mcp_server" => Some(Self::McpServer),
            _ => None,
        }
    }
}

/// Role for `proc` under the built-in Cursor profile, if a child regex hits.
///
/// Returns `None` when the profile failed to load or no role regex matches.
/// Does not look at the parent and does not open the process table.
#[must_use]
pub fn classify_role(proc: &ProcInfo) -> Option<CursorRole> {
    let set = crate::profile::builtins()?;
    role_in(set, proc)
}

fn role_in(set: &ProfileSet, proc: &ProcInfo) -> Option<CursorRole> {
    let label = set.child_role(PROFILE_ID, proc)?;
    CursorRole::from_label(label)
}
