//! Join a relative path from a tracepoint with a process cwd.
//!
//! linux.md §2.2: the tracepoint fallback copies the user string, which may
//! be relative. Userspace joins it with the cwd it read from
//! `/proc/<tgid>/cwd`. The joined string is still `path_resolved = false`:
//! the join is best-effort (it does not stat the result, and `..` is only
//! collapsed lexically). A path the probe already marked resolved is returned
//! unchanged.

/// What the caller learned from `/proc/<tgid>/cwd`.
///
/// The read itself is not done here. A decoded event never opens a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CwdLookup {
    /// The symlink resolved.
    Value(String),
    /// The process was already gone, or the read failed.
    Unavailable,
}

/// Result of joining a user path with a cwd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathJoin {
    /// The path to store. Absolute when `cwd` was known and the input was
    /// relative; otherwise the input unchanged.
    pub path: String,
    /// Always `false` for a path this function produced from a user string.
    /// Callers that already have a `bpf_d_path` result do not call this.
    pub path_resolved: bool,
    /// `true` when a relative path could not be joined because cwd was missing.
    pub cwd_missing: bool,
}

/// Join `user_path` with `cwd` when the path is not already absolute.
///
/// An empty `user_path` is returned as empty with `cwd_missing = false`: the
/// probe said the path was present and empty, which is a different fact from
/// "cwd was not read". `.` and `..` components are collapsed lexically.
/// A `..` that would climb above `/` stays at `/`.
pub fn join_cwd(user_path: &str, cwd: &CwdLookup) -> PathJoin {
    if is_absolute(user_path) {
        return PathJoin {
            path: collapse(user_path),
            path_resolved: false,
            cwd_missing: false,
        };
    }
    match cwd {
        CwdLookup::Unavailable => PathJoin {
            path: user_path.to_owned(),
            path_resolved: false,
            cwd_missing: true,
        },
        CwdLookup::Value(dir) => {
            let joined = if dir.ends_with('/') {
                format!("{dir}{user_path}")
            } else {
                format!("{dir}/{user_path}")
            };
            PathJoin {
                path: collapse(&joined),
                path_resolved: false,
                cwd_missing: false,
            }
        }
    }
}

fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// Collapse `.` and `..` without touching the filesystem.
fn collapse(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    if !absolute {
        return stack.join("/");
    }
    if stack.is_empty() {
        return "/".to_owned();
    }
    let mut out = String::from("/");
    out.push_str(&stack.join("/"));
    out
}
