//! Aider identification and the generic Python proxy plan (P5-AGENT-07).
//!
//! Aider is recognized from the `aider` executable or from `python -m aider`.
//! A plain Python script is not Aider, even when some argv element contains the
//! substring `aider`. Git children of an Aider process are labeled `vcs`.
//!
//! `python-generic` is not an automatic match. The built-in profile uses a
//! sentinel that no real process hits, so `identify` never returns it. Callers
//! apply [`PYTHON_GENERIC_ID`] only when the user passed `--agent python-generic`.
//!
//! SPIKE-04 has no filled-in result. The CA variables below follow the task
//! card (`REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`) and the httpx row in that spike
//! (`SSL_CERT_FILE`). They are marked 【待验证】. This module does not edit a
//! Python environment and does not inject `sitecustomize`.

use crate::identify::{exe_eq, AgentMatch, Inference, MatchHit, ProcInfo};
use crate::profile::ProfileSet;

/// Profile id for an explicit `--agent python-generic` selection.
pub const PYTHON_GENERIC_ID: &str = "python-generic";

/// Profile id for Aider.
pub const AIDER_ID: &str = "aider";

/// Child role for the `git` process Aider spawns.
pub const VCS_ROLE: &str = "vcs";

/// `requests` trust store. 【待验证】SPIKE-04 lists this variable and has no measured result.
pub const REQUESTS_CA_BUNDLE: &str = "REQUESTS_CA_BUNDLE";

/// OpenSSL trust store. httpx reads this name. 【待验证】SPIKE-04 lists it for httpx and has no measured result.
pub const SSL_CERT_FILE: &str = "SSL_CERT_FILE";

/// Shown when a session is labeled Aider or generic Python.
///
/// These agents have no E3 self-report. Records come from system observation only.
pub const NO_E3_NOTICE: &str = "这类 Agent 没有 E3 数据，只有系统观测。";

/// CA bundle variables this adapter would set for a Python process.
///
/// 【待验证】Combination is `REQUESTS_CA_BUNDLE` plus `SSL_CERT_FILE` (the name
/// httpx documents). SPIKE-04's result table is still empty, so this list is
/// not a measured coverage claim.
pub const PYTHON_CA_VARS: &[&str] = &[REQUESTS_CA_BUNDLE, SSL_CERT_FILE];

/// One proxy-injection assignment. The value is a PEM path the caller owns.
///
/// A name the user already set is not represented here. It is listed on
/// [`ProxyInjectPlan::kept`] instead, so this plan never overwrites it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAssignment {
    /// Environment variable name.
    pub name: &'static str,
    /// PEM path. Not a secret and not a URL.
    pub value: String,
}

/// What to merge into a Python child's environment under `--agent python-generic --proxy`.
///
/// Names the user already set are omitted. This plan never clears them and never
/// writes `sitecustomize` or any other file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyInjectPlan {
    /// Variables to set. Empty when every name was already present.
    pub assignments: Vec<ProxyAssignment>,
    /// Names left untouched because the user already had them.
    pub kept: Vec<&'static str>,
    /// [`NO_E3_NOTICE`].
    pub notice: &'static str,
}

/// Build the Python CA injection plan.
///
/// `bundle_pem` is the session bundle (`<session>/bundle.pem`). `env_get`
/// returns the value the child would already see, or `None` when the name is
/// absent. A present name — including an empty string — is kept and not overwritten.
///
/// Only [`REQUESTS_CA_BUNDLE`] and [`SSL_CERT_FILE`] are considered.
/// 【待验证】Whether requests and httpx honor these on every platform is not
/// confirmed; SPIKE-04's conclusion is still blank.
#[must_use]
pub fn plan_python_proxy(
    bundle_pem: &str,
    env_get: impl Fn(&str) -> Option<&str>,
) -> ProxyInjectPlan {
    let mut assignments = Vec::new();
    let mut kept = Vec::new();
    for name in PYTHON_CA_VARS {
        if env_get(name).is_some() {
            kept.push(*name);
            continue;
        }
        assignments.push(ProxyAssignment {
            name,
            value: bundle_pem.to_owned(),
        });
    }
    ProxyInjectPlan {
        assignments,
        kept,
        notice: NO_E3_NOTICE,
    }
}

/// `true` when `proc` is the `aider` executable or `python -m aider`.
///
/// A script path that merely contains `aider` does not count. `python -m aider`
/// requires the `-m` flag and a following argument whose file name is `aider`
/// (optional `.exe`, ASCII case-insensitive).
#[must_use]
pub fn is_aider_process(proc: &ProcInfo) -> bool {
    if exe_eq(&proc.exe_name, "aider") {
        return true;
    }
    python_module_is_aider(&proc.exe_name, &proc.argv)
}

/// Identify Aider. Returns `None` for an ordinary Python script.
///
/// The hit list is the confidence basis. Evidence is always [`Inference::I`].
#[must_use]
pub fn identify_aider(proc: &ProcInfo) -> Option<AgentMatch> {
    if exe_eq(&proc.exe_name, "aider") {
        return Some(AgentMatch {
            profile_id: AIDER_ID.to_owned(),
            hits: vec![MatchHit::ExeName(proc.exe_name.clone())],
            evidence: Inference::I,
        });
    }
    if python_module_is_aider(&proc.exe_name, &proc.argv) {
        return Some(AgentMatch {
            profile_id: AIDER_ID.to_owned(),
            hits: vec![MatchHit::ArgvRegex("-m aider".to_owned())],
            evidence: Inference::I,
        });
    }
    None
}

/// Role of a child under an Aider (or other) profile, from the compiled profile.
///
/// For Aider, a `git` / `git.exe` child is `vcs`. This does not identify the child
/// as an agent.
#[must_use]
pub fn child_role<'a>(
    profiles: &'a ProfileSet,
    profile_id: &str,
    proc: &ProcInfo,
) -> Option<&'a str> {
    profiles.child_role(profile_id, proc)
}

fn python_module_is_aider(exe_name: &str, argv: &[String]) -> bool {
    if !is_python_exe(exe_name) {
        return false;
    }
    let mut args = argv.iter().map(String::as_str);
    // `python -m aider` — skip argv[0] when it repeats the interpreter.
    if let Some(first) = args.next() {
        if !is_python_token(first) {
            // argv[0] was not the interpreter; scan it too.
            if token_is_module_flag(first) {
                return args.next().is_some_and(arg_is_aider_module);
            }
            // Fall through and scan the whole vector, including `first`.
            return scan_module_flag(argv.iter().map(String::as_str));
        }
    }
    scan_module_flag(args)
}

fn scan_module_flag<'a>(mut args: impl Iterator<Item = &'a str>) -> bool {
    while let Some(arg) = args.next() {
        if token_is_module_flag(arg) {
            return args.next().is_some_and(arg_is_aider_module);
        }
    }
    false
}

fn token_is_module_flag(arg: &str) -> bool {
    arg == "-m"
}

fn is_python_exe(name: &str) -> bool {
    is_python_token(name)
}

fn is_python_token(token: &str) -> bool {
    let base = file_name(token);
    let stem = base
        .strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".EXE"))
        .unwrap_or(base);
    let lower = stem.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "python" | "python2" | "python3" | "pythonw" | "pythonw3"
    ) || is_versioned_python(&lower)
}

fn is_versioned_python(stem: &str) -> bool {
    let rest = stem
        .strip_prefix("python")
        .or_else(|| stem.strip_prefix("pythonw"));
    let Some(rest) = rest else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    // python3.12, python3.12-config is not an interpreter; reject a non-digit tail
    // other than dots and digits. `python3.12m` (pymalloc builds) is accepted.
    let trimmed = rest.strip_suffix('m').unwrap_or(rest);
    let mut seen_digit = false;
    for ch in trimmed.chars() {
        if ch.is_ascii_digit() {
            seen_digit = true;
            continue;
        }
        if ch == '.' {
            continue;
        }
        return false;
    }
    seen_digit
}

fn arg_is_aider_module(arg: &str) -> bool {
    let base = file_name(arg);
    let stem = base
        .strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".EXE"))
        .unwrap_or(base);
    stem.eq_ignore_ascii_case("aider")
}

fn file_name(token: &str) -> &str {
    token.rsplit(['/', '\\']).next().unwrap_or(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_profiles;

    fn proc(exe: &str, argv: &[&str]) -> ProcInfo {
        ProcInfo {
            pid: 1,
            exe_name: exe.to_owned(),
            argv: argv.iter().map(|arg| (*arg).to_owned()).collect(),
            env_keys: Vec::new(),
        }
    }

    #[test]
    fn aider_exe_and_python_module_match() {
        let direct = identify_aider(&proc("aider", &["aider"]));
        assert_eq!(
            direct.as_ref().map(|hit| hit.profile_id.as_str()),
            Some(AIDER_ID)
        );
        assert_eq!(direct.as_ref().map(|hit| hit.evidence), Some(Inference::I));

        let windows = identify_aider(&proc("aider.exe", &["aider.exe", "--model", "x"]));
        assert_eq!(
            windows.as_ref().map(|hit| hit.profile_id.as_str()),
            Some(AIDER_ID)
        );

        let module = identify_aider(&proc("python", &["python", "-m", "aider"]));
        assert_eq!(
            module.as_ref().map(|hit| hit.profile_id.as_str()),
            Some(AIDER_ID)
        );
        assert!(is_aider_process(&proc(
            "python3",
            &["/usr/bin/python3", "-m", "aider"]
        )));
        assert!(is_aider_process(&proc(
            "python3.12",
            &["python3.12", "-q", "-m", "aider"]
        )));
        assert!(is_aider_process(&proc(
            "Python.exe",
            &["Python.exe", "-m", r"C:\py\aider.exe"]
        )));
    }

    #[test]
    fn plain_python_script_is_not_aider() {
        let script = proc("python", &["python", "script.py"]);
        assert!(identify_aider(&script).is_none());
        assert!(!is_aider_process(&script));

        let path_has_aider = proc("python", &["python", "/opt/aider/tools/run.py"]);
        assert!(identify_aider(&path_has_aider).is_none());

        let prefix = proc("python", &["python", "-m", "aider_tools"]);
        assert!(identify_aider(&prefix).is_none());

        let other = proc("python", &["python", "-m", "pytest"]);
        assert!(identify_aider(&other).is_none());

        let not_python = proc("node", &["node", "-m", "aider"]);
        assert!(identify_aider(&not_python).is_none());
    }

    #[test]
    fn python_generic_profile_does_not_auto_match() {
        let Ok(set) = load_profiles(None) else {
            panic!("builtins");
        };
        let python = proc("python", &["python", "agent.py"]);
        let matched = set.identify(&python, &[]);
        assert_ne!(
            matched.as_ref().map(|hit| hit.profile_id.as_str()),
            Some(PYTHON_GENERIC_ID)
        );
        let module = proc("python3", &["python3", "-m", "http.server"]);
        assert!(set.identify(&module, &[]).is_none());
        let split = proc("python", &["python", "-m", "aider"]);
        let Some(as_aider) = crate::identify(&split, &[]) else {
            panic!("python -m aider");
        };
        assert_eq!(as_aider.profile_id, AIDER_ID);
        assert_eq!(as_aider.evidence, Inference::I);
        assert_ne!(as_aider.profile_id, PYTHON_GENERIC_ID);
        let Some(profile) = set.get(PYTHON_GENERIC_ID) else {
            panic!("profile");
        };
        assert!(profile.self_report.is_empty());
    }

    #[test]
    fn git_child_of_aider_is_vcs() {
        let Ok(set) = load_profiles(None) else {
            panic!("builtins");
        };
        let git = proc("git", &["git", "status"]);
        assert_eq!(child_role(&set, AIDER_ID, &git), Some(VCS_ROLE));
        let git_exe = proc("git.exe", &[r"C:\Program Files\Git\cmd\git.exe", "diff"]);
        assert_eq!(set.child_role(AIDER_ID, &git_exe), Some(VCS_ROLE));
        let other = proc("python", &["python", "helper.py"]);
        assert!(child_role(&set, AIDER_ID, &other).is_none());
    }

    #[test]
    fn injection_sets_requests_and_ssl_names_and_keeps_user_values() {
        let empty = plan_python_proxy("/session/bundle.pem", |_| None);
        let names: Vec<&str> = empty.assignments.iter().map(|row| row.name).collect();
        assert_eq!(names, vec![REQUESTS_CA_BUNDLE, SSL_CERT_FILE]);
        assert!(empty
            .assignments
            .iter()
            .all(|row| row.value == "/session/bundle.pem"));
        assert!(empty.kept.is_empty());
        assert_eq!(empty.notice, NO_E3_NOTICE);
        assert!(empty.notice.contains("没有 E3"));
        assert!(empty.notice.contains("系统观测"));

        let partial = plan_python_proxy("/session/bundle.pem", |name| {
            if name == REQUESTS_CA_BUNDLE {
                Some("/user/cert.pem")
            } else {
                None
            }
        });
        assert_eq!(partial.kept, vec![REQUESTS_CA_BUNDLE]);
        assert_eq!(partial.assignments.len(), 1);
        assert_eq!(partial.assignments[0].name, SSL_CERT_FILE);
        assert!(!partial
            .assignments
            .iter()
            .any(|row| row.name == REQUESTS_CA_BUNDLE));

        let both = plan_python_proxy("/session/bundle.pem", |name| match name {
            REQUESTS_CA_BUNDLE => Some(""),
            SSL_CERT_FILE => Some("/user/openssl.pem"),
            _ => None,
        });
        assert!(both.assignments.is_empty());
        assert_eq!(both.kept, vec![REQUESTS_CA_BUNDLE, SSL_CERT_FILE]);
    }

    #[test]
    fn builtin_argv_rule_does_not_treat_a_script_path_as_aider() {
        let Ok(set) = load_profiles(None) else {
            panic!("builtins");
        };
        let script = proc("python", &["python", "/opt/aider/run.py"]);
        assert!(set.identify(&script, &[]).is_none());
        let direct = proc("aider", &["aider"]);
        let Some(hit) = crate::identify(&direct, &[]) else {
            panic!("aider exe");
        };
        assert_eq!(hit.profile_id, AIDER_ID);
        let path_entry = proc("python", &["python", "/usr/local/bin/aider"]);
        let Some(via_path) = crate::identify(&path_entry, &[]) else {
            panic!("path entry");
        };
        assert_eq!(via_path.profile_id, AIDER_ID);
        let plain = proc("python", &["python", "script.py"]);
        assert!(crate::identify(&plain, &[]).is_none());
    }
}
