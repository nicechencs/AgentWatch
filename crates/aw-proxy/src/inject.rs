//! Trust injection for a launched process (P3-PROXY-03, network-attribution §5.2).
//!
//! The returned map is what the launcher merges into the child environment.
//! `NO_PROXY` is appended to the user's value; it is not replaced. Every other
//! proxy or CA variable in the table overwrites the user's value, and
//! [`Injection::overwritten`] names those keys so the session metadata can
//! record that an original existed. The original value is not copied into the
//! result: it may be a credential.
//!
//! This module does not write shell rc files and does not change the system proxy.
//! Chromium-family binaries are not given `--proxy-server`. [`hint_for_exe`]
//! returns text the CLI prints.

use std::fmt;
use std::path::Path;

/// What to do when the client rejects the session CA.
///
/// `Fail` is the default: the connection fails and the record's error is
/// `cert_pinned`. `Tunnel` switches that request to a CONNECT tunnel. The URL
/// is then `NA(cert_pinned)`; domain and byte counts may still be kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyOnReject {
    /// Connection fails. Record `cert_pinned`.
    Fail,
    /// CONNECT tunnel. URL is `NA(cert_pinned)`.
    Tunnel,
}

impl ProxyOnReject {
    /// `fail` or `tunnel`, lowercase. Anything else is [`None`] — not a default.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "fail" => Some(Self::Fail),
            "tunnel" => Some(Self::Tunnel),
            _ => None,
        }
    }

    /// Config spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "fail",
            Self::Tunnel => "tunnel",
        }
    }
}

/// One variable that replaced a value the user already had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overwrite {
    /// Environment variable name.
    pub name: String,
    /// `true` when the user's value was non-empty. The value is not stored.
    pub had_value: bool,
}

/// Environment to merge, plus the overwrite report.
#[derive(Clone, PartialEq, Eq)]
pub struct Injection {
    /// Variables to set. Values are proxy URLs or PEM paths, not secrets from
    /// the user. `Debug` still prints names only.
    pub vars: Vec<(String, String)>,
    /// Keys whose previous value was replaced. `NO_PROXY` is absent: it is appended.
    pub overwritten: Vec<Overwrite>,
    /// Hint lines for the executable, when the static table has one.
    pub hints: Vec<&'static str>,
}

impl fmt::Debug for Injection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.vars.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("Injection")
            .field("vars", &names)
            .field("overwritten", &self.overwritten)
            .field("hints", &self.hints)
            .finish()
    }
}

/// Static rule: an executable base name that does not honor the proxy variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExeHint {
    /// File name without a directory, compared case-insensitively. No `.exe`.
    pub exe: &'static str,
    /// Text for `aw run` and the new-session page. Not a command to run.
    pub hint: &'static str,
}

/// Executables that need a flag this tool will not add for them.
pub const EXE_HINTS: &[ExeHint] = &[
    ExeHint {
        exe: "electron",
        hint: "Electron 不读取 HTTP_PROXY。需要自行添加 --proxy-server=http://127.0.0.1:<port>。本工具不自动追加参数。",
    },
    ExeHint {
        exe: "chrome",
        hint: "Chromium 不读取 HTTP_PROXY。需要自行添加 --proxy-server=http://127.0.0.1:<port>。本工具不自动追加参数。",
    },
    ExeHint {
        exe: "chromium",
        hint: "Chromium 不读取 HTTP_PROXY。需要自行添加 --proxy-server=http://127.0.0.1:<port>。本工具不自动追加参数。",
    },
    ExeHint {
        exe: "msedge",
        hint: "Edge 不读取 HTTP_PROXY。需要自行添加 --proxy-server=http://127.0.0.1:<port>。本工具不自动追加参数。",
    },
    ExeHint {
        exe: "code",
        hint: "VS Code / Electron 不读取 HTTP_PROXY。需要自行添加 --proxy-server。本工具不自动追加参数。",
    },
    ExeHint {
        exe: "code-insiders",
        hint: "VS Code Insiders 不读取 HTTP_PROXY。需要自行添加 --proxy-server。本工具不自动追加参数。",
    },
];

/// Hint for `exe`, which may be a path. `None` when the table has no row.
#[must_use]
pub fn hint_for_exe(exe: &str) -> Option<&'static str> {
    let base = Path::new(exe)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(exe);
    let stem = base
        .strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".EXE"))
        .unwrap_or(base);
    EXE_HINTS
        .iter()
        .find(|row| row.exe.eq_ignore_ascii_case(stem))
        .map(|row| row.hint)
}

/// Variables from network-attribution §5.2.
///
/// `proxy_port` is the session listener. `ca_pem` is `<session>/ca.pem`.
/// `bundle_pem` is `<session>/bundle.pem`. `user_env` is the environment the
/// child would have inherited; only the names in the table are consulted.
///
/// `NO_PROXY` becomes `localhost,127.0.0.1,::1` when the user had none, or that
/// list appended after the user's value when they had one. The user's entries
/// are not reordered and not dropped.
#[must_use]
pub fn plan_injection(
    proxy_port: u16,
    ca_pem: &str,
    bundle_pem: &str,
    user_env: &[(String, String)],
    exe: Option<&str>,
) -> Injection {
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    let mut vars = Vec::new();
    let mut overwritten = Vec::new();

    let overwrite_keys = [
        ("HTTP_PROXY", proxy_url.as_str()),
        ("HTTPS_PROXY", proxy_url.as_str()),
        ("http_proxy", proxy_url.as_str()),
        ("https_proxy", proxy_url.as_str()),
        ("ALL_PROXY", proxy_url.as_str()),
        ("NODE_EXTRA_CA_CERTS", ca_pem),
        ("NODE_USE_ENV_PROXY", "1"),
        ("SSL_CERT_FILE", bundle_pem),
        ("REQUESTS_CA_BUNDLE", bundle_pem),
        ("CURL_CA_BUNDLE", bundle_pem),
        ("GIT_SSL_CAINFO", bundle_pem),
        ("PIP_CERT", bundle_pem),
        ("NPM_CONFIG_CAFILE", bundle_pem),
    ];
    for (name, value) in overwrite_keys {
        if let Some(previous) = lookup(user_env, name) {
            overwritten.push(Overwrite {
                name: name.to_owned(),
                had_value: !previous.is_empty(),
            });
        }
        vars.push((name.to_owned(), value.to_owned()));
    }

    let no_proxy = match lookup(user_env, "NO_PROXY").or_else(|| lookup(user_env, "no_proxy")) {
        Some(existing) if !existing.is_empty() => {
            format!("{existing},localhost,127.0.0.1,::1")
        }
        _ => "localhost,127.0.0.1,::1".to_owned(),
    };
    vars.push(("NO_PROXY".to_owned(), no_proxy));

    let mut hints = Vec::new();
    if let Some(exe) = exe {
        if let Some(hint) = hint_for_exe(exe) {
            hints.push(hint);
        }
    }
    Injection {
        vars,
        overwritten,
        hints,
    }
}

fn lookup<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
    env.iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Attach mode cannot inject. The error is this string; there is no proxy.
pub const ATTACH_REFUSES_PROXY: &str =
    "附着模式无法注入代理。--proxy 只在 aw run 启动目标进程时可用。";

/// `Err` when a caller asks for a proxy on an attach session.
///
/// # Errors
///
/// Always. The message is [`ATTACH_REFUSES_PROXY`].
pub fn refuse_attach_proxy() -> Result<(), &'static str> {
    Err(ATTACH_REFUSES_PROXY)
}
