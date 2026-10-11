//! `aw proxy` (P3-PROXY-01).
//!
//! `ca-info` and `rotate-ca` describe a CA the caller already loaded. This
//! command does not generate one and does not open the data directory: the
//! daemon owns `ca.key`. [`UnwiredProxy`] is the production client and reports
//! that the daemon route is not connected.
//!
//! `trust` and `untrust` never call `certutil`, `security`, or
//! `update-ca-certificates`. They return a plan. `trust` without `--confirm`
//! stops and asks. `trust` without `--user` is refused: the only supported
//! scope is the user store, and even that is not installed by this process.

use std::io::{self, IsTerminal, Write};

use crate::exit;

use super::tree::ProxyCmd;
use super::Outcome;

/// What the operator may see. No key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaInfoView {
    /// SHA-256 of the certificate, lowercase hex.
    pub fingerprint: String,
    /// Unix seconds.
    pub not_before_unix: i64,
    /// Unix seconds.
    pub not_after_unix: i64,
    /// `false` when the key file is not encrypted.
    pub protected: bool,
    /// Why `protected` is false. `None` when it is true.
    pub unprotected_reason: Option<String>,
}

/// A trust-store action this process will not perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustPlan {
    /// `trust` or `untrust`.
    pub action: &'static str,
    /// `user`. System scope is not offered.
    pub scope: &'static str,
    /// Human text. Names the tool the operator would run themselves. This
    /// process does not run it.
    pub steps: String,
    /// `true` when the operator passed the explicit confirm flag.
    pub confirmed: bool,
}

/// Daemon calls. Implementations must not read `ca.key`.
pub(crate) trait ProxyApi {
    /// `GET` the public CA description.
    ///
    /// # Errors
    ///
    /// The daemon did not answer, or it has no CA.
    fn ca_info(&mut self) -> Result<CaInfoView, String>;

    /// Ask the daemon to rotate. `revoke_now` ends proxy sessions.
    ///
    /// # Errors
    ///
    /// The daemon did not answer.
    fn rotate(&mut self, revoke_now: bool) -> Result<CaInfoView, String>;

    /// Record that the operator confirmed a user-store install. Does not install.
    ///
    /// # Errors
    ///
    /// The daemon did not answer. A missing `--confirm` is handled before this
    /// is called.
    fn note_trust(&mut self, plan: &TrustPlan) -> Result<(), String>;
}

/// Confirmation boundary for certificate-store plans. Tests can fake terminal
/// answers without touching the process stdin.
pub(crate) trait Confirm {
    /// Ask once and return whether the user explicitly agreed.
    fn confirm(&mut self, prompt: &str) -> bool;
}

/// Real terminal confirmation. Redirected stdin is an immediate refusal.
#[derive(Debug, Default)]
pub(crate) struct StdinConfirm;

impl Confirm for StdinConfirm {
    fn confirm(&mut self, prompt: &str) -> bool {
        if !io::stdin().is_terminal() {
            return false;
        }
        let _ = write!(io::stderr(), "{prompt}");
        let _ = io::stderr().flush();
        let mut answer = String::new();
        io::stdin().read_line(&mut answer).is_ok()
            && matches!(
                answer.trim().to_ascii_lowercase().as_str(),
                "是" | "y" | "yes"
            )
    }
}

/// Production client. No socket is opened.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct UnwiredProxy;

const UNWIRED: &str = "后台代理 API 未接通；aw proxy 不会读取 ca.key。请先运行 `aw daemon start`，或加 --no-daemon（本地轮询采集，证据 S）";

impl ProxyApi for UnwiredProxy {
    fn ca_info(&mut self) -> Result<CaInfoView, String> {
        Err(UNWIRED.to_owned())
    }

    fn rotate(&mut self, _revoke_now: bool) -> Result<CaInfoView, String> {
        Err(UNWIRED.to_owned())
    }

    fn note_trust(&mut self, _plan: &TrustPlan) -> Result<(), String> {
        Err(UNWIRED.to_owned())
    }
}

/// Run one `aw proxy` subcommand.
///
/// `confirm` is the extra `--confirm` switch for `trust` / `untrust`. The clap
/// tree does not have that flag yet (the tree is shared and this card does not
/// edit it), so dispatch passes `false` and `trust` always stops at the prompt.
pub(crate) fn run(
    cmd: &ProxyCmd,
    json: bool,
    yes: bool,
    api: &mut dyn ProxyApi,
    confirm: &mut dyn Confirm,
) -> Outcome {
    match cmd {
        ProxyCmd::CaInfo => match api.ca_info() {
            Ok(info) => render_info(&info, json),
            Err(detail) => super::error_outcome(exit::UNREACHABLE, "unreachable", &detail, json),
        },
        ProxyCmd::RotateCa { revoke_now } => match api.rotate(*revoke_now) {
            Ok(info) => render_info(&info, json),
            Err(detail) => super::error_outcome(exit::UNREACHABLE, "unreachable", &detail, json),
        },
        ProxyCmd::Trust { user, .. } => {
            if !user {
                return super::error_outcome(
                    exit::USAGE,
                    "usage",
                    "`aw proxy trust` 需要 --user。不会安装到系统证书库。",
                    json,
                );
            }
            let confirmed = yes || confirm.confirm("将修改当前用户证书库。确定吗？[是/否]");
            let plan = trust_plan(confirmed);
            if !confirmed {
                return render_plan(&plan, json, true);
            }
            match api.note_trust(&plan) {
                Ok(()) => render_plan(&plan, json, false),
                Err(detail) => {
                    super::error_outcome(exit::UNREACHABLE, "unreachable", &detail, json)
                }
            }
        }
        ProxyCmd::Untrust { .. } => {
            let confirmed = yes || confirm.confirm("将修改当前用户证书库。确定吗？[是/否]");
            let plan = TrustPlan {
                action: "untrust",
                scope: "user",
                steps: untrust_steps(),
                confirmed,
            };
            if !confirmed {
                return render_plan(&plan, json, true);
            }
            match api.note_trust(&plan) {
                Ok(()) => render_plan(&plan, json, false),
                Err(detail) => {
                    super::error_outcome(exit::UNREACHABLE, "unreachable", &detail, json)
                }
            }
        }
    }
}

fn trust_plan(confirmed: bool) -> TrustPlan {
    TrustPlan {
        action: "trust",
        scope: "user",
        steps: [
            "这会把会话 CA 放进当前用户的证书库，使本机其他程序信任它。",
            "本进程不会执行 certutil、security 或 update-ca-certificates。",
            "确认后只把一条安装记录交给 daemon，写入 schema_meta，供卸载时清理。",
            "再次运行并带上显式确认才会记录。没有确认标志时到此为止。",
        ]
        .join(" "),
        confirmed,
    }
}

fn untrust_steps() -> String {
    "从用户证书库移除先前记下的副本。本进程不调用系统工具。确认后只记录清理意图。".to_owned()
}

fn render_info(info: &CaInfoView, json: bool) -> Outcome {
    let text = if json {
        let body = serde_json::json!({
            "fingerprint": info.fingerprint,
            "not_before_unix": info.not_before_unix,
            "not_after_unix": info.not_after_unix,
            "protected": info.protected,
            "unprotected_reason": info.unprotected_reason,
        });
        format!("{body}\n")
    } else {
        let reason = info.unprotected_reason.as_deref().unwrap_or("已保护");
        format!(
            "指纹 {}\n创建 {} 到期 {}\n私钥保护 {} ({})\n",
            info.fingerprint,
            info.not_before_unix,
            info.not_after_unix,
            if info.protected { "是" } else { "否" },
            reason
        )
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn render_plan(plan: &TrustPlan, json: bool, needs_confirm: bool) -> Outcome {
    let text = if json {
        let body = serde_json::json!({
            "action": plan.action,
            "scope": plan.scope,
            "confirmed": plan.confirmed,
            "installed": false,
            "needs_confirm": needs_confirm,
            "steps": plan.steps,
        });
        format!("{body}\n")
    } else if needs_confirm {
        format!(
            "aw proxy {} --user 尚未执行。不会修改证书库。\n{}\n",
            plan.action, plan.steps
        )
    } else {
        format!(
            "aw proxy {} 已记录意图，未修改证书库。\n{}\n",
            plan.action, plan.steps
        )
    };
    Outcome {
        code: if needs_confirm {
            exit::GENERAL
        } else {
            exit::OK
        },
        stdout: if needs_confirm {
            Vec::new()
        } else {
            text.clone().into_bytes()
        },
        stderr: if needs_confirm {
            text.into_bytes()
        } else {
            Vec::new()
        },
    }
}
