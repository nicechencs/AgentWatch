//! Chromium argv plan for `--proxy`. Does not start a process and does not
//! install a certificate.
//!
//! SPIKE-04 is still 「未开始」. Its table says Electron / Chromium does not
//! honor proxy environment variables and expects `--proxy-server`. The same
//! row says the CA comes from the system trust store. Whether Electron also
//! reads `NODE_EXTRA_CA_CERTS`, and whether Chromium's network stack ignores
//! every path except the system store, is 【待验证】. This plan does not assert
//! either answer.
//!
//! Traffic the proxy does not see stays a direct connection. The URL field for
//! that flow is `NA(direct_bypass_proxy)` — the reason string is
//! [`NA_DIRECT_BYPASS_PROXY`]. This module does not record the flow.

use std::fmt::Write as _;

/// `field_evidence` reason when a flow did not go through the session proxy.
///
/// Not a claim that any particular Cursor request bypassed the proxy. Coverage
/// has not been measured.
pub const NA_DIRECT_BYPASS_PROXY: &str = "direct_bypass_proxy";

/// How the session CA would be offered. Only the unverified label exists.
///
/// There is no variant that installs the CA. `aw proxy trust` is a separate
/// user action and is not invoked here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaInjection {
    /// 【待验证】Electron may or may not read `NODE_EXTRA_CA_CERTS`. Chromium's
    /// network stack may only use the system trust store. Neither has been
    /// measured. The plan does not set the variable and does not install a CA.
    Unverified,
}

impl CaInjection {
    /// Short label for session metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
        }
    }
}

/// Argv suffix for one proxied launch. No environment is mutated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyPlan {
    /// Single Chromium flag, `--proxy-server=<endpoint>`.
    extra_args: Vec<String>,
    ca: CaInjection,
    /// Note safe to print. No certificate bytes, no URL path from a request.
    note: String,
}

impl ProxyPlan {
    /// Arguments to append. One element.
    #[must_use]
    pub fn extra_args(&self) -> &[String] {
        &self.extra_args
    }

    /// Always [`CaInjection::Unverified`].
    #[must_use]
    pub const fn ca(&self) -> CaInjection {
        self.ca
    }

    /// Why CA injection is not applied.
    #[must_use]
    pub fn note(&self) -> &str {
        &self.note
    }

    /// Always false. This plan never installs a CA into a trust store.
    #[must_use]
    pub const fn installs_system_ca(&self) -> bool {
        false
    }
}

/// Build the `--proxy-server=` argument for `endpoint`.
///
/// `endpoint` is the session proxy address the caller already chose, for
/// example `http://127.0.0.1:1234`. It is copied into the flag and not fetched.
/// The CA note stays 【待验证】 regardless of `endpoint`.
///
/// If Chromium does not use this flag, or does not trust the session CA, flows
/// that stay direct are labeled with [`NA_DIRECT_BYPASS_PROXY`]. This function
/// does not observe those flows.
#[must_use]
pub fn plan_proxy(endpoint: &str) -> ProxyPlan {
    let mut flag = String::from("--proxy-server=");
    flag.push_str(endpoint);
    let mut note = String::new();
    let _ = write!(
        note,
        "追加 --proxy-server=。CA 注入方式【待验证】：Electron 是否认 NODE_EXTRA_CA_CERTS，\
         Chromium 网络栈是否只认系统证书库，均未实测（SPIKE-04 未开始）。\
         本计划不设置该变量，也不把 CA 装进系统或用户证书库。\
         代理未覆盖的流量按直连标注，URL 记 NA({NA_DIRECT_BYPASS_PROXY})。\
         覆盖率未测，不记录占比。"
    );
    ProxyPlan {
        extra_args: vec![flag],
        ca: CaInjection::Unverified,
        note,
    }
}
