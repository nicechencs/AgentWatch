//! Launch hint when a Cursor instance may already be running.
//!
//! Pure. The caller passes [`ExistingInstance`]. This module does not scan
//! `/proc`, does not call a process API, and does not start Cursor.
//!
//! A second launch that only hands work to an existing window is an attribution
//! break: the new process is in the session, the existing tree is not. The
//! marker is a label for the timeline. It is not a finding record and it does
//! not assert what the existing instance did.

/// Whether the caller already observed a Cursor instance.
///
/// This crate does not decide. Passing [`ExistingInstance::AlreadyRunning`]
/// without an observation is the caller's error, not something we infer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingInstance {
    /// Caller says no Cursor process is running.
    None,
    /// Caller says an instance is already running.
    AlreadyRunning,
}

/// What the user chose after the hint, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchChoice {
    /// Stop and show the hint. Do not append launch args.
    Ask,
    /// User asked to launch anyway.
    Insist,
}

/// Why a launch would not cover the already-running tree.
///
/// Wording id in the evidence model is `attr.break`. This adapter only names
/// the condition; it does not emit the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributionBreak {
    /// A new Cursor launch hands off to an instance that is outside the session.
    SecondInstanceHandoff,
}

impl AttributionBreak {
    /// Stable marker string for session metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecondInstanceHandoff => "attribution_break",
        }
    }
}

/// Result of [`plan_launch`]. No process was started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    existing: ExistingInstance,
    choice: LaunchChoice,
    /// Set only when the user insists on launching beside an existing instance.
    break_marker: Option<AttributionBreak>,
    /// Text for the CLI. Empty when there is nothing to warn about.
    message: String,
}

impl LaunchPlan {
    /// Instance flag the caller supplied.
    #[must_use]
    pub const fn existing(&self) -> ExistingInstance {
        self.existing
    }

    /// User choice the caller supplied.
    #[must_use]
    pub const fn choice(&self) -> LaunchChoice {
        self.choice
    }

    /// `Some` only for insist-while-already-running.
    #[must_use]
    pub const fn attribution_break(&self) -> Option<AttributionBreak> {
        self.break_marker
    }

    /// Hint text. Does not include a path, argv, or a process id.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Arguments this plan would append. Always empty: Cursor is not given a
    /// flag by this function. Proxy args live in [`super::plan_proxy`].
    #[must_use]
    pub fn extra_args(&self) -> &[String] {
        &[]
    }
}

/// Choose the hint or the attribution-break marker.
///
/// - No existing instance: empty message, no marker.
/// - Existing instance and [`LaunchChoice::Ask`]: message asks the user to quit
///   and restart, or to use attach mode. No marker yet.
/// - Existing instance and [`LaunchChoice::Insist`]: same situation, plus
///   [`AttributionBreak::SecondInstanceHandoff`].
#[must_use]
pub fn plan_launch(existing: ExistingInstance, choice: LaunchChoice) -> LaunchPlan {
    match (existing, choice) {
        (ExistingInstance::None, _) => LaunchPlan {
            existing,
            choice,
            break_marker: None,
            message: String::new(),
        },
        (ExistingInstance::AlreadyRunning, LaunchChoice::Ask) => LaunchPlan {
            existing,
            choice,
            break_marker: None,
            message: "已有 Cursor 实例。请退出后重启，或改用附着模式。".to_owned(),
        },
        (ExistingInstance::AlreadyRunning, LaunchChoice::Insist) => LaunchPlan {
            existing,
            choice,
            break_marker: Some(AttributionBreak::SecondInstanceHandoff),
            message: "已有 Cursor 实例。用户仍要求启动。会话将记录 attribution_break：新进程可能把工作交给会话外的已有实例，已有实例不在本次范围内。"
                .to_owned(),
        },
    }
}
