//! Install and uninstall plans (P1-DAEMON-05).
//!
//! This module **renders** a plan. It does not register a service, talk to the
//! Service Control Manager, systemd, or launchd, and it does not delete
//! directories. An administrator (or CI) applies the plan later.
//!
//! Rendering the same [`MachineState`] twice yields identical bytes. A step
//! that is already satisfied is kept in the plan and marked
//! [`StepEffect::AlreadySatisfied`], so "installed" and "not installed" stay
//! distinguishable without changing the step list.
//!
//! P1 has no proxy CA. [`remove_proxy_ca`] is the hook P3 will fill in. Today
//! it returns [`CaHookResult::NoCa`].

#![allow(dead_code)]

mod plan;
mod render;
pub mod windows;

#[cfg(test)]
mod tests;
