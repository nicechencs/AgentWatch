//! P2-MAC-02: open-subscription budget on a virtual clock.
//! CPU samples are supplied by the test. Nothing is spawned or measured.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use aw_collector_macos::{BudgetDecision, LineDecoder, OpenBudget, SubscribeOpen};
use aw_core::{EventKind, GapKind};

const SEC: u64 = 1_000_000_000;

fn gap_detail(budget: &mut OpenBudget, decoder: &mut LineDecoder, at: u64) -> Option<String> {
    let decoded = budget.take_gap(decoder, at, 1_700_000_000_000_000_000)?;
    let event = decoded.event.expect("gap event");
    match event.kind {
        EventKind::Gap(gap) => {
            assert_eq!(gap.gap_kind, GapKind::RateLimited);
            assert_eq!(gap.affects, ["file"]);
            assert_eq!(gap.count, None, "an uncounted drop stays absent");
            gap.detail
        }
        other => panic!("expected a gap, got {}", other.kind_name()),
    }
}

#[test]
fn sustained_cpu_unsubscribes_open_once_and_records_a_gap() {
    let mut budget = OpenBudget::new(SubscribeOpen::Auto);
    let mut decoder = LineDecoder::new();
    assert!(!budget.open_unsubscribed());
    assert_eq!(
        budget.observe(6, 0),
        BudgetDecision::Hold,
        "the first over-budget sample only starts the timer"
    );
    assert_eq!(budget.observe(6, 29 * SEC), BudgetDecision::Hold);
    assert!(!budget.open_unsubscribed());
    assert_eq!(budget.observe(6, 30 * SEC), BudgetDecision::Unsubscribed);
    assert!(budget.open_unsubscribed());
    assert!(budget.subscription().close);
    assert!(!budget.subscription().open);
    assert_eq!(
        gap_detail(&mut budget, &mut decoder, 30 * SEC).as_deref(),
        Some("eslogger open unsubscribed")
    );
    assert!(
        budget.take_gap(&mut decoder, 31 * SEC, 0).is_none(),
        "a second take does not invent another gap"
    );
    assert_eq!(
        budget.observe(90, 31 * SEC),
        BudgetDecision::Unchanged,
        "open stays off without a second gap"
    );
}

#[test]
fn a_dip_under_the_ceiling_restarts_the_timer() {
    let mut budget = OpenBudget::new(SubscribeOpen::Auto);
    assert_eq!(budget.observe(6, 0), BudgetDecision::Hold);
    assert_eq!(budget.observe(5, 20 * SEC), BudgetDecision::Hold);
    assert_eq!(budget.observe(6, 21 * SEC), BudgetDecision::Hold);
    assert_eq!(budget.observe(6, 50 * SEC), BudgetDecision::Hold);
    assert_eq!(budget.observe(6, 51 * SEC), BudgetDecision::Unsubscribed);
}

#[test]
fn forced_modes_ignore_cpu_and_write_no_gap() {
    let mut on = OpenBudget::new(SubscribeOpen::On);
    let mut off = OpenBudget::new(SubscribeOpen::Off);
    let mut decoder = LineDecoder::new();
    assert_eq!(on.observe(100, 0), BudgetDecision::Unchanged);
    assert_eq!(on.observe(100, 60 * SEC), BudgetDecision::Unchanged);
    assert!(!on.open_unsubscribed());
    assert!(off.open_unsubscribed());
    assert_eq!(off.observe(100, 60 * SEC), BudgetDecision::Unchanged);
    assert!(on.take_gap(&mut decoder, 60 * SEC, 0).is_none());
    assert!(off.take_gap(&mut decoder, 60 * SEC, 0).is_none());
}

#[test]
fn unknown_mode_text_is_not_auto() {
    assert_eq!(SubscribeOpen::parse("auto"), Some(SubscribeOpen::Auto));
    assert_eq!(SubscribeOpen::parse(" on "), Some(SubscribeOpen::On));
    assert_eq!(SubscribeOpen::parse("off"), Some(SubscribeOpen::Off));
    assert_eq!(SubscribeOpen::parse("yes"), None);
    let mut short = OpenBudget::with_threshold(SubscribeOpen::Auto, 5, Duration::from_secs(0));
    assert_eq!(short.observe(6, 0), BudgetDecision::Hold);
    assert_eq!(short.observe(6, 0), BudgetDecision::Unsubscribed);
}
