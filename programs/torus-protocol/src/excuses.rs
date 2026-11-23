//! Periods the issuer could not deliver in. A period's obligation is delivered during its window, which the fixed grid
//! places right after the period whose volume it comes from, and a period is provisioned only once the previous audit is
//! final. When that audit stalled (an auditor who did not record, a seed the operator could not reveal, the operator
//! down), the period is provisioned late, possibly after its window is over: the issuer then had no time to deliver,
//! through no fault of its own. Judging it would drop a tier and reset the streak for nothing.
//!   - automatic: a period provisioned after its window was over is excused in full when the previous cycle was held up
//!     by someone else (its auditor was replaced, or its sample was drawn without the operator's seed; or that period
//!     was itself excused, since one long stall can cost more than one window) and the issuer had done its own part of
//!     it on time (its commit, and any report it files for the cycle, within a quarter period after that period's
//!     window ended). An issuer that holds up its own cycle gets no excuse, so stalling never pays; a late provision
//!     with no such stall on the chain (the operator was slow, for example) is left to the auditor.
//!   - by the auditor: for a cause the chain cannot see (an outage, for example), the cycle's auditor may excuse a share
//!     of the judged obligation (excuse_shortfall), with the hash of its reasons.
//! An excused obligation is never forgiven: it stays owed (carried into the next budget, so it stays escrowed and can be
//! delivered) but is not judged again, and whatever is not delivered stays in the redemption pool for the customers'
//! liquidation. A cycle with nothing left to judge is neither a pass nor a shortfall (AuditResult::Excused).
//! Pure functions, unit-tested below.

use anchor_lang::prelude::*;

use crate::errors::TorusError;
use crate::instructions::provision_budget::mul_bps;
use crate::state::{AuditCycle, TokenState};

/// The issuer's own part of a cycle must be done within this share of a period after it could start for a late provision
/// after it to be excused (4: a quarter period).
pub const ON_TIME_PERIOD_DIVISOR: i64 = 4;

/// When the issuer's own steps of a cycle happened, and from when they were possible.
pub struct IssuerSteps {
    /// End of the period's window (the issuer delivers until then and commits after it).
    pub window_end: i64,
    /// When the period was provisioned (a period provisioned late cannot be committed before).
    pub provisioned_ts: i64,
    pub committed_ts: i64,
    /// The last report the issuer filed for the cycle, if any.
    pub last_filed_ts: Option<i64>,
}

/// The issuer's steps of the cycle being finalized (the token is still in that cycle's period).
pub fn steps_of(ts: &TokenState, audit: &AuditCycle, last_filed_ts: Option<i64>) -> Result<IssuerSteps> {
    Ok(IssuerSteps {
        window_end: ts.period_start_ts.checked_add(ts.grid_period_len).ok_or(TorusError::MathOverflow)?,
        provisioned_ts: ts.provisioned_ts,
        committed_ts: audit.committed_ts,
        last_filed_ts,
    })
}

/// Whether the issuer did its own part of a cycle on time: its commit and its last report within a quarter period after
/// they could start (the window's end, or the provision when that came later).
pub fn issuer_on_time(steps: &IssuerSteps, period_len: i64) -> bool {
    let could_start = steps.window_end.max(steps.provisioned_ts);
    let done = steps.last_filed_ts.map_or(steps.committed_ts, |filed| filed.max(steps.committed_ts));
    done <= could_start.saturating_add(period_len / ON_TIME_PERIOD_DIVISOR)
}

/// What a provision reads from the previous cycle (all false when there was none).
#[derive(Clone, Copy, Default)]
pub struct PreviousCycle {
    /// The issuer did its own part of it on time (AuditCycle.issuer_on_time).
    pub on_time: bool,
    /// Someone else held it up: its auditor was replaced, or its sample was drawn without the seed (AuditCycle.held_up).
    pub held_up: bool,
    /// Its period was excused (AuditResult::Excused).
    pub excused: bool,
}

/// The part of a new budget the issuer is judged on: the budget without the carried excused obligation, or nothing when
/// the period's window was already over when it was provisioned because someone else held up the previous cycle, while
/// the issuer had done its own part of it on time.
pub fn judged_budget(budget: u64, excused_carry: u64, window_over: bool, previous: PreviousCycle) -> u64 {
    let stalled_by_others = previous.on_time && (previous.held_up || previous.excused);
    if window_over && stalled_by_others {
        return 0;
    }
    budget.saturating_sub(excused_carry)
}

/// The judged obligation after the auditor excused a share of it (bps).
pub fn after_auditor_excuse(judged: u64, excused_bps: u16) -> Result<u64> {
    Ok(judged.saturating_sub(mul_bps(judged, excused_bps)?))
}

/// How a cycle's unmet obligation (gap) is carried: the part the issuer was judged on and missed is judged again next
/// period; the rest was excused and is only carried. Returns (judged again, only carried).
pub fn split_carry(gap: u64, judged: u64, recognized: u64) -> (u64, u64) {
    let judged_gap = judged.saturating_sub(recognized).min(gap);
    (judged_gap, gap - judged_gap)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEN: i64 = 400;
    const WINDOW_END: i64 = 10_000;

    fn steps(committed_ts: i64, last_filed_ts: Option<i64>) -> IssuerSteps {
        IssuerSteps { window_end: WINDOW_END, provisioned_ts: WINDOW_END - LEN, committed_ts, last_filed_ts }
    }

    #[test]
    fn the_issuer_is_on_time_within_a_quarter_period_of_when_it_could_start() {
        assert!(issuer_on_time(&steps(WINDOW_END + 100, None), LEN));
        assert!(!issuer_on_time(&steps(WINDOW_END + 101, None), LEN), "a late commit");
        // The last report counts too, whether filed before or after the commit.
        assert!(issuer_on_time(&steps(WINDOW_END + 10, Some(WINDOW_END - 50)), LEN));
        assert!(!issuer_on_time(&steps(WINDOW_END + 10, Some(WINDOW_END + 150)), LEN), "a late report");
        // A period provisioned after its window: the allowance runs from the provision.
        let late = IssuerSteps { provisioned_ts: WINDOW_END + 500, ..steps(WINDOW_END + 550, None) };
        assert!(issuer_on_time(&late, LEN));
        let edge = IssuerSteps { window_end: i64::MAX - 1, provisioned_ts: 0, committed_ts: i64::MAX, last_filed_ts: None };
        assert!(issuer_on_time(&edge, LEN), "no overflow at the end of time");
    }

    #[test]
    fn a_lost_window_is_excused_only_after_a_stall_by_others_with_the_issuer_on_time() {
        let held_up = PreviousCycle { on_time: true, held_up: true, excused: false };
        assert_eq!(judged_budget(1_000, 0, true, held_up), 0);
        let after_excused = PreviousCycle { on_time: true, held_up: false, excused: true };
        assert_eq!(judged_budget(1_000, 0, true, after_excused), 0, "one long stall can cost two windows");
        let late_issuer = PreviousCycle { on_time: false, ..held_up };
        assert_eq!(judged_budget(1_000, 0, true, late_issuer), 1_000, "the issuer held up its own cycle");
        let no_stall = PreviousCycle { on_time: true, held_up: false, excused: false };
        assert_eq!(judged_budget(1_000, 0, true, no_stall), 1_000, "a late provision with no stall on the chain");
        assert_eq!(judged_budget(1_000, 0, false, held_up), 1_000, "the window was still open");
        assert_eq!(judged_budget(1_000, 0, true, PreviousCycle::default()), 1_000, "no previous cycle");
        // Carried excused obligation is never judged again.
        assert_eq!(judged_budget(1_000, 300, false, no_stall), 700);
        assert_eq!(judged_budget(200, 300, false, no_stall), 0);
    }

    #[test]
    fn the_auditor_excuses_a_share_of_the_judged_obligation() {
        assert_eq!(after_auditor_excuse(1_000, 0).unwrap(), 1_000);
        assert_eq!(after_auditor_excuse(1_000, 2_500).unwrap(), 750);
        assert_eq!(after_auditor_excuse(1_000, 10_000).unwrap(), 0);
    }

    #[test]
    fn a_cycle_with_nothing_left_to_judge_is_excused() {
        use crate::constants::AuditResult;
        use crate::rules::{judge, Findings};
        let findings = |recognized, obligation, overstatement| Findings {
            overstatement,
            recognized,
            obligation,
            floor: 0,
            tax: crate::tax_rules::TaxVerdict::Clear,
        };
        assert_eq!(judge(&findings(0, 0, false)), AuditResult::Excused);
        assert_eq!(judge(&findings(250, 0, false)), AuditResult::Excused, "what was delivered anyway is paid");
        assert_eq!(judge(&findings(250, 0, true)), AuditResult::FraudOverstatement, "an excuse never covers padding");
        assert_eq!(judge(&findings(250, 250, false)), AuditResult::Pass);
    }

    #[test]
    fn the_unmet_obligation_splits_into_judged_and_excused() {
        // Judged on 700 of 1_000, delivered 500: 200 is judged again, 300 only carried.
        assert_eq!(split_carry(500, 700, 500), (200, 300));
        // Delivered all it was judged on: the rest is only carried.
        assert_eq!(split_carry(300, 700, 700), (0, 300));
        // Nothing excused: the whole gap is judged again (as before excuses existed).
        assert_eq!(split_carry(400, 1_000, 600), (400, 0));
        // Fully excused period with nothing delivered.
        assert_eq!(split_carry(1_000, 0, 0), (0, 1_000));
    }
}
