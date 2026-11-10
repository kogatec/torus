//! The arithmetic of the tax reconciliation: what the tax accountant's report means for finalizing a cycle, and what
//! each leaf of a cycle capped by the books is paid. Pure functions, unit-tested below.

use anchor_lang::prelude::*;

use crate::errors::TorusError;
use crate::instructions::provision_budget::mul_bps;

/// What the tax accountant's report means for finalizing a cycle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaxVerdict {
    /// The declared total is within the tolerance of the book total.
    Clear,
    /// A reconciled report still shows a gap: only the book total is recognized, and the cycle cannot pass.
    Capped(u64),
    /// The declared total exceeds the book total: hold the cycle (payouts wait) for a reconciled report.
    Hold,
    /// No report yet and the deadline has not passed.
    AwaitReport,
    /// On hold, no reconciled report yet, the hold has not ended.
    AwaitRefile,
    /// No report by the deadline: the issuer's default.
    Default,
    /// No reconciled report within the hold: forfeited.
    Forfeit,
}

/// Inputs of the tax reconciliation at finalization.
pub struct TaxFacts {
    /// The issuer's declared total (control total of the committed ledger).
    pub control_total: u64,
    /// Tolerance (bps), the cycle's snapshot.
    pub tolerance_bps: u16,
    /// (book total, filed again during the hold), if a report exists.
    pub report: Option<(u64, bool)>,
    /// Deadline of the first report (the audit deadline).
    pub deadline: i64,
    /// End of the hold (0 = none).
    pub hold_until: i64,
    pub now: i64,
}

/// Reads the report against the declared total: no report (wait or default), within the tolerance (clear), above it
/// (hold, then resume, cap or forfeit).
pub fn tax_verdict(f: &TaxFacts) -> Result<TaxVerdict> {
    let Some((book, refiled)) = f.report else {
        return Ok(if f.now > f.deadline { TaxVerdict::Default } else { TaxVerdict::AwaitReport });
    };
    let allowed = book
        .checked_add(mul_bps(book, f.tolerance_bps)?)
        .ok_or(TorusError::MathOverflow)?;
    if f.control_total <= allowed {
        return Ok(TaxVerdict::Clear);
    }
    if f.hold_until == 0 {
        return Ok(TaxVerdict::Hold);
    }
    if refiled {
        return Ok(TaxVerdict::Capped(book));
    }
    Ok(if f.now > f.hold_until { TaxVerdict::Forfeit } else { TaxVerdict::AwaitRefile })
}

/// Whether finalization waits for the tax reconciliation (the report, the start of a hold, or a reconciled report).
/// Overstatement found by the deviation check is fraud whatever the books say, so it never waits: a wait would leave the
/// token unfrozen, with the escrow and the bond still spendable, until the deadline or the end of the hold.
pub fn waits_for_books(overstatement: bool, tax: TaxVerdict) -> bool {
    let waiting = matches!(tax, TaxVerdict::AwaitReport | TaxVerdict::AwaitRefile | TaxVerdict::Hold);
    waiting && !overstatement
}

/// What a leaf is paid when the reconciliation capped its cycle at the book total: its amount × recognized ÷ control
/// total. The cycle then pays at most the book total, and the gap carried into the next obligation is not paid twice.
/// Unchanged when the whole control total is recognized.
pub fn recognized_share(amount: u64, recognized: u64, control_total: u64) -> u64 {
    if recognized >= control_total {
        return amount;
    }
    ((amount as u128) * (recognized as u128) / (control_total as u128)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::AuditResult;
    use crate::rules::{judge, Findings};

    fn facts(report: Option<(u64, bool)>, hold_until: i64, now: i64) -> TaxFacts {
        TaxFacts { control_total: 1_000, tolerance_bps: 500, report, deadline: 100, hold_until, now }
    }

    fn findings(overstatement: bool, recognized: u64, tax: TaxVerdict) -> Findings {
        Findings { overstatement, recognized, obligation: 1_000, floor: 900, tax }
    }

    #[test]
    fn tax_report_missing_waits_then_defaults() {
        assert_eq!(tax_verdict(&facts(None, 0, 100)).unwrap(), TaxVerdict::AwaitReport);
        assert_eq!(tax_verdict(&facts(None, 0, 101)).unwrap(), TaxVerdict::Default);
    }

    #[test]
    fn tax_within_tolerance_clears() {
        assert_eq!(tax_verdict(&facts(Some((1_000, false)), 0, 50)).unwrap(), TaxVerdict::Clear);
        assert_eq!(tax_verdict(&facts(Some((953, false)), 0, 50)).unwrap(), TaxVerdict::Clear); // 953 + 47 = 1000
        assert_eq!(tax_verdict(&facts(Some((5_000, false)), 0, 50)).unwrap(), TaxVerdict::Clear);
    }

    #[test]
    fn tax_gap_holds_then_resumes_caps_or_forfeits() {
        assert_eq!(tax_verdict(&facts(Some((900, false)), 0, 50)).unwrap(), TaxVerdict::Hold);
        assert_eq!(tax_verdict(&facts(Some((900, false)), 200, 150)).unwrap(), TaxVerdict::AwaitRefile);
        assert_eq!(tax_verdict(&facts(Some((900, false)), 200, 201)).unwrap(), TaxVerdict::Forfeit);
        assert_eq!(tax_verdict(&facts(Some((1_000, true)), 200, 150)).unwrap(), TaxVerdict::Clear);
        assert_eq!(tax_verdict(&facts(Some((900, true)), 200, 150)).unwrap(), TaxVerdict::Capped(900));
        assert_eq!(tax_verdict(&facts(Some((900, true)), 200, 900)).unwrap(), TaxVerdict::Capped(900));
    }

    #[test]
    fn judge_tax_outcomes() {
        assert_eq!(judge(&findings(false, 1_000, TaxVerdict::Default)), AuditResult::FraudUnderstatement);
        assert_eq!(judge(&findings(false, 1_000, TaxVerdict::Forfeit)), AuditResult::BookMismatch);
        // A capped cycle never passes, even when the book total covers the obligation.
        assert_eq!(judge(&findings(false, 1_000, TaxVerdict::Capped(1_000))), AuditResult::HonestShortfall);
        assert_eq!(judge(&findings(false, 800, TaxVerdict::Capped(800))), AuditResult::Underdelivered);
    }

    #[test]
    fn overstatement_is_judged_without_waiting_for_the_books() {
        for waiting in [TaxVerdict::AwaitReport, TaxVerdict::AwaitRefile, TaxVerdict::Hold] {
            assert!(waits_for_books(false, waiting));
            assert!(!waits_for_books(true, waiting));
            assert_eq!(judge(&findings(true, 1_000, waiting)), AuditResult::FraudOverstatement);
        }
        for decided in [TaxVerdict::Clear, TaxVerdict::Capped(900), TaxVerdict::Default, TaxVerdict::Forfeit] {
            assert!(!waits_for_books(false, decided));
            assert!(!waits_for_books(true, decided));
        }
    }

    #[test]
    fn a_capped_cycle_pays_each_leaf_its_share_of_the_book_total() {
        assert_eq!(recognized_share(125_000, 1_000_000, 1_000_000), 125_000); // nothing capped: unchanged
        assert_eq!(recognized_share(125_000, 950_000, 1_000_000), 118_750);
        let leaves = [333_333u64, 333_333, 333_334];
        let paid: u64 = leaves.iter().map(|&v| recognized_share(v, 500_000, 1_000_000)).sum();
        assert!(paid <= 500_000, "the leaves together never get more than the book total");
        assert_eq!(recognized_share(u64::MAX, u64::MAX - 1, u64::MAX), u64::MAX - 1); // no overflow
        assert_eq!(recognized_share(7, 0, 10), 0);
    }
}
