//! When an audit is due (TokenState.audit_deadline). After the deadline, anyone can declare a default for what the issuer
//! has not supplied (declare_default), and the operator can replace an auditor who has not recorded (replace_auditor).
//! So the deadline must never cut the issuer short:
//!   - it follows the provisioned period's window, one period after it ends, whoever cranked the provision and whenever
//!     (after_provision): the issuer delivers until the window ends and commits after it;
//!   - it leaves at least one period after the sample is drawn, however late the draw came, and after the auditor is
//!     replaced, for the new auditor to observe (extend).
//! Pure functions, unit-tested below.

use anchor_lang::prelude::*;

use crate::errors::TorusError;

/// The deadline set when a period is provisioned (`window_start` is where the provisioned period's window starts): one
/// period after that window ends, or one period after now when the window is already over (a late provision). A crank
/// right at the boundary therefore cannot leave the issuer without time to commit what it delivered in the window.
pub fn after_provision(now: i64, window_start: i64, period_len: i64) -> Result<i64> {
    let window_end = window_start.checked_add(period_len).ok_or(TorusError::MathOverflow)?;
    Ok(now.max(window_end).checked_add(period_len).ok_or(TorusError::MathOverflow)?)
}

/// A deadline leaving at least one period from now (a later one is kept).
pub fn extend(deadline: i64, now: i64, period_len: i64) -> Result<i64> {
    let earliest = now.checked_add(period_len).ok_or(TorusError::MathOverflow)?;
    Ok(deadline.max(earliest))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEN: i64 = 100;

    #[test]
    fn provision_deadline_follows_the_window_not_the_crank() {
        // The provisioned window is [1_000, 1_100): cranked at its start or in its middle, the deadline is one period
        // after it ends (the issuer always has a whole period to commit and disclose).
        assert_eq!(after_provision(1_000, 1_000, LEN).unwrap(), 1_200);
        assert_eq!(after_provision(1_050, 1_000, LEN).unwrap(), 1_200);
        // Provisioned after its window was over (a stalled audit before it): one period from the crank.
        assert_eq!(after_provision(1_150, 1_000, LEN).unwrap(), 1_250);
        assert!(after_provision(0, i64::MAX, LEN).is_err());
        assert!(after_provision(i64::MAX, 0, LEN).is_err());
    }

    #[test]
    fn a_late_draw_or_replacement_still_leaves_one_period() {
        assert_eq!(extend(1_200, 1_050, LEN).unwrap(), 1_200); // a period or more left: kept
        assert_eq!(extend(1_200, 1_150, LEN).unwrap(), 1_250); // less than a period left
        assert_eq!(extend(1_200, 1_300, LEN).unwrap(), 1_400); // drawn after the deadline
        assert!(extend(0, i64::MAX, LEN).is_err());
    }
}
