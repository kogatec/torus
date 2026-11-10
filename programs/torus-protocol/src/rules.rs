//! The rules fixed in code for safety, the judgment of an audit, and the arithmetic of the fee split and the perks.
//!
//! Rates, allocations, shares and fees are negotiated per company and set by the operator; only these rules are
//! fixed here:
//!   - the issuer's share per rank is at most 100% and never decreases as the rank rises
//!   - the local partner's share and the restamp fee are at most 100%
//!   - the perk allocation totals 100% with general ≥ trader ≥ hold
//!   - the trader perk rate is at most half the transfer fee rate
//!   - the hold perk rate is at most 100% and never rises over time (equal steps allowed)
//!   - the ask for listed trader perks is at most 90% and they pay at most 50% of a bill
//!   - the rate that can be listed never lets the issuer's side profit from trading with itself, not even together
//!     with the company's local partner (listable_rate_bps)
//! Pure functions, unit-tested below.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::provision_budget::mul_bps;
use crate::state::PerkParams;
use crate::tax_rules::TaxVerdict;

const FULL_BPS: u16 = BPS_DENOMINATOR as u16;

/// The issuer's share per rank: each at most 100%, never lower for a higher rank.
pub fn check_tier_shares(shares: &[u16; TIERS]) -> Result<()> {
    let capped = shares.iter().all(|&s| s <= FULL_BPS);
    let rising = shares.windows(2).all(|w| w[0] <= w[1]);
    require!(capped && rising, TorusError::InvalidTierShares);
    Ok(())
}

/// A share or fee in bps: at most 100%.
pub fn check_share_bps(bps: u16) -> Result<()> {
    require!(bps <= FULL_BPS, TorusError::InvalidShareBps);
    Ok(())
}

/// Perk terms: allocation 100% with general ≥ trader ≥ hold; hold rates at most 100% and non-increasing; a positive
/// step; restamp fee at most 100%; ask cap at most 90%; usage cap at most 50%.
pub fn check_perk_params(p: &PerkParams) -> Result<()> {
    require!(
        p.max_ask_bps <= MAX_ASK_LIMIT_BPS && p.usage_cap_bps <= USAGE_CAP_LIMIT_BPS,
        TorusError::InvalidPerkMarketTerms
    );
    let total = p.general_bps as u32 + p.trader_bps as u32 + p.hold_bps as u32;
    require!(
        total == BPS_DENOMINATOR as u32 && p.general_bps >= p.trader_bps && p.trader_bps >= p.hold_bps,
        TorusError::InvalidPerkAllocation
    );
    let rates = &p.hold_rate_bps;
    let capped = rates.iter().all(|&r| r <= FULL_BPS);
    let falling = rates.windows(2).all(|w| w[0] >= w[1]);
    require!(capped && falling && p.hold_step_secs > 0, TorusError::InvalidHoldRates);
    check_share_bps(p.restamp_fee_bps)
}

/// Splits the operator's share of a conversion into (local partner, Torus treasury). A revoked partner gets nothing.
pub fn split_operator_share(to_operator: u64, partner_bps: u16, partner_active: bool) -> Result<(u64, u64)> {
    let to_partner = if partner_active { mul_bps(to_operator, partner_bps)? } else { 0 };
    Ok((to_partner, to_operator - to_partner))
}

/// Trader perk rate (bps of the volume sent last period): budget ÷ volume of all registered accounts, at most half
/// the transfer fee rate, so trading with oneself to collect it always loses money.
pub fn trader_rate_bps(budget: u64, registered_volume: u64, transfer_fee_bps: u16) -> u16 {
    let cap = transfer_fee_bps / 2;
    if registered_volume == 0 {
        return 0;
    }
    let rate = (budget as u128) * (BPS_DENOMINATOR as u128) / (registered_volume as u128);
    rate.min(cap as u128) as u16
}

/// Share of the fee (bps) that comes back to nobody working with the issuer: what remains after the issuer's share at
/// the top rank and the local partner's part of the operator's share. Assumes the operator itself does not collude.
pub fn unreturned_fee_share_bps(top_issuer_share_bps: u16, partner_share_bps: u16) -> u16 {
    let operator_share = FULL_BPS.saturating_sub(top_issuer_share_bps) as u32;
    let kept = FULL_BPS.saturating_sub(partner_share_bps) as u32;
    (operator_share * kept / FULL_BPS as u32) as u16
}

/// Rate of last period's volume that can be listed for sale (bps). Half the fee is not enough here: someone tied to the
/// issuer gets part of the fee back (unreturned_fee_share_bps), so sending costs only fee × the unreturned share + the
/// return rate it adds to the obligation. Capping the rate at that cost means selling what wash trading earns never
/// pays, at any ask below 100%.
pub fn listable_rate_bps(
    trader_rate_bps: u16,
    transfer_fee_bps: u16,
    unreturned_share_bps: u16,
    return_rate_bps: u16,
) -> u16 {
    let kept_fee = transfer_fee_bps as u32 * unreturned_share_bps as u32 / FULL_BPS as u32;
    (trader_rate_bps as u32).min(kept_fee + return_rate_bps as u32) as u16
}

/// used + add, if it stays within `limit`.
pub fn within(used: u64, add: u64, limit: u64, exceeded: TorusError) -> Result<u64> {
    let total = used.checked_add(add).ok_or(TorusError::MathOverflow)?;
    if total > limit {
        return Err(exceeded.into());
    }
    Ok(total)
}

/// Hold perk rate for a stamp `age` seconds old: the rate of its step, 0% after the last step.
pub fn hold_rate_bps(p: &PerkParams, age: i64) -> u16 {
    let step = (age.max(0) / p.hold_step_secs.max(1)) as usize;
    p.hold_rate_bps.get(step).copied().unwrap_or(0)
}

/// Purchases eligible for the hold perk this period: minimum balance (base units) × cap per whole token.
pub fn hold_cap(min_balance: u64, cap_per_token: u64, decimals: u8) -> u64 {
    let unit = 10u128.pow(decimals as u32);
    ((min_balance as u128) * (cap_per_token as u128) / unit).min(u64::MAX as u128) as u64
}

/// What finalize_audit found.
pub struct Findings {
    /// The deviation check failed (attack X).
    pub overstatement: bool,
    /// Total recognized for the obligation (the control total).
    /// When the tax reconciliation capped the cycle, the book total instead.
    pub recognized: u64,
    pub obligation: u64,
    /// Obligation − shortfall band.
    pub floor: u64,
    pub tax: TaxVerdict,
}

/// Result of an audit.
/// A default or forfeit in the tax reconciliation comes first; a capped cycle never passes.
pub fn judge(f: &Findings) -> AuditResult {
    match f.tax {
        TaxVerdict::Default => return AuditResult::FraudUnderstatement,
        TaxVerdict::Forfeit => return AuditResult::BookMismatch,
        _ => {}
    }
    let met = f.recognized >= f.obligation;
    let met = met && !matches!(f.tax, TaxVerdict::Capped(_));
    if f.overstatement {
        AuditResult::FraudOverstatement
    } else if f.recognized < f.floor {
        AuditResult::Underdelivered
    } else if met {
        AuditResult::Pass
    } else {
        AuditResult::HonestShortfall
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> PerkParams {
        PerkParams {
            general_bps: 6_000,
            trader_bps: 2_500,
            hold_bps: 1_500,
            hold_rate_bps: [3_000, 2_000, 1_000],
            hold_step_secs: 60,
            cap_per_token: 1_000_000,
            restamp_fee_bps: 0,
            max_ask_bps: 8_000,
            usage_cap_bps: 3_000,
        }
    }

    #[test]
    fn tier_shares_rise_and_stay_capped() {
        assert!(check_tier_shares(&[2_000, 3_500, 5_000, 6_500]).is_ok());
        assert!(check_tier_shares(&[3_000, 3_000, 3_000, 3_000]).is_ok());
        assert!(check_tier_shares(&[0, 0, 0, 10_000]).is_ok());
        assert!(check_tier_shares(&[3_000, 2_000, 5_000, 6_500]).is_err());
        assert!(check_tier_shares(&[2_000, 3_500, 5_000, 10_001]).is_err());
    }

    #[test]
    fn shares_and_fees_at_most_full() {
        assert!(check_share_bps(0).is_ok());
        assert!(check_share_bps(10_000).is_ok());
        assert!(check_share_bps(10_001).is_err());
    }

    #[test]
    fn perk_allocation_totals_full_in_order() {
        assert!(check_perk_params(&params()).is_ok());
        let mut p = params();
        p.general_bps = 5_000; // 95% in total
        assert!(check_perk_params(&p).is_err());
        let mut p = params();
        (p.general_bps, p.trader_bps) = (2_500, 6_000); // trader above general
        assert!(check_perk_params(&p).is_err());
        let mut p = params();
        (p.trader_bps, p.hold_bps) = (1_500, 2_500); // hold above trader
        assert!(check_perk_params(&p).is_err());
        let mut p = params();
        (p.general_bps, p.trader_bps, p.hold_bps) = (10_000, 0, 0); // general returns only
        assert!(check_perk_params(&p).is_ok());
    }

    #[test]
    fn hold_rates_never_rise_and_need_a_step() {
        let mut p = params();
        p.hold_rate_bps = [2_000, 2_000, 2_000];
        assert!(check_perk_params(&p).is_ok());
        p.hold_rate_bps = [1_000, 2_000, 0];
        assert!(check_perk_params(&p).is_err());
        p.hold_rate_bps = [10_001, 0, 0];
        assert!(check_perk_params(&p).is_err());
        let mut p = params();
        p.hold_step_secs = 0;
        assert!(check_perk_params(&p).is_err());
        let mut p = params();
        p.restamp_fee_bps = 10_001;
        assert!(check_perk_params(&p).is_err());
    }

    #[test]
    fn operator_share_split_with_the_local_partner() {
        assert_eq!(split_operator_share(10_000, 3_000, true).unwrap(), (3_000, 7_000));
        assert_eq!(split_operator_share(10_000, 3_000, false).unwrap(), (0, 10_000));
        assert_eq!(split_operator_share(10_000, 10_000, true).unwrap(), (10_000, 0));
        assert_eq!(split_operator_share(7, 5_000, true).unwrap(), (3, 4)); // rounding favors the treasury
    }

    #[test]
    fn trader_rate_is_budget_over_volume_capped_at_half_the_fee() {
        assert_eq!(trader_rate_bps(1_000, 1_000_000, 100), 10); // 0.1%
        assert_eq!(trader_rate_bps(1_000_000, 1_000_000, 100), 50); // capped at half of 1%
        assert_eq!(trader_rate_bps(1_000, 0, 100), 0);
        assert_eq!(trader_rate_bps(0, 1_000, 100), 0);
    }

    #[test]
    fn self_dealing_for_the_trader_perk_always_loses() {
        // Sending v costs v × fee; the perk returns at most v × fee / 2.
        for fee in [1u16, 2, 99, 100, 10_000] {
            let rate = trader_rate_bps(u64::MAX / 2, 1, fee);
            assert!(rate as u32 * 2 <= fee as u32);
        }
    }

    #[test]
    fn perk_market_terms_stay_within_the_fixed_limits() {
        let mut p = params();
        (p.max_ask_bps, p.usage_cap_bps) = (MAX_ASK_LIMIT_BPS, USAGE_CAP_LIMIT_BPS);
        assert!(check_perk_params(&p).is_ok());
        (p.max_ask_bps, p.usage_cap_bps) = (0, 0); // listing off
        assert!(check_perk_params(&p).is_ok());
        (p.max_ask_bps, p.usage_cap_bps) = (MAX_ASK_LIMIT_BPS + 1, 3_000);
        assert!(check_perk_params(&p).is_err());
        (p.max_ask_bps, p.usage_cap_bps) = (8_000, USAGE_CAP_LIMIT_BPS + 1);
        assert!(check_perk_params(&p).is_err());
    }

    #[test]
    fn listable_rate_follows_the_issuer_share_and_the_return_rate() {
        // Fee 1%, trader rate at its cap of 0.5%. Ranks 50/60/70/80%.
        let rate = |trader: u16, share: u16, ret: u16| listable_rate_bps(trader, 100, unreturned_fee_share_bps(share, 0), ret);
        assert_eq!(rate(50, 5_000, 10), 50); // 0.5% kept + 0.1% return
        assert_eq!(rate(50, 7_000, 10), 40);
        assert_eq!(rate(50, 8_000, 10), 30);
        assert_eq!(rate(50, 8_000, 30), 50);
        assert_eq!(rate(12, 8_000, 30), 12); // never above the trader rate
        assert_eq!(rate(50, 10_000, 0), 0); // the whole fee comes back: nothing can be sold
        assert_eq!(rate(50, 11_000, 0), 0); // an out-of-range share cannot underflow
    }

    #[test]
    fn listable_rate_counts_what_comes_back_to_the_local_partner() {
        // Fee 1%, top share 80%, return 0.1%: with a partner on 50% of the operator's share, sending costs only 0.2%.
        assert_eq!(unreturned_fee_share_bps(8_000, 5_000), 1_000);
        assert_eq!(listable_rate_bps(50, 100, unreturned_fee_share_bps(8_000, 5_000), 10), 20);
        assert_eq!(listable_rate_bps(50, 100, unreturned_fee_share_bps(8_000, 10_000), 10), 10); // only the return rate is left
        assert_eq!(unreturned_fee_share_bps(8_000, 11_000), 0); // an out-of-range share cannot underflow
    }

    #[test]
    fn selling_what_wash_trading_earns_never_pays() {
        for fee in [25u32, 50, 100, 200, 10_000] {
            for share in [0u32, 2_000, 5_000, 6_500, 8_000, 9_000, 10_000] {
                for ret in [0u32, 5, 10, 30, 50, 5_000] {
                    for ask in [1u32, 5_000, 8_000, MAX_ASK_LIMIT_BPS as u32] {
                        let rate = trader_rate_bps(u64::MAX / 2, 1, fee as u16) as u32;
                        for partner in [0u32, 2_000, 5_000, 10_000] {
                            let unreturned = unreturned_fee_share_bps(share as u16, partner as u16);
                            let listable = listable_rate_bps(rate as u16, fee as u16, unreturned, ret as u16) as u64;
                            // Per unit sent, scaled by BPS³: what the sale earns vs. what sending costs.
                            let earned = listable * ask as u64 * 10_000;
                            let (fee, share, partner, ret) = (fee as u64, share as u64, partner as u64, ret as u64);
                            let cost_insider = fee * (10_000 - share) * (10_000 - partner) + ret * 100_000_000;
                            let cost_outsider = fee * 100_000_000;
                            assert!(earned <= cost_insider, "insider: fee {fee} share {share} partner {partner} ret {ret} ask {ask}");
                            assert!(earned < cost_outsider, "outsider: fee {fee} share {share} partner {partner} ret {ret} ask {ask}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn half_the_fee_alone_lets_an_insider_profit() {
        // Why listable_rate_bps exists: fee 1%, share 80%, return 0.1%, rate 0.5%, ask 80%.
        let (rate, ask, cost) = (50u32, 8_000u32, (100 * 2_000 / 10_000 + 10) * 10_000);
        assert!(rate * ask > cost);
        assert!(listable_rate_bps(50, 100, unreturned_fee_share_bps(8_000, 0), 10) as u32 * ask <= cost);
    }

    #[test]
    fn within_adds_up_to_the_limit() {
        assert_eq!(within(10, 5, 15, TorusError::PerkBudgetExceeded).unwrap(), 15);
        assert!(within(10, 6, 15, TorusError::PerkBudgetExceeded).is_err());
        assert!(within(u64::MAX, 1, u64::MAX, TorusError::PerkBudgetExceeded).is_err());
    }

    #[test]
    fn hold_rate_falls_by_step_then_zero() {
        let p = params();
        assert_eq!(hold_rate_bps(&p, 0), 3_000);
        assert_eq!(hold_rate_bps(&p, 59), 3_000);
        assert_eq!(hold_rate_bps(&p, 60), 2_000);
        assert_eq!(hold_rate_bps(&p, 179), 1_000);
        assert_eq!(hold_rate_bps(&p, 180), 0);
        assert_eq!(hold_rate_bps(&p, i64::MAX), 0);
        assert_eq!(hold_rate_bps(&p, -5), 3_000); // a stamp in the future counts as fresh
    }

    #[test]
    fn registration_stamp_starts_at_zero_percent() {
        // register_holder stamps the existing balance HOLD_STEPS steps back.
        let p = params();
        assert_eq!(hold_rate_bps(&p, p.hold_step_secs * HOLD_STEPS as i64), 0);
    }

    #[test]
    fn hold_cap_is_minimum_balance_times_cap_per_token() {
        assert_eq!(hold_cap(2_000_000, 500_000, 6), 1_000_000); // 2 tokens × 0.5
        assert_eq!(hold_cap(0, 500_000, 6), 0);
        assert_eq!(hold_cap(u64::MAX, u64::MAX, 0), u64::MAX);
    }

    fn findings(overstatement: bool, recognized: u64) -> Findings {
        Findings {
            overstatement,
            recognized,
            obligation: 1_000,
            floor: 900,
            tax: TaxVerdict::Clear,
        }
    }

    #[test]
    fn judge_keeps_the_existing_results() {
        assert_eq!(judge(&findings(false, 1_000)), AuditResult::Pass);
        assert_eq!(judge(&findings(false, 950)), AuditResult::HonestShortfall);
        assert_eq!(judge(&findings(false, 899)), AuditResult::Underdelivered);
        assert_eq!(judge(&findings(true, 1_000)), AuditResult::FraudOverstatement);
    }
}
