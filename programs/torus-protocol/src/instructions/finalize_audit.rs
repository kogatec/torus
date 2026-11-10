//! finalize_audit: atomic finalization of an audit cycle.
//!
//! In a single instruction:
//!   (Y) completeness: control total vs. obligation (deterministic detection of understatement, attack Y)
//!   (Δ) deviation: claimed vs. independently observed values (overstatement, attack X: residual + defect count)
//!   (T) tax reconciliation: the declared total vs. the tax accountant's book total. Above it (beyond the tolerance)
//!       the cycle is held and payouts wait in the pool; a reconciled report within the hold resumes it (if a gap
//!       remains, only the book total is recognized and paid out, the rest is carried and the cycle cannot pass); no
//!       reconciled report forfeits it. No report by the deadline is the issuer's default. Overstatement found by (Δ)
//!       never waits for the books: it is fraud whatever they say.
//!   (F) tier update (promotion only after consecutive passes; fraud drops to the base tier at once)
//!   (H) escrow: only on fraud, the bond (second account) and the issuer escrow are slashed;
//!       otherwise the issuer share that waited for this audit is released (it stays in the escrow)
//! all before any payout or distribution can be withdrawn (no window to take the money and run).

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{
    self, Mint, TokenAccount, TokenInterface, TransferChecked,
};

use crate::constants::*;
use crate::errors::TorusError;
use crate::rules;
use crate::state::{AuditCycle, Config, Manifest, TokenState};
use crate::state::{load_if_exists, TaxReport};
use crate::tax_rules::{self, TaxVerdict};

pub fn handler(ctx: Context<FinalizeAudit>) -> Result<()> {
    let token_state = &mut ctx.accounts.token_state;
    let manifest = &ctx.accounts.manifest;
    let audit = &mut ctx.accounts.audit;

    // --- Precondition: stage Verified ---
    require!(audit.stage == AuditStage::Verified as u8, TorusError::InvalidAuditStage);
    require!(manifest.active, TorusError::ManifestInactive);
    // All sampled leaves are disclosed (defense in depth). This binds the claimed values of Δ to the commitment
    // and the control total of Y to the tree's sum.
    require!(
        audit.verify_cursor == audit.sample_size,
        TorusError::DisclosuresIncomplete
    );

    // --- Obligation: the value snapshotted at commit (cannot be swapped afterwards) ---
    let obligation = audit.obligation;
    require!(obligation > 0, TorusError::BudgetNotProvisioned);

    // ================= (Δ) Deviation: overstatement (attack X) =================
    // Checked before the tax reconciliation: overstatement is fraud whatever the books say, so it does not wait for them.
    // (a) Aggregate residual: do claims exceed observations by more than the tolerance (over-claim)?
    let residual = audit.asserted_sample_sum.saturating_sub(audit.observed_sum);
    let residual_tolerance = mul_bps(audit.asserted_sample_sum, audit.tolerance_bps)?;
    let residual_breach = residual > residual_tolerance;

    // (b) Defect count: do more sampled elements than the pre-set k deviate beyond the tolerance? Comparing the
    // defect ratio with the per-element tolerance missed defects as the sample grew (29 samples at 5%: one defect,
    // 3.4%, passes). Detection probability is designed from the binomial upper tail including k.
    let defect_breach = audit.defect_count > audit.max_defects;

    let is_overstatement = residual_breach || defect_breach;

    // Uniqueness verified (payment IDs strictly increasing over all leaves, root matching, IDs registered). Without it, a
    // tree inflating its total by repeating the same payment could pass, so a cycle that could pass waits for the proof.
    // Overstatement is fraud with or without it: withholding the proof cannot push that verdict back to the deadline.
    require!(audit.uniqueness_verified || is_overstatement, TorusError::UniquenessNotVerified);

    // What the obligation recognizes: the control total.
    let recognized = audit.control_total;

    // ================= (T) Tax reconciliation: declared total vs. the tax accountant's book total =================
    let now = Clock::get()?.unix_timestamp;
    let report: Option<TaxReport> = load_if_exists(&ctx.accounts.tax_report, &crate::ID)?;
    let tax = tax_rules::tax_verdict(&tax_rules::TaxFacts {
        control_total: audit.control_total,
        tolerance_bps: audit.tolerance_bps,
        report: report.map(|r| (r.book_total, r.refiled)),
        deadline: token_state.audit_deadline,
        hold_until: audit.tax_hold_until,
        now,
    })?;
    // Only a cycle without overstatement waits (tax_rules::waits_for_books): waiting on a fraudulent one would leave the
    // token unfrozen, with the escrow and the bond spendable, until the deadline or the end of the hold.
    if tax_rules::waits_for_books(is_overstatement, tax) {
        match tax {
            TaxVerdict::AwaitReport => return err!(TorusError::TaxReportMissing),
            TaxVerdict::AwaitRefile => return err!(TorusError::TaxHoldActive),
            TaxVerdict::Hold => {
                // Nothing is decided: payouts wait in the pool until a reconciled report comes or the hold ends.
                audit.tax_hold_until = now
                    .checked_add(ctx.accounts.config.tax_hold_period)
                    .ok_or(TorusError::MathOverflow)?;
                msg!(
                    "finalize_audit: on hold until {} (declared total {} above the book total)",
                    audit.tax_hold_until,
                    audit.control_total
                );
                return Ok(());
            }
            _ => {}
        }
    }
    // Only the book total, if a gap remained after the reconciled report.
    let recognized = match tax {
        TaxVerdict::Capped(book) => recognized.min(book),
        _ => recognized,
    };

    // ================= (Y) Completeness: control total vs. obligation =================
    // The control total is bound to the committed ledger (sum-bound tree, uniqueness verified), so it is exactly what
    // the issuer stands behind. A shortfall is not hidden and not slashed: the gap is carried into the next obligation
    // (TokenState.unfulfilled), so under-reporting never makes an obligation disappear. Within the shortfall
    // tolerance (bps) it is an honest shortfall; beyond it the issuer also drops one tier. The threshold is the commit
    // snapshot (cannot be loosened after observations are known).
    let lcl_amount = mul_bps(obligation, audit.shortfall_tolerance_bps)?;
    let understatement_floor = obligation.saturating_sub(lcl_amount);

    // ================= Result =================
    // Overstatement (fraud): slash and drop to the base tier at once. Otherwise: obligation met = pass; below it within
    // the band = honest shortfall; further below = under-delivered.
    // A default or forfeit in the tax reconciliation is slashed too, and a cycle capped by the books never passes.
    let result = rules::judge(&rules::Findings {
        overstatement: is_overstatement,
        recognized,
        obligation,
        floor: understatement_floor,
        tax,
    });

    // ================= (F) Tier update (asymmetric) =================
    match result {
        AuditResult::Pass => {
            token_state.consecutive_passes =
                token_state.consecutive_passes.saturating_add(1);
            if token_state.consecutive_passes >= PROMOTION_CONSECUTIVE_PASSES
                && token_state.tier < MAX_TIER
            {
                token_state.tier += 1;
                token_state.consecutive_passes = 0;
            }
        }
        AuditResult::HonestShortfall => {
            // No promotion: only the streak resets (tier unchanged, nothing slashed).
            token_state.consecutive_passes = 0;
        }
        AuditResult::Underdelivered => {
            // Honest but beyond the band: one tier down, streak reset, nothing slashed, not frozen.
            token_state.tier = token_state.tier.saturating_sub(1);
            token_state.consecutive_passes = 0;
        }
        AuditResult::FraudOverstatement
        | AuditResult::FraudUnderstatement
        | AuditResult::BookMismatch
        => {
            // Fraud: immediate drop to the base tier and freeze.
            token_state.tier = 0;
            token_state.consecutive_passes = 0;
            token_state.frozen = true;
        }
        AuditResult::Pending => return err!(TorusError::InvalidAuditStage),
    }
    token_state.distribution_ratio_bps = token_state.tier_share_bps[token_state.tier as usize];

    // ================= (H) Escrow: slash the bond only on fraud =================
    // Grim trigger: the whole slashing bond moves to the compensation pool. Legitimate redemptions are paid from
    // the redemption pool separately (not touched here).
    let is_fraud = matches!(
        result,
        AuditResult::FraudOverstatement
            | AuditResult::FraudUnderstatement
            | AuditResult::BookMismatch
    );
    if is_fraud {
        let bond_balance = ctx.accounts.slashing_bond.amount;
        if bond_balance > 0 {
            let mint_key = token_state.mint;
            let seeds: &[&[u8]] = &[
                POOL_AUTHORITY_SEED,
                mint_key.as_ref(),
                &[token_state.pool_authority_bump],
            ];
            let signer: &[&[&[u8]]] = &[seeds];

            let decimals = ctx.accounts.usdc_mint.decimals;
            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.slashing_bond.to_account_info(),
                        mint: ctx.accounts.usdc_mint.to_account_info(),
                        to: ctx.accounts.slash_destination.to_account_info(),
                        authority: ctx.accounts.pool_authority.to_account_info(),
                    },
                    signer,
                ),
                bond_balance,
                decimals,
            )?;
        }

        // Slash the whole issuer escrow too (released or not, everything left in it is lost once fraud is established).
        let escrow_balance = ctx.accounts.issuer_escrow.amount;
        if escrow_balance > 0 {
            let mint_key = token_state.mint;
            let seeds: &[&[u8]] = &[
                POOL_AUTHORITY_SEED,
                mint_key.as_ref(),
                &[token_state.pool_authority_bump],
            ];
            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.issuer_escrow.to_account_info(),
                        mint: ctx.accounts.usdc_mint.to_account_info(),
                        to: ctx.accounts.slash_destination.to_account_info(),
                        authority: ctx.accounts.pool_authority.to_account_info(),
                    },
                    &[seeds],
                ),
                escrow_balance,
                ctx.accounts.usdc_mint.decimals,
            )?;
        }
        token_state.issuer_accruing = 0;
        token_state.issuer_pending = 0;
        token_state.issuer_claimable = 0;
        // Nobody can claim leaves of a fraudulent cycle, so release this cycle's reservation (in liquidation it goes to
        // recipients of clean cycles, or to the compensation pool).
        token_state.reserved = token_state.reserved.saturating_sub(obligation);
        audit.reserved_remaining = 0;
    } else {
        // No fraud: this cycle's reservation becomes min(obligation, recognized total). The part of the obligation the
        // recognized total does not reach cannot be claimed in this cycle, so it is released here and carried into the
        // next period's obligation instead (the funds stay in the redemption pool).
        audit.reserved_remaining = obligation.min(recognized);
        // Payouts of this cycle are scaled to it (tax_rules::recognized_share), so a capped cycle pays at most the book
        // total.
        audit.recognized_total = recognized;
        let gap = obligation - audit.reserved_remaining;
        token_state.reserved = token_state.reserved.saturating_sub(gap);
        token_state.unfulfilled = token_state
            .unfulfilled
            .checked_add(gap)
            .ok_or(TorusError::MathOverflow)?;
        // Issuer share: what waited for this audit is released (it stays in the escrow).
        token_state.issuer_claimable = token_state
            .issuer_claimable
            .checked_add(token_state.issuer_pending)
            .ok_or(TorusError::MathOverflow)?;
        token_state.issuer_pending = 0;
        // Basis for a liquidation split (the last audit finalized without fraud).
        token_state.last_good_period = audit.period_id;
    }

    audit.result = result as u8;
    audit.stage = AuditStage::Finalized as u8;

    msg!("finalize_audit: tax={:?}", tax);
    msg!(
        "finalize_audit: result={:?} obligation={} control_total={} recognized={} residual={} defects={}/{} tier->{}",
        result,
        obligation,
        audit.control_total,
        recognized,
        residual,
        audit.defect_count,
        audit.sample_size,
        token_state.tier
    );
    Ok(())
}

/// amount × bps / 10_000 (checked).
fn mul_bps(amount: u64, bps: u16) -> Result<u64> {
    let v = (amount as u128)
        .checked_mul(bps as u128)
        .ok_or(TorusError::MathOverflow)?
        / (BPS_DENOMINATOR as u128);
    Ok(v as u64)
}

#[derive(Accounts)]
pub struct FinalizeAudit<'info> {
    /// Anyone may crank this (pays the transaction fee).
    #[account(mut)]
    pub crank: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
    )]
    pub token_state: Account<'info, TokenState>,

    #[account(
        seeds = [MANIFEST_SEED, token_state.mint.as_ref()],
        bump = manifest.bump,
        constraint = manifest.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub manifest: Account<'info, Manifest>,

    #[account(
        mut,
        seeds = [AUDIT_SEED, token_state.mint.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
        constraint = audit.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub audit: Account<'info, AuditCycle>,

    /// The tax accountant's report on this cycle. It may not exist: none after the deadline is a default. The address is
    /// bound, so a crank cannot hide a filed report.
    /// CHECK: address bound by seeds; read only when this program owns it.
    #[account(seeds = [TAX_REPORT_SEED, token_state.mint.as_ref(), audit.period_id.to_le_bytes().as_ref()], bump)]
    pub tax_report: UncheckedAccount<'info>,

    /// Pool PDA (authority of the redemption pool and the bond).
    /// CHECK: bound by seeds; signs as a program-derived address.
    #[account(
        seeds = [POOL_AUTHORITY_SEED, token_state.mint.as_ref()],
        bump = token_state.pool_authority_bump,
    )]
    pub pool_authority: UncheckedAccount<'info>,

    /// Second account (slashing bond), USDC.
    #[account(
        mut,
        address = token_state.slashing_bond @ TorusError::Unauthorized,
    )]
    pub slashing_bond: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Issuer escrow (USDC). Slashed on fraud.
    #[account(
        mut,
        address = token_state.issuer_escrow @ TorusError::Unauthorized,
    )]
    pub issuer_escrow: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Slash destination: the compensation pool fixed in Config (USDC).
    /// The caller cannot change it, so slashing cannot be redirected to an arbitrary account.
    #[account(
        mut,
        address = config.slash_destination @ TorusError::Unauthorized,
    )]
    pub slash_destination: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(address = token_state.usdc_mint @ TorusError::NonUsdcCollateral)]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    pub token_program: Interface<'info, TokenInterface>,
}
