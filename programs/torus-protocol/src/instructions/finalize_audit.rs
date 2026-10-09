//! finalize_audit: atomic finalization of an audit cycle.
//!
//! In a single instruction:
//!   (Y) completeness: control total vs. obligation (deterministic detection of understatement, attack Y)
//!   (Δ) deviation: claimed vs. independently observed values (overstatement, attack X: residual + defect count)
//!   (F) tier update (promotion only after consecutive passes; fraud drops to the base tier at once)
//!   (H) escrow: only on fraud, the bond (second account) and the issuer escrow are slashed;
//!       otherwise the issuer share that waited for this audit becomes claimable
//! all before any payout or distribution can be withdrawn (no window to take the money and run).

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{
    self, Mint, TokenAccount, TokenInterface, TransferChecked,
};

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{AuditCycle, Config, Manifest, TokenState};

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
    // Uniqueness verified (payment IDs strictly increasing over all leaves, root matching, IDs registered). Without
    // it, a tree inflating its total by repeating the same payment could pass.
    require!(audit.uniqueness_verified, TorusError::UniquenessNotVerified);

    // --- Obligation: the value snapshotted at commit (cannot be swapped afterwards) ---
    let obligation = audit.obligation;
    require!(obligation > 0, TorusError::BudgetNotProvisioned);

    // ================= (Y) Completeness: understatement (attack Y) =================
    // A shortfall within the shortfall tolerance (bps) is allowed; falling further below the obligation is understatement.
    // The threshold is the commit snapshot (cannot be loosened after observations are known).
    let lcl_amount = mul_bps(obligation, audit.shortfall_tolerance_bps)?;
    let understatement_floor = obligation.saturating_sub(lcl_amount);
    let is_understatement = audit.control_total < understatement_floor;

    // ================= (Δ) Deviation: overstatement (attack X) =================
    // (a) Aggregate residual: do claims exceed observations by more than the tolerance (over-claim)?
    let residual = audit.asserted_sample_sum.saturating_sub(audit.observed_sum);
    let residual_tolerance = mul_bps(audit.asserted_sample_sum, audit.tolerance_bps)?;
    let residual_breach = residual > residual_tolerance;

    // (b) Defect count: do more sampled elements than the pre-set k deviate beyond the tolerance? Comparing the
    // defect ratio with the per-element tolerance missed defects as the sample grew (29 samples at 5%: one defect,
    // 3.4%, passes). Detection probability is designed from the binomial upper tail including k.
    let defect_breach = audit.defect_count > audit.max_defects;

    let is_overstatement = residual_breach || defect_breach;

    // ================= Result =================
    // Any fraud: slash and drop to the base tier at once.
    // No fraud and obligation met = pass; below it but within the band = honest shortfall.
    let result: AuditResult = if is_overstatement {
        AuditResult::FraudOverstatement
    } else if is_understatement {
        AuditResult::FraudUnderstatement
    } else if audit.control_total >= obligation {
        AuditResult::Pass
    } else {
        AuditResult::HonestShortfall
    };

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
        AuditResult::FraudOverstatement | AuditResult::FraudUnderstatement => {
            // Fraud: immediate drop to the base tier and freeze.
            token_state.tier = 0;
            token_state.consecutive_passes = 0;
            token_state.frozen = true;
        }
        AuditResult::Pending => return err!(TorusError::InvalidAuditStage),
    }
    token_state.distribution_ratio_bps = TIER_DISTRIBUTION_BPS[token_state.tier as usize];

    // ================= (H) Escrow: slash the bond only on fraud =================
    // Grim trigger: the whole slashing bond moves to the compensation pool. Legitimate redemptions are paid from
    // the redemption pool separately (not touched here).
    let is_fraud = matches!(
        result,
        AuditResult::FraudOverstatement | AuditResult::FraudUnderstatement
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

        // Slash the whole issuer escrow too (shares not yet released are lost once fraud is established).
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
        // Clean result: this cycle's reservation becomes min(obligation, control total). The part of the obligation the
        // control total does not reach (honest shortfall) cannot be claimed by anyone, so it is released.
        audit.reserved_remaining = obligation.min(audit.control_total);
        token_state.reserved = token_state
            .reserved
            .saturating_sub(obligation - audit.reserved_remaining);
        // Issuer share: what waited for this audit becomes claimable.
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

    msg!(
        "finalize_audit: result={:?} obligation={} control_total={} residual={} defects={}/{} tier->{}",
        result,
        obligation,
        audit.control_total,
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
