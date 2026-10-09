//! provision_budget: closes a period and provisions its obligation.
//!
//! Derives the budget deterministically: the closed period's on-chain volume × the fixed return rate. The volume
//! comes from the hook's VolumeCounter (cumulative, monotonic, owned by torus_hook), read here as raw bytes;
//! the period's activity is the difference between the cumulative values at its two boundaries.
//! Anyone can crank it (the signer only pays the transaction fee).

use anchor_lang::prelude::*;
use anchor_spl::token_interface::TokenAccount;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{AuditCycle, Config, Manifest, TokenState};

/// Byte offset of total (u64) in VolumeCounter.
/// Layout: [0..8] Anchor discriminator + [8..40] mint (Pubkey) + [40..48] total (u64 LE)
///         + [48] bump (u8) + [49..57] fee_total (u64 LE).
const VOLUME_TOTAL_OFFSET: usize = 8 + 32;
/// Byte offset of fee_total (u64) in VolumeCounter (cumulative expected fee, per transfer).
const VOLUME_FEE_TOTAL_OFFSET: usize = 8 + 32 + 8 + 1;
/// Cumulative volume recorded at period boundaries (written by the hook):
///   [57..65) last_snap_idx: u64 / [65..73) snap_count: u64 / [73..201) snap_idx: [u64; 16] / [201..329) snap_total: [u64; 16]
/// snap_total[s] is the cumulative volume just before the first transfer in period snap_idx[s] (= at the start of that period).
const VOLUME_SNAP_COUNT_OFFSET: usize = 65;
const VOLUME_SNAP_IDX_OFFSET: usize = 73;
const VOLUME_SNAP_TOTAL_OFFSET: usize = 201;
pub const VOLUME_SNAP_SLOTS: usize = 16;
const VOLUME_SNAP_MIN_LEN: usize = VOLUME_SNAP_TOTAL_OFFSET + 8 * VOLUME_SNAP_SLOTS;

pub fn handler(ctx: Context<ProvisionBudget>) -> Result<()> {
    require!(ctx.accounts.manifest.active, TorusError::ManifestInactive);
    // No new provisioning for a token frozen after fraud.
    require!(!ctx.accounts.token_state.frozen, TorusError::TokenFrozen);
    require!(!ctx.accounts.token_state.exited, TorusError::TokenExited);
    // No redemptions until the bond reaches its target (no metering of obligations, nothing shown to users).
    require!(ctx.accounts.token_state.redemption_started, TorusError::BondTargetNotReached);

    let now = Clock::get()?.unix_timestamp;

    // ===== Start of redemptions: metering baseline and the period grid =====
    // The first provision after the bond first reaches its target starts the metered periods. Volume before that
    // creates no obligation. This call provisions no budget (period_id stays 0).
    // Boundaries are fixed by the origin t0 and the length Δ (period k is [t0 + kΔ, t0 + (k+1)Δ)); a late close does
    // not move them, and volume is assigned to the period it happened in.
    if !ctx.accounts.token_state.periods_started {
        let period_len = ctx.accounts.manifest.period_len;
        require!(period_len > 0, TorusError::InvalidManifestTerm);
        let (counter_total, _) =
            read_volume_counter(&ctx.accounts.volume_counter.to_account_info())?;
        let ts = &mut ctx.accounts.token_state;
        ts.current_period_activity = counter_total;
        ts.prior_period_activity = 0;
        ts.grid_start_ts = now;
        ts.grid_period_len = period_len;
        ts.period_start_ts = now;
        ts.last_settled_harvested = ts.cumulative_harvested;
        ts.periods_started = true;
        msg!(
            "provision_budget: mint={} periods_started counter_total={}",
            ts.mint,
            counter_total
        );
        return Ok(());
    }

    // ===== Time gate: the end boundary of period k (= current period_id) has passed =====
    // Without it, calling provision repeatedly could let a period with a large obligation slip by and send only
    // small periods to audit (skipping obligations).
    let k = ctx.accounts.token_state.period_id;
    let period_len = ctx.accounts.token_state.grid_period_len;
    let period_end = (k as i64)
        .checked_add(1)
        .and_then(|n| n.checked_mul(period_len))
        .and_then(|d| ctx.accounts.token_state.grid_start_ts.checked_add(d))
        .ok_or(TorusError::MathOverflow)?;
    require!(now >= period_end, TorusError::PeriodNotElapsed);

    // Periods after the exit request are not provisioned (the obligation ends with the requested period).
    if ctx.accounts.token_state.exit_requested {
        require!(k <= ctx.accounts.token_state.exit_request_period, TorusError::ExitInProgress);
    }

    // ===== The previous audit is final (if the previous period had an obligation) =====
    // A provisioned obligation must go through commit → sample → disclose → verify → finalize before the next period
    // can close. Never committing is handled by declare_default as a default (understatement). A period with budget 0
    // (no volume) has nothing to audit and no audit cycle; requiring finalization there would freeze the token
    // forever after a single period without volume.
    let current_period = ctx.accounts.token_state.period_id;
    if current_period > 0 && ctx.accounts.token_state.budget > 0 {
        let prev = ctx
            .accounts
            .prev_audit
            .as_ref()
            .ok_or(TorusError::PreviousAuditNotFinalized)?;
        let mint_key = ctx.accounts.token_state.mint;
        let (expected, _) = Pubkey::find_program_address(
            &[AUDIT_SEED, mint_key.as_ref(), current_period.to_le_bytes().as_ref()],
            ctx.program_id,
        );
        require_keys_eq!(prev.key(), expected, TorusError::PreviousAuditNotFinalized);
        require!(
            prev.stage == AuditStage::Finalized as u8,
            TorusError::PreviousAuditNotFinalized
        );
    }

    // Read the hook's cumulative volume and cumulative expected fee (both monotonic).
    let (counter_total, fee_total) =
        read_volume_counter(&ctx.accounts.volume_counter.to_account_info())?;
    let return_rate_bps = ctx.accounts.manifest.return_rate_bps;
    // Read the redemption pool's actual balance first, to check the budget is covered.
    let vault_amount = ctx.accounts.redemption_vault.amount;

    let token_state = &mut ctx.accounts.token_state;

    // Activity of period k = cumulative at the start of period k+1 − cumulative at the start of period k.
    // The value at the start of k+1 comes from the hook's boundary records (so a late close still uses the right period).
    let end_total = period_start_total(&ctx.accounts.volume_counter.to_account_info(), k + 1, counter_total)?;
    let delta = end_total.saturating_sub(token_state.current_period_activity);
    token_state.prior_period_activity = delta;
    token_state.current_period_activity = end_total; // cumulative at the start of the next period.
    token_state.period_id = k.checked_add(1).ok_or(TorusError::MathOverflow)?;
    token_state.period_start_ts = period_end; // start of the next period (fixed boundary).
    // Audit deadline: if the commitment and disclosures are not complete by then, a default can be declared.
    token_state.audit_deadline = now.checked_add(period_len).ok_or(TorusError::MathOverflow)?;

    // ===== Fee cross-check: fees implied by transfers vs. fees collected =====
    // fee_total is accumulated by the hook **per transfer**, computed from the mint's fee config (including max_fee)
    // with the same formula as Token-2022: the fees that should have been withheld (self-transfers included, since
    // they also pay the fee). cumulative_harvested is what harvest_fees actually moved into fee_vault. The first comes
    // from the hook, the second from the token program's fee layer: two independent quantities.
    //   - upside: collected cannot exceed implied (cumulative_harvested <= fee_total). Strict.
    //   - downside: collection can lag while some accounts are not harvested yet, so up to the band (30%) is allowed.
    // Comparing cumulative totals avoids false alarms when collection crosses a period boundary.
    if fee_total > 0 {
        let harvested = token_state.cumulative_harvested as u128;
        let expected = fee_total as u128;
        require!(harvested <= expected, TorusError::CrossCheckMismatch);
        require!(
            harvested * (BPS_DENOMINATOR as u128)
                >= expected * ((BPS_DENOMINATOR - CROSS_CHECK_TOLERANCE_BPS) as u128),
            TorusError::CrossCheckMismatch
        );
        msg!(
            "cross_check: fee_total={} cumulative_harvested={} volume_delta={}",
            fee_total,
            token_state.cumulative_harvested,
            delta
        );
    }
    token_state.last_settled_harvested = token_state.cumulative_harvested;

    // Budget = activity of the closed period × the fixed return rate.
    let budget = mul_bps(delta, return_rate_bps)?;
    // **Pre-funding**: the redemption pool must hold the unpaid obligations (reserved) plus the new budget.
    // Without counting what is still unpaid, the same funds would be counted for two periods' obligations.
    let required = token_state
        .reserved
        .checked_add(budget)
        .ok_or(TorusError::MathOverflow)?;
    require!(vault_amount >= required, TorusError::BudgetNotEscrowed);
    token_state.budget = budget;
    token_state.reserved = required;

    // Issuer share: what accrued during the closed period waits for this cycle's audit (of that period's obligation).
    token_state.issuer_pending = token_state
        .issuer_pending
        .checked_add(token_state.issuer_accruing)
        .ok_or(TorusError::MathOverflow)?;
    token_state.issuer_accruing = 0;

    msg!(
        "provision_budget: mint={} period_id={} delta={} counter_total={} budget={} audit_deadline={}",
        token_state.mint,
        token_state.period_id,
        delta,
        counter_total,
        token_state.budget,
        token_state.audit_deadline
    );
    Ok(())
}

/// Reads total and fee_total (both u64 LE) from the raw VolumeCounter data.
pub(crate) fn read_volume_counter(acc: &AccountInfo<'_>) -> Result<(u64, u64)> {
    let data = acc.try_borrow_data()?;
    if data.len() < VOLUME_FEE_TOTAL_OFFSET + 8 {
        // The account does not have the expected layout.
        return Err(anchor_lang::solana_program::program_error::ProgramError::InvalidAccountData.into());
    }
    let read = |off: usize| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[off..off + 8]);
        u64::from_le_bytes(buf)
    };
    Ok((read(VOLUME_TOTAL_OFFSET), read(VOLUME_FEE_TOTAL_OFFSET)))
}

/// Cumulative volume at the start of period `index`: the hook record with the smallest period index >= `index`
/// (there was no transfer between that boundary and the record, so it equals the value at the start of `index`).
/// With no record, there was no transfer after the boundary and the current value is used. If closing was delayed
/// beyond the 16 kept records, volume up to the oldest remaining record is assigned to this period (none is lost).
pub(crate) fn period_start_total(acc: &AccountInfo<'_>, index: u64, current_total: u64) -> Result<u64> {
    let data = acc.try_borrow_data()?;
    if data.len() < VOLUME_SNAP_MIN_LEN {
        return Ok(current_total);
    }
    let read = |off: usize| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[off..off + 8]);
        u64::from_le_bytes(buf)
    };
    let count = read(VOLUME_SNAP_COUNT_OFFSET);
    let kept = (count as usize).min(VOLUME_SNAP_SLOTS);
    let mut best: Option<(u64, u64)> = None;
    let mut oldest = u64::MAX;
    for s in 0..kept {
        let idx = read(VOLUME_SNAP_IDX_OFFSET + 8 * s);
        let total = read(VOLUME_SNAP_TOTAL_OFFSET + 8 * s);
        oldest = oldest.min(idx);
        if idx >= index && best.map_or(true, |(b, _)| idx < b) {
            best = Some((idx, total));
        }
    }
    match best {
        Some((idx, total)) => {
            if count as usize > VOLUME_SNAP_SLOTS && oldest > index {
                msg!("provision_budget: volume snapshots before period {} were overwritten; lumping into the closing period", idx);
            }
            Ok(total)
        }
        None => Ok(current_total),
    }
}

/// amount × bps / 10_000 (checked), as in finalize_audit.rs.
pub(crate) fn mul_bps(amount: u64, bps: u16) -> Result<u64> {
    let v = (amount as u128)
        .checked_mul(bps as u128)
        .ok_or(TorusError::MathOverflow)?
        / (BPS_DENOMINATOR as u128);
    Ok(v as u64)
}

#[derive(Accounts)]
pub struct ProvisionBudget<'info> {
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

    /// The hook's VolumeCounter (cumulative, monotonic, owned by torus_hook); total and fee_total are read only.
    /// Bound to the legitimate hook-owned PDA by seeds + seeds::program + owner (no fake counter can be injected).
    /// CHECK: bound by the constraints above; only reads raw bytes (u64 LE at offsets 40 and 49, and the boundary records).
    #[account(
        seeds = [b"volume", token_state.mint.as_ref()],
        bump,
        seeds::program = config.hook_program,
        owner = config.hook_program @ TorusError::Unauthorized,
    )]
    pub volume_counter: UncheckedAccount<'info>,

    /// First account (redemption pool); its balance must cover the provisioned budget.
    #[account(address = token_state.redemption_vault @ TorusError::Unauthorized)]
    pub redemption_vault: InterfaceAccount<'info, TokenAccount>,

    /// Audit cycle of the period being closed (current period_id). Required (and must be Finalized) if period_id > 0
    /// and its budget > 0. The handler checks the address against the PDA (seeds = [audit, mint, period_id]).
    pub prev_audit: Option<Account<'info, AuditCycle>>,
}
