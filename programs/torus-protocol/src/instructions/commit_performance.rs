//! commit_performance: records the commitment.
//!
//! Records the commitment to the whole ledger (Merkle-sum root commitment) and the control total (the issuer's
//! declared total), and starts the AuditCycle. Binding the whole set before the sample is drawn rules out
//! swapping entries afterwards (the commit slot is recorded as the reference for post-commit entropy).
//! Signed by the issuer. Not possible without a provisioned budget (budget == 0).

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{AuditorRecord, AuditCycle, Manifest, TokenState};

pub fn handler(
    ctx: Context<CommitPerformance>,
    commitment_value: [u8; 32],
    control_total: u64,
    population_size: u32,
) -> Result<()> {
    // No new commitment while frozen.
    require!(!ctx.accounts.token_state.frozen, TorusError::TokenFrozen);
    require!(!ctx.accounts.token_state.exited, TorusError::TokenExited);
    // The manifest must not have expired (no commitment under an expired campaign).
    require!(
        Clock::get()?.unix_timestamp <= ctx.accounts.manifest.valid_until,
        TorusError::ManifestExpired
    );
    // A budget must be provisioned: no commitment without an obligation to measure against.
    require!(
        ctx.accounts.token_state.budget > 0,
        TorusError::BudgetNotProvisioned
    );
    // The population must be at least 1 so a sample can be drawn (population_size == 0 would block finalize).
    require!(population_size > 0, TorusError::InvalidSampleSize);

    let token_state = &ctx.accounts.token_state;
    let manifest = &ctx.accounts.manifest;
    let audit = &mut ctx.accounts.audit;

    audit.token = token_state.mint;
    audit.period_id = token_state.period_id;
    audit.commitment_value = commitment_value;
    audit.control_total = control_total;
    audit.population_size = population_size;
    audit.committed_slot = Clock::get()?.slot;

    // --- Snapshot the judging parameters and the obligation at commit ---
    //   finalize uses this snapshot and is unaffected by later changes to the manifest or the budget
    //   (no loosening thresholds after observations are known, no swapping the obligation afterwards,
    //    no swapping the auditor mid-cycle).
    audit.obligation = token_state.budget;
    audit.tolerance_bps = manifest.tolerance_bps;
    audit.shortfall_tolerance_bps = manifest.shortfall_tolerance_bps;
    audit.auditor = manifest.auditor;
    // Fix the sample size here too (the value fixed in the manifest; if larger than the population, check all).
    // Whoever designates the sample cannot choose its size.
    audit.sample_size = (manifest.sample_size as u32).min(population_size) as u16;
    // Fix the allowed defect count; if the sample shrank to the whole population, keep it within 20% of it.
    audit.max_defects = manifest.max_defects.min(
        ((audit.sample_size as u64) * MAX_DEFECT_RATE_BPS / BPS_DENOMINATOR) as u16,
    );

    // Reset the disclosure progress (verify_disclosure accumulates).
    audit.asserted_sample_sum = 0;
    audit.verify_cursor = 0;

    audit.stage = AuditStage::Committed as u8;
    audit.result = AuditResult::Pending as u8;
    audit.bump = ctx.bumps.audit;

    msg!(
        "commit_performance: mint={} period_id={} control_total={} population_size={} committed_slot={}",
        audit.token,
        audit.period_id,
        control_total,
        population_size,
        audit.committed_slot
    );
    Ok(())
}

#[derive(Accounts)]
pub struct CommitPerformance<'info> {
    /// The issuer, payer. Must equal token_state.issuer (has_one).
    #[account(mut)]
    pub issuer: Signer<'info>,

    #[account(
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
        has_one = issuer @ TorusError::Unauthorized,
    )]
    pub token_state: Account<'info, TokenState>,

    /// Current manifest: source of the judging parameters and the auditor snapshotted into the cycle.
    #[account(
        seeds = [MANIFEST_SEED, token_state.mint.as_ref()],
        bump = manifest.bump,
        constraint = manifest.active @ TorusError::ManifestInactive,
        constraint = manifest.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub manifest: Account<'info, Manifest>,

    /// Registry record of the auditor named in the manifest. If revoked, no new audit starts from a stale manifest.
    #[account(
        seeds = [AUDITOR_SEED, manifest.auditor.as_ref()],
        bump = auditor_record.bump,
        constraint = auditor_record.active @ TorusError::AuditorRevoked,
    )]
    pub auditor_record: Account<'info, AuditorRecord>,

    /// The current period's audit cycle (one per period_id).
    #[account(
        init,
        payer = issuer,
        space = 8 + AuditCycle::INIT_SPACE,
        seeds = [AUDIT_SEED, token_state.mint.as_ref(), token_state.period_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub audit: Account<'info, AuditCycle>,

    pub system_program: Program<'info, System>,
}
