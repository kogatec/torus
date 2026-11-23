//! commit_performance: records the commitment.
//!
//! Records the commitment to the whole ledger (Merkle-sum root commitment) and the control total (the issuer's
//! declared total), and starts the AuditCycle. Binding the whole set before the sample is drawn rules out
//! swapping entries afterwards. The commit also fixes where the sample's randomness will come from: the operator's
//! seed commitment as it stands now, and a slot that does not exist yet (capture_entropy, designate_sample).
//! Signed by the issuer. Not possible without a provisioned budget (budget == 0). After the campaign has ended, the audit
//! of a period that started during it still runs (a period that started in the gap has no budget to commit to).

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
    // A budget must be provisioned: no commitment without an obligation to measure against.
    require!(
        ctx.accounts.token_state.budget > 0,
        TorusError::BudgetNotProvisioned
    );
    // The ledger has at least one leaf (an empty tree has no root to commit to).
    require!(population_size > 0, TorusError::InvalidSampleSize);

    let token_state = &ctx.accounts.token_state;
    let manifest = &ctx.accounts.manifest;
    let audit = &mut ctx.accounts.audit;
    // Judging terms of the audited period: those in force when it started (fixed by provision_budget).
    let terms = token_state.cycle_terms;

    audit.token = token_state.mint;
    audit.period_id = token_state.period_id;
    audit.commitment_value = commitment_value;
    audit.control_total = control_total;
    audit.population_size = population_size;
    audit.committed_slot = Clock::get()?.slot;
    // The sample's randomness is pinned here, before anyone can know it: the operator's seed commitment as posted,
    // and a later slot whose hash does not exist yet.
    audit.seed_commit = token_state.audit_seed_commit;
    audit.entropy_slot = audit
        .committed_slot
        .checked_add(ENTROPY_DELAY_SLOTS)
        .ok_or(TorusError::MathOverflow)?;

    // --- Snapshot the judging parameters and the obligation at commit ---
    //   finalize uses this snapshot and is unaffected by later changes to the manifest or the budget
    //   (no loosening thresholds after observations are known, no swapping the obligation afterwards,
    //    no swapping the auditor mid-cycle).
    audit.obligation = token_state.budget;
    // The part judged, and when the issuer committed (excuses.rs). No auditor's excuse yet; finalize_audit decides
    // whether the issuer did its part of the cycle on time.
    audit.judged_obligation = token_state.judged_budget;
    audit.committed_ts = Clock::get()?.unix_timestamp;
    audit.auditor_excused_bps = 0;
    audit.excuse_hash = [0u8; 32];
    audit.issuer_on_time = false;
    audit.held_up = false;
    audit.tolerance_bps = terms.tolerance_bps;
    audit.shortfall_tolerance_bps = terms.shortfall_tolerance_bps;
    audit.auditor = manifest.auditor;
    // Fix the sample size here too: the value fixed in the manifest, whatever the population. Samples are drawn with
    // replacement in proportion to value, so a small population does not shrink the sample (declaring few leaves
    // must not buy a weaker audit). A zero declaration has nothing to sample.
    audit.sample_size = if control_total == 0 { 0 } else { terms.sample_size };
    // Fix the allowed defect count, within 20% of the sample.
    audit.max_defects = terms.max_defects.min(
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
    pub token_state: Box<Account<'info, TokenState>>,

    /// Current manifest: source of the auditor snapshotted into the cycle (the judging parameters come from
    /// TokenState.cycle_terms, the terms of the audited period).
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
