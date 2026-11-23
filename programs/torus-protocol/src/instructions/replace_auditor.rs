//! replace_auditor: the operator replaces an auditor who did not record by the deadline (Config.authority only).
//! The new auditor is drawn, not chosen (sampling::draw_replacement): the draw lands among the auditors counted at the
//! commit, revoked ones included, and walks in registry order to the first one still active — so revoking auditors only
//! skips them and cannot move the draw. Only when all of them were revoked: among auditors active now and listed at least
//! AUDITOR_FALLBACK_AGE_SLOTS ago (one added for the occasion is not drawn).
//!
//! Even when the issuer has disclosed everything, the cycle stays Sampled if the auditor never calls
//! record_verification. That is not the issuer's fault, so it is not a default (declare_default returns
//! DefaultNotDue), and the next period cannot close either. An issuer colluding with its auditor could stall
//! slashing and payouts on purpose. So when the deadline has passed and only the auditor's record is missing,
//! the operator swaps the auditor and gives the new one one period to finish.
//!
//! No replacement before the deadline (still no swapping to a colluding key mid-cycle), except when the current
//! auditor's registration was revoked (revoke_auditor): then it is replaced right away. Before finalization the
//! sample is observed again; after finalization only leaf confirmations (attest_leaf) move to the new auditor
//! (finalized results, observations and confirmations are kept).
//! The new auditor is never the issuer, its partners, the current auditor, nor the cycle's first auditor.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::deadlines;
use crate::errors::TorusError;
use crate::sampling;
use crate::instructions::designate_sample::{excluded_from_draw, read_registry};
use crate::state::{AuditCycle, AuditorRecord, Config, Manifest, TokenState};

pub fn handler(ctx: Context<ReplaceAuditor>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let slot = Clock::get()?.slot;
    let revoked = !ctx.accounts.current_auditor_record.active;
    // The token's period grid, as for every other deadline (a later manifest may name another period length).
    let period_len = ctx.accounts.token_state.grid_period_len;
    let entries = read_registry(&ctx.accounts.auditor_registry)?;
    let ts = &mut ctx.accounts.token_state;
    let audit = &mut ctx.accounts.audit;
    let new_auditor = draw_new_auditor(&entries, audit, excluded_from_draw(ts), slot)?;
    let finalized = audit.stage == AuditStage::Finalized as u8;
    // Only the auditor's record is missing (the issuer has disclosed everything).
    let waiting_on_auditor = (audit.stage == AuditStage::Sampled as u8
        && audit.verify_cursor == audit.sample_size)
        || audit.stage == AuditStage::Verified as u8;

    if revoked {
        // Revoked: no need to wait for the deadline. Before finalization only the current cycle (always the case).
        require!(
            finalized || audit.period_id == ts.period_id,
            TorusError::AuditorReplacementNotDue
        );
    } else {
        require!(
            audit.period_id == ts.period_id
                && audit.stage == AuditStage::Sampled as u8
                && audit.verify_cursor == audit.sample_size,
            TorusError::AuditorReplacementNotDue
        );
        require!(now > ts.audit_deadline, TorusError::AuditorReplacementNotDue);
    }

    let old = audit.auditor;
    audit.auditor = new_auditor;
    if !finalized {
        // The new auditor observes the sample again (recorded observations are discarded), and decides again whether
        // to excuse anything (excuse_shortfall).
        audit.sample_observed.clear();
        audit.observed_sum = 0;
        audit.defect_count = 0;
        audit.auditor_excused_bps = 0;
        audit.excuse_hash = [0u8; 32];
        // The issuer did not hold this cycle up (a late provision after it may be excused, excuses.rs).
        audit.held_up = true;
        if audit.stage == AuditStage::Verified as u8 {
            audit.stage = AuditStage::Sampled as u8;
            audit.report_hash = [0u8; 32];
        }
        // If the cycle is waiting on the auditor, give the new auditor one period
        // (a cycle waiting on the issuer does not get more time).
        if waiting_on_auditor {
            ts.audit_deadline = deadlines::extend(ts.audit_deadline, now, period_len)?;
        }
    }

    msg!(
        "replace_auditor: mint={} period_id={} old={} new={} revoked={} audit_deadline={}",
        ts.mint,
        audit.period_id,
        old,
        new_auditor,
        revoked,
        ts.audit_deadline
    );
    Ok(())
}

/// Draws the replacement: never the issuer, its partners, the current auditor, nor the cycle's first auditor (no
/// coming back to an auditor this cycle already dropped).
fn draw_new_auditor(entries: &[crate::state::AuditorEntry], audit: &AuditCycle, excluded: [Pubkey; 3], slot: u64) -> Result<Pubkey> {
    let first_draw = sampling::AuditorDraw { entropy: &audit.entropy, committed_slot: audit.committed_slot, previous: Pubkey::default(), excluded: &excluded };
    let first = sampling::draw_auditor(entries, &first_draw).unwrap_or_default();
    let avoided = [excluded[0], excluded[1], excluded[2], first];
    let draw = sampling::AuditorDraw { previous: audit.auditor, excluded: &avoided, ..first_draw };
    let fallback = sampling::AuditorDraw { committed_slot: slot.saturating_sub(AUDITOR_FALLBACK_AGE_SLOTS), ..draw };
    sampling::draw_replacement(entries, &draw)
        .or_else(|| sampling::draw_replacement(entries, &fallback))
        .ok_or_else(|| error!(TorusError::InvalidReplacementAuditor))
}

#[derive(Accounts)]
pub struct ReplaceAuditor<'info> {
    /// The operator (Config.authority).
    pub authority: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = authority @ TorusError::Unauthorized,
    )]
    pub config: Box<Account<'info, Config>>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
    )]
    pub token_state: Box<Account<'info, TokenState>>,

    /// The token's manifest (bound by seeds). The handler no longer reads it (the deadline follows the period grid); it
    /// stays in the accounts so the instruction's interface is unchanged.
    #[account(
        seeds = [MANIFEST_SEED, token_state.mint.as_ref()],
        bump = manifest.bump,
        constraint = manifest.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub manifest: Box<Account<'info, Manifest>>,

    /// The audit cycle. A replacement for a missed deadline is only for the current cycle (a stalled cycle is always
    /// the current one). A replacement after revocation also works on finalized cycles (to take over leaf confirmations).
    #[account(
        mut,
        seeds = [AUDIT_SEED, token_state.mint.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
        constraint = audit.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub audit: Box<Account<'info, AuditCycle>>,

    /// Registry record of the current auditor (to see whether it was revoked).
    #[account(
        seeds = [AUDITOR_SEED, audit.auditor.as_ref()],
        bump = current_auditor_record.bump,
    )]
    pub current_auditor_record: Account<'info, AuditorRecord>,

    /// The auditors the new auditor is drawn from (bound by seeds; it may not exist on a deployment from before it).
    /// CHECK: read by read_registry (owner and discriminator checked).
    #[account(seeds = [AUDITOR_REGISTRY_SEED], bump)]
    pub auditor_registry: UncheckedAccount<'info>,
}
