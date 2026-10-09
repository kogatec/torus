//! replace_auditor: the operator replaces an auditor who did not record by the deadline with another
//! registered auditor (Config.authority only).
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
//! The new auditor must be registered and active, and be neither the issuer nor the current auditor.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{AuditCycle, AuditorRecord, Config, Manifest, TokenState};

pub fn handler(ctx: Context<ReplaceAuditor>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let new_auditor = ctx.accounts.new_auditor.key();
    let revoked = !ctx.accounts.current_auditor_record.active;
    let period_len = ctx.accounts.manifest.period_len;
    let ts = &mut ctx.accounts.token_state;
    let audit = &mut ctx.accounts.audit;

    require!(
        new_auditor != ts.issuer && new_auditor != audit.auditor,
        TorusError::InvalidReplacementAuditor
    );
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
        // The new auditor observes the sample again (recorded observations are discarded).
        audit.sample_observed.clear();
        audit.observed_sum = 0;
        audit.defect_count = 0;
        if audit.stage == AuditStage::Verified as u8 {
            audit.stage = AuditStage::Sampled as u8;
            audit.report_hash = [0u8; 32];
        }
        // If the cycle is waiting on the auditor, give the new auditor one period
        // (a cycle waiting on the issuer does not get more time).
        if waiting_on_auditor {
            let deadline = now.checked_add(period_len).ok_or(TorusError::MathOverflow)?;
            ts.audit_deadline = ts.audit_deadline.max(deadline);
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

#[derive(Accounts)]
pub struct ReplaceAuditor<'info> {
    /// The operator (Config.authority).
    pub authority: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = authority @ TorusError::Unauthorized,
    )]
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

    /// The audit cycle. A replacement for a missed deadline is only for the current cycle (a stalled cycle is always
    /// the current one). A replacement after revocation also works on finalized cycles (to take over leaf confirmations).
    #[account(
        mut,
        seeds = [AUDIT_SEED, token_state.mint.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
        constraint = audit.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub audit: Account<'info, AuditCycle>,

    /// Registry record of the current auditor (to see whether it was revoked).
    #[account(
        seeds = [AUDITOR_SEED, audit.auditor.as_ref()],
        bump = current_auditor_record.bump,
    )]
    pub current_auditor_record: Account<'info, AuditorRecord>,

    /// The new auditor.
    /// CHECK: registered and active, checked through the registry record below (bound by seeds).
    pub new_auditor: UncheckedAccount<'info>,

    #[account(
        seeds = [AUDITOR_SEED, new_auditor.key().as_ref()],
        bump = new_auditor_record.bump,
        constraint = new_auditor_record.active @ TorusError::AuditorNotRegistered,
    )]
    pub new_auditor_record: Account<'info, AuditorRecord>,
}
