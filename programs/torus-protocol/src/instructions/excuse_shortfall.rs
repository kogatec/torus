//! excuse_shortfall: the cycle's auditor excuses a share of the judged obligation (excuses.rs).
//!
//! The chain excuses on its own a period that was provisioned after its window was over, when the issuer had done its
//! part of the previous cycle on time. Some causes are invisible to it (the service the issuer delivers through was
//! down, for example): for those, the cycle's auditor, drawn at random and independent of the issuer, may excuse a
//! share of the judged obligation, with the hash of its reasons (the document is kept off-chain, open to review).
//! The excused share is still owed (carried, not judged again); a cycle left with nothing to judge is Excused.
//!
//! Only the cycle's current auditor, still registered, between the draw and the finalization. Recording 0 withdraws an
//! excuse. A replaced auditor's excuse is cleared (replace_auditor): the new auditor decides again.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{AuditCycle, AuditorRecord};

/// Records the auditor's excuse (or its withdrawal) on the cycle, for finalize_audit to judge the rest.
pub fn handler(ctx: Context<ExcuseShortfall>, excused_bps: u16, reason_hash: [u8; 32]) -> Result<()> {
    let audit = &mut ctx.accounts.audit;
    require!(
        audit.stage == AuditStage::Sampled as u8 || audit.stage == AuditStage::Verified as u8,
        TorusError::InvalidAuditStage
    );
    require_keys_eq!(ctx.accounts.auditor.key(), audit.auditor, TorusError::UnauthorizedAuditor);
    // A share of at most 100%, and an excuse always comes with its reasons.
    let is_withdrawal = excused_bps == 0;
    require!(
        excused_bps as u64 <= BPS_DENOMINATOR && (is_withdrawal || reason_hash != [0u8; 32]),
        TorusError::InvalidExcuse
    );
    audit.auditor_excused_bps = excused_bps;
    audit.excuse_hash = if is_withdrawal { [0u8; 32] } else { reason_hash };
    msg!(
        "excuse_shortfall: mint={} period_id={} auditor={} excused_bps={}",
        audit.token,
        audit.period_id,
        audit.auditor,
        excused_bps
    );
    Ok(())
}

/// The cycle's auditor, the cycle, and the auditor's registry record.
#[derive(Accounts)]
pub struct ExcuseShortfall<'info> {
    /// The cycle's auditor (checked against audit.auditor in the handler).
    pub auditor: Signer<'info>,

    #[account(
        mut,
        seeds = [AUDIT_SEED, audit.token.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
    )]
    pub audit: Account<'info, AuditCycle>,

    /// Registry record of the cycle's auditor: a revoked auditor cannot excuse.
    #[account(
        seeds = [AUDITOR_SEED, audit.auditor.as_ref()],
        bump = auditor_record.bump,
        constraint = auditor_record.active @ TorusError::AuditorRevoked,
    )]
    pub auditor_record: Account<'info, AuditorRecord>,
}
