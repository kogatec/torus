//! revoke_auditor: revokes an auditor's registration (Config.authority only).
//!
//! When an auditor loses its qualification or its key is compromised, the operator revokes it. A revoked auditor
//!   - is not named for a new audit cycle (commit_performance rejects starting from a stale manifest)
//!   - cannot record observations (record_verification)
//!   - cannot confirm individual leaves (attest_leaf)
//! Ongoing cycles continue with another auditor via replace_auditor (no need to wait for the deadline).
//! A revocation alone is never treated as the issuer's fraud, and it does not cancel recipients' finalized rights.
//! Revocation is permanent (an auditor with a new key registers again).

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{AuditorRecord, Config};

pub fn handler(ctx: Context<RevokeAuditor>) -> Result<()> {
    let record = &mut ctx.accounts.auditor_record;
    require!(record.active, TorusError::AuditorRevoked);
    record.active = false;
    msg!("revoke_auditor: auditor={}", record.auditor);
    Ok(())
}

#[derive(Accounts)]
pub struct RevokeAuditor<'info> {
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
        seeds = [AUDITOR_SEED, auditor_record.auditor.as_ref()],
        bump = auditor_record.bump,
    )]
    pub auditor_record: Account<'info, AuditorRecord>,
}
