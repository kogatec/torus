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
use crate::state::{AuditorRecord, AuditorRegistry, Config};

pub fn handler(ctx: Context<RevokeAuditor>) -> Result<()> {
    let record = &mut ctx.accounts.auditor_record;
    require!(record.active, TorusError::AuditorRevoked);
    record.active = false;
    // The entry stays (cycles committed before keep their draw set); it no longer counts from this slot.
    ctx.accounts.auditor_registry.bump = ctx.bumps.auditor_registry;
    let slot = Clock::get()?.slot;
    let auditor = record.auditor;
    if let Some(entry) = ctx
        .accounts
        .auditor_registry
        .entries
        .iter_mut()
        .find(|entry| entry.auditor == auditor && entry.removed_slot == AUDITOR_NOT_REMOVED)
    {
        entry.removed_slot = slot;
    }
    msg!("revoke_auditor: auditor={}", record.auditor);
    Ok(())
}

#[derive(Accounts)]
pub struct RevokeAuditor<'info> {
    /// The operator (Config.authority); pays for the registry if it does not exist yet.
    #[account(mut)]
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

    /// Created if needed, so a deployment from before the registry can still revoke.
    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + AuditorRegistry::INIT_SPACE,
        seeds = [AUDITOR_REGISTRY_SEED],
        bump,
    )]
    pub auditor_registry: Account<'info, AuditorRegistry>,

    pub system_program: Program<'info, System>,
}
