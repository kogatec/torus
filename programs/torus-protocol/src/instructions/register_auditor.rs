//! register_auditor: adds an independent auditor to the operator's registry (Config.authority only).
//!
//! "A key other than the issuer's" is not independence: the issuer could name a friend's key. Only
//! auditors registered here can be named in set_manifest, so the issuer does not decide who counts as
//! an auditor.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{AuditorEntry, AuditorRecord, AuditorRegistry, Config};

/// Registers an auditor, or lists an active one registered before the registry existed. A revocation is permanent (a
/// revoked auditor cannot come back, so revoking others for one commit and restoring them after is impossible).
/// The registry entry records the slot: a cycle draws only among auditors listed before its commit (sampling.rs).
pub fn handler(ctx: Context<RegisterAuditor>) -> Result<()> {
    let slot = Clock::get()?.slot;
    let auditor = ctx.accounts.auditor.key();
    let registry = &mut ctx.accounts.auditor_registry;
    registry.bump = ctx.bumps.auditor_registry;
    let is_listed = registry
        .entries
        .iter()
        .any(|entry| entry.auditor == auditor && entry.removed_slot == AUDITOR_NOT_REMOVED);
    let record = &mut ctx.accounts.auditor_record;
    let is_new = record.auditor == Pubkey::default();
    require!(is_new || record.active, TorusError::AuditorRevoked);
    require!(!(record.active && is_listed), TorusError::AuditorAlreadyRegistered);
    if !is_listed {
        require!(registry.entries.len() < MAX_AUDITOR_ENTRIES, TorusError::AuditorRegistryFull);
        registry.entries.push(AuditorEntry { auditor, added_slot: slot, removed_slot: AUDITOR_NOT_REMOVED });
    }
    record.auditor = auditor;
    record.active = true;
    record.bump = ctx.bumps.auditor_record;
    msg!("register_auditor: auditor={} slot={}", auditor, slot);
    Ok(())
}

#[derive(Accounts)]
pub struct RegisterAuditor<'info> {
    /// The operator (Config.authority).
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = authority @ TorusError::Unauthorized,
    )]
    pub config: Account<'info, Config>,

    /// The auditor to register.
    /// CHECK: only the key is recorded in the registry; no signature needed.
    pub auditor: UncheckedAccount<'info>,

    /// init_if_needed: an auditor registered before the registry existed is listed once (a revoked one is refused).
    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + AuditorRecord::INIT_SPACE,
        seeds = [AUDITOR_SEED, auditor.key().as_ref()],
        bump,
    )]
    pub auditor_record: Account<'info, AuditorRecord>,

    /// The auditors a cycle's auditor is drawn from (created by the first registration).
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
