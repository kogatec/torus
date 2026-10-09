//! register_auditor: adds an independent auditor to the operator's registry (Config.authority only).
//!
//! "A key other than the issuer's" is not independence: the issuer could name a friend's key. Only
//! auditors registered here can be named in set_manifest, so the issuer does not decide who counts as
//! an auditor.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{AuditorRecord, Config};

pub fn handler(ctx: Context<RegisterAuditor>) -> Result<()> {
    let record = &mut ctx.accounts.auditor_record;
    record.auditor = ctx.accounts.auditor.key();
    record.active = true;
    record.bump = ctx.bumps.auditor_record;
    msg!("register_auditor: auditor={}", record.auditor);
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

    #[account(
        init,
        payer = authority,
        space = 8 + AuditorRecord::INIT_SPACE,
        seeds = [AUDITOR_SEED, auditor.key().as_ref()],
        bump,
    )]
    pub auditor_record: Account<'info, AuditorRecord>,

    pub system_program: Program<'info, System>,
}
