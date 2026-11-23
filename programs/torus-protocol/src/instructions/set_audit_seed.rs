//! set_audit_seed: the operator posts the commitment to its seed for the token's next sample (Config.authority only).
//!
//! An audit's sample is drawn from this seed mixed with the hash of a slot fixed at commit (sampling.rs). The seed has
//! to be fixed before the issuer commits its ledger, so its commitment is posted first: no period closes until it is
//! (provision_budget), and each reveal (designate_sample) posts the commitment for the cycle after.
//! A cycle already committed keeps the commitment it snapshotted, so posting a new one never changes its sample.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{Config, TokenState};

pub fn handler(ctx: Context<SetAuditSeed>, seed_commit: [u8; 32]) -> Result<()> {
    require!(seed_commit != [0u8; 32], TorusError::InvalidSeedCommit);
    let ts = &mut ctx.accounts.token_state;
    ts.audit_seed_commit = seed_commit;
    msg!("set_audit_seed: mint={}", ts.mint);
    Ok(())
}

#[derive(Accounts)]
pub struct SetAuditSeed<'info> {
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
    pub token_state: Box<Account<'info, TokenState>>,
}
