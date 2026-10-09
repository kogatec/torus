//! request_exit: the issuer requests a voluntary exit.
//!
//! The obligation runs through the volume of the period in which the request is made (period r on the fixed
//! grid). The exit cannot be finalized (finalize_exit) until period r is provisioned and its audit is final,
//! so requesting an exit does not escape the obligation. Volume after period r is not counted (ExitInProgress).
//! A forced exit for a violation (fraud, refusal to disclose, missing commitment) is a different path:
//! finalize_audit / declare_default slash the bond and the escrow and freeze the token.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::TokenState;

pub fn handler(ctx: Context<RequestExit>) -> Result<()> {
    let ts = &mut ctx.accounts.token_state;
    require!(!ts.frozen, TorusError::TokenFrozen);
    require!(!ts.exited, TorusError::TokenExited);
    require!(!ts.exit_requested, TorusError::ExitAlreadyRequested);

    ts.exit_requested = true;
    ts.exit_request_period = if ts.periods_started && ts.grid_period_len > 0 {
        let now = Clock::get()?.unix_timestamp;
        (now.saturating_sub(ts.grid_start_ts) / ts.grid_period_len) as u64
    } else {
        0
    };

    msg!(
        "request_exit: mint={} issuer={} period_id={} last_obligated_period={}",
        ts.mint,
        ts.issuer,
        ts.period_id,
        ts.exit_request_period
    );
    Ok(())
}

#[derive(Accounts)]
pub struct RequestExit<'info> {
    /// The issuer.
    pub issuer: Signer<'info>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
        has_one = issuer @ TorusError::Unauthorized,
    )]
    pub token_state: Account<'info, TokenState>,
}
