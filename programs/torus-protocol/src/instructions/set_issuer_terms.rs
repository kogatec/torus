//! set_issuer_terms: terms the operator sets for each company (Config.authority only).
//!
//! - bond_target: set by the operator from the company's credit and goals. If the issuer could set it,
//!   it could make it zero or tiny and remove the penalty for fraud.
//! - min_conversion_price: the floor at which a partner may buy the fee tokens. Without it, a partner
//!   colluding with the issuer could take the fees for almost nothing and empty the forced deposit into
//!   the bond and the redemption pool.
//!
//! While either is unset (0), no deposit, conversion or redemption can start.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{Config, TokenState};

pub fn handler(ctx: Context<SetIssuerTerms>, bond_target: u64, min_conversion_price: u64) -> Result<()> {
    require!(
        bond_target > 0 && min_conversion_price > 0,
        TorusError::InvalidIssuerTerms
    );
    // The minimum is fixed by the operator at initialize (no large promises on a tiny bond).
    require!(
        bond_target >= ctx.accounts.config.min_bond_target,
        TorusError::BondBelowMinimum
    );
    let ts = &mut ctx.accounts.token_state;
    ts.bond_target = bond_target;
    ts.min_conversion_price = min_conversion_price;
    msg!(
        "set_issuer_terms: mint={} bond_target={} min_conversion_price={}",
        ts.mint,
        bond_target,
        min_conversion_price
    );
    Ok(())
}

#[derive(Accounts)]
pub struct SetIssuerTerms<'info> {
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
}
