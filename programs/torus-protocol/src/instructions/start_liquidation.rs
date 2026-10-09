//! start_liquidation: starts liquidation (anyone can crank it).
//!
//! After an exit (voluntary, or forced by a violation), the part of the redemption pool beyond the amounts
//! reserved for finalized, unpaid claims (reserved) is fixed as the liquidation pool. Reserved amounts are still
//! paid through payout (recognized unpaid rights come first). The surplus is split over the leaves of the last
//! audit finalized without fraud, pro rata to their confirmed amounts (claim_liquidation). The issuer gets none.
//! If no audit was ever finalized without fraud, there is no basis for a split and the surplus goes to the
//! compensation pool fixed in Config.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{Config, TokenState};

pub fn handler(ctx: Context<StartLiquidation>) -> Result<()> {
    let vault_balance = ctx.accounts.redemption_vault.amount;
    let ts = &mut ctx.accounts.token_state;
    require!(ts.frozen || ts.exited, TorusError::LiquidationNotAllowed);
    require!(!ts.liquidation_started, TorusError::LiquidationAlreadyStarted);

    let pool = vault_balance.saturating_sub(ts.reserved);
    ts.liquidation_started = true;

    if ts.last_good_period == 0 {
        // No finalized rights to split over: the surplus goes to the compensation pool.
        ts.liquidation_pool = 0;
        if pool > 0 {
            let mint_key = ts.mint;
            let seeds: &[&[u8]] = &[POOL_AUTHORITY_SEED, mint_key.as_ref(), &[ts.pool_authority_bump]];
            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.usdc_token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.redemption_vault.to_account_info(),
                        mint: ctx.accounts.usdc_mint.to_account_info(),
                        to: ctx.accounts.slash_destination.to_account_info(),
                        authority: ctx.accounts.pool_authority.to_account_info(),
                    },
                    &[seeds],
                ),
                pool,
                ctx.accounts.usdc_mint.decimals,
            )?;
        }
    } else {
        ts.liquidation_pool = pool;
        ts.liquidation_ref_period = ts.last_good_period;
    }

    msg!(
        "start_liquidation: mint={} pool={} reserved={} ref_period={}",
        ts.mint,
        pool,
        ts.reserved,
        ts.liquidation_ref_period
    );
    Ok(())
}

#[derive(Accounts)]
pub struct StartLiquidation<'info> {
    /// Anyone may crank this (pays the transaction fee).
    pub crank: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
    )]
    pub token_state: Box<Account<'info, TokenState>>,

    /// Pool PDA (authority of the redemption pool).
    /// CHECK: bound by seeds; signs as a program-derived address.
    #[account(
        seeds = [POOL_AUTHORITY_SEED, token_state.mint.as_ref()],
        bump = token_state.pool_authority_bump,
    )]
    pub pool_authority: UncheckedAccount<'info>,

    #[account(mut, address = token_state.redemption_vault @ TorusError::Unauthorized)]
    pub redemption_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Compensation pool (fixed in Config). Used only when there is no basis for a split.
    #[account(mut, address = config.slash_destination @ TorusError::Unauthorized)]
    pub slash_destination: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(address = token_state.usdc_mint @ TorusError::NonUsdcCollateral)]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    pub usdc_token_program: Interface<'info, TokenInterface>,
}
