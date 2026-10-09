//! claim_distribution: pays the issuer share from the escrow to the issuer's USDC account (anyone can call).
//!
//! Only issuer_claimable can be paid: shares whose period's audit was finalized without fraud.
//! Shares still waiting (issuer_accruing / issuer_pending) cannot be withdrawn and are slashed on fraud or
//! default (finalization happens before any withdrawal). The destination must be owned by the issuer.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::TokenState;

pub fn handler(ctx: Context<ClaimDistribution>) -> Result<()> {
    let ts = &mut ctx.accounts.token_state;
    require!(!ts.frozen, TorusError::TokenFrozen);
    let amount = ts.issuer_claimable;
    require!(amount > 0, TorusError::NothingToClaim);
    ts.issuer_claimable = 0;

    let mint_key = ts.mint;
    let seeds: &[&[u8]] = &[
        POOL_AUTHORITY_SEED,
        mint_key.as_ref(),
        &[ts.pool_authority_bump],
    ];
    token_interface::transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.usdc_token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.issuer_escrow.to_account_info(),
                mint: ctx.accounts.usdc_mint.to_account_info(),
                to: ctx.accounts.issuer_usdc.to_account_info(),
                authority: ctx.accounts.pool_authority.to_account_info(),
            },
            &[seeds],
        ),
        amount,
        ctx.accounts.usdc_mint.decimals,
    )?;

    msg!("claim_distribution: mint={} issuer={} amount={}", mint_key, ts.issuer, amount);
    Ok(())
}

#[derive(Accounts)]
pub struct ClaimDistribution<'info> {
    /// Anyone may crank this (pays the transaction fee).
    pub crank: Signer<'info>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
    )]
    pub token_state: Account<'info, TokenState>,

    /// Pool PDA (authority of the escrow).
    /// CHECK: bound by seeds; signs as a program-derived address.
    #[account(
        seeds = [POOL_AUTHORITY_SEED, token_state.mint.as_ref()],
        bump = token_state.pool_authority_bump,
    )]
    pub pool_authority: UncheckedAccount<'info>,

    #[account(mut, address = token_state.issuer_escrow @ TorusError::Unauthorized)]
    pub issuer_escrow: InterfaceAccount<'info, TokenAccount>,

    /// Destination: a USDC account owned by the issuer.
    #[account(
        mut,
        token::mint = usdc_mint,
        constraint = issuer_usdc.owner == token_state.issuer @ TorusError::Unauthorized,
    )]
    pub issuer_usdc: InterfaceAccount<'info, TokenAccount>,

    #[account(address = token_state.usdc_mint @ TorusError::NonUsdcCollateral)]
    pub usdc_mint: InterfaceAccount<'info, Mint>,

    pub usdc_token_program: Interface<'info, TokenInterface>,
}
