//! deposit_pool: a voluntary USDC deposit into the pool (in addition to the forced deposit through convert_fees).
//!
//! Split between the two accounts: the slashing bond first, up to bond_target, then the rest to the redemption
//! pool. When the bond reaches its target, redemption_started is set (the condition for redemptions to start).
//! USDC is a classic SPL token (usdc_token_program); the transfers are signed by the depositor
//! (no PDA signature needed).

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{
    self, Mint, TokenAccount, TokenInterface, TransferChecked,
};

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::TokenState;

pub fn handler(ctx: Context<DepositPool>, amount: u64) -> Result<()> {
    // No deposits while frozen.
    require!(!ctx.accounts.token_state.frozen, TorusError::TokenFrozen);
    require!(!ctx.accounts.token_state.exited, TorusError::TokenExited);
    // The bond target is set by the operator; without it (0) a deposit would start redemptions with no bond.
    require!(ctx.accounts.token_state.bond_target > 0, TorusError::IssuerTermsNotSet);
    let bond_target = ctx.accounts.token_state.bond_target;
    let bond_balance = ctx.accounts.slashing_bond.amount;
    let decimals = ctx.accounts.usdc_mint.decimals;

    // Fill the bond up to its target first; once full, everything goes to the redemption pool.
    let to_bond = if bond_balance >= bond_target {
        0
    } else {
        bond_target.saturating_sub(bond_balance).min(amount)
    };
    let to_vault = amount.saturating_sub(to_bond);

    if to_bond > 0 {
        token_interface::transfer_checked(
            CpiContext::new(
                ctx.accounts.usdc_token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.depositor_usdc.to_account_info(),
                    mint: ctx.accounts.usdc_mint.to_account_info(),
                    to: ctx.accounts.slashing_bond.to_account_info(),
                    authority: ctx.accounts.depositor.to_account_info(),
                },
            ),
            to_bond,
            decimals,
        )?;
    }

    if to_vault > 0 {
        token_interface::transfer_checked(
            CpiContext::new(
                ctx.accounts.usdc_token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.depositor_usdc.to_account_info(),
                    mint: ctx.accounts.usdc_mint.to_account_info(),
                    to: ctx.accounts.redemption_vault.to_account_info(),
                    authority: ctx.accounts.depositor.to_account_info(),
                },
            ),
            to_vault,
            decimals,
        )?;
    }

    // Redemptions start once the bond balance after this deposit reaches the target.
    let new_bond_balance = bond_balance.saturating_add(to_bond);
    if new_bond_balance >= bond_target {
        ctx.accounts.token_state.redemption_started = true;
    }

    msg!(
        "deposit_pool: mint={} amount={} to_bond={} to_vault={} bond_balance={}->{} redemption_started={}",
        ctx.accounts.token_state.mint,
        amount,
        to_bond,
        to_vault,
        bond_balance,
        new_bond_balance,
        ctx.accounts.token_state.redemption_started
    );
    Ok(())
}

#[derive(Accounts)]
pub struct DepositPool<'info> {
    /// The depositor: owner of the source USDC account and fee payer.
    #[account(mut)]
    pub depositor: Signer<'info>,

    /// Source: the depositor's USDC token account.
    #[account(mut)]
    pub depositor_usdc: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
    )]
    pub token_state: Account<'info, TokenState>,

    /// Second account: slashing bond (USDC), filled first.
    #[account(
        mut,
        address = token_state.slashing_bond @ TorusError::Unauthorized,
    )]
    pub slashing_bond: InterfaceAccount<'info, TokenAccount>,

    /// First account: redemption pool (USDC), receives the rest once the bond is full.
    #[account(
        mut,
        address = token_state.redemption_vault @ TorusError::Unauthorized,
    )]
    pub redemption_vault: InterfaceAccount<'info, TokenAccount>,

    /// Pool currency (USDC), so the backing is not the brand token.
    #[account(address = token_state.usdc_mint @ TorusError::NonUsdcCollateral)]
    pub usdc_mint: InterfaceAccount<'info, Mint>,

    /// Token program of USDC (classic SPL, as in issue_token.rs).
    pub usdc_token_program: Interface<'info, TokenInterface>,
}
