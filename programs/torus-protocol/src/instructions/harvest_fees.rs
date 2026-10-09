//! harvest_fees: sweeps collected fees (makes it structurally impossible to avoid funding by doing nothing).
//!
//! With Token-2022's TransferFee extension, each transfer withholds the fee in the recipient's token account.
//! This instruction moves the withheld fees into the pool in two steps:
//!   (1) holder accounts → mint (harvest_withheld_tokens_to_mint: permissionless CPI)
//!   (2) mint → fee_vault (withdraw_withheld_tokens_from_mint: signed by the pool_authority PDA)
//!
//! [Design]
//!   - **No issuer signature is required.** Anyone can crank it and the only signer is the pool_authority PDA,
//!     so the issuer has no option to "not deposit" the fees: avoiding the deposit by inaction is impossible.
//!   - (1) is permissionless in Token-2022, so the holder accounts are passed in `ctx.remaining_accounts`
//!     (any number) and handed to the CPI as is. Accounts of another mint are rejected by Token-2022.
//!   - For (2), the mint's withdraw_withheld_authority must be the pool_authority PDA (checked by issue_token);
//!     otherwise this CPI fails.
//!
//! [Scope]
//!   The swept fees are **in the brand token**, not USDC. The redemption pool and the bond are in USDC; converting
//!   the fee tokens into USDC is done by convert_fees (a registered partner buys them). This instruction only
//!   guarantees that the fees move under protocol control without passing through the issuer's hands.

// Requires anchor-spl's `token_2022_extensions` feature (enabled in programs/torus-protocol/Cargo.toml).

use anchor_lang::prelude::*;
use anchor_spl::token_2022_extensions::transfer_fee::{
    harvest_withheld_tokens_to_mint, withdraw_withheld_tokens_from_mint,
    HarvestWithheldTokensToMint, WithdrawWithheldTokensFromMint,
};
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{Config, TokenState};

// NOTE: the explicit 'info lifetime is needed to pass remaining_accounts to the CPI
//   (lib.rs uses the same signature).
pub fn handler<'info>(ctx: Context<'_, '_, '_, 'info, HarvestFees<'info>>) -> Result<()> {
    // Sweeping stops for a token frozen by finalize_audit.
    require!(!ctx.accounts.token_state.frozen, TorusError::TokenFrozen);

    let mint_key = ctx.accounts.token_state.mint;
    let pool_authority_bump = ctx.accounts.token_state.pool_authority_bump;

    // fee_vault balance before the CPIs (to measure what was swept).
    let balance_before = ctx.accounts.fee_vault.amount;

    // ===== (1) holder accounts → mint (permissionless CPI, no signature) =====
    // The accounts are remaining_accounts. If empty, assume they were already harvested and only run (2).
    let sources: Vec<AccountInfo<'info>> = ctx.remaining_accounts.to_vec();
    let source_count = sources.len();
    if source_count > 0 {
        harvest_withheld_tokens_to_mint(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                HarvestWithheldTokensToMint {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            sources,
        )?;
    }

    // ===== (2) mint → fee_vault (signed by the pool_authority PDA only) =====
    // No issuer key is involved: this is what makes avoiding the deposit impossible.
    let seeds: &[&[u8]] = &[
        POOL_AUTHORITY_SEED,
        mint_key.as_ref(),
        &[pool_authority_bump],
    ];
    let signer: &[&[&[u8]]] = &[seeds];

    withdraw_withheld_tokens_from_mint(CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        WithdrawWithheldTokensFromMint {
            token_program_id: ctx.accounts.token_program.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            destination: ctx.accounts.fee_vault.to_account_info(),
            authority: ctx.accounts.pool_authority.to_account_info(),
        },
        signer,
    ))?;

    // ===== Amount swept (increase of fee_vault) =====
    ctx.accounts.fee_vault.reload()?;
    let balance_after = ctx.accounts.fee_vault.amount;
    let harvested = balance_after
        .checked_sub(balance_before)
        .ok_or(TorusError::MathOverflow)?;

    // Cumulative swept amount for the fee cross-check: only what **actually** arrived in fee_vault, monotonic.
    // provision_budget checks it against the fees implied by the transfers.
    let token_state = &mut ctx.accounts.token_state;
    token_state.cumulative_harvested = token_state
        .cumulative_harvested
        .checked_add(harvested)
        .ok_or(TorusError::MathOverflow)?;

    msg!(
        "harvest_fees: mint={} sources={} harvested={} cumulative_harvested={} (company-token denominated; USDC swap is out of scope) fee_vault={}",
        mint_key,
        source_count,
        harvested,
        token_state.cumulative_harvested,
        balance_after
    );
    Ok(())
}

#[derive(Accounts)]
pub struct HarvestFees<'info> {
    /// Anyone may crank this (pays the transaction fee only).
    /// The issuer's (token_state.issuer) signature is deliberately not required.
    #[account(mut)]
    pub crank: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
    )]
    pub token_state: Account<'info, TokenState>,

    /// The brand token's Token-2022 mint (with TransferFee).
    /// mut because harvesting writes the withheld amount to it.
    #[account(
        mut,
        address = token_state.mint @ TorusError::Unauthorized,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Pool PDA (the mint's withdraw_withheld_authority).
    /// CHECK: bound by seeds; holds no data, only signs.
    #[account(
        seeds = [POOL_AUTHORITY_SEED, token_state.mint.as_ref()],
        bump = token_state.pool_authority_bump,
    )]
    pub pool_authority: UncheckedAccount<'info>,

    /// Fee vault (in the brand token, Token-2022).
    /// Separate from the USDC redemption pool and bond.
    #[account(
        mut,
        seeds = [FEE_VAULT_SEED, token_state.mint.as_ref()],
        bump,
        token::mint = mint,
        token::authority = pool_authority,
        token::token_program = token_program,
    )]
    pub fee_vault: InterfaceAccount<'info, TokenAccount>,

    /// Token program of the brand token: Token-2022 (not the classic SPL program used for USDC).
    #[account(
        constraint = token_program.key() == anchor_spl::token_2022::ID @ TorusError::Unauthorized,
    )]
    pub token_program: Interface<'info, TokenInterface>,
}
