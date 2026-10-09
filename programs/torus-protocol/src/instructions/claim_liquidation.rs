//! claim_liquidation: pays a liquidation share (anyone can call; only to the leaf's recipient).
//!
//! The liquidation pool (the surplus fixed by start_liquidation) is split over the leaves of the basis audit (the
//! last one finalized without fraud), pro rata to each leaf's confirmed amount (observed value or the auditor's
//! confirmation, at most the leaf's value):  share = pool × confirmed ÷ control total
//! Once per leaf (LiquidationClaim is created). Shares of unconfirmed leaves stay in the pool.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::payout::confirmed_amount;
use crate::instructions::verify_disclosure::{fold_sum_proof, SumSibling};
use crate::state::{AuditCycle, LeafAttestation, LiquidationClaim, TokenState};

pub fn handler(
    ctx: Context<ClaimLiquidation>,
    index: u32,
    outcome_id: [u8; 32],
    value: u64,
    siblings: Vec<SumSibling>,
) -> Result<()> {
    let ts = &ctx.accounts.token_state;
    let audit = &ctx.accounts.audit;
    require!(
        ts.liquidation_started
            && ts.liquidation_pool > 0
            && audit.period_id == ts.liquidation_ref_period,
        TorusError::LiquidationNotStarted
    );

    let beneficiary = ctx.accounts.beneficiary_usdc.owner;
    let (root, sum) = fold_sum_proof(
        index,
        &outcome_id,
        &beneficiary,
        value,
        &siblings,
        audit.population_size,
    )?;
    require!(
        root == audit.commitment_value && sum == audit.control_total,
        TorusError::ClaimProofInvalid
    );

    let audit_key = audit.key();
    let confirmed = confirmed_amount(
        audit,
        &audit_key,
        index,
        &beneficiary,
        ctx.accounts.attestation.as_deref(),
    )?;
    let basis = value.min(confirmed);
    let share = ((ts.liquidation_pool as u128) * (basis as u128) / (audit.control_total as u128)) as u64;
    require!(share > 0, TorusError::NothingToPay);

    let record = &mut ctx.accounts.liquidation_claim;
    record.audit = audit_key;
    record.index = index;
    record.beneficiary = beneficiary;
    record.amount = share;
    record.bump = ctx.bumps.liquidation_claim;

    let mint_key = ts.mint;
    let seeds: &[&[u8]] = &[POOL_AUTHORITY_SEED, mint_key.as_ref(), &[ts.pool_authority_bump]];
    token_interface::transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.usdc_token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.redemption_vault.to_account_info(),
                mint: ctx.accounts.usdc_mint.to_account_info(),
                to: ctx.accounts.beneficiary_usdc.to_account_info(),
                authority: ctx.accounts.pool_authority.to_account_info(),
            },
            &[seeds],
        ),
        share,
        ctx.accounts.usdc_mint.decimals,
    )?;

    msg!(
        "claim_liquidation: mint={} period_id={} index={} basis={} share={}",
        mint_key,
        audit.period_id,
        index,
        basis,
        share
    );
    Ok(())
}

#[derive(Accounts)]
#[instruction(index: u32)]
pub struct ClaimLiquidation<'info> {
    /// Anyone may crank this (pays the transaction fee).
    #[account(mut)]
    pub crank: Signer<'info>,

    #[account(
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
    )]
    pub token_state: Box<Account<'info, TokenState>>,

    /// The basis audit cycle (token_state.liquidation_ref_period).
    #[account(
        seeds = [AUDIT_SEED, audit.token.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
        constraint = audit.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub audit: Box<Account<'info, AuditCycle>>,

    /// The auditor's confirmation of the leaf (needed when the leaf was not sampled); omit if there is none.
    pub attestation: Option<Account<'info, LeafAttestation>>,

    /// Pool PDA (authority of the redemption pool).
    /// CHECK: bound by seeds; signs as a program-derived address.
    #[account(
        seeds = [POOL_AUTHORITY_SEED, token_state.mint.as_ref()],
        bump = token_state.pool_authority_bump,
    )]
    pub pool_authority: UncheckedAccount<'info>,

    #[account(mut, address = token_state.redemption_vault @ TorusError::Unauthorized)]
    pub redemption_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Destination (USDC). The proof fails unless its owner is the leaf's recipient.
    #[account(mut, token::mint = usdc_mint)]
    pub beneficiary_usdc: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Liquidation claim record (one per leaf).
    #[account(
        init,
        payer = crank,
        space = 8 + LiquidationClaim::INIT_SPACE,
        seeds = [LIQUIDATION_SEED, audit.key().as_ref(), index.to_le_bytes().as_ref()],
        bump,
    )]
    pub liquidation_claim: Account<'info, LiquidationClaim>,

    #[account(address = token_state.usdc_mint @ TorusError::NonUsdcCollateral)]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    pub usdc_token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
