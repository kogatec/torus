//! Merchant registry (issuer). Perks are redeemed only with a registered merchant's signature, and each redemption
//! enters the issuer's ledger.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{MerchantRecord, TokenState};

pub fn register(ctx: Context<RegisterMerchant>) -> Result<()> {
    let r = &mut ctx.accounts.merchant_record;
    r.token = ctx.accounts.token_state.mint;
    r.merchant = ctx.accounts.merchant.key();
    r.active = true;
    r.bump = ctx.bumps.merchant_record;
    msg!("register_merchant: mint={} merchant={}", r.token, r.merchant);
    Ok(())
}

pub fn revoke(ctx: Context<RevokeMerchant>) -> Result<()> {
    let r = &mut ctx.accounts.merchant_record;
    r.active = false;
    msg!("revoke_merchant: mint={} merchant={}", r.token, r.merchant);
    Ok(())
}

#[derive(Accounts)]
pub struct RegisterMerchant<'info> {
    /// The issuer.
    #[account(mut)]
    pub issuer: Signer<'info>,

    #[account(
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
        has_one = issuer @ TorusError::Unauthorized,
    )]
    pub token_state: Account<'info, TokenState>,

    /// The merchant to register.
    /// CHECK: only the key is recorded; no signature needed.
    pub merchant: UncheckedAccount<'info>,

    #[account(
        init,
        payer = issuer,
        space = 8 + MerchantRecord::INIT_SPACE,
        seeds = [MERCHANT_SEED, token_state.mint.as_ref(), merchant.key().as_ref()],
        bump,
    )]
    pub merchant_record: Account<'info, MerchantRecord>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokeMerchant<'info> {
    /// The issuer.
    pub issuer: Signer<'info>,

    #[account(
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
        has_one = issuer @ TorusError::Unauthorized,
    )]
    pub token_state: Account<'info, TokenState>,

    #[account(
        mut,
        seeds = [MERCHANT_SEED, token_state.mint.as_ref(), merchant_record.merchant.as_ref()],
        bump = merchant_record.bump,
    )]
    pub merchant_record: Account<'info, MerchantRecord>,
}
