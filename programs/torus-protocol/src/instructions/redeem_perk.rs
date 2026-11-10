//! redeem_perk: a registered merchant and the holder of a registered account sign to record a perk.
//!
//!   - trader perk: up to (volume the account sent last period × the period's trader rate) in discounts this period
//!   - hold perk: purchases up to (lowest balance this period × cap per token) get the rate of the account's stamp age
//! Both draw on the period's budget. The receipt goes into the issuer's ledger and through the existing audit and
//! payout.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount};
use torus_hook::HolderRecord;

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::provision_budget::mul_bps;
use crate::rules;
use crate::state::{load_if_exists, HolderPerk, MerchantRecord, PerkPeriod, PerkReceipt, PerkTerms, TokenState};

pub fn handler(ctx: Context<RedeemPerk>, kind: u8, amount: u64, receipt_id: [u8; 32]) -> Result<()> {
    require!(amount > 0, TorusError::InvalidPerkRedemption);
    let ts = &ctx.accounts.token_state;
    // After the exit no commitment is accepted, so no audit could ever take the receipt.
    require!(!ts.exited, TorusError::TokenExited);
    let now = Clock::get()?.unix_timestamp;
    let period = ts.period_id;
    require!(ts.grid_index(now) == period, TorusError::PerkPeriodNotCurrent);
    require!(!ts.frozen, TorusError::TokenFrozen);
    let record: HolderRecord =
        load_if_exists(&ctx.accounts.holder_record, &torus_hook::ID)?.ok_or(TorusError::HolderNotRegistered)?;
    let terms = &ctx.accounts.perk_terms.params;

    let hp = &mut ctx.accounts.holder_perk;
    hp.enter_period(period);
    let pp = &mut ctx.accounts.perk_period;
    let discount = match kind {
        PERK_TRADER => {
            let last = period.checked_sub(1).ok_or(TorusError::PerkPeriodNotCurrent)?;
            let allowance = mul_bps(record.sent.in_period(last), pp.trader_rate_bps)?;
            hp.trader_used = rules::within(hp.trader_used, amount, allowance, TorusError::PerkAllowanceExceeded)?;
            pp.trader_used = rules::within(pp.trader_used, amount, pp.trader_budget, TorusError::PerkBudgetExceeded)?;
            amount
        }
        PERK_HOLD => {
            let min_balance = record.min_balance_in(period, ctx.accounts.holder_token.amount);
            let cap = rules::hold_cap(min_balance, terms.cap_per_token, ctx.accounts.mint.decimals);
            hp.hold_spend = rules::within(hp.hold_spend, amount, cap, TorusError::PerkAllowanceExceeded)?;
            let discount = mul_bps(amount, rules::hold_rate_bps(terms, now - record.stamp_ts))?;
            require!(discount > 0, TorusError::InvalidPerkRedemption);
            pp.hold_used = rules::within(pp.hold_used, discount, pp.hold_budget, TorusError::PerkBudgetExceeded)?;
            discount
        }
        _ => return err!(TorusError::InvalidPerkRedemption),
    };

    let receipt = &mut ctx.accounts.receipt;
    receipt.token = ts.mint;
    receipt.period_id = period;
    receipt.account = ctx.accounts.holder_token.key();
    receipt.merchant = ctx.accounts.merchant.key();
    receipt.kind = kind;
    receipt.discount = discount;
    receipt.bump = ctx.bumps.receipt;
    msg!(
        "redeem_perk: mint={} period={} account={} kind={} amount={} discount={} receipt={:?}",
        receipt.token,
        period,
        receipt.account,
        kind,
        amount,
        discount,
        receipt_id
    );
    Ok(())
}

#[derive(Accounts)]
#[instruction(kind: u8, amount: u64, receipt_id: [u8; 32])]
pub struct RedeemPerk<'info> {
    /// The registered merchant (pays for the receipt).
    #[account(mut)]
    pub merchant: Signer<'info>,

    /// Owner of the registered account receiving the perk.
    pub holder: Signer<'info>,

    #[account(seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()], bump = token_state.bump)]
    pub token_state: Box<Account<'info, TokenState>>,

    #[account(seeds = [PERK_TERMS_SEED, token_state.mint.as_ref()], bump = perk_terms.bump)]
    pub perk_terms: Box<Account<'info, PerkTerms>>,

    /// The current period's budget (opened by open_perk_period).
    #[account(
        mut,
        seeds = [PERK_PERIOD_SEED, token_state.mint.as_ref(), token_state.period_id.to_le_bytes().as_ref()],
        bump = perk_period.bump,
    )]
    pub perk_period: Box<Account<'info, PerkPeriod>>,

    #[account(
        seeds = [MERCHANT_SEED, token_state.mint.as_ref(), merchant.key().as_ref()],
        bump = merchant_record.bump,
        constraint = merchant_record.active @ TorusError::MerchantNotRegistered,
    )]
    pub merchant_record: Box<Account<'info, MerchantRecord>>,

    #[account(address = token_state.mint @ TorusError::Unauthorized)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    #[account(token::mint = mint, constraint = holder_token.owner == holder.key() @ TorusError::Unauthorized)]
    pub holder_token: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The hook's record of the account (stamp, lowest balance, volume sent).
    /// CHECK: address bound by seeds under the hook program; read only when the hook owns it.
    #[account(seeds = [HOLDER_SEED, holder_token.key().as_ref()], bump, seeds::program = torus_hook::ID)]
    pub holder_record: UncheckedAccount<'info>,

    #[account(mut, seeds = [HOLDER_PERK_SEED, holder_token.key().as_ref()], bump = holder_perk.bump)]
    pub holder_perk: Box<Account<'info, HolderPerk>>,

    /// One receipt per receipt_id, so the same redemption is never recorded twice.
    #[account(
        init,
        payer = merchant,
        space = 8 + PerkReceipt::INIT_SPACE,
        seeds = [PERK_RECEIPT_SEED, token_state.mint.as_ref(), receipt_id.as_ref()],
        bump,
    )]
    pub receipt: Box<Account<'info, PerkReceipt>>,

    pub system_program: Program<'info, System>,
}
