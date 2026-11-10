//! list_perk / close_perk_lot: a seller sets aside part of its trader perk for customers.
//!
//! The trader perk is a right inside the redemption pool: to have the pool pay at a registered merchant. Listing moves
//! that right out of the account into the seller's lot. The allowance and the budget are checked here, once per listing
//! and not at every use. A customer takes the right at checkout (off-chain, signed by the customer and the merchant's
//! terminal) and uses it on the spot, so it never circulates. The issuer's ledger then pays the face value through the
//! existing audit and payout: the discount to the merchant, the rest to the seller, the same total as if the seller had
//! used it. The local partner co-signs (it checks who the seller is off-chain first, as for restamps).

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount};
use torus_hook::HolderRecord;

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::provision_budget::mul_bps;
use crate::rules;
use crate::state::{load_if_exists, HolderPerk, LocalPartnerRecord, PerkLot, PerkPeriod, TokenState};

pub fn list(ctx: Context<ListPerk>, amount: u64) -> Result<()> {
    require!(amount > 0, TorusError::InvalidPerkListing);
    let ts = &ctx.accounts.token_state;
    // After the exit no commitment is accepted, so no audit could ever take what the lot pays.
    require!(!ts.exited, TorusError::TokenExited);
    require!(!ts.frozen, TorusError::TokenFrozen);
    let period = ts.period_id;
    require!(
        ts.grid_index(Clock::get()?.unix_timestamp) == period,
        TorusError::PerkPeriodNotCurrent
    );
    let last = period.checked_sub(1).ok_or(TorusError::PerkPeriodNotCurrent)?;

    let pp = &mut ctx.accounts.perk_period;
    require!(pp.max_ask_bps > 0 && pp.usage_cap_bps > 0, TorusError::PerkListingClosed);
    let record: HolderRecord =
        load_if_exists(&ctx.accounts.holder_record, &torus_hook::ID)?.ok_or(TorusError::HolderNotRegistered)?;
    let listable = mul_bps(record.sent.in_period(last), pp.listable_rate_bps)?;

    let hp = &mut ctx.accounts.holder_perk;
    hp.enter_period(period);
    hp.trader_used = rules::within(hp.trader_used, amount, listable, TorusError::PerkAllowanceExceeded)?;
    pp.trader_used = rules::within(pp.trader_used, amount, pp.trader_budget, TorusError::PerkBudgetExceeded)?;

    let lot = &mut ctx.accounts.lot;
    // The first lister owns the lot: if the account changes hands mid-period, the rent and the record stay with it.
    if lot.listed == 0 {
        lot.seller = ctx.accounts.seller.key();
    }
    require_keys_eq!(lot.seller, ctx.accounts.seller.key(), TorusError::Unauthorized);
    lot.token = ts.mint;
    lot.period_id = period;
    lot.account = ctx.accounts.holder_token.key();
    lot.listed = lot.listed.checked_add(amount).ok_or(TorusError::MathOverflow)?;
    lot.bump = ctx.bumps.lot;
    msg!(
        "list_perk: mint={} period={} account={} amount={} listed={}",
        lot.token,
        period,
        lot.account,
        amount,
        lot.listed
    );
    Ok(())
}

/// Returns the lot's rent once the audit of its period is over (or the token will never close another period). The
/// audit deadline is one period after the period closes, so the amount listed stays readable until then.
pub fn close(ctx: Context<ClosePerkLot>) -> Result<()> {
    let ts = &ctx.accounts.token_state;
    let lot = &ctx.accounts.lot;
    require!(
        ts.period_id > lot.period_id.saturating_add(1) || ts.frozen || ts.exited,
        TorusError::PerkLotStillOpen
    );
    msg!("close_perk_lot: mint={} period={} account={}", lot.token, lot.period_id, lot.account);
    Ok(())
}

#[derive(Accounts)]
pub struct ListPerk<'info> {
    /// Owner of the registered account (pays for the lot).
    #[account(mut)]
    pub seller: Signer<'info>,

    /// The company's local partner co-signs (it may check the seller off-chain first).
    #[account(address = token_state.local_partner @ TorusError::LocalPartnerNotRegistered)]
    pub local_partner: Signer<'info>,

    #[account(
        seeds = [LOCAL_PARTNER_SEED, local_partner.key().as_ref()],
        bump = local_partner_record.bump,
        constraint = local_partner_record.active @ TorusError::LocalPartnerNotRegistered,
    )]
    pub local_partner_record: Box<Account<'info, LocalPartnerRecord>>,

    #[account(seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()], bump = token_state.bump)]
    pub token_state: Box<Account<'info, TokenState>>,

    /// The current period's budget (opened by open_perk_period).
    #[account(
        mut,
        seeds = [PERK_PERIOD_SEED, token_state.mint.as_ref(), token_state.period_id.to_le_bytes().as_ref()],
        bump = perk_period.bump,
    )]
    pub perk_period: Box<Account<'info, PerkPeriod>>,

    #[account(address = token_state.mint @ TorusError::Unauthorized)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    #[account(token::mint = mint, constraint = holder_token.owner == seller.key() @ TorusError::Unauthorized)]
    pub holder_token: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The hook's record of the account (volume sent).
    /// CHECK: address bound by seeds under the hook program; read only when the hook owns it.
    #[account(seeds = [HOLDER_SEED, holder_token.key().as_ref()], bump, seeds::program = torus_hook::ID)]
    pub holder_record: UncheckedAccount<'info>,

    #[account(mut, seeds = [HOLDER_PERK_SEED, holder_token.key().as_ref()], bump = holder_perk.bump)]
    pub holder_perk: Box<Account<'info, HolderPerk>>,

    /// One lot per account × period; listing again adds to it.
    #[account(
        init_if_needed,
        payer = seller,
        space = 8 + PerkLot::INIT_SPACE,
        seeds = [
            PERK_LOT_SEED,
            token_state.mint.as_ref(),
            token_state.period_id.to_le_bytes().as_ref(),
            holder_token.key().as_ref(),
        ],
        bump,
    )]
    pub lot: Box<Account<'info, PerkLot>>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClosePerkLot<'info> {
    /// The seller gets the rent back.
    #[account(mut)]
    pub seller: Signer<'info>,

    #[account(seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()], bump = token_state.bump)]
    pub token_state: Box<Account<'info, TokenState>>,

    #[account(
        mut,
        close = seller,
        has_one = seller @ TorusError::Unauthorized,
        constraint = lot.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub lot: Box<Account<'info, PerkLot>>,
}
