//! open_perk_period: opens the perk budget of the current period (anyone can crank it).
//!
//! Budget = the previous period's obligation (provisioned when it closed) × the allocation. Perks cannot exceed it, so the
//! issuer can only deliver the rest of its obligation as general returns; no separate judging is needed to keep the
//! manifest at the center. The trader perk rate = trader budget ÷ volume sent by all registered accounts in the previous
//! period, capped at half the transfer fee rate (trading with oneself to collect it always loses).

use anchor_lang::prelude::*;
use torus_hook::VolumeCounter;

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::provision_budget::mul_bps;
use crate::rules;
use crate::state::{load_if_exists, LocalPartnerRecord, PerkPeriod, PerkTerms, TokenState};

pub fn handler(ctx: Context<OpenPerkPeriod>) -> Result<()> {
    let ts = &ctx.accounts.token_state;
    let now = Clock::get()?.unix_timestamp;
    let period = ts.period_id;
    require!(
        ts.periods_started && period > 0 && ts.grid_index(now) == period,
        TorusError::PerkPeriodNotCurrent
    );
    require!(!ts.frozen, TorusError::TokenFrozen);
    require!(!ts.exited, TorusError::TokenExited);

    let counter: VolumeCounter =
        load_if_exists(&ctx.accounts.volume_counter, &torus_hook::ID)?.ok_or(TorusError::Unauthorized)?;
    let registered_volume = counter.registered.in_period(period - 1);
    let terms = &ctx.accounts.perk_terms.params;
    let trader_budget = mul_bps(ts.budget, terms.trader_bps)?;

    let pp = &mut ctx.accounts.perk_period;
    pp.token = ts.mint;
    pp.period_id = period;
    pp.trader_budget = trader_budget;
    pp.hold_budget = mul_bps(ts.budget, terms.hold_bps)?;
    pp.trader_rate_bps = rules::trader_rate_bps(trader_budget, registered_volume, ts.transfer_fee_bps);
    pp.trader_used = 0;
    pp.hold_used = 0;
    pp.bump = ctx.bumps.perk_period;
    // A revoked partner gets nothing back (its share goes to the treasury), and it cannot co-sign a listing anyway.
    let lp = &ctx.accounts.local_partner_record;
    let partner_share_bps = if lp.active { lp.share_bps } else { 0 };
    pp.listable_rate_bps = rules::listable_rate_bps(
        pp.trader_rate_bps,
        ts.transfer_fee_bps,
        rules::unreturned_fee_share_bps(ts.tier_share_bps[TIERS - 1], partner_share_bps),
        ts.cycle_terms.return_rate_bps,
    );
    pp.max_ask_bps = terms.max_ask_bps;
    pp.usage_cap_bps = terms.usage_cap_bps;
    msg!(
        "open_perk_period: mint={} period={} trader_budget={} hold_budget={} trader_rate_bps={} listable_rate_bps={} registered_volume={}",
        pp.token,
        period,
        pp.trader_budget,
        pp.hold_budget,
        pp.trader_rate_bps,
        pp.listable_rate_bps,
        registered_volume
    );
    Ok(())
}

#[derive(Accounts)]
pub struct OpenPerkPeriod<'info> {
    /// Anyone (pays for the account).
    #[account(mut)]
    pub crank: Signer<'info>,

    #[account(seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()], bump = token_state.bump)]
    pub token_state: Box<Account<'info, TokenState>>,

    #[account(seeds = [PERK_TERMS_SEED, token_state.mint.as_ref()], bump = perk_terms.bump)]
    pub perk_terms: Box<Account<'info, PerkTerms>>,

    /// The company's local partner: what comes back to it lowers the rate that can be listed.
    #[account(seeds = [LOCAL_PARTNER_SEED, token_state.local_partner.as_ref()], bump = local_partner_record.bump)]
    pub local_partner_record: Box<Account<'info, LocalPartnerRecord>>,

    /// The hook's volume counter (volume sent by registered accounts).
    /// CHECK: bound to the hook-owned PDA by seeds; deserialized only when the hook owns it.
    #[account(seeds = [b"volume", token_state.mint.as_ref()], bump, seeds::program = torus_hook::ID)]
    pub volume_counter: UncheckedAccount<'info>,

    #[account(
        init,
        payer = crank,
        space = 8 + PerkPeriod::INIT_SPACE,
        seeds = [PERK_PERIOD_SEED, token_state.mint.as_ref(), token_state.period_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub perk_period: Box<Account<'info, PerkPeriod>>,

    pub system_program: Program<'info, System>,
}
