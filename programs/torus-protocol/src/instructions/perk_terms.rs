//! set_perk_terms: the perk terms the operator negotiates with each company (allocation of the obligation, hold perk
//! rates and step, cap per token, restamp fee, ask cap and usage cap of listed trader perks). Only the safety rules in
//! rules.rs are fixed.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::rules;
use crate::state::{Config, PerkParams, PerkTerms, TokenState};

pub fn handler(ctx: Context<SetPerkTerms>, params: PerkParams) -> Result<()> {
    rules::check_perk_params(&params)?;
    let t = &mut ctx.accounts.perk_terms;
    t.token = ctx.accounts.token_state.mint;
    t.params = params;
    t.bump = ctx.bumps.perk_terms;
    msg!(
        "set_perk_terms: mint={} general={} trader={} hold={} restamp_fee={}",
        t.token,
        params.general_bps,
        params.trader_bps,
        params.hold_bps,
        params.restamp_fee_bps
    );
    Ok(())
}

#[derive(Accounts)]
pub struct SetPerkTerms<'info> {
    /// The operator (Config.authority).
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = authority @ TorusError::Unauthorized)]
    pub config: Account<'info, Config>,

    #[account(seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()], bump = token_state.bump)]
    pub token_state: Account<'info, TokenState>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + PerkTerms::INIT_SPACE,
        seeds = [PERK_TERMS_SEED, token_state.mint.as_ref()],
        bump,
    )]
    pub perk_terms: Account<'info, PerkTerms>,

    pub system_program: Program<'info, System>,
}
