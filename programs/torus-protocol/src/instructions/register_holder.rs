//! register_holder: the owner registers one of its token accounts for perks.
//!
//! Creates the hook's HolderRecord (through CPI, signed by the pool PDA) and the perk usage record. The balance held at
//! registration is stamped HOLD_STEPS steps back, i.e. already at 0%: registering alone never raises the rate. Tokens
//! received from others afterwards carry today's stamp; moves between one's own accounts keep theirs.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount};
use torus_hook::cpi::accounts::InitHolder;
use torus_hook::program::TorusHook;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{HolderPerk, PerkTerms, TokenState};

pub fn handler(ctx: Context<RegisterHolder>) -> Result<()> {
    let ts = &ctx.accounts.token_state;
    let now = Clock::get()?.unix_timestamp;
    let aged = ctx.accounts.perk_terms.params.hold_step_secs.saturating_mul(HOLD_STEPS as i64);
    let mint_key = ts.mint;
    let seeds: &[&[u8]] = &[POOL_AUTHORITY_SEED, mint_key.as_ref(), &[ts.pool_authority_bump]];
    torus_hook::cpi::init_holder(
        CpiContext::new_with_signer(
            ctx.accounts.hook_program.to_account_info(),
            InitHolder {
                payer: ctx.accounts.holder.to_account_info(),
                protocol_signer: ctx.accounts.pool_authority.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                token_account: ctx.accounts.holder_token.to_account_info(),
                holder_record: ctx.accounts.holder_record.to_account_info(),
                system_program: ctx.accounts.system_program.to_account_info(),
            },
            &[seeds],
        ),
        now.saturating_sub(aged),
        ts.grid_index(now),
    )?;

    let hp = &mut ctx.accounts.holder_perk;
    hp.token = mint_key;
    hp.account = ctx.accounts.holder_token.key();
    hp.period_id = 0;
    hp.trader_used = 0;
    hp.hold_spend = 0;
    hp.bump = ctx.bumps.holder_perk;
    msg!("register_holder: mint={} account={}", mint_key, hp.account);
    Ok(())
}

#[derive(Accounts)]
pub struct RegisterHolder<'info> {
    /// Owner of the account to register (pays for both records).
    #[account(mut)]
    pub holder: Signer<'info>,

    #[account(seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()], bump = token_state.bump)]
    pub token_state: Box<Account<'info, TokenState>>,

    /// Perks start once the operator has set the terms.
    #[account(seeds = [PERK_TERMS_SEED, token_state.mint.as_ref()], bump = perk_terms.bump)]
    pub perk_terms: Box<Account<'info, PerkTerms>>,

    #[account(address = token_state.mint @ TorusError::Unauthorized)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    #[account(token::mint = mint, constraint = holder_token.owner == holder.key() @ TorusError::Unauthorized)]
    pub holder_token: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The hook's record of this account.
    /// CHECK: created by torus-hook's init_holder, which binds it by seeds.
    #[account(mut)]
    pub holder_record: UncheckedAccount<'info>,

    #[account(
        init,
        payer = holder,
        space = 8 + HolderPerk::INIT_SPACE,
        seeds = [HOLDER_PERK_SEED, holder_token.key().as_ref()],
        bump,
    )]
    pub holder_perk: Box<Account<'info, HolderPerk>>,

    /// Pool PDA: signs the hook's init_holder.
    /// CHECK: bound by seeds; signs as a program-derived address.
    #[account(seeds = [POOL_AUTHORITY_SEED, token_state.mint.as_ref()], bump = token_state.pool_authority_bump)]
    pub pool_authority: UncheckedAccount<'info>,

    pub hook_program: Program<'info, TorusHook>,
    pub system_program: Program<'info, System>,
}
