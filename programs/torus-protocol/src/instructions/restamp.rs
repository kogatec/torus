//! restamp: in one instruction signed by the holder and the company's local partner, burn → re-mint → update the stamp.
//!
//! This is the only way tokens are minted after issuance (issue_token moved the mint authority to the pool PDA). The
//! amount re-minted is exactly the amount burned in the same instruction, so the supply never grows: the holder gets it
//! back minus the restamp fee, which goes to the local partner's account. The operator never holds the tokens. The
//! re-minted amount gets today's stamp, so the hold perk rate starts over for it.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Burn, Mint, MintTo, TokenAccount, TokenInterface};
use torus_hook::cpi::accounts::SetStamp;
use torus_hook::program::TorusHook;

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::provision_budget::mul_bps;
use crate::state::{LocalPartnerRecord, PerkTerms, TokenState};

pub fn handler(ctx: Context<Restamp>, amount: u64) -> Result<()> {
    let ts = &ctx.accounts.token_state;
    require!(!ts.frozen, TorusError::TokenFrozen);
    require!(
        amount > 0 && amount <= ctx.accounts.holder_token.amount,
        TorusError::InvalidRestampAmount
    );
    let fee = mul_bps(amount, ctx.accounts.perk_terms.params.restamp_fee_bps)?;
    let reminted = amount - fee;
    let mint_key = ts.mint;
    let seeds: &[&[u8]] = &[POOL_AUTHORITY_SEED, mint_key.as_ref(), &[ts.pool_authority_bump]];
    let token_program = ctx.accounts.token_program.to_account_info();

    // 1. Burn (the holder signs).
    token_interface::burn(
        CpiContext::new(
            token_program.clone(),
            Burn {
                mint: ctx.accounts.mint.to_account_info(),
                from: ctx.accounts.holder_token.to_account_info(),
                authority: ctx.accounts.holder.to_account_info(),
            },
        ),
        amount,
    )?;

    // 2. Re-mint the burned amount (the pool PDA is the mint authority): to the holder, the fee to the partner.
    let legs = [
        (reminted, ctx.accounts.holder_token.to_account_info()),
        (fee, ctx.accounts.partner_token.to_account_info()),
    ];
    for (value, to) in legs {
        if value == 0 {
            continue;
        }
        token_interface::mint_to(
            CpiContext::new_with_signer(
                token_program.clone(),
                MintTo {
                    mint: ctx.accounts.mint.to_account_info(),
                    to,
                    authority: ctx.accounts.pool_authority.to_account_info(),
                },
                &[seeds],
            ),
            value,
        )?;
    }

    // 3. The re-minted amount gets today's stamp (mints do not pass through the hook).
    let now = Clock::get()?.unix_timestamp;
    torus_hook::cpi::set_stamp(
        CpiContext::new_with_signer(
            ctx.accounts.hook_program.to_account_info(),
            SetStamp {
                protocol_signer: ctx.accounts.pool_authority.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                token_account: ctx.accounts.holder_token.to_account_info(),
                holder_record: ctx.accounts.holder_record.to_account_info(),
            },
            &[seeds],
        ),
        reminted,
        ts.grid_index(now),
    )?;
    msg!(
        "restamp: mint={} account={} burned={} reminted={} fee={}",
        mint_key,
        ctx.accounts.holder_token.key(),
        amount,
        reminted,
        fee
    );
    Ok(())
}

#[derive(Accounts)]
pub struct Restamp<'info> {
    /// Owner of the registered account.
    pub holder: Signer<'info>,

    /// The company's local partner co-signs (it may check the holder off-chain first).
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

    /// The restamp fee is a per-company term (0 works).
    #[account(seeds = [PERK_TERMS_SEED, token_state.mint.as_ref()], bump = perk_terms.bump)]
    pub perk_terms: Box<Account<'info, PerkTerms>>,

    #[account(mut, address = token_state.mint @ TorusError::Unauthorized)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    #[account(mut, token::mint = mint, constraint = holder_token.owner == holder.key() @ TorusError::Unauthorized)]
    pub holder_token: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The partner's account receiving the fee.
    #[account(mut, token::mint = mint, constraint = partner_token.owner == local_partner.key() @ TorusError::Unauthorized)]
    pub partner_token: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The hook's record of the account.
    /// CHECK: torus-hook's set_stamp binds it by seeds.
    #[account(mut)]
    pub holder_record: UncheckedAccount<'info>,

    /// Pool PDA: the mint authority, and the signer of the hook's set_stamp.
    /// CHECK: bound by seeds; signs as a program-derived address.
    #[account(seeds = [POOL_AUTHORITY_SEED, token_state.mint.as_ref()], bump = token_state.pool_authority_bump)]
    pub pool_authority: UncheckedAccount<'info>,

    pub hook_program: Program<'info, TorusHook>,

    /// Token-2022 (the brand token's program).
    #[account(constraint = token_program.key() == anchor_spl::token_2022::ID @ TorusError::Unauthorized)]
    pub token_program: Interface<'info, TokenInterface>,
}
