//! Local partner registry (operator). A local partner serves the companies of its country: it operates restamps (the
//! only way new tokens are minted) and receives its share of the operator's fee on every conversion. Its share and its
//! USDC account are fixed at registration.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::TokenAccount;

use crate::constants::*;
use crate::errors::TorusError;
use crate::rules;
use crate::state::{Config, LocalPartnerRecord};

pub fn register(ctx: Context<RegisterLocalPartner>, share_bps: u16) -> Result<()> {
    rules::check_share_bps(share_bps)?;
    let r = &mut ctx.accounts.local_partner_record;
    r.partner = ctx.accounts.partner.key();
    r.usdc_account = ctx.accounts.partner_usdc.key();
    r.share_bps = share_bps;
    r.active = true;
    r.bump = ctx.bumps.local_partner_record;
    msg!("register_local_partner: partner={} share_bps={}", r.partner, share_bps);
    Ok(())
}

/// A revoked partner cannot restamp, and its share of later conversions goes to the Torus treasury.
pub fn revoke(ctx: Context<RevokeLocalPartner>) -> Result<()> {
    let r = &mut ctx.accounts.local_partner_record;
    r.active = false;
    msg!("revoke_local_partner: partner={}", r.partner);
    Ok(())
}

#[derive(Accounts)]
pub struct RegisterLocalPartner<'info> {
    /// The operator (Config.authority).
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = authority @ TorusError::Unauthorized)]
    pub config: Account<'info, Config>,

    /// The partner to register.
    /// CHECK: only the key is recorded; no signature needed.
    pub partner: UncheckedAccount<'info>,

    /// The partner's own USDC account, where its share is paid.
    #[account(
        constraint = partner_usdc.mint == config.usdc_mint @ TorusError::NonUsdcCollateral,
        constraint = partner_usdc.owner == partner.key() @ TorusError::Unauthorized,
    )]
    pub partner_usdc: InterfaceAccount<'info, TokenAccount>,

    #[account(
        init,
        payer = authority,
        space = 8 + LocalPartnerRecord::INIT_SPACE,
        seeds = [LOCAL_PARTNER_SEED, partner.key().as_ref()],
        bump,
    )]
    pub local_partner_record: Account<'info, LocalPartnerRecord>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokeLocalPartner<'info> {
    /// The operator (Config.authority).
    pub authority: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = authority @ TorusError::Unauthorized)]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [LOCAL_PARTNER_SEED, local_partner_record.partner.as_ref()],
        bump = local_partner_record.bump,
    )]
    pub local_partner_record: Account<'info, LocalPartnerRecord>,
}
