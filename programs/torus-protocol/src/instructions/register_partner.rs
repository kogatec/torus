//! register_partner: adds an exchange partner to the operator's registry
//! (Config.authority only). Only registered partners can buy the collected fee tokens for USDC
//! through convert_fees.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{Config, PartnerRecord};

pub fn handler(ctx: Context<RegisterPartner>) -> Result<()> {
    let record = &mut ctx.accounts.partner_record;
    record.partner = ctx.accounts.partner.key();
    record.active = true;
    record.bump = ctx.bumps.partner_record;
    msg!("register_partner: partner={}", record.partner);
    Ok(())
}

#[derive(Accounts)]
pub struct RegisterPartner<'info> {
    /// The operator (Config.authority).
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = authority @ TorusError::Unauthorized,
    )]
    pub config: Account<'info, Config>,

    /// The partner to register.
    /// CHECK: only the key is recorded in the registry; no signature needed.
    pub partner: UncheckedAccount<'info>,

    #[account(
        init,
        payer = authority,
        space = 8 + PartnerRecord::INIT_SPACE,
        seeds = [PARTNER_SEED, partner.key().as_ref()],
        bump,
    )]
    pub partner_record: Account<'info, PartnerRecord>,

    pub system_program: Program<'info, System>,
}
