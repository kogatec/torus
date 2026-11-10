//! revoke_partner: revokes an exchange partner's registration (Config.authority only).
//!
//! When a partner loses its license or its key is compromised, the operator revokes it. A revoked partner
//!   - cannot convert fees (convert_fees)
//!   - cannot approve payments from an issuer escrow it manages (approve_withdrawal)
//!   - cannot be picked as an escrow partner; an issuer whose partner was revoked may pick another one even during a
//!     campaign (set_escrow_partner)
//! Revocation is permanent (a partner with a new key registers again).

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{Config, PartnerRecord};

pub fn handler(ctx: Context<RevokePartner>) -> Result<()> {
    let record = &mut ctx.accounts.partner_record;
    require!(record.active, TorusError::PartnerRevoked);
    record.active = false;
    msg!("revoke_partner: partner={}", record.partner);
    Ok(())
}

#[derive(Accounts)]
pub struct RevokePartner<'info> {
    /// The operator (Config.authority).
    pub authority: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = authority @ TorusError::Unauthorized,
    )]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [PARTNER_SEED, partner_record.partner.as_ref()],
        bump = partner_record.bump,
    )]
    pub partner_record: Account<'info, PartnerRecord>,
}
