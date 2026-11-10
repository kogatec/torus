//! set_escrow_partner: the issuer picks the registered partner that manages its escrow (one per token).
//!
//! The escrow holds the issuer's share of converted fees. It belongs to the issuer, but the issuer cannot spend it
//! freely (like the endowment of a foundation), and the operator never touches it: a payment runs only with the
//! approval of this partner (a financial institution licensed in its country, in the operator's registry) and of the
//! manifest's auditor (request_withdrawal / approve_withdrawal).
//!   - only the issuer signs; the partner must be registered and active;
//!   - the partner, the auditor and the issuer are different keys, and the partner is not the operator;
//!   - during a campaign the partner cannot be changed, unless its registration was revoked (revoke_partner).

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{Config, Manifest, PartnerRecord, TokenState};

pub fn handler(ctx: Context<SetEscrowPartner>) -> Result<()> {
    let partner = ctx.accounts.partner.key();
    let ts = &ctx.accounts.token_state;
    let manifest = &ctx.accounts.manifest;
    require!(
        partner != ts.issuer && partner != manifest.auditor && partner != ctx.accounts.config.authority,
        TorusError::RolesNotSeparate
    );

    // During a campaign the partner stays, unless the operator revoked it (then its record is shown here).
    let current = ts.escrow_partner;
    let now = Clock::get()?.unix_timestamp;
    if current != Pubkey::default() && current != partner && now <= manifest.valid_until {
        let record = ctx
            .accounts
            .current_partner_record
            .as_ref()
            .ok_or(TorusError::EscrowPartnerLocked)?;
        require!(
            record.partner == current && !record.active,
            TorusError::EscrowPartnerLocked
        );
    }

    ctx.accounts.token_state.escrow_partner = partner;
    msg!(
        "set_escrow_partner: mint={} partner={} previous={}",
        ctx.accounts.token_state.mint,
        partner,
        current
    );
    Ok(())
}

#[derive(Accounts)]
pub struct SetEscrowPartner<'info> {
    /// The issuer. Must equal token_state.issuer (has_one).
    pub issuer: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
        has_one = issuer @ TorusError::Unauthorized,
    )]
    pub token_state: Account<'info, TokenState>,

    /// The manifest (its auditor must differ from the partner; its term decides whether a campaign is running).
    #[account(
        seeds = [MANIFEST_SEED, token_state.mint.as_ref()],
        bump = manifest.bump,
        constraint = manifest.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub manifest: Account<'info, Manifest>,

    /// The partner to pick.
    /// CHECK: registered and active, checked through the registry record below (bound by seeds).
    pub partner: UncheckedAccount<'info>,

    #[account(
        seeds = [PARTNER_SEED, partner.key().as_ref()],
        bump = partner_record.bump,
        constraint = partner_record.active @ TorusError::PartnerNotRegistered,
    )]
    pub partner_record: Account<'info, PartnerRecord>,

    /// Registry record of the current escrow partner: needed only to replace it during a campaign (it must be revoked).
    pub current_partner_record: Option<Account<'info, PartnerRecord>>,
}
