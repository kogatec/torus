//! Tax accountant registry (operator): the company's tax accountant or CPA, one per token.
//!
//! The accountant signs its registration with its own key, accepting that a false report is referred to the authority
//! supervising its license (in Japan the Minister of Finance may be asked for discipline under Article 47 of the Certified
//! Public Tax Accountant Act) and releasing its confidentiality for these reports. The signed consent stays off-chain;
//! its hash is recorded. A company without an advisor is introduced to one by its local partner.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{Config, TaxAccountantRecord, TokenState};

pub fn register(ctx: Context<RegisterTaxAccountant>, consent_hash: [u8; 32]) -> Result<()> {
    let r = &mut ctx.accounts.tax_accountant_record;
    r.token = ctx.accounts.token_state.mint;
    r.accountant = ctx.accounts.accountant.key();
    r.consent_hash = consent_hash;
    r.active = true;
    r.bump = ctx.bumps.tax_accountant_record;
    msg!("register_tax_accountant: mint={} accountant={}", r.token, r.accountant);
    Ok(())
}

/// A revoked accountant cannot file. Without a replacement no report comes, which is the company's default at the
/// deadline, so the company has every reason to name a new one.
pub fn revoke(ctx: Context<RevokeTaxAccountant>) -> Result<()> {
    let r = &mut ctx.accounts.tax_accountant_record;
    r.active = false;
    msg!("revoke_tax_accountant: mint={} accountant={}", r.token, r.accountant);
    Ok(())
}

/// The new accountant signs its consent. Reports already filed stay; the new one files the next reports, including a
/// reconciled report for a cycle on hold.
pub fn replace(ctx: Context<ReplaceTaxAccountant>, consent_hash: [u8; 32]) -> Result<()> {
    let r = &mut ctx.accounts.tax_accountant_record;
    r.accountant = ctx.accounts.accountant.key();
    r.consent_hash = consent_hash;
    r.active = true;
    msg!("replace_tax_accountant: mint={} accountant={}", r.token, r.accountant);
    Ok(())
}

#[derive(Accounts)]
pub struct RegisterTaxAccountant<'info> {
    /// The operator (Config.authority).
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = authority @ TorusError::Unauthorized)]
    pub config: Account<'info, Config>,

    #[account(seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()], bump = token_state.bump)]
    pub token_state: Account<'info, TokenState>,

    /// The accountant signs its consent. Never the issuer's key.
    #[account(constraint = accountant.key() != token_state.issuer @ TorusError::Unauthorized)]
    pub accountant: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = 8 + TaxAccountantRecord::INIT_SPACE,
        seeds = [TAX_ACCOUNTANT_SEED, token_state.mint.as_ref()],
        bump,
    )]
    pub tax_accountant_record: Account<'info, TaxAccountantRecord>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokeTaxAccountant<'info> {
    /// The operator (Config.authority).
    pub authority: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = authority @ TorusError::Unauthorized)]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [TAX_ACCOUNTANT_SEED, tax_accountant_record.token.as_ref()],
        bump = tax_accountant_record.bump,
    )]
    pub tax_accountant_record: Account<'info, TaxAccountantRecord>,
}

#[derive(Accounts)]
pub struct ReplaceTaxAccountant<'info> {
    /// The operator (Config.authority).
    pub authority: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = authority @ TorusError::Unauthorized)]
    pub config: Account<'info, Config>,

    #[account(seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()], bump = token_state.bump)]
    pub token_state: Account<'info, TokenState>,

    /// The new accountant signs its consent. Never the issuer's key.
    #[account(constraint = accountant.key() != token_state.issuer @ TorusError::Unauthorized)]
    pub accountant: Signer<'info>,

    #[account(
        mut,
        seeds = [TAX_ACCOUNTANT_SEED, token_state.mint.as_ref()],
        bump = tax_accountant_record.bump,
    )]
    pub tax_accountant_record: Account<'info, TaxAccountantRecord>,
}
