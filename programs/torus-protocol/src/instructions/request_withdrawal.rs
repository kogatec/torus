//! request_withdrawal: the issuer asks to pay from its escrow under the use plan.
//!
//! A request names an item of the use plan (whose hash the manifest records), the amount, the payee's USDC account and
//! the hash of the invoice. It moves nothing by itself: it runs only when the escrow partner and the manifest's auditor
//! have both approved it (approve_withdrawal), and then pays the payee straight from the escrow.
//! The same request can draw on the bond (second account) instead, when the company needs funds: then the bond may
//! go down to half of its target at most, the issuer's share of later fees refills it first (convert_fees), and
//! redemptions keep running in the meantime.
//! Conditions:
//!   - a manifest in force (a campaign) with a use plan;
//!   - the amount is at most the balance released by clean audits (TokenState.issuer_claimable), or, from the bond,
//!     leaves at least half of the bond target in it (and redemptions have started);
//!   - the payee is not the issuer's own account;
//!   - the invoice hash has not been used for this token (the request's address is derived from it).

use anchor_lang::prelude::*;
use anchor_spl::token_interface::TokenAccount;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{Manifest, TokenState, WithdrawalRequest};

/// Least the bond must keep after a payment from it: the bond target minus the usable share (half).
pub(crate) fn bond_floor(bond_target: u64) -> u64 {
    bond_target - ((bond_target as u128) * (BOND_USE_MAX_BPS as u128) / (BPS_DENOMINATOR as u128)) as u64
}

pub fn handler(
    ctx: Context<RequestWithdrawal>,
    plan_item: u16,
    amount: u64,
    invoice_hash: [u8; 32],
    from_bond: bool,
) -> Result<()> {
    let ts = &ctx.accounts.token_state;
    let manifest = &ctx.accounts.manifest;
    require!(!ts.frozen, TorusError::TokenFrozen);
    require!(!ts.exited, TorusError::TokenExited);
    // A manifest in force, with a use plan.
    let now = Clock::get()?.unix_timestamp;
    require!(
        manifest.active && now <= manifest.valid_until,
        TorusError::ManifestExpired
    );
    require!(manifest.use_plan_hash != [0u8; 32], TorusError::UsePlanNotSet);
    if from_bond {
        // From the bond: only after it has reached its target, and down to half of the target at most.
        require!(ts.redemption_started, TorusError::BondTargetNotReached);
        require!(
            amount > 0
                && ctx.accounts.slashing_bond.amount.saturating_sub(bond_floor(ts.bond_target)) >= amount,
            TorusError::BondUseExceedsLimit
        );
    } else {
        // Within the balance released by clean audits.
        require!(
            amount > 0 && amount <= ts.issuer_claimable,
            TorusError::WithdrawalExceedsReleased
        );
    }
    // Not to the issuer itself.
    require_keys_neq!(ctx.accounts.payee.owner, ts.issuer, TorusError::PayeeIsIssuer);

    let request = &mut ctx.accounts.request;
    request.token = ts.mint;
    request.plan_hash = manifest.use_plan_hash;
    request.plan_item = plan_item;
    request.amount = amount;
    request.payee = ctx.accounts.payee.key();
    request.invoice_hash = invoice_hash;
    request.partner_approval = Pubkey::default();
    request.auditor_approval = Pubkey::default();
    request.executed = false;
    request.bump = ctx.bumps.request;
    request.from_bond = from_bond;

    msg!(
        "request_withdrawal: mint={} item={} amount={} payee={} from_bond={}",
        request.token,
        plan_item,
        amount,
        request.payee,
        from_bond
    );
    Ok(())
}

#[derive(Accounts)]
#[instruction(plan_item: u16, amount: u64, invoice_hash: [u8; 32], from_bond: bool)]
pub struct RequestWithdrawal<'info> {
    /// The issuer, payer. Must equal token_state.issuer (has_one).
    #[account(mut)]
    pub issuer: Signer<'info>,

    #[account(
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
        has_one = issuer @ TorusError::Unauthorized,
    )]
    pub token_state: Account<'info, TokenState>,

    #[account(
        seeds = [MANIFEST_SEED, token_state.mint.as_ref()],
        bump = manifest.bump,
        constraint = manifest.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub manifest: Account<'info, Manifest>,

    /// Second account (the bond): its balance limits a request that draws on it.
    #[account(address = token_state.slashing_bond @ TorusError::Unauthorized)]
    pub slashing_bond: InterfaceAccount<'info, TokenAccount>,

    /// The payee's USDC account.
    #[account(constraint = payee.mint == token_state.usdc_mint @ TorusError::NonUsdcCollateral)]
    pub payee: InterfaceAccount<'info, TokenAccount>,

    /// The request, one per invoice hash (a second request with the same invoice fails: the account exists).
    #[account(
        init,
        payer = issuer,
        space = 8 + WithdrawalRequest::INIT_SPACE,
        seeds = [WITHDRAWAL_SEED, token_state.mint.as_ref(), invoice_hash.as_ref()],
        bump,
    )]
    pub request: Account<'info, WithdrawalRequest>,

    pub system_program: Program<'info, System>,
}
