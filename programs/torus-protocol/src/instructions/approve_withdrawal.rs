//! approve_withdrawal: the escrow partner or the manifest's auditor approves a withdrawal request.
//!
//! The request runs when both the token's current escrow partner and the manifest's current auditor have approved it:
//! the instruction carrying the second approval pays the payee straight from the escrow (signed by the pool_authority
//! PDA) and lowers the released balance, or, for a request on the bond, straight from the bond. Nobody else can
//! approve: not the operator (Config.authority), not the issuer. At that moment the amount must still be within the
//! released balance (or leave half of the bond target in the bond) and the payee must not belong to the issuer.
//! An approval by a partner or auditor that has since been replaced does not count (the new one approves instead).

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::request_withdrawal::bond_floor;
use crate::state::{AuditorRecord, Config, Manifest, PartnerRecord, TokenState, WithdrawalRequest};

pub fn handler(ctx: Context<ApproveWithdrawal>) -> Result<()> {
    let approver = ctx.accounts.approver.key();
    let partner = ctx.accounts.token_state.escrow_partner;
    let auditor = ctx.accounts.manifest.auditor;
    {
        let ts = &ctx.accounts.token_state;
        require!(!ts.frozen, TorusError::TokenFrozen);
        require!(!ts.exited, TorusError::TokenExited);
        // Never the operator or the issuer, and the two approvals come from different keys.
        require!(
            approver != ctx.accounts.config.authority && approver != ts.issuer,
            TorusError::NotAnApprover
        );
    }
    require_keys_neq!(partner, auditor, TorusError::RolesNotSeparate);
    require!(!ctx.accounts.request.executed, TorusError::WithdrawalAlreadyExecuted);
    let partner_active = ctx.accounts.partner_record.active;
    let auditor_active = ctx.accounts.auditor_record.active;

    let request = &mut ctx.accounts.request;
    if approver == partner {
        require!(partner_active, TorusError::PartnerRevoked);
        request.partner_approval = approver;
    } else if approver == auditor {
        require!(auditor_active, TorusError::AuditorRevoked);
        request.auditor_approval = approver;
    } else {
        return err!(TorusError::NotAnApprover);
    }

    // Runs only once both the current partner and the current auditor have approved.
    if request.partner_approval != partner || request.auditor_approval != auditor {
        msg!("approve_withdrawal: approved by {} (waiting for the other approval)", approver);
        return Ok(());
    }
    let amount = request.amount;
    let ts = &mut ctx.accounts.token_state;
    require_keys_neq!(ctx.accounts.payee.owner, ts.issuer, TorusError::PayeeIsIssuer);
    let source = if request.from_bond {
        // The bond keeps at least half of its target; the issuer's share of later fees refills it first.
        require!(
            ctx.accounts.slashing_bond.amount.saturating_sub(bond_floor(ts.bond_target)) >= amount,
            TorusError::BondUseExceedsLimit
        );
        ctx.accounts.slashing_bond.to_account_info()
    } else {
        require!(amount <= ts.issuer_claimable, TorusError::WithdrawalExceedsReleased);
        ts.issuer_claimable -= amount;
        ctx.accounts.issuer_escrow.to_account_info()
    };
    request.executed = true;

    let mint_key = ts.mint;
    let seeds: &[&[u8]] = &[POOL_AUTHORITY_SEED, mint_key.as_ref(), &[ts.pool_authority_bump]];
    token_interface::transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.usdc_token_program.to_account_info(),
            TransferChecked {
                from: source,
                mint: ctx.accounts.usdc_mint.to_account_info(),
                to: ctx.accounts.payee.to_account_info(),
                authority: ctx.accounts.pool_authority.to_account_info(),
            },
            &[seeds],
        ),
        amount,
        ctx.accounts.usdc_mint.decimals,
    )?;

    msg!(
        "approve_withdrawal: mint={} paid {} to {} (item {}, from_bond={}), released left {}",
        mint_key,
        amount,
        request.payee,
        request.plan_item,
        request.from_bond,
        ts.issuer_claimable
    );
    Ok(())
}

#[derive(Accounts)]
pub struct ApproveWithdrawal<'info> {
    /// The escrow partner or the manifest's auditor.
    pub approver: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
    )]
    pub token_state: Box<Account<'info, TokenState>>,

    #[account(
        seeds = [MANIFEST_SEED, token_state.mint.as_ref()],
        bump = manifest.bump,
        constraint = manifest.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub manifest: Box<Account<'info, Manifest>>,

    #[account(
        mut,
        seeds = [WITHDRAWAL_SEED, token_state.mint.as_ref(), request.invoice_hash.as_ref()],
        bump = request.bump,
        constraint = request.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub request: Box<Account<'info, WithdrawalRequest>>,

    /// Registry record of the token's escrow partner (must be active for its approval and for the payment).
    #[account(
        seeds = [PARTNER_SEED, token_state.escrow_partner.as_ref()],
        bump = partner_record.bump,
    )]
    pub partner_record: Box<Account<'info, PartnerRecord>>,

    /// Registry record of the manifest's auditor (must be active for its approval and for the payment).
    #[account(
        seeds = [AUDITOR_SEED, manifest.auditor.as_ref()],
        bump = auditor_record.bump,
    )]
    pub auditor_record: Box<Account<'info, AuditorRecord>>,

    /// Pool PDA (authority of the escrow).
    /// CHECK: bound by seeds; signs as a program-derived address.
    #[account(
        seeds = [POOL_AUTHORITY_SEED, token_state.mint.as_ref()],
        bump = token_state.pool_authority_bump,
    )]
    pub pool_authority: UncheckedAccount<'info>,

    #[account(mut, address = token_state.issuer_escrow @ TorusError::Unauthorized)]
    pub issuer_escrow: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Second account (the bond), the source of a request on the bond.
    #[account(mut, address = token_state.slashing_bond @ TorusError::Unauthorized)]
    pub slashing_bond: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The payee named in the request.
    #[account(mut, address = request.payee @ TorusError::Unauthorized)]
    pub payee: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(address = token_state.usdc_mint @ TorusError::NonUsdcCollateral)]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    pub usdc_token_program: Interface<'info, TokenInterface>,
}
