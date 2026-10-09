//! declare_default: declares a default after the audit deadline (anyone can crank it).
//!
//! provision_budget only closes the next period once the previous audit is final, so an obligation cannot be
//! skipped. But if the issuer **simply never commits**, the audit itself stalls (and if stalling had no
//! penalty, walking away from the obligation would pay).
//!
//! So once the deadline set at provisioning (TokenState.audit_deadline) has passed and something the issuer must
//! supply is missing (the commitment, the sampled disclosures, or the uniqueness proof), anyone can declare a default.
//! A default is treated as the extreme case of understatement (attack Y): like fraud in finalize_audit, the token
//! drops to the base tier, is frozen, and the whole bond and issuer escrow are slashed.
//!
//! Things that are not the issuer's responsibility (the operator has not drawn the sample, the auditor has not
//! recorded, nobody called finalize) are not a default (DefaultNotDue). If the auditor does not record, the operator
//! replaces it with replace_auditor and the audit continues.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{AuditCycle, Config, TokenState};

pub fn handler(ctx: Context<DeclareDefault>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    {
        let ts = &ctx.accounts.token_state;
        require!(!ts.frozen, TorusError::TokenFrozen);
        // A budget has been provisioned for the current period (there is an audit obligation).
        require!(ts.period_id > 0 && ts.budget > 0, TorusError::DefaultNotDue);
        require!(now > ts.audit_deadline, TorusError::DefaultNotDue);
    }

    // Decide from the current audit cycle account whether this is a default.
    let audit_ai = ctx.accounts.audit.to_account_info();
    let missing_commit = audit_ai.data_is_empty();
    if !missing_commit {
        require_keys_eq!(*audit_ai.owner, crate::ID, TorusError::DefaultNotDue);
        let mut audit = {
            let data = audit_ai.try_borrow_data()?;
            AuditCycle::try_deserialize(&mut &data[..])?
        };
        // What the issuer must supply: the sampled disclosures (after sampling) and the uniqueness proof (all leaves).
        let disclosures_withheld = audit.stage == AuditStage::Sampled as u8
            && audit.verify_cursor < audit.sample_size;
        let uniqueness_missing =
            audit.stage != AuditStage::Finalized as u8 && !audit.uniqueness_verified;
        require!(disclosures_withheld || uniqueness_missing, TorusError::DefaultNotDue);
        audit.stage = AuditStage::Finalized as u8;
        audit.result = AuditResult::FraudUnderstatement as u8;
        let mut data = audit_ai.try_borrow_mut_data()?;
        audit.try_serialize(&mut &mut data[..])?;
    }

    // Same as fraud: immediate drop to the base tier and freeze.
    let token_state = &mut ctx.accounts.token_state;
    token_state.tier = 0;
    token_state.consecutive_passes = 0;
    token_state.frozen = true;
    token_state.distribution_ratio_bps = TIER_DISTRIBUTION_BPS[0];

    // Slash the whole bond to the compensation pool (fixed in Config).
    let bond_balance = ctx.accounts.slashing_bond.amount;
    if bond_balance > 0 {
        let mint_key = token_state.mint;
        let seeds: &[&[u8]] = &[
            POOL_AUTHORITY_SEED,
            mint_key.as_ref(),
            &[token_state.pool_authority_bump],
        ];
        let signer: &[&[&[u8]]] = &[seeds];
        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.slashing_bond.to_account_info(),
                    mint: ctx.accounts.usdc_mint.to_account_info(),
                    to: ctx.accounts.slash_destination.to_account_info(),
                    authority: ctx.accounts.pool_authority.to_account_info(),
                },
                signer,
            ),
            bond_balance,
            ctx.accounts.usdc_mint.decimals,
        )?;
    }

    // Slash the whole issuer escrow too (same as fraud).
    let escrow_balance = ctx.accounts.issuer_escrow.amount;
    if escrow_balance > 0 {
        let mint_key = token_state.mint;
        let seeds: &[&[u8]] = &[
            POOL_AUTHORITY_SEED,
            mint_key.as_ref(),
            &[token_state.pool_authority_bump],
        ];
        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.issuer_escrow.to_account_info(),
                    mint: ctx.accounts.usdc_mint.to_account_info(),
                    to: ctx.accounts.slash_destination.to_account_info(),
                    authority: ctx.accounts.pool_authority.to_account_info(),
                },
                &[seeds],
            ),
            escrow_balance,
            ctx.accounts.usdc_mint.decimals,
        )?;
    }
    token_state.issuer_accruing = 0;
    token_state.issuer_pending = 0;
    token_state.issuer_claimable = 0;
    // Nobody can claim against a defaulted period, so release this period's reservation.
    token_state.reserved = token_state.reserved.saturating_sub(token_state.budget);

    msg!(
        "declare_default: mint={} period_id={} missing_commit={} slashed={}",
        token_state.mint,
        token_state.period_id,
        missing_commit,
        bond_balance
    );
    Ok(())
}

#[derive(Accounts)]
pub struct DeclareDefault<'info> {
    /// Anyone may crank this (pays the transaction fee).
    #[account(mut)]
    pub crank: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
    )]
    pub token_state: Account<'info, TokenState>,

    /// Audit cycle PDA of the current period (token_state.period_id). Does not exist if nothing was committed.
    /// CHECK: address bound by seeds; if it exists, the handler checks the owner before reading it.
    #[account(
        mut,
        seeds = [AUDIT_SEED, token_state.mint.as_ref(), token_state.period_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub audit: UncheckedAccount<'info>,

    /// Pool PDA (authority of the redemption pool and the bond).
    /// CHECK: bound by seeds; signs as a program-derived address.
    #[account(
        seeds = [POOL_AUTHORITY_SEED, token_state.mint.as_ref()],
        bump = token_state.pool_authority_bump,
    )]
    pub pool_authority: UncheckedAccount<'info>,

    /// Second account (slashing bond), USDC.
    #[account(
        mut,
        address = token_state.slashing_bond @ TorusError::Unauthorized,
    )]
    pub slashing_bond: InterfaceAccount<'info, TokenAccount>,

    /// Issuer escrow (USDC). Slashed on default.
    #[account(
        mut,
        address = token_state.issuer_escrow @ TorusError::Unauthorized,
    )]
    pub issuer_escrow: InterfaceAccount<'info, TokenAccount>,

    /// Slash destination: the compensation pool fixed in Config (USDC). The caller cannot change it.
    #[account(
        mut,
        address = config.slash_destination @ TorusError::Unauthorized,
    )]
    pub slash_destination: InterfaceAccount<'info, TokenAccount>,

    #[account(address = token_state.usdc_mint @ TorusError::NonUsdcCollateral)]
    pub usdc_mint: InterfaceAccount<'info, Mint>,

    pub token_program: Interface<'info, TokenInterface>,
}
