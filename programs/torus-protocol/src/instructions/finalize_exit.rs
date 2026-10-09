//! finalize_exit: finalizes a voluntary exit (anyone can crank it).
//!
//! [Conditions]
//!   - the issuer requested the exit (request_exit) and the token is not frozen (a forced exit for a violation)
//!   - if metering started: at least one provision after the request (the requested period's volume is
//!     provisioned) and that obligation's audit is final (a period with budget 0 has no audit)
//!
//! [Bond] On a voluntary exit, EXIT_ISSUER_SHARE_BPS (half) of the bond goes back to the issuer and the rest to
//!   the operator treasury (Config.treasury). On a forced exit for a violation the whole bond is slashed
//!   (finalize_audit / declare_default).
//!
//! [Issuer share] After the final audit, the shares left in the escrow (pending, accruing) become claimable
//!   (through claim_distribution).
//!
//! [After the exit] No provision, conversion, deposit or commitment (TokenExited). Payouts of finalized audits
//!   and claims of the issuer share continue. Only the pool_authority PDA signs.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::provision_budget::mul_bps;
use crate::state::{AuditCycle, Config, TokenState};

pub fn handler(ctx: Context<FinalizeExit>) -> Result<()> {
    {
        let ts = &ctx.accounts.token_state;
        require!(!ts.frozen, TorusError::TokenFrozen);
        require!(!ts.exited, TorusError::TokenExited);
        require!(ts.exit_requested, TorusError::ExitNotRequested);
        if ts.periods_started {
            // The requested period's volume has been provisioned (a period closed after the request).
            require!(ts.period_id > ts.exit_request_period, TorusError::ExitNotReady);
            // That obligation's audit is final. A period with budget 0 has no audit.
            if ts.budget > 0 {
                let audit = ctx.accounts.audit.as_ref().ok_or(TorusError::ExitNotReady)?;
                let (expected, _) = Pubkey::find_program_address(
                    &[AUDIT_SEED, ts.mint.as_ref(), ts.period_id.to_le_bytes().as_ref()],
                    ctx.program_id,
                );
                require_keys_eq!(audit.key(), expected, TorusError::ExitNotReady);
                require!(
                    audit.stage == AuditStage::Finalized as u8,
                    TorusError::ExitNotReady
                );
            }
        }
    }

    // ===== Bond: half to the issuer, the rest to the operator treasury =====
    let bond_balance = ctx.accounts.slashing_bond.amount;
    let to_issuer = mul_bps(bond_balance, EXIT_ISSUER_SHARE_BPS)?;
    let to_operator = bond_balance - to_issuer;

    let mint_key = ctx.accounts.token_state.mint;
    let bump = ctx.accounts.token_state.pool_authority_bump;
    let seeds: &[&[u8]] = &[POOL_AUTHORITY_SEED, mint_key.as_ref(), &[bump]];
    let decimals = ctx.accounts.usdc_mint.decimals;
    let legs: [(u64, AccountInfo<'_>); 2] = [
        (to_issuer, ctx.accounts.issuer_usdc.to_account_info()),
        (to_operator, ctx.accounts.treasury.to_account_info()),
    ];
    for (amount, to) in legs.into_iter() {
        if amount == 0 {
            continue;
        }
        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.usdc_token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.slashing_bond.to_account_info(),
                    mint: ctx.accounts.usdc_mint.to_account_info(),
                    to,
                    authority: ctx.accounts.pool_authority.to_account_info(),
                },
                &[seeds],
            ),
            amount,
            decimals,
        )?;
    }

    // ===== Issuer share: claimable after the final audit =====
    let ts = &mut ctx.accounts.token_state;
    ts.issuer_claimable = ts
        .issuer_claimable
        .checked_add(ts.issuer_pending)
        .and_then(|v| v.checked_add(ts.issuer_accruing))
        .ok_or(TorusError::MathOverflow)?;
    ts.issuer_pending = 0;
    ts.issuer_accruing = 0;
    ts.exited = true;

    msg!(
        "finalize_exit: mint={} bond={} to_issuer={} to_operator={} issuer_claimable={}",
        mint_key,
        bond_balance,
        to_issuer,
        to_operator,
        ts.issuer_claimable
    );
    Ok(())
}

#[derive(Accounts)]
pub struct FinalizeExit<'info> {
    /// Anyone may crank this (pays the transaction fee).
    pub crank: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
    )]
    pub token_state: Box<Account<'info, TokenState>>,

    /// Audit cycle of the current period (token_state.period_id). Required (and must be Finalized) if metering
    /// started and the current budget > 0. The handler checks its address against the PDA.
    pub audit: Option<Box<Account<'info, AuditCycle>>>,

    /// Pool PDA (authority of the bond).
    /// CHECK: bound by seeds; signs as a program-derived address.
    #[account(
        seeds = [POOL_AUTHORITY_SEED, token_state.mint.as_ref()],
        bump = token_state.pool_authority_bump,
    )]
    pub pool_authority: UncheckedAccount<'info>,

    /// Second account (the bond).
    #[account(mut, address = token_state.slashing_bond @ TorusError::Unauthorized)]
    pub slashing_bond: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Refund destination: a USDC account owned by the issuer.
    #[account(
        mut,
        token::mint = usdc_mint,
        constraint = issuer_usdc.owner == token_state.issuer @ TorusError::Unauthorized,
    )]
    pub issuer_usdc: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Operator treasury (fixed in Config).
    #[account(mut, address = config.treasury @ TorusError::Unauthorized)]
    pub treasury: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(address = token_state.usdc_mint @ TorusError::NonUsdcCollateral)]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    pub usdc_token_program: Interface<'info, TokenInterface>,
}
