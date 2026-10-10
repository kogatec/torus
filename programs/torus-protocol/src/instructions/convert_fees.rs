//! convert_fees: a registered partner buys collected fee tokens for USDC, and in the same instruction the USDC
//! is split into the operator's share and the issuer's share (bond → redemption pool → escrow): a forced deposit.
//!
//! [Flow] The partner (an exchange operator) pays USDC and receives brand tokens from fee_vault. Both legs happen
//! in one instruction (never one without the other). The USDC goes, in this order:
//!   1. split by the tier's distribution ratio: the operator's share (1 − ratio) → Config.treasury, the rest is
//!      the issuer's share. The operator's fee is never counted as bond.
//!   2. from the issuer's share: the bond first, up to bond_target (set per company by the operator)
//!   3. then the redemption pool, up to what is owed
//!   4. the rest into the issuer escrow (not withdrawable until the audit finalizes without fraud)
//!   owed = reserved (provisioned, unpaid) + the budget the current period's volume will create
//!          (what the next provision_budget will require; the volume and the funds come from the same transfers).
//!          Volume before metering starts (before the bond is full) is not counted.
//!   After an exit there is no obligation: nothing goes to the bond or the pool; the operator's share goes to
//!          Config.treasury and the issuer's share to the escrow, immediately claimable (claim_distribution).
//!
//! [Keys] No issuer signature. The brand tokens leave under the pool_authority PDA's signature and the USDC comes
//!   under the partner's signature straight into the pool accounts. The issuer can neither skip the deposit nor
//!   take its share first.
//!
//! [Price] A purchase below the operator's minimum price (min_conversion_price: USDC per whole brand token) is
//!   rejected (otherwise a partner colluding with the issuer could take the fees for almost nothing and empty the
//!   forced deposit).
//!
//! [Transfer hook] The transfer fee_vault → partner also goes through the transfer hook. The extra accounts it
//!   needs (hook program, ExtraAccountMetaList, torus-protocol, TokenState, VolumeCounter) come in
//!   remaining_accounts. This transfer is not counted as volume (the hook excludes it).

use anchor_lang::prelude::*;
use anchor_spl::token_2022::spl_token_2022::onchain::invoke_transfer_checked;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::provision_budget::{mul_bps, read_volume_counter};
use crate::state::{Config, Manifest, PartnerRecord, TokenState};

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, ConvertFees<'info>>,
    token_amount: u64,
    usdc_amount: u64,
) -> Result<()> {
    let ts = &ctx.accounts.token_state;
    require!(!ts.frozen, TorusError::TokenFrozen);
    require!(
        ts.bond_target > 0 && ts.min_conversion_price > 0,
        TorusError::IssuerTermsNotSet
    );
    require!(
        token_amount > 0 && token_amount <= ctx.accounts.fee_vault.amount,
        TorusError::InvalidConversionAmount
    );

    // ===== Minimum price: usdc_amount / (token_amount / 10^decimals) >= min_conversion_price =====
    let unit = 10u128.pow(ctx.accounts.mint.decimals as u32);
    require!(
        (usdc_amount as u128) * unit >= (token_amount as u128) * (ts.min_conversion_price as u128),
        TorusError::ConversionBelowMinPrice
    );

    // ===== Split =====
    // What the redemption pool must hold = unpaid obligations + the budget the current period's volume will create.
    // Volume before metering starts (before the bond is full) is not counted.
    let accrued_budget = if ts.periods_started && !ts.exited {
        let (counter_total, _) =
            read_volume_counter(&ctx.accounts.volume_counter.to_account_info())?;
        mul_bps(
            counter_total.saturating_sub(ts.current_period_activity),
            ctx.accounts.manifest.return_rate_bps,
        )?
    } else {
        0
    };
    let required = ts
        .reserved
        .checked_add(accrued_budget)
        .and_then(|r| r.checked_add(if ts.exited { 0 } else { ts.unfulfilled }))
        .ok_or(TorusError::MathOverflow)?;

    let bond_balance = ctx.accounts.slashing_bond.amount;
    let vault_balance = ctx.accounts.redemption_vault.amount;

    // 1. Operator share and issuer share (tier ratio). The operator's share never goes into the bond.
    let issuer_side = mul_bps(usdc_amount, ts.distribution_ratio_bps)?;
    let to_operator = usdc_amount - issuer_side;
    // 2. From the issuer's share, the bond first, up to its target (not after an exit)
    let to_bond = if ts.exited {
        0
    } else {
        ts.bond_target.saturating_sub(bond_balance).min(issuer_side)
    };
    let after_bond = issuer_side - to_bond;
    // 3. then the redemption pool up to what is owed, 4. the rest into the escrow
    let to_vault = if ts.exited {
        0
    } else {
        after_bond.min(required.saturating_sub(vault_balance))
    };
    let to_issuer = after_bond - to_vault;

    // ===== USDC: partner → pool accounts (signed by the partner) =====
    let usdc_decimals = ctx.accounts.usdc_mint.decimals;
    let legs: [(u64, AccountInfo<'info>); 4] = [
        (to_bond, ctx.accounts.slashing_bond.to_account_info()),
        (to_vault, ctx.accounts.redemption_vault.to_account_info()),
        (to_operator, ctx.accounts.treasury.to_account_info()),
        (to_issuer, ctx.accounts.issuer_escrow.to_account_info()),
    ];
    for (amount, to) in legs.into_iter() {
        if amount == 0 {
            continue;
        }
        token_interface::transfer_checked(
            CpiContext::new(
                ctx.accounts.usdc_token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.partner_usdc.to_account_info(),
                    mint: ctx.accounts.usdc_mint.to_account_info(),
                    to,
                    authority: ctx.accounts.partner.to_account_info(),
                },
            ),
            amount,
            usdc_decimals,
        )?;
    }

    // ===== Brand token: fee_vault → partner (signed by the pool_authority PDA, through the hook) =====
    let mint_key = ts.mint;
    let seeds: &[&[u8]] = &[
        POOL_AUTHORITY_SEED,
        mint_key.as_ref(),
        &[ts.pool_authority_bump],
    ];
    invoke_transfer_checked(
        &ctx.accounts.token_program.key(),
        ctx.accounts.fee_vault.to_account_info(),
        ctx.accounts.mint.to_account_info(),
        ctx.accounts.partner_token.to_account_info(),
        ctx.accounts.pool_authority.to_account_info(),
        ctx.remaining_accounts,
        token_amount,
        ctx.accounts.mint.decimals,
        &[seeds],
    )?;

    // ===== Bookkeeping =====
    let ts = &mut ctx.accounts.token_state;
    if ts.exited {
        // After an exit there is nothing to audit, so the issuer's share is claimable right away.
        ts.issuer_claimable = ts
            .issuer_claimable
            .checked_add(to_issuer)
            .ok_or(TorusError::MathOverflow)?;
    } else {
        ts.issuer_accruing = ts
            .issuer_accruing
            .checked_add(to_issuer)
            .ok_or(TorusError::MathOverflow)?;
        if bond_balance.saturating_add(to_bond) >= ts.bond_target {
            ts.redemption_started = true;
        }
    }

    msg!(
        "convert_fees: mint={} partner={} tokens={} usdc={} to_bond={} to_vault={} to_operator={} to_issuer={} required={} ratio_bps={}",
        mint_key,
        ctx.accounts.partner.key(),
        token_amount,
        usdc_amount,
        to_bond,
        to_vault,
        to_operator,
        to_issuer,
        required,
        ts.distribution_ratio_bps
    );
    Ok(())
}

#[derive(Accounts)]
pub struct ConvertFees<'info> {
    /// The registered partner (pays USDC, receives the brand tokens).
    #[account(mut)]
    pub partner: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,

    #[account(
        seeds = [PARTNER_SEED, partner.key().as_ref()],
        bump = partner_record.bump,
        constraint = partner_record.active @ TorusError::PartnerNotRegistered,
    )]
    pub partner_record: Box<Account<'info, PartnerRecord>>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
    )]
    pub token_state: Box<Account<'info, TokenState>>,

    /// Used for the expected next budget (volume × return rate).
    #[account(
        seeds = [MANIFEST_SEED, token_state.mint.as_ref()],
        bump = manifest.bump,
        constraint = manifest.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub manifest: Box<Account<'info, Manifest>>,

    /// The hook's volume counter (bound as in provision_budget).
    /// CHECK: bound to the hook-owned PDA by seeds + seeds::program + owner; only total (offset 40) is read.
    #[account(
        seeds = [b"volume", token_state.mint.as_ref()],
        bump,
        seeds::program = config.hook_program,
        owner = config.hook_program @ TorusError::Unauthorized,
    )]
    pub volume_counter: UncheckedAccount<'info>,

    /// The brand token mint.
    #[account(address = token_state.mint @ TorusError::Unauthorized)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    /// The fee vault (brand token).
    #[account(mut, address = token_state.fee_vault @ TorusError::Unauthorized)]
    pub fee_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Pool PDA (authority of fee_vault and the pool accounts).
    /// CHECK: bound by seeds; signs as a program-derived address.
    #[account(
        seeds = [POOL_AUTHORITY_SEED, token_state.mint.as_ref()],
        bump = token_state.pool_authority_bump,
    )]
    pub pool_authority: UncheckedAccount<'info>,

    /// The partner's account receiving the brand tokens.
    #[account(mut, token::mint = mint)]
    pub partner_token: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The partner's USDC account paying for them (authority is the partner, checked by the token program).
    #[account(mut, token::mint = usdc_mint)]
    pub partner_usdc: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(address = token_state.usdc_mint @ TorusError::NonUsdcCollateral)]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    /// Second account (the bond).
    #[account(mut, address = token_state.slashing_bond @ TorusError::Unauthorized)]
    pub slashing_bond: Box<InterfaceAccount<'info, TokenAccount>>,

    /// First account (the redemption pool).
    #[account(mut, address = token_state.redemption_vault @ TorusError::Unauthorized)]
    pub redemption_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The issuer escrow.
    #[account(mut, address = token_state.issuer_escrow @ TorusError::Unauthorized)]
    pub issuer_escrow: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The operator treasury (fixed in Config).
    #[account(mut, address = config.treasury @ TorusError::Unauthorized)]
    pub treasury: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Token program of the brand token: Token-2022.
    #[account(
        constraint = token_program.key() == anchor_spl::token_2022::ID @ TorusError::Unauthorized,
    )]
    pub token_program: Interface<'info, TokenInterface>,

    /// Token program of USDC (classic SPL).
    pub usdc_token_program: Interface<'info, TokenInterface>,
}
