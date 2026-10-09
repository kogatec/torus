//! issue_token: registers a brand token.
//!
//! Registers the company's Token-2022 mint (with TransferFee and TransferHook) and creates its TokenState and the
//! PDA-owned USDC accounts (first account = redemption pool, second account = bond, plus the issuer escrow).
//! The issuer does not set the bond (a zero or tiny bond would mean no penalty for fraud). Until the operator sets
//! it with set_issuer_terms, no deposit, conversion or redemption can start.
//!
//! [Design] The Token-2022 mint (with its extensions) is created client-side (@solana/spl-token) and passed in.
//! This instruction parses the mint on-chain and registers it only if no issuer key can change the rules:
//!   - the TransferHook points to config.hook_program and its authority is revoked
//!   - the TransferFee is non-zero, matches the declared rate, is constant, and its config authority is revoked
//!   - withheld fees can only be withdrawn by the protocol PDA; no freeze authority; only allowed extensions
//! USDC is a classic SPL token, so the pool accounts use `usdc_token_program`
//! (a different program from the brand token's Token-2022).

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};
use anchor_spl::token_2022::spl_token_2022::{
    extension::{
        transfer_fee::TransferFeeConfig, transfer_hook::TransferHook, BaseStateWithExtensions,
        ExtensionType, StateWithExtensions,
    },
    state::Mint as Token2022Mint,
};

use anchor_lang::solana_program::program_option::COption;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{Config, TokenState};

pub fn handler(
    ctx: Context<IssueToken>,
    transfer_fee_bps: u16,
    max_fee: u64,
) -> Result<()> {
    let config = &ctx.accounts.config;
    require_keys_eq!(
        ctx.accounts.usdc_mint.key(),
        config.usdc_mint,
        TorusError::NonUsdcCollateral
    );

    // (a0) The issuer must be the mint authority. Otherwise anyone could register someone else's mint built for
    //      Torus first and control its manifest (auditor, thresholds).
    require!(
        ctx.accounts.mint.mint_authority == COption::Some(ctx.accounts.issuer.key()),
        TorusError::MintAuthorityNotIssuer
    );
    // (a0) No freeze authority. Otherwise the issuer could freeze the fee vault or holders' accounts and put its key
    //      on the collection, payout and transfer paths.
    require!(
        ctx.accounts.mint.freeze_authority.is_none(),
        TorusError::FreezeAuthorityPresent
    );

    // Verify on-chain that the Torus design is burned into the mint:
    //   - a TransferHook extension exists and its program_id is config.hook_program
    //   - a TransferFee extension exists (fees fund the pool)
    // Mints that do not qualify are rejected.
    {
        let mint_ai = ctx.accounts.mint.to_account_info();
        let data = mint_ai.try_borrow_data()?;
        let mint_state = StateWithExtensions::<Token2022Mint>::unpack(&data)
            .map_err(|_| error!(TorusError::MissingTransferHook))?;

        // (a1) Only allowed extensions (an allow-list: unknown extensions are rejected too).
        //      PermanentDelegate can move tokens out of any account including fee_vault, Pausable can stop all transfers,
        //      ConfidentialTransfer hides amounts and breaks the hook's metering and the fee cross-check. Each would put
        //      an issuer key back on the money path, so they are rejected.
        let extension_types = mint_state
            .get_extension_types()
            .map_err(|_| error!(TorusError::DisallowedMintExtension))?;
        for ext in extension_types.iter() {
            require!(
                matches!(
                    ext,
                    ExtensionType::TransferFeeConfig
                        | ExtensionType::TransferHook
                        | ExtensionType::MetadataPointer
                        | ExtensionType::TokenMetadata
                ),
                TorusError::DisallowedMintExtension
            );
        }

        let hook = mint_state
            .get_extension::<TransferHook>()
            .map_err(|_| error!(TorusError::MissingTransferHook))?;
        let hook_pid: Option<Pubkey> = hook.program_id.into();
        require!(
            hook_pid == Some(config.hook_program),
            TorusError::HookProgramMismatch
        );

        // (a3) The hook authority must be **irreversibly revoked**. Otherwise the issuer could swap the hook for a
        //      harmless program after registration and the mechanism would no longer be part of the token.
        let hook_auth: Option<Pubkey> = hook.authority.into();
        require!(hook_auth.is_none(), TorusError::HookAuthorityNotRevoked);

        let fee_cfg = mint_state
            .get_extension::<TransferFeeConfig>()
            .map_err(|_| error!(TorusError::MissingTransferFee))?;

        // (a3) The fee config authority must be irreversibly revoked as well (the fee cannot be zeroed later).
        let fee_auth: Option<Pubkey> = fee_cfg.transfer_fee_config_authority.into();
        require!(fee_auth.is_none(), TorusError::FeeAuthorityNotRevoked);

        // (a2) The fee rate is non-zero and equals the declared rate.
        let bps: u16 = fee_cfg.newer_transfer_fee.transfer_fee_basis_points.into();
        let mfee: u64 = fee_cfg.newer_transfer_fee.maximum_fee.into();
        require!(
            bps > 0 && bps == transfer_fee_bps && mfee == max_fee,
            TorusError::InvalidTransferFeeRate
        );
        // (a2) The fee schedule is constant. Token-2022 keeps an older config and a newer one that applies from a given
        //      epoch. Setting older to 0 and only a far-future newer config to the declared rate, then revoking, would pass
        //      the checks above while no fee is actually taken. Both must match.
        require!(
            fee_cfg.older_transfer_fee.transfer_fee_basis_points
                == fee_cfg.newer_transfer_fee.transfer_fee_basis_points
                && fee_cfg.older_transfer_fee.maximum_fee == fee_cfg.newer_transfer_fee.maximum_fee,
            TorusError::FeeScheduleNotConstant
        );

        // (a4) The withheld-fee **withdraw authority is the protocol PDA**. A PDA is off the curve and has no private key,
        //      so the collected funds are never under the issuer's control and not depositing them is impossible.
        let ww_auth: Option<Pubkey> = fee_cfg.withdraw_withheld_authority.into();
        require!(
            ww_auth == Some(ctx.accounts.pool_authority.key()),
            TorusError::WithheldAuthorityNotProtocol
        );
    }

    let ts = &mut ctx.accounts.token_state;
    ts.issuer = ctx.accounts.issuer.key();
    ts.mint = ctx.accounts.mint.key();
    ts.usdc_mint = ctx.accounts.usdc_mint.key();

    ts.tier = 0;
    ts.consecutive_passes = 0;
    ts.distribution_ratio_bps = TIER_DISTRIBUTION_BPS[0];

    ts.prior_period_activity = 0;
    ts.current_period_activity = 0;
    ts.period_id = 0;
    ts.period_start_ts = Clock::get()?.unix_timestamp;

    ts.budget = 0;
    ts.bond_target = 0; // set by the operator with set_issuer_terms.
    ts.redemption_started = false;
    ts.frozen = false;

    ts.pool_authority_bump = ctx.bumps.pool_authority;
    ts.redemption_vault = ctx.accounts.redemption_vault.key();
    ts.slashing_bond = ctx.accounts.slashing_bond.key();
    ts.fee_vault = ctx.accounts.fee_vault.key();

    ts.manifest = Pubkey::default(); // unset until set_manifest.
    ts.bump = ctx.bumps.token_state;

    // Fee rate used by the fee cross-check (already checked against the mint above).
    ts.transfer_fee_bps = transfer_fee_bps;
    ts.audit_deadline = 0;

    ts.min_conversion_price = 0; // set by the operator with set_issuer_terms.
    ts.issuer_escrow = ctx.accounts.issuer_escrow.key();
    ts.issuer_accruing = 0;
    ts.issuer_pending = 0;
    ts.issuer_claimable = 0;
    ts.reserved = 0;

    msg!(
        "issue_token: mint={} issuer={} (USDC pool initialized; bond target is set by the operator)",
        ts.mint,
        ts.issuer
    );
    Ok(())
}

#[derive(Accounts)]
pub struct IssueToken<'info> {
    /// The issuer, payer.
    #[account(mut)]
    pub issuer: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    /// The Token-2022 mint created client-side (with TransferFee and TransferHook).
    /// Its extensions are verified in the handler.
    pub mint: InterfaceAccount<'info, Mint>,

    /// Pool currency (USDC).
    pub usdc_mint: InterfaceAccount<'info, Mint>,

    #[account(
        init,
        payer = issuer,
        space = 8 + TokenState::INIT_SPACE,
        seeds = [TOKEN_STATE_SEED, mint.key().as_ref()],
        bump,
    )]
    pub token_state: Account<'info, TokenState>,

    /// Pool PDA (authority of the pool accounts).
    /// CHECK: bound by seeds; holds no data, only signs.
    #[account(
        seeds = [POOL_AUTHORITY_SEED, mint.key().as_ref()],
        bump,
    )]
    pub pool_authority: UncheckedAccount<'info>,

    /// First account: redemption pool (USDC).
    #[account(
        init,
        payer = issuer,
        seeds = [REDEMPTION_VAULT_SEED, mint.key().as_ref()],
        bump,
        token::mint = usdc_mint,
        token::authority = pool_authority,
        token::token_program = usdc_token_program,
    )]
    pub redemption_vault: InterfaceAccount<'info, TokenAccount>,

    /// Second account: slashing bond (USDC).
    #[account(
        init,
        payer = issuer,
        seeds = [SLASHING_BOND_SEED, mint.key().as_ref()],
        bump,
        token::mint = usdc_mint,
        token::authority = pool_authority,
        token::token_program = usdc_token_program,
    )]
    pub slashing_bond: InterfaceAccount<'info, TokenAccount>,

    /// Issuer escrow (USDC). The issuer cannot withdraw until the audit finalizes without fraud.
    #[account(
        init,
        payer = issuer,
        seeds = [ISSUER_ESCROW_SEED, mint.key().as_ref()],
        bump,
        token::mint = usdc_mint,
        token::authority = pool_authority,
        token::token_program = usdc_token_program,
    )]
    pub issuer_escrow: InterfaceAccount<'info, TokenAccount>,

    /// Where collected fees (brand token) are swept. PDA-owned, no issuer key involved.
    /// `withdraw_withheld_authority` was checked to be pool_authority above.
    #[account(
        init,
        payer = issuer,
        seeds = [FEE_VAULT_SEED, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = pool_authority,
        token::token_program = token_2022_program,
    )]
    pub fee_vault: InterfaceAccount<'info, TokenAccount>,

    /// Token program of the brand token (Token-2022).
    pub token_2022_program: Interface<'info, TokenInterface>,
    /// Token program of USDC (classic SPL).
    pub usdc_token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}
