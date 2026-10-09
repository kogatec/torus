//! Torus transfer hook program (implements the Token-2022 Transfer Hook Interface).
//!
//! Roles:
//!   1. **Enforcement (block while frozen)**: if torus-protocol's `TokenState.frozen == true` (set by
//!      `finalize_audit` or `declare_default` after fraud or a default), transfers of the mint are rejected
//!      **at the token-program level**. Token-2022 calls this hook for every transfer, including ones outside
//!      the company's own venue (other wallets, DEXs), so the mechanism cannot be bypassed.
//!   2. **Volume metering**: adds the transfer amount to `VolumeCounter.total` (cumulative, monotonic), the
//!      value torus-protocol's `provision_budget` reads as the period's on-chain activity. It also records the
//!      cumulative volume at period boundaries and accumulates the expected fee per transfer.
//!
//! Built and tested on a local validator (`anchor test`). The program id is the local test key.
//! ⚠️ When deploying with other keys, run `anchor keys sync` **and set `TORUS_PROTOCOL_ID` below to
//!    torus-protocol's declare_id! by hand** (keys sync does not update this constant; a mismatch derives the
//!    TokenState PDA at a different address in Execute and disables the freeze check).

use anchor_lang::prelude::*;
use anchor_lang::system_program::{create_account, CreateAccount};
use anchor_spl::token_interface::{Mint, TokenAccount};
use anchor_spl::token_2022::spl_token_2022::{
    extension::{
        transfer_fee::TransferFeeConfig, transfer_hook::TransferHookAccount, BaseStateWithExtensions,
        StateWithExtensions,
    },
    state::{Account as Token2022Account, Mint as Token2022Mint},
};
use spl_tlv_account_resolution::{
    account::ExtraAccountMeta, seeds::Seed, state::ExtraAccountMetaList,
};
use spl_transfer_hook_interface::instruction::{ExecuteInstruction, TransferHookInstruction};

declare_id!("9LtyE8m84qUm9qeyLSLzTJUC3cUXNvL2HVp9ctqdi21a");

/// Program ID of torus-protocol (the core program).
/// The TokenState PDA (seeds = [b"token_state", mint]) is **owned by that program**, a different program from
/// this hook, so registering it in the ExtraAccountMetaList and checking its address in Execute must use the
/// core program's id.
///
/// After `anchor keys sync`, update this **by hand** to torus-protocol's key
///   (keys sync does not update it; it must equal declare_id! in torus-protocol/src/lib.rs).
pub const TORUS_PROTOCOL_ID: Pubkey = pubkey!("6n1Nme9H1aUoXY2P2RaHBVWKAHHyEVPjx9n8WdU8oGdR");

// ============================================================================
//  Byte offsets for reading TokenState by hand (following torus-protocol/src/state.rs)
// ----------------------------------------------------------------------------
//  Anchor account layout (8-byte discriminator first):
//    [0..8)    discriminator            (8)
//    [8..40)   issuer: Pubkey           (32)
//    [40..72)  mint: Pubkey             (32)
//    [72..104) usdc_mint: Pubkey        (32)
//    [104]     tier: u8                 (1)
//    [105]     consecutive_passes: u8   (1)
//    [106..108)distribution_ratio_bps:u16(2)
//    [108..116)prior_period_activity:u64(8)
//    [116..124)current_period_activity:u64(8)
//    [124..132)period_id: u64           (8)
//    [132..140)period_start_ts: i64     (8)
//    [140..148)budget: u64              (8)
//    [148..156)bond_target: u64         (8)
//    [156]     redemption_started: bool (1)
//    [157]     frozen: bool             (1)   ← read by this hook (enforcement)
//    [158]     pool_authority_bump: u8  (1)
//    [159..191)redemption_vault: Pubkey (32)
//    [191..223)slashing_bond: Pubkey    (32)
//    [223..255)manifest: Pubkey         (32)
//    [255]     bump: u8                 (1)
//    [256..288)fee_vault: Pubkey        (32)  ← read by this hook (conversion transfers are not volume)
//    [288..397) cross-check, split and exit fields (not read by this hook)
//    [397..405)grid_start_ts: i64        (8)   ← read by this hook (origin t0 of the period grid)
//    [405..413)grid_period_len: i64      (8)   ← read by this hook (period length Δ; 0 = not metering yet)
//
//  ⚠️ This must match the field order of `TokenState` in state.rs.
//     If state.rs changes, update these offsets too (the freeze check and the period grid depend on them).
// ============================================================================

/// Byte offset of `TokenState.frozen` (bool) = 157.
pub const TOKEN_STATE_FROZEN_OFFSET: usize = 157;
/// Byte offset of `TokenState.fee_vault` (Pubkey) = 256.
pub const TOKEN_STATE_FEE_VAULT_OFFSET: usize = 256;
/// Minimum account data length to read frozen and fee_vault.
pub const TOKEN_STATE_MIN_LEN: usize = TOKEN_STATE_FEE_VAULT_OFFSET + 32;
/// Byte offset of `TokenState.grid_start_ts` (i64) = 397.
pub const TOKEN_STATE_GRID_START_OFFSET: usize = 397;
/// Byte offset of `TokenState.grid_period_len` (i64) = 405.
pub const TOKEN_STATE_GRID_LEN_OFFSET: usize = 405;
/// Data length needed to read the period grid.
pub const TOKEN_STATE_GRID_MIN_LEN: usize = TOKEN_STATE_GRID_LEN_OFFSET + 8;
/// Number of boundary records kept (ring buffer).
pub const SNAPSHOT_SLOTS: usize = 16;

// ---- PDA seeds ----
/// ExtraAccountMetaList PDA (the validation account Token-2022 reads for Execute).
pub const EXTRA_ACCOUNT_METAS_SEED: &[u8] = b"extra-account-metas";
/// Volume counter PDA (owned by this hook).
pub const VOLUME_SEED: &[u8] = b"volume";
/// First seed of the TokenState PDA (owned by torus-protocol).
pub const TOKEN_STATE_SEED: &[u8] = b"token_state";

#[program]
pub mod torus_hook {
    use super::*;

    /// Creates the ExtraAccountMetaList PDA and registers the extra accounts Execute needs.
    ///
    /// Order (resolution index in Execute; 0..=4 are the standard accounts passed by Token-2022):
    ///   idx 0: source token account
    ///   idx 1: mint
    ///   idx 2: destination token account
    ///   idx 3: owner/authority
    ///   idx 4: this ExtraAccountMetaList PDA
    ///   idx 5: torus-protocol program (base program for deriving the external PDA; READONLY)
    ///   idx 6: TokenState PDA (seeds = [b"token_state", mint], owned by torus-protocol; READONLY)
    ///   idx 7: VolumeCounter PDA (seeds = [b"volume", mint], owned by this hook; WRITABLE)
    ///
    /// Also initializes the VolumeCounter (Execute writes to it, so it must exist beforehand).
    pub fn initialize_extra_account_meta_list(
        ctx: Context<InitializeExtraAccountMetaList>,
    ) -> Result<()> {
        // --- Build the metas of the extra accounts passed to Execute ---
        let account_metas = vec![
            // idx 5: torus-protocol program (fixed pubkey),
            //   used as the program for deriving the external PDA (TokenState).
            ExtraAccountMeta::new_with_pubkey(&TORUS_PROTOCOL_ID, false, false)?,
            // idx 6: TokenState PDA (owned by the external program). READONLY.
            //   program_index = 5 refers to the torus-protocol program above;
            //   seeds = [b"token_state", mint] (mint is idx 1).
            ExtraAccountMeta::new_external_pda_with_seeds(
                5,
                &[
                    Seed::Literal {
                        bytes: TOKEN_STATE_SEED.to_vec(),
                    },
                    Seed::AccountKey { index: 1 }, // mint
                ],
                false, // is_signer
                false, // is_writable (READONLY)
            )?,
            // idx 7: VolumeCounter PDA (owned by this hook). WRITABLE.
            //   seeds = [b"volume", mint] (mint is idx 1).
            ExtraAccountMeta::new_with_seeds(
                &[
                    Seed::Literal {
                        bytes: VOLUME_SEED.to_vec(),
                    },
                    Seed::AccountKey { index: 1 }, // mint
                ],
                false, // is_signer
                true,  // is_writable (WRITABLE)
            )?,
        ];

        // --- Create the ExtraAccountMetaList account by CPI (owned by this program) ---
        let account_size = ExtraAccountMetaList::size_of(account_metas.len())? as u64;
        let lamports = Rent::get()?.minimum_balance(account_size as usize);

        let mint = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            EXTRA_ACCOUNT_METAS_SEED,
            mint.as_ref(),
            &[ctx.bumps.extra_account_meta_list],
        ]];

        create_account(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.extra_account_meta_list.to_account_info(),
                },
            )
            .with_signer(signer_seeds),
            lamports,
            account_size,
            ctx.program_id,
        )?;

        // --- Write the extra accounts into the TLV ---
        ExtraAccountMetaList::init::<ExecuteInstruction>(
            &mut ctx.accounts.extra_account_meta_list.try_borrow_mut_data()?,
            &account_metas,
        )?;

        // --- Initialize VolumeCounter (cumulative, monotonic; total = 0, fee_total = 0) ---
        let vc = &mut ctx.accounts.volume_counter;
        vc.mint = mint;
        vc.total = 0;
        vc.bump = ctx.bumps.volume_counter;
        vc.fee_total = 0;
        vc.last_snap_idx = 0;
        vc.snap_count = 0;
        vc.snap_idx = [0; SNAPSHOT_SLOTS];
        vc.snap_total = [0; SNAPSHOT_SLOTS];

        msg!("torus_hook: extra-account-metas + volume counter initialized for mint {}", mint);
        Ok(())
    }

    /// Execute (the transfer-hook entry point).
    /// Token-2022 sends a raw `TransferHookInstruction::Execute`, so the actual dispatch comes from `fallback`
    /// below.
    ///
    /// Steps:
    ///   1. Read `frozen` (offset 157) from TokenState **by hand**; if true, block the transfer.
    ///   1b. If metering has started (grid_period_len > 0), on the first transfer after a period boundary, record the
    ///      cumulative volume just before it as the value at the start of that period (fixed boundaries).
    ///   2. Accumulate the expected fee (self-transfers and conversions included).
    ///   3. Skip volume for self-transfers (source.owner == destination.owner).
    ///   4. Skip volume for transfers out of the fee vault (TokenState.fee_vault, offset 256), i.e. conversions.
    ///   5. Add the amount to VolumeCounter.total (cumulative, monotonic).
    pub fn execute(ctx: Context<Execute>, amount: u64) -> Result<()> {
        // ---- 0. Only inside a real transfer ----
        // During a transfer Token-2022 sets the `transferring` flag of the source/destination TransferHookAccount
        // extensions. Direct calls (no flag) would inflate volume, so they are rejected.
        assert_transferring(&ctx.accounts.source_token.to_account_info())?;
        assert_transferring(&ctx.accounts.destination_token.to_account_info())?;

        // ---- 1. Enforcement: block if frozen ----
        let fee_vault = {
            let data = ctx.accounts.token_state.try_borrow_data()?;
            // The address is checked by the Accounts constraints (seeds + seeds::program).
            // Only the frozen byte is read here (depends on TokenState's field order in state.rs).
            require!(
                data.len() >= TOKEN_STATE_MIN_LEN,
                HookError::TokenStateTooShort
            );
            let frozen = data[TOKEN_STATE_FROZEN_OFFSET] != 0;
            require!(!frozen, HookError::TokenFrozen);
            let fee_vault = Pubkey::try_from(&data[TOKEN_STATE_FEE_VAULT_OFFSET..TOKEN_STATE_FEE_VAULT_OFFSET + 32])
                .map_err(|_| error!(HookError::TokenStateTooShort))?;
            let grid = if data.len() >= TOKEN_STATE_GRID_MIN_LEN {
                let read_i64 = |off: usize| {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&data[off..off + 8]);
                    i64::from_le_bytes(buf)
                };
                (read_i64(TOKEN_STATE_GRID_START_OFFSET), read_i64(TOKEN_STATE_GRID_LEN_OFFSET))
            } else {
                (0, 0)
            };
            (fee_vault, grid)
        };
        let (fee_vault, (grid_start, grid_len)) = fee_vault;

        // ---- 1b. Period grid: on the first transfer after a boundary, record the cumulative volume at the period start ----
        if grid_len > 0 {
            let now = Clock::get()?.unix_timestamp;
            if now >= grid_start {
                let idx = ((now - grid_start) / grid_len) as u64;
                let vc = &mut ctx.accounts.volume_counter;
                if vc.snap_count == 0 || idx > vc.last_snap_idx {
                    let slot = (vc.snap_count % SNAPSHOT_SLOTS as u64) as usize;
                    vc.snap_idx[slot] = idx;
                    vc.snap_total[slot] = vc.total;
                    vc.snap_count = vc.snap_count.checked_add(1).ok_or(HookError::MathOverflow)?;
                    vc.last_snap_idx = idx;
                }
            }
        }

        // ---- 2. Expected fee (for the fee cross-check) ----
        // Token-2022 withholds the fee for this transfer in the recipient account according to the mint's fee config
        // (rate and max_fee cap). The same config and formula (calculate_epoch_fee) accumulate the fee that should have
        // been withheld, per transfer. Self-transfers also pay the fee, so this comes before the volume exclusions.
        // provision_budget compares this total with what harvest_fees actually collected.
        let fee = expected_fee(&ctx.accounts.mint.to_account_info(), amount)?;
        let vc = &mut ctx.accounts.volume_counter;
        vc.fee_total = vc
            .fee_total
            .checked_add(fee)
            .ok_or(HookError::MathOverflow)?;

        // ---- 3. Exclude self-transfers (wash trading) ----
        // If source and destination have the same owner, it is a self-transfer with no economic substance (left hand
        // to right hand) and is not counted as volume. The transfer itself is allowed (accounts may be reorganized
        // legitimately); it is only excluded from volume.
        //
        // This is a **minimal exclusion of related-party transfers**. Broader detection (other wallets under common
        // control, circular transfers, timing patterns) is handled off-chain.
        if ctx.accounts.source_token.owner == ctx.accounts.destination_token.owner {
            msg!(
                "self-transfer: volume not counted (owner={} amount={})",
                ctx.accounts.source_token.owner,
                amount
            );
            return Ok(());
        }

        // ---- 4. Exclude conversion transfers ----
        // Transfers out of the fee vault are partner conversions (convert_fees), not the company's economic activity.
        // Counting them would inflate the next budget with every conversion.
        if ctx.accounts.source_token.key() == fee_vault {
            msg!("fee conversion: volume not counted (amount={})", amount);
            return Ok(());
        }

        // ---- 5. Volume: VolumeCounter.total += amount (monotonic) ----
        vc.total = vc
            .total
            .checked_add(amount)
            .ok_or(HookError::MathOverflow)?;

        Ok(())
    }

    /// Fallback receiving the raw transfer-hook call from Token-2022.
    /// Recognizes `TransferHookInstruction::Execute { amount }` and delegates to `execute`.
    pub fn fallback<'info>(
        program_id: &Pubkey,
        accounts: &'info [AccountInfo<'info>],
        data: &[u8],
    ) -> Result<()> {
        let instruction = TransferHookInstruction::unpack(data)?;
        match instruction {
            TransferHookInstruction::Execute { amount } => {
                let amount_bytes = amount.to_le_bytes();
                __private::__global::execute(program_id, accounts, &amount_bytes)
            }
            // Interface instructions such as InitializeExtraAccountMetaList / Update go through Anchor's generated
            // dispatch (the normal path), so they are rejected here.
            _ => Err(ProgramError::InvalidInstructionData.into()),
        }
    }
}

/// The fee Token-2022 withholds for this transfer (from the mint's TransferFeeConfig and the current epoch).
/// Uses the same `calculate_epoch_fee` as Token-2022, so the max_fee cap matches too.
fn expected_fee(mint_ai: &AccountInfo, amount: u64) -> Result<u64> {
    let data = mint_ai.try_borrow_data()?;
    let mint = StateWithExtensions::<Token2022Mint>::unpack(&data)
        .map_err(|_| error!(HookError::MissingTransferFee))?;
    let cfg = mint
        .get_extension::<TransferFeeConfig>()
        .map_err(|_| error!(HookError::MissingTransferFee))?;
    cfg.calculate_epoch_fee(Clock::get()?.epoch, amount)
        .ok_or(error!(HookError::MathOverflow))
}

/// Checks that a token account is in the "transferring" state.
/// Token-2022 sets `transferring` = true on the source/destination TransferHookAccount extensions when it calls
/// the hook. Without the flag (a direct call outside a transfer) the call is rejected.
fn assert_transferring(ai: &AccountInfo) -> Result<()> {
    let data = ai.try_borrow_data()?;
    let state = StateWithExtensions::<Token2022Account>::unpack(&data)
        .map_err(|_| error!(HookError::NotTransferring))?;
    let ext = state
        .get_extension::<TransferHookAccount>()
        .map_err(|_| error!(HookError::NotTransferring))?;
    require!(bool::from(ext.transferring), HookError::NotTransferring);
    Ok(())
}

/// Volume counter (owned by this hook, one per mint).
///
/// Layout (**read by provision_budget**):
///   [0..8)   discriminator (Anchor)
///   [8..40)  mint: Pubkey
///   [40..48) total: u64  ← cumulative transferred amount, monotonic (LE). Offset 40.
///   [48]     bump: u8
///   [49..57) fee_total: u64  ← cumulative expected fee per transfer (LE). Offset 49.
///   [57..65) last_snap_idx: u64 / [65..73) snap_count: u64
///   [73..201) snap_idx: [u64; 16] / [201..329) snap_total: [u64; 16]
///            ← cumulative volume at the start of each period (ring buffer), read by provision_budget.
///
/// ⚠️ Do not reorder fields. `total` must stay a u64 LE at offset 8+32 = 40;
///    torus-protocol's `provision_budget` reads the period activity at this offset.
#[account]
#[derive(InitSpace)]
pub struct VolumeCounter {
    /// The mint.
    pub mint: Pubkey,
    /// Cumulative transferred amount (monotonic). u64 LE at offset 40.
    pub total: u64,
    pub bump: u8,
    /// Cumulative expected fee per transfer (monotonic, self-transfers included). u64 LE at offset 49.
    pub fee_total: u64,
    /// Index of the most recently recorded period.
    pub last_snap_idx: u64,
    /// Number of records written so far (ring write position = snap_count % 16).
    pub snap_count: u64,
    /// Recorded period indices.
    pub snap_idx: [u64; SNAPSHOT_SLOTS],
    /// Cumulative volume at the start of each recorded period (total just before its first transfer).
    pub snap_total: [u64; SNAPSHOT_SLOTS],
}

#[derive(Accounts)]
pub struct InitializeExtraAccountMetaList<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// ExtraAccountMetaList PDA (read by Token-2022 for Execute).
    /// CHECK: created in this instruction with create_account, owned by this program.
    #[account(
        mut,
        seeds = [EXTRA_ACCOUNT_METAS_SEED, mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: UncheckedAccount<'info>,

    /// The Token-2022 mint (its TransferHook extension points to this program).
    pub mint: InterfaceAccount<'info, Mint>,

    /// Volume counter (owned by this hook). Initialized here because Execute writes to it.
    #[account(
        init,
        payer = payer,
        space = 8 + VolumeCounter::INIT_SPACE,
        seeds = [VOLUME_SEED, mint.key().as_ref()],
        bump,
    )]
    pub volume_counter: Account<'info, VolumeCounter>,

    pub system_program: Program<'info, System>,
    // Anyone may initialize the meta list, as in the standard example. A deployment may require the mint
    // authority here instead.
}

/// Accounts of Execute. 0..=4 are the standard accounts Token-2022 passes in a fixed order; 5..=7 are the extra
/// accounts registered in the ExtraAccountMetaList (resolved in the same order).
#[derive(Accounts)]
pub struct Execute<'info> {
    /// idx 0: source token account.
    /// The transfer authority (idx 3) is not necessarily the owner (delegated transfers exist).
    /// Token-2022 has already checked the authority, so it is not required to match the owner here.
    #[account(token::mint = mint)]
    pub source_token: InterfaceAccount<'info, TokenAccount>,

    /// idx 1: mint.
    pub mint: InterfaceAccount<'info, Mint>,

    /// idx 2: destination token account.
    #[account(token::mint = mint)]
    pub destination_token: InterfaceAccount<'info, TokenAccount>,

    /// idx 3: the source owner, or the delegate of a delegated transfer.
    /// CHECK: the authority passed by Token-2022; no signature check needed in the hook context.
    pub owner: UncheckedAccount<'info>,

    /// idx 4: ExtraAccountMetaList PDA.
    /// CHECK: bound by seeds; read-only.
    #[account(
        seeds = [EXTRA_ACCOUNT_METAS_SEED, mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: UncheckedAccount<'info>,

    /// idx 5: torus-protocol program (base for deriving the external PDA).
    /// CHECK: only checked to equal the known program id.
    #[account(address = TORUS_PROTOCOL_ID)]
    pub torus_protocol_program: UncheckedAccount<'info>,

    /// idx 6: TokenState PDA (owned by torus-protocol, READONLY).
    /// Its address is checked **with the core program's id** through `seeds::program` (deriving it with this hook's
    /// id would give a different address).
    /// CHECK: address bound by seeds + seeds::program; frozen is read by hand in the handler.
    #[account(
        seeds = [TOKEN_STATE_SEED, mint.key().as_ref()],
        bump,
        seeds::program = torus_protocol_program.key(),
    )]
    pub token_state: UncheckedAccount<'info>,

    /// idx 7: VolumeCounter PDA (owned by this hook, WRITABLE).
    #[account(
        mut,
        seeds = [VOLUME_SEED, mint.key().as_ref()],
        bump = volume_counter.bump,
    )]
    pub volume_counter: Account<'info, VolumeCounter>,
    // execute first checks the transferring flag of the source/destination TransferHookAccount and rejects direct
    // calls outside a transfer with HookError::NotTransferring (assert_transferring).
}

#[error_code]
pub enum HookError {
    #[msg("The token is frozen (fraud or default was established); transfers are blocked")]
    TokenFrozen,

    #[msg("TokenState account data is too short (not initialized or wrong layout)")]
    TokenStateTooShort,

    #[msg("Arithmetic overflow (volume counter)")]
    MathOverflow,

    #[msg("Execute called outside a transfer")]
    NotTransferring,

    #[msg("The mint has no TransferFee extension (the expected fee cannot be computed)")]
    MissingTransferFee,
}
