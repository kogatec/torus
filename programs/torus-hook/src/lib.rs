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
//!   3. **Registered accounts (perks)**: keeps each registered account's `HolderRecord` (stamp = balance-weighted
//!      average acquisition time, lowest balance of the period, volume sent per period) and the volume sent by all
//!      registered accounts. Kept here rather than in torus-protocol: calling the core program on every transfer could
//!      hit the CPI depth limit when the transfer itself comes from an exchange program. torus-protocol writes a record
//!      only on registration and restamp, through `init_holder` / `set_stamp`, signed by its pool PDA.
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
/// First seed of torus-protocol's pool PDA ([pool_authority, mint]); only the core program can sign for it.
pub const POOL_AUTHORITY_SEED: &[u8] = b"pool_authority";
/// HolderRecord PDA of a registered token account (seeds = [holder, token account]).
pub const HOLDER_SEED: &[u8] = b"holder";

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
    ///   idx 8: HolderRecord PDA of the source account (seeds = [b"holder", source]; WRITABLE, exists if registered)
    ///   idx 9: HolderRecord PDA of the destination account (seeds = [b"holder", destination]; WRITABLE, likewise)
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
            // idx 8 / 9: HolderRecord PDAs of the source (idx 0) and destination (idx 2) accounts. WRITABLE.
            ExtraAccountMeta::new_with_seeds(
                &[Seed::Literal { bytes: HOLDER_SEED.to_vec() }, Seed::AccountKey { index: 0 }],
                false,
                true,
            )?,
            ExtraAccountMeta::new_with_seeds(
                &[Seed::Literal { bytes: HOLDER_SEED.to_vec() }, Seed::AccountKey { index: 2 }],
                false,
                true,
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
        vc.registered = PeriodTally::default();

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
        let now = Clock::get()?.unix_timestamp;
        let idx = grid_index(now, grid_start, grid_len);

        // ---- 1b. Period grid: on the first transfer after a boundary, record the cumulative volume at the period start ----
        if grid_len > 0 && now >= grid_start {
            let vc = &mut ctx.accounts.volume_counter;
            if vc.snap_count == 0 || idx > vc.last_snap_idx {
                let slot = (vc.snap_count % SNAPSHOT_SLOTS as u64) as usize;
                vc.snap_idx[slot] = idx;
                vc.snap_total[slot] = vc.total;
                vc.snap_count = vc.snap_count.checked_add(1).ok_or(HookError::MathOverflow)?;
                vc.last_snap_idx = idx;
            }
        }

        // ---- 2. Expected fee (for the fee cross-check) ----
        // Token-2022 withholds the fee for this transfer in the recipient account according to the mint's fee config
        // (rate and max_fee cap). The same config and formula (calculate_epoch_fee) accumulate the fee that should have
        // been withheld, per transfer. Self-transfers also pay the fee, so this comes before the volume exclusions.
        // provision_budget compares this total with what harvest_fees actually collected.
        let fee = expected_fee(&ctx.accounts.mint.to_account_info(), amount)?;
        let is_self = ctx.accounts.source_token.owner == ctx.accounts.destination_token.owner;
        let counted = !is_self && ctx.accounts.source_token.key() != fee_vault;

        // ---- 2b. Registered accounts: stamps, the period's lowest balance, volume sent ----
        let moved = Move { amount, fee, idx, now, is_self, counted };
        let registered_sender = update_holders(ctx.accounts, &moved)?;

        let vc = &mut ctx.accounts.volume_counter;
        vc.fee_total = vc
            .fee_total
            .checked_add(fee)
            .ok_or(HookError::MathOverflow)?;
        if registered_sender {
            vc.registered.add(idx, amount);
        }

        // ---- 3. Exclude self-transfers (wash trading) ----
        // If source and destination have the same owner, it is a self-transfer with no economic substance (left hand
        // to right hand) and is not counted as volume. The transfer itself is allowed (accounts may be reorganized
        // legitimately); it is only excluded from volume.
        //
        // This is a **minimal exclusion of related-party transfers**. Broader detection (other wallets under common
        // control, circular transfers, timing patterns) is handled off-chain.
        if is_self {
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
        if !counted {
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

    /// Creates the record of a registered account (torus-protocol's register_holder, signed by its pool PDA).
    /// `stamp_ts` comes from the core program: the balance held at registration starts fully aged (0%).
    pub fn init_holder(ctx: Context<InitHolder>, stamp_ts: i64, period_idx: u64) -> Result<()> {
        let r = &mut ctx.accounts.holder_record;
        r.account = ctx.accounts.token_account.key();
        r.stamp_ts = stamp_ts;
        r.sent = PeriodTally { idx: period_idx, cur: 0, prev: 0 };
        r.min_balance = ctx.accounts.token_account.amount;
        r.bump = ctx.bumps.holder_record;
        Ok(())
    }

    /// Restamps after torus-protocol's restamp burned and re-minted (signed by its pool PDA): the re-minted amount
    /// gets today's stamp, the rest of the balance keeps its stamp.
    pub fn set_stamp(ctx: Context<SetStamp>, reminted: u64, period_idx: u64) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let balance = ctx.accounts.token_account.amount;
        let r = &mut ctx.accounts.holder_record;
        r.enter(period_idx, balance);
        r.min_balance = r.min_balance.min(balance);
        r.stamp_ts = weighted_stamp(balance.saturating_sub(reminted), r.stamp_ts, reminted, now);
        Ok(())
    }
}

/// Index of the period containing `now` on the fixed grid [start + kΔ, start + (k+1)Δ); 0 before metering starts.
pub fn grid_index(now: i64, start: i64, len: i64) -> u64 {
    if len > 0 && now >= start {
        ((now - start) / len) as u64
    } else {
        0
    }
}

/// Balance-weighted average of two stamps.
pub fn weighted_stamp(kept: u64, kept_ts: i64, added: u64, added_ts: i64) -> i64 {
    let total = kept as i128 + added as i128;
    if total == 0 {
        return added_ts;
    }
    ((kept as i128 * kept_ts as i128 + added as i128 * added_ts as i128) / total) as i64
}

/// One transfer as the hook sees it.
struct Move {
    amount: u64,
    fee: u64,
    idx: u64,
    now: i64,
    is_self: bool,
    /// Counted as volume (not a self-transfer, not a conversion out of the fee vault).
    counted: bool,
}

/// Updates the records of registered accounts: the source's lowest balance and volume sent, the destination's stamp
/// (received from others: today's; between one's own accounts: the stamp it had, or the oldest if unregistered).
/// Returns whether a registered account sent volume.
fn update_holders(a: &Execute, m: &Move) -> Result<bool> {
    if a.source_token.key() == a.destination_token.key() {
        return Ok(false);
    }
    let src = load_holder(&a.source_holder)?;
    let src_stamp = src.as_ref().map(|r| r.stamp_ts);
    if let Some(mut r) = src.clone() {
        // Token-2022 calls the hook after moving the balances: the source held `amount` more before.
        r.enter(m.idx, a.source_token.amount.saturating_add(m.amount));
        r.min_balance = r.min_balance.min(a.source_token.amount);
        if m.counted {
            r.sent.add(m.idx, m.amount);
        }
        store_holder(&a.source_holder, &r)?;
    }
    if let Some(mut r) = load_holder(&a.destination_holder)? {
        // The destination received the amount minus the withheld fee.
        let received = m.amount.saturating_sub(m.fee);
        let before = a.destination_token.amount.saturating_sub(received);
        r.enter(m.idx, before);
        let incoming = if m.is_self { src_stamp.unwrap_or(0) } else { m.now };
        r.stamp_ts = weighted_stamp(before, r.stamp_ts, received, incoming);
        store_holder(&a.destination_holder, &r)?;
    }
    Ok(m.counted && src.is_some())
}

/// The record at a HolderRecord address, if the account is registered (this program owns it).
fn load_holder(ai: &AccountInfo) -> Result<Option<HolderRecord>> {
    if ai.owner != &crate::ID || ai.data_is_empty() {
        return Ok(None);
    }
    let data = ai.try_borrow_data()?;
    Ok(Some(HolderRecord::try_deserialize(&mut &data[..])?))
}

fn store_holder(ai: &AccountInfo, r: &HolderRecord) -> Result<()> {
    let mut data = ai.try_borrow_mut_data()?;
    let mut dst: &mut [u8] = &mut data[..];
    r.try_serialize(&mut dst)
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
///   [329..353) registered: PeriodTally ← volume sent by registered accounts, read by open_perk_period.
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
    /// Volume sent by registered accounts per period (the trader perk rate divides the budget by it).
    pub registered: PeriodTally,
}

/// A quantity per period: the current period's and the previous one's.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, InitSpace, PartialEq, Eq, Debug)]
pub struct PeriodTally {
    /// Period of `cur`.
    pub idx: u64,
    pub cur: u64,
    /// Period idx − 1.
    pub prev: u64,
}

impl PeriodTally {
    /// Moves to period `idx` (never back). Returns whether it moved.
    pub fn roll(&mut self, idx: u64) -> bool {
        if idx <= self.idx {
            return false;
        }
        self.prev = if idx == self.idx + 1 { self.cur } else { 0 };
        self.cur = 0;
        self.idx = idx;
        true
    }

    pub fn add(&mut self, idx: u64, v: u64) {
        self.roll(idx);
        self.cur = self.cur.saturating_add(v);
    }

    /// Amount tallied in period `idx`.
    pub fn in_period(&self, idx: u64) -> u64 {
        if idx == self.idx {
            self.cur
        } else if idx + 1 == self.idx {
            self.prev
        } else {
            0
        }
    }
}

/// Record of a registered token account (owned by this hook; created and restamped only by torus-protocol).
#[account]
#[derive(InitSpace)]
pub struct HolderRecord {
    /// The registered token account.
    pub account: Pubkey,
    /// Stamp: balance-weighted average acquisition time (Unix seconds). The hold perk rate falls with its age.
    pub stamp_ts: i64,
    /// Volume sent per period (the trader perk uses the previous period's).
    pub sent: PeriodTally,
    /// Lowest balance during period `sent.idx` (the base of the hold perk).
    pub min_balance: u64,
    pub bump: u8,
}

impl HolderRecord {
    /// Moves the record into period `idx`; `opening` is the balance when it began.
    pub fn enter(&mut self, idx: u64, opening: u64) {
        if self.sent.roll(idx) {
            self.min_balance = opening;
        }
    }

    /// Lowest balance in period `idx`: the recorded one, or `balance` if nothing moved since the period began.
    pub fn min_balance_in(&self, idx: u64, balance: u64) -> u64 {
        match idx.cmp(&self.sent.idx) {
            core::cmp::Ordering::Equal => self.min_balance,
            core::cmp::Ordering::Greater => balance,
            core::cmp::Ordering::Less => 0,
        }
    }
}

/// Creating a HolderRecord: only torus-protocol's pool PDA for this mint can sign.
#[derive(Accounts)]
pub struct InitHolder<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// torus-protocol's pool PDA for this mint.
    #[account(seeds = [POOL_AUTHORITY_SEED, mint.key().as_ref()], bump, seeds::program = TORUS_PROTOCOL_ID)]
    pub protocol_signer: Signer<'info>,

    pub mint: InterfaceAccount<'info, Mint>,

    #[account(token::mint = mint)]
    pub token_account: InterfaceAccount<'info, TokenAccount>,

    #[account(
        init,
        payer = payer,
        space = 8 + HolderRecord::INIT_SPACE,
        seeds = [HOLDER_SEED, token_account.key().as_ref()],
        bump,
    )]
    pub holder_record: Account<'info, HolderRecord>,

    pub system_program: Program<'info, System>,
}

/// Restamping a HolderRecord: only torus-protocol's pool PDA for this mint can sign.
#[derive(Accounts)]
pub struct SetStamp<'info> {
    #[account(seeds = [POOL_AUTHORITY_SEED, mint.key().as_ref()], bump, seeds::program = TORUS_PROTOCOL_ID)]
    pub protocol_signer: Signer<'info>,

    pub mint: InterfaceAccount<'info, Mint>,

    #[account(token::mint = mint)]
    pub token_account: InterfaceAccount<'info, TokenAccount>,

    #[account(mut, seeds = [HOLDER_SEED, token_account.key().as_ref()], bump = holder_record.bump)]
    pub holder_record: Account<'info, HolderRecord>,
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

    /// idx 8: HolderRecord of the source account (exists only if registered; WRITABLE).
    /// CHECK: address bound by seeds; read and written only when this program owns it.
    #[account(mut, seeds = [HOLDER_SEED, source_token.key().as_ref()], bump)]
    pub source_holder: UncheckedAccount<'info>,

    /// idx 9: HolderRecord of the destination account (exists only if registered; WRITABLE).
    /// CHECK: address bound by seeds; read and written only when this program owns it.
    #[account(mut, seeds = [HOLDER_SEED, destination_token.key().as_ref()], bump)]
    pub destination_holder: UncheckedAccount<'info>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record(idx: u64, min_balance: u64) -> HolderRecord {
        HolderRecord {
            account: Pubkey::default(),
            stamp_ts: 0,
            sent: PeriodTally { idx, cur: 0, prev: 0 },
            min_balance,
            bump: 0,
        }
    }

    #[test]
    fn grid_index_counts_whole_periods() {
        assert_eq!(grid_index(100, 100, 10), 0);
        assert_eq!(grid_index(109, 100, 10), 0);
        assert_eq!(grid_index(110, 100, 10), 1);
        assert_eq!(grid_index(99, 100, 10), 0); // before the grid
        assert_eq!(grid_index(1_000, 100, 0), 0); // not metering
    }

    #[test]
    fn tally_keeps_the_previous_period() {
        let mut t = PeriodTally::default();
        t.add(3, 5);
        t.add(3, 7);
        assert_eq!((t.in_period(3), t.in_period(2)), (12, 0));
        t.add(4, 1);
        assert_eq!((t.in_period(4), t.in_period(3)), (1, 12));
        assert_eq!(t.in_period(5), 0);
    }

    #[test]
    fn tally_forgets_after_a_gap_and_never_goes_back() {
        let mut t = PeriodTally { idx: 3, cur: 12, prev: 4 };
        assert!(t.roll(5));
        assert_eq!((t.cur, t.prev), (0, 0));
        assert!(!t.roll(4));
        assert_eq!(t.idx, 5);
    }

    #[test]
    fn previous_period_read_before_the_tally_moves() {
        // Nothing sent yet in period 4: period 3's volume is still `cur`.
        let t = PeriodTally { idx: 3, cur: 9, prev: 2 };
        assert_eq!(t.in_period(3), 9);
        assert_eq!(t.in_period(2), 2);
    }

    #[test]
    fn entering_a_period_resets_the_lowest_balance() {
        let mut r = record(1, 50);
        r.enter(1, 999); // same period: unchanged
        assert_eq!(r.min_balance, 50);
        r.enter(2, 80);
        assert_eq!((r.sent.idx, r.min_balance), (2, 80));
    }

    #[test]
    fn lowest_balance_of_an_untouched_period_is_the_balance() {
        let r = record(2, 30);
        assert_eq!(r.min_balance_in(2, 100), 30);
        assert_eq!(r.min_balance_in(3, 100), 100);
        assert_eq!(r.min_balance_in(1, 100), 0);
    }

    #[test]
    fn stamps_average_by_balance() {
        assert_eq!(weighted_stamp(100, 1_000, 100, 2_000), 1_500);
        assert_eq!(weighted_stamp(300, 1_000, 100, 2_000), 1_250);
        assert_eq!(weighted_stamp(0, 1_000, 100, 2_000), 2_000);
        assert_eq!(weighted_stamp(100, 1_000, 0, 2_000), 1_000);
        assert_eq!(weighted_stamp(0, 1_000, 0, 2_000), 2_000);
    }

    #[test]
    fn stamps_do_not_overflow() {
        let ts = 1_800_000_000;
        assert_eq!(weighted_stamp(u64::MAX, ts, u64::MAX, ts), ts);
        assert_eq!(weighted_stamp(u64::MAX, 0, 1, ts), 0);
    }
}
