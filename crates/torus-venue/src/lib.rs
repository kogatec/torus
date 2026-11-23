//! Settling a fill of a Törus token from inside a venue program (partner API design §3.7).
//!
//! A partner's venue settles each fill on-chain, straight from the seller's token account to the buyer's, through
//! Token-2022's `transfer_checked` with the Törus transfer hook: the hook counts the volume and the mint's transfer fee is
//! withheld, once per fill. Routing a fill through the venue's own escrow would count both twice.
//!
//! The caller passes the hook's extra accounts as `hook_accounts` (the TypeScript SDK resolves them: the validation
//! account, the protocol program, the token state, the volume counter, the two holder records and the hook program).
//! Token-2022 and the hook check those accounts. This crate checks what a venue must not take on trust:
//!   - the token program is Token-2022 (a venue's PDA must never sign for another program);
//!   - the mint is a Törus token: owned by Token-2022, its transfer hook is the Törus hook the venue pinned, and it has a
//!     transfer fee. A lookalike token whose transfers skip the Törus hook is refused, so its fills are never settled as
//!     Törus trades;
//!   - the fill moves something between two different accounts.

use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError, pubkey::Pubkey};
use spl_token_2022::extension::{transfer_fee::TransferFeeConfig, transfer_hook::TransferHook, BaseStateWithExtensions, StateWithExtensions};
use spl_token_2022::state::Mint;

/// Custom error codes of this crate start here (clear of the usual program error ranges, Anchor's included).
pub const VENUE_ERROR_BASE: u32 = 0x7E00;

/// Why a fill was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VenueError {
    /// The token program, or the mint's owner, is not Token-2022.
    NotToken2022 = 0,
    /// The mint has no transfer hook, or its hook is not the pinned Törus hook.
    NotTorusHook = 1,
    /// The mint has no transfer fee (every Törus token has one).
    NoTransferFee = 2,
    /// The seller's and the buyer's accounts are the same (a self-transfer is not a trade).
    SameAccount = 3,
    /// Nothing to settle.
    ZeroAmount = 4,
}

impl From<VenueError> for ProgramError {
    fn from(error: VenueError) -> Self {
        ProgramError::Custom(VENUE_ERROR_BASE + error as u32)
    }
}

/// The accounts of one fill.
pub struct Fill<'a, 'info> {
    /// Token-2022.
    pub token_program: &'a AccountInfo<'info>,
    pub mint: &'a AccountInfo<'info>,
    /// The seller's token account.
    pub source: &'a AccountInfo<'info>,
    /// The buyer's token account.
    pub destination: &'a AccountInfo<'info>,
    /// Who moves the tokens: the venue's delegate (a PDA the seller approved), or the seller itself.
    pub authority: &'a AccountInfo<'info>,
    /// The hook's extra accounts (see the crate documentation).
    pub hook_accounts: &'a [AccountInfo<'info>],
}

/// The fee withheld on a fill and what the buyer receives (Token-2022's own calculation for the epoch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FillQuote {
    pub amount: u64,
    pub fee: u64,
    pub received: u64,
}

/// Checks that `mint` is a Törus token whose transfers go through the pinned Törus hook; returns its decimals.
pub fn check_torus_mint(mint: &AccountInfo, torus_hook: &Pubkey) -> Result<u8, ProgramError> {
    if mint.owner != &spl_token_2022::id() {
        return Err(VenueError::NotToken2022.into());
    }
    let data = mint.try_borrow_data()?;
    let state = StateWithExtensions::<Mint>::unpack(&data)?;
    let hook = state.get_extension::<TransferHook>().map_err(|_| VenueError::NotTorusHook)?;
    if Option::<Pubkey>::from(hook.program_id) != Some(*torus_hook) {
        return Err(VenueError::NotTorusHook.into());
    }
    state.get_extension::<TransferFeeConfig>().map_err(|_| VenueError::NoTransferFee)?;
    Ok(state.base.decimals)
}

/// The owner of a Token-2022 token account (refused if the account is not one). A venue uses it to check that the
/// seller's account belongs to the seller and the buyer's to the buyer.
pub fn token_account_owner(account: &AccountInfo) -> Result<Pubkey, ProgramError> {
    if account.owner != &spl_token_2022::id() {
        return Err(VenueError::NotToken2022.into());
    }
    let data = account.try_borrow_data()?;
    Ok(StateWithExtensions::<spl_token_2022::state::Account>::unpack(&data)?.base.owner)
}

/// The fee Token-2022 will withhold on a fill of `amount` in `epoch`, and what the buyer receives. The mint is checked
/// first (check_torus_mint), so a lookalike's data never yields a plausible quote.
pub fn quote_fill(mint: &AccountInfo, torus_hook: &Pubkey, amount: u64, epoch: u64) -> Result<FillQuote, ProgramError> {
    check_torus_mint(mint, torus_hook)?;
    let data = mint.try_borrow_data()?;
    let state = StateWithExtensions::<Mint>::unpack(&data)?;
    let config = state.get_extension::<TransferFeeConfig>().map_err(|_| VenueError::NoTransferFee)?;
    let fee = config.calculate_epoch_fee(epoch, amount).ok_or(ProgramError::ArithmeticOverflow)?;
    let received = amount.checked_sub(fee).ok_or(ProgramError::ArithmeticOverflow)?;
    Ok(FillQuote { amount, fee, received })
}

/// Settles one fill: checks the token program and the mint, then moves `amount` from the seller's account to the
/// buyer's through Token-2022's `transfer_checked` with the hook's extra accounts. `signer_seeds` signs for a PDA
/// authority (the venue's delegate); pass `&[]` when the authority signs the transaction itself.
pub fn settle_fill(fill: &Fill, amount: u64, torus_hook: &Pubkey, signer_seeds: &[&[&[u8]]]) -> ProgramResult {
    if fill.token_program.key != &spl_token_2022::id() {
        return Err(VenueError::NotToken2022.into());
    }
    if amount == 0 {
        return Err(VenueError::ZeroAmount.into());
    }
    if fill.source.key == fill.destination.key {
        return Err(VenueError::SameAccount.into());
    }
    let decimals = check_torus_mint(fill.mint, torus_hook)?;
    spl_token_2022::onchain::invoke_transfer_checked(
        fill.token_program.key,
        fill.source.clone(),
        fill.mint.clone(),
        fill.destination.clone(),
        fill.authority.clone(),
        fill.hook_accounts,
        amount,
        decimals,
        signer_seeds,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::program_option::COption;
    use solana_program::program_pack::Pack;
    use spl_pod::optional_keys::OptionalNonZeroPubkey;
    use spl_token_2022::extension::transfer_fee::TransferFee;
    use spl_token_2022::extension::{BaseStateWithExtensionsMut, ExtensionType, StateWithExtensionsMut};

    const DECIMALS: u8 = 6;
    const FEE_BPS: u16 = 50;
    const MAX_FEE: u64 = 1_000;

    /// A Token-2022 mint's data with the given hook (if any) and a 0.5% transfer fee capped at MAX_FEE (if `with_fee`).
    fn mint_data(hook: Option<Pubkey>, with_fee: bool) -> Vec<u8> {
        let mut extensions = vec![ExtensionType::TransferHook];
        if with_fee {
            extensions.push(ExtensionType::TransferFeeConfig);
        }
        let mut data = vec![0u8; ExtensionType::try_calculate_account_len::<Mint>(&extensions).unwrap()];
        let mut state = StateWithExtensionsMut::<Mint>::unpack_uninitialized(&mut data).unwrap();
        state.init_extension::<TransferHook>(true).unwrap().program_id = OptionalNonZeroPubkey::try_from(hook).unwrap();
        if with_fee {
            let fee = TransferFee { epoch: 0.into(), maximum_fee: MAX_FEE.into(), transfer_fee_basis_points: FEE_BPS.into() };
            let config = state.init_extension::<TransferFeeConfig>(true).unwrap();
            config.older_transfer_fee = fee;
            config.newer_transfer_fee = fee;
        }
        state.base = Mint { mint_authority: COption::None, supply: 0, decimals: DECIMALS, is_initialized: true, freeze_authority: COption::None };
        state.pack_base();
        state.init_account_type().unwrap();
        data
    }

    /// Runs `check` on an account holding `data`, owned by `owner`.
    fn with_account<T>(owner: Pubkey, mut data: Vec<u8>, check: impl FnOnce(&AccountInfo) -> T) -> T {
        let key = Pubkey::new_unique();
        let mut lamports = 1_000_000u64;
        let account = AccountInfo::new(&key, false, false, &mut lamports, &mut data, &owner, false, 0);
        check(&account)
    }

    #[test]
    fn accepts_only_a_mint_with_the_pinned_hook_and_a_fee() {
        let hook = Pubkey::new_unique();
        let token_2022 = spl_token_2022::id();
        assert_eq!(with_account(token_2022, mint_data(Some(hook), true), |mint| check_torus_mint(mint, &hook)), Ok(DECIMALS));
        let refused = |owner: Pubkey, data: Vec<u8>| with_account(owner, data, |mint| check_torus_mint(mint, &hook));
        assert_eq!(refused(token_2022, mint_data(Some(Pubkey::new_unique()), true)), Err(VenueError::NotTorusHook.into()));
        assert_eq!(refused(token_2022, mint_data(None, true)), Err(VenueError::NotTorusHook.into()));
        assert_eq!(refused(token_2022, mint_data(Some(hook), false)), Err(VenueError::NoTransferFee.into()));
        assert_eq!(refused(Pubkey::new_unique(), mint_data(Some(hook), true)), Err(VenueError::NotToken2022.into()));
    }

    #[test]
    fn quotes_the_fee_token_2022_withholds() {
        let hook = Pubkey::new_unique();
        let data = mint_data(Some(hook), true);
        let quote = with_account(spl_token_2022::id(), data.clone(), |mint| quote_fill(mint, &hook, 100_000, 0)).unwrap();
        assert_eq!(quote, FillQuote { amount: 100_000, fee: 500, received: 99_500 });
        // Capped at the mint's maximum fee.
        let capped = with_account(spl_token_2022::id(), data.clone(), |mint| quote_fill(mint, &hook, 10_000_000, 0)).unwrap();
        assert_eq!(capped, FillQuote { amount: 10_000_000, fee: MAX_FEE, received: 10_000_000 - MAX_FEE });
        // A lookalike (another hook) gets no quote.
        let other = Pubkey::new_unique();
        assert_eq!(with_account(spl_token_2022::id(), data, |mint| quote_fill(mint, &other, 100_000, 0)), Err(VenueError::NotTorusHook.into()));
    }

    #[test]
    fn a_token_account_or_garbage_is_not_a_mint() {
        let hook = Pubkey::new_unique();
        let token_2022 = spl_token_2022::id();
        let account_data = vec![0u8; spl_token_2022::state::Account::LEN];
        assert!(with_account(token_2022, account_data, |mint| check_torus_mint(mint, &hook)).is_err());
        assert!(with_account(token_2022, vec![7u8; 10], |mint| check_torus_mint(mint, &hook)).is_err());
        // token_account_owner refuses an account that Token-2022 does not own, and data that is not a token account.
        assert_eq!(with_account(Pubkey::new_unique(), vec![], |account| token_account_owner(account)), Err(VenueError::NotToken2022.into()));
        assert!(with_account(token_2022, vec![7u8; 10], |account| token_account_owner(account)).is_err());
    }

    #[test]
    fn refuses_another_token_program_a_self_transfer_and_nothing_to_settle() {
        let hook = Pubkey::new_unique();
        let token_2022 = spl_token_2022::id();
        let (other_program, mint_key, seller, buyer, venue) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
        let mut lamports = [0u64; 6];
        let mut data: [Vec<u8>; 6] = [vec![], vec![], mint_data(Some(hook), true), vec![], vec![], vec![]];
        let [l0, l1, l2, l3, l4, l5] = &mut lamports;
        let [d0, d1, d2, d3, d4, d5] = &mut data;
        let loader = Pubkey::new_unique();
        let token_program = AccountInfo::new(&token_2022, false, false, l0, d0, &loader, true, 0);
        let impostor = AccountInfo::new(&other_program, false, false, l1, d1, &loader, true, 0);
        let mint = AccountInfo::new(&mint_key, false, false, l2, d2, &token_2022, false, 0);
        let source = AccountInfo::new(&seller, false, true, l3, d3, &token_2022, false, 0);
        let destination = AccountInfo::new(&buyer, false, true, l4, d4, &token_2022, false, 0);
        let authority = AccountInfo::new(&venue, true, false, l5, d5, &loader, false, 0);
        let fill = Fill { token_program: &token_program, mint: &mint, source: &source, destination: &destination, authority: &authority, hook_accounts: &[] };
        // A venue's PDA must never sign for another program.
        let to_impostor = Fill { token_program: &impostor, ..fill };
        assert_eq!(settle_fill(&to_impostor, 1, &hook, &[]), Err(VenueError::NotToken2022.into()));
        assert_eq!(settle_fill(&fill, 0, &hook, &[]), Err(VenueError::ZeroAmount.into()));
        let to_self = Fill { destination: &source, ..fill };
        assert_eq!(settle_fill(&to_self, 1, &hook, &[]), Err(VenueError::SameAccount.into()));
    }
}
