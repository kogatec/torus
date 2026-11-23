//! An example venue program (not part of the protocol). It shows how a venue settles the token leg of a fill through
//! the `torus-venue` crate: straight from the seller's account to the buyer's, moved by the venue's delegate (a PDA the
//! seller approved), through Token-2022 with the Törus hook — so the fee and the volume are counted once.
//!
//! Who may move what is the venue's own job, and this example keeps it minimal and safe:
//!   - the seller places an order that names the buyer and the amount (signed by the seller, who owns the source);
//!   - only that buyer, signing, can take it, into an account the buyer owns, up to the amount left on the order.
//! A real venue also matches prices and collects the buyer's payment before settling; this example does not, so do not
//! deploy it as a venue. The client passes the Törus hook's extra accounts as the remaining accounts (the TypeScript SDK
//! resolves them).

use anchor_lang::prelude::*;

declare_id!("B2iBhYKK4ANFgFL8kELS9gRCvKQdHxjcao3pddyZcSck");

/// The Törus transfer hook this venue accepts. The venue pins it; it does not take it from the mint.
pub const TORUS_HOOK: Pubkey = pubkey!("4Du4ZzQ5Z84yQDUqesfwXeHTC2wxfectgWjAyQ6RgLSi");
/// Seeds of the venue's delegate.
pub const VENUE_SEED: &[u8] = b"venue";
/// Seeds of an order (one open order per seller account).
pub const ORDER_SEED: &[u8] = b"order";

#[program]
pub mod torus_venue_example {
    use super::*;

    /// The seller offers `amount` of its account to `buyer` (and approves the venue's delegate separately, client-side).
    pub fn place_order(ctx: Context<PlaceOrder>, amount: u64, buyer: Pubkey) -> Result<()> {
        require!(amount > 0, VenueExampleError::NothingToSettle);
        let owner = torus_venue::token_account_owner(ctx.accounts.source.as_ref())?;
        require_keys_eq!(owner, ctx.accounts.seller.key(), VenueExampleError::NotTheSeller);
        let order = &mut ctx.accounts.order;
        order.seller = ctx.accounts.seller.key();
        order.source = ctx.accounts.source.key();
        order.mint = ctx.accounts.mint.key();
        order.buyer = buyer;
        order.remaining = amount;
        order.bump = ctx.bumps.order;
        Ok(())
    }

    /// The named buyer takes `amount` of the order into its own account (the transfer fee is withheld from it).
    pub fn settle<'info>(ctx: Context<'_, '_, '_, 'info, Settle<'info>>, amount: u64) -> Result<()> {
        let accounts = &ctx.accounts;
        require_keys_eq!(accounts.order.buyer, accounts.buyer.key(), VenueExampleError::NotTheBuyer);
        let receiver = torus_venue::token_account_owner(accounts.destination.as_ref())?;
        require_keys_eq!(receiver, accounts.buyer.key(), VenueExampleError::NotTheBuyer);
        require!(amount > 0 && amount <= accounts.order.remaining, VenueExampleError::NothingToSettle);
        let bump = [ctx.bumps.venue_authority];
        let seeds: &[&[u8]] = &[VENUE_SEED, &bump];
        let fill = torus_venue::Fill {
            token_program: accounts.token_program.as_ref(),
            mint: accounts.mint.as_ref(),
            source: accounts.source.as_ref(),
            destination: accounts.destination.as_ref(),
            authority: accounts.venue_authority.as_ref(),
            hook_accounts: ctx.remaining_accounts,
        };
        torus_venue::settle_fill(&fill, amount, &TORUS_HOOK, &[seeds])?;
        let order = &mut ctx.accounts.order;
        order.remaining -= amount;
        msg!("venue: settled {} of {} to {}; {} left on the order", amount, order.mint, order.buyer, order.remaining);
        Ok(())
    }
}

/// An order: the seller's account, the mint, the buyer it names, and what is left to settle.
#[account]
#[derive(InitSpace)]
pub struct Order {
    pub seller: Pubkey,
    pub source: Pubkey,
    pub mint: Pubkey,
    pub buyer: Pubkey,
    pub remaining: u64,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct PlaceOrder<'info> {
    #[account(mut)]
    pub seller: Signer<'info>,
    /// CHECK: the seller's token account; place_order checks that the seller owns it (torus_venue::token_account_owner).
    pub source: UncheckedAccount<'info>,
    /// CHECK: the Törus mint; checked when the order is settled (torus_venue::settle_fill).
    pub mint: UncheckedAccount<'info>,
    #[account(init_if_needed, payer = seller, space = 8 + Order::INIT_SPACE, seeds = [ORDER_SEED, source.key().as_ref()], bump)]
    pub order: Account<'info, Order>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Settle<'info> {
    /// The buyer the order names; it signs, and receives into its own account.
    pub buyer: Signer<'info>,
    #[account(mut, seeds = [ORDER_SEED, source.key().as_ref()], bump = order.bump, has_one = source, has_one = mint)]
    pub order: Account<'info, Order>,
    /// CHECK: the venue's delegate (a PDA of this program); the seller approved it on its token account.
    #[account(seeds = [VENUE_SEED], bump)]
    pub venue_authority: UncheckedAccount<'info>,
    /// CHECK: bound to the order (has_one), and checked by torus_venue (Token-2022, the pinned Törus hook, a fee).
    pub mint: UncheckedAccount<'info>,
    /// CHECK: bound to the order (has_one); Token-2022 checks the mint, the delegate and the balance.
    #[account(mut)]
    pub source: UncheckedAccount<'info>,
    /// CHECK: settle checks that the buyer owns it (torus_venue::token_account_owner); Token-2022 checks the mint.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    /// CHECK: must be Token-2022 (torus_venue checks the address before it signs anything).
    pub token_program: UncheckedAccount<'info>,
}

#[error_code]
pub enum VenueExampleError {
    #[msg("Only the owner of the source account can place an order on it")]
    NotTheSeller,
    #[msg("Only the buyer the order names can take it, into its own account")]
    NotTheBuyer,
    #[msg("Nothing to settle: zero, or more than is left on the order")]
    NothingToSettle,
}
