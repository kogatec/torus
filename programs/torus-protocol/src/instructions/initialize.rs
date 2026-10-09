//! initialize: creates the protocol configuration (Config singleton PDA).
//!
//! Registers the USDC mint (currency of the redemption pool and the bond, so the backing is not the brand
//! token) and the transfer hook program id (burned into each mint's TransferHook at issuance). It also fixes
//! where slashed bonds go, the treasury that receives the operator's share of converted fees, and the
//! minimum bond target (min_bond_target); each company's bond target must be at least this.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::program::TorusProtocol;
use crate::state::Config;

pub fn handler(
    ctx: Context<Initialize>,
    usdc_mint: Pubkey,
    hook_program: Pubkey,
    slash_destination: Pubkey,
    treasury: Pubkey,
    min_sample_size: u16,
    min_bond_target: u64,
) -> Result<()> {
    require!(
        min_sample_size > 0 && (min_sample_size as usize) <= MAX_SAMPLE_SIZE,
        TorusError::InvalidSampleSize
    );
    let config = &mut ctx.accounts.config;
    config.authority = ctx.accounts.authority.key();
    config.usdc_mint = usdc_mint;
    config.hook_program = hook_program;
    config.slash_destination = slash_destination;
    config.bump = ctx.bumps.config;
    config.min_sample_size = min_sample_size;
    config.treasury = treasury;
    config.min_bond_target = min_bond_target;

    msg!(
        "initialize: authority={} usdc_mint={} hook_program={} slash_destination={} treasury={}",
        config.authority,
        usdc_mint,
        hook_program,
        slash_destination,
        treasury
    );
    Ok(())
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The protocol operator (= Config.authority), payer. **Must be the program's upgrade authority.**
    /// There is a single Config and whoever initializes it sets the slash destination and the hook, so this
    /// prevents front-running right after deployment.
    #[account(mut)]
    pub authority: Signer<'info>,

    /// This program itself (to find its ProgramData address).
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ TorusError::NotUpgradeAuthority)]
    pub program: Program<'info, TorusProtocol>,

    /// This program's ProgramData. Its upgrade authority must be `authority`.
    #[account(constraint = program_data.upgrade_authority_address == Some(authority.key()) @ TorusError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,

    #[account(
        init,
        payer = authority,
        space = 8 + Config::INIT_SPACE,
        seeds = [CONFIG_SEED],
        bump,
    )]
    pub config: Account<'info, Config>,

    pub system_program: Program<'info, System>,
}
