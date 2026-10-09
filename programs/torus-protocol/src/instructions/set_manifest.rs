//! set_manifest: fixes the judging rules in advance.
//!
//! Fixes the manifest before the ledger is built. Invariants:
//!   - only the issuer (token_state.issuer) can sign;
//!   - the auditor differs from the issuer (the issuer cannot audit itself) and is registered;
//!   - the return rate is at least the floor (min_return_rate_bps).

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{AuditorRecord, Config, Manifest, TokenState};

pub fn handler(
    ctx: Context<SetManifest>,
    return_rate_bps: u16,
    tolerance_bps: u16,
    shortfall_tolerance_bps: u16,
    min_return_rate_bps: u16,
    period_len: i64,
    term_len: i64,
    sample_size: u16,
    max_defects: u16,
) -> Result<()> {
    // Floor: the return rate must be at least this.
    require!(
        return_rate_bps >= min_return_rate_bps,
        TorusError::ReturnRateBelowFloor
    );

    // The term (campaign length) must be positive; no manifest without an end.
    require!(term_len > 0, TorusError::InvalidManifestTerm);
    // The period length must be positive too (used for provision_budget's time gate and the audit deadline).
    require!(period_len > 0, TorusError::InvalidManifestTerm);
    // Caps on the judging parameters: large tolerances would make fraud (attacks X and Y) undetectable, so the
    // caps are fixed in code and the issuer cannot pick values that are never detected.
    require!(
        tolerance_bps <= MAX_TOLERANCE_BPS && shortfall_tolerance_bps <= MAX_SHORTFALL_TOLERANCE_BPS,
        TorusError::ToleranceTooLarge
    );
    require!(
        (return_rate_bps as u64) <= BPS_DENOMINATOR,
        TorusError::ReturnRateBelowFloor
    );
    // Sample size: at least the operator's minimum, at most the account limit; not chosen at designation.
    require!(
        sample_size >= ctx.accounts.config.min_sample_size,
        TorusError::SampleSizeBelowMinimum
    );
    require!((sample_size as usize) <= MAX_SAMPLE_SIZE, TorusError::SampleTooLarge);
    // Allowed defects at most 20% of the sample, so the issuer cannot pick "any number of defects passes".
    require!(
        (max_defects as u64) * BPS_DENOMINATOR <= (sample_size as u64) * MAX_DEFECT_RATE_BPS,
        TorusError::TooManyAllowedDefects
    );
    // The auditor must be registered and active (the issuer cannot name a friend's key).
    require!(ctx.accounts.auditor_record.active, TorusError::AuditorNotRegistered);

    // Separation of roles: the issuer cannot be its own auditor.
    let issuer_key = ctx.accounts.issuer.key();
    let auditor_key = ctx.accounts.auditor.key();
    require_keys_neq!(auditor_key, issuer_key, TorusError::AuditorNotIndependent);

    let manifest = &mut ctx.accounts.manifest;
    manifest.token = ctx.accounts.token_state.mint;
    manifest.return_rate_bps = return_rate_bps;
    manifest.tolerance_bps = tolerance_bps;
    manifest.shortfall_tolerance_bps = shortfall_tolerance_bps;
    manifest.min_return_rate_bps = min_return_rate_bps;
    manifest.auditor = auditor_key;
    manifest.active = true;
    manifest.period_len = period_len;
    manifest.sample_size = sample_size;
    manifest.max_defects = max_defects;
    // Expiry = now + term. After it, this instruction fixes the next campaign.
    manifest.valid_until = Clock::get()?
        .unix_timestamp
        .checked_add(term_len)
        .ok_or(TorusError::MathOverflow)?;
    manifest.bump = ctx.bumps.manifest;

    let manifest_key = manifest.key();
    ctx.accounts.token_state.manifest = manifest_key;

    msg!(
        "set_manifest: mint={} auditor={} return_rate_bps={} tolerance_bps={} lcl_bps={} floor_bps={} valid_until={}",
        ctx.accounts.token_state.mint,
        auditor_key,
        return_rate_bps,
        tolerance_bps,
        shortfall_tolerance_bps,
        min_return_rate_bps,
        ctx.accounts.manifest.valid_until
    );
    Ok(())
}

#[derive(Accounts)]
pub struct SetManifest<'info> {
    /// The issuer, payer. Must equal token_state.issuer (has_one).
    #[account(mut)]
    pub issuer: Signer<'info>,

    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()],
        bump = token_state.bump,
        has_one = issuer @ TorusError::Unauthorized,
    )]
    pub token_state: Account<'info, TokenState>,

    /// The manifest. init_if_needed so it can be set again
    /// (anchor-lang's "init-if-needed" feature is enabled in Cargo.toml).
    #[account(
        init_if_needed,
        payer = issuer,
        space = 8 + Manifest::INIT_SPACE,
        seeds = [MANIFEST_SEED, token_state.mint.as_ref()],
        bump,
    )]
    pub manifest: Account<'info, Manifest>,

    /// The independent auditor; only its key is stored in Manifest.auditor.
    /// CHECK: no signature needed; the handler checks it differs from the issuer (AuditorNotIndependent).
    pub auditor: UncheckedAccount<'info>,

    /// The operator's registry record, bound to the auditor by seeds (fails if the auditor is not registered).
    #[account(
        seeds = [AUDITOR_SEED, auditor.key().as_ref()],
        bump = auditor_record.bump,
        constraint = auditor_record.auditor == auditor.key() @ TorusError::AuditorNotRegistered,
    )]
    pub auditor_record: Account<'info, AuditorRecord>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    pub system_program: Program<'info, System>,
}
