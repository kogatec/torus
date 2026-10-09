//! payout: pays from the redemption pool (first account, USDC).
//!
//! [Role]
//!   This instruction defines the point before which the audit must be finalized: "the moment money can be
//!   withdrawn" is the first moment this instruction can succeed, and finalize_audit always comes before it.
//!   Its gates are the only place where that order is enforced on-chain: before finalization, or after
//!   fraud is established, no money leaves the redemption pool by any path
//!   (there is no window to take the money and run).
//!
//! [Gates]
//!   - audit.stage == Finalized                      … no payout before finalization
//!   - audit.result ∈ {Pass, HonestShortfall}        … no payout once fraud is established
//!   - (after a freeze, recipients of audits finalized without fraud can still claim: a freeze stops new
//!     business, it does not cancel third parties' finalized rights)
//!   - token_state.redemption_started                … no redemptions before the bond is full
//!   - the leaf is confirmed                         … sampled leaves up to the observed value, others up to the
//!                                                     auditor's confirmation (attest_leaf); unconfirmed leaves are not paid
//!   - redemption_vault.amount >= amount             … no payout beyond the pool
//!   - balance after payout >= reserved             … funds reserved for other periods stay untouched
//!
//! [Who gets paid, and how much] (the caller decides neither)
//!   A payout is only a claim on a leaf of the ledger the issuer committed (Merkle sum tree). A leaf is
//!   `H(LEAF_TAG ‖ index ‖ outcome_id ‖ beneficiary ‖ value)` and contains the recipient and the amount. The
//!   claim carries the leaf's disclosure proof; the destination USDC account must be owned by the leaf's
//!   beneficiary, the amount is capped by the leaf's value, and a ClaimRecord (seeds = [claim, audit, index]) is
//!   created so the same leaf is never paid twice. Recipient and amount are bound to the audited promise itself.
//!
//! Only the pool_authority PDA signs (as in finalize_audit).
//! No issuer key is on the payout path.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::verify_disclosure::{fold_sum_proof, SumSibling};
use crate::state::{AuditCycle, ClaimRecord, Config, LeafAttestation, TokenState};

/// Confirmed amount of a leaf: the observed value for a sampled leaf, otherwise the auditor's confirmation.
/// LeafNotConfirmed if neither exists. Payouts and liquidation pay at most this (and at most the leaf's value).
pub fn confirmed_amount(
    audit: &AuditCycle,
    audit_key: &Pubkey,
    index: u32,
    beneficiary: &Pubkey,
    attestation: Option<&LeafAttestation>,
) -> Result<u64> {
    if let Some(j) = audit.sample_indices.iter().position(|&s| s == index) {
        if let Some(&observed) = audit.sample_observed.get(j) {
            return Ok(observed);
        }
    }
    let att = attestation.ok_or(TorusError::LeafNotConfirmed)?;
    require!(
        att.audit == *audit_key && att.index == index && att.beneficiary == *beneficiary,
        TorusError::LeafNotConfirmed
    );
    Ok(att.confirmed)
}

pub fn handler(
    ctx: Context<Payout>,
    index: u32,
    outcome_id: [u8; 32],
    value: u64,
    siblings: Vec<SumSibling>,
) -> Result<()> {
    let token_state = &mut ctx.accounts.token_state;
    let audit = &mut ctx.accounts.audit;

    // --- (1) The audit is finalized ---
    require!(
        audit.stage == AuditStage::Finalized as u8,
        TorusError::InvalidAuditStage
    );

    // --- (2) No fraud (Pass or honest shortfall only) ---
    // Pending / FraudOverstatement / FraudUnderstatement cannot be paid.
    require!(
        audit.result == AuditResult::Pass as u8
            || audit.result == AuditResult::HonestShortfall as u8,
        TorusError::Unauthorized
    );

    // --- (3) After a freeze, recipients of clean audits can still claim ((2) already excludes fraud) ---

    // --- (4) Redemptions have started (the bond reached its target) ---
    require!(
        token_state.redemption_started,
        TorusError::BondTargetNotReached
    );

    // --- (5) The leaf is in the committed ledger and the destination is owned by its recipient ---
    require!(index < audit.population_size, TorusError::ClaimProofInvalid);
    let beneficiary = ctx.accounts.beneficiary_usdc.owner;
    let (root_commitment, root_sum) =
        fold_sum_proof(index, &outcome_id, &beneficiary, value, &siblings, audit.population_size)?;
    require!(
        root_commitment == audit.commitment_value && root_sum == audit.control_total,
        TorusError::ClaimProofInvalid
    );

    // --- (6) The leaf is confirmed; pay at most the confirmed amount (and the leaf's value) ---
    let audit_key = audit.key();
    let confirmed = confirmed_amount(
        audit,
        &audit_key,
        index,
        &beneficiary,
        ctx.accounts.attestation.as_ref().map(|a| &***a),
    )?;
    let amount = value.min(confirmed);
    require!(amount > 0, TorusError::NothingToPay);

    // --- (7) The redemption pool holds enough ---
    require!(
        ctx.accounts.redemption_vault.amount >= amount,
        TorusError::InsufficientPoolBalance
    );

    // --- Reduce the reservation by what is paid (not beyond this cycle's reserved amount) ---
    let consumed = amount.min(audit.reserved_remaining);
    audit.reserved_remaining -= consumed;
    token_state.reserved = token_state.reserved.saturating_sub(consumed);
    // After paying, the balance must still cover what is reserved for other periods' recipients.
    // Promises beyond the obligation (leaves above the reservation) are paid only from the unreserved surplus.
    require!(
        ctx.accounts.redemption_vault.amount - amount >= token_state.reserved,
        TorusError::InsufficientPoolBalance
    );

    // --- Claim record (created by init, so a second claim already fails during account validation) ---
    let claim = &mut ctx.accounts.claim;
    claim.audit = audit.key();
    claim.index = index;
    claim.beneficiary = beneficiary;
    claim.value = amount;
    claim.bump = ctx.bumps.claim;

    // --- Pay: redemption_vault (USDC) → beneficiary_usdc, signed by the pool_authority PDA ---
    let mint_key = token_state.mint;
    let seeds: &[&[u8]] = &[
        POOL_AUTHORITY_SEED,
        mint_key.as_ref(),
        &[token_state.pool_authority_bump],
    ];
    let signer: &[&[&[u8]]] = &[seeds];

    let decimals = ctx.accounts.usdc_mint.decimals;
    token_interface::transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.usdc_token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.redemption_vault.to_account_info(),
                mint: ctx.accounts.usdc_mint.to_account_info(),
                to: ctx.accounts.beneficiary_usdc.to_account_info(),
                authority: ctx.accounts.pool_authority.to_account_info(),
            },
            signer,
        ),
        amount,
        decimals,
    )?;

    msg!(
        "payout: mint={} period_id={} result={} index={} value={} paid={} beneficiary={} to={}",
        mint_key,
        audit.period_id,
        audit.result,
        index,
        value,
        amount,
        beneficiary,
        ctx.accounts.beneficiary_usdc.key()
    );
    Ok(())
}

#[derive(Accounts)]
#[instruction(index: u32)]
pub struct Payout<'info> {
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
    pub token_state: Box<Account<'info, TokenState>>,

    /// The finalized audit cycle; whether a payout is allowed is decided by this account.
    #[account(
        mut,
        seeds = [AUDIT_SEED, audit.token.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
        constraint = audit.token == token_state.mint @ TorusError::Unauthorized,
    )]
    pub audit: Box<Account<'info, AuditCycle>>,

    /// Pool PDA (authority of the redemption pool and the bond).
    /// CHECK: bound by seeds; signs as a program-derived address.
    #[account(
        seeds = [POOL_AUTHORITY_SEED, token_state.mint.as_ref()],
        bump = token_state.pool_authority_bump,
    )]
    pub pool_authority: UncheckedAccount<'info>,

    /// First account: redemption pool (USDC).
    #[account(
        mut,
        address = token_state.redemption_vault @ TorusError::Unauthorized,
    )]
    pub redemption_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Destination (USDC). The proof fails unless its owner is the leaf's beneficiary.
    #[account(
        mut,
        token::mint = usdc_mint,
    )]
    pub beneficiary_usdc: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The auditor's confirmation of the leaf (needed when the leaf was not sampled); omit if there is none.
    pub attestation: Option<Box<Account<'info, LeafAttestation>>>,

    /// Claim record (one per audit cycle × leaf index). If it already exists, init fails: no double claim.
    #[account(
        init,
        payer = crank,
        space = 8 + ClaimRecord::INIT_SPACE,
        seeds = [CLAIM_SEED, audit.key().as_ref(), index.to_le_bytes().as_ref()],
        bump,
    )]
    pub claim: Box<Account<'info, ClaimRecord>>,

    #[account(address = token_state.usdc_mint @ TorusError::NonUsdcCollateral)]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    /// Token program of USDC (classic SPL).
    pub usdc_token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
