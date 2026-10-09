//! attest_leaf: the cycle's independent auditor confirms an individual leaf.
//!
//! A leaf that was not observed in the sample is not paid just because the audit passed overall (a passing
//! total is not a reason to pay unconfirmed recipients). The auditor records the amount confirmed for the leaf
//! from an independent record (e.g. the payment processor), and payout / claim_liquidation pay at most that.
//! The leaf is identified by a disclosure proof against the commitment (binding recipient, amount and payment ID).

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::verify_disclosure::{fold_sum_proof, SumSibling};
use crate::state::{AuditCycle, AuditorRecord, LeafAttestation};

#[allow(clippy::too_many_arguments)]
pub fn handler(
    ctx: Context<AttestLeaf>,
    index: u32,
    outcome_id: [u8; 32],
    beneficiary: Pubkey,
    value: u64,
    siblings: Vec<SumSibling>,
    confirmed: u64,
) -> Result<()> {
    let audit = &ctx.accounts.audit;
    require_keys_eq!(
        ctx.accounts.auditor.key(),
        audit.auditor,
        TorusError::UnauthorizedAuditor
    );
    let (root, sum) = fold_sum_proof(
        index,
        &outcome_id,
        &beneficiary,
        value,
        &siblings,
        audit.population_size,
    )?;
    require!(
        root == audit.commitment_value && sum == audit.control_total,
        TorusError::ClaimProofInvalid
    );

    let att = &mut ctx.accounts.attestation;
    att.audit = audit.key();
    att.index = index;
    att.beneficiary = beneficiary;
    att.confirmed = confirmed.min(value);
    att.bump = ctx.bumps.attestation;

    msg!(
        "attest_leaf: period_id={} index={} value={} confirmed={}",
        audit.period_id,
        index,
        value,
        att.confirmed
    );
    Ok(())
}

#[derive(Accounts)]
#[instruction(index: u32)]
pub struct AttestLeaf<'info> {
    /// The cycle's auditor (fixed at commit; the new auditor after a replacement).
    #[account(mut)]
    pub auditor: Signer<'info>,

    #[account(
        seeds = [AUDIT_SEED, audit.token.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
    )]
    pub audit: Box<Account<'info, AuditCycle>>,

    /// Registry record of the cycle's auditor (audit.auditor); it must still be active when confirming
    /// (the handler checks that the signer is audit.auditor).
    #[account(
        seeds = [AUDITOR_SEED, audit.auditor.as_ref()],
        bump = auditor_record.bump,
        constraint = auditor_record.active @ TorusError::AuditorRevoked,
    )]
    pub auditor_record: Box<Account<'info, AuditorRecord>>,

    /// One confirmation per leaf.
    #[account(
        init,
        payer = auditor,
        space = 8 + LeafAttestation::INIT_SPACE,
        seeds = [ATTEST_SEED, audit.key().as_ref(), index.to_le_bytes().as_ref()],
        bump,
    )]
    pub attestation: Account<'info, LeafAttestation>,

    pub system_program: Program<'info, System>,
}
