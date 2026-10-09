//! record_verification: records the observed value of each sampled leaf.
//!
//! The independent auditor records, in sample order, the value observed through an independent channel for each
//! sampled leaf (several transactions if needed). The claimed values were fixed by verify_disclosure from the proofs;
//! the program computes here the number of defects (claimed exceeds observed by more than the per-element
//! tolerance) and the observed sum. The auditor does not get to report totals or defect counts.
//! Once all samples are observed, the report hash is recorded and the cycle moves to Verified (finalize_audit judges).
//! Only the cycle's auditor (audit.auditor) can record, and its registration must still be active.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::provision_budget::mul_bps;
use crate::state::{AuditCycle, AuditorRecord};

pub fn handler(
    ctx: Context<RecordVerification>,
    observed_values: Vec<u64>,
    report_hash: [u8; 32],
) -> Result<()> {
    let audit = &mut ctx.accounts.audit;

    // Stage: sampled.
    require!(
        audit.stage == AuditStage::Sampled as u8,
        TorusError::InvalidAuditStage
    );

    // Only the auditor snapshotted at commit may record (prevents swapping in a colluding key mid-cycle
    // through the manifest; replacement only via replace_auditor).
    require_keys_eq!(
        ctx.accounts.auditor.key(),
        audit.auditor,
        TorusError::UnauthorizedAuditor
    );

    // All sampled leaves must be disclosed (claimed values fixed on-chain).
    require!(
        audit.verify_cursor == audit.sample_size,
        TorusError::DisclosuresIncomplete
    );

    let start = audit.sample_observed.len();
    require!(
        start + observed_values.len() <= audit.sample_size as usize,
        TorusError::TooManyObservations
    );
    for (k, &observed) in observed_values.iter().enumerate() {
        let asserted = audit.sample_values[start + k];
        let tolerance = mul_bps(asserted, audit.tolerance_bps)?;
        // Defect: the claim exceeds the observed value by more than the per-element tolerance (overclaim).
        if asserted > observed.saturating_add(tolerance) {
            audit.defect_count = audit
                .defect_count
                .checked_add(1)
                .ok_or(TorusError::MathOverflow)?;
        }
        audit.observed_sum = audit
            .observed_sum
            .checked_add(observed)
            .ok_or(TorusError::MathOverflow)?;
        audit.sample_observed.push(observed);
    }

    if audit.sample_observed.len() == audit.sample_size as usize {
        audit.report_hash = report_hash;
        audit.stage = AuditStage::Verified as u8;
    }

    msg!(
        "record_verification: mint={} period_id={} observed={}/{} observed_sum={} asserted_sample_sum={} defects={}",
        audit.token,
        audit.period_id,
        audit.sample_observed.len(),
        audit.sample_size,
        audit.observed_sum,
        audit.asserted_sample_sum,
        audit.defect_count
    );
    Ok(())
}

#[derive(Accounts)]
pub struct RecordVerification<'info> {
    /// The independent auditor (signer). Must equal audit.auditor snapshotted at commit
    /// (checked in the handler).
    #[account(mut)]
    pub auditor: Signer<'info>,

    #[account(
        mut,
        seeds = [AUDIT_SEED, audit.token.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
    )]
    pub audit: Account<'info, AuditCycle>,

    /// Registry record of the cycle's auditor (audit.auditor); it must still be active when recording
    /// (a revoked key cannot record; the handler checks that the signer is audit.auditor).
    #[account(
        seeds = [AUDITOR_SEED, audit.auditor.as_ref()],
        bump = auditor_record.bump,
        constraint = auditor_record.active @ TorusError::AuditorRevoked,
    )]
    pub auditor_record: Account<'info, AuditorRecord>,
}
