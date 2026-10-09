//! designate_sample: designates the sample.
//!
//! Derives the sampled leaves deterministically from entropy fixed after the commitment. Requiring the entropy
//! to come from a slot after the commitment keeps the issuer from re-choosing the sample after committing.
//!
//! **TODO: in production the entropy must come with a verified VRF proof (Switchboard/ORAO). A single hash
//!   a block producer could re-roll is not acceptable. For now only the post-commit ordering is enforced.**

use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{AuditCycle, Config};

pub fn handler(ctx: Context<DesignateSample>, entropy: [u8; 32]) -> Result<()> {
    let clock = Clock::get()?;
    let audit = &mut ctx.accounts.audit;

    // Stage: committed.
    require!(
        audit.stage == AuditStage::Committed as u8,
        TorusError::InvalidAuditStage
    );

    // The entropy must be fixed in a slot after the commitment.
    require!(
        clock.slot > audit.committed_slot,
        TorusError::EntropyNotAfterCommit
    );

    let population_size = audit.population_size;
    // The sample size was fixed from the manifest at commit (the caller cannot choose it).
    let sample_size = audit.sample_size;

    // Sample size: non-zero, at most the population, and at most MAX_SAMPLE_SIZE (account allocation).
    require!(
        sample_size > 0 && (sample_size as u32) <= population_size,
        TorusError::InvalidSampleSize
    );
    require!(
        (sample_size as usize) <= MAX_SAMPLE_SIZE,
        TorusError::SampleTooLarge
    );
    // Here sample_size >= 1 and sample_size <= population_size, so population_size >= 1
    // and the modulo below never divides by zero.

    // Derive the sample indices deterministically from the entropy (repeats allowed):
    // for each i, the first u32 of keccak(entropy || (i as u32).to_le_bytes()) modulo the population.
    let mut indices: Vec<u32> = Vec::with_capacity(sample_size as usize);
    for i in 0..(sample_size as u32) {
        let h = keccak::hashv(&[entropy.as_ref(), &i.to_le_bytes()]);
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&h.0[..4]);
        indices.push(u32::from_le_bytes(buf) % population_size);
    }

    audit.entropy = entropy;
    audit.entropy_slot = clock.slot;
    audit.sample_indices = indices;
    audit.stage = AuditStage::Sampled as u8;

    msg!(
        "designate_sample: mint={} period_id={} sample_size={} entropy_slot={} population_size={}",
        audit.token,
        audit.period_id,
        sample_size,
        audit.entropy_slot,
        population_size
    );
    Ok(())
}

#[derive(Accounts)]
pub struct DesignateSample<'info> {
    /// Supplier of the entropy: the operator (Config.authority). The issuer cannot choose it.
    /// TODO: in production add the VRF oracle accounts (Switchboard/ORAO) and derive and verify the entropy
    ///   from its proof (then the operator cannot choose it either).
    #[account(mut)]
    pub crank: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        constraint = config.authority == crank.key() @ TorusError::Unauthorized,
    )]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [AUDIT_SEED, audit.token.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
    )]
    pub audit: Account<'info, AuditCycle>,
}
