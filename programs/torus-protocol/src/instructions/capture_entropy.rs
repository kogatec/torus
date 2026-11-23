//! capture_entropy: records the hash of the slot fixed at commit (anyone can crank it).
//!
//! commit_performance fixes a slot shortly after the commitment; its hash did not exist when the ledger was committed,
//! so neither the issuer nor the operator could know it. This instruction copies that hash from the SlotHashes sysvar
//! into the cycle (the hash of the first block at or after the slot, if the slot itself was skipped).
//!
//! The sysvar only keeps recent slots. If nobody captured the hash while it could be read, the cycle cannot use it any
//! more: a later slot is fixed instead **and the sample is doubled**, so letting the window pass is never a way to get
//! a more convenient draw. Anyone can call this, the issuer included, so an honest issuer is never at the mercy of
//! someone else's crank.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar;

use crate::constants::*;
use crate::errors::TorusError;
use crate::sampling::{self, SlotPick};
use crate::state::AuditCycle;

pub fn handler(ctx: Context<CaptureEntropy>) -> Result<()> {
    let now = Clock::get()?.slot;
    let audit = &mut ctx.accounts.audit;
    require!(
        audit.stage == AuditStage::Committed as u8,
        TorusError::InvalidAuditStage
    );
    require!(audit.captured_slot == 0, TorusError::EntropyAlreadyCaptured);

    let pick = {
        let data = ctx.accounts.slot_hashes.try_borrow_data()?;
        sampling::pick_slot_hash(&data, audit.entropy_slot)?
    };
    match pick {
        SlotPick::TooEarly => return err!(TorusError::EntropyNotAfterCommit),
        SlotPick::Found(hash) => {
            audit.slot_hash = hash;
            audit.captured_slot = now;
        }
        SlotPick::Lapsed => {
            let (sample_size, max_defects) = sampling::escalate(audit.sample_size, audit.max_defects);
            audit.sample_size = sample_size;
            audit.max_defects = max_defects;
            audit.entropy_slot = now
                .checked_add(ENTROPY_DELAY_SLOTS)
                .ok_or(TorusError::MathOverflow)?;
        }
    }

    msg!(
        "capture_entropy: mint={} period_id={} entropy_slot={} captured_slot={} sample_size={}",
        audit.token,
        audit.period_id,
        audit.entropy_slot,
        audit.captured_slot,
        audit.sample_size
    );
    Ok(())
}

#[derive(Accounts)]
pub struct CaptureEntropy<'info> {
    /// Anyone may crank this (pays the transaction fee); the hash comes from the sysvar, not from the caller.
    pub crank: Signer<'info>,

    #[account(
        mut,
        seeds = [AUDIT_SEED, audit.token.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
    )]
    pub audit: Account<'info, AuditCycle>,

    /// The SlotHashes sysvar.
    /// CHECK: bound to the sysvar's address; read as raw bytes (too large to deserialize on-chain).
    #[account(address = sysvar::slot_hashes::ID)]
    pub slot_hashes: UncheckedAccount<'info>,
}
