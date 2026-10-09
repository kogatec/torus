//! verify_uniqueness: verifies that every payment in the ledger is unique (the issuer's responsibility; anyone can submit).
//!
//! Disclosing a sample alone cannot rule out a ledger that inflates its total by repeating the same payment, or by
//! reusing payments already recognized in another period (comparing neighbouring leaves is not enough either).
//! So this instruction receives all leaves in index order and checks that
//!   (1) payment IDs are strictly increasing (no duplicates in the tree)
//!   (2) the root rebuilt from all leaves matches the commitment and its sum equals the control total
//!   (3) each payment ID can be registered in the token's used-ID registry (OutcomeRecord, seeds = [outcome, mint, id]),
//!       shared by all periods (OutcomeAlreadyUsed if another audit registered it: no reuse across periods).
//!       The registry is per token so a company cannot put another company's payment IDs in its own tree, register
//!       them first and block that company. Double counting across companies is caught by independent observation.
//! finalize_audit waits for this verification; if it is not done by the deadline, it is a default.
//!
//! Large ledgers are sent over several transactions (progress is kept in UniquenessCursor). After sending a wrong
//! leaf, `restart` starts over as long as verification is not complete (records from the same audit are overwritten).
//! The tree shape matches SumTree (an odd last node is promoted at each level): merge adjacent subtrees of equal
//! height, then combine from the right at the end, and the same root comes out.

use anchor_lang::prelude::*;
use anchor_lang::system_program::{
    allocate, assign, create_account, transfer, Allocate, Assign, CreateAccount, Transfer,
};

use crate::constants::*;
use crate::errors::TorusError;
use crate::instructions::verify_disclosure::{leaf_hash, node_hash, root_commitment};
use crate::state::{AuditCycle, OutcomeRecord, UniqNode, UniquenessCursor};

/// A leaf sent for the uniqueness check (indices follow the order sent, starting at 0).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct UniqLeaf {
    pub outcome_id: [u8; 32],
    pub beneficiary: Pubkey,
    pub value: u64,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, VerifyUniqueness<'info>>,
    leaves: Vec<UniqLeaf>,
    restart: bool,
) -> Result<()> {
    let audit_key = ctx.accounts.audit.key();
    let mint = ctx.accounts.audit.token;
    {
        let audit = &ctx.accounts.audit;
        require!(
            audit.stage != AuditStage::Finalized as u8,
            TorusError::InvalidAuditStage
        );
        require!(!audit.uniqueness_verified, TorusError::UniquenessAlreadyVerified);
    }
    require!(
        leaves.len() == ctx.remaining_accounts.len(),
        TorusError::InvalidOutcomeAccount
    );

    let cursor = &mut ctx.accounts.cursor;
    if cursor.audit == Pubkey::default() {
        cursor.audit = audit_key;
        cursor.bump = ctx.bumps.cursor;
    }
    require_keys_eq!(cursor.audit, audit_key, TorusError::Unauthorized);
    if restart {
        cursor.next_index = 0;
        cursor.last_id = [0u8; 32];
        cursor.stack.clear();
    }

    let population_size = ctx.accounts.audit.population_size;
    for (i, leaf) in leaves.iter().enumerate() {
        let index = cursor.next_index;
        require!(index < population_size, TorusError::TooManyLeaves);
        // (1) payment IDs strictly increasing
        if index > 0 {
            require!(leaf.outcome_id > cursor.last_id, TorusError::LeafOrderInvalid);
        }
        // (3) register in the used-ID registry (reject if already there)
        register_outcome(
            &ctx.accounts.crank.to_account_info(),
            &ctx.accounts.system_program.to_account_info(),
            &ctx.remaining_accounts[i],
            &mint,
            leaf.outcome_id,
            audit_key,
            index,
            ctx.program_id,
        )?;
        // (2) build up the subtrees
        let mut node = UniqNode {
            hash: leaf_hash(index, &leaf.outcome_id, &leaf.beneficiary, leaf.value),
            sum: leaf.value,
            height: 0,
        };
        while cursor.stack.last().map(|top| top.height == node.height).unwrap_or(false) {
            let left = cursor.stack.pop().unwrap();
            node = UniqNode {
                hash: node_hash(&left.hash, left.sum, &node.hash, node.sum),
                sum: left.sum.checked_add(node.sum).ok_or(TorusError::MathOverflow)?,
                height: node.height + 1,
            };
        }
        require!(cursor.stack.len() < MAX_UNIQ_STACK, TorusError::TooManyLeaves);
        cursor.stack.push(node);
        cursor.last_id = leaf.outcome_id;
        cursor.next_index = index + 1;
    }

    if cursor.next_index == population_size {
        // Combine from the right to get the root (same shape as SumTree's promotion rule).
        let mut right = cursor.stack.pop().ok_or(TorusError::UniquenessRootMismatch)?;
        while let Some(left) = cursor.stack.pop() {
            right = UniqNode {
                hash: node_hash(&left.hash, left.sum, &right.hash, right.sum),
                sum: left.sum.checked_add(right.sum).ok_or(TorusError::MathOverflow)?,
                height: 0,
            };
        }
        let audit = &mut ctx.accounts.audit;
        require!(
            root_commitment(&right.hash, right.sum, population_size) == audit.commitment_value
                && right.sum == audit.control_total,
            TorusError::UniquenessRootMismatch
        );
        audit.uniqueness_verified = true;
        msg!(
            "verify_uniqueness: period_id={} population={} verified",
            audit.period_id,
            population_size
        );
    } else {
        msg!(
            "verify_uniqueness: progress {}/{}",
            cursor.next_index,
            population_size
        );
    }
    Ok(())
}

/// Creates the used-ID record (PDA: seeds = [outcome, mint, outcome_id]); rejects it if another audit created it.
/// A record created by the same audit before a restart is overwritten. To work even if someone pre-funded the
/// address with lamports, it falls back to transfer + allocate + assign when create_account cannot be used.
fn register_outcome<'info>(
    payer: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
    record: &AccountInfo<'info>,
    mint: &Pubkey,
    outcome_id: [u8; 32],
    audit: Pubkey,
    index: u32,
    program_id: &Pubkey,
) -> Result<()> {
    let (expected, bump) =
        Pubkey::find_program_address(&[OUTCOME_SEED, mint.as_ref(), &outcome_id], program_id);
    require_keys_eq!(record.key(), expected, TorusError::InvalidOutcomeAccount);

    if record.owner == program_id {
        // Already registered: overwrite if it is a restart of the same audit, reject as reuse if another audit.
        let existing = {
            let data = record.try_borrow_data()?;
            OutcomeRecord::try_deserialize(&mut &data[..])?
        };
        require_keys_eq!(existing.audit, audit, TorusError::OutcomeAlreadyUsed);
        let rec = OutcomeRecord { outcome_id, audit, index, bump };
        let mut data = record.try_borrow_mut_data()?;
        rec.try_serialize(&mut &mut data[..])?;
        return Ok(());
    }

    let space = 8 + OutcomeRecord::INIT_SPACE;
    let rent = Rent::get()?.minimum_balance(space);
    let seeds: &[&[u8]] = &[OUTCOME_SEED, mint.as_ref(), &outcome_id, &[bump]];
    let current = record.lamports();
    if current == 0 {
        create_account(
            CpiContext::new_with_signer(
                system_program.clone(),
                CreateAccount { from: payer.clone(), to: record.clone() },
                &[seeds],
            ),
            rent,
            space as u64,
            program_id,
        )?;
    } else {
        if current < rent {
            transfer(
                CpiContext::new(
                    system_program.clone(),
                    Transfer { from: payer.clone(), to: record.clone() },
                ),
                rent - current,
            )?;
        }
        allocate(
            CpiContext::new_with_signer(
                system_program.clone(),
                Allocate { account_to_allocate: record.clone() },
                &[seeds],
            ),
            space as u64,
        )?;
        assign(
            CpiContext::new_with_signer(
                system_program.clone(),
                Assign { account_to_assign: record.clone() },
                &[seeds],
            ),
            program_id,
        )?;
    }
    let rec = OutcomeRecord { outcome_id, audit, index, bump };
    let mut data = record.try_borrow_mut_data()?;
    rec.try_serialize(&mut &mut data[..])?;
    Ok(())
}

#[derive(Accounts)]
pub struct VerifyUniqueness<'info> {
    /// The caller pays for the used-ID records and the progress account (usually the issuer).
    #[account(mut)]
    pub crank: Signer<'info>,

    #[account(
        mut,
        seeds = [AUDIT_SEED, audit.token.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
    )]
    pub audit: Box<Account<'info, AuditCycle>>,

    /// Progress account (created on the first call).
    #[account(
        init_if_needed,
        payer = crank,
        space = 8 + UniquenessCursor::INIT_SPACE,
        seeds = [UNIQ_SEED, audit.key().as_ref()],
        bump,
    )]
    pub cursor: Box<Account<'info, UniquenessCursor>>,

    pub system_program: Program<'info, System>,
    // remaining_accounts: the used-ID record PDA of each leaf (seeds = [outcome, mint, outcome_id]), in leaf order.
}
