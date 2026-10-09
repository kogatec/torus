//! verify_disclosure: verifies a disclosure proof against the sum-bound commitment.
//!
//! # Why this instruction exists
//!
//! If the claimed values used by the deviation check were simply reported, and the control total were a free
//! number unrelated to `commitment_value`, the following attack would pass:
//!
//! > With an obligation O, deliver only 0.6·O, commit to **only the genuine entries**, declare a small
//! > `population_size` and `control_total = O`. Every sample is genuine, so Δ is clean, and Y passes with
//! > `control_total >= O` → **Pass, nothing slashed.**
//!
//! Y and Δ would be two unrelated checks, and **thinning the population (attack Y) would go through**.
//!
//! # Sum-bound commitment (Merkle sum tree)
//!
//! Every node carries a hash and the sum below it, and the commitment **includes the root sum**:
//! - leaf: `H(LEAF_TAG ‖ index ‖ outcome_id ‖ beneficiary ‖ value)`, sum = value
//!   (the payment ID and the recipient are in the leaf, so uniqueness and payouts are bound to the same leaves)
//! - internal: `H(NODE_TAG ‖ Lh ‖ Ls ‖ Rh ‖ Rs)`, sum = Ls + Rs
//! - commitment: `H(ROOT_TAG ‖ root_hash ‖ root_sum ‖ population_size)`
//!
//! For each sampled leaf this instruction checks the proof: (1) the leaf is in the commitment, and
//! (2) **the rebuilt root sum equals `control_total`**. Therefore:
//! - claimed values are **fixed on-chain**, not reported (Δ's input is bound to the prior commitment);
//! - the control total is **cryptographically bound** to the commitment (thinning leaves the sum short and Y fires).
//!
//! An attacker faces both constraints at once: removing entries leaves the sum short and Y fires; padding the sum
//! with fabricated entries raises the defect rate and Δ fires. **The only feasible region is actually delivering.**
//! Y and Δ are not an OR of independent checks but two projections of the same commitment that must hold together.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::AuditCycle;

/// Sibling node in a disclosure proof. `is_left = true` means the sibling is on the left.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct SumSibling {
    pub hash: [u8; 32],
    pub sum: u64,
    pub is_left: bool,
}

pub fn handler(
    ctx: Context<VerifyDisclosure>,
    outcome_id: [u8; 32],
    beneficiary: Pubkey,
    value: u64,
    siblings: Vec<SumSibling>,
) -> Result<()> {
    let audit = &mut ctx.accounts.audit;

    // Stage: sampled.
    require!(
        audit.stage == AuditStage::Sampled as u8,
        TorusError::InvalidAuditStage
    );
    require!(
        (audit.verify_cursor as usize) < (audit.sample_size as usize),
        TorusError::DisclosuresAlreadyComplete
    );

    // Leaves are verified in sample_indices order; the fixed order prevents counting one twice.
    let index = audit.sample_indices[audit.verify_cursor as usize];

    // --- The leaf is in the commitment; rebuild the root sum at the same time ---
    let (root_commitment, root_sum) =
        fold_sum_proof(index, &outcome_id, &beneficiary, value, &siblings, audit.population_size)?;
    require!(
        root_commitment == audit.commitment_value,
        TorusError::DisclosureProofInvalid
    );

    // --- Sum binding: the total implied by the commitment == the control total ---
    //     This is what deterministically blocks thinning the population (attack Y).
    require!(
        root_sum == audit.control_total,
        TorusError::ControlTotalMismatch
    );

    // --- Fix and add the claimed value on-chain (nothing reported); keep the per-sample value ---
    audit.sample_values.push(value);
    audit.asserted_sample_sum = audit
        .asserted_sample_sum
        .checked_add(value)
        .ok_or(TorusError::MathOverflow)?;
    audit.verify_cursor = audit
        .verify_cursor
        .checked_add(1)
        .ok_or(TorusError::MathOverflow)?;

    msg!(
        "verify_disclosure: idx={} beneficiary={} value={} cursor={}/{} root_sum={}",
        index,
        beneficiary,
        value,
        audit.verify_cursor,
        audit.sample_size,
        root_sum
    );
    Ok(())
}

/// Leaf `H(LEAF_TAG ‖ index ‖ outcome_id ‖ beneficiary ‖ value)`.
pub fn leaf_hash(index: u32, outcome_id: &[u8; 32], beneficiary: &Pubkey, value: u64) -> [u8; 32] {
    keccak::hashv(&[
        &[LEAF_TAG],
        &index.to_le_bytes(),
        outcome_id,
        beneficiary.as_ref(),
        &value.to_le_bytes(),
    ])
    .0
}

/// Internal node `H(NODE_TAG ‖ Lh ‖ Ls ‖ Rh ‖ Rs)`.
pub fn node_hash(left_hash: &[u8; 32], left_sum: u64, right_hash: &[u8; 32], right_sum: u64) -> [u8; 32] {
    keccak::hashv(&[
        &[NODE_TAG],
        left_hash,
        &left_sum.to_le_bytes(),
        right_hash,
        &right_sum.to_le_bytes(),
    ])
    .0
}

/// Root commitment `H(ROOT_TAG ‖ root_hash ‖ root_sum ‖ population_size)`.
pub fn root_commitment(root_hash: &[u8; 32], root_sum: u64, population_size: u32) -> [u8; 32] {
    keccak::hashv(&[
        &[ROOT_TAG],
        root_hash,
        &root_sum.to_le_bytes(),
        &population_size.to_le_bytes(),
    ])
    .0
}

/// Folds the siblings up from the leaf and returns the root commitment
/// `H(ROOT_TAG ‖ root_hash ‖ root_sum ‖ population_size)` and the root sum.
/// verify_disclosure (sample disclosure) and payout (claims) verify the same leaves with this same function.
///
/// **The tree's shape is bound to the index and the population size**: at each level, whether a sibling exists and
/// on which side follows from (index, population_size) (an odd last node is promoted without a sibling; otherwise
/// the side follows the index parity). Siblings that do not fit this shape are rejected. Otherwise fake leaves
/// outside the declared population could inflate the control total undetected (samples only come from inside it).
pub fn fold_sum_proof(
    index: u32,
    outcome_id: &[u8; 32],
    beneficiary: &Pubkey,
    value: u64,
    siblings: &[SumSibling],
    population_size: u32,
) -> Result<([u8; 32], u64)> {
    require!(siblings.len() <= MAX_PROOF_DEPTH, TorusError::ProofTooDeep);
    require!(index < population_size, TorusError::ProofShapeMismatch);
    let mut cur_hash = leaf_hash(index, outcome_id, beneficiary, value);
    let mut cur_sum: u64 = value;
    let mut idx = index;
    let mut level_len = population_size;
    let mut next_sibling = 0usize;
    while level_len > 1 {
        let promoted = level_len % 2 == 1 && idx == level_len - 1;
        if !promoted {
            let sib = siblings
                .get(next_sibling)
                .ok_or(TorusError::ProofShapeMismatch)?;
            next_sibling += 1;
            // The sibling is on the left only when this node is on the right (odd index).
            require!(sib.is_left == (idx % 2 == 1), TorusError::ProofShapeMismatch);
            cur_hash = fold_node(&cur_hash, cur_sum, sib);
            cur_sum = cur_sum
                .checked_add(sib.sum)
                .ok_or(TorusError::MathOverflow)?;
        }
        idx /= 2;
        level_len = (level_len + 1) / 2;
    }
    // More siblings than the shape allows (a deeper tree with leaves outside the population) is rejected.
    require!(next_sibling == siblings.len(), TorusError::ProofShapeMismatch);
    Ok((root_commitment(&cur_hash, cur_sum, population_size), cur_sum))
}

/// Parent of a node and its sibling.
fn fold_node(cur_hash: &[u8; 32], cur_sum: u64, sib: &SumSibling) -> [u8; 32] {
    if sib.is_left {
        node_hash(&sib.hash, sib.sum, cur_hash, cur_sum)
    } else {
        node_hash(cur_hash, cur_sum, &sib.hash, sib.sum)
    }
}

#[derive(Accounts)]
pub struct VerifyDisclosure<'info> {
    /// Anyone may crank this (pays the transaction fee); the proof verifies itself, so no authority is needed.
    #[account(mut)]
    pub crank: Signer<'info>,

    #[account(
        mut,
        seeds = [AUDIT_SEED, audit.token.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
    )]
    pub audit: Account<'info, AuditCycle>,
}
