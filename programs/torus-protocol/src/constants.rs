//! Protocol constants and PDA seeds.

use anchor_lang::prelude::*;

/// Denominator for ratios (basis points). 10_000 = 100%.
pub const BPS_DENOMINATOR: u64 = 10_000;

/// Highest tier (0 = base tier).
pub const MAX_TIER: u8 = 3;

/// Consecutive passes required to move up one tier (promotion is slow).
pub const PROMOTION_CONSECUTIVE_PASSES: u8 = 5;

/// Maximum sample size (bounded by the AuditCycle account allocation).
/// Each sampled leaf keeps its index, claimed value and observed value; 256 keeps the account under 10 KB.
pub const MAX_SAMPLE_SIZE: usize = 256;

/// Tier → distribution ratio (bps), indexed by tier.
/// Higher tiers return a larger share of the converted fees to the issuer (an incentive to keep promises).
pub const TIER_DISTRIBUTION_BPS: [u16; (MAX_TIER as usize) + 1] = [
    2_000, // tier 0 (base): 20%
    3_500, // tier 1: 35%
    5_000, // tier 2: 50%
    6_500, // tier 3: 65%
];

// ---- PDA seeds ----
pub const CONFIG_SEED: &[u8] = b"config";
pub const TOKEN_STATE_SEED: &[u8] = b"token_state";
pub const MANIFEST_SEED: &[u8] = b"manifest";
pub const AUDIT_SEED: &[u8] = b"audit";
pub const POOL_AUTHORITY_SEED: &[u8] = b"pool_authority";
pub const REDEMPTION_VAULT_SEED: &[u8] = b"redemption_vault";
pub const SLASHING_BOND_SEED: &[u8] = b"slashing_bond";
/// Where collected fees (in the brand token) are swept. Owned by a PDA, so no issuer key is involved.
pub const FEE_VAULT_SEED: &[u8] = b"fee_vault";
/// Registry of independent auditors (kept by the operator, so the issuer cannot name an arbitrary key).
pub const AUDITOR_SEED: &[u8] = b"auditor";
/// Claim record (one per audit cycle × leaf index; prevents double claims).
pub const CLAIM_SEED: &[u8] = b"claim";
/// USDC account (PDA-owned) holding the issuer's share until the audit finalizes.
pub const ISSUER_ESCROW_SEED: &[u8] = b"issuer_escrow";
/// Registry of exchange partners that convert fees (kept by the operator).
pub const PARTNER_SEED: &[u8] = b"partner";
/// Progress of the uniqueness verification (one per audit cycle).
pub const UNIQ_SEED: &[u8] = b"uniq";
/// Used payment-ID registry (seeds = [outcome, mint, outcome_id]; shared by all periods of a token,
/// so the same payment is never recognized twice).
pub const OUTCOME_SEED: &[u8] = b"outcome";
/// Auditor's confirmation of a single leaf (audit cycle × leaf index).
pub const ATTEST_SEED: &[u8] = b"attest";
/// Liquidation claim record (audit cycle × leaf index).
pub const LIQUIDATION_SEED: &[u8] = b"liq";
/// Maximum number of subtrees kept while verifying uniqueness (supports up to 2^32 leaves).
pub const MAX_UNIQ_STACK: usize = 33;

/// Upper bound (bps) on the per-element tolerance of the deviation check (Δ). Above this, overstatement
/// could no longer be detected.
pub const MAX_TOLERANCE_BPS: u16 = 2_000;
/// Upper bound (bps) on the shortfall tolerance of the completeness check (Y).
pub const MAX_SHORTFALL_TOLERANCE_BPS: u16 = 2_000;

/// Upper bound on the allowed defect count, as a share of the sample size (bps): 20%.
pub const MAX_DEFECT_RATE_BPS: u64 = 2_000;

/// On a voluntary exit, the share of the remaining bond returned to the issuer (bps); the rest goes to the
/// operator treasury (Config.treasury). On a forced exit for a violation (fraud, refusal to disclose,
/// missing commitment) the whole bond is slashed (finalize_audit / declare_default).
pub const EXIT_ISSUER_SHARE_BPS: u16 = 5_000;

/// Maximum depth of a disclosure proof (Merkle sum tree). Supports up to 2^32 elements.
pub const MAX_PROOF_DEPTH: usize = 32;

/// Downside tolerance (bps) of the fee cross-check: 30%.
/// Collected fees can lag the expected fees (per-transfer fee cap, accounts not harvested yet), so only a
/// shortfall up to this band is tolerated. Collecting more than expected is never tolerated.
pub const CROSS_CHECK_TOLERANCE_BPS: u64 = 3_000;

// ---- Domain-separation tags of the sum-bound commitment (Merkle sum tree) ----
/// Leaf: H(LEAF_TAG || index_le_u32 || outcome_id(32) || beneficiary(32) || value_le_u64), sum = value
pub const LEAF_TAG: u8 = 0x00;
/// Internal node: H(NODE_TAG || left_hash || left_sum_le || right_hash || right_sum_le), sum = left + right
pub const NODE_TAG: u8 = 0x01;
/// Root commitment: H(ROOT_TAG || root_hash || root_sum_le || population_size_le_u32)
/// Including root_sum binds the control total to the commitment cryptographically.
pub const ROOT_TAG: u8 = 0x02;

/// Stage of an audit cycle.
#[repr(u8)]
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuditStage {
    Committed = 0,
    Sampled = 1,
    Verified = 2,
    Finalized = 3,
}

/// Outcome of an audit.
#[repr(u8)]
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuditResult {
    Pending = 0,
    Pass = 1,
    /// Attack X (overstatement, fabricated entries), detected by the deviation check (Δ).
    FraudOverstatement = 2,
    /// Attack Y (understatement, thinning the population), detected by the completeness check (Y).
    /// Also used for a default (missing disclosure or uniqueness proof by the deadline).
    FraudUnderstatement = 3,
    /// Honest shortfall within the tolerance band. Progress resets, nothing is slashed.
    HonestShortfall = 4,
}
