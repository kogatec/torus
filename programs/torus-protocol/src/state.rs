//! On-chain state accounts.

use anchor_lang::prelude::*;
use crate::constants::{MAX_SAMPLE_SIZE, MAX_UNIQ_STACK};

/// Protocol-wide configuration (singleton PDA).
#[account]
#[derive(InitSpace)]
pub struct Config {
    /// Protocol operator (registers auditors and partners, sets parameters).
    pub authority: Pubkey,
    /// Currency of the redemption pool and the bond (USDC), so the backing is not the brand token itself.
    pub usdc_mint: Pubkey,
    /// Transfer hook program ID (set on the mint at issuance).
    pub hook_program: Pubkey,
    /// Where a slashed bond goes (the protocol compensation pool, a USDC account).
    /// finalize can only slash to this address; the caller cannot choose it.
    pub slash_destination: Pubkey,
    pub bump: u8,
    /// Minimum sample size (set by the operator). A manifest with a smaller sample is rejected.
    pub min_sample_size: u16,
    /// Operator treasury (USDC). The operator's share of converted fees goes only here.
    pub treasury: Pubkey,
    /// Minimum bond target (fixed at initialize). set_issuer_terms rejects anything lower.
    pub min_bond_target: u64,
}

/// State of each issued token (issuer, tier, activity, pool accounts).
#[account]
#[derive(InitSpace)]
pub struct TokenState {
    /// The issuer (the company).
    pub issuer: Pubkey,
    /// Token-2022 mint (with TransferFee and TransferHook extensions).
    pub mint: Pubkey,
    /// Pool currency (= Config.usdc_mint).
    pub usdc_mint: Pubkey,

    /// Current tier (0..=MAX_TIER). Determines the distribution ratio.
    pub tier: u8,
    /// Consecutive passes (for promotion; any fraud or shortfall resets it).
    pub consecutive_passes: u8,
    /// Distribution ratio (bps) of the current tier.
    pub distribution_ratio_bps: u16,

    /// Activity of the last closed period, fixed on-chain (the basis of the budget).
    pub prior_period_activity: u64,
    /// Cumulative volume at the start of the current period.
    pub current_period_activity: u64,

    /// Current period ID.
    pub period_id: u64,
    /// Start of the current period.
    pub period_start_ts: i64,

    /// Provisioned redemption budget for the current cycle (the obligation). 0 = nothing provisioned.
    pub budget: u64,

    /// Target of the bond (second account). Filled from the issuer's share of converted fees.
    pub bond_target: u64,
    /// Whether the bond has reached its target (redemptions start after that).
    pub redemption_started: bool,

    /// Enforcement freeze after fraud or default.
    pub frozen: bool,

    /// Bump of the pool PDA (authority of redemption_vault and slashing_bond).
    pub pool_authority_bump: u8,
    /// First account: redemption pool (USDC token account).
    pub redemption_vault: Pubkey,
    /// Second account: slashing bond (USDC token account).
    pub slashing_bond: Pubkey,

    /// Current manifest (judging rules).
    pub manifest: Pubkey,
    pub bump: u8,

    // ⚠️ Always add new fields at the end.
    //    torus-hook reads `frozen` at byte offset 157 and `fee_vault` at 256 directly. Inserting a field
    //    earlier shifts the offsets and breaks the freeze check and the conversion exclusion.
    /// Vault (PDA-owned) where collected fees in the brand token are swept.
    pub fee_vault: Pubkey,

    // ---- Fee cross-check: fees implied by transfers vs. fees collected ----
    // The hook's counters and the fees withheld by Token-2022 (swept by harvest_fees) are produced by
    // different programs through different mechanisms. Requiring them to match exposes manipulation of
    // only one of them (e.g. inflating the volume counter).
    /// Cumulative amount swept by harvest_fees (monotonic).
    pub cumulative_harvested: u64,
    /// cumulative_harvested at the last provision (baseline for differences).
    pub last_settled_harvested: u64,
    /// Transfer fee rate (bps) burned into the mint, as verified by issue_token.
    pub transfer_fee_bps: u16,
    /// Deadline of the current audit (Unix seconds), set by provision_budget to provision time + period length.
    /// If the commitment, disclosures or uniqueness proof are still missing after it, anyone can declare a default.
    pub audit_deadline: i64,

    // ---- Splitting converted fees (operator share / issuer share → bond → redemption pool → escrow) ----
    // A registered partner buys the fee tokens for USDC; in the same instruction the USDC is
    //   1. split into the operator's share (1 − tier ratio) and the issuer's share (tier ratio);
    //      the operator's fee is never counted as bond
    //   2. from the issuer's share: the bond first, up to bond_target (set per company by the operator)
    //   3. then the redemption pool, up to what is owed (reserved + the obligation now accruing)
    //   4. the rest into the issuer escrow (claimable only after the audit finalizes)
    // No issuer key is involved on any of these paths.
    /// Minimum conversion price: USDC base units per whole brand token (10^decimals units). Set by the operator.
    pub min_conversion_price: u64,
    /// USDC account (PDA-owned) holding the issuer's share until the audit finalizes.
    pub issuer_escrow: Pubkey,
    /// Issuer share accrued in the current period. Moves to issuer_pending at the next provision.
    pub issuer_accruing: u64,
    /// Issuer share waiting for the current audit. Released on a clean result, slashed on fraud or default.
    pub issuer_pending: u64,
    /// Issuer share the issuer can claim (passed a clean audit).
    pub issuer_claimable: u64,
    /// Part of the redemption pool owed for provisioned obligations and not paid yet. Kept aside before
    /// any new provision or issuer distribution.
    pub reserved: u64,

    // ---- Start of redemptions and exit ----
    /// Whether metering has started. Set at the first provision after the bond first reaches its target.
    /// Volume before that creates no obligation.
    pub periods_started: bool,
    /// Whether the issuer has requested a voluntary exit.
    pub exit_requested: bool,
    /// Period in which the exit was requested. Its volume is provisioned and audited before the exit finalizes.
    pub exit_request_period: u64,
    /// Whether a voluntary exit has been finalized. Afterwards no provision, conversion, deposit or commitment
    /// is accepted (payouts of finalized audits and claims of the issuer share continue).
    pub exited: bool,

    // ---- Fixed period boundaries (offsets 397 and 405 are read by the transfer hook) ----
    /// Origin t0 of the period grid (when metering started). Period k is [t0 + kΔ, t0 + (k+1)Δ).
    pub grid_start_ts: i64,
    /// Period length Δ (fixed from the manifest when metering starts). 0 = not metering yet.
    pub grid_period_len: i64,

    // ---- Liquidation ----
    /// period_id of the last audit finalized without fraud (0 = none). Basis of the liquidation split.
    pub last_good_period: u64,
    /// Whether liquidation has started (after an exit or a freeze).
    pub liquidation_started: bool,
    /// Amount distributed in liquidation (redemption pool balance at the start minus amounts still owed).
    pub liquidation_pool: u64,
    /// period_id of the audit cycle used as the basis of the split.
    pub liquidation_ref_period: u64,

    // ---- Honest shortfalls are carried, not slashed ----
    /// Obligation the issuer committed to less than (obligation − control total of finalized cycles without fraud).
    /// Added to the next period's budget, so under-reporting never makes an obligation disappear.
    pub unfulfilled: u64,
}

/// Judging rules, fixed before the ledger is built.
#[account]
#[derive(InitSpace)]
pub struct Manifest {
    pub token: Pubkey,
    /// Return rate (bps): obligation = period volume × this.
    pub return_rate_bps: u16,
    /// Per-element tolerance (bps) of the deviation check (Δ).
    pub tolerance_bps: u16,
    /// Shortfall tolerance (bps) of the completeness check (Y).
    pub shortfall_tolerance_bps: u16,
    /// Floor: the return rate must be at least this.
    pub min_return_rate_bps: u16,
    /// Independent auditor. Must differ from the issuer.
    pub auditor: Pubkey,
    /// Whether the manifest is active.
    pub active: bool,
    /// Period length (seconds).
    pub period_len: i64,
    /// Expiry (Unix seconds). No new commitment is accepted under an expired manifest; set_manifest
    /// fixes new rules (the next campaign). Two layers: manifest term (campaign) ⊃ settlement periods.
    pub valid_until: i64,
    pub bump: u8,
    /// Sample size (fixed in advance; at least Config.min_sample_size). Snapshotted into the cycle at
    /// commit, so whoever designates the sample cannot choose it.
    pub sample_size: u16,
    /// Allowed defect count k (sampled elements deviating beyond the tolerance). More than k is
    /// overstatement. A count, not a ratio: comparing the defect ratio with the per-element tolerance lets
    /// defects through as the sample grows (29 samples at 5% tolerance: one defect = 3.4% passes).
    pub max_defects: u16,
}

/// Audit cycle (commit → sample → verify → atomic finalization).
#[account]
#[derive(InitSpace)]
pub struct AuditCycle {
    pub token: Pubkey,
    pub period_id: u64,

    // --- Commit ---
    /// Commitment to the whole ledger (Merkle-sum root commitment).
    pub commitment_value: [u8; 32],
    /// Control total (the issuer's declared total).
    pub control_total: u64,
    /// Declared population size.
    pub population_size: u32,
    /// Slot of the commitment (entropy must be fixed after it).
    pub committed_slot: u64,

    // --- Obligation and judging parameters, snapshotted at commit ---
    /// Obligation (= the provisioned budget at commit). finalize uses this snapshot, so a later provision
    /// cannot swap the obligation.
    pub obligation: u64,
    /// Tolerance (bps) of the deviation check, snapshotted from the manifest at commit.
    pub tolerance_bps: u16,
    /// Shortfall tolerance (bps) of the completeness check, snapshotted at commit. finalize reads this, not
    /// the manifest, so the issuer cannot loosen thresholds after observations are known.
    pub shortfall_tolerance_bps: u16,

    // --- Sample designation ---
    /// Entropy fixed after the commitment (a VRF in production).
    pub entropy: [u8; 32],
    /// Slot at which the entropy was fixed (must be after committed_slot).
    pub entropy_slot: u64,
    pub sample_size: u16,
    #[max_len(MAX_SAMPLE_SIZE)]
    pub sample_indices: Vec<u32>,

    // --- Verification ---
    /// Sum of the observed values of the sample.
    pub observed_sum: u64,
    /// Sum of the claimed values of the sample. Not reported by anyone: verify_disclosure checks each
    /// disclosure proof against the commitment and adds the value on-chain, so the input of the deviation
    /// check is bound to the issuer's prior commitment.
    pub asserted_sample_sum: u64,
    /// Number of sampled leaves whose disclosure proof has been verified (progress through sample_indices).
    /// Verification and finalization wait until this reaches sample_size.
    pub verify_cursor: u16,
    /// Number of sampled elements deviating beyond the tolerance.
    pub defect_count: u16,
    /// The cycle's auditor, snapshotted from Manifest.auditor at commit. record_verification checks the signer
    /// against it, so the auditor cannot be swapped to a colluding key mid-cycle (only replace_auditor can).
    pub auditor: Pubkey,
    /// Integrity hash of the auditor's report.
    pub report_hash: [u8; 32],

    /// Stage (AuditStage as u8).
    pub stage: u8,
    /// Result (AuditResult as u8).
    pub result: u8,
    pub bump: u8,
    /// Part of this cycle's obligation still reserved in the redemption pool and unpaid. Set to
    /// min(obligation, control total) on a clean result and reduced by payouts (payouts beyond it do not reduce it).
    pub reserved_remaining: u64,
    /// Allowed defect count (snapshotted from the manifest at commit).
    pub max_defects: u16,
    /// Claimed value of each sampled leaf (fixed by verify_disclosure from the proofs, in sample order).
    #[max_len(MAX_SAMPLE_SIZE)]
    pub sample_values: Vec<u64>,
    /// Observed value of each sampled leaf (recorded by the auditor, in sample order).
    #[max_len(MAX_SAMPLE_SIZE)]
    pub sample_observed: Vec<u64>,
    /// Whether uniqueness has been verified (payment IDs strictly increasing over all leaves, root matching,
    /// every ID registered as used).
    pub uniqueness_verified: bool,
}

/// Registered independent auditor (registered by the operator, Config.authority).
/// set_manifest can only name a registered, active auditor.
#[account]
#[derive(InitSpace)]
pub struct AuditorRecord {
    pub auditor: Pubkey,
    pub active: bool,
    pub bump: u8,
}

/// Registered exchange partner (registered by the operator). Only registered, active partners can call convert_fees.
#[account]
#[derive(InitSpace)]
pub struct PartnerRecord {
    pub partner: Pubkey,
    pub active: bool,
    pub bump: u8,
}

/// Claim record. One per audit cycle × leaf index, so the same leaf is never paid twice.
#[account]
#[derive(InitSpace)]
pub struct ClaimRecord {
    pub audit: Pubkey,
    pub index: u32,
    pub beneficiary: Pubkey,
    pub value: u64,
    pub bump: u8,
}

/// Progress of the uniqueness verification (per audit cycle). Receives all leaves in index order, checks the
/// payment IDs are strictly increasing, and rebuilds the root from subtrees.
#[account]
#[derive(InitSpace)]
pub struct UniquenessCursor {
    pub audit: Pubkey,
    /// Index of the next leaf to receive.
    pub next_index: u32,
    /// Payment ID of the previous leaf (for the strictly-increasing check).
    pub last_id: [u8; 32],
    /// Completed subtrees, left to right. Two subtrees of the same height are merged.
    #[max_len(MAX_UNIQ_STACK)]
    pub stack: Vec<UniqNode>,
    pub bump: u8,
}

/// Root of a subtree (hash, sum, height).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, InitSpace)]
pub struct UniqNode {
    pub hash: [u8; 32],
    pub sum: u64,
    pub height: u8,
}

/// Used payment-ID record (seeds = [outcome, mint, outcome_id], shared by all periods of a token).
/// A payment can be recognized only once.
#[account]
#[derive(InitSpace)]
pub struct OutcomeRecord {
    pub outcome_id: [u8; 32],
    /// The audit cycle that recognized it.
    pub audit: Pubkey,
    pub index: u32,
    pub bump: u8,
}

/// The auditor's confirmation of a single leaf. Payouts are limited to this amount, or to the observed
/// value for sampled leaves.
#[account]
#[derive(InitSpace)]
pub struct LeafAttestation {
    pub audit: Pubkey,
    pub index: u32,
    pub beneficiary: Pubkey,
    /// Amount confirmed from an independent record (at most the leaf's value).
    pub confirmed: u64,
    pub bump: u8,
}

/// Liquidation claim record (one per audit cycle × leaf index).
#[account]
#[derive(InitSpace)]
pub struct LiquidationClaim {
    pub audit: Pubkey,
    pub index: u32,
    pub beneficiary: Pubkey,
    pub amount: u64,
    pub bump: u8,
}
