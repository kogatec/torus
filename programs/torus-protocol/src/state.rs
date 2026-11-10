//! On-chain state accounts.

use anchor_lang::prelude::*;
use crate::constants::{HOLD_STEPS, MAX_SAMPLE_SIZE, MAX_UNIQ_STACK, TIERS};

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
    /// How long a cycle waits for the tax accountant's reconciled report when the declared total exceeds the book
    /// total (seconds). Fixed by the operator at initialize; no company can change it.
    pub tax_hold_period: i64,
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
    //   4. the rest into the issuer escrow (released by a clean audit, spent only through approved withdrawal requests)
    // No issuer key is involved on any of these paths.
    /// Minimum conversion price: USDC base units per whole brand token (10^decimals units). Set by the operator.
    pub min_conversion_price: u64,
    /// USDC account (PDA-owned) holding the issuer's share. It belongs to the issuer but the issuer cannot spend it freely:
    /// a payment needs the approval of the escrow partner and of the auditor (approve_withdrawal).
    pub issuer_escrow: Pubkey,
    /// Issuer share accrued in the current period. Moves to issuer_pending at the next provision.
    pub issuer_accruing: u64,
    /// Issuer share waiting for the current audit. Released on a clean result, slashed on fraud or default.
    pub issuer_pending: u64,
    /// Issuer share released by a clean audit. It stays in the escrow; withdrawal requests can spend up to this.
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
    /// Amount distributed in liquidation (redemption pool balance at the start minus amounts still owed), plus the
    /// issuer shares that arrive after the start (cumulative; each leaf is paid up to its share of this total).
    pub liquidation_pool: u64,
    /// period_id of the audit cycle used as the basis of the split.
    pub liquidation_ref_period: u64,

    // ---- Honest shortfalls are carried, not slashed ----
    /// Obligation the issuer committed to less than (obligation − control total of finalized cycles without fraud).
    /// Added to the next period's budget, so under-reporting never makes an obligation disappear.
    pub unfulfilled: u64,

    // ---- Issuer escrow and the terms of the cycle being audited ----
    /// Registered partner managing the issuer escrow (picked by the issuer; default = none).
    pub escrow_partner: Pubkey,
    /// Terms of the period whose obligation was last provisioned (those in force when it started). commit_performance
    /// snapshots the judging parameters from here, so a later manifest cannot change how that period is judged.
    pub cycle_terms: ManifestTerms,

    // ---- Terms negotiated per company (set by the operator with set_issuer_terms) ----
    /// The issuer's share of converted fees for ranks 0..=3 (bps). A higher rank never gets less.
    /// distribution_ratio_bps is the entry of the current tier.
    pub tier_share_bps: [u16; TIERS],
    /// The company's local partner (operates restamps; takes its share of the operator's fee). Default = not set.
    pub local_partner: Pubkey,
}

impl TokenState {
    /// Index of the period containing `now` on the fixed grid (0 before metering starts), as the hook computes it.
    pub fn grid_index(&self, now: i64) -> u64 {
        torus_hook::grid_index(now, self.grid_start_ts, self.grid_period_len)
    }
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
    /// When the terms above took effect (the last set_manifest). A period that started earlier keeps prev_terms.
    pub valid_from: i64,
    /// Terms in force before valid_from, for periods that started before the last change and are not closed yet.
    pub prev_terms: ManifestTerms,
    /// Hash of the use plan for the issuer escrow (the items and their caps are an off-chain document).
    pub use_plan_hash: [u8; 32],
}

/// The terms of a manifest that decide a period's obligation and how its audit is judged.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, InitSpace)]
pub struct ManifestTerms {
    pub return_rate_bps: u16,
    pub tolerance_bps: u16,
    pub shortfall_tolerance_bps: u16,
    pub sample_size: u16,
    pub max_defects: u16,
    /// End of the campaign. A period that starts after it (a gap between campaigns) gets no obligation.
    pub valid_until: i64,
}

impl Manifest {
    /// The current terms.
    pub fn terms(&self) -> ManifestTerms {
        ManifestTerms {
            return_rate_bps: self.return_rate_bps,
            tolerance_bps: self.tolerance_bps,
            shortfall_tolerance_bps: self.shortfall_tolerance_bps,
            sample_size: self.sample_size,
            max_defects: self.max_defects,
            valid_until: self.valid_until,
        }
    }

    /// Terms of a period that started at `start`: those in force at that time.
    pub fn terms_at(&self, start: i64) -> ManifestTerms {
        if start >= self.valid_from {
            self.terms()
        } else {
            self.prev_terms
        }
    }
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
    /// End of the hold set by finalize_audit when the declared total exceeded the tax accountant's book total
    /// (0 = no hold). Payouts wait; a reconciled report within the hold resumes the cycle, none forfeits it.
    pub tax_hold_until: i64,
    /// Total recognized when the cycle was finalized without fraud: the control total, or the book total when the tax
    /// reconciliation capped it. Each payout is scaled by it ÷ the control total (tax_rules::recognized_share).
    pub recognized_total: u64,
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
    /// Total paid to this leaf so far (its share of the cumulative liquidation pool).
    pub amount: u64,
    pub bump: u8,
}

/// The issuer's request to pay from its escrow (one per invoice hash: the address is derived from it).
#[account]
#[derive(InitSpace)]
pub struct WithdrawalRequest {
    pub token: Pubkey,
    /// Use plan in force when the request was filed (Manifest.use_plan_hash).
    pub plan_hash: [u8; 32],
    /// Item of the use plan the payment falls under (the items and their caps are in the off-chain plan).
    pub plan_item: u16,
    pub amount: u64,
    /// The payee's USDC account (not owned by the issuer).
    pub payee: Pubkey,
    pub invoice_hash: [u8; 32],
    /// Key that approved as the escrow partner (default = not yet).
    pub partner_approval: Pubkey,
    /// Key that approved as the auditor (default = not yet).
    pub auditor_approval: Pubkey,
    pub executed: bool,
    pub bump: u8,
    /// Paid from the bond (second account) instead of the escrow. The bond may only go down to half of its target.
    pub from_bond: bool,
}

/// The account at `ai` as T, if `owner` owns it and it holds data (for PDAs that may not exist yet).
pub fn load_if_exists<T: AccountDeserialize>(ai: &AccountInfo, owner: &Pubkey) -> Result<Option<T>> {
    if ai.owner != owner || ai.data_is_empty() {
        return Ok(None);
    }
    let data = ai.try_borrow_data()?;
    Ok(Some(T::try_deserialize(&mut &data[..])?))
}

// ============================ Tax accountant reconciliation ============================

/// The company's tax accountant (or CPA), one per token. Registered by the operator; the accountant signs too,
/// accepting that a false report is referred to the authority supervising its license.
#[account]
#[derive(InitSpace)]
pub struct TaxAccountantRecord {
    pub token: Pubkey,
    pub accountant: Pubkey,
    /// Hash of the signed consent (the warning and the release from confidentiality), kept off-chain.
    pub consent_hash: [u8; 32],
    pub active: bool,
    pub bump: u8,
}

/// The tax accountant's report for a cycle: the total of the book's sub-account for Torus returns. The accountant
/// never sees the company's declared figure.
#[account]
#[derive(InitSpace)]
pub struct TaxReport {
    pub token: Pubkey,
    /// The audit cycle reported on (AuditCycle.period_id).
    pub period_id: u64,
    pub accountant: Pubkey,
    pub book_total: u64,
    /// Hash of the report document.
    pub report_hash: [u8; 32],
    pub filed_ts: i64,
    /// Filed again during a hold (a reconciled report).
    pub refiled: bool,
    pub bump: u8,
}

// ============================ Distribution ============================

/// Local partner registered by the operator. It operates restamps for the companies it serves and receives its
/// share of the operator's fee on every conversion.
#[account]
#[derive(InitSpace)]
pub struct LocalPartnerRecord {
    pub partner: Pubkey,
    /// The partner's USDC account (fixed at registration; conversions pay its share only here).
    pub usdc_account: Pubkey,
    /// Share of the operator's fee (bps), decided at registration.
    pub share_bps: u16,
    pub active: bool,
    pub bump: u8,
}

// ============================ Perks ============================

/// Perk terms negotiated per company (set by the operator). The rules fixed in code are checked in rules.rs.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, InitSpace)]
pub struct PerkParams {
    /// How the obligation is delivered: general returns ≥ trader perk ≥ hold perk, 100% in total (bps).
    pub general_bps: u16,
    pub trader_bps: u16,
    pub hold_bps: u16,
    /// Hold perk rate by time since the stamp, one entry per step; 0% after the last step (non-increasing).
    pub hold_rate_bps: [u16; HOLD_STEPS],
    /// Length of one step (seconds).
    pub hold_step_secs: i64,
    /// Purchases eligible for the hold perk per whole token of the period's minimum balance (obligation units).
    pub cap_per_token: u64,
    /// Restamp fee (bps of the restamped amount), paid to the local partner in tokens. 0 works.
    pub restamp_fee_bps: u16,
    /// Highest ask for listed trader perks (bps of the face value). 0 = this company does not allow listing.
    pub max_ask_bps: u16,
    /// Share of a bill that listed trader perks may pay (bps). 0 = this company does not allow listing.
    pub usage_cap_bps: u16,
}

#[account]
#[derive(InitSpace)]
pub struct PerkTerms {
    pub token: Pubkey,
    pub params: PerkParams,
    pub bump: u8,
}

/// Perk budget of a period: the previous period's obligation × the allocation. Perks cannot exceed it, so the rest
/// of the obligation can only be delivered as general returns.
#[account]
#[derive(InitSpace)]
pub struct PerkPeriod {
    pub token: Pubkey,
    pub period_id: u64,
    pub trader_budget: u64,
    pub hold_budget: u64,
    /// Trader perk rate (bps of the volume a registered account sent in the previous period): the budget divided by
    /// the volume of all registered accounts, at most half the transfer fee rate (self-dealing always loses).
    pub trader_rate_bps: u16,
    pub trader_used: u64,
    pub hold_used: u64,
    pub bump: u8,
    /// Rate of last period's volume that can be listed for sale (rules::listable_rate_bps). Fixed with the budget.
    pub listable_rate_bps: u16,
    /// The company's ask cap and usage cap, fixed for the period so a later change of terms cannot affect its lots.
    pub max_ask_bps: u16,
    pub usage_cap_bps: u16,
}

/// Merchant registered by the issuer (perks are redeemed only with a registered merchant's signature).
#[account]
#[derive(InitSpace)]
pub struct MerchantRecord {
    pub token: Pubkey,
    pub merchant: Pubkey,
    pub active: bool,
    pub bump: u8,
}

/// Perk usage of a registered token account in its current period (reset when the period changes).
#[account]
#[derive(InitSpace)]
pub struct HolderPerk {
    pub token: Pubkey,
    /// The registered token account.
    pub account: Pubkey,
    pub period_id: u64,
    /// Trader perks used or listed this period.
    pub trader_used: u64,
    /// Purchases that used the hold perk this period (capped by minimum balance × cap per token).
    pub hold_spend: u64,
    pub bump: u8,
}

impl HolderPerk {
    /// Starts the period's counts over the first time the account is used in a new period.
    pub fn enter_period(&mut self, period: u64) {
        if self.period_id != period {
            self.period_id = period;
            self.trader_used = 0;
            self.hold_spend = 0;
        }
    }
}

/// Trader perks a seller set aside for customers in a period. The right moves to a customer at checkout (off-chain) and
/// is used on the spot; the issuer's ledger pays the merchant and the seller through the existing audit and payout.
#[account]
#[derive(InitSpace)]
pub struct PerkLot {
    pub token: Pubkey,
    pub period_id: u64,
    /// The seller's registered token account the perks came from.
    pub account: Pubkey,
    pub seller: Pubkey,
    /// Face value set aside so far (obligation units).
    pub listed: u64,
    pub bump: u8,
}

/// Receipt of a perk redemption. It goes into the issuer's ledger and through the existing audit and payout.
#[account]
#[derive(InitSpace)]
pub struct PerkReceipt {
    pub token: Pubkey,
    pub period_id: u64,
    pub account: Pubkey,
    pub merchant: Pubkey,
    pub kind: u8,
    /// Discount delivered (obligation units).
    pub discount: u64,
    pub bump: u8,
}
