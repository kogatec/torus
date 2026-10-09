//! Törus core program.
//!
//! Verifies promises that cannot prove themselves (returns delivered off-chain): it excludes both
//! overstatement (attack X) and understatement (attack Y) and closes each audit atomically, and it builds
//! this into how a Token-2022 brand token is issued and operated.
//!
//! The program id below is the local test key. With your own keys run `anchor keys sync`
//! (and update TORUS_PROTOCOL_ID in the hook by hand).

use anchor_lang::prelude::*;

pub mod constants;
pub mod errors;
pub mod state;
pub mod instructions;

use instructions::*;

declare_id!("6n1Nme9H1aUoXY2P2RaHBVWKAHHyEVPjx9n8WdU8oGdR");

#[program]
pub mod torus_protocol {
    use super::*;

    /// Initializes the protocol: USDC mint, transfer hook program id, the compensation pool that receives
    /// slashed bonds, the operator treasury, the minimum sample size and the minimum bond target.
    /// Only the program's upgrade authority can call it.
    pub fn initialize(
        ctx: Context<Initialize>,
        usdc_mint: Pubkey,
        hook_program: Pubkey,
        slash_destination: Pubkey,
        treasury: Pubkey,
        min_sample_size: u16,
        min_bond_target: u64,
    ) -> Result<()> {
        instructions::initialize::handler(
            ctx,
            usdc_mint,
            hook_program,
            slash_destination,
            treasury,
            min_sample_size,
            min_bond_target,
        )
    }

    /// Registers a Token-2022 mint with the TransferFee and TransferHook extensions after checking that no
    /// issuer key can change the rules, and creates its TokenState and USDC accounts (redemption pool,
    /// slashing bond, issuer escrow, fee vault). The bond target is set by the operator (set_issuer_terms).
    pub fn issue_token(
        ctx: Context<IssueToken>,
        transfer_fee_bps: u16,
        max_fee: u64,
    ) -> Result<()> {
        instructions::issue_token::handler(ctx, transfer_fee_bps, max_fee)
    }

    /// Terms the operator sets per company: the bond target and the minimum price for converting fees
    /// (Config.authority only).
    pub fn set_issuer_terms(
        ctx: Context<SetIssuerTerms>,
        bond_target: u64,
        min_conversion_price: u64,
    ) -> Result<()> {
        instructions::set_issuer_terms::handler(ctx, bond_target, min_conversion_price)
    }

    /// Adds an exchange partner to the operator's registry (Config.authority only).
    pub fn register_partner(ctx: Context<RegisterPartner>) -> Result<()> {
        instructions::register_partner::handler(ctx)
    }

    /// A registered partner buys collected fee tokens for USDC. In the same instruction the USDC is split into
    /// the operator's share and the issuer's share, and the issuer's share goes to the bond, then the
    /// redemption pool (up to what is owed), then the issuer escrow.
    pub fn convert_fees<'info>(
        ctx: Context<'_, '_, '_, 'info, ConvertFees<'info>>,
        token_amount: u64,
        usdc_amount: u64,
    ) -> Result<()> {
        instructions::convert_fees::handler(ctx, token_amount, usdc_amount)
    }

    /// Pays the issuer share that passed a clean audit to the issuer's USDC account (anyone can call).
    pub fn claim_distribution(ctx: Context<ClaimDistribution>) -> Result<()> {
        instructions::claim_distribution::handler(ctx)
    }

    /// Replaces an auditor who did not record by the deadline, or whose registration was revoked, with another
    /// registered auditor (Config.authority only).
    pub fn replace_auditor(ctx: Context<ReplaceAuditor>) -> Result<()> {
        instructions::replace_auditor::handler(ctx)
    }

    /// Fixes the judging rules (manifest) before the ledger is built. The auditor must be registered and differ
    /// from the issuer; the return rate must be at least the floor; tolerances and the allowed defect count are
    /// capped.
    ///
    /// `term_len` (seconds) is the manifest's term (a campaign). After `valid_until` no new commitment is
    /// accepted until new rules are fixed. Two layers: the term (campaign) ⊃ settlement periods (period_id).
    pub fn set_manifest(
        ctx: Context<SetManifest>,
        return_rate_bps: u16,
        tolerance_bps: u16,
        shortfall_tolerance_bps: u16,
        min_return_rate_bps: u16,
        period_len: i64,
        term_len: i64,
        sample_size: u16,
        max_defects: u16,
    ) -> Result<()> {
        instructions::set_manifest::handler(
            ctx,
            return_rate_bps,
            tolerance_bps,
            shortfall_tolerance_bps,
            min_return_rate_bps,
            period_len,
            term_len,
            sample_size,
            max_defects,
        )
    }

    /// Closes a period: derives the obligation from the period's on-chain volume × the fixed return rate and
    /// reserves it in the redemption pool. Not available until the bond reaches its target; the first call
    /// after that only sets the metering baseline.
    pub fn provision_budget(ctx: Context<ProvisionBudget>) -> Result<()> {
        instructions::provision_budget::handler(ctx)
    }

    /// Records the commitment to the ledger and its control total, and starts the audit cycle.
    pub fn commit_performance(
        ctx: Context<CommitPerformance>,
        commitment_value: [u8; 32],
        control_total: u64,
        population_size: u32,
    ) -> Result<()> {
        instructions::commit_performance::handler(ctx, commitment_value, control_total, population_size)
    }

    /// Designates the sample from entropy fixed after the commitment (to be replaced by a VRF; for now only
    /// the post-commit ordering is enforced).
    pub fn designate_sample(ctx: Context<DesignateSample>, entropy: [u8; 32]) -> Result<()> {
        instructions::designate_sample::handler(ctx, entropy)
    }

    /// The independent auditor records the observed value of each sampled leaf, in sample order (may span
    /// several transactions). The program counts defects and sums; when all are in, the report hash is
    /// recorded and the cycle moves to Verified.
    pub fn record_verification(
        ctx: Context<RecordVerification>,
        observed_values: Vec<u64>,
        report_hash: [u8; 32],
    ) -> Result<()> {
        instructions::record_verification::handler(ctx, observed_values, report_hash)
    }

    /// Verifies a disclosure proof (sum-bound commitment), one sampled leaf at a time: the proof against the
    /// commitment and "rebuilt root sum == control total". The claimed value is fixed and summed on-chain, so
    /// the deviation check is bound to the issuer's prior commitment and the population cannot be thinned.
    pub fn verify_disclosure(
        ctx: Context<VerifyDisclosure>,
        outcome_id: [u8; 32],
        beneficiary: Pubkey,
        value: u64,
        siblings: Vec<SumSibling>,
    ) -> Result<()> {
        instructions::verify_disclosure::handler(ctx, outcome_id, beneficiary, value, siblings)
    }

    /// Verifies uniqueness: receives all leaves in index order, checks payment IDs are strictly increasing and
    /// the root matches, and registers each payment ID in the token's used-ID registry (shared by all periods).
    /// Large ledgers span several transactions; `restart` starts over.
    pub fn verify_uniqueness<'info>(
        ctx: Context<'_, '_, '_, 'info, VerifyUniqueness<'info>>,
        leaves: Vec<UniqLeaf>,
        restart: bool,
    ) -> Result<()> {
        instructions::verify_uniqueness::handler(ctx, leaves, restart)
    }

    /// The auditor confirms a single leaf from an independent record. Payouts and liquidation are limited to
    /// this amount, or to the observed value for sampled leaves.
    #[allow(clippy::too_many_arguments)]
    pub fn attest_leaf(
        ctx: Context<AttestLeaf>,
        index: u32,
        outcome_id: [u8; 32],
        beneficiary: Pubkey,
        value: u64,
        siblings: Vec<SumSibling>,
        confirmed: u64,
    ) -> Result<()> {
        instructions::attest_leaf::handler(ctx, index, outcome_id, beneficiary, value, siblings, confirmed)
    }

    /// Atomic finalization: the completeness check (control total vs. obligation, attack Y), the deviation check
    /// (claimed vs. observed, attack X), the tier update and the release or slash, all in one instruction,
    /// before any payout of the cycle is possible (no window to take the money and run).
    pub fn finalize_audit(ctx: Context<FinalizeAudit>) -> Result<()> {
        instructions::finalize_audit::handler(ctx)
    }

    /// Voluntary USDC deposit into the pool (in addition to the forced deposit through convert_fees). Fills the
    /// bond up to its target first, then the redemption pool; reaching the target sets redemption_started.
    pub fn deposit_pool(ctx: Context<DepositPool>, amount: u64) -> Result<()> {
        instructions::deposit_pool::handler(ctx, amount)
    }

    /// Sweeps withheld fees into the fee vault, signed only by the protocol PDA, with no issuer key involved.
    /// Anyone can call it, so the issuer cannot avoid funding the pool by doing nothing.
    pub fn harvest_fees<'info>(ctx: Context<'_, '_, '_, 'info, HarvestFees<'info>>) -> Result<()> {
        instructions::harvest_fees::handler(ctx)
    }

    /// Pays a committed leaf from the redemption pool: only after the cycle is finalized without fraud, only to
    /// the leaf's recipient, once, and up to the confirmed amount. This instruction is the point before which
    /// finalization must happen.
    pub fn payout(
        ctx: Context<Payout>,
        index: u32,
        outcome_id: [u8; 32],
        value: u64,
        siblings: Vec<SumSibling>,
    ) -> Result<()> {
        instructions::payout::handler(ctx, index, outcome_id, value, siblings)
    }

    /// Adds an independent auditor to the operator's registry (Config.authority only).
    pub fn register_auditor(ctx: Context<RegisterAuditor>) -> Result<()> {
        instructions::register_auditor::handler(ctx)
    }

    /// Revokes an auditor's registration (operator only). A revoked auditor cannot be named for a new cycle,
    /// record observations or confirm leaves; ongoing cycles are moved to another auditor with replace_auditor
    /// without waiting for the deadline.
    pub fn revoke_auditor(ctx: Context<RevokeAuditor>) -> Result<()> {
        instructions::revoke_auditor::handler(ctx)
    }

    /// Declares a default when the commitment, disclosures or uniqueness proof are missing after the deadline.
    /// Anyone can call it.
    pub fn declare_default(ctx: Context<DeclareDefault>) -> Result<()> {
        instructions::declare_default::handler(ctx)
    }

    /// The issuer requests a voluntary exit. The exit is final only after the volume up to the requested period
    /// is provisioned and audited.
    pub fn request_exit(ctx: Context<RequestExit>) -> Result<()> {
        instructions::request_exit::handler(ctx)
    }

    /// Finalizes a voluntary exit (anyone can call): half the bond goes to the issuer, the rest to the operator treasury.
    pub fn finalize_exit(ctx: Context<FinalizeExit>) -> Result<()> {
        instructions::finalize_exit::handler(ctx)
    }

    /// Starts liquidation after an exit or a freeze (anyone can call): fixes the redemption pool's surplus
    /// beyond the amounts still owed.
    pub fn start_liquidation(ctx: Context<StartLiquidation>) -> Result<()> {
        instructions::start_liquidation::handler(ctx)
    }

    /// Pays a liquidation share to a leaf recipient of the basis audit, pro rata to the confirmed amount.
    pub fn claim_liquidation(
        ctx: Context<ClaimLiquidation>,
        index: u32,
        outcome_id: [u8; 32],
        value: u64,
        siblings: Vec<SumSibling>,
    ) -> Result<()> {
        instructions::claim_liquidation::handler(ctx, index, outcome_id, value, siblings)
    }
}
