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
pub mod rules;
pub mod tax_rules;

use constants::TIERS;
use instructions::*;
use state::PerkParams;

declare_id!("6n1Nme9H1aUoXY2P2RaHBVWKAHHyEVPjx9n8WdU8oGdR");

#[program]
pub mod torus_protocol {
    use super::*;

    /// Initializes the protocol: USDC mint, transfer hook program id, the compensation pool that receives
    /// slashed bonds, the operator treasury, the minimum sample size and the minimum bond target. Only the program's
    /// upgrade authority can call it.
    /// It also fixes the hold period of the tax reconciliation.
    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        ctx: Context<Initialize>,
        usdc_mint: Pubkey,
        hook_program: Pubkey,
        slash_destination: Pubkey,
        treasury: Pubkey,
        min_sample_size: u16,
        min_bond_target: u64,
        tax_hold_period: i64,
    ) -> Result<()> {
        instructions::initialize::handler(
            ctx,
            usdc_mint,
            hook_program,
            slash_destination,
            treasury,
            min_sample_size,
            min_bond_target,
            tax_hold_period,
        )
    }

    /// Registers a Token-2022 mint with the TransferFee and TransferHook extensions after checking that no
    /// issuer key can change the rules, and creates its TokenState and USDC accounts (redemption pool,
    /// slashing bond, issuer escrow, fee vault). The bond target is set by the operator (set_issuer_terms).
    /// The mint authority moves to the program: afterwards only restamp mints, never more than it burns.
    pub fn issue_token(
        ctx: Context<IssueToken>,
        transfer_fee_bps: u16,
        max_fee: u64,
    ) -> Result<()> {
        instructions::issue_token::handler(ctx, transfer_fee_bps, max_fee)
    }

    /// Terms the operator sets per company: the bond target, the minimum price for converting fees, the issuer's
    /// share per rank and the local partner (Config.authority only).
    pub fn set_issuer_terms(
        ctx: Context<SetIssuerTerms>,
        bond_target: u64,
        min_conversion_price: u64,
        tier_share_bps: [u16; TIERS],
    ) -> Result<()> {
        instructions::set_issuer_terms::handler(ctx, bond_target, min_conversion_price, tier_share_bps)
    }

    /// Adds an exchange partner to the operator's registry (Config.authority only).
    pub fn register_partner(ctx: Context<RegisterPartner>) -> Result<()> {
        instructions::register_partner::handler(ctx)
    }

    /// A registered partner buys collected fee tokens for USDC. In the same instruction the USDC is split into
    /// the operator's share and the issuer's share, and the issuer's share goes to the bond, then the
    /// redemption pool (up to what is owed), then the issuer escrow (after an exit: to the redemption pool).
    pub fn convert_fees<'info>(
        ctx: Context<'_, '_, '_, 'info, ConvertFees<'info>>,
        token_amount: u64,
        usdc_amount: u64,
    ) -> Result<()> {
        instructions::convert_fees::handler(ctx, token_amount, usdc_amount)
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
    /// `term_len` (seconds) is the manifest's term (a campaign). A period that starts after `valid_until` gets no
    /// obligation until new rules are fixed. Two layers: the term (campaign) ⊃ settlement periods (period_id).
    /// During a campaign nothing may change in the issuer's favor, and every period keeps the terms in force when it
    /// started. `use_plan_hash` is the hash of the use plan for the issuer escrow.
    #[allow(clippy::too_many_arguments)]
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
        use_plan_hash: [u8; 32],
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
            use_plan_hash,
        )
    }

    /// Closes a period: derives the obligation from the period's on-chain volume × the return rate in force when the
    /// period started (none between campaigns) and reserves it in the redemption pool. Not available until the bond reaches its target; the first call
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

    /// Finalizes a voluntary exit (anyone can call): the issuer's half of the bond and what is left in the escrow go to
    /// the redemption pool (its customers, through liquidation), the rest of the bond to the operator treasury.
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

    /// Revokes an exchange partner's registration (operator only). A revoked partner cannot convert fees or approve
    /// escrow payments, and an issuer whose escrow partner was revoked may pick another one during a campaign.
    pub fn revoke_partner(ctx: Context<RevokePartner>) -> Result<()> {
        instructions::revoke_partner::handler(ctx)
    }

    /// The issuer picks the registered partner that manages its escrow (one per token; locked during a campaign
    /// unless revoked). The partner, the auditor and the issuer are different keys; the partner is not the operator.
    pub fn set_escrow_partner(ctx: Context<SetEscrowPartner>) -> Result<()> {
        instructions::set_escrow_partner::handler(ctx)
    }

    /// The issuer requests a payment from its escrow: an item of the use plan, the amount (within the balance released
    /// by clean audits), the payee (not the issuer) and the invoice hash (used once). With `from_bond` the payment comes
    /// from the bond instead, which must keep at least half of its target (later fees refill it; redemptions go on).
    pub fn request_withdrawal(
        ctx: Context<RequestWithdrawal>,
        plan_item: u16,
        amount: u64,
        invoice_hash: [u8; 32],
        from_bond: bool,
    ) -> Result<()> {
        instructions::request_withdrawal::handler(ctx, plan_item, amount, invoice_hash, from_bond)
    }

    /// The escrow partner or the manifest's auditor approves a request; with both approvals it pays the payee straight
    /// from the escrow. The operator and the issuer cannot approve.
    pub fn approve_withdrawal(ctx: Context<ApproveWithdrawal>) -> Result<()> {
        instructions::approve_withdrawal::handler(ctx)
    }

    // ============================ Tax accountant reconciliation ============================

    /// Registers the company's tax accountant (operator; the accountant signs its consent to the warning).
    pub fn register_tax_accountant(ctx: Context<RegisterTaxAccountant>, consent_hash: [u8; 32]) -> Result<()> {
        instructions::tax_accountant::register(ctx, consent_hash)
    }

    /// Revokes the company's tax accountant (operator).
    pub fn revoke_tax_accountant(ctx: Context<RevokeTaxAccountant>) -> Result<()> {
        instructions::tax_accountant::revoke(ctx)
    }

    /// Replaces the company's tax accountant (operator; the new accountant signs its consent).
    pub fn replace_tax_accountant(ctx: Context<ReplaceTaxAccountant>, consent_hash: [u8; 32]) -> Result<()> {
        instructions::tax_accountant::replace(ctx, consent_hash)
    }

    /// The tax accountant reports the book's sub-account total for the cycle being audited (by the audit deadline; during
    /// a hold, a reconciled report until the hold ends).
    pub fn file_tax_report(ctx: Context<FileTaxReport>, book_total: u64, report_hash: [u8; 32]) -> Result<()> {
        instructions::file_tax_report::handler(ctx, book_total, report_hash)
    }

    // ============================ Distribution ============================

    /// Registers a local partner with its share of the operator's fee and its USDC account (operator).
    pub fn register_local_partner(ctx: Context<RegisterLocalPartner>, share_bps: u16) -> Result<()> {
        instructions::local_partner::register(ctx, share_bps)
    }

    /// Revokes a local partner (operator): no more restamps; its share goes to the treasury.
    pub fn revoke_local_partner(ctx: Context<RevokeLocalPartner>) -> Result<()> {
        instructions::local_partner::revoke(ctx)
    }

    // ============================ Perks ============================

    /// Perk terms negotiated with the company (operator).
    pub fn set_perk_terms(ctx: Context<SetPerkTerms>, params: PerkParams) -> Result<()> {
        instructions::perk_terms::handler(ctx, params)
    }

    /// Registers a merchant (issuer).
    pub fn register_merchant(ctx: Context<RegisterMerchant>) -> Result<()> {
        instructions::merchant::register(ctx)
    }

    /// Revokes a merchant (issuer).
    pub fn revoke_merchant(ctx: Context<RevokeMerchant>) -> Result<()> {
        instructions::merchant::revoke(ctx)
    }

    /// Registers one of the holder's token accounts for perks (its balance starts stamped at 0%).
    pub fn register_holder(ctx: Context<RegisterHolder>) -> Result<()> {
        instructions::register_holder::handler(ctx)
    }

    /// Opens the current period's perk budget: the previous obligation × the allocation (anyone).
    pub fn open_perk_period(ctx: Context<OpenPerkPeriod>) -> Result<()> {
        instructions::open_perk_period::handler(ctx)
    }

    /// Records a perk (trader or hold), signed by a registered merchant and the holder.
    pub fn redeem_perk(ctx: Context<RedeemPerk>, kind: u8, amount: u64, receipt_id: [u8; 32]) -> Result<()> {
        instructions::redeem_perk::handler(ctx, kind, amount, receipt_id)
    }

    /// Burns, re-mints the same amount (minus the fee to the local partner) and restamps, signed by the holder and the
    /// local partner.
    pub fn restamp(ctx: Context<Restamp>, amount: u64) -> Result<()> {
        instructions::restamp::handler(ctx, amount)
    }

    /// Sets aside part of a trader perk for customers, signed by the seller and the local partner.
    pub fn list_perk(ctx: Context<ListPerk>, amount: u64) -> Result<()> {
        instructions::perk_lot::list(ctx, amount)
    }

    /// Returns a lot's rent to the seller after its period is closed.
    pub fn close_perk_lot(ctx: Context<ClosePerkLot>) -> Result<()> {
        instructions::perk_lot::close(ctx)
    }
}
