//! designate_sample / designate_without_seed: fix the entropy of a cycle's sample.
//!
//! The entropy mixes two inputs that nobody controls together (sampling.rs):
//!   - the operator's seed, whose commitment was snapshotted into the cycle when the issuer committed its ledger;
//!   - the hash of a slot fixed at commit, captured by capture_entropy.
//! The issuer cannot predict the sample (it never sees the seed before the sample is fixed), and the operator cannot
//! choose it (its seed was fixed before the slot hash existed). Samples are then positions of the ledger's running
//! sum derived from this entropy, so a leaf is drawn in proportion to its value (verify_disclosure).
//!
//! designate_sample: the operator reveals the seed and posts the commitment for the next cycle.
//! designate_without_seed: if the operator has not revealed within the grace fixed at initialize, anyone continues
//!   without the seed, **with a doubled sample**. The operator can therefore neither stall an audit nor gain from
//!   withholding a seed whose sample it dislikes.
//!
//! The same entropy draws the cycle's auditor from the registry (sampling::draw_auditor), among the auditors listed
//! before the commit (so neither the operator nor the issuer picks who audits). With nobody listed before the commit,
//! the auditor named in the manifest stays.
//!
//! Once the sample is drawn, the issuer has at least one period to disclose it (deadlines::extend), however late the
//! draw came: a late reveal by the operator, or a draw without the seed after its grace, which anyone may crank, could
//! otherwise land after the audit deadline and be followed by declare_default, even in the same transaction, before the
//! issuer could disclose anything.
//!
//! TODO: a VRF (Switchboard/ORAO) would remove the remaining case, an operator that both shares its seed with the
//!   issuer and colludes with the leader of the entropy slot.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::deadlines;
use crate::errors::TorusError;
use crate::sampling;
use crate::state::{AuditCycle, AuditorEntry, AuditorRegistry, Config, TokenState};

pub fn handler(
    ctx: Context<DesignateSample>,
    seed: [u8; 32],
    next_seed_commit: [u8; 32],
) -> Result<()> {
    let audit_key = ctx.accounts.audit.key();
    let audit = &mut ctx.accounts.audit;
    require_captured(audit)?;
    require!(
        sampling::seed_commitment(&seed) == audit.seed_commit,
        TorusError::SeedMismatch
    );
    // The revealed seed is spent: the next cycle needs a fresh commitment.
    require!(
        next_seed_commit != [0u8; 32] && next_seed_commit != audit.seed_commit,
        TorusError::InvalidSeedCommit
    );
    ctx.accounts.token_state.audit_seed_commit = next_seed_commit;

    let entropy = sampling::mix_entropy(ENTROPY_SEEDED_TAG, &seed, &audit.slot_hash, &audit_key);
    let entries = read_registry(&ctx.accounts.auditor_registry)?;
    let pool = AuditorPool { entries: &entries, excluded: excluded_from_draw(&ctx.accounts.token_state) };
    fix_sample(audit, entropy, &pool, true)?;
    leave_time_to_disclose(&mut ctx.accounts.token_state, audit, Clock::get()?.unix_timestamp)
}

pub fn handler_without_seed(ctx: Context<DesignateWithoutSeed>) -> Result<()> {
    let clock = Clock::get()?;
    let grace_end = ctx
        .accounts
        .audit
        .captured_slot
        .checked_add(ctx.accounts.config.reveal_grace_slots)
        .ok_or(TorusError::MathOverflow)?;
    let audit_key = ctx.accounts.audit.key();
    let audit = &mut ctx.accounts.audit;
    require_captured(audit)?;
    require!(clock.slot > grace_end, TorusError::RevealGraceNotOver);

    let (sample_size, max_defects) = sampling::escalate(audit.sample_size, audit.max_defects);
    audit.sample_size = sample_size;
    audit.max_defects = max_defects;
    // The operator, not the issuer, held this cycle up (a late provision after it may be excused, excuses.rs).
    audit.held_up = true;
    let entropy = sampling::mix_entropy(
        ENTROPY_UNSEEDED_TAG,
        &audit.seed_commit,
        &audit.slot_hash,
        &audit_key,
    );
    let entries = read_registry(&ctx.accounts.auditor_registry)?;
    let pool = AuditorPool { entries: &entries, excluded: excluded_from_draw(&ctx.accounts.token_state) };
    fix_sample(audit, entropy, &pool, false)?;
    leave_time_to_disclose(&mut ctx.accounts.token_state, audit, clock.unix_timestamp)
}

/// After the draw, the issuer has at least one period to disclose the sample (see the module comment). The cycle being
/// drawn is always the token's current one: the next period cannot be provisioned before this cycle is final.
fn leave_time_to_disclose(token_state: &mut TokenState, audit: &AuditCycle, now: i64) -> Result<()> {
    require!(audit.period_id == token_state.period_id, TorusError::InvalidAuditStage);
    token_state.audit_deadline = deadlines::extend(token_state.audit_deadline, now, token_state.grid_period_len)?;
    Ok(())
}

/// Who the cycle's auditor can be drawn from: the registry's entries, minus the issuer and its partners.
struct AuditorPool<'a> {
    entries: &'a [AuditorEntry],
    excluded: [Pubkey; 3],
}

/// Never drawn to audit a token: its issuer and its partners (escrow and local), who are on the issuer's side.
pub fn excluded_from_draw(token_state: &TokenState) -> [Pubkey; 3] {
    [token_state.issuer, token_state.escrow_partner, token_state.local_partner]
}

/// The registry's entries; none when the registry was never created (a deployment from before it), and then the auditor
/// named in the manifest stays. The address is bound by seeds, so a caller can neither swap in another list nor skip it.
pub fn read_registry(account: &AccountInfo) -> Result<Vec<AuditorEntry>> {
    if account.data_is_empty() {
        return Ok(Vec::new());
    }
    require_keys_eq!(*account.owner, crate::ID, TorusError::Unauthorized);
    let data = account.try_borrow_data()?;
    Ok(AuditorRegistry::try_deserialize(&mut &data[..])?.entries)
}

/// The cycle is committed and its slot hash is captured.
fn require_captured(audit: &AuditCycle) -> Result<()> {
    require!(
        audit.stage == AuditStage::Committed as u8,
        TorusError::InvalidAuditStage
    );
    require!(audit.captured_slot != 0, TorusError::EntropyNotCaptured);
    Ok(())
}

fn fix_sample(audit: &mut AuditCycle, entropy: [u8; 32], pool: &AuditorPool, seeded: bool) -> Result<()> {
    audit.entropy = entropy;
    audit.stage = AuditStage::Sampled as u8;
    let draw = sampling::AuditorDraw { entropy: &entropy, committed_slot: audit.committed_slot, previous: Pubkey::default(), excluded: &pool.excluded };
    if let Some(auditor) = sampling::draw_auditor(pool.entries, &draw) {
        audit.auditor = auditor;
    }
    msg!(
        "designate_sample: mint={} period_id={} sample_size={} entropy_slot={} seeded={} auditor={}",
        audit.token,
        audit.period_id,
        audit.sample_size,
        audit.entropy_slot,
        seeded,
        audit.auditor
    );
    Ok(())
}

#[derive(Accounts)]
pub struct DesignateSample<'info> {
    /// The operator (Config.authority): the only one who knows the seed.
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

    /// The audited token's state: receives the seed commitment for the next cycle.
    #[account(
        mut,
        seeds = [TOKEN_STATE_SEED, audit.token.as_ref()],
        bump = token_state.bump,
    )]
    pub token_state: Box<Account<'info, TokenState>>,

    /// The auditors the cycle's auditor is drawn from (bound by seeds; it may not exist on a deployment from before it).
    /// CHECK: read by read_registry (owner and discriminator checked).
    #[account(seeds = [AUDITOR_REGISTRY_SEED], bump)]
    pub auditor_registry: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct DesignateWithoutSeed<'info> {
    /// Anyone may crank this once the operator's reveal grace has passed.
    pub crank: Signer<'info>,

    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [AUDIT_SEED, audit.token.as_ref(), audit.period_id.to_le_bytes().as_ref()],
        bump = audit.bump,
    )]
    pub audit: Account<'info, AuditCycle>,

    /// The audited token's state: its issuer is never drawn, and its deadline leaves time to disclose the sample.
    #[account(mut, seeds = [TOKEN_STATE_SEED, audit.token.as_ref()], bump = token_state.bump)]
    pub token_state: Box<Account<'info, TokenState>>,

    /// The auditors the cycle's auditor is drawn from (bound by seeds; it may not exist on a deployment from before it).
    /// CHECK: read by read_registry (owner and discriminator checked).
    #[account(seeds = [AUDITOR_REGISTRY_SEED], bump)]
    pub auditor_registry: UncheckedAccount<'info>,
}
