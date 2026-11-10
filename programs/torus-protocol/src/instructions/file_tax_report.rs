//! file_tax_report: the company's tax accountant reports, for the cycle being audited, the total of the book's
//! sub-account for Torus returns. It never sees the company's declared figure; finalize_audit compares the two.
//!
//!   - The first report is due by the audit deadline. None by then is the issuer's default (settled in finalize_audit),
//!     so a late report is rejected. Before the deadline a report can be corrected.
//!   - While the cycle is on hold (declared total above the book total), a reconciled report is accepted until the hold
//!     ends.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TorusError;
use crate::state::{load_if_exists, AuditCycle, TaxAccountantRecord, TaxReport, TokenState};

pub fn handler(ctx: Context<FileTaxReport>, book_total: u64, report_hash: [u8; 32]) -> Result<()> {
    let ts = &ctx.accounts.token_state;
    require!(ts.budget > 0, TorusError::NoCycleToReport);
    let now = Clock::get()?.unix_timestamp;

    // The cycle's audit exists once the issuer has committed; the report may come before that.
    let audit: Option<AuditCycle> = load_if_exists(&ctx.accounts.audit, &crate::ID)?;
    let finalized = audit.as_ref().is_some_and(|a| a.stage == AuditStage::Finalized as u8);
    require!(!finalized, TorusError::InvalidAuditStage);
    let hold_until = audit.map_or(0, |a| a.tax_hold_until);
    let refiled = hold_until > 0;
    let deadline = if refiled { hold_until } else { ts.audit_deadline };
    require!(now <= deadline, TorusError::TaxReportLate);

    let r = &mut ctx.accounts.tax_report;
    r.token = ts.mint;
    r.period_id = ts.period_id;
    r.accountant = ctx.accounts.accountant.key();
    r.book_total = book_total;
    r.report_hash = report_hash;
    r.filed_ts = now;
    r.refiled = refiled;
    r.bump = ctx.bumps.tax_report;
    msg!(
        "file_tax_report: mint={} period={} book_total={} refiled={}",
        r.token,
        r.period_id,
        book_total,
        refiled
    );
    Ok(())
}

#[derive(Accounts)]
pub struct FileTaxReport<'info> {
    /// The company's registered tax accountant (pays for the report account).
    #[account(mut)]
    pub accountant: Signer<'info>,

    #[account(seeds = [TOKEN_STATE_SEED, token_state.mint.as_ref()], bump = token_state.bump)]
    pub token_state: Account<'info, TokenState>,

    #[account(
        seeds = [TAX_ACCOUNTANT_SEED, token_state.mint.as_ref()],
        bump = tax_accountant_record.bump,
        constraint = tax_accountant_record.active
            && tax_accountant_record.accountant == accountant.key() @ TorusError::TaxAccountantNotRegistered,
    )]
    pub tax_accountant_record: Account<'info, TaxAccountantRecord>,

    /// The cycle's audit (exists once the issuer has committed).
    /// CHECK: address bound by seeds; read only when this program owns it.
    #[account(seeds = [AUDIT_SEED, token_state.mint.as_ref(), token_state.period_id.to_le_bytes().as_ref()], bump)]
    pub audit: UncheckedAccount<'info>,

    #[account(
        init_if_needed,
        payer = accountant,
        space = 8 + TaxReport::INIT_SPACE,
        seeds = [TAX_REPORT_SEED, token_state.mint.as_ref(), token_state.period_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub tax_report: Account<'info, TaxReport>,

    pub system_program: Program<'info, System>,
}
