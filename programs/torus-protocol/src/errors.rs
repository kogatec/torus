//! Protocol errors.

use anchor_lang::prelude::*;

#[error_code]
pub enum TorusError {
    #[msg("The auditor is not independent of the issuer (the issuer cannot audit itself)")]
    AuditorNotIndependent,

    #[msg("The manifest's return rate is below the floor")]
    ReturnRateBelowFloor,

    #[msg("The manifest is not set or not active")]
    ManifestInactive,

    #[msg("The budget for this period has not been provisioned yet")]
    BudgetNotProvisioned,

    #[msg("The manifest's obligation exceeds the provisioned budget (over-declaration)")]
    ManifestExceedsBudget,

    #[msg("The manifest's obligation is below the required share of the provisioned budget (under-declaration)")]
    ManifestBelowBudgetFloor,

    #[msg("The entropy was not fixed after the commitment (it could have been chosen afterwards)")]
    EntropyNotAfterCommit,

    #[msg("The entropy failed validation")]
    EntropyInvalid,

    #[msg("The audit cycle is in the wrong stage (out of order)")]
    InvalidAuditStage,

    #[msg("The sample size exceeds the maximum")]
    SampleTooLarge,

    #[msg("The sample size is zero or larger than the population")]
    InvalidSampleSize,

    #[msg("The signer is not the auditor fixed for this cycle")]
    UnauthorizedAuditor,

    #[msg("The bond has not reached its target, so redemptions cannot start")]
    BondTargetNotReached,

    #[msg("The token is frozen (fraud or default was established)")]
    TokenFrozen,

    #[msg("Arithmetic overflow")]
    MathOverflow,

    #[msg("Only USDC may be used as collateral in the pool")]
    NonUsdcCollateral,

    #[msg("The pool balance is insufficient")]
    InsufficientPoolBalance,

    #[msg("Unauthorized")]
    Unauthorized,

    #[msg("The tier is already at its maximum")]
    MaxTierReached,

    #[msg("The mint has no TransferHook extension")]
    MissingTransferHook,

    #[msg("The mint's TransferHook does not point to the Torus hook program")]
    HookProgramMismatch,

    #[msg("The mint has no TransferFee extension")]
    MissingTransferFee,

    #[msg("The disclosure proof does not match the commitment (the leaf is not in the committed set)")]
    DisclosureProofInvalid,

    #[msg("The total implied by the commitment does not match the control total")]
    ControlTotalMismatch,

    #[msg("The disclosure proof is too deep")]
    ProofTooDeep,

    #[msg("Not all sampled leaves have been disclosed")]
    DisclosuresIncomplete,

    #[msg("All sampled leaves have already been disclosed")]
    DisclosuresAlreadyComplete,

    #[msg("The mint's TransferHook authority has not been revoked (the hook could be replaced)")]
    HookAuthorityNotRevoked,

    #[msg("The mint's TransferFee config authority has not been revoked (the fee rate could be changed)")]
    FeeAuthorityNotRevoked,

    #[msg("The transfer fee rate is zero or does not match the declared rate")]
    InvalidTransferFeeRate,

    #[msg("The withheld-fee withdraw authority is not the protocol PDA (an issuer key would be on the money path)")]
    WithheldAuthorityNotProtocol,

    #[msg("The redemption pool holds less than the provisioned budget")]
    BudgetNotEscrowed,

    #[msg("Collected fees do not match the fees implied by the transfers")]
    CrossCheckMismatch,

    #[msg("Invalid manifest term")]
    InvalidManifestTerm,

    #[msg("The manifest has expired")]
    ManifestExpired,

    #[msg("The caller is not the mint authority (registering someone else's mint is not allowed)")]
    MintAuthorityNotIssuer,

    #[msg("The mint still has a freeze authority (the issuer could freeze the fee vault or holders)")]
    FreezeAuthorityPresent,

    #[msg("The mint has a disallowed extension (PermanentDelegate, Pausable, ConfidentialTransfer, ...)")]
    DisallowedMintExtension,

    #[msg("The fee schedule is not constant (older and newer fee configs differ)")]
    FeeScheduleNotConstant,

    #[msg("The tolerance or shortfall tolerance exceeds the maximum (values that disable detection are not allowed)")]
    ToleranceTooLarge,

    #[msg("The sample size is below the operator's minimum")]
    SampleSizeBelowMinimum,

    #[msg("The auditor is not in the operator's registry or is inactive")]
    AuditorNotRegistered,

    #[msg("The settlement period has not elapsed yet")]
    PeriodNotElapsed,

    #[msg("The previous audit cycle is not finalized (an obligation cannot be skipped)")]
    PreviousAuditNotFinalized,

    #[msg("A default cannot be declared yet (before the deadline, or nothing is missing)")]
    DefaultNotDue,

    #[msg("The claim proof does not match the committed ledger (recipient, amount or index differs)")]
    ClaimProofInvalid,

    #[msg("Only the program's upgrade authority can initialize")]
    NotUpgradeAuthority,

    #[msg("The proof's shape does not match the index and population size (e.g. a leaf outside the population)")]
    ProofShapeMismatch,

    #[msg("The operator has not set this company's bond target and minimum conversion price")]
    IssuerTermsNotSet,

    #[msg("The bond target and minimum conversion price must be greater than zero")]
    InvalidIssuerTerms,

    #[msg("The exchange partner is not in the operator's registry or is inactive")]
    PartnerNotRegistered,

    #[msg("The conversion price is below the operator's minimum price")]
    ConversionBelowMinPrice,

    #[msg("Invalid conversion amount (zero or more than the fee vault holds)")]
    InvalidConversionAmount,

    #[msg("There is no issuer share to claim")]
    NothingToClaim,

    #[msg("The auditor cannot be replaced yet (before the deadline, or not waiting on the auditor)")]
    AuditorReplacementNotDue,

    #[msg("Invalid replacement auditor (the issuer, or the current auditor)")]
    InvalidReplacementAuditor,

    #[msg("The token has exited (no provisioning, conversion, deposit or commitment)")]
    TokenExited,

    #[msg("An exit has already been requested")]
    ExitAlreadyRequested,

    #[msg("No exit has been requested")]
    ExitNotRequested,

    #[msg("The exit cannot be finalized yet (the obligation up to the requested period is not provisioned and audited)")]
    ExitNotReady,

    #[msg("Too many allowed defects (at most 20% of the sample size)")]
    TooManyAllowedDefects,

    #[msg("Periods after the exit request are not provisioned (finalize the exit)")]
    ExitInProgress,

    #[msg("The bond target is below the operator's minimum")]
    BondBelowMinimum,

    #[msg("Uniqueness has not been verified (all payment IDs strictly increasing and the root matching)")]
    UniquenessNotVerified,

    #[msg("Uniqueness has already been verified")]
    UniquenessAlreadyVerified,

    #[msg("Payment IDs are not strictly increasing (a duplicate payment or a wrong order)")]
    LeafOrderInvalid,

    #[msg("The root rebuilt from all leaves does not match the commitment or the control total")]
    UniquenessRootMismatch,

    #[msg("More leaves than the population size")]
    TooManyLeaves,

    #[msg("This payment ID was already used by another audit (a payment cannot be counted twice)")]
    OutcomeAlreadyUsed,

    #[msg("Wrong account for the payment ID registry")]
    InvalidOutcomeAccount,

    #[msg("More observations than the sample size")]
    TooManyObservations,

    #[msg("This leaf is not confirmed (not observed in the sample and not attested by the auditor)")]
    LeafNotConfirmed,

    #[msg("The confirmed amount is zero")]
    NothingToPay,

    #[msg("Liquidation is only possible after an exit or a freeze")]
    LiquidationNotAllowed,

    #[msg("Liquidation has already started")]
    LiquidationAlreadyStarted,

    #[msg("Liquidation has not started, or this audit is not the liquidation basis")]
    LiquidationNotStarted,

    #[msg("This auditor's registration has been revoked")]
    AuditorRevoked,

    #[msg("During a campaign the manifest cannot change in the issuer's favor (lower return rate, looser tolerances, smaller sample, more allowed defects, shorter term or another use plan)")]
    ManifestChangeFavorsIssuer,

    #[msg("Close the elapsed periods (provision_budget) before changing the manifest again")]
    PeriodsNotClosed,

    #[msg("The issuer, the auditor and the escrow partner must be different keys, and the escrow partner cannot be the operator")]
    RolesNotSeparate,

    #[msg("The escrow partner cannot be changed during a campaign unless its registration was revoked")]
    EscrowPartnerLocked,

    #[msg("This partner's registration has been revoked")]
    PartnerRevoked,

    #[msg("The manifest has no use plan")]
    UsePlanNotSet,

    #[msg("The amount is zero or exceeds the escrow balance released by clean audits")]
    WithdrawalExceedsReleased,

    #[msg("The payee is the issuer's own account")]
    PayeeIsIssuer,

    #[msg("This withdrawal request has already been executed")]
    WithdrawalAlreadyExecuted,

    #[msg("Only the token's escrow partner and the manifest's auditor can approve (never the operator or the issuer)")]
    NotAnApprover,

    #[msg("A payment from the bond must leave at least half of the bond target in it")]
    BondUseExceedsLimit,

    #[msg("The issuer's share per rank must be at most 100% and must not decrease as the rank rises")]
    InvalidTierShares,

    #[msg("A share or fee must be at most 100%")]
    InvalidShareBps,

    #[msg("The local partner is not registered or was revoked")]
    LocalPartnerNotRegistered,

    #[msg("Perk allocation must total 100% with general >= trader >= hold")]
    InvalidPerkAllocation,

    #[msg("Hold perk rates must be at most 100%, must not rise over time, and the step must be positive")]
    InvalidHoldRates,

    #[msg("Perks run only in the current period, after its obligation is provisioned")]
    PerkPeriodNotCurrent,

    #[msg("The merchant is not registered for this token or was revoked")]
    MerchantNotRegistered,

    #[msg("The account is not registered for perks")]
    HolderNotRegistered,

    #[msg("Invalid perk kind or amount")]
    InvalidPerkRedemption,

    #[msg("The redemption exceeds the account's allowance for this period")]
    PerkAllowanceExceeded,

    #[msg("The redemption exceeds this period's perk budget")]
    PerkBudgetExceeded,

    #[msg("The restamp amount must be positive and within the balance")]
    InvalidRestampAmount,

    #[msg("The ask cap must be at most 90% and the usage cap at most 50%")]
    InvalidPerkMarketTerms,

    #[msg("The listing amount must be positive")]
    InvalidPerkListing,

    #[msg("This company does not allow trader perks to be listed")]
    PerkListingClosed,

    #[msg("The lot's period has not been closed yet")]
    PerkLotStillOpen,
    // Kept last, so the codes of the other errors are the same with or without them.

    #[msg("The hold period of the tax reconciliation must be positive")]
    InvalidHoldPeriod,

    #[msg("The tax accountant is not registered for this token or was revoked")]
    TaxAccountantNotRegistered,

    #[msg("No obligation of this cycle is waiting for a tax report")]
    NoCycleToReport,

    #[msg("The deadline for the tax accountant's report has passed")]
    TaxReportLate,

    #[msg("The tax accountant's report for this cycle has not been filed yet")]
    TaxReportMissing,

    #[msg("The cycle is on hold until the tax accountant files a reconciled report or the hold ends")]
    TaxHoldActive,
}
