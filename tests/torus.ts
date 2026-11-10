/**
 * Torus protocol lifecycle tests (local validator).
 *
 * Scenarios (each on its own mint, so a freeze does not spill over):
 *   (a) honest pass         → result = Pass, nothing slashed
 *   (b) attack X (overstatement) → observed ≪ claimed → FraudOverstatement, tier → 0, frozen, bond slashed
 *   (c) under-delivery → control_total < obligation − band → Underdelivered: not slashed, one tier down, gap carried
 *   (d) a mint without the mechanism → rejected by issue_token
 *   (e) payout fails before finalization and for a fraudulent audit
 *   (f) self-transfers are not counted as volume (but count for the fee cross-check)
 *   (g) the fee cross-check runs and matches exactly
 *   (h) fees implied without being collected → CrossCheckMismatch
 *   (i) after the manifest expires a period gets no obligation, so nothing can be committed; a new campaign brings it back
 *   Fixed holes (each test checks the attack fails and the legitimate operation still works):
 *   (j) a payout goes only to the committed leaf's recipient, the confirmed amount, once (anyone could drain the pool)
 *   (k) only the upgrade authority can initialize (front-running right after deployment)
 *   (l) key checks at issuance (freeze authority, PermanentDelegate, registering someone else's mint, fee schedule swap)
 *   (m) manifest caps on thresholds, minimum sample size, maximum allowed defects, auditor registry
 *   (n) provisioning time gate and previous audit final (no skipping obligations)
 *   (o) an expired audit (missing commitment or disclosures) is a default and slashed
 *   (p) only the operator designates the sample; the sample size is fixed by the manifest
 *   (q) self-transfers and the fee cap do not trip the cross-check (anyone could block provisioning)
 *   (r) delegated transfers also go through the hook
 *   (s) fake leaves outside the declared population cannot inflate the total (proof shape is bound)
 *   Forced deposit of fees and operations:
 *   (t) a partner's conversion is split into the operator's and the issuer's share; the issuer's share fills the bond →
 *       redemption pool (up to the obligation) → escrow (the operator's fee is never bond). Nothing is metered or provisioned
 *       until the bond is full; earlier volume creates no obligation; the issuer share waits for the audit; conversions are not volume
 *   (u) conversion rejected: only the operator sets the terms; unset terms, bond below minimum, price below minimum, unregistered partner
 *   (v) once fraud is established, the issuer escrow is slashed too
 *   (w) if the auditor does not record by the deadline, the operator replaces it and the audit continues
 *   (x) payouts of promises beyond the obligation do not touch funds reserved for the next period
 *   (h) also checks that unpaid redemptions are kept aside before the next provision
 *   Exit decisions and remaining holes:
 *   (y) a period with zero volume (budget 0) does not stop the next one (the cycle used to stall forever)
 *   (z) voluntary exit: the obligation runs to the requested period; after its audit, half the bond to customers (the
 *       redemption pool) and half to the operator; the issuer share of fees after the exit goes to customers too;
 *       liquidation shares the pool's surplus among recipients
 *   (aa) defects are judged by count: 21 samples with 0 allowed → one defect is overstatement (a ratio check let it pass)
 *   (ab) fixed period boundaries: a late close still assigns volume to the right period
 *   (ac) uniqueness: duplicates in the tree, root mismatch, finalizing unverified, and reuse in a later period are rejected
 *   (ae) payouts only for confirmed leaves up to the confirmed amount; after a freeze, finalized recipients are still paid and the surplus is liquidated
 *   (af) auditor revocation: a revoked auditor cannot record or confirm, a manifest naming it cannot start a new audit,
 *        and the operator replaces it without waiting; the new auditor observes again and the audit continues
 *   End of a manifest and the next one; the issuer escrow (2026-10-17):
 *   (ag) after the term ends, a period that started during the campaign is still audited from commitment to
 *        finalization, and is not slashed or frozen for it
 *   (ah) between campaigns no obligation arises and no default can be declared; the carried shortfall is kept and settled
 *        by the exit's final audit (or the next campaign)
 *   (ai) a manifest change does not touch periods that started before it; gap volume is not counted; tier, streak,
 *        bond and used payment IDs carry over
 *   (aj) during a campaign the manifest cannot change in the issuer's favor; a new auditor, a higher rate and a longer
 *        term are allowed
 *   (ak) a clean audit releases the issuer share inside the escrow; nothing is paid to the issuer's account
 *   (al) one escrow partner per token, picked by the issuer from the registry; locked during a campaign unless revoked
 *        (the operator revokes partners); issuer, auditor and partner are separate keys
 *   (am) the manifest records the hash of the use plan
 *   (an) withdrawal requests: a manifest in force with a use plan, within the released balance, never to the issuer,
 *        one per invoice
 *   (ao) a request runs only with both the escrow partner's and the auditor's approval and pays the payee straight from
 *        the escrow; never with one of them, the issuer or the operator
 *   (ap) fraud slashes everything left in the escrow (regression); pending requests cannot run
 *   (aq) on exit the escrow's remainder and the issuer's half of the bond go to customers through liquidation, and so
 *        do issuer shares that arrive after the exit
 *   (ar) when the company needs funds it can request a payment from the bond: down to half of the bond target, with the
 *        escrow partner's and the auditor's approval, straight to the payee; redemptions go on and later fees refill it
 *   Tax accountant reconciliation (2026-11-02):
 *   (as) the tax accountant is registered by the operator with its own signature (never the issuer's key) and files the
 *        book total; a declared total within the book total passes
 *   (at) a declared total above the book total holds the cycle (payouts wait); a reconciled report resumes it
 *   (au) a reconciled report that still shows a gap: only the book total is recognized, the rest is carried, no pass
 *   (av) no reconciled report within the hold forfeits the cycle; no report by the deadline is a default; late reports
 *        are rejected
 *   Distribution, issuance authority and perks (2026-11-02):
 *   (aw) per-company rank table and local partner: the rules are enforced and the operator's share is split with the
 *        partner
 *   (ax) the mint authority moves to the program; only a restamp mints, signed by the holder and the local partner, never
 *        more than it burns
 *   (ay) perks: registration starts at 0%, received tokens carry today's stamp, budgets come from the previous obligation,
 *        trader and hold perks stay within allowances and budgets
 *   The perk market (2026-11-06):
 *   (be) listing moves part of the trader perk into the seller's lot: within the allowance, with the local partner's
 *        signature, sharing one allowance with the seller's own use
 *   (bf) what can be listed is capped below half the fee when the issuer's share would let an insider profit
 *   (bg) a customer's use settles through the existing audit and payout: the pool pays the face value, split between the
 *        merchant and the seller; the lot's rent comes back after its period closes
 *   (bh) a company can turn listing off for a period, and later terms do not change an open period
 *   (bi) a freeze stops listing; the lot can still be closed
 *   (bj) a local partner's share lowers what can be listed; a revoked partner's does not
 *   (bk) an account that changes hands mid-period cannot redirect its lot
 *
 * Claimed values (per sample and in total) are not reported by anyone: they are fixed on-chain by disclosure proofs
 * (verify_disclosure) against the Merkle sum tree, one per sample. The auditor records an observed value per sample and
 * the program counts defects and sums. A leaf holds index, payment ID, recipient and amount; payouts are claims on leaves.
 */

import * as anchor from "@coral-xyz/anchor";
import { BN, Program } from "@coral-xyz/anchor";
import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_RENT_PUBKEY,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  AuthorityType,
  ExtensionType,
  getMintLen,
  createMint,
  createAccount,
  createAssociatedTokenAccount,
  createAssociatedTokenAccountIdempotent,
  mintTo,
  mintToChecked,
  approveChecked,
  getAccount,
  getMint,
  createInitializeMintInstruction,
  createInitializeTransferFeeConfigInstruction,
  createInitializeTransferHookInstruction,
  createInitializePermanentDelegateInstruction,
  createSetTransferFeeInstruction,
  createSetAuthorityInstruction,
  createTransferCheckedWithTransferHookInstruction,
  closeAccount,
  setAuthority,
  getAssociatedTokenAddressSync,
} from "@solana/spl-token";
import { assert } from "chai";
import { keccak_256 } from "@noble/hashes/sha3";
import { TorusClient, SumTree, distributeLeafValues, sortByOutcome, ROOT_TAG } from "../app/src/sdk";

const BPS = 10_000;
const DECIMALS = 6;

// Manifest parameters
const RETURN_RATE_BPS = 5_000; // 50%
const TOLERANCE_BPS = 500; // 5%
const LCL_BPS = 1_000; // 10%
const FLOOR_BPS = 1_000; // 10%
const BOND_TARGET = new BN(1_000_000); // 1 USDC (set per company by the operator)
const MIN_BOND = new BN(100_000); // minimum bond target (fixed by the operator at initialize)
// Minimum conversion price: 1 USDC per brand token (set per company by the operator).
const MIN_PRICE = new BN(1_000_000);
// Settlement period (seconds), used for the provisioning time gate and the audit deadline. Short in tests.
const PERIOD_LEN = 2;
// Manifest term (campaign length) = 90 days, the layer above settlement periods.
const TERM_LEN = new BN(90 * 86_400);
const FEE_BPS = 100;
const MAX_FEE = 1_000_000;
// The operator's minimum sample size and the sample size fixed in the manifest.
const MIN_SAMPLE = 4;
const SAMPLE = 4;
// Leaves per transaction for the uniqueness check, observations per transaction.
const UNIQ_BATCH = 6;
const OBS_BATCH = 32;

// Volume (= period activity). budget = VOLUME * RETURN_RATE.
const VOLUME = 2_000_000; // → budget/obligation = 1_000_000
const OBLIGATION = (VOLUME * RETURN_RATE_BPS) / BPS; // 1_000_000
const POP = 8; // population (entries in the ledger)
// Deposit enough to fill the bond first and leave at least the budget in the redemption pool.
const DEPOSIT = BOND_TARGET.toNumber() + OBLIGATION + 500_000;
// Hash of the use plan for the issuer escrow (the items and their caps are an off-chain document).
const PLAN_HASH = Array.from(keccak_256(Buffer.from("use plan v1")));
// Hold of the tax reconciliation (seconds; fixed at initialize). Short in tests.
const TAX_HOLD = 6;
// Book total the tax accountant files by default: far above any declared total, so the reconciliation is clear.
const TAX_BOOK_DEFAULT = 1_000_000_000_000;
// The issuer's share per rank, set per company (the values of the former fixed table).
const TIER_SHARES = [2_000, 3_500, 5_000, 6_500];
// Supply minted before issuance (afterwards only restamp can mint).
const SUPPLY = 1_000_000_000_000_000;
// Perk terms set per company.
const PERKS = {
  generalBps: 6_000,
  traderBps: 2_500,
  holdBps: 1_500,
  holdRateBps: [3_000, 2_000, 1_000],
  holdStepSecs: new BN(3_600),
  capPerToken: new BN(1_000_000),
  restampFeeBps: 0,
  maxAskBps: 8_000,
  usageCapBps: 3_000,
};
const consent = (s: string) => Array.from(keccak_256(Buffer.from(s)));

describe("torus-protocol lifecycle", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const connection = provider.connection;

  const program = anchor.workspace.TorusProtocol as Program<any>;
  const hook = anchor.workspace.TorusHook as Program<any>;
  const client = new TorusClient(program, hook);

  const authority = (provider.wallet as anchor.Wallet).payer;
  const issuer = authority; // simplification: issuer = operator
  const auditor = Keypair.generate();
  const auditor2 = Keypair.generate(); // (w) replacement auditor
  const slashDest = Keypair.generate();
  const treasuryOwner = Keypair.generate(); // owner of the operator treasury
  const partner = Keypair.generate(); // exchange partner
  const localPartner = Keypair.generate(); // local partner (share 0, so the treasury figures of older tests hold)
  const taxAccountant = Keypair.generate(); // the companies' tax accountant
  /** Book total the accountant files right after a provision, per mint (default TAX_BOOK_DEFAULT; null = none). */
  const taxBook = new Map<string, number | null>();

  let usdcMint: PublicKey;
  let depositorUsdc: PublicKey;
  let slashDestAta: PublicKey;
  let treasuryAta: PublicKey;
  let partnerUsdc: PublicKey;
  // Token frozen by attack X, reused in (e), (z) and (ae).
  let frozenMint: PublicKey | null = null;
  let frozenPeriodId: BN | null = null;

  // ---------------------------------------------------------------- helpers

  async function airdrop(to: PublicKey, sol = 2) {
    const sig = await connection.requestAirdrop(to, sol * 1_000_000_000);
    await connection.confirmTransaction(sig, "confirmed");
  }

  /** Returns the error text if the call fails (null if it succeeds). */
  async function failure(p: Promise<any>): Promise<string | null> {
    try {
      await p;
      return null;
    } catch (e: any) {
      return e.toString() + " " + JSON.stringify(e?.logs ?? e?.transactionLogs ?? []);
    }
  }

  async function chainTime(): Promise<number> {
    for (let i = 0; i < 50; i++) {
      const bt = await connection.getBlockTime(await connection.getSlot("confirmed"));
      if (bt !== null) return bt;
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error("block time unavailable");
  }

  /** Waits until the on-chain block time passes `ts` (fixed sleeps are flaky). */
  async function waitChainTime(ts: number) {
    for (let i = 0; i < 400; i++) {
      const bt = await connection.getBlockTime(await connection.getSlot("confirmed"));
      if (bt !== null && bt > ts) return;
      await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error(`chain time did not pass ${ts}`);
  }

  async function tokenState(mint: PublicKey): Promise<any> {
    return program.account.tokenState.fetch(client.pdas.tokenState(mint)[0]);
  }

  /** Waits until the end boundary of the open period has passed. */
  async function waitPeriod(mint: PublicKey) {
    const ts = await tokenState(mint);
    const gridLen = (ts.gridPeriodLen as BN).toNumber();
    const len = gridLen > 0 ? gridLen : ((await program.account.manifest.fetch(client.pdas.manifest(mint)[0])) as any).periodLen.toNumber();
    await waitChainTime((ts.periodStartTs as BN).toNumber() + len);
  }

  function newOutcome(): Buffer {
    return Keypair.generate().publicKey.toBuffer();
  }

  before(async () => {
    // USDC (classic SPL)
    usdcMint = await createMint(connection, authority, authority.publicKey, null, DECIMALS, undefined, undefined, TOKEN_PROGRAM_ID);
    depositorUsdc = await createAssociatedTokenAccount(connection, authority, usdcMint, authority.publicKey);
    await mintTo(connection, authority, usdcMint, depositorUsdc, authority, 1_000_000_000); // 1,000 USDC

    // Create the slash destination (compensation pool fixed in Config) first
    slashDestAta = await createAssociatedTokenAccount(connection, authority, usdcMint, slashDest.publicKey);
    // Operator treasury (fixed in Config)
    treasuryAta = await createAssociatedTokenAccount(connection, authority, usdcMint, treasuryOwner.publicKey);

    // (k) Only the upgrade authority can initialize (no front-running right after deployment).
    const squatter = Keypair.generate();
    await airdrop(squatter.publicKey);
    const squat = await failure(
      program.methods
        .initialize(
          usdcMint,
          hook.programId,
          slashDestAta,
          treasuryAta,
          MIN_SAMPLE,
          MIN_BOND,
          new BN(TAX_HOLD),
        )
        .accounts({
          authority: squatter.publicKey,
          program: program.programId,
          programData: client.pdas.programData(),
          config: client.pdas.config()[0],
          systemProgram: SystemProgram.programId,
        })
        .signers([squatter])
        .rpc(),
    );
    assert.isNotNull(squat, "initialization by someone other than the upgrade authority must be rejected");
    assert.match(squat!, /NotUpgradeAuthority/, "rejected by the upgrade-authority check");

    // Legitimate initialization (upgrade authority = the deploying key)
    await program.methods
      .initialize(
        usdcMint,
        hook.programId,
        slashDestAta,
        treasuryAta,
        MIN_SAMPLE,
        MIN_BOND,
        new BN(TAX_HOLD),
      )
      .accounts({
        authority: authority.publicKey,
        program: program.programId,
        programData: client.pdas.programData(),
        config: client.pdas.config()[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Register the auditors in the operator's registry
    for (const a of [auditor, auditor2]) {
      await program.methods
        .registerAuditor()
        .accounts({
          authority: authority.publicKey,
          config: client.pdas.config()[0],
          auditor: a.publicKey,
          auditorRecord: client.pdas.auditorRecord(a.publicKey)[0],
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      await airdrop(a.publicKey, 2);
    }

    // Register the exchange partner and give it USDC to pay with
    await program.methods
      .registerPartner()
      .accounts({
        authority: authority.publicKey,
        config: client.pdas.config()[0],
        partner: partner.publicKey,
        partnerRecord: client.pdas.partnerRecord(partner.publicKey)[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    await airdrop(partner.publicKey, 2);
    partnerUsdc = await createAssociatedTokenAccount(connection, authority, usdcMint, partner.publicKey);
    await mintTo(connection, authority, usdcMint, partnerUsdc, authority, 1_000_000_000);

    // The local partner (share 0: older tests keep the treasury's whole operator share)
    await airdrop(taxAccountant.publicKey, 2);
    await airdrop(localPartner.publicKey, 2);
    await registerLocalPartnerTx(localPartner.publicKey, 0);
  });

  async function registerLocalPartnerTx(p: PublicKey, shareBps: number, signer: Keypair = authority) {
    const usdc = await createAssociatedTokenAccountIdempotent(connection, authority, usdcMint, p);
    return program.methods
      .registerLocalPartner(shareBps)
      .accounts({
        authority: signer.publicKey,
        config: client.pdas.config()[0],
        partner: p,
        partnerUsdc: usdc,
        localPartnerRecord: client.pdas.localPartner(p)[0],
        systemProgram: SystemProgram.programId,
      })
      .signers(signer === authority ? [] : [signer])
      .rpc();
  }

  /** Registers the tax accountant of a token once (operator + the accountant's signature). */
  async function ensureTaxAccountant(mint: PublicKey) {
    const record = client.pdas.taxAccountant(mint)[0];
    if (await program.account.taxAccountantRecord.fetchNullable(record)) return;
    await program.methods
      .registerTaxAccountant(consent("warning and consent v1"))
      .accounts({
        authority: authority.publicKey,
        config: client.pdas.config()[0],
        tokenState: client.pdas.tokenState(mint)[0],
        accountant: taxAccountant.publicKey,
        taxAccountantRecord: record,
        systemProgram: SystemProgram.programId,
      })
      .signers([taxAccountant])
      .rpc();
  }

  /** The tax accountant reports the book total for the cycle being audited. */
  async function fileTaxReportTx(mint: PublicKey, bookTotal: number, signer: Keypair = taxAccountant) {
    const ts = await tokenState(mint);
    return program.methods
      .fileTaxReport(new BN(bookTotal), consent(`report ${bookTotal}`))
      .accounts({
        accountant: signer.publicKey,
        tokenState: client.pdas.tokenState(mint)[0],
        taxAccountantRecord: client.pdas.taxAccountant(mint)[0],
        audit: client.pdas.audit(mint, ts.periodId)[0],
        taxReport: client.pdas.taxReport(mint, ts.periodId)[0],
        systemProgram: SystemProgram.programId,
      })
      .signers([signer])
      .rpc();
  }

  /** Right after a provision with an obligation, the accountant files its report (taxBook decides the figure). */
  async function autoFileTaxReport(mint: PublicKey) {
    const book = taxBook.has(mint.toBase58()) ? taxBook.get(mint.toBase58())! : TAX_BOOK_DEFAULT;
    if (book === null) return;
    const ts = await tokenState(mint);
    if ((ts.budget as BN).eqn(0)) return;
    if (await program.account.taxReport.fetchNullable(client.pdas.taxReport(mint, ts.periodId)[0])) return;
    await fileTaxReportTx(mint, book);
  }

  interface MintOpts {
    freezeAuthority?: PublicKey | null;
    permanentDelegate?: PublicKey;
    feeConfigAuthority?: PublicKey | null;
    maxFee?: number;
    /** Mint authority (= the issuer) when it is not the operator's key. */
    mintAuthority?: Keypair;
  }

  /**
   * Creates a Token-2022 mint (TransferFee + TransferHook) and initializes the hook's meta list and VolumeCounter.
   * By default it satisfies issue_token's invariants (fee and hook authorities revoked, no freeze authority,
   * withheld fees withdrawable by the pool_authority PDA). `opts` builds mints that probe the holes.
   */
  async function createTorusMint(opts: MintOpts = {}): Promise<PublicKey> {
    const mintKp = Keypair.generate();
    const [poolAuthority] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool_authority"), mintKp.publicKey.toBuffer()],
      program.programId,
    );

    const extensions = [ExtensionType.TransferFeeConfig, ExtensionType.TransferHook];
    if (opts.permanentDelegate) extensions.push(ExtensionType.PermanentDelegate);
    const mintLen = getMintLen(extensions);
    const lamports = await connection.getMinimumBalanceForRentExemption(mintLen);

    const tx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: authority.publicKey,
        newAccountPubkey: mintKp.publicKey,
        space: mintLen,
        lamports,
        programId: TOKEN_2022_PROGRAM_ID,
      }),
      createInitializeTransferFeeConfigInstruction(
        mintKp.publicKey,
        opts.feeConfigAuthority ?? null, // default: fee config authority irreversibly revoked
        poolAuthority, // withdraw authority is the protocol PDA (no private key exists)
        FEE_BPS,
        BigInt(opts.maxFee ?? MAX_FEE),
        TOKEN_2022_PROGRAM_ID,
      ),
      createInitializeTransferHookInstruction(
        mintKp.publicKey,
        PublicKey.default, // zero key = None (hook authority revoked)
        hook.programId,
        TOKEN_2022_PROGRAM_ID,
      ),
    );
    if (opts.permanentDelegate) {
      tx.add(createInitializePermanentDelegateInstruction(mintKp.publicKey, opts.permanentDelegate, TOKEN_2022_PROGRAM_ID));
    }
    tx.add(
      createInitializeMintInstruction(
        mintKp.publicKey, DECIMALS, (opts.mintAuthority ?? authority).publicKey, opts.freezeAuthority ?? null, TOKEN_2022_PROGRAM_ID,
      ),
    );
    await sendAndConfirmTransaction(connection, tx, [authority, mintKp]);
    // The supply is minted before issuance: issue_token moves the mint authority to the program.
    const supplyAta = await createAssociatedTokenAccountIdempotent(
      connection, authority, mintKp.publicKey, authority.publicKey, undefined, TOKEN_2022_PROGRAM_ID,
    );
    await mintToChecked(
      connection, authority, mintKp.publicKey, supplyAta, opts.mintAuthority ?? authority, SUPPLY, DECIMALS, [], undefined, TOKEN_2022_PROGRAM_ID,
    );

    await hook.methods
      .initializeExtraAccountMetaList()
      .accounts({
        payer: authority.publicKey,
        extraAccountMetaList: client.pdas.extraAccountMetaList(mintKp.publicKey)[0],
        mint: mintKp.publicKey,
        volumeCounter: client.pdas.volumeCounter(mintKp.publicKey)[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    return mintKp.publicKey;
  }

  function issueTokenTx(mint: PublicKey, signer: Keypair = issuer, feeBps = FEE_BPS, maxFee = MAX_FEE) {
    return program.methods
      .issueToken(feeBps, new BN(maxFee))
      .accounts({
        issuer: signer.publicKey,
        config: client.pdas.config()[0],
        mint,
        usdcMint,
        tokenState: client.pdas.tokenState(mint)[0],
        poolAuthority: client.pdas.poolAuthority(mint)[0],
        redemptionVault: client.pdas.redemptionVault(mint)[0],
        slashingBond: client.pdas.slashingBond(mint)[0],
        issuerEscrow: client.pdas.issuerEscrow(mint)[0],
        feeVault: client.pdas.feeVault(mint)[0],
        token2022Program: TOKEN_2022_PROGRAM_ID,
        usdcTokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
        rent: SYSVAR_RENT_PUBKEY,
      })
      .signers(signer === issuer ? [] : [signer])
      .rpc();
  }

  /**
   * Builds up volume: a Token-2022 transfer that makes the hook add to VolumeCounter.
   * The returned `dst` holds the withheld fee (to harvest).
   */
  async function accrueVolume(mint: PublicKey, amount: number): Promise<{ src: PublicKey; dst: PublicKey }> {
    const src = await createAssociatedTokenAccountIdempotent(connection, authority, mint, authority.publicKey, undefined, TOKEN_2022_PROGRAM_ID);
    const dstOwner = Keypair.generate();
    const dst = await createAssociatedTokenAccountIdempotent(connection, authority, mint, dstOwner.publicKey, undefined, TOKEN_2022_PROGRAM_ID);
    const ix = await createTransferCheckedWithTransferHookInstruction(
      connection, src, mint, dst, authority.publicKey, BigInt(amount), DECIMALS, [], "confirmed", TOKEN_2022_PROGRAM_ID,
    );
    await sendAndConfirmTransaction(connection, new Transaction().add(ix), [authority]);
    return { src, dst };
  }

  /** Sweeps withheld fees from the given accounts (remaining_accounts) into the pool (anyone). */
  async function harvest(mint: PublicKey, withheld: PublicKey[]) {
    return program.methods
      .harvestFees()
      .accounts({
        crank: authority.publicKey,
        config: client.pdas.config()[0],
        tokenState: client.pdas.tokenState(mint)[0],
        mint,
        poolAuthority: client.pdas.poolAuthority(mint)[0],
        feeVault: client.pdas.feeVault(mint)[0],
        tokenProgram: TOKEN_2022_PROGRAM_ID,
      })
      .remainingAccounts(withheld.map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })))
      .rpc();
  }

  /** Closes a period. If the closing period has an obligation (budget > 0), its audit cycle goes in prevAudit (or pass one explicitly). */
  async function provision(mint: PublicKey, prevAudit?: PublicKey | null) {
    const ts = await tokenState(mint);
    const pid: BN = ts.periodId;
    const owed = pid.gtn(0) && (ts.budget as BN).gtn(0); // a period with budget 0 has no audit cycle
    const prev = prevAudit !== undefined ? prevAudit : owed ? client.pdas.audit(mint, pid)[0] : null;
    const sig = await program.methods
      .provisionBudget()
      .accounts({
        crank: authority.publicKey,
        config: client.pdas.config()[0],
        tokenState: client.pdas.tokenState(mint)[0],
        manifest: client.pdas.manifest(mint)[0],
        volumeCounter: client.pdas.volumeCounter(mint)[0],
        redemptionVault: client.pdas.redemptionVault(mint)[0],
        prevAudit: prev,
      })
      .rpc();
    await autoFileTaxReport(mint);
    return sig;
  }

  /**
   * Closes periods until one with volume gets a budget. Boundaries are fixed, so a slow test leaves periods without
   * volume (budget 0) in between; those have no audit and are skipped.
   */
  async function provisionUntilBudget(mint: PublicKey): Promise<{ periodId: BN; budget: number; sig: string }> {
    for (let i = 0; i < 200; i++) {
      await waitPeriod(mint);
      const sig = await provision(mint);
      const ts = await tokenState(mint);
      if ((ts.budget as BN).gtn(0)) return { periodId: ts.periodId as BN, budget: (ts.budget as BN).toNumber(), sig };
    }
    throw new Error("budget was never provisioned");
  }

  interface ManifestOpts {
    periodLen?: number;
    toleranceBps?: number;
    sampleSize?: number;
    maxDefects?: number;
    auditor?: PublicKey;
    returnRateBps?: number;
    shortfallToleranceBps?: number;
    planHash?: number[];
    /** The issuer's key when it is not the operator's. */
    issuer?: Keypair;
    /** Floor of the return rate (default FLOOR_BPS). */
    floorBps?: number;
  }

  /** Fixes (or re-fixes) the manifest. `termLen` is the term (campaign length, seconds). */
  function setManifestTx(mint: PublicKey, termLen: BN, o: ManifestOpts = {}) {
    const aud = o.auditor ?? auditor.publicKey;
    const signer = o.issuer ?? issuer;
    return program.methods
      .setManifest(
        o.returnRateBps ?? RETURN_RATE_BPS,
        o.toleranceBps ?? TOLERANCE_BPS,
        o.shortfallToleranceBps ?? LCL_BPS,
        o.floorBps ?? FLOOR_BPS,
        new BN(o.periodLen ?? PERIOD_LEN),
        termLen,
        o.sampleSize ?? SAMPLE,
        o.maxDefects ?? 0,
        o.planHash ?? PLAN_HASH,
      )
      .accounts({
        issuer: signer.publicKey,
        tokenState: client.pdas.tokenState(mint)[0],
        manifest: client.pdas.manifest(mint)[0],
        auditor: aud,
        auditorRecord: client.pdas.auditorRecord(aud)[0],
        config: client.pdas.config()[0],
        systemProgram: SystemProgram.programId,
      })
      .signers(signer === issuer ? [] : [signer])
      .rpc();
  }

  /**
   * Terms the operator sets per company (bond target, minimum conversion price, share per rank, local partner).
   * Once they are set, the company's tax accountant is registered too.
   */
  async function setTermsTx(
    mint: PublicKey,
    signer: Keypair = authority,
    bondTarget = BOND_TARGET,
    minPrice = MIN_PRICE,
    tiers = TIER_SHARES,
    lp = localPartner.publicKey,
  ) {
    const sig = await program.methods
      .setIssuerTerms(bondTarget, minPrice, tiers)
      .accounts({
        authority: signer.publicKey,
        config: client.pdas.config()[0],
        tokenState: client.pdas.tokenState(mint)[0],
        localPartnerRecord: client.pdas.localPartner(lp)[0],
      })
      .signers(signer === authority ? [] : [signer])
      .rpc();
    await ensureTaxAccountant(mint);
    return sig;
  }

  function depositTx(mint: PublicKey, amount: number) {
    return program.methods
      .depositPool(new BN(amount))
      .accounts({
        depositor: authority.publicKey,
        depositorUsdc,
        tokenState: client.pdas.tokenState(mint)[0],
        slashingBond: client.pdas.slashingBond(mint)[0],
        redemptionVault: client.pdas.redemptionVault(mint)[0],
        usdcMint,
        usdcTokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc();
  }

  /** mint → issue → manifest → operator terms → deposit (bond + redemption pool) → metering starts. */
  async function setupToken(m: ManifestOpts & { maxFee?: number; termLen?: BN; tiers?: number[] } = {}): Promise<PublicKey> {
    const mint = await createTorusMint({ maxFee: m.maxFee, mintAuthority: m.issuer });
    await issueTokenTx(mint, m.issuer ?? issuer, FEE_BPS, m.maxFee ?? MAX_FEE);
    await setManifestTx(mint, m.termLen ?? TERM_LEN, m);
    await setTermsTx(mint, authority, BOND_TARGET, MIN_PRICE, m.tiers ?? TIER_SHARES);
    await depositTx(mint, DEPOSIT);
    // The bond is full, so the first provision sets the metering baseline (redemptions start; earlier volume is not counted).
    await provision(mint);
    return mint;
  }

  /** Ledger (return promises): pop leaves with distinct payment IDs and recipients, summing to controlTotal, sorted by payment ID. */
  function buildTree(controlTotal: number, pop = POP, ids?: Buffer[]): SumTree {
    const values = distributeLeafValues(controlTotal, pop);
    const entries = values.map((value, i) => ({ outcomeId: ids?.[i] ?? newOutcome(), beneficiary: Keypair.generate().publicKey, value }));
    return new SumTree(sortByOutcome(entries));
  }

  /** Volume → harvest → provision (up to a period with volume). */
  async function accrueAndProvision(mint: PublicKey) {
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);
    const { periodId, budget } = await provisionUntilBudget(mint);
    return { periodId, budget };
  }

  /** Registry record of the auditor named in the manifest (commit checks it is still active). */
  async function manifestAuditorRecord(mint: PublicKey): Promise<PublicKey> {
    const m: any = await program.account.manifest.fetch(client.pdas.manifest(mint)[0]);
    return client.pdas.auditorRecord(m.auditor)[0];
  }

  async function commitTx(mint: PublicKey, periodId: BN, tree: SumTree, controlTotal: number, signer: Keypair = issuer) {
    return program.methods
      .commitPerformance(tree.commitmentArray(), new BN(controlTotal), tree.populationSize)
      .accounts({
        issuer: signer.publicKey,
        tokenState: client.pdas.tokenState(mint)[0],
        manifest: client.pdas.manifest(mint)[0],
        auditorRecord: await manifestAuditorRecord(mint),
        audit: client.pdas.audit(mint, periodId)[0],
        systemProgram: SystemProgram.programId,
      })
      .signers(signer === issuer ? [] : [signer])
      .rpc();
  }

  /** Uniqueness check for leaves start ≤ i < end. */
  async function uniquenessBatch(mint: PublicKey, periodId: BN, tree: SumTree, start: number, end: number, restart = false) {
    const ix = await client.verifyUniqueness({ crank: issuer.publicKey, mint, periodId, tree, start, end, restart });
    const tx = new Transaction().add(ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), ix);
    return sendAndConfirmTransaction(connection, tx, [authority]);
  }

  /** Sends all leaves and verifies uniqueness. */
  async function verifyUniqueness(mint: PublicKey, periodId: BN, tree: SumTree, restart = false) {
    for (let start = 0; start < tree.populationSize; start += UNIQ_BATCH) {
      await uniquenessBatch(mint, periodId, tree, start, start + UNIQ_BATCH, restart && start === 0);
    }
  }

  async function waitAfterCommit(mint: PublicKey, periodId: BN) {
    // The sample must be designated in a slot after the commitment.
    const committed: any = await program.account.auditCycle.fetch(client.pdas.audit(mint, periodId)[0]);
    const committedSlot = (committed.committedSlot as BN).toNumber();
    while ((await connection.getSlot("confirmed")) <= committedSlot) {
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  function designateTx(mint: PublicKey, periodId: BN, signer: Keypair = authority) {
    return program.methods
      .designateSample(Array(32).fill(7))
      .accounts({ crank: signer.publicKey, config: client.pdas.config()[0], audit: client.pdas.audit(mint, periodId)[0] })
      .signers(signer === authority ? [] : [signer])
      .rpc();
  }

  async function sampledIndices(mint: PublicKey, periodId: BN): Promise<number[]> {
    const a: any = await program.account.auditCycle.fetch(client.pdas.audit(mint, periodId)[0]);
    return (a.sampleIndices as any[]).map((i) => Number(i));
  }

  /** provision → build ledger → commit → uniqueness → sample. Returns the tree and the sample for the proofs. */
  async function commitAndSample(mint: PublicKey, controlTotalOf: (budget: number) => number, pop = POP, uniq = true) {
    const { periodId, budget } = await accrueAndProvision(mint);
    assert.equal(budget, OBLIGATION, "budget = VOLUME * return_rate");

    // Ledger: pop leaves summing exactly to control_total (sum binding).
    const controlTotal = controlTotalOf(budget);
    const tree = buildTree(controlTotal, pop);
    assert.equal(tree.total.toString(), controlTotal.toString(), "root_sum == control_total");

    await commitTx(mint, periodId, tree, controlTotal);
    if (uniq) await verifyUniqueness(mint, periodId, tree);
    await waitAfterCommit(mint, periodId);
    await designateTx(mint, periodId);

    const sampleIndices = await sampledIndices(mint, periodId);
    const m: any = await program.account.manifest.fetch(client.pdas.manifest(mint)[0]);
    assert.equal(sampleIndices.length, Math.min(m.sampleSize, pop), "the sample size is the one fixed in the manifest");

    return { periodId, budget, controlTotal, tree, sampleIndices };
  }

  /** Submits the sampled leaves' proofs in order and returns the claimed total fixed on-chain. */
  async function submitDisclosures(mint: PublicKey, periodId: BN, tree: SumTree, sampleIndices: number[]): Promise<bigint> {
    let asserted = 0n;
    for (const index of sampleIndices) {
      const value = tree.valueAt(index);
      await program.methods
        .verifyDisclosure(tree.outcomeAt(index), tree.beneficiaryAt(index), new BN(value.toString()), tree.proof(index))
        .accounts({ crank: authority.publicKey, audit: client.pdas.audit(mint, periodId)[0] })
        .rpc();
      asserted += value;
    }
    const audit: any = await program.account.auditCycle.fetch(client.pdas.audit(mint, periodId)[0]);
    assert.equal(audit.verifyCursor, sampleIndices.length, "all sampled leaves disclosed");
    assert.equal((audit.assertedSampleSum as BN).toString(), asserted.toString(), "claimed values fixed on-chain");
    return asserted;
  }

  /** The auditor records an observed value per sample (f maps claimed → observed). */
  async function observe(mint: PublicKey, periodId: BN, signer: Keypair, f: (asserted: bigint, j: number) => bigint = (a) => a) {
    const audit: any = await program.account.auditCycle.fetch(client.pdas.audit(mint, periodId)[0]);
    const observed = (audit.sampleValues as BN[]).map((v, j) => f(BigInt(v.toString()), j));
    for (let i = 0; i < observed.length; i += OBS_BATCH) {
      await program.methods
        .recordVerification(observed.slice(i, i + OBS_BATCH).map((v) => new BN(v.toString())), Array(32).fill(9))
        .accounts({
          auditor: signer.publicKey,
          audit: client.pdas.audit(mint, periodId)[0],
          auditorRecord: client.pdas.auditorRecord(audit.auditor)[0],
        })
        .signers([signer])
        .rpc();
    }
  }

  function finalizeTx(mint: PublicKey, periodId: BN) {
    return program.methods
      .finalizeAudit()
      .accounts({
        crank: authority.publicKey,
        config: client.pdas.config()[0],
        tokenState: client.pdas.tokenState(mint)[0],
        manifest: client.pdas.manifest(mint)[0],
        audit: client.pdas.audit(mint, periodId)[0],
        taxReport: client.pdas.taxReport(mint, periodId)[0],
        poolAuthority: client.pdas.poolAuthority(mint)[0],
        slashingBond: client.pdas.slashingBond(mint)[0],
        issuerEscrow: client.pdas.issuerEscrow(mint)[0],
        slashDestination: slashDestAta,
        usdcMint,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc();
  }

  /** One cycle: volume → harvest → provision → commit → uniqueness → sample → proofs → observation → finalize. */
  async function runOneCycle(mint: PublicKey, scenario: "pass" | "attackX" | "attackY") {
    const { periodId, budget, tree, sampleIndices } = await commitAndSample(mint, (b) => {
      if (scenario !== "attackY") return b;
      // Attack Y: a control total 1 below obligation − band (with sum binding, the declared total alone cannot be lowered).
      return b - Math.floor((b * LCL_BPS) / BPS) - 1;
    });

    await submitDisclosures(mint, periodId, tree, sampleIndices);
    // Attack X: observed = claimed / 10 (every sample defective, residual beyond tolerance).
    await observe(mint, periodId, auditor, scenario === "attackX" ? (a) => a / 10n : (a) => a);

    const bondBefore = Number((await getAccount(connection, client.pdas.slashingBond(mint)[0])).amount);
    const slashBefore = Number((await getAccount(connection, slashDestAta)).amount);

    await finalizeTx(mint, periodId);

    const audit: any = await program.account.auditCycle.fetch(client.pdas.audit(mint, periodId)[0]);
    const tsAfter: any = await tokenState(mint);
    const slashAfter = Number((await getAccount(connection, slashDestAta)).amount);
    return { audit, tsAfter, slashed: slashAfter - slashBefore, bondBefore, periodId, budget, tree, sampleIndices };
  }

  /** The auditor confirms a leaf (by default its full value). */
  async function attestTx(mint: PublicKey, periodId: BN, tree: SumTree, index: number, confirmed?: bigint, signer: Keypair = auditor) {
    const ix = await client.attestLeaf({
      auditor: signer.publicKey,
      mint,
      periodId,
      tree,
      index,
      confirmed: new BN((confirmed ?? tree.valueAt(index)).toString()),
    });
    return sendAndConfirmTransaction(connection, new Transaction().add(ix), [signer]);
  }

  async function attestationIfAny(mint: PublicKey, periodId: BN, index: number): Promise<PublicKey | null> {
    const pda = client.pdas.attestation(client.pdas.audit(mint, periodId)[0], index)[0];
    return (await connection.getAccountInfo(pda)) ? pda : null;
  }

  /** If the leaf was not observed in the sample, the auditor confirms its value. */
  async function confirmLeaf(mint: PublicKey, periodId: BN, tree: SumTree, index: number) {
    if ((await sampledIndices(mint, periodId)).includes(index)) return;
    if (await attestationIfAny(mint, periodId, index)) return;
    await attestTx(mint, periodId, tree, index);
  }

  async function payoutTx(mint: PublicKey, periodId: BN, beneficiaryUsdc: PublicKey, index: number, tree: SumTree, value?: bigint) {
    const audit = client.pdas.audit(mint, periodId)[0];
    return program.methods
      .payout(index, tree.outcomeAt(index), new BN((value ?? tree.valueAt(index)).toString()), tree.proof(index))
      .accounts({
        crank: authority.publicKey,
        config: client.pdas.config()[0],
        tokenState: client.pdas.tokenState(mint)[0],
        audit,
        poolAuthority: client.pdas.poolAuthority(mint)[0],
        redemptionVault: client.pdas.redemptionVault(mint)[0],
        beneficiaryUsdc,
        attestation: await attestationIfAny(mint, periodId, index),
        claim: client.pdas.claim(audit, index)[0],
        usdcMint,
        usdcTokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  }

  function declareDefaultTx(mint: PublicKey, periodId: BN) {
    return program.methods
      .declareDefault()
      .accounts({
        crank: authority.publicKey,
        config: client.pdas.config()[0],
        tokenState: client.pdas.tokenState(mint)[0],
        audit: client.pdas.audit(mint, periodId)[0],
        poolAuthority: client.pdas.poolAuthority(mint)[0],
        slashingBond: client.pdas.slashingBond(mint)[0],
        issuerEscrow: client.pdas.issuerEscrow(mint)[0],
        slashDestination: slashDestAta,
        usdcMint,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc();
  }

  async function provisionLog(sig: string): Promise<string | undefined> {
    const bh = await connection.getLatestBlockhash();
    await connection.confirmTransaction({ signature: sig, ...bh }, "confirmed");
    for (let i = 0; i < 20; i++) {
      const txInfo = await connection.getTransaction(sig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
      const logs = txInfo?.meta?.logMessages ?? [];
      if (logs.length > 0) return logs.find((l) => l.includes("cross_check:"));
      await new Promise((r) => setTimeout(r, 500));
    }
    return undefined;
  }

  async function balance(acct: PublicKey, tokenProgram = TOKEN_PROGRAM_ID): Promise<number> {
    return Number((await getAccount(connection, acct, undefined, tokenProgram)).amount);
  }

  // ---------------------------------------------------------------- core scenarios

  it("(a) honest delivery passes; nothing is slashed", async () => {
    const mint = await setupToken();
    const { audit, tsAfter, slashed } = await runOneCycle(mint, "pass");
    assert.equal(audit.result, 1, "AuditResult::Pass");
    assert.equal(tsAfter.frozen, false, "not frozen");
    assert.equal(slashed, 0, "nothing slashed");
  });

  it("(b) attack X (overstatement) → FraudOverstatement, base tier, bond slashed", async () => {
    const mint = await setupToken();
    const { audit, tsAfter, slashed, bondBefore, periodId } = await runOneCycle(mint, "attackX");
    assert.equal(audit.result, 2, "AuditResult::FraudOverstatement");
    assert.equal(audit.defectCount, SAMPLE, "the program counts defects from the per-sample observations");
    assert.equal(tsAfter.tier, 0, "immediately back to the base tier");
    assert.equal(tsAfter.frozen, true, "frozen");
    assert.equal(slashed, bondBefore, "the whole bond goes to the slash destination");
    assert.isAbove(slashed, 0, "something was slashed");
    assert.equal((tsAfter.reserved as BN).toNumber(), 0, "the fraudulent period's reservation is released");
    frozenMint = mint;
    frozenPeriodId = periodId;
  });

  it("(c) under-delivery beyond the band is not slashed: one tier down, the gap is carried into the next obligation", async () => {
    const mint = await setupToken();
    const { audit, tsAfter, slashed, budget } = await runOneCycle(mint, "attackY");
    assert.equal(audit.result, 5, "AuditResult::Underdelivered");
    assert.equal(tsAfter.frozen, false, "not frozen");
    assert.equal(slashed, 0, "nothing slashed");
    const gap = budget - (audit.controlTotal as BN).toNumber();
    assert.isAbove(gap, 0, "the ledger was short of the obligation");
    assert.equal((tsAfter.unfulfilled as BN).toNumber(), gap, "the gap is carried");

    // The next obligation includes the carried gap (the period's own volume × rate, plus the gap).
    await depositTx(mint, OBLIGATION);
    const next = await accrueAndProvision(mint);
    const ts: any = await tokenState(mint);
    const own = ((ts.priorPeriodActivity as BN).toNumber() * RETURN_RATE_BPS) / BPS;
    assert.equal(next.budget, own + gap, "next obligation = own volume × rate + carried gap");
    assert.equal((ts.unfulfilled as BN).toNumber(), 0, "the carry moved into the obligation");
  });

  it("(d) issue_token rejects a mint without the Torus mechanism", async () => {
    const plainMint = await createMint(connection, authority, authority.publicKey, null, DECIMALS, undefined, undefined, TOKEN_2022_PROGRAM_ID);
    const msg = await failure(issueTokenTx(plainMint));
    assert.isNotNull(msg, "a mint without the extensions must not be accepted");
    assert.match(msg!, /MissingTransferHook|HookProgramMismatch|MissingTransferFee/, "rejected for the missing extensions");
  });

  it("(e) payout fails before finalization and for a fraudulent audit", async () => {
    // (e-1) No payout before finalization (stage = Sampled).
    const mint = await setupToken();
    const { periodId, tree } = await commitAndSample(mint, (b) => b);
    const ata = await createAssociatedTokenAccount(connection, authority, usdcMint, tree.beneficiaryAt(0));
    const beforeFinalize = await failure(payoutTx(mint, periodId, ata, 0, tree));
    assert.isNotNull(beforeFinalize, "a payout before finalization must be rejected");
    assert.match(beforeFinalize!, /InvalidAuditStage/, "rejected for the stage");

    // (e-2) No payout for leaves of an audit finalized as fraud.
    assert.isNotNull(frozenMint, "needs the token frozen in (b)");
    const afterFraud = await failure(payoutTx(frozenMint!, frozenPeriodId!, ata, 0, tree));
    assert.isNotNull(afterFraud, "a payout after fraud must be rejected");
    assert.match(afterFraud!, /Unauthorized/, "a fraudulent audit cannot be paid");
  });

  it("(f) self-transfers (same owner) are not volume but count for the fee cross-check", async () => {
    const mint = await setupToken();
    const volumePda = client.pdas.volumeCounter(mint)[0];
    const AMT = 100_000;

    const src = await createAssociatedTokenAccountIdempotent(connection, authority, mint, authority.publicKey, undefined, TOKEN_2022_PROGRAM_ID);
    const selfDst = await createAccount(connection, authority, mint, authority.publicKey, Keypair.generate(), undefined, TOKEN_2022_PROGRAM_ID);

    const before: any = await hook.account.volumeCounter.fetch(volumePda);

    const selfIx = await createTransferCheckedWithTransferHookInstruction(
      connection, src, mint, selfDst, authority.publicKey, BigInt(AMT), DECIMALS, [], "confirmed", TOKEN_2022_PROGRAM_ID,
    );
    await sendAndConfirmTransaction(connection, new Transaction().add(selfIx), [authority]);

    const afterSelf: any = await hook.account.volumeCounter.fetch(volumePda);
    assert.equal(afterSelf.total.toString(), before.total.toString(), "a self-transfer is not counted as volume");
    assert.equal(
      afterSelf.feeTotal.sub(before.feeTotal).toNumber(),
      (AMT * FEE_BPS) / BPS,
      "a self-transfer still pays the fee, so it counts toward the expected fee",
    );
    assert.isAbove(Number((await getAccount(connection, selfDst, undefined, TOKEN_2022_PROGRAM_ID)).amount), 0, "the self-transfer itself is allowed");

    // Control: a transfer to a different owner is counted.
    const dst = await createAssociatedTokenAccountIdempotent(connection, authority, mint, Keypair.generate().publicKey, undefined, TOKEN_2022_PROGRAM_ID);
    const ix = await createTransferCheckedWithTransferHookInstruction(
      connection, src, mint, dst, authority.publicKey, BigInt(AMT), DECIMALS, [], "confirmed", TOKEN_2022_PROGRAM_ID,
    );
    await sendAndConfirmTransaction(connection, new Transaction().add(ix), [authority]);
    const afterOther: any = await hook.account.volumeCounter.fetch(volumePda);
    assert.equal(afterOther.total.sub(afterSelf.total).toNumber(), AMT, "a transfer to someone else adds its amount");
  });

  it("(g) the fee cross-check runs and matches exactly", async () => {
    const mint = await setupToken();
    const tokenStatePda = client.pdas.tokenState(mint)[0];
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);

    const afterHarvest: any = await program.account.tokenState.fetch(tokenStatePda);
    const harvested = (afterHarvest.cumulativeHarvested as BN).toNumber();
    const vc: any = await hook.account.volumeCounter.fetch(client.pdas.volumeCounter(mint)[0]);
    assert.equal(harvested, (VOLUME * FEE_BPS) / BPS, "1% of 2_000_000 = 20_000 is collected");
    assert.equal(vc.feeTotal.toNumber(), harvested, "the hook's expected fee equals what was collected");

    const { sig } = await provisionUntilBudget(mint);
    const crossCheckLog = await provisionLog(sig);
    assert.isOk(crossCheckLog, "the cross-check ran (cross_check log present)");
    console.log(`      ${crossCheckLog!.replace(/^Program log: /, "")}`);

    const ts: any = await program.account.tokenState.fetch(tokenStatePda);
    assert.equal((ts.priorPeriodActivity as BN).toNumber(), VOLUME, "period volume");
    assert.equal((ts.budget as BN).toNumber(), OBLIGATION, "budget = VOLUME * return_rate");
  });

  it("(h) fees implied but not collected are rejected with CrossCheckMismatch", async () => {
    const mint = await setupToken();
    const tokenStatePda = client.pdas.tokenState(mint)[0];

    // --- Period 1: finalize one honest cycle (needed to move on) ---
    const first = await runOneCycle(mint, "pass");
    assert.equal(first.audit.result, 1, "period 1 passes");

    // --- Period 2: add volume but do not harvest (nothing collected) ---
    const second = await accrueVolume(mint, VOLUME);
    await waitPeriod(mint);
    const before: any = await program.account.tokenState.fetch(tokenStatePda);
    const rejected = await failure(provision(mint));
    assert.isNotNull(rejected, "fees implied but not collected must be rejected");
    assert.match(rejected!, /CrossCheckMismatch/, "rejected by the cross-check (downside band)");
    const afterReject: any = await program.account.tokenState.fetch(tokenStatePda);
    assert.equal(afterReject.periodId.toNumber(), before.periodId.toNumber(), "the period does not advance when rejected");

    // --- Even after harvesting, the pool is short while period 1's unpaid redemptions stay reserved ---
    // Of the 1_500_000 in the pool, 1_000_000 is reserved for period 1's recipients. Counting the same funds for
    // period 2's obligation would double count, so a period with volume is rejected (periods without volume pass with budget 0).
    await harvest(mint, [second.dst]);
    let doubleCounted: string | null = null;
    for (let i = 0; i < 100 && !doubleCounted; i++) {
      await waitPeriod(mint);
      doubleCounted = await failure(provision(mint));
    }
    assert.match(doubleCounted ?? "", /BudgetNotEscrowed/, "funds owed for unpaid redemptions are not counted again");

    // --- Control: depositing period 2's obligation makes it pass ---
    const stuck: any = await program.account.tokenState.fetch(tokenStatePda);
    await depositTx(mint, OBLIGATION);
    assert.isNull(await failure(provision(mint)), "succeeds with fees collected and enough funds");
    const afterFix: any = await program.account.tokenState.fetch(tokenStatePda);
    assert.equal((afterFix.reserved as BN).toNumber(), 2 * OBLIGATION, "both period 1's unpaid amount and period 2's obligation are reserved");
    assert.equal(afterFix.periodId.toNumber(), stuck.periodId.toNumber() + 1, "the period advances");
  });

  it("(i) after the manifest expires a period gets no obligation, so nothing can be committed; a new campaign brings it back", async () => {
    const mint = await setupToken({ termLen: new BN(4) });
    const m: any = await program.account.manifest.fetch(client.pdas.manifest(mint)[0]);
    const validUntil = (m.validUntil as BN).toNumber();
    await waitChainTime(validUntil);
    await waitNextBoundary(mint);

    // Volume in a period that started after the term: it closes with no obligation, so there is nothing to commit to
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);
    const k = await lastTransferPeriod(mint);
    assert.isAbove(await periodStart(mint, k), validUntil, "the volume fell after the term");
    const budgets = await closeThrough(mint, k);
    assert.isNotEmpty(budgets, "the period with the volume was closed here");
    assert.deepEqual(budgets, budgets.map(() => 0), "no obligation under an expired manifest");
    const ts: any = await tokenState(mint);
    const none = await failure(commitTx(mint, ts.periodId, buildTree(OBLIGATION), OBLIGATION));
    assert.match(none ?? "", /BudgetNotProvisioned/, "nothing to commit to");

    // Control: a new campaign; a period that starts after it has an obligation again and can be committed
    await setManifestTx(mint, TERM_LEN);
    await waitNextBoundary(mint);
    const { periodId, budget } = await accrueAndProvision(mint);
    assert.equal(budget, OBLIGATION, "obligations are back under the new campaign");
    assert.isNull(await failure(commitTx(mint, periodId, buildTree(budget), budget)), "committing works under the new campaign");
  });

  // ---------------------------------------------------------------- fixed holes

  it("(j) payouts only to the committed leaf's recipient, the confirmed amount, once", async () => {
    const mint = await setupToken();
    const { audit, periodId, tree, sampleIndices } = await runOneCycle(mint, "pass");
    assert.equal(audit.result, 1, "a passing audit");
    const vault = client.pdas.redemptionVault(mint)[0];

    // Attack: a third party tries to pay itself (an earlier version allowed any amount to any account).
    const attacker = Keypair.generate();
    const attackerUsdc = await createAssociatedTokenAccountIdempotent(connection, authority, usdcMint, attacker.publicKey);
    const stolen = await failure(payoutTx(mint, periodId, attackerUsdc, 1, tree));
    assert.isNotNull(stolen, "a payout to someone other than the recipient must be rejected");
    assert.match(stolen!, /ClaimProofInvalid/, "the destination owner is not the leaf's recipient");

    // Attack: claim more than the leaf's value, even to the right recipient.
    const ben2 = await createAssociatedTokenAccountIdempotent(connection, authority, usdcMint, tree.beneficiaryAt(2));
    const inflated = await failure(payoutTx(mint, periodId, ben2, 2, tree, tree.valueAt(2) + 1n));
    assert.isNotNull(inflated, "a claim above the leaf's value must be rejected");
    assert.match(inflated!, /ClaimProofInvalid/, "the amount does not match the leaf");

    // An unconfirmed leaf (not sampled, no auditor confirmation) is not paid.
    const unconfirmed = [...Array(POP).keys()].find((i) => !sampleIndices.includes(i))!;
    const benU = await createAssociatedTokenAccountIdempotent(connection, authority, usdcMint, tree.beneficiaryAt(unconfirmed));
    assert.match((await failure(payoutTx(mint, periodId, benU, unconfirmed, tree))) ?? "", /LeafNotConfirmed/, "no payout for an unconfirmed leaf");

    // Legitimate: the recipient claims its confirmed leaf and receives the leaf's value.
    await confirmLeaf(mint, periodId, tree, 0);
    const ben0 = await createAssociatedTokenAccountIdempotent(connection, authority, usdcMint, tree.beneficiaryAt(0));
    const vaultBefore = await balance(vault);
    await payoutTx(mint, periodId, ben0, 0, tree);
    assert.equal(await balance(ben0), Number(tree.valueAt(0)), "receives the leaf's value");
    assert.equal(vaultBefore - (await balance(vault)), Number(tree.valueAt(0)), "the pool decreases by the leaf's value");

    // Attack: a second claim on the same leaf.
    const twice = await failure(payoutTx(mint, periodId, ben0, 0, tree));
    assert.isNotNull(twice, "a double claim must be rejected");
    assert.match(twice!, /already in use/, "the claim record already exists");
  });

  it("(l) key checks at issuance: freeze authority, PermanentDelegate, someone else's mint, fee schedule swap", async () => {
    // A mint with a freeze authority (the issuer could freeze the fee vault or holders).
    const withFreeze = await createTorusMint({ freezeAuthority: authority.publicKey });
    const m1 = await failure(issueTokenTx(withFreeze));
    assert.match(m1 ?? "", /FreezeAuthorityPresent/, "rejected with a freeze authority");

    // With a PermanentDelegate (could move tokens out of any account, including the fee vault).
    const withDelegate = await createTorusMint({ permanentDelegate: authority.publicKey });
    const m2 = await failure(issueTokenTx(withDelegate));
    assert.match(m2 ?? "", /DisallowedMintExtension/, "rejected with a disallowed extension");

    // Registering someone else's mint (the signer is not the mint authority).
    const legit = await createTorusMint();
    const squatter = Keypair.generate();
    await airdrop(squatter.publicKey);
    const m3 = await failure(issueTokenTx(legit, squatter));
    assert.match(m3 ?? "", /MintAuthorityNotIssuer/, "rejected unless the signer is the mint authority");
    assert.isNull(await failure(issueTokenTx(legit)), "control: the real issuer can register");

    // Fee schedule swap: only the newer config matches the declared rate while the older (current) one differs, then the authority is revoked.
    const swapped = await createTorusMint({ feeConfigAuthority: authority.publicKey });
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        createSetTransferFeeInstruction(swapped, authority.publicKey, [], 200, BigInt(MAX_FEE), TOKEN_2022_PROGRAM_ID),
        createSetAuthorityInstruction(swapped, authority.publicKey, AuthorityType.TransferFeeConfig, null, [], TOKEN_2022_PROGRAM_ID),
      ),
      [authority],
    );
    const m4 = await failure(issueTokenTx(swapped, issuer, 200, MAX_FEE));
    assert.match(m4 ?? "", /FeeScheduleNotConstant/, "rejected when older and newer configs differ");
  });

  it("(m) manifest: caps on thresholds, minimum sample size, maximum allowed defects, registered auditor", async () => {
    const mint = await createTorusMint();
    await issueTokenTx(mint);

    const t = await failure(setManifestTx(mint, TERM_LEN, { toleranceBps: 2_001 }));
    assert.match(t ?? "", /ToleranceTooLarge/, "a tolerance that disables detection is rejected");

    const s = await failure(setManifestTx(mint, TERM_LEN, { sampleSize: MIN_SAMPLE - 1 }));
    assert.match(s ?? "", /SampleSizeBelowMinimum/, "a sample below the minimum is rejected");

    const d = await failure(setManifestTx(mint, TERM_LEN, { sampleSize: 10, maxDefects: 3 }));
    assert.match(d ?? "", /TooManyAllowedDefects/, "allowed defects at most 20% of the sample");

    const stranger = Keypair.generate();
    const a = await failure(setManifestTx(mint, TERM_LEN, { auditor: stranger.publicKey }));
    assert.match(a ?? "", /AccountNotInitialized|AuditorNotRegistered/, "an unregistered auditor cannot be named");

    assert.isNull(await failure(setManifestTx(mint, TERM_LEN)), "control: within the caps and registered, it works");
  });

  it("(n) provisioning requires the period to elapse and the previous audit to be final", async () => {
    // No provisioning before the period (60 s) has elapsed.
    const slow = await setupToken({ periodLen: 60 });
    const { dst } = await accrueVolume(slow, VOLUME);
    await harvest(slow, [dst]);
    const early = await failure(provision(slow));
    assert.match(early ?? "", /PeriodNotElapsed/, "rejected before the period ends");

    // Provision period 1, only commit, and try to move to period 2 without finalizing.
    const mint = await setupToken();
    const { periodId, budget } = await accrueAndProvision(mint);
    await commitTx(mint, periodId, buildTree(budget), budget);
    const more = await accrueVolume(mint, VOLUME);
    await harvest(mint, [more.dst]);
    await waitPeriod(mint);

    const skipNull = await failure(provision(mint, null));
    assert.match(skipNull ?? "", /PreviousAuditNotFinalized/, "rejected without the previous audit");
    const skipOpen = await failure(provision(mint));
    assert.match(skipOpen ?? "", /PreviousAuditNotFinalized/, "rejected while the previous audit is open");
  });

  it("(o) an expired audit is a default: a missing commitment or disclosures is slashed; a silent auditor is not the issuer's fault", async () => {
    // --- No commitment ---
    const lazy = await setupToken();
    const { periodId } = await accrueAndProvision(lazy);
    const tooEarly = await failure(declareDefaultTx(lazy, periodId));
    assert.match(tooEarly ?? "", /DefaultNotDue/, "no default before the deadline");

    const ts1: any = await tokenState(lazy);
    await waitChainTime((ts1.auditDeadline as BN).toNumber());
    const bond = await balance(client.pdas.slashingBond(lazy)[0]);
    const slashBefore = await balance(slashDestAta);
    await declareDefaultTx(lazy, periodId);
    const after1: any = await tokenState(lazy);
    assert.equal(after1.frozen, true, "frozen on default");
    assert.equal(after1.tier, 0, "back to the base tier");
    assert.equal((await balance(slashDestAta)) - slashBefore, bond, "the whole bond is slashed");
    assert.equal((after1.reserved as BN).toNumber(), 0, "the defaulted period's reservation is released");

    // --- The sample is drawn but the issuer never discloses ---
    const silent = await setupToken();
    const c = await commitAndSample(silent, (b) => b);
    const ts2: any = await tokenState(silent);
    await waitChainTime((ts2.auditDeadline as BN).toNumber());
    await declareDefaultTx(silent, c.periodId);
    const audit2: any = await program.account.auditCycle.fetch(client.pdas.audit(silent, c.periodId)[0]);
    assert.equal(audit2.result, 3, "withheld disclosures are finalized as FraudUnderstatement");
    assert.equal(audit2.stage, 3, "Finalized");

    // --- Control: everything is disclosed but the auditor does not record (not the issuer's fault) ---
    const stalled = await setupToken();
    const d = await commitAndSample(stalled, (b) => b);
    await submitDisclosures(stalled, d.periodId, d.tree, d.sampleIndices);
    const ts3: any = await tokenState(stalled);
    await waitChainTime((ts3.auditDeadline as BN).toNumber());
    const notIssuers = await failure(declareDefaultTx(stalled, d.periodId));
    assert.match(notIssuers ?? "", /DefaultNotDue/, "a silent auditor is not the issuer's default");
  });

  it("(p) only the operator designates the sample; its size is fixed by the manifest", async () => {
    const mint = await setupToken({ sampleSize: 6 });
    const { periodId, budget } = await accrueAndProvision(mint);
    await commitTx(mint, periodId, buildTree(budget), budget);
    await waitAfterCommit(mint, periodId);

    const outsider = Keypair.generate();
    await airdrop(outsider.publicKey, 1);
    const byOutsider = await failure(designateTx(mint, periodId, outsider));
    assert.match(byOutsider ?? "", /Unauthorized/, "only the operator can supply entropy");

    await designateTx(mint, periodId);
    const audit: any = await program.account.auditCycle.fetch(client.pdas.audit(mint, periodId)[0]);
    assert.equal(audit.sampleIndices.length, 6, "the sample size is the manifest's (the caller cannot choose)");
  });

  it("(q) self-transfers and the fee cap do not trip the cross-check", async () => {
    // Repeated self-transfers add fees without volume (an earlier version stalled provisioning here).
    const mint = await setupToken();
    const { src, dst } = await accrueVolume(mint, VOLUME);
    const selfDst = await createAccount(connection, authority, mint, authority.publicKey, Keypair.generate(), undefined, TOKEN_2022_PROGRAM_ID);
    for (let i = 0; i < 3; i++) {
      const ix = await createTransferCheckedWithTransferHookInstruction(
        connection, src, mint, selfDst, authority.publicKey, BigInt(VOLUME / 4), DECIMALS, [], "confirmed", TOKEN_2022_PROGRAM_ID,
      );
      await sendAndConfirmTransaction(connection, new Transaction().add(ix), [authority]);
    }
    await harvest(mint, [dst, selfDst]);
    await waitPeriod(mint);
    assert.isNull(await failure(provision(mint)), "fees from self-transfers do not block provisioning");

    // A large transfer hitting the fee cap (an earlier version ignored the cap and stalled).
    const capped = await setupToken({ maxFee: 5_000 });
    const big = await accrueVolume(capped, VOLUME); // 1% = 20_000 → capped at 5_000
    await harvest(capped, [big.dst]);
    const vc: any = await hook.account.volumeCounter.fetch(client.pdas.volumeCounter(capped)[0]);
    assert.equal(vc.feeTotal.toNumber(), 5_000, "the expected fee includes the cap");
    await waitPeriod(capped);
    assert.isNull(await failure(provision(capped)), "a capped fee does not block provisioning");
  });

  it("(r) delegated transfers go through the hook and count as volume", async () => {
    const mint = await setupToken();
    const src = await createAssociatedTokenAccountIdempotent(connection, authority, mint, authority.publicKey, undefined, TOKEN_2022_PROGRAM_ID);
    const delegate = Keypair.generate();
    await approveChecked(connection, authority, mint, src, delegate.publicKey, authority, VOLUME, DECIMALS, [], undefined, TOKEN_2022_PROGRAM_ID);
    const dst = await createAssociatedTokenAccountIdempotent(connection, authority, mint, Keypair.generate().publicKey, undefined, TOKEN_2022_PROGRAM_ID);

    const before: any = await hook.account.volumeCounter.fetch(client.pdas.volumeCounter(mint)[0]);
    const ix = await createTransferCheckedWithTransferHookInstruction(
      connection, src, mint, dst, delegate.publicKey, BigInt(100_000), DECIMALS, [], "confirmed", TOKEN_2022_PROGRAM_ID,
    );
    await sendAndConfirmTransaction(connection, new Transaction().add(ix), [authority, delegate]);
    const after: any = await hook.account.volumeCounter.fetch(client.pdas.volumeCounter(mint)[0]);
    assert.equal(after.total.sub(before.total).toNumber(), 100_000, "a delegated transfer is counted");
  });

  it("(s) fake leaves outside the declared population cannot inflate the total", async () => {
    const mint = await setupToken();
    const { periodId, budget } = await accrueAndProvision(mint);

    // Only half the obligation is real; the other half is fake leaves placed outside the population.
    const half = Math.floor(budget / 2);
    const entries = (total: number) =>
      distributeLeafValues(total, POP).map((value) => ({ outcomeId: newOutcome(), beneficiary: Keypair.generate().publicKey, value }));
    const big = new SumTree(sortByOutcome([...entries(half), ...entries(budget - half)])); // 16 leaves
    assert.equal(big.total.toString(), budget.toString(), "with the fake leaves the total reaches the obligation");

    // The commitment declares a population of 8 (samples only come from 0..7).
    const u64 = Buffer.alloc(8);
    u64.writeBigUInt64LE(big.root.sum, 0);
    const u32 = Buffer.alloc(4);
    u32.writeUInt32LE(POP, 0);
    const commitment = Buffer.from(keccak_256(Buffer.concat([Buffer.from([ROOT_TAG]), big.root.hash, u64, u32])));
    await program.methods
      .commitPerformance(Array.from(commitment), new BN(budget), POP)
      .accounts({
        issuer: issuer.publicKey,
        tokenState: client.pdas.tokenState(mint)[0],
        manifest: client.pdas.manifest(mint)[0],
        auditorRecord: await manifestAuditorRecord(mint),
        audit: client.pdas.audit(mint, periodId)[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    await waitAfterCommit(mint, periodId);
    await designateTx(mint, periodId);
    const index = (await sampledIndices(mint, periodId))[0];

    // A proof from the 16-leaf tree (4 siblings) does not fit the shape for 8 leaves (3), so it fails.
    const shape = await failure(
      program.methods
        .verifyDisclosure(big.outcomeAt(index), big.beneficiaryAt(index), new BN(big.valueAt(index).toString()), big.proof(index))
        .accounts({ crank: authority.publicKey, audit: client.pdas.audit(mint, periodId)[0] })
        .rpc(),
    );
    assert.isNotNull(shape, "a proof from a tree with leaves outside the population must be rejected");
    assert.match(shape!, /ProofShapeMismatch/, "the proof shape does not match index and population");
  });

  // ---------------------------------------------------------------- forced deposit of fees

  /** Fee conversion (registered partner): pays usdcAmount, receives tokenAmount brand tokens from fee_vault. */
  async function convertTx(mint: PublicKey, tokenAmount: number, usdcAmount: number, who: Keypair = partner) {
    const partnerToken = await createAssociatedTokenAccountIdempotent(connection, authority, mint, who.publicKey, undefined, TOKEN_2022_PROGRAM_ID);
    const whoUsdc =
      who === partner ? partnerUsdc : await createAssociatedTokenAccountIdempotent(connection, authority, usdcMint, who.publicKey);
    const ix = await client.convertFees({
      partner: who.publicKey,
      mint,
      partnerToken,
      partnerUsdc: whoUsdc,
      usdcMint,
      treasury: treasuryAta,
      usdcTokenProgram: TOKEN_PROGRAM_ID,
      tokenAmount: new BN(tokenAmount),
      usdcAmount: new BN(usdcAmount),
    });
    const tx = new Transaction().add(ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), ix);
    return sendAndConfirmTransaction(connection, tx, [authority, who]);
  }

  /** A token funded by fees only: issue → manifest → operator terms (no deposit) → volume → harvest (20_000 in fees). */
  async function setupFeeFunded(): Promise<PublicKey> {
    const mint = await createTorusMint();
    await issueTokenTx(mint);
    await setManifestTx(mint, TERM_LEN);
    await setTermsTx(mint);
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);
    return mint;
  }

  /**
   * Fill the bond from fees only (base-tier ratio 20%; the operator's share comes off first, the bond is filled from the issuer's):
   *   1st 10_000 → 3_000_000: operator 2_400_000 / issuer 600_000 → all to the bond (target 1_000_000 not reached)
   *   2nd 10_000 → 5_000_000: operator 4_000_000 / issuer 1_000_000 → bond 400_000 (reached) → 600_000 left.
   *        Metering has not started, so nothing is owed to the pool → it goes to the escrow
   */
  async function convertTwice(mint: PublicKey) {
    await convertTx(mint, 10_000, 3_000_000);
    const ts: any = await tokenState(mint);
    const afterFirst = {
      bond: await balance(client.pdas.slashingBond(mint)[0]),
      vault: await balance(client.pdas.redemptionVault(mint)[0]),
      escrow: await balance(client.pdas.issuerEscrow(mint)[0]),
      started: ts.redemptionStarted as boolean,
    };
    await convertTx(mint, 10_000, 5_000_000);
    return afterFirst;
  }

  /**
   * After the bond is full: start metering (baseline), fill the pool up to the obligation with period 1's volume and conversion, then provision.
   *   conversion 10_000 → 5_000_000: operator 4_000_000 / issuer 1_000_000 → bond full → pool up to the expected 1_000_000
   */
  async function startAndProvisionFirstPeriod(mint: PublicKey) {
    await provision(mint);
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);
    await convertTx(mint, 10_000, 5_000_000);
    await provisionUntilBudget(mint);
    return tokenState(mint);
  }

  /** For the provisioned period: commit → uniqueness → sample → proofs → observation → finalize. */
  async function auditPeriod(mint: PublicKey, periodId: BN, controlTotal: number, scenario: "pass" | "attackX", signer: Keypair = issuer) {
    const tree = buildTree(controlTotal);
    await commitTx(mint, periodId, tree, controlTotal, signer);
    await verifyUniqueness(mint, periodId, tree);
    await waitAfterCommit(mint, periodId);
    await designateTx(mint, periodId);
    const indices = await sampledIndices(mint, periodId);
    await submitDisclosures(mint, periodId, tree, indices);
    await observe(mint, periodId, auditor, scenario === "attackX" ? (a) => a / 10n : (a) => a);
    await finalizeTx(mint, periodId);
    return tree;
  }

  it("(t) forced deposit: operator share first, then from the issuer's share bond → pool → escrow; nothing starts until the bond is full", async () => {
    const mint = await setupFeeFunded();
    const tsPda = client.pdas.tokenState(mint)[0];
    const vault = client.pdas.redemptionVault(mint)[0];
    const escrow = client.pdas.issuerEscrow(mint)[0];
    const bond = client.pdas.slashingBond(mint)[0];
    assert.equal(await balance(client.pdas.feeVault(mint)[0], TOKEN_2022_PROGRAM_ID), 20_000, "20_000 in fees swept into the vault");
    const vcBefore: any = await hook.account.volumeCounter.fetch(client.pdas.volumeCounter(mint)[0]);
    const treasuryBefore = await balance(treasuryAta);

    // No redemptions until the bond reaches its target (no metering, no provisioning)
    assert.match((await failure(provision(mint))) ?? "", /BondTargetNotReached/, "no provisioning before the bond is full");

    const first = await convertTwice(mint);
    assert.equal(first.bond, 600_000, "1. from the issuer's share (20%, after the operator's share) the bond comes first");
    assert.equal(first.vault + first.escrow, 0, "until the bond is full, nothing goes to the pool or the escrow");
    assert.equal(first.started, false, "no redemptions before the bond is full");
    assert.equal(await balance(bond), BOND_TARGET.toNumber(), "2. the second conversion fills the bond");
    assert.equal(await balance(vault), 0, "volume before metering creates no obligation, so nothing goes to the pool");
    assert.equal(await balance(escrow), 600_000, "the rest of the issuer's share goes to the escrow");
    assert.equal((await balance(treasuryAta)) - treasuryBefore, 6_400_000, "the operator's share (1 − ratio) never goes into the bond");
    const ts1: any = await program.account.tokenState.fetch(tsPda);
    assert.equal(ts1.redemptionStarted, true, "bond full: redemptions start");
    assert.equal((ts1.issuerAccruing as BN).toNumber(), 600_000, "the issuer share is recorded for the current period");
    const vcAfter: any = await hook.account.volumeCounter.fetch(client.pdas.volumeCounter(mint)[0]);
    assert.equal(vcAfter.total.toString(), vcBefore.total.toString(), "conversions (transfers out of the vault) are not volume");

    // Start of redemptions: the first provision only sets the baseline (the 2_000_000 traded before is not counted)
    await provision(mint);
    const ts2: any = await program.account.tokenState.fetch(tsPda);
    assert.equal(ts2.periodsStarted, true, "metering started");
    assert.equal((ts2.budget as BN).toNumber(), 0, "volume before the bond was full creates no obligation");
    assert.equal(ts2.currentPeriodActivity.toString(), vcAfter.total.toString(), "baseline = cumulative volume when the bond became full");

    // Period 1 volume and conversion: the bond is full, so the issuer's share fills the pool up to the expected obligation
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);
    await convertTx(mint, 10_000, 5_000_000);
    assert.equal(await balance(vault), OBLIGATION, "3. the pool is filled up to the obligation (the budget the period's volume will create)");
    assert.equal(await balance(escrow), 600_000, "all of it fills the pool; the escrow does not grow");
    assert.equal(((await tokenState(mint)).issuerClaimable as BN).toNumber(), 0, "the current period's share is not released yet");

    const p = await provisionUntilBudget(mint);
    const ts3: any = await program.account.tokenState.fetch(tsPda);
    assert.equal(p.budget, OBLIGATION, "budget = period 1 volume × return rate");
    assert.equal((ts3.reserved as BN).toNumber(), OBLIGATION, "the obligation is reserved in the pool");
    assert.equal((ts3.issuerPending as BN).toNumber(), 600_000, "the share from the closed period waits for this audit");
    assert.equal((ts3.issuerClaimable as BN).toNumber(), 0, "not released before the audit is final");

    // Audit (pass) → released inside the escrow (spent only through approved withdrawal requests, see (ak)-(ao))
    const tree = await auditPeriod(mint, ts3.periodId, OBLIGATION, "pass");
    const ts4: any = await program.account.tokenState.fetch(tsPda);
    assert.equal((ts4.issuerClaimable as BN).toNumber(), 600_000, "released after a clean result");
    assert.equal(await balance(escrow), 600_000, "the released share stays in the escrow");

    // Payouts reduce the reservation
    await confirmLeaf(mint, ts3.periodId, tree, 0);
    const ben0 = await createAssociatedTokenAccount(connection, authority, usdcMint, tree.beneficiaryAt(0));
    await payoutTx(mint, ts3.periodId, ben0, 0, tree);
    const ts5: any = await program.account.tokenState.fetch(tsPda);
    assert.equal((ts5.reserved as BN).toNumber(), OBLIGATION - Number(tree.valueAt(0)), "the reservation drops by what was paid");
  });

  it("(u) conversion rejected: only the operator sets terms; unset, below minimum bond, below minimum price, unregistered partner", async () => {
    const mint = await createTorusMint();
    await issueTokenTx(mint);
    await setManifestTx(mint, TERM_LEN);
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);

    // No deposit or conversion while the terms are unset (redemptions cannot start with a zero bond)
    assert.match((await failure(depositTx(mint, DEPOSIT))) ?? "", /IssuerTermsNotSet/, "no deposit without a bond target");
    // (without terms there is no local partner either, so its record is missing)
    assert.match(
      (await failure(convertTx(mint, 10_000, 3_000_000))) ?? "",
      /IssuerTermsNotSet|AccountNotInitialized/,
      "no conversion without terms",
    );

    // Only the operator sets terms; the bond target must be at least the minimum fixed at initialize
    const outsider = Keypair.generate();
    await airdrop(outsider.publicKey, 1);
    assert.match((await failure(setTermsTx(mint, outsider))) ?? "", /Unauthorized/, "only the operator sets the bond");
    assert.match((await failure(setTermsTx(mint, authority, new BN(0)))) ?? "", /InvalidIssuerTerms/, "a zero bond is rejected");
    assert.match((await failure(setTermsTx(mint, authority, MIN_BOND.subn(1)))) ?? "", /BondBelowMinimum/, "a bond below the minimum is rejected");
    await setTermsTx(mint);

    // Below the minimum price: 10_000 units (0.01 token) must cost at least 10_000
    assert.match((await failure(convertTx(mint, 10_000, 9_999))) ?? "", /ConversionBelowMinPrice/, "a purchase below the minimum price is rejected");
    assert.match((await failure(convertTx(mint, 20_001, 100_000_000))) ?? "", /InvalidConversionAmount/, "more than the vault holds is rejected");
    const stranger = Keypair.generate();
    await airdrop(stranger.publicKey, 1);
    assert.match(
      (await failure(convertTx(mint, 10_000, 3_000_000, stranger))) ?? "",
      /AccountNotInitialized|PartnerNotRegistered/,
      "an unregistered partner cannot convert",
    );
    assert.isNull(await failure(convertTx(mint, 10_000, 10_000)), "control: exactly the minimum price works");
  });

  it("(v) once fraud is established, the issuer escrow is slashed too", async () => {
    const mint = await setupFeeFunded();
    await convertTwice(mint);
    const escrow = client.pdas.issuerEscrow(mint)[0];
    assert.equal(await balance(escrow), 600_000, "the issuer share is in the escrow");

    const ts = await startAndProvisionFirstPeriod(mint);
    const slashBefore = await balance(slashDestAta);
    await auditPeriod(mint, ts.periodId, OBLIGATION, "attackX");

    const audit: any = await program.account.auditCycle.fetch(client.pdas.audit(mint, ts.periodId)[0]);
    assert.equal(audit.result, 2, "FraudOverstatement");
    assert.equal(await balance(escrow), 0, "the escrow is empty");
    assert.equal((await balance(slashDestAta)) - slashBefore, BOND_TARGET.toNumber() + 600_000, "both the bond and the issuer share are slashed");
    const after: any = await tokenState(mint);
    assert.equal((after.issuerPending as BN).toNumber() + (after.issuerClaimable as BN).toNumber(), 0, "nothing left to claim");
  });

  function replaceAuditorTx(mint: PublicKey, periodId: BN, currentAuditor: PublicKey, newAuditor: PublicKey, signer: Keypair = authority) {
    return program.methods
      .replaceAuditor()
      .accounts({
        authority: signer.publicKey,
        config: client.pdas.config()[0],
        tokenState: client.pdas.tokenState(mint)[0],
        manifest: client.pdas.manifest(mint)[0],
        audit: client.pdas.audit(mint, periodId)[0],
        currentAuditorRecord: client.pdas.auditorRecord(currentAuditor)[0],
        newAuditor,
        newAuditorRecord: client.pdas.auditorRecord(newAuditor)[0],
      })
      .signers(signer === authority ? [] : [signer])
      .rpc();
  }

  it("(w) if the auditor does not record by the deadline, the operator replaces it and the audit continues", async () => {
    // Make the period (= audit deadline) longer than the disclosures take, to test the rejection before the deadline.
    const mint = await setupToken({ periodLen: 12 });
    const c = await commitAndSample(mint, (b) => b);
    await submitDisclosures(mint, c.periodId, c.tree, c.sampleIndices);
    const replace = (signer: Keypair, newAuditor: PublicKey) =>
      replaceAuditorTx(mint, c.periodId, auditor.publicKey, newAuditor, signer);

    // No replacement before the deadline (still no swap to a colluding key mid-cycle)
    assert.match((await failure(replace(authority, auditor2.publicKey))) ?? "", /AuditorReplacementNotDue/, "no replacement before the deadline");

    const ts: any = await tokenState(mint);
    await waitChainTime((ts.auditDeadline as BN).toNumber());
    const outsider = Keypair.generate();
    await airdrop(outsider.publicKey, 1);
    assert.match((await failure(replace(outsider, auditor2.publicKey))) ?? "", /Unauthorized/, "only the operator can replace");
    assert.match((await failure(replace(authority, Keypair.generate().publicKey))) ?? "", /AccountNotInitialized/, "cannot replace with an unregistered auditor");
    assert.match((await failure(replace(authority, auditor.publicKey))) ?? "", /InvalidReplacementAuditor/, "cannot replace with the current auditor");

    await replace(authority, auditor2.publicKey);
    const tsAfter: any = await tokenState(mint);
    assert.isAbove((tsAfter.auditDeadline as BN).toNumber(), (ts.auditDeadline as BN).toNumber(), "the new auditor gets one more period");

    assert.match((await failure(observe(mint, c.periodId, auditor))) ?? "", /UnauthorizedAuditor/, "the old auditor can no longer record");
    await observe(mint, c.periodId, auditor2);
    await finalizeTx(mint, c.periodId);
    const audit: any = await program.account.auditCycle.fetch(client.pdas.audit(mint, c.periodId)[0]);
    assert.equal(audit.result, 1, "the audit finalizes with the new auditor's record (Pass)");
  });

  it("(x) payouts of promises beyond the obligation do not touch funds reserved for the next period", async () => {
    const mint = await setupToken();
    const vault = client.pdas.redemptionVault(mint)[0];
    const tsPda = client.pdas.tokenState(mint)[0];

    // Period 1: promise 1_600_000 against an obligation of 1_000_000 and pass (only the obligation is reserved)
    const c = await commitAndSample(mint, (b) => b + 600_000);
    await submitDisclosures(mint, c.periodId, c.tree, c.sampleIndices);
    await observe(mint, c.periodId, auditor);
    await finalizeTx(mint, c.periodId);
    const audit: any = await program.account.auditCycle.fetch(client.pdas.audit(mint, c.periodId)[0]);
    assert.equal(audit.result, 1, "Pass");
    assert.equal((audit.reservedRemaining as BN).toNumber(), OBLIGATION, "reserved up to the obligation");

    // Provision period 2 (period 1's 1_000_000 + period 2's 1_000_000 reserved)
    const more = await accrueVolume(mint, VOLUME);
    await harvest(mint, [more.dst]);
    await depositTx(mint, OBLIGATION);
    await provisionUntilBudget(mint);

    // Claim every period-1 leaf (the auditor confirms all). Each payout keeps balance ≥ reserved; once the surplus is gone, the excess is not paid
    let refused: string | null = null;
    for (let i = 0; i < POP; i++) {
      await confirmLeaf(mint, c.periodId, c.tree, i);
      const ata = await createAssociatedTokenAccount(connection, authority, usdcMint, c.tree.beneficiaryAt(i));
      const err = await failure(payoutTx(mint, c.periodId, ata, i, c.tree));
      if (err) refused = err;
      const ts: any = await program.account.tokenState.fetch(tsPda);
      assert.isAtLeast(await balance(vault), (ts.reserved as BN).toNumber(), "the balance never drops below the reservation");
    }
    assert.match(refused ?? "", /InsufficientPoolBalance/, "without unreserved surplus, the excess promise is not paid");
    const after: any = await program.account.tokenState.fetch(tsPda);
    assert.equal((after.reserved as BN).toNumber(), OBLIGATION, "period 2's obligation stays reserved");
  });

  // ---------------------------------------------------------------- exits and remaining holes

  function requestExitTx(mint: PublicKey, signer: Keypair = issuer) {
    return program.methods
      .requestExit()
      .accounts({ issuer: signer.publicKey, tokenState: client.pdas.tokenState(mint)[0] })
      .signers(signer === issuer ? [] : [signer])
      .rpc();
  }

  async function finalizeExitTx(mint: PublicKey) {
    const ts: any = await tokenState(mint);
    const pid: BN = ts.periodId;
    const audit = pid.gtn(0) && (ts.budget as BN).gtn(0) ? client.pdas.audit(mint, pid)[0] : null;
    const ix = await client.finalizeExit({
      crank: authority.publicKey,
      mint,
      audit,
      treasury: treasuryAta,
      usdcMint,
      usdcTokenProgram: TOKEN_PROGRAM_ID,
    });
    return sendAndConfirmTransaction(connection, new Transaction().add(ix), [authority]);
  }

  async function startLiquidationTx(mint: PublicKey) {
    const ix = await client.startLiquidation({ crank: authority.publicKey, mint, slashDestination: slashDestAta, usdcMint, usdcTokenProgram: TOKEN_PROGRAM_ID });
    return sendAndConfirmTransaction(connection, new Transaction().add(ix), [authority]);
  }

  async function claimLiquidationTx(mint: PublicKey, periodId: BN, tree: SumTree, index: number, beneficiaryUsdc: PublicKey) {
    const ix = await client.claimLiquidation({
      crank: authority.publicKey,
      mint,
      periodId,
      tree,
      index,
      beneficiaryUsdc,
      attestation: await attestationIfAny(mint, periodId, index),
      usdcMint,
      usdcTokenProgram: TOKEN_PROGRAM_ID,
    });
    return sendAndConfirmTransaction(connection, new Transaction().add(ix), [authority]);
  }

  it("(y) a period with zero volume (budget 0) does not stop the next one", async () => {
    const mint = await setupToken();
    const first = await runOneCycle(mint, "pass");
    assert.equal(first.audit.result, 1, "period 1 passes");

    // Next period: zero volume → budget 0 (nothing to audit)
    await waitPeriod(mint);
    await provision(mint);
    const ts2: any = await tokenState(mint);
    assert.equal(ts2.periodId.toNumber(), first.periodId.toNumber() + 1, "the period advances");
    assert.equal((ts2.budget as BN).toNumber(), 0, "zero volume → budget 0");
    const commitEmpty = await failure(commitTx(mint, ts2.periodId, buildTree(OBLIGATION), OBLIGATION));
    assert.match(commitEmpty ?? "", /BudgetNotProvisioned/, "no commitment without an obligation");
    await waitChainTime((ts2.auditDeadline as BN).toNumber());
    const noDefault = await failure(declareDefaultTx(mint, ts2.periodId));
    assert.match(noDefault ?? "", /DefaultNotDue/, "no default without an obligation");

    // On to the next period: an earlier version required a previous audit that did not exist and stalled forever
    await waitPeriod(mint);
    assert.isNull(await failure(provision(mint)), "a budget-0 period moves on without an audit");
    const ts3: any = await tokenState(mint);
    assert.equal(ts3.periodId.toNumber(), ts2.periodId.toNumber() + 1, "moved to the next period");
  });

  it("(z) voluntary exit: obligation through the requested period; after its audit half the bond to customers; fees after exit; liquidation", async () => {
    // A longer period so the request and the volume fall in the same period.
    const mint = await setupToken({ periodLen: 20 });
    const tsPda = client.pdas.tokenState(mint)[0];
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);

    const outsider = Keypair.generate();
    await airdrop(outsider.publicKey, 1);
    assert.match((await failure(requestExitTx(mint, outsider))) ?? "", /Unauthorized|ConstraintHasOne/, "only the issuer can request an exit");
    await requestExitTx(mint);
    assert.match((await failure(requestExitTx(mint))) ?? "", /ExitAlreadyRequested/, "only one request");
    const r = ((await tokenState(mint)).exitRequestPeriod as BN).toNumber();

    // The exit cannot finalize until the volume up to the requested period is provisioned and audited (no escaping the obligation)
    assert.match((await failure(finalizeExitTx(mint))) ?? "", /ExitNotReady/, "not before the provision");
    const p = await provisionUntilBudget(mint);
    assert.equal(p.budget, OBLIGATION, "volume up to the requested period becomes an obligation");
    const tree = buildTree(p.budget);
    await commitTx(mint, p.periodId, tree, p.budget);
    assert.match((await failure(finalizeExitTx(mint))) ?? "", /ExitNotReady/, "not before the audit is final");
    await verifyUniqueness(mint, p.periodId, tree);
    await waitAfterCommit(mint, p.periodId);
    await designateTx(mint, p.periodId);
    await submitDisclosures(mint, p.periodId, tree, await sampledIndices(mint, p.periodId));
    await observe(mint, p.periodId, auditor);
    await finalizeTx(mint, p.periodId);
    // No provisioning after the requested period
    while (((await tokenState(mint)).periodId as BN).toNumber() <= r) {
      await waitPeriod(mint);
      await provision(mint);
    }
    await waitPeriod(mint);
    assert.match((await failure(provision(mint))) ?? "", /ExitInProgress/, "volume after the requested period is not an obligation");

    const bondPda = client.pdas.slashingBond(mint)[0];
    const bond = await balance(bondPda);
    assert.equal(bond, BOND_TARGET.toNumber(), "bond before the exit");

    const vaultBeforeExit = await balance(client.pdas.redemptionVault(mint)[0]);
    const treasuryBefore = await balance(treasuryAta);
    await finalizeExitTx(mint);
    assert.equal((await balance(client.pdas.redemptionVault(mint)[0])) - vaultBeforeExit, bond / 2, "the issuer's half of the bond goes to customers (redemption pool)");
    assert.equal((await balance(treasuryAta)) - treasuryBefore, bond - bond / 2, "the rest to the operator treasury");
    assert.equal(await balance(bondPda), 0, "the bond is empty");
    assert.equal((await tokenState(mint)).exited, true, "exit finalized");

    // After the exit, no provisioning or deposits
    assert.match((await failure(provision(mint))) ?? "", /TokenExited/, "no provisioning after the exit");
    assert.match((await failure(depositTx(mint, 1_000))) ?? "", /TokenExited/, "no deposits after the exit");

    // Fees after the exit: no obligation; the operator's share as before, the issuer's share goes to customers (the pool)
    const treasuryMid = await balance(treasuryAta);
    const vaultBeforeConvert = await balance(client.pdas.redemptionVault(mint)[0]);
    await convertTx(mint, 10_000, 5_000_000);
    assert.equal((await balance(treasuryAta)) - treasuryMid, 4_000_000, "operator share");
    assert.equal((await balance(client.pdas.redemptionVault(mint)[0])) - vaultBeforeConvert, 1_000_000, "the issuer share (20%) goes to the pool");
    assert.equal(((await tokenState(mint)).issuerClaimable as BN).toNumber(), 0, "nothing becomes the issuer's");

    // Recipients can still claim after the exit
    await confirmLeaf(mint, p.periodId, tree, 0);
    const ben0 = await createAssociatedTokenAccount(connection, authority, usdcMint, tree.beneficiaryAt(0));
    assert.isNull(await failure(payoutTx(mint, p.periodId, ben0, 0, tree)), "recipients can still claim after the exit");

    // Liquidation: the pool's surplus (beyond what is reserved) is split over the last clean period's leaves, pro rata to the confirmed amount
    const tsBefore: any = await tokenState(mint);
    const pool = (await balance(client.pdas.redemptionVault(mint)[0])) - (tsBefore.reserved as BN).toNumber();
    assert.isAbove(pool, 0, "there is a surplus");
    await startLiquidationTx(mint);
    const tsLiq: any = await tokenState(mint);
    assert.equal((tsLiq.liquidationPool as BN).toNumber(), pool, "liquidation pool = redemption pool − reserved");
    assert.equal((tsLiq.liquidationRefPeriod as BN).toNumber(), p.periodId.toNumber(), "the basis is the last finalized clean period");
    assert.match((await failure(startLiquidationTx(mint))) ?? "", /LiquidationAlreadyStarted/, "liquidation starts only once");
    await confirmLeaf(mint, p.periodId, tree, 1);
    const ben1 = await createAssociatedTokenAccount(connection, authority, usdcMint, tree.beneficiaryAt(1));
    await claimLiquidationTx(mint, p.periodId, tree, 1, ben1);
    const expected = Math.floor((pool * Number(tree.valueAt(1))) / p.budget);
    assert.equal(await balance(ben1), expected, "split pro rata to the confirmed amount");
    assert.match((await failure(claimLiquidationTx(mint, p.periodId, tree, 1, ben1))) ?? "", /NothingToPay/, "a liquidation share is not paid twice");

    // A token frozen for a violation (forced exit) cannot recover its bond through a voluntary exit (already slashed)
    assert.isNotNull(frozenMint, "needs the token frozen in (b)");
    assert.match((await failure(requestExitTx(frozenMint!))) ?? "", /TokenFrozen/, "no refund on a forced exit");
    void tsPda;
  });

  it("(aa) defects are judged by count: 21 samples with 0 allowed → one defect is overstatement", async () => {
    const BIG_POP = 32;
    async function cycleWithOneDefect(mint: PublicKey) {
      const c = await commitAndSample(mint, (b) => b, BIG_POP);
      await submitDisclosures(mint, c.periodId, c.tree, c.sampleIndices);
      // Only the first sample is observed at half its claim (the residual stays within 5% of the total; one defect).
      await observe(mint, c.periodId, auditor, (a, j) => (j === 0 ? a / 2n : a));
      await finalizeTx(mint, c.periodId);
      return (await program.account.auditCycle.fetch(client.pdas.audit(mint, c.periodId)[0])) as any;
    }

    // An earlier version compared 1/21 ≈ 4.8% defects with the 5% tolerance and passed it
    const strict = await setupToken({ sampleSize: 21 });
    const a1 = await cycleWithOneDefect(strict);
    assert.equal(a1.defectCount, 1, "the program counts defects from the per-sample observations");
    assert.equal(a1.result, 2, "with 0 allowed, one defect is overstatement");

    // Control: with 1 allowed defect fixed in advance (within 20% of 21), one defect passes
    const lenient = await setupToken({ sampleSize: 21, maxDefects: 1 });
    const a2 = await cycleWithOneDefect(lenient);
    assert.equal(a2.result, 1, "passes within the allowed defects fixed in advance");
  });

  it("(ab) fixed period boundaries: a late close still assigns volume to the right period", async () => {
    const LEN = 4;
    const V2 = 1_000_000;
    const mint = await setupToken({ periodLen: LEN });
    const tsPda = client.pdas.tokenState(mint)[0];
    const ts0: any = await tokenState(mint);
    const t0 = (ts0.gridStartTs as BN).toNumber();
    assert.equal((ts0.gridPeriodLen as BN).toNumber(), LEN, "the period length is fixed when metering starts");

    // The origin and the length are at the byte offsets the hook reads directly (397, 405)
    const raw = (await connection.getAccountInfo(tsPda))!.data;
    assert.equal(raw.readBigInt64LE(397).toString(), t0.toString(), "origin t0 at offset 397");
    assert.equal(raw.readBigInt64LE(405).toString(), LEN.toString(), "length Δ at offset 405");

    // VOLUME in period A, then V2 in period B after a boundary.
    // A's period is read from the period index the hook recorded (counted with the processing time); deriving the
    // boundary from the confirmed block time can lag and put A and B in the same period.
    const vcPda = client.pdas.volumeCounter(mint)[0];
    const a = await accrueVolume(mint, VOLUME);
    const kA = ((await hook.account.volumeCounter.fetch(vcPda)) as any).lastSnapIdx.toNumber();
    const nextBoundary = t0 + (kA + 1) * LEN;
    await waitChainTime(nextBoundary + 1);
    const b = await accrueVolume(mint, V2);
    const kB = ((await hook.account.volumeCounter.fetch(vcPda)) as any).lastSnapIdx.toNumber();
    assert.isAbove(kB, kA, "B's transfer was recorded in a later period than A's");
    await harvest(mint, [a.dst, b.dst]);
    // Provision only after B's period has also ended (a late close)
    await waitChainTime(t0 + (kB + 1) * LEN);

    const first = await provisionUntilBudget(mint);
    assert.equal(first.budget, OBLIGATION, "the first obligation covers only A's volume (B's is not mixed in)");
    const ts1: any = await tokenState(mint);
    assert.equal(((ts1.periodStartTs as BN).toNumber() - t0) % LEN, 0, "periods start on fixed boundaries (not at processing time)");

    // After A's audit is final, catching up gives the next obligation B's volume
    await auditPeriod(mint, first.periodId, OBLIGATION, "pass");
    const second = await provisionUntilBudget(mint);
    assert.equal(second.budget, (V2 * RETURN_RATE_BPS) / BPS, "B's volume belongs to B's period");
    assert.isAbove(second.periodId.toNumber(), first.periodId.toNumber(), "a later period");
  });

  it("(ac) uniqueness: duplicates, root mismatch, finalizing unverified and reuse in a later period are rejected", async () => {
    // --- The same payment ID twice in the tree ---
    const m1 = await setupToken();
    const p1 = await accrueAndProvision(m1);
    const ids = Array.from({ length: POP }, () => newOutcome());
    ids[1] = ids[0];
    const dupTree = buildTree(p1.budget, POP, ids);
    await commitTx(m1, p1.periodId, dupTree, p1.budget);
    assert.match((await failure(verifyUniqueness(m1, p1.periodId, dupTree))) ?? "", /LeafOrderInvalid/, "a duplicate payment ID is rejected");

    // --- Without the uniqueness proof the cycle cannot finalize, and after the deadline it is the issuer's default ---
    await waitAfterCommit(m1, p1.periodId);
    await designateTx(m1, p1.periodId);
    await submitDisclosures(m1, p1.periodId, dupTree, await sampledIndices(m1, p1.periodId));
    await observe(m1, p1.periodId, auditor);
    assert.match((await failure(finalizeTx(m1, p1.periodId))) ?? "", /UniquenessNotVerified/, "no finalization before uniqueness is verified");
    const tsD: any = await tokenState(m1);
    await waitChainTime((tsD.auditDeadline as BN).toNumber());
    await declareDefaultTx(m1, p1.periodId);
    assert.equal((await tokenState(m1)).frozen, true, "failing to prove uniqueness is a default and freezes the token");

    // --- Leaves that differ from the commitment give a different root; a restart is possible before completion ---
    const m2 = await setupToken();
    const p2 = await accrueAndProvision(m2);
    const real = buildTree(p2.budget);
    const fake = buildTree(p2.budget);
    await commitTx(m2, p2.periodId, real, p2.budget);
    await uniquenessBatch(m2, p2.periodId, fake, 0, UNIQ_BATCH);
    assert.match(
      (await failure(uniquenessBatch(m2, p2.periodId, fake, UNIQ_BATCH, 2 * UNIQ_BATCH))) ?? "",
      /UniquenessRootMismatch/,
      "leaves that differ from the commitment do not match the root",
    );
    await verifyUniqueness(m2, p2.periodId, real, true);
    assert.equal(((await program.account.auditCycle.fetch(client.pdas.audit(m2, p2.periodId)[0])) as any).uniquenessVerified, true, "restarting with the right leaves verifies");
    await waitAfterCommit(m2, p2.periodId);
    await designateTx(m2, p2.periodId);
    await submitDisclosures(m2, p2.periodId, real, await sampledIndices(m2, p2.periodId));
    await observe(m2, p2.periodId, auditor);
    await finalizeTx(m2, p2.periodId);

    // --- Reusing a recognized payment ID in a later period of the same token ---
    await depositTx(m2, OBLIGATION);
    const p3 = await accrueAndProvision(m2);
    const reuse = buildTree(p3.budget, POP, [Buffer.from(real.outcomeAt(3)), ...Array.from({ length: POP - 1 }, () => newOutcome())]);
    await commitTx(m2, p3.periodId, reuse, p3.budget);
    assert.match((await failure(verifyUniqueness(m2, p3.periodId, reuse))) ?? "", /OutcomeAlreadyUsed/, "a payment recognized in another period cannot be reused");

    // --- Putting the same payment ID in another token's (company's) tree does not block that company ---
    const m3 = await setupToken();
    const p4 = await accrueAndProvision(m3);
    const elsewhere = buildTree(p4.budget, POP, [Buffer.from(real.outcomeAt(3)), ...Array.from({ length: POP - 1 }, () => newOutcome())]);
    await commitTx(m3, p4.periodId, elsewhere, p4.budget);
    assert.isNull(await failure(verifyUniqueness(m3, p4.periodId, elsewhere)), "the used-ID registry is per token (no griefing by other companies)");
  });

  it("(ae) payouts only for confirmed leaves up to the confirmed amount; after a freeze, finalized recipients are paid and the surplus is liquidated", async () => {
    const mint = await setupToken();
    const first = await runOneCycle(mint, "pass");
    const unsampled = [...Array(POP).keys()].filter((i) => !first.sampleIndices.includes(i));
    assert.isAtLeast(unsampled.length, 2, "some leaves were not sampled");

    // No payout without confirmation, and no more than the confirmed amount (half the leaf's value)
    const u = unsampled[0];
    const ataU = await createAssociatedTokenAccount(connection, authority, usdcMint, first.tree.beneficiaryAt(u));
    assert.match((await failure(payoutTx(mint, first.periodId, ataU, u, first.tree))) ?? "", /LeafNotConfirmed/, "no payout for an unconfirmed leaf");
    const outsider = Keypair.generate();
    await airdrop(outsider.publicKey, 1);
    assert.match((await failure(attestTx(mint, first.periodId, first.tree, u, undefined, outsider))) ?? "", /UnauthorizedAuditor/, "only the cycle's auditor can confirm");
    await attestTx(mint, first.periodId, first.tree, u, first.tree.valueAt(u) / 2n);
    await payoutTx(mint, first.periodId, ataU, u, first.tree);
    assert.equal(await balance(ataU), Number(first.tree.valueAt(u) / 2n), "paid only up to the confirmed amount");

    // Next period: fraud → freeze
    await depositTx(mint, OBLIGATION);
    const second = await runOneCycle(mint, "attackX");
    assert.equal(second.audit.result, 2, "FraudOverstatement");
    assert.equal(second.tsAfter.frozen, true, "frozen");

    // After the freeze, recipients of the clean period can still claim
    const s = first.sampleIndices[0];
    const ataS = await createAssociatedTokenAccount(connection, authority, usdcMint, first.tree.beneficiaryAt(s));
    await payoutTx(mint, first.periodId, ataS, s, first.tree);
    assert.equal(await balance(ataS), Number(first.tree.valueAt(s)), "a sampled leaf is paid up to its observed value (= the leaf's value)");

    // Liquidation: the pool's surplus (beyond what is reserved) is split over the last clean period's (period 1) leaves
    const tsBefore: any = await tokenState(mint);
    const pool = (await balance(client.pdas.redemptionVault(mint)[0])) - (tsBefore.reserved as BN).toNumber();
    await startLiquidationTx(mint);
    const tsLiq: any = await tokenState(mint);
    assert.equal((tsLiq.liquidationPool as BN).toNumber(), pool, "liquidation pool = redemption pool − reserved");
    assert.equal((tsLiq.liquidationRefPeriod as BN).toNumber(), first.periodId.toNumber(), "the basis is the last period finalized without fraud");
    const w = unsampled[1];
    await confirmLeaf(mint, first.periodId, first.tree, w);
    const ataW = await createAssociatedTokenAccount(connection, authority, usdcMint, first.tree.beneficiaryAt(w));
    await claimLiquidationTx(mint, first.periodId, first.tree, w, ataW);
    assert.equal(await balance(ataW), Math.floor((pool * Number(first.tree.valueAt(w))) / OBLIGATION), "split pro rata to the confirmed amount");

    // A token with only fraudulent periods: no basis for a split, so the surplus goes to the compensation pool
    assert.isNotNull(frozenMint, "needs the token frozen in (b)");
    const fts: any = await tokenState(frozenMint!);
    const frozenPool = (await balance(client.pdas.redemptionVault(frozenMint!)[0])) - (fts.reserved as BN).toNumber();
    const slashBefore = await balance(slashDestAta);
    await startLiquidationTx(frozenMint!);
    assert.equal((await balance(slashDestAta)) - slashBefore, frozenPool, "without finalized rights, the surplus goes to the compensation pool");
  });
  it("(af) auditor revocation: no recording, no confirmation, no new cycle from a stale manifest; replaced without waiting", async () => {
    // Register auditors not shared with other tests, since they get revoked.
    const a3 = Keypair.generate();
    const a4 = Keypair.generate();
    for (const a of [a3, a4]) {
      await program.methods
        .registerAuditor()
        .accounts({
          authority: authority.publicKey,
          config: client.pdas.config()[0],
          auditor: a.publicKey,
          auditorRecord: client.pdas.auditorRecord(a.publicKey)[0],
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      await airdrop(a.publicKey, 2);
    }
    const revokeTx = (signer: Keypair, a: PublicKey) =>
      program.methods
        .revokeAuditor()
        .accounts({ authority: signer.publicKey, config: client.pdas.config()[0], auditorRecord: client.pdas.auditorRecord(a)[0] })
        .signers(signer === authority ? [] : [signer])
        .rpc();

    // Make the period (= audit deadline) longer than recording takes, to test replacement before the deadline.
    const mint = await setupToken({ auditor: a3.publicKey, periodLen: 40 });
    const c = await commitAndSample(mint, (b) => b);
    await submitDisclosures(mint, c.periodId, c.tree, c.sampleIndices);
    await observe(mint, c.periodId, a3);
    const auditPda = client.pdas.audit(mint, c.periodId)[0];
    let audit: any = await program.account.auditCycle.fetch(auditPda);
    assert.equal(audit.stage, 2, "all observed: Verified");

    // Only the operator can revoke, and only once.
    const outsider = Keypair.generate();
    await airdrop(outsider.publicKey, 1);
    assert.match((await failure(revokeTx(outsider, a3.publicKey))) ?? "", /Unauthorized/, "only the operator can revoke");
    await revokeTx(authority, a3.publicKey);
    assert.match((await failure(revokeTx(authority, a3.publicKey))) ?? "", /AuditorRevoked/, "revocation happens once");

    // A revoked auditor cannot confirm leaves.
    const unsampled = [...Array(POP).keys()].find((i) => !c.sampleIndices.includes(i))!;
    assert.match((await failure(attestTx(mint, c.periodId, c.tree, unsampled, undefined, a3))) ?? "", /AuditorRevoked/, "a revoked auditor cannot confirm");

    // Even before the deadline the operator can replace a revoked auditor; before finalization the sample is observed again (Verified → Sampled).
    const ts: any = await tokenState(mint);
    assert.isBelow(await chainTime(), (ts.auditDeadline as BN).toNumber(), "still before the deadline");
    await replaceAuditorTx(mint, c.periodId, a3.publicKey, a4.publicKey);
    audit = await program.account.auditCycle.fetch(auditPda);
    assert.equal(audit.stage, 1, "back to Sampled to observe again");
    assert.equal(audit.sampleObserved.length, 0, "the revoked auditor's observations are discarded");
    assert.equal(audit.auditor.toBase58(), a4.publicKey.toBase58(), "the new auditor");
    assert.match((await failure(finalizeTx(mint, c.periodId))) ?? "", /InvalidAuditStage/, "no finalization until observed again");
    assert.match((await failure(observe(mint, c.periodId, a3))) ?? "", /UnauthorizedAuditor|AuditorRevoked/, "a revoked auditor cannot record");

    await observe(mint, c.periodId, a4);
    await finalizeTx(mint, c.periodId);
    audit = await program.account.auditCycle.fetch(auditPda);
    assert.equal(audit.result, 1, "finalized with the new auditor's observations (Pass)");

    // After finalization, the new auditor confirms leaves.
    await attestTx(mint, c.periodId, c.tree, unsampled, undefined, a4);

    // A manifest still naming the revoked auditor cannot start the next cycle.
    await depositTx(mint, OBLIGATION); // enough to reserve period 2's obligation on top of period 1's unpaid amount
    const next = await accrueAndProvision(mint);
    const tree2 = buildTree(next.budget);
    assert.match((await failure(commitTx(mint, next.periodId, tree2, next.budget))) ?? "", /AuditorRevoked/, "no new cycle from a stale manifest");
    // Re-fixing the manifest with an active auditor resumes (control).
    await setManifestTx(mint, TERM_LEN, { auditor: a4.publicKey });
    await commitTx(mint, next.periodId, tree2, next.budget);
  });

  // ---------------------------------------------------------------- end of a manifest and the next one

  /** Grid index of the period of the latest transfer (the hook records it at the first transfer after a boundary). */
  async function lastTransferPeriod(mint: PublicKey): Promise<number> {
    return ((await hook.account.volumeCounter.fetch(client.pdas.volumeCounter(mint)[0])) as any).lastSnapIdx.toNumber();
  }

  /** Start of grid period k (t0 + kΔ). */
  async function periodStart(mint: PublicKey, k: number): Promise<number> {
    const ts: any = await tokenState(mint);
    return (ts.gridStartTs as BN).toNumber() + k * (ts.gridPeriodLen as BN).toNumber();
  }

  /** Closes periods until grid period k is closed, returning each closed period's budget (none of them may need an audit). */
  async function closeThrough(mint: PublicKey, k: number): Promise<number[]> {
    const budgets: number[] = [];
    while (((await tokenState(mint)).periodId as BN).toNumber() <= k) {
      await waitPeriod(mint);
      await provision(mint);
      budgets.push(((await tokenState(mint)).budget as BN).toNumber());
    }
    return budgets;
  }

  /** Closes every period that has ended (none of them may need an audit). */
  async function catchUp(mint: PublicKey): Promise<number[]> {
    const ts: any = await tokenState(mint);
    const t0 = (ts.gridStartTs as BN).toNumber();
    const len = (ts.gridPeriodLen as BN).toNumber();
    return closeThrough(mint, Math.floor(((await chainTime()) - t0) / len) - 1);
  }

  /** Waits until the next period boundary has passed. */
  async function waitNextBoundary(mint: PublicKey) {
    const ts: any = await tokenState(mint);
    const t0 = (ts.gridStartTs as BN).toNumber();
    const len = (ts.gridPeriodLen as BN).toNumber();
    await waitChainTime(t0 + (Math.floor(((await chainTime()) - t0) / len) + 1) * len);
  }

  async function manifestOf(mint: PublicKey): Promise<any> {
    return program.account.manifest.fetch(client.pdas.manifest(mint)[0]);
  }

  it("(ag) after the term ends, a period that started during the campaign is still audited from commitment to finalization", async () => {
    // A campaign that ends shortly after the first period closes (the period is 20 s, the term 26 s).
    const mint = await setupToken({ periodLen: 20, termLen: new BN(26) });
    const validUntil = ((await manifestOf(mint)).validUntil as BN).toNumber();
    const { periodId, budget } = await accrueAndProvision(mint);
    assert.equal(budget, OBLIGATION, "the period's obligation");
    assert.isAtMost(await periodStart(mint, periodId.toNumber() - 1), validUntil, "the audited period started during the campaign");

    // Commit after the term (and before the audit deadline)
    await waitChainTime(validUntil);
    const ts: any = await tokenState(mint);
    assert.isBelow(await chainTime(), (ts.auditDeadline as BN).toNumber(), "still before the audit deadline");
    const bond = await balance(client.pdas.slashingBond(mint)[0]);
    const tree = buildTree(budget);
    assert.isNull(await failure(commitTx(mint, periodId, tree, budget)), "the commitment is accepted after the term");
    await verifyUniqueness(mint, periodId, tree);
    await waitAfterCommit(mint, periodId);
    await designateTx(mint, periodId);
    await submitDisclosures(mint, periodId, tree, await sampledIndices(mint, periodId));
    await observe(mint, periodId, auditor);
    await finalizeTx(mint, periodId);

    const audit: any = await program.account.auditCycle.fetch(client.pdas.audit(mint, periodId)[0]);
    assert.equal(audit.result, 1, "Pass");
    const after: any = await tokenState(mint);
    assert.equal(after.frozen, false, "not frozen");
    assert.equal(await balance(client.pdas.slashingBond(mint)[0]), bond, "nothing slashed");
    await waitChainTime((after.auditDeadline as BN).toNumber());
    assert.match((await failure(declareDefaultTx(mint, periodId))) ?? "", /DefaultNotDue/, "the expired campaign's audit is not a default");
  });

  it("(ah) between campaigns no obligation arises and no default can be declared; the carried shortfall waits for the exit's final audit", async () => {
    // The first period is the campaign's last one: the term ends before the second period starts (period 20 s, term 18 s).
    // (A later campaign period would take the carry into its own obligation, as in (c).)
    const mint = await setupToken({ periodLen: 20, termLen: new BN(18) });
    const validUntil = ((await manifestOf(mint)).validUntil as BN).toNumber();

    // Last campaign period: an honest shortfall (5% short, within the 10% band) is carried
    const a = await accrueAndProvision(mint);
    assert.isAbove(await periodStart(mint, a.periodId.toNumber()), validUntil, "the next period starts after the term");
    const short = a.budget / 20;
    await auditPeriod(mint, a.periodId, a.budget - short, "pass");
    const audit: any = await program.account.auditCycle.fetch(client.pdas.audit(mint, a.periodId)[0]);
    assert.equal(audit.result, 4, "HonestShortfall");
    assert.equal(((await tokenState(mint)).unfulfilled as BN).toNumber(), short, "the shortfall is carried");

    // The gap: volume in a period that started after the term, with no next manifest
    await waitChainTime(validUntil);
    await waitNextBoundary(mint);
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);
    const k = await lastTransferPeriod(mint);
    assert.isAbove(await periodStart(mint, k), validUntil, "the volume fell in the gap");
    const budgets = await closeThrough(mint, k);
    assert.isNotEmpty(budgets, "the period with the volume was closed here");
    assert.deepEqual(budgets, budgets.map(() => 0), "no new obligation in the gap (its volume is not counted)");
    const gap: any = await tokenState(mint);
    assert.equal((gap.unfulfilled as BN).toNumber(), short, "the carry is kept");
    assert.match((await failure(commitTx(mint, gap.periodId, buildTree(OBLIGATION), OBLIGATION))) ?? "", /BudgetNotProvisioned/, "nothing to commit to");
    await waitChainTime((gap.auditDeadline as BN).toNumber());
    assert.match((await failure(declareDefaultTx(mint, gap.periodId))) ?? "", /DefaultNotDue/, "no default in the gap");

    // An exit during the gap: its final audit settles the carry (the gap's volume still does not count)
    await requestExitTx(mint);
    const r = ((await tokenState(mint)).exitRequestPeriod as BN).toNumber();
    const fin = await provisionUntilBudget(mint);
    assert.equal(fin.periodId.toNumber(), r + 1, "the exit's last period");
    assert.equal(fin.budget, short, "its obligation is the carry alone");
    await auditPeriod(mint, fin.periodId, short, "pass");
    assert.equal(((await tokenState(mint)).unfulfilled as BN).toNumber(), 0, "the carry is settled");
    await finalizeExitTx(mint);
    assert.equal((await tokenState(mint)).exited, true, "exit finalized");
  });

  it("(ai) a manifest change does not touch periods that started before it; gap volume does not count; tier, streak, bond and used IDs carry over", async () => {
    const LEN = 6;
    const mint = await setupToken({ periodLen: LEN, termLen: new BN(30) });

    // Campaign A: volume, then the issuer raises the rate to 60% and the sample to 6 (allowed during a campaign) before
    // the period closes
    const v1 = await accrueVolume(mint, VOLUME);
    await harvest(mint, [v1.dst]);
    const k1 = await lastTransferPeriod(mint);
    await setManifestTx(mint, new BN(30), { periodLen: LEN, returnRateBps: 6_000, sampleSize: 6 });
    const raisedAt = ((await manifestOf(mint)).validFrom as BN).toNumber();
    assert.isBelow(await periodStart(mint, k1), raisedAt, "the volume's period started before the raise");
    const a = await provisionUntilBudget(mint);
    assert.equal(a.budget, OBLIGATION, "that period keeps the rate in force when it started (50%, not 60%)");
    const treeA = await auditPeriod(mint, a.periodId, a.budget, "pass");
    const auditA: any = await program.account.auditCycle.fetch(client.pdas.audit(mint, a.periodId)[0]);
    assert.equal(auditA.sampleSize, SAMPLE, "and its audit is judged with the sample size in force when it started");
    const before: any = await tokenState(mint);
    const bondPda = client.pdas.slashingBond(mint)[0];
    const bond = await balance(bondPda);

    // The gap, then campaign B with a lower rate (30%), fixed in a period that started in the gap; volume follows in that period
    const validUntilA = ((await manifestOf(mint)).validUntil as BN).toNumber();
    await waitChainTime(validUntilA);
    await catchUp(mint);
    await waitNextBoundary(mint);
    await setManifestTx(mint, TERM_LEN, { periodLen: LEN, returnRateBps: 3_000 });
    const validFromB = ((await manifestOf(mint)).validFrom as BN).toNumber();
    const g = await accrueVolume(mint, VOLUME);
    await harvest(mint, [g.dst]);
    const kg = await lastTransferPeriod(mint);
    assert.isAbove(await periodStart(mint, kg), validUntilA, "the transfer's period started after A's term");
    assert.isBelow(await periodStart(mint, kg), validFromB, "and before B");
    const gapBudgets = await closeThrough(mint, kg);
    assert.isNotEmpty(gapBudgets, "the period with the volume was closed here");
    assert.deepEqual(gapBudgets, gapBudgets.map(() => 0), "B adds no obligation to a period that started before it");

    // Carried over
    const after: any = await tokenState(mint);
    assert.equal(before.consecutivePasses, 1, "one pass under A");
    assert.equal(after.tier, before.tier, "tier carried over");
    assert.equal(after.consecutivePasses, before.consecutivePasses, "streak carried over");
    assert.equal(await balance(bondPda), bond, "bond carried over");

    // Campaign B: a period that starts after it uses B's rate; a payment ID recognized under A cannot be used again
    await depositTx(mint, OBLIGATION);
    const b = await accrueAndProvision(mint);
    assert.equal(b.budget, (VOLUME * 3_000) / BPS, "B's rate applies to periods that start after it");
    const reuse = buildTree(b.budget, POP, [Buffer.from(treeA.outcomeAt(0)), ...Array.from({ length: POP - 1 }, () => newOutcome())]);
    await commitTx(mint, b.periodId, reuse, b.budget);
    assert.match((await failure(verifyUniqueness(mint, b.periodId, reuse))) ?? "", /OutcomeAlreadyUsed/, "used payment IDs carry over");
  });

  it("(aj) during a campaign the manifest cannot change in the issuer's favor; a new auditor, a higher rate and a longer term are allowed", async () => {
    // A long period, so no boundary falls between the changes.
    const base = { periodLen: 60, sampleSize: 6 };
    const mint = await setupToken(base);
    const favor: [ManifestOpts, string][] = [
      [{ returnRateBps: RETURN_RATE_BPS - 1 }, "a lower return rate"],
      [{ toleranceBps: TOLERANCE_BPS + 1 }, "a wider tolerance"],
      [{ shortfallToleranceBps: LCL_BPS + 1 }, "a wider shortfall tolerance"],
      [{ sampleSize: 5 }, "a smaller sample"],
      [{ maxDefects: 1 }, "more allowed defects"],
      [{ planHash: Array(32).fill(1) }, "another use plan"],
    ];
    for (const [o, label] of favor) {
      assert.match((await failure(setManifestTx(mint, TERM_LEN, { ...base, ...o }))) ?? "", /ManifestChangeFavorsIssuer/, `${label} is rejected`);
    }
    assert.match((await failure(setManifestTx(mint, new BN(86_400), base))) ?? "", /ManifestChangeFavorsIssuer/, "a shorter term is rejected");

    const before: any = await manifestOf(mint);
    await setManifestTx(mint, TERM_LEN.addn(86_400), { ...base, auditor: auditor2.publicKey, returnRateBps: RETURN_RATE_BPS + 1_000 });
    const after: any = await manifestOf(mint);
    assert.equal(after.auditor.toBase58(), auditor2.publicKey.toBase58(), "another registered auditor");
    assert.equal(after.returnRateBps, RETURN_RATE_BPS + 1_000, "a higher return rate");
    assert.isAbove((after.validUntil as BN).toNumber(), (before.validUntil as BN).toNumber(), "a longer term");
    assert.isNull(
      await failure(
        setManifestTx(mint, TERM_LEN.addn(2 * 86_400), {
          ...base,
          auditor: auditor2.publicKey,
          returnRateBps: RETURN_RATE_BPS + 1_000,
          toleranceBps: TOLERANCE_BPS - 100,
          sampleSize: 8,
        }),
      ),
      "stricter judging is allowed too",
    );

    // A second change after a boundary that has not been closed would lose the terms an open period still needs
    const quick = await setupToken({ periodLen: 3 });
    // (a change in the same second as the period start applies to that period, so make the first one strictly later)
    await waitChainTime(((await tokenState(quick)).periodStartTs as BN).toNumber());
    await setManifestTx(quick, TERM_LEN, { periodLen: 3, returnRateBps: RETURN_RATE_BPS + 500 });
    await waitNextBoundary(quick);
    const raise = () => setManifestTx(quick, TERM_LEN, { periodLen: 3, returnRateBps: RETURN_RATE_BPS + 1_000 });
    assert.match((await failure(raise())) ?? "", /PeriodsNotClosed/, "close the elapsed periods first");
    await catchUp(quick);
    assert.isNull(await failure(raise()), "after closing them the change goes through");
  });

  // ---------------------------------------------------------------- the issuer escrow

  /** Sends one instruction, paid by the operator's wallet and signed by `signers`. */
  async function sendIx(ix: any, ...signers: Keypair[]) {
    const all = [authority, ...signers].filter((k, i, a) => a.findIndex((x) => x.publicKey.equals(k.publicKey)) === i);
    return sendAndConfirmTransaction(connection, new Transaction().add(ix), all);
  }

  function registerPartnerTx(p: PublicKey) {
    return program.methods
      .registerPartner()
      .accounts({
        authority: authority.publicKey,
        config: client.pdas.config()[0],
        partner: p,
        partnerRecord: client.pdas.partnerRecord(p)[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  }

  function revokePartnerTx(signer: Keypair, p: PublicKey) {
    return program.methods
      .revokePartner()
      .accounts({ authority: signer.publicKey, config: client.pdas.config()[0], partnerRecord: client.pdas.partnerRecord(p)[0] })
      .signers(signer === authority ? [] : [signer])
      .rpc();
  }

  async function setEscrowPartnerTx(mint: PublicKey, signer: Keypair, p: PublicKey, current?: PublicKey) {
    return sendIx(await client.setEscrowPartner({ issuer: signer.publicKey, mint, partner: p, currentPartner: current ?? null }), signer);
  }

  const invoice = (s: string) => Array.from(keccak_256(Buffer.from(s)));

  async function requestTx(mint: PublicKey, signer: Keypair, amount: number, payee: PublicKey, inv: number[], item = 1, fromBond = false) {
    return sendIx(
      await client.requestWithdrawal({ issuer: signer.publicKey, mint, planItem: item, amount: new BN(amount), payee, invoiceHash: inv, fromBond }),
      signer,
    );
  }

  async function approveTx(mint: PublicKey, signer: Keypair, inv: number[]) {
    return sendIx(
      await client.approveWithdrawal({ approver: signer.publicKey, mint, invoiceHash: inv, usdcMint, usdcTokenProgram: TOKEN_PROGRAM_ID }),
      signer,
    );
  }

  async function requestOf(mint: PublicKey, inv: number[]): Promise<any> {
    return program.account.withdrawalRequest.fetch(client.pdas.withdrawal(mint, inv)[0]);
  }

  /** A token whose issuer has its own key (not the operator's), with a registered escrow partner. */
  async function setupEscrowToken(m: ManifestOpts & { termLen?: BN } = {}) {
    const iss = Keypair.generate();
    await airdrop(iss.publicKey, 5);
    const mint = await setupToken({ ...m, issuer: iss });
    const p = Keypair.generate();
    await registerPartnerTx(p.publicKey);
    await setEscrowPartnerTx(mint, iss, p.publicKey);
    return { iss, mint, p };
  }

  /** Volume → conversion (the issuer share, 1_000_000, goes to the escrow) → provision → clean audit (the share is released). */
  async function fundAndRelease(mint: PublicKey, iss: Keypair) {
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);
    await convertTx(mint, 10_000, 5_000_000);
    const p = await provisionUntilBudget(mint);
    const tree = await auditPeriod(mint, p.periodId, p.budget, "pass", iss);
    return { ...p, tree };
  }

  it("(ak) a clean audit releases the issuer share inside the escrow; nothing is paid to the issuer's account", async () => {
    const names = (program.idl.instructions as any[]).map((ix) => String(ix.name));
    assert.isFalse(names.some((n) => /^claim_?distribution$/i.test(n)), "no instruction pays the escrow out to the issuer");

    const { iss, mint } = await setupEscrowToken();
    const issuerUsdc = await createAssociatedTokenAccount(connection, authority, usdcMint, iss.publicKey);
    await fundAndRelease(mint, iss);
    const ts: any = await tokenState(mint);
    assert.equal((ts.issuerClaimable as BN).toNumber(), 1_000_000, "the clean audit releases the issuer share");
    assert.equal(await balance(client.pdas.issuerEscrow(mint)[0]), 1_000_000, "it stays in the escrow");
    assert.equal(await balance(issuerUsdc), 0, "nothing reaches the issuer's account");
  });

  it("(al) one escrow partner per token, picked by the issuer from the registry; locked during the campaign unless revoked; separate keys", async () => {
    const iss = Keypair.generate();
    await airdrop(iss.publicKey, 5);
    const mint = await setupToken({ issuer: iss });
    const p1 = Keypair.generate();
    const p2 = Keypair.generate();
    for (const k of [p1.publicKey, p2.publicKey, iss.publicKey, auditor.publicKey, authority.publicKey]) await registerPartnerTx(k);
    const outsider = Keypair.generate();
    await airdrop(outsider.publicKey, 1);

    assert.match((await failure(setEscrowPartnerTx(mint, outsider, p1.publicKey))) ?? "", /Unauthorized|ConstraintHasOne/, "only the issuer picks the partner");
    assert.match(
      (await failure(setEscrowPartnerTx(mint, iss, Keypair.generate().publicKey))) ?? "",
      /AccountNotInitialized|PartnerNotRegistered/,
      "the partner must be registered",
    );
    for (const [k, label] of [
      [iss.publicKey, "the issuer"],
      [auditor.publicKey, "the manifest's auditor"],
      [authority.publicKey, "the operator"],
    ] as [PublicKey, string][]) {
      assert.match((await failure(setEscrowPartnerTx(mint, iss, k))) ?? "", /RolesNotSeparate/, `${label} cannot manage the escrow`);
    }
    await setEscrowPartnerTx(mint, iss, p1.publicKey);
    assert.equal(((await tokenState(mint)).escrowPartner as PublicKey).toBase58(), p1.publicKey.toBase58(), "the token's escrow partner");

    // The manifest cannot name the escrow partner as its auditor
    await program.methods
      .registerAuditor()
      .accounts({
        authority: authority.publicKey,
        config: client.pdas.config()[0],
        auditor: p1.publicKey,
        auditorRecord: client.pdas.auditorRecord(p1.publicKey)[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    assert.match(
      (await failure(setManifestTx(mint, TERM_LEN, { issuer: iss, auditor: p1.publicKey }))) ?? "",
      /RolesNotSeparate/,
      "the auditor and the escrow partner are different keys",
    );

    // Locked during the campaign
    assert.match((await failure(setEscrowPartnerTx(mint, iss, p2.publicKey))) ?? "", /EscrowPartnerLocked/, "no change during the campaign");

    // The operator revokes partners (only the operator, once); a revoked partner cannot convert fees either
    assert.match((await failure(revokePartnerTx(outsider, p1.publicKey))) ?? "", /Unauthorized|ConstraintHasOne/, "only the operator revokes");
    await revokePartnerTx(authority, p1.publicKey);
    assert.match((await failure(revokePartnerTx(authority, p1.publicKey))) ?? "", /PartnerRevoked/, "revoked once");
    assert.match((await failure(convertTx(mint, 10_000, 10_000, p1))) ?? "", /PartnerNotRegistered/, "a revoked partner cannot convert");

    // After the revocation the issuer moves to another registered partner (showing the revoked partner's record)
    assert.match((await failure(setEscrowPartnerTx(mint, iss, p2.publicKey))) ?? "", /EscrowPartnerLocked/, "still locked without the revoked record");
    await setEscrowPartnerTx(mint, iss, p2.publicKey, p1.publicKey);
    assert.equal(((await tokenState(mint)).escrowPartner as PublicKey).toBase58(), p2.publicKey.toBase58(), "replaced after the revocation");
    assert.match((await failure(setEscrowPartnerTx(mint, iss, p1.publicKey, p2.publicKey))) ?? "", /PartnerNotRegistered/, "a revoked partner cannot be picked");
  });

  it("(am) the manifest records the hash of the use plan", async () => {
    const mint = await setupToken();
    const m: any = await manifestOf(mint);
    assert.deepEqual(Array.from(m.usePlanHash as number[]), PLAN_HASH, "the use plan's hash (its items and caps are an off-chain document)");
  });

  it("(an) withdrawal requests: a manifest in force with a use plan, within the released balance, never to the issuer, one per invoice", async () => {
    const { iss, mint } = await setupEscrowToken();
    await fundAndRelease(mint, iss);
    const escrow = client.pdas.issuerEscrow(mint)[0];
    const vendorUsdc = await createAssociatedTokenAccount(connection, authority, usdcMint, Keypair.generate().publicKey);
    const issuerUsdc = await createAssociatedTokenAccount(connection, authority, usdcMint, iss.publicKey);
    const outsider = Keypair.generate();
    await airdrop(outsider.publicKey, 1);

    assert.match((await failure(requestTx(mint, outsider, 100_000, vendorUsdc, invoice("an-0")))) ?? "", /Unauthorized|ConstraintHasOne/, "only the issuer requests");
    assert.match((await failure(requestTx(mint, iss, 1_000_001, vendorUsdc, invoice("an-1")))) ?? "", /WithdrawalExceedsReleased/, "at most the released balance");
    assert.match((await failure(requestTx(mint, iss, 100_000, issuerUsdc, invoice("an-2")))) ?? "", /PayeeIsIssuer/, "not to the issuer's own account");

    await requestTx(mint, iss, 400_000, vendorUsdc, invoice("an-3"), 7);
    const req = await requestOf(mint, invoice("an-3"));
    assert.equal((req.amount as BN).toNumber(), 400_000, "amount");
    assert.equal(req.planItem, 7, "item of the use plan");
    assert.deepEqual(Array.from(req.planHash as number[]), PLAN_HASH, "the use plan in force");
    assert.equal((req.payee as PublicKey).toBase58(), vendorUsdc.toBase58(), "payee");
    assert.deepEqual(Array.from(req.invoiceHash as number[]), invoice("an-3"), "invoice hash");
    assert.equal(req.executed, false, "not executed");
    assert.match((await failure(requestTx(mint, iss, 100_000, vendorUsdc, invoice("an-3")))) ?? "", /already in use/, "an invoice is used once");
    assert.equal(await balance(escrow), 1_000_000, "a request alone moves nothing");
    assert.equal(await balance(vendorUsdc), 0, "nothing paid yet");

    // No manifest in force: without a use plan, and after the term
    const iss2 = Keypair.generate();
    await airdrop(iss2.publicKey, 5);
    const bare = await setupToken({ issuer: iss2, termLen: new BN(10), planHash: Array(32).fill(0) });
    assert.match((await failure(requestTx(bare, iss2, 1, vendorUsdc, invoice("an-4")))) ?? "", /UsePlanNotSet/, "no request without a use plan");
    await waitChainTime(((await manifestOf(bare)).validUntil as BN).toNumber());
    assert.match((await failure(requestTx(bare, iss2, 1, vendorUsdc, invoice("an-5")))) ?? "", /ManifestExpired/, "no request after the term");
  });

  it("(ao) a request runs only with both the escrow partner's and the auditor's approval, straight from the escrow; never with one of them, the issuer or the operator", async () => {
    const { iss, mint, p } = await setupEscrowToken();
    await fundAndRelease(mint, iss);
    const escrow = client.pdas.issuerEscrow(mint)[0];
    const vendorUsdc = await createAssociatedTokenAccount(connection, authority, usdcMint, Keypair.generate().publicKey);
    const outsider = Keypair.generate();

    const inv1 = invoice("ao-1");
    await requestTx(mint, iss, 400_000, vendorUsdc, inv1);
    assert.match((await failure(approveTx(mint, authority, inv1))) ?? "", /NotAnApprover/, "the operator's key cannot approve");
    assert.match((await failure(approveTx(mint, iss, inv1))) ?? "", /NotAnApprover/, "nor the issuer's");
    assert.match((await failure(approveTx(mint, outsider, inv1))) ?? "", /NotAnApprover/, "nor anyone else's");

    await approveTx(mint, p, inv1);
    assert.equal(await balance(vendorUsdc), 0, "the partner's approval alone moves nothing");
    assert.equal(await balance(escrow), 1_000_000, "the escrow is untouched");
    assert.equal((await requestOf(mint, inv1)).executed, false, "not executed");
    await approveTx(mint, p, inv1);
    assert.equal(await balance(vendorUsdc), 0, "approving twice is still one approval");

    await approveTx(mint, auditor, inv1);
    assert.equal(await balance(vendorUsdc), 400_000, "with both approvals the payee is paid");
    assert.equal(await balance(escrow), 600_000, "straight from the escrow");
    assert.equal(((await tokenState(mint)).issuerClaimable as BN).toNumber(), 600_000, "the released balance drops");
    assert.equal((await requestOf(mint, inv1)).executed, true, "executed");
    assert.match((await failure(approveTx(mint, p, inv1))) ?? "", /WithdrawalAlreadyExecuted/, "a request runs once");

    // The other order: the auditor's approval alone moves nothing either
    const inv2 = invoice("ao-2");
    await requestTx(mint, iss, 100_000, vendorUsdc, inv2);
    await approveTx(mint, auditor, inv2);
    assert.equal(await balance(vendorUsdc), 400_000, "the auditor's approval alone moves nothing");
    await approveTx(mint, p, inv2);
    assert.equal(await balance(vendorUsdc), 500_000, "paid once both have approved");

    // Two requests each within the released balance but not together: the second cannot run
    const inv3 = invoice("ao-3");
    const inv4 = invoice("ao-4");
    await requestTx(mint, iss, 500_000, vendorUsdc, inv3);
    await requestTx(mint, iss, 500_000, vendorUsdc, inv4);
    await approveTx(mint, p, inv3);
    await approveTx(mint, auditor, inv3);
    await approveTx(mint, p, inv4);
    assert.match((await failure(approveTx(mint, auditor, inv4))) ?? "", /WithdrawalExceedsReleased/, "nothing beyond the released balance");
    assert.equal(await balance(vendorUsdc), 1_000_000, "only the released balance was paid");
    assert.equal(await balance(escrow), 0, "the escrow is spent down to zero");
  });

  it("(ap) fraud slashes everything left in the escrow, released or not, and pending requests cannot run", async () => {
    const { iss, mint, p } = await setupEscrowToken();
    await fundAndRelease(mint, iss);
    const escrow = client.pdas.issuerEscrow(mint)[0];
    const vendorUsdc = await createAssociatedTokenAccount(connection, authority, usdcMint, Keypair.generate().publicKey);

    // Next period: another conversion (part fills the pool up to what is owed, the rest goes to the escrow) and a half-approved request
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);
    await convertTx(mint, 10_000, 5_000_000);
    const inv = invoice("ap-1");
    await requestTx(mint, iss, 300_000, vendorUsdc, inv);
    await approveTx(mint, p, inv);
    const next = await provisionUntilBudget(mint);
    const ts: any = await tokenState(mint);
    assert.equal((ts.issuerClaimable as BN).toNumber(), 1_000_000, "released share in the escrow");
    assert.isAbove((ts.issuerPending as BN).toNumber(), 0, "and a share waiting for this audit");
    const escrowBefore = await balance(escrow);
    const bond = await balance(client.pdas.slashingBond(mint)[0]);
    const slashBefore = await balance(slashDestAta);

    await auditPeriod(mint, next.periodId, next.budget, "attackX", iss);
    assert.equal(((await program.account.auditCycle.fetch(client.pdas.audit(mint, next.periodId)[0])) as any).result, 2, "FraudOverstatement");
    assert.equal(await balance(escrow), 0, "the whole escrow is slashed");
    assert.equal((await balance(slashDestAta)) - slashBefore, bond + escrowBefore, "bond and escrow (released and pending) go to the compensation pool");
    assert.equal(((await tokenState(mint)).issuerClaimable as BN).toNumber(), 0, "nothing released remains");
    assert.match((await failure(approveTx(mint, auditor, inv))) ?? "", /TokenFrozen/, "a pending request cannot run after fraud");
    assert.equal(await balance(vendorUsdc), 0, "nothing was paid");
  });

  it("(aq) on exit the escrow's remainder and the issuer's half of the bond go to customers through liquidation, and so do later issuer shares", async () => {
    const { iss, mint } = await setupEscrowToken({ periodLen: 20 });
    const issuerUsdc = await createAssociatedTokenAccount(connection, authority, usdcMint, iss.publicKey);
    const vault = client.pdas.redemptionVault(mint)[0];
    const escrow = client.pdas.issuerEscrow(mint)[0];
    const bondPda = client.pdas.slashingBond(mint)[0];

    // Fill the escrow and request the exit in the same period; the final audit passes and releases the share
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);
    await convertTx(mint, 10_000, 5_000_000);
    await requestExitTx(mint, iss);
    const r = ((await tokenState(mint)).exitRequestPeriod as BN).toNumber();
    const p = await provisionUntilBudget(mint);
    const tree = await auditPeriod(mint, p.periodId, p.budget, "pass", iss);
    assert.equal(((await tokenState(mint)).issuerClaimable as BN).toNumber(), 1_000_000, "released before the exit");
    while (((await tokenState(mint)).periodId as BN).toNumber() <= r) {
      await waitPeriod(mint);
      await provision(mint);
    }

    const vault0 = await balance(vault);
    const surplus0 = vault0 - ((await tokenState(mint)).reserved as BN).toNumber();
    const bond = await balance(bondPda);
    const treasury0 = await balance(treasuryAta);
    await finalizeExitTx(mint);
    assert.equal((await balance(vault)) - vault0, 1_000_000 + bond / 2, "the escrow's remainder and the issuer's half of the bond go to the redemption pool");
    assert.equal((await balance(treasuryAta)) - treasury0, bond - bond / 2, "the operator's half is unchanged");
    assert.equal(await balance(escrow), 0, "the escrow is empty");
    assert.equal(((await tokenState(mint)).issuerClaimable as BN).toNumber(), 0, "nothing stays released for the issuer");

    // An issuer share arriving after the exit goes to the pool as well
    const vault1 = await balance(vault);
    await convertTx(mint, 10_000, 5_000_000);
    assert.equal((await balance(vault)) - vault1, 1_000_000, "the issuer share after the exit goes to the pool");
    assert.equal(await balance(escrow), 0, "not to the escrow");

    // Liquidation: all of it is split over the last clean audit's leaves
    const pool = (await balance(vault)) - ((await tokenState(mint)).reserved as BN).toNumber();
    assert.equal(pool, surplus0 + 1_000_000 + bond / 2 + 1_000_000, "the liquidation surplus includes them");
    await startLiquidationTx(mint);
    assert.equal(((await tokenState(mint)).liquidationPool as BN).toNumber(), pool, "liquidation pool");
    await confirmLeaf(mint, p.periodId, tree, 1);
    const ben1 = await createAssociatedTokenAccount(connection, authority, usdcMint, tree.beneficiaryAt(1));
    await claimLiquidationTx(mint, p.periodId, tree, 1, ben1);
    const v1 = Number(tree.valueAt(1));
    assert.equal(await balance(ben1), Math.floor((pool * v1) / p.budget), "the customer's share, pro rata to the confirmed amount");

    // Issuer shares arriving after liquidation started are added to the split
    const more = await accrueVolume(mint, VOLUME);
    await harvest(mint, [more.dst]);
    await convertTx(mint, 10_000, 5_000_000);
    assert.equal(((await tokenState(mint)).liquidationPool as BN).toNumber(), pool + 1_000_000, "added to the liquidation pool");
    await claimLiquidationTx(mint, p.periodId, tree, 1, ben1);
    assert.equal(await balance(ben1), Math.floor(((pool + 1_000_000) * v1) / p.budget), "the same customer receives its share of the addition");
    assert.equal(await balance(issuerUsdc), 0, "the issuer receives nothing at any point");
  });

  it("(ar) the company can request a payment from the bond: down to half its target, with both approvals, straight to the payee; redemptions go on and fees refill it", async () => {
    const { iss, mint, p } = await setupEscrowToken();
    const bondPda = client.pdas.slashingBond(mint)[0];
    const vendorUsdc = await createAssociatedTokenAccount(connection, authority, usdcMint, Keypair.generate().publicKey);
    const issuerUsdc = await createAssociatedTokenAccount(connection, authority, usdcMint, iss.publicKey);
    const half = BOND_TARGET.toNumber() / 2;
    assert.equal(await balance(bondPda), BOND_TARGET.toNumber(), "the bond is full");

    // Up to half of the target, never to the issuer itself
    assert.match((await failure(requestTx(mint, iss, half + 1, vendorUsdc, invoice("ar-0"), 3, true))) ?? "", /BondUseExceedsLimit/, "at most half of the bond target");
    assert.match((await failure(requestTx(mint, iss, half, issuerUsdc, invoice("ar-1"), 3, true))) ?? "", /PayeeIsIssuer/, "not to the issuer's own account");
    const inv = invoice("ar-2");
    await requestTx(mint, iss, half, vendorUsdc, inv, 3, true);
    assert.equal((await requestOf(mint, inv)).fromBond, true, "a request on the bond");
    assert.match((await failure(requestTx(mint, iss, 1, vendorUsdc, inv))) ?? "", /already in use/, "the invoice is used once, whichever account pays");

    // Both approvals, never the operator; paid straight from the bond
    assert.match((await failure(approveTx(mint, authority, inv))) ?? "", /NotAnApprover/, "the operator's key cannot approve");
    await approveTx(mint, p, inv);
    assert.equal(await balance(vendorUsdc), 0, "one approval moves nothing");
    await approveTx(mint, auditor, inv);
    assert.equal(await balance(vendorUsdc), half, "the payee is paid");
    assert.equal(await balance(bondPda), BOND_TARGET.toNumber() - half, "straight from the bond");
    assert.match((await failure(requestTx(mint, iss, 1, vendorUsdc, invoice("ar-3"), 3, true))) ?? "", /BondUseExceedsLimit/, "the other half stays");

    // Redemptions go on while the bond is below its target
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);
    const next = await provisionUntilBudget(mint);
    assert.equal(next.budget, OBLIGATION, "the next obligation is provisioned as usual");

    // The issuer's share of later fees refills the bond first, then the rest goes on as before
    await convertTx(mint, 10_000, 5_000_000);
    assert.equal(await balance(bondPda), BOND_TARGET.toNumber(), "refilled to the target from the issuer's share");
    assert.equal(await balance(client.pdas.issuerEscrow(mint)[0]), 1_000_000 - half, "the rest of the issuer's share goes to the escrow");
    assert.equal(await balance(issuerUsdc), 0, "nothing goes to the issuer's account");

    // Before the bond first reaches its target, it cannot be drawn on
    const iss2 = Keypair.generate();
    await airdrop(iss2.publicKey, 5);
    const fresh = await createTorusMint({ mintAuthority: iss2 });
    await issueTokenTx(fresh, iss2);
    await setManifestTx(fresh, TERM_LEN, { issuer: iss2 });
    await setTermsTx(fresh);
    assert.match((await failure(requestTx(fresh, iss2, 1, vendorUsdc, invoice("ar-4"), 3, true))) ?? "", /BondTargetNotReached/, "not before the bond is full");
  });

  // ---------------------------------------------------------------- distribution, perks

  /** Commit → uniqueness → sample → disclosures → honest observations: the cycle is Verified, ready to finalize. */
  async function toVerified(mint: PublicKey, controlTotalOf: (budget: number) => number = (b) => b) {
    const c = await commitAndSample(mint, controlTotalOf);
    await submitDisclosures(mint, c.periodId, c.tree, c.sampleIndices);
    await observe(mint, c.periodId, auditor);
    return c;
  }

  async function auditOf(mint: PublicKey, periodId: BN): Promise<any> {
    return program.account.auditCycle.fetch(client.pdas.audit(mint, periodId)[0]);
  }

  async function transferTx(mint: PublicKey, from: Keypair, src: PublicKey, dst: PublicKey, amount: number) {
    const ix = await createTransferCheckedWithTransferHookInstruction(
      connection, src, mint, dst, from.publicKey, BigInt(amount), DECIMALS, [], "confirmed", TOKEN_2022_PROGRAM_ID,
    );
    return sendAndConfirmTransaction(connection, new Transaction().add(ix), from === authority ? [authority] : [authority, from]);
  }

  async function brandAta(mint: PublicKey, owner: PublicKey) {
    return createAssociatedTokenAccountIdempotent(connection, authority, mint, owner, undefined, TOKEN_2022_PROGRAM_ID);
  }

  function setPerkTermsTx(mint: PublicKey, params: typeof PERKS = PERKS) {
    return program.methods
      .setPerkTerms(params)
      .accounts({
        authority: authority.publicKey,
        config: client.pdas.config()[0],
        tokenState: client.pdas.tokenState(mint)[0],
        perkTerms: client.pdas.perkTerms(mint)[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  }

  function registerHolderTx(mint: PublicKey, owner: Keypair, account: PublicKey) {
    return program.methods
      .registerHolder()
      .accounts({
        holder: owner.publicKey,
        tokenState: client.pdas.tokenState(mint)[0],
        perkTerms: client.pdas.perkTerms(mint)[0],
        mint,
        holderToken: account,
        holderRecord: client.pdas.holder(account)[0],
        holderPerk: client.pdas.holderPerk(account)[0],
        poolAuthority: client.pdas.poolAuthority(mint)[0],
        hookProgram: hook.programId,
        systemProgram: SystemProgram.programId,
      })
      .signers(owner === authority ? [] : [owner])
      .rpc();
  }

  async function holderRecordOf(account: PublicKey): Promise<any> {
    return hook.account.holderRecord.fetch(client.pdas.holder(account)[0]);
  }

  function registerMerchantTx(mint: PublicKey, merchant: PublicKey) {
    return program.methods
      .registerMerchant()
      .accounts({
        issuer: issuer.publicKey,
        tokenState: client.pdas.tokenState(mint)[0],
        merchant,
        merchantRecord: client.pdas.merchant(mint, merchant)[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  }

  async function openPerkPeriodTx(mint: PublicKey) {
    const ts = await tokenState(mint);
    return program.methods
      .openPerkPeriod()
      .accounts({
        crank: authority.publicKey,
        tokenState: client.pdas.tokenState(mint)[0],
        perkTerms: client.pdas.perkTerms(mint)[0],
        localPartnerRecord: client.pdas.localPartner(ts.localPartner)[0],
        volumeCounter: client.pdas.volumeCounter(mint)[0],
        perkPeriod: client.pdas.perkPeriod(mint, ts.periodId)[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  }

  async function redeemTx(
    mint: PublicKey,
    merchant: Keypair,
    holder: Keypair,
    account: PublicKey,
    kind: number,
    amount: number,
    receiptId: number[] = Array.from(Keypair.generate().publicKey.toBytes()),
  ) {
    const ts = await tokenState(mint);
    return program.methods
      .redeemPerk(kind, new BN(amount), receiptId)
      .accounts({
        merchant: merchant.publicKey,
        holder: holder.publicKey,
        tokenState: client.pdas.tokenState(mint)[0],
        perkTerms: client.pdas.perkTerms(mint)[0],
        perkPeriod: client.pdas.perkPeriod(mint, ts.periodId)[0],
        merchantRecord: client.pdas.merchant(mint, merchant.publicKey)[0],
        mint,
        holderToken: account,
        holderRecord: client.pdas.holder(account)[0],
        holderPerk: client.pdas.holderPerk(account)[0],
        receipt: client.pdas.perkReceipt(mint, receiptId)[0],
        systemProgram: SystemProgram.programId,
      })
      .signers([merchant, holder].filter((k) => k !== authority))
      .rpc();
  }

  async function restampTx(mint: PublicKey, holder: Keypair, account: PublicKey, amount: number, lp: Keypair = localPartner) {
    return program.methods
      .restamp(new BN(amount))
      .accounts({
        holder: holder.publicKey,
        localPartner: lp.publicKey,
        localPartnerRecord: client.pdas.localPartner(lp.publicKey)[0],
        tokenState: client.pdas.tokenState(mint)[0],
        perkTerms: client.pdas.perkTerms(mint)[0],
        mint,
        holderToken: account,
        partnerToken: await brandAta(mint, lp.publicKey),
        holderRecord: client.pdas.holder(account)[0],
        poolAuthority: client.pdas.poolAuthority(mint)[0],
        hookProgram: hook.programId,
        tokenProgram: TOKEN_2022_PROGRAM_ID,
      })
      .signers([holder, lp].filter((k) => k !== authority))
      .rpc();
  }

  it("(as) tax reconciliation: registered by the operator with the accountant's signature (never the issuer's key); a declared total within the book total passes", async () => {
    const mint = await setupToken();
    taxBook.set(mint.toBase58(), OBLIGATION);
    const replaceTx = (accountant: Keypair, signer: Keypair) =>
      program.methods
        .replaceTaxAccountant(consent("warning and consent v2"))
        .accounts({
          authority: signer.publicKey,
          config: client.pdas.config()[0],
          tokenState: client.pdas.tokenState(mint)[0],
          accountant: accountant.publicKey,
          taxAccountantRecord: client.pdas.taxAccountant(mint)[0],
        })
        .signers([accountant, signer].filter((k) => k !== authority))
        .rpc();
    const outsider = Keypair.generate();
    assert.match((await failure(replaceTx(issuer, authority))) ?? "", /Unauthorized/, "never the issuer's key");
    assert.match((await failure(replaceTx(taxAccountant, outsider))) ?? "", /Unauthorized/, "only the operator");

    const { periodId } = await toVerified(mint);
    const report: any = await program.account.taxReport.fetch(client.pdas.taxReport(mint, periodId)[0]);
    assert.equal(report.bookTotal.toNumber(), OBLIGATION);
    assert.ok(report.accountant.equals(taxAccountant.publicKey));
    assert.match((await failure(fileTaxReportTx(mint, OBLIGATION, outsider))) ?? "", /TaxAccountantNotRegistered/, "only the company's accountant files");

    await finalizeTx(mint, periodId);
    assert.equal((await auditOf(mint, periodId)).result, 1, "Pass");
  });

  it("(at) a declared total above the book total holds the cycle (payouts wait); a reconciled report within the hold resumes it", async () => {
    const mint = await setupToken();
    taxBook.set(mint.toBase58(), OBLIGATION / 2);
    const { periodId } = await toVerified(mint);

    await finalizeTx(mint, periodId);
    let audit = await auditOf(mint, periodId);
    assert.equal(audit.stage, 2, "still Verified: nothing is decided and no payout can run");
    assert.isAbove(audit.taxHoldUntil.toNumber(), 0, "on hold");
    assert.match((await failure(finalizeTx(mint, periodId))) ?? "", /TaxHoldActive/, "waits for the reconciled report");

    await fileTaxReportTx(mint, OBLIGATION);
    await finalizeTx(mint, periodId);
    audit = await auditOf(mint, periodId);
    assert.equal(audit.result, 1, "resumed: Pass");
    assert.isTrue((await program.account.taxReport.fetch(client.pdas.taxReport(mint, periodId)[0])).refiled);
  });

  it("(au) a reconciled report that still shows a gap: only the book total is recognized, the rest is carried, and the cycle cannot pass", async () => {
    const mint = await setupToken();
    const book = OBLIGATION - OBLIGATION / 20; // 95%: above the shortfall floor, beyond the 5% tolerance
    taxBook.set(mint.toBase58(), book);
    const { periodId } = await toVerified(mint);
    await finalizeTx(mint, periodId); // hold
    const before = await tokenState(mint);

    await fileTaxReportTx(mint, book); // reconciled, the gap remains
    await finalizeTx(mint, periodId);
    const audit = await auditOf(mint, periodId);
    const after = await tokenState(mint);
    assert.equal(audit.result, 4, "HonestShortfall, never a pass");
    assert.equal(audit.reservedRemaining.toNumber(), book, "only the book total is recognized");
    assert.equal(after.unfulfilled.sub(before.unfulfilled).toNumber(), OBLIGATION - book, "the rest is carried");
    assert.isFalse(after.frozen);
  });

  it("(av) no reconciled report within the hold forfeits the cycle; no report by the deadline is a default and a late report is rejected", async () => {
    // A: on hold, nobody reconciles → forfeited like fraud
    const a = await setupToken();
    taxBook.set(a.toBase58(), OBLIGATION / 2);
    const ca = await toVerified(a);
    await finalizeTx(a, ca.periodId);
    await waitChainTime((await auditOf(a, ca.periodId)).taxHoldUntil.toNumber() + 1);
    assert.match((await failure(fileTaxReportTx(a, OBLIGATION))) ?? "", /TaxReportLate/, "the hold has ended");
    await finalizeTx(a, ca.periodId);
    assert.equal((await auditOf(a, ca.periodId)).result, 6, "BookMismatch");
    assert.isTrue((await tokenState(a)).frozen);
    assert.equal(await balance(client.pdas.slashingBond(a)[0]), 0, "the bond is slashed");

    // B: no report by the deadline → the issuer's default
    const b = await setupToken();
    taxBook.set(b.toBase58(), null);
    const cb = await toVerified(b);
    await waitChainTime((await tokenState(b)).auditDeadline.toNumber() + 1);
    assert.match((await failure(fileTaxReportTx(b, OBLIGATION))) ?? "", /TaxReportLate/, "a late first report is rejected");
    await finalizeTx(b, cb.periodId);
    assert.equal((await auditOf(b, cb.periodId)).result, 3, "default (FraudUnderstatement)");
    assert.isTrue((await tokenState(b)).frozen);
  });

  it("(aw) per-company rank table and local partner: the rules are enforced and the operator's share is split with the partner", async () => {
    const mint = await createTorusMint();
    await issueTokenTx(mint);
    await setManifestTx(mint, TERM_LEN);
    const terms = (tiers: number[], lp?: PublicKey) => setTermsTx(mint, authority, BOND_TARGET, MIN_PRICE, tiers, lp);
    assert.match((await failure(terms([3_000, 2_000, 5_000, 6_500]))) ?? "", /InvalidTierShares/, "a higher rank never gets less");
    assert.match((await failure(terms([2_000, 3_500, 5_000, 10_001]))) ?? "", /InvalidTierShares/, "at most 100%");

    const lp2 = Keypair.generate();
    const outsider = Keypair.generate();
    await airdrop(outsider.publicKey, 1);
    assert.match((await failure(registerLocalPartnerTx(lp2.publicKey, 10_001))) ?? "", /InvalidShareBps/, "at most 100%");
    assert.match((await failure(registerLocalPartnerTx(lp2.publicKey, 3_000, outsider))) ?? "", /Unauthorized/, "only the operator");
    await registerLocalPartnerTx(lp2.publicKey, 3_000);
    await terms([1_000, 2_000, 3_000, 4_000], lp2.publicKey);
    const ts = await tokenState(mint);
    assert.equal(ts.distributionRatioBps, 1_000, "rank 0 share of this company");
    assert.ok(ts.localPartner.equals(lp2.publicKey));

    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);
    const lpUsdc = await createAssociatedTokenAccountIdempotent(connection, authority, usdcMint, lp2.publicKey);
    const split = async () => {
      const [t0, p0] = [await balance(treasuryAta), await balance(lpUsdc)];
      await convertTx(mint, 10_000, 100_000);
      return [(await balance(treasuryAta)) - t0, (await balance(lpUsdc)) - p0];
    };
    // Operator share 90% of 100_000; the partner takes 30% of it
    assert.deepEqual(await split(), [63_000, 27_000]);

    // A revoked partner gets nothing (its share goes to the treasury) and cannot be named again
    await program.methods
      .revokeLocalPartner()
      .accounts({ authority: authority.publicKey, config: client.pdas.config()[0], localPartnerRecord: client.pdas.localPartner(lp2.publicKey)[0] })
      .rpc();
    assert.deepEqual(await split(), [90_000, 0]);
    assert.match((await failure(terms(TIER_SHARES, lp2.publicKey))) ?? "", /LocalPartnerNotRegistered/);
  });

  it("(ax) the mint authority moves to the program; only a restamp mints, signed by the holder and the local partner, never more than it burns", async () => {
    const mint = await setupToken();
    const m0 = await getMint(connection, mint, undefined, TOKEN_2022_PROGRAM_ID);
    assert.ok(m0.mintAuthority?.equals(client.pdas.poolAuthority(mint)[0]), "the program holds the mint authority");
    const src = await brandAta(mint, authority.publicKey);
    assert.isNotNull(
      await failure(mintToChecked(connection, authority, mint, src, authority, 1, DECIMALS, [], undefined, TOKEN_2022_PROGRAM_ID)),
      "the issuer can no longer mint",
    );

    await setPerkTermsTx(mint, { ...PERKS, restampFeeBps: 1_000 });
    await registerHolderTx(mint, authority, src);
    const registeredAt = await chainTime();
    const rec0 = await holderRecordOf(src);
    assert.isAtMost(rec0.stampTs.toNumber(), registeredAt - 3 * PERKS.holdStepSecs.toNumber() + 5, "the balance held at registration starts at 0%");

    const amount = await balance(src, TOKEN_2022_PROGRAM_ID);
    const stranger = Keypair.generate();
    await airdrop(stranger.publicKey, 1);
    assert.match(
      (await failure(restampTx(mint, authority, src, amount, stranger))) ?? "",
      /LocalPartnerNotRegistered|AccountNotInitialized/,
      "only with the company's local partner",
    );

    await restampTx(mint, authority, src, amount);
    const fee = amount / 10;
    const m1 = await getMint(connection, mint, undefined, TOKEN_2022_PROGRAM_ID);
    assert.equal(m1.supply, m0.supply, "the supply does not grow");
    assert.equal(await balance(src, TOKEN_2022_PROGRAM_ID), amount - fee, "the holder gets it back minus the fee");
    assert.equal(await balance(await brandAta(mint, localPartner.publicKey), TOKEN_2022_PROGRAM_ID), fee, "the fee goes to the partner");
    assert.isAtLeast((await holderRecordOf(src)).stampTs.toNumber(), registeredAt - 5, "the re-minted amount carries today's stamp");
  });

  it("(ay) perks: registration starts at 0%, received tokens carry today's stamp, budgets come from the previous obligation, trader and hold perks stay within allowances and budgets", async () => {
    const mint = await setupToken({ periodLen: 20 });
    await setPerkTermsTx(mint);
    assert.match((await failure(setPerkTermsTx(mint, { ...PERKS, generalBps: 5_000 }))) ?? "", /InvalidPerkAllocation/, "100% in total");
    assert.match((await failure(setPerkTermsTx(mint, { ...PERKS, holdRateBps: [1_000, 2_000, 0] }))) ?? "", /InvalidHoldRates/, "never rises");

    const [alice, bob, shop] = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
    for (const k of [alice, bob, shop]) await airdrop(k.publicKey, 1);
    const [src, aliceAta, bobAta] = [await brandAta(mint, authority.publicKey), await brandAta(mint, alice.publicKey), await brandAta(mint, bob.publicKey)];
    await registerHolderTx(mint, authority, src); // registered with its balance: 0%
    await registerHolderTx(mint, alice, aliceAta);
    await registerHolderTx(mint, bob, bobAta);
    await registerMerchantTx(mint, shop.publicKey);
    const funded = await chainTime();
    await transferTx(mint, authority, src, aliceAta, 1_500_000); // received from others: today's stamp
    await transferTx(mint, alice, aliceAta, bobAta, 500_000); // alice sends: trader volume
    await harvest(mint, [aliceAta, bobAta]);
    assert.isAtLeast((await holderRecordOf(aliceAta)).stampTs.toNumber(), funded - 5);

    const { periodId, budget } = await provisionUntilBudget(mint);
    await openPerkPeriodTx(mint);
    const pp: any = await program.account.perkPeriod.fetch(client.pdas.perkPeriod(mint, periodId)[0]);
    assert.equal(pp.traderBudget.toNumber(), (budget * PERKS.traderBps) / BPS, "previous obligation × allocation");
    assert.equal(pp.holdBudget.toNumber(), (budget * PERKS.holdBps) / BPS);
    assert.equal(pp.traderRateBps, FEE_BPS / 2, "capped at half the transfer fee: trading with oneself loses");

    // Trader perk: up to what alice sent last period × the rate
    const allowance = (500_000 * (FEE_BPS / 2)) / BPS;
    await redeemTx(mint, shop, alice, aliceAta, 0, allowance);
    assert.match((await failure(redeemTx(mint, shop, alice, aliceAta, 0, 1))) ?? "", /PerkAllowanceExceeded/);
    assert.match((await failure(redeemTx(mint, bob, alice, aliceAta, 1, 1_000))) ?? "", /AccountNotInitialized|MerchantNotRegistered/, "registered merchants only");

    // Hold perk: fresh stamp → 30%, on purchases up to the period's lowest balance × cap per token
    const cap = await balance(aliceAta, TOKEN_2022_PROGRAM_ID); // cap per token = 1 unit per unit
    const receipt = Array.from(Keypair.generate().publicKey.toBytes());
    await redeemTx(mint, shop, alice, aliceAta, 1, 100_000, receipt);
    const r: any = await program.account.perkReceipt.fetch(client.pdas.perkReceipt(mint, receipt)[0]);
    assert.equal(r.discount.toNumber(), 30_000);
    assert.isNotNull(await failure(redeemTx(mint, shop, alice, aliceAta, 1, 1_000, receipt)), "a receipt is recorded once");
    assert.match((await failure(redeemTx(mint, shop, alice, aliceAta, 1, cap - 100_000 + 1))) ?? "", /PerkAllowanceExceeded/);
    assert.match((await failure(redeemTx(mint, shop, authority, src, 1, 100_000))) ?? "", /InvalidPerkRedemption/, "registration alone gives 0%");
  });

  it("(az) overstatement found by the deviation check is final at once: it waits neither for the tax report nor for a hold", async () => {
    // A: no report yet and its deadline still ahead (a longer period). Waiting would leave the token unfrozen and the
    //    escrow and the bond spendable until the deadline.
    const a = await setupToken({ periodLen: 30 });
    taxBook.set(a.toBase58(), null);
    const ca = await commitAndSample(a, (b) => b);
    await submitDisclosures(a, ca.periodId, ca.tree, ca.sampleIndices);
    await observe(a, ca.periodId, auditor, (x) => x / 10n);
    assert.isBelow(await chainTime(), (await tokenState(a)).auditDeadline.toNumber(), "the report is not due yet");
    await finalizeTx(a, ca.periodId);
    assert.equal((await auditOf(a, ca.periodId)).result, 2, "FraudOverstatement without waiting for the report");
    assert.isTrue((await tokenState(a)).frozen);
    assert.equal(await balance(client.pdas.slashingBond(a)[0]), 0, "the bond is slashed at once");

    // B: the report shows a gap: no hold either
    const b = await setupToken();
    taxBook.set(b.toBase58(), OBLIGATION / 2);
    const cb = await commitAndSample(b, (x) => x);
    await submitDisclosures(b, cb.periodId, cb.tree, cb.sampleIndices);
    await observe(b, cb.periodId, auditor, (x) => x / 10n);
    await finalizeTx(b, cb.periodId);
    const audit = await auditOf(b, cb.periodId);
    assert.equal(audit.result, 2, "FraudOverstatement, not held");
    assert.equal(audit.taxHoldUntil.toNumber(), 0, "no hold");
    assert.isTrue((await tokenState(b)).frozen);
  });

  it("(ba) a cycle capped by the books pays each leaf only its share of the book total, so the carried gap is not paid twice", async () => {
    const mint = await setupToken();
    const book = OBLIGATION - OBLIGATION / 20; // as in (au): the gap remains after the reconciliation
    taxBook.set(mint.toBase58(), book);
    const c = await toVerified(mint);
    await finalizeTx(mint, c.periodId); // hold
    await fileTaxReportTx(mint, book);
    await finalizeTx(mint, c.periodId);
    assert.equal((await auditOf(mint, c.periodId)).result, 4, "HonestShortfall");

    let paid = 0;
    for (let i = 0; i < POP; i++) {
      await confirmLeaf(mint, c.periodId, c.tree, i);
      const usdc = await createAssociatedTokenAccountIdempotent(connection, authority, usdcMint, c.tree.beneficiaryAt(i));
      await payoutTx(mint, c.periodId, usdc, i, c.tree);
      const got = await balance(usdc);
      assert.equal(got, Number((c.tree.valueAt(i) * BigInt(book)) / BigInt(c.controlTotal)), "its share of the book total");
      paid += got;
    }
    assert.isAtMost(paid, book, "the cycle pays at most what the books show");
  });

  it("(bb) conversions go on when a revoked local partner has closed its USDC account; its share goes to the treasury", async () => {
    const mint = await createTorusMint();
    await issueTokenTx(mint);
    await setManifestTx(mint, TERM_LEN);
    const lp = Keypair.generate();
    await airdrop(lp.publicKey, 1);
    await registerLocalPartnerTx(lp.publicKey, 3_000);
    await setTermsTx(mint, authority, BOND_TARGET, MIN_PRICE, TIER_SHARES, lp.publicKey);
    const { dst } = await accrueVolume(mint, VOLUME);
    await harvest(mint, [dst]);

    await program.methods
      .revokeLocalPartner()
      .accounts({ authority: authority.publicKey, config: client.pdas.config()[0], localPartnerRecord: client.pdas.localPartner(lp.publicKey)[0] })
      .rpc();
    await closeAccount(connection, authority, getAssociatedTokenAddressSync(usdcMint, lp.publicKey), lp.publicKey, lp);
    const t0 = await balance(treasuryAta);
    assert.isNull(await failure(convertTx(mint, 10_000, 100_000)), "the revoked partner's account is not needed");
    assert.equal((await balance(treasuryAta)) - t0, 80_000, "the operator's whole share goes to the treasury");
  });

  it("(bc) perks stop at the exit: afterwards no redemption is recorded, since no audit can take it any more", async () => {
    const mint = await setupToken({ periodLen: 40 }); // the final audit and the exit fit in one period
    await setPerkTermsTx(mint);
    const [alice, shop] = [Keypair.generate(), Keypair.generate()];
    for (const k of [alice, shop]) await airdrop(k.publicKey, 1);
    const [src, aliceAta] = [await brandAta(mint, authority.publicKey), await brandAta(mint, alice.publicKey)];
    await registerHolderTx(mint, alice, aliceAta);
    await registerMerchantTx(mint, shop.publicKey);
    await transferTx(mint, authority, src, aliceAta, VOLUME); // the exit's last period: volume, and today's stamp for alice
    await harvest(mint, [aliceAta]);
    await requestExitTx(mint);

    const p = await provisionUntilBudget(mint);
    await openPerkPeriodTx(mint);
    await redeemTx(mint, shop, alice, aliceAta, 1, 10_000); // a perk of the final cycle is still recorded
    const tree = buildTree(p.budget);
    await commitTx(mint, p.periodId, tree, p.budget);
    await verifyUniqueness(mint, p.periodId, tree);
    await waitAfterCommit(mint, p.periodId);
    await designateTx(mint, p.periodId);
    await submitDisclosures(mint, p.periodId, tree, await sampledIndices(mint, p.periodId));
    await observe(mint, p.periodId, auditor);
    await finalizeTx(mint, p.periodId);
    await finalizeExitTx(mint);
    assert.isTrue((await tokenState(mint)).exited);
    assert.match((await failure(redeemTx(mint, shop, alice, aliceAta, 1, 10_000))) ?? "", /TokenExited/, "no perk after the exit");
    assert.match((await failure(listPerkTx(mint, alice, aliceAta, 1))) ?? "", /TokenExited/, "nothing can be listed after the exit either");
  });

  it("(bd) overstatement is final at once even without the uniqueness proof: withholding it does not delay the freeze", async () => {
    // A cycle that could pass still waits for the proof ((ac)); one whose overstatement is found is fraud either way.
    const mint = await setupToken();
    const c = await commitAndSample(mint, (b) => b, POP, false); // the issuer withholds the uniqueness proof
    await submitDisclosures(mint, c.periodId, c.tree, c.sampleIndices);
    await observe(mint, c.periodId, auditor, (x) => x / 10n);
    await finalizeTx(mint, c.periodId);
    assert.equal((await auditOf(mint, c.periodId)).result, 2, "FraudOverstatement without waiting for the deadline");
    assert.isTrue((await tokenState(mint)).frozen);
    assert.equal(await balance(client.pdas.slashingBond(mint)[0]), 0, "the bond is slashed at once");
  });

  // ---------------------------------------------------------------- the perk market

  async function listPerkTx(mint: PublicKey, seller: Keypair, account: PublicKey, amount: number, lp: Keypair = localPartner) {
    const ts = await tokenState(mint);
    return program.methods
      .listPerk(new BN(amount))
      .accounts({
        seller: seller.publicKey,
        localPartner: lp.publicKey,
        localPartnerRecord: client.pdas.localPartner(lp.publicKey)[0],
        tokenState: client.pdas.tokenState(mint)[0],
        perkPeriod: client.pdas.perkPeriod(mint, ts.periodId)[0],
        mint,
        holderToken: account,
        holderRecord: client.pdas.holder(account)[0],
        holderPerk: client.pdas.holderPerk(account)[0],
        lot: client.pdas.perkLot(mint, ts.periodId, account)[0],
        systemProgram: SystemProgram.programId,
      })
      .signers([seller, lp].filter((k) => k !== authority))
      .rpc();
  }

  function closePerkLotTx(mint: PublicKey, seller: Keypair, lot: PublicKey) {
    return program.methods
      .closePerkLot()
      .accounts({ seller: seller.publicKey, tokenState: client.pdas.tokenState(mint)[0], lot })
      .signers([seller])
      .rpc();
  }

  /**
   * A token with a seller who sent `sent` last period and an open perk period. `received` goes from an unregistered
   * account to the seller first, so the volume can be larger than what registered accounts sent.
   */
  async function setupSeller(mint: PublicKey, received: number, sent: number, perks: typeof PERKS = PERKS) {
    await setPerkTermsTx(mint, perks);
    const [seller, buyer, shop] = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
    for (const k of [seller, buyer, shop]) await airdrop(k.publicKey, 1);
    const [src, sellerAta, buyerAta] = [await brandAta(mint, authority.publicKey), await brandAta(mint, seller.publicKey), await brandAta(mint, buyer.publicKey)];
    await registerHolderTx(mint, seller, sellerAta);
    await registerMerchantTx(mint, shop.publicKey);
    await transferTx(mint, authority, src, sellerAta, received);
    await transferTx(mint, seller, sellerAta, buyerAta, sent);
    await harvest(mint, [sellerAta, buyerAta]);
    const provisioned = await provisionUntilBudget(mint);
    await openPerkPeriodTx(mint);
    return { seller, buyer, shop, sellerAta, ...provisioned, lot: client.pdas.perkLot(mint, provisioned.periodId, sellerAta)[0] };
  }

  it("(be) listing moves part of the trader perk into the seller's lot: within the allowance, with the local partner's signature, sharing one allowance with the seller's own use", async () => {
    const mint = await setupToken({ periodLen: 30 });
    assert.match((await failure(setPerkTermsTx(mint, { ...PERKS, maxAskBps: 9_001 }))) ?? "", /InvalidPerkMarketTerms/, "customers keep at least 10%");
    assert.match((await failure(setPerkTermsTx(mint, { ...PERKS, usageCapBps: 5_001 }))) ?? "", /InvalidPerkMarketTerms/, "at least half must be a real purchase");

    const { seller, buyer, shop, sellerAta, periodId, lot } = await setupSeller(mint, 1_500_000, 500_000);
    const period: any = await program.account.perkPeriod.fetch(client.pdas.perkPeriod(mint, periodId)[0]);
    assert.equal(period.traderRateBps, FEE_BPS / 2);
    assert.equal(period.listableRateBps, FEE_BPS / 2, "fee × (1 − 65%) + a 50% return rate is far above half the fee");
    assert.equal(period.maxAskBps, PERKS.maxAskBps);
    assert.equal(period.usageCapBps, PERKS.usageCapBps);
    const allowance = (500_000 * (FEE_BPS / 2)) / BPS; // 2,500

    assert.match((await failure(listPerkTx(mint, seller, sellerAta, 0))) ?? "", /InvalidPerkListing/);
    assert.match((await failure(listPerkTx(mint, seller, sellerAta, 100, Keypair.generate()))) ?? "", /AccountNotInitialized|LocalPartnerNotRegistered/, "the local partner co-signs");
    assert.isNotNull(await failure(listPerkTx(mint, buyer, sellerAta, 100)), "only the account's owner can list");

    await listPerkTx(mint, seller, sellerAta, 1_000);
    await listPerkTx(mint, seller, sellerAta, 500);
    const stored: any = await program.account.perkLot.fetch(lot);
    assert.equal(stored.listed.toNumber(), 1_500, "listing again adds to the lot");
    assert.equal(stored.seller.toBase58(), seller.publicKey.toBase58());
    assert.equal(stored.account.toBase58(), sellerAta.toBase58());
    assert.equal(stored.periodId.toNumber(), periodId.toNumber());
    assert.equal(((await program.account.perkPeriod.fetch(client.pdas.perkPeriod(mint, periodId)[0])) as any).traderUsed.toNumber(), 1_500, "the budget is reserved at listing");
    assert.match((await failure(listPerkTx(mint, seller, sellerAta, allowance - 1_500 + 1))) ?? "", /PerkAllowanceExceeded/);

    // One allowance: what is listed cannot also be used by the seller
    await redeemTx(mint, shop, seller, sellerAta, 0, allowance - 1_500);
    assert.match((await failure(redeemTx(mint, shop, seller, sellerAta, 0, 1))) ?? "", /PerkAllowanceExceeded/);
    assert.match((await failure(listPerkTx(mint, seller, sellerAta, 1))) ?? "", /PerkAllowanceExceeded/);
    assert.match((await failure(closePerkLotTx(mint, seller, lot))) ?? "", /PerkLotStillOpen/, "the period is still open");
    assert.isNotNull(await failure(closePerkLotTx(mint, buyer, lot)), "only the seller can close the lot");
  });

  it("(bf) what can be listed is capped below half the fee when the issuer's share would let an insider profit", async () => {
    // Fee 1%, top share 80%, return 0.1%: sending costs an insider 0.2% + 0.1%. Half the fee (0.5%) would pay at an ask of 80%.
    const mint = await setupToken({ periodLen: 30, returnRateBps: 10, floorBps: 10, tiers: [5_000, 6_000, 7_000, 8_000] });
    const { seller, shop, sellerAta, periodId, lot } = await setupSeller(mint, VOLUME, 100_000);
    const period: any = await program.account.perkPeriod.fetch(client.pdas.perkPeriod(mint, periodId)[0]);
    assert.equal(period.traderRateBps, FEE_BPS / 2, "few registered accounts: the trader rate is at its cap");
    assert.equal(period.listableRateBps, 30, "20 kept + 10 return");

    assert.match((await failure(listPerkTx(mint, seller, sellerAta, 301))) ?? "", /PerkAllowanceExceeded/, "100,000 × 0.3% = 300");
    await listPerkTx(mint, seller, sellerAta, 300);
    assert.equal(((await program.account.perkLot.fetch(lot)) as any).listed.toNumber(), 300);

    // The seller can still use the rest of its own allowance as a discount: only selling is capped
    await redeemTx(mint, shop, seller, sellerAta, 0, 200);
    assert.match((await failure(redeemTx(mint, shop, seller, sellerAta, 0, 1))) ?? "", /PerkAllowanceExceeded/, "100,000 × 0.5% = 500 in all");
  });

  it("(bg) a customer's use settles through the existing audit and payout: the pool pays the face value, split between the merchant and the seller; the lot's rent comes back after its period closes", async () => {
    const mint = await setupToken({ periodLen: 30 });
    const { seller, shop, sellerAta, periodId, budget, lot } = await setupSeller(mint, 1_500_000, 500_000);
    const rentBefore = await connection.getBalance(seller.publicKey);
    await listPerkTx(mint, seller, sellerAta, 2_000);

    // A customer used 1,500 of the lot at an ask of 70% at the merchant's shop (off-chain, signed at checkout).
    const face = 1_500;
    const sellerValue = (face * 7_000) / BPS;
    const merchantValue = face - sellerValue;
    const others = distributeLeafValues(budget - face, POP - 2).map((value) => ({
      outcomeId: newOutcome(),
      beneficiary: Keypair.generate().publicKey,
      value,
    }));
    const tree = new SumTree(sortByOutcome([
      { outcomeId: newOutcome(), beneficiary: seller.publicKey, value: BigInt(sellerValue) },
      { outcomeId: newOutcome(), beneficiary: shop.publicKey, value: BigInt(merchantValue) },
      ...others,
    ]));
    await commitTx(mint, periodId, tree, budget);
    await verifyUniqueness(mint, periodId, tree);
    await waitAfterCommit(mint, periodId);
    await designateTx(mint, periodId);
    await submitDisclosures(mint, periodId, tree, await sampledIndices(mint, periodId));
    await observe(mint, periodId, auditor);
    await finalizeTx(mint, periodId);
    assert.equal((await auditOf(mint, periodId)).result, 1, "Pass");

    let paid = 0;
    for (const [owner, value] of [[seller.publicKey, sellerValue], [shop.publicKey, merchantValue]] as [PublicKey, number][]) {
      const index = [...Array(POP).keys()].find((i) => tree.beneficiaryAt(i).equals(owner))!;
      const usdc = await createAssociatedTokenAccountIdempotent(connection, authority, usdcMint, owner);
      await confirmLeaf(mint, periodId, tree, index);
      await payoutTx(mint, periodId, usdc, index, tree);
      assert.equal(await balance(usdc), value);
      paid += await balance(usdc);
      assert.isNotNull(await failure(payoutTx(mint, periodId, usdc, index, tree)), "a leaf is paid once");
    }
    assert.equal(paid, face, "merchant + seller = the face value, the same as if the seller had used the perk");

    await waitPeriod(mint);
    assert.match((await failure(listPerkTx(mint, seller, sellerAta, 1))) ?? "", /PerkPeriodNotCurrent/, "the period is over, even before anyone provisions the next one");
    await provision(mint);
    assert.match((await failure(closePerkLotTx(mint, seller, lot))) ?? "", /PerkLotStillOpen/, "kept until the audit deadline of its period has passed");
    await waitPeriod(mint);
    await provision(mint);
    await closePerkLotTx(mint, seller, lot);
    assert.isNull(await connection.getAccountInfo(lot), "closed");
    assert.isAtMost(rentBefore - (await connection.getBalance(seller.publicKey)), 100_000, "the rent came back, only fees are gone");
  });

  it("(bh) a company can turn listing off for a period, and later terms do not change an open period", async () => {
    const mint = await setupToken({ periodLen: 30 });
    const { seller, sellerAta } = await setupSeller(mint, 1_500_000, 500_000, { ...PERKS, usageCapBps: 0 });
    assert.match((await failure(listPerkTx(mint, seller, sellerAta, 100))) ?? "", /PerkListingClosed/);
    await setPerkTermsTx(mint);
    assert.match((await failure(listPerkTx(mint, seller, sellerAta, 100))) ?? "", /PerkListingClosed/, "the open period keeps its terms");
  });

  it("(bi) a freeze stops listing; the lot can still be closed", async () => {
    const mint = await setupToken({ periodLen: 30 });
    const { seller, sellerAta, periodId, budget, lot } = await setupSeller(mint, 1_500_000, 500_000);
    await listPerkTx(mint, seller, sellerAta, 100);

    const tree = buildTree(budget);
    await commitTx(mint, periodId, tree, budget);
    await verifyUniqueness(mint, periodId, tree);
    await waitAfterCommit(mint, periodId);
    await designateTx(mint, periodId);
    await submitDisclosures(mint, periodId, tree, await sampledIndices(mint, periodId));
    await observe(mint, periodId, auditor, (x) => x / 10n);
    await finalizeTx(mint, periodId);
    assert.isTrue((await tokenState(mint)).frozen);

    assert.match((await failure(listPerkTx(mint, seller, sellerAta, 100))) ?? "", /TokenFrozen/);
    await closePerkLotTx(mint, seller, lot);
    assert.isNull(await connection.getAccountInfo(lot));
  });

  it("(bj) a local partner's share lowers what can be listed; a revoked partner's does not", async () => {
    // Fee 1%, top share 80%, return 0.1%: with a partner on 50%, sending costs the issuer's side and the partner only 0.1% + 0.1%.
    const mint = await setupToken({ periodLen: 30, returnRateBps: 10, floorBps: 10, tiers: [5_000, 6_000, 7_000, 8_000] });
    const lp = Keypair.generate();
    await airdrop(lp.publicKey, 1);
    await registerLocalPartnerTx(lp.publicKey, 5_000);
    await setTermsTx(mint, authority, BOND_TARGET, MIN_PRICE, [5_000, 6_000, 7_000, 8_000], lp.publicKey);
    const { seller, sellerAta, periodId, lot } = await setupSeller(mint, VOLUME, 100_000);
    const period: any = await program.account.perkPeriod.fetch(client.pdas.perkPeriod(mint, periodId)[0]);
    assert.equal(period.listableRateBps, 20, "10 kept + 10 return");
    assert.match((await failure(listPerkTx(mint, seller, sellerAta, 201, lp))) ?? "", /PerkAllowanceExceeded/, "100,000 × 0.2% = 200");
    await listPerkTx(mint, seller, sellerAta, 200, lp);
    assert.equal(((await program.account.perkLot.fetch(lot)) as any).listed.toNumber(), 200);

    // Revoked: its share goes to the treasury, so nothing comes back to it any more.
    const other = await setupToken({ periodLen: 30, returnRateBps: 10, floorBps: 10, tiers: [5_000, 6_000, 7_000, 8_000] });
    const revoked = Keypair.generate();
    await airdrop(revoked.publicKey, 1);
    await registerLocalPartnerTx(revoked.publicKey, 5_000);
    await setTermsTx(other, authority, BOND_TARGET, MIN_PRICE, [5_000, 6_000, 7_000, 8_000], revoked.publicKey);
    await program.methods
      .revokeLocalPartner()
      .accounts({ authority: authority.publicKey, config: client.pdas.config()[0], localPartnerRecord: client.pdas.localPartner(revoked.publicKey)[0] })
      .rpc();
    const opened = await setupSeller(other, VOLUME, 100_000);
    const otherPeriod: any = await program.account.perkPeriod.fetch(client.pdas.perkPeriod(other, opened.periodId)[0]);
    assert.equal(otherPeriod.listableRateBps, 30, "20 kept + 10 return");
    assert.match((await failure(listPerkTx(other, opened.seller, opened.sellerAta, 1, revoked))) ?? "", /LocalPartnerNotRegistered/, "a revoked partner cannot co-sign");
  });

  it("(bk) an account that changes hands mid-period cannot redirect its lot", async () => {
    const mint = await setupToken({ periodLen: 30 });
    await setPerkTermsTx(mint, PERKS);
    const [seller, buyer, nextOwner] = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
    for (const k of [seller, buyer, nextOwner]) await airdrop(k.publicKey, 1);
    const src = await brandAta(mint, authority.publicKey);
    const buyerAta = await brandAta(mint, buyer.publicKey);
    // An associated token account's owner is immutable, so this needs a plain account.
    const account = await createAccount(connection, authority, mint, seller.publicKey, Keypair.generate(), undefined, TOKEN_2022_PROGRAM_ID);
    await registerHolderTx(mint, seller, account);
    await transferTx(mint, authority, src, account, 1_500_000);
    await transferTx(mint, seller, account, buyerAta, 500_000);
    await harvest(mint, [account, buyerAta]);
    const { periodId } = await provisionUntilBudget(mint);
    await openPerkPeriodTx(mint);
    await listPerkTx(mint, seller, account, 100);
    await setAuthority(connection, authority, account, seller, AuthorityType.AccountOwner, nextOwner.publicKey, [], undefined, TOKEN_2022_PROGRAM_ID);
    assert.match((await failure(listPerkTx(mint, nextOwner, account, 100))) ?? "", /Unauthorized/);
    const lot: any = await program.account.perkLot.fetch(client.pdas.perkLot(mint, periodId, account)[0]);
    assert.equal(lot.seller.toBase58(), seller.publicKey.toBase58());
    assert.equal(lot.listed.toNumber(), 100);
  });
});
