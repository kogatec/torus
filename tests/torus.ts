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
 *   (i) no commitment under an expired manifest
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
 *   (z) voluntary exit: the obligation runs to the requested period; after its audit, half the bond to the issuer and
 *       half to the operator; fees after the exit are split; liquidation shares the pool's surplus among recipients
 *   (aa) defects are judged by count: 21 samples with 0 allowed → one defect is overstatement (a ratio check let it pass)
 *   (ab) fixed period boundaries: a late close still assigns volume to the right period
 *   (ac) uniqueness: duplicates in the tree, root mismatch, finalizing unverified, and reuse in a later period are rejected
 *   (ae) payouts only for confirmed leaves up to the confirmed amount; after a freeze, finalized recipients are still paid and the surplus is liquidated
 *   (af) auditor revocation: a revoked auditor cannot record or confirm, a manifest naming it cannot start a new audit,
 *        and the operator replaces it without waiting; the new auditor observes again and the audit continues
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
  createInitializeMintInstruction,
  createInitializeTransferFeeConfigInstruction,
  createInitializeTransferHookInstruction,
  createInitializePermanentDelegateInstruction,
  createSetTransferFeeInstruction,
  createSetAuthorityInstruction,
  createTransferCheckedWithTransferHookInstruction,
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
        .initialize(usdcMint, hook.programId, slashDestAta, treasuryAta, MIN_SAMPLE, MIN_BOND)
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
      .initialize(usdcMint, hook.programId, slashDestAta, treasuryAta, MIN_SAMPLE, MIN_BOND)
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
  });

  interface MintOpts {
    freezeAuthority?: PublicKey | null;
    permanentDelegate?: PublicKey;
    feeConfigAuthority?: PublicKey | null;
    maxFee?: number;
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
        mintKp.publicKey, DECIMALS, authority.publicKey, opts.freezeAuthority ?? null, TOKEN_2022_PROGRAM_ID,
      ),
    );
    await sendAndConfirmTransaction(connection, tx, [authority, mintKp]);

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
    await mintToChecked(connection, authority, mint, src, authority, amount * 2, DECIMALS, [], undefined, TOKEN_2022_PROGRAM_ID);
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
    return program.methods
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
  }

  /** Fixes (or re-fixes) the manifest. `termLen` is the term (campaign length, seconds). */
  function setManifestTx(mint: PublicKey, termLen: BN, o: ManifestOpts = {}) {
    const aud = o.auditor ?? auditor.publicKey;
    return program.methods
      .setManifest(
        RETURN_RATE_BPS,
        o.toleranceBps ?? TOLERANCE_BPS,
        LCL_BPS,
        FLOOR_BPS,
        new BN(o.periodLen ?? PERIOD_LEN),
        termLen,
        o.sampleSize ?? SAMPLE,
        o.maxDefects ?? 0,
      )
      .accounts({
        issuer: issuer.publicKey,
        tokenState: client.pdas.tokenState(mint)[0],
        manifest: client.pdas.manifest(mint)[0],
        auditor: aud,
        auditorRecord: client.pdas.auditorRecord(aud)[0],
        config: client.pdas.config()[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  }

  /** Terms the operator sets per company (bond target, minimum conversion price). */
  function setTermsTx(mint: PublicKey, signer: Keypair = authority, bondTarget = BOND_TARGET, minPrice = MIN_PRICE) {
    return program.methods
      .setIssuerTerms(bondTarget, minPrice)
      .accounts({ authority: signer.publicKey, config: client.pdas.config()[0], tokenState: client.pdas.tokenState(mint)[0] })
      .signers(signer === authority ? [] : [signer])
      .rpc();
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
  async function setupToken(m: ManifestOpts & { maxFee?: number } = {}): Promise<PublicKey> {
    const mint = await createTorusMint({ maxFee: m.maxFee });
    await issueTokenTx(mint, issuer, FEE_BPS, m.maxFee ?? MAX_FEE);
    await setManifestTx(mint, TERM_LEN, m);
    await setTermsTx(mint);
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

  async function commitTx(mint: PublicKey, periodId: BN, tree: SumTree, controlTotal: number) {
    return program.methods
      .commitPerformance(tree.commitmentArray(), new BN(controlTotal), tree.populationSize)
      .accounts({
        issuer: issuer.publicKey,
        tokenState: client.pdas.tokenState(mint)[0],
        manifest: client.pdas.manifest(mint)[0],
        auditorRecord: await manifestAuditorRecord(mint),
        audit: client.pdas.audit(mint, periodId)[0],
        systemProgram: SystemProgram.programId,
      })
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
    await mintToChecked(connection, authority, mint, src, authority, AMT * 4, DECIMALS, [], undefined, TOKEN_2022_PROGRAM_ID);

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

  it("(i) no commitment under an expired manifest (campaigns)", async () => {
    const mint = await setupToken();
    const { periodId, budget } = await accrueAndProvision(mint);
    const tree = buildTree(budget);

    // --- Switch to a 1-second campaign and wait for it to expire ---
    await setManifestTx(mint, new BN(1));
    const shortManifest: any = await program.account.manifest.fetch(client.pdas.manifest(mint)[0]);
    const validUntil = (shortManifest.validUntil as BN).toNumber();
    await waitChainTime(validUntil + 1);

    const expired = await failure(commitTx(mint, periodId, tree, budget));
    assert.isNotNull(expired, "a commitment under an expired manifest must be rejected");
    assert.match(expired!, /ManifestExpired/, "rejected because the term expired");

    // --- Control: a new campaign allows committing again ---
    await setManifestTx(mint, TERM_LEN);
    assert.isNull(await failure(commitTx(mint, periodId, tree, budget)), "committing works under the new campaign");
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
    await mintToChecked(connection, authority, mint, src, authority, VOLUME, DECIMALS, [], undefined, TOKEN_2022_PROGRAM_ID);
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

  function claimTx(mint: PublicKey, to: PublicKey) {
    return program.methods
      .claimDistribution()
      .accounts({
        crank: authority.publicKey,
        tokenState: client.pdas.tokenState(mint)[0],
        poolAuthority: client.pdas.poolAuthority(mint)[0],
        issuerEscrow: client.pdas.issuerEscrow(mint)[0],
        issuerUsdc: to,
        usdcMint,
        usdcTokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc();
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
  async function auditPeriod(mint: PublicKey, periodId: BN, controlTotal: number, scenario: "pass" | "attackX") {
    const tree = buildTree(controlTotal);
    await commitTx(mint, periodId, tree, controlTotal);
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
    assert.match((await failure(claimTx(mint, depositorUsdc))) ?? "", /NothingToClaim/, "the current period's share cannot be claimed yet");

    const p = await provisionUntilBudget(mint);
    const ts3: any = await program.account.tokenState.fetch(tsPda);
    assert.equal(p.budget, OBLIGATION, "budget = period 1 volume × return rate");
    assert.equal((ts3.reserved as BN).toNumber(), OBLIGATION, "the obligation is reserved in the pool");
    assert.equal((ts3.issuerPending as BN).toNumber(), 600_000, "the share from the closed period waits for this audit");
    assert.match((await failure(claimTx(mint, depositorUsdc))) ?? "", /NothingToClaim/, "not claimable before the audit is final");

    // Audit (pass) → claimable
    const tree = await auditPeriod(mint, ts3.periodId, OBLIGATION, "pass");
    const ts4: any = await program.account.tokenState.fetch(tsPda);
    assert.equal((ts4.issuerClaimable as BN).toNumber(), 600_000, "claimable after a clean result");

    const other = await createAssociatedTokenAccount(connection, authority, usdcMint, Keypair.generate().publicKey);
    assert.match((await failure(claimTx(mint, other))) ?? "", /Unauthorized/, "not paid to an account the issuer does not own");
    const before = await balance(depositorUsdc);
    await claimTx(mint, depositorUsdc);
    assert.equal((await balance(depositorUsdc)) - before, 600_000, "the issuer receives its share");
    assert.equal(await balance(escrow), 0, "the escrow is empty");

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
    assert.match((await failure(convertTx(mint, 10_000, 3_000_000))) ?? "", /IssuerTermsNotSet/, "no conversion without terms");

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
    assert.match((await failure(claimTx(mint, depositorUsdc))) ?? "", /TokenFrozen/, "no distribution after a freeze");
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

  async function finalizeExitTx(mint: PublicKey, issuerUsdc: PublicKey) {
    const ts: any = await tokenState(mint);
    const pid: BN = ts.periodId;
    const audit = pid.gtn(0) && (ts.budget as BN).gtn(0) ? client.pdas.audit(mint, pid)[0] : null;
    const ix = await client.finalizeExit({
      crank: authority.publicKey,
      mint,
      audit,
      issuerUsdc,
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

  it("(z) voluntary exit: obligation through the requested period; half the bond back after its audit; fees after exit; liquidation", async () => {
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
    assert.match((await failure(finalizeExitTx(mint, depositorUsdc))) ?? "", /ExitNotReady/, "not before the provision");
    const p = await provisionUntilBudget(mint);
    assert.equal(p.budget, OBLIGATION, "volume up to the requested period becomes an obligation");
    const tree = buildTree(p.budget);
    await commitTx(mint, p.periodId, tree, p.budget);
    assert.match((await failure(finalizeExitTx(mint, depositorUsdc))) ?? "", /ExitNotReady/, "not before the audit is final");
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
    const other = await createAssociatedTokenAccount(connection, authority, usdcMint, Keypair.generate().publicKey);
    assert.match((await failure(finalizeExitTx(mint, other))) ?? "", /Unauthorized/, "not refunded to an account the issuer does not own");

    const issuerBefore = await balance(depositorUsdc);
    const treasuryBefore = await balance(treasuryAta);
    await finalizeExitTx(mint, depositorUsdc);
    assert.equal((await balance(depositorUsdc)) - issuerBefore, bond / 2, "half the bond to the issuer");
    assert.equal((await balance(treasuryAta)) - treasuryBefore, bond - bond / 2, "the rest to the operator treasury");
    assert.equal(await balance(bondPda), 0, "the bond is empty");
    assert.equal((await tokenState(mint)).exited, true, "exit finalized");

    // After the exit, no provisioning or deposits
    assert.match((await failure(provision(mint))) ?? "", /TokenExited/, "no provisioning after the exit");
    assert.match((await failure(depositTx(mint, 1_000))) ?? "", /TokenExited/, "no deposits after the exit");

    // Fees after the exit: no obligation, so they split into operator and issuer shares and the issuer's is claimable at once
    const claimableBefore = ((await tokenState(mint)).issuerClaimable as BN).toNumber();
    const treasuryMid = await balance(treasuryAta);
    const vaultBeforeConvert = await balance(client.pdas.redemptionVault(mint)[0]);
    await convertTx(mint, 10_000, 5_000_000);
    assert.equal(((await tokenState(mint)).issuerClaimable as BN).toNumber() - claimableBefore, 1_000_000, "the issuer share (20%) becomes claimable");
    assert.equal((await balance(treasuryAta)) - treasuryMid, 4_000_000, "operator share");
    assert.equal(await balance(client.pdas.redemptionVault(mint)[0]), vaultBeforeConvert, "fees after the exit do not go into the pool");

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
    assert.match((await failure(claimLiquidationTx(mint, p.periodId, tree, 1, ben1))) ?? "", /already in use/, "a liquidation share is paid once");

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
});
