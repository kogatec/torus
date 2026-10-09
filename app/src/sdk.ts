/**
 * Torus protocol client SDK.
 *
 * PDA derivation (seeds follow programs/torus-protocol/src/constants.rs), thin typed wrappers for each
 * instruction, and construction of the sum-bound commitment (Merkle sum tree) with its disclosure proofs.
 *
 * Program ids come from the IDL. The Token-2022 mint (with TransferFee and TransferHook) is created with
 * @solana/spl-token, and issue_token rejects it unless
 *      - transfer_fee_config_authority = null (revoked)
 *      - transfer_hook authority        = null (revoked)
 *      - withdraw_withheld_authority    = pool_authority PDA
 *    (plus: no freeze authority, no disallowed extensions, constant fee schedule).
 */

import { BN, Program, web3 } from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID } from "@solana/spl-token";
import { keccak_256 } from "@noble/hashes/sha3";

// The generated types could be imported after anchor build:
//   import { TorusProtocol } from "../../target/types/torus_protocol";
//   import { TorusHook } from "../../target/types/torus_hook";
// `any` is used here for simplicity.
type AnyProgram = Program<any>;

/** Upgradeable program loader (used to derive ProgramData). */
export const BPF_LOADER_UPGRADEABLE_ID = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");

// ---- seeds (must match constants.rs) ----
export const SEEDS = {
  config: Buffer.from("config"),
  tokenState: Buffer.from("token_state"),
  manifest: Buffer.from("manifest"),
  audit: Buffer.from("audit"),
  poolAuthority: Buffer.from("pool_authority"),
  redemptionVault: Buffer.from("redemption_vault"),
  slashingBond: Buffer.from("slashing_bond"),
  feeVault: Buffer.from("fee_vault"),
  auditor: Buffer.from("auditor"),
  claim: Buffer.from("claim"),
  issuerEscrow: Buffer.from("issuer_escrow"),
  partner: Buffer.from("partner"),
  uniq: Buffer.from("uniq"),
  outcome: Buffer.from("outcome"),
  attest: Buffer.from("attest"),
  liq: Buffer.from("liq"),
  // hook side
  extraAccountMetas: Buffer.from("extra-account-metas"),
  volume: Buffer.from("volume"),
};

/** period_id (u64) as an 8-byte LE Buffer. */
export function periodIdLe(periodId: number | bigint | BN): Buffer {
  const bn = BN.isBN(periodId) ? (periodId as BN) : new BN(periodId.toString());
  return bn.toArrayLike(Buffer, "le", 8);
}

export class TorusPdas {
  constructor(
    public readonly protocolprogramId: PublicKey,
    public readonly hookProgramId: PublicKey,
  ) {}

  config(): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.config], this.protocolprogramId);
  }
  tokenState(mint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.tokenState, mint.toBuffer()], this.protocolprogramId);
  }
  manifest(mint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.manifest, mint.toBuffer()], this.protocolprogramId);
  }
  audit(mint: PublicKey, periodId: number | bigint | BN): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [SEEDS.audit, mint.toBuffer(), periodIdLe(periodId)],
      this.protocolprogramId,
    );
  }
  poolAuthority(mint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.poolAuthority, mint.toBuffer()], this.protocolprogramId);
  }
  redemptionVault(mint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.redemptionVault, mint.toBuffer()], this.protocolprogramId);
  }
  slashingBond(mint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.slashingBond, mint.toBuffer()], this.protocolprogramId);
  }
  /** Vault where collected fees (brand token) are swept. */
  feeVault(mint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.feeVault, mint.toBuffer()], this.protocolprogramId);
  }
  /** Record in the operator's auditor registry. */
  auditorRecord(auditor: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.auditor, auditor.toBuffer()], this.protocolprogramId);
  }
  /** Claim record (audit cycle × leaf index). */
  claim(audit: PublicKey, index: number): [PublicKey, number] {
    const idx = Buffer.alloc(4);
    idx.writeUInt32LE(index >>> 0, 0);
    return PublicKey.findProgramAddressSync([SEEDS.claim, audit.toBuffer(), idx], this.protocolprogramId);
  }
  /** Issuer escrow (USDC); not withdrawable until the audit finalizes without fraud. */
  issuerEscrow(mint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.issuerEscrow, mint.toBuffer()], this.protocolprogramId);
  }
  /** Record in the operator's exchange-partner registry. */
  partnerRecord(partner: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.partner, partner.toBuffer()], this.protocolprogramId);
  }
  /** Progress of the uniqueness verification (per audit cycle). */
  uniq(audit: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.uniq, audit.toBuffer()], this.protocolprogramId);
  }
  /** Used payment-ID record (per token, shared by all periods). */
  outcome(mint: PublicKey, outcomeId: Buffer | Uint8Array | number[]): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.outcome, mint.toBuffer(), Buffer.from(outcomeId as any)], this.protocolprogramId);
  }
  /** The auditor's confirmation of a leaf (audit cycle × leaf index). */
  attestation(audit: PublicKey, index: number): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.attest, audit.toBuffer(), u32le(index)], this.protocolprogramId);
  }
  /** Liquidation claim record (audit cycle × leaf index). */
  liquidationClaim(audit: PublicKey, index: number): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.liq, audit.toBuffer(), u32le(index)], this.protocolprogramId);
  }
  /** This program's ProgramData (initialize checks the upgrade authority against it). */
  programData(): PublicKey {
    return PublicKey.findProgramAddressSync([this.protocolprogramId.toBuffer()], BPF_LOADER_UPGRADEABLE_ID)[0];
  }
  // owned / referenced by the hook program
  extraAccountMetaList(mint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.extraAccountMetas, mint.toBuffer()], this.hookProgramId);
  }
  volumeCounter(mint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([SEEDS.volume, mint.toBuffer()], this.hookProgramId);
  }
}

// =====================================================================================
// Sum-bound commitment (Merkle sum tree)
//
// Must match the domain-separation tags in constants.rs:
//   leaf     : H(0x00 ‖ index_le_u32 ‖ outcome_id(32) ‖ beneficiary(32) ‖ value_le_u64) , sum = value
//              (payment ID and recipient are in the leaf, so uniqueness and payouts are bound to the same leaves;
//              leaves must be in strictly increasing payment-ID order, which verify_uniqueness checks)
//   internal : H(0x01 ‖ Lhash ‖ Lsum_le_u64 ‖ Rhash ‖ Rsum_le_u64)          , sum = Ls + Rs
//   commit   : H(0x02 ‖ root_hash ‖ root_sum_le_u64 ‖ population_le_u32)
//
// When the leaf count is not a power of two, an odd last node is promoted to the next level unchanged.
// The on-chain proof check binds the tree's shape to (index, population size) using this same rule, and
// root_sum always equals the sum of all leaves (promotion does not change sums).
// =====================================================================================

export const LEAF_TAG = 0x00;
export const NODE_TAG = 0x01;
export const ROOT_TAG = 0x02;

/** Node of the Merkle sum tree. */
export interface SumNode {
  hash: Buffer;
  sum: bigint;
}

/** Sibling in a disclosure proof (Anchor's SumSibling; `isLeft` = the sibling is on the left). */
export interface SumSiblingArg {
  hash: number[];
  sum: BN;
  isLeft: boolean;
}

function keccak(...parts: Buffer[]): Buffer {
  return Buffer.from(keccak_256(Buffer.concat(parts)));
}

function u32le(v: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(v >>> 0, 0);
  return b;
}

function u64le(v: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(v, 0);
  return b;
}

export function sumLeaf(index: number, outcomeId: Buffer, beneficiary: PublicKey, value: bigint): SumNode {
  return {
    hash: keccak(Buffer.from([LEAF_TAG]), u32le(index), outcomeId, beneficiary.toBuffer(), u64le(value)),
    sum: value,
  };
}

/** An entry of the ledger (a return promise): payment ID (32 bytes), recipient, amount. */
export interface LeafEntry {
  outcomeId: Buffer | Uint8Array | number[];
  beneficiary: PublicKey;
  value: number | bigint | BN;
}

/** Sorts entries by payment ID (the strictly increasing order the uniqueness check requires). */
export function sortByOutcome<T extends LeafEntry>(entries: T[]): T[] {
  return [...entries].sort((a, b) => Buffer.compare(Buffer.from(a.outcomeId as any), Buffer.from(b.outcomeId as any)));
}

export function sumParent(left: SumNode, right: SumNode): SumNode {
  return {
    hash: keccak(
      Buffer.from([NODE_TAG]),
      left.hash,
      u64le(left.sum),
      right.hash,
      u64le(right.sum),
    ),
    sum: left.sum + right.sum,
  };
}

/** Sum-bound Merkle sum tree. Built from the entries; provides the commitment and disclosure proofs. */
export class SumTree {
  /** levels[0] = leaves; the last level is the root (length 1). */
  readonly levels: SumNode[][];
  readonly values: bigint[];
  readonly beneficiaries: PublicKey[];
  readonly outcomeIds: Buffer[];

  constructor(entries: LeafEntry[]) {
    if (entries.length === 0) throw new Error("SumTree: empty population");
    this.outcomeIds = entries.map((e) => Buffer.from(e.outcomeId as any));
    if (this.outcomeIds.some((id) => id.length !== 32)) throw new Error("SumTree: payment IDs must be 32 bytes");
    this.beneficiaries = entries.map((e) => e.beneficiary);
    this.values = entries.map((e) => (BN.isBN(e.value) ? BigInt((e.value as BN).toString()) : BigInt(e.value as any)));

    let level: SumNode[] = this.values.map((v, i) => sumLeaf(i, this.outcomeIds[i], this.beneficiaries[i], v));
    this.levels = [level];
    while (level.length > 1) {
      const next: SumNode[] = [];
      for (let i = 0; i < level.length; i += 2) {
        // An odd last node is promoted unchanged (same hash, same sum).
        next.push(i + 1 < level.length ? sumParent(level[i], level[i + 1]) : level[i]);
      }
      this.levels.push(next);
      level = next;
    }
  }

  get root(): SumNode {
    return this.levels[this.levels.length - 1][0];
  }

  get populationSize(): number {
    return this.values.length;
  }

  /** Sum of all leaves = root.sum. control_total must equal this exactly. */
  get total(): bigint {
    return this.root.sum;
  }

  valueAt(index: number): bigint {
    return this.values[index];
  }

  beneficiaryAt(index: number): PublicKey {
    return this.beneficiaries[index];
  }

  outcomeAt(index: number): number[] {
    return Array.from(this.outcomeIds[index]);
  }

  /** Leaves for the uniqueness check (indices start ≤ i < end). */
  uniqLeaves(start: number, end: number): { outcomeId: number[]; beneficiary: PublicKey; value: BN }[] {
    const out: { outcomeId: number[]; beneficiary: PublicKey; value: BN }[] = [];
    for (let i = start; i < Math.min(end, this.populationSize); i++) {
      out.push({ outcomeId: this.outcomeAt(i), beneficiary: this.beneficiaries[i], value: new BN(this.values[i].toString()) });
    }
    return out;
  }

  /** The 32-byte commitment passed to commit_performance. */
  commitment(): Buffer {
    return keccak(
      Buffer.from([ROOT_TAG]),
      this.root.hash,
      u64le(this.root.sum),
      u32le(this.populationSize),
    );
  }

  commitmentArray(): number[] {
    return Array.from(this.commitment());
  }

  /** Disclosure proof of a leaf (leaf → root; isLeft = that sibling is on the left). */
  proof(index: number): SumSiblingArg[] {
    if (index < 0 || index >= this.populationSize) throw new Error(`SumTree: index out of range ${index}`);
    const siblings: SumSiblingArg[] = [];
    let idx = index;
    for (let l = 0; l < this.levels.length - 1; l++) {
      const level = this.levels[l];
      const promoted = level.length % 2 === 1 && idx === level.length - 1;
      if (!promoted) {
        const sibIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
        const sib = level[sibIdx];
        siblings.push({
          hash: Array.from(sib.hash),
          sum: new BN(sib.sum.toString()),
          isLeft: idx % 2 === 1,
        });
      }
      idx = Math.floor(idx / 2);
    }
    return siblings;
  }
}

/** Splits `total` into `count` leaf values (the remainder goes to the last one). */
export function distributeLeafValues(total: number | bigint, count: number): bigint[] {
  const t = BigInt(total);
  const n = BigInt(count);
  const base = t / n;
  const values = new Array<bigint>(count).fill(base);
  values[count - 1] = base + (t - base * n);
  return values;
}

/**
 * Thin instruction wrappers. `program` is Anchor's Program<TorusProtocol>.
 * Account names must match the fields of each instruction's #[derive(Accounts)].
 */
export class TorusClient {
  readonly pdas: TorusPdas;
  constructor(
    public readonly program: AnyProgram, // torus_protocol
    public readonly hook: AnyProgram, // torus_hook
  ) {
    this.pdas = new TorusPdas(program.programId, hook.programId);
  }

  /** Only the program's upgrade authority can initialize. */
  async initialize(
    authority: PublicKey,
    usdcMint: PublicKey,
    hookProgram: PublicKey,
    slashDestination: PublicKey,
    treasury: PublicKey, // operator treasury (USDC)
    minSampleSize: number,
    minBondTarget: BN, // minimum bond target (set by the operator)
  ) {
    const [config] = this.pdas.config();
    return this.program.methods
      .initialize(usdcMint, hookProgram, slashDestination, treasury, minSampleSize, minBondTarget)
      .accounts({
        authority,
        program: this.program.programId,
        programData: this.pdas.programData(),
        config,
        systemProgram: web3.SystemProgram.programId,
      })
      .instruction();
  }

  /** Adds an independent auditor to the operator's registry (Config.authority only). */
  async registerAuditor(authority: PublicKey, auditor: PublicKey) {
    return this.program.methods
      .registerAuditor()
      .accounts({
        authority,
        config: this.pdas.config()[0],
        auditor,
        auditorRecord: this.pdas.auditorRecord(auditor)[0],
        systemProgram: web3.SystemProgram.programId,
      })
      .instruction();
  }

  async issueToken(params: {
    issuer: PublicKey;
    mint: PublicKey; // Token-2022 mint (already created, with extensions)
    usdcMint: PublicKey;
    token2022Program: PublicKey; // brand token program (Token-2022)
    usdcTokenProgram: PublicKey; // USDC (classic SPL)
    transferFeeBps: number;
    maxFee: BN;
  }) {
    const [config] = this.pdas.config();
    const [tokenState] = this.pdas.tokenState(params.mint);
    const [poolAuthority] = this.pdas.poolAuthority(params.mint);
    const [redemptionVault] = this.pdas.redemptionVault(params.mint);
    const [slashingBond] = this.pdas.slashingBond(params.mint);
    const [feeVault] = this.pdas.feeVault(params.mint);
    return this.program.methods
      .issueToken(params.transferFeeBps, params.maxFee)
      .accounts({
        issuer: params.issuer,
        config,
        mint: params.mint,
        usdcMint: params.usdcMint,
        tokenState,
        poolAuthority,
        redemptionVault,
        slashingBond,
        issuerEscrow: this.pdas.issuerEscrow(params.mint)[0],
        feeVault,
        token2022Program: params.token2022Program,
        usdcTokenProgram: params.usdcTokenProgram,
        systemProgram: web3.SystemProgram.programId,
        rent: web3.SYSVAR_RENT_PUBKEY,
      })
      .instruction();
  }

  async setManifest(params: {
    issuer: PublicKey;
    mint: PublicKey;
    auditor: PublicKey;
    returnRateBps: number;
    toleranceBps: number;
    shortfallToleranceBps: number;
    minReturnRateBps: number;
    periodLen: BN;
    /** Manifest term in seconds (campaign length). valid_until = now + termLen. */
    termLen: BN;
    /** Sample size (at least Config.min_sample_size). */
    sampleSize: number;
    /** Allowed defects (at most 20% of the sample). More defects = overstatement. Default 0. */
    maxDefects?: number;
  }) {
    const [tokenState] = this.pdas.tokenState(params.mint);
    const [manifest] = this.pdas.manifest(params.mint);
    return this.program.methods
      .setManifest(
        params.returnRateBps,
        params.toleranceBps,
        params.shortfallToleranceBps,
        params.minReturnRateBps,
        params.periodLen,
        params.termLen,
        params.sampleSize,
        params.maxDefects ?? 0,
      )
      .accounts({
        issuer: params.issuer,
        tokenState,
        manifest,
        auditor: params.auditor,
        auditorRecord: this.pdas.auditorRecord(params.auditor)[0],
        config: this.pdas.config()[0],
        systemProgram: web3.SystemProgram.programId,
      })
      .instruction();
  }

  /** Closes a period. Fails with BudgetNotEscrowed unless the redemption pool covers the budget. */
  /**
   * When the closing period has an obligation, pass its (Finalized) audit cycle as `prevAudit`.
   * Fails with PeriodNotElapsed until the period's end boundary has passed.
   */
  async provisionBudget(crank: PublicKey, mint: PublicKey, prevAudit: PublicKey | null = null) {
    const [config] = this.pdas.config();
    const [tokenState] = this.pdas.tokenState(mint);
    const [manifest] = this.pdas.manifest(mint);
    const [volumeCounter] = this.pdas.volumeCounter(mint);
    const [redemptionVault] = this.pdas.redemptionVault(mint);
    return this.program.methods
      .provisionBudget()
      .accounts({ crank, config, tokenState, manifest, volumeCounter, redemptionVault, prevAudit })
      .instruction();
  }

  async commitPerformance(params: {
    issuer: PublicKey;
    mint: PublicKey;
    periodId: number | bigint | BN;
    commitmentValue: number[]; // 32 bytes (SumTree.commitmentArray())
    controlTotal: BN; // must equal SumTree.total
    populationSize: number;
    /** The auditor named in the manifest (the commitment is rejected if its registration was revoked). */
    auditor: PublicKey;
  }) {
    const [tokenState] = this.pdas.tokenState(params.mint);
    const [manifest] = this.pdas.manifest(params.mint);
    const [audit] = this.pdas.audit(params.mint, params.periodId);
    return this.program.methods
      .commitPerformance(params.commitmentValue, params.controlTotal, params.populationSize)
      .accounts({
        issuer: params.issuer,
        tokenState,
        manifest,
        auditorRecord: this.pdas.auditorRecord(params.auditor)[0],
        audit,
        systemProgram: web3.SystemProgram.programId,
      })
      .instruction();
  }

  async designateSample(params: {
    crank: PublicKey;
    mint: PublicKey;
    periodId: number | bigint | BN;
    entropy: number[]; // 32 bytes (from a VRF proof in production); the sample size is fixed by the manifest
  }) {
    const [audit] = this.pdas.audit(params.mint, params.periodId);
    return this.program.methods
      .designateSample(params.entropy)
      .accounts({ crank: params.crank, config: this.pdas.config()[0], audit })
      .instruction();
  }

  /**
   * Verifies a disclosure proof: one call per sampled leaf, **in `audit.sample_indices` order**
   * (cursor). record_verification / finalize_audit fail until all sample_size proofs are in.
   */
  async verifyDisclosure(params: {
    crank: PublicKey;
    mint: PublicKey;
    periodId: number | bigint | BN;
    outcomeId: number[];
    beneficiary: PublicKey;
    value: BN;
    siblings: SumSiblingArg[];
  }) {
    const [audit] = this.pdas.audit(params.mint, params.periodId);
    return this.program.methods
      .verifyDisclosure(params.outcomeId, params.beneficiary, params.value, params.siblings)
      .accounts({ crank: params.crank, audit })
      .instruction();
  }

  /**
   * Records the observed value of each sampled leaf in sample order (split if large); the program counts defects
   * and sums. Claimed values were fixed by verify_disclosure. The cycle moves to Verified when all are in.
   */
  async recordVerification(params: {
    auditor: PublicKey;
    mint: PublicKey;
    periodId: number | bigint | BN;
    observedValues: BN[];
    reportHash: number[]; // 32 bytes
  }) {
    const [audit] = this.pdas.audit(params.mint, params.periodId);
    const current: any = await (this.program.account as any).auditCycle.fetch(audit);
    return this.program.methods
      .recordVerification(params.observedValues, params.reportHash)
      .accounts({ auditor: params.auditor, audit, auditorRecord: this.pdas.auditorRecord(current.auditor)[0] })
      .instruction();
  }

  async finalizeAudit(params: {
    crank: PublicKey;
    mint: PublicKey;
    usdcMint: PublicKey;
    slashDestination: PublicKey;
    tokenProgram: PublicKey;
  }) {
    const [config] = this.pdas.config();
    const [tokenState] = this.pdas.tokenState(params.mint);
    const [manifest] = this.pdas.manifest(params.mint);
    // The caller passes the current TokenState.period_id
    // and the audit PDA is derived from it.
    const [poolAuthority] = this.pdas.poolAuthority(params.mint);
    const [slashingBond] = this.pdas.slashingBond(params.mint);
    // The caller passes period_id to derive the audit:
    return async (periodId: number | bigint | BN) => {
      const [audit] = this.pdas.audit(params.mint, periodId);
      return this.program.methods
        .finalizeAudit()
        .accounts({
          crank: params.crank,
          config,
          tokenState,
          manifest,
          audit,
          poolAuthority,
          slashingBond,
          issuerEscrow: this.pdas.issuerEscrow(params.mint)[0],
          slashDestination: params.slashDestination,
          usdcMint: params.usdcMint,
          tokenProgram: params.tokenProgram,
        })
        .instruction();
    };
  }

  /**
   * Sweeps withheld fees (permissionless). `sources` are the brand-token accounts holding withheld fees
   * (forwarded to the CPI as remaining_accounts). With an empty list, only mint → fee_vault is withdrawn.
   */
  async harvestFees(params: {
    crank: PublicKey;
    mint: PublicKey;
    token2022Program: PublicKey;
    sources?: PublicKey[];
  }) {
    const [config] = this.pdas.config();
    const [tokenState] = this.pdas.tokenState(params.mint);
    const [poolAuthority] = this.pdas.poolAuthority(params.mint);
    const [feeVault] = this.pdas.feeVault(params.mint);
    return this.program.methods
      .harvestFees()
      .accounts({
        crank: params.crank,
        config,
        tokenState,
        mint: params.mint,
        poolAuthority,
        feeVault,
        tokenProgram: params.token2022Program,
      })
      .remainingAccounts(
        (params.sources ?? []).map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
      )
      .instruction();
  }

  /**
   * Payout from the redemption pool = a claim on a committed leaf. Fails unless the audit is Finalized,
   * result ∈ {Pass, HonestShortfall} and the bond is full (after a freeze, clean audits can still be claimed).
   * `beneficiaryUsdc` must be owned by the leaf's recipient. The leaf must be confirmed: sampled leaves up to the
   * observed value, others up to the auditor's confirmation (`attestation`), never above the leaf's value.
   * A leaf is never paid twice (claim record PDA).
   */
  async payout(params: {
    crank: PublicKey;
    mint: PublicKey;
    periodId: number | bigint | BN;
    beneficiaryUsdc: PublicKey;
    usdcMint: PublicKey;
    usdcTokenProgram: PublicKey;
    index: number;
    outcomeId: number[];
    value: BN;
    siblings: SumSiblingArg[];
    /** The auditor's confirmation (needed for leaves not in the sample); null if none. */
    attestation?: PublicKey | null;
  }) {
    const [config] = this.pdas.config();
    const [tokenState] = this.pdas.tokenState(params.mint);
    const [audit] = this.pdas.audit(params.mint, params.periodId);
    const [poolAuthority] = this.pdas.poolAuthority(params.mint);
    const [redemptionVault] = this.pdas.redemptionVault(params.mint);
    return this.program.methods
      .payout(params.index, params.outcomeId, params.value, params.siblings)
      .accounts({
        crank: params.crank,
        config,
        tokenState,
        audit,
        poolAuthority,
        redemptionVault,
        beneficiaryUsdc: params.beneficiaryUsdc,
        attestation: params.attestation ?? null,
        claim: this.pdas.claim(audit, params.index)[0],
        usdcMint: params.usdcMint,
        usdcTokenProgram: params.usdcTokenProgram,
        systemProgram: web3.SystemProgram.programId,
      })
      .instruction();
  }

  /** Declares a default after the audit deadline (missing commitment, disclosures or uniqueness proof). Anyone. */
  async declareDefault(params: {
    crank: PublicKey;
    mint: PublicKey;
    periodId: number | bigint | BN;
    usdcMint: PublicKey;
    slashDestination: PublicKey;
    tokenProgram: PublicKey;
  }) {
    return this.program.methods
      .declareDefault()
      .accounts({
        crank: params.crank,
        config: this.pdas.config()[0],
        tokenState: this.pdas.tokenState(params.mint)[0],
        audit: this.pdas.audit(params.mint, params.periodId)[0],
        poolAuthority: this.pdas.poolAuthority(params.mint)[0],
        slashingBond: this.pdas.slashingBond(params.mint)[0],
        issuerEscrow: this.pdas.issuerEscrow(params.mint)[0],
        slashDestination: params.slashDestination,
        usdcMint: params.usdcMint,
        tokenProgram: params.tokenProgram,
      })
      .instruction();
  }

  /** Terms the operator sets per company: bond target and minimum conversion price (Config.authority only). */
  async setIssuerTerms(params: { authority: PublicKey; mint: PublicKey; bondTarget: BN; minConversionPrice: BN }) {
    return this.program.methods
      .setIssuerTerms(params.bondTarget, params.minConversionPrice)
      .accounts({
        authority: params.authority,
        config: this.pdas.config()[0],
        tokenState: this.pdas.tokenState(params.mint)[0],
      })
      .instruction();
  }

  /** Adds an exchange partner to the operator's registry (Config.authority only). */
  async registerPartner(authority: PublicKey, partner: PublicKey) {
    return this.program.methods
      .registerPartner()
      .accounts({
        authority,
        config: this.pdas.config()[0],
        partner,
        partnerRecord: this.pdas.partnerRecord(partner)[0],
        systemProgram: web3.SystemProgram.programId,
      })
      .instruction();
  }

  /**
   * Extra accounts for the fee_vault → partner transfer to pass through the transfer hook
   * (the order registered in the ExtraAccountMetaList: torus-protocol, TokenState, VolumeCounter, plus the hook and the meta list).
   */
  hookTransferAccounts(mint: PublicKey) {
    return [
      { pubkey: this.pdas.extraAccountMetaList(mint)[0], isSigner: false, isWritable: false },
      { pubkey: this.program.programId, isSigner: false, isWritable: false },
      { pubkey: this.pdas.tokenState(mint)[0], isSigner: false, isWritable: true },
      { pubkey: this.pdas.volumeCounter(mint)[0], isSigner: false, isWritable: true },
      { pubkey: this.hook.programId, isSigner: false, isWritable: false },
    ];
  }

  /**
   * Fee conversion (registered partners only). The partner pays `usdcAmount` and receives `tokenAmount` brand tokens
   * from fee_vault. In the same instruction the USDC is split into the operator's and the issuer's share; the issuer's
   * share goes to the bond → redemption pool (up to what is owed) → escrow (after an exit: only the two shares).
   * Fails with ConversionBelowMinPrice below the operator's minimum price.
   */
  async convertFees(params: {
    partner: PublicKey;
    mint: PublicKey;
    partnerToken: PublicKey; // receives the brand tokens (Token-2022)
    partnerUsdc: PublicKey; // pays the USDC
    usdcMint: PublicKey;
    treasury: PublicKey; // Config.treasury
    usdcTokenProgram: PublicKey;
    tokenAmount: BN;
    usdcAmount: BN;
  }) {
    return this.program.methods
      .convertFees(params.tokenAmount, params.usdcAmount)
      .accounts({
        partner: params.partner,
        config: this.pdas.config()[0],
        partnerRecord: this.pdas.partnerRecord(params.partner)[0],
        tokenState: this.pdas.tokenState(params.mint)[0],
        manifest: this.pdas.manifest(params.mint)[0],
        volumeCounter: this.pdas.volumeCounter(params.mint)[0],
        mint: params.mint,
        feeVault: this.pdas.feeVault(params.mint)[0],
        poolAuthority: this.pdas.poolAuthority(params.mint)[0],
        partnerToken: params.partnerToken,
        partnerUsdc: params.partnerUsdc,
        usdcMint: params.usdcMint,
        slashingBond: this.pdas.slashingBond(params.mint)[0],
        redemptionVault: this.pdas.redemptionVault(params.mint)[0],
        issuerEscrow: this.pdas.issuerEscrow(params.mint)[0],
        treasury: params.treasury,
        tokenProgram: TOKEN_2022_PROGRAM_ID,
        usdcTokenProgram: params.usdcTokenProgram,
      })
      .remainingAccounts(this.hookTransferAccounts(params.mint))
      .instruction();
  }

  /** Pays the issuer share that passed a clean audit to the issuer's USDC account (anyone). */
  async claimDistribution(params: {
    crank: PublicKey;
    mint: PublicKey;
    issuerUsdc: PublicKey; // a USDC account owned by the issuer
    usdcMint: PublicKey;
    usdcTokenProgram: PublicKey;
  }) {
    return this.program.methods
      .claimDistribution()
      .accounts({
        crank: params.crank,
        tokenState: this.pdas.tokenState(params.mint)[0],
        poolAuthority: this.pdas.poolAuthority(params.mint)[0],
        issuerEscrow: this.pdas.issuerEscrow(params.mint)[0],
        issuerUsdc: params.issuerUsdc,
        usdcMint: params.usdcMint,
        usdcTokenProgram: params.usdcTokenProgram,
      })
      .instruction();
  }

  /**
   * Replaces the auditor with another registered auditor (Config.authority only): when it did not record by the
   * deadline (current cycle), or when it was revoked (no wait; on a finalized cycle only leaf confirmations move).
   */
  async replaceAuditor(params: {
    authority: PublicKey;
    mint: PublicKey;
    periodId: number | bigint | BN;
    /** The current auditor (audit.auditor). */
    currentAuditor: PublicKey;
    newAuditor: PublicKey;
  }) {
    return this.program.methods
      .replaceAuditor()
      .accounts({
        authority: params.authority,
        config: this.pdas.config()[0],
        tokenState: this.pdas.tokenState(params.mint)[0],
        manifest: this.pdas.manifest(params.mint)[0],
        audit: this.pdas.audit(params.mint, params.periodId)[0],
        currentAuditorRecord: this.pdas.auditorRecord(params.currentAuditor)[0],
        newAuditor: params.newAuditor,
        newAuditorRecord: this.pdas.auditorRecord(params.newAuditor)[0],
      })
      .instruction();
  }

  /** Revokes an auditor's registration (Config.authority only; permanent). */
  async revokeAuditor(authority: PublicKey, auditor: PublicKey) {
    return this.program.methods
      .revokeAuditor()
      .accounts({ authority, config: this.pdas.config()[0], auditorRecord: this.pdas.auditorRecord(auditor)[0] })
      .instruction();
  }

  /**
   * Uniqueness check: sends leaves start ≤ i < end. Leaves must be in strictly increasing payment-ID order.
   * The used-ID record PDA of each leaf goes in remaining_accounts, in the same order. Done after the last leaf.
   */
  async verifyUniqueness(params: {
    crank: PublicKey;
    mint: PublicKey;
    periodId: number | bigint | BN;
    tree: SumTree;
    start: number;
    end: number;
    /** Start over (e.g. after sending a wrong leaf; only before verification completes). */
    restart?: boolean;
  }) {
    const [audit] = this.pdas.audit(params.mint, params.periodId);
    const leaves = params.tree.uniqLeaves(params.start, params.end);
    return this.program.methods
      .verifyUniqueness(leaves, params.restart ?? false)
      .accounts({ crank: params.crank, audit, cursor: this.pdas.uniq(audit)[0], systemProgram: web3.SystemProgram.programId })
      .remainingAccounts(leaves.map((l) => ({ pubkey: this.pdas.outcome(params.mint, l.outcomeId)[0], isSigner: false, isWritable: true })))
      .instruction();
  }

  /** The auditor confirms a leaf (amount confirmed from an independent record, at most the leaf's value). */
  async attestLeaf(params: { auditor: PublicKey; mint: PublicKey; periodId: number | bigint | BN; tree: SumTree; index: number; confirmed: BN }) {
    const [audit] = this.pdas.audit(params.mint, params.periodId);
    const current: any = await (this.program.account as any).auditCycle.fetch(audit);
    return this.program.methods
      .attestLeaf(
        params.index,
        params.tree.outcomeAt(params.index),
        params.tree.beneficiaryAt(params.index),
        new BN(params.tree.valueAt(params.index).toString()),
        params.tree.proof(params.index),
        params.confirmed,
      )
      .accounts({
        auditor: params.auditor,
        audit,
        auditorRecord: this.pdas.auditorRecord(current.auditor)[0],
        attestation: this.pdas.attestation(audit, params.index)[0],
        systemProgram: web3.SystemProgram.programId,
      })
      .instruction();
  }

  /** The issuer requests a voluntary exit. */
  async requestExit(issuer: PublicKey, mint: PublicKey) {
    return this.program.methods.requestExit().accounts({ issuer, tokenState: this.pdas.tokenState(mint)[0] }).instruction();
  }

  /** Finalizes a voluntary exit (anyone). If the current budget > 0, pass the current audit cycle as `audit`. */
  async finalizeExit(params: {
    crank: PublicKey;
    mint: PublicKey;
    audit: PublicKey | null;
    issuerUsdc: PublicKey;
    treasury: PublicKey;
    usdcMint: PublicKey;
    usdcTokenProgram: PublicKey;
  }) {
    return this.program.methods
      .finalizeExit()
      .accounts({
        crank: params.crank,
        config: this.pdas.config()[0],
        tokenState: this.pdas.tokenState(params.mint)[0],
        audit: params.audit,
        poolAuthority: this.pdas.poolAuthority(params.mint)[0],
        slashingBond: this.pdas.slashingBond(params.mint)[0],
        issuerUsdc: params.issuerUsdc,
        treasury: params.treasury,
        usdcMint: params.usdcMint,
        usdcTokenProgram: params.usdcTokenProgram,
      })
      .instruction();
  }

  /** Starts liquidation (after an exit or a freeze; anyone). */
  async startLiquidation(params: { crank: PublicKey; mint: PublicKey; slashDestination: PublicKey; usdcMint: PublicKey; usdcTokenProgram: PublicKey }) {
    return this.program.methods
      .startLiquidation()
      .accounts({
        crank: params.crank,
        config: this.pdas.config()[0],
        tokenState: this.pdas.tokenState(params.mint)[0],
        poolAuthority: this.pdas.poolAuthority(params.mint)[0],
        redemptionVault: this.pdas.redemptionVault(params.mint)[0],
        slashDestination: params.slashDestination,
        usdcMint: params.usdcMint,
        usdcTokenProgram: params.usdcTokenProgram,
      })
      .instruction();
  }

  /** Claims a liquidation share (a leaf of the basis audit, pro rata to its confirmed amount). */
  async claimLiquidation(params: {
    crank: PublicKey;
    mint: PublicKey;
    periodId: number | bigint | BN;
    tree: SumTree;
    index: number;
    beneficiaryUsdc: PublicKey;
    attestation?: PublicKey | null;
    usdcMint: PublicKey;
    usdcTokenProgram: PublicKey;
  }) {
    const [audit] = this.pdas.audit(params.mint, params.periodId);
    return this.program.methods
      .claimLiquidation(
        params.index,
        params.tree.outcomeAt(params.index),
        new BN(params.tree.valueAt(params.index).toString()),
        params.tree.proof(params.index),
      )
      .accounts({
        crank: params.crank,
        tokenState: this.pdas.tokenState(params.mint)[0],
        audit,
        attestation: params.attestation ?? null,
        poolAuthority: this.pdas.poolAuthority(params.mint)[0],
        redemptionVault: this.pdas.redemptionVault(params.mint)[0],
        beneficiaryUsdc: params.beneficiaryUsdc,
        liquidationClaim: this.pdas.liquidationClaim(audit, params.index)[0],
        usdcMint: params.usdcMint,
        usdcTokenProgram: params.usdcTokenProgram,
        systemProgram: web3.SystemProgram.programId,
      })
      .instruction();
  }
}
