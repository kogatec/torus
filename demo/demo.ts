/**
 * Törus — narrated protocol demo.
 *
 * Runs the real programs end to end and prints each step in plain English. Every "BLOCKED"
 * line is a genuine on-chain rejection; if a guard does not trigger, the demo stops instead of
 * printing a false result.
 *
 *   demo/run.sh                  fresh local validator, auto-paced
 *   demo/run.sh --step           wait for Enter before each scene
 *   demo/run.sh --fast           no pauses
 *   demo/run.sh --only 3,4       run selected scenes (1-6)
 *   demo/run.sh --links          print Solana Explorer links for key transactions
 *   demo/run.sh --hold           set up, then wait for Enter before scene 1 (for recording)
 *   demo/run.sh --min f          f.min[i] = shortest time (ms) for the intro (0), scenes 1-6 and the summary (7)
 *   demo/run.sh --timing f       write how long each scene took (ms) to f
 *
 * Against devnet (programs already deployed, wallet funded):
 *   ANCHOR_PROVIDER_URL=https://api.devnet.solana.com ANCHOR_WALLET=<deployer> demo/run.sh --links
 */

import * as anchor from "@coral-xyz/anchor";
import { BN, Program } from "@coral-xyz/anchor";
import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  SYSVAR_RENT_PUBKEY,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  ExtensionType,
  getMintLen,
  getMint,
  getAccount,
  getTransferFeeConfig,
  getTransferHook,
  createMint,
  createAssociatedTokenAccountIdempotent,
  mintTo,
  mintToChecked,
  createInitializeMintInstruction,
  createInitializeTransferFeeConfigInstruction,
  createInitializeTransferHookInstruction,
  createTransferCheckedInstruction,
  createTransferCheckedWithTransferHookInstruction,
  createWithdrawWithheldTokensFromAccountsInstruction,
} from "@solana/spl-token";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as readline from "readline";
import { TorusClient, SumTree, sortByOutcome } from "../app/src/sdk";

// ============================================================================
// Options
// ============================================================================

const argv = process.argv.slice(2);
const flag = (name: string) => argv.includes(name);
const arg = (name: string): string | undefined => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const STEP = flag("--step");
const FAST = flag("--fast");
const LINKS = flag("--links");
const HOLD = flag("--hold");
const ONLY: number[] | null = arg("--only")
  ? arg("--only")!
      .split(",")
      .map((s) => parseInt(s, 10))
      .filter((n) => n >= 1 && n <= 6)
  : null;
const MIN_MS: number[] | null = arg("--min") ? JSON.parse(fs.readFileSync(arg("--min")!, "utf8")).min : null;
const TIMING_OUT = arg("--timing");
const PACE_MS = FAST ? 0 : parseInt(process.env.DEMO_PACE_MS ?? "350", 10);
const RPC = process.env.ANCHOR_PROVIDER_URL ?? "http://127.0.0.1:8899";
const DEVNET = /devnet/.test(RPC);

// ============================================================================
// Demo parameters (6 decimals for both the brand token and USDC)
// ============================================================================

const DEC = 6;
const UNIT = 1_000_000n;
const u = (whole: number) => BigInt(Math.round(whole * 1_000_000));

const FEE_BPS = 100; // 1% transfer fee
const MAX_FEE = u(1_000_000); // per-transfer cap (high: effectively uncapped in the demo)
const RETURN_RATE_BPS = 20; // obligation = 0.2% of the period's trading volume
const FLOOR_BPS = 20;
const TOLERANCE_BPS = 500; // 5%: allowed gap between a claimed and an observed payment
const LCL_BPS = 1_000; // 10%: honest shortfall band
const PERIOD_LEN = parseInt(process.env.DEMO_PERIOD_LEN ?? (DEVNET ? "20" : "4"), 10); // seconds
// ACME (scenes 1-3) trades several times inside one period, so its period is longer.
const HERO_PERIOD_LEN = parseInt(process.env.DEMO_HERO_PERIOD_LEN ?? (DEVNET ? "60" : "12"), 10);
const TERM_LEN = 90 * 86_400;
const SAMPLE = 4;
const MIN_BOND = u(1_000); // operator's floor for any bond target (fixed at initialize)
const BOND_TARGET = u(2_000); // set by the operator for this company
const MIN_PRICE = u(1); // a partner pays at least 1 USDC per brand token
const UNIQ_BATCH = 6;

// The company's ledger of delivered returns for one period: who was paid, for which payment.
const MERCHANTS = [
  "Sakura Taxi",
  "Hikari Delivery",
  "Kaze Mart",
  "Sakura Taxi",
  "Hikari Delivery",
  "Kaze Mart",
  "Sakura Taxi",
  "Hikari Delivery",
];
const LEDGER = [180, 95, 140, 60, 210, 75, 130, 110]; // = 1,000 USDC (meets the obligation)
const LEDGER_HONEST = [170, 90, 130, 55, 200, 70, 125, 110]; // = 950 USDC (honestly short, within the band)

// ============================================================================
// Output helpers
// ============================================================================

const COLOR = !process.env.NO_COLOR;
const c = (code: string) => (s: string | number) => (COLOR ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const bold = c("1");
const dim = c("2");
const red = c("31");
const green = c("32");
const yellow = c("33");
const cyan = c("36");
const magenta = c("35");
const gray = c("90");

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function line(s = "", pace = PACE_MS) {
  console.log(s);
  if (pace > 0) await sleep(pace);
}

function fmt(base: bigint | number | BN, dp = 2): string {
  const v = BigInt(base.toString());
  const whole = v / UNIT;
  const frac = (v % UNIT).toString().padStart(6, "0").slice(0, dp);
  return whole.toLocaleString("en-US") + (dp > 0 ? "." + frac : "");
}
const usdc = (b: bigint | number | BN) => `${fmt(b)} USDC`;
const tok = (b: bigint | number | BN, sym: string) => `${fmt(b, 0)} ${sym}`;
const short = (k: PublicKey | string) => {
  const s = k.toString();
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
};

async function step(s: string) {
  await line(`  ${cyan("→")} ${s}`);
}
async function ok(s: string, detail = "") {
  await line(`    ${green("✔")} ${s}${detail ? gray("  " + detail) : ""}`);
}
async function info(s: string) {
  await line(`      ${gray(s)}`);
}
async function blocked(s: string, code: string) {
  await line(`    ${red("⛔ BLOCKED")} ${s}  ${yellow("[" + code + "]")}`);
}
async function alert(s: string) {
  await line(`    ${magenta("⚡")} ${bold(s)}`);
}
async function link(sig: string) {
  if (!LINKS) return;
  const cluster = DEVNET ? "cluster=devnet" : `cluster=custom&customUrl=${encodeURIComponent(RPC)}`;
  await line(`      ${dim(`explorer: https://explorer.solana.com/tx/${sig}?${cluster}`)}`, 0);
}

async function waitEnter(prompt: string) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  await new Promise<void>((r) => rl.question(gray(prompt), () => r()));
  rl.close();
}

let showStart = 0;
const timings: number[] = [];
let segmentStart = 0;
let segment = 0; // 0 = intro, 1-6 = scenes, 7 = summary

/** Holds the previous segment on screen until its narration has finished. */
async function nextSegment(n: number) {
  if (MIN_MS && MIN_MS[segment] !== undefined) {
    const wait = segmentStart + MIN_MS[segment] - Date.now();
    if (wait > 0) await sleep(wait);
  }
  segment = n;
  segmentStart = Date.now();
  timings[n] = segmentStart - showStart;
}

async function scene(n: number, title: string, subtitle: string) {
  if (STEP) await waitEnter(`\n  [Enter] scene ${n} `);
  await nextSegment(n);
  const bar = "━".repeat(76);
  console.log("\n" + cyan(bar));
  console.log(bold(`  SCENE ${n}  ${title}`));
  console.log(gray(`  ${subtitle}`));
  console.log(cyan(bar));
  await sleep(PACE_MS * 2);
}

/** On-chain error name (Anchor code, Token program error, or "already in use"). */
function errorCode(e: any): string {
  const anchorCode = e?.error?.errorCode?.code;
  if (anchorCode) return anchorCode;
  const logs: string[] = e?.logs ?? e?.transactionLogs ?? e?.transactionError?.logs ?? [];
  const text = `${e?.toString?.() ?? e}\n${logs.join("\n")}`;
  const m = text.match(/Error Code: (\w+)/);
  if (m) return m[1];
  if (/already in use/.test(text)) return "AlreadyClaimed";
  const hex = text.match(/custom program error: (0x[0-9a-f]+)/i);
  if (hex) {
    const spl: Record<string, string> = { "0x1": "InsufficientFunds", "0x4": "OwnerMismatch", "0x11": "AccountFrozen" };
    return spl[hex[1].toLowerCase()] ?? `ProgramError ${hex[1]}`;
  }
  return text.split("\n")[0].slice(0, 80);
}

/** Runs an action the protocol must reject; returns the error name. */
async function mustFail(what: string, fn: () => Promise<unknown>, expect?: RegExp): Promise<string> {
  try {
    await fn();
  } catch (e: any) {
    const code = errorCode(e);
    if (expect && !expect.test(code)) throw new Error(`demo integrity: "${what}" failed for an unexpected reason: ${code}`);
    return code;
  }
  throw new Error(`demo integrity: "${what}" should have been rejected but succeeded`);
}

// ============================================================================
// Chain setup
// ============================================================================

const walletPath = process.env.ANCHOR_WALLET ?? path.join(os.homedir(), ".config/solana/id.json");
const operator = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(walletPath, "utf8"))));
const connection = new Connection(RPC, "confirmed");
const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(operator), { commitment: "confirmed" });
anchor.setProvider(provider);

const root = path.join(__dirname, "..");
const program = new Program(JSON.parse(fs.readFileSync(path.join(root, "target/idl/torus_protocol.json"), "utf8")), provider) as Program<any>;
const hook = new Program(JSON.parse(fs.readFileSync(path.join(root, "target/idl/torus_hook.json"), "utf8")), provider) as Program<any>;
const client = new TorusClient(program, hook);
const accounts: any = program.account;
const hookAccounts: any = hook.account;
const pm: any = program.methods; // `any`: Program<any> type expansion is too deep (TS2589)
const pdas = client.pdas;

// Cast. On devnet the protocol config persists between runs, so the registered parties are reused.
interface Cast {
  company: Keypair; // token issuer
  auditor: Keypair; // independent verifier registered by the operator
  partner: Keypair; // registered exchange partner that buys the collected fees for USDC
  compPool: Keypair; // owner of the compensation pool (slash destination)
  treasury: Keypair; // owner of the operator's treasury
  usdcMint?: string;
}
const statePath = path.join(root, "demo", ".state", DEVNET ? "devnet.json" : "none.json");
function loadCast(): Cast {
  const kp = (s?: number[]) => (s ? Keypair.fromSecretKey(Uint8Array.from(s)) : Keypair.generate());
  const saved = DEVNET && fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, "utf8")) : {};
  return {
    company: kp(saved.company),
    auditor: kp(saved.auditor),
    partner: kp(saved.partner),
    compPool: kp(saved.compPool),
    treasury: kp(saved.treasury),
    usdcMint: saved.usdcMint,
  };
}
function saveCast(cast: Cast) {
  if (!DEVNET) return;
  fs.mkdirSync(path.dirname(statePath), { recursive: true });
  const sk = (k: Keypair) => Array.from(k.secretKey);
  fs.writeFileSync(
    statePath,
    JSON.stringify({
      company: sk(cast.company),
      auditor: sk(cast.auditor),
      partner: sk(cast.partner),
      compPool: sk(cast.compPool),
      treasury: sk(cast.treasury),
      usdcMint: cast.usdcMint,
    }),
  );
}

const cast = loadCast();
const { company, auditor, partner } = cast;
const stranger = Keypair.generate();
const alice = Keypair.generate();
const bob = Keypair.generate();
const carol = Keypair.generate();
const dave = Keypair.generate(); // a customer; also acts as a permissionless crank

let usdcMint: PublicKey;
let companyUsdc: PublicKey;
let compPoolUsdc: PublicKey;
let treasuryUsdc: PublicKey;
let partnerUsdc: PublicKey;

/** Gives `to` SOL: airdrop on a local validator, a transfer from the operator elsewhere. */
async function fund(to: PublicKey, sol: number) {
  if (!DEVNET) {
    const sig = await connection.requestAirdrop(to, sol * LAMPORTS_PER_SOL);
    const bh = await connection.getLatestBlockhash();
    await connection.confirmTransaction({ signature: sig, ...bh }, "confirmed");
    return;
  }
  const have = await connection.getBalance(to);
  const want = Math.round(sol * LAMPORTS_PER_SOL);
  if (have >= want) return;
  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(SystemProgram.transfer({ fromPubkey: operator.publicKey, toPubkey: to, lamports: want - have })),
    [operator],
  );
}

async function setupChain() {
  if (!DEVNET) {
    if (await connection.getAccountInfo(pdas.config()[0])) {
      throw new Error("Protocol config already exists on this validator. Run through demo/run.sh (fresh ledger).");
    }
    if ((await connection.getBalance(operator.publicKey)) < 50 * LAMPORTS_PER_SOL) await fund(operator.publicKey, 100);
  }
  const sol = DEVNET ? { company: 0.6, auditor: 0.05, partner: 0.05, user: 0.02 } : { company: 20, auditor: 5, partner: 5, user: 5 };
  await fund(company.publicKey, sol.company);
  await fund(auditor.publicKey, sol.auditor);
  await fund(partner.publicKey, sol.partner);
  for (const kp of [alice, bob, carol, dave, stranger]) await fund(kp.publicKey, sol.user);

  const configExists = !!(await connection.getAccountInfo(pdas.config()[0]));
  if (configExists) {
    const cfg: any = await accounts.config.fetch(pdas.config()[0]);
    usdcMint = cfg.usdcMint;
    if (!cast.usdcMint || cast.usdcMint !== usdcMint.toBase58()) {
      throw new Error("The protocol is initialized with a USDC mint this demo did not create (demo/.state missing?).");
    }
  } else {
    usdcMint = await createMint(connection, operator, operator.publicKey, null, DEC, undefined, undefined, TOKEN_PROGRAM_ID);
    cast.usdcMint = usdcMint.toBase58();
  }
  const ataOf = (owner: PublicKey) => createAssociatedTokenAccountIdempotent(connection, operator, usdcMint, owner);
  companyUsdc = await ataOf(company.publicKey);
  compPoolUsdc = await ataOf(cast.compPool.publicKey);
  treasuryUsdc = await ataOf(cast.treasury.publicKey);
  partnerUsdc = await ataOf(partner.publicKey);
  await mintTo(connection, operator, usdcMint, companyUsdc, operator, 50_000n * UNIT); // the company's own USDC
  await mintTo(connection, operator, usdcMint, partnerUsdc, operator, 50_000n * UNIT); // the partner's USDC

  if (!configExists) {
    // Only the program's upgrade authority (the operator) can initialize the protocol.
    await pm
      .initialize(usdcMint, hook.programId, compPoolUsdc, treasuryUsdc, SAMPLE, new BN(MIN_BOND.toString()))
      .accounts({
        authority: operator.publicKey,
        program: program.programId,
        programData: pdas.programData(),
        config: pdas.config()[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    await pm
      .registerAuditor()
      .accounts({
        authority: operator.publicKey,
        config: pdas.config()[0],
        auditor: auditor.publicKey,
        auditorRecord: pdas.auditorRecord(auditor.publicKey)[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    await pm
      .registerPartner()
      .accounts({
        authority: operator.publicKey,
        config: pdas.config()[0],
        partner: partner.publicKey,
        partnerRecord: pdas.partnerRecord(partner.publicKey)[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  }
  saveCast(cast);
}

// ============================================================================
// Protocol actions
// ============================================================================

async function createBrandMint(opts: { freezeAuthority?: boolean } = {}): Promise<PublicKey> {
  const mintKp = Keypair.generate();
  const poolAuthority = pdas.poolAuthority(mintKp.publicKey)[0];
  const extensions = [ExtensionType.TransferFeeConfig, ExtensionType.TransferHook];
  const mintLen = getMintLen(extensions);
  const lamports = await connection.getMinimumBalanceForRentExemption(mintLen);
  const tx = new Transaction().add(
    SystemProgram.createAccount({
      fromPubkey: company.publicKey,
      newAccountPubkey: mintKp.publicKey,
      space: mintLen,
      lamports,
      programId: TOKEN_2022_PROGRAM_ID,
    }),
    // fee-rate authority revoked; withheld fees withdrawable only by the protocol's program address
    createInitializeTransferFeeConfigInstruction(mintKp.publicKey, null, poolAuthority, FEE_BPS, MAX_FEE, TOKEN_2022_PROGRAM_ID),
    // hook authority revoked (zero key)
    createInitializeTransferHookInstruction(mintKp.publicKey, PublicKey.default, hook.programId, TOKEN_2022_PROGRAM_ID),
    createInitializeMintInstruction(mintKp.publicKey, DEC, company.publicKey, opts.freezeAuthority ? company.publicKey : null, TOKEN_2022_PROGRAM_ID),
  );
  await sendAndConfirmTransaction(connection, tx, [company, mintKp]);
  await (hook.methods as any)
    .initializeExtraAccountMetaList()
    .accounts({
      payer: operator.publicKey,
      extraAccountMetaList: pdas.extraAccountMetaList(mintKp.publicKey)[0],
      mint: mintKp.publicKey,
      volumeCounter: pdas.volumeCounter(mintKp.publicKey)[0],
      systemProgram: SystemProgram.programId,
    })
    .rpc();
  return mintKp.publicKey;
}

async function issue(mint: PublicKey): Promise<string> {
  return pm
    .issueToken(FEE_BPS, new BN(MAX_FEE.toString()))
    .accounts({
      issuer: company.publicKey,
      config: pdas.config()[0],
      mint,
      usdcMint,
      tokenState: pdas.tokenState(mint)[0],
      poolAuthority: pdas.poolAuthority(mint)[0],
      redemptionVault: pdas.redemptionVault(mint)[0],
      slashingBond: pdas.slashingBond(mint)[0],
      issuerEscrow: pdas.issuerEscrow(mint)[0],
      feeVault: pdas.feeVault(mint)[0],
      token2022Program: TOKEN_2022_PROGRAM_ID,
      usdcTokenProgram: TOKEN_PROGRAM_ID,
      systemProgram: SystemProgram.programId,
      rent: SYSVAR_RENT_PUBKEY,
    })
    .signers([company])
    .rpc();
}

async function setManifest(mint: PublicKey, auditorKey: PublicKey, periodLen = PERIOD_LEN) {
  return pm
    .setManifest(RETURN_RATE_BPS, TOLERANCE_BPS, LCL_BPS, FLOOR_BPS, new BN(periodLen), new BN(TERM_LEN), SAMPLE, 0)
    .accounts({
      issuer: company.publicKey,
      tokenState: pdas.tokenState(mint)[0],
      manifest: pdas.manifest(mint)[0],
      auditor: auditorKey,
      auditorRecord: pdas.auditorRecord(auditorKey)[0],
      config: pdas.config()[0],
      systemProgram: SystemProgram.programId,
    })
    .signers([company])
    .rpc();
}

async function setTerms(mint: PublicKey, signer: Keypair = operator) {
  return pm
    .setIssuerTerms(new BN(BOND_TARGET.toString()), new BN(MIN_PRICE.toString()))
    .accounts({ authority: signer.publicKey, config: pdas.config()[0], tokenState: pdas.tokenState(mint)[0] })
    .signers(signer === operator ? [] : [signer])
    .rpc();
}

async function deposit(mint: PublicKey, amount: bigint) {
  return pm
    .depositPool(new BN(amount.toString()))
    .accounts({
      depositor: company.publicKey,
      depositorUsdc: companyUsdc,
      tokenState: pdas.tokenState(mint)[0],
      slashingBond: pdas.slashingBond(mint)[0],
      redemptionVault: pdas.redemptionVault(mint)[0],
      usdcMint,
      usdcTokenProgram: TOKEN_PROGRAM_ID,
    })
    .signers([company])
    .rpc();
}

async function ata(mint: PublicKey, owner: PublicKey) {
  return createAssociatedTokenAccountIdempotent(connection, operator, mint, owner, undefined, TOKEN_2022_PROGRAM_ID);
}

async function mintBrand(mint: PublicKey, to: PublicKey, amount: bigint) {
  await mintToChecked(connection, operator, mint, await ata(mint, to), company, amount, DEC, [], undefined, TOKEN_2022_PROGRAM_ID);
}

/** A customer-to-customer transfer: Token-2022 withholds the fee; the hook counts the volume. */
async function trade(mint: PublicKey, from: Keypair, to: PublicKey, amount: bigint): Promise<PublicKey> {
  const src = await ata(mint, from.publicKey);
  const dst = await ata(mint, to);
  const ix = await createTransferCheckedWithTransferHookInstruction(
    connection, src, mint, dst, from.publicKey, amount, DEC, [], "confirmed", TOKEN_2022_PROGRAM_ID,
  );
  await sendAndConfirmTransaction(connection, new Transaction().add(ix), [operator, from]);
  return dst;
}

async function harvest(mint: PublicKey, withheld: PublicKey[], crank: Keypair = operator) {
  return pm
    .harvestFees()
    .accounts({
      crank: crank.publicKey,
      config: pdas.config()[0],
      tokenState: pdas.tokenState(mint)[0],
      mint,
      poolAuthority: pdas.poolAuthority(mint)[0],
      feeVault: pdas.feeVault(mint)[0],
      tokenProgram: TOKEN_2022_PROGRAM_ID,
    })
    .remainingAccounts(withheld.map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })))
    .signers(crank === operator ? [] : [crank])
    .rpc();
}

/** The registered partner buys collected fee tokens for USDC; the program splits the USDC. */
async function convert(mint: PublicKey, tokenAmount: bigint, usdcAmount: bigint): Promise<string> {
  const partnerToken = await ata(mint, partner.publicKey);
  const ix = await client.convertFees({
    partner: partner.publicKey,
    mint,
    partnerToken,
    partnerUsdc,
    usdcMint,
    treasury: treasuryUsdc,
    usdcTokenProgram: TOKEN_PROGRAM_ID,
    tokenAmount: new BN(tokenAmount.toString()),
    usdcAmount: new BN(usdcAmount.toString()),
  });
  const tx = new Transaction().add(ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), ix);
  return sendAndConfirmTransaction(connection, tx, [operator, partner]);
}

async function chainTime(): Promise<number> {
  for (let i = 0; i < 100; i++) {
    const bt = await connection.getBlockTime(await connection.getSlot("confirmed"));
    if (bt !== null) return bt;
    await sleep(200);
  }
  throw new Error("block time unavailable");
}

async function waitChainTimeAfter(ts: number, show?: string) {
  let shown = -1;
  for (let i = 0; i < 2_000; i++) {
    const bt = await connection.getBlockTime(await connection.getSlot("confirmed"));
    if (bt !== null && bt > ts) break;
    const left = bt === null ? shown : Math.max(0, ts - bt + 1);
    if (show && process.stdout.isTTY && left !== shown) {
      process.stdout.write(`\r      ${gray(`${show} in ${left}s `)}`);
      shown = left;
    }
    await sleep(250);
  }
  if (show && process.stdout.isTTY) process.stdout.write("\r" + " ".repeat(60) + "\r");
}

const tokenState = async (mint: PublicKey): Promise<any> => accounts.tokenState.fetch(pdas.tokenState(mint)[0]);
const auditOf = async (mint: PublicKey, periodId: BN): Promise<any> => accounts.auditCycle.fetch(pdas.audit(mint, periodId)[0]);
const bal = async (acct: PublicKey, programId = TOKEN_PROGRAM_ID) => (await getAccount(connection, acct, "confirmed", programId)).amount;

async function waitPeriod(mint: PublicKey) {
  const ts = await tokenState(mint);
  const len = (ts.gridPeriodLen as BN).toNumber() || PERIOD_LEN;
  await waitChainTimeAfter((ts.periodStartTs as BN).toNumber() + len - 1);
}

async function provision(mint: PublicKey): Promise<string> {
  const ts = await tokenState(mint);
  const pid: BN = ts.periodId;
  const prevAudit = pid.gtn(0) && (ts.budget as BN).gtn(0) ? pdas.audit(mint, pid)[0] : null;
  return pm
    .provisionBudget()
    .accounts({
      crank: operator.publicKey,
      config: pdas.config()[0],
      tokenState: pdas.tokenState(mint)[0],
      manifest: pdas.manifest(mint)[0],
      volumeCounter: pdas.volumeCounter(mint)[0],
      redemptionVault: pdas.redemptionVault(mint)[0],
      prevAudit,
    })
    .rpc();
}

/** Closes periods until one with trading volume gets an obligation (empty periods are skipped). */
async function provisionUntilBudget(mint: PublicKey): Promise<{ periodId: BN; budget: bigint; sig: string }> {
  for (let i = 0; i < 200; i++) {
    await waitPeriod(mint);
    const sig = await provision(mint);
    const ts = await tokenState(mint);
    if ((ts.budget as BN).gtn(0)) return { periodId: ts.periodId, budget: BigInt(ts.budget.toString()), sig };
  }
  throw new Error("no obligation was provisioned");
}

function buildLedger(values: number[], ids?: Buffer[]) {
  const merchants = values.map(() => Keypair.generate());
  const entries = values.map((v, i) => ({
    outcomeId: ids?.[i] ?? crypto.randomBytes(32),
    beneficiary: merchants[i].publicKey,
    value: u(v),
    label: MERCHANTS[i % MERCHANTS.length],
    merchant: merchants[i],
  }));
  const sorted = sortByOutcome(entries);
  return { tree: new SumTree(sorted), rows: sorted };
}

async function commit(mint: PublicKey, periodId: BN, tree: SumTree) {
  const m: any = await accounts.manifest.fetch(pdas.manifest(mint)[0]);
  return pm
    .commitPerformance(tree.commitmentArray(), new BN(tree.total.toString()), tree.populationSize)
    .accounts({
      issuer: company.publicKey,
      tokenState: pdas.tokenState(mint)[0],
      manifest: pdas.manifest(mint)[0],
      auditorRecord: pdas.auditorRecord(m.auditor)[0],
      audit: pdas.audit(mint, periodId)[0],
      systemProgram: SystemProgram.programId,
    })
    .signers([company])
    .rpc();
}

async function verifyUniqueness(mint: PublicKey, periodId: BN, tree: SumTree) {
  for (let start = 0; start < tree.populationSize; start += UNIQ_BATCH) {
    const ix = await client.verifyUniqueness({ crank: company.publicKey, mint, periodId, tree, start, end: start + UNIQ_BATCH });
    const tx = new Transaction().add(ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), ix);
    await sendAndConfirmTransaction(connection, tx, [company]);
  }
}

/** The operator supplies randomness only after the commit is on-chain (a VRF in production). */
async function designate(mint: PublicKey, periodId: BN): Promise<number[]> {
  const auditPda = pdas.audit(mint, periodId)[0];
  const committed: any = await accounts.auditCycle.fetch(auditPda);
  while ((await connection.getSlot("confirmed")) <= (committed.committedSlot as BN).toNumber()) await sleep(200);
  await pm
    .designateSample(Array.from(crypto.randomBytes(32)))
    .accounts({ crank: operator.publicKey, config: pdas.config()[0], audit: auditPda })
    .rpc();
  const a: any = await accounts.auditCycle.fetch(auditPda);
  return (a.sampleIndices as any[]).map((i) => Number(i));
}

async function disclose(mint: PublicKey, periodId: BN, tree: SumTree, index: number) {
  return pm
    .verifyDisclosure(tree.outcomeAt(index), tree.beneficiaryAt(index), new BN(tree.valueAt(index).toString()), tree.proof(index))
    .accounts({ crank: operator.publicKey, audit: pdas.audit(mint, periodId)[0] })
    .rpc();
}

async function observe(mint: PublicKey, periodId: BN, f: (asserted: bigint) => bigint) {
  const a: any = await auditOf(mint, periodId);
  const observed = (a.sampleValues as BN[]).map((v) => f(BigInt(v.toString())));
  return pm
    .recordVerification(observed.map((v) => new BN(v.toString())), Array.from(crypto.randomBytes(32)))
    .accounts({ auditor: auditor.publicKey, audit: pdas.audit(mint, periodId)[0], auditorRecord: pdas.auditorRecord(a.auditor)[0] })
    .signers([auditor])
    .rpc();
}

async function finalize(mint: PublicKey, periodId: BN) {
  return pm
    .finalizeAudit()
    .accounts({
      crank: operator.publicKey,
      config: pdas.config()[0],
      tokenState: pdas.tokenState(mint)[0],
      manifest: pdas.manifest(mint)[0],
      audit: pdas.audit(mint, periodId)[0],
      poolAuthority: pdas.poolAuthority(mint)[0],
      slashingBond: pdas.slashingBond(mint)[0],
      issuerEscrow: pdas.issuerEscrow(mint)[0],
      slashDestination: compPoolUsdc,
      usdcMint,
      tokenProgram: TOKEN_PROGRAM_ID,
    })
    .rpc();
}

async function declareDefault(mint: PublicKey, periodId: BN, crank: Keypair) {
  return pm
    .declareDefault()
    .accounts({
      crank: crank.publicKey,
      config: pdas.config()[0],
      tokenState: pdas.tokenState(mint)[0],
      audit: pdas.audit(mint, periodId)[0],
      poolAuthority: pdas.poolAuthority(mint)[0],
      slashingBond: pdas.slashingBond(mint)[0],
      issuerEscrow: pdas.issuerEscrow(mint)[0],
      slashDestination: compPoolUsdc,
      usdcMint,
      tokenProgram: TOKEN_PROGRAM_ID,
    })
    .signers(crank === operator ? [] : [crank])
    .rpc();
}

async function attest(mint: PublicKey, periodId: BN, tree: SumTree, index: number) {
  const ix = await client.attestLeaf({ auditor: auditor.publicKey, mint, periodId, tree, index, confirmed: new BN(tree.valueAt(index).toString()) });
  return sendAndConfirmTransaction(connection, new Transaction().add(ix), [operator, auditor]);
}

/** Anyone may submit a claim for a ledger entry; the money can only go to that entry's merchant. */
async function claim(mint: PublicKey, periodId: BN, tree: SumTree, index: number, toUsdc: PublicKey, crank: Keypair = dave) {
  const audit = pdas.audit(mint, periodId)[0];
  const attestation = pdas.attestation(audit, index)[0];
  return pm
    .payout(index, tree.outcomeAt(index), new BN(tree.valueAt(index).toString()), tree.proof(index))
    .accounts({
      crank: crank.publicKey,
      config: pdas.config()[0],
      tokenState: pdas.tokenState(mint)[0],
      audit,
      poolAuthority: pdas.poolAuthority(mint)[0],
      redemptionVault: pdas.redemptionVault(mint)[0],
      beneficiaryUsdc: toUsdc,
      attestation: (await connection.getAccountInfo(attestation)) ? attestation : null,
      claim: pdas.claim(audit, index)[0],
      usdcMint,
      usdcTokenProgram: TOKEN_PROGRAM_ID,
      systemProgram: SystemProgram.programId,
    })
    .signers(crank === operator ? [] : [crank])
    .rpc();
}

const RESULT: Record<number, string> = {
  1: "PASS",
  2: "FRAUD (claimed more than was delivered)",
  3: "FRAUD (under-reported / defaulted)",
  4: "HONEST SHORTFALL",
};

/** Launch a brand token with the bond and pool pre-funded by a deposit, and close one traded period. */
async function quickLaunch(symbol: string): Promise<{ mint: PublicKey; periodId: BN; budget: bigint }> {
  const mint = await createBrandMint();
  await issue(mint);
  await setManifest(mint, auditor.publicKey);
  await setTerms(mint);
  await deposit(mint, BOND_TARGET + u(1_500)); // bond first, the rest to the redemption pool
  await provision(mint); // bond is full → metering starts here
  await mintBrand(mint, alice.publicKey, u(1_000_000));
  const dst = await trade(mint, alice, bob.publicKey, u(500_000));
  await harvest(mint, [dst]);
  const p = await provisionUntilBudget(mint);
  await line(gray(`  (${symbol}: registered · bond ${usdc(BOND_TARGET)} · 500,000 ${symbol} traded · obligation ${usdc(p.budget)})`));
  return { mint, ...p };
}

async function commitAndSample(mint: PublicKey, periodId: BN, values: number[], opts: { show?: boolean; ids?: Buffer[]; skipUniqueness?: boolean } = {}) {
  const ledger = buildLedger(values, opts.ids);
  const { tree, rows } = ledger;
  if (opts.show) {
    await step(`The company's ledger of returns it delivered this period (${values.length} payments, kept off-chain):`);
    for (let i = 0; i < rows.length; i++) {
      await line(gray(`      #${i}  ${rows[i].label.padEnd(16)} ${usdc(tree.valueAt(i)).padStart(14)}   payment ${Buffer.from(tree.outcomeAt(i)).toString("hex").slice(0, 8)}…`), PACE_MS / 3);
    }
  }
  const sig = await commit(mint, periodId, tree);
  await ok(`Committed on-chain: Merkle-sum root ${tree.commitment().toString("hex").slice(0, 16)}… · total ${usdc(tree.total)}`, "(only the root goes on-chain)");
  await link(sig);
  if (opts.skipUniqueness) return { ...ledger, sample: [] as number[] };
  await verifyUniqueness(mint, periodId, tree);
  await ok(`Every payment ID is unique and registered`, "(a payment cannot be counted twice, now or in a later period)");
  const sample = await designate(mint, periodId);
  await ok(`Random sample drawn after the commit: payments ${sample.map((i) => "#" + i).join(", ")}`, "(the company could not pick them)");
  return { ...ledger, sample };
}

async function discloseAll(mint: PublicKey, periodId: BN, tree: SumTree, sample: number[]) {
  for (const i of sample) await disclose(mint, periodId, tree, i);
  await ok(`Disclosed the ${sample.length} sampled payments — each Merkle-sum proof checked on-chain`);
}

// ============================================================================
// Scenes
// ============================================================================

let hero: { mint: PublicKey; periodId?: BN } | null = null;

async function scene1() {
  await scene(1, "Rules are locked at issuance", "No one — not even the issuer — can change the fee, the hook, or reach the money later.");

  await step("A company tries to register a token it could still freeze");
  const freezable = await createBrandMint({ freezeAuthority: true });
  await blocked("a freeze key could stop the fee flow", await mustFail("freezable mint", () => issue(freezable), /FreezeAuthorityPresent/));

  await step("The company registers ACME (Token-2022, 1% transfer fee, Törus transfer hook)");
  const mint = await createBrandMint();
  const sig = await issue(mint);
  await ok("ACME registered", short(mint));
  await link(sig);
  const mi = await getMint(connection, mint, "confirmed", TOKEN_2022_PROGRAM_ID);
  const fee = getTransferFeeConfig(mi)!;
  const hk = getTransferHook(mi)!;
  const none = (k: PublicKey) => (k.equals(PublicKey.default) ? green("none (revoked)") : red(k.toBase58()));
  await info(`transfer fee ............ ${fee.newerTransferFee.transferFeeBasisPoints / 100}% of every transfer`);
  await info(`fee-rate authority ...... ${none(fee.transferFeeConfigAuthority)}`);
  await info(`hook authority .......... ${none(hk.authority)}`);
  await info(`fee withdraw authority .. ${green("program address " + short(fee.withdrawWithheldAuthority))} (no private key exists)`);

  await step("The company tries to appoint its own key as the auditor");
  await blocked(
    "the auditor must be independent and registered by the operator",
    await mustFail("self-audit", () => setManifest(mint, company.publicKey), /AccountNotInitialized|AuditorNotRegistered|AuditorNotIndependent/),
  );
  await setManifest(mint, auditor.publicKey, HERO_PERIOD_LEN);
  await ok(`Rules fixed in advance: obligation = ${RETURN_RATE_BPS / 100}% of each period's volume · ${SAMPLE} payments sampled per audit`, "independent auditor appointed");

  await step("The company tries to set its own (tiny) bond");
  await blocked("only the operator sets the bond", await mustFail("company sets terms", () => setTerms(mint, company), /Unauthorized|ConstraintHasOne/));
  await setTerms(mint);
  await ok(`Operator sets ACME's bond target: ${usdc(BOND_TARGET)}`, `minimum fee price ${usdc(MIN_PRICE)} per ACME`);
  hero = { mint };
}

async function scene2() {
  await scene(2, "Fees fill the bond first", "Every trade pays 1% that the issuer cannot touch. Redemptions start only once the bond is full.");
  if (!hero) {
    hero = { mint: await createBrandMint() };
    await issue(hero.mint);
    await setManifest(hero.mint, auditor.publicKey, HERO_PERIOD_LEN);
    await setTerms(hero.mint);
  }
  const mint = hero.mint;

  await mintBrand(mint, alice.publicKey, u(2_000_000));
  await step("Customers trade ACME");
  const withheld: PublicKey[] = [];
  for (const [from, to, amt, label] of [
    [alice, bob, 600_000, "alice → bob  "],
    [alice, carol, 400_000, "alice → carol"],
  ] as Array<[Keypair, Keypair, number, string]>) {
    withheld.push(await trade(mint, from, to.publicKey, u(amt)));
    await ok(`${label}  ${tok(u(amt), "ACME").padStart(14)}`, `fee ${tok(u(amt / 100), "ACME")} withheld by Token-2022 · volume counted by the hook`);
  }

  await step("The company tries to withdraw the collected fees itself");
  const companyAcme = await ata(mint, company.publicKey);
  await blocked(
    "only the protocol's program address can collect fees",
    await mustFail(
      "company withdraws fees",
      () =>
        sendAndConfirmTransaction(
          connection,
          new Transaction().add(createWithdrawWithheldTokensFromAccountsInstruction(mint, companyAcme, company.publicKey, [], withheld, TOKEN_2022_PROGRAM_ID)),
          [operator, company],
        ),
      /OwnerMismatch|ProgramError/,
    ),
  );
  await step("Anyone can collect them into the program-owned fee vault (here: customer dave)");
  await harvest(mint, withheld, dave);
  const vaultTokens = await bal(pdas.feeVault(mint)[0], TOKEN_2022_PROGRAM_ID);
  await ok(`Fee vault holds ${tok(vaultTokens, "ACME")}`);

  await step("Try to start redemptions before the bond is full");
  await blocked("no promises are accepted until the bond is full", await mustFail("early start", () => provision(mint), /BondTargetNotReached/));

  await step(`A registered exchange partner buys the ${tok(vaultTokens, "ACME")} of fees for ${usdc(vaultTokens)}`);
  const treasuryBefore = await bal(treasuryUsdc);
  let sig = await convert(mint, vaultTokens, vaultTokens);
  await link(sig);
  await ok(`Operator's share (80% at the base tier) → treasury: ${usdc((await bal(treasuryUsdc)) - treasuryBefore)}`, "never counted as bond");
  await ok(`Company's share → slashing bond first: ${usdc(await bal(pdas.slashingBond(mint)[0]))} of ${usdc(BOND_TARGET)}`);
  await alert("Bond full → redemptions start now; volume before this point creates no obligation");
  await provision(mint);

  await step("A new period: customers keep trading");
  const w2: PublicKey[] = [];
  w2.push(await trade(mint, bob, dave.publicKey, u(300_000)));
  w2.push(await trade(mint, carol, alice.publicKey, u(200_000)));
  await ok("bob → dave 300,000 ACME · carol → alice 200,000 ACME");
  await harvest(mint, w2, dave);
  const t2 = await bal(pdas.feeVault(mint)[0], TOKEN_2022_PROGRAM_ID);
  await convert(mint, t2, t2);
  await ok(`Partner buys ${tok(t2, "ACME")} of fees → company's share fills the redemption pool: ${usdc(await bal(pdas.redemptionVault(mint)[0]))}`);

  await step("The period ends on a fixed boundary → the obligation is computed on-chain");
  const p = await provisionUntilBudget(mint);
  await link(p.sig);
  const ts = await tokenState(mint);
  await alert(`Obligation for the period: ${tok(ts.priorPeriodActivity, "ACME")} traded × ${RETURN_RATE_BPS / 100}% = ${usdc(p.budget)}`);
  await info("the program derives it from the trading volume — the company does not report it");
  hero.periodId = p.periodId;
}

async function scene3() {
  await scene(3, "Keep the promise → the money moves", "Commit, check uniqueness, random sample, proofs, independent observation — then pay the merchants.");
  let mint: PublicKey;
  let periodId: BN;
  if (hero?.periodId) {
    mint = hero.mint;
    periodId = hero.periodId;
  } else {
    const q = await quickLaunch("ACME");
    mint = q.mint;
    periodId = q.periodId;
  }

  const { tree, rows, sample } = await commitAndSample(mint, periodId, LEDGER, { show: true });
  await discloseAll(mint, periodId, tree, sample);
  await step("The auditor checks each sampled payment against the payment processor's records");
  await observe(mint, periodId, (a) => a);
  await ok("All sampled payments confirmed · 0 defects", "the program, not the auditor, counts the defects");

  await step("Anyone finalizes the audit");
  const sig = await finalize(mint, periodId);
  const a = await auditOf(mint, periodId);
  await alert(`Result: ${green(RESULT[a.result])}`);
  await link(sig);

  const s0 = sample[0];
  const merchantUsdc = await createAssociatedTokenAccountIdempotent(connection, operator, usdcMint, tree.beneficiaryAt(s0));
  await step(`Someone tries to redirect payment #${s0} (${rows[s0].label}) to their own wallet`);
  const strangerUsdc = await createAssociatedTokenAccountIdempotent(connection, operator, usdcMint, stranger.publicKey);
  await blocked(
    "the money can only go to the merchant committed in the ledger",
    await mustFail("redirect", () => claim(mint, periodId, tree, s0, strangerUsdc), /ClaimProofInvalid/),
  );
  await step(`Claim payment #${s0} for ${rows[s0].label}`);
  await claim(mint, periodId, tree, s0, merchantUsdc);
  await ok(`${rows[s0].label} received ${usdc(await bal(merchantUsdc))}`, "anyone can submit the claim; only the merchant gets paid");
  await blocked("each payment is paid once", await mustFail("double claim", () => claim(mint, periodId, tree, s0, merchantUsdc), /AlreadyClaimed/));

  const u0 = [...Array(tree.populationSize).keys()].find((i) => !sample.includes(i));
  if (u0 !== undefined) {
    const uUsdc = await createAssociatedTokenAccountIdempotent(connection, operator, usdcMint, tree.beneficiaryAt(u0));
    await step(`Claim payment #${u0}, which was not in the sample`);
    await blocked("not paid until the auditor confirms it", await mustFail("unconfirmed", () => claim(mint, periodId, tree, u0, uUsdc), /LeafNotConfirmed/));
    await attest(mint, periodId, tree, u0);
    await claim(mint, periodId, tree, u0, uUsdc);
    await ok(`Auditor confirmed #${u0} → ${rows[u0].label} received ${usdc(await bal(uUsdc))}`);
  }
}

async function scene4() {
  await scene(4, "Lie → lose the bond", "A company claims returns it never delivered. The sample catches it; the bond is slashed automatically.");
  const { mint, periodId } = await quickLaunch("BRAVO");

  await step(`BRAVO claims it delivered ${usdc(u(1_000))} — but the payments were fabricated`);
  const { tree, sample } = await commitAndSample(mint, periodId, LEDGER);
  await discloseAll(mint, periodId, tree, sample);
  await step("The auditor checks the sampled payments with the payment processor");
  await observe(mint, periodId, (a) => a / 10n);
  await ok("Only 10% of each sampled payment actually arrived", `${sample.length}/${sample.length} defective`);

  const bondBefore = await bal(pdas.slashingBond(mint)[0]);
  const poolBefore = await bal(compPoolUsdc);
  await step("Anyone finalizes the audit");
  const sig = await finalize(mint, periodId);
  const a = await auditOf(mint, periodId);
  const ts = await tokenState(mint);
  await alert(`Result: ${red(RESULT[a.result])}`);
  await ok(`Bond slashed: ${usdc(bondBefore)} → compensation pool (${usdc(poolBefore)} → ${usdc(await bal(compPoolUsdc))})`);
  await ok(`Tier reset to ${ts.tier} · token frozen: ${ts.frozen}`);
  await link(sig);

  await step("A customer tries to trade BRAVO");
  await blocked("trading halts", await mustFail("trade frozen token", () => trade(mint, bob, carol.publicKey, u(1_000)), /TokenFrozen/));
}

async function scene5() {
  await scene(5, "No escape hatches", "Counting a payment twice, skipping ahead, or going silent all fail — silence is treated as fraud.");
  const { mint, periodId } = await quickLaunch("CHARLIE");

  await step("CHARLIE pads its ledger by listing the same payment twice");
  const dup = crypto.randomBytes(32);
  const ids = LEDGER.map(() => crypto.randomBytes(32));
  ids[3] = dup;
  ids[5] = dup;
  const { tree } = await commitAndSample(mint, periodId, LEDGER, { ids, skipUniqueness: true });
  await blocked("the uniqueness check rejects the duplicate", await mustFail("duplicate", () => verifyUniqueness(mint, periodId, tree), /LeafOrderInvalid/));

  await step("CHARLIE tries to move on to the next period");
  await waitPeriod(mint);
  await blocked("no new period until this audit is settled", await mustFail("skip period", () => provision(mint), /PreviousAuditNotFinalized/));

  await step("A customer tries to call the deadline early");
  const ts0 = await tokenState(mint);
  const deadline = (ts0.auditDeadline as BN).toNumber();
  if ((await chainTime()) <= deadline) {
    await blocked("the deadline has not passed", await mustFail("early default", () => declareDefault(mint, periodId, dave), /DefaultNotDue/));
  }
  await step("CHARLIE goes silent…");
  await waitChainTimeAfter(deadline, "audit deadline");
  await ok("Audit deadline passed");

  const bondBefore = await bal(pdas.slashingBond(mint)[0]);
  await step("Any customer can now enforce it (dave declares the default)");
  const sig = await declareDefault(mint, periodId, dave);
  const a = await auditOf(mint, periodId);
  await alert(`Result: ${red(RESULT[a.result])}`);
  await ok(`Bond slashed: ${usdc(bondBefore)} → compensation pool · token frozen: ${(await tokenState(mint)).frozen}`);
  await link(sig);
}

async function scene6() {
  await scene(6, "Honest shortfalls are not slashed", "Falling slightly short and saying so costs progress, not the bond — only lies get slashed.");
  const { mint, periodId, budget } = await quickLaunch("DELTA");

  const total = LEDGER_HONEST.reduce((x, y) => x + y, 0);
  await step(`DELTA honestly reports ${usdc(u(total))} delivered against a ${usdc(budget)} obligation`);
  const { tree, sample } = await commitAndSample(mint, periodId, LEDGER_HONEST);
  await discloseAll(mint, periodId, tree, sample);
  await step("The auditor checks the sampled payments");
  await observe(mint, periodId, (a) => a);
  await ok("All sampled payments confirmed · 0 defects");

  const bondBefore = await bal(pdas.slashingBond(mint)[0]);
  await step("Anyone finalizes the audit");
  await finalize(mint, periodId);
  const a = await auditOf(mint, periodId);
  const ts = await tokenState(mint);
  await alert(`Result: ${yellow(RESULT[a.result])}`);
  await ok(`Bond untouched: ${usdc(await bal(pdas.slashingBond(mint)[0]))} (was ${usdc(bondBefore)}) · token frozen: ${ts.frozen}`);
  await ok(`Progress toward a better tier resets (consecutive passes: ${ts.consecutivePasses})`);
  await info(`A shortfall within the ${LCL_BPS / 100}% band is honest; claiming more than was delivered is what gets slashed.`);
}

async function finale(ran: number[]) {
  if (STEP) await waitEnter("\n  [Enter] summary ");
  await nextSegment(7);
  const bar = "━".repeat(76);
  console.log("\n" + cyan(bar));
  console.log(bold("  SUMMARY — every outcome above was decided by the program, not by a person"));
  console.log(cyan(bar));
  const rows: Array<[number, string, string]> = [
    [1, "Changing the fee/hook, picking the auditor or bond", green("no key can — checked at issuance")],
    [2, "Fees and the obligation", green("collected, bond-first, computed on-chain")],
    [3, "Promise kept (sampled, observed)", green("PASS → merchants paid, only them, once")],
    [4, "Inflated claim", red("FRAUD → bond slashed, trading frozen")],
    [5, "Double-counting / skipping / silence", red("rejected, or slashed after the deadline")],
    [6, "Honest shortfall (within the band)", yellow("no slash → loses tier progress")],
  ];
  for (const [n, what, outcome] of rows) if (ran.includes(n)) await line(`  ${what.padEnd(50)} ${outcome}`, PACE_MS / 2);
  console.log("");
  console.log(gray(`  torus_protocol ${program.programId.toBase58()}  ·  torus_hook ${hook.programId.toBase58()}`));
  console.log(gray(`  ${DEVNET ? "Solana devnet" : "local Solana validator"} ${RPC}`));
  console.log("");
}

// ============================================================================

async function main() {
  const scenes: Array<[number, () => Promise<void>]> = [
    [1, scene1], [2, scene2], [3, scene3], [4, scene4], [5, scene5], [6, scene6],
  ];
  const run = ONLY && ONLY.length ? ONLY : scenes.map(([n]) => n);

  if (!HOLD) {
    console.log("");
    console.log(bold("  TÖRUS") + gray("  ·  verifiable return promises for brand tokens on Solana"));
  }
  process.stdout.write(gray("  Setting up accounts… "));
  await setupChain();
  console.log(gray("done"));
  if (HOLD) {
    await waitEnter("  ready — press Enter to start ");
    console.clear();
    console.log("");
    console.log(bold("  TÖRUS") + gray("  ·  verifiable return promises for brand tokens on Solana"));
  }
  console.log(gray("  A company issues a token and promises to return part of its trading activity to real people."));
  console.log(gray("  Törus makes that promise checkable — and makes lying cost more than it gains."));
  showStart = Date.now();
  segmentStart = showStart;
  timings[0] = 0;

  for (const [n, fn] of scenes) if (run.includes(n)) await fn();
  await finale(run);
  if (MIN_MS && MIN_MS[7] !== undefined) await sleep(Math.max(0, segmentStart + MIN_MS[7] - Date.now()));
  if (TIMING_OUT) fs.writeFileSync(TIMING_OUT, JSON.stringify({ starts: timings, end: Date.now() - showStart }));
}

main().then(
  () => process.exit(0),
  (e) => {
    console.error("\n" + red("Demo stopped: ") + (e?.message ?? e));
    if (e?.logs) console.error(gray(e.logs.join("\n")));
    process.exit(1);
  },
);
