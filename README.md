# Törus

**Verifiable return promises for brand tokens on Solana.**

A company issues a token and promises to give part of its trading activity back to real people (discounts, fee waivers, cash back delivered through merchants). Today nobody can check whether that promise is kept. Törus turns the promise into rules a Solana program enforces:

- the obligation is **computed on-chain from trading volume**, not reported by the company;
- the money to pay it is **collected from every transfer into accounts the company cannot touch**;
- the company's claim that it delivered is **committed, checked for double counting, sampled at random and checked against an independent record**;
- a false claim, a refusal to disclose, or silence **slashes the company's bond automatically**, while an honest shortfall is never slashed: the missing amount is carried into the next obligation.

> **Status:** hackathon prototype, unaudited. Patent pending (Japan, filed October 2026). See [Limitations](#limitations).

---

## How it works

```
 every transfer ──► Token-2022 withholds the 1% fee ──► fee vault (program-owned)
                    Törus transfer hook counts volume        │
                                                             ▼
                    registered exchange partner buys the fees for USDC (at or above a floor price)
                                                             │
              operator share ◄───────────────────────────────┤
                                                             ▼ company share
                                  1. slashing bond, up to the target set by the operator
                                  2. redemption pool, up to the obligation now accruing
                                  3. company escrow (released only after a clean audit)

 bond full ──► metering starts; periods are fixed (t0 + kΔ); each closed period's
               obligation = volume × return rate (fixed before the period)

 audit cycle ─► commit Merkle-sum root of the ledger ─► verify uniqueness of every entry
             ─► random sample after the commit ─► on-chain disclosure proofs
             ─► independent auditor records each sampled payment
             ─► finalize in one instruction: shortfall check (gap carried), defect count,
                tier update, slash or release
             ─► merchants claim their own entries (only the committed recipient, once,
                up to the amount the auditor confirmed)
```

### 1. Issuance locks the rules
`issue_token` accepts a Token-2022 mint only if it has a transfer fee and the Törus transfer hook, the authorities to change the fee and the hook are revoked, there is no freeze authority or other disallowed extension (e.g. a permanent delegate), the fee schedule cannot change later, and the withheld fees can only be withdrawn by a program-derived address. The operator, not the company, registers auditors and exchange partners and sets each company's bond target and minimum conversion price.

### 2. Fees fund the bond first
`harvest_fees` (anyone) moves withheld fees into the program-owned fee vault. `convert_fees` lets a registered partner buy them for USDC in one atomic swap. The USDC is split: the operator's share goes to the operator treasury and is never counted as bond; the company's share fills the **slashing bond first**, then the **redemption pool** up to the obligation now accruing, and the rest goes to a **company escrow** the company can claim only after the audit for that period finalizes cleanly. Until the bond reaches its target, no period is metered and no obligation exists.

### 3. The obligation is computed, not reported
Periods start at the first close after the bond is full and run on a fixed grid. The transfer hook records the cumulative volume at the first transfer after each boundary, so a late close still assigns volume to the right period. `provision_budget` derives the obligation (`volume × return_rate`) and reserves it in the redemption pool; the previous period's audit must be final before the next period can close.

### 4. The audit
| Step | Instruction | What it enforces |
|---|---|---|
| Commit | `commit_performance` | The company commits a Merkle-sum tree root over its ledger (each leaf: index, payment ID, recipient, amount). Judging parameters and the auditor are snapshotted. |
| Uniqueness | `verify_uniqueness` | All leaves in order: payment IDs strictly increasing, root and total match the commitment, every ID registered once per token. The same payment cannot appear twice in a ledger or be reused in a later period. |
| Sample | `designate_sample` | Indices drawn from randomness fixed after the commit slot. |
| Disclose | `verify_disclosure` | A proof per sampled leaf, bound to (index, population size), so no hidden leaves can inflate the total. |
| Observe | `record_verification` | The registered auditor records the observed amount for each sampled payment; the program counts defects and sums. |
| Finalize | `finalize_audit` | One atomic step: shortfall check, overstatement check (residual and defect count), tier update, then either release (company escrow becomes claimable) or slash (bond and escrow to the compensation pool, token frozen). A shortfall is not slashed: the gap is carried into the next period's obligation, and a shortfall beyond the band (10% in the demo) also costs one tier. |
| Pay | `payout`, `attest_leaf` | Anyone can submit a claim, but funds go only to the recipient committed in the leaf, once, up to the confirmed amount: the observed value for sampled leaves, or the auditor's per-leaf confirmation for the others. |

`declare_default` lets anyone settle a cycle whose disclosure or uniqueness check was not completed by the deadline: it is treated like fraud. A late auditor can be replaced by the operator (`replace_auditor`); a revoked auditor (`revoke_auditor`) can no longer record, confirm, or be named for a new cycle.

### 5. Exit and liquidation
`request_exit` / `finalize_exit`: a voluntary exit settles the obligation up to the period of the request; after that audit, half the bond goes back to the company and half to the operator. A token frozen for a violation loses its bond. After a freeze or exit, `start_liquidation` / `claim_liquidation` distribute what is left in the redemption pool (beyond amounts already owed) pro rata over the confirmed entries of the last clean audit.

---

## Repository layout

```
programs/torus-protocol   issuance checks, fee conversion, metering, audit cycle, payouts, exit, liquidation
programs/torus-hook       Token-2022 transfer hook: blocks transfers of frozen tokens, counts volume,
                          records cumulative volume at period boundaries
app/src/sdk.ts            TypeScript client: PDAs, Merkle-sum tree, instruction builders
tests/torus.ts            30 end-to-end scenarios on a local validator
demo/                     narrated end-to-end demo (local validator or devnet)
```

## Build, test, demo

Requirements: Rust, Solana CLI (Agave) 4.2.x, Anchor 0.31.2, Node 18+.

```bash
npm install
anchor build
anchor test          # 30 scenarios on a local validator (about 12 minutes)
demo/run.sh          # narrated demo on a fresh local validator (--step, --fast, --links, --only 3,4)
```

`anchor test` deploys the programs as upgradeable because `initialize` may only be called by the upgrade authority (`[test] upgradeable = true` in `Anchor.toml`). If you use your own program keys, run `anchor keys sync` and update `TORUS_PROTOCOL_ID` in `programs/torus-hook/src/lib.rs` by hand.

## Invariants (what to review)

1. **Atomic close.** Completeness check, sample comparison, tier update and slash/release happen in `finalize_audit`, before any payout for the cycle is possible.
2. **USDC, not the brand token**, backs the bond and the redemption pool.
3. **Post-commit randomness.** The sample is fixed after the commitment.
4. **Separation of roles.** The company cannot be its own auditor, set its own bond, or redirect payouts; slashing happens only through audit finalization or default.
5. **No issuer key on the money path.** Fee withdrawal, conversion, pool and bond are controlled by program-derived addresses.
6. **Payout title.** A payout is a claim on a committed leaf: recipient and maximum amount are fixed by the commitment; each leaf is paid at most once.
7. **Uniqueness.** A cycle cannot finalize until every payment ID has been checked and registered.
8. **Fixed periods.** Periods are counted on a fixed grid; delaying a close cannot change their length or which volume they contain.
9. **Bond first.** The operator's share is never counted as bond; the company's share fills the bond before anything else, and nothing is metered until the bond is full.
10. **Continuity.** A period cannot close until the previous audit is final; missing disclosures or uniqueness proofs become a default after the deadline.
11. **Obligations do not disappear.** An honest shortfall is not slashed, but the gap is added to the next period's obligation (and must be funded before that period can close).

## Limitations

- **Randomness:** the sample is drawn from entropy the operator supplies after the commit. Production needs a VRF (e.g. Switchboard, ORAO) so that no one can choose it.
- **Observation:** the auditor's observed amounts are entered by the auditor. Connecting payment processors' signed records is the next step.
- **Not implemented yet:** a provisional/dispute window before finality, statistical lower bounds per recipient (payouts currently require per-leaf confirmation), auditor bonds, and binding payment IDs to the issuer with external signatures (today the used-ID registry is per token).
- **Legal:** program-owned accounts keep the funds away from the company's keys. Whether that makes them bankruptcy-remote is a legal question that depends on jurisdiction and contracts.
- **Unaudited code.** Do not use with real funds.

## License

Copyright 2026 kogatec. Licensed under the [Apache License, Version 2.0](LICENSE).

This repository is the open core of Törus: the on-chain programs, the SDK, the tests and the demo. Off-chain components (issuer risk scoring, sampling design, auditor selection, related-party detection) are proprietary and not included.

Patent pending (Japan). The patent license in Section 3 of the Apache License applies to this code; no other patent rights are granted.
