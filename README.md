# Törus

**Verifiable return promises for brand tokens on Solana.**

A company issues a token and promises to give part of its trading activity back to real people (discounts, fee waivers, cash back delivered through merchants). Today nobody can check whether that promise is kept. Törus turns the promise into rules a Solana program enforces:

- the obligation is **computed on-chain from trading volume**, not reported by the company;
- the money to pay it is **collected from every transfer into accounts the company cannot touch**;
- the company's claim that it delivered is **committed, checked for double counting, sampled at random and checked against an independent record**;
- a false claim, a refusal to disclose, or silence **slashes the company's bond automatically**, while an honest shortfall is never slashed: the missing amount is carried into the next obligation;
- the company's own share waits in an escrow that pays out **only on requests approved by two parties the company does not control**;
- the company's tax accountant reports the **book total** behind each claim: a claim above the books **holds the payouts** until a reconciled report comes, and no report forfeits the bond.

> **Status:** hackathon prototype, unaudited. Patent pending (Japan, filed October and November 2026). See [Limitations](#limitations).

---

## How it works

```
 every transfer ──► Token-2022 withholds the 1% fee ──► fee vault (program-owned)
                    Törus transfer hook counts volume        │
                                                             ▼
                    registered exchange partner buys the fees for USDC (at or above a floor price)
                                                             │
 operator share ◄────────────────────────────────────────────┤
 (split with the company's local partner)                    ▼ company share
                                  1. slashing bond, up to the target set by the operator
                                  2. redemption pool, up to the obligation now accruing
                                  3. company escrow (pays out only on approved requests)

 bond full ──► metering starts; periods are fixed (t0 + kΔ); each closed period's
               obligation = volume × return rate (the terms in force when the period started)

 audit cycle ─► commit Merkle-sum root of the ledger ─► verify uniqueness of every entry
             ─► random sample after the commit ─► on-chain disclosure proofs
             ─► independent auditor records each sampled payment
             ─► finalize in one instruction: shortfall check (gap carried), defect count,
                tier update, slash or release
             ─► merchants claim their own entries (only the committed recipient, once,
                up to the amount the auditor confirmed)

 perks ──────► each period's perk budget = the previous obligation × the company's allocation;
               trader and hold perks are recorded by a merchant and the holder, and go into
               the company's ledger and through the same audit
```

### 1. Issuance locks the rules
`issue_token` accepts a Token-2022 mint only if it has a transfer fee and the Törus transfer hook, the authorities to change the fee and the hook are revoked, there is no freeze authority or other disallowed extension (e.g. a permanent delegate), the fee schedule cannot change later, and the withheld fees can only be withdrawn by a program-derived address. The mint authority moves to the program: afterwards only `restamp` can mint, and never more than it burns. The operator, not the company, registers auditors and exchange partners and sets each company's terms (`set_issuer_terms`): the bond target, the minimum conversion price, the company's share of the fees per rank, and its local partner.

### 2. Fees fund the bond first
`harvest_fees` (anyone) moves withheld fees into the program-owned fee vault. `convert_fees` lets a registered partner buy them for USDC in one atomic swap. The USDC is split: the operator's share goes to the operator treasury (minus the share of the company's local partner) and is never counted as bond; the company's share fills the **slashing bond first**, then the **redemption pool** up to the obligation now accruing, and the rest goes to a **company escrow**. Until the bond reaches its target, no period is metered and no obligation exists.

The escrow is released period by period, only after clean audits, and even then the company cannot take it. It asks with `request_withdrawal` (an item of its use plan, the amount, a payee other than itself and an invoice hash that can be used once), and the payment runs only when both its escrow partner (`set_escrow_partner`) and the auditor approve it (`approve_withdrawal`). A request may also be paid from the bond, which must keep at least half of its target; later fees refill it first.

### 3. The obligation is computed, not reported
Periods start at the first close after the bond is full and run on a fixed grid. The transfer hook records the cumulative volume at the first transfer after each boundary, so a late close still assigns volume to the right period. `provision_budget` derives the obligation (`volume × return_rate`) and reserves it in the redemption pool; the previous period's audit must be final before the next period can close.

`set_manifest` fixes the judging rules for a term (a campaign). Every period keeps the terms in force when it started, nothing may change in the company's favor during a campaign, and a period that starts between campaigns has no obligation until new rules are fixed.

### 4. The audit
| Step | Instruction | What it enforces |
|---|---|---|
| Commit | `commit_performance` | The company commits a Merkle-sum tree root over its ledger (each leaf: index, payment ID, recipient, amount). Judging parameters and the auditor are snapshotted. |
| Uniqueness | `verify_uniqueness` | All leaves in order: payment IDs strictly increasing, root and total match the commitment, every ID registered once per token. The same payment cannot appear twice in a ledger or be reused in a later period. |
| Sample | `designate_sample` | Indices drawn from randomness fixed after the commit slot. |
| Disclose | `verify_disclosure` | A proof per sampled leaf, bound to (index, population size), so no hidden leaves can inflate the total. |
| Observe | `record_verification` | The registered auditor records the observed amount for each sampled payment; the program counts defects and sums. |
| Books | `file_tax_report` | The company's tax accountant (registered with `register_tax_accountant`, signed by the accountant) reports the book total for the period. At finalization a declared total above the books plus the tolerance holds the cycle: payouts wait until a reconciled report, which may cap the recognized total at the books (the rest is carried, the cycle cannot pass); no report by the deadline or within the hold forfeits the bond. Overstatement found by the sample never waits. |
| Finalize | `finalize_audit` | One atomic step: shortfall check, overstatement check (residual and defect count), tier update, then either release (the escrow balance of the period becomes requestable) or slash (bond and escrow to the compensation pool, token frozen). A shortfall is not slashed: the gap is carried into the next period's obligation, and a shortfall beyond the band (10% in the demo) also costs one tier. Overstatement is final at once, even before the uniqueness proof. |
| Pay | `payout`, `attest_leaf` | Anyone can submit a claim, but funds go only to the recipient committed in the leaf, once, up to the confirmed amount: the observed value for sampled leaves, or the auditor's per-leaf confirmation for the others. |

`declare_default` lets anyone settle a cycle whose disclosure or uniqueness check was not completed by the deadline: it is treated like fraud. A late auditor can be replaced by the operator (`replace_auditor`); a revoked auditor (`revoke_auditor`) can no longer record, confirm, or be named for a new cycle.

### 5. Exit and liquidation
`request_exit` / `finalize_exit`: a voluntary exit settles the obligation up to the period of the request. After that audit, the company's half of the bond and whatever is left in its escrow go to the redemption pool, that is, to its customers through liquidation; the other half of the bond goes to the operator treasury. Company shares of fees that arrive after the exit go to the redemption pool too. A token frozen for a violation loses its bond. After a freeze or exit, `start_liquidation` / `claim_liquidation` distribute what is left in the redemption pool (beyond amounts already owed) pro rata over the confirmed entries of the last clean audit.

### 6. Perks
The operator sets each company's perk terms (`set_perk_terms`): how the perk budget is split between general returns, the trader perk and the hold perk (general ≥ trader ≥ hold), the hold perk's rates by step, and a cap per token. `open_perk_period` (anyone) opens the current period's budget from the previous period's obligation, so perks never add to what the company owes; they are a way of delivering it.

- **Registered holders.** `register_holder` registers one of a holder's token accounts. The transfer hook keeps a record for it: a stamp (the balance-weighted time the tokens were received), the lowest balance in the period, and the volume sent. A new registration starts at 0%, so registering old tokens gains nothing.
- **Trader perk.** Up to the volume an account sent last period × the period's trader rate. The rate is the trader budget ÷ the volume of all registered accounts, capped at half the transfer fee, so trading with oneself to collect it always loses money.
- **Hold perk.** Purchases up to the period's lowest balance × the cap per token get the rate of the stamp's age; the rate never rises over time and is 0% after the last step.
- **Recording.** `redeem_perk` is signed by a merchant the company registered (`register_merchant`) and by the holder. Each receipt is recorded once and goes into the company's ledger, through the audit and payout above.
- **Restamp.** `restamp` burns and re-mints the same amount (minus the local partner's fee) and gives it today's stamp, signed by the holder and the local partner.

### 7. Perk market
A trader who does not use its perk can offer it to customers. `list_perk` sets part of the trader perk aside in the seller's lot for the period, signed by the seller and the local partner; it draws on the same allowance as the seller's own use. A customer's use is settled through the same ledger, audit and payout: the pool pays the face value once, split between the merchant (the discount) and the seller (the price of the perk). `close_perk_lot` returns the lot's rent after its period is closed.

What can be listed is capped lower than the trader perk: at the part of the fee that comes back to neither the company (at its top rank) nor its local partner, plus the return rate. So someone tied to the company cannot profit by trading with itself to sell the perk, at any price below the face value. Each company fixes a cap on the price and on the share of a bill a perk may pay (at most 90% and 50%), or turns listing off.

---

## Repository layout

```
programs/torus-protocol   issuance checks, fee conversion, metering, audit cycle, payouts, escrow requests,
                          exit, liquidation, local partners, perks and the perk market
programs/torus-hook       Token-2022 transfer hook: blocks transfers of frozen tokens, counts volume,
                          records cumulative volume at period boundaries, keeps registered holders' records
app/src/sdk.ts            TypeScript client: PDAs, Merkle-sum tree, instruction builders
tests/torus.ts            55 end-to-end scenarios on a local validator
demo/                     narrated end-to-end demo (local validator or devnet)
```

## Build, test, demo

Requirements: Rust, Solana CLI (Agave) 4.2.x, Anchor 0.31.2, Node 18+.

```bash
npm install
anchor build
cargo test -p torus-protocol --lib   # unit tests of the fixed rules
anchor test          # 55 scenarios on a local validator (about 30 minutes)
demo/run.sh          # narrated demo on a fresh local validator (--step, --fast, --links, --only 3,4)
```

`anchor test` deploys the programs as upgradeable because `initialize` may only be called by the upgrade authority (`[test] upgradeable = true` in `Anchor.toml`). Some scenarios use periods of a few seconds, so run the tests on an otherwise idle machine. If you use your own program keys, run `anchor keys sync` and update `TORUS_PROTOCOL_ID` in `programs/torus-hook/src/lib.rs` by hand.

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
12. **Terms fixed in advance.** A period is judged by the terms in force when it started, and nothing may change in the company's favor during a campaign.
13. **Two approvals for the escrow.** Escrow payments need both the escrow partner and the auditor; neither the operator nor the company can approve.
14. **No new supply.** After issuance only `restamp` mints, never more than it burns.
15. **Perks stay inside the obligation.** Perk budgets come from the previous obligation; the trader perk is at most half the fee, and what can be listed never pays for trading with oneself.

## Limitations

- **Randomness:** the sample is drawn from entropy the operator supplies after the commit. Production needs a VRF (e.g. Switchboard, ORAO) so that no one can choose it.
- **Observation:** the auditor's observed amounts are entered by the auditor. Connecting payment processors' signed records is the next step.
- **Perks:** the merchant app and the customer's checkout are off-chain and not part of this repository.
- **Not implemented yet:** a provisional/dispute window before finality, statistical lower bounds per recipient (payouts currently require per-leaf confirmation), auditor bonds, and binding payment IDs to the issuer with external signatures (today the used-ID registry is per token).
- **Legal:** program-owned accounts keep the funds away from the company's keys. Whether that makes them bankruptcy-remote is a legal question that depends on jurisdiction and contracts.
- **Unaudited code.** Do not use with real funds.

## License

Copyright © 2026 Keiichirou Koga (kogatec). All rights reserved. Patent pending (Japan).

This code is published for review only. You may view it, and run it locally or on devnet, to evaluate this hackathon submission. Any other use, including copying, modifying, redistributing, deploying to mainnet or building a product that works the same way, requires written permission. No patent license is granted, expressly or by implication. See [LICENSE](LICENSE).
