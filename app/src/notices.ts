/**
 * Deadline warnings of the tax reconciliation (off-chain).
 *
 * Each cycle has up to two deadlines: the first report (the audit deadline) and, when the cycle is on hold, the
 * reconciled report (the end of the hold). The day before each, the tax accountant gets a warning, with a copy to the
 * company. Sending the mail is the caller's job; this decides which warnings are due, each once.
 */

export const DAY = 86_400;

/** What the chain says about a cycle (TokenState.audit_deadline, TaxReport, AuditCycle.tax_hold_until / stage). */
export interface CycleDeadlines {
  mint: string;
  periodId: number;
  /** Deadline of the first report (Unix seconds). */
  reportDeadline: number;
  reportFiled: boolean;
  /** End of the hold, 0 = no hold. */
  holdUntil: number;
  /** A reconciled report was filed during the hold. */
  refiled: boolean;
  finalized: boolean;
}

export type NoticeKind = "report" | "reconciled_report";

export interface Notice {
  /** Identifies the warning, so it is sent once. */
  key: string;
  kind: NoticeKind;
  mint: string;
  periodId: number;
  deadline: number;
  to: "tax_accountant";
  cc: "issuer";
}

/** Warnings due at `now` (from a day before a deadline until it passes) and not sent yet (`sent` holds their keys). */
export function dueNotices(cycle: CycleDeadlines, now: number, sent: ReadonlySet<string>): Notice[] {
  if (cycle.finalized) return [];
  const deadlines: { kind: NoticeKind; deadline: number; done: boolean }[] = [
    { kind: "report", deadline: cycle.reportDeadline, done: cycle.reportFiled },
    { kind: "reconciled_report", deadline: cycle.holdUntil, done: cycle.holdUntil === 0 || cycle.refiled },
  ];
  return deadlines
    .filter((d) => !d.done && now >= d.deadline - DAY && now <= d.deadline)
    .map((d) => ({
      key: `${cycle.mint}:${cycle.periodId}:${d.kind}`,
      kind: d.kind,
      mint: cycle.mint,
      periodId: cycle.periodId,
      deadline: d.deadline,
      to: "tax_accountant" as const,
      cc: "issuer" as const,
    }))
    .filter((n) => !sent.has(n.key));
}
