/** Deadline warnings of the tax reconciliation (pure, no validator needed). */

import { assert } from "chai";
import { CycleDeadlines, DAY, dueNotices } from "../app/src/notices";

const T = 1_800_000_000;

function cycle(over: Partial<CycleDeadlines> = {}): CycleDeadlines {
  return {
    mint: "M",
    periodId: 7,
    reportDeadline: T,
    reportFiled: false,
    holdUntil: 0,
    refiled: false,
    finalized: false,
    ...over,
  };
}

const kinds = (c: CycleDeadlines, now: number, sent = new Set<string>()) => dueNotices(c, now, sent).map((n) => n.kind);

describe("tax reconciliation deadline warnings", () => {
  it("warns the accountant the day before the report deadline, with a copy to the company", () => {
    const [n] = dueNotices(cycle(), T - DAY, new Set());
    assert.equal(n.kind, "report");
    assert.equal(n.deadline, T);
    assert.equal(n.to, "tax_accountant");
    assert.equal(n.cc, "issuer");
    assert.equal(n.key, "M:7:report");
  });

  it("is quiet before the last day and after the deadline", () => {
    assert.deepEqual(kinds(cycle(), T - DAY - 1), []);
    assert.deepEqual(kinds(cycle(), T + 1), []);
  });

  it("still warns late on the last day (a missed run is caught up)", () => {
    assert.deepEqual(kinds(cycle(), T - 60), ["report"]);
    assert.deepEqual(kinds(cycle(), T), ["report"]);
  });

  it("sends nothing once the report is filed", () => {
    assert.deepEqual(kinds(cycle({ reportFiled: true }), T - DAY), []);
  });

  it("sends each warning once", () => {
    assert.deepEqual(kinds(cycle(), T - DAY, new Set(["M:7:report"])), []);
  });

  it("warns the day before the hold ends until a reconciled report is filed", () => {
    const held = cycle({ reportFiled: true, holdUntil: T + 7 * DAY });
    assert.deepEqual(kinds(held, T + 6 * DAY), ["reconciled_report"]);
    assert.deepEqual(kinds(held, T + 5 * DAY), []);
    assert.deepEqual(kinds({ ...held, refiled: true }, T + 6 * DAY), []);
  });

  it("sends nothing for a finalized cycle", () => {
    assert.deepEqual(kinds(cycle({ finalized: true }), T - DAY), []);
  });

  it("keeps cycles apart", () => {
    const sent = new Set(["M:6:report"]);
    assert.deepEqual(kinds(cycle(), T - DAY, sent), ["report"]);
  });
});
