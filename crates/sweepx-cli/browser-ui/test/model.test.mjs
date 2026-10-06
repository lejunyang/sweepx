import { test } from "node:test";
import assert from "node:assert/strict";
import { total, sortedDomains, partition } from "../src/model.mjs";
test("aggregation preserves unknown, lower bounds and integers beyond Number precision", () => {
  assert.deepEqual(
    total([{ bytes: null, complete: false }], "bytes", "complete"),
    { value: null, complete: false },
  );
  assert.deepEqual(
    total(
      [
        { bytes: "9007199254740993", complete: true },
        { bytes: "7", complete: true },
      ],
      "bytes",
      "complete",
    ),
    { value: "9007199254741000", complete: true },
  );
  assert.deepEqual(
    total(
      [
        { bytes: "7", complete: true },
        { bytes: null, complete: false },
      ],
      "bytes",
      "complete",
    ),
    { value: "7", complete: false },
  );
});
test("sorting handles unknown separately from zero and never mutates scan rows", () => {
  const rows = [
    { domain: "z.test", bytes: null },
    { domain: "a.test", bytes: "0" },
    { domain: "b.test", bytes: "9007199254740993" },
  ];
  assert.deepEqual(
    sortedDomains(rows, "", "size").map((r) => r.domain),
    ["b.test", "a.test", "z.test"],
  );
  assert.equal(rows[0].domain, "z.test");
  assert.deepEqual(
    sortedDomains(rows, "A.TEST", "name").map((r) => r.domain),
    ["a.test"],
  );
});
test("partition labels preserve unfamiliar keys instead of guessing ownership", () => {
  assert.deepEqual(
    partition({ storageKey: "https://example.test/^0https://top.test" }),
    { kind: "embedded", site: "top.test" },
  );
  assert.deepEqual(partition({ storageKey: "https://example.test/^31" }), {
    kind: "cross-site",
  });
  assert.deepEqual(
    partition({ storageKey: "https://example.test/^99opaque" }),
    { kind: "unknown" },
  );
});
