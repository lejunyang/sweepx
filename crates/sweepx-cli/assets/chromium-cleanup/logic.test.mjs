import { test } from "node:test";
import assert from "node:assert/strict";
import { validatePlan, removalRequest, removeWithBrowser } from "./logic.mjs";
const plan = {
  schema: "sweepx.browser_cleanup.plan/v1",
  operation: "browser_managed_origin_removal",
  browser: "edge",
  profile: "Default",
  domain: "example.com",
  origins: ["https://example.com", "https://example.com:8443"],
};
test("exact origins preserve ports and require explicit scope and profile confirmation", () => {
  const selected = validatePlan(plan);
  assert.deepEqual(selected.origins, plan.origins);
  for (const args of [
    ["cache", false],
    ["", true],
    ["storage", false],
  ])
    assert.throws(() => removalRequest(selected, ...args));
  const r = removalRequest(selected, "storage", true);
  assert.deepEqual(r.options, {
    since: 0,
    origins: plan.origins,
    originTypes: {
      unprotectedWeb: true,
      protectedWeb: false,
      extension: false,
    },
  });
  assert.deepEqual(r.types, {
    cache: true,
    cacheStorage: true,
    indexedDB: true,
    localStorage: true,
    serviceWorkers: true,
    fileSystems: true,
  });
  assert.deepEqual(removalRequest(selected, "cache", true).types, {
    cache: true,
    cacheStorage: true,
  });
});
test("foreign domains paths schemes credentials and empty wildcard selections are rejected", () => {
  for (const origins of [
    [],
    ["https://sub.example.com"],
    ["https://example.com/"],
    ["file:///example.com"],
    ["https://user:pass@example.com"],
    ["https://example.com/path"],
  ])
    assert.throws(() => validatePlan({ ...plan, origins }));
  assert.throws(() => validatePlan({ ...plan, profile: "../../wrong" }));
});
test("real API completion is awaited and failures cannot become success", async () => {
  let finish,
    calls = 0,
    completed = false;
  const req = removalRequest(validatePlan(plan), "cache", true);
  const pending = removeWithBrowser(
    {
      remove: (options, types) => {
        calls++;
        assert.deepEqual(options, req.options);
        assert.deepEqual(types, req.types);
        return new Promise((resolve) => (finish = resolve));
      },
    },
    req,
  ).then(() => (completed = true));
  await Promise.resolve();
  assert.equal(completed, false);
  finish();
  await pending;
  assert.equal(calls, 1);
  assert.equal(completed, true);
  await assert.rejects(
    removeWithBrowser(
      {
        remove: async () => {
          throw new Error("denied");
        },
      },
      req,
    ),
    /denied/,
  );
  await assert.rejects(removeWithBrowser(null, req), /unavailable/);
});
test("manual site selection is explicit, independent of native profile, and keeps exact ports", async () => {
  const { manualSelection } = await import("./logic.mjs");
  const bare = manualSelection("Example.com");
  assert.deepEqual(bare.origins, ["https://example.com", "http://example.com"]);
  assert.equal(bare.profile, undefined);
  const origin = manualSelection("https://example.com:8443/");
  assert.deepEqual(origin.origins, ["https://example.com:8443"]);
  assert.deepEqual(
    removalRequest(origin, "cache", true).options.origins,
    origin.origins,
  );
  for (const value of [
    "*.example.com",
    "https://example.com/path",
    "https://user:pass@example.com",
    "https://example.com?x=1",
    "https://example.com#part",
    "example.com:8443",
    "file:///tmp/a",
    "a..example.com",
  ])
    assert.throws(() => manualSelection(value));
  assert.throws(() =>
    removalRequest(
      { ...origin, origins: ["https://evil.test"] },
      "cache",
      true,
    ),
  );
});
