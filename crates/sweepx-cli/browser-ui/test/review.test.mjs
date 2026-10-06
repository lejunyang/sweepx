import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { setImmediate as tick } from "node:timers/promises";
import { JSDOM } from "jsdom";
import { createApp } from "../../assets/chromium-cleanup/review.mjs";
const nativePlan = {
  schema: "sweepx.browser_cleanup.plan/v1",
  operation: "browser_managed_origin_removal",
  browser: "edge",
  profile: "Default",
  domain: "example.test",
  origins: ["https://example.test:8443"],
};
const pending = () => ({
  schema: "sweepx.browser_bridge.request/v1",
  requestId: "fixture-request",
  expiresAt: Math.floor(Date.now() / 1000) + 900,
  plan: nativePlan,
});
async function page(
  run,
  {
    queued = null,
    pendingError = null,
    pendingState = "none",
    completionError = null,
    remove = async () => {},
    holdScan = false,
  } = {},
) {
  const dom = new JSDOM(
      readFileSync(
        new URL("../../assets/chromium-cleanup/review.html", import.meta.url),
        "utf8",
      ),
      { url: "https://extension.test/" },
    ),
    { document } = dom.window;
  dom.window.localStorage.setItem(
    "sweepx-ui",
    JSON.stringify({ lang: "en", browser: "edge", profile: "Default" }),
  );
  const el = (id) => document.getElementById(id),
    sent = [],
    disconnectEvents = [],
    removals = [];
  let interval,
    nativeCalls = 0;
  const runtime = {
    getManifest: () => ({ version: "0.3.0" }),
    connectNative() {
      nativeCalls++;
      let receive, disconnected;
      return {
        onMessage: {
          addListener(fn) {
            receive = fn;
          },
        },
        onDisconnect: {
          addListener(fn) {
            disconnected = fn;
            disconnectEvents.push(fn);
          },
        },
        disconnect() {
          disconnected();
        },
        postMessage(message) {
          sent.push(message);
          const reply = (value) =>
            queueMicrotask(() => receive({ id: message.id, ...value }));
          if (message.op === "hello")
            reply({ kind: "hello", protocol: 1, hostVersion: "fixture" });
          else if (message.op === "pending")
            reply(
              pendingError
                ? { kind: "error", error: pendingError }
                : { kind: "pending", request: queued, state: pendingState },
            );
          else if (message.op === "plan")
            reply({ kind: "plan", plan: nativePlan });
          else if (message.op === "complete") {
            reply(
              completionError
                ? { kind: "error", error: completionError }
                : { kind: "recorded" },
            );
            if (!completionError) queued = null;
          } else if (message.op === "scan") {
            reply({ kind: "start", report: { status: "ok", issues: [] } });
            reply({
              kind: "rows",
              collection: "domains",
              rows: [
                {
                  domain: "example.test",
                  bytes: "7",
                  sizeComplete: true,
                  storageItemCount: 1,
                },
                {
                  domain: "unknown.test",
                  bytes: null,
                  sizeComplete: false,
                  storageItemCount: 1,
                },
              ],
            });
            reply({
              kind: "rows",
              collection: "origins",
              rows: [
                {
                  domain: "example.test",
                  storageKey: "https://example.test:8443/^0https://top.test",
                  bytes: "7",
                  complete: true,
                  subsystem: "indexed_db",
                  bucketId: 9,
                  bucketName: "_default",
                },
              ],
            });
            reply({
              kind: "rows",
              collection: "categories",
              rows: [
                {
                  subsystem: "indexed_db",
                  subsystemBytes: "7",
                  unattributedBytes: null,
                  sizeComplete: false,
                },
              ],
            });
            if (!holdScan) reply({ kind: "done" });
          } else throw new Error(`Unexpected op: ${message.op}`);
        },
      };
    },
  };
  const app = createApp({
    document,
    window: dom.window,
    chrome: {
      runtime,
      browsingData: {
        async remove(...args) {
          removals.push(args);
          return remove(...args);
        },
      },
    },
    setInterval(fn) {
      interval = fn;
      return 1;
    },
    clearInterval() {},
  });
  const act = async (id, event = "click") => {
    if (event === "click") el(id).click();
    else
      el(id).dispatchEvent(
        new dom.window.Event(event, { bubbles: true, cancelable: true }),
      );
    await tick();
    await tick();
  };
  const selectDomain = async () => {
    await act("scan");
    el("domains").querySelector("button").click();
    await tick();
  };
  const confirm = async () => {
    document.querySelector('[name="mode"][value="cache"]').checked = true;
    el("profile").checked = true;
    el("confirm").value = "example.test";
    await act("confirm", "input");
  };
  try {
    await run({
      el,
      document,
      app,
      act,
      selectDomain,
      confirm,
      sent,
      removals,
      disconnectEvents,
      interval: () => interval(),
      nativeCalls: () => nativeCalls,
      setQueued: (v) => {
        queued = v;
      },
      setPendingError: (v) => {
        pendingError = v;
      },
    });
  } finally {
    app.destroy();
    dom.window.close();
  }
}
test("connect polls immediately; reconnect reopens the same request; late old disconnect is ignored", async () => {
  await page(
    async ({ el, act, disconnectEvents, sent, removals }) => {
      await act("connect");
      assert.match(el("review-source").textContent, /PENDING SWEEPX/);
      assert.equal(el("remove").disabled, true);
      await act("dialog-close");
      await act("connect");
      disconnectEvents[0]();
      assert.match(el("connection").textContent, /connected/);
      assert.match(el("review-source").textContent, /PENDING SWEEPX/);
      assert.equal(sent.filter((r) => r.op === "pending").length, 2);
      assert.equal(removals.length, 0);
    },
    { queued: pending() },
  );
});
test("manual poll replaces a reviewed plan and resets confirmations; automatic checks preserve review", async () => {
  await page(
    async ({
      el,
      act,
      selectDomain,
      confirm,
      interval,
      sent,
      setQueued,
      removals,
    }) => {
      await selectDomain();
      await act("prepare");
      await confirm();
      assert.equal(el("remove").disabled, false);
      setQueued(pending());
      const before = sent.length;
      interval();
      await tick();
      assert.equal(sent.length, before);
      await act("poll");
      assert.match(el("review-source").textContent, /PENDING SWEEPX/);
      assert.equal(el("profile").checked, false);
      assert.equal(el("confirm").value, "");
      assert.equal(el("remove").disabled, true);
      assert.equal(removals.length, 0);
    },
  );
});
test("empty/mismatched checks preserve review; errors and expiry are visible", async () => {
  await page(
    async ({ el, act, selectDomain, setQueued, setPendingError, removals }) => {
      await selectDomain();
      await act("prepare");
      const previous = el("preview").textContent;
      await act("poll");
      assert.equal(el("preview").textContent, previous);
      assert.match(
        el("request-status").textContent,
        /edge \/ Default.*No active/,
      );
      setQueued({
        ...pending(),
        plan: { ...nativePlan, profile: "Profile 1" },
      });
      await act("poll");
      assert.equal(el("preview").textContent, previous);
      assert.equal(el("reject").hidden, true);
      setPendingError("fixture_permission_denied");
      await act("poll");
      assert.match(
        el("request-status").textContent,
        /Could not check requests: fixture_permission_denied/,
      );
      assert.match(el("connection").textContent, /connected/);
      assert.equal(removals.length, 0);
    },
  );
  await page(
    async ({ el, act }) => {
      await act("connect");
      assert.match(el("request-status").textContent, /Request expired/);
      assert.equal(el("review-dialog").open, false);
    },
    { pendingState: "expired" },
  );
});
test("queued rejection is acknowledged and never invokes removal", async () => {
  await page(
    async ({ el, act, sent, removals }) => {
      await act("connect");
      await act("reject");
      assert.equal(sent.at(-1).status, "rejected");
      assert.equal(sent.at(-1).mode, null);
      assert.match(el("status").textContent, /rejected/);
      assert.equal(removals.length, 0);
    },
    { queued: pending() },
  );
});
test("expiry is rechecked at the irreversible action boundary, even after the button was enabled", async () => {
  const queued = pending();
  await page(
    async ({ el, act, confirm, document, removals }) => {
      await act("connect");
      await confirm();
      assert.equal(el("remove").disabled, false);
      const original = Date.now;
      try {
        Date.now = () => queued.expiresAt * 1000;
        el("remove").dispatchEvent(new document.defaultView.Event("click"));
        await tick();
        assert.equal(removals.length, 0);
        assert.match(el("status").textContent, /Request expired/);
        assert.equal(el("remove").disabled, true);
      } finally {
        Date.now = original;
      }
    },
    { queued },
  );
});
test("standalone cleanup needs no native connection, preserves the port and awaits the actual API", async () => {
  let finish;
  await page(
    async ({ el, act, confirm, document, nativeCalls, removals }) => {
      el("direct-site").value = "https://example.test:8443";
      await act("direct-form", "submit");
      assert.match(el("review-target").textContent, /size unknown/);
      assert.equal(el("remove").disabled, true);
      await confirm();
      await act("remove");
      assert.equal(nativeCalls(), 0);
      assert.equal(removals.length, 1);
      assert.deepEqual(removals[0][0].origins, ["https://example.test:8443"]);
      assert.deepEqual(removals[0][1], { cache: true, cacheStorage: true });
      assert.match(el("operation-status").textContent, /Keep this page open/);
      assert.equal(el("dialog-close").disabled, true);
      assert.doesNotMatch(el("status").textContent, /completed/);
      finish();
      await tick();
      await tick();
      assert.match(
        el("status").textContent,
        /Browser clearing request completed/,
      );
      assert.equal(el("review-dialog").open, false);
    },
    {
      remove: () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    },
  );
});
test("failed browser cleanup cannot be reported as success", async () => {
  await page(
    async ({ el, act, confirm }) => {
      el("direct-site").value = "example.test";
      await act("direct-form", "submit");
      await confirm();
      await act("remove");
      assert.match(
        el("status").textContent,
        /Completion not confirmed: denied/,
      );
      assert.doesNotMatch(el("status").textContent, /request completed/);
    },
    {
      remove: async () => {
        throw new Error("denied");
      },
    },
  );
});
test("browser completion and failed acknowledgement are reported separately", async () => {
  await page(
    async ({ el, act, confirm, removals }) => {
      await act("connect");
      await confirm();
      await act("remove");
      assert.equal(removals.length, 1);
      assert.match(
        el("status").textContent,
        /Browser clearing request completed/,
      );
      assert.match(
        el("status").textContent,
        /Report failed: expired_acknowledgement/,
      );
      assert.equal(el("review-dialog").open, false);
    },
    { queued: pending(), completionError: "expired_acknowledgement" },
  );
});
test("partial scan is never published and cancellation rejects unfinished data", async () => {
  await page(
    async ({ el, act }) => {
      await act("scan");
      assert.equal(el("stat-count").textContent, "—");
      assert.equal(el("scan-state").hidden, false);
      await act("cancel");
      assert.equal(el("stat-count").textContent, "—");
      assert.equal(el("scan-state").hidden, true);
      assert.equal(el("domains").children.length, 0);
    },
    { holdScan: true },
  );
});
test("unknown sizes, partitions, search, language switch and profile invalidation remain distinct", async () => {
  await page(async ({ el, act, selectDomain }) => {
    await selectDomain();
    assert.equal(el("stat-size").textContent, "≥ 7 B");
    assert.equal(el("stat-shared").textContent, "Unknown");
    assert.match(el("details").textContent, /embedded in top.test/);
    assert.match(el("details").textContent, /bucket 9/);
    el("domain-filter").value = "unknown";
    await act("domain-filter", "input");
    assert.equal(el("domains").children.length, 1);
    assert.match(el("domains").textContent, /Unknown/);
    el("language").value = "zh";
    await act("language", "change");
    assert.match(el("domains").textContent, /未知/);
    assert.doesNotMatch(el("sites-view").textContent, /Select a website/);
    el("native-profile").value = "Profile 1";
    await act("native-profile", "change");
    assert.equal(el("stat-count").textContent, "—");
    assert.equal(el("domains").children.length, 0);
  });
});
