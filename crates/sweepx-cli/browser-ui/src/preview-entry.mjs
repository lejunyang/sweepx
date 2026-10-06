import { createApp } from "./review.mjs";
// All identifiers, sizes and rows here are fictional. No real extension API is
// exposed to this HTTP page, and the removal adapter never mutates browser data.
const GiB = 1024 ** 3,
  MiB = 1024 ** 2;
const specs = [
  ["workspace.example.test", 11.7 * GiB, 8],
  ["notes.example.test", 1.6 * GiB, 1],
  ["files.example.test", 849.6 * MiB, 2],
  ["studio.example.test", 837.7 * MiB, 2],
  ["reader.example.test", 768.6 * MiB, 2],
  ["board.example.test", 390.8 * MiB, 2],
  ["console.example.test", 205.9 * MiB, 2],
  ["design.example.test", 122.8 * MiB, 3],
  ["archive.example.test", null, 1],
];
const domains = specs.map(([domain, n, storageItemCount]) => ({
  domain,
  bytes: n === null ? null : String(Math.floor(n)),
  sizeComplete: n !== null,
  storageItemCount,
}));
const origins = [
  [
    "service_worker_cache_storage",
    3.7 * GiB,
    "https://workspace.example.test/",
  ],
  ["indexed_db", 79.1 * MiB, "https://workspace.example.test"],
  ...[
    [2.5, "company.example.test"],
    [1.6, "studio.example.test"],
    [1.4, "news.example.test"],
    [1, "video.example.test"],
    [682.4 / 1024, "reader.example.test"],
    [662.3 / 1024, null],
  ].map(([n, top]) => [
    "web_storage",
    n * GiB,
    `https://workspace.example.test/${top ? `^0https://${top}` : "^31"}`,
  ]),
].map(([subsystem, n, storageKey], i) => ({
  domain: "workspace.example.test",
  bytes: String(Math.floor(n)),
  complete: true,
  subsystem,
  storageKey,
  bucketId: i > 1 ? i * 21 : null,
  bucketName: "_default",
}));
for (const row of domains.slice(1))
  origins.push({
    domain: row.domain,
    bytes: row.bytes,
    complete: row.sizeComplete,
    subsystem: "indexed_db",
    storageKey: `https://${row.domain}`,
  });
const categories = [
  {
    subsystem: "http_cache_shared",
    subsystemBytes: "1200000000",
    unattributedBytes: "1200000000",
    sizeComplete: true,
    issues: [],
  },
  {
    subsystem: "code_cache_shared",
    subsystemBytes: "312000000",
    unattributedBytes: "312000000",
    sizeComplete: true,
    issues: [],
  },
  {
    subsystem: "indexed_db",
    subsystemBytes: "2170000000",
    unattributedBytes: "0",
    sizeComplete: true,
    issues: [],
  },
];
const runtime = {
  getManifest: () => ({ version: "0.3.1" }),
  connectNative() {
    let listener, disconnect;
    let closed = false;
    return {
      onMessage: {
        addListener(fn) {
          listener = fn;
        },
      },
      onDisconnect: {
        addListener(fn) {
          disconnect = fn;
        },
      },
      disconnect() {
        closed = true;
        disconnect();
      },
      postMessage(m) {
        const reply = (value) => {
          if (!closed) listener({ id: m.id, ...value });
        };
        setTimeout(() => {
          if (m.op === "hello")
            reply({ kind: "hello", protocol: 1, hostVersion: "demo" });
          if (m.op === "pending")
            reply({ kind: "pending", state: "none", request: null });
          if (m.op === "scan") {
            reply({
              kind: "start",
              report: {
                status: "partial",
                issues: ["demo: one storage size could not be observed"],
              },
            });
            for (const [collection, rows] of Object.entries({
              domains,
              categories,
              origins,
            }))
              reply({ kind: "rows", collection, rows });
            reply({ kind: "done" });
          }
          if (m.op === "plan")
            reply({
              kind: "plan",
              plan: {
                schema: "sweepx.browser_cleanup.plan/v1",
                operation: "browser_managed_origin_removal",
                browser: m.browser,
                profile: m.profile,
                domain: m.domain,
                origins: [`https://${m.domain}`],
              },
            });
          if (m.op === "complete") reply({ kind: "recorded" });
        }, 300);
      },
    };
  },
};
createApp({
  document,
  window,
  chrome: {
    runtime,
    browsingData: {
      remove: () => new Promise((resolve) => setTimeout(resolve, 1000)),
    },
  },
  preview: true,
});
