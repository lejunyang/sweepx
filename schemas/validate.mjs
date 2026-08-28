import { readFileSync, readdirSync, statSync } from "node:fs";
import { Buffer } from "node:buffer";
import path from "node:path";
import process from "node:process";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaDir = path.resolve(path.dirname(new URL(import.meta.url).pathname));
const repoRoot = path.resolve(schemaDir, "..");

function listJsonFiles(dir) {
  const entries = readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listJsonFiles(fullPath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith(".json")) {
      files.push(fullPath);
    }
  }
  return files.sort();
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function readNdjson(filePath) {
  return readFileSync(filePath, "utf8")
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        throw new Error(`${path.relative(repoRoot, filePath)}:${index + 1}: ${error.message}`);
      }
    });
}

const ajv = new Ajv2020({
  allErrors: true,
  strict: false
});
addFormats(ajv);

const schemaFiles = listJsonFiles(schemaDir).filter((file) => file.endsWith(".schema.json"));
for (const file of schemaFiles) {
  ajv.addSchema(readJson(file));
}

const validations = [
  {
    schemaId: "https://sweepx.dev/schemas/sweepx.output/v1",
    file: path.join(schemaDir, "examples", "sweepx.output.scan.result.example.json")
  },
  {
    schemaId: "https://sweepx.dev/schemas/sweepx.output/v1",
    file: path.join(schemaDir, "examples", "sweepx.output.status.result.example.json")
  },
  {
    schemaId: "https://sweepx.dev/schemas/sweepx.output/v1",
    file: path.join(schemaDir, "examples", "sweepx.output.cache-status.result.example.json")
  },
  {
    schemaId: "https://sweepx.dev/schemas/sweepx.output/v1",
    file: path.join(schemaDir, "examples", "sweepx.output.cargo-detect.result.example.json")
  },
  {
    schemaId: "https://sweepx.dev/schemas/sweepx.output/v1",
    file: path.join(schemaDir, "examples", "sweepx.output.cancel.result.example.json")
  },
  {
    schemaId: "https://sweepx.dev/schemas/sweepx.output/v1",
    file: path.join(schemaDir, "examples", "sweepx.output.plan.result.example.json")
  },
  {
    schemaId: "https://sweepx.dev/schemas/sweepx.event/v1",
    file: path.join(schemaDir, "examples", "sweepx.event.operation.started.example.json")
  },
  {
    schemaId: "https://sweepx.dev/schemas/capability-record/v1",
    file: path.join(schemaDir, "examples", "capability-record.example.json")
  },
  {
    schemaId: "https://sweepx.dev/schemas/fixture-manifest/v1",
    file: path.join(repoRoot, "fixtures", "contracts", "minimal.fixture-manifest.json")
  },
  {
    schemaId: "https://sweepx.dev/schemas/receipt/v1",
    file: path.join(repoRoot, "fixtures", "contracts", "minimal.expected-receipt.json")
  },
  {
    schemaId: "https://sweepx.dev/schemas/policy/state-transitions/v1",
    file: path.join(repoRoot, "policy", "state-transitions.json")
  }
];

const results = [];
let failed = false;

for (const { schemaId, file } of validations) {
  const validate = ajv.getSchema(schemaId);
  if (!validate) {
    throw new Error(`Missing compiled schema: ${schemaId}`);
  }
  const data = readJson(file);
  const ok = validate(data);
  if (!ok) {
    failed = true;
  }
  results.push({
    schemaId,
    file: path.relative(repoRoot, file),
    ok,
    errors: validate.errors ?? []
  });
}

const capabilityValidator = ajv.getSchema(
  "https://sweepx.dev/schemas/capability-record/v1"
);
if (!capabilityValidator) {
  throw new Error("Missing compiled capability-record schema");
}

const digest =
  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const validQualifiedCapability = {
  schema: "sweepx.capability-record/v1",
  recordedAt: "2026-08-27T06:00:00Z",
  qualificationKey: {
    scope: "platform",
    coreVersion: "0.9.0-beta.1",
    scannerSemanticsVersion: 2,
    safetyPolicyDigest: digest,
    adapterId: "linux-gio-trash",
    adapterDigest: digest,
    osFamily: "linux",
    osBuild: "6.12.10-arch1-1",
    arch: "x86_64",
    filesystem: "ext4",
    filesystemVersion: "1.0-feature-set",
    volumeClass: "local",
    providerOrDesktopBackend: "gio-2.84.1",
    runtimePrivilegeProfile: "ordinary_user",
    capability: "trash.local.file"
  },
  state: "qualified",
  reasonCode: "TEST_ONLY_SCHEMA_FIXTURE",
  evidence: {
    bundleDigest: digest,
    evidenceClass: "real_os_qualification",
    reviewedBy: ["schema-test"],
    limitations: ["synthetic schema fixture only"],
    invalidatesOn: ["adapter-digest-change"],
    validity: {
      status: "current",
      validFrom: "2026-08-27T00:00:00Z",
      expiresAt: "2026-08-28T00:00:00Z"
    }
  }
};

const clone = (value) => JSON.parse(JSON.stringify(value));

const eventValidator = ajv.getSchema(
  "https://sweepx.dev/schemas/sweepx.event/v1"
);
if (!eventValidator) {
  throw new Error("Missing compiled sweepx.event schema");
}

const durableEventGolden = readNdjson(
  path.join(schemaDir, "examples", "sweepx.event.durable-stream.golden.ndjson")
);
const eventStartedExample = readJson(
  path.join(schemaDir, "examples", "sweepx.event.operation.started.example.json")
);

const eventSchemaCases = [
  {
    name: "legacy in-memory operation.started envelope remains valid",
    source: eventStartedExample,
    expected: true,
    mutate() {}
  },
  {
    name: "durable operation.terminal golden is structurally valid",
    source: durableEventGolden[2],
    expected: true,
    mutate() {}
  },
  {
    name: "non-terminal type cannot set terminal=true",
    source: durableEventGolden[1],
    expected: false,
    mutate(event) {
      event.terminal = true;
    }
  },
  {
    name: "operation.terminal must set terminal=true",
    source: durableEventGolden[2],
    expected: false,
    mutate(event) {
      event.terminal = false;
    }
  },
  {
    name: "durable operation.terminal requires snapshotDigest",
    source: durableEventGolden[2],
    expected: false,
    mutate(event) {
      delete event.payload.snapshotDigest;
    }
  },
  {
    name: "durable operation.terminal rejects unknown payload fields",
    source: durableEventGolden[2],
    expected: false,
    mutate(event) {
      event.payload.resumable = false;
    }
  },
  {
    name: "durable operation.terminal requires a lowercase SHA-256 digest",
    source: durableEventGolden[2],
    expected: false,
    mutate(event) {
      event.payload.snapshotDigest = `sha256:${"A".repeat(64)}`;
    }
  },
  {
    name: "non-durable legacy terminal payload remains envelope-compatible",
    source: durableEventGolden[2],
    expected: true,
    mutate(event) {
      event.cursor = "stream-golden-001:3";
      event.checkpoint = { durable: false, lastDurableSequence: "1" };
      event.payload = {
        status: "ok",
        exitCode: 0,
        kind: "scan.result",
        resumable: false
      };
    }
  },
  {
    name: "event sequence must be non-zero",
    source: durableEventGolden[0],
    expected: false,
    mutate(event) {
      event.sequence = "0";
    }
  },
  {
    name: "event IDs are bounded",
    source: durableEventGolden[0],
    expected: false,
    mutate(event) {
      event.streamId = "s".repeat(129);
    }
  },
  {
    name: "event IDs reject whitespace and path syntax",
    source: durableEventGolden[0],
    expected: false,
    mutate(event) {
      event.operationId = "op invalid/path";
    }
  },
  {
    name: "event cursor is bounded",
    source: durableEventGolden[0],
    expected: false,
    mutate(event) {
      event.cursor = "c".repeat(1025);
    }
  },
  {
    name: "event emittedAt must use UTC",
    source: durableEventGolden[0],
    expected: false,
    mutate(event) {
      event.emittedAt = "2026-08-28T09:00:00+08:00";
    }
  },
  {
    name: "event envelope rejects unknown fields",
    source: durableEventGolden[0],
    expected: false,
    mutate(event) {
      event.unbounded = true;
    }
  },
  {
    name: "event checkpoint rejects unknown fields",
    source: durableEventGolden[0],
    expected: false,
    mutate(event) {
      event.checkpoint.digest = "not-part-of-v1";
    }
  }
];

for (const testCase of eventSchemaCases) {
  const event = clone(testCase.source);
  testCase.mutate(event);
  const ok = eventValidator(event);
  if (ok !== testCase.expected) {
    failed = true;
    console.log(`FAIL event schema case: ${testCase.name}`);
    for (const error of eventValidator.errors ?? []) {
      console.log(`  ${error.instancePath || "/"} ${error.message}`);
    }
  } else {
    console.log(`PASS event schema case: ${testCase.name}`);
  }
}

const U128_MAX = (1n << 128n) - 1n;
const MAX_EVENT_PAYLOAD_BYTES = 256 * 1024;
const EXIT_SEVERITY = new Map([
  [0, 0],
  [4, 10],
  [3, 20],
  [8, 30],
  [13, 40],
  [12, 50],
  [6, 60],
  [5, 70],
  [7, 80],
  [10, 90],
  [9, 95],
  [11, 99],
  [2, 100]
]);
const STATUS_EXIT = new Map([
  ["ok", 0],
  ["partial", 4],
  ["blocked", 5],
  ["authorization_required", 6],
  ["stale", 7],
  ["failed", 8],
  ["needs_reconciliation", 9],
  ["cancelled", 10],
  ["unsupported", 3]
]);

function invariant(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function decimalU128(value, field, allowZero = true) {
  invariant(typeof value === "string" && /^(0|[1-9][0-9]*)$/u.test(value),
    `${field} must be a canonical decimal string`);
  const parsed = BigInt(value);
  invariant(parsed <= U128_MAX, `${field} exceeds u128`);
  invariant(allowZero || parsed !== 0n, `${field} must be non-zero`);
  return parsed;
}

function utcTimestampNs(value, field) {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/u.exec(value);
  invariant(match !== null, `${field} must be an RFC 3339 UTC timestamp`);
  const milliseconds = Date.parse(`${match[1]}Z`);
  invariant(!Number.isNaN(milliseconds), `${field} must be a valid timestamp`);
  const fractionalNs = BigInt((match[2] ?? "").padEnd(9, "0") || "0");
  return BigInt(milliseconds) * 1_000_000n + fractionalNs;
}

function validateDurableEventStream(events, expectedTerminal) {
  invariant(Array.isArray(events) && events.length > 0, "durable event stream is empty");

  for (const [index, event] of events.entries()) {
    invariant(eventValidator(event),
      `event ${index + 1} fails the event schema: ${ajv.errorsText(eventValidator.errors)}`);
    invariant(Buffer.byteLength(JSON.stringify(event.payload), "utf8") <= MAX_EVENT_PAYLOAD_BYTES,
      `event ${index + 1} payload exceeds ${MAX_EVENT_PAYLOAD_BYTES} bytes`);
    invariant(/^sxcur1\.[A-Za-z0-9_-]{16,1017}$/u.test(event.cursor),
      `event ${index + 1} cursor is not an opaque sxcur1 cursor`);
  }

  invariant(events[0].type === "operation.started",
    "durable event stream must start with operation.started");
  invariant(events[0].checkpoint.durable === true,
    "operation.started must be durable");
  invariant(events.filter((event) => event.type === "operation.started").length === 1,
    "operation.started must be unique");

  const terminalEvents = events.filter((event) => event.type === "operation.terminal");
  invariant(terminalEvents.length === 1,
    "durable event stream must contain exactly one operation.terminal");
  invariant(events.at(-1).type === "operation.terminal",
    "operation.terminal must be last");
  invariant(events.at(-1).checkpoint.durable === true,
    "operation.terminal must be durable");

  const streamId = events[0].streamId;
  const operationId = events[0].operationId;
  const seenCursors = new Set();
  let lastDurableSequence = 0n;
  let previousTimestamp = null;
  let previousMonotonicOffset = null;

  for (const [index, event] of events.entries()) {
    const sequence = decimalU128(event.sequence, `event ${index + 1} sequence`, false);
    invariant(sequence === BigInt(index + 1),
      `event ${index + 1} sequence is not contiguous from one`);
    invariant(event.streamId === streamId, `event ${index + 1} changes streamId`);
    invariant(event.operationId === operationId, `event ${index + 1} changes operationId`);
    invariant(!seenCursors.has(event.cursor), `event ${index + 1} repeats a cursor`);
    seenCursors.add(event.cursor);

    const timestamp = utcTimestampNs(event.emittedAt, `event ${index + 1} emittedAt`);
    invariant(previousTimestamp === null || timestamp >= previousTimestamp,
      `event ${index + 1} emittedAt regresses`);
    previousTimestamp = timestamp;

    const monotonicOffset = decimalU128(
      event.monotonicOffsetNs,
      `event ${index + 1} monotonicOffsetNs`
    );
    invariant(previousMonotonicOffset === null || monotonicOffset >= previousMonotonicOffset,
      `event ${index + 1} monotonicOffsetNs regresses`);
    previousMonotonicOffset = monotonicOffset;

    const checkpointSequence = decimalU128(
      event.checkpoint.lastDurableSequence,
      `event ${index + 1} checkpoint.lastDurableSequence`
    );
    const expectedCheckpoint = event.checkpoint.durable ? sequence : lastDurableSequence;
    invariant(checkpointSequence === expectedCheckpoint,
      `event ${index + 1} checkpoint history is inconsistent`);
    if (event.checkpoint.durable) {
      lastDurableSequence = sequence;
    }
  }

  const terminal = events.at(-1).payload;
  const minimumExit = STATUS_EXIT.get(terminal.status);
  invariant(EXIT_SEVERITY.get(terminal.exitCode) >= EXIT_SEVERITY.get(minimumExit),
    "operation.terminal exitCode is weaker than status");
  for (const field of ["status", "exitCode", "kind", "snapshotDigest"]) {
    invariant(terminal[field] === expectedTerminal[field],
      `operation.terminal ${field} does not match the expected snapshot`);
  }
}

const expectedTerminal = {
  status: "ok",
  exitCode: 0,
  kind: "scan.result",
  snapshotDigest: "sha256:89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
};
const durableStreamCases = [
  { name: "durable event stream golden", expected: true, mutate() {} },
  {
    name: "durable cursor requires the sxcur1 opaque format",
    expected: false,
    mutate(events) { events[1].cursor = "stream-golden-001:2"; }
  },
  {
    name: "durable stream rejects sequence gaps",
    expected: false,
    mutate(events) { events[1].sequence = "4"; }
  },
  {
    name: "durable stream rejects streamId drift",
    expected: false,
    mutate(events) { events[1].streamId = "other-stream"; }
  },
  {
    name: "durable stream rejects operationId drift",
    expected: false,
    mutate(events) { events[1].operationId = "other-operation"; }
  },
  {
    name: "durable stream requires operation.started first",
    expected: false,
    mutate(events) { events[0].type = "scan.progress"; }
  },
  {
    name: "durable stream rejects a repeated operation.started",
    expected: false,
    mutate(events) { events[1].type = "operation.started"; }
  },
  {
    name: "durable stream requires exactly one terminal event",
    expected: false,
    mutate(events) { events.pop(); }
  },
  {
    name: "durable stream requires terminal last",
    expected: false,
    mutate(events) {
      const terminal = events.pop();
      terminal.sequence = "2";
      terminal.checkpoint.lastDurableSequence = "2";
      events[1].sequence = "3";
      events[1].checkpoint.lastDurableSequence = "2";
      events.splice(1, 0, terminal);
    }
  },
  {
    name: "durable stream rejects checkpoint history drift",
    expected: false,
    mutate(events) { events[1].checkpoint.lastDurableSequence = "0"; }
  },
  {
    name: "durable stream rejects emittedAt regression",
    expected: false,
    mutate(events) { events[1].emittedAt = "2026-08-28T00:59:59Z"; }
  },
  {
    name: "durable stream rejects monotonic offset regression",
    expected: false,
    mutate(events) { events[2].monotonicOffsetNs = "999"; }
  },
  {
    name: "durable stream rejects duplicate cursors",
    expected: false,
    mutate(events) { events[1].cursor = events[0].cursor; }
  },
  {
    name: "durable stream rejects oversized payloads",
    expected: false,
    mutate(events) { events[1].payload = { value: "x".repeat(MAX_EVENT_PAYLOAD_BYTES) }; }
  },
  {
    name: "terminal status cannot have a weaker exit code",
    expected: false,
    mutate(events) { events[2].payload.status = "failed"; }
  },
  {
    name: "terminal facts must match the expected snapshot",
    expected: false,
    mutate(_events, expected) {
      expected.snapshotDigest = `sha256:${"0".repeat(64)}`;
    }
  }
];

for (const testCase of durableStreamCases) {
  const events = clone(durableEventGolden);
  const expected = clone(expectedTerminal);
  testCase.mutate(events, expected);
  let ok = true;
  try {
    validateDurableEventStream(events, expected);
  } catch {
    ok = false;
  }
  if (ok !== testCase.expected) {
    failed = true;
    console.log(`FAIL durable event stream case: ${testCase.name}`);
  } else {
    console.log(`PASS durable event stream case: ${testCase.name}`);
  }
}

const scanOutputValidator = ajv.getSchema(
  "https://sweepx.dev/schemas/sweepx.output/v1"
);
if (!scanOutputValidator) {
  throw new Error("Missing compiled sweepx.output schema");
}

const liveScanOutput = readJson(
  path.join(schemaDir, "examples", "sweepx.output.scan.result.example.json")
);
const scanSchemaCases = [
  {
    name: "live scan identity, native locator, and aggregate scan entry ID",
    expected: true,
    mutate() {}
  },
  {
    name: "legacy imported entry without identity",
    expected: true,
    mutate(output) {
      delete output.data.roots[0].identity;
      delete output.data.roots[0].nativeLocator;
      delete output.data.entries[0].identity;
      delete output.data.entries[0].nativeLocator;
      output.data.aggregates[0].directoryIdentity = "/legacy/path";
    }
  },
  {
    name: "legacy v1 native locator without absolute root remains readable",
    expected: true,
    mutate(output) {
      delete output.data.roots[0].nativeLocator.scanRootAbsolutePath;
      delete output.data.entries[0].nativeLocator.scanRootAbsolutePath;
    }
  },
  {
    name: "malformed scan entry ID is not accepted as legacy identity",
    expected: false,
    mutate(output) {
      output.data.aggregates[0].directoryIdentity =
        "scan-entry:v1:c2Nhbi1wMC1taW5pbWFs:0";
    }
  },
  {
    name: "path is rejected inside live identity block",
    expected: false,
    mutate(output) {
      output.data.roots[0].identity.entryId = "/fixtures/p0-minimal";
    }
  },
  {
    name: "live scan supports explicit unknown identity evidence",
    expected: true,
    mutate(output) {
      output.data.roots[0].identity.platformFileIdentity = {
        state: "unknown",
        reason: "unknown_identity"
      };
    }
  },
  {
    name: "identity evidence cannot use a scalar sentinel",
    expected: false,
    mutate(output) {
      output.data.roots[0].identity.platformFileIdentity.value = 0;
    }
  },
  {
    name: "malformed scan entry ID is rejected in native locator recipe",
    expected: false,
    mutate(output) {
      output.data.entries[0].nativeLocator.parentReopenRecipe[0].entryId =
        "scan-entry:v1:c2Nhbi1wMC1taW5pbWFs:0";
    }
  },
  {
    name: "child native locator requires a root-to-parent recipe",
    expected: false,
    mutate(output) {
      output.data.entries[0].nativeLocator.parentReopenRecipe = [];
    }
  },
  {
    name: "root native locator has an empty parent recipe",
    expected: false,
    mutate(output) {
      output.data.roots[0].nativeLocator.parentReopenRecipe.push(
        clone(output.data.roots[0].nativeLocator.scanRoot)
      );
    }
  },
  {
    name: "native locator requires an explicit parent recipe array",
    expected: false,
    mutate(output) {
      delete output.data.entries[0].nativeLocator.parentReopenRecipe;
    }
  },
  {
    name: "non-root locator entry requires its direct parent identity",
    expected: false,
    mutate(output) {
      delete output.data.entries[0].nativeLocator.entry.parentId;
    }
  },
  {
    name: "scan-root locator component cannot claim a parent",
    expected: false,
    mutate(output) {
      output.data.entries[0].nativeLocator.scanRoot.parentId =
        output.data.entries[0].identity.entryId;
    }
  },
  {
    name: "non-root recipe ancestors require direct parent identity",
    expected: false,
    mutate(output) {
      const root = clone(output.data.entries[0].nativeLocator.scanRoot);
      const parent = clone(root);
      parent.entryId = "scan-entry:v1:c2Nhbi1wMC1taW5pbWFs:3";
      output.data.entries[0].nativeLocator.parentReopenRecipe = [root, parent];
    }
  },
  {
    name: "display path is rejected as native locator entry ID",
    expected: false,
    mutate(output) {
      output.data.entries[0].nativeLocator.entry.entryId =
        "/fixtures/p0-minimal/fixture.bin";
    }
  },
  {
    name: "display path is rejected as lossless native basename",
    expected: false,
    mutate(output) {
      output.data.entries[0].nativeLocator.entry.nativeBasename.value =
        "/fixtures/p0-minimal/fixture.bin";
    }
  },
  {
    name: "padded scan root absolute path is rejected",
    expected: false,
    mutate(output) {
      output.data.entries[0].nativeLocator.scanRootAbsolutePath.value += "=";
    }
  },
  {
    name: "unknown native locator field is rejected",
    expected: false,
    mutate(output) {
      output.data.entries[0].nativeLocator.unknownField = true;
    }
  }
];

for (const testCase of scanSchemaCases) {
  const output = clone(liveScanOutput);
  testCase.mutate(output);
  const ok = scanOutputValidator(output);
  if (ok !== testCase.expected) {
    failed = true;
    console.log(`FAIL scan schema case: ${testCase.name}`);
    for (const error of scanOutputValidator.errors ?? []) {
      console.log(`  ${error.instancePath || "/"} ${error.message}`);
    }
  } else {
    console.log(`PASS scan schema case: ${testCase.name}`);
  }
}

const resultSchemaCases = [
  {
    name: "plan result matches its exact review-only data branch",
    file: "sweepx.output.plan.result.example.json",
    expected: true,
    mutate() {}
  },
  {
    name: "plan result rejects unknown data fields",
    file: "sweepx.output.plan.result.example.json",
    expected: false,
    mutate(output) {
      output.data.approvalId = "forbidden";
    }
  },
  {
    name: "plan result rejects unknown summary fields",
    file: "sweepx.output.plan.result.example.json",
    expected: false,
    mutate(output) {
      output.summary.approvalId = "forbidden";
    }
  },
  {
    name: "plan result summary is always review only",
    file: "sweepx.output.plan.result.example.json",
    expected: false,
    mutate(output) {
      output.summary.reviewOnly = false;
    }
  },
  {
    name: "plan result is always review only",
    file: "sweepx.output.plan.result.example.json",
    expected: false,
    mutate(output) {
      output.data.authority.reviewOnly = false;
    }
  },
  {
    name: "plan result carries no approval",
    file: "sweepx.output.plan.result.example.json",
    expected: false,
    mutate(output) {
      output.data.authority.approvalState = "approved";
    }
  },
  {
    name: "plan result carries no execution authorization",
    file: "sweepx.output.plan.result.example.json",
    expected: false,
    mutate(output) {
      output.data.authority.executionState = "authorized";
    }
  },
  {
    name: "plan result rejects numeric counts",
    file: "sweepx.output.plan.result.example.json",
    expected: false,
    mutate(output) {
      output.data.actionCount = 2;
    }
  },
  {
    name: "plan result rejects leading-zero decimal strings",
    file: "sweepx.output.plan.result.example.json",
    expected: false,
    mutate(output) {
      output.data.items[0].potentiallyReclaimableBytes.lowerBound = "04096";
    }
  },
  {
    name: "plan result keeps machine enums stable",
    file: "sweepx.output.plan.result.example.json",
    expected: false,
    mutate(output) {
      output.data.items[0].riskTier = "中风险";
    }
  },
  {
    name: "known reclaimable values are point values without a redundant upper bound",
    file: "sweepx.output.plan.result.example.json",
    expected: false,
    mutate(output) {
      output.data.potentiallyReclaimableBytes = {
        lowerBound: "4096",
        upperBound: "4096",
        state: "known",
        reasonCodes: []
      };
    }
  },
  {
    name: "plan result rejects an authorization-shaped action field",
    file: "sweepx.output.plan.result.example.json",
    expected: false,
    mutate(output) {
      output.data.items[0].actions[0].permit = "forbidden";
    }
  },
  {
    name: "plan review never guarantees capacity release",
    file: "sweepx.output.plan.result.example.json",
    expected: false,
    mutate(output) {
      output.data.recoveryExpectation.capacityReleaseGuaranteed = true;
    }
  },
  {
    name: "status result matches its exact data branch",
    file: "sweepx.output.status.result.example.json",
    expected: true,
    mutate() {}
  },
  {
    name: "status result rejects unknown data fields",
    file: "sweepx.output.status.result.example.json",
    expected: false,
    mutate(output) {
      output.data.unknownField = true;
    }
  },
  {
    name: "status result requires its nullable count fields",
    file: "sweepx.output.status.result.example.json",
    expected: false,
    mutate(output) {
      delete output.data.entryCount;
    }
  },
  {
    name: "cache status result matches its exact typed data branch",
    file: "sweepx.output.cache-status.result.example.json",
    expected: true,
    mutate() {}
  },
  {
    name: "cache status result rejects unknown data fields",
    file: "sweepx.output.cache-status.result.example.json",
    expected: false,
    mutate(output) {
      output.data.previewRoot = "/private/cache";
    }
  },
  {
    name: "cache status result rejects numeric counts",
    file: "sweepx.output.cache-status.result.example.json",
    expected: false,
    mutate(output) {
      output.data.generationCount = 0;
    }
  },
  {
    name: "cache status result rejects untyped inspection errors",
    file: "sweepx.output.cache-status.result.example.json",
    expected: false,
    mutate(output) {
      output.data.errors = [{ kind: "unknown_cache_error", path: "/private/cache" }];
    }
  },
  {
    name: "cache status result rejects unsafe generation identifiers",
    file: "sweepx.output.cache-status.result.example.json",
    expected: false,
    mutate(output) {
      output.data.disposition = "degraded";
      output.status = "partial";
      output.exitCode = 4;
      output.data.exists = true;
      output.data.currentGeneration = "../../secret";
    }
  },
  {
    name: "cache status available requires an existing healthy cache",
    file: "sweepx.output.cache-status.result.example.json",
    expected: false,
    mutate(output) {
      output.data.disposition = "available";
    }
  },
  {
    name: "cache status degraded requires partial exit four",
    file: "sweepx.output.cache-status.result.example.json",
    expected: false,
    mutate(output) {
      output.data.disposition = "degraded";
    }
  },
  {
    name: "cache status degraded requires a degradation witness",
    file: "sweepx.output.cache-status.result.example.json",
    expected: false,
    mutate(output) {
      output.data.disposition = "degraded";
      output.data.exists = true;
      output.data.currentGeneration = "gen-example";
      output.data.storedSchema = "sweepx.preview.cache/v1";
      output.data.currentHealth = "available";
      output.data.schemaHealth = "available";
      output.status = "partial";
      output.exitCode = 4;
    }
  },
  {
    name: "cache status absent requires zero complete aggregate state",
    file: "sweepx.output.cache-status.result.example.json",
    expected: false,
    mutate(output) {
      output.data.approxBytes = "1";
      output.data.approxBytesComplete = false;
    }
  },
  {
    name: "cache status available rejects quarantine presence",
    file: "sweepx.output.cache-status.result.example.json",
    expected: false,
    mutate(output) {
      output.data.disposition = "available";
      output.data.exists = true;
      output.data.currentGeneration = "gen-example";
      output.data.storedSchema = "sweepx.preview.cache/v1";
      output.data.currentHealth = "available";
      output.data.schemaHealth = "available";
      output.data.quarantineCount = "1";
    }
  },
  {
    name: "cache status unsupported requires the unsupported exit code",
    file: "sweepx.output.cache-status.result.example.json",
    expected: false,
    mutate(output) {
      output.data.disposition = "unsupported";
      output.status = "unsupported";
      output.exitCode = 11;
      output.data.approxBytesComplete = false;
    }
  },
  {
    name: "cargo detect result locks the config-scope golden shape",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: true,
    mutate() {}
  },
  {
    name: "cargo detect incompatible gate keeps every authority disabled",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: true,
    mutate(output) {
      output.status = "failed";
      output.exitCode = 12;
      output.summary = {
        command: "cleaner.cargo-detect",
        cleanerId: "org.sweepx.cargo-target",
        experimental: true,
        liveOnly: true,
        scanPerformed: false,
        matchCount: "0",
        hintCount: "0",
        rootCount: "1",
        reasonCode: "builtin_manifest_incompatible",
        cleanerSetDigest: "sha256:example"
      };
      output.data = {
        command: "cleaner.cargo-detect",
        experimental: true,
        liveOnly: true,
        scanPerformed: false,
        builtinManifestCompatible: false,
        matchCount: "0",
        hintCount: "0",
        matches: [],
        hints: [],
        reasons: ["builtin_manifest_incompatible"],
        readOnly: true,
        candidateAllowed: false,
        planAllowed: false,
        approvalAllowed: false,
        executionAllowed: false
      };
      output.warnings = [];
      output.errors = [{
        code: "cleaner.compatibility",
        class: "cleaner",
        messageKey: "cleaner.compatibility",
        params: {
          cleanerRef: "org.sweepx.cargo-target@0.1.0",
          requiredCore: ">=1.0.0, <2.0.0",
          currentCore: "0.1.0"
        },
        retryable: false
      }];
    }
  },
  {
    name: "cargo detect incompatible gate cannot enable candidate projection",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.status = "failed";
      output.exitCode = 12;
      output.summary = {
        command: "cleaner.cargo-detect",
        cleanerId: "org.sweepx.cargo-target",
        experimental: true,
        liveOnly: true,
        scanPerformed: false,
        matchCount: "0",
        hintCount: "0",
        rootCount: "1",
        reasonCode: "builtin_manifest_incompatible",
        cleanerSetDigest: "sha256:example"
      };
      output.data = {
        command: "cleaner.cargo-detect",
        experimental: true,
        liveOnly: true,
        scanPerformed: false,
        builtinManifestCompatible: false,
        matchCount: "0",
        hintCount: "0",
        matches: [],
        hints: [],
        reasons: ["builtin_manifest_incompatible"],
        readOnly: true,
        candidateAllowed: true,
        planAllowed: false,
        approvalAllowed: false,
        executionAllowed: false
      };
      output.warnings = [];
      output.errors = [];
    }
  },
  {
    name: "cargo detect rejects an unknown config-scope schema",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.schema = "cargo.config-scope.v2";
    }
  },
  {
    name: "cargo detect rejects snake_case config-scope fields",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      const scope = output.data.hints[0].evidence.cargo.configScope;
      scope.precedence_complete = scope.precedenceComplete;
      delete scope.precedenceComplete;
    }
  },
  {
    name: "cargo detect requires a typed workspace pair snapshot",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.workspace.pairSnapshot =
        "not_checked";
    }
  },
  {
    name: "cargo detect rejects an untagged config file state",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.workspace.config = {};
    }
  },
  {
    name: "cargo detect rejects atomic absence claims without a stable pair snapshot",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.workspace.configToml = {
        state: "verified_absent"
      };
    }
  },
  {
    name: "cargo detect binds each environment field to its exact variable name",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.environment.cargoTargetDir.name =
        "CARGO_HOME";
    }
  },
  {
    name: "cargo detect rejects raw environment values",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.environment.cargoTargetDir.value =
        "/private/target";
    }
  },
  {
    name: "cargo detect requires present environment values to be redacted",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.environment.cargoTargetDir.valueRedacted =
        false;
    }
  },
  {
    name: "cargo detect rejects redaction claims for absent environment values",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.environment.cargoHome.valueRedacted =
        true;
    }
  },
  {
    name: "cargo detect rejects unknown config-scope blockers",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.blockers.push("unknown_blocker");
    }
  },
  {
    name: "cargo detect rejects duplicate config-scope blockers",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      const blockers = output.data.hints[0].evidence.cargo.configScope.blockers;
      blockers.push(blockers[0]);
    }
  },
  {
    name: "cargo detect rejects too many config-scope blockers",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.blockers = Array.from(
        { length: 24 },
        (_, index) => `blocker_${index}`
      );
    }
  },
  {
    name: "cargo detect rejects raw workspace target-dir values",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.workspace.targetDirDeclaration.value =
        "private-target";
    }
  },
  {
    name: "cargo detect rejects workspace target-dir path components",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.workspace.targetDirDeclaration.relativeComponents =
        ["private-target"];
    }
  },
  {
    name: "cargo detect requires workspace target-dir declaration redaction",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.workspace.targetDirDeclaration.valueRedacted =
        false;
    }
  },
  {
    name: "cargo detect workspace declaration source matches its observed config file",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.workspace.targetDirDeclaration.source =
        "config_toml";
    }
  },
  {
    name: "cargo detect rejects a config declaration without a present config file",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.workspace.config = {
        state: "not_checked",
        reasonCode: "config_scope_not_checked"
      };
    }
  },
  {
    name: "cargo detect rejects a config-toml declaration without a present config-toml file",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      const workspace = output.data.hints[0].evidence.cargo.configScope.workspace;
      workspace.config = {
        state: "not_checked",
        reasonCode: "config_scope_not_checked"
      };
      workspace.targetDirDeclaration.source = "config_toml";
    }
  },
  {
    name: "cargo detect accepts a non-atomic config-toml declaration with downgraded config absence",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: true,
    mutate(output) {
      const workspace = output.data.hints[0].evidence.cargo.configScope.workspace;
      workspace.config = {
        state: "not_checked",
        reasonCode: "config_scope_not_checked"
      };
      workspace.configToml = { state: "present" };
      workspace.targetDirDeclaration.source = "config_toml";
    }
  },
  {
    name: "cargo detect rejects a stable absent pair with a known declaration",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      const workspace = output.data.hints[0].evidence.cargo.configScope.workspace;
      workspace.pairSnapshot = { state: "stable_snapshot" };
      workspace.config = { state: "verified_absent" };
      workspace.configToml = { state: "verified_absent" };
      workspace.selected = "none";
    }
  },
  {
    name: "cargo detect stable config-toml selection matches both file states",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: true,
    mutate(output) {
      const workspace = output.data.hints[0].evidence.cargo.configScope.workspace;
      workspace.pairSnapshot = { state: "stable_snapshot" };
      workspace.config = { state: "verified_absent" };
      workspace.configToml = { state: "present" };
      workspace.selected = "config_toml";
      workspace.targetDirDeclaration.source = "config_toml";
    }
  },
  {
    name: "cargo detect rejects a stable config-toml file selected as config",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      const workspace = output.data.hints[0].evidence.cargo.configScope.workspace;
      workspace.pairSnapshot = { state: "stable_snapshot" };
      workspace.config = { state: "verified_absent" };
      workspace.configToml = { state: "present" };
      workspace.selected = "config";
      workspace.targetDirDeclaration.source = "config_toml";
    }
  },
  {
    name: "cargo detect rejects a stable present config selected as none",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      const workspace = output.data.hints[0].evidence.cargo.configScope.workspace;
      workspace.pairSnapshot = { state: "stable_snapshot" };
      workspace.config = { state: "present" };
      workspace.configToml = { state: "verified_absent" };
      workspace.selected = "none";
    }
  },
  {
    name: "cargo detect stable pair prefers extensionless config when both files are present",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: true,
    mutate(output) {
      const workspace = output.data.hints[0].evidence.cargo.configScope.workspace;
      workspace.pairSnapshot = { state: "stable_snapshot" };
      workspace.config = { state: "present" };
      workspace.configToml = { state: "present" };
      workspace.selected = "config";
      workspace.targetDirDeclaration = {
        state: "known",
        source: "config",
        valueRedacted: true
      };
    }
  },
  {
    name: "cargo detect cannot claim complete precedence",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.configScope.precedenceComplete = true;
    }
  },
  {
    name: "cargo detect cannot promote targetDir to known",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.targetDir = {
        state: "known",
        reasonCode: null,
        relativePath: "target"
      };
    }
  },
  {
    name: "cargo detect not-checked targetDir has the config-scope reason",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.targetDir.reasonCode = "missing_identity";
    }
  },
  {
    name: "cargo detect cannot promote targetShape to known",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].evidence.cargo.targetShape = {
        state: "known",
        reasonCode: null,
        classification: "recognized_generated_structure"
      };
    }
  },
  {
    name: "cargo detect rejects candidate authority",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.hints[0].candidate = { id: "forbidden" };
    }
  },
  {
    name: "cargo detect cannot enable candidate projection",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.candidateAllowed = true;
    }
  },
  {
    name: "cargo detect rejects plan authority",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.plan = { id: "forbidden" };
    }
  },
  {
    name: "cargo detect cannot enable approval",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.approvalAllowed = true;
    }
  },
  {
    name: "cargo detect cannot enable execution",
    file: "sweepx.output.cargo-detect.result.example.json",
    expected: false,
    mutate(output) {
      output.data.executionAllowed = true;
    }
  },
  {
    name: "cancel result matches its exact data branch",
    file: "sweepx.output.cancel.result.example.json",
    expected: true,
    mutate() {}
  },
  {
    name: "cancel result rejects unknown data fields",
    file: "sweepx.output.cancel.result.example.json",
    expected: false,
    mutate(output) {
      output.data.unknownField = true;
    }
  },
  {
    name: "missing cancel result cannot carry an operation",
    file: "sweepx.output.cancel.result.example.json",
    expected: false,
    mutate(output) {
      output.data.disposition = "not_found";
    }
  },
  {
    name: "terminal cancel result requires an operation",
    file: "sweepx.output.cancel.result.example.json",
    expected: false,
    mutate(output) {
      output.data.operation = null;
    }
  },
  {
    name: "unsupported cancel result cannot carry an operation",
    file: "sweepx.output.cancel.result.example.json",
    expected: false,
    mutate(output) {
      output.data.disposition = "unsupported";
    }
  }
];

for (const testCase of resultSchemaCases) {
  const output = readJson(path.join(schemaDir, "examples", testCase.file));
  testCase.mutate(output);
  const ok = scanOutputValidator(output);
  if (ok !== testCase.expected) {
    failed = true;
    console.log(`FAIL output schema case: ${testCase.name}`);
    for (const error of scanOutputValidator.errors ?? []) {
      console.log(`  ${error.instancePath || "/"} ${error.message}`);
    }
  } else {
    console.log(`PASS output schema case: ${testCase.name}`);
  }
}

const qualifiedSchemaCases = [
  {
    name: "valid exact platform tuple",
    expected: true,
    mutate() {}
  },
  {
    name: "valid exact cleaner tuple",
    expected: true,
    mutate(record) {
      record.qualificationKey.scope = "cleaner";
      record.qualificationKey.cleanerId = "org.sweepx.test-cleaner";
      record.qualificationKey.cleanerVersion = "1.2.3";
    }
  },
  {
    name: "qualified preview cache inspection accepts development evidence",
    expected: true,
    mutate(record) {
      record.qualificationKey.capability = "cache.preview.inspect";
      record.evidence.evidenceClass = "development_snapshot";
    }
  },
  {
    name: "qualified completed replay accepts development evidence",
    expected: true,
    mutate(record) {
      record.qualificationKey.capability = "operation.event.completed_replay";
      record.evidence.evidenceClass = "development_snapshot";
    }
  },
  {
    name: "missing evidence provenance",
    expected: false,
    mutate(record) {
      delete record.evidence.evidenceClass;
    }
  },
  {
    name: "unknown destructive cell with development evidence",
    expected: false,
    mutate(record) {
      record.qualificationKey.capability = "delete.local.file";
      record.evidence.evidenceClass = "development_snapshot";
    }
  },
  {
    name: "repeated placeholder digest",
    expected: false,
    mutate(record) {
      record.qualificationKey.adapterDigest = `sha256:${"0".repeat(64)}`;
    }
  },
  {
    name: "glob-bearing exact tuple",
    expected: false,
    mutate(record) {
      record.qualificationKey.osBuild = "6.*";
    }
  },
  {
    name: "platform scope with cleaner identity",
    expected: false,
    mutate(record) {
      record.qualificationKey.cleanerId = "org.sweepx.test-cleaner";
      record.qualificationKey.cleanerVersion = "1.2.3";
    }
  },
  {
    name: "cleaner scope missing full identity",
    expected: false,
    mutate(record) {
      record.qualificationKey.scope = "cleaner";
      record.qualificationKey.cleanerId = "org.sweepx.test-cleaner";
    }
  },
  {
    name: "legacy duplicate expiry field",
    expected: false,
    mutate(record) {
      record.evidence.expiresAt = "2026-08-29T00:00:00Z";
    }
  },
  {
    name: "strong qualification missing expiry",
    expected: false,
    mutate(record) {
      delete record.evidence.validity.expiresAt;
    }
  }
];

for (const testCase of qualifiedSchemaCases) {
  const record = clone(validQualifiedCapability);
  testCase.mutate(record);
  const ok = capabilityValidator(record);
  if (ok !== testCase.expected) {
    failed = true;
    console.log(`FAIL capability schema case: ${testCase.name}`);
    for (const error of capabilityValidator.errors ?? []) {
      console.log(`  ${error.instancePath || "/"} ${error.message}`);
    }
  } else {
    console.log(`PASS capability schema case: ${testCase.name}`);
  }
}

for (const result of results) {
  if (result.ok) {
    console.log(`PASS ${result.file} -> ${result.schemaId}`);
    continue;
  }
  console.log(`FAIL ${result.file} -> ${result.schemaId}`);
  for (const error of result.errors) {
    console.log(`  ${error.instancePath || "/"} ${error.message}`);
  }
}

if (failed) {
  process.exit(1);
}
