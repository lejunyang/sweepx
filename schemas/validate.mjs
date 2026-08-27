import { readFileSync, readdirSync, statSync } from "node:fs";
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
    file: path.join(schemaDir, "examples", "sweepx.output.cancel.result.example.json")
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
