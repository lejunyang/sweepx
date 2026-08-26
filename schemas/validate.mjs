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
