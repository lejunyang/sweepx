import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

test("embedded build is reproducible outside the project directory", () => {
  const result = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("../build.mjs", import.meta.url)), "--check"],
    {
      cwd: tmpdir(),
      timeout: 15000,
      encoding: "utf8",
      maxBuffer: 65536,
    },
  );
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.match(result.stdout, /Embedded assets match source/);
});
