import { build } from "esbuild";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
const root = new URL("./", import.meta.url),
  assets = new URL("../assets/chromium-cleanup/", root);
// Shipped output is committed and embedded by Rust. Building needs Node; running
// SweepX or the extension does not. Keep one shared removal/bridge implementation.
const result = await build({
  // Stable section names regardless of the caller's directory (including CI).
  absWorkingDir: fileURLToPath(root),
  entryPoints: [fileURLToPath(new URL("src/main.mjs", root))],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: ["chrome96"],
  write: false,
  external: ["./logic.mjs", "./bridge.mjs"],
  legalComments: "none",
  charset: "utf8",
});
const outputs = {
  "review.mjs": result.outputFiles[0].text,
  "review.html": await readFile(new URL("src/index.html", root), "utf8"),
  "review.css": await readFile(new URL("src/style.css", root), "utf8"),
};
for (const [name, value] of Object.entries(outputs)) {
  if (process.argv.includes("--check")) {
    if ((await readFile(new URL(name, assets), "utf8")) !== value)
      throw new Error(`Stale extension asset: ${name}; run npm run build`);
  } else await writeFile(new URL(name, assets), value);
}
console.log(
  process.argv.includes("--check")
    ? "Embedded assets match source."
    : "Built embedded extension UI.",
);
