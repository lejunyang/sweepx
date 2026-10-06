import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
// A loopback-only synthetic frontend preview, never a proxy for Native Messaging.
// Whitelisted static files only: no disk scan, user profile reads or write routes.
const assets = new URL("../assets/chromium-cleanup/", import.meta.url),
  mime = {
    ".html": "text/html",
    ".css": "text/css",
    ".mjs": "text/javascript",
  };
const files = new Map();
for (const name of [
  "review.html",
  "review.css",
  "review.mjs",
  "logic.mjs",
  "bridge.mjs",
])
  files.set(`/${name}`, await readFile(new URL(name, assets)));
files.set(
  "/preview-entry.mjs",
  await readFile(new URL("src/preview-entry.mjs", import.meta.url)),
);
files.set(
  "/",
  Buffer.from(
    files
      .get("/review.html")
      .toString()
      .replace('src="review.mjs"', 'src="preview-entry.mjs"'),
  ),
);
const server = createServer((req, res) => {
  const path = new URL(req.url, "http://127.0.0.1").pathname,
    body = files.get(path);
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'none'; img-src 'none'; object-src 'none'",
  );
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "GET" || !body) {
    res.writeHead(404);
    res.end();
    return;
  }
  res.setHeader(
    "Content-Type",
    path === "/" ? mime[".html"] : mime[path.slice(path.lastIndexOf("."))],
  );
  res.end(body);
});
server.listen(4173, "127.0.0.1", () =>
  console.log("Synthetic UI preview: http://127.0.0.1:4173/"),
);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => server.close());
