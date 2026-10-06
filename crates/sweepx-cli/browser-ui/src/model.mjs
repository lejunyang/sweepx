// Presentation facts are never cleanup authority. Missing observations cannot
// turn into zero bytes, nor can a sum of logical bytes become reclaimable space.
export const bytes = (value) =>
  typeof value === "string" && /^\d+$/.test(value) ? BigInt(value) : null;
export function total(rows, field, completeField) {
  let sum = 0n,
    known = 0,
    complete = true;
  for (const row of rows) {
    const n = bytes(row[field]);
    if (n === null) complete = false;
    else {
      sum += n;
      known++;
    }
    if (row[completeField] !== true) complete = false;
  }
  return {
    value: known ? sum.toString() : null,
    complete: known === rows.length && complete,
  };
}
export function sortedDomains(rows, query, sort) {
  const filtered = rows.filter((r) =>
    r.domain.toLowerCase().includes(query.trim().toLowerCase()),
  );
  return filtered.sort((a, b) => {
    if (sort === "name") return a.domain.localeCompare(b.domain);
    const av = bytes(a.bytes),
      bv = bytes(b.bytes);
    if (av === null || bv === null)
      return av === bv
        ? a.domain.localeCompare(b.domain)
        : av === null
          ? 1
          : -1;
    return av === bv ? a.domain.localeCompare(b.domain) : av > bv ? -1 : 1;
  });
}
export function partition(row) {
  const key = row.storageKey || "",
    match = key.match(/\^0(https?:\/\/[^\^]+)$/);
  if (match) {
    try {
      return { kind: "embedded", site: new URL(match[1]).hostname };
    } catch {
      /* Keep unfamiliar keys as raw evidence. */
    }
  }
  if (/\^31$/.test(key)) return { kind: "cross-site" };
  if (key.includes("^")) return { kind: "unknown" };
  return { kind: "first-party" };
}
export const subsystemNames = {
  service_worker_cache_storage: ["网站离线缓存", "Offline cache"],
  indexed_db: ["网站数据库", "Website databases"],
  web_storage: ["分区网站存储", "Partitioned site storage"],
  local_storage_shared: ["共享本地存储", "Shared local storage"],
  http_cache_shared: ["网页资源缓存", "HTTP resource cache"],
  code_cache_shared: ["代码缓存", "Code cache"],
  service_worker_shared: [
    "共享 Service Worker 数据",
    "Shared service worker data",
  ],
  service_worker_database_shared: [
    "Service Worker 数据库",
    "Service worker database",
  ],
  service_worker_script_cache_shared: [
    "Service Worker 脚本缓存",
    "Service worker script cache",
  ],
  extensions_shared: ["扩展程序文件", "Extension files"],
  session_storage_shared: ["会话存储", "Session storage"],
  file_system: ["网站文件", "Website files"],
};
