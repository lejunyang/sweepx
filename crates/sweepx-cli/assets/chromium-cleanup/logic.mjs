// Plans describe a selection, never filesystem authority. Browser APIs own the actual removal.
// No network, page injection or filesystem path is consumed by this adapter.
export function validatePlan(plan) {
  if (
    plan?.schema !== "sweepx.browser_cleanup.plan/v1" ||
    plan.operation !== "browser_managed_origin_removal" ||
    ![
      "chrome",
      "edge",
      "chrome-beta",
      "chrome-dev",
      "edge-beta",
      "edge-dev",
    ].includes(plan.browser) ||
    typeof plan.profile !== "string" ||
    !/^(Default|Profile [0-9]+)$/.test(plan.profile) ||
    typeof plan.domain !== "string" ||
    plan.domain.length > 253 ||
    !Array.isArray(plan.origins) ||
    plan.origins.length === 0 ||
    plan.origins.length > 128
  ) {
    throw new Error("无效或不支持的计划 / Invalid or unsupported plan");
  }
  const domain = plan.domain.toLowerCase();
  const origins = exactOrigins(plan.origins, domain);
  return Object.freeze({
    browser: plan.browser,
    profile: plan.profile,
    domain,
    origins: Object.freeze(origins),
  });
}
function exactOrigins(values, domain) {
  return [
    ...new Set(
      values.map((origin) => {
        if (typeof origin !== "string" || origin.length > 4096)
          throw new Error("Invalid origin");
        const url = new URL(origin);
        if (
          !["https:", "http:"].includes(url.protocol) ||
          url.hostname.toLowerCase() !== domain ||
          url.username ||
          url.password ||
          url.origin !== origin
        )
          throw new Error("域名与 origin 不匹配 / Origin mismatch");
        return url.origin;
      }),
    ),
  ];
}
// Standalone selection belongs to the extension's current profile, not a guessed
// native directory. A bare hostname explicitly selects its two default origins;
// an HTTP(S) origin preserves its scheme and non-default port. Never accept paths.
export function manualSelection(input) {
  if (typeof input !== "string" || input.length > 4096)
    throw new Error("Invalid site");
  const text = input.trim();
  let origins, domain;
  if (/^https?:\/\//i.test(text)) {
    const url = new URL(text);
    if (
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      url.pathname !== "/" ||
      text.replace(/\/$/, "").toLowerCase() !== url.origin.toLowerCase()
    )
      throw new Error("Enter a hostname or exact HTTP(S) origin");
    domain = url.hostname.toLowerCase();
    origins = [url.origin];
  } else {
    if (!text || /[\s\/:?#@*\\]/.test(text))
      throw new Error("Enter a hostname or exact HTTP(S) origin");
    domain = new URL(`https://${text}`).hostname.toLowerCase();
    origins = [`https://${domain}`, `http://${domain}`];
  }
  if (
    domain.length > 253 ||
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(domain) ||
    domain.includes("..")
  )
    throw new Error("Invalid hostname");
  return Object.freeze({
    schema: "sweepx.browser_cleanup.manual/v1",
    domain,
    origins: Object.freeze(exactOrigins(origins, domain)),
  });
}
export function removalRequest(plan, mode, confirmedDomain, matchingProfile) {
  // Revalidate even already-reviewed objects at the action boundary. Manual
  // selections do not have native profile claims and cannot impersonate a plan.
  const selection =
    plan?.schema === "sweepx.browser_cleanup.manual/v1"
      ? validateManual(plan)
      : validatePlan({
          ...plan,
          schema: "sweepx.browser_cleanup.plan/v1",
          operation: "browser_managed_origin_removal",
        });
  if (
    !matchingProfile ||
    confirmedDomain !== selection.domain ||
    !["cache", "storage"].includes(mode)
  ) {
    throw new Error(
      "请确认范围、浏览器个人资料和域名 / Confirm scope, profile and domain",
    );
  }
  return {
    options: {
      since: 0,
      origins: [...selection.origins],
      originTypes: {
        unprotectedWeb: true,
        protectedWeb: false,
        extension: false,
      },
    },
    types:
      mode === "cache"
        ? { cache: true, cacheStorage: true }
        : {
            cache: true,
            cacheStorage: true,
            indexedDB: true,
            localStorage: true,
            serviceWorkers: true,
            fileSystems: true,
          },
  };
}
function validateManual(plan) {
  if (
    typeof plan.domain !== "string" ||
    !Array.isArray(plan.origins) ||
    plan.origins.length < 1 ||
    plan.origins.length > 2
  )
    throw new Error("Invalid manual selection");
  const selection = manualSelection(plan.origins[0]);
  if (
    selection.domain !== plan.domain ||
    exactOrigins(plan.origins, plan.domain).length !== plan.origins.length
  )
    throw new Error("Invalid manual selection");
  return plan;
}
export async function removeWithBrowser(api, request) {
  // Await the real API result. Rejection or an unfinished promise is never presented as success.
  if (!api?.remove)
    throw new Error("浏览器清理接口不可用 / Browser API unavailable");
  await api.remove(request.options, request.types);
}
