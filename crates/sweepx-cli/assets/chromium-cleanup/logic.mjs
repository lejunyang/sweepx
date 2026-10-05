// Plans describe a selection, never filesystem authority. Browser APIs own the actual removal.
// No network, page injection or filesystem path is consumed by this adapter.
export function validatePlan(plan) {
  if (plan?.schema !== 'sweepx.browser_cleanup.plan/v1' || plan.operation !== 'browser_managed_origin_removal' ||
      !['chrome','edge','chrome-beta','chrome-dev','edge-beta','edge-dev'].includes(plan.browser) ||
      typeof plan.profile !== 'string' || !/^(Default|Profile [0-9]+)$/.test(plan.profile) ||
      typeof plan.domain !== 'string' || plan.domain.length > 253 ||
      !Array.isArray(plan.origins) || plan.origins.length === 0 || plan.origins.length > 128) {
    throw new Error('无效或不支持的计划 / Invalid or unsupported plan');
  }
  const domain = plan.domain.toLowerCase();
  const origins = [...new Set(plan.origins.map(origin => {
    if (typeof origin !== 'string' || origin.length > 4096) throw new Error('Invalid origin');
    const url = new URL(origin);
    if (!['https:','http:'].includes(url.protocol) || url.hostname.toLowerCase() !== domain ||
        url.username || url.password || url.origin !== origin) throw new Error('域名与 origin 不匹配 / Origin mismatch');
    return url.origin;
  }))];
  return Object.freeze({browser:plan.browser,profile:plan.profile,domain,origins:Object.freeze(origins)});
}
export function removalRequest(plan, mode, confirmedDomain, matchingProfile) {
  const selection = validatePlan({...plan,schema:'sweepx.browser_cleanup.plan/v1',operation:'browser_managed_origin_removal'});
  if (!matchingProfile || confirmedDomain !== selection.domain || !['cache','storage'].includes(mode)) {
    throw new Error('请确认范围、浏览器个人资料和域名 / Confirm scope, profile and domain');
  }
  return {options:{since:0,origins:[...selection.origins],originTypes:{unprotectedWeb:true,protectedWeb:false,extension:false}},
    types: mode === 'cache' ? {cache:true,cacheStorage:true} : {cache:true,cacheStorage:true,indexedDB:true,localStorage:true,serviceWorkers:true,fileSystems:true}};
}
export async function removeWithBrowser(api, request) {
  // Await the real API result. Rejection or an unfinished promise is never presented as success.
  if (!api?.remove) throw new Error('浏览器清理接口不可用 / Browser API unavailable');
  await api.remove(request.options, request.types);
}
