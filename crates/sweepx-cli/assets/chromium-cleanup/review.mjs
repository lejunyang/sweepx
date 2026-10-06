// src/main.mjs
import {
  validatePlan,
  manualSelection,
  removalRequest,
  removeWithBrowser
} from "./logic.mjs";
import { Bridge, matchingRequest, formatBytes } from "./bridge.mjs";

// src/model.mjs
var bytes = (value) => typeof value === "string" && /^\d+$/.test(value) ? BigInt(value) : null;
function total(rows, field, completeField) {
  let sum = 0n, known = 0, complete = true;
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
    complete: known === rows.length && complete
  };
}
function sortedDomains(rows, query, sort) {
  const filtered = rows.filter(
    (r) => r.domain.toLowerCase().includes(query.trim().toLowerCase())
  );
  return filtered.sort((a, b) => {
    if (sort === "name") return a.domain.localeCompare(b.domain);
    const av = bytes(a.bytes), bv = bytes(b.bytes);
    if (av === null || bv === null)
      return av === bv ? a.domain.localeCompare(b.domain) : av === null ? 1 : -1;
    return av === bv ? a.domain.localeCompare(b.domain) : av > bv ? -1 : 1;
  });
}
function partition(row) {
  const key = row.storageKey || "", match = key.match(/\^0(https?:\/\/[^\^]+)$/);
  if (match) {
    try {
      return { kind: "embedded", site: new URL(match[1]).hostname };
    } catch {
    }
  }
  if (/\^31$/.test(key)) return { kind: "cross-site" };
  if (key.includes("^")) return { kind: "unknown" };
  return { kind: "first-party" };
}
var subsystemNames = {
  service_worker_cache_storage: ["网站离线缓存", "Offline cache"],
  indexed_db: ["网站数据库", "Website databases"],
  web_storage: ["分区网站存储", "Partitioned site storage"],
  local_storage_shared: ["共享本地存储", "Shared local storage"],
  http_cache_shared: ["网页资源缓存", "HTTP resource cache"],
  code_cache_shared: ["代码缓存", "Code cache"],
  service_worker_shared: [
    "共享 Service Worker 数据",
    "Shared service worker data"
  ],
  service_worker_database_shared: [
    "Service Worker 数据库",
    "Service worker database"
  ],
  service_worker_script_cache_shared: [
    "Service Worker 脚本缓存",
    "Service worker script cache"
  ],
  extensions_shared: ["扩展程序文件", "Extension files"],
  session_storage_shared: ["会话存储", "Session storage"],
  file_system: ["网站文件", "Website files"]
};

// src/main.mjs
function createApp({
  document: document2,
  window: window2,
  chrome: chrome2,
  setInterval = window2.setInterval.bind(window2),
  clearInterval = window2.clearInterval.bind(window2),
  preview = false
}) {
  const el = (id) => document2.getElementById(id);
  let lang = "zh", view = "sites", inventory = null, selected = null, page = 0, bridge = null;
  let plan = null, pendingRequest = null, seenRequest = null, polling = false, busy = false, removing = false, phase = "", generation = 0;
  let scanTime = null, connectionText = null, requestText = null, statusText = null, lastFocus = null, detailPage = 0;
  const text = (zh, en) => lang === "zh" ? zh : en;
  const label = (name) => subsystemNames[name] ? text(...subsystemNames[name]) : name;
  const size = (value, complete) => value == null ? text("未知", "Unknown") : formatBytes(value, complete);
  const selection = () => ({
    browser: el("browser").value,
    profile: el("native-profile").value
  });
  const connected = () => bridge && !bridge.closed;
  const expired = () => pendingRequest && !matchingRequest(pendingRequest, selection().browser, selection().profile);
  const mode = () => document2.querySelector('input[name="mode"]:checked')?.value || "";
  const say = (zh, en, error = false) => {
    statusText = { zh, en, error };
    renderStatus();
  };
  const requestSay = (zh, en) => {
    requestText = { zh, en };
    el("request-status").textContent = text(zh, en);
  };
  const connectionSay = (zh, en, ok = false) => {
    connectionText = { zh, en };
    el("connection").textContent = text(zh, en);
    el("connection-dot").classList.toggle("connected", ok);
  };
  const node = (tag, content, className) => {
    const n = document2.createElement(tag);
    if (content != null) n.textContent = content;
    if (className) n.className = className;
    return n;
  };
  const appendText = (parent, tag, content, className) => {
    const n = node(tag, content, className);
    parent.append(n);
    return n;
  };
  function renderStatus() {
    el("status").hidden = !statusText;
    if (statusText) {
      el("status").textContent = text(statusText.zh, statusText.en);
      el("status").classList.toggle("error", statusText.error);
    }
  }
  function remember() {
    try {
      window2.localStorage.setItem(
        "sweepx-ui",
        JSON.stringify({
          lang,
          browser: selection().browser,
          profile: selection().profile
        })
      );
    } catch {
    }
  }
  el("browser").value = /Edg\//.test(window2.navigator.userAgent) ? "edge" : "chrome";
  try {
    const stored = window2.localStorage.getItem("sweepx-ui");
    if (stored?.length <= 512) {
      const p = JSON.parse(stored);
      if (["zh", "en"].includes(p.lang)) lang = p.lang;
      if ([...el("browser").options].some((o) => o.value === p.browser))
        el("browser").value = p.browser;
      if (/^(Default|Profile [0-9]+)$/.test(p.profile))
        el("native-profile").value = p.profile;
    }
  } catch {
  }
  el("language").value = lang;
  el("extension-version").textContent = `v${chrome2.runtime.getManifest?.().version || "0.3.0"}`;
  if (preview) el("preview-banner").hidden = false;
  function localize() {
    document2.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    document2.title = text("SweepX · 网站存储", "SweepX · Site storage");
    for (const n of document2.querySelectorAll("[data-zh]"))
      n.textContent = text(n.dataset.zh, n.dataset.en);
    for (const n of document2.querySelectorAll("[data-placeholder-zh]"))
      n.placeholder = text(n.dataset.placeholderZh, n.dataset.placeholderEn);
    if (preview)
      el("preview-banner").textContent = text(
        "开发预览 · 使用虚构数据，所有清理操作均为模拟",
        "Development preview · fictional data, all clearing is simulated"
      );
    if (connectionText)
      connectionSay(connectionText.zh, connectionText.en, !!connected());
    if (requestText) requestSay(requestText.zh, requestText.en);
    renderStatus();
    renderContext();
    renderInventory();
    renderDetails();
    renderPlan();
    showView(view);
  }
  function renderContext() {
    const s = selection();
    el("browser-label").textContent = el("browser").selectedOptions[0].textContent;
    el("profile-label").textContent = s.profile;
  }
  function showView(next) {
    if (removing) return;
    view = next;
    for (const name of ["sites", "direct", "settings"])
      el(`${name}-view`).hidden = name !== view;
    for (const button of document2.querySelectorAll("[data-view]")) {
      button.classList.toggle("active", button.dataset.view === view);
      if (button.dataset.view === view)
        button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    }
    el("view-label").textContent = text(
      ...{
        sites: ["网站存储", "Site storage"],
        direct: ["指定网站清理", "Clear a website"],
        settings: ["连接与设置", "Connection & settings"]
      }[view]
    );
  }
  const rows = () => sortedDomains(
    inventory?.domains || [],
    el("domain-filter").value,
    el("sort").value
  );
  function renderInventory() {
    if (!inventory) {
      for (const id of ["stat-size", "stat-count", "stat-shared"])
        el(id).textContent = "—";
      el("inventory-status").textContent = text("等待扫描", "Awaiting scan");
      el("stat-items").textContent = text(
        "扫描后按占用排序",
        "Sorted by size after scanning"
      );
    } else {
      const sum = total(inventory.domains, "bytes", "sizeComplete"), shared = total(
        inventory.categories,
        "unattributedBytes",
        "sizeComplete"
      );
      el("stat-size").textContent = size(sum.value, sum.complete);
      el("stat-shared").textContent = size(shared.value, shared.complete);
      el("stat-count").textContent = String(inventory.domains.length);
      el("stat-items").textContent = text(
        `${inventory.origins.length} 个存储条目`,
        `${inventory.origins.length} storage items`
      );
      el("inventory-status").textContent = `${inventory.report.status === "ok" ? text("扫描完成", "Scan complete") : text("部分结果", "Partial results")} · ${scanTime.toLocaleTimeString(lang === "zh" ? "zh-CN" : "en", { hour: "2-digit", minute: "2-digit" })}`;
    }
    const filtered = rows();
    page = Math.min(page, Math.max(0, Math.ceil(filtered.length / 50) - 1));
    el("empty").hidden = filtered.length > 0;
    el("table-wrap").hidden = !filtered.length;
    el("pagination").hidden = !filtered.length;
    el("empty-title").textContent = inventory ? text(filtered.length ? "" : "没有匹配的网站", "No matching websites") : text("从一次扫描开始", "Start with a scan");
    el("empty-description").textContent = inventory ? text(
      inventory.domains.length ? "试试其他关键词。" : "没有识别到可归属的网站存储。请查看扫描覆盖和读取问题。",
      inventory.domains.length ? "Try another search." : "No attributed site storage was recognized. Review scan coverage and read issues."
    ) : text(
      "连接本地组件后，查看各网站的缓存、数据库和分区存储。",
      "Connect the local component to inspect caches, databases and partitioned storage."
    );
    el("domains").replaceChildren();
    const max = filtered.reduce((n, r) => {
      const v = bytes(r.bytes);
      return v !== null && v > n ? v : n;
    }, 0n);
    for (const row of filtered.slice(page * 50, (page + 1) * 50)) {
      const tr = node(
        "tr",
        null,
        `site-row${selected === row.domain ? " selected" : ""}`
      ), td = node("td"), button = node("button", null, "site-button");
      button.type = "button";
      button.setAttribute(
        "aria-label",
        text(`查看 ${row.domain}`, `Review ${row.domain}`)
      );
      button.disabled = busy;
      button.append(node("span", row.domain, "site-name"));
      button.addEventListener("click", () => {
        if (!busy) {
          selected = row.domain;
          detailPage = 0;
          renderInventory();
          renderDetails();
          if (window2.innerWidth < 930)
            el("detail-content").scrollIntoView?.({
              block: "start",
              behavior: "smooth"
            });
        }
      });
      td.append(button);
      tr.append(td);
      const sizeCell = node("td", null, "align-right size-cell");
      appendText(sizeCell, "strong", size(row.bytes, row.sizeComplete));
      const bar = node("div", null, "size-bar"), fill = node("span");
      const amount = bytes(row.bytes);
      fill.style.width = `${amount !== null && max > 0n ? Number(amount * 100n / max) : 0}%`;
      bar.setAttribute("aria-hidden", "true");
      bar.append(fill);
      sizeCell.append(bar);
      tr.append(
        sizeCell,
        node("td", String(row.storageItemCount), "align-right numeric")
      );
      el("domains").append(tr);
    }
    el("page-label").textContent = text(
      `${filtered.length} 个网站 · 第 ${filtered.length ? page + 1 : 0} / ${Math.ceil(filtered.length / 50)} 页`,
      `${filtered.length} websites · Page ${filtered.length ? page + 1 : 0} / ${Math.ceil(filtered.length / 50)}`
    );
    el("categories").replaceChildren();
    for (const row of inventory?.categories || []) {
      const tr = node("tr");
      tr.append(
        node("td", label(row.subsystem)),
        node("td", size(row.subsystemBytes, row.sizeComplete), "align-right"),
        node(
          "td",
          size(row.unattributedBytes, row.sizeComplete),
          "align-right"
        )
      );
      el("categories").append(tr);
    }
    el("scan-issues").replaceChildren();
    const issues = [
      ...inventory?.report.issues || [],
      ...(inventory?.categories || []).flatMap(
        (r) => (r.issues || []).map((i) => `${label(r.subsystem)}: ${i}`)
      )
    ];
    for (const issue of issues.slice(0, 200))
      el("scan-issues").append(node("li", issue));
    if (issues.length > 200)
      el("scan-issues").append(
        node(
          "li",
          text(
            `另有 ${issues.length - 200} 条读取问题`,
            `${issues.length - 200} additional read issues`
          )
        )
      );
    update();
  }
  function renderDetails() {
    const row = inventory?.domains.find((r) => r.domain === selected);
    el("detail-empty").hidden = !!row;
    el("detail-content").hidden = !row;
    if (!row) return;
    el("detail-domain").textContent = row.domain;
    el("detail-size").textContent = size(row.bytes, row.sizeComplete);
    const details = inventory.origins.filter((r) => r.domain === selected), groups = /* @__PURE__ */ new Map();
    for (const detail of details) {
      if (!groups.has(detail.subsystem)) groups.set(detail.subsystem, []);
      groups.get(detail.subsystem).push(detail);
    }
    el("detail-breakdown").replaceChildren();
    for (const [subsystem, list] of groups) {
      const sum = total(list, "bytes", "complete"), line = node("div", null, "breakdown-row");
      line.append(
        node("span", label(subsystem)),
        node("strong", size(sum.value, sum.complete))
      );
      el("detail-breakdown").append(line);
    }
    el("details").replaceChildren();
    detailPage = Math.min(
      detailPage,
      Math.max(0, Math.ceil(details.length / 50) - 1)
    );
    for (const detail of details.slice(
      detailPage * 50,
      (detailPage + 1) * 50
    )) {
      const item = node("article", null, "storage-item"), head = node("header");
      head.append(
        node("span", label(detail.subsystem)),
        node("strong", size(detail.bytes, detail.complete))
      );
      item.append(head);
      const p = partition(detail);
      appendText(
        item,
        "p",
        p.kind === "embedded" ? text(
          `在 ${p.site} 中嵌入时保存的数据`,
          `Data stored when embedded in ${p.site}`
        ) : p.kind === "cross-site" ? text(
          "同站点来源，包含跨站嵌入上下文",
          "Same-site origin with cross-site ancestor context"
        ) : p.kind === "unknown" ? text(
          "存储分区未识别，保留原始证据",
          "Unrecognized partition; raw evidence retained"
        ) : text("网站自身保存的数据", "Data saved by this website")
      );
      const raw = node("details");
      raw.append(
        node("summary", text("技术明细", "Technical details")),
        node(
          "code",
          `${detail.storageKey}${detail.bucketId != null ? `
bucket ${detail.bucketId} · ${detail.bucketName || "?"}` : ""}`
        )
      );
      item.append(raw);
      el("details").append(item);
    }
    if (details.length > 50) {
      const paging = node("div", null, "pagination");
      paging.append(
        node("span", `${detailPage + 1} / ${Math.ceil(details.length / 50)}`)
      );
      for (const [direction, caption] of [
        [-1, "←"],
        [1, "→"]
      ]) {
        const button = node("button", caption, "icon-button");
        button.type = "button";
        button.setAttribute(
          "aria-label",
          direction < 0 ? text("上一页明细", "Previous details page") : text("下一页明细", "Next details page")
        );
        button.disabled = busy || detailPage + direction < 0 || (detailPage + direction) * 50 >= details.length;
        button.addEventListener("click", () => {
          if (busy) return;
          detailPage += direction;
          renderDetails();
          el("details").scrollTop = 0;
        });
        paging.append(button);
      }
      el("details").append(paging);
    }
    update();
  }
  function clearPlan() {
    plan = null;
    pendingRequest = null;
    for (const input of document2.querySelectorAll('[name="mode"]'))
      input.checked = false;
    el("profile").checked = false;
    el("operation-status").hidden = true;
    update();
  }
  function closeDialog() {
    if (removing) return;
    if (el("review-dialog").open) {
      el("review-dialog").close?.();
      el("review-dialog").removeAttribute("open");
    }
    clearPlan();
    lastFocus?.focus?.();
  }
  function showPlan(value, queued = null, manual = false) {
    plan = manual ? value : validatePlan(value);
    pendingRequest = queued;
    for (const input of document2.querySelectorAll('[name="mode"]'))
      input.checked = false;
    el("profile").checked = false;
    el("operation-status").hidden = true;
    renderPlan();
    lastFocus = document2.activeElement;
    const dialog = el("review-dialog");
    if (!dialog.open) {
      if (dialog.showModal) dialog.showModal();
      else dialog.setAttribute("open", "");
    }
    el("dialog-close").focus();
    update();
  }
  function renderPlan() {
    if (!plan) return;
    const manual = plan.schema === "sweepx.browser_cleanup.manual/v1";
    el("review-source").textContent = pendingRequest ? text("SWEEPX 待确认请求", "PENDING SWEEPX REQUEST") : manual ? text(
      "指定网站 · 无需本地连接",
      "DIRECT CLEARING · NO LOCAL CONNECTION"
    ) : text("已核对的清理计划", "REVIEWED CLEANUP PLAN");
    el("review-domain").textContent = plan.domain;
    el("review-target").textContent = manual ? text(
      "当前浏览器个人资料 · 占用大小未知",
      "Current browser profile · size unknown"
    ) : `${plan.browser} / ${plan.profile}`;
    el("preview").replaceChildren(
      ...plan.origins.map((origin) => node("li", origin))
    );
    el("profile-confirm-label").textContent = manual ? text(
      "我确认在当前个人资料中清理此网站。",
      "I confirm clearing this website in the current profile."
    ) : text(
      `我确认当前浏览器与个人资料是 ${plan.browser} / ${plan.profile}。`,
      `I confirm the current browser and profile are ${plan.browser} / ${plan.profile}.`
    );
    update();
  }
  function request() {
    if (expired())
      throw new Error(
        text(
          "请求已过期，请重新从 SweepX 发起。",
          "Request expired; send a new request from SweepX."
        )
      );
    return removalRequest(plan, mode(), el("profile").checked);
  }
  function update() {
    try {
      request();
      el("remove").disabled = busy || !plan;
    } catch {
      el("remove").disabled = true;
    }
    for (const id of [
      "language",
      "browser",
      "native-profile",
      "connect",
      "scan",
      "domain-filter",
      "sort",
      "direct-site",
      "direct-review",
      "prepare"
    ])
      el(id).disabled = busy;
    for (const input of document2.querySelectorAll('[name="mode"],#profile'))
      input.disabled = busy;
    el("prepare").disabled = busy || !selected || !connected();
    el("poll").disabled = busy || !connected();
    el("disconnect").disabled = !connected() || removing;
    el("cancel").hidden = phase !== "scan";
    el("cancel").disabled = removing;
    el("scan-state").hidden = phase !== "scan";
    el("page-prev").disabled = busy || page === 0;
    el("page-next").disabled = busy || (page + 1) * 50 >= rows().length;
    el("reject").hidden = !pendingRequest;
    el("reject").disabled = busy || !connected() || !!expired();
    el("dialog-close").disabled = removing;
    el("dialog-cancel").disabled = removing;
    for (const button of el("domains").querySelectorAll("button"))
      button.disabled = busy;
    el("review-expiry").hidden = !pendingRequest;
    if (pendingRequest) {
      const isExpired = expired();
      el("review-expiry").classList.toggle("error", !!isExpired);
      el("review-expiry").textContent = isExpired ? text(
        "此请求已过期，未执行清理。请重新发起。",
        "This request expired; nothing was cleared. Send a new request."
      ) : text(
        `有效至 ${new Date(pendingRequest.expiresAt * 1e3).toLocaleTimeString()}`,
        `Valid until ${new Date(pendingRequest.expiresAt * 1e3).toLocaleTimeString()}`
      );
    }
  }
  async function perform(action, nextPhase = "") {
    if (busy) return;
    busy = true;
    phase = nextPhase;
    update();
    try {
      await action();
    } catch (e) {
      say(
        `未确认完成：${e.message}`,
        `Completion not confirmed: ${e.message}`,
        true
      );
    } finally {
      busy = false;
      phase = "";
      update();
    }
  }
  async function connect() {
    const previous = bridge;
    bridge = null;
    previous?.close();
    seenRequest = null;
    connectionSay("正在连接…", "Connecting…");
    requestSay("正在连接并检查请求", "Connecting and checking requests");
    const current = new Bridge(chrome2.runtime, (reason) => {
      if (bridge !== current) return;
      connectionSay("未连接本地组件", "Local component disconnected");
      requestSay(`连接已断开：${reason}`, `Connection closed: ${reason}`);
      update();
    });
    bridge = current;
    try {
      const hello = await current.request("hello");
      if (hello.protocol !== 1) throw new Error("Unsupported bridge version");
      connectionSay(
        `本地组件已连接 · ${hello.hostVersion}`,
        `Local component connected · ${hello.hostVersion}`,
        true
      );
    } catch (e) {
      if (bridge === current) {
        current.close();
        connectionSay("连接失败", "Connection failed");
      }
      throw e;
    }
  }
  async function poll(manual = false) {
    if (!connected() || busy || polling) return;
    if (pendingRequest) {
      update();
      if (!expired()) {
        if (manual) el("dialog-close").focus();
        return;
      }
      if (!manual) return;
    }
    if (plan && !manual) return;
    const currentBridge = bridge, { browser, profile } = selection();
    polling = true;
    const current = () => bridge === currentBridge && !currentBridge.closed && selection().browser === browser && selection().profile === profile;
    try {
      const response = await currentBridge.request("pending", {
        browser,
        profile
      });
      if (!current()) return;
      if (matchingRequest(response.request, browser, profile)) {
        if (manual || response.request.requestId !== seenRequest) {
          seenRequest = response.request.requestId;
          showPlan(response.request.plan, response.request);
          requestSay(
            "收到 SweepX 待确认请求",
            "Pending SweepX request received"
          );
        }
      } else if (response.state === "expired")
        requestSay(
          `${browser} / ${profile}：请求已过期，请重新发起。`,
          `${browser} / ${profile}: Request expired; send a new request.`
        );
      else if (response.state === "different_selection")
        requestSay(
          "待确认请求属于其他浏览器或个人资料，请核对扫描目标。",
          "The pending request targets another browser or profile. Check the scan target."
        );
      else
        requestSay(
          `${browser} / ${profile}：暂无有效待确认请求`,
          `${browser} / ${profile}: No active pending request`
        );
    } catch (e) {
      if (current())
        requestSay(
          `读取待确认请求失败：${e.message}`,
          `Could not check requests: ${e.message}`
        );
    } finally {
      polling = false;
    }
  }
  const handlers = [];
  function on(target, event, handler) {
    target.addEventListener(event, handler);
    handlers.push(() => target.removeEventListener(event, handler));
  }
  for (const button of document2.querySelectorAll("[data-view]"))
    on(button, "click", () => showView(button.dataset.view));
  on(document2.querySelector(".brand"), "click", (event) => {
    event.preventDefault();
    showView("sites");
  });
  on(el("context-settings"), "click", () => showView("settings"));
  on(el("empty-direct"), "click", () => showView("direct"));
  on(el("language"), "change", () => {
    lang = el("language").value;
    remember();
    localize();
  });
  for (const id of ["domain-filter", "sort"])
    on(el(id), id === "sort" ? "change" : "input", () => {
      page = 0;
      renderInventory();
    });
  on(el("page-prev"), "click", () => {
    if (!busy && page > 0) {
      page--;
      renderInventory();
    }
  });
  on(el("page-next"), "click", () => {
    if (!busy && (page + 1) * 50 < rows().length) {
      page++;
      renderInventory();
    }
  });
  on(el("connect"), "click", async () => {
    await perform(async () => {
      closeDialog();
      await connect();
      say(
        "本地组件已连接，可以开始扫描。",
        "Local component connected. Ready to scan."
      );
    });
    await poll();
  });
  on(el("scan"), "click", async () => {
    await perform(async () => {
      closeDialog();
      if (!connected()) await connect();
      say("正在读取本机网站存储…", "Reading local site storage…");
      const data = await bridge.request("scan", selection());
      inventory = data;
      selected = null;
      scanTime = /* @__PURE__ */ new Date();
      page = 0;
      renderInventory();
      renderDetails();
      say(
        data.report.status === "ok" ? "扫描完成。选择网站查看明细。" : "扫描返回部分结果，请查看读取问题。",
        data.report.status === "ok" ? "Scan complete. Select a website for details." : "Scan returned partial results. Review read issues."
      );
    }, "scan");
    await poll();
  });
  function disconnect() {
    bridge?.close();
    connectionSay("未连接本地组件", "Local component disconnected");
    say(
      "已断开连接；未完成的扫描结果已丢弃。原生阻塞调用可能延迟结束。",
      "Disconnected; unfinished scan results discarded. A blocking native call may take longer to stop."
    );
    update();
  }
  on(el("disconnect"), "click", disconnect);
  on(el("cancel"), "click", disconnect);
  on(el("poll"), "click", () => poll(true));
  for (const id of ["browser", "native-profile"])
    on(el(id), "change", () => {
      generation++;
      seenRequest = null;
      closeDialog();
      inventory = null;
      selected = null;
      page = 0;
      remember();
      renderContext();
      renderInventory();
      renderDetails();
      requestSay(
        "扫描目标已改变，请重新检查请求。",
        "Scan target changed; check requests again."
      );
    });
  on(
    el("prepare"),
    "click",
    () => perform(async () => {
      if (!selected) throw new Error("No website selected");
      const response = await bridge.request("plan", {
        ...selection(),
        domain: selected
      });
      showPlan(response.plan);
    })
  );
  on(el("direct-form"), "submit", (event) => {
    event.preventDefault();
    if (busy) return;
    try {
      showPlan(manualSelection(el("direct-site").value), null, true);
    } catch (e) {
      say(`请检查网址：${e.message}`, `Check the website: ${e.message}`, true);
    }
  });
  for (const input of document2.querySelectorAll('[name="mode"],#profile'))
    on(input, "input", update);
  on(el("dialog-close"), "click", closeDialog);
  on(el("dialog-cancel"), "click", closeDialog);
  on(el("review-dialog"), "cancel", (event) => {
    event.preventDefault();
    closeDialog();
  });
  on(
    el("reject"),
    "click",
    () => perform(async () => {
      const queued = pendingRequest;
      if (!queued) return;
      if (expired()) throw new Error("Request expired");
      await bridge.request("complete", {
        request_id: queued.requestId,
        status: "rejected",
        mode: null
      });
      closeDialog();
      requestSay("已拒绝，未清除", "Rejected; nothing removed");
      say(
        "已拒绝 SweepX 请求，未清除任何网站数据。",
        "SweepX request rejected; no website data was cleared."
      );
    })
  );
  on(
    el("remove"),
    "click",
    () => perform(async () => {
      const removal = request(), queued = pendingRequest, chosenMode = mode();
      removing = true;
      update();
      el("operation-status").hidden = false;
      el("operation-status").textContent = text(
        "浏览器正在清理，请保持此页打开…",
        "Browser is clearing data. Keep this page open…"
      );
      try {
        await removeWithBrowser(chrome2.browsingData, removal);
      } catch (e) {
        if (queued && connected()) {
          try {
            await bridge.request("complete", {
              request_id: queued.requestId,
              status: "failed",
              mode: chosenMode
            });
          } catch {
          }
        }
        removing = false;
        closeDialog();
        throw e;
      } finally {
        removing = false;
        update();
      }
      let deliveryZh = "", deliveryEn = "";
      if (queued) {
        try {
          await bridge.request("complete", {
            request_id: queued.requestId,
            status: "browser_completed",
            mode: chosenMode
          });
          deliveryZh = " 已回传 SweepX。";
          deliveryEn = " Reported to SweepX.";
        } catch (e) {
          deliveryZh = ` 回传失败：${e.message}`;
          deliveryEn = ` Report failed: ${e.message}`;
        }
      }
      closeDialog();
      say(
        preview ? "模拟清理完成；未更改真实浏览器数据。" : `浏览器已完成清理请求。请重新扫描验证占用；网站可能重新创建数据。${deliveryZh}`,
        preview ? "Simulation completed; real browser data is unchanged." : `Browser clearing request completed. Rescan to verify usage; sites may recreate data.${deliveryEn}`
      );
    })
  );
  const interval = setInterval(() => {
    update();
    if (!document2.hidden) void poll();
  }, 5e3);
  on(window2, "beforeunload", () => bridge?.close());
  connectionSay("未连接本地组件", "Local component disconnected");
  requestSay("连接后可检查 SweepX 请求。", "Connect to check SweepX requests.");
  localize();
  update();
  return {
    destroy() {
      clearInterval(interval);
      for (const remove of handlers) remove();
      bridge?.close();
    },
    poll,
    update
  };
}
var runtime = globalThis.chrome?.runtime;
if (globalThis.document && runtime?.id === "bcidfcdfefinmefhopannchcnicdopad")
  createApp({ document, window, chrome });
export {
  createApp
};
