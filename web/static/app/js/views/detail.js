/**
 * Scan detail view — live pipeline + findings for one scan.
 *
 * Live updates arrive over the WebSocket bus (pipeline_event,
 * pipeline_state, scan_completed). A status poll runs ONLY while the
 * socket is disconnected, so a healthy connection means zero polling.
 */
import { api } from "../core/api.js";
import { bus } from "../core/bus.js";
import { subscribeScan, isWsConnected } from "../core/ws.js";
import { h, clear, loading, emptyState, sevKey, sevWeight, toast } from "../core/dom.js";

const MACRO = ["recon", "scan", "exploit", "collect"];
const MAX_FEED = 300;

export function mount(root, params) {
  const scanId = params[0];
  if (!scanId) {
    root.appendChild(emptyState("No scan id"));
    return;
  }

  const subs = [];
  let pollTimer = null;
  let findingsTimer = null;
  let done = false;

  const phaseBadge = h("span", { class: "pill pill-phase" }, "connecting…");
  const findingsCount = h("span", { class: "pill" }, "0 findings");
  const stages = h("div", { class: "stages" });
  const feed = h("div", { class: "feed" }, loading("Waiting for events…"));
  const findingsBody = h("div", { class: "card" }, loading());

  root.append(
    h("div", { class: "view-head" },
      h("h2", {}, "Scan "), h("span", { class: "mono" }, scanId),
      phaseBadge, findingsCount,
      h("span", { class: "grow" }),
      ...["html", "json", "csv"].map((f) =>
        h("a", { class: "btn btn-sm btn-ghost", href: `/api/report/${scanId}/${f}`, target: "_blank", rel: "noopener" }, `report.${f}`))),
    h("div", { class: "card" }, h("h3", {}, "Pipeline"), stages,
      h("h4", {}, "Live feed"), feed),
    h("div", { class: "view-head" }, h("h3", {}, "Findings")),
    findingsBody
  );

  function renderStages(current) {
    clear(stages);
    const cur = String(current || "").toLowerCase();
    // Map granular phase to a macro stage index when possible.
    const macroIdx = MACRO.indexOf(cur);
    for (let i = 0; i < MACRO.length; i++) {
      const state = macroIdx === -1
        ? (i === 0 ? "active" : "pending")
        : i < macroIdx ? "done" : i === macroIdx ? "active" : "pending";
      stages.appendChild(h("div", { class: `stage stage-${state}` }, MACRO[i]));
    }
    phaseBadge.textContent = current || "—";
  }

  function summarize(ev) {
    const d = ev.data || {};
    const bits = [];
    if (d.phase) bits.push(d.phase);
    if (d.technique) bits.push(d.technique);
    if (d.url) bits.push(d.url);
    if (d.reason) bits.push(d.reason);
    if (d.findings != null) bits.push(`${d.findings} findings`);
    return bits.join(" · ");
  }

  function appendEvent(ev) {
    if (feed.firstChild && feed.firstChild.classList && feed.firstChild.classList.contains("loading")) {
      clear(feed);
    }
    const row = h("div", { class: `feed-row feed-${(ev.type || "").replace(/_/g, "-")}` },
      h("span", { class: "feed-type" }, ev.type || "event"),
      h("span", { class: "feed-desc" }, summarize(ev)));
    feed.appendChild(row);
    while (feed.childElementCount > MAX_FEED) feed.removeChild(feed.firstChild);
    feed.scrollTop = feed.scrollHeight;
    if (ev.type === "finding_new") scheduleFindings();
  }

  function renderFindings(list) {
    clear(findingsBody);
    if (!list || !list.length) {
      findingsBody.appendChild(emptyState("No findings yet"));
      return;
    }
    const sorted = [...list].sort((a, b) => sevWeight(a.severity) - sevWeight(b.severity));
    findingsCount.textContent = `${list.length} findings`;
    const rows = sorted.map((f) =>
      h("tr", {},
        h("td", {}, h("span", { class: `sev-tag sev-${sevKey(f.severity).toLowerCase()}` }, sevKey(f.severity))),
        h("td", {}, f.technique || ""),
        h("td", { class: "mono truncate" }, f.url || ""),
        h("td", {}, f.param || ""),
        h("td", {}, f.confidence != null ? `${Math.round(f.confidence * 100)}%` : ""),
        h("td", {}, f.cvss ? String(f.cvss) : ""))
    );
    findingsBody.appendChild(
      h("table", { class: "data-table" },
        h("thead", {}, h("tr", {}, ...["Severity", "Technique", "URL", "Param", "Conf", "CVSS"].map((t) => h("th", {}, t)))),
        h("tbody", {}, ...rows)));
  }

  async function loadFindings() {
    try {
      const list = await api.get(`/api/findings/${scanId}`);
      renderFindings(list);
    } catch (e) {
      clear(findingsBody);
      findingsBody.appendChild(emptyState("Findings unavailable"));
    }
  }
  function scheduleFindings() {
    clearTimeout(findingsTimer);
    findingsTimer = setTimeout(() => {
      api.invalidate(`/api/findings/${scanId}`);
      loadFindings();
    }, 800);
  }

  async function loadStatus() {
    try {
      const info = await api.get(`/api/scan/${scanId}/status`);
      if (info) {
        const phase = (info.pipeline && info.pipeline.phase) || info.status;
        renderStages(phase);
        if (info.findings != null) findingsCount.textContent = `${info.findings} findings`;
        if (info.status === "completed" || phase === "done") stopPolling();
      }
    } catch (e) {
      /* scan may not be active; findings still load below */
    }
  }

  function startPolling() {
    if (pollTimer || done) return;
    pollTimer = setInterval(() => {
      if (isWsConnected()) return; // socket recovered → let events drive
      loadStatus();
    }, 3000);
  }
  function stopPolling() {
    done = true;
    clearInterval(pollTimer);
    pollTimer = null;
  }

  // Live wiring.
  subs.push(bus.on("ws:pipeline_state", (st) => {
    if (st && st.scan_id === scanId) {
      renderStages(st.phase);
      if (st.findings_count != null) findingsCount.textContent = `${st.findings_count} findings`;
    }
  }));
  subs.push(bus.on("ws:pipeline_event", (ev) => ev && appendEvent(ev)));
  subs.push(bus.on("ws:scan_completed", (d) => {
    if (!d || d.scan_id === scanId) {
      renderStages("done");
      stopPolling();
      scheduleFindings();
    }
  }));
  subs.push(bus.on("ws:status", ({ connected }) => {
    if (connected) subscribeScan(scanId);
  }));

  // Initial paint.
  renderStages("recon");
  subscribeScan(scanId);
  loadStatus();
  loadFindings();
  startPolling();

  return () => {
    subs.forEach((off) => off());
    clearInterval(pollTimer);
    clearTimeout(findingsTimer);
  };
}
