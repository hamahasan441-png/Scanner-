/**
 * Overview view — KPI cards + live active-scan list.
 * Fully WebSocket-driven: no polling. Falls back to a single stats
 * fetch on mount; live counts arrive via the bus.
 */
import { api } from "../core/api.js";
import { bus } from "../core/bus.js";
import { h, clear, loading, emptyState, relTime, sevKey } from "../core/dom.js";
import { go } from "../core/router.js";

const SEVS = ["critical", "high", "medium", "low", "info"];

export function mount(root) {
  const subs = [];
  const active = new Map(); // scan_id -> info

  const cards = h("div", { class: "kpi-grid" });
  const activeWrap = h("div", { class: "card" }, h("h3", {}, "Active scans"));
  const activeList = h("div", { class: "active-list" }, loading());
  activeWrap.appendChild(activeList);

  root.append(
    h("div", { class: "view-head" }, h("h2", {}, "Overview")),
    cards,
    activeWrap
  );

  function renderCards(stats) {
    clear(cards);
    const kpi = (label, value, mod) =>
      h("div", { class: `kpi ${mod || ""}` },
        h("div", { class: "kpi-value" }, String(value ?? 0)),
        h("div", { class: "kpi-label" }, label));
    cards.append(
      kpi("Total scans", stats.total_scans),
      kpi("Findings", stats.total_findings),
      kpi("Active", stats.active_scans, "kpi-active"),
      kpi("Critical", stats.critical, "sev-critical"),
      kpi("High", stats.high, "sev-high"),
      kpi("Medium", stats.medium, "sev-medium"),
      kpi("Low", stats.low, "sev-low"),
      kpi("Info", stats.info, "sev-info")
    );
  }

  function renderActive() {
    clear(activeList);
    if (active.size === 0) {
      activeList.appendChild(emptyState("No scans running"));
      return;
    }
    const frag = document.createDocumentFragment();
    for (const [id, info] of active) {
      frag.appendChild(
        h("div", { class: "active-row", onClick: () => go(`/scan/${id}`) },
          h("span", { class: "mono" }, id),
          h("span", { class: "grow" }, info.target || ""),
          h("span", { class: "pill" }, `${info.findings ?? 0} findings`),
          h("span", { class: "muted" }, relTime(info.start_time)))
      );
    }
    activeList.appendChild(frag);
  }

  let statsTimer = null;
  async function refreshStats() {
    try {
      const stats = await api.get("/api/stats", { cache: true, ttl: 1500 });
      renderCards(stats);
    } catch (e) {
      clear(cards);
      cards.appendChild(emptyState("Stats unavailable"));
    }
  }
  function scheduleStats() {
    clearTimeout(statsTimer);
    statsTimer = setTimeout(() => {
      api.invalidate("/api/stats");
      refreshStats();
    }, 400);
  }

  // Live wiring.
  subs.push(bus.on("ws:active_scans", (map) => {
    active.clear();
    for (const [id, info] of Object.entries(map || {})) active.set(id, info);
    renderActive();
  }));
  subs.push(bus.on("ws:scan_started", (d) => {
    if (d && d.scan_id) active.set(d.scan_id, d);
    renderActive();
    scheduleStats();
  }));
  subs.push(bus.on("ws:scan_completed", (d) => {
    if (d && d.scan_id) active.delete(d.scan_id);
    renderActive();
    scheduleStats();
  }));

  refreshStats();
  renderActive();

  return () => {
    clearTimeout(statsTimer);
    subs.forEach((off) => off());
  };
}

export { sevKey, SEVS };
