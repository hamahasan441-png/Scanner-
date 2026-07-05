/**
 * Dashboard bootstrap.
 *
 * Registers lazy-loaded routes, builds the nav, opens the single
 * WebSocket connection and reflects live status/active-scan counts in
 * the chrome. Keeping this file tiny means the browser parses almost
 * nothing before first paint; views stream in on demand.
 */
import { api } from "./core/api.js";
import { bus } from "./core/bus.js";
import { initWs } from "./core/ws.js";
import { h } from "./core/dom.js";
import * as router from "./core/router.js";

// Route table — loaders are dynamic imports (code-split per view).
router.register("overview", { label: "Overview", icon: "◎", loader: () => import("./views/overview.js") });
router.register("new", { label: "New scan", icon: "＋", loader: () => import("./views/newscan.js") });
router.register("scans", { label: "Scans", icon: "▤", loader: () => import("./views/scans.js") });
router.register("tools", { label: "Tools", icon: "⚙", loader: () => import("./views/tools.js") });
// Detail is reachable via #/scan/<id> but hidden from the nav.
router.register("scan", { label: "Scan", icon: "", nav: false, loader: () => import("./views/detail.js") });

function buildChrome() {
  const wsDot = h("span", { class: "ws-dot ws-off", id: "ws-dot", title: "WebSocket" });
  const activeBadge = h("span", { class: "nav-badge hidden", id: "active-badge" }, "0");

  const navLinks = router.navItems().map((it) =>
    h("a", { class: "nav-link", href: `#/${it.name}`, "data-route": it.name },
      h("span", { class: "nav-ico" }, it.icon), it.label,
      it.name === "overview" ? activeBadge : null));

  const sidebar = h("aside", { class: "sidebar" },
    h("div", { class: "brand" }, h("span", { class: "brand-mark" }, "⚛"), h("span", {}, "ATOMIC")),
    h("nav", { class: "nav" }, ...navLinks),
    h("div", { class: "sidebar-foot" },
      wsDot, h("span", { class: "muted", id: "ws-label" }, "offline"),
      h("a", { class: "muted legacy-link", href: "/legacy" }, "Legacy UI")));

  const outlet = h("main", { class: "outlet", id: "outlet" });
  const shell = h("div", { class: "shell" }, sidebar, outlet);
  document.body.appendChild(shell);
  router.setOutlet(outlet);

  router.onRouteChange((name) => {
    for (const a of navLinks) a.classList.toggle("active", a.dataset.route === name);
  });

  // WebSocket status indicator.
  bus.on("ws:status", ({ connected, available }) => {
    wsDot.className = "ws-dot " + (connected ? "ws-on" : available ? "ws-off" : "ws-na");
    const label = document.getElementById("ws-label");
    if (label) label.textContent = connected ? "live" : available ? "reconnecting…" : "polling";
  });

  // Active-scan badge from live events.
  const active = new Set();
  const paint = () => {
    activeBadge.textContent = String(active.size);
    activeBadge.classList.toggle("hidden", active.size === 0);
  };
  bus.on("ws:active_scans", (m) => { active.clear(); Object.keys(m || {}).forEach((k) => active.add(k)); paint(); });
  bus.on("ws:scan_started", (d) => { if (d && d.scan_id) active.add(d.scan_id); paint(); });
  bus.on("ws:scan_completed", (d) => { if (d && d.scan_id) active.delete(d.scan_id); paint(); });
}

function boot() {
  buildChrome();
  // Prime the CSRF cookie so the first POST doesn't round-trip.
  api.get("/api/csrf-token").catch(() => {});
  initWs();
  router.start();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}
