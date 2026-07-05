/**
 * Scans view — history table with report download + delete.
 */
import { api } from "../core/api.js";
import { h, clear, loading, emptyState, fmtTime, toast } from "../core/dom.js";
import { go } from "../core/router.js";

const FORMATS = ["html", "json", "csv", "txt"];

export function mount(root) {
  const body = h("div", { class: "card" }, loading());
  root.append(
    h("div", { class: "view-head" },
      h("h2", {}, "Scans"),
      h("button", { class: "btn", onClick: () => go("/new") }, "+ New scan")),
    body
  );

  async function load() {
    clear(body);
    body.appendChild(loading());
    let scans;
    try {
      scans = await api.get("/api/scans", { cache: true, ttl: 2000 });
    } catch (e) {
      clear(body);
      body.appendChild(emptyState("Could not load scans"));
      return;
    }
    clear(body);
    if (!scans || !scans.length) {
      body.appendChild(emptyState("No scans yet — launch one from “New scan”."));
      return;
    }

    const rows = scans.map((s) =>
      h("tr", {},
        h("td", { class: "mono", onClick: () => go(`/scan/${s.scan_id}`), style: { cursor: "pointer" } }, s.scan_id),
        h("td", {}, s.target || ""),
        h("td", {}, String(s.findings_count ?? 0)),
        h("td", {}, String(s.total_requests ?? 0)),
        h("td", { class: "muted" }, fmtTime(s.start_time)),
        h("td", { class: "row-actions" },
          h("button", { class: "btn btn-sm", onClick: () => go(`/scan/${s.scan_id}`) }, "View"),
          ...FORMATS.map((f) =>
            h("a", { class: "btn btn-sm btn-ghost", href: `/api/report/${s.scan_id}/${f}`, target: "_blank", rel: "noopener" }, f)),
          h("button", { class: "btn btn-sm btn-danger", onClick: () => remove(s.scan_id) }, "Delete")))
    );

    const table = h("table", { class: "data-table" },
      h("thead", {}, h("tr", {},
        h("th", {}, "ID"), h("th", {}, "Target"), h("th", {}, "Findings"),
        h("th", {}, "Requests"), h("th", {}, "Started"), h("th", {}, "Actions"))),
      h("tbody", {}, ...rows));
    body.appendChild(table);
  }

  async function remove(id) {
    if (!confirm(`Delete scan ${id}?`)) return;
    try {
      await api.del(`/api/scan/${id}`);
      api.invalidate("/api/scans");
      toast("Scan deleted", "success");
      load();
    } catch (e) {
      toast(e.message || "Delete failed", "error");
    }
  }

  load();
}
