/**
 * New scan view — launch a single target or a batch.
 * POSTs to /api/scan and routes to the live detail view on success.
 */
import { api } from "../core/api.js";
import { h, toast } from "../core/dom.js";
import { go } from "../core/router.js";

const MODULES = [
  ["sqli", "SQL Injection"],
  ["xss", "XSS"],
  ["lfi", "LFI / Path Traversal"],
  ["cmdi", "Command Injection"],
  ["ssrf", "SSRF"],
  ["ssti", "SSTI"],
  ["xxe", "XXE"],
  ["idor", "IDOR"],
  ["nosql", "NoSQL Injection"],
  ["cors", "CORS"],
  ["jwt", "JWT"],
  ["upload", "File Upload"],
];

export function mount(root) {
  let mode = "single";

  const targetSingle = h("input", { type: "url", placeholder: "https://target.example.com", class: "input", autocomplete: "off" });
  const targetBatch = h("textarea", { class: "input", rows: "6", placeholder: "One URL per line…", style: { display: "none" } });

  const modBoxes = MODULES.map(([key, label]) =>
    h("label", { class: "check" }, h("input", { type: "checkbox", value: key }), label));

  const fullScan = h("input", { type: "checkbox" });
  const autoExploit = h("input", { type: "checkbox" });
  const recon = h("input", { type: "checkbox" });
  const evasion = h("select", { class: "input" },
    ...["none", "low", "medium", "high"].map((v) => h("option", { value: v }, v)));
  const depth = h("input", { type: "number", class: "input", value: "2", min: "1", max: "10" });
  const threads = h("input", { type: "number", class: "input", value: "10", min: "1", max: "100" });

  const submit = h("button", { class: "btn btn-primary", type: "submit" }, "Launch scan");

  const modeBtn = (m, label) =>
    h("button", {
      type: "button",
      class: "seg" + (m === mode ? " active" : ""),
      onClick: (e) => {
        mode = m;
        for (const b of e.target.parentElement.children) b.classList.toggle("active", b === e.target);
        targetSingle.style.display = m === "single" ? "" : "none";
        targetBatch.style.display = m === "single" ? "none" : "";
      },
    }, label);

  const form = h("form", { class: "card scan-form" },
    h("div", { class: "seg-group" }, modeBtn("single", "Single target"), modeBtn("file", "Batch")),
    targetSingle,
    targetBatch,
    h("h4", {}, "Modules"),
    h("div", { class: "mod-grid" }, ...modBoxes),
    h("div", { class: "opt-grid" },
      h("label", { class: "check" }, fullScan, "Full scan (all modules)"),
      h("label", { class: "check" }, autoExploit, "Auto-exploit"),
      h("label", { class: "check" }, recon, "Recon")),
    h("div", { class: "field-grid" },
      h("label", {}, "Evasion", evasion),
      h("label", {}, "Depth", depth),
      h("label", {}, "Threads", threads)),
    submit);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = {
      modules: modBoxes.map((l) => l.querySelector("input")).filter((c) => c.checked).map((c) => c.value),
      full_scan: fullScan.checked,
      auto_exploit: autoExploit.checked,
      recon: recon.checked,
      evasion: evasion.value,
      depth: Number(depth.value) || 2,
      threads: Number(threads.value) || 10,
    };
    if (mode === "single") {
      const t = targetSingle.value.trim();
      if (!t) return toast("Enter a target URL", "error");
      body.target = t;
    } else {
      const list = targetBatch.value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      if (!list.length) return toast("Enter at least one URL", "error");
      body.targets = list;
    }

    submit.disabled = true;
    submit.textContent = "Launching…";
    try {
      const data = await api.post("/api/scan", body);
      const first = data.scan_ids && data.scan_ids[0];
      toast(data.message || "Scan started", "success");
      if (data.skipped && data.skipped.length) toast(`Skipped ${data.skipped.length} invalid URL(s)`, "warn");
      if (first) go(`/scan/${first.scan_id}`);
      else go("/scans");
    } catch (err) {
      toast(err.message || "Failed to start scan", "error");
    } finally {
      submit.disabled = false;
      submit.textContent = "Launch scan";
    }
  });

  root.append(h("div", { class: "view-head" }, h("h2", {}, "New scan")), form);
}
