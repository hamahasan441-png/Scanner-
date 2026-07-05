/**
 * Tools view — encode/decode/hash + HTTP repeater.
 * Thin UI over the /api/tools/* endpoints.
 */
import { api } from "../core/api.js";
import { h, toast } from "../core/dom.js";

const ENCODINGS = ["url", "base64", "html", "hex", "unicode"];
const ALGOS = ["md5", "sha1", "sha256", "sha512"];

function panel(title, ...children) {
  return h("div", { class: "card tool-panel" }, h("h3", {}, title), ...children);
}

function transformTool() {
  const input = h("textarea", { class: "input", rows: "4", placeholder: "Input…" });
  const output = h("textarea", { class: "input", rows: "4", readonly: true, placeholder: "Result…" });
  const enc = h("select", { class: "input" }, ...ENCODINGS.map((e) => h("option", { value: e }, e)));

  async function run(kind) {
    const data = input.value;
    if (!data) return toast("Enter input", "warn");
    try {
      const res = kind === "encode"
        ? await api.post("/api/tools/encode", { data, encoding: enc.value })
        : await api.post("/api/tools/decode", { data, encoding: enc.value });
      output.value = res.result ?? "";
    } catch (e) {
      toast(e.message || "Failed", "error");
    }
  }

  return panel("Encoder / Decoder",
    input,
    h("div", { class: "field-grid" },
      h("label", {}, "Encoding", enc),
      h("button", { class: "btn", onClick: () => run("encode") }, "Encode"),
      h("button", { class: "btn", onClick: () => run("decode") }, "Smart decode")),
    output);
}

function hashTool() {
  const input = h("textarea", { class: "input", rows: "3", placeholder: "Data to hash…" });
  const output = h("input", { class: "input mono", readonly: true });
  const algo = h("select", { class: "input" }, ...ALGOS.map((a) => h("option", { value: a }, a)));
  async function run() {
    if (!input.value) return toast("Enter data", "warn");
    try {
      const res = await api.post("/api/tools/hash", { data: input.value, algorithm: algo.value });
      output.value = res.result ?? "";
    } catch (e) {
      toast(e.message || "Failed", "error");
    }
  }
  return panel("Hasher", input,
    h("div", { class: "field-grid" }, h("label", {}, "Algorithm", algo), h("button", { class: "btn", onClick: run }, "Hash")),
    output);
}

function repeaterTool() {
  const method = h("select", { class: "input" }, ...["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"].map((m) => h("option", { value: m }, m)));
  const url = h("input", { class: "input", type: "url", placeholder: "https://target/endpoint" });
  const reqBody = h("textarea", { class: "input", rows: "3", placeholder: "Request body (optional)…" });
  const out = h("pre", { class: "code-out" }, "");
  async function send() {
    if (!url.value) return toast("Enter a URL", "warn");
    out.textContent = "Sending…";
    try {
      const res = await api.post("/api/tools/repeater", { method: method.value, url: url.value, body: reqBody.value || undefined });
      out.textContent = `HTTP ${res.status_code}  (${res.elapsed ?? "?"}s, ${res.size ?? "?"} bytes)\n\n` + (res.body || "");
    } catch (e) {
      out.textContent = "Error: " + (e.message || "request failed");
    }
  }
  return panel("HTTP Repeater",
    h("div", { class: "field-grid" }, h("label", {}, "Method", method)),
    url, reqBody,
    h("button", { class: "btn btn-primary", onClick: send }, "Send"),
    out);
}

export function mount(root) {
  root.append(
    h("div", { class: "view-head" }, h("h2", {}, "Tools")),
    h("div", { class: "tools-grid" }, transformTool(), hashTool(), repeaterTool())
  );
}
