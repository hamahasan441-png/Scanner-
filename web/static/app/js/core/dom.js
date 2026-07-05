/**
 * Minimal, XSS-safe DOM helpers.
 *
 * A security scanner renders untrusted data (URLs, payloads, evidence
 * snippets, WAF responses). The legacy dashboard used innerHTML with
 * string concatenation in many places — a self-XSS foot-gun. Here we
 * build nodes with textContent by default; raw HTML is never injected
 * from server data.
 */

/**
 * Create an element.
 * @param {string} tag
 * @param {Object} [attrs]  class, dataset, on<Event> handlers, or attributes.
 * @param {...(Node|string|number|null|Array)} kids
 * @returns {HTMLElement}
 */
export function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else if (k.startsWith("on") && typeof v === "function") {
      el.addEventListener(k.slice(2).toLowerCase(), v);
    } else if (k === "value") el.value = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, kids);
  return el;
}

export function append(el, kids) {
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false || kid === true) continue;
    el.append(kid && kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
}

export function clear(el) {
  if (el) el.replaceChildren();
  return el;
}

export function qs(sel, root = document) {
  return root.querySelector(sel);
}

/** Severity → css modifier + display order weight. */
const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
export function sevKey(sev) {
  return String(sev || "INFO").toUpperCase();
}
export function sevWeight(sev) {
  return SEV_ORDER[sevKey(sev)] ?? 5;
}

export function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

export function relTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso).getTime();
  if (isNaN(d)) return String(iso);
  const s = Math.max(0, (Date.now() - d) / 1000);
  if (s < 60) return `${s | 0}s ago`;
  if (s < 3600) return `${(s / 60) | 0}m ago`;
  if (s < 86400) return `${(s / 3600) | 0}h ago`;
  return `${(s / 86400) | 0}d ago`;
}

let _toastRoot = null;
export function toast(message, type = "info", ttl = 3500) {
  if (!_toastRoot) {
    _toastRoot = h("div", { class: "toast-root", id: "toast-root" });
    document.body.appendChild(_toastRoot);
  }
  const t = h("div", { class: `toast toast-${type}` }, String(message));
  _toastRoot.appendChild(t);
  requestAnimationFrame(() => t.classList.add("show"));
  setTimeout(() => {
    t.classList.remove("show");
    setTimeout(() => t.remove(), 300);
  }, ttl);
}

/** Small spinner/placeholder node. */
export function loading(label = "Loading…") {
  return h("div", { class: "loading" }, h("span", { class: "spinner" }), label);
}

export function emptyState(label = "Nothing here yet") {
  return h("div", { class: "empty-state" }, label);
}
