/**
 * Hash-based router with lazy (code-split) view loading.
 *
 * Each route maps to a loader that dynamically `import()`s the view
 * module only when first visited, so the initial payload stays tiny and
 * heavy views (scan detail, tools) never cost anything until used.
 *
 * A view module exports:
 *   export function mount(root, params) -> optional cleanup function
 *
 * The returned cleanup (or an exported `destroy`) is invoked on
 * navigation so listeners/timers/bus subscriptions are released.
 */

/** @type {Map<string, {label:string, icon:string, loader:()=>Promise<any>, nav:boolean}>} */
const routes = new Map();
let outlet = null;
let current = { destroy: null, name: null };
let onChange = null;

export function register(name, def) {
  routes.set(name, { nav: true, icon: "", label: name, ...def });
}

export function setOutlet(el) {
  outlet = el;
}

export function onRouteChange(fn) {
  onChange = fn;
}

export function navItems() {
  return [...routes.entries()]
    .filter(([, d]) => d.nav)
    .map(([name, d]) => ({ name, label: d.label, icon: d.icon }));
}

export function go(hash) {
  location.hash = hash.startsWith("#") ? hash : "#" + hash;
}

function parse() {
  // #/name/arg  ->  { name, params:[arg] }
  const raw = (location.hash || "#/").replace(/^#\/?/, "");
  const [name, ...params] = raw.split("/").filter(Boolean);
  return { name: name || "overview", params };
}

async function resolve() {
  const { name, params } = parse();
  const def = routes.get(name) || routes.get("overview");

  // Tear down previous view.
  if (current.destroy) {
    try {
      current.destroy();
    } catch (e) {
      console.error("[router] destroy failed:", e);
    }
    current = { destroy: null, name: null };
  }
  if (outlet) outlet.replaceChildren();

  if (!def) return;

  try {
    const mod = await def.loader();
    const cleanup = mod.mount ? mod.mount(outlet, params) : null;
    current = {
      name,
      destroy: typeof cleanup === "function" ? cleanup : mod.destroy || null,
    };
  } catch (e) {
    console.error(`[router] failed to load view "${name}":`, e);
    if (outlet) {
      outlet.replaceChildren();
      const div = document.createElement("div");
      div.className = "empty-state";
      div.textContent = "Failed to load this view.";
      outlet.appendChild(div);
    }
  }

  if (onChange) onChange(name);
}

export function start() {
  window.addEventListener("hashchange", resolve);
  resolve();
}

export function currentName() {
  return current.name;
}
