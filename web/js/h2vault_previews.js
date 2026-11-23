// H2Vault (AGPL-3.0). New for H2Vault (owner 2026-11-23: previews from inside a vault, shown on the vault node).
//
// The server (nodes/previews.py) re-addresses every preview an inner node produces to the VAULT node and merges them:
//   output.images        still / animated images -> core's own image preview draws them (both renderers); untouched here
//   output.h2v_previews  every item, labelled ("Preview 1" or the author's label), never an inner name or type
// This widget shows what core has no generic renderer for - videos (VHS Video Combine, Save Video), audio, text - and
// one line per label saying what it showed. It also shows live sampler frames from KJNodes' Model Preview Override when
// that node runs inside a vault (its own panel exists only on its own node). Live latent previews from core samplers
// need nothing here: core draws them on the vault (their metadata names the vault).
//
// The panel is a display-only DOM widget (never saved: serialize = false), created on the first preview, so the saved
// widget order [vault_id, vault_payload, p_* ...] never moves.
import { app } from "../../scripts/app.js";
import { api } from "../../scripts/api.js";
import { tagDomWidget } from "./_h2v_rebind.js";
import { plan, viewPath } from "./_h2v_previews_core.js";

const VAULT_TYPES = new Set(["H2Vault_ProtectedSubgraph", "H2Vault_ProtectedSubgraphOutput"]);
const WIDGET = "vault_previews";
const MAX_H = 460;

const isVault = (node) => VAULT_TYPES.has(node?.comfyClass ?? node?.type);

function el(tag, attrs = {}, kids = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "text") e.textContent = v;
    else if (k === "style") Object.assign(e.style, v);
    else e.setAttribute(k, v);
  }
  for (const c of kids) if (c) e.append(c);
  return e;
}

const viewUrl = (f) => api.apiURL(viewPath(f));

function ensureStyles() {
  if (document.getElementById("h2v-previews-css")) return;
  const css = `
.h2v-pv{box-sizing:border-box;width:100%;max-height:${MAX_H}px;overflow:auto;padding:6px 8px;border-radius:8px;
  background:var(--comfy-input-bg,#1e1e24);color:var(--input-text,#ddd);font:12px/1.35 system-ui,sans-serif}
.h2v-pv__head{display:flex;justify-content:space-between;gap:8px;opacity:.8;margin-bottom:4px}
.h2v-pv__rows{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:6px}
.h2v-pv__chip{padding:1px 7px;border-radius:999px;background:rgba(127,127,127,.18);white-space:nowrap}
.h2v-pv__item{margin:6px 0}
.h2v-pv__cap{opacity:.75;margin-bottom:2px}
.h2v-pv video,.h2v-pv img{display:block;max-width:100%;max-height:300px;border-radius:6px;background:#000}
.h2v-pv audio{width:100%}
.h2v-pv pre{margin:0;white-space:pre-wrap;word-break:break-word;max-height:160px;overflow:auto;
  background:rgba(0,0,0,.22);padding:4px 6px;border-radius:6px;font:11px/1.35 ui-monospace,monospace}
.h2v-pv__note{opacity:.75;font-style:italic}`;
  document.head.append(el("style", { id: "h2v-previews-css", text: css }));
}

function ensurePanel(node) {
  ensureStyles();
  let w = node.widgets?.find((x) => x.name === WIDGET);
  if (w) return w;
  if (typeof node.addDOMWidget !== "function") return null;
  const root = el("div", { class: "h2v h2v-pv", "data-h2v-previews": "1" });
  for (const ev of ["pointerdown", "mousedown", "wheel"]) root.addEventListener(ev, (e) => e.stopPropagation(), { passive: true });
  w = node.addDOMWidget(WIDGET, WIDGET, root, { serialize: false, margin: 4,
    getMinHeight: () => Math.min(MAX_H, root.__h || 40), getHeight: () => Math.min(MAX_H, root.__h || 40) });
  w.serialize = false;
  w.computeSize = (width) => [width, Math.min(MAX_H, root.__h || 40) + 8];
  w.__root = root;
  w.__final = el("div");
  w.__live = el("div");
  root.append(w.__live, w.__final);
  try { tagDomWidget(w); } catch (_) { /* Nodes 2.0 rebind tag is a nicety */ }
  return w;
}

function relayout(node, w) {
  const root = w.__root;
  requestAnimationFrame(() => {
    // the content's height (scrollHeight never shrinks below the height the frontend gave the element)
    root.__h = Math.min(MAX_H, Math.max(40, (w.__live.offsetHeight || 0) + (w.__final.offsetHeight || 0) + 14));
    // Nodes 2.0 sizes the node from its content; setSize there only adds blank space (frontend-engineering rules)
    if (!globalThis.LiteGraph?.vueNodesMode) {
      try {
        const want = node.computeSize?.();
        if (want && node.size && node.size[1] < want[1]) node.setSize([Math.max(node.size[0], want[0]), want[1]]);
      } catch (_) { /* sizing is best effort */ }
    }
    node.setDirtyCanvas?.(true, true);
  });
}

function mediaEl(m, onLoad) {
  if (m.kind === "video") {
    const v = el("video", { controls: "", loop: "", muted: "", autoplay: "", playsinline: "", preload: "metadata" });
    v.muted = true;
    v.src = m.url;
    v.addEventListener("loadedmetadata", onLoad, { once: true });
    return v;
  }
  if (m.kind === "audio") return el("audio", { controls: "", preload: "metadata", src: m.url });
  if (m.kind === "image") {
    const i = el("img", { alt: m.label, src: m.url });
    i.addEventListener("load", onLoad, { once: true });
    return i;
  }
  return el("pre", { text: m.text });
}

export function showPreviews(node, output) {
  if (!isVault(node) || !Array.isArray(output?.h2v_previews)) return;
  const w = ensurePanel(node);
  if (!w) return;
  const p = plan(output, viewUrl);
  const box = w.__final;
  const head = el("div", { class: "h2v-pv__head" }, [el("span", { text: "Previews from inside" }),
    el("span", { text: `${p.count} item${p.count === 1 ? "" : "s"}` })]);
  const rows = el("div", { class: "h2v-pv__rows" }, p.rows.map((r) => el("span", { class: "h2v-pv__chip",
    text: `${r.label} · ${r.text}` })));
  const kids = [head, rows];
  const again = () => relayout(node, w);
  for (const m of p.media) {
    kids.push(el("div", { class: "h2v-pv__item" }, [el("div", { class: "h2v-pv__cap", text: m.label }), mediaEl(m, again)]));
  }
  for (const n of p.notes) kids.push(el("div", { class: "h2v-pv__note", text: n }));
  box.replaceChildren(...kids);
  w.__live.replaceChildren();                                  // the results replace the live frame
  relayout(node, w);
}

// ── KJNodes ModelPreviewOverrideKJ inside a vault: its live frames name the vault (display id) ──────────────────
function nodeByExecId(id) {
  const parts = String(id).split(":");
  let g = app.rootGraph ?? app.graph;
  for (let i = 0; i < parts.length - 1; i++) {
    const n = g?.getNodeById?.(Number(parts[i]));
    if (!n?.subgraph) return null;
    g = n.subgraph;
  }
  return g?.getNodeById?.(Number(parts[parts.length - 1])) ?? null;
}

const LIVE_URLS = new WeakMap();

export function showLive(node, d) {
  if (!isVault(node) || node._kjPreviewHandler || !d?.image) return;
  const w = ensurePanel(node);
  if (!w) return;
  let url;
  try {
    const bin = atob(d.image);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    url = URL.createObjectURL(new Blob([arr], { type: d.mime || "image/jpeg" }));
  } catch (_) { return; }
  const old = LIVE_URLS.get(node);
  if (old) URL.revokeObjectURL(old);
  LIVE_URLS.set(node, url);
  const isVideo = String(d.mime || "").startsWith("video/");
  const media = isVideo ? el("video", { autoplay: "", loop: "", muted: "", playsinline: "" }) : el("img", { alt: "Live preview" });
  if (isVideo) media.muted = true;
  media.src = url;
  const step = Number.isFinite(d.step) && Number.isFinite(d.total) && d.total > 0 ? ` · step ${d.step}/${d.total}` : "";
  w.__live.replaceChildren(el("div", { class: "h2v-pv__item" }, [el("div", { class: "h2v-pv__cap",
    text: `Live preview${step}` }), media]));
  relayout(node, w);
}

function clearLive() {
  for (const g of [app.rootGraph ?? app.graph]) {
    const walk = (graph) => {
      for (const n of graph?._nodes || graph?.nodes || []) {
        if (n.subgraph) walk(n.subgraph);
        if (!isVault(n)) continue;
        const w = n.widgets?.find((x) => x.name === WIDGET);
        if (w?.__live?.childNodes.length) { w.__live.replaceChildren(); relayout(n, w); }
      }
    };
    walk(g);
  }
}

if (!globalThis.__h2vPreviews) {
  globalThis.__h2vPreviews = true;
  app.registerExtension({
    name: "H2Vault.Previews",
    setup() {
      api.addEventListener("kj_preview_override", (e) => {
        const d = e?.detail;
        if (d?.node_id == null) return;
        const node = nodeByExecId(d.node_id);
        if (node) showLive(node, d);
      });
      api.addEventListener("execution_start", clearLive);        // a live frame stays until the next run / results
    },
    async beforeRegisterNodeDef(nodeType, nodeData) {
      if (!VAULT_TYPES.has(nodeData?.name)) return;
      const executed = nodeType.prototype.onExecuted;
      nodeType.prototype.onExecuted = function (output) {
        const r = executed?.apply(this, arguments);
        try { showPreviews(this, output); } catch (err) { console.warn("[H2Vault] preview panel:", err); }
        return r;
      };
    },
  });
}
