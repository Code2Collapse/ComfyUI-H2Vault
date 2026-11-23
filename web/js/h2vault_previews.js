// H2Vault (AGPL-3.0). New for H2Vault (owner 2026-11-23: previews from inside a vault, shown on the vault node);
// extended into the full preview viewer (owner 2026-11-24, PART 3, L9.342).
//
// The server (nodes/previews.py) re-addresses every preview an inner node produces to the VAULT node and merges them:
//   output.images        core's image entries (kept for older front ends and the history; this panel shows them)
//   output.h2v_previews  every item, labelled ("Preview 1" or the author's label), never an inner name or type
// This panel is the vault's ONE viewer: images (navigation, fit / zoom, large view, animated GIF / WebP), a real video
// player (./_h2v_player.js), audio, text, and the LIVE sampler frames while the inside runs. Core's own image preview
// and its live latent preview are kept off the vault node (they drew everything a second time). The api's dispatch is
// wrapped (see setup(): core's listeners are registered first and run first, a capture listener does not help):
//   * `executed` carrying a vault's merge: `images` / `animated` are removed before core sees them, so core stores
//     nothing to draw; onExecuted still gets everything.
//   * `b_preview_with_metadata` naming a vault (the server maps the inner sampler's ids to the vault): the frame goes to
//     this panel. Trade-off: a vault on the root graph gives core no frame, so the job queue's thumbnail of a running
//     vault job shows none (the frame is on the vault node); a vault inside a subgraph gives core the frame re-addressed
//     to its subgraph node.
// Live sources (adapters): core samplers (KSampler, KSamplerAdvanced, SamplerCustom*, anything using core's progress
// preview) via b_preview_with_metadata; servers / clients without metadata via the legacy `b_preview` (attributed to
// the vault that runs); KJNodes Model Preview Override via `kj_preview_override` (its own panel exists only on its
// own node); Video Helper Suite's animated latent preview format (VHS samplers, KJNodes' LTX2 preview override): drawn
// by VHS itself when its "animated previews" setting is on (the panel then only says so), else shown by the panel.
// Steps: `progress` (and `progress_state` as fallback). Captions are neutral: never a node name, a class, a pack name
// or an id.
//
// The panel is a display-only DOM widget (never saved: serialize = false), created on the first preview, so the saved
// widget order [vault_id, vault_payload, p_* ...] never moves. Nothing of it is persisted.
import { app } from "../../scripts/app.js";
import { api } from "../../scripts/api.js";
import { tagDomWidget } from "./_h2v_rebind.js";
import { plan, viewPath } from "./_h2v_previews_core.js";
import { createLive, createViewer } from "./_h2v_player_core.js";
import { createImageViewer, createVideoPlayer, ensurePlayerStyles, openLightbox } from "./_h2v_player.js";

const VAULT_TYPES = new Set(["H2Vault_ProtectedSubgraph", "H2Vault_ProtectedSubgraphOutput"]);
const WIDGET = "vault_previews";
const MAX_H = 760;
const STAGE_H = 300;
const KIND_WORD = { image: "image", video: "video", audio: "audio clip", text: "text" };
const PANELS = new Set();                                         // the panels that exist (never a graph walk)

const isVault = (node) => VAULT_TYPES.has(node?.comfyClass ?? node?.type);

function el(tag, attrs = {}, kids = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null) continue;
    if (k === "text") e.textContent = v;
    else if (k === "style") Object.assign(e.style, v);
    else e.setAttribute(k, v);
  }
  for (const c of kids) if (c) e.append(c);
  return e;
}

const viewUrl = (f) => api.apiURL(viewPath(f));

function ensureStyles() {
  ensurePlayerStyles();
  if (document.getElementById("h2v-previews-css")) return;
  const css = `
.h2v-pv{box-sizing:border-box;width:100%;max-height:${MAX_H}px;overflow:auto;padding:6px 8px;border-radius:8px;
  background:var(--comfy-input-bg,#1e1e24);color:var(--input-text,#ddd);font:12px/1.35 system-ui,sans-serif}
.h2v-pv__head{display:flex;justify-content:space-between;gap:8px;opacity:.8;margin-bottom:4px}
.h2v-pv__rows{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:6px}
.h2v-pv__chip{padding:1px 7px;border-radius:999px;background:rgba(127,127,127,.18);white-space:nowrap;border:1px solid
  transparent;color:inherit;font:inherit;cursor:pointer}
.h2v-pv__chip[aria-current="true"]{border-color:rgba(120,170,255,.8)}
.h2v-pv__chip:focus-visible,.h2v-pv__nav button:focus-visible{outline:2px solid #6aa0ff;outline-offset:1px}
.h2v-pv__nav{display:flex;align-items:center;gap:6px;margin:2px 0 6px}
.h2v-pv__nav button{min-width:26px;height:24px;border-radius:6px;border:1px solid var(--border-color,#444);
  background:var(--comfy-menu-bg,#2a2a30);color:inherit;cursor:pointer}
.h2v-pv__cap{opacity:.8;margin-bottom:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.h2v-pv__navcap{flex:1 1 auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.h2v-pv__live{margin-bottom:8px}
.h2v-pv__livehead{display:flex;justify-content:space-between;gap:8px;opacity:.85;margin-bottom:2px}
.h2v-pv__prog{height:3px;border-radius:2px;background:rgba(127,127,127,.25);margin-bottom:4px;overflow:hidden}
.h2v-pv__prog>div{height:100%;width:0;background:#6aa0ff;transition:width .15s}
.h2v-pv__liveimg{display:block;width:100%;max-height:${STAGE_H}px;object-fit:contain;border-radius:6px;background:#000}
.h2v-pv__audio{width:100%}
.h2v-pv pre{margin:0;white-space:pre-wrap;word-break:break-word;max-height:200px;overflow:auto;
  background:rgba(0,0,0,.22);padding:4px 6px;border-radius:6px;font:11px/1.35 ui-monospace,monospace}
.h2v-pv__note{opacity:.75;font-style:italic;margin-top:4px}`;
  document.head.append(el("style", { id: "h2v-previews-css", text: css }));
}

// ── the panel ──────────────────────────────────────────────────────────────────────────────────────────────────
function disposePanel(w) {
  try { w.__cur?.inst?.destroy?.(); } catch (_) { /* ignore */ }
  w.__cur = null;
  try { w.__lightbox?.close(); } catch (_) { /* ignore */ }
  const old = w.__liveModel?.clear();
  if (old) URL.revokeObjectURL(old);
  PANELS.delete(w);
}

function ensurePanel(node) {
  ensureStyles();
  let w = node.widgets?.find((x) => x.name === WIDGET);
  if (w) return w;
  if (typeof node.addDOMWidget !== "function") return null;
  const root = el("div", { class: "h2v h2v-pv", "data-h2v-previews": "1" });
  for (const ev of ["pointerdown", "mousedown"]) root.addEventListener(ev, (e) => e.stopPropagation(), { passive: true });
  // keys typed while the viewer has focus stay in the viewer: Delete / Backspace must never reach the graph (it would
  // delete the selected vault); shortcuts with Ctrl / Cmd / Alt (save, queue, ...) and Escape / Tab pass
  root.addEventListener("keydown", (e) => {
    if (!e.ctrlKey && !e.metaKey && !e.altKey && e.key !== "Escape" && e.key !== "Tab") e.stopPropagation();
  });
  w = node.addDOMWidget(WIDGET, WIDGET, root, { serialize: false, margin: 4,
    getMinHeight: () => Math.min(MAX_H, root.__h || 40), getHeight: () => Math.min(MAX_H, root.__h || 40) });
  w.serialize = false;
  w.computeSize = (width) => [width, Math.min(MAX_H, root.__h || 40) + 8];
  w.__root = root;
  w.__live = el("div", { class: "h2v-pv__live" });
  w.__final = el("div");
  w.__viewer = createViewer();
  w.__liveModel = createLive();
  w.__node = node;
  root.append(w.__live, w.__final);
  try { tagDomWidget(w); } catch (_) { /* Nodes 2.0 rebind tag is a nicety */ }
  PANELS.add(w);
  const removed = node.onRemoved;
  node.onRemoved = function () {
    try { disposePanel(w); } catch (_) { /* ignore */ }
    return removed?.apply(this, arguments);
  };
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

// ── results: navigation + one stage per kind ──────────────────────────────────────────────────────────────────
function caption(e) {
  if (!e) return "";
  const word = KIND_WORD[e.kind] || e.kind;
  return e.of > 1 ? `${e.label} · ${word} ${e.n} of ${e.of}` : `${e.label} · ${word}`;
}

function openLarge(w, e) {
  const imgs = w.__viewer.entries.filter((x) => x.kind === "image");
  const images = imgs.map((x) => ({ url: x.url, label: caption(x), name: x.name, animated: x.animated }));
  w.__lightbox = openLightbox({ title: "Previews from inside", images, index: Math.max(0, imgs.indexOf(e)),
    onClose: () => { w.__lightbox = null; } });
}

function buildStage(w, e) {
  if (e.kind === "image") return createImageViewer(e, { height: STAGE_H, onLarge: () => openLarge(w, e) });
  if (e.kind === "video") {
    return createVideoPlayer(e, w.__viewer.stateOf(e.key), { height: STAGE_H,
      onState: (s) => w.__viewer.saveState(e.key, s),
      onInspect: (img) => { w.__lightbox = openLightbox({ title: img.title, images: [img],
        onClose: () => { w.__lightbox = null; } }); } });
  }
  if (e.kind === "audio") {
    const a = el("audio", { class: "h2v-pv__audio", controls: "", preload: "metadata", "aria-label": e.label });
    a.src = e.url;
    a.addEventListener("pointerdown", (x) => x.stopPropagation());
    return { el: a, destroy() { a.pause(); a.removeAttribute("src"); try { a.load(); } catch (_) { /* ignore */ } } };
  }
  const pre = el("pre", { text: e.text });
  const copy = el("button", { type: "button", class: "h2v-pl__btn", text: "Copy", "aria-label": "Copy the text" });
  copy.addEventListener("click", async (x) => {
    x.stopPropagation();
    try { await navigator.clipboard.writeText(e.text); copy.textContent = "Copied"; } catch (_) { copy.textContent = "Copy failed"; }
    setTimeout(() => { copy.textContent = "Copy"; }, 1500);
  });
  const box = el("div", {}, [pre, el("div", { class: "h2v-pl__bar" }, [copy])]);
  return { el: box, destroy() { box.remove(); } };
}

function renderStage(node, w) {
  const e = w.__viewer.current();
  if (w.__cur && e && w.__cur.key === e.key && w.__stageBox.contains(w.__cur.inst.el)) return;
  try { w.__cur?.inst?.destroy?.(); } catch (_) { /* ignore */ }      // a video saves its own state here
  w.__cur = null;
  if (!e) { w.__stageBox.replaceChildren(); return; }
  const inst = buildStage(w, e);
  w.__stageBox.replaceChildren(el("div", { class: "h2v-pv__cap", text: caption(e) }), inst.el);
  w.__cur = { key: e.key, inst };
}

function renderNav(node, w, p) {
  const v = w.__viewer, n = v.entries.length, cur = v.current();
  const go = (d) => { v.go(d); renderNav(node, w, p); renderStage(node, w); relayout(node, w); };
  const kids = [];
  if (n > 1) {
    const prev = el("button", { type: "button", "aria-label": "Previous preview", title: "Previous preview", text: "‹" });
    const next = el("button", { type: "button", "aria-label": "Next preview", title: "Next preview", text: "›" });
    prev.addEventListener("click", (x) => { x.stopPropagation(); go(-1); });
    next.addEventListener("click", (x) => { x.stopPropagation(); go(+1); });
    kids.push(el("div", { class: "h2v-pv__nav", role: "group", "aria-label": "Preview navigation" }, [prev,
      el("span", { class: "h2v-pl__ro", text: `${v.index + 1} / ${n}` }),
      el("span", { class: "h2v-pv__navcap", text: caption(cur) }), next]));
  }
  const chips = p.rows.map((r) => {
    const first = v.entries.findIndex((x) => x.label === r.label);
    const b = el("button", { type: "button", class: "h2v-pv__chip", text: `${r.label} · ${r.text}`,
      title: first >= 0 ? `Show ${r.label}` : r.label, "aria-current": cur?.label === r.label ? "true" : "false" });
    if (first >= 0) b.addEventListener("click", (x) => { x.stopPropagation(); v.select(first); go(0); });
    else b.disabled = true;
    return b;
  });
  w.__navBox.replaceChildren(...kids, el("div", { class: "h2v-pv__rows" }, chips));
}

export function showPreviews(node, output) {
  if (!isVault(node) || !Array.isArray(output?.h2v_previews)) return;
  const w = ensurePanel(node);
  if (!w) return;
  const p = plan(output, viewUrl);
  w.__viewer.setEntries(p.entries);
  if (!w.__navBox) {
    w.__head = el("div", { class: "h2v-pv__head" });
    w.__navBox = el("div");
    w.__stageBox = el("div");
    w.__notes = el("div");
    w.__final.replaceChildren(w.__head, w.__navBox, w.__stageBox, w.__notes);
  }
  w.__head.replaceChildren(el("span", { text: "Previews from inside" }),
    el("span", { text: `${p.count} item${p.count === 1 ? "" : "s"}` }));
  renderNav(node, w, p);
  renderStage(node, w);                                     // the same entry keeps playing (cumulative outputs)
  w.__notes.replaceChildren(...p.notes.map((n) => el("div", { class: "h2v-pv__note", text: n })));
  clearLive(w, false);                                      // the results replace the live frame
  relayout(node, w);
}

// ── live sampler previews ──────────────────────────────────────────────────────────────────────────────────────
function renderLive(w) {
  const s = w.__liveModel.state, box = w.__live;
  if (!s.url && !s.note) {
    if (box.childNodes.length) { box.replaceChildren(); w.__liveEls = null; relayout(w.__node, w); }
    return;
  }
  let L = w.__liveEls;
  if (!L) {
    L = w.__liveEls = { cap: el("span"), step: el("span", { class: "h2v-pl__ro" }), fill: el("div"), media: el("div"),
      url: null };
    L.bar = el("div", { class: "h2v-pv__prog", role: "progressbar", "aria-label": "Sampling progress" }, [L.fill]);
    box.replaceChildren(el("div", { class: "h2v-pv__livehead" }, [L.cap, L.step]), L.bar, L.media);
  }
  L.cap.textContent = s.note || "Live preview";
  const known = s.step !== null && s.total;
  L.step.textContent = known ? `step ${s.step} / ${s.total}` : "";
  L.bar.hidden = !known;
  if (known) {
    L.bar.setAttribute("aria-valuenow", String(s.step));
    L.bar.setAttribute("aria-valuemax", String(s.total));
    L.fill.style.width = `${Math.min(100, (100 * s.step) / s.total)}%`;
  }
  if (s.url !== L.url) {
    L.url = s.url;
    if (!s.url) L.media.replaceChildren();
    else if (String(s.kind).startsWith("video/")) {
      const v = el("video", { class: "h2v-pv__liveimg", autoplay: "", loop: "", muted: "", playsinline: "" });
      v.muted = true;
      v.src = s.url;
      L.media.replaceChildren(v);
    } else {
      let img = L.media.firstChild;
      if (!(img instanceof HTMLImageElement)) {
        img = el("img", { class: "h2v-pv__liveimg", alt: "Live sampling preview" });
        img.addEventListener("load", () => relayout(w.__node, w), { once: true });
        L.media.replaceChildren(img);
      }
      img.src = s.url;
    }
  }
  relayout(w.__node, w);
}

function liveFrame(node, url, kind) {
  const w = ensurePanel(node);
  if (!w) { URL.revokeObjectURL(url); return; }
  if (w.__liveModel.state.note && !String(w.__liveModel.state.note).startsWith("Animated")) w.__liveModel.note(null);
  const old = w.__liveModel.frame(url, kind);
  renderLive(w);
  if (old && old !== url) URL.revokeObjectURL(old);
}

function liveProgress(node, value, max) {
  const w = node.widgets?.find((x) => x.name === WIDGET);
  if (!w) return;
  w.__liveModel.progress(Number(value), Number(max));
  if (w.__liveEls) renderLive(w);
}

/** end = the run finished: the last frame stays (captioned), steps go; otherwise everything goes. */
function clearLive(w, end) {
  const m = w.__liveModel;
  if (!m) return;
  if (end && m.state.url) {
    m.note("Last live preview");
    m.state.step = null;
    renderLive(w);
    return;
  }
  const old = m.clear();
  renderLive(w);
  if (old) URL.revokeObjectURL(old);
}

export function showLive(node, d) {
  if (!isVault(node) || node._kjPreviewHandler || !d?.image) return;
  let url;
  try {
    const bin = atob(d.image);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    const mime = /^(image\/(jpeg|png|webp)|video\/(mp4|webm))$/.test(String(d.mime)) ? d.mime : "image/jpeg";
    url = URL.createObjectURL(new Blob([arr], { type: mime }));
    liveFrame(node, url, mime);
  } catch (_) { if (url) URL.revokeObjectURL(url); return; }
  if (Number.isFinite(d.step) && Number.isFinite(d.total) && d.total > 0) liveProgress(node, d.step, d.total);
}

// ── adapters ───────────────────────────────────────────────────────────────────────────────────────────────────
function nodeByExecId(id) {
  if (id === null || id === undefined || id === "") return null;
  const parts = String(id).split(":");
  let g = app.rootGraph ?? app.graph;
  for (let i = 0; i < parts.length - 1; i++) {
    const n = g?.getNodeById?.(Number(parts[i]));
    if (!n?.subgraph) return null;
    g = n.subgraph;
  }
  return g?.getNodeById?.(Number(parts[parts.length - 1])) ?? null;
}

function vaultOf(id) {
  try {
    const n = nodeByExecId(id);
    return isVault(n) ? n : null;
  } catch (_) {
    return null;
  }
}

function locatorOf(node) {
  const root = app.rootGraph ?? app.graph;
  return !node.graph || node.graph === root ? String(node.id) : `${node.graph.id}:${node.id}`;
}

function restore(node) {
  try {
    if (!isVault(node) || node.widgets?.some((x) => x.name === WIDGET)) return;
    const out = app.nodeOutputs?.[locatorOf(node)];
    if (Array.isArray(out?.h2v_previews)) showPreviews(node, out);
  } catch (_) { /* best effort: a tab switch */ }
}

const isImageHead = (b) => (b[0] === 0xff && b[1] === 0xd8) || (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47);

/** An `executed` output the vault server merged: core must not draw its images on the vault (the panel does). Judged
 *  by the output alone (only a vault's merge carries h2v_previews), so a vault in a workflow tab that is not on screen
 *  is covered too. */
function stripCoreImages(d) {
  const out = d?.output;
  if (!out || !Array.isArray(out.h2v_previews) || !("images" in out || "animated" in out)) return;
  const { images: _i, animated: _a, ...rest } = out;
  d.output = rest;
}

const parentOf = (id) => { const s = String(id); const i = s.lastIndexOf(":"); return i > 0 ? s.slice(0, i) : null; };
const vhsLive = () => { try { return !!app.ui?.settings?.getSettingValue?.("VHS.LatentPreview"); } catch (_) { return false; } };

if (!globalThis.__h2vPreviews) {
  globalThis.__h2vPreviews = true;
  let running = null, lastMetaBlob = null, runToken = 0;
  const each = (fn) => { for (const w of [...PANELS]) { try { fn(w); } catch (_) { /* one panel never stops the rest */ } } };
  /** A live sampler frame with metadata: shown on the vault's panel. -> true when it was a vault's (handled). */
  const takeMeta = (d) => {
    const node = d?.blob instanceof Blob ? vaultOf(d.displayNodeId) : null;
    if (!node) return false;
    lastMetaBlob = d.blob;
    liveFrame(node, URL.createObjectURL(d.blob), d.blob.type || "image/jpeg");
    return true;
  };
  app.registerExtension({
    name: "H2Vault.Previews",
    setup() {
      // Core's own handlers for `executed` and `b_preview_with_metadata` are registered before any extension, and a
      // listener runs in registration order (measured, Chromium 148: a capture listener on an EventTarget does NOT run
      // first). So the api's own dispatch is wrapped (instance property over ComfyApi.prototype.dispatchCustomEvent):
      // `executed` of a vault loses core's image keys before anyone sees it; a vault's live frame goes to the panel
      // instead of core's node preview - for a vault inside a subgraph core still gets the frame, re-addressed to the
      // parent subgraph node (its preview there and the queue thumbnail stay). Without that method (another frontend)
      // plain listeners do what they can.
      const orig = api.dispatchCustomEvent;
      if (typeof orig === "function" && !orig.__h2vPreviews) {
        const wrapped = function (type, detail) {
          try {
            if (type === "executed") stripCoreImages(detail);
            else if (type === "b_preview_with_metadata" && takeMeta(detail)) {
              const parent = parentOf(detail.displayNodeId);
              if (parent === null) return true;
              return orig.call(this, type, { ...detail, displayNodeId: parent, nodeId: parent, realNodeId: parent,
                parentNodeId: parentOf(parent) ?? parent });
            }
          } catch (_) { /* never break core's messages */ }
          return orig.apply(this, arguments);
        };
        wrapped.__h2vPreviews = true;
        api.dispatchCustomEvent = wrapped;
      } else if (typeof orig !== "function") {
        api.addEventListener("executed", (e) => stripCoreImages(e?.detail));
        api.addEventListener("b_preview_with_metadata", (e) => takeMeta(e?.detail));
      }
      api.addEventListener("b_preview", async (e) => {
        const b = e?.detail;
        if (!(b instanceof Blob) || b === lastMetaBlob) return;
        const token = runToken;
        try {
          const head = new Uint8Array(await b.slice(0, 24).arrayBuffer());
          if (token !== runToken) return;                       // the run ended / a new one started meanwhile
          if (isImageHead(head)) {                              // legacy: no metadata, drawn on the node that runs
            const node = vaultOf(running);
            if (node) liveFrame(node, URL.createObjectURL(b), b.type || "image/jpeg");
            return;
          }
          // Video Helper Suite's animated latent preview format (also KJNodes' LTX2 preview override): >I 1, >I index,
          // 16p node id, JPEG. VHS draws it itself when its "animated previews" setting is on; otherwise the panel does.
          const dv = new DataView(head.buffer);
          if (head.length < 24 || dv.getUint32(0) !== 1 || vhsLive()) return;
          const n = head[8];
          const id = n > 0 && n <= 15 ? new TextDecoder().decode(head.slice(9, 9 + n)) : null;
          const node = vaultOf(id);
          if (node) liveFrame(node, URL.createObjectURL(b.slice(24, b.size, "image/jpeg")), "image/jpeg");
        } catch (_) { /* not an image */ }
      });
      api.addEventListener("progress", (e) => {
        const d = e?.detail;
        const node = vaultOf(d?.node);
        if (node) liveProgress(node, d.value, d.max);
      });
      api.addEventListener("progress_state", (e) => {
        for (const [id, st] of Object.entries(e?.detail?.nodes || {})) {
          if (st?.state !== "running" || !(st.max > 1)) continue;
          const node = PANELS.size ? vaultOf(id) : null;
          if (node) liveProgress(node, st.value, st.max);
        }
      });
      api.addEventListener("kj_preview_override", (e) => {
        const d = e?.detail;
        const node = vaultOf(d?.node_id);
        if (node) showLive(node, d);
      });
      api.addEventListener("VHS_latentpreview", (e) => {
        if (!vhsLive()) return;                                 // VHS draws nothing: the panel shows the frames
        const node = vaultOf(e?.detail?.id);
        const w = node ? ensurePanel(node) : null;
        if (!w) return;
        w.__liveModel.note("Animated sampling preview (drawn on this node)");
        renderLive(w);
      });
      api.addEventListener("executing", (e) => {
        running = e?.detail ?? null;
        if (running === null) { runToken += 1; each((w) => clearLive(w, true)); }
      });
      api.addEventListener("execution_start", () => { running = null; runToken += 1; each((w) => clearLive(w, false)); });
      for (const ev of ["execution_success", "execution_error", "execution_interrupted"]) {
        api.addEventListener(ev, () => { running = null; runToken += 1; each((w) => clearLive(w, true)); });
      }
    },
    nodeCreated(node) {
      if (isVault(node)) setTimeout(() => restore(node), 0);
    },
    afterConfigureGraph() {
      setTimeout(() => {
        for (const n of (app.rootGraph ?? app.graph)?.nodes || []) if (isVault(n)) restore(n);
      }, 0);
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
