// Derived from Code2Collapse ComfyUI-CustomNodePacks js/_vue_dom_rebind.js (Apache-2.0, Copyright Code2Collapse);
// modified for H2Vault (AGPL-3.0): H2Vault nodes only, h2v attribute. See NOTICE.
//
// Nodes 2.0 + subgraphs: keep an H2Vault DOM widget (the vault node's status card) showing ITS OWN element.
// Measured on frontend 1.53.10 (CNP L2.50): "Convert to subgraph" builds a NEW node instance with the same id inside
// the subgraph and removes the old one; Nodes 2.0 reuses the view keyed by node id and keeps the OLD instance's DOM
// element, while the new instance's element is never attached. After every graph switch, each tagged widget whose
// element is detached replaces the stale element with the same tag inside its node's view. Classic renderer: nothing
// to do. Cheap: only the nodes of the graph on screen, once per switch, never per frame.
import { app } from "../../scripts/app.js";

const ATTR = "data-h2v-widget";
const H2V_TYPES = new Set(["H2Vault_ProtectedSubgraph", "H2Vault_ProtectedSubgraphOutput"]);

/** Mark a DOM widget so a stale copy of it can be found and replaced; a display-only panel is never saved. */
export function tagDomWidget(widget) {
  try {
    if (widget?.element && widget.name) widget.element.setAttribute(ATTR, widget.name);
    if (widget?.element && widget.options?.serialize === false && widget.serialize !== false) widget.serialize = false;
  } catch (_e) { /* ignore */ }
}

function isH2vNode(node) {
  return H2V_TYPES.has(node?.comfyClass ?? node?.type);
}

export function rebindNode(node) {
  if (!globalThis.LiteGraph?.vueNodesMode || !node || !isH2vNode(node)) return 0;
  let host = null;
  try { host = document.querySelector(`[data-node-id="${CSS.escape(String(node.id))}"]`); } catch (_e) { return 0; }
  if (!host) return 0;
  let swapped = 0;
  for (const w of node.widgets || []) {
    const el = w?.element;
    if (!el || el.isConnected || !el.getAttribute?.(ATTR)) continue;
    const stale = host.querySelector(`[${ATTR}="${CSS.escape(String(w.name))}"]`);
    if (stale && stale !== el) {
      stale.replaceWith(el);
      swapped += 1;
    }
  }
  return swapped;
}

function rebindGraph(graph) {
  let n = 0;
  for (const node of graph?._nodes || graph?.nodes || []) n += rebindNode(node);
  return n;
}

function afterRender(fn) {
  requestAnimationFrame(() => requestAnimationFrame(() => { fn(); setTimeout(fn, 120); }));
}

if (!globalThis.__h2vRebind) {
  globalThis.__h2vRebind = true;
  app.registerExtension({
    name: "H2Vault.VueDomRebind",
    setup() {
      app.canvas?.canvas?.addEventListener?.("litegraph:set-graph", (e) => {
        const g = e?.detail?.newGraph || app.canvas?.graph;
        afterRender(() => rebindGraph(g));
      });
    },
  });
}
