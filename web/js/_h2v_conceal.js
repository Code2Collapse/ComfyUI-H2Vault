// H2Vault (AGPL-3.0) - workstream V3, model and node identity concealment: the RECIPIENT side.
//
// A concealed vault arrives with a public half only (nodes/concealment.py public_interface): a title, socket labels
// and the Controls the author exposed (sampler, scheduler, steps, cfg, seed, denoise, sizes, prompts, "Model A/B").
// This module renders exactly that on the vault node - nothing else - and keeps the values in widgets named
// `p_<key>`, which the server maps onto the inside (Aliases resolve there, never here).
//
// Imported module ("_" prefix): it registers no extension. Used by the vault front end, the author's "Preview as
// recipient" pane (renderPreview) and the live demo fixture. The whitelist itself lives in _h2v_public.js.
import { app } from "../../scripts/app.js";
import { ComfyWidgets } from "../../scripts/widgets.js";
import { previewModel, whitelistPublic } from "./_h2v_public.js";
import { el } from "./_h2v_ui.js";

export { whitelistPublic };

function hide(w) {
  if (!w) return;
  w.type = "hidden";
  w.hidden = true;
  w.computeSize = () => [0, -4];
  w.options = { ...(w.options || {}), hidden: true };
}

function makeWidget(node, p) {
  const name = `p_${p.key}`;
  const t = String(p.type || "").toUpperCase();
  const opts = {};
  for (const k of ["min", "max", "step"]) if (typeof p[k] === "number") opts[k] = p[k];
  let spec;
  if (Array.isArray(p.options) && p.options.length) spec = ["COMBO", [p.options, { default: p.value ?? p.options[0] }]];
  else if (t === "BOOLEAN") spec = ["BOOLEAN", ["BOOLEAN", { default: !!p.value }]];
  else if (t === "INT") spec = ["INT", ["INT", { default: Number(p.value ?? 0), ...opts, step: opts.step ?? 1 }]];
  else if (t === "FLOAT") spec = ["FLOAT", ["FLOAT", { default: Number(p.value ?? 0), ...opts, step: opts.step ?? 0.01,
    round: false }]];
  // placeholder: the public label (core's default placeholder would be the internal widget name `p_<key>`)
  else spec = ["STRING", ["STRING", { default: p.value == null ? "" : String(p.value), multiline: !!p.multiline,
    placeholder: p.name }]];
  const [kind, inputData] = spec;
  let w = null;
  try {
    w = ComfyWidgets[kind]?.(node, name, inputData, app)?.widget ?? null;
  } catch (_) { w = null; }
  if (!w) {                                   // the plain LiteGraph widgets, if a ComfyWidgets factory is missing
    if (kind === "COMBO") w = node.addWidget("combo", name, inputData[1].default, () => {}, { values: p.options });
    else if (kind === "BOOLEAN") w = node.addWidget("toggle", name, !!p.value, () => {});
    else if (kind === "INT" || kind === "FLOAT") w = node.addWidget("number", name, Number(p.value ?? 0), () => {}, opts);
    else w = node.addWidget("text", name, p.value == null ? "" : String(p.value), () => {});
  }
  w.label = p.name;
  if (p.value != null && w.value !== p.value) w.value = p.value;
  return w;
}

/** One exposed Control as a widget `p_<key>` (created once; an existing widget is returned as is). */
export function ensureControl(node, p) {
  return node.widgets?.find((w) => w.name === `p_${p.key}`) ?? makeWidget(node, p);
}

/** The public half the server answered for a concealed vault (protect / commit / snapshot), whitelisted again;
 *  undefined for an ordinary vault. */
export function serverPublic(data) {
  return data?.public_interface ? whitelistPublic(data.public_interface) : undefined;
}

/** Render a concealed vault for the Recipient: the author's title, the exposed Controls, labelled outputs.
 *  Every other widget of the node (payload, vault id) is hidden. Idempotent. Returns the public half it rendered,
 *  which is also what the workflow keeps in `properties.h2vault_public`. */
export function renderConcealedVault(node, pub) {
  const p = whitelistPublic(pub);
  const wanted = new Set(p.params.map((q) => `p_${q.key}`));
  for (const w of node.widgets || []) if (!wanted.has(w.name)) hide(w);
  for (const q of p.params) if (!node.widgets?.some((w) => w.name === `p_${q.key}`)) makeWidget(node, q);
  p.out.forEach((o, j) => {
    if (!node.outputs?.[j]) node.addOutput(`out_${j}`, o.type || "*");
    node.outputs[j].label = o.name;
    node.outputs[j].type = o.type || "*";
  });
  while ((node.outputs || []).length > p.out.length) node.removeOutput(node.outputs.length - 1);
  node.properties = node.properties || {};
  node.properties.h2vault_public = p;
  node.title = p.title;
  node.color = "#2d4a6b";
  node.bgcolor = "#1c2c40";
  const sz = node.computeSize?.();
  if (sz) node.setSize?.([Math.max(node.size?.[0] ?? 0, sz[0], 320), sz[1]]);
  node.setDirtyCanvas?.(true, true);
  return p;
}

/** Saved values back onto the rendered widgets, by NAME (frontend 1.53 restores widgets_values by position before
 *  onConfigure, when these widgets do not exist yet). `values` = info.widgets_values, `order` = widget names in the
 *  order they were serialized (properties.h2vault_order). */
export function restoreValues(node, values, order) {
  if (!Array.isArray(values) || !Array.isArray(order)) return;
  order.forEach((name, i) => {
    const w = node.widgets?.find((x) => x.name === name);
    if (w && values[i] !== undefined) w.value = values[i];
  });
}

/** The widget order to store with the node, so restoreValues can map values by name. */
export function widgetOrder(node) {
  return (node.widgets || []).map((w) => w.name);
}

/** The author's "Preview as recipient": the same public half, the same whitelist, drawn as the vault node the
 *  recipient will get (title, sockets, one row per exposed control). DOM only, text only (never HTML). */
export function renderPreview(container, pub) {
  const m = previewModel(pub);
  const rows = m.controls.map((c) => {
    let value;
    if (c.kind === "choice") value = el("span", { class: "h2v-pv__val h2v-pv__val--choice", text: String(c.value) });
    else if (c.kind === "switch") value = el("span", { class: "h2v-pv__val", text: c.value ? "on" : "off" });
    else if (c.kind === "textarea") value = el("span", { class: "h2v-pv__val h2v-pv__val--text", text: String(c.value) });
    else value = el("span", { class: "h2v-pv__val", text: String(c.value) });
    const kids = [el("span", { class: "h2v-pv__label", text: c.label }), value];
    if (c.kind === "choice") kids.push(el("span", { class: "h2v-pv__more", text: `${c.choices} choice${c.choices === 1 ? "" : "s"}` }));
    return el("li", { class: `h2v-pv__row${c.kind === "textarea" ? " h2v-pv__row--wide" : ""}` }, kids);
  });
  const sockets = el("div", { class: "h2v-pv__sockets" }, [
    el("span", { class: "h2v-pv__in", text: m.inputs.length ? m.inputs.join(", ") : "" }),
    el("span", { class: "h2v-pv__out", text: m.outputs.join(", ") })]);
  const card = el("div", { class: "h2v-pv", role: "group", "aria-label": `Recipient view of ${m.title}` }, [
    el("div", { class: "h2v-pv__title", text: m.title }), sockets,
    rows.length ? el("ul", { class: "h2v-pv__rows" }, rows)
      : el("p", { class: "h2v-pv__empty", text: "No controls: the recipient can only run it." })]);
  container.replaceChildren(card);
  return m;
}
