// H2Vault (AGPL-3.0) - workstream V5, "Lock parameters" (docs/h2vault/V5_enhancements_design.md section 5).
// The idea of locking a node's parameters in place from the node, group and selection menus was inspired by
// ComfyUI-NodeEncrypt (lvqunx); no code or text was taken from it. See NOTICE.
//
// A Locked node is a one-node H2Vault vault drawn like the node it replaces: same title, colours and sockets; the
// rows the author leaves open become the vault's promoted controls; the locked rows' values exist only inside the
// encrypted payload. This module is the pure part: which rows a node has, and the request the protect transaction
// sends. No DOM, no ComfyUI import (tests run it under node). Shapes are frontend 1.53.10's: node.widgets
// [{name, label, value, type, options}], node.inputs [{name, link, widget: {name}}], nodeData {input: {required,
// optional}, display_name, output_node}.

// front-end helper widgets that are not inputs of the node (they never reach the server)
const FRONTEND_ONLY = new Set(["control_after_generate", "control_before_generate", "upload", "image_upload"]);
const COLOR = /^#[0-9a-fA-F]{6}$/;
const SCALAR = (v) => ["string", "number", "boolean"].includes(typeof v);

function specOf(nodeDef, name) {
  const inp = nodeDef?.input || {};
  return inp.required?.[name] ?? inp.optional?.[name] ?? null;
}

function typeOf(spec, value) {
  const t = Array.isArray(spec) ? spec[0] : null;
  if (Array.isArray(t)) return "COMBO";
  if (typeof t === "string" && t) return t.toUpperCase();
  return typeof value === "number" ? "FLOAT" : typeof value === "boolean" ? "BOOLEAN" : "STRING";
}

/** The value rows of `node` that can be locked: real inputs of its class shown as widgets, not wired from
 *  elsewhere, holding a plain value. -> [{name, label, value, type, options?}] in widget order. */
export function lockableRows(node, nodeDef) {
  const rows = [];
  for (const w of node?.widgets || []) {
    if (!w || typeof w.name !== "string" || FRONTEND_ONLY.has(w.name)) continue;
    if (w.type === "hidden" || w.hidden || w.options?.hidden || w.serialize === false) continue;
    const spec = specOf(nodeDef, w.name);
    if (!spec) continue;
    const socket = (node.inputs || []).find((i) => i?.widget?.name === w.name || i?.name === w.name);
    if (socket && socket.link != null) continue;                 // fed by a wire: that is data, not a value
    if (!SCALAR(w.value)) continue;
    const row = { name: w.name, label: String(w.label || w.name), value: w.value, type: typeOf(spec, w.value) };
    const opts = w.options?.values;
    if (Array.isArray(opts)) row.options = opts.filter(SCALAR);
    rows.push(row);
  }
  return rows;
}

/** What the Locked node looks like (public: anyone who receives the workflow can read it). */
export function lockLook(node, nodeDef) {
  const label = String(nodeDef?.display_name || node?.type || "").slice(0, 80);
  return {
    title: String(node?.title || label || "Locked node").slice(0, 80),
    color: COLOR.test(node?.color || "") ? node.color : null,
    bgcolor: COLOR.test(node?.bgcolor || "") ? node.bgcolor : null,
    node_label: label || null,
  };
}

/** The key of an open row's control (the vault widget is `p_<key>`; the name survives widget <-> socket changes). */
export const openKey = (name) => `w_${String(name).replace(/[^\w]/g, "_")}`;

/**
 * The protect request for one node: `locked` = the row names to lock (default: every row, owner D5).
 * -> {lock: {node, rows, look}, extraParams: [{key, nodeId, input, name, type, options}], openRows, lockedRows}
 */
export function lockRequest(node, nodeDef, locked = null) {
  const rows = lockableRows(node, nodeDef);
  const want = locked == null ? new Set(rows.map((r) => r.name)) : new Set(locked);
  const lockedRows = rows.filter((r) => want.has(r.name));
  const openRows = rows.filter((r) => !want.has(r.name));
  const nodeId = String(node.id);
  return {
    lock: { node: nodeId, rows: lockedRows.map((r) => r.name), look: lockLook(node, nodeDef) },
    extraParams: openRows.map((r) => ({ key: openKey(r.name), nodeId, input: r.name, name: r.label, type: r.type,
      ...(r.options ? { options: [...r.options] } : {}) })),
    openRows, lockedRows,
  };
}

/** The public lock part as the browser may keep it (re-whitelisted: a tampered workflow cannot add fields). */
export function whitelistLock(pub) {
  if (!pub || typeof pub !== "object" || !Array.isArray(pub.rows)) return null;
  const look = pub.look && typeof pub.look === "object" ? pub.look : {};
  const s = (v, n = 80) => (typeof v === "string" ? v.slice(0, n) : null);
  return {
    rows: pub.rows.filter((r) => typeof r === "string").map((r) => r.slice(0, 80)),
    look: { title: s(look.title) || "", node_label: s(look.node_label),
      color: COLOR.test(look.color || "") ? look.color : null, bgcolor: COLOR.test(look.bgcolor || "") ? look.bgcolor : null },
  };
}

/** extraParams for re-sealing an opened Locked node: its open controls, from the public interface it carries. */
export function reopenParams(info) {
  const node = info?.lock_node;
  if (!node || !info?.lock) return [];
  return (info.interface?.params || []).filter((p) => String(p.key || "").startsWith("w_") && p.input)
    .map((p) => ({ key: p.key, nodeId: String(node), input: p.input, name: p.name, type: p.type,
      ...(Array.isArray(p.options) ? { options: [...p.options] } : {}) }));
}
