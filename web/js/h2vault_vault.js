// Derived from Code2Collapse ComfyUI-CustomNodePacks js/c2c_secure_subgraph.js (Apache-2.0, Copyright Code2Collapse; working copy of
// the V1 vault UX overhaul, 2026-11-20); modified for H2Vault (AGPL-3.0). See NOTICE.
// H2Vault protected native subgraphs - front end (docs/ARCHITECTURE.md; CNP design: VAULT_DESIGN_A18.md).
//
//   Locked state  : ONE node (H2Vault_ProtectedSubgraph / ..._Output): public sockets, promoted controls, the encrypted
//                   payload. No inner node, link, value or layout in the workflow.
//   Editing state : a real native subgraph node (same id, same links), entered like any subgraph. Leaving it
//                   (breadcrumb / navigation) re-encrypts and puts the vault node back (owner: exit = lock).
// While a vault is open, every serialization (save, autosave, export, the queued workflow) writes the vault in its
// locked form, copying the open subgraph is refused, and a queue encrypts a snapshot of the current edit first.
import { app } from "../../scripts/app.js";
import { api } from "../../scripts/api.js";
import { BUSY_MESSAGE, ProtectError, absSource, captureBoundary, ensureReroutes, execIdOf, outerWires, relSource,
  rerouteChain, runTransaction, verifyConversion, verifyVaultWiring } from "./_h2v_protect_tx.js";
// V1 (owner 2026-11-20): one-step "Lock selection as H2Vault" + the Vault UI overhaul (docs/h2vault/V1_cnp_vault_ux_spec.md)
import { isVaultType, protectFailureText, resolveLockSelection, stageLabel, summarizeSelection } from "./_h2v_selection.js";
import { block, capsule, choiceCards, codeField, copyRow, disclosure, el as vel, factList, field, noticeEl, passwordField,
  statusCard, stepSection, switchRow, textArea, textField, vaultDialog, vbutton } from "./_h2v_ui.js";
import { tagDomWidget } from "./_h2v_rebind.js";
// V3 identity concealment, recipient side (docs/h2vault/V3_concealment_design.md)
import { ensureControl, serverPublic } from "./_h2v_conceal.js";
import { candidate, inventory, previewsOf, promotedValues, socketsOf } from "./_h2v_expose.js";
import { exposeStep } from "./_h2v_expose_ui.js";
// V5 (docs/h2vault/V5_enhancements_design.md): Lock parameters and offline licences
import { lockRequest, lockableRows, reopenParams, whitelistLock } from "./_h2v_lockparams.js";
import { EXPIRY_CHOICES, HONOUR_NOTE, fmtDate, ledgerState, licenceLine, licenceTerms } from "./_h2v_licence.js";

const VAULT_TYPES = new Set(["H2Vault_ProtectedSubgraph", "H2Vault_ProtectedSubgraphOutput"]);
const PACK_AUX_ID = "Code2Collapse/ComfyUI-H2Vault";
const OPEN = new Map();            // native SubgraphNode -> edit session
const RUN_UNLOCKED = new Set();    // Locked vault ids unlocked in this tab
let RAW_G2P = null;                // app.graphToPrompt before the guard (buildApi needs the inner nodes)
const LOG = (...a) => console.info("[H2Vault]", ...a);

const PROFILES = [
  { id: "sealed_installs", title: "Sealed — authorized installations", tag: "Recommended",
    run: "Without a password, only on ComfyUI installations you authorize (yours is always included).",
    edit: "Vault password + your authenticator code + editor list.",
    net: "None - runs offline.", where: "On each authorized installation's GPU.",
    custody: "A per-vault key, wrapped for each authorized installation's own key pair.",
    security: "Encrypted. Other installations cannot run or read it, even with this pack.", risk: "" },
  { id: "sealed_licensed", title: "Licensed — one licence per installation", tag: "Share widely",
    run: "Only on installations you send a licence to (yours gets one automatically). Everyone gets the same " +
      "workflow; each person adds the small licence you send them.",
    edit: "Vault password + your authenticator code + editor list.",
    net: "None - licences are checked offline, nothing is sent anywhere.", where: "On each licensed installation's GPU.",
    custody: "A per-vault licence key, wrapped inside each licence for that installation's own key pair; licences " +
      "are signed with your author key.",
    security: "Encrypted. Stops casual sharing: the workflow file alone does not run without a licence for that " +
      "installation. One licence key per workflow, shared by all licensees: a determined licensee can extract it. " +
      "End dates and run limits are kept by H2Vault on their computer. Revoking = a new licence key.", risk: "" },
  { id: "locked", title: "Locked — password to run", tag: "",
    run: "Anyone with the vault password; asked once per browser tab.",
    edit: "Vault password + your authenticator code + editor list.",
    net: "None - runs offline.", where: "On the GPU of whoever runs it.",
    custody: "A per-vault key, unlocked by the password (Argon2id).",
    security: "Encrypted. Without the password nothing runs or opens.", risk: "" },
  { id: "sealed_portable", title: "Portable — obfuscation only", tag: "Not secure",
    run: "Anyone, anywhere, without a password.",
    edit: "Vault password + your authenticator code + editor list.",
    net: "None.", where: "On the GPU of whoever runs it.",
    custody: "A key every copy of this pack can derive.",
    security: "OBFUSCATION ONLY: a knowledgeable recipient can extract the graph. Use only when a vault must run " +
      "on machines you cannot authorize.", risk: "warn" },
  { id: "owner_hosted", title: "Sealed — owner-hosted (coming)", tag: "Planned", disabled: true,
    run: "Recipients send inputs to YOUR server and get outputs back.", edit: "Only you.",
    net: "Recipients need your server online.", where: "On your server's GPU.",
    custody: "Graph and key never leave your server.", security: "Strongest: recipients never receive the graph. " +
      "Planned.",
    risk: "" },
];

// ── small helpers ───────────────────────────────────────────────────────────────────────────────────────────
async function post(route, body) {
  const r = await api.fetchApi(route, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body) });
  let data = {};
  try { data = await r.json(); } catch (_) { /* keep {} */ }
  return { ok: r.ok && data.ok !== false, status: r.status, data };
}

function el(tag, props = {}, kids = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "style") Object.assign(e.style, v);
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) e.addEventListener(ev, fn);
    else if (k in e) e[k] = v;
    else e.setAttribute(k, v);
  }
  for (const c of [].concat(kids)) if (c != null) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}

/** `warn`: true -> a warning; or a severity string ("success" | "info" | "warn" | "error"). */
function toast(text, warn, summary = "H2Vault") {
  const severity = typeof warn === "string" ? warn : (warn ? "warn" : "info");
  try {
    app.extensionManager?.toast?.add({ severity, summary, detail: text, life: severity === "error" ? 8000 : 5000 });
  } catch (_) { LOG(text); }
}

// ── graph helpers ───────────────────────────────────────────────────────────────────────────────────────────
function isSubgraphNode(n) {
  try { return typeof n?.isSubgraphNode === "function" && n.isSubgraphNode(); } catch (_) { return false; }
}

function linkOf(graph, id) {
  if (id == null || !graph) return null;
  const L = graph.links ?? graph._links;
  return (L instanceof Map ? L.get(id) : L?.[id]) ?? null;
}

function nodeDefOf(type) {
  return LiteGraph.registered_node_types?.[type]?.nodeData ?? null;
}

/** The wires of a node: input slot index -> source, output index -> targets (sources/targets by id). */
function captureWires(graph, node) {
  const ins = (node.inputs || []).map((inp, i) => {
    const l = linkOf(graph, inp?.link);
    return l ? { i, origin: l.origin_id, slot: l.origin_slot, parent: l.parentId ?? null } : null;
  }).filter(Boolean);
  const outs = [];
  (node.outputs || []).forEach((o, j) => (o?.links || []).forEach((lid) => {
    const l = linkOf(graph, lid);
    if (l) outs.push({ j, target: l.target_id, slot: l.target_slot, parent: l.parentId ?? null });
  }));
  return { ins, outs };
}

/**
 * Put `to` where `from` is: same id (the prompt, history and the workflow keep naming the same node), same position,
 * every wire back. `mapIn(i)` turns an input slot index of `from` into one of `to` (vault inputs skip the promoted
 * controls of a subgraph); -1 drops that wire. The id is set BEFORE the node joins the graph: renumbering a node after
 * it is wired leaves its links pointing at an id nothing has (measured: InvalidLinkError at queue time).
 */
function replaceNode(graph, from, to, mapIn = (i) => i) {
  const wires = captureWires(graph, from);
  const id = from.id;
  to.pos = [...from.pos];
  graph.remove(from);
  if (id != null && graph.getNodeById(id) == null) to.id = id;
  graph.add(to);
  return wires;
}

function restoreWires(graph, wires, to, mapIn = (i) => i) {
  // inside a subgraph, wires to its own input / output node carry those nodes' ids, which getNodeById does not know
  // (measured: a vault made inside a subgraph lost them and its inner node had "no input at all")
  const ioIn = graph.inputNode, ioOut = graph.outputNode;
  // L9.249 V3: a wire keeps its native link reroutes (its parent reroute id) when that reroute still exists
  const via = (c) => (c.parent != null && graph.reroutes?.get?.(c.parent) ? c.parent : undefined);
  for (const c of wires.ins) {
    const k = mapIn(c.i);
    if (k < 0 || k >= (to.inputs || []).length) continue;
    if (ioIn && c.origin === ioIn.id) { ioIn.slots?.[c.slot]?.connect(to.inputs[k], to, via(c)); continue; }
    const origin = graph.getNodeById(c.origin);
    if (origin) origin.connect(c.slot, to, k, via(c));
  }
  for (const c of wires.outs) {
    if (c.j >= (to.outputs || []).length) continue;
    if (ioOut && c.target === ioOut.id) { ioOut.slots?.[c.slot]?.connect(to.outputs[c.j], to, via(c)); continue; }
    const target = graph.getNodeById(c.target);
    if (target) to.connect(c.j, target, c.slot, via(c));
  }
}

/** Vault input slot index (by name in_<k>) for subgraph input i, given the non-promoted input order. */
function vaultSlotOf(v, inputMap, i) {
  const k = (inputMap || []).indexOf(i);
  return k < 0 ? -1 : (v.inputs || []).findIndex((x) => x.name === `in_${k}`);
}

/** Subgraph node input index for vault input slot `slot` (named in_<k>). */
function subgraphSlotOf(v, inputMap, slot) {
  const m = /^in_(\d+)$/.exec(v.inputs?.[slot]?.name || "");
  return m ? (inputMap?.[Number(m[1])] ?? Number(m[1])) : -1;
}

// ── V3 seam (docs/ARCHITECTURE.md section 7) ───────────────────────────────────────────────────────────────────
/**
 * The interface written onto the vault node (its properties, the locked form a save writes, the open-vault snapshot):
 * socket names / types and the promoted controls with their values - everything about the inside that is public.
 * For a CONCEALED vault (V3) it is the whitelisted interface the server answered (`built.public`, set from every
 * protect / commit / snapshot answer): Author-chosen labels and alias choices, never the real file names that the
 * extracted interface carries in its COMBO options and values.
 */
export function publicInterface(built) {
  return built.public ?? built.interface;
}

// ── vault node appearance and sockets ───────────────────────────────────────────────────────────────────────
function vaultInfo(node) { return node.properties?.h2vault || {}; }

function hideWidget(w) {
  if (!w) return;
  w.type = "hidden";
  w.hidden = true;
  w.computeSize = () => [0, -4];
  w.options = { ...(w.options || {}), hidden: true };
}

function promotedWidget(node, p) {
  const name = `p_${p.key}`;
  let w = node.widgets?.find((x) => x.name === name);
  if (w) return w;
  const t = String(p.type || "").toUpperCase();
  const v = p.value;
  if (Array.isArray(p.options) && p.options.length) w = node.addWidget("combo", name, v ?? p.options[0], () => {}, { values: p.options });
  else if (t === "BOOLEAN") w = node.addWidget("toggle", name, !!v, () => {});
  else if (t === "INT" || t === "FLOAT" || typeof v === "number") {
    w = node.addWidget("number", name, Number(v ?? 0), () => {}, { precision: t === "INT" ? 0 : 3,
      step2: t === "INT" ? 1 : 0.01 });
  } else w = node.addWidget("text", name, v == null ? "" : String(v), () => {});
  w.label = p.name || name;
  return w;
}

function applyInterface(node) {
  setTimeout(() => { try { autoProvision(node); } catch (_) { /* best effort */ } }, 800);
  const info = vaultInfo(node);
  const iface = info.interface || {};
  hideWidget(node.widgets?.find((w) => w.name === "vault_id"));
  hideWidget(node.widgets?.find((w) => w.name === "vault_payload"));
  for (const p of iface.params || []) (iface.concealed ? ensureControl : promotedWidget)(node, p);
  const nIn = (iface.in || []).length, nOut = (iface.out || []).length;
  // the node def declares 256 outputs; a vault shows the ones its inside has
  while ((node.outputs || []).length > nOut) node.removeOutput(node.outputs.length - 1);
  (iface.out || []).forEach((o, j) => {
    if (!node.outputs[j]) node.addOutput(`out_${j}`, o.type || "*");
    node.outputs[j].label = o.name;
    node.outputs[j].type = o.type || "*";
  });
  (iface.in || []).forEach((s, i) => {
    const name = `in_${i}`;
    let slot = node.inputs?.find((x) => x.name === name);
    if (!slot) slot = node.addInput(name, s.type || "*");
    slot.label = s.name;
    slot.type = s.type || "*";
  });
  while ((node.inputs || []).filter((x) => /^in_\d+$/.test(x.name)).length > nIn) {
    const idx = node.inputs.findIndex((x) => x.name === `in_${nIn}`);
    if (idx < 0) break;
    node.removeInput(idx);
  }
  node.properties = node.properties || {};
  node.properties.aux_id = PACK_AUX_ID;                   // a machine without the pack offers to install it
  const prof = PROFILES.find((p) => p.id === info.profile);
  const legacy = info.profile === "sealed_portable";
  const lock = whitelistLock(info.lock);                  // V5: a Locked node is drawn like the node it replaced
  node.title = info.title || (lock && lock.look.title) || (iface.concealed && iface.title) || node.title || "H2Vault";
  node.color = lock?.look.color || (legacy ? "#5a4a22" : "#2b2552");
  node.bgcolor = lock?.look.bgcolor || (legacy ? "#2e2716" : "#191632");
  node.__h2vBadge = `🔒 ${legacy ? "portable - obfuscation only" : (prof?.id === "locked" ? "locked" : "sealed")}` +
    (info.node_count && !iface.concealed && !lock ? ` · ${info.node_count} nodes` : "");      // V3: no inner count
  ensureLockRows(node, lock);
  ensureStatusCard(node);
  if (info.profile === "sealed_licensed") refreshLicence(node);
  if (!node.__h2vMinWidth && typeof node.computeSize === "function") {
    // a DOM widget's computeSize gives a height only: the status card's minimum width comes from the node
    const cs = node.computeSize;
    node.computeSize = function (...a) { const r = cs.apply(this, a); if (Array.isArray(r)) r[0] = Math.max(r[0], 380); return r; };
    node.__h2vMinWidth = true;
  }
  node.setSize?.(node.computeSize?.() ?? node.size);
  node.setDirtyCanvas?.(true, true);
}

// ── the vault node's body: a status card (V1) ──────────────────────────────────────────────────────────────────
// A display-only DOM widget, in both renderers (the old badge was canvas text above the title that Nodes 2.0 never
// drew). It is never saved (widget.serialize = false: frontend 1.53.10 saves any widget whose own .serialize is not
// false, L9.237) and it is always the LAST widget, so the saved order [vault_id, vault_payload, p_* ...] never moves.
// It shows only public facts: profile, inner node COUNT, this tab's run state - never an inner name or type.
const STATUS_WIDGET = "vault_status";
const STATUS_H = 60;

function ensureStatusCard(node) {
  if (typeof document === "undefined" || typeof node?.addDOMWidget !== "function") return;
  let w = node.widgets?.find((x) => x.name === STATUS_WIDGET);
  if (!w) {
    const card = statusCard();
    w = node.addDOMWidget(STATUS_WIDGET, STATUS_WIDGET, card.el, { serialize: false, margin: 4,
      getMinHeight: () => STATUS_H, getHeight: () => STATUS_H });
    w.serialize = false;
    w.computeSize = (width) => [width, STATUS_H + 8];
    w.__vaultCard = card;
    try { tagDomWidget(w); } catch (_) { /* the Nodes 2.0 rebind tag is a nicety */ }
  }
  const ws = node.widgets || [];
  const at = ws.indexOf(w);
  if (at >= 0 && at !== ws.length - 1) { ws.splice(at, 1); ws.push(w); }
  updateStatusCard(node);
}

// Concealed vaults report WHAT the current step does in simple words ("Sampling", "Decoding" ...) and a step count -
// never a node name or type (server: concealment.functional_label). Keyed by the vault node's id in the prompt.
const PHASES = new Map();

function phaseText(node) {
  const p = PHASES.get(String(node?.id));
  return p ? `${p.label} · step ${p.step} of ${p.total}` : "";
}

function onPhase(e) {
  const d = e?.detail || {};
  if (!d.vault || typeof d.label !== "string") return;
  PHASES.set(String(d.vault).split(":").pop(), { label: d.label.slice(0, 40), step: Number(d.step) || 1,
    total: Number(d.total) || 1 });
  refreshCards();
}

function clearPhases() {
  if (!PHASES.size) return;
  PHASES.clear();
  refreshCards();
}

function updateStatusCard(node) {
  const card = node?.widgets?.find((x) => x.name === STATUS_WIDGET)?.__vaultCard;
  if (!card) return;
  const info = vaultInfo(node);
  const vid = node.widgets?.find((x) => x.name === "vault_id")?.value;
  const prep = PREPARING.get(vid);
  if (prep && vid) {
    card.update({ tone: prep.failed ? "warn" : "accent", title: prep.failed ? "Could not prepare this vault"
      : `Preparing this vault · ${prep.pct} %`, detail: prep.failed ? prep.failed : "Downloading what it needs",
      meta: "What it downloads stays private", action: null });
    return;
  }
  const running = phaseText(node);
  if (running && vid) {
    card.update({ tone: "ok", title: running, detail: "Running", meta: "Inside steps stay private",
      action: null });
    return;
  }
  const n = info.interface?.concealed ? 0 : (Number(info.node_count) || 0);     // V3: a concealed vault hides it
  const lockInfo = whitelistLock(info.lock);
  const nLocked = lockInfo ? (Number(info.lock?.count) || lockInfo.rows.length) : 0;
  const detail = lockInfo ? `${nLocked} value${nLocked === 1 ? "" : "s"} locked`
    : n ? `${n} node${n === 1 ? "" : "s"} inside` : "Protected subgraph";
  if (!vid) {
    card.update({ tone: "warn", title: "Empty vault", detail: "Lock a selection to fill it",
      meta: "Right-click nodes › Protect with H2Vault" });
    return;
  }
  if (info.profile === "sealed_portable") {
    card.update({ tone: "warn", title: "Portable · obfuscation only", detail, meta: "Runs anywhere without a password",
      action: { label: "Open…", ariaLabel: `Open ${node.title || "vault"}`, onClick: () => openVault(node) } });
    return;
  }
  if (info.profile === "sealed_licensed") {
    const line = licenceLine(LICENCE_STATE.get(vid));
    card.update({ tone: line?.tone || "accent", title: line?.title || "Licensed · one licence per installation", detail,
      meta: line?.meta || "Checking this installation's licence…", metaTone: line?.tone === "ok" ? "ok" : "",
      action: line && line.tone !== "ok"
        ? { label: "Add licence…", ariaLabel: `Add a licence for ${node.title || "vault"}`, onClick: () => addLicence(node) }
        : { label: "Open…", ariaLabel: `Open ${node.title || "vault"}`, onClick: () => openVault(node) } });
    return;
  }
  const locked = info.profile === "locked";
  const unlocked = locked && RUN_UNLOCKED.has(vid);
  card.update({ tone: unlocked ? "ok" : "accent",
    title: locked ? "Locked · password to run" : "Sealed · authorized installations", detail,
    meta: locked ? (unlocked ? "Unlocked in this tab" : "Asks for the password when you run it")
      : "Runs without a password on authorized installations", metaTone: unlocked ? "ok" : "",
    action: { label: "Open…", ariaLabel: `Open ${node.title || "vault"}`, onClick: () => openVault(node) } });
}

// ── V5: the locked rows of a Locked node (display only, never saved) ──────────────────────────────────────────
// One DOM widget listing what is locked: the setting names when the author published them, otherwise only how many.
// widget.serialize = false and it sits just before the status card, so the saved order [vault_id, vault_payload,
// p_* ...] never moves (frontend 1.53 restores by position, L9.102).
const LOCKROWS_WIDGET = "vault_locked_rows";
const ROW_H = 22;

function ensureLockRows(node, lock) {
  const existing = node.widgets?.find((x) => x.name === LOCKROWS_WIDGET);
  if (!lock) {
    if (existing) {
      const i = node.widgets.indexOf(existing);
      existing.onRemove?.();
      node.widgets.splice(i, 1);
    }
    return;
  }
  if (typeof document === "undefined" || typeof node?.addDOMWidget !== "function") return;
  const count = Number(vaultInfo(node).lock?.count) || lock.rows.length;
  const lines = lock.rows.length ? lock.rows : [`${count} value${count === 1 ? "" : "s"} locked`];
  const h = lines.length * ROW_H + 8;
  let w = existing;
  if (!w) {
    const box = vel("div", { class: "h2v h2v-lockrows", style: { display: "flex", flexDirection: "column", gap: "2px",
      padding: "4px 6px", boxSizing: "border-box", font: "12px/1.4 var(--font-sans, system-ui, sans-serif)" } });
    w = node.addDOMWidget(LOCKROWS_WIDGET, LOCKROWS_WIDGET, box, { serialize: false, margin: 4,
      getMinHeight: () => w.__h2vH, getHeight: () => w.__h2vH });
    w.serialize = false;
    w.__h2vBox = box;
    try { tagDomWidget(w); } catch (_) { /* the Nodes 2.0 rebind tag is a nicety */ }
  }
  w.__h2vH = h;
  w.computeSize = (width) => [width, h + 8];
  w.__h2vBox.replaceChildren(...lines.map((name) => vel("div", { style: { display: "flex", justifyContent:
    "space-between", alignItems: "center", height: `${ROW_H - 2}px`, padding: "0 8px", borderRadius: "6px",
    background: "var(--comfy-input-bg, #16171a)", color: "var(--input-text, #ddd)" } }, [
    vel("span", { text: `🔒 ${name}`, style: { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" } }),
    vel("span", { text: lock.rows.length ? "locked" : "", style: { opacity: "0.6", fontSize: "11px" } })])));
}

// ── V5: licence state per vault id (this installation), from /h2vault/licence/status ───────────────────────────
const LICENCE_STATE = new Map();
const LICENCE_ASKED = new Set();

async function refreshLicence(node, force = false) {
  const vid = node.widgets?.find((w) => w.name === "vault_id")?.value;
  const payload = node.widgets?.find((w) => w.name === "vault_payload")?.value;
  if (!vid || !payload || (!force && LICENCE_ASKED.has(vid))) return;
  LICENCE_ASKED.add(vid);
  try {
    const r = await post("/h2vault/licence/status", { payload, vault_id: vid });
    if (r.ok) LICENCE_STATE.set(vid, r.data);
  } catch (_) { /* the card keeps "checking" */ }
  refreshCards(vid);
}

/** After a run: the licence state of every Licensed vault on screen (runs left, an ended licence). */
function refreshLicensedCards() {
  const walk = (g, seen = new Set()) => {
    if (!g || seen.has(g)) return;
    seen.add(g);
    for (const n of g.nodes || g._nodes || []) {
      if (VAULT_TYPES.has(n.type) && vaultInfo(n).profile === 'sealed_licensed') refreshLicence(n, true);
      if (isSubgraphNode(n)) walk(n.subgraph, seen);
    }
  };
  try { walk(app.rootGraph ?? app.graph); } catch (_) { /* display only */ }
}

/** Refresh the cards of every vault with this id (after a run unlock). */
function refreshCards(vaultId) {
  const walk = (g, seen = new Set()) => {
    if (!g || seen.has(g)) return;
    seen.add(g);
    for (const n of g.nodes || g._nodes || []) {
      if (VAULT_TYPES.has(n.type) && (!vaultId || n.widgets?.find((w) => w.name === "vault_id")?.value === vaultId)) {
        updateStatusCard(n);
      }
      if (isSubgraphNode(n)) walk(n.subgraph, seen);
    }
  };
  try { walk(app.rootGraph ?? app.graph); } catch (_) { /* display only */ }
}

function markRunUnlocked(vaultId) {
  RUN_UNLOCKED.add(vaultId);
  refreshCards(vaultId);
}

// ── API form from the frontend's own graphToPrompt (exact widget / primitive / nested-subgraph conversion) ──
// A26 L9.203: the subgraph node's exact execution path (the frontend's own algorithm, see _vault_protect_tx.js) -
// never "a key whose last two segments look right", which matched the wrong instance of a shared definition.
function execPrefix(output, sg) {
  const id = execIdOf(sg, app.rootGraph ?? app.graph);
  if (!id) return null;
  const prefix = `${id}:`;
  return Object.keys(output).some((k) => k.startsWith(prefix)) ? prefix : null;
}

function promotedOf(sg) {
  // native promotion: subgraph inputs wired to inner widgets show as widgets on the subgraph node
  const out = [];
  const inputs = sg.subgraph?.inputs || [];
  inputs.forEach((inp, i) => {
    const w = sg.widgets?.find((x) => x.name === inp.name);
    if (!w) return;
    // A26 L9.203: a promoted widget input that an OUTER wire feeds is data, not a control - treating it as a control
    // left that inner input without a source ("vault input undefined"; the old flow sealed it unwired)
    if (sg.inputs?.[i]?.link != null) return;
    const targets = [];
    for (const lid of inp.linkIds || []) {
      const l = linkOf(sg.subgraph, lid);
      const n = l && sg.subgraph.getNodeById(l.target_id);
      const name = n?.inputs?.[l.target_slot]?.widget?.name ?? n?.inputs?.[l.target_slot]?.name;
      if (n && name) targets.push({ node: String(n.id), input: name });
    }
    if (targets.length) out.push({ key: `i${i}`, name: inp.label || inp.name, type: inp.type, value: w.value,
      options: w.options?.values, targets, index: i });
  });
  return out;
}

async function buildApi(sg, extraParams = []) {
  const { output } = await (RAW_G2P ?? app.graphToPrompt.bind(app))();
  const prefix = execPrefix(output, sg);
  if (!prefix) throw new Error("This subgraph has no nodes that run (nothing to protect).");
  const nodes = {};
  for (const [k, v] of Object.entries(output)) {
    if (k.startsWith(prefix)) nodes[k.slice(prefix.length)] = { class_type: v.class_type, inputs: { ...v.inputs } };
  }
  const graph = sg.graph;
  // outer sources of each vault input (resolved like graphToPrompt resolves them)
  const inputs = (sg.inputs || []).map((s) => ({ name: s.label || s.name, type: String(s.type || "*") }));
  const outerSrc = new Map();
  (sg.inputs || []).forEach((s, i) => {
    const l = linkOf(graph, s.link);
    if (l) outerSrc.set(i, l);
  });
  const promoted = promotedOf(sg);
  const promotedIdx = new Set(promoted.map((p) => p.index));
  // inner inputs fed from a vault input -> {"vault_in": i}: by the subgraph's own input links ...
  const sub = sg.subgraph;
  (sub?.inputs || []).forEach((inp, i) => {
    if (promotedIdx.has(i)) return;
    for (const lid of inp.linkIds || []) {
      const l = linkOf(sub, lid);
      const n = l && sub.getNodeById(l.target_id);
      const name = n?.inputs?.[l.target_slot]?.widget?.name ?? n?.inputs?.[l.target_slot]?.name;
      const id = n && String(n.id);
      if (id && nodes[id] && name) nodes[id].inputs[name] = { vault_in: i };
    }
  });
  // ... and any remaining link that leaves the subgraph (nested subgraphs): matched by the EXACT resolved execution
  // source of each vault input's outer wire (A26 L9.203 - it used to compare only the last segment of the id)
  const root = app.rootGraph ?? app.graph;
  const sgPath = prefix.slice(0, -1);
  const graphPath = sgPath.split(":").slice(0, -1).join(":");
  const bySource = new Map();
  for (const [i, l] of outerSrc) {
    const src = absSource(root, graph, l, graphPath);
    if (src) bySource.set(`${src.id}#${src.slot}`, i);
  }
  for (const n of Object.values(nodes)) for (const [name, v] of Object.entries(n.inputs)) {
    if (Array.isArray(v) && v.length === 2 && typeof v[0] === "string") {
      if (v[0].startsWith(prefix)) n.inputs[name] = [v[0].slice(prefix.length), v[1]];
      else if (!nodes[v[0]]) {
        const i = bySource.get(`${v[0]}#${v[1]}`);
        if (i != null) n.inputs[name] = { vault_in: i };
        else throw new Error("A node inside reads from outside the selection through a path the vault cannot " +
          "follow. Include that source in the selection, or wire it to a subgraph input.");
      }
    }
  }
  // outputs: the inner source of each subgraph output
  const outputs = (sg.outputs || []).map((o, j) => {
    let r = null;
    try { r = sg.resolveSubgraphOutputLink?.(j); } catch (_) { /* below */ }
    const node = r?.outputNode ?? r?.node ?? null;
    const innerSlot = r?.link?.origin_slot ?? r?.slot ?? r?.outputSlot ?? 0;
    // an inner subgraph node resolves to its exact inner source (A26: no "first key starting with that id")
    const rs = node ? relSource(node, innerSlot) : null;
    const id = rs ? rs.id : null;
    const slot = rs ? rs.slot : innerSlot;
    if (!id || !nodes[id]) {
      const lnk = sub?.outputNode?.slots?.[j]?.getLinks?.()?.[0];
      if (lnk && nodes[String(lnk.origin_id)]) return { name: o.label || o.name, type: String(o.type || "*"),
        node: String(lnk.origin_id), slot: lnk.origin_slot };
      throw new Error(`Output "${o.label || o.name}" is not connected inside the subgraph.`);
    }
    return { name: o.label || o.name, type: String(o.type || "*"), node: id, slot };
  });
  const apiPromoted = [];
  for (const p of promoted) for (const t of p.targets) apiPromoted.push({ key: p.key, node: t.node, input: t.input });
  const carried = [];
  for (const ep of extraParams || []) {              // an upgraded old vault's controls, read from the inner widget
    if (!nodes[ep.nodeId] || promoted.some((p) => p.key === ep.key)) continue;
    const w = sg.subgraph?.getNodeById?.(ep.nodeId)?.widgets?.find((x) => x.name === ep.input);
    apiPromoted.push({ key: ep.key, node: ep.nodeId, input: ep.input });
    carried.push({ key: ep.key, name: ep.name, type: ep.type, value: w?.value, options: ep.options,
      ...(ep.input ? { input: ep.input } : {}) });
  }
  const interface_ = {
    in: inputs.filter((_, i) => !promotedIdx.has(i)).map((s) => s),
    out: outputs.map((o) => ({ name: o.name, type: o.type })),
    params: [...promoted.map((p) => ({ key: p.key, name: p.name, type: p.type, value: p.value, options: p.options })),
      ...carried],
  };
  // vault inputs are numbered without the promoted ones
  const remap = new Map();
  let k = 0;
  inputs.forEach((_, i) => { if (!promotedIdx.has(i)) remap.set(i, k++); });
  for (const n of Object.values(nodes)) for (const [name, v] of Object.entries(n.inputs)) {
    if (v && typeof v === "object" && !Array.isArray(v) && "vault_in" in v) n.inputs[name] = { vault_in: remap.get(v.vault_in) };
  }
  const outputsNode = Object.values(nodes).some((n) => nodeDefOf(n.class_type)?.output_node);
  const inputMap = inputs.map((_, i) => i).filter((i) => !promotedIdx.has(i));
  return { api: { nodes, inputs: interface_.in, outputs, promoted: apiPromoted }, interface: interface_, outputsNode,
    inputMap };
}

function exportUi(sg) {
  const defs = [];
  const seen = new Set();
  const walk = (subgraph) => {
    if (!subgraph || seen.has(subgraph.id)) return;
    seen.add(subgraph.id);
    defs.push(subgraph.asSerialisable ? subgraph.asSerialisable() : subgraph.export?.());
    for (const n of subgraph.nodes || subgraph._nodes || []) if (isSubgraphNode(n)) walk(n.subgraph);
  };
  walk(sg.subgraph);
  return { root: sg.subgraph.id, definitions: defs, title: sg.title, size: [...sg.size], promoted: promotedOf(sg)
    .map((p) => ({ name: p.name, value: p.value })) };
}

// ── creating a vault from a subgraph node ───────────────────────────────────────────────────────────────────
const MAX_VAULT_OUTPUTS = 256;                     // nodes/secure_subgraph.py MAX_OUTPUTS

/** VAULT_PAYLOAD_VALIDATION (A26 L9.203): the extracted graph is complete and consistent before anything is sealed. */
function validateBuilt(built) {
  const fail = (m) => { throw new ProtectError("VAULT_PAYLOAD_VALIDATION", m); };
  const { nodes, inputs, outputs, promoted } = built.api;
  if (!Object.keys(nodes).length) fail("This subgraph has no nodes that run (nothing to protect).");
  if (outputs.length > MAX_VAULT_OUTPUTS) fail(`A vault can have at most ${MAX_VAULT_OUTPUTS} outputs (this has ${outputs.length}).`);
  const outCount = (id) => (nodeDefOf(nodes[id]?.class_type)?.output || []).length;
  for (const [id, n] of Object.entries(nodes)) {
    if (!nodeDefOf(n.class_type)) fail(`Node ${id} is a "${n.class_type}", which this ComfyUI does not have.`);
    for (const [name, v] of Object.entries(n.inputs || {})) {
      if (Array.isArray(v) && v.length === 2 && typeof v[0] === "string") {
        if (!nodes[v[0]]) fail(`Input "${name}" of node ${id} reads from node ${v[0]}, which is not inside.`);
        if (!(Number.isInteger(v[1]) && v[1] >= 0 && v[1] < outCount(v[0]))) fail(`Input "${name}" of node ${id} reads output ${v[1]} of node ${v[0]}, which does not exist.`);
      } else if (v && typeof v === "object" && "vault_in" in v) {
        if (!(Number.isInteger(v.vault_in) && v.vault_in >= 0 && v.vault_in < inputs.length)) fail(`Input "${name}" of node ${id} names vault input ${v.vault_in}, which does not exist.`);
      }
    }
  }
  outputs.forEach((o, j) => {
    if (!nodes[o.node] || !(o.slot >= 0 && o.slot < outCount(o.node))) fail(`Vault output ${j} ("${o.name}") does not point at an existing output inside.`);
  });
  for (const p of promoted || []) if (!nodes[p.node]) fail(`The control "${p.key}" targets node ${p.node}, which is not inside.`);
}

/**
 * "Protect selection" / "Protect this subgraph" as ONE transaction (A26 L9.203): stages per _h2v_protect_tx.js
 * STAGES; any failure restores the exact original graph (never a leftover ordinary subgraph) and names the stage.
 */
async function protectTransaction(nodes, opts) {
  const graph = nodes[0].graph;
  const single = nodes.length === 1 && isSubgraphNode(nodes[0]);
  let sg = single ? nodes[0] : null, manifest = null, built = null, res = null, vault = null, before = null, wires = null;
  let chains = [];
  try {
    await runTransaction(app, [
      ["SELECTION_VALIDATION", () => {
        if (nodes.some((n) => n.graph !== graph)) throw new ProtectError("SELECTION_VALIDATION", "Select nodes from one graph.");
        if (nodes.some((n) => VAULT_TYPES.has(n.type))) {
          throw new ProtectError("SELECTION_VALIDATION", "The selection contains a vault; protect the nodes around it separately.");
        }
      }],
      ["BOUNDARY_CAPTURE", () => { manifest = single ? null : captureBoundary(graph, nodes); }],
      ["NATIVE_SUBGRAPH_CONVERSION", () => {
        if (!single) sg = graph.convertToSubgraph(new Set(nodes))?.node ?? null;
        if (!sg) throw new ProtectError("NATIVE_SUBGRAPH_CONVERSION", "The selection could not be turned into a subgraph.");
      }],
      ["SUBGRAPH_INTERFACE_VALIDATION", () => {
        if (manifest) verifyConversion(graph, sg, manifest);
        if ((sg.outputs || []).length > MAX_VAULT_OUTPUTS) {
          throw new ProtectError("SUBGRAPH_INTERFACE_VALIDATION", `A vault can have at most ${MAX_VAULT_OUTPUTS} outputs.`);
        }
        removeVaultOutputs(sg, opts.dropOutputs);
      }],
      ["INNER_GRAPH_EXTRACTION", async () => { built = await buildApi(sg, opts.extraParams || []); }],
      ["VAULT_PAYLOAD_VALIDATION", () => validateBuilt(built)],
      ["ENCRYPTION_AND_SEALING", async () => {
        const r = await post("/h2vault/vault/protect", { password: opts.password, profile: opts.profile,
          recipients: opts.recipients, editors: opts.editors, interface: built.interface, api: built.api, ui: exportUi(sg),
          outputs_node: built.outputsNode, client_id: api.clientId, ...(opts.conceal ? { conceal: opts.conceal } : {}),
          ...(opts.downloads?.length ? { downloads: opts.downloads } : {}), ...(opts.lock ? { lock: opts.lock } : {}) });
        if (!r.ok) throw new ProtectError("ENCRYPTION_AND_SEALING", r.data?.error || `Locking failed (${r.status}).`);
        res = r.data;
        built.public = serverPublic(res);                  // V3: a concealed vault publishes the server's whitelist
      }],
      ["VAULT_NODE_INSERTION", () => {
        before = outerWires(graph, sg);
        const type = built.outputsNode ? "H2Vault_ProtectedSubgraphOutput" : "H2Vault_ProtectedSubgraph";
        vault = LiteGraph.createNode(type);
        if (!vault) throw new ProtectError("VAULT_NODE_INSERTION", `${type} is not registered (is the pack loaded?).`);
        vault.properties = { ...(vault.properties || {}), h2vault: { interface: publicInterface(built), profile: res.profile,
          node_count: res.node_count, title: sg.title, vault_id: res.vault_id, outputs_node: !!built.outputsNode,
          input_map: built.inputMap || null,
          ...(res.public_lock ? { lock: lockPublic(res.public_lock), lock_node: opts.lock?.node ?? null } : {}) } };
        vault.widgets.find((w) => w.name === "vault_id").value = res.vault_id;
        vault.widgets.find((w) => w.name === "vault_payload").value = res.payload;
        // a FRESH id: Nodes 2.0 keys a node's view by id and kept showing the subgraph's view ("New Subgraph",
        // "Enter subgraph") on the vault; nothing outside refers to this subgraph node's id (A26 L9.203)
        wires = captureWires(graph, sg);
        // removing the subgraph node can delete reroutes only its wires used: keep their chains to re-make them
        chains = [...wires.ins, ...wires.outs].filter((c) => c.parent != null).map((c) => rerouteChain(graph, c.parent))
          .filter(Boolean);
        vault.pos = [...sg.pos];
        graph.remove(sg);
        graph.add(vault);
        applyInterface(vault);
        // the frontend names every converted subgraph "New Subgraph": a vault made from one is called "H2Vault"
        const named = typeof opts.title === "string" ? opts.title.trim().slice(0, 80) : "";
        const t = named || (sg.title && sg.title !== "New Subgraph" ? sg.title : "H2Vault");
        vault.title = t;
        vault.properties.h2vault.title = t;
      }],
      ["EXTERNAL_WIRE_RESTORATION", () => {
        for (const ch of chains) {
          if (!ensureReroutes(graph, ch)) {
            throw new ProtectError("EXTERNAL_WIRE_RESTORATION", "A wire's reroute dots could not be re-made on the vault.");
          }
        }
        restoreWires(graph, wires, vault, (i) => vaultSlotOf(vault, built.inputMap, i));
      }],
      ["FINAL_GRAPH_VALIDATION", () => {
        const kept = new Set(built.inputMap || []);
        const promotedIdx = new Set((sg.inputs || []).map((_, i) => i).filter((i) => !kept.has(i)));
        verifyVaultWiring(graph, vault, before, (i) => vaultSlotOf(vault, built.inputMap, i), promotedIdx);
        removeDefinitionIfUnused(sg);
      }],
    ], { onStage: opts.onStage });
  } catch (e) {
    // L9.249 V6: sealing already stored this tab's run key for the new vault (Locked profile); the vault no longer
    // exists in the graph, so drop that server session too. Best effort: the graph is already restored.
    if (res?.vault_id) await dropProtectSession(res.vault_id);
    throw e;
  }
  if (opts.profile === "locked") markRunUnlocked(res.vault_id);
  updateStatusCard(vault);
  graph.setDirtyCanvas?.(true, true);
  return vault;
}

/** V6: ask the server to forget the run session a failed protect left behind (POST /h2vault/vault/protect/abort). */
async function dropProtectSession(vaultId) {
  try {
    const r = await post("/h2vault/vault/protect/abort", { vault_id: vaultId, client_id: api.clientId });
    LOG("dropped the run session of the vault a failed protect made", vaultId, r.data?.dropped);
  } catch (err) { console.warn("[H2Vault] could not drop the failed protect's run session:", err); }
}

async function protectSubgraphNode(sg, opts) {
  const built = await buildApi(sg);
  const ui = exportUi(sg);
  const r = await post("/h2vault/vault/protect", { password: opts.password, profile: opts.profile,
    recipients: opts.recipients, editors: opts.editors, interface: built.interface, api: built.api, ui,
    outputs_node: built.outputsNode, client_id: api.clientId, ...(opts.conceal ? { conceal: opts.conceal } : {}),
          ...(opts.downloads?.length ? { downloads: opts.downloads } : {}) });
  if (!r.ok) throw new Error(r.data.error || `Locking failed (${r.status}).`);
  const v = makeVaultNode(sg.graph, r.data, built, sg);
  removeDefinitionIfUnused(sg);
  if (opts.profile === "locked") markRunUnlocked(r.data.vault_id);
  return v;
}

/** The locked vault node (built = {interface, outputsNode, inputMap}); replaces `replace` (a subgraph node) in place. */
function makeVaultNode(graph, res, built, replace) {
  const type = built.outputsNode ? "H2Vault_ProtectedSubgraphOutput" : "H2Vault_ProtectedSubgraph";
  const v = LiteGraph.createNode(type);
  built.public = serverPublic(res);                        // V3: a concealed vault publishes the server's whitelist
  v.properties = { ...(v.properties || {}), h2vault: { interface: publicInterface(built), profile: res.profile,
    node_count: res.node_count, title: replace?.title, vault_id: res.vault_id, outputs_node: !!built.outputsNode,
    input_map: built.inputMap || null,
    ...(res.public_lock ? { lock: lockPublic(res.public_lock), lock_node: res.lock_node ?? null } : {}) } };
  v.widgets.find((w) => w.name === "vault_id").value = res.vault_id;
  v.widgets.find((w) => w.name === "vault_payload").value = res.payload;
  if (!replace) {
    graph.add(v);
    applyInterface(v);
    return v;
  }
  const wires = replaceNode(graph, replace, v);
  applyInterface(v);                                         // the in_<k> / out_<j> sockets exist from here on
  restoreWires(graph, wires, v, (i) => vaultSlotOf(v, built.inputMap, i));
  if (replace.title) v.title = replace.title;
  return v;
}

/** The public lock part as stored on the node: the whitelist + the locked-value count. */
function lockPublic(pub) {
  const w = whitelistLock(pub);
  return w ? { ...w, count: Number(pub?.count) || w.rows.length } : null;
}

function removeDefinitionIfUnused(sg) {
  const root = app.rootGraph ?? app.graph;
  const ids = vaultDefIds(sg.subgraph);
  if (!ids.size || !root?.subgraphs) return;
  // a definition stays only if a node OUTSIDE the vault (the root, or a definition not in the vault) still uses it
  const used = new Set();
  const visit = (g, seen = new Set()) => {
    if (!g || seen.has(g)) return;
    seen.add(g);
    for (const n of g.nodes || g._nodes || []) {
      if (!isSubgraphNode(n) || n === sg) continue;
      used.add(n.subgraph?.id);
      if (!ids.has(n.subgraph?.id)) visit(n.subgraph, seen);
    }
  };
  visit(root);
  for (const id of ids) if (!used.has(id)) root.subgraphs.delete?.(id);
}

// ── dialogs (V1: js/_vault_ui.js design system; docs/h2vault/V1_cnp_vault_ux_spec.md) ─────────────────────────
const SHORT = {
  sealed_installs: { title: "Sealed", tag: "Recommended", tone: "ok" },
  sealed_licensed: { title: "Licensed", tag: "Licence per person", tone: "" },
  locked: { title: "Locked", tag: "Password to run", tone: "" },
  sealed_portable: { title: "Portable", tag: "Obfuscation only", tone: "warn" },
};
const PROTECT_FOOT = "The password is never stored. Keep it safe: without it nobody can open the vault.";

function profileFacts(p) {
  return factList([["Runs", p.run], ["Opens for editing", p.edit], ["Network", p.net], ["Runs on", p.where],
    ["Key", p.custody], ["Protection", p.security]]);
}

const splitCodes = (text) => String(text || "").split(/\s+/).map((s) => s.trim()).filter(Boolean);

/**
 * THE protect dialog (spec 4.1): one dialog for "lock a selection" and "protect this subgraph". `run(opts)` performs
 * the lock (protectTransaction) while the dialog shows its stages; a failure is shown inside the dialog, which stays
 * open. Resolves with the vault node, or null when cancelled.
 */
function protectDialog({ count, kind, summary, title, defaultProfile, run, exposure = null }) {
  const many = count === 1 ? "" : "s";
  const d = vaultDialog({
    title: kind === "subgraph" ? `Lock "${title || "subgraph"}" as a vault` : `Lock ${count} node${many} as a vault`,
    subtitle: kind === "subgraph" ? "The subgraph becomes one node whose inside is encrypted."
      : `${count === 1 ? "It becomes" : "They become"} one node whose inside is encrypted. Everything outside stays as it is.`,
    width: 600 });
  d.body.append(capsule(summary));
  if (summary.hasSubgraph && kind !== "subgraph") {
    d.body.append(noticeEl("info", "The selection contains a subgraph. If ComfyUI loses one of its wires while " +
      "grouping, nothing is changed and you are told - then unpack it (right-click › Unpack Subgraph) and lock again."));
  }
  const name = textField({ label: "Vault name", value: title || "H2Vault", maxLength: 80,
    hint: "Shown on the node. Anyone who receives the workflow can read the name." });
  const facts = vel("div");
  const choice = choiceCards({ label: "Who can run it", value: defaultProfile || "sealed_installs",
    options: PROFILES.map((p) => ({ id: p.id, title: SHORT[p.id]?.title ?? p.title, tag: SHORT[p.id]?.tag,
      tone: SHORT[p.id]?.tone, summary: p.run, disabled: p.disabled })),
    onChange: () => render() });
  const hosted = PROFILES.find((p) => p.id === "owner_hosted");
  const pw2 = passwordField({ label: "Repeat the password" });
  const pw = passwordField({ label: "Vault password", strength: true, generate: true,
    hint: "Opens the vault for editing, together with your authenticator app.", onGenerate: (v) => pw2.setValue(v) });
  const recip = textArea({ label: "Installation codes, one per line", placeholder: "h2vk1:...", rows: 3,
    hint: "Each person finds theirs under right-click on a vault › My installation code. Yours is always included." });
  const others = disclosure("Other installations that may run it (optional)");
  others.body.append(recip.el, vel("div", { class: "h2v-row" }, [vbutton("Import key file…", { small: true,
    onClick: async () => {
      const k = await importKeyFile();
      if (k?.error) { d.notice("danger", k.error); return; }
      if (k && !recip.input.value.includes(k.code)) recip.input.value = `${recip.input.value.trim()}\n${k.code}`.trim();
    } })]));
  function render() {
    const p = PROFILES.find((x) => x.id === choice.value());
    facts.replaceChildren(profileFacts(p));
    if (p.risk === "warn") facts.append(vel("div", { style: { marginTop: "8px" } }, [noticeEl("warn", p.security)]));
    others.el.style.display = p.id === "sealed_installs" ? "" : "none";
  }
  d.body.append(name.el, choice.el, facts);
  if (hosted) {
    d.body.append(vel("p", { class: "h2v-dim", text: "Owner-hosted vaults (recipients send inputs to your " +
      "server and never receive the graph) are planned." }));
  }
  d.body.append(vel("div", { class: "h2v-grid2" }, [pw.el, pw2.el]), others.el);
  // V3: "Conceal models and nodes" -> the "Choose what to expose" step (docs/h2vault/V3_concealment_design.md)
  let step = null, refusedNotice = false;
  const stepHost = vel("div");
  if (exposure) {
    const concealSw = switchRow("Conceal models and nodes", { checked: false, onChange: (on) => {
      if (on && !step) {
        step = exposeStep({ controls: exposure.controls, sockets: exposure.sockets, previews: exposure.previews,
          title: () => name.input.value, check: exposure.check,
          // a refusal notice goes as soon as the listed problems are fixed (it must not contradict the step)
          onChecked: (r) => { if (r.ok && refusedNotice) { d.notice(null); refusedNotice = false; } },
          onUnconceal: () => {
            refusedNotice = false;
            if (concealSw.checked()) concealSw.el.click();                 // the switch's own handler hides the step
            d.notice("info", "Concealment is off: the vault is locked as an ordinary vault. Its outputs are kept, " +
              "and whoever runs it sees inner node types in error messages and the real file names in its controls.");
          } });
        name.input.addEventListener("input", () => step?.refresh());
      }
      stepHost.replaceChildren(...(on && step ? [vel("p", { class: "h2v-dim", text: "Tick what the person who runs " +
        "this vault may set, and how each is called. Model files become choices with names you pick." }), step.el] : []));
      d.panel.style.setProperty("--h2v-w", on ? "1040px" : "600px");
      if (on) step?.refresh();
    } });
    d.body.append(vel("div", { class: "h2v-block" }, [concealSw.el, vel("p", { class: "h2v-block__hint",
      text: "The recipient sees only the controls you choose - never model, node or custom-node names." })]), stepHost);
    exposure.on = () => concealSw.checked();
  }
  // V7: "Downloads for people who run it" - one HTTPS link per model file; kept inside the encryption
  const links = [];
  if (exposure?.models?.length) {
    const dl = disclosure(`Downloads for people who run it (optional, ${exposure.models.length} model file` +
      `${exposure.models.length === 1 ? "" : "s"})`);
    dl.body.append(vel("p", { class: "h2v-dim", text: "Give a download link (https://) for each model file. When " +
      "someone runs this vault on a ComfyUI without the file, it downloads by itself under a private name and is " +
      "checked against your file. The links and file names stay inside the vault." }));
    for (const file of exposure.models) {
      const f = textField({ label: file, value: "", maxLength: 2000, hint: "" });
      f.input.placeholder = "https://...";
      links.push({ file, input: f.input });
      dl.body.append(f.el);
    }
    d.body.append(dl.el);
  }
  render();
  d.status(PROTECT_FOOT);
  d.addAction("Cancel", { onClick: () => d.close(null) });
  const go = async () => {
    if (d.busy) return;
    d.notice(null);
    if (pw.value().length < 8) { d.notice("danger", "Use at least 8 characters for the vault password."); pw.input.focus(); return; }
    if (pw.value() !== pw2.value()) { d.notice("danger", "The two passwords differ."); pw2.input.focus(); return; }
    let conceal = null, dropOutputs = [];
    if (exposure?.on?.() && step) {
      const r = await step.ready();
      if (!r.ok) {
        const n = r.problems?.length || 1;
        d.notice("danger", `${n} thing${n === 1 ? "" : "s"} to fix under "Choose what to expose" before locking - ` +
          "each one is marked on its row with a way to fix it.");
        refusedNotice = true;
        step.focusProblem();
        return;
      }
      conceal = r.conceal;
      dropOutputs = r.dropped || [];
    }
    const downloads = links.map((l) => ({ file: l.file, url: l.input.value.trim() })).filter((l) => l.url);
    const badLink = downloads.find((l) => !/^https:\/\//i.test(l.url));
    if (badLink) { d.notice("danger", "Download links must start with https://."); return; }
    d.setBusy(true, downloads.length ? "Locking (checking model files)…" : "Locking…");
    d.status(`${stageLabel("SELECTION_VALIDATION")}…`);
    try {
      const vault = await run({ profile: choice.value(), password: pw.value(), recipients: splitCodes(recip.input.value),
        title: name.input.value, conceal, downloads, dropOutputs,
        onStage: (s) => d.status(s === "COMMIT" ? "Locked." : `${stageLabel(s)}…`) });
      d.close(vault);
    } catch (e) {
      LOG("protect failed", e?.stage, e?.message);
      d.setBusy(false);
      d.status(PROTECT_FOOT);
      d.notice(e?.busy ? "warn" : "danger", protectFailureText(e));
    }
  };
  d.addAction(kind === "subgraph" ? "Lock subgraph" : `Lock ${count} node${many}`, { primary: true, onClick: go });
  d.onSubmit(go);
  return d.result;
}

/**
 * Password (+ authenticator code) dialog that STAYS OPEN until `submit` succeeds (spec 4.2 / 4.3 / 4.5).
 * submit({password, code}) -> {ok: true, ...} | {enrol: true} | {error: string}. Resolves with that result or null.
 */
function credentialDialog({ title, subtitle, needCode = true, primary = "Open vault", submit }) {
  const d = vaultDialog({ title, subtitle, width: 440 });
  const pw = passwordField({ label: "Vault password", autocomplete: "current-password" });
  const code = needCode ? codeField({ allowRecovery: true, hint: "Or one of your recovery codes. A code works once: " +
    "if you just used one, wait for the next." }) : null;
  if (code) d.onCleanup(code.destroy);
  d.body.append(pw.el);
  if (code) d.body.append(code.el);
  d.addAction("Cancel", { onClick: () => d.close(null) });
  const go = async () => {
    if (d.busy) return;
    d.notice(null);
    if (!pw.value()) { d.notice("danger", "Type the vault password."); pw.input.focus(); return; }
    if (code && !code.value()) { d.notice("danger", "Type the code your authenticator app shows now."); code.input.focus(); return; }
    d.setBusy(true, "Checking…");
    let out;
    try { out = await submit({ password: pw.value(), code: code ? code.value() : "" }); }
    catch (e) { out = { error: String(e?.message || e) }; }
    if (out?.ok || out?.enrol) { d.close(out); return; }
    d.setBusy(false);
    d.notice("danger", out?.error || "That did not work. Check the password and try again.");
    if (code) { code.clear(); code.input.focus(); } else pw.input.select();
  };
  d.addAction(primary, { primary: true, onClick: go });
  d.onSubmit(go);
  return d.result;
}

/** A server answer for a failed open / access check, in words (reused code, clock drift, wrong password ...). */
function authError(r, fallback) {
  const d = r?.data || {};
  if (d.reason === "reused") return `That code was already used. Wait for the next one${d.next_in ? ` (${d.next_in} s)` : ""}, then type it.`;
  if (d.reason === "clock") return d.error || "The code is for another time: this computer's or the phone's clock is off. Set both to automatic time.";
  if (r?.status === 429) return d.error || "Too many attempts. Wait a few minutes, then try again.";
  return d.error || fallback;
}

async function enrolDialog() {
  const st = await post("/h2vault/2fa/enrol/begin", {});
  if (!st.ok) { toast(st.data.error || "Could not start the setup.", "error"); return false; }
  const data = st.data;
  const d = vaultDialog({ title: "Set up two-factor for H2Vault",
    subtitle: "Opening a vault on this installation needs a code from an authenticator app, as well as the password.",
    width: 640 });
  const qr = vel("div", { class: "h2v-qr" }, [vel("img", { alt: "QR code for your authenticator app",
    src: `data:image/svg+xml;charset=utf-8,${encodeURIComponent(data.qr_svg || "")}` })]);
  const scan = stepSection(1, "Scan the code with your authenticator app",
    vel("div", { class: "h2v-row", style: { alignItems: "flex-start", gap: "16px", flexWrap: "wrap" } }, [qr,
      vel("div", { style: { flex: "1", minWidth: "220px", display: "flex", flexDirection: "column", gap: "8px" } }, [
        vel("p", { class: "h2v-dim", text: "Google Authenticator, Microsoft Authenticator, 1Password, Aegis and " +
          "others work. No camera? Type the setup key instead:" }),
        copyRow({ label: "setup key", value: data.secret_grouped }),
        vel("p", { class: "h2v-dim", text: `${data.issuer} · ${data.account} · ${data.algorithm}, ${data.digits} ` +
          `digits, every ${data.period} s` })])]));
  const codes = data.recovery_codes || [];
  const saved = vel("input", { type: "checkbox" });
  const download = () => {
    const url = URL.createObjectURL(new Blob([`H2Vault recovery codes (each works once)\n\n${codes.join("\n")}\n`],
      { type: "text/plain" }));
    const a = vel("a", { href: url, download: "h2vault-recovery-codes.txt" });
    document.body.append(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
  };
  const copyAll = vbutton("Copy all", { small: true, onClick: async () => {
    try { await navigator.clipboard.writeText(codes.join("\n")); copyAll.querySelector(".h2v-btn__label").textContent = "Copied"; }
    catch (_) { /* the grid is selectable */ }
  } });
  const keep = stepSection(2, "Save your recovery codes",
    vel("p", { class: "h2v-dim", text: "Each works once instead of a code if you lose the phone. They are not shown again." }),
    vel("div", { class: "h2v-codes" }, codes.map((c) => vel("span", { text: c }))),
    vel("div", { class: "h2v-row", style: { justifyContent: "space-between", flexWrap: "wrap" } }, [
      vel("label", { class: "h2v-check" }, [saved, vel("span", { text: "I saved the recovery codes" })]),
      vel("div", { class: "h2v-row" }, [copyAll, vbutton("Download .txt", { small: true, onClick: download })])]));
  const code = codeField({ label: "Code from the app" });
  d.onCleanup(code.destroy);
  const confirm = stepSection(3, "Type the code your app shows now", code.el);
  d.body.append(scan, keep, confirm);
  d.addAction("Cancel", { onClick: () => d.close(false) });
  const go = async () => {
    if (d.busy) return;
    d.notice(null);
    if (!saved.checked) { d.notice("danger", "Confirm that you saved the recovery codes first."); saved.focus(); return; }
    if (!/^\d{6}$/.test(code.value())) { d.notice("danger", "Type the 6-digit code your app shows now."); code.input.focus(); return; }
    d.setBusy(true, "Confirming…");
    const r = await post("/h2vault/2fa/enrol/confirm", { code: code.value() });
    if (r.ok) {
      d.close(true);
      toast("Two-factor is set up. A code works once: the next sign-in needs the next code.", "success", "Two-factor on");
      return;
    }
    d.setBusy(false);
    d.notice("danger", authError(r, "That code is not right. Check the phone's time and type the current code."));
    code.clear();
    code.input.focus();
  };
  d.addAction("Confirm", { primary: true, onClick: go });
  d.onSubmit(go);
  // the dialog takes focus on the first text field, which is the code at the bottom: start at the top instead
  setTimeout(() => d.panel.focus(), 0);
  return d.result;
}

/** Two-factor setup from the vault menu: a second setup first needs a current code or a recovery code (owner: the
 *  pasted setup key is exposed - setting it up again must be possible from here). */
async function twoFactorSetup() {
  const st = await (await api.fetchApi("/h2vault/2fa/status")).json().catch(() => ({}));
  if (st.enrolled) {
    const d = vaultDialog({ title: "Set up the authenticator again",
      subtitle: "Use this when the setup key was shared or the phone changed. The old key stops working.", width: 460 });
    d.body.append(noticeEl("info", `An authenticator is set up on this installation (${st.recovery_codes_left ?? 0} ` +
      "recovery codes left). Confirm with a code from it, or with a recovery code."));
    const code = codeField({ label: "Current code or a recovery code", allowRecovery: true });
    d.onCleanup(code.destroy);
    d.body.append(code.el);
    d.addAction("Cancel", { onClick: () => d.close(false) });
    const go = async () => {
      if (d.busy) return;
      d.notice(null);
      if (!code.value()) { d.notice("danger", "Type a current code or a recovery code."); return; }
      d.setBusy(true, "Checking…");
      const r = await post("/h2vault/2fa/reset", { code: code.value() });
      if (r.ok) { d.close(true); return; }
      d.setBusy(false);
      d.notice("danger", authError(r, "That code is not right."));
      code.clear();
      code.input.focus();
    };
    d.addAction("Replace", { primary: true, onClick: go });
    d.onSubmit(go);
    if (!(await d.result)) return false;
  }
  return enrolDialog();
}

// ── opening (auth -> native subgraph) and auto-lock on leaving ──────────────────────────────────────────────
async function openVault(v) {
  const st = await (await api.fetchApi("/h2vault/2fa/status")).json().catch(() => ({}));
  if (!st.enrolled) {
    toast("Opening a vault needs an authenticator app on this installation. Set it up now.");
    if (!(await enrolDialog())) return;
  }
  const payload = v.widgets.find((w) => w.name === "vault_payload")?.value;
  const vaultId = v.widgets.find((w) => w.name === "vault_id")?.value;
  const title = v.title || "vault";
  let opened = null;
  const out = await credentialDialog({ title: `Open "${title}"`, primary: "Open vault",
    subtitle: "Type the vault password and the code your authenticator app shows.",
    submit: async ({ password, code }) => {
      const r = await post("/h2vault/vault/open", { payload, vault_id: vaultId, password, code, client_id: api.clientId });
      if (r.ok) { opened = r.data; return { ok: true }; }
      if (r.data.needs_enrolment) return { enrol: true };
      return { error: authError(r, "Could not open the vault.") };
    } });
  if (!out) return;
  if (out.enrol) {
    if (await enrolDialog()) await openVault(v);
    return;
  }
  try {
    await enterOpened(v, opened, payload);
  } catch (e) {
    toast(`The vault opened but could not be shown: ${e?.message || e}`, "error");
  }
}

async function enterOpened(v, res, payload) {
  const graph = v.graph;
  const root = app.rootGraph ?? app.graph;
  let sg;
  const extraParams = reopenParams(vaultInfo(v));        // V5: a Locked node's open controls survive an edit
  if (res.ui?.definitions?.length) {
    // nested definitions first, the vault's own last
    const defs = [...res.ui.definitions];
    const own = defs.find((d) => d.id === res.ui.root) ?? defs[0];
    for (const d of defs) if (d !== own && !root.subgraphs?.has?.(d.id)) root.createSubgraph(d);
    const subgraph = root.subgraphs?.get?.(own.id) ?? root.createSubgraph(own);
    sg = LiteGraph.createNode(subgraph.id);
    if (!sg) throw new Error("This front end cannot create the subgraph node.");
    const inputMap = vaultInfo(v).input_map;
    const wires = replaceNode(graph, v, sg);
    if (res.ui.size) sg.size = [...res.ui.size];
    sg.title = v.title || res.ui.title;            // the vault node's title wins (the layout keeps the pre-lock one)
    try { if (sg.title) subgraph.name = sg.title; } catch (_) { /* the breadcrumb then shows the layout's name */ }
    restoreWires(graph, wires, sg, (slot) => subgraphSlotOf(v, inputMap, slot));
  } else {
    // H2Vault never writes the first (flattened) vault layout, so a vault without an editable layout is foreign
    post("/h2vault/vault/cancel", { edit_token: res.edit_token });
    throw new Error("This vault has no editable layout. Ask its author for a fresh copy.");
  }
  OPEN.set(sg, { token: res.edit_token, vaultId: v.widgets.find((w) => w.name === "vault_id").value, payload,
    profile: res.profile, info: { ...vaultInfo(v) }, title: v.title, graph, extraParams,
    conceal: res.conceal ?? null, removeConceal: false });
  app.canvas.openSubgraph?.(sg.subgraph, sg);
  LOG("opened", sg.id);
}

let LOCKING = false;
async function lockOpened(sg, sess) {
  if (LOCKING) return;
  LOCKING = true;
  try {
    const built = await buildApi(sg, sess.extraParams);
    const r = await post("/h2vault/vault/commit", { edit_token: sess.token, api: built.api, ui: exportUi(sg),
      interface: built.interface, payload_hash: sess.payloadHash, ...(sess.removeConceal ? { conceal: null } : {}) });
    if (!r.ok) throw new Error(r.data.error || `Locking failed (${r.status}).`);
    OPEN.delete(sg);
    makeVaultNode(sg.graph, { ...r.data, node_count: r.data.node_count, lock_node: sess.info?.lock_node ?? null },
      built, sg);
    removeDefinitionIfUnused(sg);
    if (sess.profile === "locked") markRunUnlocked(sess.vaultId);
    toast("Vault locked again: what you changed is encrypted.", "success", "Vault locked");
  } catch (e) {
    toast(`${e.message} The vault stays open; fix it and leave the subgraph again.`, true);
  } finally { LOCKING = false; }
}

/** Is `g` the vault's subgraph or a subgraph nested anywhere inside it? (Subgraphs carry no parent pointer.) */
function contains(sub, g, seen = new Set()) {
  if (!sub || !g) return false;
  if (g === sub) return true;
  if (seen.has(sub)) return false;
  seen.add(sub);
  for (const n of sub.nodes || sub._nodes || []) if (isSubgraphNode(n) && contains(n.subgraph, g, seen)) return true;
  return false;
}

/** Subgraph definition ids used inside a vault (its own and every nested one). */
function vaultDefIds(sub, out = new Set()) {
  if (!sub || out.has(sub.id)) return out;
  out.add(sub.id);
  for (const n of sub.nodes || sub._nodes || []) if (isSubgraphNode(n)) vaultDefIds(n.subgraph, out);
  return out;
}

function onSetGraph(e) {
  const { newGraph, oldGraph } = e.detail || {};
  for (const [sg, sess] of [...OPEN]) {
    // leaving the vault (to its parent or anywhere outside) locks it; going deeper into a nested subgraph does not
    if (oldGraph && contains(sg.subgraph, oldGraph) && !contains(sg.subgraph, newGraph)) lockOpened(sg, sess);
  }
}

// ── serialization / clipboard / queue guards ────────────────────────────────────────────────────────────────
function lockedForm(sg, sess) {
  // the vault node as of its last encrypted snapshot, placed where the subgraph node is: inputs in_<k> follow the
  // non-promoted subgraph inputs (input_map), promoted controls go back into the p_ widgets' values
  const built = sess.built;
  const info = { ...(sess.info || {}), ...(built ? { interface: publicInterface(built), outputs_node: !!built.outputsNode,
    input_map: built.inputMap } : {}) };
  const map = info.input_map || (sg.inputs || []).map((_, i) => i);
  const params = info.interface?.params || [];
  return { id: sg.id, type: info.outputs_node ? "H2Vault_ProtectedSubgraphOutput" : "H2Vault_ProtectedSubgraph",
    pos: [...sg.pos], size: [...sg.size], flags: {}, order: sg.order ?? 0, mode: sg.mode ?? 0,
    title: sess.title, properties: { h2vault: info, aux_id: PACK_AUX_ID },
    inputs: map.map((i, k) => ({ name: `in_${k}`, label: sg.inputs?.[i]?.label || sg.inputs?.[i]?.name,
      type: sg.inputs?.[i]?.type, link: sg.inputs?.[i]?.link ?? null })),
    outputs: (sg.outputs || []).map((o, j) => ({ name: `out_${j}`, label: o.label || o.name, type: o.type,
      links: o.links ? [...o.links] : null })),
    widgets_values: [sess.vaultId, sess.payload, ...params.map((prm) => prm.value)] };
}

/** Serialized links into a node that became its locked form: target slot = the subgraph input -> in_<k>. */
function remapLinkSlots(serialized, nodeId, map) {
  const fix = (slot) => { const k = (map || []).indexOf(slot); return k < 0 ? slot : k; };
  for (const l of serialized.links || []) {
    if (Array.isArray(l)) { if (l[3] === nodeId) l[4] = fix(l[4]); }
    else if (l && l.target_id === nodeId) l.target_slot = fix(l.target_slot);
  }
}

function scrub(serialized) {
  if (!OPEN.size || !serialized) return serialized;
  const ids = new Set();
  for (const sg of OPEN.keys()) for (const id of vaultDefIds(sg.subgraph)) ids.add(id);
  const strip = (nodes, holder) => (nodes || []).map((n) => {
    for (const [sg, sess] of OPEN) {
      if (n?.id === sg.id && n.type === sg.subgraph?.id) {
        const lf = lockedForm(sg, sess);
        remapLinkSlots(holder, sg.id, lf.properties.h2vault.input_map);
        return lf;
      }
    }
    return n;
  });
  serialized.nodes = strip(serialized.nodes, serialized);
  const defs = serialized.definitions?.subgraphs;
  if (Array.isArray(defs)) {
    for (const d of defs) d.nodes = strip(d.nodes, d);
    serialized.definitions.subgraphs = defs.filter((d) => !ids.has(d.id));
  }
  return serialized;
}

function installGuards() {
  const G = (app.rootGraph ?? app.graph)?.constructor;
  if (G && !G.prototype.__h2vSerialize) {
    const orig = G.prototype.serialize;
    G.prototype.serialize = function (...a) { return scrub(orig.apply(this, a)); };
    G.prototype.__h2vSerialize = true;
  }
  const C = app.canvas?.constructor;
  if (C && C.prototype.copyToClipboard && !C.prototype.__h2vCopy) {
    const orig = C.prototype.copyToClipboard;
    C.prototype.copyToClipboard = function (items, ...a) {
      const sel = items ?? this.selectedItems ?? this.selected_nodes;
      const list = sel instanceof Set ? [...sel] : Array.isArray(sel) ? sel : Object.values(sel || {});
      if (list.some((n) => OPEN.has(n))) {
        toast("An open vault cannot be copied. Leave it (it locks), then copy the vault node.", true);
        return;
      }
      return orig.call(this, items, ...a);
    };
    C.prototype.__h2vCopy = true;
  }
  if (!app.__h2vQueue) {
    RAW_G2P = app.graphToPrompt.bind(app);
    app.graphToPrompt = async function (...a) {
      await snapshotOpen();
      const out = await RAW_G2P(...a);
      if (out?.output) rewriteOpenVaults(out.output);
      return out;
    };
    // the run password of a Locked vault is asked when a prompt is QUEUED, not on every graphToPrompt (other code -
    // Save Video's next-path preview, exports - calls that too)
    const q = api.queuePrompt.bind(api);
    api.queuePrompt = async function (number, data, ...rest) {
      await ensureRunKeys(data?.output);
      return q(number, data, ...rest);
    };
    app.__h2vQueue = true;
  }
  window.addEventListener("beforeunload", () => {
    try { navigator.sendBeacon?.(api.apiURL("/h2vault/vault/forget_run"), JSON.stringify({ client_id: api.clientId })); }
    catch (_) { /* best effort */ }
  });
}

/** The flattened prompt of an OPEN vault -> its locked node: inner nodes out, the vault in, wires re-pointed. */
function rewriteOpenVaults(output) {
  for (const [sg, sess] of OPEN) {
    const prefix = execPrefix(output, sg);
    const built = sess.built;
    if (!prefix || !built) continue;
    const vid = prefix.slice(0, -1);
    const inputs = { vault_id: sess.vaultId, vault_payload: sess.payload };
    for (const [nid, n] of Object.entries(built.api.nodes)) {
      for (const [name, v] of Object.entries(n.inputs)) {
        if (!v || typeof v !== "object" || Array.isArray(v) || !("vault_in" in v)) continue;
        const flat = output[prefix + nid]?.inputs?.[name];
        if (flat !== undefined && inputs[`in_${v.vault_in}`] === undefined) inputs[`in_${v.vault_in}`] = flat;
      }
    }
    for (const prm of built.interface.params || []) {
      const t = (built.api.promoted || []).find((x) => x.key === prm.key);
      const flat = t ? output[prefix + t.node]?.inputs?.[t.input] : undefined;
      inputs[`p_${prm.key}`] = flat !== undefined ? flat : prm.value;
    }
    for (const k of Object.keys(output)) if (k.startsWith(prefix)) delete output[k];
    const outIdx = new Map(built.api.outputs.map((o, j) => [`${o.node}#${o.slot}`, j]));
    for (const n of Object.values(output)) {
      for (const [name, v] of Object.entries(n.inputs || {})) {
        if (!Array.isArray(v) || typeof v[0] !== "string" || !v[0].startsWith(prefix)) continue;
        const j = outIdx.get(`${v[0].slice(prefix.length)}#${v[1]}`);
        if (j != null) n.inputs[name] = [vid, j];
        else delete n.inputs[name];                 // never send an inner id; the server names what is missing
      }
    }
    output[vid] = { class_type: built.outputsNode ? "H2Vault_ProtectedSubgraphOutput" : "H2Vault_ProtectedSubgraph", inputs,
      _meta: { title: sess.title || "H2Vault" } };
  }
  return output;
}

let SNAPPING = false;
async function snapshotOpen() {
  if (!OPEN.size || SNAPPING) return;
  SNAPPING = true;
  try {
    for (const [sg, sess] of OPEN) {
      const built = await buildApi(sg, sess.extraParams);
      const r = await post("/h2vault/vault/snapshot", { edit_token: sess.token, api: built.api, ui: exportUi(sg),
        interface: built.interface, payload_hash: sess.payloadHash, ...(sess.removeConceal ? { conceal: null } : {}) });
      if (!r.ok) throw new Error(r.data.error || "Could not encrypt the open vault for this run.");
      sess.payload = r.data.payload;
      built.public = serverPublic(r.data);                 // V3 (see publicInterface)
      sess.built = built;
      sess.payloadHash = undefined;
      sess.info = { ...sess.info, interface: publicInterface(built), outputs_node: built.outputsNode,
        node_count: r.data.node_count };
    }
  } finally { SNAPPING = false; }
}

async function ensureRunKeys(output) {
  for (const [id, n] of Object.entries(output || {})) {
    if (!VAULT_TYPES.has(n.class_type)) continue;
    const graphNode = (app.rootGraph ?? app.graph).getNodeById?.(id.split(":")[0]);
    const info = graphNode ? vaultInfo(graphNode) : {};
    const vid = n.inputs?.vault_id;
    if (info.profile !== "locked" || RUN_UNLOCKED.has(vid)) continue;
    // V5: Locked nodes made together share their password - one prompt unlocks the whole set
    if (info.lock_set && SET_PASSWORDS.has(info.lock_set)) {
      const r = await post("/h2vault/vault/unlock_run", { payload: n.inputs.vault_payload, vault_id: vid,
        password: SET_PASSWORDS.get(info.lock_set), client_id: api.clientId });
      if (r.ok) { markRunUnlocked(vid); continue; }
    }
    let typed = "";
    const ok = await credentialDialog({ title: `Run "${graphNode?.title || "this vault"}"`, needCode: false,
      primary: "Run", subtitle: "This vault is Locked: it needs its password once per browser tab.",
      submit: async ({ password }) => {
        const r = await post("/h2vault/vault/unlock_run", { payload: n.inputs.vault_payload, vault_id: vid, password,
          client_id: api.clientId });
        if (r.ok) typed = password;
        return r.ok ? { ok: true } : { error: authError(r, "Wrong password.") };
      } });
    if (!ok) { SET_PASSWORDS.clear(); throw new Error("Run cancelled: a Locked vault needs its password."); }
    markRunUnlocked(vid);
    if (info.lock_set) SET_PASSWORDS.set(info.lock_set, typed);
  }
  SET_PASSWORDS.clear();                                  // held only while this queue's prompts are answered
}
const SET_PASSWORDS = new Map();

// ── menus ───────────────────────────────────────────────────────────────────────────────────────────────────
/** The canvas selection as canvas items (nodes, groups, reroutes); _vault_selection.js decides what is locked. */
function selectedItemsOf(canvas) {
  const s = canvas?.selectedItems ?? canvas?.selected_nodes;
  return s instanceof Set ? [...s] : Object.values(s || {});
}

/**
 * Frontend 1.53.10 bug (measured 2026-10-25): convertToSubgraph INSIDE a subgraph drops the wires that come from the
 * containing subgraph's own input node - the new subgraph node's inputs exist but are unwired, so a vault made there
 * ran without its inputs. Record them before converting ...
 */
function wiresFromParentInputs(graph, nodes) {
  const io = graph?.inputNode;
  if (!io) return [];
  const out = [];
  for (const n of nodes) {
    (n.inputs || []).forEach((inp, i) => {
      const l = linkOf(graph, inp?.link);
      if (l && String(l.origin_id) === String(io.id)) out.push({ slot: l.origin_slot, node: String(n.id), input: i,
        type: inp.type });
    });
  }
  return out;
}

/** ... and put each back on the ONE subgraph input that feeds the same inner socket. A26 L9.203: the old fallback
 *  ("first unlinked input of the same type, in order") could swap two INT inputs; an unplaceable wire now throws. */
function reconnectParentInputs(graph, sg, wires) {
  const io = graph.inputNode;
  const sub = sg?.subgraph;
  if (!io || !sub) return;
  for (const w of wires) {
    const hits = [];
    (sub.inputs || []).forEach((si, i) => {
      if ((si.linkIds || []).some((lid) => {
        const L = linkOf(sub, lid);
        return L && String(L.target_id) === w.node && L.target_slot === w.input;
      })) hits.push(i);
    });
    if (hits.length !== 1) {
      throw new Error(`A wire from the surrounding subgraph into node ${w.node} cannot be restored unambiguously ` +
        `(${hits.length} matching inputs).`);
    }
    const idx = hits[0];
    if (sg.inputs[idx]?.link != null) continue;                 // the frontend kept it
    io.slots?.[w.slot]?.connect(sg.inputs[idx], sg);
  }
}

/**
 * V1 one-step lock: whatever is selected (nodes, a group, or one subgraph node) -> ONE dialog -> the A26 transaction
 * (convert to a native subgraph + protect, one undo step, exact rollback). `items` overrides the canvas selection
 * (the node menu on an unselected node). Resolves with the vault node or null.
 */
async function lockSelection(canvas, profileHint, items = null) {
  const r = resolveLockSelection(items ?? selectedItemsOf(canvas), { LiteGraph: globalThis.LiteGraph });
  if (r.problems.length) { toast(r.problems[0], true); return null; }
  let boundary = null;
  if (r.kind === "nodes") {
    try { boundary = captureBoundary(r.nodes[0].graph, r.nodes); } catch (_) { boundary = { entering: [], leaving: [] }; }
  }
  const summary = summarizeSelection(r.nodes, boundary);
  // A failed attempt restores the graph by reloading it (new node objects, same ids) and the dialog stays open for a
  // retry: each attempt therefore takes the nodes by id from the graph on screen, never the stale objects.
  const ids = r.nodes.map((n) => n.id);
  const live = () => {
    if (r.nodes.every((n) => n.graph && n.graph.getNodeById?.(n.id) === n)) return r.nodes;
    const g = app.canvas?.graph;
    const again = ids.map((id) => g?.getNodeById?.(id)).filter(Boolean);
    if (again.length !== ids.length) {
      throw new ProtectError("SELECTION_VALIDATION", "The selected nodes are no longer in the graph on screen. " +
        "Close this dialog and select them again.");
    }
    return again;
  };
  const vault = await protectDialog({ count: r.nodes.length, kind: r.kind, summary, title: r.title,
    defaultProfile: profileHint || "sealed_installs", run: async (opts) => protectTransaction(live(), opts),
    exposure: exposureOf(r, boundary) });
  if (!vault) return null;
  try { canvas?.deselectAll?.(); canvas?.select?.(vault); } catch (_) { /* selection is a nicety */ }
  const what = r.kind === "subgraph" ? "the subgraph" : `${r.nodes.length} node${r.nodes.length === 1 ? "" : "s"}`;
  toast(`Locked ${what} into "${vault.title}". Double-click it to open (password + authenticator).`, "success",
    "Vault locked");
  return vault;
}

/** V3 (lead decision 3): an editor of an open concealed vault may remove the concealment - after confirming. The
 *  removal happens when the vault is locked again (commit / snapshot send `conceal: null`). */
function concealMenuItems(sess) {
  if (!sess?.conceal || sess.removeConceal) return [];
  return [null, { content: "Remove concealment from this vault…", callback: () => confirmRemoveConceal(sess) }];
}

async function confirmRemoveConceal(sess) {
  const d = vaultDialog({ title: "Remove the concealment?", tone: "warn", width: 480,
    subtitle: "The vault stays encrypted; only what it shows changes." });
  d.body.append(noticeEl("warn", "When you leave this vault it is locked without concealment. Anyone who runs it then " +
    "sees inner node types in error messages and the real file names in its controls. Copies already sent keep " +
    "their concealment."));
  d.addAction("Keep it concealed", { onClick: () => d.close(false) });
  d.addAction("Remove concealment", { danger: true, onClick: () => d.close(true) });
  if (await d.result) {
    sess.removeConceal = true;
    toast("Concealment will be removed when you leave this vault.", "info", "Concealment");
  }
}

/** V3: what the "Choose what to expose" step offers for this selection (the nodes about to be locked, or the inside
 *  of the subgraph), and how it asks the server to check a choice (same rules as sealing). */
// V7: model files the selection uses (widget values that look like model files) - offered in the protect dialog so
// the author can give a download link for each; size and SHA-256 are computed on the author's machine at lock time.
const MODEL_EXT = /\.(safetensors|ckpt|pt|pth|bin|gguf|sft|onnx|pkl|pb|engine)$/i;
function modelFilesOf(nodes) {
  const seen = new Set();
  const walk = (list) => {
    for (const n of list || []) {
      for (const w of n.widgets || []) {
        if (typeof w.value === "string" && MODEL_EXT.test(w.value) && !w.value.includes("..")) seen.add(w.value);
      }
      if (n.subgraph) walk(n.subgraph.nodes || n.subgraph._nodes);
    }
  };
  walk(nodes);
  return [...seen].sort();
}

/** How many OTHER subgraph nodes (root + every definition) use the same definition as `sg`. */
function otherUsesOf(sg) {
  const root = app.rootGraph ?? app.graph;
  const id = sg?.subgraph?.id;
  if (!id || !root) return 0;
  let n = 0;
  for (const g of [root, ...(root.subgraphs?.values?.() ?? [])]) {
    for (const x of g?.nodes || g?._nodes || []) if (x !== sg && isSubgraphNode(x) && x.subgraph?.id === id) n++;
  }
  return n;
}

/** Owner 2026-11-23 "Remove this output from the vault": take the chosen outputs (by inner source "<node>#<slot>",
 *  the key the dialog and the server use) out of the subgraph before it is extracted. The inner graph is untouched
 *  (only the wire to the output node goes); the outer wires from those outputs are dropped with them. A definition
 *  used elsewhere is never changed (the dialog says so first). Runs inside the transaction: any failure restores. */
function removeVaultOutputs(sg, keys) {
  if (!keys?.length) return;
  const sub = sg?.subgraph;
  if (otherUsesOf(sg) > 0) {
    throw new ProtectError("SUBGRAPH_INTERFACE_VALIDATION", "This subgraph is also used elsewhere in the workflow, " +
      "so an output cannot be removed from it without changing the other copies. Remove the output inside the " +
      "subgraph yourself, or lock without concealment.");
  }
  const want = new Set(keys.map(String));
  const doomed = (sub?.outputs || []).filter((so) => {
    const l = linkOf(sub, (so.linkIds || [])[0]);
    return l && want.has(`${l.origin_id}#${l.origin_slot}`);
  });
  if (!doomed.length || typeof sub.removeOutput !== "function") {
    throw new ProtectError("SUBGRAPH_INTERFACE_VALIDATION", "An output chosen for removal is no longer in the " +
      "subgraph. Close this dialog and lock again.");
  }
  for (const so of doomed) sub.removeOutput(so);
}

function exposureOf(r, boundary) {
  const defOf = (type) => globalThis.LiteGraph?.registered_node_types?.[type]?.nodeData ?? null;
  const sg = r.kind === "subgraph" ? r.nodes[0] : null;
  const nodes = sg ? [...(sg.subgraph?.nodes || sg.subgraph?._nodes || [])] : r.nodes;
  const sockets = socketsOf({ kind: r.kind, nodes, boundary, sg });
  const shared = sg ? otherUsesOf(sg) : 0;
  for (const s of sockets) if (s.kind === "out") s.shared = shared;
  const cand = () => candidate(nodes, sockets);
  return {
    controls: inventory(nodes, { defOf, promoted: sg ? promotedValues(sg) : null }), sockets,
    previews: previewsOf(nodes, { defOf }),
    models: modelFilesOf(nodes),
    check: async (conceal) => {
      const c = cand();
      const res = await post("/h2vault/vault/conceal/check", { api: c.api, interface: c.interface, ui: c.ui, conceal });
      if (!res.ok) throw new Error(res.data?.error || `The check failed (${res.status}).`);
      return res.data;
    },
  };
}

/** Protect without a dialog (browser tests, A26 L9.203). True / false; the outcome is told in a toast. */
async function protectWithFeedback(nodes, opts) {
  try {
    await protectTransaction(nodes, opts);
    toast("Locked. Double-click the vault to open it (password + authenticator).", "success", "Vault locked");
    return true;
  } catch (e) {
    // never a success message for a half-done protect: the original graph is back
    LOG("protect failed", e?.stage, e?.message);
    if (e?.busy) { toast(BUSY_MESSAGE, true); return false; }       // L9.249 V2: the running one is untouched
    toast(protectFailureText(e), "error", "Not locked");
    return false;
  }
}

async function showInstallCode() {
  const r = await (await api.fetchApi("/h2vault/vault/install_code")).json().catch(() => ({}));
  const d = vaultDialog({ title: "My installation code",
    subtitle: "Send this to a vault author so their Sealed vaults run here. It is a public key: safe to share.",
    width: 520 });
  const name = textField({ label: "Name the author will see (optional)", placeholder: "e.g. Studio B", maxLength: 60 });
  if (r.code) d.body.append(copyRow({ label: "installation code", value: r.code }));
  else d.body.append(noticeEl("danger", "This installation's code is not available. Check that the H2Vault server part loaded."));
  d.body.append(name.el);
  if (r.code) d.addAction("Save key file", { onClick: () => saveKeyFile(r.code, name.input.value.trim()) });
  d.addAction("Done", { primary: true, onClick: () => d.close(true) });
  d.onSubmit(() => d.close(true));
  await d.result;
}

// ── access management (L9.48): installations, editors, password ─────────────────────────────────────────────
const KEYFILE_FORMAT = "h2vault-install-key";
const CODE_PREFIX = "h2vk1:";

/** <name>.h2vkey: this installation's PUBLIC key as a file (docs/VAULT_DESIGN_A18.md, Access management). */
function saveKeyFile(code, label) {
  const data = { format: KEYFILE_FORMAT, version: 1, code, label: label || "", created: new Date().toISOString() };
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 1)], { type: "application/json" }));
  const a = el("a", { href: url, download: `${(label || "h2vault-installation").replace(/[^\w.-]+/g, "_").slice(0, 40)}.h2vkey` });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
}

/** Pick a key file -> {code, label}, {error} or null (cancelled). A text file holding just a code works too. */
function importKeyFile() {
  return new Promise((resolve) => {
    const inp = el("input", { type: "file", accept: ".h2vkey,.json,.txt", style: { display: "none" } });
    const done = (v) => { inp.remove(); resolve(v); };
    inp.addEventListener("cancel", () => done(null));
    inp.addEventListener("change", async () => {
      const f = inp.files?.[0];
      if (!f) return done(null);
      const text = (await f.text().catch(() => "")).trim();
      try {
        const d = JSON.parse(text);
        if (d?.format === KEYFILE_FORMAT && typeof d.code === "string") {
          return done({ code: d.code.trim(), label: String(d.label || "") });
        }
      } catch (_) { /* not JSON: maybe a bare code */ }
      if (text.startsWith(CODE_PREFIX)) return done({ code: text.split(/\s+/)[0], label: f.name.replace(/\.[^.]+$/, "") });
      done({ error: `${f.name} is not an H2Vault installation key file.` });
    });
    document.body.append(inp);
    inp.click();
  });
}

function shortCode(code) {
  return code.length > 30 ? `${code.slice(0, 18)}…${code.slice(-8)}` : code;
}

/** The access dialog (spec 4.5). `apply(choice)` -> {ok} or {error}; on an error the dialog stays open with the
 *  message. Resolves with apply's result, or null when cancelled. */
function accessDialog(v, res, focus, apply) {
  const sealed = res.profile === "sealed_installs";
  const d = vaultDialog({ title: `${focus === "password" ? "Change the password of" : "Access to"} "${v.title || "vault"}"`,
    subtitle: sealed ? "Who may run this vault, who may open it for editing, and its password."
      : "Who may open this vault for editing, and its password.", width: 640 });
  const lists = { editors: res.editors.map((r) => ({ ...r })), recipients: res.recipients.map((r) => ({ ...r })) };
  const setLabel = (code, label) => {
    for (const r of [...lists.editors, ...lists.recipients]) if (r.code === code) r.label = label;
  };
  const section = (key, title, hint) => {
    const rows = vel("div", { class: "h2v-list" });
    const draw = () => rows.replaceChildren(...lists[key].map((r, i) => {
      const name = vel("input", { type: "text", class: "h2v-input", value: r.label || "", maxLength: 60,
        placeholder: r.me ? "This installation" : "Name (optional)", "aria-label": `Name for installation ${shortCode(r.code)}`,
        on: { input: (e) => setLabel(r.code, e.target.value) } });
      return vel("div", { class: "h2v-keyrow" }, [name,
        vel("span", { class: "h2v-keycode", text: shortCode(r.code), title: r.code }),
        r.me ? vel("span", { class: "h2v-badge", text: "This installation" })
          : vbutton("Remove", { small: true, ariaLabel: `Remove installation ${shortCode(r.code)}`,
            onClick: () => { lists[key].splice(i, 1); draw(); } })]);
    }));
    const code = vel("input", { type: "text", class: "h2v-input", placeholder: "Paste an installation code (h2vk1:...)",
      "aria-label": `Add to ${title.toLowerCase()}`, spellcheck: false });
    const add = (c, label) => {
      c = String(c || "").trim();
      if (!c) return;
      if (!c.startsWith(CODE_PREFIX)) { d.notice("danger", `An installation code starts with ${CODE_PREFIX}`); return; }
      if (lists[key].some((r) => r.code === c)) { d.notice("warn", "That installation is already in the list."); return; }
      const known = [...lists.editors, ...lists.recipients].find((r) => r.code === c);
      lists[key].push({ code: c, label: label || known?.label || "", me: false });
      code.value = "";
      d.notice(null);
      draw();
    };
    code.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); add(code.value); } });
    draw();
    return block(title, hint, rows, vel("div", { class: "h2v-row" }, [
      vel("div", { style: { flex: "1", minWidth: "0" } }, [code]),
      vbutton("Add", { onClick: () => add(code.value) }),
      vbutton("Import key file…", { onClick: async () => {
        const k = await importKeyFile();
        if (k?.error) d.notice("danger", k.error);
        else if (k) add(k.code, k.label);
      } })]));
  };
  if (sealed) {
    d.body.append(section("recipients", "Installations that may run it",
      "Without a password, only on these ComfyUI installations. This one is always included."));
  } else {
    d.body.append(noticeEl("info", res.profile === "locked" ? "Locked vault: whoever has the password can run it, so " +
      "there are no installations to manage here." : "Portable vault: it runs anywhere (obfuscation only)."));
  }
  d.body.append(section("editors", "Editors", "Installations that may open it for editing - each with the password " +
    "and its own authenticator. This one stays an editor."));
  const pw = passwordField({ label: "New vault password", strength: true });
  const pw2 = passwordField({ label: "Repeat the new password" });
  const pwBox = vel("div", { class: "h2v-grid2" }, [pw.el, pw2.el]);
  const change = switchRow("Change the password", { checked: focus === "password",
    onChange: (on) => { pwBox.style.display = on ? "" : "none"; if (on) pw.input.focus(); } });
  pwBox.style.display = change.checked() ? "" : "none";
  d.body.append(vel("div", { class: "h2v-block" }, [change.el, pwBox]));
  d.body.append(noticeEl("info", (sealed ? "Removing an installation protects new copies only: a copy it already has " +
    "still runs there. " : "") + "Applying re-encrypts the vault with fresh keys; save the workflow afterwards so the " +
    "new access goes with it."));
  d.addAction("Cancel", { onClick: () => d.close(null) });
  const go = async () => {
    if (d.busy) return;
    d.notice(null);
    let newPassword = null;
    if (change.checked()) {
      if (pw.value().length < 8) { d.notice("danger", "Use at least 8 characters for the new password."); pw.input.focus(); return; }
      if (pw.value() !== pw2.value()) { d.notice("danger", "The two new passwords differ."); pw2.input.focus(); return; }
      newPassword = pw.value();
    }
    const labels = {};
    for (const r of [...lists.editors, ...lists.recipients]) if (String(r.label || "").trim()) labels[r.code] = r.label.trim();
    d.setBusy(true, "Applying…");
    d.status("Re-encrypting the vault…");
    const out = await apply({ editors: lists.editors.map((r) => r.code), recipients: lists.recipients.map((r) => r.code),
      labels, new_password: newPassword });
    if (out?.error) { d.setBusy(false); d.status(""); d.notice("danger", out.error); return; }
    d.close(out);
  };
  d.addAction("Apply", { primary: true, onClick: go });
  if (focus === "password") setTimeout(() => pw.input.focus(), 0);
  return d.result;
}

// ── V7 concealed provisioning: what a vault needs arrives by itself, names never shown (owner 2026-11-23) ──────
const PROVISION_SETTING = "h2vault.provision.mode";
const PREPARING = new Map();           // vault id -> {pct, failed}
const PROVISIONED = new Set();         // vault ids handled in this tab

function provisionMode() {
  try {
    const v = app.extensionManager?.setting?.get?.(PROVISION_SETTING);
    return v === "ask" || v === "never" ? v : "auto";
  } catch (_) { return "auto"; }
}

async function autoProvision(v) {
  const W = (name) => v.widgets?.find((w) => w.name === name);
  const vid = W("vault_id")?.value, payload = W("vault_payload")?.value;
  const mode = provisionMode();
  if (!vid || !payload || mode === "never" || PROVISIONED.has(vid)) return;
  PROVISIONED.add(vid);
  const body = { payload, vault_id: vid, client_id: api.clientId };
  const plan = await post("/h2vault/vault/provision/plan", body);
  if (!plan.ok) return;                               // e.g. a Locked vault before its password: the run asks
  const s = plan.data;
  if (s.nodes_missing) {
    if (mode === "auto") {
      const r = await post("/h2vault/vault/install_missing", { ...body, consent: true });
      if (r.ok && r.data?.installed) toast(`Installed what this workflow needs (${r.data.installed} extension` +
        `${r.data.installed !== 1 ? "s" : ""}). Restart ComfyUI to load ${r.data.installed !== 1 ? "them" : "it"}.`);
    } else installMissing(v, { auto: true });
  }
  if (!s.models_missing) return;
  if (!s.downloadable) {
    toast("This workflow needs model files its vault cannot download. Ask the vault's author.", true);
    return;
  }
  const gb = (s.bytes / 1e9).toFixed(s.bytes > 1e10 ? 0 : 1);
  if (mode === "ask") {
    const ask = vaultDialog({ title: "Prepare this workflow", width: 460 });
    ask.body.append(vel("p", { style: { margin: "0" }, text: `It needs ${s.models_missing} model file` +
      `${s.models_missing !== 1 ? "s" : ""} (${gb} GB) that this ComfyUI does not have. They download in the background ` +
      "and are checked before use; what they are stays private." }));
    ask.addAction("Not now", { onClick: () => ask.close(false) });
    ask.addAction("Download", { primary: true, onClick: () => ask.close(true) });
    if (!(await ask.result)) return;
  }
  const st = await post("/h2vault/vault/provision/start", { ...body, consent: true });
  if (!st.ok) { toast(st.data?.error || "Could not prepare this vault.", true); return; }
  const token = st.data.token;
  PREPARING.set(vid, { pct: 0 });
  refreshCards(vid);
  const tick = async () => {
    const r = await post("/h2vault/vault/provision/status", { token });
    const d = r.data || {};
    const pct = d.total_bytes ? Math.min(100, Math.floor((100 * d.done_bytes) / d.total_bytes)) : 0;
    if (d.state === "running") {
      PREPARING.set(vid, { pct });
      refreshCards(vid);
      setTimeout(tick, 2000);
      return;
    }
    if (d.state === "done") {
      PREPARING.delete(vid);
      toast("This workflow is ready: everything it needs is downloaded and checked.");
    } else PREPARING.set(vid, { pct, failed: d.error || "A download failed; try again later." });
    refreshCards(vid);
  };
  setTimeout(tick, 1500);
}

// ── missing custom nodes (L9.50): one click, names never shown (owner A18) ─────────────────────────────────
let INSTALL_OFFER_OPEN = false;
const MISSING_PREFIX = "This workflow needs custom nodes that are not installed";

/** Offer to install what this vault needs here. `auto`: from a failed run (asked on every run attempt, owner). */
async function installMissing(v, { auto = false } = {}) {
  if (INSTALL_OFFER_OPEN) return;
  INSTALL_OFFER_OPEN = true;
  try {
    const W = (name) => v.widgets.find((w) => w.name === name);
    const body = { payload: W("vault_payload")?.value, vault_id: W("vault_id")?.value, client_id: api.clientId };
    const m = await post("/h2vault/vault/missing", body);
    if (!m.ok) { toast(m.data.error || "Could not check this vault.", true); return; }
    const s = m.data;
    if (!s.missing) {
      if (!auto) toast("Nothing is missing: this vault's custom nodes are all installed here.");
      return;
    }
    const n = s.packs, many = n !== 1;
    const ask = vaultDialog({ title: "Custom nodes needed",
      subtitle: "This workflow's vault uses custom nodes that this ComfyUI does not have.", width: 500 });
    if (s.installable) {
      ask.body.append(vel("p", { style: { margin: "0" }, text: `It needs ${n} custom node pack${many ? "s" : ""} that ` +
        `${many ? "are" : "is"} not installed here (from ${s.hosts.join(", ")}). Without ${many ? "them" : "it"} the ` +
        "workflow will not run." }));
      if (s.installable < n || s.unknown_classes) {
        ask.body.append(noticeEl("warn", "Some of them cannot be installed from here - ask the vault's author for those."));
      }
      ask.body.append(noticeEl("warn", `Installing downloads ${many ? "them" : "it"} and runs ${many ? "their" : "its"} ` +
        "code when ComfyUI restarts. Install only if you trust where this workflow comes from."));
      ask.addAction("Cancel", { onClick: () => ask.close(false) });
      ask.addAction("Install", { primary: true, onClick: () => ask.close(true) });
    } else {
      ask.body.append(vel("p", { style: { margin: "0" }, text: "The vault does not say where to get them. Ask the " +
        "vault's author which ones to install." }));
      ask.addAction("Close", { primary: true, onClick: () => ask.close(false) });
    }
    const go = await ask.result;
    if (!go) return;
    toast("Installing the custom nodes this workflow needs…");
    const r = await post("/h2vault/vault/install_missing", { ...body, consent: true });
    const d = r.data || {};
    const lines = [];
    if (!r.ok) lines.push(["danger", d.error || `Installing failed (${r.status}).`]);
    if (d.installed) lines.push(["ok", `Installed ${d.installed} pack${d.installed !== 1 ? "s" : ""}. Restart ComfyUI to ` +
      `load ${d.installed !== 1 ? "them" : "it"}, then run the workflow again.`]);
    if (d.skipped) lines.push(["info", `${d.skipped} folder${d.skipped !== 1 ? "s" : ""} already existed and ` +
      `${d.skipped !== 1 ? "were" : "was"} left as ${d.skipped !== 1 ? "they were" : "it was"}.`]);
    for (const f of d.failed || []) lines.push(["danger", `Not installed: ${f}.`]);
    if (d.requirements?.note) lines.push(["info", `Their Python requirements: ${d.requirements.note}.`]);
    if (!lines.length) lines.push(["info", "Nothing was installed."]);
    const done = vaultDialog({ title: "Custom nodes", tone: r.ok ? "ok" : "danger", width: 500 });
    done.body.append(...lines.map(([tone, t]) => noticeEl(tone, t)));
    done.addAction("OK", { primary: true, onClick: () => done.close(true) });
    done.onSubmit(() => done.close(true));
    await done.result;
  } finally { INSTALL_OFFER_OPEN = false; }
}

/** The node an execution id names ("5", or "12:5" inside a subgraph). */
function nodeByExecId(id) {
  let g = app.rootGraph ?? app.graph, n = null;
  for (const part of String(id).split(":")) {
    n = g?.getNodeById?.(Number(part)) ?? g?.getNodeById?.(part) ?? null;
    if (!n) return null;
    g = n.subgraph;
  }
  return n;
}

function onExecutionError(e) {
  const d = e?.detail || {};
  if (!VAULT_TYPES.has(d.node_type) || !String(d.exception_message || "").startsWith(MISSING_PREFIX)) return;
  const v = nodeByExecId(d.node_id);
  if (v) setTimeout(() => installMissing(v, { auto: true }), 0);
}

async function manageAccess(v, focus) {
  const st = await (await api.fetchApi("/h2vault/2fa/status")).json().catch(() => ({}));
  if (!st.enrolled) {
    toast("Managing a vault's access needs an authenticator app on this installation. Set it up now.");
    if (!(await enrolDialog())) return;
  }
  const W = (name) => v.widgets.find((w) => w.name === name);
  const payload = W("vault_payload")?.value;
  const vaultId = W("vault_id")?.value;
  let res = null;
  const verb = focus === "password" ? "Change the password of" : "Manage access to";
  const ok = await credentialDialog({ title: `${verb} "${v.title || "vault"}"`, primary: "Continue",
    subtitle: "Confirm with the vault password and your authenticator code. The inside stays closed.",
    submit: async ({ password, code }) => {
      const r = await post("/h2vault/vault/access/open", { payload, vault_id: vaultId, password, code,
        client_id: api.clientId });
      if (r.ok) { res = r.data; return { ok: true }; }
      if (r.data.needs_enrolment) return { enrol: true };
      return { error: authError(r, "Could not unlock the vault's access.") };
    } });
  if (!ok) return;
  if (ok.enrol) {
    if (await enrolDialog()) await manageAccess(v, focus);
    return;
  }
  const out = await accessDialog(v, res, focus, async (choice) => {
    const r = await post("/h2vault/vault/access/apply", { access_token: res.access_token, payload, ...choice });
    if (!r.ok) return { error: r.data.error || `Could not apply the change (${r.status}).` };
    W("vault_payload").value = r.data.payload;                  // swapped only now: a failure left the old vault
    if (res.profile === "locked") markRunUnlocked(vaultId);
    v.setDirtyCanvas?.(true, true);
    try { app.extensionManager?.workflow?.activeWorkflow?.changeTracker?.checkState?.(); } catch (_) {}
    return { ok: true, data: r.data };
  });
  if (!out) { post("/h2vault/vault/access/cancel", { access_token: res.access_token }); return; }
  toast(out.data.password_changed
    ? "Password changed and the vault re-encrypted. Save the workflow - copies saved before still open with the old password."
    : "Access updated and the vault re-encrypted. Save the workflow so the new access goes with it.", "success",
  out.data.password_changed ? "Password changed" : "Access updated");
}

// ── V5: Lock parameters (docs/h2vault/V5_enhancements_design.md section 5) ────────────────────────────────────────
// Each chosen node becomes a one-node vault drawn like itself. The locked values are sealed inside; the open rows stay
// editable as the vault's controls. Nodes are locked one after the other, each in its own A26 transaction (a failure
// restores that node and stops; the nodes already locked stay locked and are named in the message).
const USUAL_OPEN = new Set(["seed", "noise_seed", "steps", "cfg", "sampler_name", "scheduler", "denoise", "width",
  "height", "batch_size"]);

function lockableNodes(nodes) {
  return (nodes || []).filter((n) => n && !isSubgraphNode(n) && !VAULT_TYPES.has(n.type) && Number(n.id) >= 0
    && lockableRows(n, nodeDefOf(n.type)).length > 0);
}

function checkRow(label, checked, hint) {
  const input = vel("input", { type: "checkbox" });
  input.checked = !!checked;
  const row = vel("label", { class: "h2v-row", style: { gap: "8px", alignItems: "center", cursor: "pointer",
    padding: "2px 0" } }, [input, vel("span", { text: label }), hint ? vel("span", { class: "h2v-dim", text: hint }) : null]
    .filter(Boolean));
  return { el: row, input, checked: () => input.checked };
}

/** Lock one node's parameters (no dialog). `locked` = row names (null = every row, owner D5). */
async function lockNodeParameters(node, locked, opts) {
  const req = lockRequest(node, nodeDefOf(node.type), locked);
  if (!req.lock.rows.length) throw new ProtectError("SELECTION_VALIDATION", `"${node.title}" has no value left to lock.`);
  req.lock.look.show_rows = !!opts.showRows;
  if (!opts.showKind) {
    const kind = req.lock.look.node_label;
    req.lock.look.node_label = null;
    // V8: an un-renamed node's title IS its kind ("Load Checkpoint"); without "show the kind" it is not published
    const t = String(req.lock.look.title || "").trim().toLowerCase();
    if ([kind, node.type].some((k) => k && String(k).trim().length >= 3 && t.includes(String(k).trim().toLowerCase()))) {
      req.lock.look.title = "Locked node";
    }
  }
  if (typeof opts.title === "string" && opts.title.trim()) req.lock.look.title = opts.title.trim().slice(0, 80);
  const vault = await protectTransaction([node], { profile: opts.profile, password: opts.password,
    recipients: opts.recipients || [], editors: [], title: req.lock.look.title, lock: req.lock,
    extraParams: req.extraParams, onStage: opts.onStage });
  if (opts.lockSet) {
    vault.properties.h2vault.lock_set = opts.lockSet;            // one password unlocks the set (ensureRunKeys)
  }
  return vault;
}

async function lockParameters(items) {
  const r = resolveLockSelection(items ?? selectedItemsOf(app.canvas), { LiteGraph: globalThis.LiteGraph });
  if (r.problems.length) { toast(r.problems[0], true); return null; }
  const nodes = lockableNodes(r.nodes);
  if (!nodes.length) {
    toast("Nothing to lock: select nodes that have settings (a subgraph is protected as a vault instead).", true);
    return null;
  }
  const ids = nodes.map((n) => n.id);
  const graph = nodes[0].graph;
  const many = nodes.length !== 1;
  const d = vaultDialog({ title: many ? `Lock the parameters of ${nodes.length} nodes`
    : `Lock the parameters of "${nodes[0].title}"`,
  subtitle: "Each node stays where it is with its sockets. The values you lock are encrypted; the ones you leave " +
    "open stay editable.", width: 640 });
  d.body.append(noticeEl("info", "Anyone who receives the workflow sees each node's title and how many values are " +
    "locked - never the locked values. To hide what the nodes are as well, protect them as a concealed vault."));
  const perNode = nodes.map((n) => {
    const rows = lockableRows(n, nodeDefOf(n.type));
    const title = textField({ label: "Title shown on the node", value: n.title || "", maxLength: 80 });
    const checks = rows.map((row) => ({ name: row.name, box: checkRow(row.label, true) }));
    const list = vel("div", { style: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
      gap: "0 12px" } }, checks.map((c) => c.box.el));
    return { node: n, title, checks, el: block(n.title || n.type, "Ticked = locked (hidden). Untick what the person " +
      "running it may change.", title.el, list) };
  });
  const usual = vbutton("Keep seed, steps, CFG, sampler, scheduler, denoise and sizes open", { kind: "text", small: true,
    onClick: () => perNode.forEach((p) => p.checks.forEach((c) => { if (USUAL_OPEN.has(c.name)) c.box.input.checked = false; })) });
  const showRows = checkRow("Show the names of the locked settings", false, "(otherwise only how many)");
  const showKind = checkRow("Show what kind of node each one is", false, "(otherwise only its title)");
  const choice = choiceCards({ label: "Who can run them", value: "sealed_installs",
    options: PROFILES.filter((p) => ["sealed_installs", "sealed_licensed", "locked"].includes(p.id))
      .map((p) => ({ id: p.id, title: SHORT[p.id]?.title ?? p.title, tag: SHORT[p.id]?.tag, tone: SHORT[p.id]?.tone,
        summary: p.run })), onChange: () => { recip.el.style.display = choice.value() === "sealed_installs" ? "" : "none"; } });
  const pw2 = passwordField({ label: "Repeat the password" });
  const pw = passwordField({ label: "Password", strength: true, generate: true,
    hint: "Opens the nodes for editing, together with your authenticator app.", onGenerate: (v) => pw2.setValue(v) });
  const recip = textArea({ label: "Other installations that may run them (optional)", placeholder: "h2vk1:...", rows: 2,
    hint: "Installation codes, one per line. Yours is always included." });
  d.body.append(...perNode.map((p) => p.el), vel("div", { class: "h2v-row" }, [usual]), showRows.el, showKind.el,
    choice.el, vel("div", { class: "h2v-grid2" }, [pw.el, pw2.el]), recip.el);
  d.status(PROTECT_FOOT);
  d.addAction("Cancel", { onClick: () => d.close(null) });
  const done = [];
  const go = async () => {
    if (d.busy) return;
    d.notice(null);
    if (pw.value().length < 8) { d.notice("danger", "Use at least 8 characters for the password."); pw.input.focus(); return; }
    if (pw.value() !== pw2.value()) { d.notice("danger", "The two passwords differ."); pw2.input.focus(); return; }
    const plan = perNode.map((p) => ({ id: p.node.id, title: p.title.input.value,
      locked: p.checks.filter((c) => c.box.checked()).map((c) => c.name) }));
    const empty = plan.find((x) => !x.locked.length);
    if (empty) { d.notice("danger", `Tick at least one value to lock on "${empty.title || "every node"}".`); return; }
    d.setBusy(true, "Locking…");
    const lockSet = `ls${Math.random().toString(36).slice(2, 10)}`;
    for (const x of plan) {
      if (done.includes(x.id)) continue;
      const node = graph.getNodeById?.(x.id) ?? (app.canvas?.graph?.getNodeById?.(x.id));
      try {
        if (!node) throw new Error("The node is no longer in the graph on screen.");
        d.status(`Locking "${x.title || node.title}"…`);
        await lockNodeParameters(node, x.locked, { profile: choice.value(), password: pw.value(), title: x.title,
          recipients: splitCodes(recip.input.value), showRows: showRows.checked(), showKind: showKind.checked(), lockSet });
        done.push(x.id);
      } catch (e) {
        d.setBusy(false);
        d.status(PROTECT_FOOT);
        const kept = done.length ? ` ${done.length} node${done.length === 1 ? " is" : "s are"} already locked.` : "";
        d.notice(e?.busy ? "warn" : "danger", `"${x.title || "A node"}" was not locked: ${protectFailureText(e)}${kept}`);
        return;
      }
    }
    d.close(done.length);
  };
  d.addAction(many ? `Lock ${nodes.length} nodes` : "Lock parameters", { primary: true, onClick: go });
  d.onSubmit(go);
  const n = await d.result;
  if (n) toast(`Locked the parameters of ${n} node${n === 1 ? "" : "s"}. Their values are encrypted.`, "success",
    "Parameters locked");
  return n;
}

// ── V5: Remove protection (design 7.4) ──────────────────────────────────────────────────────────────────────────
async function removeProtection(v) {
  const isLock = !!vaultInfo(v).lock;
  const sure = vaultDialog({ title: isLock ? "Unlock these parameters for good?" : "Remove the protection for good?",
    subtitle: isLock ? "The original node comes back with its values in plain view." :
      "The vault becomes an ordinary subgraph. Anyone who receives the workflow can then read everything inside.",
    width: 460, tone: "warn" });
  sure.addAction("Cancel", { onClick: () => sure.close(false) });
  sure.addAction(isLock ? "Unlock for good" : "Remove protection", { primary: true, danger: true,
    onClick: () => sure.close(true) });
  if (!(await sure.result)) return;
  const st = await (await api.fetchApi("/h2vault/2fa/status")).json().catch(() => ({}));
  if (!st.enrolled && !(await enrolDialog())) return;
  const payload = v.widgets.find((w) => w.name === "vault_payload")?.value;
  const vaultId = v.widgets.find((w) => w.name === "vault_id")?.value;
  let opened = null;
  const out = await credentialDialog({ title: `Remove the protection of "${v.title || "vault"}"`, primary: "Remove",
    subtitle: "Type the password and the code your authenticator app shows.",
    submit: async ({ password, code }) => {
      const r = await post("/h2vault/vault/open", { payload, vault_id: vaultId, password, code, client_id: api.clientId });
      if (r.ok) { opened = r.data; return { ok: true }; }
      if (r.data.needs_enrolment) return { enrol: true };
      return { error: authError(r, "Could not open the vault.") };
    } });
  if (!out?.ok || !opened) return;
  post("/h2vault/vault/cancel", { edit_token: opened.edit_token });     // nothing is re-sealed: the session ends
  // the open controls' CURRENT values (the layout keeps the values of when it was locked)
  const openVals = {};
  for (const prm of vaultInfo(v).interface?.params || []) {
    const w = v.widgets?.find((x) => x.name === `p_${prm.key}`);
    if (prm.input && w) openVals[prm.input] = w.value;
  }
  try {
    const graph = v.graph;
    const before = new Set((graph.nodes || graph._nodes || []).map((n) => n));
    const sg = materialize(v, opened);
    if (isLock && typeof graph.unpackSubgraph === "function") {
      graph.unpackSubgraph(sg);
      const back = (graph.nodes || graph._nodes || []).filter((n) => !before.has(n) && n !== sg);
      if (back.length === 1) {
        for (const [name, value] of Object.entries(openVals)) {
          const w = back[0].widgets?.find((x) => x.name === name);
          if (w) w.value = value;
        }
      }
    }
    graph.setDirtyCanvas?.(true, true);
    toast(isLock ? "The node is back with its values." : "The vault is now an ordinary subgraph.", "success",
      "Protection removed");
  } catch (e) {
    toast(`The vault opened but could not be shown: ${e?.message || e}`, "error");
  }
}

/** The vault's editable layout as a native subgraph node in its place (no edit session, no auto-lock). */
function materialize(v, res) {
  if (!res.ui?.definitions?.length) throw new Error("This vault has no editable layout. Ask its author for a fresh copy.");
  const graph = v.graph;
  const root = app.rootGraph ?? app.graph;
  const defs = [...res.ui.definitions];
  const own = defs.find((d) => d.id === res.ui.root) ?? defs[0];
  for (const d of defs) if (d !== own && !root.subgraphs?.has?.(d.id)) root.createSubgraph(d);
  const subgraph = root.subgraphs?.get?.(own.id) ?? root.createSubgraph(own);
  const sg = LiteGraph.createNode(subgraph.id);
  if (!sg) throw new Error("This front end cannot create the subgraph node.");
  const inputMap = vaultInfo(v).input_map;
  const wires = replaceNode(graph, v, sg);
  if (res.ui.size) sg.size = [...res.ui.size];
  sg.title = v.title || res.ui.title;
  restoreWires(graph, wires, sg, (slot) => subgraphSlotOf(v, inputMap, slot));
  return sg;
}

// ── V5: licences (design section 6) ─────────────────────────────────────────────────────────────────────────────
function downloadText(name, text, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
}

function pickTextFile(accept) {
  return new Promise((resolve) => {
    const inp = el("input", { type: "file", accept, style: { display: "none" } });
    const done = (v) => { inp.remove(); resolve(v); };
    inp.addEventListener("cancel", () => done(null));
    inp.addEventListener("change", async () => {
      const f = inp.files?.[0];
      done(f ? { name: f.name, text: (await f.text().catch(() => "")).trim() } : null);
    });
    document.body.append(inp);
    inp.click();
  });
}

const safeFile = (s) => String(s || "licence").replace(/[^\w.-]+/g, "_").slice(0, 40);

function vaultRefs(v) {
  return { payload: v.widgets.find((w) => w.name === "vault_payload")?.value,
    vault_id: v.widgets.find((w) => w.name === "vault_id")?.value };
}

async function addLicence(v) {
  const d = vaultDialog({ title: `Add a licence for "${v.title || "this workflow"}"`,
    subtitle: "Paste the licence its author sent you, or open the licence file.", width: 520 });
  const box = textArea({ label: "Licence", placeholder: "h2vl1:...", rows: 4 });
  d.body.append(box.el, vel("div", { class: "h2v-row" }, [vbutton("Open licence file…", { small: true, onClick: async () => {
    const f = await pickTextFile(".h2vlicence,.txt");
    if (f) box.input.value = f.text;
  } })]));
  const st = LICENCE_STATE.get(vaultRefs(v).vault_id);
  if (st?.install_code) d.body.append(copyRow({ label: "your installation code (send it to the author)", value: st.install_code }));
  d.addAction("Cancel", { onClick: () => d.close(null) });
  const go = async () => {
    if (d.busy) return;
    d.notice(null);
    if (!box.input.value.trim()) { d.notice("danger", "Paste the licence first."); return; }
    d.setBusy(true, "Checking…");
    const r = await post("/h2vault/licence/add", { ...vaultRefs(v), licence: box.input.value.trim() });
    d.setBusy(false);
    if (!r.ok) { d.notice("danger", r.data?.error || "That licence could not be added."); return; }
    d.close(r.data);
  };
  d.addAction("Add licence", { primary: true, onClick: go });
  d.onSubmit(go);
  const ok = await d.result;
  if (ok) {
    await refreshLicence(v, true);
    toast("Licence added. This workflow can run on this installation now.", "success", "Licence added");
  }
}

async function issueLicence(v) {
  const d = vaultDialog({ title: `Issue a licence for "${v.title || "this workflow"}"`,
    subtitle: "For one ComfyUI installation. Ask the person for their installation code.", width: 560 });
  const code = textArea({ label: "Their installation code", placeholder: "h2vk1:...", rows: 2 });
  const name = textField({ label: "Name (you and they see it)", placeholder: "e.g. Studio B", maxLength: 60 });
  const until = vel("select", { class: "h2v-input" }, EXPIRY_CHOICES.map((c) => vel("option", { value: c.value, text: c.label })));
  until.value = "30";
  const date = vel("input", { type: "date", class: "h2v-input", style: { display: "none" } });
  until.addEventListener("change", () => { date.style.display = until.value === "date" ? "" : "none"; });
  const runs = textField({ label: "Run limit (optional)", placeholder: "no limit" });
  d.body.append(code.el, vel("div", { class: "h2v-row" }, [vbutton("Import key file…", { small: true, onClick: async () => {
    const k = await importKeyFile();
    if (k?.error) { d.notice("danger", k.error); return; }
    if (k) { code.input.value = k.code; if (!name.input.value) name.input.value = k.label || ""; }
  } })]), name.el, field({ label: "Valid until", control: vel("div", { class: "h2v-row" }, [until, date]) }),
  runs.el, noticeEl("info", HONOUR_NOTE));
  d.addAction("Cancel", { onClick: () => d.close(null) });
  const go = () => {
    d.notice(null);
    if (!code.input.value.trim().startsWith("h2vk1:")) { d.notice("danger", "Paste their installation code (it starts with h2vk1:)."); return; }
    const t = licenceTerms({ choice: until.value, date: date.value, runs: runs.input.value });
    if (!t.ok) { d.notice("danger", t.error); return; }
    d.close({ install_code: code.input.value.trim().split(/\s+/)[0], label: name.input.value.trim(), ...t.terms });
  };
  d.addAction("Next", { primary: true, onClick: go });
  d.onSubmit(go);
  const terms = await d.result;
  if (!terms) return;
  let issued = null;
  const out = await credentialDialog({ title: "Sign the licence", primary: "Issue licence",
    subtitle: "Type this workflow's password and your authenticator code.",
    submit: async ({ password, code: c }) => {
      const r = await post("/h2vault/licence/issue", { ...vaultRefs(v), password, code: c, title: v.title || "", ...terms });
      if (r.ok && r.data.licence_text) { issued = r.data; return { ok: true }; }
      if (r.data?.needs_enrolment) return { enrol: true };
      return { error: authError(r, "The licence could not be issued.") };
    } });
  if (out?.enrol) { await enrolDialog(); return; }
  if (!issued) return;
  showLicences([{ ...issued, label: terms.label }], v.title);
}

function showLicences(list, title) {
  const d = vaultDialog({ title: list.length === 1 ? "Licence ready" : `${list.length} licences ready`,
    subtitle: "Send each one to its person. It only works on their installation, for this workflow.", width: 600 });
  for (const it of list) {
    const l = it.licence || {};
    const what = `${l.label || "Licence"} · ${l.exp ? `until ${fmtDate(l.exp)}` : "no end date"}${l.runs ? ` · ${l.runs} runs` : ""}`;
    d.body.append(vel("p", { class: "h2v-dim", text: what }), copyRow({ label: "licence", value: it.licence_text,
      display: `${it.licence_text.slice(0, 36)}…` }),
    vel("div", { class: "h2v-row" }, [vbutton("Download licence file", { small: true,
      onClick: () => downloadText(`${safeFile(title)}-${safeFile(l.label)}.h2vlicence`, it.licence_text) })]));
  }
  d.addAction("Done", { primary: true, onClick: () => d.close(true) });
  d.onSubmit(() => d.close(true));
  return d.result;
}

async function rotateLicences(v) {
  const refs = vaultRefs(v);
  const ledger = await (await api.fetchApi("/h2vault/licence/ledger")).json().catch(() => ({}));
  const rows = (ledger.rows || []).filter((r) => r.vault_id === refs.vault_id && r.state !== "ended");
  const d = vaultDialog({ title: "Revoke this workflow's licences", width: 560, tone: "warn",
    subtitle: "A new licence key is made and the vault is sealed again. Every licence issued so far stops working " +
      "for the NEW copy of the workflow; tick the people who should get a new licence right away." });
  d.body.append(noticeEl("warn", "People who already have the old copy of the workflow and its licence can keep " +
    "running that old copy - an offline licence cannot be taken back. Send everyone the new copy. Re-issued " +
    "licences start their run limits from zero again."));
  const checks = rows.map((r) => ({ lid: r.lid, box: checkRow(`${r.label || "Unnamed"} · ${ledgerState(r).detail}`, true) }));
  if (checks.length) d.body.append(block("Issue new licences to", null, ...checks.map((c) => c.box.el)));
  else d.body.append(vel("p", { class: "h2v-dim", text: "No licence of this workflow is listed on this installation." }));
  d.addAction("Cancel", { onClick: () => d.close(null) });
  d.addAction("Next", { primary: true, onClick: () => d.close(checks.filter((c) => c.box.checked()).map((c) => c.lid)) });
  const reissue = await d.result;
  if (!reissue) return;
  let res = null;
  const out = await credentialDialog({ title: "Revoke licences", primary: "Revoke and re-seal",
    subtitle: "Type this workflow's password and your authenticator code.",
    submit: async ({ password, code }) => {
      const r = await post("/h2vault/licence/rotate", { ...refs, password, code, reissue });
      if (r.ok && r.data.payload) { res = r.data; return { ok: true }; }
      if (r.data?.needs_enrolment) return { enrol: true };
      return { error: authError(r, "The licences could not be revoked.") };
    } });
  if (out?.enrol) { await enrolDialog(); return; }
  if (!res) return;
  v.widgets.find((w) => w.name === "vault_payload").value = res.payload;
  LICENCE_ASKED.delete(refs.vault_id);
  await refreshLicence(v, true);
  v.graph?.setDirtyCanvas?.(true, true);
  toast("Licences revoked. Save the workflow and send the new copy.", "success", "Licences revoked");
  if (res.reissued?.length) await showLicences(res.reissued, v.title);
}

async function ledgerDialog() {
  const data = await (await api.fetchApi("/h2vault/licence/ledger")).json().catch(() => ({}));
  const rows = data?.rows || [];
  const d = vaultDialog({ title: "Licences issued", width: 680,
    subtitle: "Every licence you issued on this installation. Nothing here is sent anywhere." });
  const only = checkRow("Only those ending within 7 days", false);
  const list = vel("div", { style: { display: "flex", flexDirection: "column", gap: "6px" } });
  const paint = () => {
    const shown = rows.filter((x) => !only.checked() || x.state === "expiring");
    list.replaceChildren(...(shown.length ? shown.map((x) => {
      const st = ledgerState(x);
      return vel("div", { class: "h2v-row", style: { justifyContent: "space-between", gap: "12px" } }, [
        vel("span", { text: `${x.vault_title || "Workflow"} · ${x.label || "Unnamed"}` }),
        vel("span", { class: "h2v-dim", text: `${st.detail} · ${shortCode(String(x.install_code || ""))}` }),
        vel("span", { text: st.state })]);
    }) : [vel("p", { class: "h2v-dim", text: rows.length ? "None ends within 7 days." : "You have not issued a licence yet." })]));
  };
  only.input.addEventListener("change", paint);
  paint();
  d.body.append(only.el, list);
  d.addAction("Done", { primary: true, onClick: () => d.close(true) });
  d.onSubmit(() => d.close(true));
  await d.result;
}

/** The Licensed vault an author-key action works through: the one right-clicked, or the only one on screen. */
function licensedVaultFor(v) {
  if (v && vaultInfo(v).profile === "sealed_licensed") return v;
  const found = [];
  const walk = (g, seen = new Set()) => {
    if (!g || seen.has(g)) return;
    seen.add(g);
    for (const n of g.nodes || g._nodes || []) {
      if (VAULT_TYPES.has(n.type) && vaultInfo(n).profile === "sealed_licensed") found.push(n);
      if (isSubgraphNode(n)) walk(n.subgraph, seen);
    }
  };
  try { walk(app.rootGraph ?? app.graph); } catch (_) { /* none */ }
  if (found.length === 1) return found[0];
  toast(found.length ? "Right-click the Licensed vault whose author key you mean, then choose the action there."
    : "Open a workflow with one of your Licensed vaults first: the author key is proven with that vault's password " +
      "and your authenticator.", "warn");
  return null;
}

/** Back up the author key: the same proof as issuing a licence (vault password + authenticator, review P1-4). */
async function exportAuthorKey(node) {
  const v = licensedVaultFor(node);
  if (!v) return;
  const d = vaultDialog({ title: "Back up my author key", width: 480,
    subtitle: "Your author key signs every licence. Without it (a new computer, a reinstall) you cannot issue licences " +
      "for the workflows you already shared." });
  const pw2 = passwordField({ label: "Repeat the backup password" });
  const pw = passwordField({ label: "Password for the backup file", strength: true, generate: true,
    onGenerate: (x) => pw2.setValue(x) });
  d.body.append(pw.el, pw2.el);
  d.addAction("Cancel", { onClick: () => d.close(null) });
  const next = () => {
    if (pw.value().length < 8) { d.notice("danger", "Use at least 8 characters."); return; }
    if (pw.value() !== pw2.value()) { d.notice("danger", "The two passwords differ."); return; }
    d.close(pw.value());
  };
  d.addAction("Next", { primary: true, onClick: next });
  d.onSubmit(next);
  const filePassword = await d.result;
  if (!filePassword) return;
  let file = null;
  const out = await credentialDialog({ title: "Prove it is your key", primary: "Download backup",
    subtitle: `Type the password of "${v.title || "this vault"}" and your authenticator code.`,
    submit: async ({ password, code }) => {
      const r = await post("/h2vault/licence/author/export", { ...vaultRefs(v), password, code,
        file_password: filePassword });
      if (r.ok && r.data.file) { file = r.data.file; return { ok: true }; }
      if (r.data?.needs_enrolment) return { enrol: true };
      return { error: authError(r, "The backup could not be made.") };
    } });
  if (out?.enrol) { await enrolDialog(); return; }
  if (!file) return;
  downloadText("h2vault-author-key.h2vauthor", JSON.stringify(file, null, 1), "application/json");
  toast("Author key backup downloaded. Keep the file and its password apart.", "success");
}

/** Restore the author key: vault password + authenticator, the backup must belong to that vault; replacing a
 *  different key needs an explicit confirmation and saves the current key to a dated file first (review P1-4). */
async function importAuthorKey(node) {
  const v = licensedVaultFor(node);
  if (!v) return;
  const f = await pickTextFile(".h2vauthor,.json");
  if (!f) return;
  const d = vaultDialog({ title: "Restore author key", subtitle: f.name, width: 480 });
  const fpw = passwordField({ label: "Backup file password", autocomplete: "current-password" });
  const replace = checkRow("Replace the author key this installation has now", false,
    "(it is saved first to a dated backup file)");
  d.body.append(fpw.el, replace.el);
  d.addAction("Cancel", { onClick: () => d.close(null) });
  const next = () => { if (!fpw.value()) { d.notice("danger", "Type the backup file's password."); return; }
    d.close({ file_password: fpw.value(), replace: replace.checked() }); };
  d.addAction("Next", { primary: true, onClick: next });
  d.onSubmit(next);
  const opts = await d.result;
  if (!opts) return;
  let done = null;
  const out = await credentialDialog({ title: "Prove it is your workflow", primary: "Restore",
    subtitle: `Type the password of "${v.title || "this vault"}" and your authenticator code.`,
    submit: async ({ password, code }) => {
      const r = await post("/h2vault/licence/author/import", { ...vaultRefs(v), password, code, file: f.text,
        file_password: opts.file_password, ...(opts.replace ? { replace: true, confirm: "replace" } : {}) });
      if (r.ok) { done = r.data; return { ok: true }; }
      if (r.data?.needs_enrolment) return { enrol: true };
      return { error: authError(r, "The backup could not be restored.") };
    } });
  if (out?.enrol) { await enrolDialog(); return; }
  if (!done) return;
  toast(done.backup ? `Author key restored. The previous key was saved as ${done.backup} in the H2Vault user folder ` +
    "(same password as this backup)." : "Author key restored.", "success");
}

// ── commands, menus, settings ───────────────────────────────────────────────────────────────────────────────
const LOCK_LABEL = "🔒 Protect with H2Vault (locked, password to run)…";
const PARAMS_LABEL = "🔒 Lock parameters…";
const SEAL_LABEL = "🔒 Protect with H2Vault (sealed, authorized installations)…";
const DEFAULT_PROFILE_SETTING = "h2vault.protect.defaultProfile";

function defaultProfile() {
  try {
    const v = app.extensionManager?.setting?.get?.(DEFAULT_PROFILE_SETTING);
    return v === "locked" || v === "sealed_installs" ? v : "sealed_installs";
  } catch (_) { return "sealed_installs"; }
}

/** The protect entries (canvas and node menus) for `items`; [] when nothing protectable is in them. */
function lockMenuItems(items) {
  const r = resolveLockSelection(items, { LiteGraph: globalThis.LiteGraph });
  if (r.kind === "empty") return [];
  if (r.kind === "subgraph") {
    return [null, { content: "🔒 Protect this subgraph with H2Vault…",
      callback: () => lockSelection(app.canvas, defaultProfile(), items) }];
  }
  const out = [null,
    { content: SEAL_LABEL, callback: () => lockSelection(app.canvas, "sealed_installs", items) },
    { content: LOCK_LABEL, callback: () => lockSelection(app.canvas, "locked", items) }];
  const n = lockableNodes(r.nodes).length;
  if (n) out.push({ content: n === 1 ? PARAMS_LABEL : `🔒 Lock parameters of ${n} nodes…`,
    callback: () => lockParameters(items) });
  return out;
}

/** V5 design 7.1: right-click on a group (core's own group entries use the same hook and getGroupOnPos). */
function groupMenuItems(canvas) {
  const g = canvas?.graph?.getGroupOnPos?.(canvas.graph_mouse?.[0], canvas.graph_mouse?.[1]);
  if (!g || selectedItemsOf(canvas).length) return [];
  const items = [g];
  const r = resolveLockSelection(items, { LiteGraph: globalThis.LiteGraph });
  if (r.kind === "empty" || r.problems.length) return [];
  const out = [null, { content: "🔒 Protect this group with H2Vault…",
    callback: () => lockSelection(app.canvas, defaultProfile(), items) }];
  if (lockableNodes(r.nodes).length) out.push({ content: "🔒 Lock parameters in this group…",
    callback: () => lockParameters(items) });
  return out;
}

function isOutputNodeType(type) {
  return !!globalThis.LiteGraph?.registered_node_types?.[type]?.nodeData?.output_node;
}

/** "Protect the whole workflow": every node of the graph on screen except output nodes (they stay outside to show
 *  and save results) and vaults, then the usual protect dialog. */
function protectWholeWorkflow() {
  const g = app.canvas?.graph ?? app.graph;
  const items = (g?.nodes || g?._nodes || []).filter((n) => n && n.id != null && Number(n.id) >= 0
    && !isVaultType(n.type) && !isOutputNodeType(n.type));
  if (!items.length) {
    toast("Nothing to protect: this graph has no nodes besides its outputs.", true);
    return null;
  }
  return lockSelection(app.canvas, "sealed_installs", items);
}

app.registerExtension({
  name: "H2Vault.Vault",
  commands: [
    { id: "h2vault.protect.sealed", label: "H2Vault: Protect selection (sealed, authorized installations)",
      icon: "pi pi-lock", function: () => lockSelection(app.canvas, "sealed_installs") },
    { id: "h2vault.protect.locked", label: "H2Vault: Protect selection (locked, password to run)", icon: "pi pi-lock",
      function: () => lockSelection(app.canvas, "locked") },
    { id: "h2vault.protect.wholeWorkflow", label: "H2Vault: Protect the whole workflow", icon: "pi pi-shield",
      function: () => protectWholeWorkflow() },
    { id: "h2vault.twoFactor.setup", label: "H2Vault: Two-factor setup", icon: "pi pi-mobile",
      function: () => twoFactorSetup() },
    { id: "h2vault.installCode.show", label: "H2Vault: My installation code", icon: "pi pi-key",
      function: () => showInstallCode() },
    { id: "h2vault.lockParams", label: "H2Vault: Lock parameters of the selected nodes", icon: "pi pi-lock",
      function: () => lockParameters(selectedItemsOf(app.canvas)) },
    { id: "h2vault.licence.ledger", label: "H2Vault: Licences issued", icon: "pi pi-list",
      function: () => ledgerDialog() },
    { id: "h2vault.licence.exportAuthor", label: "H2Vault: Back up my author key", icon: "pi pi-download",
      function: () => exportAuthorKey() },
    { id: "h2vault.licence.importAuthor", label: "H2Vault: Restore author key", icon: "pi pi-upload",
      function: () => importAuthorKey() },
  ],
  menuCommands: [{ path: ["H2Vault"], commands: ["h2vault.protect.sealed", "h2vault.protect.locked",
    "h2vault.protect.wholeWorkflow", "h2vault.lockParams", "h2vault.twoFactor.setup", "h2vault.installCode.show",
    "h2vault.licence.ledger", "h2vault.licence.exportAuthor", "h2vault.licence.importAuthor"] }],
  settings: [{ id: DEFAULT_PROFILE_SETTING, category: ["H2Vault", "Protect", "Default profile"],
    name: "Profile chosen first when protecting a subgraph", type: "combo", defaultValue: "sealed_installs",
    options: [{ text: "Sealed - authorized installations", value: "sealed_installs" },
      { text: "Locked - password to run", value: "locked" }] },
    { id: PROVISION_SETTING, category: ["H2Vault", "Run", "Install what a vault needs"],
      name: "When a workflow's vault needs model files or extensions this ComfyUI lacks", type: "combo",
      defaultValue: "auto",
      tooltip: "Automatically: download them in the background (checked before use; what they are stays private). "
        + "Extensions are code and need a ComfyUI restart.",
      options: [{ text: "Install automatically", value: "auto" }, { text: "Ask first", value: "ask" },
        { text: "Never", value: "never" }] }],
  setup() {
    installGuards();
    app.canvas?.canvas?.addEventListener("litegraph:set-graph", onSetGraph);
    api.addEventListener("execution_error", onExecutionError);      // offer the install on every failed attempt
    api.addEventListener("h2vault.phase", onPhase);
    for (const ev of ["execution_success", "execution_error", "execution_interrupted"]) {
      api.addEventListener(ev, clearPhases);
      api.addEventListener(ev, refreshLicensedCards);              // V5: runs left / an ended licence
    }
  },
  async beforeRegisterNodeDef(nodeType, nodeData) {
    if (VAULT_TYPES.has(nodeData.name)) {
      const created = nodeType.prototype.onNodeCreated;
      nodeType.prototype.onNodeCreated = function (...a) {
        const r = created?.apply(this, a);
        applyInterface(this);
        return r;
      };
      const configured = nodeType.prototype.onConfigure;
      nodeType.prototype.onConfigure = function (...a) {
        const r = configured?.apply(this, a);
        applyInterface(this);
        // frontend 1.53 restores widgets_values by POSITION before onConfigure, when the p_ controls do not exist
        // yet: put the saved values back (saved order: vault_id, vault_payload, then the controls in interface order)
        const vals = a[0]?.widgets_values;
        if (Array.isArray(vals)) {
          (vaultInfo(this).interface?.params || []).forEach((p, i) => {
            const w = this.widgets?.find((x) => x.name === `p_${p.key}`);
            if (w && vals[2 + i] !== undefined && vals[2 + i] !== null) w.value = vals[2 + i];
          });
        }
        return r;
      };
      nodeType.prototype.onDblClick = function () { openVault(this); return true; };
    }
  },
  getCanvasMenuItems(canvas) {
    const items = [...lockMenuItems(selectedItemsOf(canvas)), ...groupMenuItems(canvas)];
    for (const [sg, sess] of OPEN) {                    // V3: inside an open concealed vault
      if (sg.subgraph === canvas?.graph) items.push(...concealMenuItems(sess));
    }
    return items;
  },
  getNodeMenuItems(node) {
    const type = node?.comfyClass ?? node?.type;
    if (VAULT_TYPES.has(type)) {
      const licensed = vaultInfo(node).profile === "sealed_licensed";
      return [null,
        { content: "🔓 Open / edit vault…", callback: () => openVault(node) },
        ...(licensed ? [
          { content: "🎫 Add licence…", callback: () => addLicence(node) },
          { content: "🧾 Issue a licence…", callback: () => issueLicence(node) },
          { content: "♻️ Revoke licences (new licence key)…", callback: () => rotateLicences(node) },
          { content: "💾 Back up my author key…", callback: () => exportAuthorKey(node) },
          { content: "📥 Restore author key…", callback: () => importAuthorKey(node) }] : []),
        { content: "👥 Manage installations & editors…", callback: () => manageAccess(node, "access") },
        { content: "🔐 Change password…", callback: () => manageAccess(node, "password") },
        { content: "📦 Install missing custom nodes…", callback: () => installMissing(node) },
        { content: vaultInfo(node).lock ? "🔓 Unlock parameters (remove protection)…" : "🗝️ Remove protection…",
          callback: () => removeProtection(node) },
        { content: "🔑 My installation code", callback: showInstallCode },
        { content: "📱 Two-factor setup…", callback: () => twoFactorSetup() }];
    }
    if (OPEN.has(node)) return concealMenuItems(OPEN.get(node));
    if (node?.id == null || Number(node.id) < 0) return [];
    // right-clicking a node is where people look: it acts on the selection when the node is part of it, otherwise
    // on that node alone; one subgraph node gets "Protect this subgraph"
    const sel = selectedItemsOf(app.canvas);
    return lockMenuItems(sel.includes(node) ? sel : [node]);
  },
});

// browser tests: protect given nodes without the dialog
globalThis.__h2vault = { lockSelection: (profile) => lockSelection(app.canvas, profile),
  protectNodes: (nodes, opts) => protectWithFeedback(nodes, opts), protectTransaction, protectWholeWorkflow,
  lockNodeParameters, lockRequest, refreshLicence, LICENCE_STATE, issueLicence, addLicence, ledgerDialog, lockParameters,
  removeProtection };

export { buildApi, exportUi, scrub, OPEN };
