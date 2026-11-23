// H2Vault (AGPL-3.0) - workstream V3, identity concealment: the AUTHOR side's pure logic ("Choose what to expose").
//
// From the nodes about to be locked it lists every control a person could set, groups them by role (sampler,
// scheduler, steps, cfg, seed, denoise, sizes, prompts, model choices, other), pre-selects the usual ones, proposes
// plain labels, and turns the author's choices into the `conceal` section the server seals INSIDE the vault
// (nodes/concealment.py merge_exposure / check_public). Model choices become aliases ("Model A" -> a real file):
// the real file names travel only in the alias table, which the server keeps inside the encrypted payload.
//
// Pure: no DOM, no import from the ComfyUI frontend (tests run it under node). Shapes are frontend 1.53.10's:
// node.widgets [{name, value, type, options}], node.inputs [{name, type, link, widget?}], node.outputs [{links}],
// graph.links a Map (or an object) of {origin_id, origin_slot, target_id, target_slot, type}.

export const ROLES = Object.freeze([
  { id: "sampler", title: "Sampler" },
  { id: "scheduler", title: "Scheduler" },
  { id: "steps", title: "Steps" },
  { id: "cfg", title: "CFG" },
  { id: "seed", title: "Seed" },
  { id: "denoise", title: "Denoise" },
  { id: "size", title: "Sizes" },
  { id: "prompt", title: "Prompts" },
  { id: "model", title: "Model choices" },
  { id: "other", title: "Other settings" },
]);
export const DEFAULT_ROLES = new Set(["sampler", "scheduler", "steps", "cfg", "seed", "denoise", "size", "prompt"]);

const FILE_RE = /\.(safetensors|ckpt|pt|pth|bin|gguf|onnx|sft|yaml|yml|json|cube|png|jpe?g|webp)$/i;
const FRONTEND_ONLY = new Set(["control_after_generate", "control_before_generate", "upload", "image_upload"]);
// the server forces its own output prefix for a concealed vault; offering this one would be a dead control
const NEVER = new Set(["filename_prefix"]);
const VALUE_TYPES = new Set(["INT", "FLOAT", "STRING", "BOOLEAN", "COMBO"]);
const NAME_ROLE = {
  sampler_name: "sampler", sampler: "sampler", scheduler: "scheduler", steps: "steps", cfg: "cfg", cfg_scale: "cfg",
  guidance: "cfg", seed: "seed", noise_seed: "seed", denoise: "denoise", width: "size", height: "size",
};
const PROMPT_NAMES = new Set(["text", "prompt", "positive", "negative", "text_g", "text_l", "clip_l", "t5xxl"]);
const TYPE_LABEL = { IMAGE: "Image", LATENT: "Latent", MASK: "Mask", CONDITIONING: "Conditioning", AUDIO: "Audio",
  VIDEO: "Video", INT: "Number", FLOAT: "Number", STRING: "Text", BOOLEAN: "Switch" };

const isFile = (v) => typeof v === "string" && FILE_RE.test(v);
const humanize = (s) => { const t = String(s).replace(/_+/g, " ").trim(); return t.charAt(0).toUpperCase() + t.slice(1); };
const typeLabel = (t, kind = "out") => (String(t ?? "*").trim() === "*" || !String(t ?? "").trim() ?
  (kind === "in" ? "Input" : "Output") :                        // a wildcard socket: never the name "*"
  TYPE_LABEL[String(t).toUpperCase()] ?? humanize(String(t).toLowerCase()));

/** The role of one inner control (by its input name, value and spec). */
export function roleOf(name, value, spec = {}) {
  const n = String(name || "").toLowerCase();
  if (NAME_ROLE[n]) return NAME_ROLE[n];
  if (spec.type === "COMBO" && (isFile(value) || (spec.options || []).some(isFile))) return "model";
  if (spec.type === "STRING" && (spec.multiline || PROMPT_NAMES.has(n))) return "prompt";
  return "other";
}

function specOf(def, name, w) {
  const req = def?.input?.required || {}, opt = def?.input?.optional || {};
  const s = req[name] ?? opt[name];
  if (Array.isArray(s)) {
    const [t, o = {}] = s;
    if (Array.isArray(t)) return { type: "COMBO", options: t.slice(), ...o };
    if (t === "COMBO") return { ...o, type: "COMBO", options: (o.options || []).slice() };
    return { ...o, type: String(t) };
  }
  // no definition (a frontend-only node): the widget says what it is
  if (w?.type === "combo") return { type: "COMBO", options: (w.options?.values || []).slice() };
  if (w?.type === "toggle") return { type: "BOOLEAN" };
  if (w?.type === "number") return { type: Number.isInteger(w.value) ? "INT" : "FLOAT", ...pick(w.options) };
  if (w?.type === "customtext") return { type: "STRING", multiline: true };
  if (w?.type === "text") return { type: "STRING" };
  return { type: "" };
}
function pick(o = {}) {
  const r = {};
  for (const k of ["min", "max", "step"]) if (typeof o[k] === "number") r[k] = o[k];
  return r;
}
const linkOf = (g, id) => (g?.links instanceof Map ? g.links.get(id) : g?.links?.[id]) ?? null;
const isSub = (n) => !!n?.subgraph || (typeof n?.isSubgraphNode === "function" && n.isSubgraphNode());

function settable(n, w, promoted) {
  if (!w || !w.name || typeof w.value === "function") return false;
  if (String(w.name).startsWith("$$") || FRONTEND_ONLY.has(w.name) || NEVER.has(w.name)) return false;
  if (w.type === "button" || w.type === "hidden" || w.hidden || w.options?.hidden) return false;
  // a widget promoted onto the subgraph node is still a control (its value lives on the subgraph node)
  if (promoted?.has(`${n.id}:${w.name}`)) return true;
  // fed by a wire: its value comes from that wire, not from a control
  return !(n.inputs || []).some((i) => i?.widget?.name === w.name && i.link != null);
}

/** Does one of this node's outputs feed an input named "negative"? (the negative prompt, by its wire) */
function feedsNegative(n, byId) {
  for (const o of n.outputs || []) for (const lid of o?.links || []) {
    const l = linkOf(n.graph, lid);
    const t = l && byId.get(String(l.target_id));
    if (t && String(t.inputs?.[l.target_slot]?.name || "").toLowerCase() === "negative") return true;
  }
  return false;
}

/** Every control the author could expose, in role order, with default selection and labels. `promoted`:
 *  Map "<inner node id>:<widget>" -> value for widgets promoted onto a subgraph node (frontend 1.53 auto-promotes
 *  some when nodes become a subgraph); they are controls, with the subgraph node's value. */
export function inventory(nodes, { defOf = () => null, promoted = null } = {}) {
  const list = (nodes || []).filter((n) => n && !isSub(n));
  const byId = new Map(list.map((n) => [String(n.id), n]));
  const out = [];
  for (const n of list) {
    const def = defOf(n.type);
    for (const w of n.widgets || []) {
      if (!settable(n, w, promoted)) continue;
      const spec = specOf(def, w.name, w);
      const value = promoted?.has(`${n.id}:${w.name}`) ? promoted.get(`${n.id}:${w.name}`) : w.value;
      if (!VALUE_TYPES.has(spec.type)) continue;
      const role = roleOf(w.name, value, spec);
      let label;
      if (role === "prompt") label = feedsNegative(n, byId) ? "Negative prompt" : "Prompt";
      else if (role === "size") label = humanize(w.name);
      else if (role === "model") label = "Model";
      else if (role === "other") label = humanize(w.name);
      else label = ROLES.find((r) => r.id === role).title;
      const c = { id: `${n.id}:${w.name}`, node: String(n.id), nodeTitle: String(n.title || n.type || ""),
        input: w.name, role, label, type: role === "model" ? "COMBO" : spec.type, value,
        selected: DEFAULT_ROLES.has(role) };
      if (spec.type === "COMBO") c.options = (spec.options || []).slice();
      Object.assign(c, pick(spec));
      if (spec.type === "STRING" && (spec.multiline || role === "prompt")) c.multiline = true;
      if (role === "model") c.aliases = [{ label: "Model A", value }];
      out.push(c);
    }
  }
  const order = new Map(ROLES.map((r, i) => [r.id, i]));
  out.sort((a, b) => order.get(a.role) - order.get(b.role));
  const seen = new Map();                                // "Seed", "Seed 2" ... (a label names one control)
  for (const c of out) {
    const k = c.label.toLowerCase();
    const n = (seen.get(k) || 0) + 1;
    seen.set(k, n);
    if (n > 1) c.label = `${c.label} ${n}`;
  }
  return out;
}

function numberLabels(socks) {
  const seen = new Map();
  for (const s of socks) {
    const k = `${s.kind}:${s.label}`;
    const n = (seen.get(k) || 0) + 1;
    seen.set(k, n);
    if (n > 1) s.label = `${s.label} ${n}`;
  }
  return socks;
}

/** V2's rule (h2vault_vault.js promotedOf): a subgraph input that shows as a widget on the subgraph node and has no
 *  outer wire is a promoted control. */
export function isPromoted(sg, inp, i) {
  return !!sg?.widgets?.some?.((w) => w.name === inp?.name) && sg?.inputs?.[i]?.link == null;
}

/** "<inner node id>:<widget>" -> value for every widget promoted onto subgraph node `sg`. */
export function promotedValues(sg) {
  const map = new Map();
  const sub = sg?.subgraph;
  (sub?.inputs || []).forEach((inp, i) => {
    if (!isPromoted(sg, inp, i)) return;
    const value = sg.widgets.find((w) => w.name === inp.name)?.value;
    for (const lid of inp.linkIds || []) {
      const l = linkOf(sub, lid);
      const t = l && sub.getNodeById?.(l.target_id);
      const name = t?.inputs?.[l.target_slot]?.widget?.name;
      if (t && name) map.set(`${t.id}:${name}`, value);
    }
  });
  return map;
}

/** The vault's sockets (what the recipient wires), keyed the way the server renames them (merge_exposure). */
export function socketsOf({ kind, nodes = [], boundary = null, sg = null } = {}) {
  const socks = [];
  if (kind === "subgraph" && sg?.subgraph) {
    const sub = sg.subgraph;
    (sub.inputs || []).forEach((inp, i) => {
      if (isPromoted(sg, inp, i)) return;                // a control on the subgraph node, not a socket
      const l = linkOf(sub, (inp.linkIds || [])[0]);
      const t = l && sub.getNodeById?.(l.target_id);
      const name = t?.inputs?.[l.target_slot]?.widget?.name ?? t?.inputs?.[l.target_slot]?.name;
      if (t && name) socks.push({ kind: "in", key: `${t.id}:${name}`, type: String(inp.type || "*"), label: typeLabel(inp.type, "in") });
    });
    (sub.outputs || []).forEach((o, j) => {
      const l = linkOf(sub, (o.linkIds || [])[0]);
      if (l) socks.push({ kind: "out", key: `${l.origin_id}#${l.origin_slot}`, type: String(o.type || "*"),
        label: typeLabel(o.type), wires: (sg.outputs?.[j]?.links || []).length });
    });
    return numberLabels(socks);
  }
  const seenIn = new Set(), seenOut = new Set();
  for (const e of boundary?.entering || []) {
    const outer = `${e.origin_id}#${e.origin_slot}`;
    if (seenIn.has(outer)) continue;
    seenIn.add(outer);
    socks.push({ kind: "in", key: `${e.target_id}:${e.widget ?? e.target_name}`, type: String(e.type || "*"),
      label: typeLabel(e.type, "in") });
  }
  for (const e of boundary?.leaving || []) {
    const key = `${e.origin_id}#${e.origin_slot}`;
    if (seenOut.has(key)) continue;
    seenOut.add(key);
    socks.push({ kind: "out", key, type: String(e.type || "*"), label: typeLabel(e.type),
      wires: (boundary.leaving || []).filter((x) => `${x.origin_id}#${x.origin_slot}` === key).length });
  }
  return numberLabels(socks);
}

/** Inner nodes whose results may show on the vault (core's output nodes: previews, saves). */
export function previewsOf(nodes, { defOf = () => null } = {}) {
  return (nodes || []).filter((n) => n && !isSub(n) && defOf(n.type)?.output_node).map((n) => String(n.id));
}

/** The author's choices -> {conceal, problems}. `problems` are the checks that need no server (names given, alias
 *  tables well formed); everything about the inside is judged by the server's check route. */
export function buildConceal(inv, { title = "", sockets = [], previews = [] } = {}) {
  const problems = [];
  if (!String(title).trim()) problems.push("Give the vault a title: it is the only name the recipient sees.");
  const controls = [], aliases = {};
  let i = 0;
  for (const c of inv || []) {
    if (!c.selected) continue;
    const label = String(c.label || "").trim();
    if (!label) { problems.push("Every exposed control needs a name - one is empty."); continue; }
    const key = `c${i++}`;
    const entry = { key, node: String(c.node), input: String(c.input), name: label, type: c.type };
    if (c.role === "model") {
      const rows = (c.aliases || []).map((a) => ({ label: String(a.label || "").trim(), value: a.value }));
      if (!rows.length) { problems.push(`"${label}" needs at least one choice.`); continue; }
      if (rows.some((a) => !a.label)) problems.push(`"${label}": every choice needs a name.`);
      const names = rows.map((a) => a.label.toLowerCase());
      if (new Set(names).size !== names.length) problems.push(`"${label}": two choices have the same name.`);
      entry.type = "COMBO";
      entry.options = rows.map((a) => a.label);
      entry.value = rows[0].label;
      aliases[key] = Object.fromEntries(rows.map((a) => [a.label, a.value]));
    } else {
      entry.value = c.value;
      if (Array.isArray(c.options)) entry.options = c.options.slice();
      for (const k of ["min", "max", "step"]) if (typeof c[k] === "number") entry[k] = c[k];
      if (c.multiline) entry.multiline = true;
    }
    controls.push(entry);
  }
  const sock = { in: {}, out: {} };
  const types = {};
  for (const s of sockets || []) {
    if (s.kind === "out" && s.drop) continue;          // removed from the vault (owner 2026-11-23)
    const label = String(s.label || "").trim();
    if (!label) {
      problems.push(`The ${s.kind === "in" ? "input" : "output"} socket of type ${s.type || "*"} needs a name - ` +
        "its name field is empty.");
      continue;
    }
    sock[s.kind === "in" ? "in" : "out"][s.key] = label;
    if (s.kind === "out" && s.showAs) types[s.key] = String(s.showAs);
  }
  if (Object.keys(types).length) sock.types = types;
  return { conceal: { version: 1, title: String(title).trim(), controls, aliases, sockets: sock,
    previews: (previews || []).map(String) }, problems };
}

/** The inner graph as the server's check route judges it (before anything is grouped or sealed): classes, widget
 *  values, the author's own node titles, socket types. Sealing judges the real extracted graph again. */
export function candidate(nodes, sockets = []) {
  const list = (nodes || []).filter((n) => n && !isSub(n));
  const byId = new Map(list.map((n) => [String(n.id), n]));
  // the real source of a wire: frontend-only nodes (a legacy Reroute) are followed through their first input, like
  // graphToPrompt does; null when the source is not one of these nodes (a subgraph input, a nested subgraph)
  const sourceOf = (g, id, slot, depth = 0) => {
    const n = byId.get(String(id)) ?? g?.getNodeById?.(id) ?? null;
    if (!n || depth > 32) return null;
    if (n.isVirtualNode && !isSub(n)) {
      const l = linkOf(n.graph ?? g, (n.inputs || [])[0]?.link);
      return l ? sourceOf(n.graph ?? g, l.origin_id, l.origin_slot, depth + 1) : null;
    }
    return byId.has(String(n.id)) ? [String(n.id), Number(slot)] : null;
  };
  const apiNodes = {};
  for (const n of list) {
    const inputs = {};
    for (const w of n.widgets || []) {
      if (!w?.name || typeof w.value === "function" || String(w.name).startsWith("$$") || FRONTEND_ONLY.has(w.name)) continue;
      inputs[w.name] = w.value;
    }
    // owner 2026-11-23: the inner wires, so the check can trace a "*" output to what really reaches it
    for (const inp of n.inputs || []) {
      const l = inp?.link != null ? linkOf(n.graph, inp.link) : null;
      const src = l && sourceOf(n.graph, l.origin_id, l.origin_slot);
      const name = inp.widget?.name ?? inp.name;
      if (src && name) inputs[name] = src;
    }
    apiNodes[String(n.id)] = { class_type: String(n.type), inputs };
  }
  const ins = [], outs = [];
  for (const s of sockets || []) {
    if (s.kind === "in") {
      const [nid, name] = String(s.key).split(":");
      if (apiNodes[nid]) apiNodes[nid].inputs[name] = { vault_in: ins.length };
      ins.push({ name: String(s.label || ""), type: String(s.type || "*") });
    } else if (!s.drop) {
      const [nid, slot] = String(s.key).split("#");
      const src = sourceOf(list[0]?.graph, nid, Number(slot)) ?? [nid, Number(slot)];
      outs.push({ name: String(s.label || ""), type: String(s.type || "*"), node: src[0], slot: src[1] });
    }
  }
  const titled = list.map((n) => ({ id: n.id, type: String(n.type), title: String(n.title || "") }))
    .filter((n) => n.title);
  return { api: { nodes: apiNodes, inputs: ins, outputs: outs, promoted: [] },
    interface: { in: ins.map((x) => ({ ...x })), out: outs.map(({ name, type }) => ({ name, type })), params: [] },
    ui: { definitions: [{ id: "candidate", nodes: titled }] } };
}

// ── owner 2026-11-23: the dialog's per-output fixes ("never a dead end") ───────────────────────────────────────
/** Apply one fix the server's output review offers (nodes/concealment.py review_outputs) to an output socket:
 *  "remove" (the output leaves the vault when it is locked), "keep" (undo), "show_as" (publish a traced "*" output as
 *  its one concrete type), "show_as_undo". -> true when something changed. */
export function applyOutputFix(sock, fix) {
  if (!sock || sock.kind !== "out" || !fix) return false;
  if (fix.id === "remove") { sock.drop = true; return true; }
  if (fix.id === "keep") { sock.drop = false; return true; }
  // a socket still called by its default name ("Output") is renamed after the type it is shown as, and back
  if (fix.id === "show_as" && fix.type) {
    if (sock.label === typeLabel(sock.showAs ?? sock.type)) sock.label = typeLabel(fix.type);
    sock.showAs = String(fix.type);
    return true;
  }
  if (fix.id === "show_as_undo") {
    if (sock.showAs && sock.label === typeLabel(sock.showAs)) sock.label = typeLabel(sock.type);
    delete sock.showAs;
    return true;
  }
  return false;
}

/** The keys of the outputs the author removed (the protect transaction removes them from the subgraph). */
export function droppedOutputs(sockets) {
  return (sockets || []).filter((s) => s.kind === "out" && s.drop).map((s) => s.key);
}

/** The server's review entries -> the output socket each belongs to (Map socket -> entry), by key; entries of
 *  outputs with the same inner source go to the next socket with that key. Removed sockets get none. */
export function matchReview(sockets, review) {
  const outs = (sockets || []).filter((s) => s.kind === "out" && !s.drop);
  const map = new Map();
  (review || []).forEach((r, j) => {
    const s = outs.find((x) => x.key === r?.key && !map.has(x)) ?? (!map.has(outs[r?.index ?? j]) ? outs[r?.index ?? j] : null);
    if (s) map.set(s, r);
  });
  return map;
}
