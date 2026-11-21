// H2Vault (AGPL-3.0) - workstream V3, identity concealment: the public half of a concealed vault, as the browser may
// hold it. One whitelist for everything that shows or stores it: the recipient's vault node (_h2v_conceal.js), the
// author's "Preview as recipient" pane and the saved workflow. Pure: no DOM, no ComfyUI import (tests run it in node).

const PARAM_FIELDS = ["key", "name", "type", "value", "options", "min", "max", "step", "multiline"];
const SCALAR = (v) => ["string", "number", "boolean"].includes(typeof v);

/** The public half, re-whitelisted in the browser: a malformed or tampered workflow cannot make the renderer show
 *  (or re-save) a field the server would never publish. */
export function whitelistPublic(pub) {
  const p = pub && typeof pub === "object" ? pub : {};
  const sock = (s) => ({ name: String(s?.name ?? ""), type: String(s?.type ?? "*") });
  const params = (Array.isArray(p.params) ? p.params : []).filter((x) => x && typeof x === "object").map((x) => {
    const q = {};
    for (const f of PARAM_FIELDS) {
      if (!(f in x)) continue;
      if (f === "options") { if (Array.isArray(x.options)) q.options = x.options.filter(SCALAR); }
      else if (f === "value" ? (x.value == null || SCALAR(x.value)) : SCALAR(x[f])) q[f] = x[f];
    }
    q.key = String(q.key ?? "");
    q.name = String(q.name ?? q.key);
    return q;
  }).filter((q) => q.key);
  return {
    title: String(p.title ?? "H2Vault"),
    in: (Array.isArray(p.in) ? p.in : []).map(sock),
    out: (Array.isArray(p.out) ? p.out : []).map(sock),
    params,
    concealed: true,
  };
}

/** What the recipient's node shows, as data: title, socket labels, one row per control (label, kind, value). */
export function previewModel(pub) {
  const p = whitelistPublic(pub);
  return {
    title: p.title,
    inputs: p.in.map((s) => s.name),
    outputs: p.out.map((s) => s.name),
    controls: p.params.map((q) => {
      const t = String(q.type || "").toUpperCase();
      if (Array.isArray(q.options) && q.options.length) {
        return { label: q.name, kind: "choice", value: q.value ?? q.options[0], choices: q.options.length };
      }
      if (t === "BOOLEAN") return { label: q.name, kind: "switch", value: !!q.value };
      if (t === "INT" || t === "FLOAT") return { label: q.name, kind: "number", value: q.value ?? 0 };
      return { label: q.name, kind: q.multiline ? "textarea" : "text", value: q.value ?? "" };
    }),
  };
}
