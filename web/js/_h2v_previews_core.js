// H2Vault (AGPL-3.0). New for H2Vault (owner 2026-11-23): previews from inside a vault - the pure part (no DOM, no
// ComfyUI app), shared by the vault's preview panel (h2vault_previews.js) and the author's settings
// (_h2v_previews_ui.js). Tests: tests/test_previews_frontend.mjs.

const KIND_WORD = { image: ["image", "images"], video: ["video", "videos"], audio: ["audio clip", "audio clips"],
  text: ["text", "texts"], file: ["file", "files"], other: ["preview", "previews"] };
const DEFAULT_PREFIX = /^ComfyUI(\b|_|$)/;

/** label -> what it showed ("2 images, 1 video"), in the server's order (the inner graph's). */
export function summarize(items) {
  const rows = new Map();
  for (const it of items || []) {
    const lab = String(it?.label || "Preview");
    if (!rows.has(lab)) rows.set(lab, {});
    const r = rows.get(lab);
    r[it.kind] = (r[it.kind] || 0) + 1;
  }
  return [...rows].map(([label, kinds]) => ({ label, text: Object.entries(kinds).map(([k, n]) => {
    const w = KIND_WORD[k] || KIND_WORD.other;
    return `${n} ${n === 1 ? w[0] : w[1]}`;
  }).join(", ") }));
}

/** What the vault's panel shows for a merged output: {rows, media, notes, count}. `urlOf(file)` -> a /view URL. */
export function plan(output, urlOf) {
  const items = Array.isArray(output?.h2v_previews) ? output.h2v_previews : [];
  const media = [], notes = [];
  for (const it of items) {
    if (it.kind === "video" || it.kind === "audio" || (it.kind === "image" && !it.core)) {
      if (it.file?.filename) media.push({ label: it.label, kind: it.kind, url: urlOf(it.file), format: it.file.format });
    } else if (it.kind === "text") {
      media.push({ label: it.label, kind: "text", text: String(it.text ?? "") });
    }
  }
  const other = items.filter((x) => x.kind === "other" || x.kind === "file");
  if (other.length) {
    const labs = [...new Set(other.map((x) => x.label))].join(", ");
    notes.push(`${labs}: ${other.length === 1 ? "a preview" : "previews"} of a kind the vault cannot show here ` +
      "(it shows images, videos, audio and text). Saved files, if any, are in your output folder.");
  }
  if (items.some((x) => x.kind === "image" && x.core)) notes.push("Images are shown by ComfyUI's own image preview.");
  return { rows: summarize(items), media, notes, count: items.length };
}

/** The /view URL of an output file (core server.py /view: filename, subfolder, type). */
export function viewPath(f) {
  const q = new URLSearchParams({ filename: f?.filename || "", subfolder: f?.subfolder || "", type: f?.type || "output" });
  return `/view?${q}`;
}

const idKey = (id) => String(id).split(":").map((x) => (/^\d+$/.test(x) ? Number(x) : x));
function cmpIds(a, b) {
  const ka = idKey(a), kb = idKey(b);
  if ((ka.length > 1) !== (kb.length > 1)) return ka.length > 1 ? 1 : -1;     // top-level ids first (as the server)
  for (let i = 0; i < Math.max(ka.length, kb.length); i++) {
    if (ka[i] === kb[i]) continue;
    if (ka[i] === undefined) return -1;
    if (kb[i] === undefined) return 1;
    return typeof ka[i] === typeof kb[i] ? (ka[i] < kb[i] ? -1 : 1) : (typeof ka[i] === "number" ? -1 : 1);
  }
  return 0;
}

/** The output nodes (previews, saves) among `nodes`, numbered in the server's "Preview N" order
 *  (nodes/previews.py order_of: top-level ids, numerically). */
export function previewItems(nodes, { defOf = () => null } = {}) {
  const out = [];
  for (const n of nodes || []) {
    if (!n || n.subgraph || !defOf(n.type)?.output_node) continue;
    const prefix = (n.widgets || []).find((w) => w.name === "filename_prefix")?.value;
    out.push({ id: String(n.id), title: n.title || n.type, type: String(n.type),
      prefix: typeof prefix === "string" ? prefix : null });
  }
  out.sort((a, b) => cmpIds(a.id, b.id));
  return out.map((x, i) => ({ ...x, number: i + 1 }));
}

/** Save nodes' own file name prefixes (they show in the saved file names). */
export function customPrefixes(items) {
  return [...new Set((items || []).map((x) => x.prefix).filter((p) => p && !DEFAULT_PREFIX.test(p)))];
}
