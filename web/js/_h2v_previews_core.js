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

// ── file references (L9.342: validated again here; the server checks them first, nodes/previews.py safe_file) ──
const FILE_TYPES = new Set(["output", "temp", "input"]);

/** A file reference the panel may turn into a /view URL: a bare file name, a relative sub folder, a known type. */
export function safeFile(f) {
  if (!f || typeof f !== "object") return false;
  const name = f.filename, sub = f.subfolder ?? "", type = f.type;
  if (typeof name !== "string" || !name || name.length > 255 || name === "." || name === "..") return false;
  if (/[/\\:\u0000]/.test(name)) return false;
  if (typeof sub !== "string" || sub.length > 512 || /[:\u0000]/.test(sub) || /^[/\\]/.test(sub)) return false;
  if (sub.split(/[/\\]/).some((seg) => seg === "..")) return false;
  return type === undefined || type === null || FILE_TYPES.has(type);
}

const EXT_MIME = { mp4: "video/mp4", m4v: "video/mp4", webm: "video/webm", mov: "video/quicktime",
  mkv: "video/x-matroska", avi: "video/x-msvideo", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg",
  webp: "image/webp", gif: "image/gif", bmp: "image/bmp", avif: "image/avif", tif: "image/tiff", tiff: "image/tiff",
  mp3: "audio/mpeg", wav: "audio/wav", flac: "audio/flac", ogg: "audio/ogg", opus: "audio/ogg", m4a: "audio/mp4",
  aac: "audio/mp4" };

const extOf = (name) => {
  const s = String(name || "").toLowerCase();
  const i = s.lastIndexOf(".");
  return i >= 0 ? s.slice(i + 1) : "";
};

/** A MIME type for the browser's canPlayType check: Video Helper Suite's `format` first, then the extension. */
export function mimeOf(file) {
  const fmt = String(file?.format || "").toLowerCase();
  if (fmt) {
    if (fmt.includes("h265") || fmt.includes("hevc")) return 'video/mp4; codecs="hvc1"';
    if (fmt.includes("av1") && fmt.includes("webm")) return 'video/webm; codecs="av01.0.05M.08"';
    if (fmt.includes("av1")) return 'video/mp4; codecs="av01.0.05M.08"';
    if (fmt.includes("webm")) return "video/webm";
    if (fmt.includes("mp4")) return "video/mp4";
    if (fmt.includes("prores") || fmt.includes("mov")) return "video/quicktime";
    if (fmt.includes("mkv") || fmt.includes("matroska")) return "video/x-matroska";
    if (fmt === "image/gif" || fmt === "image/webp") return fmt;
  }
  return EXT_MIME[extOf(file?.filename)] || "";
}

/** The browser's own answer for a MIME type: "yes" (probably), "maybe", "no" (it says it cannot). */
export function playability(mime, canPlay) {
  if (!mime) return "maybe";
  let a = "";
  try { a = canPlay(mime) || ""; } catch (_) { a = ""; }
  return a === "probably" ? "yes" : a === "maybe" ? "maybe" : "no";
}

/** FNV-1a of a string, base 36 (a key that changes with the text). */
function textHash(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return `${s.length}.${h.toString(36)}`;
}

const fpsOf = (file) => {
  const x = Number(file?.frame_rate);
  return file?.frame_rate != null && Number.isFinite(x) && x > 0 && x <= 1000 ? x : null;
};

/** What the vault's panel shows for a merged output: {rows, entries, media (= entries), notes, count}.
 *  entries: every image (core's included: core no longer draws them on the vault), video, audio and text, in the
 *  server's order, each {key, label, kind, url | text, mime, fps, name, animated, n, of}. `urlOf(file)` -> /view URL. */
export function plan(output, urlOf) {
  const items = Array.isArray(output?.h2v_previews) ? output.h2v_previews : [];
  const entries = [], notes = [];
  let unsafe = 0;
  for (const it of items) {
    if (it?.kind === "image" || it?.kind === "video" || it?.kind === "audio") {
      if (!it.file?.filename) continue;
      if (!safeFile(it.file)) { unsafe += 1; continue; }
      const url = urlOf(it.file);
      const name = String(it.file.filename);
      entries.push({ key: `${it.kind}:${url}`, label: String(it.label || "Preview"), kind: it.kind, url,
        mime: mimeOf(it.file), fps: fpsOf(it.file), name, format: it.file.format || "",
        animated: it.kind === "image" && (it.animated === true || extOf(name) === "gif") });
    } else if (it?.kind === "text") {
      entries.push({ label: String(it.label || "Preview"), kind: "text", text: String(it.text ?? "") });
    }
  }
  const seen = new Map();
  for (const e of entries) {
    const k = `${e.label}\u0000${e.kind}`;
    seen.set(k, (seen.get(k) || 0) + 1);
    e.n = seen.get(k);
  }
  for (const e of entries) {
    e.of = seen.get(`${e.label}\u0000${e.kind}`);
    if (e.kind === "text") e.key = `text:${e.label}:${e.n}:${textHash(e.text)}`;   // a new text = a new entry
  }
  const other = items.filter((x) => x?.kind === "other" || x?.kind === "file");
  unsafe += other.filter((x) => x.unsafe === true).length;
  const shown = other.filter((x) => x.unsafe !== true);
  if (shown.length) {
    const labs = [...new Set(shown.map((x) => x.label))].join(", ");
    notes.push(`${labs}: ${shown.length === 1 ? "a preview" : "previews"} of a kind the vault cannot show here ` +
      "(it shows images, videos, audio and text). Saved files, if any, are in your output folder.");
  }
  if (unsafe) {
    notes.push(`${unsafe} preview file reference${unsafe === 1 ? " was" : "s were"} not safe to show and ` +
      `${unsafe === 1 ? "was" : "were"} skipped.`);
  }
  return { rows: summarize(items), entries, media: entries, notes, count: items.length };
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
