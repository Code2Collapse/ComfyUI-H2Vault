// H2Vault (AGPL-3.0). New for H2Vault (owner 2026-11-23): the author's "Show previews from inside" setting.
// Used by the lock dialog and by "Previews on the vault…" inside an open vault. The setting and the labels are sent
// to the server and kept INSIDE the encryption (nodes/previews.py choice); the vault node only learns "off".
import { disclosure, el, noticeEl, switchRow, textField } from "./_h2v_ui.js";
import { customPrefixes, previewItems } from "./_h2v_previews_core.js";

export { previewItems };

const MAX_LABEL = 40;

/** {el, value()} -> value() = {show, labels} for the server. */
export function previewSection({ items = [], value = null, nestedNote = false } = {}) {
  const cur = { show: value?.show !== false, labels: { ...(value?.labels || {}) } };
  const sw = switchRow("Show previews from inside on the vault", { checked: cur.show });
  const hint = el("p", { class: "h2v-block__hint", text: "Images, videos, audio and text that preview and save nodes " +
    "inside produce appear on the vault node, live sampler previews included - labelled \"Preview 1\", \"Preview 2\" " +
    "or with the names you give below, never with node names or types. Off: nothing from inside shows (the progress " +
    "bar still moves, and the vault says its previews are off)." });
  const kids = [sw.el, hint];
  const fields = [];
  if (items.length) {
    const d = disclosure(`Preview names (optional, ${items.length} preview node${items.length === 1 ? "" : "s"})`);
    d.body.append(el("p", { class: "h2v-dim", text: "Only you see the node names in this list. People who run the " +
      "vault see the name you type, or \"Preview N\"." }));
    for (const it of items) {
      const f = textField({ label: `Preview ${it.number} - ${it.title}`, value: cur.labels[it.id] || "",
        maxLength: MAX_LABEL });
      f.input.placeholder = `Preview ${it.number}`;
      fields.push({ id: it.id, input: f.input });
      d.body.append(f.el);
    }
    if (nestedNote) {
      d.body.append(el("p", { class: "h2v-dim", text: "Preview nodes inside nested subgraphs are numbered after " +
        "these and cannot be named here." }));
    }
    kids.push(d.el);
  }
  const prefixes = customPrefixes(items);
  if (prefixes.length) {
    kids.push(noticeEl("info", `Saved files keep the file names you set (${prefixes.map((p) => `"${p}"`).join(", ")}): ` +
      "whoever runs the vault sees them on the vault and in their output folder. Use a neutral prefix if the " +
      "name says something about the inside."));
  }
  return {
    el: el("section", { class: "h2v-block" }, [el("h3", { class: "h2v-block__title", text: "Previews" }), ...kids]),
    value() {
      const labels = {};
      for (const f of fields) {
        const v = f.input.value.trim().slice(0, MAX_LABEL);
        if (v) labels[f.id] = v;
      }
      return { show: sw.checked(), labels };
    },
  };
}
