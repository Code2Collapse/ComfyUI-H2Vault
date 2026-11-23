// PORTED FROM: https://github.com/jtydhr88/ComfyUI-Workflow-Encrypt js/comfyui-workflow-encrypt.js @ 5ec45fd
// (AGPL-3.0, jtydhr88); modified for H2Vault (AGPL-3.0). See NOTICE.
//
// Encrypted workflow files (docs/ARCHITECTURE.md section 2.2). The original added "Save(Encrypted)" / "Load(Decrypted)"
// buttons to the old .comfy-menu, alerted the key and prompted for it with window.prompt. Here: commands in the
// H2Vault menu, a dialog that shows the key once (copy / save as a file), optional remembering in the H2Vault key store,
// a password mode, and decryption on load - ComfyUI's own Open and drag-and-drop reach it, because the saved file is a
// JSON wrapper that app.loadGraphData receives.
import { app } from "../../scripts/app.js";
import { api } from "../../scripts/api.js";
import { block, choiceCards, copyRow, el, noticeEl, passwordField, switchRow, textField, vaultDialog,
  vbutton } from "./_h2v_ui.js";

const MARKER = "h2vault_encrypted_workflow";
const REMEMBER_SETTING = "h2vault.workflow.rememberKeys";
const FERNET_KEY_RE = /[A-Za-z0-9_-]{43}=/;
const LOG = (...a) => console.info("[H2Vault]", ...a);

async function post(route, body) {
  const r = await api.fetchApi(route, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body) });
  let data = {};
  try { data = await r.json(); } catch (_) { /* keep {} */ }
  return { ok: r.ok && data.ok !== false, status: r.status, data };
}

function toast(text, severity = "info", summary = "H2Vault") {
  try {
    app.extensionManager?.toast?.add({ severity, summary, detail: text, life: severity === "error" ? 8000 : 5000 });
  } catch (_) { LOG(text); }
}

function rememberDefault() {
  try { return app.extensionManager?.setting?.get?.(REMEMBER_SETTING) !== false; } catch (_) { return true; }
}

function download(filename, text, mime = "application/json") {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = el("a", { href: url, download: filename });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
}

function safeName(name) {
  return String(name || "workflow").replace(/\.(json|h2vault)$/i, "").replace(/[^\w.\- ]+/g, "_").trim().slice(0, 80)
    || "workflow";
}

function activeWorkflowName() {
  try {
    const wf = app.extensionManager?.workflow?.activeWorkflow;
    return wf?.filename || wf?.path?.split(/[\\/]/).pop() || "workflow";
  } catch (_) { return "workflow"; }
}

function pickFile(accept) {
  return new Promise((resolve) => {
    const inp = el("input", { type: "file", accept, style: { display: "none" } });
    const done = (v) => { inp.remove(); resolve(v); };
    inp.addEventListener("cancel", () => done(null));
    inp.addEventListener("change", async () => {
      const f = inp.files?.[0];
      if (!f) return done(null);
      done({ name: f.name, text: await f.text().catch(() => "") });
    });
    document.body.append(inp);
    inp.click();
  });
}

// V5 (design 7.5): an encrypted FILE does not keep a pipeline out of images - ComfyUI writes the workflow and the
// prompt into every PNG it saves (core SaveImage, unless ComfyUI runs with --disable-metadata)
const METADATA_NOTE = "This protects the file. Images you render from it contain the workflow in readable form " +
  "(ComfyUI writes it into every PNG). To keep a pipeline out of images, protect its nodes as a vault, or start " +
  "ComfyUI with --disable-metadata.";

// V5 (design 7.3): the encrypted file this tab opened last, to save it again with the same key. Fingerprint + scheme
// only: the key itself stays in the server's secrets store (only a remembered key can be reused).
let LAST_OPENED = null;

// ── save ────────────────────────────────────────────────────────────────────────────────────────────────────────
async function saveEncrypted() {
  let workflow;
  try { workflow = (await app.graphToPrompt())?.workflow; } catch (e) {
    toast(`Could not read the workflow: ${e?.message || e}`, "error");
    return;
  }
  if (!workflow || !(workflow.nodes || []).length) { toast("The workflow is empty: nothing to encrypt.", "warn"); return; }
  const d = vaultDialog({ title: "Save workflow encrypted",
    subtitle: "Everything in this workflow becomes one encrypted file. Only someone with its key or password can open it.",
    width: 560 });
  const name = textField({ label: "File name", value: safeName(activeWorkflowName()), maxLength: 80 });
  let scheme = "fernet";
  const pw = passwordField({ label: "Password", strength: true, generate: true });
  const pw2 = passwordField({ label: "Repeat the password" });
  const pwBox = el("div", { class: "h2v-grid2" }, [pw.el, pw2.el]);
  const remember = switchRow("Remember the key on this installation", { checked: rememberDefault() });
  const keyHelp = el("p", { class: "h2v-dim", text: "A random key is made for this file and shown once. Files saved " +
    "this way also open in ComfyUI-Workflow-Encrypt." });
  const keyBox = el("div", { class: "h2v-block" }, [keyHelp, remember.el]);
  const choice = choiceCards({ label: "Protect it with", value: "fernet", options: [
    { id: "fernet", title: "A key", tag: "Compatible", tone: "ok", summary: "A random key, shown once. Send the key and " +
      "the file separately." },
    { id: "argon2id-aesgcm", title: "A password", summary: "A password you choose (Argon2id + AES-256-GCM). Nothing " +
      "is stored on this installation." }],
  onChange: (v) => { scheme = v; render(); } });
  function render() {
    keyBox.style.display = scheme === "fernet" ? "" : "none";
    pwBox.style.display = scheme === "fernet" ? "none" : "";
  }
  d.body.append(name.el, choice.el, keyBox, pwBox, noticeEl("info", METADATA_NOTE));
  render();
  d.status("The decrypted workflow is plain again once opened: protect the parts you want hidden with a vault.");
  d.addAction("Cancel", { onClick: () => d.close(null) });
  const go = async () => {
    if (d.busy) return;
    d.notice(null);
    if (scheme !== "fernet") {
      if (pw.value().length < 8) { d.notice("danger", "Use at least 8 characters for the password."); pw.input.focus(); return; }
      if (pw.value() !== pw2.value()) { d.notice("danger", "The two passwords differ."); pw2.input.focus(); return; }
    }
    d.setBusy(true, "Encrypting…");
    const r = await post("/h2vault/workflow/encrypt", { workflow, scheme, password: scheme === "fernet" ? undefined : pw.value(),
      remember: scheme === "fernet" && remember.checked(), label: name.input.value.trim() });
    if (!r.ok) { d.setBusy(false); d.notice("danger", r.data.error || `Encrypting failed (${r.status}).`); return; }
    d.close({ ...r.data, fileName: safeName(name.input.value) });
  };
  d.addAction("Encrypt and save", { primary: true, onClick: go });
  d.onSubmit(go);
  const out = await d.result;
  if (!out) return;
  download(`${out.fileName}.h2vault.json`, JSON.stringify(out.file, null, 1));
  if (out.key) await showKeyOnce(out);
  else toast(`Saved "${out.fileName}.h2vault.json". It opens with the password you chose.`, "success", "Encrypted");
}

/** V5: save the workflow again with the key (or password) of the encrypted file this tab opened. */
async function saveSameKey() {
  if (!LAST_OPENED) {
    toast("Open an encrypted workflow first; then this saves it again with the same key.", "warn");
    return;
  }
  let workflow;
  try { workflow = (await app.graphToPrompt())?.workflow; } catch (e) {
    toast(`Could not read the workflow: ${e?.message || e}`, "error");
    return;
  }
  const fileName = safeName(LAST_OPENED.name || activeWorkflowName());
  if (LAST_OPENED.scheme !== "fernet") {
    const d = vaultDialog({ title: "Save again with the same password", width: 480,
      subtitle: `"${fileName}" was protected with a password. Type it again (it is never kept).` });
    const pw = passwordField({ label: "Password", autocomplete: "current-password" });
    const pw2 = passwordField({ label: "Repeat the password", autocomplete: "current-password" });
    d.body.append(pw.el, pw2.el, noticeEl("info", METADATA_NOTE));
    d.addAction("Cancel", { onClick: () => d.close(null) });
    const go = async () => {
      if (d.busy) return;
      if (pw.value().length < 8) { d.notice("danger", "Use at least 8 characters for the password."); return; }
      if (pw.value() !== pw2.value()) { d.notice("danger", "The two passwords differ."); return; }
      d.setBusy(true, "Checking the password…");
      // review P2-10: the server first opens the file this tab opened with this password (a typo is refused)
      const r = await post("/h2vault/workflow/encrypt", { workflow, scheme: "argon2id-aesgcm", password: pw.value(),
        same_as_file: LAST_OPENED.file });
      if (!r.ok) { d.setBusy(false); d.notice("danger", r.data.error || `Encrypting failed (${r.status}).`); return; }
      d.close(r.data);
    };
    d.addAction("Encrypt and save", { primary: true, onClick: go });
    d.onSubmit(go);
    const out = await d.result;
    if (!out) return;
    download(`${fileName}.h2vault.json`, JSON.stringify(out.file, null, 1));
    toast(`Saved "${fileName}.h2vault.json" with the same password.`, "success", "Encrypted");
    return;
  }
  const r = await post("/h2vault/workflow/encrypt", { workflow, scheme: "fernet", same_key_of: LAST_OPENED.fingerprint,
    label: fileName });
  if (!r.ok) { toast(r.data.error || `Encrypting failed (${r.status}).`, "error"); return; }
  download(`${fileName}.h2vault.json`, JSON.stringify(r.data.file, null, 1));
  LAST_OPENED = { ...LAST_OPENED, fingerprint: r.data.fingerprint };
  toast(`Saved "${fileName}.h2vault.json" with the same key. It opens with the key you already shared.`, "success",
    "Encrypted");
}

/** The key, shown exactly once (spec: Workflow-Encrypt's "the key will ONLY be shown ONCE"). */
async function showKeyOnce(out) {
  const d = vaultDialog({ title: "Your workflow key", tone: "ok",
    subtitle: `"${out.fileName}.h2vault.json" is saved. Copy the key now: it is not shown again.`, width: 560 });
  d.body.append(copyRow({ label: "workflow key", value: out.key }));
  d.body.append(noticeEl(out.remembered ? "ok" : "warn", out.remembered
    ? "This installation remembers the key, so the file opens here without asking. Anyone else needs the key."
    : "This installation does not keep the key. Without it nobody can open the file."));
  d.body.append(el("div", { class: "h2v-row", style: { flexWrap: "wrap" } }, [
    vbutton("Save key as a file", { small: true, onClick: () => download(`${out.fileName}.h2vault-key.txt`,
      `${out.key}\n`, "text/plain") }),
    vbutton("Export for Workflow-Encrypt (.txt)", { small: true, onClick: () => download(`${out.fileName}.encrypted.txt`,
      out.file.token, "text/plain") })]));
  d.body.append(el("p", { class: "h2v-dim", text: "Send the key and the file through different channels." }));
  d.addAction("Done", { primary: true, onClick: () => d.close(true) });
  d.onSubmit(() => d.close(true));
  await d.result;
}

// ── open ────────────────────────────────────────────────────────────────────────────────────────────────────────
/** -> the decrypted workflow, or null (cancelled). Tries a remembered key first, then asks. */
async function decryptFile(file, fileName) {
  const first = await post("/h2vault/workflow/decrypt", { file });
  if (first.ok) {
    if (first.data.used_remembered) toast("Opened with the key this installation remembers.", "success", "Decrypted");
    LAST_OPENED = { fingerprint: first.data.fingerprint, scheme: first.data.scheme, name: fileName, file };
    return first.data.workflow;
  }
  if (first.status !== 401) { toast(first.data.error || `Could not open the file (${first.status}).`, "error"); return null; }
  const needs = first.data.needs === "password" ? "password" : "key";
  const d = vaultDialog({ title: `Open "${fileName || "encrypted workflow"}"`, width: 520,
    subtitle: needs === "password" ? "This workflow is protected with a password."
      : "This workflow is encrypted with a key. It was shown once to whoever saved it." });
  let workflow = null;
  const secret = needs === "password"
    ? passwordField({ label: "Password", autocomplete: "current-password" })
    : textField({ label: "Workflow key", placeholder: "44 characters ending in =", autocomplete: "off" });
  d.body.append(secret.el);
  let remember = null;
  if (needs === "key") {
    secret.input.classList.add("h2v-secret");
    d.body.append(el("div", { class: "h2v-row", style: { justifyContent: "space-between", flexWrap: "wrap" } }, [
      (remember = switchRow("Remember the key on this installation", { checked: rememberDefault() })).el,
      vbutton("Load key file…", { small: true, onClick: async () => {
        const f = await pickFile(".txt,.key");
        const m = f && FERNET_KEY_RE.exec(f.text);
        if (f && !m) { d.notice("danger", `${f.name} does not contain a workflow key.`); return; }
        if (m) { secret.input.value = m[0]; d.notice(null); }
      } })]));
  }
  d.addAction("Cancel", { onClick: () => d.close(null) });
  const go = async () => {
    if (d.busy) return;
    d.notice(null);
    const value = secret.input.value.trim();
    if (!value) { d.notice("danger", needs === "password" ? "Type the password." : "Paste the key."); return; }
    d.setBusy(true, "Decrypting…");
    const r = await post("/h2vault/workflow/decrypt", needs === "password" ? { file, password: value }
      : { file, key: value, remember: !!remember?.checked(), label: fileName || "" });
    if (r.ok) {
      workflow = r.data.workflow;
      LAST_OPENED = { fingerprint: r.data.fingerprint, scheme: r.data.scheme, name: fileName, file };
      d.close(true);
      return;
    }
    d.setBusy(false);
    d.notice("danger", r.data.error || `Could not open the file (${r.status}).`);
    secret.input.select?.();
  };
  d.addAction("Open", { primary: true, onClick: go });
  d.onSubmit(go);
  return (await d.result) ? workflow : null;
}

let ORIG_LOAD = null;
function installLoadHook() {
  if (app.__h2vLoadHook || typeof app.loadGraphData !== "function") return;
  ORIG_LOAD = app.loadGraphData.bind(app);
  app.__h2vLoadHook = true;
  // loadGraphData(graphData, clean, restore_view, workflow, options) on frontend 1.53.10. `workflow` is a file name
  // (drag-and-drop / Open) or a saved workflow object (opened from the Workflows sidebar). The decrypted graph never
  // loads into that saved .h2vault.json workflow - a save there would overwrite the encrypted file with plaintext: it
  // opens as a new, unsaved workflow instead. A cancelled dialog answers false, which openWorkflow treats as "aborted"
  // and so restores the previous tab.
  app.loadGraphData = async function (graphData, ...rest) {
    if (graphData && typeof graphData === "object" && graphData[MARKER] === 1) {
      const target = rest[2];
      const fromFile = typeof target === "string" ? target
        : String(target?.filename || target?.path?.split(/[\\/]/).pop() || "encrypted workflow");
      const name = fromFile.replace(/\.(h2vault\.json|json)$/i, "").replace(/\.h2vault$/i, "");
      const workflow = await decryptFile(graphData, name);
      if (!workflow) return false;
      const args = [...rest];
      args[2] = `${name} (decrypted)`;
      return ORIG_LOAD(workflow, ...args);
    }
    return ORIG_LOAD(graphData, ...rest);
  };
}

async function openEncrypted() {
  const f = await pickFile(".json,.txt");
  if (!f) return;
  const text = f.text.trim();
  const name = f.name.replace(/\.(h2vault\.json|encrypted\.txt|json|txt)$/i, "");
  let file = text;
  if (text.startsWith("{")) {
    try { file = JSON.parse(text); } catch (_) { toast(`${f.name} is not an encrypted workflow.`, "error"); return; }
    if (file?.[MARKER] !== 1) { toast(`${f.name} is not an encrypted workflow.`, "error"); return; }
  }
  const workflow = await decryptFile(file, name);
  if (workflow) await (ORIG_LOAD ?? app.loadGraphData.bind(app))(workflow, true, true, name);
}

// ── remembered keys ─────────────────────────────────────────────────────────────────────────────────────────────
async function manageKeys() {
  const r = await api.fetchApi("/h2vault/keys/list");
  const data = await r.json().catch(() => ({}));
  const d = vaultDialog({ title: "Remembered workflow keys", width: 560,
    subtitle: "Keys this installation keeps so its encrypted workflows open without asking. The keys are never shown." });
  if (!r.ok) {
    d.body.append(noticeEl("danger", data.error || `The key list is not available (${r.status}).`));
  } else {
    const list = el("div", { class: "h2v-list" });
    const draw = (keys) => {
      list.replaceChildren(...(keys.length ? keys.map((k) => el("div", { class: "h2v-keyrow" }, [
        el("span", { text: k.label || "Unnamed workflow" }),
        el("span", { class: "h2v-keycode", text: `${k.fingerprint.slice(0, 12)}…  ${k.created
          ? new Date(k.created * 1000).toLocaleDateString() : ""}`, title: k.fingerprint }),
        vbutton("Forget", { small: true, ariaLabel: `Forget the key of ${k.label || k.fingerprint.slice(0, 12)}`,
          onClick: async () => {
            const f = await post("/h2vault/keys/forget", { fingerprint: k.fingerprint });
            if (!f.ok) { d.notice("danger", f.data.error || "Could not forget the key."); return; }
            draw(keys.filter((x) => x !== k));
          } })]))
        : [el("p", { class: "h2v-dim", text: "No keys are remembered on this installation." })]));
    };
    draw(data.keys || []);
    d.body.append(block("Keys", "Forgetting a key does not change any file: the file then needs its key again.", list));
  }
  d.addAction("Done", { primary: true, onClick: () => d.close(true) });
  await d.result;
}

app.registerExtension({
  name: "H2Vault.WorkflowEncrypt",
  commands: [
    { id: "h2vault.workflow.saveEncrypted", label: "H2Vault: Save workflow encrypted…", icon: "pi pi-lock",
      function: () => saveEncrypted() },
    { id: "h2vault.workflow.openEncrypted", label: "H2Vault: Open encrypted workflow…", icon: "pi pi-lock-open",
      function: () => openEncrypted() },
    { id: "h2vault.workflow.manageKeys", label: "H2Vault: Remembered workflow keys…", icon: "pi pi-key",
      function: () => manageKeys() },
    { id: "h2vault.workflow.saveSameKey", label: "H2Vault: Save workflow encrypted again (same key)", icon: "pi pi-save",
      function: () => saveSameKey() },
  ],
  menuCommands: [{ path: ["H2Vault"], commands: ["h2vault.workflow.saveEncrypted", "h2vault.workflow.saveSameKey",
    "h2vault.workflow.openEncrypted", "h2vault.workflow.manageKeys"] }],
  settings: [{ id: REMEMBER_SETTING, category: ["H2Vault", "Encrypted workflows", "Remember keys"],
    name: "Remember workflow keys on this installation by default", type: "boolean", defaultValue: true,
    tooltip: "Keys go to the OS credential store (or H2Vault's encrypted file in the user folder), never into a workflow." }],
  setup() { installLoadHook(); },
});

globalThis.__h2vaultWorkflow = { saveEncrypted, saveSameKey, openEncrypted, decryptFile, manageKeys };
