// H2Vault (AGPL-3.0) - second-factor methods, the DOM part: the method picker shown wherever a second factor is asked,
// the "Second factor" settings dialog (H2Vault menu) and the per-vault method choice (lock dialog, Manage access).
// No ComfyUI import (the caller passes `post` and `getStatus`); never innerHTML; no secret is logged.
import { block, copyRow, codeField, disclosure, el, noticeEl, passwordField, vaultDialog, vbutton } from "./_h2v_ui.js";
import { METHOD_LABELS, METHOD_ORDER, NOT_OFFLINE_TEXT, TOTP_DRIFT_TEXT, createOptions, credentialJSON, defaultMethod,
  factorErrorText, getOptions, hardenSecret, initialTicks, isRecoveryShape, lostAllText, offeredMethods,
  passkeyErrorText, passkeySupport, policyFromTicks, recallMethod, rememberMethod } from "./_h2v_factor.js";

const STYLE_ID = "h2v-factor-style";
const CSS = `
.h2v-seg { display: flex; flex-wrap: wrap; gap: 4px; padding: 3px; border: 1px solid var(--h2v-edge);
  border-radius: var(--h2v-r-ctl); background: var(--h2v-sunken); }
.h2v-seg__opt { flex: 1 1 auto; min-width: 0; padding: 6px 10px; border: 0; border-radius: 4px; background: transparent;
  color: var(--h2v-ink-soft); font: inherit; font-size: 12.5px; cursor: pointer; white-space: nowrap; }
.h2v-seg__opt[aria-checked="true"] { background: var(--h2v-raised); color: var(--h2v-ink); font-weight: 600;
  box-shadow: inset 0 0 0 1px var(--h2v-edge-strong); }
.h2v-seg__opt:focus-visible { outline: 2px solid var(--h2v-accent); outline-offset: 1px; }
.h2v-factor { display: flex; flex-direction: column; gap: 10px; }
.h2v-factor__panel { display: flex; flex-direction: column; gap: 8px; }
.h2v-mrow { display: grid; grid-template-columns: 1fr auto; gap: 4px 12px; align-items: center; padding: 10px 12px;
  border: 1px solid var(--h2v-edge); border-radius: var(--h2v-r-card); background: var(--h2v-sunken); }
.h2v-mrow__title { font-weight: 600; }
.h2v-mrow__state { grid-column: 1; font-size: 12px; color: var(--h2v-ink-dim); }
.h2v-mrow__acts { grid-column: 2; grid-row: 1 / span 2; display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
.h2v-mrow__more { grid-column: 1 / -1; display: flex; flex-direction: column; gap: 8px; }
.h2v-mrow__more:empty { display: none; }
.h2v-pk { display: flex; gap: 8px; align-items: center; font-size: 12.5px; }
.h2v-pk__name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.h2v-ticks { display: flex; flex-direction: column; gap: 6px; }
.h2v-ticks .h2v-check small { color: var(--h2v-ink-dim); font-size: 11.5px; }
`;

function ensureStyles() {
  if (document.getElementById(STYLE_ID)) return;
  document.head.append(el("style", { id: STYLE_ID, text: CSS }));
}

function passkeyEnv() {
  const loc = globalThis.location || {};
  return { PublicKeyCredential: globalThis.PublicKeyCredential, isSecureContext: !!globalThis.isSecureContext,
    hostname: loc.hostname, port: loc.port };
}

const storage = () => { try { return globalThis.localStorage; } catch (_) { return null; } };

/** An APG radio group as a segmented control. */
function segmented({ label, options, value, onChange }) {
  let cur = value;
  const group = el("div", { class: "h2v-seg", role: "radiogroup", "aria-label": label });
  const btns = options.map((o) => {
    const b = el("button", { type: "button", class: "h2v-seg__opt", role: "radio", text: o.label, "data-id": o.id });
    b.addEventListener("click", () => set(o.id, true));
    return b;
  });
  group.append(...btns);
  const sync = () => btns.forEach((b, i) => {
    const on = options[i].id === cur;
    b.setAttribute("aria-checked", on ? "true" : "false");
    b.tabIndex = on ? 0 : -1;
  });
  function set(id, fire) {
    if (id === cur) return;
    cur = id;
    sync();
    if (fire) onChange?.(id);
  }
  group.addEventListener("keydown", (e) => {
    const i = options.findIndex((o) => o.id === cur);
    let j = null;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") j = (i + 1) % options.length;
    else if (e.key === "ArrowLeft" || e.key === "ArrowUp") j = (i - 1 + options.length) % options.length;
    if (j == null) return;
    e.preventDefault();
    set(options[j].id, true);
    btns[j].focus();
  });
  sync();
  return { el: group, value: () => cur };
}

/**
 * The second factor wherever one is asked. status = /h2vault/2fa/status; allowed = the vault's methods when known.
 * collect() -> {factor} | {error}. restrict(allowed) after the server named the vault's methods.
 */
export function factorPicker({ status, allowed = null, post, label = "Second factor" }) {
  ensureStyles();
  const root = el("div", { class: "h2v-factor" });
  let allowedNow = allowed, cur = null, inputs = {}, timers = [];
  const destroyTimers = () => { for (const t of timers.splice(0)) t(); };

  function panelFor(id) {
    if (id === "totp") {
      const c = codeField({ label: "Code from your authenticator app", hint: TOTP_DRIFT_TEXT });
      timers.push(c.destroy);
      inputs.totp = c;
      return c.el;
    }
    if (id === "recovery") {
      const input = hardenSecret(el("input", { type: "text", class: "h2v-input h2v-code", maxLength: 14,
        placeholder: "ABCD-EFGH-JK", "aria-label": "Recovery code" }));
      input.style.letterSpacing = "0.12em";
      inputs.recovery = { input, value: () => input.value.trim(), clear: () => { input.value = ""; } };
      const left = status?.recovery_codes_left ?? 0;
      return el("div", { class: "h2v-factor__panel" }, [input, el("p", { class: "h2v-dim",
        text: `One of the recovery codes you saved when you set up the second factor. Each works once - ${left} ` +
          `left on this installation.` })]);
    }
    if (id === "backup_password") {
      const p = passwordField({ label: "Backup password" });
      inputs.backup_password = p;
      return p.el;
    }
    inputs.passkey = {};
    return el("p", { class: "h2v-dim", text: "When you continue, your browser asks for your passkey, security key or " +
      "Windows Hello." });
  }

  const panelHost = el("div", { class: "h2v-factor__panel" });
  function show(id) {
    destroyTimers();
    inputs = {};
    cur = id;
    panelHost.replaceChildren(panelFor(id));
  }

  function render() {
    const { offer, unavailable } = offeredMethods(status, allowedNow, passkeyEnv());
    const kids = [];
    if (!offer.length) {
      cur = null;
      destroyTimers();
      const names = (allowedNow || []).map((m) => METHOD_LABELS[m]).join(", ");
      kids.push(noticeEl("warn", allowedNow
        ? `This vault accepts: ${names}. None of them is set up on this installation (or usable on this page). Set ` +
          "one up under H2Vault menu › Second factor."
        : "No second factor is set up on this installation. Set one up under H2Vault menu › Second factor."));
    } else {
      const first = defaultMethod(offer, cur || recallMethod(storage()));
      if (offer.length > 1) {
        kids.push(el("div", { class: "h2v-label", text: label }),
          segmented({ label, options: offer, value: first, onChange: (id) => { show(id); focus(); } }).el);
      } else {
        kids.push(el("div", { class: "h2v-label", text: `${label}: ${offer[0].label}` }));
      }
      show(first);
      kids.push(panelHost);
    }
    for (const u of unavailable) kids.push(el("p", { class: "h2v-dim", text: `${u.label}: ${u.reason}` }));
    const lost = disclosure("Lost your phone or key?");
    lost.body.append(el("p", { class: "h2v-dim", text: lostAllText(status) }));
    kids.push(lost.el);
    root.replaceChildren(...kids);
  }

  function focus() {
    const i = inputs[cur]?.input;
    if (i) setTimeout(() => i.focus(), 0);
  }

  async function collect() {
    if (!cur) return { error: "Choose a second factor this vault accepts (see the note above)." };
    if (cur === "totp") {
      const v = inputs.totp.value();
      if (!/^\d{6}$/.test(v)) return { error: "Type the 6-digit code your authenticator app shows now.", focus: true };
      return { factor: { method: "totp", code: v } };
    }
    if (cur === "recovery") {
      const v = inputs.recovery.value();
      if (!isRecoveryShape(v)) return { error: "A recovery code looks like ABCD-EFGH-JK (10 letters and digits).", focus: true };
      return { factor: { method: "recovery", code: v } };
    }
    if (cur === "backup_password") {
      const v = inputs.backup_password.value();
      if (!v) return { error: "Type your backup password.", focus: true };
      return { factor: { method: "backup_password", secret: v } };
    }
    const sup = passkeySupport(passkeyEnv());
    if (!sup.ok) return { error: sup.reason };
    const ch = await post("/h2vault/2fa/passkey/challenge", {});
    if (!ch.ok) return { error: ch.data?.error || "Could not start the passkey check." };
    let cred;
    try { cred = await navigator.credentials.get({ publicKey: getOptions(ch.data.publicKey) }); }
    catch (e) { return { error: passkeyErrorText(e) }; }
    if (!cred) return { error: "No passkey answer came back. Try again." };
    return { factor: { method: "passkey", challenge_id: ch.data.challenge_id, credential: credentialJSON(cred) } };
  }

  render();
  return {
    el: root, collect, focus,
    method: () => cur,
    restrict(list) { allowedNow = list?.length ? list : null; render(); focus(); },
    succeeded() { rememberMethod(storage(), cur); },
    failed() { inputs[cur]?.clear?.(); focus(); },
    destroy: destroyTimers,
  };
}

/** The per-vault choice: which methods may open this vault for editing. Recovery codes are always allowed. */
export function policyEditor({ status, current = null, title = "Second factor for editing" }) {
  ensureStyles();
  const ticks = initialTicks(status, current);
  const have = status?.methods || {};
  const warn = el("div");
  const boxes = {};
  const rows = METHOD_ORDER.map((m) => {
    const box = el("input", { type: "checkbox" });
    box.checked = !!ticks[m];
    if (m === "recovery") { box.checked = true; box.disabled = true; }
    box.addEventListener("change", paint);
    boxes[m] = box;
    const state = m === "recovery" ? "always allowed, as the fallback"
      : have[m] ? "set up on this installation" : "not set up on this installation yet";
    return el("label", { class: "h2v-check" }, [box, el("span", {}, [m === "recovery" ? "Recovery codes"
      : METHOD_LABELS[m], " ", el("small", { text: `(${state})` })])]);
  });
  function value() {
    return policyFromTicks(Object.fromEntries(METHOD_ORDER.map((m) => [m, boxes[m].checked])));
  }
  function paint() {
    const v = value();
    warn.replaceChildren();
    if (!v.ok) { warn.append(noticeEl("danger", v.error)); return; }
    if (!v.methods.some((m) => m !== "recovery" && have[m]) && !(have.recovery > 0)) {
      warn.append(noticeEl("warn", "None of the ticked methods is set up on this installation yet. Set one up " +
        "(H2Vault menu › Second factor) before you open this vault for editing - running it is not affected."));
    }
  }
  paint();
  const elRoot = block(title, "Opening this vault for editing needs its password plus one of these. Each editor " +
    "uses the methods set up on their own installation.", el("div", { class: "h2v-ticks" }, rows), warn);
  return { el: elRoot, value };
}

function codesPanel(codes, { onSaved } = {}) {
  const saved = el("input", { type: "checkbox" });
  saved.addEventListener("change", () => onSaved?.(saved.checked));
  const download = () => {
    const url = URL.createObjectURL(new Blob([`H2Vault recovery codes (each works once)\n\n${codes.join("\n")}\n`],
      { type: "text/plain" }));
    const a = el("a", { href: url, download: "h2vault-recovery-codes.txt" });
    document.body.append(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
  };
  const copyAll = vbutton("Copy all", { small: true, onClick: async () => {
    try { await navigator.clipboard.writeText(codes.join("\n")); copyAll.querySelector(".h2v-btn__label").textContent = "Copied"; }
    catch (_) { /* the grid is selectable */ }
  } });
  return { saved, el: el("div", { class: "h2v-block" }, [
    el("p", { class: "h2v-dim", text: "Shown once. Each code works once instead of your other methods. Keep them " +
      "somewhere safe, away from this computer." }),
    el("div", { class: "h2v-codes" }, codes.map((c) => el("span", { text: c }))),
    el("div", { class: "h2v-row", style: { justifyContent: "space-between", flexWrap: "wrap" } }, [
      el("label", { class: "h2v-check" }, [saved, el("span", { text: "I saved the recovery codes" })]),
      el("div", { class: "h2v-row" }, [copyAll, vbutton("Download .txt", { small: true, onClick: download })])])]) };
}

/**
 * H2Vault menu › Second factor: see, add, replace and remove the methods of this installation. Changing them needs one
 * proof (any method) first; nothing is needed while none is set up. enrolTotp(manageToken) runs the authenticator
 * setup dialog. Resolves with true when at least one method is set up at the end.
 */
export async function secondFactorDialog({ post, getStatus, enrolTotp, firstRun = false }) {
  ensureStyles();
  let status = await getStatus();
  let token = null, proof = null;
  const d = vaultDialog({ title: "Second factor on this installation", width: 620,
    subtitle: firstRun ? "Opening a vault for editing needs its password plus a second factor. Set up at least one."
      : "Opening a vault for editing needs its password plus one of these. Each vault's author chooses which it accepts." });
  const host = el("div", { class: "h2v-block" });
  d.body.append(host);
  d.addAction("Done", { primary: true, onClick: () => d.close(true) });
  d.onCleanup(() => proof?.destroy());

  const refresh = async () => { status = await getStatus(); draw(); };
  const call = async (route, body = {}) => {
    const r = await post(route, { ...body, manage_token: token });
    if (!r.ok && r.status === 403 && /Confirm it is you/.test(r.data?.error || "")) { token = null; draw(); }
    return r;
  };

  function draw() {
    d.notice(null);
    proof?.destroy();
    proof = null;
    if (status.enrolled && !token) return drawProof();
    return drawMethods();
  }

  function drawProof() {
    proof = factorPicker({ status, post, label: "Confirm with" });
    const go = async () => {
      if (d.busy) return;
      d.notice(null);
      const got = await proof.collect();
      if (got.error) { d.notice("danger", got.error); if (got.focus) proof.focus(); return; }
      d.setBusy(true, "Checking…");
      const r = await post("/h2vault/2fa/manage/begin", { factor: got.factor });
      d.setBusy(false);
      if (!r.ok) { d.notice("danger", r.status === 429 ? r.data?.error : factorErrorText(r.data)); proof.failed(); return; }
      proof.succeeded();
      token = r.data.manage_token;
      await refresh();
    };
    d.onSubmit(go);
    host.replaceChildren(noticeEl("info", "Confirm it is you with one of your methods to change them (valid for 10 " +
      "minutes)."), proof.el, el("div", { class: "h2v-row" }, [vbutton("Confirm", { kind: "primary", onClick: go })]));
    proof.focus();
  }

  function row(title, state, acts, more = []) {
    return el("div", { class: "h2v-mrow" }, [el("div", { class: "h2v-mrow__title", text: title }),
      el("div", { class: "h2v-mrow__acts" }, acts.filter(Boolean)), el("div", { class: "h2v-mrow__state", text: state }),
      el("div", { class: "h2v-mrow__more" }, more.filter(Boolean))]);
  }

  /** A remove button that asks once more inline (no browser confirm()). */
  function removeBtn(label, fn) {
    let armed = false, t = null;
    const b = vbutton(label, { small: true, kind: "danger" });
    b.addEventListener("click", async () => {
      if (!armed) {
        armed = true;
        b.querySelector(".h2v-btn__label").textContent = "Click again to remove";
        t = setTimeout(() => { armed = false; b.querySelector(".h2v-btn__label").textContent = label; }, 4000);
        return;
      }
      clearTimeout(t);
      await fn();
    });
    return b;
  }

  function drawMethods() {
    d.onSubmit(() => {});
    const m = status.methods || {};
    const env = passkeyEnv(), pkSup = passkeySupport(env);
    const out = [];

    // authenticator app
    out.push(row(METHOD_LABELS.totp, m.totp ? "Set up. A code works once; codes 30 s early or late are accepted."
      : "Not set up. Google / Microsoft Authenticator, 1Password, Aegis and others work.", [
      vbutton(m.totp ? "Replace" : "Set up", { small: true, onClick: async () => {
        if (m.totp) {
          const r = await call("/h2vault/2fa/reset", {});
          if (!r.ok) { d.notice("danger", r.data?.error || "Could not remove the old authenticator."); return; }
        }
        await enrolTotp(token);
        await refresh();
      } }),
      m.totp ? removeBtn("Remove", async () => {
        const r = await call("/h2vault/2fa/totp/remove");
        if (!r.ok) d.notice("danger", r.data?.error || "Could not remove it.");
        await refresh();
      }) : null]));

    // passkeys
    const pkList = (status.passkeys || []).map((p) => el("div", { class: "h2v-pk" }, [
      el("span", { class: "h2v-pk__name", text: `${p.label} · ${p.rp_id}`, title: `Added ${new Date(p.created * 1000).toLocaleDateString()}` }),
      removeBtn("Remove", async () => {
        const r = await call("/h2vault/2fa/passkey/remove", { id: p.id });
        if (!r.ok) d.notice("danger", r.data?.error || "Could not remove it.");
        await refresh();
      })]));
    const pkName = el("input", { type: "text", class: "h2v-input", maxLength: 60, placeholder: "Name, e.g. YubiKey or Windows Hello",
      "aria-label": "Name for the new passkey" });
    hardenSecret(pkName);
    out.push(row(METHOD_LABELS.passkey, pkSup.ok
      ? `${m.passkey ? `${m.passkey} registered.` : "None registered."} A passkey belongs to the address it was made on (${env.hostname}).`
      : `${m.passkey ? `${m.passkey} registered. ` : ""}Not available on this page: ${pkSup.reason}`, [
      pkSup.ok ? vbutton("Add", { small: true, onClick: async () => {
        d.notice(null);
        const b = await call("/h2vault/2fa/passkey/register/begin", { label: pkName.value.trim() });
        if (!b.ok) { d.notice("danger", b.data?.error || "Could not start the passkey setup."); return; }
        let cred;
        try { cred = await navigator.credentials.create({ publicKey: createOptions(b.data.publicKey) }); }
        catch (e) { d.notice("danger", passkeyErrorText(e)); return; }
        const f = await call("/h2vault/2fa/passkey/register/finish", { challenge_id: b.data.challenge_id,
          credential: credentialJSON(cred) });
        if (!f.ok) { d.notice("danger", f.data?.error || "The passkey could not be registered."); return; }
        await refresh();
        d.notice("ok", `Passkey "${f.data.passkey.label}" added.`);
      } }) : null], [pkSup.ok ? pkName : null, ...pkList]));

    // backup password
    const bpHost = el("div");
    out.push(row(METHOD_LABELS.backup_password, m.backup_password ? "Set. Stored as a hash; nobody can read it back."
      : "Not set. A second secret, different from every vault password.", [
      vbutton(m.backup_password ? "Change" : "Set", { small: true, onClick: () => {
        const a = passwordField({ label: "Backup password", strength: true });
        const b = passwordField({ label: "Repeat it" });
        const save = async () => {
          d.notice(null);
          if (a.value().length < 10) { d.notice("danger", "Use at least 10 characters for the backup password."); return; }
          if (a.value() !== b.value()) { d.notice("danger", "The two backup passwords differ."); return; }
          const r = await call("/h2vault/2fa/backup_password/set", { secret: a.value() });
          if (!r.ok) { d.notice("danger", r.data?.error || "Could not save it."); return; }
          await refresh();
          d.notice("ok", "Backup password saved.");
        };
        d.onSubmit(save);
        bpHost.replaceChildren(el("div", { class: "h2v-grid2" }, [a.el, b.el]),
          el("p", { class: "h2v-dim", text: "Use a different password from your vault passwords: it is the second " +
            "factor, so it must not be something a person who knows a vault password also knows." }),
          el("div", { class: "h2v-row" }, [vbutton("Save backup password", { kind: "primary", small: true, onClick: save })]));
        a.input.focus();
      } }),
      m.backup_password ? removeBtn("Remove", async () => {
        await call("/h2vault/2fa/backup_password/remove");
        await refresh();
      }) : null], [bpHost]));

    // recovery codes
    const rcHost = el("div");
    out.push(row("Recovery codes", m.recovery ? `${m.recovery} left. Each works once; always accepted as a fallback.`
      : "None. Generate a set so a lost phone or key does not lock you out of editing.", [
      vbutton(m.recovery ? "Generate a new set" : "Generate", { small: true, onClick: async () => {
        const r = await call("/h2vault/2fa/recovery/new");
        if (!r.ok) { d.notice("danger", r.data?.error || "Could not generate codes."); return; }
        status = await getStatus();
        const p = codesPanel(r.data.recovery_codes || []);
        rcHost.replaceChildren(p.el);
        if (m.recovery) d.notice("info", "The previous recovery codes no longer work.");
      } })], [rcHost]));

    if (!m.totp && !m.passkey && !m.backup_password) {
      out.unshift(noticeEl(m.recovery ? "warn" : "info", m.recovery
        ? "Only recovery codes are left: set up an authenticator app, a passkey or a backup password."
        : "Set up at least one method to open vaults for editing."));
    }
    const lost = disclosure("Lost every method?");
    lost.body.append(el("p", { class: "h2v-dim", text: lostAllText(status) }));
    out.push(el("p", { class: "h2v-dim", text: NOT_OFFLINE_TEXT }), lost.el);
    host.replaceChildren(...out);
  }

  draw();
  const ok = await d.result;
  status = await getStatus().catch(() => status);
  return !!(ok && status.enrolled) || !!status.enrolled;
}

export { copyRow };
