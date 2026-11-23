// H2Vault (AGPL-3.0) - second-factor methods, the DOM part: the method picker shown wherever a second factor is asked,
// the "Second factor" settings dialog (H2Vault menu) and the per-vault method choice (lock dialog, Manage access).
// No ComfyUI import (the caller passes `post` and `getStatus`); never innerHTML; no secret is logged.
import { block, choiceCards, copyRow, codeField, disclosure, el, noticeEl, passwordField, switchRow, vaultDialog,
  vbutton } from "./_h2v_ui.js";
import { CUSTOM_CHOICE, FACTOR_ORDER, METHOD_LABELS, POLICY_MODES, PROTECTION_CHOICES, RECOVERY_FALLBACK_TEXT,
  RECOVERY_RULES, TOTP_DRIFT_TEXT, allFactors, builderStateOf, choiceNotes, choiceOfPolicy, createOptions,
  credentialJSON, defaultMethod, factorErrorText, getOptions, hardenSecret, initialChoice, isRecoveryShape,
  localhostUrl, lostAllText, methodCatalog, offeredMethods, passkeyErrorText, passkeySupport, policyFromBuilder,
  policyNotes, policySummary, promptPlan, recallMethod, rememberMethod, secondFactorFromChoice } from "./_h2v_factor.js";

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
.h2v-mrow__title { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; font-weight: 600; }
.h2v-pchoice .h2v-choices { grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); }
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
export function factorPicker({ status, allowed = null, post, label = "Second factor", lostHelp = true }) {
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
          "one up under H2Vault menu › Second factor, or ask the vault's author to choose a method you have (Manage " +
          "access › Opening for editing)."
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
    if (lostHelp) {
      const lost = disclosure("Lost your phone or key?");
      lost.body.append(el("p", { class: "h2v-dim", text: lostAllText(status) }));
      kids.push(lost.el);
    }
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
    /** Nothing typed yet (a passkey is never "empty": it is asked for on submit). */
    isEmpty: () => !cur || (cur !== "passkey" && !String(inputs[cur]?.value?.() ?? "").trim()),
    restrict(list) { allowedNow = list?.length ? list : null; render(); focus(); },
    succeeded() { rememberMethod(storage(), cur); },
    failed() { inputs[cur]?.clear?.(); focus(); },
    destroy: destroyTimers,
  };
}

/**
 * The per-vault protection (owner 2026-11-23 "one question"; L9.343 policy builder). The one-click answers stay; the
 * last card, "Advanced: build a policy", opens the builder: factors (with what is set up here), ANY / ALL, the
 * recovery-code rule, and (per vault) only particular authenticator apps. A preview says the final policy in plain
 * words before sealing. `current` = the vault's method list, `currentPolicy` = its policy (server policy_public), both
 * null for a new vault. `onAddAuthenticator()` -> a fresh status after the author added an app (the Second factor
 * dialog); omitted = no button. value() -> {ok, choice, methods, secondFactor, policy} | {ok: false, error}.
 */
export function protectionChoice({ status, current = null, currentPolicy = null, title = "Opening for editing",
  onAddAuthenticator = null }) {
  ensureStyles();
  let st = status || {};
  const startPolicy = currentPolicy || (Array.isArray(current) ? { methods: current.filter((m) => m !== "recovery"),
    mode: "any", recovery: current.includes("recovery") || !current.length ? "fallback" : "off" } : null);
  const start = currentPolicy ? choiceOfPolicy(currentPolicy) : initialChoice(current);
  const options = [...PROTECTION_CHOICES, CUSTOM_CHOICE].map((c) => ({ id: c.id, title: c.label, tag: c.tag,
    tone: c.tone, summary: c.summary }));
  const state = builderStateOf(start === "custom" ? startPolicy : null, st);

  // the builder (shown for "custom")
  const factorHost = el("div", { class: "h2v-ticks" });
  const modeHost = el("div");
  const ruleHost = el("div", { class: "h2v-ticks", role: "radiogroup", "aria-label": "Recovery codes" });
  const appsHost = el("div", { class: "h2v-ticks" });
  let restrictSw = null;
  function drawFactors() {
    const have = st.methods || {};
    factorHost.replaceChildren(...FACTOR_ORDER.map((m) => {
      const box = el("input", { type: "checkbox" });
      box.checked = !!state.factors[m];
      box.addEventListener("change", () => { state.factors[m] = box.checked; drawApps(); paint(); });
      return el("label", { class: "h2v-check" }, [box, el("span", {}, [METHOD_LABELS[m], " ",
        el("small", { text: `(${have[m] ? "set up on this computer" : "not set up on this computer yet"})` })])]);
    }));
  }
  function drawRules() {
    const rules = RECOVERY_RULES[state.mode];
    if (!rules.some((r) => r.id === state.recovery)) state.recovery = rules[0].id;
    ruleHost.replaceChildren(el("div", { class: "h2v-label", text: "Recovery codes" }), ...rules.map((r) => {
      const radio = el("input", { type: "radio", name: `h2v-rule-${uid}` });
      radio.checked = r.id === state.recovery;
      radio.addEventListener("change", () => { if (radio.checked) { state.recovery = r.id; paint(); } });
      return el("label", { class: "h2v-check", "data-rule": r.id }, [radio, el("span", {}, [r.label, " ",
        el("small", { text: r.hint })])]);
    }));
  }
  function drawApps() {
    const apps = st.authenticators || [];
    const kids = [];
    if (state.factors.totp) {
      restrictSw = switchRow("Only particular authenticator apps (advanced, per vault)", { checked: state.restrict,
        onChange: (on) => { state.restrict = on; drawApps(); paint(); } });
      kids.push(restrictSw.el);
      if (state.restrict) {
        if (!apps.length) kids.push(el("p", { class: "h2v-dim", text: "No authenticator app is set up on this computer yet." }));
        for (const a of apps) {
          const box = el("input", { type: "checkbox" });
          box.checked = state.authenticators.includes(a.id);
          box.addEventListener("change", () => {
            state.authenticators = box.checked ? [...new Set([...state.authenticators, a.id])]
              : state.authenticators.filter((x) => x !== a.id);
            paint();
          });
          kids.push(el("label", { class: "h2v-check" }, [box, el("span", { text: a.label })]));
        }
      }
    }
    appsHost.replaceChildren(...kids);
  }
  const uid = Math.random().toString(36).slice(2, 8);
  const mode = segmented({ label: "How many of the ticked factors", options: POLICY_MODES, value: state.mode,
    onChange: (id) => { state.mode = id; drawRules(); paint(); } });
  modeHost.append(el("div", { class: "h2v-label", text: "The editor needs" }), mode.el);
  const builder = el("div", { class: "h2v-factor__panel h2v-pchoice__adv" }, [
    el("div", { class: "h2v-label", text: "Factors" }), factorHost, modeHost, ruleHost, appsHost]);

  // what is registered here + "Add another authenticator" (B5 / B6): no new QR per vault, the apps are reused
  const registered = el("div", { class: "h2v-pk h2v-pchoice__apps" });
  function drawRegistered() {
    const apps = (st.authenticators || []).map((a) => a.label);
    const kids = [el("span", { class: "h2v-dim", style: { flex: "1", minWidth: "0" }, text: apps.length
      ? `Authenticator apps on this computer: ${apps.join(", ")} - reused by every vault, no new QR code.`
      : "No authenticator app on this computer yet." })];
    if (onAddAuthenticator) {
      kids.push(vbutton(apps.length ? "Add another authenticator" : "Add an authenticator", { small: true,
        onClick: async () => {
          const before = new Set((st.authenticators || []).map((x) => x.id));
          const fresh = await onAddAuthenticator();
          if (fresh) {
            st = fresh;
            const added = (st.authenticators || []).map((x) => x.id).filter((id) => !before.has(id));
            if (added.length) {                       // the new app is ticked for this vault (and for the app factor)
              state.factors.totp = true;
              state.authenticators = [...new Set([...state.authenticators, ...added])];
            }
            drawFactors(); drawApps(); drawRegistered(); paint();
          }
        } }));
    }
    registered.replaceChildren(...kids);
  }

  const fallback = el("p", { class: "h2v-dim", text: RECOVERY_FALLBACK_TEXT });
  const preview = el("div", { class: "h2v-mrow h2v-pchoice__preview", role: "status" });
  const notes = el("div", { class: "h2v-factor__panel" });
  const cards = choiceCards({ label: "How should this vault be opened for editing?", options, value: start,
    onChange: paint });
  function value() {
    const id = cards.value();
    if (id !== "custom") {
      const v = secondFactorFromChoice(id);
      if (!v.ok) return v;
      const policy = { methods: v.methods.filter((m) => m !== "recovery"), mode: "any",
        recovery: v.methods.length ? "fallback" : "off", authenticators: [] };
      return { ...v, policy, secondFactor: { choice: v.choice, methods: v.methods } };
    }
    const p = policyFromBuilder(state);
    if (!p.ok) return p;
    return { ok: true, choice: "custom", methods: [...p.policy.methods, ...(p.policy.recovery === "off" ? [] : ["recovery"])],
      policy: p.policy, secondFactor: p.secondFactor };
  }
  function paint() {
    const id = cards.value();
    builder.style.display = id === "custom" ? "" : "none";
    fallback.style.display = id === "custom" || id === "password" ? "none" : "";
    const v = value();
    notes.replaceChildren();
    if (!v.ok) {
      preview.replaceChildren(el("span", { class: "h2v-dim", text: "Preview: choose the factors first." }));
      notes.append(noticeEl("danger", v.error));
      return;
    }
    const names = (st.authenticators || []).filter((a) => v.policy.authenticators.includes(a.id)).map((a) => a.label);
    preview.replaceChildren(el("div", { class: "h2v-mrow__title", text: "This vault will open for editing with" }),
      el("div", { class: "h2v-mrow__state", text: policySummary(v.policy, names) }));
    for (const n of (id === "custom" ? policyNotes(v.policy, st) : choiceNotes(v.choice, v.methods, st))) {
      notes.append(noticeEl(n.tone, n.text));
    }
  }
  drawFactors();
  drawRules();
  drawApps();
  drawRegistered();
  paint();
  const root = block(title, null, cards.el, builder, fallback, registered, preview, notes);
  root.classList.add("h2v-pchoice");
  return { el: root, value };
}

/**
 * The second factor for a vault whose policy needs ALL of several factors (L9.343): one input per factor, plus the
 * recovery-code door the author allowed ("replace ONE missing factor" or "emergency override"). collect() ->
 * {factors} | {error}. Same contract as factorPicker otherwise.
 */
export function allFactorsPrompt({ status, policy, post }) {
  ensureStyles();
  const plan = promptPlan(policy);
  const root = el("div", { class: "h2v-factor" });
  const pickers = plan.steps.map((m, i) => ({ m, p: factorPicker({ status, post, allowed: [m],
    label: `${i + 1} of ${plan.steps.length}`, lostHelp: i === plan.steps.length - 1 }) }));
  let recovery = null, replaces = plan.steps[0], useRecovery = false;
  const pickerHost = el("div", { class: "h2v-factor__panel" }, pickers.map((x) => x.p.el));
  const kids = [el("p", { class: "h2v-dim", text: policySummary(policy, policy.authenticators) }), pickerHost];
  if (plan.recovery === "replace_one" || plan.recovery === "override") {
    const recHost = el("div", { class: "h2v-factor__panel" });
    const sw = switchRow(plan.recovery === "override" ? "Emergency: open with a recovery code instead"
      : "Use a recovery code for one missing factor", { onChange: (on) => { useRecovery = on; draw(); } });
    const draw = () => {
      recovery?.destroy();
      recovery = null;
      recHost.replaceChildren();
      pickers.forEach((x) => { x.p.el.style.display = ""; });
      if (!useRecovery) return;
      recovery = factorPicker({ status, post, allowed: ["recovery"], label: "Recovery code", lostHelp: false });
      const kidsR = [recovery.el];
      if (plan.recovery === "replace_one") {
        const sel = el("select", { class: "h2v-input", "aria-label": "The factor the recovery code replaces" },
          plan.steps.map((m) => el("option", { value: m, text: `instead of: ${METHOD_LABELS[m]}` })));
        sel.value = replaces;
        const hide = () => pickers.forEach((x) => { x.p.el.style.display = x.m === replaces ? "none" : ""; });
        sel.addEventListener("change", () => { replaces = sel.value; hide(); });
        kidsR.unshift(sel);
        hide();
      } else {
        pickers.forEach((x) => { x.p.el.style.display = "none"; });
      }
      recHost.replaceChildren(...kidsR);
      recovery.focus();
    };
    kids.push(sw.el, recHost);
  }
  root.append(...kids);
  return {
    el: root,
    async collect() {
      const got = {};
      for (const x of pickers) {
        if (useRecovery && (plan.recovery === "override" || x.m === replaces)) continue;
        const r = await x.p.collect();
        if (r.error) return { ...r, error: `${METHOD_LABELS[x.m]}: ${r.error}` };
        got[x.m] = r.factor;
      }
      let rec = null;
      if (useRecovery && recovery) {
        const r = await recovery.collect();
        if (r.error) return r;
        rec = r.factor;
      }
      const out = allFactors(plan, got, rec, replaces);
      return out.ok ? { factors: out.factors } : { error: out.error };
    },
    focus() { pickers[0]?.p.focus(); },
    isEmpty: () => pickers.every((x) => x.p.isEmpty()) && (!recovery || recovery.isEmpty()),
    restrict() { /* the policy is fixed; nothing to narrow */ },
    succeeded() { pickers.forEach((x) => x.p.succeeded()); },
    failed() { pickers.forEach((x) => x.p.failed()); recovery?.failed(); },
    destroy() { pickers.forEach((x) => x.p.destroy()); recovery?.destroy(); },
    method: () => "all",
  };
}

const PASSKEY_KIND_LABELS = Object.freeze({ any: "Any passkey or key", platform: "This device (Windows Hello, Touch ID)",
  security_key: "Security key (YubiKey...)" });

/** The Second factor dialog's facts after a proof: the last activity and what each known vault accepts. */
function overviewRows(data, when) {
  const rows = [];
  const act = data?.activity || [];
  rows.push(block("Last authentication activity", act.length ? null : "Nothing yet on this computer.",
    ...act.slice(0, 5).map((e) => el("div", { class: "h2v-pk" }, [el("span", { class: "h2v-pk__name",
      text: `${e.label || METHOD_LABELS[e.method] || e.method} · ${e.where === "vault" ? "opening a vault" : "settings"}` }),
    el("small", { class: "h2v-dim", text: e.at ? `${when(e.at)} ${new Date(e.at * 1000).toLocaleTimeString()}` : "" })]))));
  const vaults = data?.vaults || [];
  if (vaults.length) {
    rows.push(block("Vaults this computer knows - what each accepts", "Vaults locked or opened here since the update.",
      ...vaults.slice(0, 20).map((v) => el("div", { class: "h2v-mrow" }, [el("div", { class: "h2v-mrow__title", text: v.title }),
        el("div", { class: "h2v-mrow__state", text: v.policy?.summary || "" })]))));
  }
  return rows;
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
    subtitle: firstRun ? "This vault needs its password plus a second factor. Add at least one method on this computer."
      : "Every method this computer can use to open vaults that ask for a second factor. Each vault's author chooses " +
        "which it accepts (or 'Password only')." });
  const host = el("div", { class: "h2v-block" });
  d.body.append(host);
  let unsavedCodes = null;               // a new recovery set on screen: "Done" waits for the "I saved them" tick
  d.addAction("Done", { primary: true, onClick: () => {
    if (unsavedCodes && !unsavedCodes.checked) {
      d.notice("danger", "Tick 'I saved the recovery codes' first - the new codes are not shown again.");
      unsavedCodes.focus();
      return;
    }
    d.close(true);
  } });
  d.onCleanup(() => proof?.destroy());

  if (!status.enrolled) {                 // nothing to prove yet: the token covers every method set up in this dialog
    const t = await post("/h2vault/2fa/manage/begin", {});
    if (t.ok) token = t.data.manage_token;
  }
  const refresh = async () => { status = await getStatus(); draw(); };
  /** L9.343: a change a vault's policy guards needs one more proof in this settings session (step-up). */
  async function stepUp(data) {
    const accepted = data?.needed?.length ? data.needed : data?.vaults?.[0]?.policy?.accepted || null;
    const picker = factorPicker({ status, post, allowed: accepted?.length ? accepted : null, label: "Confirm with" });
    const sd = vaultDialog({ title: "Confirm once more", subtitle: data?.error || "", width: 500 });
    sd.body.append(picker.el);
    sd.onCleanup(() => picker.destroy());
    sd.addAction("Cancel", { onClick: () => sd.close(false) });
    const go = async () => {
      if (sd.busy) return;
      sd.notice(null);
      const got = await picker.collect();
      if (got.error) { sd.notice("danger", got.error); if (got.focus) picker.focus(); return; }
      sd.setBusy(true, "Checking…");
      const r = await post("/h2vault/2fa/manage/begin", { factor: got.factor, manage_token: token });
      sd.setBusy(false);
      if (!r.ok) { sd.notice("danger", r.status === 429 ? r.data?.error : factorErrorText(r.data)); picker.failed(); return; }
      picker.succeeded();
      sd.close(true);
    };
    sd.addAction("Confirm", { primary: true, onClick: go });
    sd.onSubmit(go);
    picker.focus();
    return sd.result;
  }
  const call = async (route, body = {}) => {
    for (let round = 0; round < 4; round++) {
      const r = await post(route, { ...body, manage_token: token });
      if (!r.ok && r.status === 403 && /Confirm it is you/.test(r.data?.error || "")) { token = null; draw(); return r; }
      if (r.data?.reason !== "step_up") return r;
      if (!(await stepUp(r.data))) return { ok: false, data: { error: "Not changed: the extra confirmation was cancelled." } };
    }
    return { ok: false, data: { error: "Not changed: more confirmation is needed than this dialog can ask for." } };
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

  const STATE_TAG = { set_up: ["Set up", "ok"], not_set_up: ["Not set up", ""], unavailable: ["Not possible here", "warn"] };

  /** One method: name + state tag, what it is / why not here, its actions, and its list (apps, passkeys ...). */
  function row(info, acts, more = []) {
    const [tagText, tone] = STATE_TAG[info.state] || STATE_TAG.not_set_up;
    const title = el("div", { class: "h2v-mrow__title" }, [info.label,
      el("span", { class: `h2v-tag${tone ? ` h2v-tag--${tone}` : ""}`, text: tagText })]);
    const state = el("div", { class: "h2v-mrow__state", text: info.state === "unavailable" ? info.reason : info.detail });
    return el("div", { class: "h2v-mrow", "data-method": info.id }, [title,
      el("div", { class: "h2v-mrow__acts" }, acts.filter(Boolean)), state,
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

  /**
   * Remove an item through `route`. The server refuses (409, naming the vaults and the fix) when a vault it knows
   * would have no accepted method left here; it asks to confirm when a warning is due (last of its kind, vaults left
   * with recovery codes only) and, for the last authenticator app, a fresh proof. The confirm panel goes into `host`.
   */
  async function removeChecked(route, body, host, what) {
    d.notice(null);
    const r = await call(route, body);
    if (r.ok) { await refresh(); d.notice("ok", `${what} removed.`); return; }
    if (r.data?.reason !== "confirm") { d.notice("danger", r.data?.error || `Could not remove the ${what.toLowerCase()}.`); return; }
    let picker = null;
    const cancel = () => { picker?.destroy(); host.replaceChildren(); d.onSubmit(() => {}); };
    const go = async () => {
      if (d.busy) return;
      d.notice(null);
      let factor = null;
      if (picker) {
        const got = await picker.collect();
        if (got.error) { d.notice("danger", got.error); if (got.focus) picker.focus(); return; }
        factor = got.factor;
      }
      d.setBusy(true, "Removing…");
      const again = await call(route, { ...body, confirm: true, ...(factor ? { factor } : {}) });
      d.setBusy(false);
      if (again.ok) { cancel(); await refresh(); d.notice("ok", `${what} removed.`); return; }
      d.notice("danger", factorErrorText(again.data) || "Could not remove it.");
      picker?.failed();
    };
    const kids = [noticeEl("warn", r.data.warning)];
    if (r.data.needs_proof) {
      picker = factorPicker({ status, post, label: "Confirm once more with" });
      kids.push(picker.el);
      d.onCleanup(() => picker?.destroy());
    }
    kids.push(el("div", { class: "h2v-row" }, [vbutton("Keep it", { small: true, onClick: cancel }),
      vbutton(`Remove ${what.toLowerCase()} anyway`, { small: true, kind: "danger", onClick: go })]));
    host.replaceChildren(el("div", { class: "h2v-factor__panel" }, kids));
    d.onSubmit(go);
    picker?.focus();
  }

  /** "Add" with a name first (the phone shows "H2Vault: <name>", the list here too); `kinds` adds a kind choice. */
  function nameThenAdd(host, { placeholder, button, onGo, kinds = null }) {
    const name = hardenSecret(el("input", { type: "text", class: "h2v-input", maxLength: 60, placeholder,
      "aria-label": placeholder }));
    const kind = kinds ? el("select", { class: "h2v-input", "aria-label": "Kind of passkey" },
      Object.entries(kinds).map(([id, text]) => el("option", { value: id, text }))) : null;
    const go = async () => { if (d.busy) return; await onGo(name.value.trim(), kind?.value); };
    name.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); go(); } });
    host.replaceChildren(el("div", { class: "h2v-row" }, [el("div", { style: { flex: "1", minWidth: "0" } }, [name]), kind,
      vbutton("Cancel", { small: true, onClick: () => host.replaceChildren() }),
      vbutton(button, { small: true, kind: "primary", onClick: go })]));
    setTimeout(() => name.focus(), 0);
  }

  const when = (s) => (s ? new Date(s * 1000).toLocaleDateString() : "");
  const disabledAdd = () => { const b = vbutton("Add", { small: true }); b.disabled = true; return b; };

  function drawMethods() {
    d.onSubmit(() => {});
    const env = passkeyEnv();
    const cat = Object.fromEntries(methodCatalog(status, env).map((r) => [r.id, r]));
    const m = status.methods || {};
    const out = [];

    // authenticator apps: several, each with a name
    const appAdd = el("div");
    const apps = (status.authenticators || []).map((a) => {
      const nameEl = el("span", { class: "h2v-pk__name" }, [a.label, " ", el("small", { class: "h2v-dim",
        text: `· added ${when(a.created) || "before names existed"} · ${a.last_used ? `last used ${when(a.last_used)}`
          : "not used yet"}` })]);
      const line = el("div", { class: "h2v-pk" });
      const confirmHost = el("div");
      const rename = vbutton("Rename", { small: true, onClick: () => {
        const input = hardenSecret(el("input", { type: "text", class: "h2v-input", maxLength: 60, value: a.label,
          "aria-label": `New name for ${a.label}` }));
        input.value = a.label;
        const save = async () => {
          const r = await call("/h2vault/2fa/totp/rename", { id: a.id, label: input.value.trim() });
          if (!r.ok) { d.notice("danger", r.data?.error || "Could not rename it."); input.focus(); return; }
          await refresh();
        };
        input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); save(); }
          if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); draw(); } });
        line.replaceChildren(el("div", { style: { flex: "1", minWidth: "0" } }, [input]),
          vbutton("Cancel", { small: true, onClick: () => draw() }), vbutton("Save", { small: true, kind: "primary", onClick: save }));
        setTimeout(() => input.focus(), 0);
      } });
      line.append(nameEl, rename, removeBtn("Remove", () => removeChecked("/h2vault/2fa/totp/remove", { id: a.id },
        confirmHost, "Authenticator app")));
      return el("div", {}, [line, confirmHost]);
    });
    out.push(row(cat.totp, [vbutton(m.totp ? "Add another" : "Add", { small: true, onClick: () => nameThenAdd(appAdd, {
      placeholder: m.totp ? "Name, e.g. Backup phone or Anna's phone" : "Name, e.g. My phone",
      button: "Continue", onGo: async (label) => {
        const may = await call("/h2vault/2fa/manage/check", { change: "totp" });     // step-up first (L9.343)
        if (!may.ok) { d.notice("danger", may.data?.error || "Not allowed."); return; }
        appAdd.replaceChildren(); await enrolTotp(token, label); await refresh();
      } }) })],
    [...apps, appAdd, m.totp ? el("p", { class: "h2v-dim", text: TOTP_DRIFT_TEXT }) : null]));

    // passkeys
    const pkHost = el("div");
    const pkList = (status.passkeys || []).map((p) => {
      const confirmHost = el("div");
      return el("div", {}, [el("div", { class: "h2v-pk" }, [
        el("span", { class: "h2v-pk__name" }, [`${p.label} · ${PASSKEY_KIND_LABELS[p.kind] || PASSKEY_KIND_LABELS.any}`,
          " ", el("small", { class: "h2v-dim", text: `· ${p.rp_id} · added ${when(p.created)} · ` +
            `${p.last_used ? `last used ${when(p.last_used)}` : "not used yet"}` })]),
        removeBtn("Remove", () => removeChecked("/h2vault/2fa/passkey/remove", { id: p.id }, confirmHost, "Passkey"))]),
      confirmHost]);
    });
    const local = localhostUrl(globalThis.location || {});
    out.push(row(cat.passkey, [
      cat.passkey.canAdd ? vbutton(m.passkey ? "Add another" : "Add", { small: true, onClick: () => nameThenAdd(pkHost, {
        placeholder: "Name, e.g. YubiKey or Windows Hello", button: "Register", kinds: PASSKEY_KIND_LABELS,
        onGo: async (label, kind) => {
          d.notice(null);
          const b = await call("/h2vault/2fa/passkey/register/begin", { label, kind });
          if (!b.ok) { d.notice("danger", b.data?.error || "Could not start the passkey setup."); return; }
          let cred;
          try { cred = await navigator.credentials.create({ publicKey: createOptions(b.data.publicKey) }); }
          catch (e) { d.notice("danger", passkeyErrorText(e)); return; }
          const f = await call("/h2vault/2fa/passkey/register/finish", { challenge_id: b.data.challenge_id,
            credential: credentialJSON(cred) });
          if (!f.ok) { d.notice("danger", f.data?.error || "The passkey could not be registered."); return; }
          await refresh();
          d.notice("ok", `Passkey "${f.data.passkey.label}" added.`);
        } }) })
        : local ? vbutton("Open as localhost", { small: true, onClick: () => globalThis.open?.(local, "_blank", "noopener") })
          : disabledAdd()], [pkHost, ...pkList]));

    // backup password
    const bpHost = el("div");
    const bpConfirm = el("div");
    out.push(row(cat.backup_password, [
      vbutton(m.backup_password ? "Change" : "Add", { small: true, onClick: () => {
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
      m.backup_password ? removeBtn("Remove", () => removeChecked("/h2vault/2fa/backup_password/remove", {}, bpConfirm,
        "Backup password")) : null], [m.backup_password ? el("p", { class: "h2v-dim", text: status.backup_password_last_used
        ? `Last used ${when(status.backup_password_last_used)}.` : "Not used yet." }) : null, bpHost, bpConfirm]));

    // recovery codes
    const rcHost = el("div");
    out.push(row(cat.recovery, [
      vbutton(m.recovery ? "New set" : "Add", { small: true, onClick: async () => {
        d.notice(null);
        const made = (r) => {
          const p = codesPanel(r.data.recovery_codes || []);
          unsavedCodes = p.saved;
          rcHost.replaceChildren(p.el);
          getStatus().then((x) => { status = x; });
          if (r.data.replaced) d.notice("info", "The previous recovery codes no longer work.");
        };
        const r = await call("/h2vault/2fa/recovery/new");
        if (r.ok) { made(r); return; }
        if (r.data?.reason !== "confirm") { d.notice("danger", r.data?.error || "Could not generate codes."); return; }
        // codes are left: say what happens to them first (L9.343), nothing changes until "Make a new set"
        rcHost.replaceChildren(el("div", { class: "h2v-factor__panel" }, [noticeEl("warn", r.data.warning),
          el("div", { class: "h2v-row" }, [vbutton("Keep my codes", { small: true, onClick: () => rcHost.replaceChildren() }),
            vbutton("Make a new set", { small: true, kind: "danger", onClick: async () => {
              const again = await call("/h2vault/2fa/recovery/new", { confirm: true });
              if (!again.ok) { d.notice("danger", again.data?.error || "Could not generate codes."); return; }
              made(again);
            } })])]));
      } })], [rcHost]));

    // not possible offline: listed, so nobody wonders where they are
    for (const id of ["email", "sms"]) out.push(row(cat[id], [disabledAdd()]));

    if (!m.totp && !m.passkey && !m.backup_password) {
      out.unshift(noticeEl(m.recovery ? "warn" : "info", m.recovery
        ? "Only recovery codes are left: add an authenticator app, a passkey or a backup password."
        : "Add at least one method to open vaults that ask for a second factor (vaults set to 'Password only' never do)."));
    }
    // last activity + which vaults accept what (after the proof: vault names are not for anyone)
    const facts = el("div", { class: "h2v-factor__panel" });
    if (token && status.enrolled) {
      call("/h2vault/2fa/overview").then((r) => { if (r.ok) facts.replaceChildren(...overviewRows(r.data, when)); });
    }
    out.push(facts);
    out.push(block("Recovery and reset", null, el("p", { class: "h2v-dim", text: lostAllText(status) })));
    host.replaceChildren(...out);
  }

  draw();
  const ok = await d.result;
  status = await getStatus().catch(() => status);
  return !!(ok && status.enrolled) || !!status.enrolled;
}

export { copyRow };
