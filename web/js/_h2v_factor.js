// H2Vault (AGPL-3.0) - second-factor methods, the pure part (owner 2026-11-23: "more options than just authenticator,
// selective options"; recovery codes must be enterable; no browser "save password" prompts).
// No DOM at import, no ComfyUI import: tests run it under node (tests/test_auth_frontend.mjs).

export const METHOD_ORDER = Object.freeze(["totp", "passkey", "backup_password", "recovery"]);
export const METHOD_LABELS = Object.freeze({ totp: "Authenticator app", passkey: "Passkey or security key",
  backup_password: "Backup password", recovery: "Recovery code" });
export const DEFAULT_METHODS = Object.freeze(["totp", "recovery"]);   // vaults locked before methods existed
export const LAST_METHOD_KEY = "h2vault.secondFactor.last";
export const NOT_OFFLINE_TEXT = "Email and text-message (SMS) codes are not offered: they need a mail or SMS " +
  "provider and a server that sends them, and H2Vault works offline.";
export const TOTP_DRIFT_TEXT = "Codes from 30 s before or after are accepted, in case the clocks differ a little.";

// ── secret inputs that browsers and password managers leave alone ────────────────────────────────────────────
// Root cause of the owner's "save password again and again" (2026-11-23): every vault password box was an
// <input type="password"> (autocomplete current-password / new-password). Chromium's password manager treats a password
// field that disappears after a successful fetch() as a submitted login form and offers to save it - so EVERY lock,
// open, run-unlock, access change and licence step asked. autocomplete="off" is ignored for type=password. The fix: a
// masked TEXT input (-webkit-text-security) - no password field, so nothing to save - plus the opt-out attributes of
// the common managers, no <form>, no name/id that says "password". Browsers without that CSS keep type=password with
// autocomplete="new-password" (they may still offer to save; said in the field's hint).
export const NO_SAVE_ATTRS = Object.freeze({ autocomplete: "off", "data-1p-ignore": "true", "data-lpignore": "true",
  "data-bwignore": "true", "data-form-type": "other", "data-protonpass-ignore": "true", autocapitalize: "off",
  autocorrect: "off", spellcheck: "false" });

/** Can this browser mask a text input (Chromium, Safari, current Firefox)? `css` = globalThis.CSS. */
export function maskingSupported(css) {
  try { return !!css?.supports?.("-webkit-text-security", "disc"); } catch (_) { return false; }
}

/** How a secret input is built: {type, autocomplete, masked}. */
export function secretInputSpec(masking) {
  return masking ? { type: "text", autocomplete: "off", masked: true }
    : { type: "password", autocomplete: "new-password", masked: false };
}

let seq = 0;
/** Apply the no-save attributes to an element (anything with setAttribute) - a neutral name that never says
 *  "password" / "login" (some managers key on it). */
export function hardenSecret(input) {
  for (const [k, v] of Object.entries(NO_SAVE_ATTRS)) input.setAttribute(k, v);
  input.setAttribute("name", `h2v-k${++seq}`);
  return input;
}

// ── passkeys (WebAuthn) ────────────────────────────────────────────────────────────────────────────────────────
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Can a passkey be used on this page? env = {PublicKeyCredential, isSecureContext, hostname, port}.
 *  -> {ok: true} | {ok: false, reason}. Browsers refuse WebAuthn on an IP address and on insecure pages. */
export function passkeySupport(env) {
  if (!env?.PublicKeyCredential) return { ok: false, reason: "This browser does not support passkeys." };
  if (!env.isSecureContext) {
    return { ok: false, reason: "Passkeys need a secure page: open ComfyUI as http://localhost or over https." };
  }
  const host = String(env.hostname || "").replace(/^\[|\]$/g, "");
  if (IPV4.test(host) || host.includes(":")) {
    const port = env.port ? `:${env.port}` : "";
    return { ok: false, reason: `Browsers allow passkeys only on a name, not on an IP address (${host}). Open ` +
      `ComfyUI as http://localhost${port} to use passkeys.` };
  }
  return { ok: true };
}

/** The methods to offer: set up on this installation (status.methods) AND accepted by the vault (`allowed`, null =
 *  unknown yet). -> {offer: [{id,label}], unavailable: [{id,label,reason}]}. */
export function offeredMethods(status, allowed = null, passkeyEnv = null) {
  const have = status?.methods || {};
  const offer = [], unavailable = [];
  for (const id of METHOD_ORDER) {
    if (allowed && !allowed.includes(id)) continue;
    if (!have[id]) continue;
    if (id === "passkey") {
      const sup = passkeySupport(passkeyEnv);
      if (!sup.ok) { unavailable.push({ id, label: METHOD_LABELS[id], reason: sup.reason }); continue; }
    }
    offer.push({ id, label: METHOD_LABELS[id] });
  }
  return { offer, unavailable };
}

/** The method selected first: the last one used (if offered), else the first offered. */
export function defaultMethod(offer, last) {
  const ids = (offer || []).map((m) => m.id);
  return ids.includes(last) ? last : (ids[0] ?? null);
}

export function recallMethod(storage) {
  try { return storage?.getItem?.(LAST_METHOD_KEY) || null; } catch (_) { return null; }
}

export function rememberMethod(storage, id) {
  try { if (METHOD_ORDER.includes(id)) storage?.setItem?.(LAST_METHOD_KEY, id); } catch (_) { /* a nicety */ }
}

/** Looks like a recovery code (XXXX-XXXX-XX, case and dashes free)? */
export function isRecoveryShape(code) {
  return /^[A-HJ-NP-Z2-9]{10}$/.test(String(code || "").toUpperCase().replace(/[\s-]/g, ""));
}

/** The author's ticks -> {ok, methods} | {ok: false, error}. Recovery codes are always included; at least one other. */
export function policyFromTicks(ticks) {
  const chosen = METHOD_ORDER.filter((m) => m !== "recovery" && ticks?.[m]);
  if (!chosen.length) {
    return { ok: false, error: "Tick at least one second factor besides recovery codes: authenticator app, passkey " +
      "or backup password." };
  }
  return { ok: true, methods: [...chosen, "recovery"] };
}

/** Which ticks to start from in the lock dialog: the methods set up here (else the authenticator). */
export function initialTicks(status, current = null) {
  const src = current?.length ? current : METHOD_ORDER.filter((m) => m !== "recovery" && status?.methods?.[m]);
  const pick = src.length ? src : ["totp"];
  return Object.fromEntries(METHOD_ORDER.map((m) => [m, m === "recovery" || pick.includes(m)]));
}

// ── the one question: "How should this vault be opened for editing?" (owner 2026-11-23) ─────────────────────────
// Each answer is a method list the server stores ([] = password only); nodes/twofactor.py CHOICES is the same table.
export const PROTECTION_CHOICES = Object.freeze([
  { label: "Password only", id: "password", tag: "no second factor", tone: "warn", methods: [],
    summary: "Whoever knows the password can open it for editing on an editor's computer. Simplest, and weaker: a " +
      "leaked password is enough." },
  { label: "Password + authenticator app", id: "totp", methods: ["totp", "recovery"],
    summary: "A 6-digit code from any authenticator app registered on the editor's computer (phone, backup phone…)." },
  { label: "Password + passkey", id: "passkey", methods: ["passkey", "recovery"],
    summary: "A security key, Windows Hello or a phone passkey. The page must be opened as http://localhost:<port>." },
  { label: "Password + backup password", id: "backup_password", methods: ["backup_password", "recovery"],
    summary: "A second secret, different from the vault password, set up on the editor's computer." },
  { label: "Password + any second factor", id: "any", tag: "most flexible", tone: "ok",
    methods: ["totp", "passkey", "backup_password", "recovery"],
    summary: "Each editor uses whatever they set up on their own computer: authenticator app, passkey or backup " +
      "password." },
]);
export const CUSTOM_CHOICE = Object.freeze({ label: "Advanced: build a policy", id: "custom",
  summary: "Any one or ALL of the factors you tick, what a recovery code may do, and (per vault) particular " +
    "authenticator apps." });
const SHORT_NAMES = Object.freeze({ totp: "authenticator app", passkey: "passkey", backup_password: "backup password" });
// shown under the one-click answers, where it holds; a built policy says its own recovery rule (policySummary)
export const RECOVERY_FALLBACK_TEXT = "Recovery codes are always accepted as a fallback whenever a second factor is " +
  "required.";

export function methodsOfChoice(id) {
  const c = PROTECTION_CHOICES.find((x) => x.id === id);
  return c ? [...c.methods] : null;
}

/** A vault's method list -> the answer to the one question ("custom" when none fits). */
export function choiceOfMethods(methods) {
  const have = new Set(methods || []);
  if (have.size) have.add("recovery");                  // always part of a list that needs a second factor
  const c = PROTECTION_CHOICES.find((x) => x.methods.length === have.size && x.methods.every((m) => have.has(m)));
  return c ? c.id : "custom";
}

/** The answer to start from: the vault's current one, or (a new vault) the most flexible one that still asks for a
 *  second factor. */
export function initialChoice(current) {
  return Array.isArray(current) ? choiceOfMethods(current) : "any";
}

/** The dialog's answer -> {ok, choice, methods} | {ok: false, error}. `ticks` only for "custom". */
export function secondFactorFromChoice(id, ticks = null) {
  if (id === "custom") {
    const p = policyFromTicks(ticks);
    return p.ok ? { ok: true, choice: "custom", methods: p.methods } : p;
  }
  const methods = methodsOfChoice(id);
  return methods ? { ok: true, choice: id, methods } : { ok: false, error: "Choose how this vault is opened for editing." };
}

/** The notes shown under the choice: what "Password only" gives up; methods not set up on this computer yet. */
export function choiceNotes(id, methods, status) {
  const notes = [];
  if (id === "password") {
    notes.push({ tone: "warn", text: "Only the password protects editing: anyone who learns it can open the vault " +
      "for editing on any editor installation, and the vault's licence and author-key actions need only the " +
      "password too. Running the vault is not affected. Choose a second factor for anything you would not want " +
      "changed by someone who saw the password." });
    return notes;
  }
  const have = status?.methods || {};
  const needed = (methods || []).filter((m) => m !== "recovery");
  const missing = needed.filter((m) => !have[m]);
  if (needed.length && missing.length === needed.length) {
    const what = needed.length === 1
      ? `No ${SHORT_NAMES[needed[0]]} is set up on this computer yet.`
      : "None of them is set up on this computer yet.";
    notes.push({ tone: "warn", text: `${what} Set one up (H2Vault menu › Second factor) before you open this vault ` +
      "for editing here; other editors use their own. Running it is not affected." });
  }
  return notes;
}

// ── policies: ANY / ALL of the chosen factors (L9.343, docs/AUTH_POLICY.md; nodes/twofactor.py is the same model) ──
export const FACTOR_ORDER = Object.freeze(["totp", "passkey", "backup_password"]);
export const POLICY_MODES = Object.freeze([
  { label: "Any one of them (OR)", id: "any" }, { label: "All of them (AND)", id: "all" }]);
export const RECOVERY_RULES = Object.freeze({
  any: Object.freeze([
    { label: "Accepted instead of the factor", id: "fallback", hint: "Each code works once." },
    { label: "Not accepted", id: "off", hint: "Only the chosen factors open it." }]),
  all: Object.freeze([
    { label: "Not accepted", id: "off", hint: "Safest: ALL factors are always needed." },
    { label: "May replace ONE missing factor", id: "replace_one",
      hint: "The editor gives every other factor plus one recovery code." },
    { label: "Emergency override", id: "override",
      hint: "The password plus a recovery code alone opens it - as strong as 'any one' with recovery codes." }]),
});
const FACTOR_WORDS = Object.freeze({ totp: "a code from an authenticator app", passkey: "a passkey or security key",
  backup_password: "the backup password" });
const RECOVERY_WORDS = Object.freeze({
  "any/fallback": "A recovery code can be used instead (each works once).",
  "any/off": "Recovery codes are not accepted.",
  "all/off": "Recovery codes are not accepted.",
  "all/replace_one": "A recovery code may replace ONE missing factor (each code works once).",
  "all/override": "Emergency override: the password plus a recovery code alone also opens it (each code works once).",
});

/** A policy in plain words (the same sentence as twofactor.policy_summary). `appNames` = names of the chosen apps. */
export function policySummary(policy, appNames = []) {
  const methods = policy?.methods || [];
  if (!methods.length) return "The vault password only - no second factor.";
  const words = methods.map((m) => {
    if (m === "totp" && (policy.authenticators?.length || policy.restricted)) {
      const names = (appNames || []).filter(Boolean);
      return "a code from " + (names.length ? `one of these authenticator apps: ${names.join(", ")}`
        : "one of the authenticator apps chosen for this vault");
    }
    return FACTOR_WORDS[m];
  });
  let need;
  if (words.length === 1) need = words[0];
  else if (policy.mode === "all") need = words.join(" AND ");
  else need = `ONE of: ${words.slice(0, -1).join(", ")} or ${words[words.length - 1]}`;
  return `The vault password AND ${need}. ${RECOVERY_WORDS[`${policy.mode}/${policy.recovery}`] || ""}`.trim();
}

/** The builder's state -> {ok, policy, secondFactor} | {ok: false, error}. state = {factors: {totp, passkey,
 *  backup_password}, mode, recovery, restrict, authenticators: [ids]}. `secondFactor` is what the server reads. */
export function policyFromBuilder(state) {
  const methods = FACTOR_ORDER.filter((m) => state?.factors?.[m]);
  if (!methods.length) {
    return { ok: false, error: "Tick at least one second factor besides recovery codes: authenticator app, passkey " +
      "or backup password." };
  }
  const mode = state?.mode === "all" ? "all" : "any";
  const rules = RECOVERY_RULES[mode].map((r) => r.id);
  const recovery = rules.includes(state?.recovery) ? state.recovery : rules[0];
  if (mode === "all" && recovery === "replace_one" && methods.length === 1) {
    return { ok: false, error: "With only one factor, 'a recovery code may replace one missing factor' would let a " +
      "recovery code alone open the vault. Choose 'Emergency override' if that is what you want, or tick more factors." };
  }
  const restrict = !!state?.restrict && methods.includes("totp");
  const authenticators = restrict ? [...new Set(state?.authenticators || [])] : [];
  if (restrict && !authenticators.length) {
    return { ok: false, error: "Tick at least one authenticator app for this vault, or switch 'Only particular " +
      "authenticator apps' off." };
  }
  const policy = { methods, mode, recovery, authenticators };
  return { ok: true, policy, secondFactor: { choice: "custom", methods, mode, recovery, authenticators } };
}

/** A server answer's policy (twofactor.policy_public) or a vault's method list -> the builder's starting state. */
export function builderStateOf(policy, status) {
  if (policy?.methods?.length) {
    const ids = (status?.authenticators || []).filter((a) => (policy.authenticators || []).includes(a.label))
      .map((a) => a.id);
    return { factors: Object.fromEntries(FACTOR_ORDER.map((m) => [m, policy.methods.includes(m)])),
      mode: policy.mode === "all" ? "all" : "any", recovery: policy.recovery || "fallback",
      restrict: !!policy.restricted, authenticators: ids };
  }
  const ticks = initialTicks(status);
  return { factors: Object.fromEntries(FACTOR_ORDER.map((m) => [m, !!ticks[m]])), mode: "any", recovery: "fallback",
    restrict: false, authenticators: [] };
}

/** Is this policy one of the one-click answers? -> its id, else "custom". */
export function choiceOfPolicy(policy) {
  if (!policy) return "any";
  if (!policy.methods?.length) return "password";
  if (policy.mode !== "any" || policy.recovery !== "fallback" || policy.restricted || policy.authenticators?.length) {
    return "custom";
  }
  return choiceOfMethods([...policy.methods, "recovery"]);
}

/** What the author must know before sealing: factors not set up on this computer, the AND / restriction caveats. */
export function policyNotes(policy, status) {
  const notes = [];
  if (!policy?.methods?.length) return notes;
  const have = status?.methods || {};
  const missing = policy.methods.filter((m) => !have[m]);
  if (policy.mode === "all" && missing.length) {
    notes.push({ tone: "warn", text: `Not set up on this computer yet: ${missing.map((m) => SHORT_NAMES[m]).join(", ")}. ` +
      "With 'all of them' you cannot open this vault for editing here until every one is set up (H2Vault menu › " +
      "Second factor). Running it is not affected." });
  } else if (missing.length === policy.methods.length) {
    notes.push({ tone: "warn", text: "None of them is set up on this computer yet. Set one up (H2Vault menu › Second " +
      "factor) before you open this vault for editing here; other editors use their own." });
  }
  if (policy.authenticators?.length) {
    notes.push({ tone: "info", text: "Only the ticked authenticator apps of THIS computer count. Other editors' apps " +
      "are not accepted, and removing a ticked app here leaves this vault without its app." });
  }
  if (policy.mode === "all" && policy.recovery === "off") {
    notes.push({ tone: "info", text: "If a factor is lost, this vault cannot be opened for editing until it is set " +
      "up again (the administrator reset removes the methods of this computer; new ones then count)." });
  }
  if (policy.mode === "all" && policy.recovery === "override") {
    notes.push({ tone: "warn", text: "Emergency override: a recovery code alone (with the password) opens this vault." });
  }
  return notes;
}

/** Which inputs the open dialog shows: one picker for "any", one per factor for "all". */
export function promptPlan(policy) {
  const methods = policy?.methods || [];
  if (!methods.length) return { mode: "none", steps: [] };
  if (policy.mode !== "all") {
    return { mode: "any", accepted: policy.accepted || [...methods, ...(policy.recovery === "off" ? [] : ["recovery"])] };
  }
  return { mode: "all", steps: [...methods], recovery: policy.recovery || "off" };
}

/** The factors an "all" prompt sends: every step's factor, except the one a recovery code replaces (replace_one) or
 *  all of them (override). -> {ok, factors} | {ok: false, error}. `got` = {method: factor}, `recovery` = factor|null,
 *  `replaces` = the method the recovery code stands in for. */
export function allFactors(plan, got, recovery = null, replaces = null) {
  if (recovery && plan.recovery === "override") return { ok: true, factors: [recovery] };
  const steps = plan.steps.filter((m) => !(recovery && plan.recovery === "replace_one" && m === replaces));
  const missing = steps.filter((m) => !got?.[m]);
  if (missing.length) {
    return { ok: false, error: `This vault needs all of its factors: still missing ${missing.map((m) => METHOD_LABELS[m].toLowerCase()).join(", ")}.` };
  }
  return { ok: true, factors: [...steps.map((m) => got[m]), ...(recovery && plan.recovery === "replace_one" ? [recovery] : [])] };
}

/** "used: <name>" after a successful check (names only; the server never sends a secret). */
export function usedText(used) {
  const names = (used || []).map((u) => u?.label || METHOD_LABELS[u?.method]).filter(Boolean);
  return names.length ? `Used: ${names.join(" + ")}` : "";
}

/** The same page on http://localhost (passkeys refuse an IP address) - only for this computer's loopback address. */
export function localhostUrl(loc) {
  const host = String(loc?.hostname || "").replace(/^\[|\]$/g, "");
  if (!(host === "::1" || /^127(\.\d{1,3}){3}$/.test(host))) return null;
  return `${loc.protocol || "http:"}//localhost${loc.port ? `:${loc.port}` : ""}${loc.pathname || "/"}`;
}

/** Every method the Second factor page lists, with its state on this computer:
 *  [{id, label, state: "set_up" | "not_set_up" | "unavailable", detail, reason?, canAdd}]. */
export function methodCatalog(status, env) {
  const m = status?.methods || {};
  const pk = passkeySupport(env);
  const apps = Number(m.totp || 0), keys = Number(m.passkey || 0), codes = Number(m.recovery || 0);
  const local = localhostUrl({ protocol: "http:", hostname: env?.hostname, port: env?.port, pathname: "/" });
  const rows = [
    { label: "Authenticator apps", id: "totp", state: apps ? "set_up" : "not_set_up", canAdd: true,
      detail: apps ? `${apps} authenticator app${apps === 1 ? "" : "s"}. A code of any of them works, once.`
        : "Google / Microsoft Authenticator, 1Password, Aegis and others. Add one per phone or editor." },
    { label: "Passkeys and security keys", id: "passkey", canAdd: pk.ok,
      state: !pk.ok ? "unavailable" : keys ? "set_up" : "not_set_up",
      detail: keys ? `${keys} registered. A passkey belongs to the address it was made on.`
        : "Windows Hello, a security key (YubiKey…) or a phone passkey.",
      ...(pk.ok ? {} : { reason: local ? `Browsers allow passkeys only on a name: open this page as ${local} ` +
        "(save your workflow first - each address keeps its own browser storage)." : pk.reason }) },
    { label: "Backup password", id: "backup_password", state: m.backup_password ? "set_up" : "not_set_up",
      canAdd: true, detail: m.backup_password ? "Set. Stored as a hash; nobody can read it back."
        : "A second secret, different from every vault password." },
    { label: "Recovery codes", id: "recovery", state: codes ? "set_up" : "not_set_up", canAdd: true,
      detail: codes ? `${codes} left. Each works once, where a vault's protection allows recovery codes.`
        : "Single-use codes for when a phone or key is lost." },
    { label: "Email code", id: "email", state: "unavailable", canAdd: false, detail: "",
      reason: "Needs an email provider and a server that sends mail; H2Vault works offline, so it cannot send codes." },
    { label: "Text message (SMS)", id: "sms", state: "unavailable", canAdd: false, detail: "",
      reason: "Needs a paid, online SMS provider; H2Vault works offline, so it cannot send codes." },
  ];
  return rows;
}

/** The words shown when someone has lost every method (no secret, no path guessing). */
export function lostAllText(status) {
  const left = status?.recovery_codes_left ?? 0;
  const parts = [];
  if (left) parts.push(`You still have ${left} recovery code${left === 1 ? "" : "s"}: choose "Recovery code".`);
  parts.push("Each vault stays runnable as before - only opening it for editing needs a second factor.");
  parts.push("If every method is lost, the administrator of this computer can remove them: start ComfyUI once with " +
    "H2VAULT_RESET_SECOND_FACTOR=remove-all, then remove that setting, restart and set up a method again. Vaults, " +
    "installation keys and licences are not touched.");
  return parts.join(" ");
}

// ── base64url <-> bytes, WebAuthn JSON ────────────────────────────────────────────────────────────────────────
export function b64urlToBytes(s) {
  const b64 = String(s || "").replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(s || "").length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Server JSON -> navigator.credentials.create({publicKey}) options. */
export function createOptions(pk) {
  return { ...pk, challenge: b64urlToBytes(pk.challenge), user: { ...pk.user, id: b64urlToBytes(pk.user.id) },
    excludeCredentials: (pk.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBytes(c.id) })) };
}

/** Server JSON -> navigator.credentials.get({publicKey}) options. */
export function getOptions(pk) {
  return { ...pk, challenge: b64urlToBytes(pk.challenge),
    allowCredentials: (pk.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBytes(c.id) })) };
}

/** A PublicKeyCredential (create or get) -> the JSON the server reads. */
export function credentialJSON(cred) {
  const r = cred.response, out = { id: cred.id, type: cred.type, response: {
    clientDataJSON: bytesToB64url(r.clientDataJSON) } };
  if (r.attestationObject) out.response.attestationObject = bytesToB64url(r.attestationObject);
  if (r.authenticatorData) out.response.authenticatorData = bytesToB64url(r.authenticatorData);
  if (r.signature) out.response.signature = bytesToB64url(r.signature);
  return out;
}

/** A WebAuthn DOMException -> plain words. */
export function passkeyErrorText(err) {
  const n = err?.name || "";
  if (n === "NotAllowedError") return "The passkey prompt was cancelled or timed out. Try again, or choose another method.";
  if (n === "InvalidStateError") return "This passkey or security key is already registered here.";
  if (n === "SecurityError") return "The browser refused passkeys on this address. Open ComfyUI as http://localhost.";
  if (n === "NotSupportedError") return "This authenticator does not support the signature types H2Vault uses.";
  return `The passkey did not work: ${err?.message || err}`;
}

/** The server's answer to a failed second factor -> words (+ which methods the vault accepts). */
export function factorErrorText(data) {
  const d = data || {};
  if (d.reason === "reused") return `That code was already used. Wait for the next one${d.next_in ? ` (${d.next_in} s)` : ""}, then type it.`;
  if (d.reason === "method_not_allowed") {
    const names = (d.allowed || d.methods || []).map((m) => METHOD_LABELS[m]).filter(Boolean).join(", ");
    return `This vault does not accept that method. It accepts: ${names}.`;
  }
  return d.error || "That did not work. Check and try again.";
}
