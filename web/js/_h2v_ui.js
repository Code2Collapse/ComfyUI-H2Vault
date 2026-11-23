// Derived from Code2Collapse ComfyUI-CustomNodePacks js/_vault_ui.js (V1 vault design system, Apache-2.0, Copyright
// Code2Collapse); modified for H2Vault (AGPL-3.0): h2v- class names and --h2v-* tokens mapped onto ComfyUI's own theme
// variables (no C2C palette dependency). See NOTICE.
//
// H2Vault's design system: dialog shell, fields, choice cards, notices, copy rows, the seal mark, the selection capsule
// and the vault node's status card. Rules: no import of the ComfyUI frontend (a wrong relative depth 404s the pack's
// whole front end); side-effect free at import (tests import it under node); never innerHTML - elements and text only.

// ── pure helpers (unit-tested) ─────────────────────────────────────────────────────────────────────────────────
/** Password strength for the meter. Under 8 characters is never accepted (the server rule). */
export function passwordStrength(pw) {
  const s = String(pw ?? "");
  if (!s) return { score: 0, label: "", ok: false };
  if (s.length < 8) return { score: 0, label: "Too short", ok: false };
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((re) => re.test(s)).length;
  const score = Math.min(4, 1 + (s.length >= 12 ? 1 : 0) + (s.length >= 16 ? 1 : 0) + (classes >= 3 ? 1 : 0));
  return { score, label: ["", "Fair", "Good", "Strong", "Very strong"][score], ok: true };
}

/** Seconds until an authenticator (TOTP) code changes, by this machine's clock. */
export function secondsLeft(nowMs, period = 30) {
  return period - (Math.floor(nowMs / 1000) % period);
}

/** V5 (design 7.2): is this page reached over the network without encryption? A password typed here then crosses
 *  the network in clear. Loopback hosts and https pages are fine. `loc` = window.location (or a stand-in). */
export function isInsecurePage(loc) {
  if (!loc || loc.protocol !== "http:") return false;
  const host = String(loc.hostname || "").replace(/^\[|\]$/g, "").toLowerCase();
  return !(host === "localhost" || host === "::1" || /^127\.\d+\.\d+\.\d+$/.test(host));
}

export const INSECURE_TEXT = "This page is not on this computer and not on https: the password travels unencrypted. " +
  "Use an SSH tunnel or https.";

// ── styles ─────────────────────────────────────────────────────────────────────────────────────────────────────
const STYLE_ID = "h2v-style";
const CSS = `
.h2v { --h2v-panel: var(--comfy-menu-bg, #1f2024); --h2v-sunken: var(--comfy-input-bg, #16171a);
  --h2v-raised: var(--comfy-menu-secondary-bg, #2a2b30); --h2v-ink: var(--fg-color, #e6e6e9);
  --h2v-ink-soft: color-mix(in srgb, var(--h2v-ink) 74%, transparent);
  --h2v-ink-dim: color-mix(in srgb, var(--h2v-ink) 54%, transparent); --h2v-edge: var(--border-color, #3b3c43);
  --h2v-edge-strong: color-mix(in srgb, var(--h2v-edge) 70%, var(--h2v-ink) 30%);
  --h2v-accent: var(--p-primary-color, #5b8def); --h2v-accent-hover: color-mix(in srgb, var(--h2v-accent) 85%, #ffffff);
  --h2v-on-accent: var(--p-primary-contrast-color, #0b0d10); --h2v-ok: #3fb68b; --h2v-warn: #e0a43a;
  --h2v-danger: var(--error-text, #ff6b6b); }
.h2v { --h2v-r-dialog: 10px; --h2v-r-card: 8px; --h2v-r-ctl: 6px; font-family: inherit; color: var(--h2v-ink);
  font-size: 13px; line-height: 1.45; }
.h2v *, .h2v *::before, .h2v *::after { box-sizing: border-box; }
.h2v-backdrop { position: fixed; inset: 0; z-index: 10000; display: flex; align-items: center;
  justify-content: center; padding: 16px; background: rgba(4, 4, 16, 0.62); }
.h2v-panel { width: min(var(--h2v-w, 480px), 94vw); max-height: 90vh; display: flex; flex-direction: column;
  background: var(--h2v-panel); border: 1px solid var(--h2v-edge-strong); border-radius: var(--h2v-r-dialog);
  box-shadow: 0 24px 64px rgba(0, 0, 0, 0.55); outline: none; animation: h2v-in 120ms ease-out; }
@keyframes h2v-in { from { opacity: 0; transform: scale(0.98); } to { opacity: 1; transform: none; } }
@media (prefers-reduced-motion: reduce) { .h2v-panel { animation: none; } }
.h2v-head { display: flex; gap: 12px; align-items: flex-start; padding: 16px 16px 12px 20px;
  border-bottom: 1px solid var(--h2v-edge); }
.h2v-head__text { flex: 1; min-width: 0; padding-top: 2px; }
.h2v-title { margin: 0; font-size: 15px; font-weight: 600; line-height: 1.3; color: var(--h2v-ink);
  overflow-wrap: anywhere; }
.h2v-sub { margin: 4px 0 0; font-size: 12.5px; color: var(--h2v-ink-soft); }
.h2v-x { flex: 0 0 auto; width: 32px; height: 32px; border-radius: var(--h2v-r-ctl); border: 1px solid transparent;
  background: transparent; color: var(--h2v-ink-soft); cursor: pointer; display: grid; place-items: center; }
.h2v-x:hover:not(:disabled) { background: var(--h2v-raised); color: var(--h2v-ink); }
.h2v-body { padding: 16px 20px; overflow: auto; display: flex; flex-direction: column; gap: 16px; }
.h2v-slot:empty { display: none; }
.h2v-slot { padding: 0 20px 12px; }
.h2v-foot { display: flex; gap: 12px; align-items: center; padding: 12px 16px 16px 20px;
  border-top: 1px solid var(--h2v-edge); }
.h2v-status { flex: 1; min-width: 0; font-size: 12px; color: var(--h2v-ink-soft); }
.h2v-actions { display: flex; gap: 8px; flex: 0 0 auto; }
.h2v :focus { outline: none; }
.h2v :focus-visible { outline: 2px solid var(--h2v-accent); outline-offset: 2px; }

.h2v-btn { height: 32px; padding: 0 14px; border-radius: var(--h2v-r-ctl); font: inherit; font-size: 12.5px;
  font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; white-space: nowrap;
  border: 1px solid var(--h2v-edge-strong); background: transparent; color: var(--h2v-ink); }
.h2v-btn:hover:not(:disabled) { border-color: var(--h2v-ink-dim); background: var(--h2v-raised); }
.h2v-btn--primary { background: var(--h2v-accent); border-color: var(--h2v-accent); color: var(--h2v-on-accent); }
.h2v-btn--primary:hover:not(:disabled) { background: var(--h2v-accent-hover); border-color: var(--h2v-accent-hover); }
.h2v-btn--danger { color: var(--h2v-danger); border-color: color-mix(in srgb, var(--h2v-danger) 55%, transparent); }
.h2v-btn--small { height: 26px; padding: 0 10px; font-size: 11.5px; }
.h2v-btn--text { border-color: transparent; padding: 0 8px; color: var(--h2v-ink-soft); font-weight: 500; }
.h2v-btn--text:hover:not(:disabled) { color: var(--h2v-ink); background: var(--h2v-raised); border-color: transparent; }
.h2v-btn:disabled { opacity: 0.55; cursor: default; }
.h2v-btn--primary:disabled { opacity: 0.8; }
.h2v-spin { width: 12px; height: 12px; border-radius: 50%; border: 2px solid currentColor;
  border-right-color: transparent; animation: h2v-spin 0.7s linear infinite; }
@keyframes h2v-spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .h2v-spin { animation-duration: 2.4s; } }

.h2v-field { display: flex; flex-direction: column; gap: 6px; }
.h2v-label { font-size: 12px; font-weight: 600; color: var(--h2v-ink-soft); }
.h2v-hint { font-size: 12px; color: var(--h2v-ink-dim); }
.h2v-input, .h2v-textarea { width: 100%; height: 34px; padding: 0 10px; border-radius: var(--h2v-r-ctl);
  border: 1px solid var(--h2v-edge-strong); background: var(--h2v-sunken); color: var(--h2v-ink); font: inherit;
  font-size: 13px; }
.h2v-textarea { height: auto; min-height: 64px; padding: 8px 10px; resize: vertical; font-family: ui-monospace,
  "Cascadia Mono", Consolas, monospace; font-size: 12px; }
.h2v-input::placeholder, .h2v-textarea::placeholder { color: var(--h2v-ink-dim); }
.h2v-input:hover:not(:disabled), .h2v-textarea:hover:not(:disabled) { border-color: var(--h2v-ink-dim); }
.h2v-input:focus-visible, .h2v-textarea:focus-visible { outline: none; border-color: var(--h2v-accent);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--h2v-accent) 35%, transparent); }
.h2v-input:disabled, .h2v-textarea:disabled { opacity: 0.6; }
.h2v-inputwrap { position: relative; display: flex; }
.h2v-inputwrap .h2v-input { padding-right: 64px; }
.h2v-inputwrap .h2v-btn { position: absolute; right: 3px; top: 3px; height: 28px; }
.h2v-meter { display: flex; align-items: center; gap: 8px; min-height: 16px; }
.h2v-meter__bars { display: grid; grid-template-columns: repeat(4, 1fr); gap: 4px; width: 120px; }
.h2v-meter__bars span { height: 4px; border-radius: 2px; background: var(--h2v-edge); }
.h2v-meter__text { font-size: 11.5px; color: var(--h2v-ink-soft); }
.h2v-row { display: flex; gap: 8px; align-items: center; }
.h2v-grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
@media (max-width: 560px) { .h2v-grid2 { grid-template-columns: 1fr; } }

.h2v-code { height: 44px; text-align: center; font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  font-size: 18px; letter-spacing: 0.3em; }
.h2v-clock { display: flex; align-items: center; gap: 8px; font-size: 11.5px; color: var(--h2v-ink-dim); }
.h2v-clock__bar { flex: 1; height: 3px; border-radius: 2px; background: var(--h2v-edge); overflow: hidden; }
.h2v-clock__bar span { display: block; height: 100%; background: var(--h2v-accent); transition: width 1s linear; }
@media (prefers-reduced-motion: reduce) { .h2v-clock__bar span { transition: none; } }

.h2v-choices { display: grid; gap: 8px; }
.h2v-choice { display: grid; grid-template-columns: 16px 1fr; gap: 4px 10px; padding: 10px 12px;
  border-radius: var(--h2v-r-card); border: 1px solid var(--h2v-edge-strong); background: var(--h2v-sunken);
  cursor: pointer; text-align: left; }
.h2v-choice:hover { border-color: var(--h2v-ink-dim); }
.h2v-choice[aria-checked="true"] { border-color: var(--h2v-accent);
  background: color-mix(in srgb, var(--h2v-accent) 10%, var(--h2v-sunken)); }
.h2v-choice__dot { grid-row: span 2; width: 16px; height: 16px; margin-top: 1px; border-radius: 50%;
  border: 1.5px solid var(--h2v-ink-dim); display: grid; place-items: center; }
.h2v-choice[aria-checked="true"] .h2v-choice__dot { border-color: var(--h2v-accent); }
.h2v-choice[aria-checked="true"] .h2v-choice__dot::after { content: ""; width: 8px; height: 8px;
  border-radius: 50%; background: var(--h2v-accent); }
.h2v-choice__title { display: flex; gap: 8px; align-items: center; font-weight: 600; font-size: 13px; }
.h2v-choice__sum { font-size: 12px; color: var(--h2v-ink-soft); }
.h2v-tag { font-size: 11px; font-weight: 600; padding: 1px 8px; border-radius: 999px;
  border: 1px solid var(--h2v-edge-strong); color: var(--h2v-ink-soft); }
.h2v-tag--ok { color: var(--h2v-ok); border-color: color-mix(in srgb, var(--h2v-ok) 45%, transparent); }
.h2v-tag--warn { color: var(--h2v-warn); border-color: color-mix(in srgb, var(--h2v-warn) 45%, transparent); }
.h2v-tag--accent { color: var(--h2v-accent); border-color: color-mix(in srgb, var(--h2v-accent) 45%, transparent); }

.h2v-facts { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0; padding: 12px;
  border-radius: var(--h2v-r-card); background: color-mix(in srgb, var(--h2v-sunken) 60%, transparent);
  border: 1px solid var(--h2v-edge); }
.h2v-facts dt { font-size: 12px; color: var(--h2v-ink-dim); }
.h2v-facts dd { margin: 0; font-size: 12.5px; color: var(--h2v-ink); }

.h2v-notice { display: flex; gap: 10px; padding: 10px 12px; border-radius: var(--h2v-r-card); font-size: 12.5px;
  border: 1px solid var(--h2v-edge); border-left: 3px solid var(--h2v-ink-dim); background: var(--h2v-sunken);
  color: var(--h2v-ink); white-space: pre-wrap; overflow-wrap: anywhere; }
.h2v-notice--info { border-left-color: var(--h2v-accent); }
.h2v-notice--ok { border-left-color: var(--h2v-ok); background: color-mix(in srgb, var(--h2v-ok) 8%, var(--h2v-sunken)); }
.h2v-notice--warn { border-left-color: var(--h2v-warn); background: color-mix(in srgb, var(--h2v-warn) 8%, var(--h2v-sunken)); }
.h2v-notice--danger { border-left-color: var(--h2v-danger); background: color-mix(in srgb, var(--h2v-danger) 9%, var(--h2v-sunken)); }

.h2v-copy { display: flex; gap: 8px; align-items: stretch; }
.h2v-copy__val { flex: 1; min-width: 0; padding: 8px 10px; border-radius: var(--h2v-r-ctl); background: var(--h2v-sunken);
  border: 1px solid var(--h2v-edge); font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12px;
  word-break: break-all; user-select: all; color: var(--h2v-ink); }
.h2v-copy .h2v-btn { align-self: center; }

.h2v-capsule { display: flex; flex-direction: column; gap: 8px; padding: 12px; border-radius: var(--h2v-r-card);
  border: 1px dashed var(--h2v-edge-strong); background: color-mix(in srgb, var(--h2v-sunken) 70%, transparent); }
.h2v-capsule__flow { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.h2v-chips { display: flex; gap: 6px; flex-wrap: wrap; flex: 1; min-width: 0; }
.h2v-chip { max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px;
  padding: 3px 10px; border-radius: 999px; background: var(--h2v-raised); border: 1px solid var(--h2v-edge-strong);
  color: var(--h2v-ink); }
.h2v-chip--more { color: var(--h2v-ink-soft); background: transparent; }
.h2v-arrow { color: var(--h2v-ink-dim); flex: 0 0 auto; }
.h2v-capsule__meta { font-size: 12px; color: var(--h2v-ink-soft); }

.h2v-seal { flex: 0 0 auto; display: grid; place-items: center; border-radius: 8px; color: var(--h2v-accent);
  background: color-mix(in srgb, currentColor 12%, var(--h2v-sunken));
  box-shadow: inset 0 0 0 1px color-mix(in srgb, currentColor 45%, transparent); }
.h2v-seal--ok { color: var(--h2v-ok); }
.h2v-seal--warn { color: var(--h2v-warn); }
.h2v-seal--danger { color: var(--h2v-danger); }

.h2v-disc { border: 1px solid var(--h2v-edge); border-radius: var(--h2v-r-card); }
.h2v-disc > summary { list-style: none; cursor: pointer; padding: 8px 12px; font-size: 12.5px; font-weight: 600;
  color: var(--h2v-ink-soft); display: flex; gap: 8px; align-items: center; border-radius: var(--h2v-r-card); }
.h2v-disc > summary::-webkit-details-marker { display: none; }
.h2v-disc > summary::before { content: ""; width: 6px; height: 6px; border-right: 1.5px solid currentColor;
  border-bottom: 1.5px solid currentColor; transform: rotate(-45deg); transition: transform 120ms; }
.h2v-disc[open] > summary::before { transform: rotate(45deg); }
.h2v-disc__body { padding: 4px 12px 12px; display: flex; flex-direction: column; gap: 8px; }

.h2v-switch { display: flex; align-items: center; gap: 10px; background: none; border: 0; padding: 0;
  color: var(--h2v-ink); font: inherit; font-size: 13px; font-weight: 600; cursor: pointer; }
.h2v-switch__track { width: 30px; height: 18px; border-radius: 999px; background: var(--h2v-edge-strong);
  position: relative; transition: background 120ms; }
.h2v-switch__track::after { content: ""; position: absolute; top: 2px; left: 2px; width: 14px; height: 14px;
  border-radius: 50%; background: var(--h2v-ink); transition: transform 120ms; }
.h2v-switch[aria-checked="true"] .h2v-switch__track { background: var(--h2v-accent); }
.h2v-switch[aria-checked="true"] .h2v-switch__track::after { transform: translateX(12px);
  background: var(--h2v-on-accent); }

.h2v-step { display: grid; grid-template-columns: 24px 1fr; gap: 4px 12px; }
.h2v-step__n { width: 24px; height: 24px; border-radius: 50%; display: grid; place-items: center; font-size: 12px;
  font-weight: 700; color: var(--h2v-accent); box-shadow: inset 0 0 0 1.5px var(--h2v-accent); }
.h2v-step__title { margin: 0; font-size: 13px; font-weight: 600; align-self: center; }
.h2v-step__body { grid-column: 2; display: flex; flex-direction: column; gap: 8px; }

.h2v-badge { font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 999px; white-space: nowrap;
  color: var(--h2v-ok); background: color-mix(in srgb, var(--h2v-ok) 12%, transparent); }
.h2v-keyrow { display: grid; grid-template-columns: 160px 1fr auto; gap: 8px; align-items: center; }
.h2v-keyrow .h2v-input { height: 30px; font-size: 12.5px; }
.h2v-keycode { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px;
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; color: var(--h2v-ink-soft); }
.h2v-list { display: flex; flex-direction: column; gap: 6px; }
.h2v-block { display: flex; flex-direction: column; gap: 8px; }
.h2v-block__title { margin: 0; font-size: 13px; font-weight: 600; }
.h2v-block__hint { margin: -4px 0 0; font-size: 12px; color: var(--h2v-ink-dim); }
.h2v-check { display: flex; gap: 8px; align-items: center; font-size: 12.5px; cursor: pointer; }
.h2v-check input { width: 16px; height: 16px; accent-color: var(--h2v-accent); margin: 0; }
.h2v-qr { flex: 0 0 auto; width: 184px; height: 184px; padding: 8px; border-radius: var(--h2v-r-card);
  background: #ffffff; }
.h2v-qr img { display: block; width: 168px; height: 168px; image-rendering: pixelated; }
.h2v-codes { display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px 16px; padding: 10px 12px;
  border-radius: var(--h2v-r-ctl); background: var(--h2v-sunken); border: 1px solid var(--h2v-edge);
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12.5px; user-select: all; }
.h2v-dim { font-size: 12px; color: var(--h2v-ink-dim); margin: 0; }

.h2v-card { display: flex; gap: 10px; align-items: center; width: 100%; height: 100%; padding: 8px 10px;
  border-radius: var(--h2v-r-card); background: color-mix(in srgb, var(--h2v-sunken) 85%, transparent);
  border: 1px solid var(--h2v-edge); overflow: hidden; }
.h2v-card__text { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 1px; }
.h2v-card__title { font-size: 12.5px; font-weight: 600; white-space: nowrap; overflow: hidden;
  text-overflow: ellipsis; color: var(--h2v-ink); }
.h2v-card__title--warn { color: var(--h2v-warn); }
.h2v-card__detail { font-size: 11.5px; color: var(--h2v-ink-soft); white-space: nowrap; overflow: hidden;
  text-overflow: ellipsis; }
.h2v-card__meta { font-size: 11px; color: var(--h2v-ink-dim); white-space: nowrap; overflow: hidden;
  text-overflow: ellipsis; }
.h2v-card__meta--ok { color: var(--h2v-ok); }
`;

export function ensureVaultStyles() {
  if (typeof document === "undefined") return;
  if (document.getElementById(STYLE_ID)) return;
  const s = document.createElement("style");
  s.id = STYLE_ID;
  s.textContent = CSS;
  document.head.appendChild(s);
}

// ── tiny DOM helpers ───────────────────────────────────────────────────────────────────────────────────────────
let UID = 0;
const uid = (p) => `h2v-${p}-${++UID}`;

/** el("div", {class, text, attrs..., on: {click}}, children) - text only, never HTML. */
export function el(tag, props = {}, kids = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k === "style") Object.assign(e.style, v);
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) e.addEventListener(ev, fn);
    else if (k in e && typeof e[k] !== "function" && !k.startsWith("aria") && k !== "role") {
      try { e[k] = v; } catch (_) { e.setAttribute(k, v); }
    } else e.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of [].concat(kids)) if (c != null && c !== false) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}

const SVG = "http://www.w3.org/2000/svg";
function svg(tag, attrs = {}, kids = []) {
  const e = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
  for (const c of kids) e.append(c);
  return e;
}

/** The seal: a padlock in a ringed tile - the Vault's one recurring mark. */
export function sealGlyph({ size = 36, tone = "accent" } = {}) {
  ensureVaultStyles();
  const g = Math.round(size * 0.56);
  const icon = svg("svg", { width: g, height: g, viewBox: "0 0 24 24", fill: "none", "aria-hidden": "true",
    focusable: "false" }, [
    svg("path", { d: "M7.5 10.5V8a4.5 4.5 0 0 1 9 0v2.5", stroke: "currentColor", "stroke-width": "1.8",
      "stroke-linecap": "round" }),
    svg("rect", { x: "4.5", y: "10.5", width: "15", height: "10", rx: "2.2", fill: "currentColor", "fill-opacity": "0.18",
      stroke: "currentColor", "stroke-width": "1.8" }),
    svg("circle", { cx: "12", cy: "14.6", r: "1.5", fill: "currentColor" }),
    svg("path", { d: "M12 15.8v2", stroke: "currentColor", "stroke-width": "1.8", "stroke-linecap": "round" }),
  ]);
  const tile = el("span", { class: `h2v-seal${tone && tone !== "accent" ? ` h2v-seal--${tone}` : ""}`,
    "aria-hidden": "true", style: { width: `${size}px`, height: `${size}px`, borderRadius: `${Math.round(size / 4.5)}px` } },
  [icon]);
  return tile;
}

function closeIcon() {
  return svg("svg", { width: 14, height: 14, viewBox: "0 0 14 14", "aria-hidden": "true", focusable: "false" }, [
    svg("path", { d: "M3 3l8 8M11 3l-8 8", stroke: "currentColor", "stroke-width": "1.6", "stroke-linecap": "round" })]);
}

function arrowIcon() {
  return svg("svg", { width: 28, height: 14, viewBox: "0 0 28 14", class: "h2v-arrow", "aria-hidden": "true",
    focusable: "false" }, [
    svg("path", { d: "M2 7h22M19 2.5L24 7l-5 4.5", stroke: "currentColor", "stroke-width": "1.6", fill: "none",
      "stroke-linecap": "round", "stroke-linejoin": "round" })]);
}

/** A button. kind: "primary" | "secondary" (default) | "danger" | "text"; small: compact height. */
export function vbutton(label, { kind = "secondary", small = false, onClick, ariaLabel, type = "button" } = {}) {
  ensureVaultStyles();
  const b = el("button", { type, class: `h2v-btn${kind !== "secondary" ? ` h2v-btn--${kind}` : ""}` +
    (small ? " h2v-btn--small" : ""), "aria-label": ariaLabel || null });
  b.append(el("span", { class: "h2v-btn__label", text: label }));
  if (onClick) b.addEventListener("click", onClick);
  return b;
}

function setButtonBusy(b, on, label) {
  if (!b) return;
  if (on) {
    if (b.__vaultLabel == null) b.__vaultLabel = b.querySelector(".h2v-btn__label")?.textContent ?? b.textContent;
    b.replaceChildren(el("span", { class: "h2v-spin", "aria-hidden": "true" }),
      el("span", { class: "h2v-btn__label", text: label || b.__vaultLabel }));
  } else if (b.__vaultLabel != null) {
    b.replaceChildren(el("span", { class: "h2v-btn__label", text: b.__vaultLabel }));
    b.__vaultLabel = null;
  }
}

// ── the dialog shell ───────────────────────────────────────────────────────────────────────────────────────────
const FOCUSABLE = "button:not([disabled]), input:not([disabled]):not([type=hidden]), textarea:not([disabled]), " +
  "select:not([disabled]), summary, [tabindex]:not([tabindex='-1'])";

/**
 * A modal dialog. Returns a controller; `result` resolves with whatever close() gets (Esc / the close button: null).
 * Focus is trapped while open and returned on close; key presses never reach the canvas behind it.
 */
export function vaultDialog({ title, subtitle = "", width = 480, tone = "accent" } = {}) {
  ensureVaultStyles();
  const tid = uid("title"), sid = uid("sub");
  const prevFocus = document.activeElement;
  let busy = false, done = false, submit = null, resolveFn;
  const cleanups = [];
  const result = new Promise((r) => { resolveFn = r; });
  const xBtn = el("button", { type: "button", class: "h2v-x", "aria-label": "Close" }, [closeIcon()]);
  const titleEl = el("h2", { class: "h2v-title", id: tid, text: title });
  const head = el("div", { class: "h2v-head" }, [sealGlyph({ size: 36, tone }),
    el("div", { class: "h2v-head__text" }, [titleEl, subtitle ? el("p", { class: "h2v-sub", id: sid,
      text: subtitle }) : null]), xBtn]);
  const body = el("div", { class: "h2v-body" });
  const slot = el("div", { class: "h2v-slot" });
  const statusEl = el("div", { class: "h2v-status", role: "status", "aria-live": "polite" });
  const actions = el("div", { class: "h2v-actions" });
  const footer = el("div", { class: "h2v-foot" }, [statusEl, actions]);
  const panel = el("div", { class: "h2v-panel", role: "dialog", "aria-modal": "true", "aria-labelledby": tid,
    "aria-describedby": subtitle ? sid : null, tabindex: "-1", style: { "--h2v-w": `${width}px` } },
  [head, body, slot, footer]);
  panel.style.setProperty("--h2v-w", `${width}px`);
  const back = el("div", { class: "h2v h2v-backdrop" }, [panel]);
  let primaryBtn = null;

  const close = (value = null) => {
    if (done) return;
    done = true;
    for (const fn of cleanups.splice(0)) { try { fn(); } catch (_) { /* cleanup only */ } }
    for (const i of panel.querySelectorAll("input[type=password], input.h2v-secret")) i.value = "";
    back.remove();
    try { if (prevFocus && typeof prevFocus.focus === "function" && document.contains(prevFocus)) prevFocus.focus(); }
    catch (_) { /* focus is a nicety */ }
    resolveFn(value);
  };
  xBtn.addEventListener("click", () => { if (!busy) close(null); });
  panel.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      if (!busy) close(null);
    } else if (e.key === "Tab") {
      const f = [...panel.querySelectorAll(FOCUSABLE)].filter((x) => x.offsetParent !== null || x === document.activeElement);
      if (f.length) {
        const first = f[0], last = f[f.length - 1];
        if (e.shiftKey && (document.activeElement === first || !panel.contains(document.activeElement))) {
          e.preventDefault(); last.focus();
        } else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    } else if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
      const t = e.target;
      if (t?.tagName === "INPUT" && t.type !== "checkbox" && submit && !busy) { e.preventDefault(); submit(); }
    }
    e.stopPropagation();        // canvas shortcuts (h, v, Delete, Ctrl+Z ...) never fire while a dialog is open
  });
  for (const ev of ["keyup", "keypress"]) panel.addEventListener(ev, (e) => e.stopPropagation());
  document.body.append(back);

  const api = {
    root: back, panel, body, footer, result, close,
    get busy() { return busy; },
    addAction(label, { primary = false, danger = false, onClick } = {}) {
      const b = vbutton(label, { kind: primary ? "primary" : danger ? "danger" : "secondary", onClick });
      actions.append(b);
      if (primary) primaryBtn = b;
      return b;
    },
    setBusy(on, label) {
      busy = !!on;
      panel.setAttribute("aria-busy", busy ? "true" : "false");
      for (const c of panel.querySelectorAll("input, button, textarea, select")) {
        if (busy) { if (!c.disabled) { c.disabled = true; c.__vaultBusy = true; } }
        else if (c.__vaultBusy) { c.disabled = false; c.__vaultBusy = false; }
      }
      setButtonBusy(primaryBtn, busy, label);
    },
    status(text) { statusEl.textContent = text || ""; },
    notice(tone, text) {
      slot.replaceChildren();
      if (tone && text) slot.append(noticeEl(tone, text));
    },
    onSubmit(fn) { submit = fn; },
    onCleanup(fn) { cleanups.push(fn); },
    focusFirst() {
      const f = panel.querySelector("input:not([disabled]):not([type=checkbox]), textarea:not([disabled])")
        ?? panel.querySelector(FOCUSABLE);
      (f ?? panel).focus();
    },
  };
  setTimeout(() => { if (!done) api.focusFirst(); }, 0);
  return api;
}

// ── fields ─────────────────────────────────────────────────────────────────────────────────────────────────────
/** A labelled row around any control. */
export function field({ label, hint, control, id }) {
  ensureVaultStyles();
  const cid = id || control?.id || uid("f");
  const target = control?.matches?.("input, textarea, select") ? control : control?.querySelector?.("input, textarea, select");
  if (target && !target.id) target.id = cid;
  const lab = el("label", { class: "h2v-label", text: label, for: target?.id || cid });
  const kids = [lab, control];
  if (hint) {
    const h = el("div", { class: "h2v-hint", id: uid("h"), text: hint });
    if (target) target.setAttribute("aria-describedby", h.id);
    kids.push(h);
  }
  return el("div", { class: "h2v-field" }, kids);
}

export function textField({ label, value = "", placeholder = "", autocomplete = "off", hint, maxLength } = {}) {
  const input = el("input", { type: "text", class: "h2v-input", value, placeholder, autocomplete,
    spellcheck: false, maxLength: maxLength || null });
  return { el: field({ label, hint, control: input }), input };
}

export function textArea({ label, placeholder = "", rows = 3, hint } = {}) {
  const input = el("textarea", { class: "h2v-textarea", placeholder, rows, spellcheck: false });
  return { el: field({ label, hint, control: input }), input };
}

const PW_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*-_=+";
function generatePassword(len = 20) {
  const buf = new Uint32Array(len);
  crypto.getRandomValues(buf);
  let out = "";
  for (let i = 0; i < len; i++) out += PW_ALPHABET[buf[i] % PW_ALPHABET.length];
  return out;
}

/** Password input with Show / Hide, an optional strength meter and an optional Generate. */
export function passwordField({ label, autocomplete = "new-password", strength = false, generate = false, hint,
  placeholder = "", onGenerate } = {}) {
  ensureVaultStyles();
  const input = el("input", { type: "password", class: "h2v-input", autocomplete, placeholder, spellcheck: false });
  const toggle = vbutton("Show", { kind: "text", small: true, ariaLabel: `Show ${label.toLowerCase()}` });
  toggle.setAttribute("aria-pressed", "false");
  toggle.addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    if (show) input.classList.add("h2v-secret"); else input.classList.remove("h2v-secret");
    toggle.setAttribute("aria-pressed", show ? "true" : "false");
    toggle.querySelector(".h2v-btn__label").textContent = show ? "Hide" : "Show";
    toggle.setAttribute("aria-label", `${show ? "Hide" : "Show"} ${label.toLowerCase()}`);
  });
  const wrap = el("div", { class: "h2v-inputwrap" }, [input, toggle]);
  const extra = [];
  let meter = null;
  if (strength) {
    const bars = el("div", { class: "h2v-meter__bars", "aria-hidden": "true" },
      [0, 1, 2, 3].map(() => el("span")));
    const txt = el("span", { class: "h2v-meter__text" });
    meter = el("div", { class: "h2v-meter" }, [bars, txt]);
    const paint = () => {
      const s = passwordStrength(input.value);
      const col = !s.ok ? "var(--h2v-danger)" : s.score <= 1 ? "var(--h2v-warn)" : "var(--h2v-ok)";
      [...bars.children].forEach((b, i) => {
        b.style.background = input.value && i < Math.max(1, s.score) ? col : "";
      });
      txt.textContent = s.label ? `Strength: ${s.label}` : "At least 8 characters";
      txt.style.color = !input.value ? "" : !s.ok ? "var(--h2v-danger)" : "";
    };
    input.addEventListener("input", paint);
    paint();
  }
  const genOut = el("div");
  if (generate) {
    const gen = vbutton("Generate a strong password", { kind: "text", small: true });
    gen.addEventListener("click", () => {
      const pw = generatePassword(20);
      input.value = pw;
      input.dispatchEvent(new Event("input", { bubbles: true }));
      genOut.replaceChildren(copyRow({ label: "generated password", value: pw }),
        el("p", { class: "h2v-dim", text: "Shown once. Store it in your password manager before you lock." }));
      onGenerate?.(pw);
    });
    extra.push(el("div", { class: "h2v-row", style: { justifyContent: "space-between" } }, [meter, gen]));
  } else if (meter) extra.push(meter);
  const f = field({ label, hint, control: wrap });
  if (extra.length) f.append(...extra);
  f.append(genOut);
  if (isInsecurePage(globalThis.location)) f.append(noticeEl("warn", INSECURE_TEXT));      // V5 design 7.2
  return { el: f, input, value: () => input.value, clear: () => { input.value = ""; genOut.replaceChildren();
    input.dispatchEvent(new Event("input")); }, setValue: (v) => { input.value = v; input.dispatchEvent(new Event("input")); } };
}

/** The authenticator code: one input + a bar showing when the code changes. */
export function codeField({ label = "Authenticator code", period = 30, allowRecovery = false, hint } = {}) {
  ensureVaultStyles();
  // inputmode stays "numeric" (the common case is the 6-digit code); allowRecovery only lets a recovery code fit
  const input = el("input", { type: "text", class: "h2v-input h2v-code", autocomplete: "one-time-code",
    maxLength: allowRecovery ? 11 : 6, spellcheck: false, placeholder: "123456" });
  input.setAttribute("inputmode", "numeric");
  const fill = el("span");
  const txt = el("span");
  const clock = el("div", { class: "h2v-clock" }, [el("div", { class: "h2v-clock__bar", "aria-hidden": "true" },
    [fill]), txt]);
  const tick = () => {
    const s = secondsLeft(Date.now(), period);
    fill.style.width = `${(s / period) * 100}%`;
    txt.textContent = `New code in ${s} s`;
  };
  tick();
  // h2v-allow-interval: a 1 s countdown only while an auth dialog is open; destroy() (dialog cleanup) clears it
  const timer = setInterval(tick, 1000); // h2v-allow-interval: cleared by destroy()
  const f = field({ label, hint, control: input });
  f.append(clock);
  return { el: f, input, value: () => input.value.replace(/\s/g, ""), clear: () => { input.value = ""; },
    destroy: () => clearInterval(timer) };
}

/** An APG radio group of cards. Disabled options are left out (say why elsewhere, never a dead control). */
export function choiceCards({ label, options, value, onChange }) {
  ensureVaultStyles();
  const opts = options.filter((o) => !o.disabled);
  let cur = opts.some((o) => o.id === value) ? value : opts[0]?.id;
  const group = el("div", { class: "h2v-choices", role: "radiogroup", "aria-label": label });
  const cards = opts.map((o) => {
    const tagCls = o.tone === "warn" ? " h2v-tag--warn" : o.tone === "ok" ? " h2v-tag--ok" : "";
    const c = el("div", { class: "h2v-choice", role: "radio", "data-id": o.id }, [
      el("span", { class: "h2v-choice__dot", "aria-hidden": "true" }),
      el("span", { class: "h2v-choice__title" }, [o.title, o.tag ? el("span", { class: `h2v-tag${tagCls}`,
        text: o.tag }) : null]),
      el("span", { class: "h2v-choice__sum", text: o.summary || "" })]);
    c.addEventListener("click", () => set(o.id, true));
    return c;
  });
  const sync = () => cards.forEach((c, i) => {
    const on = opts[i].id === cur;
    c.setAttribute("aria-checked", on ? "true" : "false");
    c.tabIndex = on ? 0 : -1;
  });
  function set(id, fire) {
    if (!opts.some((o) => o.id === id)) return;
    const changed = id !== cur;
    cur = id;
    sync();
    if (fire && changed) onChange?.(id);
  }
  group.addEventListener("keydown", (e) => {
    const i = opts.findIndex((o) => o.id === cur);
    let j = null;
    if (e.key === "ArrowDown" || e.key === "ArrowRight") j = (i + 1) % opts.length;
    else if (e.key === "ArrowUp" || e.key === "ArrowLeft") j = (i - 1 + opts.length) % opts.length;
    else if (e.key === " " || e.key === "Enter") { e.preventDefault(); return; }
    if (j == null) return;
    e.preventDefault();
    set(opts[j].id, true);
    cards[j].focus();
  });
  group.append(...cards);
  sync();
  return { el: el("div", { class: "h2v-field" }, [el("div", { class: "h2v-label", text: label }), group]),
    value: () => cur, set: (id) => set(id, true) };
}

export function factList(pairs) {
  ensureVaultStyles();
  const dl = el("dl", { class: "h2v-facts" });
  for (const [k, v] of pairs) if (v) dl.append(el("dt", { text: k }), el("dd", { text: v }));
  return dl;
}

/** A notice block. Errors and warnings are announced (role=alert). */
export function noticeEl(tone, text) {
  ensureVaultStyles();
  return el("div", { class: `h2v-notice h2v-notice--${tone}`,
    role: tone === "danger" || tone === "warn" ? "alert" : "status", text });
}

export function copyRow({ label, value, display, mono = true } = {}) {
  ensureVaultStyles();
  const val = el("div", { class: "h2v-copy__val", text: display ?? value, title: value });
  if (!mono) val.style.fontFamily = "inherit";
  const b = vbutton("Copy", { small: true, ariaLabel: `Copy ${label}` });
  let t = null;
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(String(value ?? ""));
      b.querySelector(".h2v-btn__label").textContent = "Copied";
      clearTimeout(t);
      t = setTimeout(() => { b.querySelector(".h2v-btn__label").textContent = "Copy"; }, 1500);
    } catch (_) {
      const r = document.createRange();
      r.selectNodeContents(val);
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(r);
    }
  });
  return el("div", { class: "h2v-copy" }, [val, b]);
}

/** The selection capsule: these nodes -> one locked node. */
export function capsule({ chips = [], more = 0, inputs = 0, outputs = 0 }) {
  ensureVaultStyles();
  const list = el("div", { class: "h2v-chips" }, chips.map((t) => el("span", { class: "h2v-chip", text: t,
    title: t })));
  if (more > 0) list.append(el("span", { class: "h2v-chip h2v-chip--more", text: `+${more} more` }));
  const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
  return el("div", { class: "h2v-capsule" }, [
    el("div", { class: "h2v-capsule__flow" }, [list, arrowIcon(), sealGlyph({ size: 28 })]),
    el("div", { class: "h2v-capsule__meta", text: `${plural(inputs, "input")} · ${plural(outputs, "output")} ` +
      "on the vault node" })]);
}

export function disclosure(title, { open = false } = {}) {
  ensureVaultStyles();
  const body = el("div", { class: "h2v-disc__body" });
  const d = el("details", { class: "h2v-disc" }, [el("summary", { text: title }), body]);
  d.open = !!open;
  return { el: d, body };
}

export function switchRow(label, { checked = false, onChange } = {}) {
  ensureVaultStyles();
  const b = el("button", { type: "button", class: "h2v-switch", role: "switch", "aria-checked": checked ? "true" : "false" },
    [el("span", { class: "h2v-switch__track", "aria-hidden": "true" }), el("span", { text: label })]);
  let on = !!checked;
  b.addEventListener("click", () => { on = !on; b.setAttribute("aria-checked", on ? "true" : "false"); onChange?.(on); });
  return { el: b, checked: () => on };
}

export function stepSection(n, title, ...children) {
  ensureVaultStyles();
  return el("section", { class: "h2v-step" }, [
    el("span", { class: "h2v-step__n", text: String(n), "aria-hidden": "true" }),
    el("h3", { class: "h2v-step__title", text: title }),
    el("div", { class: "h2v-step__body" }, children.filter(Boolean))]);
}

export function block(title, hint, ...children) {
  ensureVaultStyles();
  return el("section", { class: "h2v-block" }, [el("h3", { class: "h2v-block__title", text: title }),
    hint ? el("p", { class: "h2v-block__hint", text: hint }) : null, ...children.filter(Boolean)]);
}

/** The vault node's body: seal + what it is + run state + one action. Display only. */
export function statusCard() {
  ensureVaultStyles();
  const sealHost = el("span");
  const title = el("div", { class: "h2v-card__title" });
  const detail = el("div", { class: "h2v-card__detail" });
  const meta = el("div", { class: "h2v-card__meta" });
  const actHost = el("span");
  const root = el("div", { class: "h2v h2v-card" }, [sealHost,
    el("div", { class: "h2v-card__text" }, [title, detail, meta]), actHost]);
  for (const ev of ["pointerdown", "mousedown"]) actHost.addEventListener(ev, (e) => e.stopPropagation());
  let lastTone = null;
  return {
    el: root,
    update({ tone = "accent", title: t = "", detail: d = "", meta: m = "", metaTone = "", action = null } = {}) {
      if (tone !== lastTone) { sealHost.replaceChildren(sealGlyph({ size: 26, tone })); lastTone = tone; }
      title.textContent = t;
      title.className = `h2v-card__title${tone === "warn" ? " h2v-card__title--warn" : ""}`;
      detail.textContent = d;
      detail.style.display = d ? "" : "none";
      meta.textContent = m;
      meta.className = `h2v-card__meta${metaTone === "ok" ? " h2v-card__meta--ok" : ""}`;
      meta.style.display = m ? "" : "none";
      actHost.replaceChildren(action ? vbutton(action.label, { small: true, onClick: (e) => { e.stopPropagation();
        action.onClick?.(); }, ariaLabel: action.ariaLabel }) : "");
    },
  };
}
