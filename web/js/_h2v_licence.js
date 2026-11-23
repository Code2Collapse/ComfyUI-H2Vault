// H2Vault (AGPL-3.0) - workstream V5, offline licences (docs/h2vault/V5_enhancements_design.md section 6): the pure
// part of the licence UI - status lines, the "valid until" choices and the terms sent to /h2vault/licence/issue.
// What licences are (review P1-1): they stop casual sharing of the workflow FILE - without a licence for that
// installation it does not run. They are not DRM: a workflow has ONE licence key shared by every licensee, so a
// determined licensee can extract it from their own machine and pass it on; revoking = a new licence key.
// The idea of per-recipient access keys with an expiry was inspired by ComfyUI-XLJworkflowCipher (weiqing1987); no
// code or text was taken from it. See NOTICE. No DOM, no ComfyUI import (tests run it under node).

export const HONOUR_NOTE = "A licence stops casual sharing: the workflow file alone does not run without a licence " +
  "for that installation. It is not copy protection: someone who has a licence can, with effort, extract the " +
  "workflow's licence key on their own machine and pass it on. End dates and run limits are kept by H2Vault on " +
  "their computer and can be ignored by modified software. To cut people off, revoke (new licence key) and send " +
  "the new copy only to the others.";

export const EXPIRY_CHOICES = Object.freeze([
  { value: "none", label: "No end date" },
  { value: "7", label: "7 days" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
  { value: "date", label: "Until a date…" },
]);

const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
  "November", "December"];

/** "3 March 2027" in UTC, like the server's messages. */
export function fmtDate(unix) {
  const d = new Date(Number(unix) * 1000);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

/**
 * The terms for /h2vault/licence/issue from the dialog's raw values.
 * choice: an EXPIRY_CHOICES value; date: "YYYY-MM-DD" (end of that day, UTC); runs: "" or a whole number.
 * -> {ok: true, terms: {exp_days?|exp?, runs}} | {ok: false, error}
 */
export function licenceTerms({ choice = "none", date = "", runs = "" } = {}, nowMs = Date.now()) {
  const terms = { runs: null };
  if (choice === "date") {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(date || "").trim());
    if (!m) return { ok: false, error: "Pick the last day the licence is valid." };
    const exp = Math.floor(Date.UTC(+m[1], +m[2] - 1, +m[3], 23, 59, 59) / 1000);
    if (exp * 1000 <= nowMs) return { ok: false, error: "That day is already over. Pick a later date." };
    terms.exp = exp;
  } else if (choice !== "none") {
    const days = Number(choice);
    if (!Number.isInteger(days) || days < 1) return { ok: false, error: "Choose how long the licence is valid." };
    terms.exp_days = days;
  }
  const r = String(runs ?? "").trim();
  if (r) {
    if (!/^\d+$/.test(r) || Number(r) < 1) return { ok: false, error: "The run limit must be a whole number of at least 1." };
    terms.runs = Number(r);
  }
  return { ok: true, terms };
}

/** One line for the vault's status card from /h2vault/licence/status. -> {tone, title, meta} */
export function licenceLine(st) {
  if (!st || st.licensed_vault === false) return null;
  if (!st.licensed) {
    return { tone: "warn", title: "Licence needed", meta: String(st.problem || "No licence for this installation yet.") };
  }
  const l = st.licence || {};
  const until = l.exp ? `until ${fmtDate(l.exp)}` : "no end date";
  const runs = l.runs_left == null ? "" : ` · ${l.runs_left} run${l.runs_left === 1 ? "" : "s"} left`;
  return { tone: "ok", title: "Licensed on this installation", meta: `${l.label ? `${l.label} · ` : ""}${until}${runs}` };
}

/** Ledger row -> words for the "Licences issued" list. */
export function ledgerState(row) {
  const until = row?.exp ? fmtDate(row.exp) : "no end date";
  const runs = row?.runs ? ` · ${row.runs} runs` : "";
  const state = row?.state === "ended" ? "Ended" : row?.state === "expiring" ? "Ends within 7 days" : "Active";
  return { state, detail: `${until}${runs}` };
}
