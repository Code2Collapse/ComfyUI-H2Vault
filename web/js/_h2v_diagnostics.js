// H2Vault (AGPL-3.0) - security check panel, the pure part (L9.341: security capability registry, fail closed).
// No DOM at import, no ComfyUI import: tests run it under node (tests/test_diagnostics_frontend.mjs).

export const STATUS_TEXT = Object.freeze({
  active: "Active",
  failed: "Not working",
  unavailable: "Unavailable",
  not_needed: "Not needed here",
  off: "Off",
  not_checked: "Not checked",
});

export const GROUPS = Object.freeze([
  { id: "problem", title: "Not working (concealed vaults are refused)", tone: "danger" },
  { id: "active", title: "Active", tone: "ok" },
  { id: "optional", title: "Optional, unavailable", tone: "warn" },
  { id: "idle", title: "Not needed on this ComfyUI", tone: "muted" },
]);

/** Which group a capability row belongs to. */
export function groupOf(cap) {
  if (!cap) return "idle";
  if (cap.status === "active") return "active";
  if (cap.ok) return "idle";                              // not_needed / off
  return cap.critical ? "problem" : "optional";
}

/** The report -> [{group, rows}] in GROUPS order, empty groups left out. */
export function groupRows(report) {
  const caps = Array.isArray(report?.capabilities) ? report.capabilities : [];
  return GROUPS.map((g) => ({ group: g, rows: caps.filter((c) => groupOf(c) === g.id) }))
    .filter((x) => x.rows.length);
}

/** The head line: {tone, text}. */
export function headline(report) {
  const s = report?.summary || {};
  if (s.state === "refusing") return { tone: "danger", text: s.message || "Concealed vaults are refused." };
  if (s.state === "protected") return { tone: "ok", text: s.message || "Every critical protection is active." };
  return { tone: "info", text: s.message || "The security check has not run." };
}

/** One row's secondary text: what it protects, why it failed, what to do. */
export function rowText(cap) {
  const parts = [];
  if (cap?.protects) parts.push(`Protects ${cap.protects}.`);
  if (cap?.detail) parts.push(cap.ok ? cap.detail : `Problem: ${cap.detail}.`);
  if (!cap?.ok && cap?.action) parts.push(cap.action);
  return parts.join(" ");
}

/** Version facts for the panel foot. */
export function versionFacts(report, frontend) {
  const v = report?.versions || {};
  const core = v.comfyui ? `${v.comfyui}${v.comfyui_tested ? "" : " (not in the tested list: " +
    (v.tested_comfyui || []).join(", ") + ")"}` : "unknown";
  return [["ComfyUI", core], ["Front end", frontend || "unknown"], ["H2Vault", v.h2vault || "unknown"],
    ["Python", v.python || "unknown"]];
}

/** "checked 3 min ago" style text from an epoch-seconds stamp. */
export function checkedText(epochSeconds, nowMs = Date.now()) {
  if (!epochSeconds) return "Not checked yet.";
  const s = Math.max(0, Math.round(nowMs / 1000 - epochSeconds));
  if (s < 60) return "Checked just now.";
  const m = Math.round(s / 60);
  if (m < 60) return `Checked ${m} min ago.`;
  const h = Math.round(m / 60);
  return `Checked ${h} h ago.`;
}
