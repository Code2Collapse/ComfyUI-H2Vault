// H2Vault (AGPL-3.0) - H2Vault menu > Security check (L9.341: security capability registry, fail closed).
// Shows which protections are active, which are not working (concealed vaults are then refused), which optional
// ones are unavailable, the versions, and what to do. Data: GET /h2vault/diagnostics; "Check again" runs the
// server's full self-test (POST /h2vault/diagnostics/selftest). Both answer only the page on this machine.
import { app } from "../../scripts/app.js";
import { api } from "../../scripts/api.js";
import { el, factList, noticeEl, vaultDialog } from "./_h2v_ui.js";
import { STATUS_TEXT, checkedText, groupRows, headline, rowText, versionFacts } from "./_h2v_diagnostics.js";

const TONE_COLOR = { danger: "var(--h2v-danger)", ok: "var(--h2v-ok)", warn: "var(--h2v-warn)",
  muted: "var(--h2v-ink-dim)" };

async function call(route, method = "GET") {
  try {
    const r = await api.fetchApi(route, method === "POST" ? { method, headers: { "Content-Type": "application/json" },
      body: "{}" } : { method });
    let data = {};
    try { data = await r.json(); } catch (_) { /* keep {} */ }
    return { ok: r.ok && data.ok !== false, status: r.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: { error: "The server did not answer. Is ComfyUI still running?" } };
  }
}

function frontendVersion() {
  try { return globalThis.__COMFYUI_FRONTEND_VERSION__ || null; } catch (_) { return null; }
}

function rowEl(cap, tone) {
  const badge = el("span", { class: "h2v-tag", text: STATUS_TEXT[cap.status] || cap.status,
    style: { color: TONE_COLOR[tone], borderColor: "currentColor", flex: "0 0 auto" } });
  const title = el("div", { style: { display: "flex", gap: "8px", alignItems: "center", justifyContent: "space-between" } },
    [el("span", { text: cap.label + (cap.critical ? "" : " (optional)"),
      style: { fontWeight: "600", fontSize: "12.5px" } }), badge]);
  return el("li", { style: { listStyle: "none", padding: "8px 10px", borderLeft: `3px solid ${TONE_COLOR[tone]}`,
    background: "color-mix(in srgb, var(--h2v-sunken) 60%, transparent)", borderRadius: "6px" } },
  [title, el("p", { class: "h2v-dim", text: rowText(cap), style: { marginTop: "3px" } })]);
}

function render(d, report) {
  const head = headline(report);
  const kids = [noticeEl(head.tone, head.text)];
  for (const { group, rows } of groupRows(report)) {
    kids.push(el("h3", { text: `${group.title} (${rows.length})`,
      style: { fontSize: "12px", margin: "10px 0 4px", color: TONE_COLOR[group.tone] } }));
    kids.push(el("ul", { style: { display: "flex", flexDirection: "column", gap: "6px", margin: "0", padding: "0" } },
      rows.map((c) => rowEl(c, group.tone))));
  }
  kids.push(el("h3", { text: "Versions", style: { fontSize: "12px", margin: "10px 0 4px" } }));
  kids.push(factList(versionFacts(report, frontendVersion())));
  d.body.replaceChildren(...kids);
  d.status(checkedText(report.checked_at));
}

export async function securityCheck() {
  const d = vaultDialog({ title: "Security check", subtitle: "Is every H2Vault protection working on this ComfyUI?",
    width: 560 });
  d.body.append(el("p", { class: "h2v-dim", text: "Checking…" }));
  const load = async (route, method) => {
    d.setBusy(true, "Checking…");
    const r = await call(route, method);
    d.setBusy(false);
    if (!r.ok) { d.notice(r.status === 409 ? "warn" : "danger", r.data?.error || `The check failed (${r.status}).`); return; }
    d.notice(null);
    render(d, r.data);
  };
  d.addAction("Close", { onClick: () => d.close(null) });
  d.addAction("Check again", { primary: true, onClick: () => load("/h2vault/diagnostics/selftest", "POST") });
  await load("/h2vault/diagnostics", "GET");
  return d.result;
}

app.registerExtension({
  name: "H2Vault.Diagnostics",
  commands: [{ id: "h2vault.diagnostics.show", label: "H2Vault: Security check", icon: "pi pi-shield",
    function: () => securityCheck() }],
  menuCommands: [{ path: ["H2Vault"], commands: ["h2vault.diagnostics.show"] }],
});
