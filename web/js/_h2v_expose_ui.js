// H2Vault (AGPL-3.0) - workstream V3, identity concealment: the AUTHOR's "Choose what to expose" step inside the
// protect dialog. The list (grouped by role, defaults pre-selected, editable names, model choices as named aliases,
// socket names) is on the left; on the right the vault exactly as the recipient will get it, drawn by the recipient
// renderer (_h2v_conceal.js renderPreview) from the public half the SERVER computed with the sealing rules
// (POST /h2vault/vault/conceal/check). Problems are shown inline and block locking until fixed.
//
// Text only (never HTML), native form controls (keyboard and screen readers work as everywhere), H2Vault tokens.
import { ROLES, applyOutputFix, buildConceal, droppedOutputs, matchReview } from "./_h2v_expose.js";
import { renderPreview } from "./_h2v_conceal.js";
import { el, ensureVaultStyles, vbutton } from "./_h2v_ui.js";

const STYLE_ID = "h2v-expose-style";
const CSS = `
.h2v-expose { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(250px, 1fr); gap: 16px; align-items: start; }
@media (max-width: 860px) { .h2v-expose { grid-template-columns: 1fr; } }
.h2v-expose__list { display: flex; flex-direction: column; gap: 12px; max-height: 52vh; overflow: auto; padding-right: 4px; }
.h2v-xgroup { margin: 0; padding: 8px 10px 10px; border: 1px solid var(--h2v-edge); border-radius: var(--h2v-r-card);
  display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.h2v-xgroup > legend { padding: 0 6px; font-size: 12px; font-weight: 600; color: var(--h2v-ink-soft); }
.h2v-xrow { display: grid; grid-template-columns: 18px minmax(0, 1fr) minmax(0, 1fr); gap: 4px 8px; align-items: center; }
.h2v-xrow input[type=checkbox] { width: 16px; height: 16px; margin: 0; accent-color: var(--h2v-accent); }
.h2v-xrow .h2v-input { height: 30px; font-size: 12.5px; }
.h2v-xrow__meta { min-width: 0; font-size: 11.5px; color: var(--h2v-ink-dim); white-space: nowrap; overflow: hidden;
  text-overflow: ellipsis; }
.h2v-xrow--off .h2v-input { opacity: 0.55; }
.h2v-xrow .h2v-input[aria-invalid="true"] { border-color: var(--h2v-danger); }
.h2v-xalias { grid-column: 2 / 4; display: flex; flex-direction: column; gap: 6px; padding: 6px 0 2px; }
.h2v-xalias__row { display: grid; grid-template-columns: minmax(0, 0.8fr) minmax(0, 1.2fr) auto; gap: 6px; align-items: center; }
.h2v-xalias select { height: 30px; min-width: 0; border-radius: var(--h2v-r-ctl); border: 1px solid var(--h2v-edge-strong);
  background: var(--h2v-sunken); color: var(--h2v-ink); font: inherit; font-size: 12px; padding: 0 6px; }
.h2v-xsock__type { font-size: 11px; font-weight: 600; color: var(--h2v-ink-soft); }
.h2v-xproblems { margin: 0; padding: 8px 12px 8px 28px; border-radius: var(--h2v-r-card); font-size: 12.5px;
  border: 1px solid var(--h2v-edge); border-left: 3px solid var(--h2v-danger);
  background: color-mix(in srgb, var(--h2v-danger) 9%, var(--h2v-sunken)); }
.h2v-xproblems:empty { display: none; }
.h2v-xproblems li + li { margin-top: 4px; }
.h2v-expose__side { position: sticky; top: 0; display: flex; flex-direction: column; gap: 8px; }
.h2v-expose__side h4 { margin: 0; font-size: 13px; font-weight: 600; }
.h2v-xstate { font-size: 12px; color: var(--h2v-ink-soft); min-height: 16px; }
.h2v-xstate--ok { color: var(--h2v-ok); }
.h2v-pv { border-radius: var(--h2v-r-card); border: 1px solid var(--h2v-edge-strong); background: var(--h2v-raised);
  overflow: hidden; }
.h2v-pv__title { padding: 6px 10px; font-size: 12.5px; font-weight: 600; color: var(--h2v-ink);
  background: color-mix(in srgb, var(--h2v-accent) 22%, var(--h2v-raised)); }
.h2v-pv__sockets { display: flex; justify-content: space-between; gap: 8px; padding: 4px 10px; font-size: 11.5px;
  color: var(--h2v-ink-soft); }
.h2v-pv__out { margin-left: auto; text-align: right; }
.h2v-pv__rows { list-style: none; margin: 0; padding: 4px 8px 8px; display: flex; flex-direction: column; gap: 4px; }
.h2v-pv__row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 2px 8px; align-items: center;
  padding: 4px 8px; border-radius: var(--h2v-r-ctl); background: var(--h2v-sunken); font-size: 12px; }
.h2v-pv__row--wide { grid-template-columns: 1fr; }
.h2v-pv__label { color: var(--h2v-ink-soft); }
.h2v-pv__val { color: var(--h2v-ink); font-variant-numeric: tabular-nums; text-align: right; overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap; max-width: 180px; }
.h2v-pv__val--text { text-align: left; max-width: none; white-space: normal; font-family: ui-monospace, Consolas, monospace;
  font-size: 11.5px; }
.h2v-pv__more { grid-column: 1 / -1; font-size: 11px; color: var(--h2v-ink-dim); }
.h2v-pv__empty { margin: 0; padding: 8px 10px; font-size: 12px; color: var(--h2v-ink-dim); }
.h2v-xsock__status { grid-column: 2 / 4; display: flex; flex-wrap: wrap; gap: 4px 8px; align-items: center;
  font-size: 12px; }
.h2v-xsock__status:empty { display: none; }
.h2v-xsock__msg { flex-basis: 100%; color: var(--h2v-ink-soft); line-height: 1.4; }
.h2v-xsock__msg--danger { color: var(--h2v-danger); }
.h2v-xrow--blocking > .h2v-input { border-color: var(--h2v-danger); }
.h2v-xrow--flash { outline: 2px solid var(--h2v-danger); outline-offset: 3px; border-radius: var(--h2v-r-ctl); }
.h2v-xproblems li button { margin-left: 6px; }
`;

function ensureStyles() {
  ensureVaultStyles();
  if (document.getElementById(STYLE_ID)) return;
  const s = document.createElement("style");
  s.id = STYLE_ID;
  s.textContent = CSS;
  document.head.appendChild(s);
}

let UID = 0;
const uid = (p) => `h2v-x${p}-${++UID}`;
const short = (v) => { const t = typeof v === "string" ? v.replace(/\s+/g, " ") : String(v); return t.length > 28 ? `${t.slice(0, 27)}…` : t; };
const nextAlias = (rows) => {
  const used = new Set(rows.map((r) => String(r.label).trim().toLowerCase()));
  for (let i = 0; i < 26; i++) { const l = `Model ${String.fromCharCode(65 + i)}`; if (!used.has(l.toLowerCase())) return l; }
  return `Model ${rows.length + 1}`;
};

/**
 * The step. `controls` (inventory) and `sockets` are edited in place; `title()` gives the vault name; `check(conceal)`
 * asks the server (-> {problems, public_interface}). Returns {el, ready(), refresh(), destroy()}; ready() resolves with
 * {ok, conceal, problems} after the latest check.
 */
export function exposeStep({ controls, sockets, previews, title, check, onUnconceal = null, onChecked = null }) {
  ensureStyles();
  const rowsByLabel = new Map();          // label input -> control (for inline marks)
  const list = el("div", { class: "h2v-expose__list" });
  const problemsEl = el("ul", { class: "h2v-xproblems", role: "alert", "aria-live": "assertive" });
  const stateEl = el("div", { class: "h2v-xstate", role: "status", "aria-live": "polite" });
  const pvHost = el("div");
  const side = el("aside", { class: "h2v-expose__side", "aria-label": "Preview as recipient" }, [
    el("h4", { text: "Preview as recipient" }), stateEl, problemsEl, pvHost,
    el("p", { class: "h2v-dim", text: "Model files show only under the names you give them. Nothing else from inside " +
      "leaves your machine with the workflow." })]);
  const root = el("section", { class: "h2v-expose", "aria-label": "Choose what to expose" }, [
    el("div", { class: "h2v-expose__main" }, [list]), side]);

  for (const role of ROLES) {
    const mine = controls.filter((c) => c.role === role.id);
    if (!mine.length) continue;
    const count = el("span");
    const legend = el("legend", {}, [role.title, " ", count]);
    const group = el("fieldset", { class: "h2v-xgroup" }, [legend]);
    const recount = () => { count.textContent = `(${mine.filter((c) => c.selected).length} of ${mine.length} shown)`; };
    for (const c of mine) group.append(controlRow(c, () => { recount(); schedule(); }));
    recount();
    list.append(group);
  }
  const sockRows = new Map();             // socket -> {row, inp, status} (owner 2026-11-23: per-output state + fixes)
  if (sockets.length) {
    const group = el("fieldset", { class: "h2v-xgroup" }, [el("legend", { text: "Socket names" })]);
    for (const s of sockets) {
      const inp = el("input", { type: "text", class: "h2v-input", value: s.label, maxLength: 60, spellcheck: false,
        "aria-label": `Name of the ${s.kind === "in" ? "input" : "output"} socket (${s.type})` });
      inp.addEventListener("input", () => { s.label = inp.value; schedule(); });
      rowsByLabel.set(inp, () => s.label);
      const status = el("div", { class: "h2v-xsock__status", role: "group", "aria-live": "polite" });
      const row = el("div", { class: "h2v-xrow" }, [el("span"), inp,
        el("span", { class: "h2v-xsock__type", text: `${s.kind === "in" ? "Input" : "Output"} · ${s.type}` }), status]);
      sockRows.set(s, { row, inp, status });
      group.append(row);
    }
    list.append(group);
  }

  // ── output fixes: every blocking problem names its socket and offers a way out, right on its row ──
  function fix(s, f) {
    if (!applyOutputFix(s, f)) return;
    for (const u of sockRows.values()) u.row.classList.remove("h2v-xrow--flash");
    renderSockets(lastReview);
    schedule();
  }
  const msg = (text, danger = false) => el("span", { class: `h2v-xsock__msg${danger ? " h2v-xsock__msg--danger" : ""}`, text });
  const act = (label, onClick, { kind = "secondary", disabled = false, hint = null } = {}) => {
    const b = vbutton(label, { kind, small: true, onClick });
    b.disabled = disabled;
    if (hint) b.title = hint;
    return b;
  };
  const sharedText = (n) => `This subgraph is used ${n} more time${n === 1 ? "" : "s"} in the workflow, so this ` +
    "output cannot be removed here (it would change the other copies). Remove the output inside the subgraph " +
    "yourself, or lock without concealment.";
  function statusOf(s, r, inputNotes) {
    if (s.kind === "in") {
      const n = inputNotes.find((x) => x.name === String(s.label || "").trim());
      return n ? [msg(n.message)] : [];
    }
    if (s.drop) {
      const w = s.wires || 0;
      return [msg(`Removed: this output is not part of the vault when you lock it${w ? `, and its ${w} wire` +
        `${w === 1 ? "" : "s"} outside will be disconnected` : ""}.`),
        act("Keep this output", () => fix(s, { id: "keep" }))];
    }
    if (!r) return [];
    const out = [];
    if (r.message) out.push(msg(r.message, !!r.blocking));
    for (const f of r.fixes || []) {
      if (f.id === "remove") {
        const shared = s.shared || 0;
        out.push(act("Remove this output from the vault", () => fix(s, f), {
          kind: r.blocking ? "primary" : "secondary", disabled: shared > 0, hint: shared > 0 ? sharedText(shared) : null }));
        if (shared > 0) out.push(msg(sharedText(shared)));
      } else if (f.id === "unconceal" && onUnconceal) {
        out.push(act("Lock without concealment", () => onUnconceal()));
      } else if (f.id === "show_as") {
        out.push(act(`Show it as ${f.type}`, () => fix(s, f)));
      } else if (f.id === "show_as_undo") {
        out.push(act("Show its real type", () => fix(s, f), { kind: "primary" }));
      }
    }
    if (s.showAs && !r.blocking) {
      out.push(msg(`Shown to the person who runs the vault as ${s.showAs}.`));
      out.push(act("Show its real type", () => fix(s, { id: "show_as_undo" })));
    }
    return out;
  }
  let lastReview = { outputs: [], inputs: [] };
  function renderSockets(review) {
    const m = matchReview(sockets, review?.outputs || []);
    for (const [s, ui] of sockRows) {
      const r = m.get(s);
      if (ui.inp.value !== s.label && document.activeElement !== ui.inp) ui.inp.value = s.label;
      ui.inp.disabled = !!s.drop;
      ui.row.classList.toggle("h2v-xrow--off", !!s.drop);
      ui.row.classList.toggle("h2v-xrow--blocking", !!r?.blocking && !s.drop);
      ui.status.replaceChildren(...statusOf(s, r, review?.inputs || []));
    }
  }
  function reveal(row) {
    if (!row) return;
    row.scrollIntoView?.({ block: "center", behavior: "smooth" });
    row.classList.add("h2v-xrow--flash");
    setTimeout(() => row.classList.remove("h2v-xrow--flash"), 1800);
    const target = row.querySelector(".h2v-xsock__status button:not([disabled])") ?? row.querySelector("input:not([disabled])");
    target?.focus?.({ preventScroll: true });
  }
  const rowOfProblem = (p) => {
    for (const [s, ui] of sockRows) {
      const l = String(s.label || "").trim();
      if (l && (p.includes(`'${l}'`) || p.includes(`"${l}"`))) return ui.row;
    }
    for (const [inp, get] of rowsByLabel) {
      const l = String(get() || "").trim();
      if (l && (p.includes(`'${l}'`) || p.includes(`"${l}"`))) return inp.closest(".h2v-xrow");
    }
    return null;
  };

  function controlRow(c, changed) {
    const id = uid("c");
    const box = el("input", { type: "checkbox", id, checked: !!c.selected,
      "aria-label": `Show "${c.label}" to the recipient (${c.nodeTitle}, ${c.input})` });
    const name = el("input", { type: "text", class: "h2v-input", value: c.label, maxLength: 60, spellcheck: false,
      disabled: !c.selected, "aria-label": `Name the recipient sees for ${c.nodeTitle} ${c.input}` });
    const meta = el("span", { class: "h2v-xrow__meta", title: `${c.nodeTitle} · ${c.input} = ${c.value}`,
      text: `${c.nodeTitle} · ${short(c.value)}` });
    const row = el("div", { class: `h2v-xrow${c.selected ? "" : " h2v-xrow--off"}` }, [box, name, meta]);
    box.addEventListener("change", () => {
      c.selected = box.checked;
      name.disabled = !box.checked;
      row.classList.toggle("h2v-xrow--off", !box.checked);
      if (aliasBox) aliasBox.hidden = !box.checked;
      changed();
    });
    name.addEventListener("input", () => { c.label = name.value; changed(); });
    rowsByLabel.set(name, () => c.label);
    let aliasBox = null;
    if (c.role === "model") {
      aliasBox = el("div", { class: "h2v-xalias", role: "group", "aria-label": `Choices offered for ${c.label}` });
      aliasBox.hidden = !c.selected;
      const draw = () => {
        aliasBox.replaceChildren();
        c.aliases.forEach((a, i) => {
          const nm = el("input", { type: "text", class: "h2v-input", value: a.label, maxLength: 40, spellcheck: false,
            "aria-label": `Name of choice ${i + 1}` });
          nm.addEventListener("input", () => { a.label = nm.value; changed(); });
          const sel = el("select", { "aria-label": `File used for choice ${i + 1}` },
            (c.options || []).map((f) => el("option", { value: f, text: f, selected: f === a.value })));
          sel.addEventListener("change", () => { a.value = sel.value; changed(); });
          const rm = vbutton("Remove", { kind: "text", small: true, ariaLabel: `Remove choice ${i + 1}`,
            onClick: () => { c.aliases.splice(i, 1); draw(); changed(); } });
          rm.disabled = c.aliases.length <= 1;
          aliasBox.append(el("div", { class: "h2v-xalias__row" }, [nm, sel, rm]));
        });
        const add = vbutton("Add a choice", { kind: "text", small: true, onClick: () => {
          const used = new Set(c.aliases.map((a) => a.value));
          c.aliases.push({ label: nextAlias(c.aliases), value: (c.options || []).find((f) => !used.has(f)) ?? c.value });
          draw();
          changed();
          aliasBox.querySelectorAll("input")[c.aliases.length - 1]?.focus();
        } });
        add.disabled = !(c.options || []).length;
        aliasBox.append(el("div", {}, [add]));
      };
      draw();
      row.append(aliasBox);
    }
    return row;
  }

  // ── the check (debounced; the latest answer wins) ──
  let timer = null, gen = 0, pending = null, last = { ok: false, conceal: null, problems: [] };
  function showProblems(problems) {
    problemsEl.replaceChildren(...problems.map((p) => {
      const row = rowOfProblem(p);
      return el("li", {}, [p, row ? vbutton("Show me", { kind: "text", small: true, onClick: () => reveal(row) }) : null]);
    }));
    for (const [inp, get] of rowsByLabel) {
      const l = String(get() || "").trim();
      const bad = !inp.disabled && (!l || problems.some((p) => p.includes(`'${l}'`) || p.includes(`"${l}"`)));
      if (bad) inp.setAttribute("aria-invalid", "true"); else inp.removeAttribute("aria-invalid");
    }
  }
  async function run() {
    const my = ++gen;
    const { conceal, problems: local } = buildConceal(controls, { title: title(), sockets, previews });
    stateEl.className = "h2v-xstate";
    stateEl.textContent = "Checking…";
    let server = { problems: [], public_interface: null };
    try { server = await check(conceal); }
    catch (e) { server = { problems: [String(e?.message || e || "The check could not run.")], public_interface: null }; }
    if (my !== gen) return last;
    const problems = [...new Set([...local, ...(server.problems || [])])];
    lastReview = { outputs: server.outputs || [], inputs: server.inputs || [] };
    renderSockets(lastReview);
    showProblems(problems);
    if (server.public_interface) renderPreview(pvHost, server.public_interface);
    const ok = !problems.length && !!server.public_interface;
    stateEl.className = `h2v-xstate${ok ? " h2v-xstate--ok" : ""}`;
    stateEl.textContent = ok ? "This is all the recipient will see." :
      `${problems.length} thing${problems.length === 1 ? "" : "s"} to fix before locking.`;
    last = { ok, conceal, problems, dropped: droppedOutputs(sockets) };
    onChecked?.(last);
    return last;
  }
  function schedule() {
    clearTimeout(timer);
    pending = new Promise((res) => { timer = setTimeout(() => res(run()), 300); });
  }
  schedule();
  return {
    el: root,
    refresh: schedule,
    async ready() { clearTimeout(timer); return run(); },
    // "Fix what is listed": scroll to the first row that blocks, highlight it, focus its first fix
    focusProblem() {
      const first = [...sockRows.values()].find((u) => u.row.classList.contains("h2v-xrow--blocking"))?.row ??
        list.querySelector("[aria-invalid=true]")?.closest(".h2v-xrow");
      if (first) reveal(first); else problemsEl.scrollIntoView?.({ block: "nearest" });
    },
    destroy() { clearTimeout(timer); gen++; },
    get pending() { return pending; },
  };
}
