# Derived from Code2Collapse ComfyUI-CustomNodePacks nodes/secure_subgraph_routes.py (Apache-2.0, Copyright Code2Collapse);
# modified for H2Vault (AGPL-3.0). See NOTICE.
"""HTTP routes of H2Vault's protected subgraphs and second factor (docs/ARCHITECTURE.md).

  POST /h2vault/vault/protect     selection / subgraph -> encrypted vault (password, profile, recipients, editors)
  POST /h2vault/vault/protect/abort  L9.249: a protect failed after sealing - drop the run key it stored for that tab
  POST /h2vault/vault/unlock_run  Locked profile: password once per browser tab (key kept in memory for that tab)
  POST /h2vault/vault/forget_run  the tab closed: drop its run keys
  POST /h2vault/vault/open        password + second factor + editor check -> the inner graph for native editing
  POST /h2vault/vault/commit      leaving the subgraph: re-encrypt the edited graph (auto-lock)
  POST /h2vault/vault/cancel      leave without changes
  GET  /h2vault/vault/install_code  this installation's code (public key) to send to a vault author
  POST /h2vault/vault/info        public facts of a payload (profile, this installation) - never the inside
  POST /h2vault/vault/access/open   L9.48: the same checks as open -> the access lists only (never the graph)
  POST /h2vault/vault/access/apply  re-encrypt with new recipients / editors / labels / password (atomic)
  POST /h2vault/vault/access/cancel drop the access session
  POST /h2vault/vault/missing          L9.50: what this install lacks to run it (counts + hosts, never names)
  POST /h2vault/vault/install_missing  clone those packs at their pinned commits - only with consent
  GET  /h2vault/2fa/status       is an authenticator set up here (no secret)
  POST /h2vault/2fa/enrol/begin  a new TOTP secret + recovery codes, shown once        (this machine's page only)
  POST /h2vault/2fa/enrol/confirm  the first code activates it                        (this machine's page only)
  POST /h2vault/2fa/reset        remove it, with a current code or a recovery code     (this machine's page only)
  POST /h2vault/licence/status   V5: may this installation run a Licensed vault now (this machine's page only)
  POST /h2vault/licence/add      V5: keep a licence the author sent (verified first)    (this machine's page only)
  POST /h2vault/licence/remove   V5: forget a stored licence                              (this machine's page only)
  POST /h2vault/licence/issue    V5: the author signs a licence (password + second factor + editor)
  POST /h2vault/licence/rotate   V5: new licence key = revoke every licence; re-issue chosen ones (same checks)
  GET  /h2vault/licence/ledger   V5: the licences this author issued (no keys)          (this machine's page only)
  POST /h2vault/licence/author/export|import  V5: password-protected author key backup  (this machine's page only)

The password travels only over these routes; it is never a widget, never in a prompt or a workflow, never stored. The
server keeps derived keys in memory only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import struct
import threading
import time
from typing import Any, Optional

from . import packs as vault_packs
from .crypto import VaultError

PROFILES = {"locked": 0, "sealed_installs": 1, "sealed_portable": 2, "sealed_licensed": 3}
PROFILE_NAMES = {v: k for k, v in PROFILES.items()}
EDIT_IDLE_SECONDS = 6 * 3600           # an edit session also ends when the user leaves the subgraph (owner A18)
ACCESS_IDLE_SECONDS = 15 * 60          # an access session (L9.48) only lives while its dialog is open
LABEL_MAX = 60
_lock = threading.Lock()
_KDF_GATE = threading.Semaphore(1)     # every password route derives one Argon2id key at a time (RAM; see unlock_run)
MAX_FAILED_ATTEMPTS = 5                # per vault id: the guesser already has the file, so cap guesses per blob
LOCKOUT_SECONDS = 5 * 60
_EDITS: dict[str, dict] = {}
# L9.249 V6: vaults this server just sealed, vault_id -> (client_id, time). A protect that fails in the browser AFTER
# sealing (node insertion, wiring, final check) restores the graph; /protect/abort then drops the run key protect()
# stored - only for the tab that made the vault, and only shortly after.
PENDING_SECONDS = 15 * 60
PENDING_MAX = 256
_PENDING: dict[str, tuple] = {}


class _Guesses:
    """Failed password attempts per vault id (CNP vault_node._SessionStore's lockout). In memory only."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._fails: dict[str, tuple[int, float]] = {}

    def note_failure(self, vault_id: str) -> None:
        with self._lock:
            count, _ = self._fails.get(vault_id, (0, 0.0))
            self._fails[vault_id] = (count + 1, time.monotonic() + LOCKOUT_SECONDS)

    def clear_failures(self, vault_id: str) -> None:
        with self._lock:
            self._fails.pop(vault_id, None)

    def locked_out(self, vault_id: str) -> float:
        """Seconds left in the lockout, or 0."""
        with self._lock:
            count, until = self._fails.get(vault_id, (0, 0.0))
            if count < MAX_FAILED_ATTEMPTS:
                return 0.0
            remaining = until - time.monotonic()
            if remaining <= 0:
                self._fails.pop(vault_id, None)
                return 0.0
            return remaining


GUESSES = _Guesses()


def _password_attempt(vault_id: str, fn):
    """Run `fn()` (which derives the password key) under the lockout and the one-KDF-at-a-time gate. A VaultError
    (wrong password or tampered payload, one message for both) counts as a failure. PermissionError -> 429."""
    wait = GUESSES.locked_out(vault_id)
    if wait > 0:
        raise PermissionError(f"Too many failed attempts. Try again in {int(wait // 60) + 1} minute(s).")
    try:
        with _KDF_GATE:
            out = fn()
    except VaultError:
        GUESSES.note_failure(vault_id)
        raise
    GUESSES.clear_failures(vault_id)
    return out


def _hash(payload: str) -> str:
    return hashlib.sha256((payload or "").encode("ascii", "ignore")).hexdigest()


def _this_install_code() -> str:
    from . import keys as vault_keys
    return vault_keys.public_text(vault_keys.install_public_key())


def _codes_to_keys(codes) -> list:
    from . import keys as vault_keys
    out = []
    for c in codes or []:
        raw = vault_keys.parse_public_text(str(c))
        if raw not in out:
            out.append(raw)
    return out


def boundary_exec(interface: dict) -> dict:
    """The v2 envelope wants the old flattened block; a new vault carries an EMPTY one (no nodes), so the old
    executor can never run it, plus the boundary names / types it authenticates."""
    return {"nodes": [], "links": [],
            "boundary_in": [{"name": str(s.get("name")), "type": str(s.get("type", "*"))}
                            for s in interface.get("in") or []],
            "boundary_out": [{"name": str(s.get("name")), "type": str(s.get("type", "*"))}
                             for s in interface.get("out") or []]}


def _validate_api(api: dict, interface: dict) -> None:
    if not isinstance(api, dict) or not isinstance(api.get("nodes"), dict) or not api["nodes"]:
        raise VaultError("Nothing to protect: the selection has no nodes that run.")
    n_in = len(interface.get("in") or [])
    for nid, node in api["nodes"].items():
        if not isinstance(node, dict) or not node.get("class_type"):
            raise VaultError(f"Malformed inner node {nid!r}.")
        for name, v in (node.get("inputs") or {}).items():
            if isinstance(v, dict) and "vault_in" in v and not (0 <= int(v["vault_in"]) < n_in):
                raise VaultError(f"Inner input {name!r} reads vault input {v['vault_in']}, which does not exist.")
            if isinstance(v, (list, tuple)) and len(v) == 2 and isinstance(v[0], str) and v[0] not in api["nodes"]:
                raise VaultError(f"Inner link to unknown node {v[0]!r}.")
    for out in api.get("outputs") or []:
        if "node" in out and str(out["node"]) not in api["nodes"]:
            raise VaultError(f"Vault output {out.get('name')!r} reads an unknown node.")
    # A26 L9.204: the full check (registry classes, link slots and types, outputs <= MAX_OUTPUTS, controls)
    from . import protected_subgraph as SS
    try:
        SS.validate_api(api, n_in, detailed=True)
    except SS.InvalidVault as exc:
        raise VaultError(str(exc)) from None


def _with_conceal(plain: dict, conceal) -> Optional[dict]:
    """V3 concealment (nodes/concealment.py): a concealed vault carries its `conceal` section INSIDE the payload, and
    sealing refuses one whose public half would name its inside. -> the whitelisted public interface, or None for an
    ordinary vault."""
    if conceal is None:
        return None
    from . import concealment
    if not isinstance(conceal, dict):
        raise VaultError("The concealment settings of this vault are malformed.")
    plain["conceal"] = conceal
    problems = concealment.check_public(plain)
    if problems:
        raise VaultError(" ".join(problems))
    return concealment.public_interface(plain)


def _expose(api, interface, conceal):
    from . import concealment
    return concealment.merge_exposure(api, interface, conceal) if isinstance(conceal, dict) else (api, interface)


# ── V5: Lock parameters (a one-node vault drawn like its node; design 5) ─────────────────────────────────────────
LOCK_TITLE_MAX = 80
LOCK_NEUTRAL_TITLE = "Locked node"


def _names_kind(title: str, class_type) -> bool:
    """V8: does a Locked node's title name the node's kind (its class id or display name)? Then it is not published
    unless the author chose to show the kind."""
    t = str(title or "").strip().lower()
    if not t or not isinstance(class_type, str):
        return False
    kinds = {class_type}
    try:
        import nodes as core_nodes
        kinds.add(str(getattr(core_nodes, "NODE_DISPLAY_NAME_MAPPINGS", {}).get(class_type) or ""))
    except Exception:  # noqa: BLE001 - outside ComfyUI: the class id alone
        pass
    return any(k and len(k.strip()) >= 3 and k.strip().lower() in t for k in kinds)
_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


def _with_lock(plain: dict, lock, *, strict: bool = True) -> Optional[dict]:
    """Validate a Lock-parameters request against the vault's inside; store it in the plaintext. -> the whitelisted
    public part for the node, or None (no lock). `strict=False` (an edit that no longer fits) drops the lock instead
    of refusing."""
    plain.pop("lock", None)
    if lock is None:
        return None
    try:
        if not isinstance(lock, dict):
            raise VaultError("The Lock parameters settings are malformed.")
        nodes_ = (plain.get("api") or {}).get("nodes") or {}
        node_id = str(lock.get("node"))
        if len(nodes_) != 1 or node_id not in nodes_:
            raise VaultError("Lock parameters works on one node at a time.")
        inputs = nodes_[node_id].get("inputs") or {}
        promoted = {str(x.get("input")) for x in ((plain.get("api") or {}).get("promoted") or [])
                    if isinstance(x, dict) and str(x.get("node")) == node_id}
        rows = []
        for r in lock.get("rows") or []:
            r = str(r)
            if r not in inputs:
                raise VaultError(f"{r!r} is not a setting of this node.")
            if r in promoted:
                raise VaultError(f"{r!r} is both locked and offered as a control; choose one.")
            if r not in rows:
                rows.append(r)
        if not rows:
            raise VaultError("Choose at least one value to lock.")
        look_in = lock.get("look") if isinstance(lock.get("look"), dict) else {}
        look = {"title": str(look_in.get("title") or "")[:LOCK_TITLE_MAX],
                "node_label": str(look_in.get("node_label") or "")[:LOCK_TITLE_MAX] or None,
                "show_rows": look_in.get("show_rows") is True}
        for key in ("color", "bgcolor"):
            c = look_in.get(key)
            look[key] = c if isinstance(c, str) and _COLOR.match(c) else None
        if not look["node_label"] and _names_kind(look["title"], nodes_[node_id].get("class_type")):
            look["title"] = LOCK_NEUTRAL_TITLE          # V8: an un-renamed node's title IS its kind ("Load Checkpoint")
        # owner 2026-11-23 ("0 information"): the setting names and the node's kind are published only when the
        # author asks for it; otherwise the node shows its title and how many values are locked
        public = {"rows": list(rows) if look["show_rows"] else [], "count": len(rows), "look": look}
        leaks = [inputs[r] for r in rows if isinstance(inputs[r], str) and len(inputs[r].strip()) >= 3]
        shown = json.dumps([plain.get("interface"), public], ensure_ascii=False)
        if any(v in shown for v in leaks):
            raise VaultError("A locked value appears in the public part of this node; it would be readable by "
                             "anyone. Rename the node or change what is offered.")
    except VaultError:
        if strict:
            raise
        return None
    plain["lock"] = {"version": 1, "node": node_id, "rows": rows, "look": look}
    return public


def conceal_check(body: dict) -> dict:
    """V3 author step: the refusals sealing would give for this exposure, and the public interface the recipient
    would see - computed by the same code as sealing, without sealing (no key, no payload)."""
    from . import concealment
    conceal = body.get("conceal")
    if not isinstance(conceal, dict):
        raise VaultError("Nothing to check: no concealment settings were sent.")
    api, interface = _expose(body.get("api") or {}, body.get("interface") or {}, conceal)
    plain = {"api": api, "interface": interface, "ui": body.get("ui"), "conceal": conceal}
    problems = concealment.check_public(plain)
    return {"ok": True, "problems": problems,
            "public_interface": None if problems else concealment.public_interface(plain)}


def protect(body: dict) -> dict:
    from . import protected_subgraph as SS
    from . import crypto as v2

    profile = str(body.get("profile") or "sealed_installs")
    if profile not in PROFILES:
        raise VaultError(f"Unknown security profile {profile!r}.")
    password = str(body.get("password") or "")
    if len(password) < 8:
        raise VaultError("Choose a vault password of at least 8 characters (it is needed to open the vault).")
    interface = body.get("interface") or {}
    api = body.get("api") or {}
    api, interface = _expose(api, interface, body.get("conceal"))       # V3: the author's exposed controls
    _validate_api(api, interface)
    me = _this_install_code()
    editors = [me] + [c for c in (body.get("editors") or []) if str(c) != me]
    _codes_to_keys(editors)                                      # validates every code
    recipients = None
    if profile == "sealed_installs":
        recipients = _codes_to_keys([me] + list(body.get("recipients") or []))       # this install first
    vault_id = "v" + secrets.token_hex(8)
    plain = {"exec": boundary_exec(interface), "api": api, "ui": body.get("ui"), "interface": interface,
             "editors": editors, "profile": profile, "packs": vault_packs.record_safely(api),          # L9.50
             "created": int(time.time())}
    if body.get("models") or body.get("downloads"):         # V7: model downloads, kept INSIDE the encryption
        from . import provision
        try:
            manifest = provision.validate_manifest(body.get("models") or [])
            known = {e["file"] for e in manifest}
            manifest += [e for e in provision.describe_downloads(body.get("downloads") or []) if e["file"] not in known]
            if manifest:
                plain["models"] = manifest
        except provision.ProvisionError as exc:
            raise VaultError(str(exc)) from None
    public = _with_conceal(plain, body.get("conceal"))
    public_lock = _with_lock(plain, body.get("lock"))
    licensing = None
    if profile == "sealed_licensed":                           # V5: a fresh licence key; this author's signing key
        from . import licence as L
        licensing = {"lk": os.urandom(32), "author_pub": L.author_public_key(create=True)}
    payload, kek = v2.lock(plain, password, vault_id=vault_id, mode=PROFILES[profile], iface=_iface(interface),
                           recipients=recipients, licensing=licensing)
    if licensing:
        _license_this_installation(vault_id, licensing)       # the author runs it at once
    if profile == "locked" and body.get("client_id"):
        SS.RUN_SESSIONS.put(str(body["client_id"]), vault_id, kek)   # the creator can run it right away
        _note_pending(vault_id, str(body["client_id"]))
    out = {"vault_id": vault_id, "payload": payload, "profile": profile,
           "outputs_node": bool(body.get("outputs_node")), "node_count": len(api["nodes"])}
    if public is not None:
        out["public_interface"] = public
    if public_lock is not None:
        out["public_lock"] = public_lock
    return out


def _license_this_installation(vault_id: str, licensing: dict) -> str:
    """V5: the author's own installation gets an open licence (no end, no run limit) - not listed in the Ledger."""
    from . import keys as vault_keys, licence as L
    pub = vault_keys.install_public_key()
    text = L.issue(author_priv=L.author_private_key(), vault_id=vault_id, lk=licensing["lk"], install_pub=pub,
                   label=L.AUTHOR_LABEL)
    L.add(text, author_pub=licensing["author_pub"], vault_id=vault_id, install_pub=pub)
    return text


def _note_pending(vault_id: str, client_id: str) -> None:
    now = time.time()
    with _lock:
        for v in [v for v, (_c, at) in _PENDING.items() if now - at > PENDING_SECONDS]:
            _PENDING.pop(v, None)
        while len(_PENDING) >= PENDING_MAX:
            _PENDING.pop(next(iter(_PENDING)), None)               # oldest first (insertion order)
        _PENDING[vault_id] = (client_id, now)


def protect_abort(body: dict) -> dict:
    """L9.249 V6: the browser could not finish the protect it sealed (the graph went back to the original nodes).
    Drop the run key protect() stored for that vault - only when this server sealed it for the SAME tab within
    PENDING_SECONDS. Anything else is a no-op answer (dropped false), never an error: the graph is already restored."""
    from . import protected_subgraph as SS

    vault_id, client_id = str(body.get("vault_id") or ""), str(body.get("client_id") or "")
    with _lock:
        rec = _PENDING.get(vault_id)
        ok = bool(rec and client_id and rec[0] == client_id and time.time() - rec[1] <= PENDING_SECONDS)
        if ok:
            _PENDING.pop(vault_id, None)
    if ok:
        SS.RUN_SESSIONS.drop_vault(vault_id)                     # a brand-new vault: only this tab ever had its key
    return {"ok": True, "dropped": ok}


def _iface(interface: dict) -> dict:
    """The authenticated part (v2 interface_struct): socket names / types and promoted parameter ids / names."""
    return {"in": interface.get("in") or [], "out": interface.get("out") or [],
            "params": [{"id": p.get("key"), "name": p.get("name"), "type": p.get("type", "*")}
                       for p in interface.get("params") or []]}


def unlock_run(body: dict) -> dict:
    from . import protected_subgraph as SS
    from . import crypto as v2

    payload, vault_id = str(body.get("payload") or ""), str(body.get("vault_id") or "")
    client_id = str(body.get("client_id") or "")
    if not client_id:
        raise VaultError("No browser tab id - reload the page.")
    try:
        v2.parse(payload)
    except VaultError as err:                                 # a damaged payload is a bad request, not a guess
        err.status = 400
        raise
    # NOTE (measured on CNP, docs/evidence/L9.263): cryptography's Argon2id holds the GIL for the whole derivation, so
    # even off the event loop other requests only get the switch interval between KDFs.
    _plain, kek, _p = _password_attempt(
        vault_id, lambda: v2.open_with_password(payload, str(body.get("password") or ""), vault_id=vault_id))
    SS.RUN_SESSIONS.put(client_id, vault_id, kek)
    return {"ok": True}


def forget_run(body: dict) -> dict:
    from . import protected_subgraph as SS
    SS.RUN_SESSIONS.drop_client(str(body.get("client_id") or ""))
    return {"ok": True}


def _authorize(body: dict, *, require_editor: bool = True) -> tuple:
    """Password -> second factor -> editor list (A18 3.5) -> (plain, k, second factor, None), or (None, None, None,
    error answer) for the answers the dialog handles (enrolment, code reasons, not an editor). A wrong password or a
    tampered payload raises VaultError (one message for both). `require_editor=False` only where the author signing
    key itself is the proof (author-key restore / issue on the author's new computer, review 2026-11-23)."""
    from . import twofactor as vault_2fa, crypto as v2

    payload, vault_id = str(body.get("payload") or ""), str(body.get("vault_id") or "")
    password = str(body.get("password") or "")
    if not vault_2fa.enrolled():
        return None, None, None, {
            "ok": False, "needs_enrolment": True,
            "error": "Opening a vault needs a second factor on this installation. Set up an authenticator app first "
                     "(H2Vault menu > Two-factor setup)."}
    try:                                                       # a damaged / foreign payload is a bad request, never a
        v2.parse(payload)                                      # counted password guess (it would lock the vault id)
    except VaultError as err:
        err.status = 400
        raise
    plain, kek, parsed = _password_attempt(vault_id, lambda: v2.open_with_password(payload, password,
                                                                                    vault_id=vault_id))
    k = {"kek": kek, "salt": parsed["salt"], "kdf": parsed["kdf"]}
    detail = vault_2fa.verify_detail(str(body.get("code") or ""))
    if not detail["ok"]:
        return None, None, None, {"ok": False, "reason": detail["reason"], "error": detail["message"],
                                  **({"next_in": detail["next_in"]} if "next_in" in detail else {})}
    editors = plain.get("editors")
    if require_editor and editors and _this_install_code() not in editors:
        return None, None, None, {
            "ok": False, "reason": "not_editor",
            "error": "This installation is not an editor of this vault. Ask its author to add your installation code "
                     "(H2Vault menu > My installation code)."}
    return plain, k, detail["reason"], None


def _holds_author_key(p: dict) -> bool:
    """True when THIS installation stores the signing key of the vault's author (header author_pub). Whoever holds it
    can sign licences offline anyway, so the editor list adds no protection for licence actions - a restored key on
    the author's new computer must be usable without first becoming an editor."""
    from . import licence as L
    try:
        priv = L.author_private_key(create=False)
        return bool(priv) and L.ed25519_public(priv) == p.get("author_pub")
    except Exception:  # noqa: BLE001 - no key / unreadable store = not the author here
        return False


def open_for_edit(body: dict) -> dict:
    """Password -> second factor -> editor list. Returns the inner graph for native editing + an edit token."""
    payload, vault_id = str(body.get("payload") or ""), str(body.get("vault_id") or "")
    plain, k, factor, refused = _authorize(body)
    if refused:
        return refused
    detail = {"reason": factor}
    editors = plain.get("editors")
    me = _this_install_code()
    token = secrets.token_urlsafe(24)
    with _lock:
        _EDITS[token] = {"vault_id": vault_id, "k": k, "payload_hash": _hash(payload),
                         "profile": plain.get("profile") or PROFILE_NAMES.get(_mode_of(payload), "locked"),
                         "editors": editors or [me], "recipients": plain.get("recipients") or [],
                         "packs": plain.get("packs") or [], "at": time.time(),
                         "conceal": plain.get("conceal"),
                         "lock": plain.get("lock"),                        # V5
                         "licensing": v2_licensing(plain),                 # V5: an edit keeps the licence key
                         "client_id": str(body.get("client_id") or "")}
    out = {"ok": True, "edit_token": token, "interface": plain.get("interface"), "profile": _EDITS[token]["profile"],
           "second_factor": detail["reason"]}
    if isinstance(plain.get("conceal"), dict):
        out["conceal"] = plain["conceal"]                      # the author may change what the recipient sees
    if not isinstance(plain.get("ui"), dict):
        # H2Vault always stores the editable layout; without it there is nothing the editor can show, so the inner
        # graph is never sent (the CNP first-format rebuild path is not part of H2Vault)
        with _lock:
            _EDITS.pop(token, None)
        raise VaultError("This vault has no editable layout. Ask its author for a fresh copy.")
    out["ui"] = plain["ui"]
    return out


def v2_licensing(plain: dict):
    from . import crypto as v2
    return v2.licensing_of(plain)


def _mode_of(payload: str) -> int:
    from . import crypto as v2
    return v2.parse(payload)["mode"]


def _session(token: str, kind: str = "edit") -> dict:
    with _lock:
        s = _EDITS.get(str(token))
        idle = ACCESS_IDLE_SECONDS if kind == "access" else EDIT_IDLE_SECONDS
        if not s or s.get("kind", "edit") != kind or time.time() - s["at"] > idle:
            if s and s.get("kind", "edit") == kind:
                _EDITS.pop(str(token), None)
            raise VaultError("This edit session has ended (the vault re-locked). Open the vault again."
                             if kind == "edit" else
                             "This access session has ended. Choose Manage access again.")
        return s


def _canonical_codes(codes, what: str) -> list:
    """Installation codes, validated and de-duplicated, in a canonical spelling."""
    from . import keys as vault_keys
    out = []
    for c in codes or []:
        c = str(c or "").strip()
        if not c:
            continue
        try:
            canon = vault_keys.public_text(vault_keys.parse_public_text(c))
        except VaultError as exc:
            raise VaultError(f"{what}: {exc} ({c[:24]}...)") from None
        if canon not in out:
            out.append(canon)
    return out


def access_open(body: dict) -> dict:
    """L9.48: the access lists of a vault, after the same checks as opening it for editing. The graph never leaves
    the server here."""
    from . import crypto as v2, keys as vault_keys

    payload, vault_id = str(body.get("payload") or ""), str(body.get("vault_id") or "")
    plain, k, factor, refused = _authorize(body)
    if refused:
        return refused
    me = _this_install_code()
    profile = plain.get("profile") or PROFILE_NAMES.get(_mode_of(payload), "locked")
    editors = list(plain.get("editors") or [me])
    recipients = [vault_keys.public_text(r) for r in v2.recipients_of(plain)] if profile == "sealed_installs" else []
    labels = dict(plain.get("access_labels") or {})
    token = secrets.token_urlsafe(24)
    with _lock:
        _EDITS[token] = {"kind": "access", "vault_id": vault_id, "k": k, "payload_hash": _hash(payload),
                         "profile": profile, "at": time.time(), "client_id": str(body.get("client_id") or "")}

    def row(c):
        return {"code": c, "label": labels.get(c, ""), "me": c == me}
    return {"ok": True, "access_token": token, "profile": profile, "editors": [row(c) for c in editors],
            "recipients": [row(c) for c in recipients], "second_factor": factor}


def access_apply(body: dict) -> dict:
    """Re-encrypt the SAME inside with new recipients / editors / labels and, optionally, a new password: fresh data
    key and nonces (a new password: a new salt and key). The new payload is checked to open before anything else
    changes; the front end swaps the node's payload only on success, so a failure leaves the old vault as it was.
    Then every other session of this vault ends (A18 3.6); a password change also drops every tab's run key."""
    from . import protected_subgraph as SS
    from . import crypto as v2, keys as vault_keys

    token = str(body.get("access_token") or "")
    s = _session(token, kind="access")
    payload = str(body.get("payload") or "")
    if _hash(payload) != s["payload_hash"]:
        raise VaultError("This vault was changed since you unlocked its access (another tab, or an edit). Choose "
                         "Manage access again.")
    plain = v2.open_with_kek(payload, s["k"]["kek"], vault_id=s["vault_id"])
    me = _this_install_code()
    editors = _canonical_codes(body.get("editors"), "Editors")
    if me not in editors:
        raise VaultError("This installation must stay an editor - otherwise nobody here could open the vault again.")
    sealed = s["profile"] == "sealed_installs"
    recipients = _canonical_codes(body.get("recipients"), "Installations") if sealed else []
    if sealed and me not in recipients:
        recipients.insert(0, me)                               # this install always runs its own vaults
    keep = set(editors) | set(recipients)
    labels = {str(c): str(v)[:LABEL_MAX].strip() for c, v in (body.get("labels") or {}).items()
              if str(c) in keep and str(v or "").strip()}
    new_password = body.get("new_password")
    if new_password:
        if len(str(new_password)) < 8:
            raise VaultError("Choose a new password of at least 8 characters.")
        k = v2.new_kek(str(new_password))
    else:
        k = s["k"]
    inner = {key: v for key, v in plain.items() if key not in ("recipients", "format")}
    inner.update(editors=editors, access_labels=labels, updated=int(time.time()))
    raw = [vault_keys.parse_public_text(c) for c in recipients] if sealed else None
    new_payload = v2.lock_with(inner, k, vault_id=s["vault_id"], mode=PROFILES[s["profile"]],
                               iface=_iface(plain.get("interface") or {}), recipients=raw)
    check = v2.open_with_kek(new_payload, k["kek"], vault_id=s["vault_id"])       # it opens, or nothing changes
    if check.get("editors") != editors:
        raise VaultError("The re-encrypted vault did not read back correctly; nothing was changed.")
    with _lock:
        for t in [t for t, x in _EDITS.items() if x.get("vault_id") == s["vault_id"]]:
            _EDITS.pop(t, None)                                # this session too: one apply per authorization
    if new_password:
        SS.RUN_SESSIONS.drop_vault(s["vault_id"])
    if s["profile"] == "locked" and s.get("client_id"):
        SS.RUN_SESSIONS.put(s["client_id"], s["vault_id"], k["kek"])
    return {"ok": True, "payload": new_payload, "vault_id": s["vault_id"], "profile": s["profile"],
            "password_changed": bool(new_password), "editors": len(editors), "recipients": len(recipients)}


def _open_like_a_run(body: dict) -> tuple:
    """The vault opened with exactly what a run on this install / tab may use - installing needs no more rights."""
    from . import protected_subgraph as SS
    vault_id = str(body.get("vault_id") or "")
    plain = SS.open_for_run(str(body.get("payload") or ""), vault_id, client_id=str(body.get("client_id") or ""))
    return plain, vault_id


def missing(body: dict) -> dict:
    """L9.50: what this install lacks to run the vault - counts and hosts only, never names (owner)."""
    from . import protected_subgraph as SS
    plain, vault_id = _open_like_a_run(body)
    classes = SS.missing_classes(SS.api_of(plain))
    return {"ok": True, "missing": bool(classes), **SS._note_missing(vault_id, classes, plain.get("packs") or [])}


def provision_plan(body: dict) -> dict:
    """V7: what this install lacks to run the vault - model COUNT and bytes, plus the node count (never names)."""
    from . import protected_subgraph as SS
    from . import provision
    plain, vault_id = _open_like_a_run(body)
    nodes_missing = len(vault_packs.needed(SS.missing_classes(SS.api_of(plain)), plain.get("packs") or [])[0])
    return {"ok": True, **provision.plan(plain), "nodes_missing": nodes_missing}


def provision_start(body: dict) -> dict:
    """V7: download the vault's missing model files (hash names, verified); progress as numbers only."""
    from . import provision
    if body.get("consent") is not True:
        raise VaultError("Downloading needs your consent (or the automatic setting).")
    plain, vault_id = _open_like_a_run(body)
    token = "p" + secrets.token_hex(8)
    return {"ok": True, "token": token, **provision.start(plain, token)}


def provision_status(body: dict) -> dict:
    from . import provision
    return {"ok": True, **provision.status(str(body.get("token") or ""))}


def provision_cancel(body: dict) -> dict:
    from . import provision
    provision.cancel(str(body.get("token") or ""))
    return {"ok": True}


def install_missing(body: dict) -> dict:
    """L9.50: clone the packs the vault needs at their pinned commits - only after the user's click (consent)."""
    from pathlib import Path

    from . import protected_subgraph as SS
    if body.get("consent") is not True:
        raise VaultError("Installing needs your consent (the Install button).")
    if vault_packs.disabled():
        raise VaultError(f"Installing custom nodes from a vault is switched off ({vault_packs.KILL_SWITCH}=off). "
                         "Install them manually.")
    plain, _vault_id = _open_like_a_run(body)
    classes = SS.missing_classes(SS.api_of(plain))
    want, unknown = vault_packs.needed(classes, plain.get("packs") or [])
    if not want:
        return {"ok": True, "installed": 0, "nothing": not classes, "unknown_classes": unknown}
    import folder_paths
    out = vault_packs.install(want, Path(folder_paths.get_folder_paths("custom_nodes")[0]))
    return {"ok": True, **out, "unknown_classes": unknown}


def access_cancel(body: dict) -> dict:
    with _lock:
        s = _EDITS.get(str(body.get("access_token") or ""))
        if s and s.get("kind") == "access":
            _EDITS.pop(str(body.get("access_token")), None)
    return {"ok": True}


def snapshot(body: dict) -> dict:
    """Queueing while a vault is open: encrypt the current edit WITHOUT ending the session, so the run uses the
    edited graph and nothing goes to the server in plaintext."""
    out = commit(dict(body, _keep_open=True))
    s = _session(str(body.get("edit_token") or ""))
    with _lock:
        s["payload_hash"] = _hash(out["payload"])
        s["at"] = time.time()
    return out


def commit(body: dict) -> dict:
    """Re-encrypt the edited inside under the session's key; the session ends (owner: exit = lock)."""
    from . import crypto as v2

    s = _session(str(body.get("edit_token") or ""))
    if body.get("payload_hash") and body["payload_hash"] != s["payload_hash"]:
        raise VaultError("This vault was changed elsewhere while it was open here. Reload the workflow and open it "
                         "again.")
    interface = body.get("interface") or {}
    api = body.get("api") or {}
    # V3: an edit that does not resend the conceal section keeps the vault concealed (never silently published);
    # an explicit `conceal: null` removes it (the front end asks the editor to confirm first)
    conceal = body["conceal"] if "conceal" in body else s.get("conceal")
    api, interface = _expose(api, interface, conceal)
    _validate_api(api, interface)
    plain = {"exec": boundary_exec(interface), "api": api, "ui": body.get("ui"), "interface": interface,
             "editors": s["editors"], "profile": s["profile"],
             "packs": vault_packs.record_safely(api, s["packs"]),                                    # L9.50
             "updated": int(time.time())}
    public = _with_conceal(plain, conceal)
    # V5: an explicit `lock` is checked strictly; the session's lock is kept only while it still fits the inside
    public_lock = (_with_lock(plain, body["lock"]) if "lock" in body
                   else _with_lock(plain, s.get("lock"), strict=False))
    recipients = None
    if s["profile"] == "sealed_installs":
        recipients = [base64.b64decode(r) for r in s["recipients"]] or _codes_to_keys([_this_install_code()])
    payload = v2.lock_with(plain, s["k"], vault_id=s["vault_id"], mode=PROFILES[s["profile"]],
                           iface=_iface(interface), recipients=recipients,
                           licensing=s.get("licensing") if s["profile"] == "sealed_licensed" else None)
    with _lock:
        s["lock"] = plain.get("lock")
    if s["profile"] == "locked" and s.get("client_id"):
        from . import protected_subgraph as SS
        SS.RUN_SESSIONS.put(s["client_id"], s["vault_id"], s["k"]["kek"])
    if not body.get("_keep_open"):
        with _lock:
            _EDITS.pop(str(body.get("edit_token")), None)
    out = {"ok": True, "payload": payload, "vault_id": s["vault_id"], "profile": s["profile"],
           "node_count": len(api["nodes"]), "public_lock": public_lock}
    if public is not None:
        out["public_interface"] = public
    return out


def cancel(body: dict) -> dict:
    with _lock:
        _EDITS.pop(str(body.get("edit_token") or ""), None)
    return {"ok": True}


def info(body: dict) -> dict:
    from . import crypto as v2
    payload = str(body.get("payload") or "")
    if not payload:
        return {"ok": False}
    mode = _mode_of(payload)
    return {"ok": True, "profile": PROFILE_NAMES.get(mode, "locked"),
            "obfuscation_only": mode == 2,
            "this_install": _this_install_code()}


# ── V5 licences (nodes/licence.py, design section 6) ───────────────────────────────────────────────────────────
NOT_LICENSED = "Licences are for vaults protected as Licensed installations."
NOT_AUTHOR_HERE = ("This installation does not hold the author key of this workflow. Restore your author key backup "
                   "first (H2Vault menu > Restore author key).")
MAX_LICENCE_DAYS = 3650


class _BadRequest(VaultError):
    status = 400


def _licensed(body: dict) -> tuple:
    from . import crypto as v2
    payload, vault_id = str(body.get("payload") or ""), str(body.get("vault_id") or "")
    try:
        p = v2.parse(payload)
    except VaultError as err:
        raise _BadRequest(str(err)) from None
    if vault_id and p["vault_id"] != vault_id:
        raise _BadRequest("Vault payload does not belong to this vault.")
    return payload, p["vault_id"], p


def _lic_error(fn):
    """LicenceError (plain text) -> a 400 answer with that text."""
    def run(body):
        from . import licence as L
        try:
            return fn(body)
        except L.LicenceError as exc:
            raise _BadRequest(str(exc)) from None
    run.__name__ = fn.__name__
    return run


def _public_licence(lic: dict) -> dict:
    from . import licence as L
    return {"lid": lic["lid"], "label": lic["label"], "issued": lic["issued"], "nbf": lic["nbf"], "exp": lic["exp"],
            "runs": lic["runs"], "runs_left": L.runs_left(lic),
            "exp_text": L.fmt_date(lic["exp"]) if lic["exp"] is not None else None}


@_lic_error
def licence_status(body: dict) -> dict:
    """May this installation run this Licensed vault now? (never counts a run)"""
    from . import crypto as v2, keys as vault_keys, licence as L
    payload, vault_id, p = _licensed(body)
    if p["mode"] != v2.MODE_SEALED_LICENSED:
        return {"ok": True, "licensed_vault": False}
    if vault_keys.install_private_key(create=False) is None:
        return {"ok": True, "licensed_vault": True, "licensed": False, "problem": L.NEEDS_LICENCE}
    from . import protected_subgraph as SS
    pub = vault_keys.install_public_key()
    try:                                                       # the same check as a run (this copy opens), no count
        _plain, lic = SS.open_licensed(payload, vault_id)
        problem = None
    except VaultError as exc:
        lic, problem = None, str(exc)
    out = {"ok": True, "licensed_vault": True, "licensed": lic is not None, "problem": problem,
           "install_code": vault_keys.public_text(pub)}
    if lic is not None:
        out["licence"] = _public_licence(lic)
    return out


@_lic_error
def licence_add(body: dict) -> dict:
    from . import crypto as v2, keys as vault_keys, licence as L
    payload, vault_id, p = _licensed(body)
    if p["mode"] != v2.MODE_SEALED_LICENSED:
        raise _BadRequest(NOT_LICENSED)
    lic = L.add(str(body.get("licence") or ""), author_pub=p["author_pub"], vault_id=vault_id,
                install_pub=vault_keys.install_public_key())
    return {"ok": True, "licence": _public_licence(lic)}


@_lic_error
def licence_remove(body: dict) -> dict:
    from . import licence as L
    return {"ok": True, "removed": L.remove(str(body.get("lid") or ""))}


def _author_for(p: dict) -> bytes:
    from . import licence as L
    priv = L.author_private_key(create=False)
    if priv is None or L.ed25519_public(priv) != p["author_pub"]:
        raise VaultError(NOT_AUTHOR_HERE)
    return priv


def _licence_terms(body: dict, now: int) -> dict:
    exp = body.get("exp")
    days = body.get("exp_days")
    if exp is not None:
        if not isinstance(exp, int) or isinstance(exp, bool):
            raise _BadRequest("The end date is not a valid date.")
    elif days is not None:
        if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= MAX_LICENCE_DAYS:
            raise _BadRequest(f"Choose between 1 and {MAX_LICENCE_DAYS} days.")
        exp = now + days * 86400
    runs = body.get("runs")
    if runs is not None and (not isinstance(runs, int) or isinstance(runs, bool) or not 1 <= runs <= 10_000_000):
        raise _BadRequest("The run limit must be a whole number of at least 1.")
    return {"exp": exp, "runs": runs, "label": str(body.get("label") or "").strip()[:60]}


@_lic_error
def licence_issue(body: dict) -> dict:
    """The author signs a licence for one installation (password + second factor + editor, as opening)."""
    from . import crypto as v2, keys as vault_keys, licence as L
    payload, vault_id, p = _licensed(body)
    if p["mode"] != v2.MODE_SEALED_LICENSED:
        raise _BadRequest(NOT_LICENSED)
    install_pub = vault_keys.parse_public_text(str(body.get("install_code") or ""))
    now = int(time.time())
    terms = _licence_terms(body, now)
    plain, _k, _factor, refused = _authorize(body, require_editor=not _holds_author_key(p))
    if refused:
        return refused
    author_priv = _author_for(p)
    lk = v2.licensing_of(plain)["lk"]
    text = L.issue(author_priv=author_priv, vault_id=vault_id, lk=lk, install_pub=install_pub, now=now, **terms)
    lic = L.parse(text)
    L.ledger_add({**lic, "lid": lic["lid"], "vault_id": vault_id, "vault_title": str(body.get("title") or "")[:80],
                  "install_code": vault_keys.public_text(install_pub)})
    return {"ok": True, "licence_text": text, "licence": _public_licence(lic)}


@_lic_error
def licence_rotate(body: dict) -> dict:
    """Revoke every licence of this vault: a new licence key, the vault re-sealed (same id and password), then fresh
    licences for the Ledger rows the author ticked. Old copies of the workflow keep running for old holders."""
    from . import crypto as v2, keys as vault_keys, licence as L
    payload, vault_id, p = _licensed(body)
    if p["mode"] != v2.MODE_SEALED_LICENSED:
        raise _BadRequest(NOT_LICENSED)
    plain, k, _factor, refused = _authorize(body)
    if refused:
        return refused
    author_priv = _author_for(p)
    licensing = {"lk": os.urandom(32), "author_pub": p["author_pub"]}
    inner = {key: v for key, v in plain.items() if key not in ("recipients", "format")}
    inner["updated"] = int(time.time())
    new_payload = v2.lock_with(inner, k, vault_id=vault_id, mode=v2.MODE_SEALED_LICENSED,
                               iface=_iface(plain.get("interface") or {}), licensing=licensing)
    v2.open_with_licence_key(new_payload, licensing["lk"], vault_id=vault_id)      # it opens, or nothing changes
    reissued = []
    now = int(time.time())
    for lid in body.get("reissue") or []:
        row = L.ledger_row(str(lid))
        if not row or row.get("vault_id") != vault_id:
            continue
        exp = row.get("exp")
        if exp is not None and exp <= now:                     # an ended licence is not renewed by a rotation
            continue
        pub = vault_keys.parse_public_text(row["install_code"])
        text = L.issue(author_priv=author_priv, vault_id=vault_id, lk=licensing["lk"], install_pub=pub,
                       label=row.get("label") or "", exp=exp, runs=row.get("runs"), now=now)
        lic = L.parse(text)
        L.ledger_add({**lic, "vault_id": vault_id, "vault_title": row.get("vault_title") or "",
                      "install_code": row["install_code"]})
        reissued.append({"licence_text": text, "licence": _public_licence(lic), "replaces": str(lid)})
    _license_this_installation(vault_id, licensing)
    with _lock:
        for t in [t for t, x in _EDITS.items() if x.get("vault_id") == vault_id]:
            _EDITS.pop(t, None)                                # every open session holds the old licence key
    return {"ok": True, "payload": new_payload, "vault_id": vault_id, "reissued": reissued}


def licence_ledger(_body: dict) -> dict:
    from . import licence as L
    now = time.time()
    rows = []
    for r in L.ledger_rows():
        exp = r.get("exp")
        state = "active" if exp is None or exp > now + 7 * 86400 else ("expiring" if exp > now else "ended")
        rows.append({**r, "state": state, "exp_text": L.fmt_date(exp) if exp else None})
    return {"ok": True, "rows": rows}


NOT_THIS_AUTHOR = "This backup is not the author key of this workflow."


@_lic_error
def author_export(body: dict) -> dict:
    """Back up the author key - with the same proof as issuing a licence (review P1-4): a Licensed vault of this
    author, its password, the authenticator code and the editor list; the stored key must be that vault's author key."""
    from . import crypto as v2, licence as L
    payload, vault_id, p = _licensed(body)
    if p["mode"] != v2.MODE_SEALED_LICENSED:
        raise _BadRequest(NOT_LICENSED)
    file_password = str(body.get("file_password") or "")
    if len(file_password) < 8:                                 # checked before the password: never a counted guess
        raise _BadRequest("Choose a password of at least 8 characters for the backup.")
    _plain, _k, _factor, refused = _authorize(body, require_editor=not _holds_author_key(p))
    if refused:
        return refused
    _author_for(p)
    return {"ok": True, "file": L.export_author(file_password)}


@_lic_error
def author_import(body: dict) -> dict:
    """Restore the author key - same proof as issuing, and the backup must be THIS vault's author key. Replacing a
    different key needs `replace: true` AND `confirm: "replace"`, and the current key is first written to a dated,
    password-encrypted backup file in the H2Vault user folder (review P1-4)."""
    from . import crypto as v2, licence as L
    payload, vault_id, p = _licensed(body)
    if p["mode"] != v2.MODE_SEALED_LICENSED:
        raise _BadRequest(NOT_LICENSED)
    file_password = str(body.get("file_password") or "")
    # restore on the author's NEW computer: that installation is not an editor yet; the backup must still be this
    # vault's author key (checked below), with the vault password + authenticator + the backup's own password
    _plain, _k, _factor, refused = _authorize(body, require_editor=False)
    if refused:
        return refused
    priv = L.read_author_file(body.get("file"), file_password)
    if L.ed25519_public(priv) != p["author_pub"]:
        raise _BadRequest(NOT_THIS_AUTHOR)
    backup = None
    cur = L.author_private_key(create=False)
    if cur and cur != priv:
        if not (body.get("replace") is True and body.get("confirm") == "replace"):
            raise VaultError(L.OTHER_AUTHOR_KEY)
        backup = L.backup_current_author(file_password)
    L.store_author(priv)
    return {"ok": True, "author": L.key_id(L.ed25519_public(priv)), "backup": backup.name if backup else None}


# ── second factor (CNP vault_node /c2c_vault/2fa/*) ──────────────────────────────────────────────────────────────
def tfa_status(_body: dict) -> dict:
    from . import twofactor
    return {"ok": True, "enrolled": twofactor.enrolled(), "locked_out_seconds": int(twofactor.locked_out()),
            "recovery_codes_left": twofactor.recovery_codes_left()}


def tfa_begin(_body: dict) -> dict:
    from . import twofactor
    try:
        return {"ok": True, **twofactor.begin_enrolment()}
    except PermissionError as exc:                            # already enrolled: a conflict, not a rate limit
        raise _Conflict(str(exc)) from None


def tfa_confirm(body: dict) -> dict:
    from . import twofactor
    try:
        ok = twofactor.confirm_enrolment(str(body.get("code") or ""))
    except PermissionError as exc:
        raise _Conflict(str(exc)) from None
    return {"ok": ok, "error": None if ok else (twofactor.last_enrolment_error() or "That code is not right.")}


def tfa_reset(body: dict) -> dict:
    from . import twofactor
    return {"ok": twofactor.reset(str(body.get("code") or ""))}


class _Conflict(VaultError):
    status = 409


def register_routes(server) -> None:
    from aiohttp import web

    from .local_guard import refuse_remote

    routes = server.routes

    def wrap(fn, status_on_error=403, offload=False, local_only=None, local_when=None):
        """`local_only`: a phrase naming the feature - the route then answers only the ComfyUI page on this machine.
        `local_when(body)` -> such a phrase for requests that need it (a Licensed protect creates the author key)."""
        async def handler(request):
            if local_only:
                refused = refuse_remote(request, local_only)
                if refused is not None:
                    return refused
            try:
                body = await request.json() if request.method == "POST" else {}
            except Exception:  # noqa: BLE001
                body = {}
            phrase = local_when(body) if local_when and isinstance(body, dict) else None
            if phrase:
                refused = refuse_remote(request, phrase)
                if refused is not None:
                    return refused
            try:
                if offload:                                   # L9.263: the password KDF runs off the event loop
                    import asyncio
                    out = await asyncio.get_running_loop().run_in_executor(None, fn, body)
                else:
                    out = fn(body)
                status = 200 if out.get("ok", True) else 403
                return web.json_response({"ok": True, **out} if "ok" not in out else out, status=status)
            except VaultError as exc:
                return web.json_response({"ok": False, "error": str(exc)},
                                         status=getattr(exc, "status", None) or status_on_error)
            except PermissionError as exc:
                return web.json_response({"ok": False, "error": str(exc)}, status=429)
        return handler

    routes.post("/h2vault/vault/protect")(wrap(protect, 400, offload=True, local_when=lambda b: (
        "Protecting as Licensed (it creates your author key)" if b.get("profile") == "sealed_licensed" else None)))   # V7: hashing model files is slow
    routes.post("/h2vault/vault/conceal/check")(wrap(conceal_check, 400))
    routes.post("/h2vault/vault/protect/abort")(wrap(protect_abort))
    routes.post("/h2vault/vault/unlock_run")(wrap(unlock_run, offload=True))
    routes.post("/h2vault/vault/forget_run")(wrap(forget_run))
    routes.post("/h2vault/vault/open")(wrap(open_for_edit, offload=True))           # password KDF off the loop
    routes.post("/h2vault/vault/commit")(wrap(commit, 409))
    routes.post("/h2vault/vault/snapshot")(wrap(snapshot, 409))
    routes.post("/h2vault/vault/cancel")(wrap(cancel))
    routes.post("/h2vault/vault/info")(wrap(info, 400))
    async def install_handler(request):                       # git clone can take a minute: off the event loop
        import asyncio
        refused = refuse_remote(request, "Installing custom nodes")
        if refused is not None:
            return refused
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        try:
            out = await asyncio.get_running_loop().run_in_executor(None, install_missing, body)
            return web.json_response(out)
        except VaultError as exc:
            return web.json_response({"ok": False, "error": str(exc)}, status=403)

    routes.post("/h2vault/vault/missing")(wrap(missing))
    routes.post("/h2vault/vault/provision/plan")(wrap(provision_plan, local_only="Preparing a vault"))
    routes.post("/h2vault/vault/provision/start")(wrap(provision_start, local_only="Preparing a vault"))
    routes.post("/h2vault/vault/provision/status")(wrap(provision_status, local_only="Preparing a vault"))
    routes.post("/h2vault/vault/provision/cancel")(wrap(provision_cancel, local_only="Preparing a vault"))
    routes.post("/h2vault/vault/install_missing")(install_handler)
    routes.post("/h2vault/vault/access/open")(wrap(access_open, offload=True))
    routes.post("/h2vault/vault/access/apply")(wrap(access_apply, 409))
    routes.post("/h2vault/vault/access/cancel")(wrap(access_cancel))
    async def install_code(request):
        # the first call creates this installation's key pair: only the local page may cause that write
        from . import keys as vault_keys
        if vault_keys.install_private_key(create=False) is None:
            refused = refuse_remote(request, "Creating this installation's key")
            if refused is not None:
                return refused
        try:
            return web.json_response({"ok": True, "code": _this_install_code()})
        except VaultError as exc:
            return web.json_response({"ok": False, "error": str(exc)}, status=500)

    routes.get("/h2vault/vault/install_code")(install_code)
    routes.get("/h2vault/2fa/status")(wrap(tfa_status))
    routes.post("/h2vault/2fa/enrol/begin")(wrap(tfa_begin, 409, local_only="Setting up the authenticator"))
    routes.post("/h2vault/2fa/enrol/confirm")(wrap(tfa_confirm, 403, local_only="Setting up the authenticator"))
    routes.post("/h2vault/2fa/reset")(wrap(tfa_reset, 403, local_only="Resetting the authenticator"))
    # V5 licences
    routes.post("/h2vault/licence/status")(wrap(licence_status, 400, local_only="Licence status"))
    routes.post("/h2vault/licence/add")(wrap(licence_add, 400, local_only="Adding a licence"))
    routes.post("/h2vault/licence/remove")(wrap(licence_remove, 400, local_only="Removing a licence"))
    routes.post("/h2vault/licence/issue")(wrap(licence_issue, 403, offload=True, local_only="Issuing a licence"))
    routes.post("/h2vault/licence/rotate")(wrap(licence_rotate, 403, offload=True,
                                                local_only="Revoking licences"))
    routes.get("/h2vault/licence/ledger")(wrap(licence_ledger, 400, local_only="The licence ledger"))
    routes.post("/h2vault/licence/author/export")(wrap(author_export, 400, offload=True,
                                                       local_only="Backing up the author key"))
    routes.post("/h2vault/licence/author/import")(wrap(author_import, 400, offload=True,
                                                       local_only="Restoring the author key"))
