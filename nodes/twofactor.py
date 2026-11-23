# Derived from Code2Collapse ComfyUI-CustomNodePacks nodes/vault_2fa.py (Apache-2.0, Copyright Code2Collapse);
# modified for H2Vault (AGPL-3.0). See NOTICE.
"""Second factor for opening a vault to edit, per person per install (A17 s2.6, owner D0.25; methods 2026-11-23).

Methods (set up on this installation; a vault chooses which of them may open it - `policy_of`):
  totp             authenticator apps, RFC 6238 via the `cryptography` package (SHA-1, 6 digits, 30 s - what apps
                   use), up to MAX_AUTHENTICATORS per install, each with a name (phone, backup phone, a second
                   editor's app ...); a code of any of them is accepted. Codes from one step before / after are
                   accepted (clock drift); a code works once per app.
  passkey          passkey / security key / Windows Hello through WebAuthn (`webauthn_min`), several per install.
  backup_password  a second secret, different from any vault password; stored as an scrypt hash.
  recovery         single-use recovery codes (8 per set), stored as scrypt hashes; always allowed as a fallback.
Email and SMS codes need a mail / SMS provider and a server that sends them: not possible offline (`NOT_OFFLINE`).

A vault may also need no second factor at all ("Password only", owner 2026-11-23): its method list is empty.

Policies (L9.343, docs/AUTH_POLICY.md): a vault needs ANY one (OR) or ALL (AND) of its chosen factors, with an explicit
recovery-code rule and, optionally, only particular authenticator apps. `policy_detail` reads any stored form (old
vaults map to the equivalent policy); `verify_policy` checks every given factor WITHOUT side effects first and commits
(time step, used-up recovery code, passkey counter) only when all of them pass.

Everything lives only in the local secrets store (`store`), never in a workflow, never derived from a vault password.
Each authenticator secret is its own store entry (`totp_auth_<id>`, index `totp_authenticators`): the Windows
credential store keeps at most 2560 bytes per entry, so a growing list never shares one entry.
Failed attempts are counted per scope (a vault id, or "manage" for settings) and across all scopes; the lockout grows
exponentially (5 min, 10, 20 ... capped at 1 h) and is persisted, so a restart does not reset it. Comparisons are
constant time.

Honest scope: this protects editing against other users of this ComfyUI and casual access. The machine's administrator
can remove every method (`admin_reset_from_env`, H2VAULT_RESET_SECOND_FACTOR=remove-all at start) - that is the
documented way back when every method is lost; nothing else about the vaults changes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import threading
import time
from typing import Optional

from . import store as vault_store

log = logging.getLogger("h2vault.twofactor")

DIGITS, STEP, WINDOW = 6, 30, 1
MAX_FAILS, LOCKOUT_SECONDS = 5, 5 * 60
MAX_FAILS_ALL, MAX_LOCKOUT_SECONDS = 10, 60 * 60
_SECRET, _LAST, _RECOVERY, _FAILS = "totp_secret", "totp_last_step", "totp_recovery", "totp_fails"
_BACKUP_PW, _PASSKEYS, _USER_HANDLE = "backup_password", "webauthn_credentials", "webauthn_user"
_AUTH_INDEX, _AUTH_PREFIX = "totp_authenticators", "totp_auth_"     # several authenticator apps (2026-11-23)
_lock = threading.RLock()
_pending: dict = {}                    # enrolment waiting for its first code: {"secret": bytes, "codes": [...]}
_challenges: dict = {}                 # passkey challenges: id -> {"challenge", "kind", "rp_id", "at", "label"}
_manage: dict = {}                     # settings tokens: token -> expiry (monotonic)

METHODS = ("totp", "passkey", "backup_password", "recovery")
DEFAULT_POLICY = ("totp", "recovery")  # vaults locked before methods existed (no stored choice)
# The one question the author answers ("How should this vault be opened for editing?") -> the vault's method list.
# Anything else is "custom" (Advanced: pick methods). Recovery codes join every list that needs a second factor.
CHOICES = {"password": (), "totp": ("totp", "recovery"), "passkey": ("passkey", "recovery"),
           "backup_password": ("backup_password", "recovery"),
           "any": ("totp", "passkey", "backup_password", "recovery")}
MAX_AUTHENTICATORS = 10              # the default; H2VAULT_MAX_AUTHENTICATORS may raise it up to the cap
MAX_AUTHENTICATORS_CAP, MAX_AUTHENTICATORS_ENV = 50, "H2VAULT_MAX_AUTHENTICATORS"
FACTORS = ("totp", "passkey", "backup_password")             # what a policy chooses; recovery codes have a rule
MODES = ("any", "all")
# the recovery-code rule a mode allows, the default first (docs/AUTH_POLICY.md section 4)
RECOVERY_RULES = {"any": ("fallback", "off"), "all": ("off", "replace_one", "override")}
RECOVERY_MODES = ("auto", "new", "keep")                     # begin_enrolment: what happens to the recovery codes
LABEL_MAX = 60
METHOD_LABELS = {"totp": "Authenticator app", "passkey": "Passkey or security key",
                 "backup_password": "Backup password", "recovery": "Recovery code"}
NOT_OFFLINE = {
    "email": "Email codes need an email provider and a server that sends mail; H2Vault works offline, so it cannot "
             "send them.",
    "sms": "Text-message codes need an SMS provider (paid, online); H2Vault works offline, so it cannot send them."}
RECOVERY_COUNT = 8
BACKUP_PASSWORD_MIN = 10
CHALLENGE_SECONDS, CHALLENGE_MAX = 5 * 60, 64
MANAGE_SECONDS = 10 * 60
# scrypt (RFC 7914) cost: N=2^14 (16 MiB, tens of ms) for 50-bit random recovery codes, N=2^15 for a chosen password
RECOVERY_KDF = {"n": 2 ** 14, "r": 8, "p": 1}
PASSWORD_KDF = {"n": 2 ** 15, "r": 8, "p": 1}


def max_authenticators() -> int:
    """How many authenticator apps one installation may have: MAX_AUTHENTICATORS, or H2VAULT_MAX_AUTHENTICATORS (1 to
    MAX_AUTHENTICATORS_CAP). Safe for the credential store: every app is its own small entry (< 400 bytes) and the index
    holds only ids (~15 bytes each), far below the Windows limit of 2560 bytes per entry."""
    try:
        n = int(os.environ.get(MAX_AUTHENTICATORS_ENV, "") or MAX_AUTHENTICATORS)
    except ValueError:
        n = MAX_AUTHENTICATORS
    return max(1, min(MAX_AUTHENTICATORS_CAP, n))


def _totp(secret: bytes):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.twofactor.totp import TOTP

    return TOTP(secret, DIGITS, hashes.SHA1(), STEP, enforce_key_length=False)


def _scrypt(secret: str, salt: bytes, kdf: dict) -> bytes:
    n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
    return hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=256 * 1024 * 1024, dklen=32)


# ── what is set up ──────────────────────────────────────────────────────────────────────────────────────────────
def enrolled() -> bool:
    """At least one authenticator app is set up (the historical meaning; see any_enrolled for 'some method')."""
    return bool(_authenticators())


# ── authenticator apps: one store entry each ────────────────────────────────────────────────────────────────────
def _auth_ids() -> list:
    try:
        ids = json.loads(vault_store.get(_AUTH_INDEX) or "[]")
    except ValueError:
        ids = []
    return [i for i in ids if isinstance(i, str) and i] if isinstance(ids, list) else []


def _auth_save(rec: dict) -> None:
    vault_store.put(_AUTH_PREFIX + rec["id"], json.dumps(rec))
    ids = _auth_ids()
    if rec["id"] not in ids:
        vault_store.put(_AUTH_INDEX, json.dumps(ids + [rec["id"]]))


def _auth_delete(aid: str) -> None:
    vault_store.delete(_AUTH_PREFIX + aid)
    ids = [i for i in _auth_ids() if i != aid]
    if ids:
        vault_store.put(_AUTH_INDEX, json.dumps(ids))
    else:
        vault_store.delete(_AUTH_INDEX)


def _migrate_single_secret() -> None:
    """The first release kept ONE secret (`totp_secret` + `totp_last_step`): it becomes the first named app. Written
    before the old entries are removed, so an interruption never loses it."""
    legacy = vault_store.get(_SECRET)
    if not legacy:
        return
    try:
        last = int(vault_store.get(_LAST) or "-1")
    except ValueError:
        last = -1
    _auth_save({"id": secrets.token_hex(6), "label": "Authenticator app", "secret": legacy, "last_step": last,
                "created": 0, "last_used": 0})
    vault_store.delete(_SECRET)
    vault_store.delete(_LAST)


def _authenticators() -> list:
    """Every authenticator app of this installation, oldest first: [{"id", "label", "secret" (base64), "last_step",
    "created", "last_used"}]. Internal: the secret never leaves this module (see authenticators_public)."""
    with _lock:
        _migrate_single_secret()
        out = []
        for aid in _auth_ids():
            try:
                rec = json.loads(vault_store.get(_AUTH_PREFIX + aid) or "null")
            except ValueError:
                rec = None
            if isinstance(rec, dict) and rec.get("secret"):
                out.append({**rec, "id": aid})
        return out


def authenticators_public() -> list:
    """Names and dates only - never a secret."""
    return [{"id": a["id"], "label": a.get("label") or "Authenticator app", "created": a.get("created", 0),
             "last_used": a.get("last_used", 0)} for a in _authenticators()]


def _clean_label(label) -> str:
    return " ".join(str(label or "").split())[:LABEL_MAX]


def _label_taken(label: str, auths: list, except_id: str = "") -> bool:
    return any(a["id"] != except_id and str(a.get("label", "")).casefold() == label.casefold() for a in auths)


def _default_label(auths: list) -> str:
    n, label = len(auths) + 1, "Authenticator app"
    while _label_taken(label, auths):
        label = f"Authenticator app {n}"
        n += 1
    return label


def rename_totp(auth_id: str, label: str) -> None:
    label = _clean_label(label)
    if not label:
        raise ValueError("Give the authenticator a name, e.g. 'My phone'.")
    with _lock:
        auths = _authenticators()
        rec = next((a for a in auths if a["id"] == str(auth_id)), None)
        if rec is None:
            raise LookupError("That authenticator is not set up here any more (removed in another tab?). Reload this "
                              "list.")
        if _label_taken(label, auths, rec["id"]):
            raise ValueError(f"Another authenticator is already called '{label}'. Choose another name.")
        rec["label"] = label
        _auth_save(rec)


def _passkeys() -> list:
    try:
        out = json.loads(vault_store.get(_PASSKEYS) or "[]")
        return out if isinstance(out, list) else []
    except ValueError:
        return []


def _save_passkeys(creds: list) -> None:
    if creds:
        vault_store.put(_PASSKEYS, json.dumps(creds))
    else:
        vault_store.delete(_PASSKEYS)


def methods_set_up() -> dict:
    """{"totp": apps, "passkey": count, "backup_password": bool, "recovery": codes left} - never a secret."""
    return {"totp": len(_authenticators()), "passkey": len(_passkeys()),
            "backup_password": bool(vault_store.get(_BACKUP_PW)), "recovery": recovery_codes_left()}


def usable_methods() -> list:
    m = methods_set_up()
    return [k for k in METHODS if m[k]]


def any_enrolled() -> bool:
    return bool(usable_methods())


# ── which methods a vault accepts ───────────────────────────────────────────────────────────────────────────────
def normalise_policy(methods) -> list:
    """The author's choice -> canonical list. At least one method besides recovery codes; recovery codes are always
    included (the fallback when a phone or key is lost). Raises ValueError in plain words."""
    if not isinstance(methods, (list, tuple)):
        raise ValueError("Choose which second factors may open this vault.")
    chosen = {str(m) for m in methods}
    unknown = chosen - set(METHODS)
    if unknown:
        raise ValueError(f"Unknown second-factor method: {sorted(unknown)[0]}.")
    if not chosen - {"recovery"}:
        raise ValueError("Choose at least one second factor besides recovery codes (authenticator app, passkey or "
                         "backup password).")
    chosen.add("recovery")
    return [m for m in METHODS if m in chosen]


def normalise_choice(value) -> list:
    """The author's answer -> canonical method list. {"choice": one of CHOICES} (the one question; "password" = []),
    or {"choice": "custom" / absent, "methods": [...]} (Advanced: pick methods). An empty list is accepted ONLY as the
    explicit "password" choice, so a buggy client never makes a vault password-only by accident."""
    if isinstance(value, dict) and value.get("choice") not in (None, "custom"):
        choice = str(value.get("choice"))
        if choice not in CHOICES:
            raise ValueError(f"Unknown protection choice: {choice[:40]}.")
        return list(CHOICES[choice])
    return normalise_policy(value.get("methods") if isinstance(value, dict) else value)


def choice_of(methods) -> str:
    """The method list -> the answer to the one question ("custom" when no simple answer fits)."""
    have = set(methods or [])
    if have:
        have.add("recovery")                                   # always part of a list that needs a second factor
    for choice, listed in CHOICES.items():
        if have == set(listed):
            return choice
    return "custom"


def policy_of(plain: dict) -> list:
    """The methods a vault accepts ([] = password only). Vaults locked before methods existed accept the
    authenticator + recovery codes. An H2Vault from before "Password only" reads [] as damaged and falls back to the
    authenticator + recovery codes: stricter, never weaker. L9.343: the methods that can play a part under the vault's
    policy (`policy_detail`; the same lists as before for every vault of the previous format)."""
    return accepted_methods(policy_detail(plain))


def labels(methods) -> str:
    return ", ".join(METHOD_LABELS[m] for m in methods if m in METHOD_LABELS)


# ── policies: ANY / ALL of the chosen factors (L9.343, docs/AUTH_POLICY.md) ─────────────────────────────────────
PASSWORD_ONLY = {"methods": [], "mode": "any", "recovery": "off", "authenticators": []}
DEFAULT_DETAIL = {"methods": ["totp"], "mode": "any", "recovery": "fallback", "authenticators": []}
STRICTEST = {"methods": list(FACTORS), "mode": "all", "recovery": "off", "authenticators": []}


def _read_policy(sf: dict) -> dict:
    """A stored `second_factor` record -> policy detail. Raises ValueError on anything it cannot read."""
    if sf.get("v") is not None and sf.get("v") != 2:
        raise ValueError("a policy format this H2Vault does not know")
    if sf.get("v") == 2:
        raw = sf.get("methods")
        if not isinstance(raw, list) or {str(m) for m in raw} - set(METHODS):
            raise ValueError("bad methods")
        factors = [m for m in FACTORS if m in raw]
        mode, rule = sf.get("mode"), sf.get("recovery")
        if not factors or mode not in MODES or rule not in RECOVERY_RULES[mode]:
            raise ValueError("bad policy")
        auths = sf.get("authenticators") or []
        if not isinstance(auths, list) or not all(isinstance(a, str) and a for a in auths) or (
                auths and "totp" not in factors):
            raise ValueError("bad authenticators")
        return {"methods": factors, "mode": mode, "recovery": rule, "authenticators": list(auths)}
    if sf.get("methods") == []:
        return dict(PASSWORD_ONLY, methods=[], authenticators=[])
    listed = normalise_policy(sf.get("methods"))               # the format before L9.343: OR, recovery as fallback
    return {"methods": [m for m in listed if m != "recovery"], "mode": "any", "recovery": "fallback",
            "authenticators": []}


def policy_detail(plain: dict) -> dict:
    """The vault's policy {"methods": [factors], "mode": "any"|"all", "recovery": rule, "authenticators": [ids]}.
    Old vaults map to the equivalent policy (docs/AUTH_POLICY.md section 2); anything unreadable to the authenticator
    app + recovery codes (stricter, never weaker - as policy_of always did)."""
    sf = plain.get("second_factor") if isinstance(plain, dict) else None
    if isinstance(sf, dict):
        try:
            return _read_policy(sf)
        except (ValueError, TypeError):
            if sf.get("v") is not None:                        # a policy record this code cannot read (damaged, or
                return dict(STRICTEST, methods=list(FACTORS), authenticators=[])   # newer): never weaker
    return dict(DEFAULT_DETAIL, methods=["totp"], authenticators=[])


def accepted_methods(policy: dict) -> list:
    """Every method that can play a part in opening the vault ([] = password only), in METHODS order."""
    if not policy["methods"]:
        return []
    return [m for m in METHODS if m in policy["methods"] or (m == "recovery" and policy["recovery"] != "off")]


def normalise_policy_choice(value) -> dict:
    """The author's answer -> what the vault stores. The one question ({"choice": ...}) and the previous Advanced form
    ({"methods": [...]}) store the old shape {"methods": [...]}; a policy ({"methods", "mode", "recovery",
    "authenticators"}) stores the old shape too when it means the same (OR, recovery as fallback, every app), else a
    `v: 2` record. Raises ValueError in plain words."""
    if not isinstance(value, dict) or value.get("choice") not in (None, "custom") or not (
            "mode" in value or "recovery" in value or value.get("authenticators")):
        return {"methods": normalise_choice(value)}
    raw = value.get("methods")
    if not isinstance(raw, (list, tuple)):
        raise ValueError("Choose which second factors may open this vault.")
    unknown = {str(m) for m in raw} - set(METHODS)
    if unknown:
        raise ValueError(f"Unknown second-factor method: {sorted(unknown)[0]}.")
    factors = [m for m in FACTORS if m in {str(x) for x in raw}]
    if not factors:
        raise ValueError("Choose at least one second factor besides recovery codes (authenticator app, passkey or "
                         "backup password).")
    mode = str(value.get("mode") or "any")
    if mode not in MODES:
        raise ValueError("Choose whether ANY one of the factors is enough or ALL of them are needed.")
    rule = str(value.get("recovery") or RECOVERY_RULES[mode][0])
    if rule not in RECOVERY_RULES[mode]:
        raise ValueError("With 'any one factor', recovery codes are either accepted or not; with 'all factors' they "
                         "are not accepted, may replace one missing factor, or are an emergency override.")
    if mode == "all" and rule == "replace_one" and len(factors) == 1:
        raise ValueError("With only one factor, 'a recovery code may replace one missing factor' would let a recovery "
                         "code alone open the vault. Choose 'Emergency override' if that is what you want, or tick "
                         "more factors.")
    auths = value.get("authenticators") or []
    if not isinstance(auths, (list, tuple)):
        raise ValueError("Choose the authenticator apps from the list.")
    auths = list(dict.fromkeys(str(a) for a in auths if str(a or "")))
    if auths:
        if "totp" not in factors:
            raise ValueError("Particular authenticator apps can be chosen only when the vault accepts an authenticator "
                             "app.")
        known = {a["id"] for a in _authenticators()}
        if any(a not in known for a in auths):
            raise ValueError("One of the chosen authenticator apps is not set up on this installation (removed in "
                             "another tab?). Reload the list and choose again.")
    if mode == "any" and rule == "fallback" and not auths:
        return {"methods": factors + ["recovery"]}             # byte-for-byte the format before L9.343
    out = {"methods": factors, "mode": mode, "recovery": rule, "v": 2}
    if auths:
        out["authenticators"] = auths
    return out


FACTOR_WORDS = {"totp": "a code from an authenticator app", "passkey": "a passkey or security key",
                "backup_password": "the backup password"}
RECOVERY_WORDS = {
    ("any", "fallback"): "A recovery code can be used instead (each works once).",
    ("any", "off"): "Recovery codes are not accepted.",
    ("all", "off"): "Recovery codes are not accepted.",
    ("all", "replace_one"): "A recovery code may replace ONE missing factor (each code works once).",
    ("all", "override"): "Emergency override: the password plus a recovery code alone also opens it (each code works "
                         "once)."}


def policy_summary(policy: dict, app_names=None) -> str:
    """The policy in one or two plain sentences (the same words as the lock dialog's preview)."""
    if not policy["methods"]:
        return "The vault password only - no second factor."
    words = []
    for m in policy["methods"]:
        if m == "totp" and policy["authenticators"]:
            names = [n for n in (app_names or []) if n]
            words.append("a code from " + (f"one of these authenticator apps: {', '.join(names)}" if names else
                                           "one of the authenticator apps chosen for this vault"))
        else:
            words.append(FACTOR_WORDS[m])
    if len(words) == 1:
        need = words[0]
    elif policy["mode"] == "any":
        need = "ONE of: " + ", ".join(words[:-1]) + " or " + words[-1]
    else:
        need = " AND ".join(words)
    return f"The vault password AND {need}. {RECOVERY_WORDS[(policy['mode'], policy['recovery'])]}"


def policy_public(policy: dict) -> dict:
    """What an answer may say about a policy: kinds, mode, rule, the NAMES of the chosen apps - never a secret."""
    names = []
    if policy["authenticators"]:
        known = {a["id"]: a.get("label") or "Authenticator app" for a in _authenticators()}
        names = [known[i] for i in policy["authenticators"] if i in known]
    return {"methods": list(policy["methods"]), "mode": policy["mode"], "recovery": policy["recovery"],
            "accepted": accepted_methods(policy), "authenticators": names,
            "restricted": bool(policy["authenticators"]), "summary": policy_summary(policy, names)}


def satisfiable(policy: dict, have: dict, auth_ids=None) -> str:
    """Can the policy still be met with `have` ({method: count / bool}, methods_set_up form) and the authenticator
    app ids `auth_ids`? -> "ok", "recovery_only" (only by a recovery code) or "no"."""
    factors = policy["methods"]
    if not factors:
        return "ok"
    chosen = set(policy.get("authenticators") or [])

    def available(m):
        if m == "totp" and chosen and auth_ids is not None:
            return bool(chosen & set(auth_ids))
        return bool(have.get(m))
    met = [m for m in factors if available(m)]
    codes = bool(have.get("recovery"))
    if policy["mode"] == "any":
        if met:
            return "ok"
        return "recovery_only" if policy["recovery"] == "fallback" and codes else "no"
    if len(met) == len(factors):
        return "ok"
    if codes and (policy["recovery"] == "override" or
                  (policy["recovery"] == "replace_one" and len(factors) - len(met) == 1)):
        return "recovery_only"
    return "no"


# ── failures and lockout (per scope + across scopes, exponential) ───────────────────────────────────────────────
def _fails_load() -> dict:
    try:
        state = json.loads(vault_store.get(_FAILS) or "{}")
    except ValueError:
        state = {}
    if not isinstance(state, dict):
        state = {}
    if "count" in state:                                       # the format before scopes: one install-wide counter
        state = {"scopes": {"manage": {"count": state.get("count", 0), "until": state.get("until", 0)}}}
    state.setdefault("scopes", {})
    return state


def _fails_save(state: dict) -> None:
    scopes = state.get("scopes", {})
    if len(scopes) > 256:                                      # keep the busiest; a counter is never lost silently
        keep = sorted(scopes.items(), key=lambda kv: (kv[0] == "*", kv[1].get("count", 0)), reverse=True)[:256]
        state["scopes"] = dict(keep)
    if state["scopes"]:
        vault_store.put(_FAILS, json.dumps(state))
    else:
        vault_store.delete(_FAILS)


def _remaining(entry: dict, limit: int, t: float) -> float:
    if int(entry.get("count", 0)) < limit:
        return 0.0
    return max(0.0, float(entry.get("until", 0)) - t)


def locked_out(now: Optional[float] = None, scope: Optional[str] = None) -> float:
    """Seconds until another attempt is allowed in `scope` (default "manage") or across all scopes, or 0."""
    t = time.time() if now is None else now
    scopes = _fails_load()["scopes"]
    return max(_remaining(scopes.get(scope or "manage", {}), MAX_FAILS, t),
               _remaining(scopes.get("*", {}), MAX_FAILS_ALL, t))


def _lockout_for(count: int, limit: int) -> float:
    if count < limit:
        return 0.0
    return float(min(MAX_LOCKOUT_SECONDS, LOCKOUT_SECONDS * (2 ** min(count - limit, 12))))


def _fail(now: Optional[float], scope: Optional[str] = None) -> None:
    t = time.time() if now is None else now
    state = _fails_load()
    for name, limit in ((scope or "manage", MAX_FAILS), ("*", MAX_FAILS_ALL)):
        e = state["scopes"].setdefault(name, {"count": 0, "until": 0})
        e["count"] = int(e.get("count", 0)) + 1
        e["until"] = t + _lockout_for(e["count"], limit)
    _fails_save(state)


def _succeeded(scope: Optional[str] = None) -> None:
    state = _fails_load()
    state["scopes"].pop(scope or "manage", None)
    state["scopes"].pop("*", None)
    _fails_save(state)


def _lockout_message(wait: float) -> str:
    mins = int(wait // 60) + 1
    return (f"Too many wrong codes. Try again in {mins} minute{'s' if mins != 1 else ''} (each further mistake "
            "doubles the wait, up to an hour).")


# ── authenticator app (TOTP) ────────────────────────────────────────────────────────────────────────────────────
def _hash(code: str) -> str:
    """The recovery-code hash of the format before 0.3 (plain SHA-256). Still accepted for existing sets."""
    return hashlib.sha256(_norm_recovery(code).encode("ascii", "ignore")).hexdigest()


def _norm_recovery(code: str) -> str:
    return (code or "").strip().upper().replace("-", "").replace(" ", "")


def _recovery_code() -> str:
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"            # no 0/O/1/I/L
    raw = "".join(secrets.choice(alphabet) for _ in range(10))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def _codes_for(recovery: str) -> list:
    """The recovery codes a new enrolment brings: "auto" = a first set only when none are left (the behaviour before
    L9.343, now named), "new" = a fresh set that REPLACES the old one when the app is confirmed, "keep" = none."""
    if recovery == "new" or (recovery == "auto" and recovery_codes_left() == 0):
        return [_recovery_code() for _ in range(RECOVERY_COUNT)]
    return []


def begin_enrolment(account: str = "ComfyUI vault", label: str = "", add: bool = False,
                    recovery: str = "auto") -> dict:
    """A new secret (+ recovery codes per `recovery`, see _codes_for), shown ONCE; active only after
    confirm_enrolment(first code). `add`: another app next to the ones set up (the caller checked a proof first)."""
    if recovery not in RECOVERY_MODES:
        raise ValueError(f"Unknown recovery-code choice: {str(recovery)[:20]}.")
    with _lock:
        auths = _authenticators()
        if auths and not add:
            raise PermissionError("An authenticator is already set up on this install. Add another under H2Vault menu "
                                  "> Second factor (needs one of your methods).")
        limit = max_authenticators()
        if len(auths) >= limit:
            raise PermissionError(f"This installation has {len(auths)} authenticator apps, at most "
                                  f"{limit} are allowed. Remove one you no longer use first.")
        label = _clean_label(label)
        if label and _label_taken(label, auths):
            raise PermissionError(f"Another authenticator is already called '{label}'. Choose another name.")
        label = label or _default_label(auths)
        if _pending and time.time() - _pending.get("at", 0) <= 15 * 60:
            secret = _pending["secret"]                      # same setup while it is pending (QR <-> key)
            if _pending.get("recovery_mode", "auto") != recovery:
                _pending["codes"] = _codes_for(recovery)     # the author changed the recovery choice: new codes
            codes = _pending["codes"]
        else:
            secret = os.urandom(20)
            codes = _codes_for(recovery)
            _pending.clear()
            _pending.update({"secret": secret, "codes": codes, "at": time.time()})
        _pending["label"], _pending["recovery_mode"] = label, recovery
    left = recovery_codes_left()
    account = label if auths else account                    # the phone shows "H2Vault: <name>": two apps stay apart
    uri = _totp(secret).get_provisioning_uri(account, "H2Vault")
    b32 = base64.b32encode(secret).decode("ascii").rstrip("=")
    return {"secret_base32": b32, "secret_grouped": " ".join(b32[i:i + 4] for i in range(0, len(b32), 4)),
            "otpauth_uri": uri, "qr_svg": qr_svg(uri), "recovery_codes": codes,
            "recovery_kept": 0 if codes else left, "recovery_replaces": left if codes else 0,
            "recovery_mode": recovery, "issuer": "H2Vault",
            "account": account, "label": label, "algorithm": "SHA1", "digits": DIGITS, "period": STEP}


def pending_has_codes() -> bool:
    """Does the waiting enrolment bring recovery codes (the page must say they were saved before it is confirmed)?"""
    with _lock:
        return bool(_pending.get("codes")) and time.time() - _pending.get("at", 0) <= 15 * 60


def qr_svg(text: str, border: int = 4) -> str:
    """The QR code of `text` as a small standalone SVG (vendored Nayuki qrcodegen, MIT). '' if it cannot."""
    try:
        from ._vendor.qrcodegen import QrCode
    except Exception:  # noqa: BLE001
        return ""
    qr = QrCode.encode_text(text, QrCode.Ecc.MEDIUM)
    n = qr.get_size()
    parts = [f"M{x + border},{y + border}h1v1h-1z" for y in range(n) for x in range(n) if qr.get_module(x, y)]
    size = n + 2 * border
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" shape-rendering="crispEdges">'
            f'<rect width="100%" height="100%" fill="#ffffff"/><path d="{" ".join(parts)}" fill="#000000"/></svg>')


def cancel_enrolment() -> None:
    with _lock:
        _pending.clear()


def last_enrolment_error() -> str:
    return str(_pending.get("last_error") or "")


def confirm_enrolment(code: str, now: Optional[float] = None, recovery_saved: Optional[bool] = None) -> bool:
    """`recovery_saved` (the page's "I saved the recovery codes"): False refuses (ValueError) an enrolment that brings
    recovery codes; None = not asked (module callers)."""
    with _lock:
        if not _pending or time.time() - _pending.get("at", 0) > 15 * 60:
            _pending.clear()
            raise PermissionError("No enrolment is waiting (or it expired). Start the setup again.")
        if recovery_saved is False and _pending.get("codes"):
            raise ValueError("Confirm that you saved the recovery codes first (tick 'I saved the recovery codes').")
        step = _match(_pending["secret"], code, now)
        if step is None:
            skew = _probe_clock(_pending["secret"], code, now)
            _pending["last_error"] = (
                f"That code matches a time {abs(skew)} s away: this computer's clock and your phone's disagree. Turn "
                "on automatic time sync on both, then enter a fresh code." if skew is not None else
                "That code is not right. Enter the current code of the new 'H2Vault' entry (scan the QR code or "
                "type the setup key again if the app shows no entry).")
            return False
        auths = _authenticators()
        if len(auths) >= max_authenticators():
            _pending.clear()
            raise PermissionError(f"At most {max_authenticators()} authenticator apps per installation.")
        label = _pending.get("label") or _default_label(auths)
        if _label_taken(label, auths):                       # another tab took the name meanwhile
            label = _default_label(auths)
        _auth_save({"id": secrets.token_hex(6), "label": label,
                    "secret": base64.b64encode(_pending["secret"]).decode("ascii"), "last_step": step,
                    "created": int(time.time()), "last_used": 0})
        if _pending.get("codes"):
            _store_recovery(_pending["codes"])
        _succeeded("manage")
        _pending.clear()
        return True


def _match(secret: bytes, code: str, now: Optional[float]) -> Optional[int]:
    from cryptography.hazmat.primitives.twofactor import InvalidToken

    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    t = time.time() if now is None else now
    for offset in range(-WINDOW, WINDOW + 1):
        when = t + offset * STEP
        try:
            _totp(secret).verify(code.encode("ascii"), int(when))
            return int(when // STEP)
        except InvalidToken:
            continue
    return None


CLOCK_PROBE_STEPS = 20                 # how far (x 30 s) to look for a code from a drifted clock - never accepted


def _probe_clock(secret: bytes, code: str, now: Optional[float]) -> Optional[int]:
    """Seconds the server clock is AHEAD (+) or BEHIND (-) the app's, when the code belongs to a nearby time step
    outside the accepted window. Diagnosis only: such a code is never accepted."""
    from cryptography.hazmat.primitives.twofactor import InvalidToken

    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    t = time.time() if now is None else now
    for k in range(WINDOW + 1, CLOCK_PROBE_STEPS + 1):
        for offset in (k, -k):
            try:
                _totp(secret).verify(code.encode("ascii"), int(t + offset * STEP))
                return -offset * STEP
            except InvalidToken:
                continue
    return None


def remove_totp(auth_id: Optional[str] = None) -> int:
    """Remove one authenticator app (`auth_id`) or, without one, every app (the first release's reset). -> removed."""
    with _lock:
        gone = [a for a in _authenticators() if auth_id is None or a["id"] == str(auth_id)]
        for a in gone:
            _auth_delete(a["id"])
        if auth_id is None:
            _pending.clear()
        return len(gone)


# ── recovery codes ──────────────────────────────────────────────────────────────────────────────────────────────
def _recovery_load() -> dict:
    raw = vault_store.get(_RECOVERY)
    try:
        data = json.loads(raw) if raw else None
    except ValueError:
        data = None
    if isinstance(data, list):                                 # before 0.3: unsalted SHA-256 hex digests
        return {"v": 1, "hashes": [str(h) for h in data]}
    if isinstance(data, dict) and data.get("v") == 2:
        return data
    return {"v": 2, "hashes": []}


def _store_recovery(codes: list) -> None:
    salt = os.urandom(16)
    kdf = dict(RECOVERY_KDF)
    vault_store.put(_RECOVERY, json.dumps({"v": 2, "salt": base64.b64encode(salt).decode("ascii"), "kdf": kdf,
                                           "hashes": [_scrypt(_norm_recovery(c), salt, kdf).hex() for c in codes]}))


def recovery_codes_left() -> int:
    return len(_recovery_load()["hashes"])


def new_recovery_codes() -> list:
    """A fresh set of RECOVERY_COUNT codes (the old set stops working). Returned ONCE; only hashes are kept."""
    codes = [_recovery_code() for _ in range(RECOVERY_COUNT)]
    with _lock:
        _store_recovery(codes)
    return codes


def _find_recovery(code: str):
    """-> (stored data, index of the matching hash) or None. No side effect. Every stored hash is compared (constant
    time)."""
    norm = _norm_recovery(code)
    if not norm or len(norm) > 32:
        return None
    data = _recovery_load()
    if not data["hashes"]:
        return None
    if data["v"] == 1:
        h = hashlib.sha256(norm.encode("ascii", "ignore")).hexdigest()
    else:
        h = _scrypt(norm, base64.b64decode(data["salt"]), data.get("kdf") or RECOVERY_KDF).hex()
    hit = None
    for k, known in enumerate(data["hashes"]):
        if hmac.compare_digest(str(known), h) and hit is None:
            hit = k
    return None if hit is None else (data, hit)


def _consume_recovery(data: dict, hit: int) -> int:
    data["hashes"].pop(hit)
    if data["v"] == 1:
        vault_store.put(_RECOVERY, json.dumps(data["hashes"]))
    else:
        vault_store.put(_RECOVERY, json.dumps(data))
    return len(data["hashes"])


def _use_recovery(code: str) -> Optional[int]:
    """Consume a matching recovery code -> codes left, or None."""
    found = _find_recovery(code)
    return None if found is None else _consume_recovery(*found)


# ── backup password ─────────────────────────────────────────────────────────────────────────────────────────────
def set_backup_password(secret: str) -> None:
    secret = str(secret or "")
    if len(secret) < BACKUP_PASSWORD_MIN:
        raise ValueError(f"Choose a backup password of at least {BACKUP_PASSWORD_MIN} characters.")
    if len(secret) > 1024:
        raise ValueError("That backup password is too long (at most 1024 characters).")
    salt, kdf = os.urandom(16), dict(PASSWORD_KDF)
    with _lock:
        vault_store.put(_BACKUP_PW, json.dumps({"v": 1, "salt": base64.b64encode(salt).decode("ascii"), "kdf": kdf,
                                                "hash": _scrypt(secret, salt, kdf).hex()}))


def remove_backup_password() -> None:
    with _lock:
        vault_store.delete(_BACKUP_PW)


def _check_backup_password(secret: str) -> bool:
    raw = vault_store.get(_BACKUP_PW)
    if not raw or not secret or len(secret) > 1024:
        return False
    rec = json.loads(raw)
    got = _scrypt(str(secret), base64.b64decode(rec["salt"]), rec.get("kdf") or PASSWORD_KDF).hex()
    return hmac.compare_digest(got, str(rec["hash"]))


def _stamp_backup_password(t: float) -> None:
    """Note when the backup password was last used (a date, never the password or its hash outside the store)."""
    try:
        rec = json.loads(vault_store.get(_BACKUP_PW) or "null")
    except ValueError:
        return
    if isinstance(rec, dict):
        rec["last_used"] = int(t)
        vault_store.put(_BACKUP_PW, json.dumps(rec))


def backup_password_info() -> dict:
    """{"set": bool, "last_used": unix time or 0} - never the hash."""
    try:
        rec = json.loads(vault_store.get(_BACKUP_PW) or "null")
    except ValueError:
        rec = None
    return {"set": isinstance(rec, dict), "last_used": int(rec.get("last_used") or 0) if isinstance(rec, dict) else 0}


# ── passkeys (WebAuthn) ─────────────────────────────────────────────────────────────────────────────────────────
def check_rp_id(rp_id: str) -> str:
    """The page's host name as the passkey's relying-party id. Browsers refuse passkeys on an IP address."""
    rp_id = str(rp_id or "").strip().lower().rstrip(".")
    if not rp_id or len(rp_id) > 253 or any(c in rp_id for c in "/:@ []"):
        raise PermissionError("Passkeys need the page's address name.")
    try:
        ipaddress.ip_address(rp_id)
    except ValueError:
        return rp_id
    raise PermissionError(f"Browsers allow passkeys only on a name, not on an IP address like {rp_id}. Open ComfyUI "
                          "as http://localhost:<port> (same port) to use or set up a passkey.")


def _new_challenge(kind: str, rp_id: str, **extra) -> tuple:
    now = time.monotonic()
    with _lock:
        for cid in [c for c, v in _challenges.items() if now - v["at"] > CHALLENGE_SECONDS]:
            _challenges.pop(cid, None)
        while len(_challenges) >= CHALLENGE_MAX:
            _challenges.pop(next(iter(_challenges)))
        cid, challenge = secrets.token_urlsafe(16), os.urandom(32)
        _challenges[cid] = {"challenge": challenge, "kind": kind, "rp_id": rp_id, "at": now, **extra}
    return cid, challenge


def _take_challenge(cid: str, kind: str) -> dict:
    with _lock:
        c = _challenges.pop(str(cid or ""), None)           # single use, whatever the outcome
    if not c or c["kind"] != kind or time.monotonic() - c["at"] > CHALLENGE_SECONDS:
        raise PermissionError("The passkey request expired. Try again.")
    return c


def _user_handle() -> bytes:
    from .webauthn_min import b64url, unb64url
    raw = vault_store.get(_USER_HANDLE)
    if raw:
        return unb64url(raw)
    handle = os.urandom(16)
    vault_store.put(_USER_HANDLE, b64url(handle))
    return handle


PASSKEY_KINDS = {"any": None, "platform": "platform", "security_key": "cross-platform"}   # -> authenticatorAttachment


def passkey_register_begin(rp_id: str, label: str = "", kind: str = "any") -> dict:
    """navigator.credentials.create() options (JSON-safe: binary fields are base64url). `kind`: "platform" (Windows
    Hello / Touch ID on this device), "security_key" (YubiKey and other FIDO2 keys) or "any" (the browser offers
    all)."""
    from .webauthn_min import SUPPORTED_ALGS, b64url
    rp_id = check_rp_id(rp_id)
    kind = str(kind or "any")
    if kind not in PASSKEY_KINDS:
        raise PermissionError("Choose the kind of passkey: this device, a security key, or any.")
    label = str(label or "").strip()[:60] or "Passkey"
    cid, challenge = _new_challenge("create", rp_id, label=label, pk_kind=kind)
    selection = {"userVerification": "preferred", "residentKey": "discouraged"}
    if PASSKEY_KINDS[kind]:
        selection["authenticatorAttachment"] = PASSKEY_KINDS[kind]
    return {"challenge_id": cid, "publicKey": {
        "challenge": b64url(challenge), "rp": {"id": rp_id, "name": "H2Vault"},
        "user": {"id": b64url(_user_handle()), "name": "h2vault", "displayName": "H2Vault on this ComfyUI"},
        "pubKeyCredParams": [{"type": "public-key", "alg": a} for a in SUPPORTED_ALGS],
        "excludeCredentials": [{"type": "public-key", "id": c["id"]} for c in _passkeys() if c.get("rp_id") == rp_id],
        "authenticatorSelection": selection,
        "attestation": "none", "timeout": CHALLENGE_SECONDS * 1000}}


def passkey_register_finish(challenge_id: str, credential: dict, origins) -> dict:
    from .webauthn_min import unb64url, verify_registration
    c = _take_challenge(challenge_id, "create")
    resp = (credential or {}).get("response") or {}
    out = verify_registration(client_data_json=unb64url(resp.get("clientDataJSON")),
                              attestation_object=unb64url(resp.get("attestationObject")),
                              challenge=c["challenge"], origins=origins, rp_id=c["rp_id"])
    with _lock:
        creds = _passkeys()
        if any(hmac.compare_digest(x["id"], out["id"]) for x in creds):
            raise PermissionError("This passkey is already registered here.")
        rec = {**out, "rp_id": c["rp_id"], "label": c.get("label") or "Passkey", "created": int(time.time()),
               "last_used": 0, "kind": c.get("pk_kind") or "any"}
        creds.append(rec)
        _save_passkeys(creds)
    return _public_passkey(rec)


def _public_passkey(c: dict) -> dict:
    return {"id": c["id"], "label": c.get("label", "Passkey"), "rp_id": c.get("rp_id", ""),
            "created": c.get("created", 0), "last_used": c.get("last_used", 0), "kind": c.get("kind") or "any"}


def passkeys_public() -> list:
    return [_public_passkey(c) for c in _passkeys()]


def remove_passkey(cred_id: str) -> bool:
    with _lock:
        creds = _passkeys()
        keep = [c for c in creds if c["id"] != str(cred_id)]
        _save_passkeys(keep)
    return len(keep) != len(creds)


def passkey_challenge(rp_id: str) -> dict:
    """navigator.credentials.get() options for the passkeys registered on THIS address."""
    from .webauthn_min import b64url
    rp_id = check_rp_id(rp_id)
    creds = [c for c in _passkeys() if c.get("rp_id") == rp_id]
    if not creds:
        other = sorted({c.get("rp_id", "") for c in _passkeys()})
        raise PermissionError("No passkey is set up for this address." + (
            f" Passkeys belong to the address they were made on: open ComfyUI as http://{other[0]}:<port>."
            if other else " Set one up under H2Vault menu > Second factor."))
    cid, challenge = _new_challenge("get", rp_id)
    return {"challenge_id": cid, "publicKey": {
        "challenge": b64url(challenge), "rpId": rp_id, "timeout": CHALLENGE_SECONDS * 1000,
        "userVerification": "preferred", "allowCredentials": [{"type": "public-key", "id": c["id"]} for c in creds]}}


def _check_passkey(factor: dict, origins) -> tuple:
    """-> (ok, message, commit, label). A wrong / foreign answer is (False, message, None, None); an expired request
    raises PermissionError. The challenge is used up at once (single use); the counter and date are written only by
    commit()."""
    from .webauthn_min import WebAuthnError, unb64url, verify_assertion
    c = _take_challenge(factor.get("challenge_id"), "get")
    cred = factor.get("credential") or {}
    resp = cred.get("response") or {}
    with _lock:
        creds = _passkeys()
        rec = next((x for x in creds if hmac.compare_digest(x["id"], str(cred.get("id") or ""))
                    and x.get("rp_id") == c["rp_id"]), None)
        if rec is None:
            return False, "That passkey is not registered on this installation.", None, None
        try:
            count = verify_assertion(credential=rec, client_data_json=unb64url(resp.get("clientDataJSON")),
                                     authenticator_data=unb64url(resp.get("authenticatorData")),
                                     signature=unb64url(resp.get("signature")), challenge=c["challenge"],
                                     origins=origins, rp_id=c["rp_id"])
        except WebAuthnError as exc:
            return False, str(exc), None, None

    def commit():
        rec["sign_count"], rec["last_used"] = count, int(time.time())
        _save_passkeys(creds)
    return True, "Verified with your passkey.", commit, rec.get("label") or "Passkey"


# ── verifying a factor ──────────────────────────────────────────────────────────────────────────────────────────
def method_of(factor) -> str:
    """The method a request uses. Requests from before methods existed send only {"code": ...}: six digits are an
    authenticator code, anything else a recovery code (what the old single field accepted)."""
    if isinstance(factor, dict) and factor.get("method") in METHODS:
        return factor["method"]
    code = _norm_recovery(str((factor or {}).get("code") or "")) if isinstance(factor, dict) else ""
    return "totp" if len(code) == DIGITS and code.isdigit() else "recovery"


def _gate(now: Optional[float], scope: str) -> None:
    """Raises PermissionError while locked out or when no method is set up at all (never counted)."""
    if not any_enrolled():
        raise PermissionError("No second factor is set up on this install yet. Set one up under H2Vault menu > "
                              "Second factor.")
    wait = locked_out(now, scope)
    if wait > 0:
        raise PermissionError(_lockout_message(wait))


def _not_set_up(method: str, auth_ids=None) -> Optional[dict]:
    """None when `method` can be checked here; else the (uncounted) "not_set_up" answer. `auth_ids`: only these
    authenticator apps count (a vault that names particular apps)."""
    if method == "totp":
        n = len([a for a in _authenticators() if auth_ids is None or a["id"] in auth_ids])
    elif method == "passkey":
        n = len(_passkeys())
    elif method == "backup_password":
        n = bool(vault_store.get(_BACKUP_PW))
    else:
        n = recovery_codes_left()
    if n:
        return None
    if method == "totp" and auth_ids is not None and _authenticators():
        message = ("This vault accepts only particular authenticator apps (chosen when it was locked), and none of "
                   "them is set up on this installation. Use another method it accepts.")
    else:
        message = (f"No {METHOD_LABELS[method].lower()} is set up on this installation" + (
            " (no recovery codes left)" if method == "recovery" else "") +
            ". Use another method, or set one up under H2Vault menu > Second factor.")
    return {"ok": False, "reason": "not_set_up", "method": method, "message": message}


def _check(method: str, factor: dict, now: Optional[float], origins, auth_ids=None) -> dict:
    """Check ONE factor without side effects (a passkey challenge is used up - it is single use anyway). -> the answer
    verify_factor gives, plus "commit" (a callable that writes the side effects and returns extra answer fields) and
    "label" (what was used, never a secret) when it passed."""
    if method == "totp":
        return _check_totp(str(factor.get("code") or ""), now, auth_ids)
    if method == "recovery":
        found = _find_recovery(str(factor.get("code") or ""))
        if found is None:
            return {"ok": False, "reason": "wrong", "method": "recovery",
                    "message": "That recovery code is not right or was already used (each works once)."}

        def used_up():
            left = _consume_recovery(*found)
            return {"recovery_codes_left": left, "message": f"Recovery code used ({left} left)."}
        return {"ok": True, "reason": "recovery", "method": "recovery", "label": METHOD_LABELS["recovery"],
                "commit": used_up}
    if method == "backup_password":
        if _check_backup_password(str(factor.get("secret") or "")):
            t = time.time() if now is None else now
            return {"ok": True, "reason": "backup_password", "method": method, "message": "Verified.",
                    "label": METHOD_LABELS[method], "commit": lambda: _stamp_backup_password(t) or {}}
        return {"ok": False, "reason": "wrong", "method": method, "message": "That backup password is not right."}
    ok, message, commit, label = _check_passkey(factor, origins)
    if ok:
        return {"ok": True, "reason": "passkey", "method": "passkey", "message": message, "label": label,
                "commit": lambda: commit() or {}}
    return {"ok": False, "reason": "wrong", "method": "passkey", "message": message}


def _finish(results: list, scope: str, now: Optional[float], combined: Optional[dict] = None) -> dict:
    """All checks done: any failure -> that answer (ONE counted failure when a factor was wrong, whatever the number
    of factors); else every side effect is committed together and the answer names what was used."""
    bad = [r for r in results if not r["ok"]]
    if bad:
        wrong = [r for r in bad if r["reason"] == "wrong"]
        if wrong:
            _fail(now, scope)
        out = dict((wrong or bad)[0])
        out.pop("commit", None)
        if wrong and len(results) > 1:                         # several factors: never say which one was wrong
            out = {"ok": False, "reason": "wrong", "method": "policy",
                   "message": "One of the factors is not right (or a recovery code was already used). Check them "
                              "all and try again with a fresh authenticator code."}
        return out
    used, extra = [], {}
    for r in results:
        extra.update(r["commit"]() or {})
        used.append({"method": r["method"], "label": r.get("label") or METHOD_LABELS.get(r["method"], "")})
    _succeeded(scope)
    note_activity(used, scope)
    if len(results) == 1:
        out = {k: v for k, v in results[0].items() if k not in ("commit", "label")}
    else:
        out = {"ok": True, "reason": "policy", "method": results[0]["method"], "message": "Verified."}
    out.update(extra)
    out["used"] = used
    if combined:
        out.update(combined)
    return out


def verify_factor(factor: dict, *, allowed=None, scope: Optional[str] = None, now: Optional[float] = None,
                  origins=(), authenticators=None) -> dict:
    """{"ok": bool, "reason", "method", "message", "used", ...}. Reasons that are not guesses are never counted:
    "method_not_allowed" (+ "allowed"), "not_set_up", "reused" (+ "next_in"), "clock" (+ "skew_seconds").
    "wrong" is counted in `scope` and across scopes. Raises PermissionError while locked out or when no method is
    set up at all. `authenticators`: only these app ids count as an authenticator code."""
    factor = factor if isinstance(factor, dict) else {}
    method = method_of(factor)
    scope = scope or "manage"
    with _lock:
        _gate(now, scope)
        allowed = list(allowed) if allowed else list(METHODS)
        if method not in allowed:
            return {"ok": False, "reason": "method_not_allowed", "method": method, "allowed": allowed,
                    "message": f"This vault does not accept a {METHOD_LABELS[method].lower()}. It accepts: "
                               f"{labels(allowed)}."}
        missing = _not_set_up(method, authenticators)
        if missing:
            return missing
        return _finish([_check(method, factor, now, origins, authenticators)], scope, now)


def _need_words(methods) -> str:
    return " and ".join(METHOD_LABELS[m].lower() for m in methods)


def verify_policy(factors, policy: dict, *, scope: Optional[str] = None, now: Optional[float] = None,
                  origins=()) -> dict:
    """Check the second factor(s) of a request against a vault's policy (docs/AUTH_POLICY.md sections 4-5). The
    password was checked before. `factors`: [{"method", ...}, ...] (the first of each method counts). Answers like
    verify_factor, plus "factor_required" (+ "missing") when a factor the policy needs was not given (not counted)."""
    scope = scope or "manage"
    given = []
    for f in factors or []:
        if has_factor(f) and method_of(f) not in [m for m, _ in given]:
            given.append((method_of(f), f))
    accepted = accepted_methods(policy)
    if not accepted:                                           # password only: nothing to check, nothing used up
        return {"ok": True, "reason": "password_only", "used": []}
    auth_ids = list(policy["authenticators"]) or None
    with _lock:
        _gate(now, scope)
        if not given:
            return {"ok": False, "reason": "factor_required", "missing": list(policy["methods"]),
                    "message": "This vault also needs a second factor: " + labels(accepted) + "."}
        for m, _f in given:
            if m not in accepted:
                return {"ok": False, "reason": "method_not_allowed", "method": m, "allowed": accepted,
                        "message": f"This vault does not accept a {METHOD_LABELS[m].lower()}. It accepts: "
                                   f"{labels(accepted)}."}
        if policy["mode"] == "any":                            # a recovery code only when nothing else was given
            use = [next((g for g in given if g[0] != "recovery"), given[0])]
        else:
            by = dict(given)
            missing = [m for m in policy["methods"] if m not in by]
            if not missing:
                use = [(m, by[m]) for m in policy["methods"]]              # a recovery code not needed: not used up
            elif "recovery" in by and policy["recovery"] == "override":
                use = [("recovery", by["recovery"])]          # the author's explicit emergency override
            elif "recovery" in by and policy["recovery"] == "replace_one" and len(missing) == 1:
                use = [(m, by[m]) for m in policy["methods"] if m in by] + [("recovery", by["recovery"])]
            else:
                return {"ok": False, "reason": "factor_required", "missing": missing,
                        "message": "This vault needs ALL of its second factors. Still missing: " +
                                   _need_words(missing) + "."}
        for m, _f in use:
            absent = _not_set_up(m, auth_ids)
            if absent:
                return absent
        return _finish([_check(m, f, now, origins, auth_ids) for m, f in use], scope, now)


def _check_totp(code: str, now: Optional[float], auth_ids=None) -> dict:
    """Any registered (or, for a vault that names apps, any named) app's code is accepted, once per app: each app has
    its own last accepted time step. Every app is checked (the time taken does not tell which one matched). No side
    effect: the time step and date are written by "commit"; a wrong code is counted by the caller, ONCE."""
    auths = [a for a in _authenticators() if auth_ids is None or a["id"] in auth_ids]
    t = time.time() if now is None else now
    hits = []
    for a in auths:
        step = _match(base64.b64decode(a["secret"]), code, now)
        if step is not None:
            hits.append((a, step))
    fresh = [(a, step) for a, step in hits if step > int(a.get("last_step", -1))]
    if fresh:
        a, step = fresh[0]

        def commit():
            a["last_step"], a["last_used"] = step, int(t)
            _auth_save(a)
            return {}
        return {"ok": True, "reason": "ok", "method": "totp", "authenticator": a.get("label", ""),
                "authenticator_id": a["id"], "label": a.get("label") or METHOD_LABELS["totp"], "message": "Verified.",
                "commit": commit}
    if hits:
        nxt = int(STEP - (t % STEP)) + 1
        return {"ok": False, "reason": "reused", "method": "totp", "next_in": nxt,
                "message": f"That code was already used (each code works once). Wait for the next code in "
                           f"your app - about {nxt} s - and enter that one."}
    skew = None
    for a in auths:
        skew = _probe_clock(base64.b64decode(a["secret"]), code, now)
        if skew is not None:
            break
    if skew is not None:
        side = "ahead of" if skew > 0 else "behind"
        return {"ok": False, "reason": "clock", "method": "totp", "skew_seconds": skew,
                "message": f"That code matches a time {abs(skew)} s away: this computer's clock is about "
                           f"{abs(skew)} s {side} your phone's. Codes depend on the clock (not the time zone): "
                           "turn on automatic time sync on both, then try a fresh code."}
    return {"ok": False, "reason": "wrong", "method": "totp",
            "message": "That code is not right. Use the current 6-digit code of the 'H2Vault' entry in your "
                       "authenticator app (codes from 30 s before or after are accepted)."}


# ── last authentication activity (not secret: when, which method, which app's NAME) ────────────────────────────
ACTIVITY_FILE, ACTIVITY_MAX = "second_factor_activity.json", 10


def _activity_path():
    from . import secrets_store
    return secrets_store._user_dir() / ACTIVITY_FILE


def activity() -> list:
    """The last ACTIVITY_MAX successful second-factor checks, newest first: [{"at", "method", "label", "where"}]."""
    try:
        data = json.loads(_activity_path().read_text("utf-8"))
    except (OSError, ValueError):
        return []
    return [e for e in data if isinstance(e, dict)][:ACTIVITY_MAX] if isinstance(data, list) else []


def note_activity(used: list, scope: str) -> None:
    """Best effort: a failure here never stops an open. `where` = "vault" (opening / access) or "settings"."""
    try:
        where = "vault" if str(scope).startswith("v:") else "settings"
        now = int(time.time())
        events = [{"at": now, "method": u["method"], "label": _clean_label(u.get("label")), "where": where}
                  for u in used]
        with _lock:
            path = _activity_path()
            data = (events + activity())[:ACTIVITY_MAX]
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, path)
    except Exception as exc:  # noqa: BLE001
        log.warning("[H2Vault] could not note the second-factor activity: %s", type(exc).__name__)


def verify_detail(code: str, now: Optional[float] = None) -> dict:
    """The single-field check of the first release: an authenticator code or a recovery code (see method_of)."""
    return verify_factor({"code": code}, now=now)


def verify(code: str, now: Optional[float] = None) -> bool:
    """A current authenticator code (once) or an unused recovery code (consumed). Never raises on a wrong code."""
    return bool(verify_detail(code, now)["ok"])


def reset(code: str, now: Optional[float] = None) -> bool:
    """Remove the authenticator (to set it up again) - only with a valid code or recovery code."""
    if not verify(code, now):
        return False
    remove_totp()
    return True


# ── settings tokens: one proof, then a few minutes to change methods ───────────────────────────────────────────
ALL_PROVEN = "*"                       # a token made while nothing was set up: the first setup session


def _proven_of(detail: dict) -> set:
    """What a successful check proved: method names, plus "totp:<app id>" for the authenticator app used."""
    out = {u["method"] for u in detail.get("used") or [] if u.get("method")}
    if detail.get("authenticator_id"):
        out.add(f"totp:{detail['authenticator_id']}")
    return out


def manage_begin(factor: Optional[dict] = None, *, now: Optional[float] = None, origins=(),
                 token: Optional[str] = None) -> dict:
    """{"ok": True, "manage_token", "expires_in"} after a proof with any method set up here (none needed while no
    method exists), else the verify_factor answer. L9.343: the token remembers WHAT was proven; `token` (a live one)
    adds this proof to it (a change a vault's policy guards may need more than one factor, see step_up_vaults)."""
    if any_enrolled():
        detail = verify_factor(factor or {}, scope="manage", now=now, origins=origins)
        if not detail["ok"]:
            return detail
        proven = _proven_of(detail)
    else:
        detail, proven = {"ok": True, "reason": "none_set_up"}, {ALL_PROVEN}
    t = time.monotonic()
    with _lock:
        for k in [k for k, rec in _manage.items() if rec["exp"] < t]:
            _manage.pop(k, None)
        rec = _manage.get(str(token or "")) if token else None
        if rec is None:
            token = secrets.token_urlsafe(24)
            rec = _manage[token] = {"exp": t + MANAGE_SECONDS, "proven": set()}
        rec["proven"] |= proven
    out = {k: v for k, v in detail.items() if k != "authenticator_id"}
    return {**out, "ok": True, "manage_token": token, "expires_in": MANAGE_SECONDS}


def proven_by(token: str) -> set:
    with _lock:
        rec = _manage.get(str(token or ""))
        return set(rec["proven"]) if rec and rec["exp"] >= time.monotonic() else set()


def add_proof(token: str, detail: dict) -> None:
    """A proof made inside another request (e.g. removing the last app) counts for the token too."""
    with _lock:
        rec = _manage.get(str(token or ""))
        if rec and detail.get("ok"):
            rec["proven"] |= _proven_of(detail)


def proof_satisfies(policy: dict, proven) -> bool:
    """Would the factors proven in this settings session open a vault with `policy`?"""
    proven = set(proven or ())
    factors = policy["methods"]
    if not factors or ALL_PROVEN in proven:
        return True

    def has(m):
        if m == "totp" and policy.get("authenticators"):
            return any(f"totp:{i}" in proven for i in policy["authenticators"])
        return m in proven
    got = [m for m in factors if has(m)]
    rec = "recovery" in proven
    if policy["mode"] == "any":
        return bool(got) or (rec and policy["recovery"] == "fallback")
    if len(got) == len(factors):
        return True
    return rec and (policy["recovery"] == "override" or
                    (policy["recovery"] == "replace_one" and len(factors) - len(got) == 1))


def step_up_vaults(kind: str, proven, *, item: Optional[str] = None, adding: bool = False) -> list:
    """The vaults this installation knows that accept `kind`, can be opened here today, and would NOT be opened by
    what this settings session proved. Changing `kind` (adding, replacing or removing it) then needs more proof:
    otherwise one factor could replace another and open an AND vault (L9.343 review). Vaults that cannot be opened
    here today are not guarded - their missing factor is set up by whoever owns this installation. A vault bound to
    particular apps is not touched by a NEW app (`adding`) or by removing an app it does not name (`item`)."""
    have = methods_set_up()
    ids = [a["id"] for a in _authenticators()]

    def touched(pol):
        if kind == "totp" and pol["authenticators"]:
            return not adding and (item is None or item in pol["authenticators"])
        return True
    return [v for v in known_vaults() if kind in accepted_methods(v["policy"]) and touched(v["policy"])
            and satisfiable(v["policy"], have, ids) != "no" and not proof_satisfies(v["policy"], proven)]


class StepUpRequired(PermissionError):
    """A change guarded by a vault's policy: the settings session must prove more (`vaults`)."""

    def __init__(self, kind: str, vaults: list):
        self.kind, self.vaults = kind, vaults
        names = _vault_names(vaults)
        super().__init__(f"To change your {METHOD_LABELS.get(kind, kind).lower()}s, confirm once more with what "
                         f"{names} need{'s' if len(vaults) == 1 else ''} to open: "
                         f"{policy_summary(vaults[0]['policy'])}")


def check_manage(token: str, change: Optional[str] = None, *, item: Optional[str] = None,
                 adding: bool = False) -> None:
    """Raises PermissionError unless `token` is a live settings token - or nothing is set up yet (first setup).
    `change` (a method kind being added, replaced or removed): StepUpRequired unless the token's proofs would open
    every known vault that accepts that kind (step_up_vaults)."""
    if not any_enrolled():
        return
    with _lock:
        rec = _manage.get(str(token or ""))
    if rec is None or rec["exp"] < time.monotonic():
        raise PermissionError("Confirm it is you first (one of your second-factor methods); the confirmation lasts "
                              "10 minutes.")
    if change:
        need = step_up_vaults(change, rec["proven"], item=item, adding=adding)
        if need:
            raise StepUpRequired(change, need)


# ── which vaults need which method (for "removing this would lock you out of ...") ─────────────────────────────
# A vault's method list is inside its encryption, so the installation keeps a small note of the vaults it locked or
# opened: {vault id: {"title", "methods", "seen"}} in <user dir>/h2vault/second_factor_vaults.json. Not a secret (ids
# and titles are on the vault nodes anyway, methods are names); it never holds a password, key or code.
KNOWN_VAULTS_MAX = 1000
KNOWN_VAULTS_FILE = "second_factor_vaults.json"


def _known_path():
    from . import secrets_store
    return secrets_store._user_dir() / KNOWN_VAULTS_FILE


def known_vaults() -> list:
    try:
        data = json.loads(_known_path().read_text("utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    return [{"vault_id": str(k), "title": str(v.get("title") or ""), "methods": list(v.get("methods") or []),
             "policy": _noted_policy(v)} for k, v in data.items() if isinstance(v, dict)]


def _noted_policy(note: dict) -> dict:
    """A note -> the vault's policy. Notes from before L9.343 carry only the method list (OR, recovery as fallback)."""
    rec = {"methods": list(note.get("methods") or [])}
    if note.get("mode"):
        rec.update(mode=note.get("mode"), recovery=note.get("recovery"),
                   authenticators=list(note.get("authenticators") or []), v=2)
    return policy_detail({"second_factor": rec})


def note_vault(vault_id: str, methods, title: str = "", policy: Optional[dict] = None) -> None:
    """Remember (or refresh) a vault's methods (and, L9.343, its policy). Best effort: a failure here never stops a
    lock or an open."""
    vault_id = str(vault_id or "")
    if not vault_id:
        return
    try:
        with _lock:
            path = _known_path()
            try:
                data = json.loads(path.read_text("utf-8"))
                data = data if isinstance(data, dict) else {}
            except (OSError, ValueError):
                data = {}
            old = data.get(vault_id) if isinstance(data.get(vault_id), dict) else {}
            data[vault_id] = {"title": _clean_label(title)[:80] or old.get("title", ""), "methods": list(methods),
                              "seen": int(time.time())}
            if policy and policy.get("methods"):
                data[vault_id].update(methods=list(policy["methods"]), mode=policy["mode"],
                                      recovery=policy["recovery"], authenticators=list(policy["authenticators"]))
            if len(data) > KNOWN_VAULTS_MAX:
                keep = sorted(data.items(), key=lambda kv: kv[1].get("seen", 0), reverse=True)[:KNOWN_VAULTS_MAX]
                data = dict(keep)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, path)
    except Exception as exc:  # noqa: BLE001
        log.warning("[H2Vault] could not note the vault's second-factor methods: %s", type(exc).__name__)


def _vault_names(vaults: list) -> str:
    names = [f"'{v['title']}'" if v["title"] else f"vault {v['vault_id']}" for v in vaults[:6]]
    more = len(vaults) - len(names)
    return ", ".join(names) + (f" and {more} more" if more > 0 else "")


def removal_impact(method: str, item_id: Optional[str] = None) -> dict:
    """What removing one item of `method` (an app / passkey by id, or the backup password) does to the vaults this
    installation knows. {"last_of_kind", "unopenable": [vaults with no accepted method left here, not even a recovery
    code], "recovery_only": [vaults then openable here only with a recovery code], "warning": words}. Vaults this
    installation has not locked or opened since 2026-11-23 are not known; the warning says so."""
    have = methods_set_up()
    after = dict(have)
    ids = [a["id"] for a in _authenticators()]
    ids_after = ids
    if method in ("totp", "passkey"):
        after[method] = max(0, int(have[method]) - (1 if item_id else int(have[method])))
        if method == "totp":
            ids_after = [i for i in ids if item_id and i != str(item_id)]
    elif method == "backup_password":
        after[method] = False
    last = bool(have.get(method)) and not after.get(method)
    rank = {"ok": 2, "recovery_only": 1, "no": 0}
    unopenable, recovery_only = [], []
    for v in known_vaults():                                   # only vaults this removal makes WORSE are named
        before, now_ = satisfiable(v["policy"], have, ids), satisfiable(v["policy"], after, ids_after)
        if rank[now_] >= rank[before]:
            continue
        (recovery_only if now_ == "recovery_only" else unopenable).append(v)
    words = []
    if last:
        words.append({"totp": "This is your last authenticator app on this installation.",
                      "passkey": "This is your last passkey on this installation.",
                      "backup_password": "This removes your backup password."}.get(method, ""))
    if recovery_only:
        words.append(f"After this, {_vault_names(recovery_only)} can be opened for editing here only with a recovery "
                     f"code ({after['recovery']} left).")
    if last and not unopenable and not recovery_only:
        words.append("Vaults that accept only this method cannot be opened for editing here until you set up another "
                     "method (vaults this installation has not opened since the update are not listed).")
    return {"last_of_kind": last, "unopenable": unopenable, "recovery_only": recovery_only,
            "warning": " ".join(w for w in words if w)}


def refusal_text(method: str, unopenable: list) -> str:
    one = len(unopenable) == 1
    return (f"Not removed: {_vault_names(unopenable)} would no longer open for editing on this installation - "
            f"{'it accepts' if one else 'they accept'} no other method set up here and no recovery codes are left. "
            f"Fix: first set up another method {'that vault' if one else 'those vaults'} accept"
            f"{'s' if one else ''} (H2Vault menu > Second factor), generate recovery codes if "
            f"{'it accepts' if one else 'they accept'} them, or change "
            f"{'its' if one else 'their'} protection (vault menu > Manage access).")


def has_factor(factor) -> bool:
    """Does a request carry a second factor at all? An empty one is not a guess (never counted)."""
    if not isinstance(factor, dict):
        return False
    if factor.get("method") in METHODS:
        return True
    return bool(str(factor.get("code") or "").strip())


# ── every method lost ───────────────────────────────────────────────────────────────────────────────────────────
RESET_ENV, RESET_VALUE = "H2VAULT_RESET_SECOND_FACTOR", "remove-all"


def reset_all() -> None:
    """Remove every second-factor method of this installation (vaults, keys and licences are untouched)."""
    with _lock:
        for aid in _auth_ids():
            vault_store.delete(_AUTH_PREFIX + aid)
        for name in (_SECRET, _LAST, _AUTH_INDEX, _RECOVERY, _FAILS, _BACKUP_PW, _PASSKEYS, _USER_HANDLE):
            vault_store.delete(name)
        _pending.clear()
        _challenges.clear()
        _manage.clear()


def admin_reset_from_env() -> bool:
    """H2VAULT_RESET_SECOND_FACTOR=remove-all when ComfyUI starts: the machine's administrator removes every method
    (the documented way back when all are lost). Whoever can set it can already read this install's secret store."""
    if os.environ.get(RESET_ENV, "").strip() != RESET_VALUE:
        return False
    reset_all()
    log.warning("[H2Vault] Every second-factor method of this installation was removed (%s=%s). Remove that "
                "setting and restart, then set up a method again.", RESET_ENV, RESET_VALUE)
    return True
