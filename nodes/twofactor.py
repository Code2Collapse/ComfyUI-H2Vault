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
MAX_AUTHENTICATORS = 10
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
    authenticator + recovery codes: stricter, never weaker."""
    sf = plain.get("second_factor") if isinstance(plain, dict) else None
    try:
        if isinstance(sf, dict):
            if sf.get("methods") == []:
                return []
            return normalise_policy(sf.get("methods"))
    except ValueError:
        pass
    return list(DEFAULT_POLICY)


def labels(methods) -> str:
    return ", ".join(METHOD_LABELS[m] for m in methods if m in METHOD_LABELS)


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


def begin_enrolment(account: str = "ComfyUI vault", label: str = "", add: bool = False) -> dict:
    """A new secret (+ a first set of recovery codes when this install has none), shown ONCE; active only after
    confirm_enrolment(first code). `add`: another app next to the ones set up (the caller checked a proof first)."""
    with _lock:
        auths = _authenticators()
        if auths and not add:
            raise PermissionError("An authenticator is already set up on this install. Add another under H2Vault menu "
                                  "> Second factor (needs one of your methods).")
        if len(auths) >= MAX_AUTHENTICATORS:
            raise PermissionError(f"This installation has {len(auths)} authenticator apps, at most "
                                  f"{MAX_AUTHENTICATORS} are allowed. Remove one you no longer use first.")
        label = _clean_label(label)
        if label and _label_taken(label, auths):
            raise PermissionError(f"Another authenticator is already called '{label}'. Choose another name.")
        label = label or _default_label(auths)
        if _pending and time.time() - _pending.get("at", 0) <= 15 * 60:
            secret, codes = _pending["secret"], _pending["codes"]   # same setup while it is pending (QR <-> key)
        else:
            secret = os.urandom(20)
            codes = [_recovery_code() for _ in range(RECOVERY_COUNT)] if recovery_codes_left() == 0 else []
            _pending.clear()
            _pending.update({"secret": secret, "codes": codes, "at": time.time()})
        _pending["label"] = label
    account = label if auths else account                    # the phone shows "H2Vault: <name>": two apps stay apart
    uri = _totp(secret).get_provisioning_uri(account, "H2Vault")
    b32 = base64.b32encode(secret).decode("ascii").rstrip("=")
    return {"secret_base32": b32, "secret_grouped": " ".join(b32[i:i + 4] for i in range(0, len(b32), 4)),
            "otpauth_uri": uri, "qr_svg": qr_svg(uri), "recovery_codes": codes,
            "recovery_kept": 0 if codes else recovery_codes_left(), "issuer": "H2Vault",
            "account": account, "label": label, "algorithm": "SHA1", "digits": DIGITS, "period": STEP}


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


def confirm_enrolment(code: str, now: Optional[float] = None) -> bool:
    with _lock:
        if not _pending or time.time() - _pending.get("at", 0) > 15 * 60:
            _pending.clear()
            raise PermissionError("No enrolment is waiting (or it expired). Start the setup again.")
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
        if len(auths) >= MAX_AUTHENTICATORS:
            _pending.clear()
            raise PermissionError(f"At most {MAX_AUTHENTICATORS} authenticator apps per installation.")
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


def _use_recovery(code: str) -> Optional[int]:
    """Consume a matching recovery code -> codes left, or None. Every stored hash is compared (constant time)."""
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
    if hit is None:
        return None
    data["hashes"].pop(hit)
    if data["v"] == 1:
        vault_store.put(_RECOVERY, json.dumps(data["hashes"]))
    else:
        vault_store.put(_RECOVERY, json.dumps(data))
    return len(data["hashes"])


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


def passkey_register_begin(rp_id: str, label: str = "") -> dict:
    """navigator.credentials.create() options (JSON-safe: binary fields are base64url)."""
    from .webauthn_min import SUPPORTED_ALGS, b64url
    rp_id = check_rp_id(rp_id)
    label = str(label or "").strip()[:60] or "Passkey"
    cid, challenge = _new_challenge("create", rp_id, label=label)
    return {"challenge_id": cid, "publicKey": {
        "challenge": b64url(challenge), "rp": {"id": rp_id, "name": "H2Vault"},
        "user": {"id": b64url(_user_handle()), "name": "h2vault", "displayName": "H2Vault on this ComfyUI"},
        "pubKeyCredParams": [{"type": "public-key", "alg": a} for a in SUPPORTED_ALGS],
        "excludeCredentials": [{"type": "public-key", "id": c["id"]} for c in _passkeys() if c.get("rp_id") == rp_id],
        "authenticatorSelection": {"userVerification": "preferred", "residentKey": "discouraged"},
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
               "last_used": 0}
        creds.append(rec)
        _save_passkeys(creds)
    return _public_passkey(rec)


def _public_passkey(c: dict) -> dict:
    return {"id": c["id"], "label": c.get("label", "Passkey"), "rp_id": c.get("rp_id", ""),
            "created": c.get("created", 0), "last_used": c.get("last_used", 0)}


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
    """-> (ok, message). A wrong / foreign answer is (False, message); an expired request raises PermissionError."""
    from .webauthn_min import WebAuthnError, unb64url, verify_assertion
    c = _take_challenge(factor.get("challenge_id"), "get")
    cred = factor.get("credential") or {}
    resp = cred.get("response") or {}
    with _lock:
        creds = _passkeys()
        rec = next((x for x in creds if hmac.compare_digest(x["id"], str(cred.get("id") or ""))
                    and x.get("rp_id") == c["rp_id"]), None)
        if rec is None:
            return False, "That passkey is not registered on this installation."
        try:
            count = verify_assertion(credential=rec, client_data_json=unb64url(resp.get("clientDataJSON")),
                                     authenticator_data=unb64url(resp.get("authenticatorData")),
                                     signature=unb64url(resp.get("signature")), challenge=c["challenge"],
                                     origins=origins, rp_id=c["rp_id"])
        except WebAuthnError as exc:
            return False, str(exc)
        rec["sign_count"], rec["last_used"] = count, int(time.time())
        _save_passkeys(creds)
    return True, "Verified with your passkey."


# ── verifying a factor ──────────────────────────────────────────────────────────────────────────────────────────
def method_of(factor) -> str:
    """The method a request uses. Requests from before methods existed send only {"code": ...}: six digits are an
    authenticator code, anything else a recovery code (what the old single field accepted)."""
    if isinstance(factor, dict) and factor.get("method") in METHODS:
        return factor["method"]
    code = _norm_recovery(str((factor or {}).get("code") or "")) if isinstance(factor, dict) else ""
    return "totp" if len(code) == DIGITS and code.isdigit() else "recovery"


def verify_factor(factor: dict, *, allowed=None, scope: Optional[str] = None, now: Optional[float] = None,
                  origins=()) -> dict:
    """{"ok": bool, "reason", "method", "message", ...}. Reasons that are not guesses are never counted:
    "method_not_allowed" (+ "allowed"), "not_set_up", "reused" (+ "next_in"), "clock" (+ "skew_seconds").
    "wrong" is counted in `scope` and across scopes. Raises PermissionError while locked out or when no method is
    set up at all."""
    factor = factor if isinstance(factor, dict) else {}
    method = method_of(factor)
    scope = scope or "manage"
    with _lock:
        if not any_enrolled():
            raise PermissionError("No second factor is set up on this install yet. Set one up under H2Vault menu > "
                                  "Second factor.")
        wait = locked_out(now, scope)
        if wait > 0:
            raise PermissionError(_lockout_message(wait))
        allowed = list(allowed) if allowed else list(METHODS)
        if method not in allowed:
            return {"ok": False, "reason": "method_not_allowed", "method": method, "allowed": allowed,
                    "message": f"This vault does not accept a {METHOD_LABELS[method].lower()}. It accepts: "
                               f"{labels(allowed)}."}
        have = methods_set_up()
        if not have[method]:
            return {"ok": False, "reason": "not_set_up", "method": method,
                    "message": f"No {METHOD_LABELS[method].lower()} is set up on this installation" + (
                        " (no recovery codes left)" if method == "recovery" else "") +
                    ". Use another method, or set one up under H2Vault menu > Second factor."}
        if method == "totp":
            return _verify_totp(str(factor.get("code") or ""), now, scope)
        if method == "recovery":
            left = _use_recovery(str(factor.get("code") or ""))
            if left is not None:
                _succeeded(scope)
                return {"ok": True, "reason": "recovery", "method": "recovery", "recovery_codes_left": left,
                        "message": f"Recovery code used ({left} left)."}
            _fail(now, scope)
            return {"ok": False, "reason": "wrong", "method": "recovery",
                    "message": "That recovery code is not right or was already used (each works once)."}
        if method == "backup_password":
            if _check_backup_password(str(factor.get("secret") or "")):
                _succeeded(scope)
                return {"ok": True, "reason": "backup_password", "method": method, "message": "Verified."}
            _fail(now, scope)
            return {"ok": False, "reason": "wrong", "method": method, "message": "That backup password is not right."}
        ok, message = _check_passkey(factor, origins)
        if ok:
            _succeeded(scope)
            return {"ok": True, "reason": "passkey", "method": "passkey", "message": message}
        _fail(now, scope)
        return {"ok": False, "reason": "wrong", "method": "passkey", "message": message}


def _verify_totp(code: str, now: Optional[float], scope: str) -> dict:
    """Any registered app's code is accepted, once per app. Every app is checked (the time taken does not tell which
    one matched); a wrong code is ONE failure however many apps there are."""
    auths = _authenticators()
    t = time.time() if now is None else now
    hits = []
    for a in auths:
        step = _match(base64.b64decode(a["secret"]), code, now)
        if step is not None:
            hits.append((a, step))
    fresh = [(a, step) for a, step in hits if step > int(a.get("last_step", -1))]
    if fresh:
        a, step = fresh[0]
        a["last_step"], a["last_used"] = step, int(t)
        _auth_save(a)
        _succeeded(scope)
        return {"ok": True, "reason": "ok", "method": "totp", "authenticator": a.get("label", ""),
                "message": "Verified."}
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
    _fail(now, scope)
    return {"ok": False, "reason": "wrong", "method": "totp",
            "message": "That code is not right. Use the current 6-digit code of the 'H2Vault' entry in your "
                       "authenticator app (codes from 30 s before or after are accepted)."}


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
def manage_begin(factor: Optional[dict] = None, *, now: Optional[float] = None, origins=()) -> dict:
    """{"ok": True, "manage_token", "expires_in"} after a proof with any method set up here (none needed while no
    method exists), else the verify_factor answer."""
    if any_enrolled():
        detail = verify_factor(factor or {}, scope="manage", now=now, origins=origins)
        if not detail["ok"]:
            return detail
    else:
        detail = {"ok": True, "reason": "none_set_up"}
    token = secrets.token_urlsafe(24)
    t = time.monotonic()
    with _lock:
        for k in [k for k, exp in _manage.items() if exp < t]:
            _manage.pop(k, None)
        _manage[token] = t + MANAGE_SECONDS
    return {**detail, "ok": True, "manage_token": token, "expires_in": MANAGE_SECONDS}


def check_manage(token: str) -> None:
    """Raises PermissionError unless `token` is a live settings token - or nothing is set up yet (first setup)."""
    if not any_enrolled():
        return
    with _lock:
        exp = _manage.get(str(token or ""))
    if exp is None or exp < time.monotonic():
        raise PermissionError("Confirm it is you first (one of your second-factor methods); the confirmation lasts "
                              "10 minutes.")


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
    return [{"vault_id": str(k), "title": str(v.get("title") or ""), "methods": list(v.get("methods") or [])}
            for k, v in data.items() if isinstance(v, dict)]


def note_vault(vault_id: str, methods, title: str = "") -> None:
    """Remember (or refresh) a vault's methods. Best effort: a failure here never stops a lock or an open."""
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
    if method in ("totp", "passkey"):
        after[method] = max(0, int(have[method]) - (1 if item_id else int(have[method])))
    elif method == "backup_password":
        after[method] = False
    last = bool(have.get(method)) and not after.get(method)
    unopenable, recovery_only = [], []
    for v in known_vaults():
        pol = v["methods"]
        if not pol or method not in pol:
            continue
        if any(m != "recovery" and after.get(m) for m in pol):
            continue
        (recovery_only if "recovery" in pol and after["recovery"] else unopenable).append(v)
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
            f"{'s' if one else ''} (H2Vault menu > Second factor), generate recovery codes, or change "
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
