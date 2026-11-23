# Derived from Code2Collapse ComfyUI-CustomNodePacks nodes/vault_2fa.py (Apache-2.0, Copyright Code2Collapse);
# modified for H2Vault (AGPL-3.0). See NOTICE.
"""Second factor for opening a vault to edit, per person per install (A17 s2.6, owner D0.25; methods 2026-11-23).

Methods (set up on this installation; a vault chooses which of them may open it - `policy_of`):
  totp             authenticator app, RFC 6238 via the `cryptography` package (SHA-1, 6 digits, 30 s - what apps
                   use). Codes from one step before / after are accepted (clock drift); a code works once.
  passkey          passkey / security key / Windows Hello through WebAuthn (`webauthn_min`), several per install.
  backup_password  a second secret, different from any vault password; stored as an scrypt hash.
  recovery         single-use recovery codes (8 per set), stored as scrypt hashes; always allowed as a fallback.
Email and SMS codes need a mail / SMS provider and a server that sends them: not possible offline (`NOT_OFFLINE`).

Everything lives only in the local secrets store (`store`), never in a workflow, never derived from a vault password.
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
_lock = threading.RLock()
_pending: dict = {}                    # enrolment waiting for its first code: {"secret": bytes, "codes": [...]}
_challenges: dict = {}                 # passkey challenges: id -> {"challenge", "kind", "rp_id", "at", "label"}
_manage: dict = {}                     # settings tokens: token -> expiry (monotonic)

METHODS = ("totp", "passkey", "backup_password", "recovery")
DEFAULT_POLICY = ("totp", "recovery")  # vaults locked before methods existed (no stored choice)
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
    """The authenticator app is set up (the historical meaning; see any_enrolled for 'some method')."""
    return bool(vault_store.get(_SECRET))


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
    """{"totp": bool, "passkey": count, "backup_password": bool, "recovery": codes left} - never a secret."""
    return {"totp": enrolled(), "passkey": len(_passkeys()), "backup_password": bool(vault_store.get(_BACKUP_PW)),
            "recovery": recovery_codes_left()}


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


def policy_of(plain: dict) -> list:
    """The methods a vault accepts. Vaults locked before methods existed accept the authenticator + recovery codes."""
    sf = plain.get("second_factor") if isinstance(plain, dict) else None
    try:
        if isinstance(sf, dict):
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


def begin_enrolment(account: str = "ComfyUI vault") -> dict:
    """A new secret (+ a first set of recovery codes when this install has none), shown ONCE; active only after
    confirm_enrolment(first code)."""
    with _lock:
        if enrolled():
            raise PermissionError("An authenticator is already set up on this install. Replace it under H2Vault menu "
                                  "> Second factor (needs one of your methods).")
        if _pending and time.time() - _pending.get("at", 0) <= 15 * 60:
            secret, codes = _pending["secret"], _pending["codes"]   # same setup while it is pending (QR <-> key)
        else:
            secret = os.urandom(20)
            codes = [_recovery_code() for _ in range(RECOVERY_COUNT)] if recovery_codes_left() == 0 else []
            _pending.clear()
            _pending.update({"secret": secret, "codes": codes, "at": time.time()})
    uri = _totp(secret).get_provisioning_uri(account, "H2Vault")
    b32 = base64.b32encode(secret).decode("ascii").rstrip("=")
    return {"secret_base32": b32, "secret_grouped": " ".join(b32[i:i + 4] for i in range(0, len(b32), 4)),
            "otpauth_uri": uri, "qr_svg": qr_svg(uri), "recovery_codes": codes,
            "recovery_kept": 0 if codes else recovery_codes_left(), "issuer": "H2Vault",
            "account": account, "algorithm": "SHA1", "digits": DIGITS, "period": STEP}


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
        vault_store.put(_SECRET, base64.b64encode(_pending["secret"]).decode("ascii"))
        if _pending.get("codes"):
            _store_recovery(_pending["codes"])
        vault_store.put(_LAST, str(step))
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


def remove_totp() -> None:
    with _lock:
        for name in (_SECRET, _LAST):
            vault_store.delete(name)
        _pending.clear()


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
    stored = vault_store.get(_SECRET)
    secret = base64.b64decode(stored)
    t = time.time() if now is None else now
    step = _match(secret, code, now)
    if step is not None:
        last = int(vault_store.get(_LAST) or "-1")
        if step <= last:
            nxt = int(STEP - (t % STEP)) + 1
            return {"ok": False, "reason": "reused", "method": "totp", "next_in": nxt,
                    "message": f"That code was already used (each code works once). Wait for the next code in "
                               f"your app - about {nxt} s - and enter that one."}
        vault_store.put(_LAST, str(step))
        _succeeded(scope)
        return {"ok": True, "reason": "ok", "method": "totp", "message": "Verified."}
    skew = _probe_clock(secret, code, now)
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


# ── every method lost ───────────────────────────────────────────────────────────────────────────────────────────
RESET_ENV, RESET_VALUE = "H2VAULT_RESET_SECOND_FACTOR", "remove-all"


def reset_all() -> None:
    """Remove every second-factor method of this installation (vaults, keys and licences are untouched)."""
    with _lock:
        for name in (_SECRET, _LAST, _RECOVERY, _FAILS, _BACKUP_PW, _PASSKEYS, _USER_HANDLE):
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
