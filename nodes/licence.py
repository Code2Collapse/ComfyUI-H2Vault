# H2Vault (AGPL-3.0). New for H2Vault (workstream V5, design docs/h2vault/V5_enhancements_design.md section 6).
# The idea of per-recipient access keys with an expiry was inspired by ComfyUI-XLJworkflowCipher (weiqing1987); no code
# or text was taken from it (it has no licence). See NOTICE.
"""Offline licences for Licensed vaults: one public workflow, one small signed text per installation.

A licence is `h2vl1:<body>.<signature>`. The body names the vault, the installation it is for, the dates and the run
limit, and carries the vault's licence key (LK) wrapped to that installation's X25519 key. The Author signs it with an
Ed25519 key whose public half is bound into the vault header (AES-GCM associated data), so only that Author can issue
licences for that vault.

What is cryptographic and what is not (README "Licences", design 6.1):
  cryptographic   no licence for this installation -> no LK -> the vault cannot be decrypted here; a licence works only
                  on its installation and only for its vault; nobody but the Author can issue one; after a licence-key
                  rotation, later versions of the vault refuse earlier licences.
  honour-system   expiry, not-before, run count, the clock check, "newest licence wins": kept by the unmodified H2Vault
                  runtime; someone who already ran the vault and modifies software on their own machine can ignore them.

Everything stays on the machine: no network call is ever made. Stored state lives in H2Vault's secrets store (OS
credential store or its encrypted file): scopes `licences`, `licence_usage`, `licence_clock`, `licence_ledger`,
`author`. Nothing here logs or returns a key.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

PREFIX = "h2vl1:"
MAX_TEXT = 4096
FMT = "h2vault-licence"
VERSION = 1
SIG_DOMAIN = b"h2vault-licence-v1\x00"
WRAP_INFO = b"h2vault-v2 licence wrap|"
LABEL_MAX = 60
TITLE_MAX = 80
CLOCK_TOLERANCE = 15 * 60          # seconds the clock may go back (time-zone / NTP corrections) before a refusal
MAX_STORED = 16                    # licences kept per vault on one installation
AUTHOR_LABEL = "This installation (author)"

KEYS = frozenset({"fmt", "v", "lid", "vault", "author", "install", "issued", "nbf", "exp", "runs", "label", "wrap"})
WRAP_KEYS = frozenset({"eph", "n", "ct"})

SCOPE_LICENCES, SCOPE_USAGE, SCOPE_CLOCK, SCOPE_LEDGER, SCOPE_AUTHOR = (
    "licences", "licence_usage", "licence_clock", "licence_ledger", "author")
_AUTHOR_NAME = "ed25519_private"
AUTHOR_FILE_FORMAT = "h2vault-author-key"

DAMAGED = "This licence is damaged."
NOT_AUTHOR = "This licence was not issued by this workflow's author, or it has been changed."
OTHER_VAULT = "This licence is for a different workflow."
OTHER_INSTALL = ("This licence was issued for another ComfyUI installation. Ask the author for one for this "
                 "installation (send your installation code).")
NEEDS_LICENCE = ("This workflow needs a licence from its author for this installation. Send them your installation "
                 "code (right-click the vault > My installation code), then add the licence they send you (right-click "
                 "the vault > Add licence...).")
NEWER_STORED = "A newer licence for this workflow is already installed."
OTHER_VERSION = ("The licences on this installation are for another copy of this workflow (its author has since "
                 "renewed its licence key). Ask the author for a licence for this copy, or use the copy they sent "
                 "with your licence.")
CLOCK_BACK = ("Your computer's clock is earlier than the last time this workflow ran. Correct the clock and try "
              "again.")
WRONG_FILE_PASSWORD = "Wrong password, or the file was changed."
OTHER_AUTHOR_KEY = ("This installation already has a different author key. Back it up first, then choose Replace.")

_lock = threading.RLock()


class LicenceError(ValueError):
    """A licence cannot be used. The message is plain English and names only public facts."""


# ── encoding helpers ────────────────────────────────────────────────────────────────────────────────────────────

_B64U = re.compile(r"^[A-Za-z0-9_-]*$")


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    if not isinstance(text, str) or not _B64U.match(text):
        raise LicenceError(DAMAGED)
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:  # noqa: BLE001
        raise LicenceError(DAMAGED) from exc


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def key_id(public_raw: bytes) -> str:
    """The short public id of an Ed25519 author key or an X25519 installation key."""
    return hashlib.sha256(public_raw).digest()[:8].hex()


def _wrap_key(shared: bytes, lid: bytes, vault_id: str) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=lid,
                info=WRAP_INFO + vault_id.encode("utf-8")).derive(shared)


def _wrap_aad(body: dict) -> bytes:
    return canonical({k: v for k, v in body.items() if k != "wrap"})


def _x25519_public(private_raw: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    return X25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed25519_public(private_raw: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# ── issue / parse / verify / unwrap ─────────────────────────────────────────────────────────────────────────────

def issue(*, author_priv: bytes, vault_id: str, lk: bytes, install_pub: bytes, label: str = "",
          exp: Optional[int] = None, runs: Optional[int] = None, nbf: Optional[int] = None,
          now: Optional[float] = None) -> str:
    """A signed licence text for one installation and one vault."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(lk) != 32 or len(install_pub) != 32:
        raise LicenceError("A licence needs a 32-byte licence key and an installation key.")
    if runs is not None and (not isinstance(runs, int) or isinstance(runs, bool) or runs < 1):
        raise LicenceError("The run limit must be a whole number of at least 1.")
    issued = int(now if now is not None else time.time())
    nbf = issued if nbf is None else int(nbf)
    if exp is not None and int(exp) <= nbf:
        raise LicenceError("The licence would end before it starts. Choose a later end date.")
    lid = os.urandom(16)
    body = {"fmt": FMT, "v": VERSION, "lid": b64u(lid), "vault": str(vault_id),
            "author": key_id(ed25519_public(author_priv)), "install": key_id(install_pub), "issued": issued,
            "nbf": nbf, "exp": None if exp is None else int(exp), "runs": runs,
            "label": str(label or "").strip()[:LABEL_MAX]}
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(install_pub))
    nonce = os.urandom(12)
    ct = AESGCM(_wrap_key(shared, lid, str(vault_id))).encrypt(nonce, lk, _wrap_aad(body))
    body["wrap"] = {"eph": b64u(eph.public_key().public_bytes(serialization.Encoding.Raw,
                                                              serialization.PublicFormat.Raw)),
                    "n": b64u(nonce), "ct": b64u(ct)}
    sig = Ed25519PrivateKey.from_private_bytes(author_priv).sign(SIG_DOMAIN + canonical(body))
    text = PREFIX + b64u(canonical(body)) + "." + b64u(sig)
    if len(text) > MAX_TEXT:
        raise LicenceError("The licence would be too long; shorten its name.")
    return text


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def parse(text: Any) -> dict:
    """Strict structural parse (never trusts a field before the signature is checked by `verify`)."""
    if not isinstance(text, str):
        raise LicenceError(DAMAGED)
    text = text.strip()
    if not text.startswith(PREFIX) or len(text) > MAX_TEXT or text.count(".") != 1:
        raise LicenceError(DAMAGED)
    body_b64, sig_b64 = text[len(PREFIX):].split(".")
    raw, sig = unb64u(body_b64), unb64u(sig_b64)
    try:
        body = json.loads(raw.decode("ascii"))
    except Exception as exc:  # noqa: BLE001
        raise LicenceError(DAMAGED) from exc
    if not isinstance(body, dict) or set(body) != KEYS or len(sig) != 64:
        raise LicenceError(DAMAGED)
    w = body["wrap"]
    ok = (body["fmt"] == FMT and body["v"] == VERSION and isinstance(body["lid"], str)
          and isinstance(body["vault"], str) and body["vault"]
          and isinstance(body["author"], str) and re.fullmatch(r"[0-9a-f]{16}", body["author"])
          and isinstance(body["install"], str) and re.fullmatch(r"[0-9a-f]{16}", body["install"])
          and _is_int(body["issued"]) and _is_int(body["nbf"])
          and (body["exp"] is None or _is_int(body["exp"]))
          and (body["runs"] is None or (_is_int(body["runs"]) and body["runs"] >= 1))
          and isinstance(body["label"], str) and len(body["label"]) <= LABEL_MAX
          and isinstance(w, dict) and set(w) == WRAP_KEYS and all(isinstance(w[k], str) for k in WRAP_KEYS))
    if not ok:
        raise LicenceError(DAMAGED)
    if canonical(body) != raw:                   # one spelling only: the signed bytes ARE the canonical body
        raise LicenceError(DAMAGED)
    if len(unb64u(body["lid"])) != 16 or len(unb64u(w["eph"])) != 32 or len(unb64u(w["n"])) != 12 \
            or len(unb64u(w["ct"])) != 48:
        raise LicenceError(DAMAGED)
    return {**body, "sig": sig, "text": text}


def verify(lic: dict, *, author_pub: bytes, vault_id: str, install_pub: bytes) -> dict:
    """Signature first, then author / vault / installation. -> the licence; LicenceError otherwise."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    body = {k: lic[k] for k in KEYS}
    try:
        Ed25519PublicKey.from_public_bytes(author_pub).verify(lic["sig"], SIG_DOMAIN + canonical(body))
    except (InvalidSignature, ValueError) as exc:
        raise LicenceError(NOT_AUTHOR) from exc
    if lic["author"] != key_id(author_pub):
        raise LicenceError(NOT_AUTHOR)
    if lic["vault"] != str(vault_id):
        raise LicenceError(OTHER_VAULT)
    if lic["install"] != key_id(install_pub):
        raise LicenceError(OTHER_INSTALL)
    return lic


def unwrap(lic: dict, install_priv: bytes) -> bytes:
    """The vault's licence key, with this installation's private key."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    body = {k: lic[k] for k in KEYS}
    w = lic["wrap"]
    try:
        shared = X25519PrivateKey.from_private_bytes(install_priv).exchange(
            X25519PublicKey.from_public_bytes(unb64u(w["eph"])))
        return AESGCM(_wrap_key(shared, unb64u(lic["lid"]), lic["vault"])).decrypt(
            unb64u(w["n"]), unb64u(w["ct"]), _wrap_aad(body))
    except LicenceError:
        raise
    except Exception as exc:  # noqa: BLE001 - InvalidTag: not this installation's licence, or changed
        raise LicenceError(OTHER_INSTALL) from exc


# ── policy (honour-system limits) ───────────────────────────────────────────────────────────────────────────────

_MONTHS = ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
           "November", "December")


def fmt_date(ts: float) -> str:
    """UTC date in words, e.g. "3 March 2027" (no locale, so the same on every machine)."""
    d = datetime.fromtimestamp(int(ts), tz=timezone.utc)
    return f"{d.day} {_MONTHS[d.month - 1]} {d.year}"


def check_policy(lic: dict, *, now: float, used_runs: int = 0, last_seen: Optional[float] = None) -> Optional[str]:
    """None when the licence may run now, else the refusal text (pure: the caller passes the clock and the usage)."""
    if last_seen and now < float(last_seen) - CLOCK_TOLERANCE:
        return CLOCK_BACK
    if now < lic["nbf"]:
        return f"Your licence for this workflow starts on {fmt_date(lic['nbf'])}."
    if lic["exp"] is not None and now >= lic["exp"]:
        return f"Your licence for this workflow ended on {fmt_date(lic['exp'])}. Ask its author for a new one."
    if lic["runs"] is not None and int(used_runs) >= lic["runs"]:
        n = lic["runs"]
        return (f"Your licence allowed {n} run{'s' if n != 1 else ''} of this workflow and all have been used. Ask "
                "its author for a new one.")
    return None


# ── local stores (H2Vault secrets store) ────────────────────────────────────────────────────────────────────────

def _ss():
    from . import secrets_store
    return secrets_store


def _get_json(scope: str, name: str, default):
    raw = _ss().get(scope, name)
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return default


def _put_json(scope: str, name: str, value) -> None:
    _ss().set_(scope, name, json.dumps(value, separators=(",", ":")))


def stored(vault_id: str) -> list:
    """The licence texts kept on this installation for a vault (newest issued first)."""
    v = _get_json(SCOPE_LICENCES, str(vault_id), [])
    return [t for t in v if isinstance(t, str)] if isinstance(v, list) else []


def add(text: str, *, author_pub: bytes, vault_id: str, install_pub: bytes) -> dict:
    """Verify a licence against the vault it is added to, then keep it. -> the parsed licence."""
    lic = verify(parse(text), author_pub=author_pub, vault_id=vault_id, install_pub=install_pub)
    with _lock:
        texts = stored(vault_id)
        mine = []
        for t in texts:
            try:
                mine.append(parse(t))
            except LicenceError:
                continue
        if any(m["lid"] == lic["lid"] for m in mine):
            return lic
        if any(m["install"] == lic["install"] and m["issued"] > lic["issued"] for m in mine):
            raise LicenceError(NEWER_STORED)
        keep = sorted([lic, *mine], key=lambda m: m["issued"], reverse=True)[:MAX_STORED]
        _put_json(SCOPE_LICENCES, str(vault_id), [m["text"] for m in keep])
    return lic


def remove(lid: str) -> bool:
    """Forget one stored licence (any vault)."""
    with _lock:
        removed = False
        for vault in _ss().list_(SCOPE_LICENCES):
            texts = stored(vault)
            keep = []
            for t in texts:
                try:
                    if parse(t)["lid"] == lid:
                        removed = True
                        continue
                except LicenceError:
                    pass
                keep.append(t)
            if len(keep) != len(texts):
                if keep:
                    _put_json(SCOPE_LICENCES, vault, keep)
                else:
                    _ss().delete(SCOPE_LICENCES, vault)
        return removed


def usage(lid: str) -> dict:
    u = _get_json(SCOPE_USAGE, str(lid), {})
    return {"runs": int(u.get("runs") or 0), "last_seen": u.get("last_seen")} if isinstance(u, dict) \
        else {"runs": 0, "last_seen": None}


def clock_last_seen() -> Optional[float]:
    v = _ss().get(SCOPE_CLOCK, "last_seen")
    try:
        return float(v) if v else None
    except ValueError:
        return None


def record_run(lid: str, now: Optional[float] = None) -> dict:
    """One real run of a licensed vault on this installation (cached re-queues never get here)."""
    now = int(now if now is not None else time.time())
    with _lock:
        u = usage(lid)
        u = {"runs": u["runs"] + 1, "last_seen": now}
        _put_json(SCOPE_USAGE, str(lid), u)
        last = clock_last_seen()
        if last is None or now > last:
            _ss().set_(SCOPE_CLOCK, "last_seen", str(now))
    return u


def candidates(vault_id: str, *, author_pub: bytes, install_pub: bytes) -> list:
    """The stored licences that verify for this vault and installation, newest issued first."""
    valid = []
    for t in stored(vault_id):
        try:
            valid.append(verify(parse(t), author_pub=author_pub, vault_id=vault_id, install_pub=install_pub))
        except LicenceError:
            continue
    return sorted(valid, key=lambda m: m["issued"], reverse=True)


def policy(lic: dict, now: Optional[float] = None) -> Optional[str]:
    """check_policy with this installation's stored usage and clock."""
    now = float(now if now is not None else time.time())
    return check_policy(lic, now=now, used_runs=usage(lic["lid"])["runs"], last_seen=clock_last_seen())


def best_for_run(vault_id: str, *, author_pub: bytes, install_pub: bytes,
                 now: Optional[float] = None) -> tuple:
    """-> (licence, None) for the newest stored licence that verifies for this vault and installation and may run
    now, else (None, refusal text). The refusal names the newest matching licence's problem."""
    now = float(now if now is not None else time.time())
    valid = []
    for t in stored(vault_id):
        try:
            valid.append(verify(parse(t), author_pub=author_pub, vault_id=vault_id, install_pub=install_pub))
        except LicenceError:
            continue
    if not valid:
        return None, NEEDS_LICENCE
    lic = max(valid, key=lambda m: m["issued"])
    u = usage(lic["lid"])
    problem = check_policy(lic, now=now, used_runs=u["runs"], last_seen=clock_last_seen())
    return (None, problem) if problem else (lic, None)


def runs_left(lic: dict) -> Optional[int]:
    if lic.get("runs") is None:
        return None
    return max(0, int(lic["runs"]) - usage(lic["lid"])["runs"])


# ── the Author's signing key and Ledger ─────────────────────────────────────────────────────────────────────────

def author_private_key(create: bool = True) -> Optional[bytes]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with _lock:
        raw = _ss().get(SCOPE_AUTHOR, _AUTHOR_NAME)
        if raw:
            return base64.b64decode(raw)
        if not create:
            return None
        priv = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                          serialization.NoEncryption())
        _ss().set_(SCOPE_AUTHOR, _AUTHOR_NAME, base64.b64encode(priv).decode("ascii"))
        return priv


def author_public_key(create: bool = True) -> Optional[bytes]:
    priv = author_private_key(create=create)
    return ed25519_public(priv) if priv else None


def ledger_add(row: dict) -> None:
    keep = ("lid", "vault_id", "vault_title", "label", "install_code", "issued", "nbf", "exp", "runs")
    clean = {k: row.get(k) for k in keep}
    _put_json(SCOPE_LEDGER, str(row["lid"]), clean)


def ledger_rows() -> list:
    rows = []
    for name in _ss().list_(SCOPE_LEDGER):
        r = _get_json(SCOPE_LEDGER, name, None)
        if isinstance(r, dict):
            rows.append(r)
    return sorted(rows, key=lambda r: r.get("issued") or 0, reverse=True)


def ledger_row(lid: str) -> Optional[dict]:
    r = _get_json(SCOPE_LEDGER, str(lid), None)
    return r if isinstance(r, dict) else None


def _author_aad(obj: dict) -> bytes:
    return canonical({k: obj[k] for k in ("format", "v", "kdf", "salt", "author")})


def export_author(password: str) -> dict:
    """The author key as a password-protected file object (Argon2id + AES-256-GCM; the header is the AAD)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from . import crypto

    if not isinstance(password, str) or len(password) < 8:
        raise LicenceError("Choose a password of at least 8 characters for the backup.")
    priv = author_private_key(create=True)
    salt = os.urandom(crypto.SALT_LEN)
    kdf = dict(crypto.ARGON2_V1)
    obj = {"format": AUTHOR_FILE_FORMAT, "v": 1, "kdf": kdf, "salt": b64u(salt),
           "author": key_id(ed25519_public(priv))}
    nonce = os.urandom(12)
    ct = AESGCM(crypto.kek_from_password(password, salt, kdf)).encrypt(nonce, priv, _author_aad(obj))
    return {**obj, "nonce": b64u(nonce), "ct": b64u(ct)}


def import_author(obj: Any, password: str, replace: bool = False) -> str:
    """Restore an author key backup. -> its key id."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from . import crypto

    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except Exception as exc:  # noqa: BLE001
            raise LicenceError("This is not an H2Vault author key file.") from exc
    if not isinstance(obj, dict) or obj.get("format") != AUTHOR_FILE_FORMAT or obj.get("v") != 1:
        raise LicenceError("This is not an H2Vault author key file.")
    try:
        kdf = {k: int(obj["kdf"][k]) for k in ("memory_kib", "iterations", "lanes")}
        crypto.check_kdf(kdf)
        salt, nonce, ct = unb64u(obj["salt"]), unb64u(obj["nonce"]), unb64u(obj["ct"])
        header = {**obj, "kdf": obj["kdf"]}
        priv = AESGCM(crypto.kek_from_password(str(password or "x"), salt, kdf)).decrypt(
            nonce, ct, _author_aad(header))
    except crypto.VaultError as exc:
        raise LicenceError("This author key file is malformed.") from exc
    except Exception as exc:  # noqa: BLE001
        raise LicenceError(WRONG_FILE_PASSWORD) from exc
    kid = key_id(ed25519_public(priv))
    with _lock:
        cur = author_private_key(create=False)
        if cur and cur != priv and not replace:
            raise LicenceError(OTHER_AUTHOR_KEY)
        _ss().set_(SCOPE_AUTHOR, _AUTHOR_NAME, base64.b64encode(priv).decode("ascii"))
    return kid
