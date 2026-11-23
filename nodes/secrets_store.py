# Derived from Code2Collapse ComfyUI-CustomNodePacks nodes/_c2c_secrets.py (Apache-2.0, Copyright Code2Collapse);
# modified for H2Vault (AGPL-3.0): own keyring service / folder / env names, no HTTP routes. See NOTICE.
"""H2Vault's local secret store: the install key pair, the second factor and remembered workflow keys.

Backends, chosen at import time:
  1. ``keyring`` (Windows Credential Manager / macOS Keychain / libsecret): service ``h2vault:<scope>``, user ``<name>``.
     A separate entry ``h2vault:_index`` keeps the names per scope (keyring cannot enumerate).
  2. Encrypted file ``<ComfyUI user dir>/h2vault/secrets.enc.json`` (Fernet, key = PBKDF2-HMAC-SHA256 of a passphrase,
     200 000 iterations, random salt kept in the file). The passphrase comes from ``H2VAULT_SECRETS_PASSPHRASE`` or, if
     unset, a random one written once to ``<user dir>/h2vault/secrets.passphrase`` (0600 on POSIX). Honest scope: the
     file and its passphrase sit side by side, so this protects against reading the file alone (a copied workflow
     folder, a backup), not against someone with the whole user directory - set the env passphrase for more.
  3. Neither: ``set_`` raises; nothing is ever stored in plaintext.

``H2VAULT_SECRETS_BACKEND=file`` forces the file backend: the OS credential store is one per OS user and shared by every
ComfyUI install of that user, so a test install must never read the production install's vault key.

Values never leave this module through HTTP; callers are in-process Python only.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import secrets as _stdlib_secrets
import threading
from pathlib import Path
from typing import Optional

log = logging.getLogger("h2vault.secrets")
_LOCK = threading.RLock()
_SERVICE = "h2vault"


def _user_dir() -> Path:
    """<ComfyUI user dir>/h2vault - created if missing. H2VAULT_USER_DIR overrides the base (tests, and installs that
    keep secrets apart from the ComfyUI user folder)."""
    override = os.environ.get("H2VAULT_USER_DIR")
    if override:
        base = Path(override)
    else:
        try:
            import folder_paths  # type: ignore
            base = Path(folder_paths.get_user_directory())
        except Exception:  # noqa: BLE001 - outside ComfyUI
            base = Path(__file__).resolve().parents[1] / "_user"
    out = base / "h2vault"
    out.mkdir(parents=True, exist_ok=True)
    return out


def _enc_path() -> Path:
    return _user_dir() / "secrets.enc.json"


def _passphrase_path() -> Path:
    return _user_dir() / "secrets.passphrase"


def _try_keyring():
    try:
        import keyring  # type: ignore
        kr_backend = keyring.get_keyring()
        name = type(kr_backend).__name__
        module = type(kr_backend).__module__ or ""
        # keyring's null and fail backends both silently discard / refuse every secret
        if "Fail" in name or "Null" in name or module.endswith((".null", ".fail")):
            log.info("keyring present but its backend is %s; using the encrypted file", name)
            return None
        return keyring
    except Exception:  # noqa: BLE001
        return None


def _has_cryptography() -> bool:
    try:
        from cryptography.fernet import Fernet  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


_FORCED = os.environ.get("H2VAULT_SECRETS_BACKEND", "").strip().lower()
_KR = None if _FORCED == "file" else _try_keyring()
_BACKEND = "keyring" if _KR is not None else ("enc-file" if _has_cryptography() else "none")


def backend_name() -> str:
    return _BACKEND


# ── keyring ─────────────────────────────────────────────────────────────────────────────────────────────────────
def _kr_service(scope: str) -> str:
    return f"{_SERVICE}:{scope}"


def _kr_index_load() -> dict:
    try:
        raw = _KR.get_password(f"{_SERVICE}:_index", "index")
        d = json.loads(raw) if raw else {}
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _kr_index_save(idx: dict) -> None:
    try:
        _KR.set_password(f"{_SERVICE}:_index", "index", json.dumps(idx))
    except Exception as exc:  # noqa: BLE001
        log.warning("keyring index save failed: %s", type(exc).__name__)


# Windows Credential Manager keeps at most 2560 bytes per entry (UTF-16: ~1280 characters); several passkeys or a long
# record did not fit (2026-11-23). A longer value is stored in pieces: the entry itself holds a marker with the piece
# count, the pieces sit under "<name>#h2vc<i>". Short values are stored exactly as before (old stores keep working).
_KR_PIECE = 1000
_KR_MARK = "~h2v-pieces~:"           # printable: a Windows credential string must not start with a NUL


def _kr_piece_name(name: str, i: int) -> str:
    return f"{name}#h2vc{i}"


def _kr_pieces(service: str, name: str) -> int:
    try:
        raw = _KR.get_password(service, name)
    except Exception:  # noqa: BLE001
        return 0
    if raw and raw.startswith(_KR_MARK):
        try:
            return max(0, int(raw[len(_KR_MARK):]))
        except ValueError:
            return 0
    return 0


def _kr_drop_pieces(service: str, name: str, keep: int = 0) -> None:
    for i in range(keep, _kr_pieces(service, name)):
        try:
            _KR.delete_password(service, _kr_piece_name(name, i))
        except Exception:  # noqa: BLE001
            pass


def _kr_set(service: str, name: str, value: str) -> None:
    if len(value) <= _KR_PIECE:
        _kr_drop_pieces(service, name)
        _KR.set_password(service, name, value)
        return
    parts = [value[i:i + _KR_PIECE] for i in range(0, len(value), _KR_PIECE)]
    _kr_drop_pieces(service, name, keep=len(parts))
    for i, part in enumerate(parts):
        _KR.set_password(service, _kr_piece_name(name, i), part)
    _KR.set_password(service, name, f"{_KR_MARK}{len(parts)}")      # written last: a crash leaves the old value


def _kr_get(service: str, name: str):
    raw = _KR.get_password(service, name)
    if not raw or not raw.startswith(_KR_MARK):
        return raw
    parts = []
    for i in range(_kr_pieces(service, name)):
        part = _KR.get_password(service, _kr_piece_name(name, i))
        if part is None:
            log.warning("secret %s is incomplete (a piece is missing)", name)
            return None
        parts.append(part)
    return "".join(parts)


# ── encrypted file ──────────────────────────────────────────────────────────────────────────────────────────────
def _read_or_create_passphrase() -> bytes:
    env = os.environ.get("H2VAULT_SECRETS_PASSPHRASE")
    if env:
        return env.encode("utf-8")
    p = _passphrase_path()
    if p.exists():
        return p.read_bytes().strip()
    pp = _stdlib_secrets.token_urlsafe(32).encode("utf-8")
    p.write_bytes(pp)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return pp


def _enc_load() -> dict:
    p = _enc_path()
    if not p.exists():
        return {"salt": base64.b64encode(_stdlib_secrets.token_bytes(16)).decode("ascii"), "data": {}}
    return json.loads(p.read_text("utf-8"))           # a damaged file raises: never clobbered silently


def _enc_save(blob: dict) -> None:
    p = _enc_path()
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(blob, indent=1), encoding="utf-8")
    os.replace(tmp, p)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def _enc_fernet(blob: dict):
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=base64.b64decode(blob["salt"]), iterations=200000)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(_read_or_create_passphrase())))


# ── public API ──────────────────────────────────────────────────────────────────────────────────────────────────
def _validate(scope: str, name: str) -> None:
    if not isinstance(scope, str) or not scope or "/" in scope or ":" in scope:
        raise ValueError(f"invalid scope: {scope!r}")
    if not isinstance(name, str) or not name or len(name) > 256:
        raise ValueError("invalid secret name")


def get(scope: str, name: str) -> Optional[str]:
    _validate(scope, name)
    with _LOCK:
        if _BACKEND == "keyring":
            try:
                return _kr_get(_kr_service(scope), name)
            except Exception as exc:  # noqa: BLE001
                log.warning("secret %s/%s could not be read: %s", scope, name, type(exc).__name__)
                return None
        if _BACKEND == "enc-file":
            try:
                blob = _enc_load()
                ct = blob.get("data", {}).get(scope, {}).get(name)
                return _enc_fernet(blob).decrypt(ct.encode("ascii")).decode("utf-8") if ct else None
            except Exception as exc:  # noqa: BLE001
                log.warning("secret %s/%s could not be decrypted: %s", scope, name, type(exc).__name__)
                return None
        return None


def set_(scope: str, name: str, value: str) -> None:
    _validate(scope, name)
    if not isinstance(value, str) or not value:
        raise ValueError("value must be a non-empty string")
    if len(value) > 64 * 1024:
        raise ValueError("value too large (max 64 KiB)")
    with _LOCK:
        if _BACKEND == "keyring":
            _kr_set(_kr_service(scope), name, value)
            idx = _kr_index_load()
            idx[scope] = sorted(set(idx.get(scope, [])) | {name})
            _kr_index_save(idx)
            return
        if _BACKEND == "enc-file":
            blob = _enc_load()
            blob.setdefault("data", {}).setdefault(scope, {})[name] = \
                _enc_fernet(blob).encrypt(value.encode("utf-8")).decode("ascii")
            _enc_save(blob)
            return
        raise RuntimeError("H2Vault has no place to keep secrets: install 'cryptography' (or 'keyring'). It never "
                           "stores secrets in plaintext.")


def delete(scope: str, name: str) -> bool:
    _validate(scope, name)
    with _LOCK:
        if _BACKEND == "keyring":
            try:
                _kr_drop_pieces(_kr_service(scope), name)
                _KR.delete_password(_kr_service(scope), name)
                ok = True
            except Exception:  # noqa: BLE001
                ok = False
            idx = _kr_index_load()
            if name in idx.get(scope, []):
                idx[scope] = [n for n in idx[scope] if n != name]
                if not idx[scope]:
                    idx.pop(scope, None)
                _kr_index_save(idx)
            return ok
        if _BACKEND == "enc-file":
            try:
                blob = _enc_load()
            except Exception:  # noqa: BLE001
                return False
            d = blob.get("data", {}).get(scope, {})
            if name not in d:
                return False
            del d[name]
            if not d:
                blob["data"].pop(scope, None)
            _enc_save(blob)
            return True
        return False


def list_(scope: str) -> list[str]:
    """Names in a scope (never values)."""
    if not scope:
        raise ValueError("scope required")
    with _LOCK:
        if _BACKEND == "keyring":
            return sorted(_kr_index_load().get(scope, []))
        if _BACKEND == "enc-file":
            try:
                return sorted(_enc_load().get("data", {}).get(scope, {}).keys())
            except Exception:  # noqa: BLE001
                return []
        return []
