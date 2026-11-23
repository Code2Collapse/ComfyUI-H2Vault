# PORTED FROM: https://github.com/jtydhr88/ComfyUI-Workflow-Encrypt __init__.py @ 5ec45fd (AGPL-3.0, jtydhr88);
# modified for H2Vault (AGPL-3.0). See NOTICE.
"""Encrypted workflow files (docs/ARCHITECTURE.md section 2.2).

Two schemes:
  "fernet"            ComfyUI-Workflow-Encrypt's format, byte compatible: token = Fernet(key).encrypt(json.dumps(wf)).
                      A random key is made per file and returned ONCE; it can be remembered in the H2Vault secrets
                      store (scope "workflow_keys", by the token's SHA-256 fingerprint) so this install opens the file
                      again without asking.
  "argon2id-aesgcm"   password mode: Argon2id(password, salt) -> AES-256-GCM, the file's header fields are the AAD.

The saved file is a JSON wrapper, so ComfyUI's own Open / drag-and-drop passes it to app.loadGraphData, where the front
end asks for the key. A bare token (a file made by Workflow-Encrypt) is accepted too, and "export for Workflow-Encrypt"
is just the wrapper's token.

Unlike the original, nothing here prints or logs a key, a password, a token or workflow content.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from typing import Any, Optional

from .crypto import ARGON2_V1, VaultError, check_kdf, kek_from_password

MARKER = "h2vault_encrypted_workflow"
SCHEME_FERNET = "fernet"
SCHEME_PASSWORD = "argon2id-aesgcm"
SCHEMES = (SCHEME_FERNET, SCHEME_PASSWORD)
MAX_BYTES = 64 * 1024 * 1024
MIN_PASSWORD = 8
LABEL_MAX = 80
KEY_SCOPE = "workflow_keys"
NOTE = "Encrypted with H2Vault. Open it in ComfyUI with ComfyUI-H2Vault installed and enter its key or password."
SAME_ERROR = ("Could not decrypt this workflow: wrong key or password, or the file was changed. (These are deliberately "
              "reported the same way.)")
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 5 * 60

KEYSTORE: Optional[dict] = None        # tests: a dict {fingerprint: json}; else the secrets store
_KDF_GATE = threading.Semaphore(1)     # one Argon2id derivation at a time (each takes 128 MiB)
_lock = threading.Lock()
_fails: dict[str, tuple[int, float]] = {}


class Malformed(VaultError):
    status = 400


class NeedsSecret(VaultError):
    """No key / password was given and none is remembered: the dialog asks for it."""

    def __init__(self, msg: str, needs: str):
        super().__init__(msg)
        self.needs = needs


def fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("ascii", "ignore")).hexdigest()


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _workflow_bytes(workflow: Any) -> bytes:
    if not isinstance(workflow, dict):
        raise Malformed("The workflow to encrypt must be a JSON object.")
    data = json.dumps(workflow).encode("utf-8")
    if len(data) > MAX_BYTES:
        raise Malformed("This workflow is too large to encrypt (64 MB).")
    return data


def _decode_workflow(data: bytes) -> dict:
    try:
        out = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise Malformed("The file decrypted, but its content is not a workflow (not JSON).") from exc
    if not isinstance(out, dict):
        raise Malformed("The file decrypted, but its content is not a workflow (not a JSON object).")
    return out


def _fernet(key: str):
    from cryptography.fernet import Fernet
    try:
        return Fernet(key.strip().encode("ascii"))
    except Exception as exc:
        raise Malformed("That is not a valid key: a workflow key is 44 characters of letters, digits, '-' and '_', "
                        "ending in '='.") from exc


# ── the file ────────────────────────────────────────────────────────────────────────────────────────────────────
def parse_file(file: Any) -> dict:
    """A wrapper dict, a wrapper JSON string or a bare Fernet token -> a normalised wrapper dict."""
    if isinstance(file, str):
        text = file.strip()
        if len(text) > MAX_BYTES * 2:
            raise Malformed("This file is too large.")
        if text.startswith("{"):
            try:
                file = json.loads(text)
            except Exception as exc:
                raise Malformed("This file is not an encrypted workflow (broken JSON).") from exc
        elif text.startswith("gAAAAA"):          # a Fernet token (version byte 0x80) as Workflow-Encrypt writes it
            return {MARKER: 1, "scheme": SCHEME_FERNET, "token": text, "fingerprint": fingerprint(text)}
        else:
            raise Malformed("This file is not an encrypted workflow.")
    if not isinstance(file, dict) or file.get(MARKER) != 1:
        raise Malformed("This file is not an H2Vault encrypted workflow.")
    scheme = file.get("scheme")
    if scheme == SCHEME_FERNET:
        token = file.get("token")
        if not isinstance(token, str) or not token.strip():
            raise Malformed("This encrypted workflow has no content.")
        token = token.strip()
        return {MARKER: 1, "scheme": scheme, "token": token, "fingerprint": fingerprint(token)}
    if scheme == SCHEME_PASSWORD:
        try:
            kdf = {k: int(file["kdf"][k]) for k in ("memory_kib", "iterations", "lanes")}
            salt, nonce, ct = (base64.b64decode(file[k], validate=True) for k in ("salt", "nonce", "ciphertext"))
        except Exception as exc:
            raise Malformed("This encrypted workflow is damaged (missing or broken fields).") from exc
        check_kdf(kdf)                           # a file can neither weaken the KDF nor demand absurd memory
        if len(salt) != 16 or len(nonce) != 12 or len(ct) <= 16:
            raise Malformed("This encrypted workflow is damaged (bad field sizes).")
        return {MARKER: 1, "scheme": scheme, "kdf": kdf, "salt": file["salt"], "nonce": file["nonce"],
                "ciphertext": file["ciphertext"], "fingerprint": fingerprint(file["ciphertext"])}
    raise Malformed(f"Unknown encryption scheme {str(scheme)[:30]!r}: update ComfyUI-H2Vault.")


def _aad(kdf: dict, salt_b64: str) -> bytes:
    return _canon({MARKER: 1, "scheme": SCHEME_PASSWORD, "kdf": kdf, "salt": salt_b64})


def encrypt_fernet(workflow: dict, key: Optional[str] = None) -> tuple[str, dict]:
    """-> (key, wrapper). The key exists only in the return value. `key` = save again with a key already in use (V5
    "same key": only ever a key remembered in this installation's secrets store, never one sent by a page)."""
    from cryptography.fernet import Fernet
    key = key.encode("ascii") if key else Fernet.generate_key()
    token = Fernet(key).encrypt(_workflow_bytes(workflow)).decode("ascii")
    return key.decode("ascii"), {MARKER: 1, "scheme": SCHEME_FERNET, "token": token, "fingerprint": fingerprint(token),
                                 "note": NOTE}


def encrypt_password(workflow: dict, password: str, kdf: Optional[dict] = None) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise Malformed(f"Choose a password of at least {MIN_PASSWORD} characters.")
    kdf = dict(kdf or ARGON2_V1)
    check_kdf(kdf)
    salt, nonce = os.urandom(16), os.urandom(12)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    with _KDF_GATE:
        key = kek_from_password(password, salt, kdf)
    ct = base64.b64encode(AESGCM(key).encrypt(nonce, _workflow_bytes(workflow), _aad(kdf, salt_b64))).decode("ascii")
    return {MARKER: 1, "scheme": SCHEME_PASSWORD, "kdf": kdf, "salt": salt_b64,
            "nonce": base64.b64encode(nonce).decode("ascii"), "ciphertext": ct, "fingerprint": fingerprint(ct),
            "note": NOTE}


def decrypt_fernet(wrapper: dict, key: str) -> dict:
    from cryptography.fernet import InvalidToken
    f = _fernet(key)
    try:
        data = f.decrypt(wrapper["token"].encode("ascii"))
    except (InvalidToken, ValueError, TypeError) as exc:
        raise VaultError(SAME_ERROR) from exc
    return _decode_workflow(data)


def decrypt_password(wrapper: dict, password: str) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not isinstance(password, str) or not password:
        raise NeedsSecret("Enter the password of this workflow.", "password")
    salt = base64.b64decode(wrapper["salt"])
    with _KDF_GATE:
        key = kek_from_password(password, salt, wrapper["kdf"])
    try:
        data = AESGCM(key).decrypt(base64.b64decode(wrapper["nonce"]), base64.b64decode(wrapper["ciphertext"]),
                                   _aad(wrapper["kdf"], wrapper["salt"]))
    except Exception as exc:
        raise VaultError(SAME_ERROR) from exc
    return _decode_workflow(data)


# ── remembered keys ─────────────────────────────────────────────────────────────────────────────────────────────
def _ks_get(fp: str) -> Optional[str]:
    if KEYSTORE is not None:
        return KEYSTORE.get(fp)
    from . import secrets_store
    return secrets_store.get(KEY_SCOPE, fp)


def _ks_put(fp: str, value: str) -> None:
    if KEYSTORE is not None:
        KEYSTORE[fp] = value
        return
    from . import secrets_store
    secrets_store.set_(KEY_SCOPE, fp, value)


def _ks_names() -> list:
    if KEYSTORE is not None:
        return sorted(KEYSTORE)
    from . import secrets_store
    return secrets_store.list_(KEY_SCOPE)


def _ks_delete(fp: str) -> bool:
    if KEYSTORE is not None:
        return KEYSTORE.pop(fp, None) is not None
    from . import secrets_store
    return secrets_store.delete(KEY_SCOPE, fp)


def _check_fp(fp: Any) -> str:
    fp = str(fp or "")
    if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
        raise Malformed("Not a workflow fingerprint.")
    return fp


def remember(fp: str, key: str, label: str = "") -> None:
    _fernet(key)                                             # only a valid key is ever stored
    _ks_put(_check_fp(fp), json.dumps({"key": key.strip(), "label": str(label or "")[:LABEL_MAX].strip(),
                                       "created": int(time.time())}))


def lookup(fp: str) -> Optional[str]:
    raw = _ks_get(_check_fp(fp))
    if not raw:
        return None
    try:
        return str(json.loads(raw)["key"])
    except Exception:  # noqa: BLE001 - a damaged entry is treated as absent
        return None


def list_keys() -> list:
    """Labels and fingerprints of the remembered keys - never a key."""
    out = []
    for fp in _ks_names():
        try:
            meta = json.loads(_ks_get(fp) or "{}")
        except Exception:  # noqa: BLE001
            meta = {}
        out.append({"fingerprint": fp, "label": str(meta.get("label") or ""), "created": int(meta.get("created") or 0)})
    return sorted(out, key=lambda r: -r["created"])


def forget(fp: str) -> bool:
    return _ks_delete(_check_fp(fp))


# ── lockout for password guesses (per file) ─────────────────────────────────────────────────────────────────────
def _locked_out(fp: str) -> float:
    with _lock:
        count, until = _fails.get(fp, (0, 0.0))
        if count < MAX_FAILED_ATTEMPTS:
            return 0.0
        left = until - time.monotonic()
        if left <= 0:
            _fails.pop(fp, None)
            return 0.0
        return left


def _note_failure(fp: str) -> None:
    with _lock:
        count, _ = _fails.get(fp, (0, 0.0))
        _fails[fp] = (count + 1, time.monotonic() + LOCKOUT_SECONDS)


def _clear(fp: str) -> None:
    with _lock:
        _fails.pop(fp, None)


# ── route bodies (plain functions: body dict in, dict out) ──────────────────────────────────────────────────────
def encrypt(body: dict) -> dict:
    scheme = str(body.get("scheme") or SCHEME_FERNET)
    if scheme not in SCHEMES:
        raise Malformed(f"Unknown encryption scheme {scheme[:30]!r}.")
    workflow = body.get("workflow")
    if scheme == SCHEME_PASSWORD:
        file = encrypt_password(workflow, str(body.get("password") or ""))
        return {"ok": True, "file": file, "fingerprint": file["fingerprint"], "remembered": False}
    same = body.get("same_key_of")
    if same:                                   # V5: save again with the key of the file this tab opened
        old = lookup(_check_fp(same))
        if not old:
            raise NeedsSecret("The key of the file you opened is not remembered on this installation, so it cannot be "
                              "reused. Save with a new key instead.", "key")
        _key, file = encrypt_fernet(workflow, old)
        remember(file["fingerprint"], old, str(body.get("label") or ""))
        return {"ok": True, "file": file, "fingerprint": file["fingerprint"], "remembered": True, "key_reused": True}
    key, file = encrypt_fernet(workflow)
    remembered = False
    if body.get("remember", True):
        remember(file["fingerprint"], key, str(body.get("label") or ""))
        remembered = True
    return {"ok": True, "file": file, "fingerprint": file["fingerprint"], "key": key, "remembered": remembered}


def decrypt(body: dict) -> dict:
    wrapper = parse_file(body.get("file"))
    fp = wrapper["fingerprint"]
    if wrapper["scheme"] == SCHEME_PASSWORD:
        wait = _locked_out(fp)
        if wait > 0:
            raise PermissionError(f"Too many wrong passwords. Try again in {int(wait // 60) + 1} minute(s).")
        try:
            workflow = decrypt_password(wrapper, str(body.get("password") or ""))
        except NeedsSecret:
            raise
        except VaultError as exc:
            if not isinstance(exc, Malformed):
                _note_failure(fp)
            raise
        _clear(fp)
        return {"ok": True, "workflow": workflow, "scheme": SCHEME_PASSWORD, "used_remembered": False,
                "fingerprint": fp}
    key = str(body.get("key") or "").strip()
    used_remembered = False
    if not key:
        key = lookup(fp) or ""
        used_remembered = bool(key)
    if not key:
        raise NeedsSecret("Enter the key of this workflow (it was shown once when the file was saved).", "key")
    workflow = decrypt_fernet(wrapper, key)
    remembered = False
    if body.get("remember") and not used_remembered:
        remember(fp, key, str(body.get("label") or ""))
        remembered = True
    return {"ok": True, "workflow": workflow, "scheme": SCHEME_FERNET, "used_remembered": used_remembered,
            "remembered": remembered, "fingerprint": fp}


def keys_list(_body: dict) -> dict:
    return {"ok": True, "keys": list_keys()}


def keys_forget(body: dict) -> dict:
    return {"ok": True, "forgotten": forget(str(body.get("fingerprint") or ""))}


def register_routes(server) -> None:
    import asyncio

    from aiohttp import web

    from .local_guard import refuse_remote

    routes = server.routes

    def wrap(fn, offload=False):
        async def handler(request):
            refused = refuse_remote(request, "Encrypted workflows")
            if refused is not None:
                return refused
            try:
                body = await request.json() if request.method == "POST" else {}
            except Exception:  # noqa: BLE001
                body = {}
            if not isinstance(body, dict):
                body = {}
            try:
                out = (await asyncio.get_running_loop().run_in_executor(None, fn, body)) if offload else fn(body)
                return web.json_response(out)
            except NeedsSecret as exc:
                return web.json_response({"ok": False, "error": str(exc), "needs": exc.needs}, status=401)
            except VaultError as exc:
                return web.json_response({"ok": False, "error": str(exc)}, status=getattr(exc, "status", None) or 403)
            except PermissionError as exc:
                return web.json_response({"ok": False, "error": str(exc)}, status=429)
        return handler

    routes.post("/h2vault/workflow/encrypt")(wrap(encrypt, offload=True))
    routes.post("/h2vault/workflow/decrypt")(wrap(decrypt, offload=True))
    routes.get("/h2vault/keys/list")(wrap(keys_list))
    routes.post("/h2vault/keys/forget")(wrap(keys_forget))
