# Derived from Code2Collapse ComfyUI-CustomNodePacks nodes/vault_keys.py (Apache-2.0, Copyright Code2Collapse);
# modified for H2Vault (AGPL-3.0). See NOTICE.
"""This install's vault key pair (X25519): who may run a Sealed vault without its password (A17, D0.25).

The private key is created once and kept in the local secrets store (vault_store: OS credential store or the pack's
encrypted file) - never in a workflow. The public key is a short text (`h2vk1:<base64>`) a person can send to a
vault author so the author seals vaults for this install. A public key is not a secret.
"""

from __future__ import annotations

import base64
import threading

from . import store as vault_store
from .crypto import VaultError

PREFIX = "h2vk1:"
_NAME = "install_x25519_private"
_lock = threading.Lock()


def _raw_public(private_raw: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    return X25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def install_private_key(create: bool = True) -> bytes | None:
    """The raw 32-byte private key of this install (created on first use)."""
    with _lock:
        stored = vault_store.get(_NAME)
        if stored:
            return base64.b64decode(stored)
        if not create:
            return None
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        raw = X25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                        serialization.NoEncryption())
        vault_store.put(_NAME, base64.b64encode(raw).decode("ascii"))
        return raw


def install_public_key() -> bytes:
    return _raw_public(install_private_key())


def public_text(public_raw: bytes) -> str:
    return PREFIX + base64.b64encode(public_raw).decode("ascii")


def parse_public_text(text: str) -> bytes:
    text = (text or "").strip()
    if not text.startswith(PREFIX):
        raise VaultError(f"Not an H2Vault installation code (it starts with {PREFIX!r}).")
    try:
        raw = base64.b64decode(text[len(PREFIX):], validate=True)
    except Exception as exc:
        raise VaultError("The install key is not valid base64.") from exc
    if len(raw) != 32:
        raise VaultError("The install key has the wrong length.")
    return raw
