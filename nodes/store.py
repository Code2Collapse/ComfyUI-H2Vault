# Derived from Code2Collapse ComfyUI-CustomNodePacks nodes/vault_store.py (Apache-2.0, Copyright Code2Collapse);
# modified for H2Vault (AGPL-3.0). See NOTICE.
"""Where the vault keeps its local secrets: the install key pair and the second-factor state (A17, D0.25).

Everything goes through H2Vault's secrets store (`secrets_store`, scope "vault"): the OS credential store via `keyring`
when available, else an encrypted file in the ComfyUI user directory - never a workflow, never plaintext.
Tests replace BACKEND with a dict.
"""

from __future__ import annotations

from typing import Optional

SCOPE = "vault"
BACKEND = None          # tests: a dict {name: value}


def get(name: str) -> Optional[str]:
    if BACKEND is not None:
        return BACKEND.get(name)
    from . import secrets_store

    return secrets_store.get(SCOPE, name)


def put(name: str, value: str) -> None:
    if BACKEND is not None:
        BACKEND[name] = value
        return
    from . import secrets_store

    secrets_store.set_(SCOPE, name, value)


def delete(name: str) -> None:
    if BACKEND is not None:
        BACKEND.pop(name, None)
        return
    from . import secrets_store

    secrets_store.delete(SCOPE, name)


def backend_name() -> str:
    if BACKEND is not None:
        return "test"
    from . import secrets_store

    return secrets_store.backend_name()
