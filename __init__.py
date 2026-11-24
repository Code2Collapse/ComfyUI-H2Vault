"""ComfyUI-H2Vault - protected subgraphs and encrypted workflow files for ComfyUI (AGPL-3.0, docs/ARCHITECTURE.md).

Every module is imported behind its own guard: one failing module (a missing dependency, a broken file) is reported
in words and never takes the rest of the pack - or the vault nodes saved in a workflow - down with it.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("h2vault")

WEB_DIRECTORY = "./web/js"
NODE_CLASS_MAPPINGS: dict = {}
NODE_DISPLAY_NAME_MAPPINGS: dict = {}
LOAD_ERRORS: dict[str, str] = {}

_MIN_CRYPTOGRAPHY = (44, 0)          # Argon2id arrived in cryptography 44


def _fail(what: str, exc: BaseException, hint: str = "") -> None:
    LOAD_ERRORS[what] = f"{type(exc).__name__}: {exc}"
    log.warning("[H2Vault] %s is unavailable: %s%s", what, LOAD_ERRORS[what], f" - {hint}" if hint else "")


def _check_cryptography() -> None:
    try:
        import cryptography
        ver = tuple(int(x) for x in cryptography.__version__.split(".")[:2])
    except Exception as exc:  # noqa: BLE001
        _fail("cryptography", exc, "install it: <ComfyUI python> -m pip install \"cryptography>=44\"")
        return
    if ver < _MIN_CRYPTOGRAPHY:
        _fail("cryptography", RuntimeError(f"version {cryptography.__version__} is older than 44 (no Argon2id)"),
              "upgrade it: <ComfyUI python> -m pip install -U \"cryptography>=44\"")


_check_cryptography()

# The vault nodes register even when cryptography is missing, so a saved workflow still LOADS and the node itself says
# what to install when it runs, instead of vanishing from the graph.
_ps = None
try:
    from .nodes import protected_subgraph as _ps
    NODE_CLASS_MAPPINGS.update(_ps.NODE_CLASS_MAPPINGS)
    NODE_DISPLAY_NAME_MAPPINGS.update(_ps.NODE_DISPLAY_NAME_MAPPINGS)
except Exception as _exc:  # noqa: BLE001
    _fail("protected subgraph nodes", _exc)


def _register_server_side() -> None:
    try:
        from server import PromptServer
        server = PromptServer.instance
    except Exception:  # noqa: BLE001 - imported outside a running ComfyUI (tests, introspection)
        return
    if _ps is None and os.environ.get("H2VAULT_HOSTED", "").strip().lower() in ("1", "true", "yes", "on"):
        # L9.341: Hosted mode never starts without its restrictions (they are installed with the vault nodes)
        raise SystemExit("[H2Vault] Hosted mode refused to start: the vault nodes did not load "
                         f"({LOAD_ERRORS.get('protected subgraph nodes', 'unknown error')}). Fix it, or turn hosted "
                         "mode off (H2VAULT_HOSTED).")
    if _ps is not None:
        try:
            _ps.install_message_filter(server)
        except Exception as exc:  # noqa: BLE001
            _fail("vault message filter", exc)
        try:                       # V3: AFTER the vault filter - concealment must be the outermost wrapper
            from .nodes import concealment as _conceal
            if not _conceal.install(server):     # L9.341: a critical protection failed its self-test
                gone = set(_conceal.CAPABILITIES.missing())
                missing = [label for cid, label, *_ in _conceal.CAPABILITY_SPEC if cid in gone]
                _fail("vault concealment", RuntimeError(
                    "protections not working: " + (", ".join(missing) or "not installed")),
                    "concealed vaults refuse to run; H2Vault menu > Security check shows why")
        except Exception as exc:  # noqa: BLE001 - HostedStartRefused is a SystemExit: it stops ComfyUI on purpose
            _fail("vault concealment", exc)
        try:
            from .nodes import diagnostics as _diag
            _diag.register_routes(server)
        except Exception as exc:  # noqa: BLE001
            _fail("security diagnostics", exc)
        try:
            from .nodes import routes as _routes
            _routes.register_routes(server)
        except Exception as exc:  # noqa: BLE001
            _fail("vault routes", exc)
    try:
        from .nodes import workflow_encrypt as _wfe
        _wfe.register_routes(server)
    except Exception as exc:  # noqa: BLE001
        _fail("encrypted workflow routes", exc)


_register_server_side()
if LOAD_ERRORS:
    log.warning("[H2Vault] loaded with problems: %s", "; ".join(LOAD_ERRORS))
else:
    log.info("[H2Vault] loaded: %d nodes", len(NODE_CLASS_MAPPINGS))

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS", "WEB_DIRECTORY"]
