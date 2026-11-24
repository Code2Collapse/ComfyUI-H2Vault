"""H2Vault (AGPL-3.0) - security diagnostics (L9.341, roadmap item 1 / Part 4 A).

The registry itself lives in nodes/concealment.py (CAPABILITIES: every protection install() puts in place, its
self-test result, critical or optional). This module only serves it to the ComfyUI page on THIS machine:

  GET  /h2vault/diagnostics            the report (re-checks cheaply first)                (this machine's page only)
  POST /h2vault/diagnostics/selftest   run the full self-test again (not while a vault runs) (this machine's page only)

Nothing here names anything from inside a vault: the report carries protection names, statuses, plain-English
details and versions only.
"""
from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import Optional

TESTED_COMFYUI = ("0.39",)               # core versions the self-test and the leak suites were run against
BUSY_TEXT = "A protected workflow is running. Run the check again when it has finished."


def _comfyui_version() -> Optional[str]:
    try:
        import comfyui_version
        return str(comfyui_version.__version__)
    except Exception:  # noqa: BLE001 - outside ComfyUI, or an old core without the file
        return None


def _h2vault_version() -> Optional[str]:
    try:
        import tomllib
        with open(Path(__file__).resolve().parents[1] / "pyproject.toml", "rb") as fh:
            return str(tomllib.load(fh)["project"]["version"])
    except Exception:  # noqa: BLE001
        return None


def versions() -> dict:
    core = _comfyui_version()
    tested = bool(core) and any(core == t or core.startswith(t + ".") for t in TESTED_COMFYUI)
    return {"comfyui": core, "h2vault": _h2vault_version(), "python": platform.python_version(),
            "platform": sys.platform, "tested_comfyui": list(TESTED_COMFYUI), "comfyui_tested": tested}


def summary(rep: dict) -> dict:
    """One line for the panel's head: protected / refusing / not started."""
    if not rep.get("attempted"):
        return {"state": "not_started", "message": "H2Vault's protections were not started (no ComfyUI server)."}
    if rep.get("refusal"):
        return {"state": "refusing", "message": "Concealed vaults are refused on this ComfyUI until the problems "
                                                "below are fixed. Nothing of them is shown or run."}
    optional = [c for c in rep.get("capabilities", []) if not c["critical"] and not c["ok"]]
    note = f" {len(optional)} optional feature(s) are unavailable." if optional else ""
    return {"state": "protected", "message": "Every critical protection is active and passed its self-test." + note}


def report(*, recheck: bool = True) -> dict:
    from . import concealment as C
    if recheck:
        try:
            C.check_liveness()
        except Exception:  # noqa: BLE001 - the report still shows the last known state
            pass
    rep = C.CAPABILITIES.report()
    return {"ok": True, **rep, "summary": summary(rep), "versions": versions()}


def selftest() -> tuple[dict, int]:
    from . import concealment as C
    # the probes never touch a running prompt's state (they use their own concealer); waiting for the queue to be
    # idle only keeps the check from running through other extensions' hooks in the middle of a render
    q = getattr(C._INSTALL.get("server"), "prompt_queue", None)
    if list(C._concealer()._active) or getattr(q, "currently_running", None):
        return {"ok": False, "error": BUSY_TEXT}, 409
    C.run_selftest()
    return report(recheck=False), 200


def register_routes(server) -> None:
    from aiohttp import web

    from .local_guard import refuse_remote

    async def get_report(request):
        refused = refuse_remote(request, "The security check")
        if refused is not None:
            return refused
        return web.json_response(report())

    async def post_selftest(request):
        refused = refuse_remote(request, "The security check")
        if refused is not None:
            return refused
        import asyncio
        body, status = await asyncio.get_running_loop().run_in_executor(None, selftest)
        return web.json_response(body, status=status)

    server.routes.get("/h2vault/diagnostics")(get_report)
    server.routes.post("/h2vault/diagnostics/selftest")(post_selftest)
