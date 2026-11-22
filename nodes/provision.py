"""H2Vault (AGPL-3.0) - V7 concealed provisioning: a vault's missing model files download themselves without revealing
what they are (owner 2026-11-23; design docs/h2vault/V7_concealed_provisioning.md in the workspace).

The vault payload (inside the encryption) may carry a model manifest: [{folder, file, url, sha256, size}]. On the
recipient's machine a missing file is fetched over public HTTPS into ``models/<folder>/h2v/<sha256[:20]>.<ext>`` -
a hash name, so the file name on disk tells nothing - resumed from a ``.part`` file, capped at the declared size and
verified against the SHA-256 before it is renamed into place. When the vault runs, an inner loader input that names
a manifest file absent under its own name is rewritten to that hash name (server side, never shown). Everything the
browser learns is a count, a byte total or a percentage.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import os
import re
import socket
import threading
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional

HASH_DIR = "h2v"
CHUNK = 1 << 20
_FOLDER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class ProvisionError(Exception):
    """A refusal in plain words (never a file name or URL from inside a vault)."""


# ── manifest ───────────────────────────────────────────────────────────────────────────────────────────────

def validate_manifest(entries) -> list:
    out = []
    for e in entries or []:
        if not isinstance(e, dict):
            raise ProvisionError("A model download entry is malformed.")
        folder, file = str(e.get("folder") or ""), str(e.get("file") or "")
        if not _FOLDER_RE.match(folder) or ".." in folder:
            raise ProvisionError("A model download entry names an invalid model folder.")
        parts = file.replace("\\", "/").split("/")
        if not file or any(p in ("", ".", "..") for p in parts) or file.startswith("/"):
            raise ProvisionError("A model download entry names an invalid file.")
        sha = str(e.get("sha256") or "").lower()
        if not _SHA_RE.match(sha):
            raise ProvisionError("A model download entry has no valid SHA-256.")
        try:
            size = int(e.get("size"))
        except (TypeError, ValueError):
            raise ProvisionError("A model download entry has no valid size.") from None
        if size <= 0:
            raise ProvisionError("A model download entry has no valid size.")
        url = str(e.get("url") or "")
        out.append({"folder": folder, "file": file, "url": url, "sha256": sha, "size": size})
    return out


def _manifest(plain) -> list:
    try:
        return validate_manifest((plain or {}).get("models") or [])
    except ProvisionError:
        return []


# ── paths ──────────────────────────────────────────────────────────────────────────────────────────────────

def _folder_root(folder: str) -> Path:
    import folder_paths
    roots = folder_paths.get_folder_paths(folder)
    if not roots:
        raise ProvisionError("This ComfyUI has no folder for one of the vault's models.")
    return Path(roots[0])


def hashed_name(e: dict) -> str:
    ext = Path(e["file"]).suffix.lower()
    ext = ext if re.fullmatch(r"\.[a-z0-9]{1,12}", ext or "") else ".bin"
    return f"{e['sha256'][:20]}{ext}"


def hashed_path(e: dict) -> Path:
    return _folder_root(e["folder"]) / HASH_DIR / hashed_name(e)


def _present_own_name(e: dict) -> bool:
    import folder_paths
    try:
        return folder_paths.get_full_path(e["folder"], e["file"]) is not None
    except Exception:  # noqa: BLE001
        return False


def is_missing(e: dict) -> bool:
    if _present_own_name(e):
        return False
    try:
        return not hashed_path(e).is_file()
    except ProvisionError:
        return True


# ── plan (counts only) ─────────────────────────────────────────────────────────────────────────────────────

def plan(plain) -> dict:
    missing = [e for e in _manifest(plain) if is_missing(e)]
    return {"models_missing": len(missing), "bytes": sum(e["size"] for e in missing),
            "downloadable": all(bool(e["url"]) for e in missing)}


# ── URL safety ─────────────────────────────────────────────────────────────────────────────────────────────

def _resolve(host: str) -> list:
    return [ai[4][0] for ai in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)]


def check_url(url: str) -> None:
    """Public HTTPS only: no plain http, no file / ftp, no loopback / private / link-local / reserved targets."""
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        raise ProvisionError("A model download source is not a valid address.") from None
    if u.scheme != "https" or not u.hostname:
        raise ProvisionError("Model downloads are allowed over HTTPS only.")
    try:
        addrs = _resolve(u.hostname)
    except OSError:
        raise ProvisionError("A model download source could not be reached.") from None
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast \
                or ip.is_unspecified:
            raise ProvisionError("A model download source points at a private or local address; refused.")


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_opener(url: str, start: int = 0):
    check_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": "H2Vault", **({"Range": f"bytes={start}-"} if start else {})})
    return urllib.request.build_opener(_HttpsOnlyRedirect).open(req, timeout=60)


# ── fetch ──────────────────────────────────────────────────────────────────────────────────────────────────

def fetch(e: dict, *, opener: Optional[Callable] = None, progress: Optional[Callable[[int], None]] = None,
          cancelled: Optional[Callable[[], bool]] = None) -> Path:
    """Download one manifest entry to its hash name; resume, cap, verify. Returns the final path."""
    e = validate_manifest([e])[0]
    if not e["url"]:
        raise ProvisionError("One of this vault's models has no download source; ask its author.")
    target = hashed_path(e)
    if target.is_file():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    part = target.parent / (target.name + ".part")
    start = part.stat().st_size if part.is_file() else 0
    if start > e["size"]:
        part.unlink()
        start = 0
    op = opener or _default_opener
    try:
        resp_cm = op(e["url"], start)
    except ProvisionError:
        raise
    except OSError:                       # URLError, timeouts, refused proxies: the source was not reachable
        raise ProvisionError("The download source could not be reached (network, proxy or firewall). "
                             "Try again later.") from None
    with resp_cm as resp:
        status = getattr(resp, "status", 200)
        mode = "ab" if (start and status == 206) else "wb"
        written = start if mode == "ab" else 0
        with open(part, mode) as fh:
            while True:
                if cancelled is not None and cancelled():
                    raise ProvisionError("The download was cancelled.")
                chunk = resp.read(CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > e["size"]:
                    fh.close()
                    part.unlink(missing_ok=True)
                    raise ProvisionError("A model download was larger than the vault declared; refused.")
                fh.write(chunk)
                if progress is not None:
                    progress(len(chunk))
    h = hashlib.sha256()
    with open(part, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    if h.hexdigest() != e["sha256"]:
        part.unlink(missing_ok=True)
        raise ProvisionError("A downloaded model did not match the vault's checksum; it was removed.")
    os.replace(part, target)
    return target


# ── expansion remap ────────────────────────────────────────────────────────────────────────────────────────

def remap(graph: dict, plain) -> dict:
    """Point inner inputs at hash-named copies for manifest files that are absent under their own name."""
    table = {}
    for e in _manifest(plain):
        if not _present_own_name(e):
            try:
                if hashed_path(e).is_file():
                    table[e["file"]] = f"{HASH_DIR}/{hashed_name(e)}"
            except ProvisionError:
                continue
    if not table:
        return graph
    g = copy.deepcopy(graph)
    for node in g.values():
        inputs = node.get("inputs") if isinstance(node, dict) else None
        if isinstance(inputs, dict):
            for k, v in list(inputs.items()):
                if isinstance(v, str) and v in table:
                    inputs[k] = table[v]
    return g


# ── background jobs (percentages only) ────────────────────────────────────────────────────────────────────

_JOBS: dict = {}
_LOCK = threading.Lock()


def start(plain, token: str, *, opener: Optional[Callable] = None) -> dict:
    missing = [e for e in _manifest(plain) if is_missing(e)]
    job = {"state": "running", "files_total": len(missing), "files_done": 0,
           "total_bytes": sum(e["size"] for e in missing), "done_bytes": 0, "error": None, "cancel": False}
    with _LOCK:
        _JOBS[token] = job

    def add(n):
        job["done_bytes"] += n

    def run():
        try:
            for e in missing:
                fetch(e, opener=opener, progress=add, cancelled=lambda: job["cancel"])
                job["files_done"] += 1
            job["state"] = "done"
        except ProvisionError as exc:
            job["state"], job["error"] = "failed", str(exc)
        except Exception:  # noqa: BLE001 - never a URL or name in the message
            job["state"], job["error"] = "failed", "A model download failed; try again."

    threading.Thread(target=run, name="h2vault-provision", daemon=True).start()
    return status(token)


def status(token: str) -> dict:
    with _LOCK:
        job = _JOBS.get(token)
    if job is None:
        return {"state": "unknown"}
    return {k: job[k] for k in ("state", "files_total", "files_done", "total_bytes", "done_bytes", "error")}


def cancel(token: str) -> None:
    with _LOCK:
        job = _JOBS.get(token)
    if job is not None:
        job["cancel"] = True
