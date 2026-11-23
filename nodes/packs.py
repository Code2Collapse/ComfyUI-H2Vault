# Derived from Code2Collapse ComfyUI-CustomNodePacks nodes/vault_packs.py (Apache-2.0, Copyright Code2Collapse);
# modified for H2Vault (AGPL-3.0). See NOTICE.
"""Which custom-node packs a vault's inside uses, and the consent install of the missing ones (L9.50, A18 P5.6).
Design: docs/VAULT_DESIGN_A18.md, "Missing custom nodes: consent install".

At lock time the vault records, INSIDE its encryption, each pack its inner nodes come from: the git `origin` URL and
the commit that was checked out. On a machine missing some inner classes, the user is told only how many packs are
needed and from which hosts (owner: never the names), and one click installs exactly those commits.

Guardrails: https on a known git host only, a full 40-hex commit, a fresh folder (an existing one is never touched),
at most MAX_PACKS. Their Python requirements are never pip-installed here: ComfyUI-Manager finishes them. Installing
custom nodes runs their code at the next start - the user consents to that; the guardrails limit WHERE the code comes
from, not what it does.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

KILL_SWITCH = "H2VAULT_INSTALL"
ALLOWED_HOSTS = ("github.com", "gitlab.com", "codeberg.org", "bitbucket.org")
MAX_PACKS = 16
GIT_TIMEOUT = 600
_TEST_ALLOW_FILE = "H2VAULT_INSTALL_ALLOW_FILE_URLS"   # tests only: local file:// fixture repos
_SHA = re.compile(r"^[0-9a-f]{40}$")
_NAME = re.compile(r"^(?!\.)[A-Za-z0-9._-]{1,100}$")    # never ".", "..", or a hidden folder


def disabled() -> bool:
    return os.environ.get(KILL_SWITCH, "").strip().lower() in ("0", "off", "false", "no")


# ── reading a pack's git state (no subprocess) ──────────────────────────────────────────────────────────────

def _git_dir(folder: Path) -> Optional[Path]:
    g = folder / ".git"
    if g.is_dir():
        return g
    if g.is_file():                                          # a worktree / submodule: "gitdir: <path>"
        t = g.read_text(encoding="utf-8", errors="replace").strip()
        if t.startswith("gitdir:"):
            p = Path(t[7:].strip())
            p = p if p.is_absolute() else (folder / p)
            return p if p.is_dir() else None
    return None


def _common_dir(gitdir: Path) -> Path:
    c = gitdir / "commondir"
    if c.is_file():
        p = Path(c.read_text(encoding="utf-8").strip())
        return p if p.is_absolute() else (gitdir / p).resolve()
    return gitdir


def origin_url(gitdir: Path) -> Optional[str]:
    cfg = _common_dir(gitdir) / "config"
    if not cfg.is_file():
        return None
    section = None
    for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s.startswith("["):
            section = s
        elif section and re.fullmatch(r'\[remote\s+"origin"\]', section) and s.split("=", 1)[0].strip() == "url":
            return s.split("=", 1)[1].strip()
    return None


def head_commit(gitdir: Path) -> Optional[str]:
    head = gitdir / "HEAD"
    if not head.is_file():
        return None
    t = head.read_text(encoding="utf-8").strip()
    if _SHA.match(t):
        return t                                             # detached
    if not t.startswith("ref:"):
        return None
    ref = t[4:].strip()
    common = _common_dir(gitdir)
    for base in (gitdir, common):
        f = base / ref
        if f.is_file():
            sha = f.read_text(encoding="utf-8").strip()
            return sha if _SHA.match(sha) else None
    packed = common / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split(" ")
            if len(parts) == 2 and parts[1] == ref and _SHA.match(parts[0]):
                return parts[0]
    return None


# ── recording at lock time ──────────────────────────────────────────────────────────────────────────────────

def _module_dir(class_type: str) -> Optional[Path]:
    """The custom-node folder a class was loaded from; None for core classes or an unknown class."""
    import nodes                                             # ComfyUI core
    cls = nodes.NODE_CLASS_MAPPINGS.get(class_type)
    mod = str(getattr(cls, "RELATIVE_PYTHON_MODULE", "") or "")
    if not mod.startswith("custom_nodes."):
        return None
    d = getattr(nodes, "LOADED_MODULE_DIRS", {}).get(mod.split(".", 1)[1])
    return Path(d) if d else None


def record(api: dict) -> list[dict]:
    """[{url, commit, classes}] for the packs the inner nodes use (core classes record nothing). A pack that is not
    a git clone with an origin is recorded without a URL, so a recipient is told to ask the author."""
    by_dir: dict[str, dict] = {}
    for node in (api.get("nodes") or {}).values():
        ct = str(node.get("class_type") or "")
        try:
            d = _module_dir(ct)
        except Exception:  # noqa: BLE001 - a class core does not know: nothing to record
            d = None
        if d is None:
            continue
        e = by_dir.get(str(d))
        if e is None:
            g = _git_dir(d)
            e = by_dir[str(d)] = {"url": origin_url(g) if g else None, "commit": head_commit(g) if g else None,
                                  "classes": []}
        if ct not in e["classes"]:
            e["classes"].append(ct)
    return sorted(by_dir.values(), key=lambda e: e["url"] or "")


def merge(new: list, old: list, api: dict) -> list:
    """Re-lock after an edit: this machine's record, plus the earlier record for classes still inside that this
    machine could not attribute (an editor without git info for a pack keeps the author's entry)."""
    inside = {str(n.get("class_type")) for n in (api.get("nodes") or {}).values()}
    covered = {c for p in new for c in p.get("classes") or []}
    out = list(new)
    for p in old or []:
        keep = [c for c in p.get("classes") or [] if c in inside and c not in covered]
        if keep:
            out.append(dict(p, classes=keep))
            covered.update(keep)
    return out


def record_safely(api: dict, old: Optional[list] = None) -> list:
    """record() + merge(), never raising (a vault locks even when the packs cannot be read)."""
    try:
        new = record(api)
    except Exception:  # noqa: BLE001
        new = []
    return merge(new, old or [], api) if old else new


# ── what a recipient lacks ──────────────────────────────────────────────────────────────────────────────────

def needed(missing: list, packs: list) -> tuple[list, int]:
    """(packs that provide missing classes, how many missing classes no recorded pack provides)."""
    want, covered = [], set()
    for p in packs or []:
        hit = [c for c in p.get("classes") or [] if c in missing]
        if hit:
            want.append(p)
            covered.update(hit)
    return want, len([c for c in missing if c not in covered])


def summary(want: list, unknown: int) -> dict:
    """What the user may be told: counts and hosts, never names (owner)."""
    def host(url):
        u = urlparse(url or "")
        return u.hostname or ("a local folder" if u.scheme == "file" else "an unknown place")
    hosts = sorted({host(p.get("url")) for p in want})
    return {"packs": len(want), "hosts": hosts, "unknown_classes": unknown,
            "installable": sum(1 for p in want if check(p) is None)}


def folder_name(url: str) -> str:
    name = (urlparse(url).path.rstrip("/").rsplit("/", 1)[-1] or "")
    return name[:-4] if name.endswith(".git") else name


def check(p: dict) -> Optional[str]:
    """None when the pack may be installed, else why not (in words)."""
    url, commit = str(p.get("url") or ""), str(p.get("commit") or "")
    if not url:
        return "the vault does not say where one of its packs comes from - ask the vault's author"
    u = urlparse(url)
    if u.scheme == "file" and os.environ.get(_TEST_ALLOW_FILE) == "1":
        pass
    elif u.scheme != "https" or (u.hostname or "").lower() not in ALLOWED_HOSTS:
        # V8: only the host (already shown by design), never a piece of the URL - its path names the pack
        return (f"a pack is not on a known git host over https ({u.hostname or 'unrecognised address'}) - ask the "
                "vault's author")
    if not _SHA.match(commit):
        return "a pack has no pinned commit - ask the vault's author"
    if not _NAME.match(folder_name(url)):
        return "a pack's folder name is not safe"
    return None


CLONE_REASONS = ("the repository or commit was not found", "the git host could not be reached",
                 "the git host asked for credentials", "git failed")


def clone_failure_reason(git_output: str) -> str:
    """git's own error text names the repository URL (= the pack); the answer is one of CLONE_REASONS only (V8)."""
    t = (git_output or "").lower()
    if "not found" in t or "did not match any" in t or "unknown revision" in t or "reference is not a tree" in t:
        return CLONE_REASONS[0]
    if "could not resolve host" in t or "unable to access" in t or "timed out" in t or "connection" in t:
        return CLONE_REASONS[1]
    if "authentication" in t or "terminal prompts disabled" in t or "username" in t:
        return CLONE_REASONS[2]
    return CLONE_REASONS[3]


# ── installing ──────────────────────────────────────────────────────────────────────────────────────────────

def _git(args: list, cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")          # never hang on a credentials prompt
    return subprocess.run(["git", *args], cwd=str(cwd) if cwd else None, env=env, capture_output=True, text=True,
                          timeout=GIT_TIMEOUT)


def _remove_new_folder(dest: Path) -> None:
    """Remove a folder THIS call created. Git marks object files read-only, which a plain rmtree cannot delete on
    Windows: clear the flag and retry."""
    import stat

    def again(func, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    if dest.exists():
        shutil.rmtree(dest, onexc=again) if sys.version_info >= (3, 12) else shutil.rmtree(dest, onerror=again)


def _requirements(folder: Path) -> list[str]:
    f = folder / "requirements.txt"
    if not f.is_file():
        return []
    out = []
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.split("#", 1)[0].strip()
        if s and not s.startswith(("-", "git+", "http:", "https:", "file:")) and "@" not in s:
            out.append(s)
    return out


def install(want: list, custom_nodes_dir: Path) -> dict[str, Any]:
    """Clone each pack at its pinned commit into a NEW folder; its requirements are left to ComfyUI-Manager.
    -> {installed, skipped (already there), failed: [reason], requirements: {...}, restart: bool}. Never names a pack
    in the answer (owner)."""
    if disabled():
        return {"installed": 0, "failed": [f"installing is switched off ({KILL_SWITCH}=off)"], "restart": False}
    if len(want) > MAX_PACKS:
        return {"installed": 0, "failed": [f"more than {MAX_PACKS} packs - install them manually"], "restart": False}
    installed, skipped, failed, reqs = 0, 0, [], []
    for p in want:
        why = check(p)
        if why:
            failed.append(why)
            continue
        dest = custom_nodes_dir / folder_name(p["url"])
        if dest.resolve().parent != custom_nodes_dir.resolve():  # belt and braces next to the name check
            failed.append("a pack's folder would land outside custom_nodes")
            continue
        if dest.exists():
            skipped += 1                                     # never touch an existing folder
            continue
        try:
            r = _git(["clone", "--quiet", p["url"], str(dest)])
            if r.returncode == 0:
                r = _git(["checkout", "--quiet", "--detach", p["commit"]], cwd=dest)
            if r.returncode != 0:
                raise RuntimeError(clone_failure_reason(r.stderr or r.stdout or ""))
        except Exception as exc:  # noqa: BLE001 - only the folder this call created is removed
            try:
                _remove_new_folder(dest)
            except OSError as rm_exc:
                # V8: strerror only - str(OSError) carries the folder path, i.e. the pack's name
                failed.append("a half-cloned folder could not be removed "
                              f"({rm_exc.strerror or 'operating system error'})")
            why = str(exc) if isinstance(exc, RuntimeError) and str(exc) in CLONE_REASONS else type(exc).__name__
            failed.append(f"a pack could not be cloned ({why})")
            continue
        installed += 1
        reqs += _requirements(dest)
    # H2Vault never pip-installs (it could replace torch / numpy under ComfyUI): the user finishes requirements in
    # ComfyUI-Manager, which knows the environment
    req_result: dict[str, Any] = {"count": len(reqs)}
    if reqs:
        req_result["note"] = ("install the new packs' Python requirements with ComfyUI-Manager (Install missing / Fix) "
                              "before restarting")
    return {"installed": installed, "skipped": skipped, "failed": failed, "requirements": req_result,
            "restart": installed > 0}
