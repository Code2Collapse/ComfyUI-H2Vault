# H2Vault (AGPL-3.0). New for H2Vault (owner 2026-11-23: "if i lock preview nodes ... preview should come").
"""Previews from inside a vault, shown on the vault node.

What a vault's inner nodes show (owner 2026-11-23): every preview an inner node produces reaches the VAULT node -
images of PreviewImage / SaveImage, VHS videos, text, audio - under a public label: the author's own label or
"Preview 1", "Preview 2", ... in the inner graph's order. Never an inner node id, type or title.

Seams (everything else here is implementation):

    choice(raw, api)                    the author's setting, validated -> plaintext["previews"] (inside the encryption)
    HUB.register(vault, plain, prefix)  a vault expanded: start collecting its previews for this run
    HUB.collect(vault, inner, output)   an inner node's `executed` output -> the merged output for the vault, or DROP
    HUB.show(vault)                     the author's choice for this vault (default: shown)
    HUB.replay(vault)                   a vault served from core's cache -> the previews its cached run produced
    collapse_progress(nodes, vault_of)  core's progress_state -> one entry per vault, carrying the running step
    install_replay()                    wrap core's execution.execute once (records the vault's cache key)

The merged output keeps core's `images` key for still / animated images (core's own image preview draws them on the
vault in both renderers) and lists EVERY item, labelled, under `h2v_previews` (the vault's preview widget,
web/js/h2vault_previews.js, plays videos and audio and shows text; core has no generic renderer for those).
`h2v_previews` entries never carry a top-level `filename`, so the frontend's result-item parsers skip them.

File names: an inner Save node writes its files into the user's own output folder, under the prefix / folder the
author set. Those names are what the frontend needs to load the file (/view?filename=...&subfolder=...), and the
person who runs the vault sees them on disk anyway, so they stay; the lock dialog says so. VHS's `fullpath` (the
server's absolute path) and `workflow` (a side file) are not passed to the vault.
"""
from __future__ import annotations

import logging
import math
import threading
from collections import OrderedDict
from typing import Any, Callable, Optional

log = logging.getLogger("h2vault.previews")

VAULT_CLASSES = ("H2Vault_ProtectedSubgraph", "H2Vault_ProtectedSubgraphOutput")
MAX_LABEL = 40
MAX_LABELS = 64
MAX_ITEMS = 256
MAX_TEXT = 4000
MAX_VAULTS = 64
MAX_REPLAYS = 64

IMAGE_EXT = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".avif")
VIDEO_EXT = (".mp4", ".webm", ".mov", ".mkv", ".avi", ".m4v")
AUDIO_EXT = (".mp3", ".wav", ".flac", ".ogg", ".opus", ".m4a", ".aac")
FILE_FIELDS = ("filename", "subfolder", "type", "format", "frame_rate")
# core's own progress / sampler-preview events: never touched by the custom-event rules below
CORE_EVENTS = frozenset({"status", "progress", "progress_state", "executing", "executed", "execution_start",
                         "execution_cached", "execution_success", "execution_error", "execution_interrupted", "logs",
                         "crystools.monitor"})
# custom live-preview events that name the node they draw on (its DISPLAY id = the vault for an inner node)
ID_FIELDS = ("node_id", "id", "node", "display_node", "display_node_id")
# KJNodes ModelPreviewOverrideKJ: the sampler's sigma schedule and its latent delta describe the inner settings
KJ_EVENT = "kj_preview_override"
KJ_PRIVATE = ("sigma", "sigmas", "db_curve", "delta")


class _Drop:
    def __repr__(self):
        return "DROP"


try:                                       # one sentinel for every H2Vault filter (concealment defines it first)
    from .concealment import DROP
except Exception:  # noqa: BLE001 - loaded on its own (tests)
    DROP = _Drop()


# ── the author's setting (inside the encrypted plaintext) ──────────────────────────────────────────────────────

def _clean_label(s) -> str:
    s = "".join(ch for ch in str(s) if ch.isprintable()).strip()
    return s[:MAX_LABEL]


def choice(raw, api: Optional[dict] = None) -> Optional[dict]:
    """The lock dialog's answer -> {"show": bool, "labels": {inner id: label}}, or None (not given: default shown).
    Labels for nodes that are not inside are dropped; labels are public (they show on the vault)."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("The preview setting is malformed.")
    inner = set(((api or {}).get("nodes") or {}).keys()) if api is not None else None
    labels = {}
    for k, v in (raw.get("labels") or {}).items() if isinstance(raw.get("labels"), dict) else []:
        k, lab = str(k), _clean_label(v)
        if lab and (inner is None or k in inner):
            labels[k] = lab
        if len(labels) >= MAX_LABELS:
            break
    return {"show": raw.get("show", True) is not False, "labels": labels}


def setting_of(plain) -> dict:
    p = plain.get("previews") if isinstance(plain, dict) else None
    return choice(p) if isinstance(p, dict) else {"show": True, "labels": {}}


def _id_key(i: str):
    return tuple(int(x) if x.isdigit() else x for x in str(i).replace(":", " ").split())


def order_of(api: dict) -> list:
    """Inner ids of core output nodes (previews, saves) in a stable order: top-level ids first, numerically, then the
    ones inside nested subgraphs ("12:4"). "Preview N" is the N-th of this list - the lock dialog numbers the same."""
    try:
        import nodes as core_nodes
        reg = core_nodes.NODE_CLASS_MAPPINGS
    except Exception:  # noqa: BLE001
        reg = {}
    ids = []
    for nid, n in ((api or {}).get("nodes") or {}).items():
        cls = reg.get(str((n or {}).get("class_type")))
        try:
            out = bool(getattr(cls, "OUTPUT_NODE", False)) if cls is not None else False
        except Exception:  # noqa: BLE001
            out = False
        if out:
            ids.append(str(nid))
    return sorted(ids, key=lambda i: (":" in i, _id_key(i)))


# ── merging inner outputs into the vault's output ──────────────────────────────────────────────────────────────

def _ext(name: str) -> str:
    name = str(name).lower()
    return name[name.rfind("."):] if "." in name else ""


def _kind(key: str, entry: dict) -> str:
    ext = _ext(entry.get("filename", ""))
    fmt = str(entry.get("format") or "").lower()
    if ext in VIDEO_EXT or fmt.startswith("video/"):
        return "video"
    if ext in AUDIO_EXT or key == "audio" or fmt.startswith("audio/"):
        return "audio"
    if ext in IMAGE_EXT:
        return "image"
    return "file"


FILE_TYPES = frozenset({"output", "temp", "input"})


def safe_file(entry) -> bool:
    """L9.342 (owner PART 3 F): a file reference the vault may show - a bare file name, a relative sub folder without
    "..", one of core's media folder types. Core's /view checks again; this keeps anything else off the vault (and off
    the browser's URL bar) entirely."""
    if not isinstance(entry, dict):
        return False
    name, sub, typ = entry.get("filename"), entry.get("subfolder", ""), entry.get("type")
    if not isinstance(name, str) or not name or len(name) > 255 or name in (".", ".."):
        return False
    if any(c in name for c in "/\\:\x00"):
        return False
    if sub is None:
        sub = ""
    if not isinstance(sub, str) or len(sub) > 512 or any(c in sub for c in ":\x00") or sub[:1] in ("/", "\\"):
        return False
    if ".." in sub.replace("\\", "/").split("/"):
        return False
    return typ is None or (isinstance(typ, str) and typ in FILE_TYPES)


def _file_fields(e: dict) -> dict:
    f = {k: e[k] for k in FILE_FIELDS if k in e and isinstance(e[k], (str, int, float)) and not isinstance(e[k], bool)}
    fr = f.get("frame_rate")
    if fr is not None and not (isinstance(fr, (int, float)) and math.isfinite(fr) and 0 < fr <= 1000):
        f.pop("frame_rate")                               # the player's frame stepping needs a real rate, else it measures
    return f


def merge(groups: list) -> dict:
    """[(label, inner ui output)] -> the vault's output (see the module docstring)."""
    images, items, animated = [], [], False
    for label, output in groups:
        if not isinstance(output, dict):
            continue
        anim = any(bool(a) for a in (output.get("animated") or []) if not isinstance(a, (dict, list)))
        for key, entries in output.items():
            if key == "animated" or not isinstance(entries, (list, tuple)):
                continue
            for e in entries:
                if len(items) >= MAX_ITEMS:
                    break
                if isinstance(e, dict) and isinstance(e.get("filename"), str) and e.get("filename"):
                    if not safe_file(e):                  # counted on the vault, never shown or linked
                        items.append({"label": label, "kind": "other", "source": key, "unsafe": True})
                        continue
                    kind = _kind(key, e)
                    f = _file_fields(e)
                    core = key == "images" and kind == "image"
                    if core:
                        images.append({k: v for k, v in e.items() if k not in ("fullpath", "workflow")})
                        animated = animated or (anim and _ext(e["filename"]) in (".webp", ".png"))
                    item = {"label": label, "kind": kind, "source": key, "file": f, "core": core}
                    if kind == "image" and anim:
                        item["animated"] = True
                    items.append(item)
                elif isinstance(e, (str, int, float)) and not isinstance(e, bool) and key in ("text", "string"):
                    items.append({"label": label, "kind": "text", "source": key, "text": str(e)[:MAX_TEXT]})
                else:
                    items.append({"label": label, "kind": "other", "source": key})
    out: dict[str, Any] = {}
    if images:
        out["images"] = images
        if animated:
            out["animated"] = [True]
    out["h2v_previews"] = items
    return out


def history_form(groups: list) -> dict:
    """[(label, output)] -> the history entry of the vault: the inner outputs by their own keys (the queue / assets
    panels read these), without VHS's server path."""
    out: dict[str, list] = {}
    for _label, output in groups:
        for key, val in (output or {}).items():
            vals = list(val) if isinstance(val, (list, tuple)) else [val]
            vals = [x for x in vals if not (isinstance(x, dict) and isinstance(x.get("filename"), str)
                                            and not safe_file(x))]      # L9.342: no unsafe file reference
            vals = [{k: v for k, v in x.items() if k not in ("fullpath",)} if isinstance(x, dict) else x for x in vals]
            out[key] = list(out.get(key, [])) + vals
    return out


def is_merged(output) -> bool:
    return isinstance(output, dict) and isinstance(output.get("h2v_previews"), list)


# ── per-run state ─────────────────────────────────────────────────────────────────────────────────────────────

class PreviewHub:
    def __init__(self):
        self._lock = threading.RLock()
        self._vaults: "OrderedDict[str, dict]" = OrderedDict()    # vault id -> setting, order, prefix, items
        self._keys: dict[str, Any] = {}                            # vault id -> core cache key of its current run
        self._replays: "OrderedDict[tuple, dict]" = OrderedDict()  # (vault id, cache key) -> {show, groups}
        self.replayed: dict[str, list] = {}                        # vault id -> groups replayed in this prompt

    def reset_prompt(self) -> None:
        with self._lock:
            self.replayed.clear()

    def register(self, vault_id: str, plain: dict, prefix: str, api: Optional[dict] = None) -> None:
        s = setting_of(plain)
        api = api if api is not None else (plain or {}).get("api") or {}
        with self._lock:
            self._vaults.pop(str(vault_id), None)
            self._vaults[str(vault_id)] = {"show": s["show"], "labels": s["labels"], "prefix": str(prefix),
                                           "order": order_of(api), "extra": [],
                                           "items": OrderedDict()}
            while len(self._vaults) > MAX_VAULTS:
                self._vaults.popitem(last=False)

    def known(self, vault_id) -> bool:
        return str(vault_id) in self._vaults

    def show(self, vault_id) -> bool:
        info = self._vaults.get(str(vault_id))
        if info is not None:
            return info["show"]
        rec = self._replay_record(vault_id)
        return True if rec is None else rec["show"]

    def _label(self, info: dict, inner: str) -> tuple:
        rest = inner[len(info["prefix"]):] if inner.startswith(info["prefix"]) else inner.rsplit(".", 1)[-1]
        api_id = rest.split(".", 1)[0]
        if api_id in info["labels"]:
            lab = info["labels"][api_id]
        else:
            if api_id not in info["order"] and api_id not in info["extra"]:
                info["extra"].append(api_id)
            pos = info["order"].index(api_id) if api_id in info["order"] \
                else len(info["order"]) + info["extra"].index(api_id)
            lab = f"Preview {pos + 1}"
        rank = info["order"].index(api_id) if api_id in info["order"] else 10_000 + info["extra"].index(api_id) \
            if api_id in info["extra"] else 20_000
        return lab, rank

    def _groups(self, info: dict) -> list:
        ranked = sorted(info["items"].values(), key=lambda x: (x[0], x[3]))
        return [(lab, out) for _rank, lab, out, _seq in ranked]

    def collect(self, vault_id, inner_id, output):
        """An inner node's ui output -> the merged output of everything the vault's inner nodes showed in this run, or
        DROP when the author turned previews off."""
        vid, inner = str(vault_id), str(inner_id)
        with self._lock:
            info = self._vaults.get(vid)
            if info is None:                                  # not registered (should not happen): show this one only
                return merge([("Preview", output)])
            if not info["show"]:
                return DROP
            lab, rank = self._label(info, inner)
            seq = info["items"][inner][3] if inner in info["items"] else len(info["items"])
            info["items"][inner] = (rank, lab, output if isinstance(output, dict) else {}, seq)
            groups = self._groups(info)
            key = self._keys.get(vid)
            if key is not None:
                self._replays.pop((vid, key), None)
                self._replays[(vid, key)] = {"show": True, "groups": groups}
                while len(self._replays) > MAX_REPLAYS:
                    self._replays.popitem(last=False)
            return merge(groups)

    def groups(self, vault_id) -> list:
        with self._lock:
            info = self._vaults.get(str(vault_id))
            return self._groups(info) if info else []

    # cached runs
    def note_key(self, vault_id: str, key) -> None:
        with self._lock:
            if key is None:
                self._keys.pop(str(vault_id), None)
            else:
                self._keys[str(vault_id)] = key

    def _replay_record(self, vault_id) -> Optional[dict]:
        key = self._keys.get(str(vault_id))
        if key is None:
            return None
        try:
            return self._replays.get((str(vault_id), key))
        except TypeError:                                     # an unhashable key never matches
            return None

    def replay(self, vault_id):
        """The vault was served from core's cache (its `executed` carries no output of its own): the merged previews of
        the run that filled that cache entry, None when there is none, DROP when the author turned previews off."""
        with self._lock:
            rec = self._replay_record(vault_id)
            if rec is None:
                return None
            if not rec["show"]:
                return DROP
            self.replayed[str(vault_id)] = rec["groups"]
            return merge(rec["groups"])

    def note_hidden_run(self, vault_id) -> None:
        """A run of a vault whose previews are off: a later cached run must not show an older run's previews."""
        with self._lock:
            key = self._keys.get(str(vault_id))
            if key is not None:
                try:
                    self._replays[(str(vault_id), key)] = {"show": False, "groups": []}
                except TypeError:
                    pass

    def clear(self) -> None:
        with self._lock:
            self._vaults.clear()
            self._keys.clear()
            self._replays.clear()
            self.replayed.clear()


HUB = PreviewHub()


# ── progress: one entry per vault ─────────────────────────────────────────────────────────────────────────────

def collapse_progress(nodes: dict, vault_of: Callable[[Any], Optional[str]]) -> dict:
    """core progress_state `nodes` -> the same with every inner node folded into its vault: the vault's entry carries
    the value / max of the inner node that is running (a sampler's steps), else of the vault itself."""
    out, inner = {}, {}
    for k, st in (nodes or {}).items():
        v = vault_of(k)
        if v is None:
            out[k] = st
        elif isinstance(st, dict):
            inner.setdefault(v, []).append(st)
    for v, sts in inner.items():
        running = [s for s in sts if s.get("state") == "running"]
        pick = (next((s for s in reversed(running) if (s.get("max") or 0) > 1), None)
                or (running[-1] if running else None))
        own = out.get(v)
        base = dict(pick or own or sts[-1])
        if own is not None and pick is None:
            base = dict(own)
        if own is not None and own.get("state") == "running":
            base["state"] = "running"
        elif pick is not None:
            base["state"] = "running"
        base.update({"node_id": v, "display_node_id": v, "real_node_id": v, "parent_node_id": None})
        out[v] = base
    return out


# ── custom live-preview events (VHS animated latent preview, KJNodes ModelPreviewOverrideKJ, ...) ────────────────

def named_vault(data: dict, is_vault: Callable[[str], bool]) -> Optional[str]:
    for f in ID_FIELDS:
        x = data.get(f)
        if isinstance(x, (str, int)) and not isinstance(x, bool) and is_vault(str(x)):
            return str(x)
    return None


def filter_custom_event(event: str, data: dict, is_vault: Callable[[str], bool]):
    """A non-core event drawing on a vault (its display id): DROP when the vault's previews are off; KJNodes' sampler
    schedule fields removed otherwise. Anything else passes unchanged."""
    if event in CORE_EVENTS or not isinstance(data, dict):
        return data
    v = named_vault(data, is_vault)
    if v is None:
        return data
    if not HUB.show(v):
        return DROP
    if event == KJ_EVENT and any(k in data for k in KJ_PRIVATE):
        return {k: val for k, val in data.items() if k not in KJ_PRIVATE}
    return data


# ── core's cache key of a vault (cached runs replay their previews) ───────────────────────────────────────────

def cache_key(caches, node_id):
    """core's input-signature key of `node_id` in the outputs cache (comfy_execution/caching.py, core 0.39), or None.
    Internal API, read only and fully guarded: on any change the replay is simply off."""
    try:
        c = getattr(caches, "outputs", None)
        if hasattr(c, "_get_cache_for"):
            c = c._get_cache_for(node_id)
        ks = getattr(c, "cache_key_set", None)
        key = ks.get_data_key(node_id) if ks is not None else None
        if key is None:
            return None
        hash(key)
        return key
    except Exception:  # noqa: BLE001
        return None


_INSTALLED: dict = {}


def install_replay() -> bool:
    """Wrap core's `execution.execute` (looked up by name on every call) to note each vault's cache key before it runs."""
    try:
        import execution as core_execution
    except Exception:  # noqa: BLE001 - outside ComfyUI
        return False
    orig = getattr(core_execution, "execute", None)
    if orig is None:
        return False
    if getattr(orig, "__h2vault_previews__", False):
        return True

    async def execute(server, dynprompt, caches, current_item, *a, _orig=orig, **k):
        try:
            node = dynprompt.get_node(current_item)
            if str((node or {}).get("class_type")) in VAULT_CLASSES:
                HUB.note_key(str(current_item), cache_key(caches, current_item))
        except Exception:  # noqa: BLE001 - never break execution
            pass
        return await _orig(server, dynprompt, caches, current_item, *a, **k)

    execute.__h2vault_previews__ = True
    execute.__wrapped__ = orig
    core_execution.execute = execute
    _INSTALLED["execute"] = (core_execution, orig)
    return True


def uninstall_replay() -> None:
    got = _INSTALLED.pop("execute", None)
    if got is not None:
        mod, orig = got
        mod.execute = orig
