# H2Vault (AGPL-3.0). The id-mapping approach of the message filter (progress_state collapse, binary TEXT event
# parsing) follows Code2Collapse ComfyUI-CustomNodePacks nodes/secure_subgraph.py (Apache-2.0, Copyright
# Code2Collapse); the rest is new for H2Vault. See NOTICE.
"""H2Vault concealment (workstream V3): run a protected subgraph without anything that leaves the server naming its
inside - no inner class type, inner node title, inner (ephemeral) node id, model / file name, the author's output
prefix or the folder of an inner custom-node pack.

Design + threat model: docs/h2vault/V3_concealment_design.md (workspace). Concealment is a MODE of a vault: a vault
whose decrypted plaintext has a `conceal` section. It never changes what runs - core's native expansion still runs the
real classes - only what the Author publishes (`public_interface`) and what the server says while it runs.

Interface (everything else here is implementation):

    is_concealed(plain) / check_public(plain) / public_interface(plain)     author side, sealing
    resolve_params(plain, params) / after_expansion(vault_id, plain, graph, prefix)   the vault node's run
    public_node_type(vault_id, inner_type)
    install(server) / uninstall()                                           server adapters
    hosted_enabled() / hosted_middleware()                                  Hosted profile guard

The honest limit (design section 7): code in the same process, the server's filesystem and the model files on disk
are out of reach of any filter. Concealment protects against the workflow's recipient using the ComfyUI UI / API.

This file must import with the stdlib only: ComfyUI and aiohttp are imported lazily, each behind a guard.
"""
from __future__ import annotations

import copy
import logging
import os
import re
import struct
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Iterable, Optional

log = logging.getLogger("h2vault.conceal")

PUBLIC_NODE_TYPE = "H2Vault_ProtectedSubgraph"
CONCEALED_PREFIX = "H2Vault/concealed"
CONCEALED_LOG_LINE = "[H2Vault] concealed output"
CONCEALED_EXCEPTION_TYPE = "H2VaultConcealedError"

MODEL_BEARING_TYPES = frozenset({
    "MODEL", "CLIP", "VAE", "CLIP_VISION", "CONTROL_NET", "STYLE_MODEL", "GLIGEN", "UPSCALE_MODEL",
    "LATENT_UPSCALE_MODEL", "HOOKS", "LORA_MODEL", "PHOTOMAKER", "IPADAPTER", "INSTANTID", "PULID", "INSIGHTFACE", "*",
})
HOSTED_ALLOWED_CLASSES = frozenset({
    "H2Vault_ProtectedSubgraph", "H2Vault_ProtectedSubgraphOutput", "LoadImage", "LoadImageMask", "PreviewImage",
    "SaveImage", "PrimitiveInt", "PrimitiveFloat", "PrimitiveString", "PrimitiveStringMultiline", "PrimitiveBoolean",
})
# Rules with no observable leak path in core 0.39 (kept as defence in depth, so no must-fail case can exist):
# execution_cached only ever lists ids of the ORIGINAL prompt; core never sends an ephemeral node's _meta.
DEFENSIVE_RULES = frozenset({"execution_cached", "meta"})
RULE_NAMES = ("executing", "progress", "progress_state", "executed", "execution_cached", "binary", "custom_events",
              "errors", "history", "logs", "filename_prefix", "meta")

MEDIA_KEYS = ("images", "gifs", "video", "audio", "animated")
MEDIA_FIELDS = ("filename", "subfolder", "type")
MIN_TERM = 4
MAX_VAULTS = 64

_FILE_RE = re.compile(r"\.(safetensors|ckpt|pt|pth|bin|gguf|onnx|sft|yaml|yml|json|png|jpe?g|webp)\b|[\\/]", re.I)
_PBAR_RE = re.compile(r"^\r?\s*\d{1,3}%\|[^|\n]*\|\s*\d+/\d+ \[[^\]\n]*\]\s*$")

MSG_OOM = "The protected workflow ran out of memory. Try a smaller size or batch size."
MSG_MISSING = ("A file the protected workflow needs is missing on this installation. Ask the workflow's author which "
               "files to install.")
MSG_FAILED = ("A protected step of this workflow failed. Check the values you set; if it keeps failing, ask the "
              "workflow's author.")


class ConcealError(ValueError):
    """Text that names only public labels; safe to show to the Recipient (run time) or the Author (sealing)."""


class _Drop:
    def __repr__(self):
        return "DROP"


DROP = _Drop()


# ── the plaintext ───────────────────────────────────────────────────────────────────────────────────────────

def is_concealed(plain) -> bool:
    return isinstance(plain, dict) and isinstance(plain.get("conceal"), dict)


def _conceal(plain) -> dict:
    return plain.get("conceal") if is_concealed(plain) else {}


def _api(plain) -> dict:
    api = plain.get("api") if isinstance(plain, dict) else None
    return api if isinstance(api, dict) else {}


def _nodes(plain) -> dict:
    n = _api(plain).get("nodes")
    return n if isinstance(n, dict) else {}


def _aliases(plain) -> dict:
    a = _conceal(plain).get("aliases")
    return {str(k): v for k, v in a.items() if isinstance(v, dict)} if isinstance(a, dict) else {}


def _iface(plain, interface=None) -> dict:
    i = interface if interface is not None else (plain.get("interface") if isinstance(plain, dict) else None)
    return i if isinstance(i, dict) else {}


def _looks_like_file(s) -> bool:
    return isinstance(s, str) and bool(_FILE_RE.search(s))


def _stem(s: str) -> str:
    base = re.split(r"[\\/]", s)[-1]
    return base.rsplit(".", 1)[0] if "." in base else base


def _default_pack_of(class_type: str) -> Optional[str]:
    """The custom_nodes folder that defines a class (core classes -> None)."""
    try:
        import inspect
        import nodes as core_nodes
        cls = core_nodes.NODE_CLASS_MAPPINGS.get(class_type)
        path = inspect.getfile(cls) if cls is not None else ""
    except Exception:  # noqa: BLE001
        return None
    parts = re.split(r"[\\/]", path)
    for i, p in enumerate(parts[:-1]):
        if p == "custom_nodes" and i + 1 < len(parts) - 1:
            return parts[i + 1]
    return None


def secret_terms(plain, *, pack_of: Optional[Callable[[str], Optional[str]]] = None) -> frozenset:
    """The Secret Lexicon: strings that would identify the inside."""
    pack_of = pack_of or _default_pack_of
    terms: set = set()
    for n in _nodes(plain).values():
        if not isinstance(n, dict):
            continue
        ct = n.get("class_type")
        if isinstance(ct, str):
            terms.add(ct)
            pk = pack_of(ct)
            if pk:
                terms.add(pk)
        title = (n.get("_meta") or {}).get("title") if isinstance(n.get("_meta"), dict) else None
        if isinstance(title, str):
            terms.add(title)
        for v in (n.get("inputs") or {}).values():
            if _looks_like_file(v):
                terms.update((v, _stem(v)))

    def ui_titles(o, in_nodes=False):
        if isinstance(o, dict):
            if in_nodes and isinstance(o.get("title"), str):
                terms.add(o["title"])
            for k, v in o.items():
                ui_titles(v, in_nodes=(k == "nodes"))
        elif isinstance(o, list):
            for v in o:
                ui_titles(v, in_nodes=in_nodes)

    if isinstance(plain, dict):
        ui_titles(plain.get("ui"))
    for table in _aliases(plain).values():
        for real in table.values():
            if isinstance(real, str):
                terms.update((real, _stem(real)))
    return frozenset(t for t in terms if isinstance(t, str) and len(t.strip()) >= MIN_TERM)


def _contains_term(s, low_terms) -> Optional[str]:
    if not isinstance(s, str):
        return None
    sl = s.lower()
    return next((t for t in low_terms if t in sl), None)


# ── sealing (author side) ───────────────────────────────────────────────────────────────────────────────────

def check_public(plain, interface=None) -> list:
    """Author-facing problems that would make the published vault name its inside; [] = fine to seal."""
    if not is_concealed(plain):
        return ["This vault is not concealed (no conceal section)."]
    iface = _iface(plain, interface)
    low = sorted({t.lower() for t in secret_terms(plain)}, key=len, reverse=True)
    problems = []

    def public(s, where):
        hit = _contains_term(s, low)
        if hit:
            problems.append(f"{where} would name something inside the vault ({hit!r}). Choose another name.")

    public(_conceal(plain).get("title"), "The vault title")
    for kind in ("in", "out"):
        for s in iface.get(kind) or []:
            if isinstance(s, dict):
                public(s.get("name"), f"Socket {s.get('name')!r}")
    out_types = [s.get("type") for s in (iface.get("out") or []) if isinstance(s, dict)]
    out_types += [o.get("type") for o in (_api(plain).get("outputs") or []) if isinstance(o, dict)]
    for t in sorted({str(t) for t in out_types if t is not None}):
        if t.upper() in MODEL_BEARING_TYPES:
            problems.append(f"An output of type {t} would hand out a model (it could be saved and identified). "
                            "Expose images, latents, masks, audio or video instead.")
    aliases = _aliases(plain)
    params = [p for p in (iface.get("params") or []) if isinstance(p, dict)]
    by_key = {str(p.get("key")): p for p in params}
    for p in params:
        label = p.get("name") or p.get("key")
        public(p.get("name"), f"Control {label!r}")
        for o in p.get("options") or []:
            public(o, f"An option of control {label!r}")
        if isinstance(p.get("value"), str):
            public(p["value"], f"The value of control {label!r}")
        if str(p.get("key")) not in aliases and any(_looks_like_file(o) for o in p.get("options") or []):
            problems.append(f"Control {label!r} offers file names. Make it an alias (\"Model A\", \"Model B\") so "
                            "the real files stay inside.")
    for key, table in aliases.items():
        p = by_key.get(key)
        if p is None:
            problems.append(f"An alias is set for a control that is not exposed ({key!r}).")
            continue
        label = p.get("name") or key
        opts = list(p.get("options") or [])
        if sorted(map(str, opts)) != sorted(map(str, table)) or len(opts) != len(table):
            problems.append(f"Control {label!r}: its offered choices and its alias table differ.")
        elif p.get("value") not in table:
            problems.append(f"Control {label!r}: its value is not one of its alias choices.")
    inner = set(_nodes(plain))
    for c in _conceal(plain).get("controls") or []:
        if isinstance(c, dict) and str(c.get("node")) not in inner:
            problems.append(f"Control {c.get('name') or c.get('key')!r} drives a node that is not inside the vault.")
    for pv in _conceal(plain).get("previews") or []:
        if str(pv) not in inner:
            problems.append("A preview is declared for a node that is not inside the vault.")
    return problems


PUBLIC_PARAM_FIELDS = ("name", "type", "value", "options", "min", "max", "step", "multiline")


def merge_exposure(api, interface, conceal):
    """The author's "Choose what to expose" step -> the vault's controls and socket labels.

    `conceal.controls` = [{key, node, input, name, type, value, options?, min?, max?, step?, multiline?}] become
    promoted controls (the secret half: key -> inner node + input, in `api.promoted`) and interface params (the public
    half). `conceal.sockets` = {"in": {"<inner node>:<input>": label}, "out": {"<inner node>#<slot>": label}} rename the
    vault's sockets. They live INSIDE `conceal`, so an edit that re-extracts the inner graph (which knows nothing of
    them) gets them back on the next seal. -> (api, interface), both copies; non-concealed input is returned as is."""
    if not isinstance(conceal, dict):
        return api, interface
    api = copy.deepcopy(api) if isinstance(api, dict) else {}
    iface = copy.deepcopy(interface) if isinstance(interface, dict) else {}
    controls = [c for c in conceal.get("controls") or [] if isinstance(c, dict) and str(c.get("key") or "").strip()]
    keys = {str(c["key"]) for c in controls}
    if isinstance(conceal.get("controls"), list):
        # the author's choice is the WHOLE exposure: controls promoted any other way (frontend 1.53 auto-promotes
        # filename_prefix / seed / text when nodes become a subgraph) are not exposed; their inner inputs keep the
        # value they had, which the extracted graph carries as a literal
        promoted, params = [], []
    else:
        promoted = [p for p in api.get("promoted") or [] if isinstance(p, dict) and str(p.get("key")) not in keys]
        params = [p for p in iface.get("params") or [] if isinstance(p, dict) and str(p.get("key")) not in keys]
    for c in controls:
        promoted.append({"key": str(c["key"]), "node": str(c.get("node")), "input": str(c.get("input"))})
        q = {"key": str(c["key"])}
        q.update({k: c[k] for k in PUBLIC_PARAM_FIELDS if k in c})
        params.append(q)
    api["promoted"] = promoted
    iface["params"] = params
    sockets = conceal.get("sockets") if isinstance(conceal.get("sockets"), dict) else {}
    outs = sockets.get("out") if isinstance(sockets.get("out"), dict) else {}
    iface_out = iface.get("out") if isinstance(iface.get("out"), list) else []
    for j, o in enumerate(api.get("outputs") or []):
        if not isinstance(o, dict) or "node" not in o:
            continue
        label = outs.get(f"{o.get('node')}#{o.get('slot')}")
        if isinstance(label, str) and label.strip():
            o["name"] = label.strip()
            if j < len(iface_out) and isinstance(iface_out[j], dict):
                iface_out[j]["name"] = label.strip()
    ins = sockets.get("in") if isinstance(sockets.get("in"), dict) else {}
    iface_in = iface.get("in") if isinstance(iface.get("in"), list) else []
    api_in = api.get("inputs") if isinstance(api.get("inputs"), list) else []
    for nid, n in (api.get("nodes") or {}).items():
        for name, v in ((n or {}).get("inputs") or {}).items() if isinstance(n, dict) else []:
            if isinstance(v, dict) and isinstance(v.get("vault_in"), int):
                label = ins.get(f"{nid}:{name}")
                i = v["vault_in"]
                if isinstance(label, str) and label.strip():
                    for side in (iface_in, api_in):
                        if 0 <= i < len(side) and isinstance(side[i], dict):
                            side[i]["name"] = label.strip()
    return api, iface


def public_interface(plain, interface=None) -> dict:
    """What is written into the workflow for a concealed vault: a whitelist, never a copy."""
    problems = check_public(plain, interface)
    if problems:
        raise ConcealError(" ".join(problems))
    iface = _iface(plain, interface)

    def sock(s):
        return {"name": str(s.get("name", "")), "type": str(s.get("type", "*"))}

    params = []
    for p in iface.get("params") or []:
        if not isinstance(p, dict):
            continue
        q = {"key": str(p.get("key")), "name": str(p.get("name") or p.get("key")), "type": str(p.get("type", "")),
             "value": p.get("value")}
        if isinstance(p.get("options"), list):
            q["options"] = [o for o in p["options"] if isinstance(o, (str, int, float, bool))]
        for k in ("min", "max", "step"):
            if isinstance(p.get(k), (int, float)) and not isinstance(p.get(k), bool):
                q[k] = p[k]
        if isinstance(p.get("multiline"), bool):
            q["multiline"] = p["multiline"]
        params.append(q)
    return {"title": str(_conceal(plain).get("title") or "H2Vault"),
            "in": [sock(s) for s in iface.get("in") or [] if isinstance(s, dict)],
            "out": [sock(s) for s in iface.get("out") or [] if isinstance(s, dict)],
            "params": params, "concealed": True}


# ── run time: the vault node's calls ────────────────────────────────────────────────────────────────────────

def resolve_params(plain, params: dict) -> dict:
    """Control values from the Recipient -> the values the inside receives. Aliases resolve here, server-side."""
    if not is_concealed(plain):
        return params
    out_types = [o.get("type") for o in (_api(plain).get("outputs") or []) if isinstance(o, dict)]
    out_types += [s.get("type") for s in (_iface(plain).get("out") or []) if isinstance(s, dict)]
    if any(str(t).upper() in MODEL_BEARING_TYPES for t in out_types if t is not None):
        raise ConcealError("This protected workflow offers an output that cannot be concealed. Ask its author for a "
                           "fresh copy.")
    names = {str(p.get("key")): str(p.get("name") or "a control")
             for p in (_iface(plain).get("params") or []) if isinstance(p, dict)}
    out = dict(params)
    for key, table in _aliases(plain).items():
        if key not in out:
            continue
        label = out[key]
        if not isinstance(label, str) or label not in table:
            raise ConcealError(f"{names.get(key, 'A control')!r} is set to a choice this workflow does not offer. "
                               "Pick one of its listed choices.")
        out[key] = table[label]
    return out


def after_expansion(vault_id, plain, graph: dict, prefix: str, *, concealer: "Optional[Concealer]" = None) -> dict:
    """Post-process the expansion of a concealed vault and register it, so the filters can attribute its ids."""
    if not is_concealed(plain):
        return graph
    c = concealer or CONCEALER
    g = copy.deepcopy(graph)
    for node in g.values():
        if not isinstance(node, dict):
            continue
        if c.rules.get("meta", True):
            node.pop("_meta", None)
        if c.rules.get("filename_prefix", True):
            inputs = node.get("inputs")
            if isinstance(inputs, dict) and isinstance(inputs.get("filename_prefix"), str):
                inputs["filename_prefix"] = CONCEALED_PREFIX
    previews = {f"{prefix}{p}" for p in (_conceal(plain).get("previews") or [])}
    c.register(str(vault_id), set(g), previews & set(g), secret_terms(plain))
    return g


def public_node_type(vault_id, inner_type):
    return PUBLIC_NODE_TYPE if CONCEALER.is_concealed_vault(str(vault_id)) else inner_type


# ── the runtime filter ──────────────────────────────────────────────────────────────────────────────────────

class Concealer:
    """Process-wide state: which ids belong to which concealed vault, which vaults ran in this prompt, and the
    Concealed Window (an inner node is executing)."""

    def __init__(self):
        self.rules = {r: True for r in RULE_NAMES}
        self._lock = threading.RLock()
        self._vaults: "OrderedDict[str, dict]" = OrderedDict()     # vault id -> {inner, previews, terms}
        self._active: set = set()
        self._window: Optional[str] = None
        self._last_executing: Optional[str] = None
        self._marker_open = False

    # registration / state
    def register(self, vault_id: str, inner_ids: Iterable[str], preview_ids: Iterable[str], terms: Iterable[str]):
        with self._lock:
            self._vaults.pop(vault_id, None)
            self._vaults[vault_id] = {"inner": set(map(str, inner_ids)), "previews": set(map(str, preview_ids)),
                                      "low_terms": sorted({t.lower() for t in terms}, key=len, reverse=True)}
            while len(self._vaults) > MAX_VAULTS:
                self._vaults.popitem(last=False)
            self._active.add(vault_id)

    def is_concealed_vault(self, vault_id: str) -> bool:
        return vault_id in self._vaults

    def any_registered(self) -> bool:
        return bool(self._vaults)

    def vault_of(self, node_id) -> Optional[str]:
        """Structural attribution: the vault whose expansion made this id (or an expansion inside it)."""
        if not isinstance(node_id, str) or "." not in node_id:
            return None
        best = None
        for v, info in self._vaults.items():
            if not node_id.startswith(v + "."):
                continue
            inner = info["inner"]
            hit = node_id in inner or any(node_id.startswith(i + ".") for i in inner)
            if hit and (best is None or len(v) < len(best)):
                best = v                                     # the outermost concealed vault wins
        return best

    def on_node_start(self, node_id) -> None:
        with self._lock:
            self._window = self.vault_of(str(node_id)) if node_id is not None else None

    def end_prompt(self) -> None:
        with self._lock:
            self._active.clear()
            self._window = None
            self._last_executing = None
            self._marker_open = False

    @property
    def window(self) -> Optional[str]:
        return self._window

    # messages
    def _window_terms(self) -> list:
        info = self._vaults.get(self._window) if self._window else None
        return info["low_terms"] if info else []

    def _names_inner(self, obj) -> bool:
        if isinstance(obj, str):
            return self.vault_of(obj) is not None
        if isinstance(obj, dict):
            return any(self._names_inner(k) or self._names_inner(v) for k, v in obj.items())
        if isinstance(obj, (list, tuple)):
            return any(self._names_inner(x) for x in obj)
        return False

    def _has_term(self, obj, low_terms) -> bool:
        if not low_terms:
            return False
        if isinstance(obj, str):
            return _contains_term(obj, low_terms) is not None
        if isinstance(obj, dict):
            return any(self._has_term(k, low_terms) or self._has_term(v, low_terms) for k, v in obj.items())
        if isinstance(obj, (list, tuple)):
            return any(self._has_term(x, low_terms) for x in obj)
        return False

    def _map_ids(self, obj):
        if isinstance(obj, str):
            v = self.vault_of(obj)
            return v if v is not None else obj
        if isinstance(obj, dict):
            return {self._map_ids(k) if isinstance(k, str) else k: self._map_ids(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._map_ids(x) for x in obj]
        if isinstance(obj, tuple):
            return tuple(self._map_ids(x) for x in obj)
        return obj

    @staticmethod
    def _reduce_ui(output) -> dict:
        out = {}
        for k in MEDIA_KEYS:
            entries = output.get(k) if isinstance(output, dict) else None
            if isinstance(entries, list):
                out[k] = [{f: e[f] for f in MEDIA_FIELDS if f in e} for e in entries if isinstance(e, dict)]
        return out

    def _filter_error(self, event, d: dict) -> dict:
        nid = str(d.get("node_id"))
        v = self.vault_of(nid)
        if v is None and nid in self._active:
            v = nid
        if v is None:
            return d
        d = dict(d)
        d["node_id"] = v
        if nid != v:
            d["node_type"] = PUBLIC_NODE_TYPE
        if isinstance(d.get("executed"), list):
            d["executed"] = [x for x in d["executed"] if self.vault_of(x) is None]
        if event == "execution_error":
            text = f"{d.get('exception_type', '')} {d.get('exception_message', '')}".lower()
            if "out of memory" in text or "outofmemory" in text:
                msg = MSG_OOM
            elif "filenotfound" in text or "no such file" in text or "not found" in text:
                msg = MSG_MISSING
            else:
                msg = MSG_FAILED
            d.update({"exception_type": CONCEALED_EXCEPTION_TYPE, "exception_message": msg, "traceback": [],
                      "current_inputs": {}, "current_outputs": []})
        else:
            for k in ("traceback", "current_inputs", "current_outputs", "exception_message"):
                d.pop(k, None)
        return d

    def _filter_binary(self, event: int, data):
        if not self.rules["binary"]:
            return data
        if event == 3 and isinstance(data, (bytes, bytearray)) and len(data) >= 4:
            n = struct.unpack(">I", bytes(data[:4]))[0]
            node = bytes(data[4:4 + n]).decode("utf-8", "replace")
            return DROP if self.vault_of(node) is not None else data
        if event == 4 and isinstance(data, tuple) and len(data) == 2 and isinstance(data[1], dict):
            return (data[0], self._map_ids(data[1]))
        return data

    def filter_message(self, event, data, *, live: bool = True):
        if not self._vaults:
            if live and event == "executing" and isinstance(data, dict):     # the vault's own `executing` comes
                node = data.get("node")                                    # before its expansion registers
                self._last_executing = None if node is None else str(node)
            return data
        if isinstance(event, int):
            return self._filter_binary(event, data)
        if not isinstance(data, dict):
            return data
        if event in ("execution_error", "execution_interrupted"):
            return self._filter_error(event, data) if self.rules["errors"] else data
        if event == "execution_start":
            if live:
                self._last_executing = None
            return data
        if event in ("status", "execution_success", "logs"):
            return data
        d = dict(data)
        if event == "executing":
            if not self.rules["executing"]:
                return data
            node = d.get("node")
            v = self.vault_of(node)
            public = v if v is not None else node
            if v is not None:
                d["node"] = v
                if "display_node" in d:
                    d["display_node"] = v
                if live and self._last_executing == v:
                    return DROP
            if live:
                self._last_executing = None if public is None else str(public)
            return d
        if event == "progress":
            if self.rules["progress"]:
                v = self.vault_of(d.get("node"))
                if v is not None:
                    d["node"] = v
            return d
        if event == "progress_state":
            if not self.rules["progress_state"]:
                return data
            nodes_ = {}
            synth = {}
            for k, st in (d.get("nodes") or {}).items():
                v = self.vault_of(k)
                if v is None:
                    nodes_[k] = st
                elif v not in synth and isinstance(st, dict):
                    s = dict(st)
                    s.update({"node_id": v, "display_node_id": v, "real_node_id": v, "parent_node_id": None})
                    synth[v] = s
            for v, s in synth.items():
                nodes_.setdefault(v, s)
            d["nodes"] = nodes_
            return d
        if event == "executed":
            if not self.rules["executed"]:
                return data
            node = d.get("node")
            v = self.vault_of(node)
            if v is None:
                return d
            if str(node) not in self._vaults[v]["previews"]:
                return DROP
            d["node"] = v
            d["display_node"] = v
            d["output"] = self._reduce_ui(d.get("output"))
            return d
        if event == "execution_cached":
            if self.rules["execution_cached"]:
                d["nodes"] = [x for x in (d.get("nodes") or []) if self.vault_of(x) is None]
            return d
        # any other event (custom packs' telemetry, previews of other kinds, ...): default deny when attributable
        if not self.rules["custom_events"]:
            return data
        if self._names_inner(d):
            return DROP
        if self._window and self._has_term(d, self._window_terms()):
            return DROP
        return data

    def filter_history(self, result):
        if not self._vaults or not self.rules["history"] or not isinstance(result, dict):
            return result
        out = dict(result)
        outputs = {}
        for k, v in (result.get("outputs") or {}).items():
            vault = self.vault_of(k)
            if vault is None:
                outputs[k] = v
                continue
            if str(k) not in self._vaults[vault]["previews"]:
                continue
            merged = outputs.setdefault(vault, {})
            for key, entries in self._reduce_ui(v).items():
                merged[key] = list(merged.get(key, [])) + entries
        out["outputs"] = outputs
        if isinstance(result.get("meta"), dict):
            out["meta"] = {k: v for k, v in result["meta"].items() if self.vault_of(k) is None}
        return out

    def filter_status(self, status):
        """task_done's status: an ExecutionStatus NamedTuple (or a dict) whose messages are (event, data) pairs."""
        if not self._vaults or status is None:
            return status
        msgs = status.get("messages") if isinstance(status, dict) else getattr(status, "messages", None)
        if not msgs:
            return status
        kept = []
        for ev, data in msgs:
            new = self.filter_message(ev, data, live=False)
            if new is not DROP:
                kept.append((ev, new))
        if isinstance(status, dict):
            return {**status, "messages": kept}
        return status._replace(messages=kept) if hasattr(status, "_replace") else status

    # logs
    def filter_log_text(self, text):
        if self._window is None or not self.rules["logs"] or not isinstance(text, str) or not text:
            return text
        out = []
        with self._lock:
            for line in text.splitlines(keepends=True):
                body = line.rstrip("\r\n")
                if not body.strip("\r \t"):
                    out.append(line)
                    continue
                if _PBAR_RE.match(body):
                    out.append(line)
                    self._marker_open = False
                    continue
                if self._marker_open:
                    continue
                self._marker_open = True
                out.append(CONCEALED_LOG_LINE + line[len(body):])
        return "".join(out)


CONCEALER = Concealer()


# ── server adapters ─────────────────────────────────────────────────────────────────────────────────────────

_INSTALL: dict = {}


def install(server=None, *, concealer: Optional[Concealer] = None) -> bool:
    """Wrap the server's outbound paths. Must run AFTER the vault's own message filter so that this one is the
    outermost wrapper and sees core's raw inner ids first."""
    if _INSTALL:
        return True
    c = concealer or CONCEALER
    try:
        if server is None:
            from server import PromptServer
            server = PromptServer.instance
    except Exception as exc:  # noqa: BLE001
        log.warning("H2Vault concealment not installed (no server): %s", exc)
        return False

    orig_send = server.send_sync

    def send_sync(event, data, sid=None, _orig=orig_send):
        try:
            data = c.filter_message(event, data)
        except Exception:  # noqa: BLE001 - fail closed while a concealed vault is known
            log.error("H2Vault concealment: message filter failed (message %s)",
                      "dropped" if c.any_registered() else "passed")
            if c.any_registered():
                return None
        if data is DROP:
            return None
        return _orig(event, data, sid)

    server.send_sync = send_sync
    _INSTALL["send"] = (server, orig_send)

    q = getattr(server, "prompt_queue", None)
    if q is not None and hasattr(q, "task_done"):
        orig_done = q.task_done

        def task_done(item_id, history_result, status=None, *a, _orig=orig_done, **k):
            try:
                history_result = c.filter_history(history_result)
                status = c.filter_status(status)
            except Exception:  # noqa: BLE001
                log.error("H2Vault concealment: history filter failed (history of this run withheld)")
                if c.any_registered():
                    history_result, status = {"outputs": {}, "meta": {}}, None
            try:
                return _orig(item_id, history_result, status, *a, **k)
            finally:
                c.end_prompt()

        q.task_done = task_done
        _INSTALL["queue"] = (q, orig_done)

    try:
        from comfy_execution.progress import ProgressRegistry
        orig_start = ProgressRegistry.start_progress

        def start_progress(self, node_id, _orig=orig_start):
            try:
                c.on_node_start(node_id)
            except Exception:  # noqa: BLE001
                pass
            return _orig(self, node_id)

        ProgressRegistry.start_progress = start_progress
        _INSTALL["progress"] = (ProgressRegistry, orig_start)
    except Exception as exc:  # noqa: BLE001
        log.warning("H2Vault concealment: no progress registry (log concealment off): %s", exc)

    try:
        import app.logger as core_logger
        streams = []
        for attr in ("stdout_interceptor", "stderr_interceptor"):
            s = getattr(core_logger, attr, None)
            if s is None:
                continue
            orig_write = s.write                              # the bound method (instance shadowing below)

            def write(data, _orig=orig_write):
                try:
                    data = c.filter_log_text(data)
                except Exception:  # noqa: BLE001
                    if c.window is not None:
                        data = CONCEALED_LOG_LINE + "\n"
                return _orig(data)

            s.write = write
            streams.append(s)
        _INSTALL["logs"] = streams
    except Exception as exc:  # noqa: BLE001
        log.warning("H2Vault concealment: no log interceptor (log concealment off): %s", exc)

    if hosted_enabled():
        app = getattr(server, "app", None)
        try:
            app.middlewares.append(hosted_middleware())
            log.info("H2Vault hosted mode: model lists, logs and model routes are withheld from every client")
        except Exception as exc:  # noqa: BLE001
            log.error("H2Vault hosted mode requested but the guard could not be attached: %s", exc)
    return True


def uninstall() -> None:
    """Restore everything install() wrapped (tests; the hosted middleware cannot be detached from a running app)."""
    if "send" in _INSTALL:
        server, orig = _INSTALL["send"]
        server.send_sync = orig
    if "queue" in _INSTALL:
        q, orig = _INSTALL["queue"]
        q.task_done = orig
    if "progress" in _INSTALL:
        cls, orig = _INSTALL["progress"]
        cls.start_progress = orig
    for s in _INSTALL.get("logs", []):
        try:
            del s.write
        except AttributeError:
            pass
    _INSTALL.clear()


# ── Hosted profile ──────────────────────────────────────────────────────────────────────────────────────────

_BLOCKED_EXACT = {"/internal/folder_paths", "/models"}
_BLOCKED_PREFIX = ("/internal/logs", "/models/", "/view_metadata/", "/experiment/models")
_HOSTED_REFUSAL = "Not available: this server runs in H2Vault hosted mode (protected workflows only)."
_model_cache: dict = {}


def hosted_enabled() -> bool:
    return os.environ.get("H2VAULT_HOSTED", "").strip().lower() in ("1", "true", "yes", "on")


def hosted_allowed_classes() -> frozenset:
    """HOSTED_ALLOWED_CLASSES plus the operator's own (env H2VAULT_HOSTED_ALLOW, comma-separated class ids)."""
    extra = {c.strip() for c in os.environ.get("H2VAULT_HOSTED_ALLOW", "").split(",") if c.strip()}
    return HOSTED_ALLOWED_CLASSES | frozenset(extra)


def _server_model_names() -> set:
    now = time.monotonic()
    if _model_cache.get("t", -1e9) + 60 > now:
        return _model_cache["names"]
    names: set = set()
    try:
        import folder_paths
        for folder in list(folder_paths.folder_names_and_paths):
            if folder in ("custom_nodes", "configs"):
                continue
            try:
                names.update(folder_paths.get_filename_list(folder))
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    _model_cache.update(t=now, names=names)
    return names


def _redact_object_info(info, model_names: set):
    if not isinstance(info, dict):
        return info
    for spec in info.values():
        inputs = spec.get("input") if isinstance(spec, dict) else None
        for section in (inputs or {}).values() if isinstance(inputs, dict) else []:
            if not isinstance(section, dict):
                continue
            for name, s in section.items():
                if not isinstance(s, list) or not s:
                    continue
                if isinstance(s[0], list) and any(o in model_names for o in s[0] if isinstance(o, str)):
                    s[0] = []
                elif (s[0] == "COMBO" and len(s) > 1 and isinstance(s[1], dict)
                      and isinstance(s[1].get("options"), list)
                      and any(o in model_names for o in s[1]["options"] if isinstance(o, str))):
                    s[1]["options"] = []
    return info


def hosted_middleware(*, model_names: Optional[Callable[[], set]] = None,
                      allowed_classes: Optional[frozenset] = None):
    """aiohttp middleware for the Hosted profile: every client is a Recipient (design 4.4)."""
    from aiohttp import web
    import json as _json
    names_fn = model_names or _server_model_names
    allowed_classes = allowed_classes if allowed_classes is not None else hosted_allowed_classes()

    def refuse():
        return web.json_response({"error": _HOSTED_REFUSAL}, status=403)

    @web.middleware
    async def h2vault_hosted_guard(request, handler):
        path = request.path
        p = path[4:] if path.startswith("/api/") else path
        if p in _BLOCKED_EXACT or p.startswith(_BLOCKED_PREFIX):
            return refuse()
        if request.method == "POST" and p == "/prompt":
            try:
                body = await request.json()
                prompt = body.get("prompt") if isinstance(body, dict) else None
                classes = {str(n.get("class_type")) for n in (prompt or {}).values() if isinstance(n, dict)}
            except Exception:  # noqa: BLE001
                return refuse()
            if not classes or not classes <= set(allowed_classes):
                return web.json_response({"error": {"type": "h2vault_hosted", "message": _HOSTED_REFUSAL,
                                                    "details": ""}, "node_errors": {}}, status=403)
            return await handler(request)
        if request.method == "GET" and (p == "/object_info" or p.startswith("/object_info/")):
            resp = await handler(request)
            try:
                info = _json.loads(resp.body)
            except Exception:  # noqa: BLE001
                return refuse()
            return web.json_response(_redact_object_info(info, set(names_fn())), status=resp.status)
        return await handler(request)

    return h2vault_hosted_guard
