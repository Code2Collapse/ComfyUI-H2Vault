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
    CAPABILITIES / run_selftest() / capability_refusal()                    L9.341 security capability registry:
                                                                            every hook self-tested; fail closed
    hosted_enabled() / hosted_middleware()                                  Hosted profile guard
    metadata_guard / WindowLogFilter / hash_folder_middleware               V8 zero-information guards (every
                                                                            vault / every profile; install() wires them)

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

# Vault OUTPUT types (design S11; owner 2026-11-23). A concealed vault never hands out a model. The decision is by
# type name (output_type_kind) at sealing, plus a check of the real VALUE at run time (check_output_value).
# `*` is NOT a model type: a wildcard output is judged by what really reaches it (review_outputs traces it).
MODEL_BEARING_TYPES = frozenset({
    "MODEL", "CLIP", "VAE", "CLIP_VISION", "CONTROL_NET", "STYLE_MODEL", "GLIGEN", "UPSCALE_MODEL",
    "LATENT_UPSCALE_MODEL", "HOOKS", "LORA_MODEL", "PHOTOMAKER", "IPADAPTER", "INSTANTID", "PULID", "INSIGHTFACE",
    # custom packs, checked in their code (2026-11-23): SeC SeCModelLoader, Impact KSamplerWrapper / UpscalerWrapper
    # (both hold the model), LivePortrait cropper (face models), WhisperX ASR pipeline, cubiq FaceAnalysis
    "SEC_MODEL", "KSAMPLER", "KSAMPLER_ADVANCED", "UPSCALER", "LPCROPPER", "WHISPER_ASR", "FACE_ANALYSIS",
})
_SEALING_V1_MODEL_TYPES = frozenset({
    "MODEL", "CLIP", "VAE", "CLIP_VISION", "CONTROL_NET", "STYLE_MODEL", "GLIGEN", "UPSCALE_MODEL",
    "LATENT_UPSCALE_MODEL", "HOOKS", "LORA_MODEL", "PHOTOMAKER", "IPADAPTER", "INSTANTID", "PULID", "INSIGHTFACE"})
# any type NAME with one of these words is treated as model-bearing (custom packs name their model types this way:
# SAM_MODEL, SAM2MODEL, BBOX_DETECTOR, BASIC_PIPE, PIPE_LINE, WANVAE, WANTEXTENCODER, WANVIDLORA ...)
_MODEL_WORDS = re.compile(r"MODEL|CLIP|VAE|PIPE|CHECKPOINT|CKPT|LORA|PREDICTOR|DETECTOR|GUIDER|IPADAPTER|INSIGHTFACE"
                          r"|CONTROL_?NET|UNET|ENCODER|UPSCALER|CLASSIFIER|RESAMPLER|(?:^|_)SAM\d*(?:_|$)")
# core's plain data types: never flagged, nothing to say about them
CORE_DATA_TYPES = frozenset({
    "IMAGE", "MASK", "LATENT", "AUDIO", "VIDEO", "STRING", "INT", "FLOAT", "BOOLEAN", "COMBO", "CONDITIONING",
    "SIGMAS", "NOISE", "SAMPLER", "TIMESTEPS_RANGE", "TRACKS", "LOSS_MAP", "BBOX", "POINT", "WAN_CAMERA_EMBEDDING",
})
# data types whose NAME has a model word, decided from their producer's code (2026-11-23):
#   SAM3_TRACK_DATA      core comfy_extras/nodes_sam3.py SAM3_VideoTrack -> comfy/ldm/sam3/tracker.py: a dict of
#                        packed_masks (tensor), n_frames, scores, orig_size - no model, no predictor
#   CLIP_VISION_OUTPUT   comfy/clip_vision.py Output: tensors (image_embeds, last_hidden_state, ...)
#   AUDIO_ENCODER_OUTPUT comfy/audio_encoders: a dict of tensors
DECIDED_DATA_TYPES = frozenset({"SAM3_TRACK_DATA", "CLIP_VISION_OUTPUT", "AUDIO_ENCODER_OUTPUT"})


def output_type_kind(t) -> str:
    """'model' (hands out something that could be saved as a model), 'data' (core data or a decided custom data
    type), 'custom' (another custom type: allowed, checked at run time), 'any' (a wildcard / run-time type)."""
    s = str(getattr(t, "value", t) if t is not None else "").strip().upper()
    if not s or s == "*" or s == "ANY" or s.startswith("COMFY_"):
        return "any"
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if len(parts) > 1:
        kinds = {output_type_kind(p) for p in parts}
        return next(k for k in ("model", "any", "custom", "data") if k in kinds)
    if s in CORE_DATA_TYPES or s in DECIDED_DATA_TYPES:
        return "data"
    if s in MODEL_BEARING_TYPES or _MODEL_WORDS.search(s):
        return "model"
    return "custom"
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

def check_public(plain, interface=None, *, class_of: Optional[Callable[[str], Any]] = None) -> list:
    """Author-facing problems that would make the published vault name its inside or hand out a model; [] = fine to
    seal. `class_of(class_type)` -> node class (default: ComfyUI's registry) - used to trace wildcard outputs."""
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
    problems += [r["message"] for r in review_outputs(plain, interface, class_of=class_of) if r["blocking"]]
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


# ── the vault's outputs (owner 2026-11-23): what each one really carries ──────────────────────────────────────

def _is_link(v) -> bool:
    return isinstance(v, (list, tuple)) and len(v) == 2 and isinstance(v[0], str) and isinstance(v[1], int) \
        and not isinstance(v[1], bool)


def _tname(t) -> str:
    if isinstance(t, (list, tuple)):
        return "COMBO"
    return str(getattr(t, "value", t) if t is not None else "")


def _signature(cls):
    """(output types, {input name: type}) of a V1 class or a V3 schema node; (None, {}) when unreadable."""
    info = None
    if cls is not None and hasattr(cls, "GET_NODE_INFO_V1"):
        try:
            info = cls.GET_NODE_INFO_V1()
        except Exception:  # noqa: BLE001
            info = None
    if isinstance(info, dict):
        outs, spec = info.get("output"), info.get("input") or {}
    else:
        try:
            outs = getattr(cls, "RETURN_TYPES", None)
        except Exception:  # noqa: BLE001
            outs = None
        try:
            spec = cls.INPUT_TYPES() if cls is not None else {}
        except Exception:  # noqa: BLE001 - a broken INPUT_TYPES says nothing
            spec = {}
    outs = [_tname(o) for o in outs] if isinstance(outs, (list, tuple)) else None
    ins = {}
    for section in ("required", "optional"):
        sect = spec.get(section) if isinstance(spec, dict) else None
        if isinstance(sect, dict):
            for name, v in sect.items():
                ins[name] = _tname(v[0] if isinstance(v, (list, tuple)) and v else v)
    return outs, ins


UNKNOWN = "?"


def _types_of(t) -> frozenset:
    return frozenset(p.strip().upper() for p in _tname(t).split(",") if p.strip())


def _trace(api, nid, slot, class_of, memo, depth=0) -> frozenset:
    """The concrete types that can reach output `slot` of inner node `nid`: its declared type, or - for a wildcard
    output (Lazy Switch, any-switches, reroute-like nodes) - the union over its wildcard inputs, followed upstream.
    UNKNOWN stands for "cannot be told before it runs" (a node not installed, a wildcard with nothing to follow)."""
    key = (str(nid), slot)
    if key in memo:
        return memo[key]                       # in progress (a malformed cycle) contributes nothing
    if depth > 64:
        return frozenset({UNKNOWN})
    memo[key] = frozenset()
    res = frozenset({UNKNOWN})
    node = (api.get("nodes") or {}).get(str(nid)) if isinstance(api, dict) else None
    if isinstance(node, dict):
        cls = class_of(node.get("class_type"))
        outs, ins = _signature(cls) if cls is not None else (None, {})
        if outs is not None and isinstance(slot, int) and 0 <= slot < len(outs):
            if output_type_kind(outs[slot]) != "any":
                res = _types_of(outs[slot])
            else:
                found: set = set()
                for name, v in (node.get("inputs") or {}).items():
                    if name in ins and output_type_kind(ins[name]) != "any":
                        continue                   # a typed input (the switch's BOOLEAN) is not passed through
                    if _is_link(v):
                        found |= _trace(api, v[0], v[1], class_of, memo, depth + 1)
                    elif isinstance(v, dict) and isinstance(v.get("vault_in"), int):
                        found |= _vault_in_types(api, v["vault_in"])
                res = frozenset(found) or frozenset({UNKNOWN})
    memo[key] = res
    return res


def _vault_in_types(api, i) -> frozenset:
    ins = api.get("inputs") if isinstance(api, dict) else None
    t = ins[i].get("type") if isinstance(ins, list) and 0 <= i < len(ins) and isinstance(ins[i], dict) else None
    return frozenset({UNKNOWN}) if output_type_kind(t) == "any" else _types_of(t)


_RUN_CHECK = "When the vault runs, it checks the value and stops it if it carries a model."


def _a(t: str) -> str:
    return f"an {t}" if t[:1] in "AEIOU" else f"a {t}"


def review_outputs(plain, interface=None, *, class_of: Optional[Callable[[str], Any]] = None) -> list:
    """One entry per vault output: {index, key, name, type, shown, resolved, verdict, blocking, message, fixes}.
    verdict: "model" (blocking: it hands out a model), "data", "custom" (a custom type), "unknown" (a wildcard that
    cannot be traced; allowed - the run-time check stops a model). `fixes` are the dialog's actions: "remove" (take
    the output out of the vault), "unconceal" (lock without concealment), "show_as" (publish a traced wildcard as its
    one concrete type). Text names only the socket's public label and type names."""
    class_of = class_of or _class_of
    api, iface = _api(plain), _iface(plain, interface)
    outs = [o for o in (api.get("outputs") or []) if isinstance(o, dict)]
    socks = [s for s in (iface.get("out") or []) if isinstance(s, dict)]
    memo: dict = {}
    review = []
    for j in range(max(len(outs), len(socks))):
        o = outs[j] if j < len(outs) else {}
        s = socks[j] if j < len(socks) else {}
        name = str(s.get("name") or o.get("name") or f"Output {j + 1}")
        real = _tname(o.get("type", s.get("type", "*")))
        shown = _tname(s.get("type", real))
        key = None
        if "node" in o:
            key = f"{o.get('node')}#{o.get('slot')}"
        elif "input" in o:
            key = f"in:{o.get('input')}"
        r = {"index": j, "key": key, "name": name, "type": real, "shown": shown, "blocking": False, "message": "",
             "fixes": []}
        if "input" in o:                         # the recipient's own input passed straight through
            r.update(resolved=sorted(_types_of(real)) or [UNKNOWN], verdict="data")
            review.append(r)
            continue
        if output_type_kind(real) == "any":
            resolved = _trace(api, o.get("node"), o.get("slot"), class_of, memo) if "node" in o else {UNKNOWN}
        else:
            resolved = _types_of(real)
        resolved = sorted(resolved)
        r["resolved"] = resolved
        known = [t for t in resolved if t != UNKNOWN]
        models = [t for t in known if output_type_kind(t) == "model"]
        customs = [t for t in known if output_type_kind(t) == "custom"]
        wild = output_type_kind(real) == "any"
        if models or output_type_kind(shown) == "model":
            what = " or ".join(_a(t) for t in (models or [shown.upper()]))
            r.update(verdict="model", blocking=True, fixes=[{"id": "remove"}, {"id": "unconceal"}],
                     message=(f"Output {name!r} (type *) can pass on {what} from inside" if wild else
                              f"Output {name!r} gives out {what}") +
                     ": a model the person who runs the vault could save and identify. Remove this output from the "
                     "vault, or lock without concealment.")
        elif UNKNOWN in resolved:
            r.update(verdict="unknown", message=f"Output {name!r} (type *) passes on a value whose type cannot be told "
                                                f"before it runs. {_RUN_CHECK}")
        elif customs:
            r.update(verdict="custom", message=f"Output {name!r} is {' or '.join(_a(t) for t in customs)}: the person "
                                               f"who runs the vault sees this type name. {_RUN_CHECK}")
        else:
            r["verdict"] = "data"
            decided = [t for t in known if t in DECIDED_DATA_TYPES]
            if wild:
                r["message"] = f"Output {name!r} (type *) carries {' or '.join(_a(t) for t in known)}."
                if len(known) == 1 and shown.upper() != known[0]:
                    r["fixes"] = [{"id": "show_as", "type": known[0]}]
            elif decided:
                r["message"] = (f"Output {name!r} is {_a(decided[0])} (checked: data only, no model). The person who "
                                "runs the vault sees this type name.")
        if shown != real and r["verdict"] != "model":
            # "show as": allowed only for a wildcard that carries exactly that one data type
            if not (wild and r["verdict"] == "data" and [shown.upper()] == known):
                r.update(blocking=True, fixes=[{"id": "show_as_undo"}],
                         message=f"Output {name!r} cannot be shown as {shown}: it carries "
                                 f"{' or '.join(_a(t) for t in known) or 'a value of unknown type'}.")
        review.append(r)
    return review


def review_inputs(plain, interface=None) -> list:
    """Notes (never blocking) about the vault's inputs: an input of a model type means the person who runs the vault
    wires in their own model - nothing of the author's leaves through it."""
    notes = []
    for s in (_iface(plain, interface).get("in") or []):
        if isinstance(s, dict) and output_type_kind(s.get("type")) == "model":
            t = _tname(s.get("type"))
            notes.append({"name": str(s.get("name") or ""), "type": t, "blocking": False,
                          "message": f"Input {str(s.get('name') or '')!r} takes {_a(t)}: the person who runs the "
                                     f"vault wires in their own {t}. Nothing of yours leaves through it."})
    return notes


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
    shown = sockets.get("types") if isinstance(sockets.get("types"), dict) else {}
    for j, o in enumerate(api.get("outputs") or []):
        if not isinstance(o, dict) or "node" not in o:
            continue
        label = outs.get(f"{o.get('node')}#{o.get('slot')}")
        if isinstance(label, str) and label.strip():
            o["name"] = label.strip()
            if j < len(iface_out) and isinstance(iface_out[j], dict):
                iface_out[j]["name"] = label.strip()
        # "Show it as <type>" (owner 2026-11-23): only the PUBLIC socket type changes; the real type stays in `api`
        # and check_public / review_outputs verify that the output really carries exactly that type
        t = shown.get(f"{o.get('node')}#{o.get('slot')}")
        if isinstance(t, str) and t.strip() and j < len(iface_out) and isinstance(iface_out[j], dict):
            iface_out[j]["type"] = t.strip().upper()
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
    refused = capability_refusal()             # L9.341: fail closed when a critical protection is not working
    if refused:
        raise ConcealError(refused)
    out_types = [o.get("type") for o in (_api(plain).get("outputs") or []) if isinstance(o, dict)]
    out_types += [s.get("type") for s in (_iface(plain).get("out") or []) if isinstance(s, dict)]
    # what sealing has always refused (a vault sealed before 2026-11-23 keeps running as it did); everything else -
    # wildcards and newly recognised model types included - is checked by VALUE when it runs (guard_outputs)
    if any(str(t).upper() in _SEALING_V1_MODEL_TYPES for t in out_types if t is not None):
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


# ── run time: the vault's outputs are checked BEFORE they leave (owner 2026-11-23, defence in depth) ──────────
# A concealed vault's expansion routes every inner output through one H2Vault_OutputCheck node, which refuses a
# value that is or contains a model (torch module, ComfyUI model wrapper, anything with weights to save). This is
# what lets a wildcard output whose type cannot be traced be allowed at sealing.

OUTPUT_CHECK_TYPE = "H2Vault_OutputCheck"
REFUSED_PREFIX = "The protected workflow stopped its output"
# methods that give out weights: torch state_dict / parameters, ComfyUI ModelPatcher.model_state_dict, CLIP / VAE get_sd
_WEIGHT_METHODS = ("state_dict", "parameters", "named_parameters", "model_state_dict", "get_sd")
_MAX_DEPTH, _MAX_VISITS = 8, 20000


class H2VaultOutputRefused(RuntimeError):
    """A concealed vault's output carried a model. Its text names only the public socket label."""


OutputRefused = H2VaultOutputRefused


class _Budget(Exception):
    pass


def _carries_model(value) -> bool:
    """Is `value` a model, or does it contain one (dict / list / tuple / set values, dataclass fields, an object's
    attributes, a bound method's object, a closure's or partial's captured values)? Depth- and size-capped; a value
    past the caps (a very large list of tensors) is not refused - the type check at sealing still applies."""
    import sys as _sys
    torch = _sys.modules.get("torch")
    np = _sys.modules.get("numpy")
    tensor = getattr(torch, "Tensor", None) if torch is not None else None
    module = getattr(getattr(torch, "nn", None), "Module", None) if torch is not None else None
    seen: set = set()
    visits = [0]

    def walk(v, depth) -> bool:
        if v is None or isinstance(v, (str, bytes, bytearray, int, float, complex, bool, range)):
            return False
        if module is not None and isinstance(v, module):
            return True
        if tensor is not None and isinstance(v, tensor):
            return False
        if np is not None and isinstance(v, (np.ndarray, np.generic)):
            return False
        if isinstance(v, type):
            return False
        if id(v) in seen:
            return False
        seen.add(id(v))
        visits[0] += 1
        if visits[0] > _MAX_VISITS:
            raise _Budget
        cls = type(v)
        if any(callable(getattr(cls, m, None)) for m in _WEIGHT_METHODS):
            return True
        if depth >= _MAX_DEPTH:
            return False
        if isinstance(v, dict):
            return any(walk(x, depth + 1) for x in list(v.values()))
        if isinstance(v, (list, tuple, set, frozenset)) or cls.__name__ == "deque":
            return any(walk(x, depth + 1) for x in list(v))
        kids = []
        if hasattr(v, "__self__") and not isinstance(getattr(v, "__self__", None), type(_sys)):
            kids.append(getattr(v, "__self__", None))          # a bound method carries its object
        for c in getattr(v, "__closure__", None) or ():
            try:
                kids.append(c.cell_contents)
            except ValueError:
                pass
        if cls.__name__ == "partial":
            kids += [getattr(v, "func", None), getattr(v, "args", ()), getattr(v, "keywords", None)]
        try:
            kids += list(vars(v).values())
        except TypeError:
            pass
        for slot in getattr(cls, "__slots__", ()) or ():
            if isinstance(slot, str) and hasattr(v, slot):
                kids.append(getattr(v, slot, None))
        return any(walk(x, depth + 1) for x in kids)

    try:
        return walk(value, 0)
    except _Budget:
        log.debug("[H2Vault] output check: value too large to walk completely")
        return False
    except RecursionError:
        return False


def check_output_value(value, label: str) -> None:
    if _carries_model(value):
        raise H2VaultOutputRefused(
            f"{REFUSED_PREFIX} \"{str(label)[:80]}\" because it carries a model, which could be saved and identified. "
            "Ask the workflow's author for a copy without that output.")


class _AnyType(str):
    def __ne__(self, other):
        return False


class H2Vault_OutputCheck:
    """Internal: placed by a concealed H2Vault vault between its inside and each of its outputs (never added by
    hand). Passes the value on unchanged, or stops the run if the value carries a model."""

    CATEGORY = "H2Vault"
    FUNCTION = "check"
    RETURN_TYPES = (_AnyType("*"),)
    RETURN_NAMES = ("value",)
    INPUT_IS_LIST = True                       # one call sees every item of a list output, unchanged
    OUTPUT_IS_LIST = (True,)
    DEV_ONLY = True                            # hidden from the node library (core 0.39 node_info "dev_only")
    DESCRIPTION = ("Used inside a concealed H2Vault vault when it runs: lets the vault's output through unless it "
                   "carries a model. Added automatically; not for use in a workflow.")

    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {"value": (_AnyType("*"), {}), "label": ("STRING", {"default": ""})}}

    def check(self, value, label=None):
        name = label[0] if isinstance(label, list) and label else (label or "an output")
        for item in (value if isinstance(value, list) else [value]):
            check_output_value(item, str(name))
        return (value,)


def guard_outputs(plain, graph: dict, result: list, prefix: str, display_id) -> tuple:
    """Route every inner output of a CONCEALED vault's expansion through H2Vault_OutputCheck. Outputs that pass a
    boundary input straight on (an outer link) are the recipient's own value and are left as they are. Ordinary
    vaults are returned unchanged. -> (graph, result)."""
    if not is_concealed(plain):
        return graph, result
    socks = [s for s in (_iface(plain).get("out") or []) if isinstance(s, dict)]
    graph, result = dict(graph), list(result)
    for j, r in enumerate(result):
        if not (_is_link(r) and r[0] in graph):
            continue
        cid = f"{prefix}h2v_out{j}"
        label = str(socks[j].get("name") or f"Output {j + 1}") if j < len(socks) else f"Output {j + 1}"
        graph[cid] = {"class_type": OUTPUT_CHECK_TYPE, "inputs": {"value": list(r), "label": label},
                      "override_display_id": str(display_id)}
        result[j] = [cid, 0]
    return graph, result


# ── functional phase names (owner 2026-11-23): what a step DOES, in simple words, never what it is ─────────────
# Derived from a node's declared types (RETURN_TYPES / INPUT_TYPES / OUTPUT_NODE), never from its name, so the label
# set stays coarse and generic: it cannot single out a node pack or a model.
_MODEL_TYPES = {"MODEL", "CLIP", "VAE", "CONTROL_NET", "UPSCALE_MODEL", "CLIP_VISION", "STYLE_MODEL", "GLIGEN",
                "PHOTOMAKER", "SAM_MODEL", "BBOX_DETECTOR", "SEGM_DETECTOR"}


def _type_name(r) -> str:
    return str(getattr(r, "value", r)).upper()


def _declared(cls):
    """(output types, input types, output node?) from a V1 class or a V3 schema node (GET_NODE_INFO_V1)."""
    ret, req, out_node = set(), set(), bool(getattr(cls, "OUTPUT_NODE", False))
    info = None
    if cls is not None and hasattr(cls, "GET_NODE_INFO_V1"):
        try:
            info = cls.GET_NODE_INFO_V1()
        except Exception:  # noqa: BLE001
            info = None
    if isinstance(info, dict):
        ret = {_type_name(r) for r in (info.get("output") or []) if isinstance(r, (str,)) or hasattr(r, "value")}
        spec = info.get("input") or {}
        out_node = out_node or bool(info.get("output_node"))
    else:
        try:
            ret = {_type_name(r) for r in (getattr(cls, "RETURN_TYPES", ()) or ())
                   if isinstance(r, str) or hasattr(r, "value")}
        except Exception:  # noqa: BLE001
            ret = set()
        try:
            spec = cls.INPUT_TYPES() if cls is not None else {}
        except Exception:  # noqa: BLE001 - a broken INPUT_TYPES says nothing
            spec = {}
    for section in ("required", "optional"):
        for v in ((spec or {}).get(section) or {}).values():
            if isinstance(v, (tuple, list)) and v and (isinstance(v[0], str) or hasattr(v[0], "value")):
                req.add(_type_name(v[0]))
    return ret, req, out_node


def functional_label(cls) -> str:
    if cls is None:
        return "Processing"
    ret, req, out_node = _declared(cls)
    if out_node:
        return "Saving results"
    if ret & _MODEL_TYPES and not ret & {"IMAGE", "LATENT", "MASK"}:
        return "Loading models"
    if "LATENT" in ret and "MODEL" in req:
        return "Sampling"
    if "IMAGE" in ret and "LATENT" in req:
        return "Decoding"
    if "LATENT" in ret and "IMAGE" in req:
        return "Encoding"
    if "CONDITIONING" in ret:
        return "Preparing prompts"
    if "IMAGE" in ret and "UPSCALE_MODEL" in req:
        return "Upscaling"
    if "MASK" in ret:
        return "Masking"
    if "IMAGE" in ret:
        return "Processing image" if "IMAGE" in req else "Creating image"
    if "VIDEO" in ret:
        return "Processing video"
    if "AUDIO" in ret:
        return "Processing audio"
    if "LATENT" in ret:
        return "Preparing latents"
    return "Processing"


def _class_of(class_type):
    try:
        import nodes as core_nodes
        return core_nodes.NODE_CLASS_MAPPINGS.get(class_type)
    except Exception:  # noqa: BLE001 - outside ComfyUI
        return None


def _send_phase(data: dict) -> None:
    try:
        from server import PromptServer
        srv = PromptServer.instance
        srv.send_sync("h2vault.phase", data, getattr(srv, "client_id", None))
    except Exception:  # noqa: BLE001 - display only
        pass


def after_expansion(vault_id, plain, graph: dict, prefix: str, *, concealer: "Optional[Concealer]" = None) -> dict:
    """Post-process the expansion of a concealed vault and register it, so the filters can attribute its ids.
    A vault that is not concealed is only noted (V8: its inner outputs carry no prompt / workflow metadata either);
    its graph is returned unchanged."""
    c = concealer or CONCEALER
    if not is_concealed(plain):
        c.register_plain(str(vault_id), set(graph) if isinstance(graph, dict) else ())
        return graph
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
    phases = {nid: functional_label(_class_of(node.get("class_type"))) for nid, node in g.items()
              if isinstance(node, dict)}
    c.register(str(vault_id), set(g), previews & set(g), secret_terms(plain), phases=phases)
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
        self._plain: "OrderedDict[str, set]" = OrderedDict()       # V8: vaults that are not concealed -> inner ids
        self._active: set = set()
        self._window: Optional[str] = None
        self._last_executing: Optional[str] = None
        self._marker_open = False

    # registration / state
    def register(self, vault_id: str, inner_ids: Iterable[str], preview_ids: Iterable[str], terms: Iterable[str],
                 phases: Optional[dict] = None):
        with self._lock:
            self._vaults.pop(vault_id, None)
            self._plain.pop(vault_id, None)
            inner = set(map(str, inner_ids))
            phase_map = {str(k): str(v) for k, v in (phases or {}).items()}
            # V8: steps count distinct functional labels, never inner nodes (a node count is graph structure)
            self._vaults[vault_id] = {"inner": inner, "previews": set(map(str, preview_ids)),
                                      "low_terms": sorted({t.lower() for t in terms}, key=len, reverse=True),
                                      "phases": phase_map, "started": [], "seen": [], "last_label": None,
                                      "total": max(1, len(set(phase_map.values())))}
            while len(self._vaults) > MAX_VAULTS:
                self._vaults.popitem(last=False)
            self._active.add(vault_id)

    def register_plain(self, vault_id: str, inner_ids: Iterable[str]) -> None:
        """V8: a vault that is not concealed. Only the metadata guard uses this (its inner outputs embed no prompt /
        workflow); the message filters leave such a vault to the A18 rules of protected_subgraph."""
        with self._lock:
            # the same outer node id may have been a CONCEALED vault in an earlier prompt (core's expansion ids are
            # deterministic: "<vault>.0.0.<inner>"): that stale registration must not half-apply to this vault
            self._vaults.pop(vault_id, None)
            self._active.discard(vault_id)
            self._plain.pop(vault_id, None)
            self._plain[vault_id] = set(map(str, inner_ids))
            while len(self._plain) > MAX_VAULTS:
                self._plain.popitem(last=False)

    def is_concealed_vault(self, vault_id: str) -> bool:
        return vault_id in self._vaults

    def any_registered(self) -> bool:
        return bool(self._vaults)

    @staticmethod
    def _lookup(table: dict, node_id, inner_of: Callable[[Any], set]) -> Optional[str]:
        if not isinstance(node_id, str) or "." not in node_id:
            return None
        best = None
        for v, info in list(table.items()):              # a copy: another thread may register meanwhile
            if not node_id.startswith(v + "."):
                continue
            inner = inner_of(info)
            hit = node_id in inner or any(node_id.startswith(i + ".") for i in inner)
            if hit and (best is None or len(v) < len(best)):
                best = v                                     # the outermost vault wins
        return best

    def vault_of(self, node_id) -> Optional[str]:
        """Structural attribution: the concealed vault whose expansion made this id (or an expansion inside it)."""
        return self._lookup(self._vaults, node_id, lambda info: info["inner"])

    def protected_vault_of(self, node_id) -> Optional[str]:
        """Any vault (concealed or not) whose expansion made this id."""
        v = self.vault_of(node_id)
        if v is not None:
            return v
        with self._lock:
            plain = dict(self._plain)
        return self._lookup(plain, node_id, lambda inner: inner)

    def on_node_start(self, node_id) -> None:
        event = None
        with self._lock:
            self._window = self.vault_of(str(node_id)) if node_id is not None else None
            info = self._vaults.get(self._window) if self._window else None
            if info is not None:
                nid = str(node_id)
                key = next((i for i in info["inner"] if nid == i or nid.startswith(i + ".")), nid)
                if key not in info["started"]:
                    info["started"].append(key)
                label = info["phases"].get(key, "Processing")
                if label != info["last_label"]:            # one event per change of label, not per node
                    info["last_label"] = label
                    if label not in info["seen"]:
                        info["seen"].append(label)
                    event = {"vault": self._window, "label": label, "step": len(info["seen"]),
                             "total": max(info["total"], len(info["seen"]))}
        if event is not None and _probing() is None:       # the security self-test never reaches a client
            _send_phase(event)

    def current_label(self, vault_id) -> Optional[str]:
        info = self._vaults.get(str(vault_id))
        return info.get("last_label") if info else None

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
            raw = str(d.get("exception_message") or "")
            if str(d.get("exception_type") or "").endswith(H2VaultOutputRefused.__name__) and \
                    raw.startswith(REFUSED_PREFIX):
                # the vault's own output check: its text names only a public socket label - say what happened
                d.update({"exception_type": CONCEALED_EXCEPTION_TYPE, "exception_message": raw[:400],
                          "traceback": [], "current_inputs": {}, "current_outputs": []})
                return d
            if "out of memory" in text or "outofmemory" in text:
                msg = MSG_OOM
            elif "filenotfound" in text or "no such file" in text or "not found" in text:
                msg = MSG_MISSING
            else:
                msg = MSG_FAILED
            label = self.current_label(v)                   # V8: the functional label of the failing step only
            if label:
                msg = f"{msg} (failed step: {label})"
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
            pv = _previews_module()
            if pv is not None:                                  # one entry per vault, with the running step
                d["nodes"] = pv.collapse_progress(d.get("nodes") or {}, self.vault_of)
                return d
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
            merged = _collect_preview(v, str(node), self._reduce_ui(d.get("output")), live)
            if merged is None:
                return DROP
            d["output"] = merged
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
            if str(k) not in self._vaults[vault]["previews"] or not _preview_shown(vault):
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


def _previews_module():
    """nodes/previews.py when this module is part of the package (a copy loaded by file path, in tests, has none)."""
    try:
        from . import previews
        return previews
    except Exception:  # noqa: BLE001
        return None


def _preview_shown(vault_id) -> bool:
    pv = _previews_module()
    return True if pv is None else pv.HUB.show(vault_id)


def _collect_preview(vault_id, inner_id, output, live: bool):
    """A declared preview of a concealed vault -> the vault's merged previews (owner 2026-11-23), or None when the
    author turned previews off. Without the preview hub: the reduced output as before."""
    pv = _previews_module()
    if pv is None:
        return output
    if not live:
        return output if pv.HUB.show(vault_id) else None
    merged = pv.HUB.collect(vault_id, inner_id, output)
    return None if type(merged).__name__ == "_Drop" else merged


# ── V8: zero-information guards that do not depend on a websocket message ────────────────────────────────────

_METADATA_HIDDEN = {"PROMPT": {}, "EXTRA_PNGINFO": None}       # V1 hidden type -> what an inner node receives
_METADATA_HIDDEN_V3 = {"prompt": {}, "extra_pnginfo": None}     # io.Hidden member name -> the same


def strip_metadata(class_def, result):
    """core `get_input_data` result for a node INSIDE a vault -> the same without the prompt / workflow that save and
    preview nodes embed in their files (PNG text chunks, video metadata). Every other value is untouched."""
    if not isinstance(result, tuple) or not result:
        return result
    input_data_all = result[0]
    try:
        hidden = class_def.INPUT_TYPES().get("hidden") or {}
    except Exception:  # noqa: BLE001 - a V3 node's hidden inputs are in v3_data below
        hidden = {}
    if isinstance(input_data_all, dict) and isinstance(hidden, dict):
        for name, kind in hidden.items():
            if kind in _METADATA_HIDDEN and name in input_data_all:
                input_data_all[name] = [copy.copy(_METADATA_HIDDEN[kind])]
    if len(result) >= 3 and isinstance(result[2], dict):
        h3 = result[2].get("hidden_inputs")
        if isinstance(h3, dict):
            for k in list(h3):
                name = str(getattr(k, "name", k))
                if name in _METADATA_HIDDEN_V3:
                    h3[k] = copy.copy(_METADATA_HIDDEN_V3[name])
    return result


def metadata_guard(orig, *, concealer: "Optional[Concealer]" = None):
    """Wrap core `execution.get_input_data`: a node inside any vault gets no prompt / workflow to embed. Fails
    CLOSED: if the strip itself fails, the node does not run (an inner save would otherwise write the metadata)."""
    c = concealer or CONCEALER

    def get_input_data(inputs, class_def, unique_id, *a, **k):
        result = orig(inputs, class_def, unique_id, *a, **k)
        if _cur(c).protected_vault_of(None if unique_id is None else str(unique_id)) is None:
            return result
        try:
            return strip_metadata(class_def, result)
        except Exception:  # noqa: BLE001
            raise RuntimeError("H2Vault could not withhold a protected step's file metadata, so the step did not "
                               "run.") from None

    get_input_data.__h2vault_guard__ = True
    return get_input_data


def attach_root_filter(flt: logging.Filter) -> list:
    """Attach a logging filter where every record passes: the root logger (records logged on it) and every root handler
    (records propagated from child loggers skip the root LOGGER's filters). Shared by V5's locked-value redaction
    (protected_subgraph.install_log_redaction) and V8's window filter. -> the objects it was attached to."""
    root = logging.getLogger()
    out = []
    for t in [root, *root.handlers]:
        if flt not in t.filters:
            t.addFilter(flt)
            out.append(t)
    return out


class WindowLogFilter(logging.Filter):
    """V8: a logging filter for handlers that write formatted records directly (core `--verbose LEVEL FILE` file
    logs, any other root handler): inside a Concealed Window a record becomes the concealed marker, without its
    arguments or traceback. Outside the window nothing is touched (no oracle)."""

    def __init__(self, concealer: "Optional[Concealer]" = None):
        super().__init__("h2vault.window")
        self.c = concealer or CONCEALER

    def filter(self, record):
        try:
            cc = _cur(self.c)                       # the self-test's own concealer while it probes
            if cc.window is not None and cc.rules.get("logs", True):
                record.msg, record.args = CONCEALED_LOG_LINE, None
                record.exc_info = record.exc_text = record.stack_info = None
        except Exception:  # noqa: BLE001 - never break logging
            pass
        return True


_HASH_NAME_RE = re.compile(r"^h2v[\\/]")                  # provision.HASH_DIR: V7 hash-named model copies
_HASH_SCRUB_EXACT = {"/object_info", "/embeddings", "/api/assets"}
_HASH_SCRUB_PREFIX = ("/object_info/", "/models/", "/experiment/models/")
_HASH_NAME_KEYS = ("name", "loader_path", "filename", "path")


def _is_hash_name(s) -> bool:
    return isinstance(s, str) and bool(_HASH_NAME_RE.match(s))


def scrub_hash_names(obj):
    """Drop every V7 hash-named model file (``h2v/<sha256 prefix>.<ext>``) from a JSON listing: a SHA-256 prefix is
    a public lookup key (model sites search by hash), so the name alone would identify a vault's model. -> (new, n
    removed)."""
    removed = 0

    def walk(o):
        nonlocal removed
        if isinstance(o, list):
            out = []
            for x in o:
                if _is_hash_name(x) or (isinstance(x, dict) and any(_is_hash_name(x.get(k)) for k in _HASH_NAME_KEYS)):
                    removed += 1
                    continue
                out.append(walk(x))
            return out
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items() if not _is_hash_name(v)}
        return o

    new = walk(obj)
    return new, removed


# Per-node routes of co-installed packs that list / describe nodes by id (CNP Tensor Inspector: an index of node ids and
# each node's output shapes and types). Inner vault ids are dropped from the index; a query naming one is refused.
_NODE_ID_INDEXES = {"/mec/tensor_snapshot/index": ("data", "node_ids")}
_NODE_ID_QUERY_KEYS = ("node_id", "node", "id", "unique_id")


def hash_folder_middleware(*, concealer: "Optional[Concealer]" = None):
    """aiohttp middleware (every profile, not only Hosted): model listings never show the hash-named copies a vault
    downloaded, and their safetensors metadata / previews are not served; per-node routes of other packs never list or
    describe a node inside a vault. Vault runs are unaffected - the server resolves those names itself."""
    from aiohttp import web
    import json as _json
    c = concealer or CONCEALER

    def not_found():
        return web.json_response({"error": "Not found."}, status=404)

    @web.middleware
    async def h2vault_hash_folder_guard(request, handler):
        if request.method != "GET":
            return await handler(request)
        path = request.path
        p = path[4:] if path.startswith("/api/") and not path.startswith("/api/assets") else path
        if p.startswith("/view_metadata/") and _is_hash_name(request.query.get("filename", "")):
            return not_found()
        if p.startswith("/experiment/models/preview/") and re.search(r"/\d+/h2v[\\/]", p):
            return not_found()
        if any(_cur(c).protected_vault_of(request.query.get(k)) is not None for k in _NODE_ID_QUERY_KEYS):
            return not_found()                               # V8: a node inside a vault is not described by id
        resp = await handler(request)
        if p in _NODE_ID_INDEXES:
            return _scrub_node_index(resp, _NODE_ID_INDEXES[p], c, web, _json)
        if not (p in _HASH_SCRUB_EXACT or p.startswith(_HASH_SCRUB_PREFIX)):
            return resp
        body = getattr(resp, "body", None)
        if not isinstance(body, (bytes, bytearray)) or not (b'"h2v/' in body or b'"h2v\\\\' in body):
            return resp
        try:
            data = _json.loads(bytes(body))
        except Exception:  # noqa: BLE001 - not JSON: nothing this guard understands, refuse rather than leak
            return not_found()
        data, removed = scrub_hash_names(data)
        if isinstance(data, dict) and isinstance(data.get("total"), int):
            data["total"] = max(0, data["total"] - removed)
        return web.json_response(data, status=resp.status)

    return h2vault_hash_folder_guard


def _scrub_node_index(resp, keys, c, web, _json):
    body = getattr(resp, "body", None)
    if not isinstance(body, (bytes, bytearray)):
        return resp
    try:
        data = _json.loads(bytes(body))
        holder = data
        for k in keys[:-1]:
            holder = holder[k]
        ids = holder[keys[-1]]
        if not isinstance(ids, list):
            return resp
    except Exception:  # noqa: BLE001 - not the shape this guard knows: leave it
        return resp
    holder[keys[-1]] = [i for i in ids if _cur(c).protected_vault_of(str(i)) is None]
    return web.json_response(data, status=resp.status)


# ── security capability registry (L9.341, roadmap item 1): fail closed ──────────────────────────────────────
# Every protection install() puts in place is a capability: installed, then EXERCISED by a self-test that sends a
# synthetic probe through the real hook (never to a client), and re-checked cheaply before each concealed run. A
# concealed vault does not run while a critical capability is not working; Hosted mode does not start.

ACTIVE, FAILED, UNAVAILABLE, NOT_NEEDED, OFF, NOT_CHECKED = (
    "active", "failed", "unavailable", "not_needed", "off", "not_checked")
_OK_STATES = frozenset({ACTIVE, NOT_NEEDED, OFF})

# (id, label, critical, what it protects - plain words for the diagnostics panel)
CAPABILITY_SPEC = (
    ("vault_filter", "Vault message filter", True,
     "inner node ids, types and locked values of every vault in messages and history"),
    ("messages", "Concealed message filter", True,
     "what the inner steps of a concealed vault say over the websocket"),
    ("previews", "Preview concealment", True,
     "file paths and inner ids of previews shown from inside a concealed vault"),
    ("history", "History filter", True, "inner outputs and ids kept in the queue history"),
    ("progress", "Concealed step window", True,
     "knowing which concealed step runs (console and log concealment depend on it)"),
    ("log_streams", "Console and log-feed filter", True,
     "print output of inner steps (console, /internal/logs, the logs feed)"),
    ("log_records", "Log record filter", True, "log records of inner steps, log files included"),
    ("cache_keys", "Cache-key window", True,
     "warnings ComfyUI writes while it computes an inner step's cache key"),
    ("metadata", "File metadata guard", True,
     "the prompt and workflow that save and preview nodes embed in their files"),
    ("listings", "Model listing guard", True,
     "hash-named model copies in model lists, and per-node routes of other packs"),
    ("hosted", "Hosted mode restrictions", True,
     "model lists, logs and model routes withheld from every client; only allowed node types run"),
    ("preview_replay", "Cached preview replay", False,
     "previews of a vault that ComfyUI served from its cache (display only)"),
)
_SPEC = {s[0]: s for s in CAPABILITY_SPEC}
ACTION_UPDATE = ("Update H2Vault and ComfyUI, restart ComfyUI, then run this check again. If it still fails, "
                 "report this ComfyUI version to H2Vault.")
_ACTIONS = {
    "vault_filter": "Restart ComfyUI. If it still fails, check the console for the H2Vault start-up message.",
    "hosted": "Hosted mode cannot start without these restrictions: fix the problem shown, or turn hosted mode off "
              "(H2VAULT_HOSTED).",
    "preview_replay": "Optional: only cached runs lose their previews. Updating H2Vault may restore it.",
}


class HostedStartRefused(SystemExit):
    """Hosted mode was asked for but a mandatory restriction is not working: ComfyUI must not start (it would serve
    protected workflows without their protection). SystemExit passes core's `except Exception` in load_custom_node."""


class Capabilities:
    """The registry: per capability a status (ACTIVE, FAILED, UNAVAILABLE, NOT_NEEDED, OFF, NOT_CHECKED) and a short
    detail in plain words (never a name from inside a vault)."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.attempted = False                 # install() ran against a real server
            self.hosted = False
            self.checked_at: Optional[float] = None
            self._state = {cid: {"status": NOT_CHECKED, "detail": ""} for cid in _SPEC}

    def set(self, cid: str, status: str, detail: str = "") -> None:
        with self._lock:
            self._state[cid] = {"status": status, "detail": str(detail or "")[:300]}

    def status(self, cid: str) -> str:
        return self._state[cid]["status"]

    def detail(self, cid: str) -> str:
        return self._state[cid]["detail"]

    def is_critical(self, cid: str) -> bool:
        return bool(_SPEC[cid][2]) and (cid != "hosted" or self.hosted)

    def missing(self) -> list:
        """Critical capabilities that are not working, in registry order."""
        return [cid for cid in _SPEC if self.is_critical(cid) and self._state[cid]["status"] not in _OK_STATES]

    def refusal(self) -> Optional[str]:
        """Plain-English reason + next step when concealed execution must be refused; None when it may run."""
        if not self.attempted:
            return None                            # no server: nothing can reach a client
        miss = self.missing()
        if not miss:
            return None
        cid = miss[0]
        why = self.detail(cid) or "it did not pass its start-up check"
        more = f" ({len(miss) - 1} more protection{'s' if len(miss) > 2 else ''} also failed)" if len(miss) > 1 else ""
        return (f"H2Vault did not run this protected workflow: its protection \"{_SPEC[cid][1]}\" is not working on "
                f"this ComfyUI ({why}){more}. Running it could reveal what is inside. Next step: update H2Vault, "
                "restart ComfyUI, then open the H2Vault menu > Security check to see what is missing.")

    def report(self) -> dict:
        with self._lock:
            state = {k: dict(v) for k, v in self._state.items()}
        caps = []
        for cid, label, critical, protects in CAPABILITY_SPEC:
            st = state[cid]
            crit = bool(critical) and (cid != "hosted" or self.hosted)
            ok = st["status"] in _OK_STATES
            caps.append({"id": cid, "label": label, "critical": crit, "status": st["status"], "ok": ok,
                         "detail": st["detail"], "protects": protects,
                         "action": "" if ok else _ACTIONS.get(cid, ACTION_UPDATE)})
        return {"attempted": self.attempted, "hosted": self.hosted, "checked_at": self.checked_at,
                "refusal": self.refusal(), "capabilities": caps}


CAPABILITIES = Capabilities()

# The self-test's probe: a synthetic vault that exists only while a probe runs, in THIS thread's probe mode.
PROBE_SID = "h2vault-selftest"
PROBE_VAULT = "h2vault-selftest"
PROBE_INNER = PROBE_VAULT + ".0.0.1"
PROBE_PREVIEW = PROBE_VAULT + ".0.0.2"
PROBE_TERM = "h2vault-selftest-secret-term"
PROBE_ITEM = "h2vault-selftest-item"
PROBE_FILE = "h2vault-selftest.png"
PROBE_LOG_LINE = "H2Vault security self-test line"
_PROBE = threading.local()


def _probing() -> Optional[list]:
    """The probe sink of this thread while a self-test runs, else None."""
    return getattr(_PROBE, "sink", None)


class _ProbeScope:
    """Probe mode for THIS thread: the wrappers use a private Concealer that knows only the probe vault (`_cur`), so
    the real concealer's vaults, window and executing state are never read or written by a probe - a prompt running
    in another thread meanwhile is not affected, and two probes in two threads do not see each other."""

    def __init__(self, c: "Concealer"):
        self.c = c

    def __enter__(self) -> list:
        pc = Concealer()
        pc.rules = dict(self.c.rules)
        pc._vaults[PROBE_VAULT] = {"inner": {PROBE_INNER, PROBE_PREVIEW}, "previews": {PROBE_PREVIEW},
                                   "low_terms": [PROBE_TERM], "phases": {PROBE_INNER: "Processing",
                                                                         PROBE_PREVIEW: "Saving results"},
                                   "started": [], "seen": [], "last_label": None, "total": 1}
        pc._active.add(PROBE_VAULT)
        _PROBE.concealer, _PROBE.sink = pc, []
        return _PROBE.sink

    def __exit__(self, *exc):
        _PROBE.sink = _PROBE.concealer = None
        return False


def _cur(c: "Concealer") -> "Concealer":
    """The concealer a wrapper uses now: the self-test's private one while this thread probes, else `c`."""
    pc = getattr(_PROBE, "concealer", None)
    return pc if pc is not None else c


def _pc() -> "Concealer":
    return _PROBE.concealer


class _ProbeStop(Exception):
    pass


class _ProbeObj:
    """Stands in for a core object (`self` of a wrapped method): the first attribute the ORIGINAL method reads calls
    `hit` and stops it, so the original never acts on anything real."""

    def __init__(self, hit: Optional[Callable[[], None]] = None):
        object.__setattr__(self, "_h2v_hit", hit)

    def __getattr__(self, name):
        hit = object.__getattribute__(self, "_h2v_hit")
        if hit is not None:
            hit()
        raise _ProbeStop(name)


def _drive(coro):
    """Run a coroutine that must not wait on I/O (the guards under test answer at once) without an event loop."""
    try:
        coro.send(None)
    except StopIteration as stop:
        return stop.value
    coro.close()
    raise RuntimeError("the guard waited on I/O during the self-test")


class _ProbeRequest:
    def __init__(self, method: str, path: str, query: Optional[dict] = None, body=None):
        self.method, self.path, self.query, self._body = method, path, dict(query or {}), body

    async def json(self):
        return self._body


def _why(exc: BaseException) -> str:
    return f"its check raised {type(exc).__name__}"


# ── the probes (each returns (status, detail)) ────────────────────────────────────────────────────────────

OUTER_TEXT = ("works; note: another extension wraps this hook outside H2Vault and sees what passes through it before H2Vault filters it (code in the same process is outside any filter)")
_PROBE_LOCK = threading.RLock()            # one self-test / re-check at a time (the registry is shared)


def _probe_messages(server, c) -> dict:
    """Send synthetic messages through the server's REAL send_sync chain with the probe session id (core would send
    them to no client: no such socket). Our wrapper records what it would forward instead of forwarding it."""
    nid = PROBE_INNER.encode("utf-8")
    sends = [
        ("executing", {"node": PROBE_INNER, "display_node": PROBE_INNER, "prompt_id": PROBE_ITEM}),
        ("executed", {"node": PROBE_INNER, "display_node": PROBE_INNER, "prompt_id": PROBE_ITEM,
                      "output": {"text": [PROBE_TERM]}}),
        (3, struct.pack(">I", len(nid)) + nid + PROBE_TERM.encode("utf-8")),
        ("h2vault.selftest", {"node_id": PROBE_INNER, "text": PROBE_TERM}),
        ("executed", {"node": PROBE_PREVIEW, "display_node": PROBE_PREVIEW, "prompt_id": PROBE_ITEM,
                      "output": {"images": [{"filename": PROBE_FILE, "subfolder": "", "type": "temp",
                                             "fullpath": f"/{PROBE_TERM}/{PROBE_FILE}"}]}}),
    ]
    with _ProbeScope(c) as sink:
        for ev, data in sends:
            try:
                server.send_sync(ev, data, PROBE_SID)
            except Exception as exc:  # noqa: BLE001
                sink.append(("error", ev, _why(exc)))
    got = [r for r in sink if r[0] == "send"]
    out = {}
    if len(got) != len(sends):
        detail = "the message hook is no longer in place" if not got else "a message took another path"
        return {"messages": (FAILED, detail), "previews": (FAILED, detail)}
    first, *dropped, preview = [r[2] for r in got]
    ok_exec = isinstance(first, dict) and first.get("node") == PROBE_VAULT and PROBE_INNER not in repr(first)
    ok_drop = all(d is DROP for d in dropped)
    outer = "" if getattr(server, "send_sync", None) is _INSTALL.get("send_fn") else OUTER_TEXT
    out["messages"] = (ACTIVE, outer) if ok_exec and ok_drop else (
        FAILED, "an inner step's message was not re-addressed or withheld")
    text = repr(preview)
    ok_prev = (isinstance(preview, dict) and preview.get("node") == PROBE_VAULT and PROBE_TERM not in text
               and PROBE_INNER not in text and PROBE_PREVIEW not in text and PROBE_FILE in text)
    out["previews"] = (ACTIVE, "") if ok_prev else (FAILED, "a preview kept an inner id or a file path")
    return out


def _probe_history(server, c):
    q = getattr(server, "prompt_queue", None)
    if q is None or not hasattr(q, "task_done"):
        return UNAVAILABLE, "this ComfyUI has no prompt queue H2Vault can filter"
    hist = {"outputs": {PROBE_INNER: {"text": [PROBE_TERM]},
                        PROBE_PREVIEW: {"images": [{"filename": PROBE_FILE, "subfolder": "", "type": "temp"}]}},
            "meta": {PROBE_INNER: {"node_id": PROBE_INNER, "display_node": PROBE_INNER}}}
    status = {"status_str": "success", "messages": [("executing", {"node": PROBE_INNER, "prompt_id": PROBE_ITEM})]}
    with _ProbeScope(c) as sink:
        try:
            q.task_done(PROBE_ITEM, hist, status)
        except Exception as exc:  # noqa: BLE001 - core's own task_done refuses an unknown item: hook not reached
            sink.append(("error", _why(exc)))
    got = [r for r in sink if r[0] == "history"]
    if not got:
        return FAILED, "the history hook is no longer in place"
    _, h, st = got[0]
    text = repr((h, st))
    ok = (isinstance(h, dict) and list((h.get("outputs") or {})) == [PROBE_VAULT]
          and PROBE_INNER not in text and PROBE_PREVIEW not in text and PROBE_TERM not in text)
    outer = "" if getattr(q, "task_done", None) is _INSTALL.get("queue_fn") else OUTER_TEXT
    return (ACTIVE, outer) if ok else (FAILED, "the history kept an inner output or id")


def _probe_progress(c):
    try:
        from comfy_execution.progress import ProgressRegistry
    except Exception:  # noqa: BLE001
        return UNAVAILABLE, "this ComfyUI has no progress registry"
    with _ProbeScope(c) as sink:
        try:
            ProgressRegistry.start_progress(_ProbeObj(), PROBE_INNER)
        except Exception:  # noqa: BLE001 - the original method stopped by the probe object: hook not reached
            pass
    got = [r for r in sink if r[0] == "progress"]
    return (ACTIVE, "") if got and got[0][1] == PROBE_VAULT else (
        FAILED, "the step-start hook is no longer in place")


def _probe_cache_keys(c):
    try:
        import execution as core_execution
        icc = core_execution.IsChangedCache
    except Exception:  # noqa: BLE001
        return UNAVAILABLE, "this ComfyUI has no cache-key step H2Vault knows"
    with _ProbeScope(c) as sink:
        pc = _pc()
        before = pc.window
        obj = _ProbeObj(lambda: sink.append(("cache_key", pc.window)))
        try:
            _drive(icc.get(obj, PROBE_INNER))
        except Exception:  # noqa: BLE001 - _ProbeStop from the original method, or a changed core
            pass
        after = pc.window
    seen = [r[1] for r in sink if r[0] == "cache_key"]
    if not seen:
        return FAILED, "the cache-key step changed in this ComfyUI"
    return (ACTIVE, "") if seen[0] == PROBE_VAULT and after == before else (
        FAILED, "the cache-key hook is no longer in place")


class _ProbeNode:
    """A V1 class with the hidden inputs save / preview nodes use."""

    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {}, "hidden": {"prompt": "PROMPT", "extra_pnginfo": "EXTRA_PNGINFO"}}


class _ProbeDyn:
    def get_original_prompt(self):
        return {PROBE_VAULT: {"class_type": PROBE_TERM, "inputs": {}}}


def _probe_metadata(c):
    try:
        import execution as core_execution
        gid = core_execution.get_input_data
    except Exception:  # noqa: BLE001
        return UNAVAILABLE, "this ComfyUI has no input step H2Vault knows"
    with _ProbeScope(c):
        try:
            out = gid({}, _ProbeNode, PROBE_INNER, None, dynprompt=_ProbeDyn(),
                      extra_data={"extra_pnginfo": {"workflow": PROBE_TERM}})
        except Exception as exc:  # noqa: BLE001
            return FAILED, _why(exc)
    data = out[0] if isinstance(out, tuple) and out else None
    ok = isinstance(data, dict) and data.get("prompt") == [{}] and data.get("extra_pnginfo") == [None]
    return (ACTIVE, "") if ok else (FAILED, "a protected step would still receive the workflow to embed")


def _interceptors() -> Optional[list]:
    try:
        import app.logger as core_logger
    except Exception:  # noqa: BLE001
        return None
    return [s for s in (getattr(core_logger, "stdout_interceptor", None),
                        getattr(core_logger, "stderr_interceptor", None)) if s is not None]


def _probe_log_streams(c):
    streams = _interceptors()
    if not streams:
        return NOT_NEEDED, "this ComfyUI has no console log feed"
    with _ProbeScope(c) as sink:
        for s in streams:
            pc = _pc()
            with pc._lock:
                pc._window, pc._marker_open = PROBE_VAULT, False
            try:
                s.write(PROBE_LOG_LINE + "\n")
            except Exception as exc:  # noqa: BLE001
                sink.append(("error", _why(exc)))
    got = [r[1] for r in sink if r[0] == "log"]
    if len(got) != len(streams):
        return FAILED, "the console hook is no longer in place"
    ok = all(g == CONCEALED_LOG_LINE + "\n" for g in got)
    return (ACTIVE, "") if ok else (FAILED, "a console line was not concealed")


def _probe_log_records(c):
    got = _INSTALL.get("log_filters")
    if not got:
        return FAILED, "the log filter was not attached"
    flt = got[0]
    _INSTALL["log_filters"] = (flt, list(got[1]) + attach_root_filter(flt))     # handlers added since start-up
    root = logging.getLogger()
    bad = 0
    with _ProbeScope(c):
        pc = _pc()
        with pc._lock:
            pc._window = PROBE_VAULT
        for t in [root, *root.handlers]:
            rec = logging.LogRecord("h2vault.selftest", logging.WARNING, __file__, 0, PROBE_LOG_LINE + " %s",
                                    (PROBE_TERM,), None)
            kept = t.filter(rec)
            if kept and rec.msg != CONCEALED_LOG_LINE:
                bad += 1
    return (ACTIVE, "") if not bad else (FAILED, f"{bad} log destination(s) would print an inner step's record")


def _probe_middleware(server, key: str, hosted: bool):
    app = getattr(server, "app", None)
    mw = _INSTALL.get(key)
    if app is None:
        return (FAILED, "this server has no web app to restrict") if hosted else (
            NOT_NEEDED, "this server has no web routes")
    try:
        present = mw is not None and any(m is mw for m in list(app.middlewares))
    except Exception as exc:  # noqa: BLE001
        return FAILED, _why(exc)
    if not present:
        return FAILED, "the web guard is not in the server's request chain"
    try:
        from aiohttp import web
    except Exception:  # noqa: BLE001
        return FAILED, "aiohttp is not available"
    import json as _json
    try:
        if hosted:
            async def ok_handler(request):
                return web.json_response({"ok": True})
            r1 = _drive(mw(_ProbeRequest("GET", "/internal/logs"), ok_handler))
            r2 = _drive(mw(_ProbeRequest("POST", "/prompt", body={"prompt": {"1": {"class_type": PROBE_TERM}}}),
                           ok_handler))
            return (ACTIVE, "") if (r1.status, r2.status) == (403, 403) else (
                FAILED, "a restricted route or node type was let through")
        name = f"{HASH_DIR_NAME}/{'0' * 64}.safetensors"

        async def listing(request):
            return web.json_response({"Probe": {"input": {"required": {"ckpt_name": [[name, PROBE_FILE]]}}}})

        r = _drive(mw(_ProbeRequest("GET", "/object_info"), listing))
        text = _json.dumps(_json.loads(r.body))
        with _ProbeScope(_concealer()):
            r2 = _drive(mw(_ProbeRequest("GET", "/h2vault-selftest/node", {"node_id": PROBE_INNER}), listing))
        ok = name not in text and PROBE_FILE in text and r2.status == 404
        return (ACTIVE, "") if ok else (FAILED, "a hash-named model copy or an inner node would be listed")
    except Exception as exc:  # noqa: BLE001
        return FAILED, _why(exc)


HASH_DIR_NAME = "h2v"                      # provision.HASH_DIR (this module imports with the stdlib only)


def _concealer() -> "Concealer":
    return _INSTALL.get("concealer") or CONCEALER


def _vault_filter_state():
    try:
        from . import protected_subgraph as ps
    except Exception:  # noqa: BLE001 - this module loaded on its own (tests): the vault filter is not part of it
        return NOT_NEEDED, "not part of this module copy"
    return (ACTIVE, "") if getattr(ps, "_installed", False) else (FAILED, "it was not installed at start-up")


def _preview_replay_state():
    try:
        import execution as core_execution
    except Exception:  # noqa: BLE001
        return NOT_NEEDED, "outside ComfyUI"
    return (ACTIVE, "") if getattr(getattr(core_execution, "execute", None), "__h2vault_previews__", False) else (
        UNAVAILABLE, "ComfyUI's executor could not be wrapped")


def run_selftest(server=None, c: Optional["Concealer"] = None) -> dict:
    """Exercise every installed hook with the probe and record the results. -> CAPABILITIES.report()."""
    with _PROBE_LOCK:
        return _run_selftest(server, c)


def _run_selftest(server=None, c: Optional["Concealer"] = None) -> dict:
    server = server if server is not None else _INSTALL.get("server")
    c = c or _concealer()
    if server is None or not CAPABILITIES.attempted:
        return CAPABILITIES.report()
    _record("vault_filter", _vault_filter_state)
    try:
        for cid, res in _probe_messages(server, c).items():
            CAPABILITIES.set(cid, *res)
    except Exception as exc:  # noqa: BLE001
        CAPABILITIES.set("messages", FAILED, _why(exc))
        CAPABILITIES.set("previews", FAILED, _why(exc))
    _record("history", lambda: _probe_history(server, c))
    _record("progress", lambda: _probe_progress(c))
    _wrap_streams(c)                                  # a console feed created since start-up is covered too
    _record("log_streams", lambda: _probe_log_streams(c))
    _record("log_records", lambda: _probe_log_records(c))
    _record("cache_keys", lambda: _probe_cache_keys(c))
    _record("metadata", lambda: _probe_metadata(c))
    _record("listings", lambda: _probe_middleware(server, "listing_mw", hosted=False))
    if CAPABILITIES.hosted:
        _record("hosted", lambda: _probe_middleware(server, "hosted_mw", hosted=True))
    else:
        CAPABILITIES.set("hosted", OFF, "hosted mode is off")
    _record("preview_replay", _preview_replay_state)
    CAPABILITIES.checked_at = time.time()
    return CAPABILITIES.report()


def _record(cid: str, probe: Callable[[], tuple]) -> None:
    try:
        CAPABILITIES.set(cid, *probe())
    except Exception as exc:  # noqa: BLE001 - a probe that breaks fails its capability (fail closed)
        CAPABILITIES.set(cid, FAILED, _why(exc))


def check_liveness() -> None:
    """Cheap re-check before a concealed run (and for the diagnostics panel): a hook that is no longer the one
    install() put in place is probed again; log handlers / console feeds added since start-up are covered now."""
    with _PROBE_LOCK:
        _check_liveness()


def _check_liveness() -> None:
    server = _INSTALL.get("server")
    if server is None or not CAPABILITIES.attempted:
        return
    c = _concealer()
    if "send" in _INSTALL and getattr(server, "send_sync", None) is not _INSTALL.get("send_fn"):
        try:
            for cid, res in _probe_messages(server, c).items():
                CAPABILITIES.set(cid, *res)
        except Exception as exc:  # noqa: BLE001
            CAPABILITIES.set("messages", FAILED, _why(exc))
    q = getattr(server, "prompt_queue", None)
    if "queue" in _INSTALL and getattr(q, "task_done", None) is not _INSTALL.get("queue_fn"):
        _record("history", lambda: _probe_history(server, c))
    if "progress" in _INSTALL:
        cls = _INSTALL["progress"][0]
        if getattr(cls, "start_progress", None) is not _INSTALL.get("progress_fn"):
            _record("progress", lambda: _probe_progress(c))
    if "is_changed" in _INSTALL:
        cls = _INSTALL["is_changed"][0]
        if getattr(cls, "get", None) is not _INSTALL.get("is_changed_fn"):
            _record("cache_keys", lambda: _probe_cache_keys(c))
    if "metadata" in _INSTALL:
        mod = _INSTALL["metadata"][0]
        if getattr(mod, "get_input_data", None) is not _INSTALL.get("metadata_fn"):
            _record("metadata", lambda: _probe_metadata(c))
    streams = _interceptors() or []
    if any(s.__dict__.get("write") not in _INSTALL.get("log_writers", ()) for s in streams):
        _wrap_streams(c)                           # ComfyUI replaced its console feed: cover the new one
        _record("log_streams", lambda: _probe_log_streams(c))
    got = _INSTALL.get("log_filters")
    if got:
        added = attach_root_filter(got[0])
        if added:
            _INSTALL["log_filters"] = (got[0], list(got[1]) + added)
    app = getattr(server, "app", None)
    for cid, key in (("listings", "listing_mw"), ("hosted", "hosted_mw")):
        mw = _INSTALL.get(key)
        if app is not None and mw is not None and not any(m is mw for m in list(app.middlewares)):
            CAPABILITIES.set(cid, FAILED, "the web guard was removed from the server's request chain")


def capability_refusal() -> Optional[str]:
    """None when concealed execution may run; else the plain-English reason and next step."""
    if not CAPABILITIES.attempted:
        return None
    try:
        check_liveness()
    except Exception as exc:  # noqa: BLE001 - a broken re-check refuses (fail closed)
        CAPABILITIES.set("messages", FAILED, _why(exc))
    return CAPABILITIES.refusal()


# ── server adapters ─────────────────────────────────────────────────────────────────────────────────────────

_INSTALL: dict = {}


def _wrap_streams(c: "Concealer") -> None:
    """Wrap core's console feeds (app.logger LogInterceptor write, on the instance) that are not wrapped yet."""
    streams = _INSTALL.setdefault("logs", [])
    writers = _INSTALL.setdefault("log_writers", [])
    for s in _interceptors() or []:
        if s.__dict__.get("write") in writers:
            continue
        orig_write = s.write                              # the bound method (instance shadowing below)

        def write(data, _orig=orig_write):
            cc = _cur(c)
            try:
                data = cc.filter_log_text(data)
            except Exception:  # noqa: BLE001
                if cc.window is not None:
                    data = CONCEALED_LOG_LINE + "\n"
            probe = _probing()
            if probe is not None and cc.window == PROBE_VAULT:
                probe.append(("log", data))               # the self-test: recorded, never printed
                return 0
            return _orig(data)

        s.write = write
        if s not in streams:
            streams.append(s)
        writers.append(write)


def install(server=None, *, concealer: Optional[Concealer] = None) -> bool:
    """Wrap the server's outbound paths, then self-test every protection (CAPABILITIES). Must run AFTER the vault's
    own message filter so that this one is the outermost wrapper and sees core's raw inner ids first.
    -> True only when every critical protection works; False otherwise (concealed vaults then refuse to run).
    Hosted mode with a critical protection missing raises HostedStartRefused (ComfyUI does not start)."""
    if _INSTALL:
        return CAPABILITIES.refusal() is None
    c = concealer or CONCEALER
    try:
        if server is None:
            from server import PromptServer
            server = PromptServer.instance
    except Exception as exc:  # noqa: BLE001
        log.warning("H2Vault concealment not installed (no server): %s", exc)
        return False
    CAPABILITIES.reset()
    CAPABILITIES.attempted = True
    CAPABILITIES.hosted = hosted_enabled()
    _INSTALL["server"], _INSTALL["concealer"] = server, c
    try:
        return _install_hooks(server, c)
    except HostedStartRefused:
        raise
    except Exception as exc:  # noqa: BLE001 - unexpected: every capability not yet checked stays "not checked"
        log.error("[H2Vault] security set-up failed (%s): concealed vaults will refuse to run", type(exc).__name__)
        if CAPABILITIES.hosted:
            raise HostedStartRefused("[H2Vault] Hosted mode refused to start: the security set-up failed "
                                     f"({type(exc).__name__}). Fix it, or turn hosted mode off "
                                     "(H2VAULT_HOSTED).") from None
        return False


def _install_hooks(server, c: Concealer) -> bool:
    """install()'s body: every hook, then the self-test. Raises HostedStartRefused (hosted mode, a critical
    protection not working)."""
    try:
        orig_send = server.send_sync

        def send_sync(event, data, sid=None, _orig=orig_send):
            probe = _probing() if sid == PROBE_SID else None
            cc = _cur(c)
            try:
                data = cc.filter_message(event, data)
            except Exception:  # noqa: BLE001 - fail closed while a concealed vault is known
                log.error("H2Vault concealment: message filter failed (message %s)",
                          "dropped" if cc.any_registered() else "passed")
                if cc.any_registered():
                    data = DROP
            if probe is not None:
                probe.append(("send", event, data))       # the self-test: recorded, never sent
                return None
            if data is DROP:
                return None
            return _orig(event, data, sid)

        server.send_sync = send_sync
        _INSTALL["send"] = (server, orig_send)
        _INSTALL["send_fn"] = send_sync
    except Exception as exc:  # noqa: BLE001
        CAPABILITIES.set("messages", FAILED, f"the message hook could not be installed ({type(exc).__name__})")
        CAPABILITIES.set("previews", FAILED, "the message hook could not be installed")

    q = getattr(server, "prompt_queue", None)
    if q is not None and hasattr(q, "task_done"):
        orig_done = q.task_done

        def task_done(item_id, history_result, status=None, *a, _orig=orig_done, **k):
            probe = _probing() if item_id == PROBE_ITEM else None
            cc = _cur(c)
            try:
                history_result = cc.filter_history(history_result)
                status = cc.filter_status(status)
            except Exception:  # noqa: BLE001
                log.error("H2Vault concealment: history filter failed (history of this run withheld)")
                if cc.any_registered():
                    history_result, status = {"outputs": {}, "meta": {}}, None
            if probe is not None:
                probe.append(("history", history_result, status))
                return None
            try:
                return _orig(item_id, history_result, status, *a, **k)
            finally:
                c.end_prompt()

        q.task_done = task_done
        _INSTALL["queue"] = (q, orig_done)
        _INSTALL["queue_fn"] = task_done
    else:
        CAPABILITIES.set("history", UNAVAILABLE, "this ComfyUI has no prompt queue H2Vault can filter")

    try:
        from comfy_execution.progress import ProgressRegistry
        orig_start = ProgressRegistry.start_progress

        def start_progress(self, node_id, _orig=orig_start):
            cc = _cur(c)
            try:
                cc.on_node_start(node_id)
            except Exception:  # noqa: BLE001
                pass
            probe = _probing()
            if probe is not None and str(node_id).startswith(PROBE_VAULT + "."):
                probe.append(("progress", cc.window))
                return None
            return _orig(self, node_id)

        ProgressRegistry.start_progress = start_progress
        _INSTALL["progress"] = (ProgressRegistry, orig_start)
        _INSTALL["progress_fn"] = start_progress
    except Exception as exc:  # noqa: BLE001
        log.warning("H2Vault concealment: no progress registry (log concealment off): %s", exc)
        CAPABILITIES.set("progress", UNAVAILABLE, "this ComfyUI has no progress registry")

    try:
        if _interceptors() is None:
            CAPABILITIES.set("log_streams", NOT_NEEDED, "this ComfyUI has no console log feed")
        else:
            _wrap_streams(c)
    except Exception as exc:  # noqa: BLE001
        log.warning("H2Vault concealment: no log interceptor (log concealment off): %s", exc)
        CAPABILITIES.set("log_streams", FAILED, f"the console hook could not be installed ({type(exc).__name__})")

    # V8: handlers that format records themselves (core's --verbose LEVEL FILE log files, any other root handler)
    flt = WindowLogFilter(c)
    _INSTALL["log_filters"] = (flt, attach_root_filter(flt))

    # V8: core computes an inner node's cache key (IS_CHANGED / fingerprint_inputs) BEFORE that node starts, and logs
    # its exception ("WARNING: [Errno 2] No such file ...: '<inner file>'", measured live): open the window for it
    try:
        import execution as core_execution
        icc = getattr(core_execution, "IsChangedCache", None)
        if icc is None:
            CAPABILITIES.set("cache_keys", UNAVAILABLE, "this ComfyUI has no cache-key step H2Vault knows")
        elif not getattr(icc.get, "__h2vault_guard__", False):
            orig_icc_get = icc.get

            async def is_changed_get(self, node_id, _orig=orig_icc_get):
                cc = _cur(c)
                v = cc.vault_of(None if node_id is None else str(node_id))
                if v is None:
                    return await _orig(self, node_id)
                with cc._lock:
                    prev, cc._window = cc._window, v
                try:
                    return await _orig(self, node_id)
                finally:
                    with cc._lock:
                        cc._window = prev

            is_changed_get.__h2vault_guard__ = True
            icc.get = is_changed_get
            _INSTALL["is_changed"] = (icc, orig_icc_get)
            _INSTALL["is_changed_fn"] = is_changed_get
        else:
            CAPABILITIES.set("cache_keys", FAILED, "another copy of H2Vault already holds this hook")
    except Exception as exc:  # noqa: BLE001
        log.warning("H2Vault: cache-key window not installed (an inner node's cache-key warning may name it): %s", exc)
        CAPABILITIES.set("cache_keys", UNAVAILABLE, "this ComfyUI has no cache-key step H2Vault knows")

    # V8: nodes inside a vault embed no prompt / workflow in the files they write
    try:
        import execution as core_execution
        orig_gid = core_execution.get_input_data
        if not getattr(orig_gid, "__h2vault_guard__", False):
            guard = metadata_guard(orig_gid, concealer=c)
            core_execution.get_input_data = guard
            _INSTALL["metadata"] = (core_execution, orig_gid)
            _INSTALL["metadata_fn"] = guard
        # else: another copy holds the hook - the probe below tells whether it protects THIS copy's vaults
    except Exception as exc:  # noqa: BLE001
        log.warning("H2Vault: output metadata guard not installed (outputs made inside a vault may embed the "
                    "workflow): %s", exc)
        CAPABILITIES.set("metadata", UNAVAILABLE, "this ComfyUI has no input step H2Vault knows")

    app = getattr(server, "app", None)
    if app is not None:
        try:
            mw = hash_folder_middleware(concealer=c)
            app.middlewares.append(mw)
            _INSTALL["listing_mw"] = mw
        except Exception as exc:  # noqa: BLE001
            log.warning("H2Vault: model-listing guard not attached (downloaded vault models may be listed): %s", exc)

    if CAPABILITIES.hosted:
        try:
            hmw = hosted_middleware()
            app.middlewares.append(hmw)
            _INSTALL["hosted_mw"] = hmw
            log.info("H2Vault hosted mode: model lists, logs and model routes are withheld from every client")
        except Exception as exc:  # noqa: BLE001
            log.error("H2Vault hosted mode requested but the guard could not be attached: %s", exc)

    report = run_selftest(server, c)
    missing = CAPABILITIES.missing()
    if missing:
        log.error("[H2Vault] security check: %s not working - concealed vaults will refuse to run. H2Vault menu > "
                  "Security check shows the details.",
                  ", ".join(_SPEC[m][1] for m in missing))
        if CAPABILITIES.hosted:
            raise HostedStartRefused(
                "[H2Vault] Hosted mode refused to start: these protections are not working: "
                + "; ".join(f"{_SPEC[m][1]} ({CAPABILITIES.detail(m) or 'failed its check'})" for m in missing)
                + ". Fix them, or turn hosted mode off (H2VAULT_HOSTED). H2Vault menu > Security check shows details.")
    else:
        log.info("[H2Vault] security check passed (%d protections active)",
                 sum(1 for x in report["capabilities"] if x["status"] == ACTIVE))
    return not missing


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
    if "log_filters" in _INSTALL:
        flt, targets = _INSTALL["log_filters"]
        for t in targets:
            t.removeFilter(flt)
    if "metadata" in _INSTALL:
        mod, orig = _INSTALL["metadata"]
        mod.get_input_data = orig
    if "is_changed" in _INSTALL:
        cls, orig = _INSTALL["is_changed"]
        cls.get = orig
    app = getattr(_INSTALL.get("server"), "app", None)
    for key in ("listing_mw", "hosted_mw"):
        mw = _INSTALL.get(key)
        if mw is not None and app is not None:
            try:
                app.middlewares.remove(mw)
            except Exception:  # noqa: BLE001 - a started app's middleware list is frozen
                pass
    _INSTALL.clear()
    CAPABILITIES.reset()


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
