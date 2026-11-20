# Derived from Code2Collapse ComfyUI-CustomNodePacks nodes/_local_ui_guard.py and nodes/magnific/security.py
# (Apache-2.0, Copyright Code2Collapse); modified for H2Vault (AGPL-3.0). See NOTICE.
"""Local-UI guard for routes that create, read or change local secrets.

refuse_remote(request) -> None when the request comes from the ComfyUI page on THIS machine, else a 403 JSON response.
Three checks: the TCP peer is loopback (read from the socket, never from a header a proxy middleware could rewrite),
the Host header is a loopback literal (never resolved: a DNS rebind keeps an attacker's name there), and fetch metadata
is not cross-site / same-site and any Origin names a loopback host. Through an SSH tunnel the page still counts as
local (the tunnel ends on loopback). H2VAULT_TRUSTED_HOSTS (comma-separated) relaxes only the Host literal, for a
same-box reverse proxy with its own authentication; the peer check is never relaxed.
"""
from __future__ import annotations

import ipaddress
import os
import urllib.parse

_TRUSTED_HOSTS = {h.strip().lower() for h in os.environ.get("H2VAULT_TRUSTED_HOSTS", "").split(",") if h.strip()}
_FORBIDDEN_FETCH_SITES = frozenset({"cross-site", "same-site"})


def _hostname_from_host_header(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if value[0] == "[":                                     # [::1]:8188
        end = value.find("]")
        return value[1:end] if end != -1 else ""
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value


def _is_loopback_ip(value: str) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    mapped = getattr(address, "ipv4_mapped", None)
    return bool(mapped is not None and mapped.is_loopback)


def _is_loopback_name(hostname: str) -> bool:
    if not hostname:
        return False
    if hostname.lower() in _TRUSTED_HOSTS or hostname == "localhost":
        return True
    return _is_loopback_ip(hostname)


def is_local_ui_origin(headers, peer_ip) -> bool:
    if not _is_loopback_ip(peer_ip):
        return False
    if not _is_loopback_name(_hostname_from_host_header(headers.get("Host", ""))):
        return False
    if headers.get("Sec-Fetch-Site") in _FORBIDDEN_FETCH_SITES:
        return False
    origin = headers.get("Origin")
    return not origin or _is_loopback_name(urllib.parse.urlsplit(origin).hostname or "")


def peer_ip(request):
    t = getattr(request, "transport", None)
    pn = t.get_extra_info("peername") if t else None
    return pn[0] if isinstance(pn, (tuple, list)) and pn else None


def is_local(request) -> bool:
    try:
        return bool(is_local_ui_origin(request.headers, peer_ip(request)))
    except Exception:  # noqa: BLE001 - a broken guard refuses (fail closed)
        return False


def refuse_remote(request, what: str = "This"):
    if is_local(request):
        return None
    from aiohttp import web
    return web.json_response(
        {"ok": False, "error": f"{what} works only from the ComfyUI page on this machine (http://127.0.0.1 or "
                               "localhost).", "code": "LOCAL_UI_ONLY"},
        status=403)
