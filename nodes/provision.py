"""H2Vault (AGPL-3.0) - V7 concealed provisioning: a vault's missing model files download themselves without revealing
what they are (owner 2026-11-23; design docs/h2vault/V7_concealed_provisioning.md in the workspace).

The vault payload (inside the encryption) may carry a model manifest: [{folder, file, url, sha256, size}]. On the
recipient's machine a missing file is fetched over public HTTPS into ``models/<folder>/h2v/<sha256>.<ext>`` - the
full SHA-256 as the name, so the file name on disk tells nothing - resumed from a ``.part`` file, capped at the
declared size and verified against the SHA-256 before it is renamed into place. When the vault runs, an inner loader
input that names a manifest file absent under its own name is rewritten to that hash name (server side, never shown).
Everything the browser learns is a count, a byte total, a percentage or a plain-English refusal.

Network: every hop (the first request and at most 5 redirects) resolves its host ONCE, refuses unless every address
is public (_ip_allowed), connects to that IP literal, checks the peer address and only then speaks TLS with the URL's
host name (SNI and certificate check stay on) - the host name is never resolved a second time (DNS rebinding). An
http:// proxy from the environment is sent ``CONNECT <ip>:<port>``, never the host name.
Cache: a copy is used only after a full SHA-256 check, remembered in a ``<name>.verified`` stamp (size + mtime_ns);
older copies named by the first 20 hex digits are verified and renamed. Recipient limits: 256 GiB per model, 1 TiB
in total and 256 entries per vault (env H2VAULT_MAX_MODEL_GIB / H2VAULT_MAX_MANIFEST_GIB), and enough free disk.
One download per hash at a time, across threads and processes (a ``<sha256>.lock`` file in the h2v folder).
"""
from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import http.client
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import ssl
import stat
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional

HASH_DIR = "h2v"
CHUNK = 1 << 20
GiB = 1 << 30
MAX_MODEL_BYTES = 256 * GiB
MAX_MANIFEST_BYTES = 1024 * GiB
MAX_MANIFEST_ENTRIES = 256
MAX_REDIRECTS = 5
TIMEOUT = 60
_LEGACY_HEX = 20                                   # names before 2026-11-24 used sha256[:20]
_REDIRECTS = (301, 302, 303, 307, 308)
_FOLDER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTENT_RANGE_RE = re.compile(r"\s*bytes\s+(\d+)-(\d+)/(\d+|\*)\s*")
_CANCELLED = "The download was cancelled."


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


# ── recipient limits (read at call time; authors seal as before) ───────────────────────────────────────────

def _env_bytes(name: str, default: int) -> int:
    try:
        gib = float(os.environ.get(name, ""))
    except ValueError:
        return default
    return int(gib * GiB) if math.isfinite(gib) and gib > 0 else default


def _limit_problem(manifest: list, downloads: list) -> Optional[str]:
    """Plain-English refusal when the manifest is too long or what would be downloaded is too large, else None."""
    max_model = _env_bytes("H2VAULT_MAX_MODEL_GIB", MAX_MODEL_BYTES)
    max_total = _env_bytes("H2VAULT_MAX_MANIFEST_GIB", MAX_MANIFEST_BYTES)
    if len(manifest) > MAX_MANIFEST_ENTRIES:
        return f"This vault lists more than {MAX_MANIFEST_ENTRIES} model downloads; refused."
    if any(e["size"] > max_model for e in downloads):
        return (f"One of this vault's models is larger than this computer's download limit "
                f"({max_model / GiB:g} GiB); refused. The limit is set with H2VAULT_MAX_MODEL_GIB.")
    if sum(e["size"] for e in downloads) > max_total:
        return (f"This vault's model downloads add up to more than this computer's limit "
                f"({max_total / GiB:g} GiB); refused. The limit is set with H2VAULT_MAX_MANIFEST_GIB.")
    return None


# ── paths ──────────────────────────────────────────────────────────────────────────────────────────────────

def _folder_root(folder: str) -> Path:
    import folder_paths
    roots = folder_paths.get_folder_paths(folder)
    if not roots:
        raise ProvisionError("This ComfyUI has no folder for one of the vault's models.")
    return Path(roots[0])


def _ext(e: dict) -> str:
    ext = Path(e["file"]).suffix.lower()
    return ext if re.fullmatch(r"\.[a-z0-9]{1,12}", ext or "") else ".bin"


def hashed_name(e: dict) -> str:
    return f"{e['sha256']}{_ext(e)}"


def _legacy_name(e: dict) -> str:
    return f"{e['sha256'][:_LEGACY_HEX]}{_ext(e)}"


def hashed_path(e: dict) -> Path:
    return _folder_root(e["folder"]) / HASH_DIR / hashed_name(e)


def _present_own_name(e: dict) -> bool:
    import folder_paths
    try:
        return folder_paths.get_full_path(e["folder"], e["file"]) is not None
    except Exception:  # noqa: BLE001
        return False


# ── cache: full verification, remembered in a stamp ────────────────────────────────────────────────────────

def _stamp_path(p: Path) -> Path:
    return p.with_name(p.name + ".verified")


def _discard(p: Path) -> None:
    """Remove one of H2Vault's own cache files (and its stamp); a file still in use is left for next time."""
    for q in (p, _stamp_path(p)):
        try:
            q.unlink(missing_ok=True)
        except OSError:
            pass


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _stamp_ok(p: Path, e: dict, st: os.stat_result) -> bool:
    try:
        rec = json.loads(_stamp_path(p).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return (isinstance(rec, dict) and rec.get("v") == 1 and rec.get("sha256") == e["sha256"]
            and rec.get("size") == st.st_size == e["size"] and rec.get("mtime_ns") == st.st_mtime_ns)


def _write_stamp(p: Path, e: dict) -> None:
    """Record a successful full check (atomic). A stamp that cannot be written only costs a re-check later."""
    try:
        st = os.stat(p)
        tmp = p.with_name(p.name + ".verified.tmp")
        tmp.write_text(json.dumps({"v": 1, "sha256": e["sha256"], "size": st.st_size, "mtime_ns": st.st_mtime_ns}),
                       encoding="utf-8")
        os.replace(tmp, _stamp_path(p))
    except OSError:
        pass


def _verified(p: Path, e: dict) -> bool:
    """True when p is a regular file with the declared size and SHA-256 (stamp, else a full hash that is then
    stamped). A copy whose content does not match its SHA-256 name is deleted (H2Vault's own cache file); a size that
    differs from what THIS manifest declares deletes nothing (a wrong manifest must not cost another vault's copy)."""
    try:
        st = os.stat(p)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_size != e["size"]:
        return False
    if _stamp_ok(p, e, st):
        return True
    try:
        digest = _sha256_file(p)
    except OSError:
        return False
    if digest == e["sha256"]:
        _write_stamp(p, e)
        return True
    _discard(p)
    return False


def _verified_target(e: dict) -> Optional[Path]:
    """The verified copy of e (full name; a valid legacy copy is renamed to it first), or None."""
    target = hashed_path(e)
    if _verified(target, e):
        return target
    legacy = target.with_name(_legacy_name(e))
    if not _verified(legacy, e):
        return None
    try:
        os.replace(legacy, target)
    except OSError:                          # in use, or another worker moved it first
        if _verified(target, e):
            return target
        return legacy if legacy.is_file() else None
    try:
        os.replace(_stamp_path(legacy), _stamp_path(target))      # rename keeps mtime_ns, so the stamp stays valid
    except OSError:
        pass
    return target


def _candidate_present(e: dict) -> bool:
    """Cheap (no hashing; plan/is_missing run on the event loop): a full- or legacy-named copy of the right size."""
    target = hashed_path(e)
    for p in (target, target.with_name(_legacy_name(e))):
        try:
            st = os.stat(p)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_size == e["size"]:
            return True
    return False


def is_missing(e: dict) -> bool:
    if _present_own_name(e):
        return False
    try:
        return not _candidate_present(e)
    except ProvisionError:
        return True


# ── plan (counts only) ─────────────────────────────────────────────────────────────────────────────────────

def plan(plain) -> dict:
    manifest = _manifest(plain)
    missing = [e for e in manifest if is_missing(e)]
    return {"models_missing": len(missing), "bytes": sum(e["size"] for e in missing),
            "downloadable": all(bool(e["url"]) for e in missing), "problem": _limit_problem(manifest, missing)}


# ── URL safety ─────────────────────────────────────────────────────────────────────────────────────────────

def _resolve(host: str) -> list:
    return [ai[4][0] for ai in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)]


_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def _in_nat64(ip) -> bool:
    return any(ip in n for n in _NAT64)


def _ip_allowed(ip_str: str) -> bool:
    """The one address policy: public unicast only (IPv4-mapped / 6to4 / Teredo are judged by what they embed)."""
    try:
        ip = ipaddress.ip_address(str(ip_str).split("%")[0])
    except ValueError:
        return False
    candidates = [ip]
    if ip.version == 6:
        if _in_nat64(ip):                           # 64:ff9b::/96, 64:ff9b:1::/48: the last 32 bits are IPv4
            candidates = [ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)]
        elif ip.ipv4_mapped is not None:
            candidates = [ip.ipv4_mapped]
        elif ip.sixtofour is not None:
            candidates = [ip.sixtofour]
        elif ip.teredo is not None:
            candidates = list(ip.teredo)
    return all(a.is_global and not (a.is_multicast or a.is_unspecified or a.is_reserved or a.is_loopback
                                    or a.is_link_local or a.is_private) for a in candidates)


def _split(url: str):
    """(ascii host, port, request path) of an https URL, or a refusal in words."""
    try:
        u = urllib.parse.urlsplit(url)
        host, port = u.hostname, u.port or 443
    except ValueError:
        raise ProvisionError("A model download source is not a valid address.") from None
    if u.scheme != "https" or not host:
        raise ProvisionError("Model downloads are allowed over HTTPS only.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise ProvisionError("A model download source is not a valid address.") from None
    return host, port, urllib.parse.urlunsplit(("", "", u.path or "/", u.query, ""))


def _vet_host(host: str) -> list:
    """Resolve host ONCE; every address must be allowed. Returns the vetted IP literals."""
    try:
        addrs = [str(a).split("%")[0] for a in _resolve(host)]
    except (OSError, UnicodeError):
        raise ProvisionError("A model download source could not be reached.") from None
    if not addrs:
        raise ProvisionError("A model download source could not be reached.")
    if not all(_ip_allowed(a) for a in addrs):
        raise ProvisionError("A model download source points at a private or local address; refused.")
    return addrs


def check_url(url: str) -> None:
    """Public HTTPS only: no plain http, no file / ftp, no loopback / private / link-local / reserved targets."""
    _vet_host(_split(url)[0])


# ── pinned HTTPS client (stdlib) ───────────────────────────────────────────────────────────────────────────

def _ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def _proxy_for(host: str):
    """The environment's https proxy (as urllib used it), or None. Only http:// proxies are supported."""
    proxy = urllib.request.getproxies().get("https")
    if not proxy or urllib.request.proxy_bypass(host):
        return None
    if "://" not in proxy:
        proxy = "http://" + proxy
    try:
        p = urllib.parse.urlsplit(proxy)
        ok = p.scheme == "http" and bool(p.hostname) and (p.port or 80) > 0
    except ValueError:
        ok = False
    if not ok:
        raise ProvisionError("Model downloads support only an http:// proxy; check the HTTPS_PROXY setting.")
    return p


def _same_ip(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_address(str(a).split("%")[0]) == ipaddress.ip_address(str(b).split("%")[0])
    except ValueError:
        return False


def _tunnel(sock: socket.socket, ip: str, port: int, proxy) -> None:
    """CONNECT the proxy to the pinned IP literal (never the host name)."""
    target = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", "User-Agent: H2Vault"]
    if proxy.username is not None:
        cred = f"{urllib.parse.unquote(proxy.username)}:{urllib.parse.unquote(proxy.password or '')}"
        lines.append("Proxy-Authorization: Basic " + base64.b64encode(cred.encode("utf-8")).decode("ascii"))
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > 64 * 1024:
            raise ProvisionError("The proxy sent an invalid answer; the download source could not be reached.")
        chunk = sock.recv(4096)
        if not chunk:
            raise ProvisionError("The proxy closed the connection; the download source could not be reached.")
        buf += chunk
    head, _, extra = buf.partition(b"\r\n\r\n")
    fields = head.split(b"\r\n", 1)[0].split()
    code = fields[1].decode("ascii", "replace") if len(fields) > 1 else "?"
    if code != "200" or extra:
        raise ProvisionError(f"The proxy refused the connection to the download source (HTTP {code[:3]}).")


def _open_tls(host: str, port: int, timeout: float) -> ssl.SSLSocket:
    """One resolution, vetted addresses, connect to the IP literal, peer check, then TLS for host."""
    addrs = _vet_host(host)
    proxy = _proxy_for(host)
    sock, last = None, None
    for ip in addrs:
        try:
            if proxy is not None:
                sock = socket.create_connection((proxy.hostname, proxy.port or 80), timeout)
                try:
                    _tunnel(sock, ip, port, proxy)
                except BaseException:
                    sock.close()
                    raise
            else:
                sock = socket.create_connection((ip, port), timeout)
                peer = sock.getpeername()[0]
                if not (_same_ip(peer, ip) and _ip_allowed(peer)):
                    sock.close()
                    raise ProvisionError("The download connection did not reach the checked address; refused.")
            break
        except OSError as exc:
            sock, last = None, exc
    if sock is None:
        raise last or ProvisionError("A model download source could not be reached.")
    try:
        return _ssl_context().wrap_socket(sock, server_hostname=host)
    except ssl.SSLError:
        sock.close()
        raise ProvisionError("The download source's security certificate could not be verified; refused.") from None
    except BaseException:
        sock.close()
        raise


class _PinnedConnection(http.client.HTTPConnection):
    default_port = 443                          # so the Host header omits :443

    def connect(self):
        self.sock = _open_tls(self.host, self.port, self.timeout)


class _Response:
    """opener contract: a context manager with .status, .headers (.get) and .read(n); closes the connection."""

    def __init__(self, conn, resp):
        self._conn, self._resp = conn, resp
        self.status, self.headers = resp.status, resp.headers

    def read(self, n: int = -1) -> bytes:
        return self._resp.read(n)

    def close(self) -> None:
        self._resp.close()
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _default_opener(url: str, start: int = 0):
    headers = {"User-Agent": "H2Vault", "Accept-Encoding": "identity", **({"Range": f"bytes={start}-"} if start else {})}
    for _hop in range(MAX_REDIRECTS + 1):
        host, port, path = _split(url)
        conn = _PinnedConnection(host, port, timeout=TIMEOUT)
        try:
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
        except http.client.HTTPException:
            conn.close()
            raise ProvisionError("The download source sent an invalid answer. Try again later.") from None
        except BaseException:
            conn.close()
            raise
        if resp.status not in _REDIRECTS:
            return _Response(conn, resp)
        location = resp.headers.get("Location")
        resp.close()
        conn.close()
        if not location:
            raise ProvisionError("The download source sent an incomplete redirect; refused.")
        url = urllib.parse.urljoin(url, location)
    raise ProvisionError("The download source redirected too many times; refused.")


# ── per-hash lock (threads and processes) ──────────────────────────────────────────────────────────────────

_HASH_LOCKS: dict = {}
_HASH_LOCKS_GUARD = threading.Lock()


def _try_file_lock(fd: int) -> bool:
    try:
        if os.name == "nt":
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _unlock_file(fd: int) -> None:
    try:
        if os.name == "nt":
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass


@contextlib.contextmanager
def _hash_lock(folder: Path, sha: str, cancelled: Optional[Callable[[], bool]] = None):
    """Hold the download of one hash: a thread lock plus an OS lock on <folder>/<sha>.lock (left in place)."""
    with _HASH_LOCKS_GUARD:
        tlock = _HASH_LOCKS.setdefault(sha, threading.Lock())
    while not tlock.acquire(timeout=0.25):
        if cancelled is not None and cancelled():
            raise ProvisionError(_CANCELLED)
    try:
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(folder / f"{sha}.lock", flags, 0o600)
        try:
            while not _try_file_lock(fd):
                if cancelled is not None and cancelled():
                    raise ProvisionError(_CANCELLED)
                time.sleep(0.25)
            try:
                yield
            finally:
                _unlock_file(fd)
        finally:
            os.close(fd)
    finally:
        tlock.release()


# ── fetch ──────────────────────────────────────────────────────────────────────────────────────────────────

def _disk_free(path) -> int:
    return shutil.disk_usage(path).free


def _margin(size: int) -> int:
    return max(GiB, size * 2 // 100)


def _check_disk(folder: Path, size: int, start: int) -> None:
    need = (size - start) + _margin(size)
    try:
        free = _disk_free(folder)
    except OSError:
        return
    if free < need:
        raise ProvisionError(f"There is not enough free disk space for one of this vault's models (about "
                             f"{need / GiB:.1f} GiB needed). Free some space and try again.")


def _part_size(part: Path) -> int:
    try:
        st = os.lstat(part)
    except FileNotFoundError:
        return 0
    if not stat.S_ISREG(st.st_mode):
        raise ProvisionError("A partial model download in the models folder is not a regular file; refused. "
                             "Remove it and try again.")
    return st.st_size


def _status(resp) -> int:
    try:
        return int(getattr(resp, "status", 200) or 200)
    except (TypeError, ValueError):
        return 0


def _accepted_start(resp, code: int, start: int, e: dict, part: Path) -> int:
    """Validate the answer; return the byte the body starts at (0 when a resume request was answered in full)."""
    if not 200 <= code < 300:
        raise ProvisionError(f"The download source answered with an error (HTTP {code}). Try again later.")
    if start and code == 206:
        m = _CONTENT_RANGE_RE.fullmatch(resp.headers.get("Content-Range") or "")
        if not m or int(m[1]) != start or int(m[2]) < start or int(m[2]) >= e["size"] \
                or (m[3] != "*" and int(m[3]) != e["size"]):
            _discard(part)
            raise ProvisionError("The download source answered a resumed download incorrectly; the partial file "
                                 "was removed. Try again.")
    elif start:
        start = 0                                       # the range was ignored: the body is the whole file
    length = str(resp.headers.get("Content-Length") or "").strip()
    if length.isdigit() and start + int(length) > e["size"]:
        raise ProvisionError("A model download was larger than the vault declared; refused.")
    return start


def _open_part(part: Path, append: bool):
    _part_size(part)                                    # refuses a symlink / non-regular .part
    flags = (os.O_CREAT | os.O_WRONLY | (os.O_APPEND if append else os.O_TRUNC)
             | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    return os.fdopen(os.open(part, flags, 0o600), "ab" if append else "wb")


def _hash_part(part: Path, n: int, h) -> None:
    """Feed the first n bytes of the existing part into h (resume: the file is never read twice)."""
    if not n:
        return
    fd = os.open(part, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as fh:
        left = n
        while left:
            chunk = fh.read(min(CHUNK, left))
            if not chunk:
                break
            h.update(chunk)
            left -= len(chunk)


def _finish(part: Path, target: Path, e: dict, digest: str) -> Path:
    if digest != e["sha256"]:
        _discard(part)
        raise ProvisionError("A downloaded model did not match the vault's checksum; it was removed.")
    os.replace(part, target)
    _write_stamp(target, e)
    return target


def _open_response(op, url: str, start: int):
    try:
        return op(url, start)
    except ProvisionError:
        raise
    except (OSError, http.client.HTTPException, ValueError):   # timeouts, refused connections, proxies, bad paths
        raise ProvisionError("The download source could not be reached (network, proxy or firewall). "
                             "Try again later.") from None


def _download(e: dict, target: Path, op, progress, cancelled) -> Path:
    part = target.with_name(target.name + ".part")
    start = _part_size(part)
    if start > e["size"]:
        _discard(part)
        start = 0
    for _attempt in range(2):
        _check_disk(target.parent, e["size"], start)
        with _open_response(op, e["url"], start) as resp:
            code = _status(resp)
            if not (start and code == 416):
                start = _accepted_start(resp, code, start, e, part)
                h = hashlib.sha256()
                _hash_part(part, start, h)
                written = start
                with _open_part(part, append=bool(start)) as fh:
                    while True:
                        if cancelled is not None and cancelled():
                            raise ProvisionError(_CANCELLED)
                        try:
                            chunk = resp.read(CHUNK)
                        except (OSError, http.client.HTTPException):
                            raise ProvisionError("The download was interrupted. Try again later; it continues "
                                                 "where it stopped.") from None
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > e["size"]:
                            fh.close()
                            _discard(part)
                            raise ProvisionError("A model download was larger than the vault declared; refused.")
                        fh.write(chunk)
                        h.update(chunk)
                        if progress is not None:
                            progress(len(chunk))
                if written < e["size"]:
                    raise ProvisionError("The download stopped before it was complete. Try again later; it "
                                         "continues where it stopped.")
                return _finish(part, target, e, h.hexdigest())
        # 416 on a resume: nothing after `start` - the part may already be the whole file
        if start == e["size"] and _sha256_file(part) == e["sha256"]:
            return _finish(part, target, e, e["sha256"])
        _discard(part)
        start = 0
    raise ProvisionError("The download source refused to resume the download. Try again later.")


def fetch(e: dict, *, opener: Optional[Callable] = None, progress: Optional[Callable[[int], None]] = None,
          cancelled: Optional[Callable[[], bool]] = None) -> Path:
    """Download one manifest entry to its hash name; resume, cap, verify. Returns the final path."""
    e = validate_manifest([e])[0]
    if not e["url"]:
        raise ProvisionError("One of this vault's models has no download source; ask its author.")
    problem = _limit_problem([e], [e])
    if problem:
        raise ProvisionError(problem)
    found = _verified_target(e)
    if found is not None:
        return found
    target = hashed_path(e)
    target.parent.mkdir(parents=True, exist_ok=True)
    with _hash_lock(target.parent, e["sha256"], cancelled):
        found = _verified_target(e)                     # another worker may have finished it meanwhile
        if found is not None:
            return found
        return _download(e, target, opener or _default_opener, progress, cancelled)


# ── expansion remap ────────────────────────────────────────────────────────────────────────────────────────

def remap(graph: dict, plain) -> dict:
    """Point inner inputs at verified hash-named copies for manifest files that are absent under their own name."""
    table = {}
    for e in _manifest(plain):
        if not _present_own_name(e):
            try:
                found = _verified_target(e)
            except (ProvisionError, OSError):
                continue
            if found is not None:
                table[e["file"]] = f"{HASH_DIR}/{found.name}"
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


def _space_problem(missing: list) -> Optional[str]:
    """Free space per filesystem for the whole job (remaining bytes + one margin), else None."""
    need: dict = {}
    for e in missing:
        root = _folder_root(e["folder"])
        try:
            dev = os.stat(root).st_dev
        except OSError:
            continue
        try:
            have = os.lstat(root / HASH_DIR / (hashed_name(e) + ".part")).st_size
        except OSError:
            have = 0
        folder, remaining, total = need.get(dev, (root, 0, 0))
        need[dev] = (folder, remaining + max(0, e["size"] - have), total + e["size"])
    for folder, remaining, total in need.values():
        try:
            free = _disk_free(folder)
        except OSError:
            continue
        if free < remaining + _margin(total):
            return (f"There is not enough free disk space for this vault's models (about "
                    f"{(remaining + _margin(total)) / GiB:.1f} GiB needed). Free some space and try again.")
    return None


def start(plain, token: str, *, opener: Optional[Callable] = None) -> dict:
    manifest = _manifest(plain)
    missing = [e for e in manifest if is_missing(e)]
    job = {"state": "running", "files_total": len(missing), "files_done": 0,
           "total_bytes": sum(e["size"] for e in missing), "done_bytes": 0, "error": None, "cancel": False}
    with _LOCK:
        _JOBS[token] = job
    try:
        problem = _limit_problem(manifest, missing) or _space_problem(missing)
    except ProvisionError as exc:
        problem = str(exc)
    if problem:
        with _LOCK:
            job["state"], job["error"] = "failed", problem
        return status(token)

    def add(n):
        with _LOCK:
            job["done_bytes"] += n

    def run():
        try:
            for e in missing:
                fetch(e, opener=opener, progress=add, cancelled=lambda: job["cancel"])
                with _LOCK:
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


# ── author side: the author gives links; size and SHA-256 come from the author's own files ─────────────────

def _find_local(file: str):
    """(folder, full path) of a model file on THIS (the author's) machine, searching ComfyUI's model folders."""
    import folder_paths
    names = getattr(folder_paths, "folder_names_and_paths", {}) or {}
    for folder in names:
        if folder in ("custom_nodes", "configs"):
            continue
        try:
            if file in (folder_paths.get_filename_list(folder) or []):
                full = folder_paths.get_full_path(folder, file)
                if full:
                    return folder, Path(full)
        except Exception:  # noqa: BLE001 - one odd folder never blocks the others
            continue
    return None, None


def describe_downloads(links) -> list:
    """[{file, url}] from the protect dialog -> validated manifest entries (empty links are skipped)."""
    out = []
    for item in links or []:
        file, url = str((item or {}).get("file") or ""), str((item or {}).get("url") or "").strip()
        if not url:
            continue
        if not url.lower().startswith("https://"):
            raise ProvisionError("Download links must use HTTPS (start with https://).")
        check_url(url)
        folder, full = _find_local(file)
        if full is None:
            raise ProvisionError(f"The model file {file!r} was not found in this ComfyUI's model folders.")
        h = hashlib.sha256()
        with open(full, "rb") as fh:
            for chunk in iter(lambda: fh.read(CHUNK), b""):
                h.update(chunk)
        out.append({"folder": folder, "file": file, "url": url, "sha256": h.hexdigest(), "size": full.stat().st_size})
    return validate_manifest(out)
