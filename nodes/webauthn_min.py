# H2Vault (AGPL-3.0). Written for H2Vault; no code was copied from another project. See NOTICE.
"""Minimal WebAuthn (passkey / security key / Windows Hello) verification for the second factor.

Why this file exists: the `webauthn` (py_webauthn) package is not part of ComfyUI's environment and H2Vault never
installs packages by itself. Everything here uses the `cryptography` package ComfyUI already ships, plus a small
CBOR reader limited to what WebAuthn sends (definite lengths, depth and size caps).

What is verified (W3C WebAuthn Level 2, sections 7.1 and 7.2):
  registration  clientData.type == "webauthn.create", the challenge this server issued (single use), the origin of
                the page, rpIdHash == SHA-256(rp id), user present, the attested credential (id + COSE public key).
  assertion     clientData.type == "webauthn.get", challenge, origin, rpIdHash, user present, the signature over
                authenticatorData || SHA-256(clientDataJSON) with the stored key, and the signature counter (a
                counter that goes backwards means a cloned authenticator and is refused).
Algorithms: ES256 (-7, P-256), EdDSA (-8, Ed25519), RS256 (-257).

Honest scope: attestation statements are NOT verified (the browser is asked for attestation "none"), so H2Vault does
not prove WHICH make of authenticator was used - it proves that the same authenticator that was registered on this
installation signs the challenge. That is the second factor H2Vault needs; registration itself is local-page only and
needs an existing factor once one is set up.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct

ALG_ES256, ALG_EDDSA, ALG_RS256 = -7, -8, -257
SUPPORTED_ALGS = (ALG_ES256, ALG_EDDSA, ALG_RS256)
FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40
_MAX_DEPTH, _MAX_ITEMS, _MAX_BYTES = 16, 4096, 64 * 1024


class WebAuthnError(ValueError):
    """A passkey answer that does not verify. The message is plain English and names no secret."""


# ── base64url ───────────────────────────────────────────────────────────────────────────────────────────────────
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(text) -> bytes:
    if not isinstance(text, str) or len(text) > 4 * _MAX_BYTES:
        raise WebAuthnError("The passkey answer is not readable.")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception:  # noqa: BLE001
        raise WebAuthnError("The passkey answer is not readable.") from None


# ── CBOR (RFC 8949), the subset WebAuthn uses ───────────────────────────────────────────────────────────────────
def cbor_decode(data: bytes, offset: int = 0):
    """-> (value, offset after it). Definite lengths only; raises WebAuthnError on anything malformed."""
    if len(data) > _MAX_BYTES:
        raise WebAuthnError("The passkey answer is too large.")
    budget = [_MAX_ITEMS]
    return _item(data, offset, 0, budget)


def _need(data: bytes, offset: int, n: int) -> None:
    if n < 0 or offset + n > len(data):
        raise WebAuthnError("The passkey answer is cut short.")


def _arg(data: bytes, offset: int, info: int):
    if info < 24:
        return info, offset
    sizes = {24: 1, 25: 2, 26: 4, 27: 8}
    if info not in sizes:
        raise WebAuthnError("The passkey answer uses an encoding H2Vault does not accept.")
    n = sizes[info]
    _need(data, offset, n)
    return int.from_bytes(data[offset:offset + n], "big"), offset + n


def _item(data: bytes, offset: int, depth: int, budget: list):
    if depth > _MAX_DEPTH:
        raise WebAuthnError("The passkey answer is nested too deeply.")
    budget[0] -= 1
    if budget[0] < 0:
        raise WebAuthnError("The passkey answer has too many parts.")
    _need(data, offset, 1)
    head = data[offset]
    offset += 1
    major, info = head >> 5, head & 0x1F
    if major == 7:
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info in (22, 23):
            return None, offset
        raise WebAuthnError("The passkey answer uses an encoding H2Vault does not accept.")
    value, offset = _arg(data, offset, info)
    if major == 0:
        return value, offset
    if major == 1:
        return -1 - value, offset
    if major in (2, 3):
        _need(data, offset, value)
        raw = bytes(data[offset:offset + value])
        offset += value
        if major == 2:
            return raw, offset
        try:
            return raw.decode("utf-8"), offset
        except UnicodeDecodeError:
            raise WebAuthnError("The passkey answer is not readable.") from None
    if major == 4:
        out = []
        for _ in range(value):
            item, offset = _item(data, offset, depth + 1, budget)
            out.append(item)
        return out, offset
    if major == 5:
        out = {}
        for _ in range(value):
            k, offset = _item(data, offset, depth + 1, budget)
            if isinstance(k, (list, dict)):
                raise WebAuthnError("The passkey answer is not readable.")
            v, offset = _item(data, offset, depth + 1, budget)
            out[k] = v
        return out, offset
    raise WebAuthnError("The passkey answer uses an encoding H2Vault does not accept.")       # tags (6)


# ── COSE keys ───────────────────────────────────────────────────────────────────────────────────────────────────
def cose_to_public_key(cose: dict):
    """A COSE_Key map -> (cryptography public key, alg)."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    if not isinstance(cose, dict):
        raise WebAuthnError("The passkey's public key is not readable.")
    kty, alg = cose.get(1), cose.get(3)
    try:
        if kty == 2 and alg == ALG_ES256 and cose.get(-1) == 1:
            x, y = cose.get(-2), cose.get(-3)
            if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
                raise WebAuthnError("The passkey's public key is not readable.")
            nums = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1())
            return nums.public_key(), alg
        if kty == 1 and alg == ALG_EDDSA and cose.get(-1) == 6:
            x = cose.get(-2)
            if not (isinstance(x, bytes) and len(x) == 32):
                raise WebAuthnError("The passkey's public key is not readable.")
            return ed25519.Ed25519PublicKey.from_public_bytes(x), alg
        if kty == 3 and alg == ALG_RS256:
            n, e = cose.get(-1), cose.get(-2)
            if not (isinstance(n, bytes) and isinstance(e, bytes)) or len(n) < 256:
                raise WebAuthnError("The passkey's RSA key is missing or shorter than 2048 bits.")
            return rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key(), alg
    except WebAuthnError:
        raise
    except Exception:  # noqa: BLE001 - a point not on the curve, a bad RSA number ...
        raise WebAuthnError("The passkey's public key is not valid.") from None
    raise WebAuthnError("This passkey uses a signature type H2Vault does not support (supported: ES256, EdDSA, "
                        "RS256).")


def public_key_der(key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_public_key(der: bytes):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_der_public_key(der)


# ── shared checks ───────────────────────────────────────────────────────────────────────────────────────────────
def _client_data(raw: bytes, kind: str, challenge: bytes, origins) -> dict:
    try:
        cd = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        raise WebAuthnError("The passkey answer is not readable.") from None
    if not isinstance(cd, dict) or cd.get("type") != kind:
        raise WebAuthnError("The passkey answer is for another kind of request.")
    got = unb64url(str(cd.get("challenge") or ""))
    if not hmac.compare_digest(got, challenge):
        raise WebAuthnError("The passkey answer is for another request (or an old one). Try again.")
    if cd.get("origin") not in set(origins or ()):
        raise WebAuthnError("The passkey answer comes from another web address than this page.")
    if cd.get("crossOrigin") is True:
        raise WebAuthnError("The passkey answer came from an embedded page of another site.")
    return cd


def _auth_data(raw: bytes, rp_id: str) -> tuple:
    if len(raw) < 37:
        raise WebAuthnError("The passkey answer is cut short.")
    if not hmac.compare_digest(raw[:32], hashlib.sha256(rp_id.encode("idna")).digest()):
        raise WebAuthnError(f"The passkey belongs to another address than {rp_id}.")
    flags = raw[32]
    if not flags & FLAG_UP:
        raise WebAuthnError("The security key was not touched (no user presence).")
    (count,) = struct.unpack(">I", raw[33:37])
    return flags, count


# ── registration ────────────────────────────────────────────────────────────────────────────────────────────────
def verify_registration(*, client_data_json: bytes, attestation_object: bytes, challenge: bytes, origins,
                        rp_id: str) -> dict:
    """-> {"id": b64url credential id, "public_key": b64 DER SPKI, "alg": int, "sign_count": int, "uv": bool}."""
    _client_data(client_data_json, "webauthn.create", challenge, origins)
    att, _end = cbor_decode(attestation_object)
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
        raise WebAuthnError("The passkey answer is not readable.")
    auth = att["authData"]
    flags, count = _auth_data(auth, rp_id)
    if not flags & FLAG_AT:
        raise WebAuthnError("The passkey answer carries no new credential.")
    off = 37 + 16                                              # aaguid
    _need(auth, off, 2)
    (n,) = struct.unpack(">H", auth[off:off + 2])
    off += 2
    if n == 0 or n > 1023:
        raise WebAuthnError("The passkey's credential id is not valid.")
    _need(auth, off, n)
    cred_id = bytes(auth[off:off + n])
    off += n
    cose, _off = cbor_decode(auth, off)
    key, alg = cose_to_public_key(cose)
    return {"id": b64url(cred_id), "public_key": base64.b64encode(public_key_der(key)).decode("ascii"), "alg": alg,
            "sign_count": count, "uv": bool(flags & FLAG_UV)}


# ── assertion ───────────────────────────────────────────────────────────────────────────────────────────────────
def verify_assertion(*, credential: dict, client_data_json: bytes, authenticator_data: bytes, signature: bytes,
                     challenge: bytes, origins, rp_id: str) -> int:
    """Raises WebAuthnError unless the stored credential signed this challenge; -> the new signature counter."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    _client_data(client_data_json, "webauthn.get", challenge, origins)
    _flags, count = _auth_data(authenticator_data, rp_id)
    key = load_public_key(base64.b64decode(credential["public_key"]))
    signed = bytes(authenticator_data) + hashlib.sha256(client_data_json).digest()
    alg = int(credential.get("alg", 0))
    try:
        if alg == ALG_ES256:
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == ALG_EDDSA:
            key.verify(signature, signed)
        elif alg == ALG_RS256:
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise WebAuthnError("This passkey uses a signature type H2Vault does not support.")
    except InvalidSignature:
        raise WebAuthnError("The passkey's signature is not valid.") from None
    except (TypeError, ValueError) as exc:
        if isinstance(exc, WebAuthnError):
            raise
        raise WebAuthnError("The passkey's signature is not valid.") from None
    stored = int(credential.get("sign_count", 0) or 0)
    if (count or stored) and count <= stored:
        raise WebAuthnError("This passkey's counter went backwards - it may have been copied. Remove it in H2Vault "
                            "menu > Second factor and register it again.")
    return count
