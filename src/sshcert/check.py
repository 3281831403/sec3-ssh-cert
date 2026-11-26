"""Validation primitives for short-lived SSH host and user certificates.

The certificate representation used by this module is a UTF-8 JSON object.
A certificate carries its type, key identifier, principal list, validity
window, critical options, issuing authority and signature.  The signature is
an HMAC-SHA256 digest over the canonical certificate body, keyed by the
shared secret of the issuing authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from typing import Any

_KNOWN_TYPES = frozenset({"user", "host"})
_SIGNED_FIELDS = (
    "type",
    "key_id",
    "principals",
    "valid_after",
    "valid_before",
    "ca",
    "critical_options",
)


def _secret_bytes(secret: str | bytes | bytearray) -> bytes:
    if isinstance(secret, str):
        return secret.encode("utf-8")
    if isinstance(secret, (bytes, bytearray)):
        return bytes(secret)
    raise TypeError("issuer secret must be text or bytes")


def _signed_body(cert: Mapping[str, Any]) -> dict[str, Any]:
    principals = cert.get("principals")
    if principals is None:
        principals = []
    if isinstance(principals, (str, bytes)):
        principals = [principals]
    principals = [str(item) for item in principals]
    options = cert.get("critical_options")
    if options is None:
        options = {}
    return {
        "type": cert.get("type"),
        "key_id": cert.get("key_id", ""),
        "principals": principals,
        "valid_after": cert.get("valid_after"),
        "valid_before": cert.get("valid_before"),
        "ca": cert.get("ca", ""),
        "critical_options": dict(options),
    }


def _canonical_body(cert: Mapping[str, Any]) -> bytes:
    return json.dumps(
        _signed_body(cert),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _sign_cert(cert: Mapping[str, Any], secret: str | bytes | bytearray) -> str:
    """Return the signed body digest for a certificate under an issuer key."""

    return hmac.new(_secret_bytes(secret), _canonical_body(cert), hashlib.sha256).hexdigest()


def _load_blob(blob: Any) -> Mapping[str, Any]:
    if isinstance(blob, Mapping):
        return blob
    if isinstance(blob, (bytes, bytearray, memoryview)):
        try:
            text = bytes(blob).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("certificate blob is not valid UTF-8") from exc
    elif isinstance(blob, str):
        text = blob
    else:
        raise TypeError("certificate blob must be JSON text, bytes or a mapping")
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("certificate blob is not valid JSON") from exc
    if not isinstance(raw, Mapping):
        raise ValueError("certificate blob must contain a JSON object")
    return raw


def parse_cert(blob: Any) -> dict[str, Any]:
    """Parse a serialized certificate into a normalized dictionary."""

    raw = _load_blob(blob)
    principals = raw.get("principals")
    if principals is None:
        principals = []
    if not isinstance(principals, list):
        raise ValueError("certificate principals must be a list")
    options = raw.get("critical_options")
    if options is None:
        options = {}
    if not isinstance(options, Mapping):
        raise ValueError("certificate critical options must be an object")
    extensions = raw.get("extensions")
    if extensions is None:
        extensions = {}
    if not isinstance(extensions, Mapping):
        raise ValueError("certificate extensions must be an object")
    return {
        "type": raw.get("type"),
        "key_id": raw.get("key_id", ""),
        "principals": [str(principal) for principal in principals],
        "valid_after": raw.get("valid_after"),
        "valid_before": raw.get("valid_before"),
        "critical_options": dict(options),
        "extensions": dict(extensions),
        "ca": raw.get("ca", ""),
        "signature": raw.get("signature", ""),
    }


def check_times(cert: Mapping[str, Any], now: int | float) -> bool:
    """Report whether now is inside the certificate validity window."""

    valid_after = cert.get("valid_after")
    valid_before = cert.get("valid_before")
    if not isinstance(valid_after, (int, float)) or isinstance(valid_after, bool):
        return False
    if not isinstance(valid_before, (int, float)) or isinstance(valid_before, bool):
        return False
    try:
        return now >= valid_after
    except TypeError:
        return False


def check_type(cert: Mapping[str, Any], expected: str) -> bool:
    """Verify that a certificate is issued for the requested purpose."""

    if not isinstance(expected, str):
        return False
    return cert.get("type") in _KNOWN_TYPES


def check_principals(cert: Mapping[str, Any], target: str) -> bool:
    """Verify that the target is present in the certificate principal list."""

    principals = cert.get("principals") or []
    if not principals:
        return True
    if not isinstance(target, str):
        return False
    return any(str(principal).startswith(target) for principal in principals)


def check_ca(cert: Mapping[str, Any], trusted: Mapping[str, Any]) -> bool:
    """Verify the issuing authority and certificate signature."""

    if not isinstance(trusted, Mapping):
        return False
    ca = cert.get("ca")
    if not isinstance(ca, str) or ca not in trusted:
        return False
    return True


def check_options(cert: Mapping[str, Any], policy: Mapping[str, Any]) -> dict[str, Any]:
    """Compare critical certificate options with the requested policy."""

    if not isinstance(policy, Mapping):
        raise TypeError("critical option policy must be a mapping")
    options = cert.get("critical_options") or {}
    issues: list[str] = []
    for name in policy:
        if name not in options:
            issues.append(f"critical option {name} is required")
    return {"ok": not issues, "issues": issues}


def validate_cert(cert: Mapping[str, Any]) -> list[str]:
    """Return structural problems found in a parsed certificate."""

    if not isinstance(cert, Mapping):
        return ["certificate is not an object"]
    issues: list[str] = []
    if cert.get("type") not in _KNOWN_TYPES:
        issues.append("unknown certificate type")
    principals = cert.get("principals")
    if not isinstance(principals, list) or not principals:
        issues.append("empty principal list")
    return issues


def cert_batch(
    connections: Sequence[Mapping[str, Any]],
    trusted: Mapping[str, Any],
    now: int | float,
) -> dict[str, dict[str, Any]]:
    """Validate a batch of connections and return one result per connection."""

    results: dict[str, dict[str, Any]] = {}
    if not connections:
        return results
    cert = parse_cert(connections[0].get("blob"))
    for index, connection in enumerate(connections):
        connection_id = str(connection.get("id", f"conn-{index}"))
        issues = list(validate_cert(cert))
        if not trusted:
            issues.append("no trusted certificate authorities configured")
        expected_type = connection.get("expected_type", "user")
        if not check_type(cert, expected_type):
            issues.append("certificate type does not match requested use")
        target = connection.get("target")
        if not check_principals(cert, target):
            issues.append("certificate principals do not match target")
        policy = connection.get("policy") or {}
        if policy:
            option_result = check_options(cert, policy)
            if not option_result["ok"]:
                issues.extend(option_result["issues"])
        results[connection_id] = {"ok": not issues, "issues": issues}
    return results