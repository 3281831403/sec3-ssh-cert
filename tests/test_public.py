"""Public contract tests for SSH certificate validation."""

from __future__ import annotations

import json
from typing import Any

from sshcert.check import (
    _sign_cert,
    cert_batch,
    check_principals,
    check_times,
    check_type,
    parse_cert,
    validate_cert,
)

SECRET = "public-ca-secret"
TRUSTED = {"ca-main": SECRET}


def _certificate(**overrides: Any) -> dict[str, Any]:
    certificate: dict[str, Any] = {
        "type": "user",
        "key_id": "alice",
        "principals": ["alice"],
        "valid_after": 100,
        "valid_before": 200,
        "critical_options": {"force_command": "/usr/bin/id"},
        "extensions": {},
        "ca": "ca-main",
    }
    certificate.update(overrides)
    certificate["signature"] = _sign_cert(certificate, SECRET)
    return certificate


def _blob(certificate: dict[str, Any]) -> bytes:
    return json.dumps(certificate, sort_keys=True, ensure_ascii=False).encode("utf-8")


def test_parse_cert_extracts_fields_and_reports_missing_validity() -> None:
    parsed = parse_cert(_blob(_certificate()))

    assert parsed["type"] == "user"
    assert parsed["key_id"] == "alice"
    assert parsed["principals"] == ["alice"]
    assert parsed["critical_options"] == {"force_command": "/usr/bin/id"}
    assert parsed["ca"] == "ca-main"

    incomplete = _certificate()
    del incomplete["valid_after"]
    issues = validate_cert(parse_cert(_blob(incomplete)))
    assert any("valid" in issue.lower() for issue in issues), issues


def test_check_times_rejects_expired_certificate() -> None:
    certificate = _certificate(valid_after=100, valid_before=200)

    assert check_times(certificate, 100) is True
    assert check_times(certificate, 200) is True
    assert check_times(certificate, 201) is False


def test_check_type_rejects_certificate_for_other_purpose() -> None:
    host_certificate = _certificate(type="host")

    assert check_type(host_certificate, "host") is True
    assert check_type(host_certificate, "user") is False


def test_check_principals_requires_exact_match() -> None:
    assert check_principals(_certificate(principals=["alice"]), "alice") is True
    assert check_principals(_certificate(principals=["alice-admin"]), "alice") is False


def test_cert_batch_checks_two_connections_independently() -> None:
    alice = _certificate(key_id="alice", principals=["alice"])
    bob = _certificate(key_id="bob", principals=["bob"])
    connections = [
        {
            "id": "alice",
            "blob": _blob(alice),
            "target": "alice",
            "expected_type": "user",
        },
        {
            "id": "bob",
            "blob": _blob(bob),
            "target": "bob",
            "expected_type": "user",
        },
    ]

    results = cert_batch(connections, TRUSTED, now=150)

    assert results["alice"]["ok"] is True, results["alice"]
    assert results["bob"]["ok"] is True, results["bob"]