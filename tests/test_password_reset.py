import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from sud.password_reset import PasswordResetService


def test_generate_and_validate_token_round_trip():
    service = PasswordResetService(secret_key="secret", token_ttl_seconds=10)
    token = service.generate_token("user-123")
    assert service.validate_token(token) == "user-123"


def test_token_expiration(monkeypatch):
    service = PasswordResetService(secret_key="secret", token_ttl_seconds=1)

    frozen_time = [1_000_000]

    def fake_time():
        return frozen_time[0]

    monkeypatch.setattr("sud.password_reset.time.time", fake_time)
    token = service.generate_token("user-123")

    frozen_time[0] += 2
    assert service.validate_token(token) is None


def test_token_integrity_failure():
    service = PasswordResetService(secret_key="secret")
    token = service.generate_token("user-123")

    payload_b64, signature_b64 = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode("utf-8"))
    payload["uid"] = "attacker"
    tampered_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        .rstrip(b"=")
        .decode("utf-8")
    )
    tampered = f"{tampered_payload_b64}.{signature_b64}"
    assert service.validate_token(tampered) is None


def test_rate_limit_enforced(monkeypatch):
    service = PasswordResetService(secret_key="secret", rate_limit_per_hour=2)

    base_time = [1_000_000]

    def fake_time():
        return base_time[0]

    monkeypatch.setattr("sud.password_reset.time.time", fake_time)

    service.generate_token("user-123")
    service.generate_token("user-123")
    with pytest.raises(ValueError):
        service.generate_token("user-123")

    base_time[0] += 3601
    token = service.generate_token("user-123")
    assert service.validate_token(token) == "user-123"
