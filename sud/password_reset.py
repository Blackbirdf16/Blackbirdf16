"""Password reset token issuance and validation with security controls."""

from __future__ import annotations

import base64
import hmac
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


@dataclass
class PasswordResetService:
    secret_key: str
    token_ttl_seconds: int = 3600
    rate_limit_per_hour: int = 5
    _issued_timestamps: Dict[str, List[float]] = field(default_factory=dict, init=False, repr=False)
    _consumed_nonces: Dict[str, float] = field(default_factory=dict, init=False, repr=False)

    def _now(self) -> float:
        return time.time()

    def _prune_old(self, user_id: str) -> None:
        cutoff = self._now() - 3600
        timestamps = self._issued_timestamps.get(user_id, [])
        self._issued_timestamps[user_id] = [ts for ts in timestamps if ts >= cutoff]

    def can_issue(self, user_id: str) -> bool:
        self._prune_old(user_id)
        return len(self._issued_timestamps.get(user_id, [])) < self.rate_limit_per_hour

    def rate_limit_remaining(self, user_id: str) -> int:
        """Return how many reset tokens can still be issued for the user in the current hour window."""

        self._prune_old(user_id)
        return max(self.rate_limit_per_hour - len(self._issued_timestamps.get(user_id, [])), 0)

    def _sign(self, payload: str) -> bytes:
        return hmac.new(self.secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()

    def generate_token(self, user_id: str) -> str:
        if not user_id:
            raise ValueError("user_id is required")
        if not self.can_issue(user_id):
            raise ValueError("rate limit exceeded for password reset tokens")

        payload = {
            "uid": user_id,
            "ts": int(self._now()),
            "nonce": secrets.token_urlsafe(8),
        }
        payload_json = json.dumps(payload, separators=(",", ":"))
        signature = self._sign(payload_json)

        token = f"{_b64encode(payload_json.encode())}.{_b64encode(signature)}"
        self._issued_timestamps.setdefault(user_id, []).append(payload["ts"])
        return token

    def validate_token(self, token: str) -> Optional[str]:
        return self._validate_token_internal(token, consume=False)[0]

    def validate_token_once(self, token: str) -> Optional[str]:
        """Validate the token and consume it so it cannot be reused."""

        return self._validate_token_internal(token, consume=True)[0]

    def _validate_token_internal(self, token: str, consume: bool) -> Tuple[Optional[str], Optional[str]]:
        try:
            payload_b64, signature_b64 = token.split(".")
            payload_json = _b64decode(payload_b64).decode("utf-8")
            provided_sig = _b64decode(signature_b64)
            expected_sig = self._sign(payload_json)
        except Exception:
            return None, None

        if not hmac.compare_digest(provided_sig, expected_sig):
            return None, None

        try:
            payload = json.loads(payload_json)
            issued_at = int(payload.get("ts", 0))
            user_id = str(payload.get("uid", ""))
            nonce = str(payload.get("nonce", ""))
        except (TypeError, ValueError):
            return None, None

        if not user_id:
            return None, None

        if consume and (not nonce or self._is_nonce_consumed(nonce)):
            return None, None

        if self._now() - issued_at > self.token_ttl_seconds:
            return None, None

        if consume and nonce:
            self._consumed_nonces[nonce] = issued_at

        self._prune_consumed()
        return user_id, nonce

    def _is_nonce_consumed(self, nonce: str) -> bool:
        self._prune_consumed()
        return nonce in self._consumed_nonces

    def _prune_consumed(self) -> None:
        cutoff = self._now() - self.token_ttl_seconds
        self._consumed_nonces = {
            nonce: ts for nonce, ts in self._consumed_nonces.items() if ts >= cutoff
        }
