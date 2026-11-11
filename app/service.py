"""回调接收编排：头部校验 -> 时间窗 -> 原始字节验签 -> JSON 解析 -> 账本交接。

顺序不可调换：JSON 解析发生在验签**之后**，验签始终作用于未经任何重编码
的原始字节。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol

from .ledger import Ledger, utc_now
from .security import (
    ALGORITHM,
    SIGNATURE_VERSION,
    Keyring,
    check_timestamp,
    valid_event_id,
)


class Clock(Protocol):
    def now(self) -> int: ...


class SystemClock:
    def now(self) -> int:
        return utc_now()


class FixedClock:
    """测试用固定时钟。"""

    def __init__(self, epoch: int):
        self._epoch = epoch

    def now(self) -> int:
        return self._epoch

    def set(self, epoch: int) -> None:
        self._epoch = epoch


REQUIRED_HEADERS = ("X-Event-Id", "X-Sent-At", "X-Signature")


@dataclass(frozen=True)
class CallbackResult:
    status: int
    body: dict


class IngestService:
    def __init__(self, *, keyring: Keyring, ledger: Ledger,
                 window_seconds: int = 300, clock: Clock | None = None):
        self.keyring = keyring
        self.ledger = ledger
        self.window_seconds = window_seconds
        self.clock = clock or SystemClock()

    def handle_callback(self, headers: dict, raw_body: bytes) -> CallbackResult:
        now = self.clock.now()
        if not isinstance(raw_body, (bytes, bytearray)):
            return CallbackResult(400, {"error": "body_must_be_bytes"})
        raw_body = bytes(raw_body)

        missing = [h for h in REQUIRED_HEADERS if not headers.get(h)]
        if missing:
            return CallbackResult(400, {"error": "missing_headers",
                                        "missing": missing})

        event_id = headers["X-Event-Id"]
        sent_at = headers["X-Sent-At"]
        signature = headers["X-Signature"]
        claimed_key_id = headers.get("X-Key-Id")
        version = headers.get("X-Sig-Version") or SIGNATURE_VERSION
        safe_event_id = event_id if valid_event_id(event_id) else None
        body_sha = hashlib.sha256(raw_body).hexdigest()

        def reject(reason: str, status: int = 401,
                   key_id: str | None = None) -> CallbackResult:
            self.ledger.record_rejection(
                event_id=safe_event_id, observed_at=now, reason=reason,
                key_id=key_id, signature=signature, body_sha256=body_sha,
            )
            return CallbackResult(status, {"error": reason})

        if version != SIGNATURE_VERSION:
            return reject("unsupported_signature_version", 400)
        if not valid_event_id(event_id):
            return reject("bad_event_id", 400)

        ts_ok, ts_value, ts_reason = check_timestamp(sent_at, now,
                                                     self.window_seconds)
        if not ts_ok:
            return reject(ts_reason or "bad_timestamp", 401)

        result = self.keyring.verify(
            event_id=event_id, sent_at=sent_at, raw_body=raw_body,
            signature_hex=signature, now_epoch=now,
            claimed_key_id=claimed_key_id,
        )
        if not result.ok:
            return reject(result.reason or "bad_signature", 401)

        # 验签通过后才允许解析 JSON，且只用于字段交叉核对，不参与验签。
        try:
            parsed = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return reject("invalid_json", 400, key_id=result.key_id)
        if not isinstance(parsed, dict) or not isinstance(
            parsed.get("event_id"), str
        ):
            return reject("body_not_event_object", 400, key_id=result.key_id)
        if parsed["event_id"] != event_id:
            return reject("event_id_header_body_mismatch", 400,
                          key_id=result.key_id)

        outcome = self.ledger.ingest(
            event_id=event_id, raw_body=raw_body, body_sha256=body_sha,
            sent_at=ts_value, received_at=now, key_id=result.key_id,
            signature=signature, sig_version=version,
        )
        if outcome.result == "accepted":
            return CallbackResult(202, {
                "status": "accepted",
                "event_id": event_id,
                "key_id": result.key_id,
                "algorithm": ALGORITHM,
                "delivery": "pending",
            })
        if outcome.result == "duplicate":
            # 已持久化的相同重放：明确应答成功，阻止发送方继续无限重试。
            return CallbackResult(200, {
                "status": "duplicate_ignored",
                "event_id": event_id,
                "key_id": result.key_id,
            })
        return CallbackResult(409, {
            "error": "conflict_same_id_different_body",
            "event_id": event_id,
            "conflict_id": outcome.conflict_id,
        })
