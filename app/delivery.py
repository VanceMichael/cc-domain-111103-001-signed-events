"""下游交付：可故障注入的队列抽象与 outbox 恢复泵。

应答/交接协调原则
=================
回调在事件**持久化进接收账本**后就返回 2xx（202 Accepted），即使下游队列
暂时不可用。事件停留在账本的 outbox（status='accepted' + next_attempt_at），
由本模块的泵按退避重试。发送方因此不会无限重试，也不会产生重复副作用；
恢复交付由租约（attempt 行）+ 退避保证不丢事件、崩溃后可继续。
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .ledger import ClaimedDelivery, Ledger


class QueueUnavailable(RuntimeError):
    """下游队列暂时不可用（可重试错误）。"""


class DownstreamQueue:
    """队列接口。生产实现可换成 Kafka/SQS/内部 RPC；样例用目录队列。"""

    def publish(self, *, event_id: str, payload: dict) -> None:
        raise NotImplementedError


class DirectoryQueue(DownstreamQueue):
    """把交付物原子写入目录的本地队列；可注入故障用于恢复演练。

    以 event_id 命名落盘，因此即使上层重复调用，下游也只会出现一条消息
    （下游按事件 ID 幂等的本地替身）。
    """

    def __init__(self, directory: str | Path, *, fail_times: int = 0):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._remaining_failures = fail_times
        self.publish_calls = 0

    def inject_failure(self, times: int = 1) -> None:
        self._remaining_failures += times

    def publish(self, *, event_id: str, payload: dict) -> None:
        self.publish_calls += 1
        if self._remaining_failures > 0:
            self._remaining_failures -= 1
            raise QueueUnavailable("合成故障：队列暂不可用")
        target = self.directory / f"{event_id}.json"
        if target.exists():
            # 下游幂等：同一事件 ID 的重复 publish 不产生副作用。
            return
        fd, tmp = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False)
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def delivered_ids(self) -> list[str]:
        return sorted(p.stem for p in self.directory.glob("*.json"))


@dataclass
class PumpStats:
    claimed: int = 0
    delivered: int = 0
    failed: int = 0


def build_payload(claim: ClaimedDelivery) -> dict:
    """构造下游消息：原始正文 + 原始签名证据，绝不重新签名。"""
    return {
        "event_id": claim.event_id,
        "raw_body": claim.raw_body.decode("utf-8"),
        "evidence": {
            "key_id": claim.key_id,
            "signature": claim.signature,
            "sent_at": claim.sent_at,
            "attempt_no": claim.attempt_no,
            "origin": claim.origin,
        },
    }


class OutboxPump:
    def __init__(self, ledger: Ledger, queue: DownstreamQueue, *,
                 base_backoff: int = 5, max_backoff: int = 300,
                 lease_seconds: int = 60):
        self.ledger = ledger
        self.queue = queue
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self.lease_seconds = lease_seconds

    def _backoff(self, attempt_no: int) -> int:
        return min(self.max_backoff, self.base_backoff * 2 ** max(0, attempt_no - 1))

    def run_once(self, now_epoch: int, *, limit: int = 16,
                 origin: str = "pump") -> PumpStats:
        self.ledger.reclaim_stuck(now_epoch, self.lease_seconds)
        stats = PumpStats()
        for claim in self.ledger.claim_due(now_epoch, limit=limit, origin=origin):
            stats.claimed += 1
            try:
                self.queue.publish(event_id=claim.event_id,
                                   payload=build_payload(claim))
            except QueueUnavailable as exc:
                stats.failed += 1
                self.ledger.finish_attempt(
                    claim.attempt_id, delivered=False, now_epoch=now_epoch,
                    backoff_seconds=self._backoff(claim.attempt_no),
                    error=str(exc),
                )
            except Exception as exc:  # 未知错误也按可重试处理并留痕
                stats.failed += 1
                self.ledger.finish_attempt(
                    claim.attempt_id, delivered=False, now_epoch=now_epoch,
                    backoff_seconds=self.max_backoff,
                    error=f"{type(exc).__name__}: {exc}",
                )
            else:
                stats.delivered += 1
                self.ledger.finish_attempt(claim.attempt_id, delivered=True,
                                           now_epoch=now_epoch)
        return stats

    def deliver_now(self, ledger: Ledger, event_id: str, now_epoch: int,
                    *, operator: str, origin: str = "manual_replay") -> dict:
        """操作重放：立即跑一次该事件的交付，沿用原始证据。

        手动重放无视泵的指数退避——`request_replay` 会把事件重新置为
        accepted，随后用 `claim_event` 强制认领，保证新尝试立刻产生。
        """
        scheduled = ledger.request_replay(event_id, now_epoch, operator)
        target = ledger.claim_event(event_id, now_epoch, origin=origin)
        if target is None:
            return {"scheduled": scheduled, "delivered": False,
                    "error": "claim_unavailable"}
        try:
            self.queue.publish(event_id=target.event_id,
                               payload=build_payload(target))
        except QueueUnavailable as exc:
            ledger.finish_attempt(target.attempt_id, delivered=False,
                                  now_epoch=now_epoch,
                                  backoff_seconds=self.base_backoff,
                                  error=str(exc))
            return {"scheduled": scheduled, "delivered": False, "error": str(exc)}
        ledger.finish_attempt(target.attempt_id, delivered=True,
                              now_epoch=now_epoch)
        return {"scheduled": scheduled, "delivered": True,
                "attempt_no": target.attempt_no}
