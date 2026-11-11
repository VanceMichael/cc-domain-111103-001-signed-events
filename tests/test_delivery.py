"""outbox 交接与队列恢复测试。"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.delivery import DirectoryQueue, OutboxPump, QueueUnavailable  # noqa: E402
from app.ledger import Ledger  # noqa: E402
from tests.support import SAMPLE_NOW, build_service, sample_request  # noqa: E402

T0 = SAMPLE_NOW  # 与账本接收时间同一基准（真实 epoch 秒）


class DeliveryRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = root / "events.db"
        self.queue_dir = root / "queue"
        self.service, _ = build_service(self.db)
        self.ledger = self.service.ledger

    def tearDown(self):
        self.tmp.cleanup()

    def _accept(self, name="a-signed-new-key.json"):
        headers, raw = sample_request(name)
        result = self.service.handle_callback(headers, raw)
        self.assertEqual(result.status, 202)
        return headers["X-Event-Id"]

    def test_accepted_event_waits_in_outbox_when_queue_down(self):
        event_id = self._accept()
        queue = DirectoryQueue(self.queue_dir, fail_times=1)
        pump = OutboxPump(self.ledger, queue, base_backoff=10)

        first = pump.run_once(now_epoch=T0)
        self.assertEqual((first.claimed, first.failed, first.delivered),
                         (1, 1, 0))
        audit = self.ledger.get_audit(event_id)
        self.assertEqual(audit["event"]["status"], "accepted")
        self.assertEqual(audit["delivery_attempts"][-1]["outcome"], "failed")
        self.assertEqual(queue.delivered_ids(), [])

        # 退避未到期不重试；到期后队列恢复 -> 交付成功，事件不丢
        self.assertEqual(pump.run_once(now_epoch=T0+5).claimed, 0)
        second = pump.run_once(now_epoch=T0+10)
        self.assertEqual((second.claimed, second.delivered), (1, 1))
        self.assertEqual(queue.delivered_ids(), [event_id])
        audit = self.ledger.get_audit(event_id)
        self.assertEqual(audit["event"]["status"], "delivered")
        self.assertEqual(len(audit["delivery_attempts"]), 2)

    def test_repeated_pump_runs_do_not_duplicate_side_effects(self):
        event_id = self._accept()
        queue = DirectoryQueue(self.queue_dir)
        pump = OutboxPump(self.ledger, queue)
        pump.run_once(now_epoch=T0)
        pump.run_once(now_epoch=T0+1)
        pump.run_once(now_epoch=T0+2)
        self.assertEqual(queue.delivered_ids(), [event_id])
        # 下游目录队列按 event_id 幂等，publish 只产生一条消息
        self.assertEqual(len(list(Path(self.queue_dir).glob("*.json"))), 1)

    def test_manual_replay_creates_new_attempt_reusing_original_evidence(self):
        event_id = self._accept()
        queue = DirectoryQueue(self.queue_dir)
        pump = OutboxPump(self.ledger, queue)
        pump.run_once(now_epoch=T0)  # 首次交付成功

        report = pump.deliver_now(self.ledger, event_id, now_epoch=T0+1000,
                                  operator="ops-liu")
        self.assertTrue(report["delivered"])
        self.assertTrue(report["scheduled"]["reuses_original_signature"])
        self.assertEqual(report["attempt_no"], 2)

        audit = self.ledger.get_audit(event_id)
        origins = [a["origin"] for a in audit["delivery_attempts"]]
        self.assertEqual(origins, ["pump", "manual_replay"])
        # 新尝试沿用的签名与事件首次接收时完全一致
        payload = Path(self.queue_dir / f"{event_id}.json")
        import json
        message = json.loads(payload.read_text(encoding="utf-8"))
        self.assertEqual(message["evidence"]["signature"],
                         audit["event"]["signature"])
        self.assertEqual(message["evidence"]["key_id"],
                         audit["event"]["key_id"])
        self.assertIn("replay_requested",
                      [o["outcome"] for o in audit["observations"]])

    def test_replay_while_pending_supersedes_old_attempt(self):
        event_id = self._accept()
        queue = DirectoryQueue(self.queue_dir)
        # 认领但不结束，模拟一次挂住的尝试
        claims = self.ledger.claim_due(now_epoch=T0)
        self.assertEqual(len(claims), 1)
        pump = OutboxPump(self.ledger, queue)
        report = pump.deliver_now(self.ledger, event_id, now_epoch=T0+1,
                                  operator="ops-chen")
        self.assertTrue(report["delivered"])
        audit = self.ledger.get_audit(event_id)
        outcomes = [a["outcome"] for a in audit["delivery_attempts"]]
        self.assertEqual(outcomes, ["superseded", "delivered"])

    def test_stuck_lease_is_reclaimed_after_timeout(self):
        event_id = self._accept()
        queue = DirectoryQueue(self.queue_dir)
        pump = OutboxPump(self.ledger, queue, lease_seconds=60)
        self.ledger.claim_due(now_epoch=T0)  # 模拟进程崩溃，未 finish
        # 租约期内不回收
        self.assertEqual(pump.run_once(now_epoch=T0+30).claimed, 0)
        # 超时后回收并重新交付
        stats = pump.run_once(now_epoch=T0+70)
        self.assertEqual(stats.delivered, 1)
        audit = self.ledger.get_audit(event_id)
        outcomes = [a["outcome"] for a in audit["delivery_attempts"]]
        self.assertEqual(outcomes, ["failed", "delivered"])
        self.assertEqual(audit["delivery_attempts"][0]["error"],
                         "lease_expired")


if __name__ == "__main__":
    unittest.main()
