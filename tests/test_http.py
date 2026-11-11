"""HTTP 端到端测试：原始字节上线、队列恢复、审计查询与安全重放入口。"""

import http.client
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.delivery import DirectoryQueue  # noqa: E402
from app.http_server import build_server  # noqa: E402
from app.ledger import Ledger  # noqa: E402
from app.security import Keyring  # noqa: E402
from app.service import FixedClock, IngestService  # noqa: E402
from tests.support import FIXTURES, SAMPLE_NOW, sample_request  # noqa: E402

ADMIN_TOKEN = "synthetic-admin-token"


class HttpGatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.queue = DirectoryQueue(root / "queue")
        self.clock = FixedClock(SAMPLE_NOW)
        keyring = Keyring.load(FIXTURES / "keystore.json")
        self.ledger = Ledger(root / "events.db")
        self.ingest = IngestService(keyring=keyring, ledger=self.ledger,
                                    window_seconds=300, clock=self.clock)
        # 不启动后台泵，恢复时机由测试显式控制
        self.server = build_server(
            keyring=keyring, ledger=self.ledger, queue=self.queue,
            admin_token=ADMIN_TOKEN, start_pump=False, clock=self.clock,
        )
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.tmp.cleanup()

    def _conn(self) -> http.client.HTTPConnection:
        return http.client.HTTPConnection(self.host, self.port, timeout=10)

    def _post_raw(self, path: str, headers: dict, raw: bytes,
                  admin: bool = False):
        conn = self._conn()
        hdrs = dict(headers)
        hdrs["Content-Type"] = "application/json"
        if admin:
            hdrs["X-Admin-Token"] = ADMIN_TOKEN
        conn.request("POST", path, body=raw, headers=hdrs)
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        return resp.status, data

    def test_callback_audit_and_replay_flow(self):
        headers, raw = sample_request("a-signed-new-key.json")
        status, data = self._post_raw("/callbacks/quality-event",
                                      headers, raw)
        self.assertEqual(status, 202)
        self.assertEqual(data["key_id"], "local-2026-11")
        event_id = headers["X-Event-Id"]

        # 重发同一原始请求 -> 幂等 200
        status2, data2 = self._post_raw("/callbacks/quality-event",
                                        headers, raw)
        self.assertEqual(status2, 200)
        self.assertEqual(data2["status"], "duplicate_ignored")

        # 审计查询
        conn = self._conn()
        conn.request("GET", f"/audit/events/{event_id}")
        resp = conn.getresponse()
        audit = json.loads(resp.read().decode("utf-8"))
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertEqual(audit["event"]["event_id"], event_id)
        self.assertEqual(len(audit["observations"]), 2)
        self.assertIn("raw_body_b64", audit["event"])

        # 队列暂时不可用：先让泵失败一次，应答仍然是 2xx 且事件留存
        self.queue.inject_failure(1)
        stats = self.server.pump.run_once(self.clock.now())
        self.assertEqual(stats.failed, 1)
        self.assertEqual(self.queue.delivered_ids(), [])

        # 管理端重放需要 token
        conn = self._conn()
        conn.request("POST", f"/admin/events/{event_id}/replay")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 403)
        resp.read()
        conn.close()

        # 推进时间越过退避，安全重放：新交付尝试 + 原始签名证据
        self.clock.set(SAMPLE_NOW + 60)
        status3, report = self._post_raw(
            f"/admin/events/{event_id}/replay", {}, b"", admin=True)
        self.assertEqual(status3, 200)
        self.assertTrue(report["delivered"])
        self.assertTrue(report["scheduled"]["reuses_original_signature"])
        self.assertEqual(self.queue.delivered_ids(), [event_id])

        message = json.loads(
            (Path(self.queue.directory) / f"{event_id}.json").read_text(
                encoding="utf-8"))
        self.assertEqual(message["evidence"]["signature"],
                         headers["X-Signature"])
        self.assertEqual(message["evidence"]["attempt_no"], 2)

        # 再次审计：交付历史完整
        conn = self._conn()
        conn.request("GET", f"/audit/events/{event_id}")
        audit2 = json.loads(conn.getresponse().read().decode("utf-8"))
        conn.close()
        self.assertEqual(audit2["event"]["status"], "delivered")
        self.assertEqual(
            [a["outcome"] for a in audit2["delivery_attempts"]],
            ["failed", "delivered"],
        )

    def test_unknown_event_audit_404_and_replay_404(self):
        conn = self._conn()
        conn.request("GET", "/audit/events/nope")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 404)
        resp.read()
        conn.close()

        status, _ = self._post_raw("/admin/events/nope/replay", {}, b"",
                                   admin=True)
        self.assertEqual(status, 404)

    def test_healthz_reports_pending(self):
        headers, raw = sample_request("b-signed-new-key.json")
        self._post_raw("/callbacks/quality-event", headers, raw)
        conn = self._conn()
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertEqual(data["pending_delivery"], 1)


if __name__ == "__main__":
    unittest.main()
