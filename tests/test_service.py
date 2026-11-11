"""端到端接收流程：时间窗、原始字节验签、去重、冲突与审计。"""

import base64
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.support import (  # noqa: E402
    FIXTURES,
    SAMPLE_NOW,
    build_service,
    load_sample,
    sample_request,
)


class IngestFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "events.db"
        self.service, self.clock = build_service(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def _post(self, sample_name):
        headers, raw = sample_request(sample_name)
        return self.service.handle_callback(headers, raw), headers, raw

    def test_accept_new_key_in_overlap(self):
        result, headers, _ = self._post("a-signed-new-key.json")
        self.assertEqual(result.status, 202)
        self.assertEqual(result.body["key_id"], "local-2026-11")
        audit = self.service.ledger.get_audit(headers["X-Event-Id"])
        self.assertEqual(audit["event"]["status"], "accepted")
        self.assertEqual(audit["event"]["key_id"], "local-2026-11")

    def test_in_flight_old_key_still_accepted_during_overlap(self):
        result, headers, _ = self._post("a-signed-old-key.json")
        self.assertEqual(result.status, 202)
        self.assertEqual(result.body["key_id"], "local-2026-10")
        audit = self.service.ledger.get_audit(headers["X-Event-Id"])
        self.assertEqual(audit["observations"][0]["outcome"], "accepted")

    def test_identical_redelivery_is_idempotent(self):
        first, headers, _ = self._post("a-signed-new-key.json")
        self.assertEqual(first.status, 202)
        second, _, _ = self._post("a-redelivery.json")
        # 相同 ID + 相同字节：明确 2xx，且不重复入队
        self.assertEqual(second.status, 200)
        self.assertEqual(second.body["status"], "duplicate_ignored")
        audit = self.service.ledger.get_audit(headers["X-Event-Id"])
        self.assertEqual(len(audit["delivery_attempts"]), 0)
        outcomes = [o["outcome"] for o in audit["observations"]]
        self.assertEqual(outcomes, ["accepted", "duplicate"])

    def test_same_id_different_body_is_conflict_not_replay(self):
        self._post("a-signed-new-key.json")
        conflict, headers, _ = self._post("a-conflict-body.json")
        self.assertEqual(conflict.status, 409)
        self.assertIn("conflict", conflict.body["error"])
        audit = self.service.ledger.get_audit(headers["X-Event-Id"])
        # 原始事件保持不变，冲突另留证据
        self.assertEqual(len(audit["conflicts"]), 1)
        self.assertNotEqual(
            audit["conflicts"][0]["existing_sha"],
            audit["conflicts"][0]["incoming_sha"],
        )
        self.assertEqual(audit["event"]["status"], "accepted")

    def test_reencoded_bytes_fail_signature_even_if_json_equal(self):
        # 先接受原始请求
        ok, headers, raw = self._post("a-signed-new-key.json")
        self.assertEqual(ok.status, 202)
        # 重编码字节即使 JSON 语义等价，原签名也无法通过
        sample = load_sample("a-reencoded-tampered.json")
        reencoded = base64.b64decode(sample["raw_body_b64"])
        import json
        self.assertEqual(json.loads(reencoded), json.loads(raw))
        result = self.service.handle_callback(dict(sample["headers"]),
                                              reencoded)
        self.assertEqual(result.status, 401)
        self.assertEqual(result.body["error"], "bad_signature")

    def test_stale_timestamp_rejected(self):
        result, _, _ = self._post("a-stale-timestamp.json")
        self.assertEqual(result.status, 401)
        self.assertEqual(result.body["error"], "outside_window")

    def test_tampered_signature_rejected(self):
        headers, raw = sample_request("a-signed-new-key.json")
        headers["X-Signature"] = "0" * len(headers["X-Signature"])
        result = self.service.handle_callback(headers, raw)
        self.assertEqual(result.status, 401)
        self.assertEqual(result.body["error"], "bad_signature")

    def test_missing_header_rejected(self):
        headers, raw = sample_request("a-signed-new-key.json")
        del headers["X-Signature"]
        result = self.service.handle_callback(headers, raw)
        self.assertEqual(result.status, 400)
        self.assertEqual(result.body["error"], "missing_headers")

    def test_body_event_id_must_match_header(self):
        headers, raw = sample_request("a-signed-new-key.json")
        # 伪造一份自洽签名但 ID 与头部不一致的请求
        from app.security import sign_request
        secret = (FIXTURES / "keys" / "local-2026-11.json").read_text()
        import json as _json
        key = _json.loads(secret)
        forged = b'{"event_id":"evt-other","value":1}'
        sig = sign_request(key["secret"].encode(), headers["X-Sent-At"],
                           headers["X-Event-Id"], forged)
        headers["X-Signature"] = sig
        result = self.service.handle_callback(headers, forged)
        self.assertEqual(result.status, 400)
        self.assertEqual(result.body["error"], "event_id_header_body_mismatch")

    def test_no_secret_material_persisted(self):
        self._post("a-signed-new-key.json")
        self._post("b-signed-new-key.json")
        self._post("c-signed-old-key.json")
        secret_markers = (
            b"synthetic-new-shared-key-202611",
            b"synthetic-old-shared-key-202610",
            b"synthetic-future-shared-key-202612",
        )
        # 直接扫数据库所有页，确认密钥本身从未落盘
        for db_file in Path(self.tmp.name).iterdir():
            if db_file.suffix in (".db", ".wal", ".shm") or db_file.name.endswith("-wal"):
                blob = db_file.read_bytes()
                for marker in secret_markers:
                    self.assertNotIn(marker, blob, f"密钥泄漏到 {db_file}")
        # 审计里只有 key_id 和签名证据
        audit = self.service.ledger.get_audit("evt-line-001")
        self.assertEqual(audit["event"]["key_id"], "local-2026-11")
        self.assertIn("signature", audit["event"])
        self.assertNotIn("secret", audit["event"])

    def test_retention_purge_removes_only_old_delivered(self):
        self._post("a-signed-new-key.json")
        ledger = self.service.ledger
        # 未交付不会被清理
        removed = ledger.purge_expired(SAMPLE_NOW + 9999, retention_seconds=10)
        self.assertEqual(removed, 0)
        # 标记交付后，超出保留期才清理
        claims = ledger.claim_due(SAMPLE_NOW)
        for claim in claims:
            ledger.finish_attempt(claim.attempt_id, delivered=True,
                                  now_epoch=SAMPLE_NOW)
        removed = ledger.purge_expired(SAMPLE_NOW + 9999, retention_seconds=10)
        self.assertEqual(removed, 1)
        self.assertIsNone(ledger.get_audit("evt-line-001"))


if __name__ == "__main__":
    unittest.main()
