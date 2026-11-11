"""签名原语与密钥轮换测试。"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.security import (  # noqa: E402
    SIGNATURE_VERSION,
    Keyring,
    build_signed_input,
    check_timestamp,
    parse_iso8601,
    sign_request,
    valid_event_id,
)
from tests.support import FIXTURES, SAMPLE_NOW  # noqa: E402

OLD_KEY = "local-2026-10"
NEW_KEY = "local-2026-11"
FUTURE_KEY = "local-2026-12"


class KeyRotationTests(unittest.TestCase):
    def setUp(self):
        self.keyring = Keyring.load(FIXTURES / "keystore.json")

    def test_overlap_period_accepts_both_keys_and_prefers_new(self):
        # 交叉期内两把密钥都在效
        active = {k.key_id for k in self.keyring.active_keys(SAMPLE_NOW)}
        self.assertEqual(active, {OLD_KEY, NEW_KEY})
        # 新密钥优先（默认顺序的第一个）
        self.assertEqual(self.keyring.active_keys(SAMPLE_NOW)[0].key_id,
                         NEW_KEY)

    def test_old_key_retired_after_overlap(self):
        retired = parse_iso8601("2026-11-15T00:00:00Z")
        active = {k.key_id for k in self.keyring.active_keys(retired)}
        self.assertNotIn(OLD_KEY, active)
        self.assertIn(NEW_KEY, active)

    def test_future_key_not_active(self):
        active = {k.key_id for k in self.keyring.active_keys(SAMPLE_NOW)}
        self.assertNotIn(FUTURE_KEY, active)

    def test_claimed_key_id_used_first_in_overlap(self):
        # 同一份请求分别由新旧密钥签署；验签后记录实际采用的 key_id
        from tests.support import sample_request
        for name, expected in (
            ("a-signed-old-key.json", OLD_KEY),
            ("a-signed-new-key.json", NEW_KEY),
        ):
            headers, raw = sample_request(name)
            result = self.keyring.verify(
                event_id=headers["X-Event-Id"],
                sent_at=headers["X-Sent-At"], raw_body=raw,
                signature_hex=headers["X-Signature"], now_epoch=SAMPLE_NOW,
                claimed_key_id=headers["X-Key-Id"],
            )
            self.assertTrue(result.ok, name)
            self.assertEqual(result.key_id, expected)

    def test_future_key_signature_rejected(self):
        from tests.support import sample_request
        headers, raw = sample_request("a-future-key.json")
        result = self.keyring.verify(
            event_id=headers["X-Event-Id"], sent_at=headers["X-Sent-At"],
            raw_body=raw, signature_hex=headers["X-Signature"],
            now_epoch=SAMPLE_NOW,
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "bad_signature")


class RawByteSignatureTests(unittest.TestCase):
    def test_length_prefixed_framing_is_unambiguous(self):
        f1 = build_signed_input("100", "evt-1", b"ab")
        f2 = build_signed_input("1000", "evt", b"-1ab")
        self.assertNotEqual(f1, f2)
        self.assertTrue(f1.startswith(SIGNATURE_VERSION.encode() + b"|"))

    def test_signature_covers_raw_bytes(self):
        key = b"unit-secret"
        body = b'{"event_id":"evt-x","v":1}'
        sig = sign_request(key, "1000", "evt-x", body)
        # 任意单字节改动都使验签失败
        tampered = body.replace(b"1", b"2", 1)
        self.assertNotEqual(
            sign_request(key, "1000", "evt-x", tampered), sig
        )

    def test_semantically_equal_reencoded_bytes_have_other_signature(self):
        key = b"unit-secret"
        original = b'{\n  "event_id": "evt-x",\n  "v": 1\n}'
        reencoded = b'{"v": 1, "event_id": "evt-x"}'
        import json
        self.assertEqual(json.loads(original), json.loads(reencoded))
        self.assertNotEqual(
            sign_request(key, "1000", "evt-x", original),
            sign_request(key, "1000", "evt-x", reencoded),
        )

    def test_bad_event_id_rejected(self):
        self.assertFalse(valid_event_id(""))
        self.assertFalse(valid_event_id("bad id"))
        self.assertFalse(valid_event_id("x" * 129))
        self.assertTrue(valid_event_id("evt_line-1"))


class TimestampWindowTests(unittest.TestCase):
    def test_within_and_outside_window(self):
        ok, ts, reason = check_timestamp(str(SAMPLE_NOW + 120), SAMPLE_NOW, 300)
        self.assertTrue(ok)
        self.assertIsNone(reason)
        ok, ts, reason = check_timestamp(str(SAMPLE_NOW + 301), SAMPLE_NOW, 300)
        self.assertFalse(ok)
        self.assertEqual(reason, "outside_window")

    def test_malformed_timestamp(self):
        ok, ts, reason = check_timestamp("not-a-number", SAMPLE_NOW, 300)
        self.assertFalse(ok)
        self.assertEqual(reason, "bad_timestamp")


if __name__ == "__main__":
    unittest.main()
