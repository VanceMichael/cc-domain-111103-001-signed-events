"""生成本地合成样例：密钥、虚构设备事件、已签名请求。

运行（从仓库根目录）：

    python3 -I scripts/generate_fixtures.py

所有内容均为合成数据：虚构密钥只用于离线测试，不存在真实生产凭据；
设备/产线/事件全部虚构，没有任何真实设备连接或真实企业数据。
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.security import (  # noqa: E402
    ALGORITHM,
    SIGNATURE_VERSION,
    Keyring,
    parse_iso8601,
    sign_request,
)

FIXTURES = ROOT / "fixtures"
KEYS_DIR = FIXTURES / "keys"
SAMPLES_DIR = FIXTURES / "signed-samples"

# 合成时间线（UTC）。接收测试把“当前时刻”固定在 SAMPLE_NOW，
# 交叉期 = 2026-11-08T00:00Z ~ 2026-11-15T00:00Z，两把密钥同时在效。
SAMPLE_NOW_ISO = "2026-11-11T09:00:00Z"
SENT_AT_ISO = "2026-11-11T08:59:50Z"
STALE_AT_ISO = "2026-11-11T07:00:00Z"  # 距 SAMPLE_NOW 两小时，超出 300s 窗口

SYNTHETIC_KEYS = [
    {
        "key_id": "local-2026-10",
        "secret": "synthetic-old-shared-key-202610",
        "valid_from": "2026-10-01T00:00:00Z",
        "retired_at": "2026-11-15T00:00:00Z",
        "note": "旧密钥，交接期末退役（虚构）",
    },
    {
        "key_id": "local-2026-11",
        "secret": "synthetic-new-shared-key-202611",
        "valid_from": "2026-11-08T00:00:00Z",
        "retired_at": "2026-12-01T00:00:00Z",
        "note": "新密钥，交接期内与旧密钥同时在效（虚构）",
    },
    {
        "key_id": "local-2026-12",
        "secret": "synthetic-future-shared-key-202612",
        "valid_from": "2026-12-01T00:00:00Z",
        "retired_at": "2027-01-01T00:00:00Z",
        "note": "尚未生效的密钥，用于负向样例（虚构）",
    },
]

# 全部是虚构产线/设备事件。
EVENTS = {
    "event-a.json": {
        "event_id": "evt-line-001",
        "device_sn": "SYN-PRESS-0001",
        "line": "L-01",
        "quality": "ok",
        "value": 17,
        "occurred_at": "2026-11-11T08:59:40Z",
    },
    "event-b.json": {
        "event_id": "evt-line-002",
        "device_sn": "SYN-WELDER-0007",
        "line": "L-02",
        "quality": "review",
        "value": 21,
        "occurred_at": "2026-11-11T08:59:42Z",
    },
    "event-c.json": {
        "event_id": "evt-line-003",
        "device_sn": "SYN-CAMERA-0013",
        "line": "L-03",
        "quality": "alarm",
        "value": 99,
        "occurred_at": "2026-11-11T08:59:44Z",
    },
}

# 同一 event_id 的另一种**字节级**正文（JSON 语义仍带相同 event_id），
# 用来演示“相同 ID 不同正文”的冲突，而不是普通重放。
CONFLICT_BODY = (
    b'{\n  "event_id": "evt-line-001",\n'
    b'  "device_sn": "SYN-PRESS-0001",\n'
    b'  "line": "L-01",\n  "quality": "alarm",\n'
    b'  "value": 88,\n  "occurred_at": "2026-11-11T08:59:40Z"\n}'
)

# 语义等价但字节不同的重编码正文（键序/空白变化），同样必须验签失败。
REENCODED_BODY = (
    b'{"value": 17, "quality": "ok", "line": "L-01", '
    b'"event_id": "evt-line-001", '
    b'"occurred_at": "2026-11-11T08:59:40Z", '
    b'"device_sn": "SYN-PRESS-0001"}'
)


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")


def _sample(key, sent_at_iso: str, event_id: str, raw_body: bytes) -> dict:
    sent_at = str(parse_iso8601(sent_at_iso))
    signature = sign_request(key.secret, sent_at, event_id, raw_body)
    return {
        "description": "合成已签名请求；签名覆盖原始字节、sent_at 与 event_id",
        "algorithm": ALGORITHM,
        "sig_version": SIGNATURE_VERSION,
        "signed_format": (
            "SIG-V1 分帧：版本头 + 对 sent_at / event_id / 原始正文依次写入"
            "[8 字节大端长度][字段字节]，再做 HMAC-SHA256"
        ),
        "headers": {
            "X-Event-Id": event_id,
            "X-Sent-At": sent_at,
            "X-Key-Id": key.key_id,
            "X-Sig-Version": SIGNATURE_VERSION,
            "X-Signature": signature,
        },
        "raw_body_b64": base64.b64encode(raw_body).decode("ascii"),
        "raw_body_utf8": raw_body.decode("utf-8"),
        "synthetic_note": "虚构设备事件，仅用于离线测试",
    }


def _with_body(sample: dict, raw_body: bytes) -> dict:
    """保留样例的签名证据，仅替换被运送的正文（模拟字节被篡改/重编码）。"""
    cloned = json.loads(json.dumps(sample))
    cloned["raw_body_b64"] = base64.b64encode(raw_body).decode("ascii")
    cloned["raw_body_utf8"] = raw_body.decode("utf-8")
    cloned["tamper_note"] = "签名保持原值，仅正文被替换，验签应失败"
    return cloned


def main() -> None:
    keyring = Keyring.load  # 触发一次属性访问，确认类可导入
    del keyring
    keys_by_id = {item["key_id"]: item for item in SYNTHETIC_KEYS}

    # 1) 密钥材料：合并 keystore + 单把文件（与旧 fixtures/test-key.json 兼容）
    _write(FIXTURES / "keystore.json", {"keys": SYNTHETIC_KEYS})
    for item in SYNTHETIC_KEYS:
        _write(KEYS_DIR / f"{item['key_id']}.json", item)

    # 2) 原始事件正文（UTF-8 JSON，保留原始字节）
    for name, event in EVENTS.items():
        _write(FIXTURES / name, event)
    _write(FIXTURES / "event-a-conflict.json",
            json.loads(CONFLICT_BODY.decode("utf-8")))

    body_a = (FIXTURES / "event-a.json").read_bytes()
    body_b = (FIXTURES / "event-b.json").read_bytes()
    body_c = (FIXTURES / "event-c.json").read_bytes()
    old_key = type("K", (), {
        "key_id": keys_by_id["local-2026-10"]["key_id"],
        "secret": keys_by_id["local-2026-10"]["secret"].encode("utf-8"),
    })
    new_key = type("K", (), {
        "key_id": keys_by_id["local-2026-11"]["key_id"],
        "secret": keys_by_id["local-2026-11"]["secret"].encode("utf-8"),
    })
    future_key = type("K", (), {
        "key_id": keys_by_id["local-2026-12"]["key_id"],
        "secret": keys_by_id["local-2026-12"]["secret"].encode("utf-8"),
    })

    valid_new = _sample(new_key, SENT_AT_ISO, "evt-line-001", body_a)
    samples = {
        # 交叉期：同一事件分别由旧/新密钥签署（在途通知场景）
        "a-signed-new-key.json": valid_new,
        "a-signed-old-key.json": _sample(old_key, SENT_AT_ISO,
                                          "evt-line-001", body_a),
        # 供应商超时重发：同 ID、同字节、同签名（幂等重放样例）
        "a-redelivery.json": _sample(new_key, SENT_AT_ISO,
                                     "evt-line-001", body_a),
        # 同 ID 不同正文：冲突样例（新密钥对新字节重新签名）
        "a-conflict-body.json": _sample(new_key, SENT_AT_ISO,
                                        "evt-line-001", CONFLICT_BODY),
        # 语义等价但字节被重编码：**保留原签名**，只替换正文。
        # 接收方对重编码后的字节验签必然失败——证明不能“解析 JSON 再编码验签”。
        "a-reencoded-tampered.json": _with_body(valid_new, REENCODED_BODY),
        # 时间戳超出窗口
        "a-stale-timestamp.json": _sample(new_key, STALE_AT_ISO,
                                          "evt-line-001", body_a),
        # 尚未生效的密钥签名
        "a-future-key.json": _sample(future_key, SENT_AT_ISO,
                                     "evt-line-001", body_a),
        "b-signed-new-key.json": _sample(new_key, SENT_AT_ISO,
                                         "evt-line-002", body_b),
        "c-signed-old-key.json": _sample(old_key, SENT_AT_ISO,
                                         "evt-line-003", body_c),
    }
    for name, payload in samples.items():
        _write(SAMPLES_DIR / name, payload)

    # 3) 兼容旧入口 fixtures/sample-headers.json / test-key.json
    first = samples["a-signed-new-key.json"]
    _write(FIXTURES / "sample-headers.json", {
        **first["headers"],
        "signed_format": first["signed_format"],
        "sample_now_iso": SAMPLE_NOW_ISO,
    })
    _write(FIXTURES / "test-key.json", keys_by_id["local-2026-11"])

    timeline = {
        "sample_now_iso": SAMPLE_NOW_ISO,
        "sample_now_epoch": parse_iso8601(SAMPLE_NOW_ISO),
        "sent_at_iso": SENT_AT_ISO,
        "sent_at_epoch": parse_iso8601(SENT_AT_ISO),
        "stale_at_iso": STALE_AT_ISO,
        "stale_at_epoch": parse_iso8601(STALE_AT_ISO),
        "default_window_seconds": 300,
        "overlap_window_utc": ["2026-11-08T00:00:00Z", "2026-11-15T00:00:00Z"],
        "synthetic_notice": "全部为虚构样例，无真实凭据或设备",
    }
    _write(FIXTURES / "timeline.json", timeline)
    print(f"生成完成：{len(SYNTHETIC_KEYS)} 把合成密钥，"
          f"{len(EVENTS)} 个虚构事件，{len(samples)} 个已签名样例 -> {FIXTURES}")


if __name__ == "__main__":
    main()
