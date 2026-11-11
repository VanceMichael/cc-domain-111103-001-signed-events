"""测试辅助：从 fixtures 加载合成密钥/样例，构造已签名请求。"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.ledger import Ledger  # noqa: E402
from app.security import Keyring  # noqa: E402
from app.service import FixedClock, IngestService  # noqa: E402

FIXTURES = ROOT / "fixtures"
SAMPLES = FIXTURES / "signed-samples"
TIMELINE = json.loads((FIXTURES / "timeline.json").read_text(encoding="utf-8"))
SAMPLE_NOW = TIMELINE["sample_now_epoch"]
WINDOW = TIMELINE["default_window_seconds"]


def load_sample(name: str) -> dict:
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def sample_request(name: str) -> tuple[dict, bytes]:
    """返回 (请求头, 原始字节正文)，正文由 base64 还原，保持字节一致。"""
    sample = load_sample(name)
    raw = base64.b64decode(sample["raw_body_b64"])
    return dict(sample["headers"]), raw


def build_service(db_path, *, window_seconds: int = WINDOW,
                  now: int = SAMPLE_NOW) -> tuple[IngestService, FixedClock]:
    keyring = Keyring.load(FIXTURES / "keystore.json")
    ledger = Ledger(db_path)
    clock = FixedClock(now)
    return IngestService(keyring=keyring, ledger=ledger,
                         window_seconds=window_seconds, clock=clock), clock
