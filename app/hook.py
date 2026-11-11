"""来源材料的基础读取入口（保留原有离线调试能力）。

注意：本模块的 JSON 解析只用于来源检查；回调验签流程在
``app.service`` 中，且始终对请求原始字节进行，见 ``app.security``。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Delivery:
    headers: dict
    body: bytes


def decode_body(raw: bytes) -> dict:
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("事件正文必须是对象")
    if not value.get("event_id"):
        raise ValueError("事件缺少身份")
    return value


def body_fingerprint(raw: bytes) -> str:
    """原始字节级指纹；同 ID 不同字节的正文据此判定为冲突。"""
    return hashlib.sha256(raw).hexdigest()
