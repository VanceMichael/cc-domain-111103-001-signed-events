import json
from dataclasses import dataclass

@dataclass(frozen=True)
class Delivery:
    headers: dict
    body: bytes

def decode_body(raw):
    value=json.loads(raw.decode("utf-8"))
    if not isinstance(value,dict): raise ValueError("事件正文必须是对象")
    if not value.get("event_id"): raise ValueError("事件缺少身份")
    return value
