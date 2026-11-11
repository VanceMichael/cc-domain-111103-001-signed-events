"""受信任回调的签名原语与密钥轮换选择。

设计约束（对应值班场景）：

* 签名覆盖请求的**原始字节**、发送时间和事件 ID。接收方绝不先解析 JSON
  再重新编码后验签——重编码（空白、键序、Unicode 转义）会改变字节，
  伪造正文可以借此绕过校验。
* 签名输入采用带版本号的长度前缀分帧，字段之间不依赖分隔符，避免歧义。
* 密钥只有生效/退役时刻，交接期内新旧密钥可能同时有效。同一请求在交叉
  期可以用任一在效密钥通过；选择结果（key_id）会被记入审计，密钥本身
  （secret）不入库、不出现在任何持久化输出里。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SIGNATURE_VERSION = "SIG-V1"
ALGORITHM = "HMAC-SHA256"
# 事件 ID 只允许 URL/日志安全字符，且长度受限；它同时参与签名分帧。
_EVENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
# 发送时间约定为 Unix  epoch 秒的 ASCII 数字。
_SENT_AT_RE = re.compile(r"[0-9]{1,20}\Z")
_LENGTH_PREFIX_BYTES = 8


class SignatureError(ValueError):
    """签名材料格式不合法（区别于“验签不通过”）。"""


def valid_event_id(event_id: str) -> bool:
    return isinstance(event_id, str) and bool(_EVENT_ID_RE.fullmatch(event_id))


def build_signed_input(sent_at: str, event_id: str, raw_body: bytes) -> bytes:
    """按 SIG-V1 分帧构造被签名的字节串。

    格式::

        b"SIG-V1|" + 对每个字段依次写入 [8 字节大端长度][字段原始字节]

    字段顺序固定为：sent_at（ASCII）、event_id（ASCII）、raw_body（原始正文）。
    长度前缀保证任何字段内容都不会产生歧义拼接。
    """
    if not isinstance(raw_body, (bytes, bytearray)):
        raise SignatureError("raw_body 必须是原始字节")
    if not isinstance(sent_at, str) or not _SENT_AT_RE.fullmatch(sent_at):
        raise SignatureError("sent_at 必须是 epoch 秒 ASCII 数字")
    if not valid_event_id(event_id):
        raise SignatureError("event_id 字符或长度不合法")
    chunks = [SIGNATURE_VERSION.encode("ascii"), b"|"]
    for field in (sent_at.encode("ascii"), event_id.encode("ascii"), bytes(raw_body)):
        chunks.append(len(field).to_bytes(_LENGTH_PREFIX_BYTES, "big"))
        chunks.append(field)
    return b"".join(chunks)


def compute_signature(secret: bytes, signed_input: bytes) -> str:
    return hmac.new(secret, signed_input, hashlib.sha256).hexdigest()


def sign_request(secret: bytes, sent_at: str, event_id: str, raw_body: bytes) -> str:
    """供本地合成样例/发送方使用的签名函数；接收流程不会调用它。"""
    signed_input = build_signed_input(sent_at, event_id, raw_body)
    return compute_signature(secret, signed_input)


def parse_epoch(value: str) -> int:
    if not isinstance(value, str) or not _SENT_AT_RE.fullmatch(value):
        raise SignatureError("时间戳必须是 epoch 秒 ASCII 数字")
    return int(value)


def check_timestamp(sent_at: str, now_epoch: int, window_seconds: int) -> tuple[bool, int | None, str | None]:
    """时间戳窗口校验，返回 (是否通过, 解析出的时间, 拒绝原因)。"""
    try:
        ts = parse_epoch(sent_at)
    except SignatureError:
        return False, None, "bad_timestamp"
    if abs(now_epoch - ts) > window_seconds:
        return False, ts, "outside_window"
    return True, ts, None


def parse_iso8601(value: str) -> int:
    """把 fixtures 中的 ISO-8601（Z 结尾）转为 epoch 秒。"""
    text = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


@dataclass(frozen=True)
class TrustedKey:
    """一把受信密钥的内存表示。secret 只存在于进程内存中。"""

    key_id: str
    secret: bytes
    valid_from: int  # 含
    retired_at: int  # 不含，半开区间 [valid_from, retired_at)

    def active_at(self, epoch_seconds: int) -> bool:
        return self.valid_from <= epoch_seconds < self.retired_at

    @classmethod
    def from_dict(cls, data: dict) -> "TrustedKey":
        return cls(
            key_id=str(data["key_id"]),
            secret=str(data["secret"]).encode("utf-8"),
            valid_from=_to_epoch(data["valid_from"]),
            retired_at=_to_epoch(data["retired_at"]),
        )


def _to_epoch(value) -> int:
    if isinstance(value, int):
        return value
    return parse_iso8601(str(value))


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    key_id: str | None
    reason: str | None


class Keyring:
    """受信密钥集合，负责交接期的密钥选择与验签。"""

    def __init__(self, keys: list[TrustedKey]):
        seen: set[str] = set()
        for key in keys:
            if key.key_id in seen:
                raise ValueError(f"key_id 重复: {key.key_id}")
            seen.add(key.key_id)
        # 静态顺序：新生效的在前；同刻生效按 key_id 排序，保证选择确定性。
        self._keys = sorted(keys, key=lambda k: (-k.valid_from, k.key_id))

    @classmethod
    def load(cls, path: str | Path) -> "Keyring":
        """从 JSON 加载合成/配置密钥。

        支持顶层为数组，或 ``{"keys": [...]}``。该文件由部署侧授权维护，
        项目内的副本只含虚构样例。
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = data["keys"] if isinstance(data, dict) else data
        return cls([TrustedKey.from_dict(item) for item in entries])

    def active_keys(self, now_epoch: int) -> list[TrustedKey]:
        return [key for key in self._keys if key.active_at(now_epoch)]

    def verify(
        self,
        *,
        event_id: str,
        sent_at: str,
        raw_body: bytes,
        signature_hex: str,
        now_epoch: int,
        claimed_key_id: str | None = None,
    ) -> VerificationResult:
        """对原始请求字节验签。

        交接期内可能有多把在效密钥：优先尝试发送方声明的 key_id，其余按
        “新密钥优先”的确定顺序尝试，模拟旧密钥签署的在途通知仍可被接受，
        而轮换完成后新签名稳定走新密钥。
        """
        if not valid_event_id(event_id):
            return VerificationResult(False, None, "bad_event_id")
        try:
            signed_input = build_signed_input(sent_at, event_id, raw_body)
        except SignatureError as exc:
            return VerificationResult(False, None, str(exc))
        try:
            provided = bytes.fromhex(signature_hex)
        except (ValueError, TypeError):
            return VerificationResult(False, None, "bad_signature_encoding")

        active = self.active_keys(now_epoch)
        if not active:
            return VerificationResult(False, None, "no_active_key")
        ordered = sorted(
            active,
            key=lambda k: (k.key_id != claimed_key_id, -k.valid_from, k.key_id),
        )
        for key in ordered:
            expected = hmac.new(key.secret, signed_input, hashlib.sha256).digest()
            if hmac.compare_digest(expected, provided):
                return VerificationResult(True, key.key_id, None)
        return VerificationResult(False, None, "bad_signature")
