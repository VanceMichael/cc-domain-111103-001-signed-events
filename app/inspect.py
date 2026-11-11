"""离线调试入口：读取一个合成事件并打印解析结果与字节指纹。

注意：这里的 JSON 解析仅用于人工检查来源材料；真实回调流程在
``app.service`` 中对原始字节验签后才解析。
"""

from pathlib import Path

from app.hook import body_fingerprint, decode_body


def main() -> None:
    raw = Path("fixtures/event-a.json").read_bytes()
    event = decode_body(raw)
    print(event)
    print("sha256(raw_bytes) =", body_fingerprint(raw))


if __name__ == "__main__":
    main()
