"""HTTP 接入层（标准库 ThreadingHTTPServer）。

路由
====
* ``POST /callbacks/quality-event`` 供应商回调（原始字节进 IngestService）
* ``GET  /audit/events/{event_id}``  单事件审计记录
* ``POST /admin/events/{event_id}/replay`` 安全重放（复用原始签名证据）
* ``GET  /healthz`` 存活与待交付计数

管理端用独立的 admin token 授权；账本里依然不保存任何密钥。
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from .delivery import OutboxPump
from .ledger import Ledger
from .security import Keyring
from .service import IngestService, SystemClock


class CallbackHandler(BaseHTTPRequestHandler):
    server_version = "SignedEventGateway/1.0"

    # ---- 工具 ---------------------------------------------------------
    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _header(self, name: str) -> str | None:
        return self.headers.get(name)

    def log_message(self, fmt, *args):  # 安静一点，测试输出不被污染
        if getattr(self.server, "access_log", False):
            super().log_message(fmt, *args)

    def _authorized_admin(self) -> bool:
        expected = self.server.admin_token
        if not expected:
            return False
        presented = self._header("X-Admin-Token") or ""
        import hmac as _hmac
        return _hmac.compare_digest(presented, expected)

    # ---- 路由 ---------------------------------------------------------
    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send_json(200, {
                "status": "ok",
                "pending_delivery": self.server.ledger.pending_count(),
            })
            return
        if self.path.startswith("/audit/events/"):
            event_id = unquote(self.path[len("/audit/events/"):])
            record = self.server.ledger.get_audit(event_id)
            if record is None:
                self._send_json(404, {"error": "event_not_found",
                                      "event_id": event_id})
            else:
                self._send_json(200, record)
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = self.path
        if path == "/callbacks/quality-event":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            headers = {
                "X-Event-Id": self._header("X-Event-Id"),
                "X-Sent-At": self._header("X-Sent-At"),
                "X-Key-Id": self._header("X-Key-Id"),
                "X-Signature": self._header("X-Signature"),
                "X-Sig-Version": self._header("X-Sig-Version"),
            }
            result = self.server.ingest.handle_callback(headers, raw)
            self._send_json(result.status, result.body)
            return

        if path.startswith("/admin/events/") and path.endswith("/replay"):
            if not self._authorized_admin():
                self._send_json(403, {"error": "admin_token_required"})
                return
            event_id = unquote(path[len("/admin/events/"):-len("/replay")])
            try:
                report = self.server.pump.deliver_now(
                    self.server.ledger, event_id,
                    self.server.clock.now(), operator="http_admin",
                )
            except KeyError:
                self._send_json(404, {"error": "event_not_found",
                                      "event_id": event_id})
                return
            status = 200 if report.get("delivered") else 202
            self._send_json(status, report)
            return

        self._send_json(404, {"error": "not_found"})


def build_server(*, keyring: Keyring, ledger: Ledger, queue,
                 window_seconds: int = 300, admin_token: str | None = None,
                 host: str = "127.0.0.1", port: int = 0,
                 pump_interval: float = 1.0, start_pump: bool = True,
                 clock=None) -> ThreadingHTTPServer:
    clock = clock or SystemClock()
    ingest = IngestService(keyring=keyring, ledger=ledger,
                           window_seconds=window_seconds, clock=clock)
    pump = OutboxPump(ledger, queue)
    server = ThreadingHTTPServer((host, port), CallbackHandler)
    server.ingest = ingest
    server.ledger = ledger
    server.pump = pump
    server.clock = clock
    server.admin_token = admin_token
    server.access_log = False

    if start_pump:
        stop = threading.Event()

        def _loop() -> None:
            while not stop.wait(pump_interval):
                try:
                    pump.run_once(clock.now())
                except Exception:  # 泵异常不能杀死线程
                    pass

        thread = threading.Thread(target=_loop, name="outbox-pump",
                                  daemon=True)
        thread.start()
        server.stop_pump = stop.set  # type: ignore[attr-defined]
    else:
        server.stop_pump = lambda: None  # type: ignore[attr-defined]
    return server


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="受信质量事件回调网关（合成样例）")
    parser.add_argument("--keys", default="fixtures/keystore.json")
    parser.add_argument("--db", default="runtime/events.db")
    parser.add_argument("--queue-dir", default="runtime/queue")
    parser.add_argument("--window", type=int, default=300)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--admin-token", default=None)
    args = parser.parse_args()

    from pathlib import Path
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    keyring = Keyring.load(args.keys)
    ledger = Ledger(args.db)
    from .delivery import DirectoryQueue
    queue = DirectoryQueue(args.queue_dir)
    server = build_server(keyring=keyring, ledger=ledger, queue=queue,
                          window_seconds=args.window,
                          admin_token=args.admin_token, host=args.host,
                          port=args.port)
    print(f"listening on http://{server.server_address[0]}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop_pump()
        time.sleep(0.05)
        server.shutdown()


if __name__ == "__main__":
    main()
