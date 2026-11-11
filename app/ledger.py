"""接收账本：去重、冲突留痕、交付状态与审计查询。

并发模型
========
多个工作进程/线程可能同时收到同一事件的重试。所有“检查是否已存在 →
写入/判定”的流程都放在单条 ``BEGIN IMMEDIATE`` 事务里，配合 SQLite 的
唯一主键（``events.event_id``）串行化：同一 event_id 的并发请求只有一个
成为 accepted，其余在同一事务里被判定为 duplicate 或 conflict，结果一致。

注意：本模块的表结构里**没有任何密钥字段**，只有验签后选定的 key_id 和
签名证据（签名不是秘密）。
"""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id         TEXT PRIMARY KEY,
    raw_body         BLOB NOT NULL,
    body_sha256      TEXT NOT NULL,
    sent_at          INTEGER NOT NULL,
    received_at      INTEGER NOT NULL,
    key_id           TEXT NOT NULL,
    signature        TEXT NOT NULL,
    sig_version      TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('accepted', 'delivered')),
    delivery_attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at  INTEGER,
    next_attempt_at  INTEGER,
    last_error       TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_due
    ON events(status, next_attempt_at);

CREATE TABLE IF NOT EXISTS event_observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT,
    observed_at INTEGER NOT NULL,
    outcome     TEXT NOT NULL,
    reason      TEXT,
    key_id      TEXT,
    sent_at     INTEGER,
    body_sha256 TEXT,
    signature   TEXT
);

CREATE INDEX IF NOT EXISTS idx_obs_event
    ON event_observations(event_id, id);

CREATE TABLE IF NOT EXISTS delivery_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id   TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    attempt_no INTEGER NOT NULL,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    outcome    TEXT NOT NULL CHECK (outcome IN
                 ('pending', 'delivered', 'failed', 'superseded')),
    origin     TEXT NOT NULL,
    error      TEXT
);

CREATE INDEX IF NOT EXISTS idx_attempts_event
    ON delivery_attempts(event_id, id);

CREATE TABLE IF NOT EXISTS conflicts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      TEXT NOT NULL,
    observed_at   INTEGER NOT NULL,
    existing_sha  TEXT NOT NULL,
    incoming_sha  TEXT NOT NULL,
    key_id        TEXT,
    sent_at       INTEGER,
    signature     TEXT,
    raw_body      BLOB NOT NULL
);
"""


@dataclass(frozen=True)
class IngestOutcome:
    result: str  # "accepted" | "duplicate" | "conflict"
    event_id: str
    body_sha256: str
    key_id: str | None = None
    conflict_id: int | None = None


@dataclass(frozen=True)
class ClaimedDelivery:
    attempt_id: int
    attempt_no: int
    event_id: str
    raw_body: bytes
    key_id: str
    signature: str
    sent_at: int
    origin: str


class Ledger:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._local = threading.local()
        self._init_schema()

    # ---- 连接管理：每线程一条连接，进程间通过文件锁/WAL 协调 ----
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            conn.row_factory = sqlite3.Row
            # busy_timeout 必须先于可能加锁的 WAL 切换设置，
            # 否则多进程同时建库时首个 pragma 就会立即抛 locked。
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        conn = self._conn()
        # 多进程并发首次打开时，WAL 模式切换可能短暂抢不到锁，做有限重试。
        for attempt in range(5):
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError:
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))
        conn.executescript(SCHEMA)

    @contextmanager
    def transaction(self):
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    # ---- 接收侧主路径 -------------------------------------------------
    def ingest(
        self,
        *,
        event_id: str,
        raw_body: bytes,
        body_sha256: str,
        sent_at: int,
        received_at: int,
        key_id: str,
        signature: str,
        sig_version: str,
    ) -> IngestOutcome:
        """原子完成“查重 → 接受/重放/冲突”判定，绝不重复入队。"""
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT body_sha256 FROM events WHERE event_id=?", (event_id,)
            ).fetchone()
            if row is None:
                conn.execute(
                    """INSERT INTO events(event_id, raw_body, body_sha256, sent_at,
                           received_at, key_id, signature, sig_version, status,
                           delivery_attempts, next_attempt_at)
                       VALUES (?,?,?,?,?,?,?,?,'accepted',0,?)""",
                    (event_id, raw_body, body_sha256, sent_at, received_at,
                     key_id, signature, sig_version, received_at),
                )
                conn.execute(
                    """INSERT INTO event_observations(event_id, observed_at,
                           outcome, reason, key_id, sent_at, body_sha256, signature)
                       VALUES (?,?, 'accepted', NULL, ?, ?, ?, ?)""",
                    (event_id, received_at, key_id, sent_at, body_sha256, signature),
                )
                return IngestOutcome("accepted", event_id, body_sha256, key_id)

            if row["body_sha256"] == body_sha256:
                # 完全相同的重放：幂等吞掉，不产生新的入队/副作用。
                conn.execute(
                    """INSERT INTO event_observations(event_id, observed_at,
                           outcome, reason, key_id, sent_at, body_sha256, signature)
                       VALUES (?,?, 'duplicate', 'identical_redelivery', ?, ?, ?, ?)""",
                    (event_id, received_at, key_id, sent_at, body_sha256, signature),
                )
                return IngestOutcome("duplicate", event_id, body_sha256, key_id)

            # 相同 ID、不同正文：冲突，保留双方证据，绝不按普通重放吞掉。
            cur = conn.execute(
                """INSERT INTO conflicts(event_id, observed_at, existing_sha,
                       incoming_sha, key_id, sent_at, signature, raw_body)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (event_id, received_at, row["body_sha256"], body_sha256,
                 key_id, sent_at, signature, raw_body),
            )
            conn.execute(
                """INSERT INTO event_observations(event_id, observed_at,
                       outcome, reason, key_id, sent_at, body_sha256, signature)
                   VALUES (?,?, 'conflict', 'same_id_different_body', ?, ?, ?, ?)""",
                (event_id, received_at, key_id, sent_at, body_sha256, signature),
            )
            return IngestOutcome("conflict", event_id, body_sha256, key_id,
                                 conflict_id=cur.lastrowid)

    def record_rejection(
        self,
        *,
        event_id: str | None,
        observed_at: int,
        reason: str,
        key_id: str | None = None,
        sent_at: int | None = None,
        body_sha256: str | None = None,
        signature: str | None = None,
    ) -> None:
        """记录被拒绝的投递（签名失败、时间窗超限等），供值班排查。"""
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO event_observations(event_id, observed_at, outcome,
                       reason, key_id, sent_at, body_sha256, signature)
                   VALUES (?,?,'rejected', ?, ?, ?, ?, ?)""",
                (event_id, observed_at, reason, key_id, sent_at,
                 body_sha256, signature),
            )

    # ---- 交付侧：租约、退避、崩溃恢复 ---------------------------------
    def reclaim_stuck(self, now_epoch: int, lease_seconds: int) -> int:
        """把进程崩溃留下的 pending 尝试标记失败并重新排期。"""
        cutoff = now_epoch - lease_seconds
        fixed = 0
        with self.transaction() as conn:
            rows = conn.execute(
                """SELECT id, event_id FROM delivery_attempts
                   WHERE outcome='pending' AND started_at < ?""",
                (cutoff,),
            ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE delivery_attempts SET outcome='failed', "
                    "finished_at=?, error='lease_expired' WHERE id=?",
                    (now_epoch, row["id"]),
                )
                conn.execute(
                    "UPDATE events SET next_attempt_at=? "
                    "WHERE event_id=? AND status='accepted' AND next_attempt_at IS NULL",
                    (now_epoch, row["event_id"]),
                )
                fixed += 1
        return fixed

    def claim_due(self, now_epoch: int, limit: int = 16,
                  origin: str = "pump") -> list[ClaimedDelivery]:
        """认领到期事件并创建新的交付尝试行（含审计序号）。"""
        with self.transaction() as conn:
            rows = conn.execute(
                """SELECT * FROM events
                   WHERE status='accepted' AND next_attempt_at IS NOT NULL
                     AND next_attempt_at <= ?
                   ORDER BY next_attempt_at, event_id LIMIT ?""",
                (now_epoch, limit),
            ).fetchall()
            return [self._claim_row(conn, row, now_epoch, origin) for row in rows]

    def claim_event(self, event_id: str, now_epoch: int,
                    origin: str = "manual_replay") -> ClaimedDelivery | None:
        """强制认领单个 accepted 事件，无视退避（操作重放专用）。"""
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM events WHERE event_id=? AND status='accepted'",
                (event_id,),
            ).fetchone()
            if row is None:
                return None
            return self._claim_row(conn, row, now_epoch, origin)

    def _claim_row(self, conn, row, now_epoch: int,
                   origin: str) -> ClaimedDelivery:
        attempt_no = row["delivery_attempts"] + 1
        cur = conn.execute(
            """INSERT INTO delivery_attempts(event_id, attempt_no,
                   started_at, outcome, origin)
               VALUES (?,?,?, 'pending', ?)""",
            (row["event_id"], attempt_no, now_epoch, origin),
        )
        conn.execute(
            """UPDATE events SET delivery_attempts=?, last_attempt_at=?,
                   next_attempt_at=NULL WHERE event_id=?""",
            (attempt_no, now_epoch, row["event_id"]),
        )
        return ClaimedDelivery(
            attempt_id=cur.lastrowid,
            attempt_no=attempt_no,
            event_id=row["event_id"],
            raw_body=row["raw_body"],
            key_id=row["key_id"],
            signature=row["signature"],
            sent_at=row["sent_at"],
            origin=origin,
        )

    def finish_attempt(self, attempt_id: int, *, delivered: bool,
                       now_epoch: int, backoff_seconds: int = 0,
                       error: str | None = None) -> None:
        with self.transaction() as conn:
            attempt = conn.execute(
                "SELECT event_id FROM delivery_attempts WHERE id=?", (attempt_id,)
            ).fetchone()
            if attempt is None:
                raise ValueError(f"未知交付尝试: {attempt_id}")
            event_id = attempt["event_id"]
            if delivered:
                conn.execute(
                    "UPDATE delivery_attempts SET outcome='delivered', "
                    "finished_at=?, error=NULL WHERE id=?",
                    (now_epoch, attempt_id),
                )
                conn.execute(
                    "UPDATE events SET status='delivered', next_attempt_at=NULL, "
                    "last_error=NULL WHERE event_id=?",
                    (event_id,),
                )
            else:
                conn.execute(
                    "UPDATE delivery_attempts SET outcome='failed', "
                    "finished_at=?, error=? WHERE id=?",
                    (now_epoch, error, attempt_id),
                )
                conn.execute(
                    "UPDATE events SET status='accepted', next_attempt_at=?, "
                    "last_error=? WHERE event_id=?",
                    (now_epoch + backoff_seconds, error, event_id),
                )

    def request_replay(self, event_id: str, now_epoch: int,
                       operator: str) -> dict:
        """操作人员安全重放入口：复用原始签名证据，只产生新的交付尝试。"""
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM events WHERE event_id=?", (event_id,)
            ).fetchone()
            if row is None:
                raise KeyError(event_id)
            # 若上一次尝试还挂着（租约内），先作废旧尝试，避免双发。
            conn.execute(
                "UPDATE delivery_attempts SET outcome='superseded', "
                "finished_at=?, error='superseded_by_replay' "
                "WHERE event_id=? AND outcome='pending'",
                (now_epoch, event_id),
            )
            conn.execute(
                "UPDATE events SET status='accepted', next_attempt_at=? "
                "WHERE event_id=?",
                (now_epoch, event_id),
            )
            conn.execute(
                """INSERT INTO event_observations(event_id, observed_at,
                       outcome, reason, key_id, sent_at, body_sha256, signature)
                   VALUES (?,?,'replay_requested', ?, ?, ?, ?, ?)""",
                (event_id, now_epoch, f"operator={operator}", row["key_id"],
                 row["sent_at"], row["body_sha256"], row["signature"]),
            )
            return {
                "event_id": event_id,
                "status": "accepted",
                "next_attempt_at": now_epoch,
                "reuses_original_signature": True,
                "key_id": row["key_id"],
            }

    # ---- 审计与保留期 -------------------------------------------------
    def get_audit(self, event_id: str) -> dict | None:
        conn = self._conn()
        event = conn.execute(
            "SELECT * FROM events WHERE event_id=?", (event_id,)
        ).fetchone()
        if event is None:
            # 可能只留下拒绝/冲突观察记录
            obs = conn.execute(
                "SELECT * FROM event_observations WHERE event_id=? ORDER BY id",
                (event_id,),
            ).fetchall()
            if not obs:
                return None
            return {"event_id": event_id, "event": None,
                    "observations": [dict(r) for r in obs],
                    "delivery_attempts": [], "conflicts": []}
        observations = conn.execute(
            "SELECT * FROM event_observations WHERE event_id=? ORDER BY id",
            (event_id,),
        ).fetchall()
        attempts = conn.execute(
            "SELECT * FROM delivery_attempts WHERE event_id=? ORDER BY id",
            (event_id,),
        ).fetchall()
        conflicts = conn.execute(
            "SELECT id, observed_at, existing_sha, incoming_sha, key_id, "
            "sent_at, signature FROM conflicts WHERE event_id=? ORDER BY id",
            (event_id,),
        ).fetchall()
        data = dict(event)
        data["raw_body_b64"] = _b64(data.pop("raw_body"))
        return {
            "event_id": event_id,
            "event": data,
            "observations": [dict(r) for r in observations],
            "delivery_attempts": [dict(r) for r in attempts],
            "conflicts": [dict(r) for r in conflicts],
        }

    def purge_expired(self, now_epoch: int, retention_seconds: int) -> int:
        """删除超出保留期且已交付的事件；未交付的永不清理，避免丢事件。"""
        cutoff = now_epoch - retention_seconds
        with self.transaction() as conn:
            expired = [r["event_id"] for r in conn.execute(
                "SELECT event_id FROM events "
                "WHERE status='delivered' AND received_at < ?",
                (cutoff,),
            ).fetchall()]
            for event_id in expired:
                # delivery_attempts 由外键级联删除；其余表显式清理。
                conn.execute("DELETE FROM event_observations WHERE event_id=?",
                             (event_id,))
                conn.execute("DELETE FROM conflicts WHERE event_id=?",
                             (event_id,))
            cur = conn.execute(
                "DELETE FROM events WHERE status='delivered' AND received_at < ?",
                (cutoff,),
            )
            return cur.rowcount

    def pending_count(self) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) AS c FROM events WHERE status='accepted'"
        ).fetchone()["c"]


def _b64(raw: bytes) -> str:
    import base64
    return base64.b64encode(raw).decode("ascii")


def utc_now() -> int:
    return int(datetime.now(timezone.utc).timestamp())
