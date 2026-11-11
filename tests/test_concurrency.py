"""并发重复投递测试：多个工作进程/线程同时收到同一事件的重试。

验证“验证、去重、持久化交接”给出一致结果：同一 event_id 恰好一个
accepted，其余全部 duplicate；同 ID 不同字节则被记为 conflict。
"""

import multiprocessing as mp
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.support import build_service, sample_request  # noqa: E402


def _worker(db_path: str, sample_name: str, results, index: int) -> None:
    """子进程入口：各自打开自己的 Ledger 连接，指向同一个数据库文件。"""
    service, _ = build_service(db_path)
    headers, raw = sample_request(sample_name)
    result = service.handle_callback(headers, raw)
    results[index] = result.status


class ConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "events.db")
        # 与部署一致：父进程先建好 schema，工作进程只负责并发写入。
        build_service(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_parallel_processes_identical_redelivery_single_accept(self):
        ctx = mp.get_context("fork")
        n = 6
        manager = ctx.Manager()
        results = manager.list([None] * n)
        procs = [
            ctx.Process(target=_worker,
                        args=(self.db, "a-signed-new-key.json", results, i))
            for i in range(n)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=30)
        self.assertTrue(all(p.exitcode == 0 for p in procs))

        statuses = list(results)
        self.assertEqual(statuses.count(202), 1, statuses)
        self.assertEqual(statuses.count(200), n - 1, statuses)

        service, _ = build_service(self.db)
        audit = service.ledger.get_audit("evt-line-001")
        outcomes = [o["outcome"] for o in audit["observations"]]
        self.assertEqual(outcomes.count("accepted"), 1)
        self.assertEqual(outcomes.count("duplicate"), n - 1)
        # 尚未交付前不会有任何交付尝试
        self.assertEqual(audit["delivery_attempts"], [])

    def test_parallel_threads_mixed_bodies_one_accept_rest_conflict(self):
        n = 8
        statuses: list[int] = []
        barrier = threading.Barrier(n)
        lock = threading.Lock()

        def hit(sample_name: str) -> None:
            service, _ = build_service(self.db)
            headers, raw = sample_request(sample_name)
            barrier.wait()  # 尽量把写入挤到同一时刻
            result = service.handle_callback(headers, raw)
            with lock:
                statuses.append(result.status)

        threads = []
        for i in range(n):
            name = ("a-signed-new-key.json" if i % 2 == 0
                    else "a-conflict-body.json")
            threads.append(threading.Thread(target=hit, args=(name,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        accepted = [s for s in statuses if s == 202]
        conflicts = [s for s in statuses if s == 409]
        # 谁先抢到不确定，但 accepted 只能有一个；其余同 ID 不同字节全冲突，
        # 同字节重放为 200。
        self.assertEqual(len(accepted), 1, statuses)
        service, _ = build_service(self.db)
        audit = service.ledger.get_audit("evt-line-001")
        conflict_obs = [o for o in audit["observations"]
                        if o["outcome"] == "conflict"]
        self.assertEqual(len(conflict_obs), len(conflicts))
        self.assertEqual(len(audit["conflicts"]), len(conflicts))


if __name__ == "__main__":
    unittest.main()
