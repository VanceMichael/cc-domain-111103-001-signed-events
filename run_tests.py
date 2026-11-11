#!/usr/bin/env python3
"""根级测试入口，兼容隔离模式：

    python3 -I run_tests.py

等价于 unittest discover，但显式把仓库根目录加入 sys.path（-I 会忽略
PYTHONPATH 和当前工作目录的隐式导入）。
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "tests"), pattern="test_*.py",
                           top_level_dir=str(ROOT))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
