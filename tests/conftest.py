"""Every test here is hermetic: no test may ever touch a real msf console.

爷爷 2026-10-07 之后，引擎改成"本机用 msf 的 python 库直连控制台"（`runtime/msfservice.py`）。
这对真跑是好事，对测试是陷阱：只要跑测试的那台机器上恰好装了库、环境里 `AGV_MSF_RPC` 又指着
真靶场，某个漏了 stub 的用例就会**真的去连**（`ensure_console` 甚至会去 ssh 重起控制台）——
表现就是"跑了几分钟一点动静都没有"，看起来像测试写错了。

所以这里给整套测试装一个**死端点**：任何漏网的调用都会立刻"连接被拒"，而不是打到靶场上。
需要控制台的用例照旧自己用 `tests/support.py::wire_console` 接一条假会话。
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from runtime import msfservice  # noqa: E402 - the path bootstrap above comes first


@pytest.fixture(autouse=True)
def hermetic_console(monkeypatch):
    """死端点 + 清掉连接缓存：测试永远不该碰到真的控制台。"""
    monkeypatch.setenv("AGV_MSF_RPC", "msf:hermetic@127.0.0.1:1")
    msfservice._CLIENTS.clear()
    yield
    msfservice._CLIENTS.clear()


@pytest.fixture(autouse=True)
def isolated_checkpoints(monkeypatch, tmp_path_factory):
    """Default checkpoint databases belong to this test's temporary directory."""
    from orchestration import langgraph_runner

    identity = langgraph_runner.checkpoint_identity
    directory = None

    def temporary_identity(*, root, repository, materials_dir=None):
        nonlocal directory
        if materials_dir is None:
            if directory is None:
                directory = tmp_path_factory.mktemp("private-checkpoints")
            materials_dir = directory
        return identity(root=root, repository=repository, materials_dir=materials_dir)

    monkeypatch.setattr(langgraph_runner, "checkpoint_identity", temporary_identity)
