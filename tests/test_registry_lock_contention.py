"""walk-184 regression: 账本的读路径不取锁，且共用状态的写锁是有界等待。"""
import json
import multiprocessing as mp
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "src", ROOT / "scripts"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from runtime import session_registry
from runtime import session_registry
from runtime.runner import ownership


REGISTRY = {"sessions": {"channel-1": {"lifecycle": "active", "host": "192.0.2.7"}},
            "resources": {}, "releases": {}, "contexts": {"row-1": {"channel_id": "channel-1"}}}


def _hold_write_lock(root, ready, release):
    """拿着写闸不放，直到父进程读完快照之后才松开（不用 sleep 猜窗口）。"""
    with ownership(Path(root) / ".session-registry"):
        ready.send("LOCKED")
        if not release.wait(15):
            raise RuntimeError("读数慢于测试预算")
    ready.close()


def test_reads_succeed_while_another_process_holds_the_write_lock(tmp_path):
    """walk-184 就是死在这里：读去抢写闸、被弹回，异常穿到进程入口，整轮崩。"""
    (tmp_path / "sessions.json").write_text(json.dumps(REGISTRY), encoding="utf-8")
    context = mp.get_context("spawn")
    ready_recv, ready_send = context.Pipe(duplex=False)
    release = context.Event()
    holder = context.Process(target=_hold_write_lock, args=(str(tmp_path), ready_send, release))
    holder.start()
    try:
        assert ready_recv.recv() == "LOCKED"
        rows = session_registry.snapshot(tmp_path)          # 读：不许取锁、不许等
        observed = session_registry.observations(tmp_path)  # 读：同理
    finally:
        release.set()
        holder.join(15)
    assert holder.exitcode == 0
    assert rows == [dict(REGISTRY["sessions"]["channel-1"],
                         registry_root=str(Path(tmp_path).resolve()))]
    assert observed == [dict(REGISTRY["contexts"]["row-1"],
                             registry_root=str(Path(tmp_path).resolve()))]


def test_writes_wait_for_the_shared_lock_instead_of_failing(tmp_path, monkeypatch):
    """编排与探活守护共用一份账本：谁在写就等一会儿，不再"抢不到就崩"。"""
    (tmp_path / "sessions.json").write_text(json.dumps(REGISTRY), encoding="utf-8")
    seen = {}
    real = session_registry.ownership

    def spy(folder, *, wait=None):
        seen["wait"] = wait
        return real(folder)

    monkeypatch.setattr(session_registry, "ownership", spy)
    session_registry._mutate(tmp_path, lambda value: value["contexts"].update({"row-2": {"channel_id": "channel-1"}}))
    assert seen["wait"] == session_registry.REGISTRY_WRITE_WAIT_S
    assert seen["wait"] > 0
    written = json.loads((tmp_path / "sessions.json").read_text(encoding="utf-8"))
    assert set(written["contexts"]) == {"row-1", "row-2"}
