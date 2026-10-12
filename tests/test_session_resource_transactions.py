import json
import multiprocessing
from pathlib import Path
from unittest.mock import create_autospec

import pytest

from runtime import session_registry


def test_reserve_resources_conflict_is_atomic(tmp_path):
    occupied = _ledger_resource(31001)
    available = _ledger_resource(31002)

    session_registry.reserve_resources(
        tmp_path, owner="owner-a", resources=[occupied]
    )
    before = _ledger_held(tmp_path)

    # 空闲资源放在前面，确保冲突不会造成前半批提交。
    with pytest.raises(ValueError, match=r"^SESSION_RESOURCE_BUSY$"):
        session_registry.reserve_resources(
            tmp_path,
            owner="owner-b",
            resources=[available, occupied],
        )

    assert _ledger_held(tmp_path) == before

    # 再实际预留一次，确认失败批次没有占住 available。
    session_registry.reserve_resources(
        tmp_path, owner="owner-c", resources=[available]
    )
    assert _ledger_held(tmp_path) == [
        ("127.0.0.1", 31001),
        ("127.0.0.1", 31002),
    ]




def test_reserve_resources_competing_owners(tmp_path):
    import os
    import subprocess
    import sys
    import time

    worker = r"""
import json
import sys
import time
from pathlib import Path

from runtime import session_registry

root = Path(sys.argv[1])
owner = sys.argv[2]
(root / (owner + ".ready")).write_text("ready", encoding="utf-8")
deadline = time.monotonic() + 35.0

while not (root / "go").exists():
    if time.monotonic() >= deadline:
        raise RuntimeError("test barrier timed out")
    time.sleep(0.01)

try:
    session_registry.reserve_resources(
        root,
        owner=owner,
        resources=[{
            "host": "192.0.2.10",
            "port": 1080,
            "protocol": "tcp",
        }],
    )
except ValueError as error:
    if str(error) != "SESSION_RESOURCE_BUSY":
        raise
    result = {"owner": owner, "state": "busy"}
else:
    result = {"owner": owner, "state": "held"}

print(json.dumps(result), flush=True)
"""

    environment = os.environ.copy()
    import_paths = [
        str(Path(session_registry.__file__).resolve().parents[1]),
        *(entry or os.getcwd() for entry in sys.path),
    ]
    environment["PYTHONPATH"] = os.pathsep.join(
        dict.fromkeys(import_paths))

    children = []
    owners = ("race-a", "race-b")
    try:
        for owner in owners:
            child = subprocess.Popen(
                [sys.executable, "-c", worker, str(tmp_path), owner],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            children.append((owner, child))

        ready_deadline = time.monotonic() + 30.0
        while not all(
                (tmp_path / (owner + ".ready")).is_file()
                for owner in owners):
            for owner, child in children:
                if child.poll() is not None:
                    stdout, stderr = child.communicate(timeout=5.0)
                    pytest.fail(
                        f"{owner} exited before the barrier: "
                        f"rc={child.returncode}\n{stdout}\n{stderr}"
                    )
            if time.monotonic() >= ready_deadline:
                pytest.fail("reservation workers did not reach the barrier")
            time.sleep(0.01)

        (tmp_path / "go").write_text("go", encoding="utf-8")

        results = []
        for owner, child in children:
            stdout, stderr = child.communicate(timeout=45.0)
            assert child.returncode == 0, (
                f"{owner}: rc={child.returncode}\n{stdout}\n{stderr}"
            )
            result = json.loads(stdout)
            assert result["owner"] == owner
            results.append(result)

        assert sorted(result["state"] for result in results) == [
            "busy", "held",
        ]
        winner = next(
            result["owner"]
            for result in results
            if result["state"] == "held"
        )

        value = session_registry._registry(
            session_registry._resource_root(tmp_path))
        assert len(value["resources"]) == 1
        assert next(iter(value["resources"].values()))["owner"] == winner
        assert value["releases"] == {}
        assert session_registry.held_resources(tmp_path) == [
            ["192.0.2.10", 1080],
        ]
    finally:
        for _owner, child in children:
            if child.poll() is None:
                child.kill()
        for _owner, child in children:
            child.wait(timeout=5.0)
            if child.stdout is not None:
                child.stdout.close()
            if child.stderr is not None:
                child.stderr.close()


@pytest.mark.parametrize("receipts", [
    [],
    [{"confirmed": False, "command_rc": 0}],
    [{"confirmed": True, "command_rc": 1}],
    [{"confirmed": True}],
    [
        {"confirmed": True, "command_rc": 0},
        {"confirmed": False, "command_rc": None},
    ],
])
def test_release_resources_requires_confirmed_cleanup(tmp_path, receipts):
    session_registry.reserve_resources(
        tmp_path,
        owner="owner-a",
        resources=[{
            "host": "192.0.2.10",
            "port": 1080,
            "protocol": "tcp",
        }],
    )
    resource_root = session_registry._resource_root(tmp_path)
    before = session_registry._registry(resource_root)

    with pytest.raises(
            ValueError, match="^SESSION_RESOURCE_CLEANUP_UNCONFIRMED$"):
        session_registry.release_resources(
            tmp_path, owner="owner-a", receipts=receipts)

    assert session_registry._registry(resource_root) == before
    assert session_registry.held_resources(tmp_path) == [
        ["192.0.2.10", 1080],
    ]



def _ledger_resource(port):
    return {
        "host": "127.0.0.1",
        "port": port,
        "protocol": "tcp",
    }


def _ledger_held(root):
    return sorted(
        tuple(item)
        for item in session_registry.held_resources(root)
    )


def _ledger_cleanup_receipts():
    return [{"confirmed": True, "command_rc": 0}]


def test_released_owner_cannot_reserve_again(tmp_path):
    session_registry.reserve_resources(
        tmp_path,
        owner="released-owner",
        resources=[_ledger_resource(31001)],
    )
    session_registry.release_resources(
        tmp_path,
        owner="released-owner",
        receipts=_ledger_cleanup_receipts(),
    )
    assert _ledger_held(tmp_path) == []

    # 使用另一空闲端口，排除资源冲突造成的假阳性。
    with pytest.raises(
        ValueError, match=r"^SESSION_RESOURCE_OWNER_RELEASED$"
    ):
        session_registry.reserve_resources(
            tmp_path,
            owner="released-owner",
            resources=[_ledger_resource(31002)],
        )

    assert _ledger_held(tmp_path) == []


def test_release_is_scoped_to_owner(tmp_path):
    session_registry.reserve_resources(
        tmp_path,
        owner="temporary-owner",
        resources=[
            _ledger_resource(31001),
            _ledger_resource(31002),
        ],
    )
    session_registry.reserve_resources(
        tmp_path,
        owner="persistent-owner",
        resources=[_ledger_resource(31003)],
    )

    session_registry.release_resources(
        tmp_path,
        owner="temporary-owner",
        receipts=_ledger_cleanup_receipts(),
    )

    assert _ledger_held(tmp_path) == [("127.0.0.1", 31003)]

    # 临时 owner 的幂等释放同样不能影响另一个 owner。
    session_registry.release_resources(
        tmp_path,
        owner="temporary-owner",
        receipts=_ledger_cleanup_receipts(),
    )
    assert _ledger_held(tmp_path) == [("127.0.0.1", 31003)]


@pytest.mark.parametrize(
    "receipts",
    [
        None,
        [],
        [{"confirmed": False, "command_rc": 0}],
        [{"confirmed": True, "command_rc": None}],
        [{"confirmed": True, "command_rc": 1}],
        [
            {"confirmed": True, "command_rc": 0},
            {"confirmed": False, "command_rc": 0},
        ],
    ],
)


def test_unconfirmed_cleanup_keeps_reservations(tmp_path, receipts):
    session_registry.reserve_resources(
        tmp_path,
        owner="owner-a",
        resources=[
            _ledger_resource(31001),
            _ledger_resource(31002),
        ],
    )
    before = _ledger_held(tmp_path)

    with pytest.raises(
        ValueError, match=r"^SESSION_RESOURCE_CLEANUP_UNCONFIRMED$"
    ):
        session_registry.release_resources(
            tmp_path, owner="owner-a", receipts=receipts
        )

    assert _ledger_held(tmp_path) == before

    # 失败释放不能写入墓碑，随后真实的成功路径仍应可提交。
    session_registry.release_resources(
        tmp_path,
        owner="owner-a",
        receipts=_ledger_cleanup_receipts(),
    )
    assert _ledger_held(tmp_path) == []


# 必须放在模块顶层，供 Windows spawn 导入。


def _ledger_reservation_worker(root, owner, ready, start, results):
    ready.put(owner)

    if not start.wait(timeout=20):
        results.put((owner, "START_TIMEOUT"))
        return

    try:
        session_registry.reserve_resources(
            root,
            owner=owner,
            resources=[_ledger_resource(31001)],
        )
    except ValueError as error:
        results.put((owner, str(error)))
    else:
        results.put((owner, "reserved"))


def test_concurrent_reservation_has_one_winner(tmp_path):
    context = multiprocessing.get_context("spawn")
    ready = context.Queue()
    results = context.Queue()
    start = context.Event()
    owners = ("owner-a", "owner-b")

    processes = [
        context.Process(
            target=_ledger_reservation_worker,
            args=(str(tmp_path), owner, ready, start, results),
        )
        for owner in owners
    ]
    started = []

    try:
        for process in processes:
            process.start()
            started.append(process)

        assert {
            ready.get(timeout=20),
            ready.get(timeout=20),
        } == set(owners)

        start.set()
        outcomes = [
            results.get(timeout=20),
            results.get(timeout=20),
        ]

        for process in started:
            process.join(timeout=10)
            assert not process.is_alive()
            assert process.exitcode == 0

        assert {owner for owner, _ in outcomes} == set(owners)
        assert sorted(status for _, status in outcomes) == [
            "SESSION_RESOURCE_BUSY",
            "reserved",
        ]
        assert _ledger_held(tmp_path) == [("127.0.0.1", 31001)]

        # 验证资源确实归属于报告成功的 owner。
        winner = next(
            owner for owner, status in outcomes
            if status == "reserved"
        )
        session_registry.release_resources(
            tmp_path,
            owner=winner,
            receipts=_ledger_cleanup_receipts(),
        )
        assert _ledger_held(tmp_path) == []

    finally:
        start.set()
        for process in started:
            if process.is_alive():
                process.terminate()
            process.join(timeout=5)

        ready.close()
        results.close()
