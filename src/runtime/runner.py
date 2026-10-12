"""Fixed-argv execution with call ids and raw artifacts.

One call = one ``execute(...)``: the adapter fixes the argv, the runner runs it and
writes every byte that came back under ``<run_dir>/<call_id>/`` so any later reviewer
can trace an evidence field to the exact output that produced it.

The executor is injectable on purpose: unit tests pass a fake and stay offline, while
production passes the subprocess executor on the host that owns the tools (Kali).
Nothing in this module decides pass/fail - that belongs to the checker, driven by the
skill card.
"""

from __future__ import annotations

import json
import random
import subprocess
import time
import uuid
from collections.abc import Callable, Iterable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from graph.files import atomic_write
from .redact import redact_argv, redact_text


#: 抢不到锁不是错误：多进程共用一份状态时，谁在写就等一小会儿再来。
#: walk-184 整轮崩，就是"读路径去抢写闸、非阻塞立刻被弹回 -> 异常穿到进程入口、整轮死"。
OWNERSHIP_WAIT_S = 0.0


class OwnershipBusy(TimeoutError):
    """Another process held the lock past the budget: report it, do not kill the run."""


def _take(stream):
    """Try once, non-blocking: raises OSError when somebody else holds the lock."""
    stream.seek(0)
    if __import__("os").name == "nt":
        import msvcrt
        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _drop(stream):
    stream.seek(0)
    if __import__("os").name == "nt":
        import msvcrt
        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(stream, fcntl.LOCK_UN)


@contextmanager
def ownership(folder, *, wait=None):
    """Single control host; OS lock dies with the owner, no live takeover.

    ``wait`` = bounded wait budget in seconds. Default ``0`` keeps the historic
    fail-fast meaning (""somebody is using this shell right now""), which callers that claim a
    physical session depend on. Shared-state callers that only need serialised writes pass an
    explicit budget, so transient contention waits instead of killing a whole round.
    """
    budget = OWNERSHIP_WAIT_S if wait is None else float(wait)
    path = Path(folder) / "owner.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        if budget <= 0:
            #: 历史语义：立刻失败（调用方要能分辨"别人正在用这条会话"与"锁坏了"）。
            _take(stream)
        else:
            deadline = time.monotonic() + budget
            while True:
                try:
                    _take(stream)
                except OSError as error:
                    if time.monotonic() >= deadline:
                        raise OwnershipBusy("OWNERSHIP_BUSY: " + str(path)) from error
                    time.sleep(0.02 + random.random() * 0.08)
                    continue
                break
        try:
            yield
        finally:
            _drop(stream)




@dataclass
class ExecOutcome:
    """Executor output plus what the carrier observed about the read.

    ``returncode`` 是**载体**的返回码；远端命令自己的退出码是另一个事实，只能来自观测到的结束帧
    （见 ``observe_marker_frame``）。``read_stop`` 说明这一次捕获**为什么**停下来：
    ``end_marker``（唯一算"完成"的）/ ``deadline`` / ``prompt`` / ``idle`` / ``None``（非控制台执行器）。
    """

    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    tool_error: str | None = None
    read_stop: str | None = None


Executor = Callable[[Sequence[str], float], ExecOutcome]


def observe_marker_frame(text: str, marker: str) -> tuple[bool, int | None]:
    """观测一个**有序、完整**的 start/end 帧；返回 `(complete, command_rc)`。

    "出现过某个字符串"和"这一发真的跑完了"是两件事（2026-10-07 桥评审 + 真机现场）：
      * 结束行必须是**一整行** —— 最后一段没有换行的尾巴不算（分块到达时 `end` 先到、退出码后到，
        以前会被当成"齐了"；真机 node 48 就出现过"结束帧先到、命令行后到"的假阳性）；
      * `start` 必须**先于** `end`；
      * 命令回显里含标记文本**不算**帧（回显不等于目标侧执行）；
      * `<marker>end`（不带码）→ `(True, None)`：运输完成，但**命令码未知**；
        `<marker>end 17` → `(True, 17)`；`end 0 junk` 这种带尾巴的**不算**。
    """
    import re

    if not marker:
        return False, None

    start = marker + "start"
    end_pattern = re.compile(re.escape(marker + "end") + r"(?:[ \t]+([+-]?[0-9]+))?")
    started = False

    #: 最后一段没有换行 ⇒ 这一行还没收完，不能当帧。
    for raw in str(text or "").split("\n")[:-1]:
        line = raw.rstrip("\r").strip(" \t")
        if not started:
            started = line == start
            continue
        match = end_pattern.fullmatch(line)
        if match is not None:
            code = match.group(1)
            return True, int(code) if code is not None else None

    return False, None


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def new_call_id() -> str:
    return datetime.now().strftime("call-%Y%m%dT%H%M%S-") + uuid.uuid4().hex[:6]


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def subprocess_executor(argv: Sequence[str], timeout: float) -> ExecOutcome:
    """Default executor: run locally, capture text output, never raise."""
    try:
        completed = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired as error:
        return ExecOutcome(None, _text(error.stdout), _text(error.stderr), timed_out=True)
    except FileNotFoundError as error:
        return ExecOutcome(None, tool_error=f"command not found: {error.filename or argv[0]}")
    except OSError as error:
        return ExecOutcome(None, tool_error=f"executor failed: {error}")
    return ExecOutcome(completed.returncode, completed.stdout or "", completed.stderr or "")


#: Exit codes a transport client uses to say "I never reached the endpoint". EX_TEMPFAIL (75) is
#: the portable spelling of that; the msf client's own header documents it. A call that returns it
#: delivered nothing, so it is judged as a transport failure and the connection-pause rule applies.
TRANSPORT_EXIT_CODES = frozenset({75})

#: The structured reason line a transport client prints on stderr (its own header documents the
#: shape). The exit code keeps saying *whether* the call failed; this line says *what kind* of
#: failure it was, so a record never has to guess from prose. Reading it changes no judgement:
#: a malformed line is dropped, and an absent line means "the client is older than the contract".
EXEC_DETAIL_PREFIX = "EXEC_DETAIL "


def parse_exec_detail(text: str) -> dict | None:
    """The last ``EXEC_DETAIL`` object in ``text``, or None. Never raises."""
    found = None
    for line in (text or "").splitlines():
        if not line.startswith(EXEC_DETAIL_PREFIX):
            continue
        try:
            payload = json.loads(line[len(EXEC_DETAIL_PREFIX):])
        except ValueError:
            continue
        if isinstance(payload, dict):
            found = payload
    return found


@dataclass
class CallResult:
    """One executed call: a redacted view for the model, artifacts for the record."""

    call_id: str
    skill_id: str
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    tool_error: str | None
    started_at: str
    duration_s: float
    call_dir: Path
    artifacts: dict[str, str] = field(default_factory=dict)
    vantage: str | None = None
    material_kept: bool = False
    detail: dict | None = None
    read_stop: str | None = None

    @property
    def status(self) -> str:
        if self.timed_out:
            return "timeout"
        if self.tool_error:
            return "tool_missing"

        #: ``prompt`` / ``idle`` 只说明"捕获为什么停"：它们**不是**命令完成的证据。
        #: ``quiet`` 是"没有结束帧的动词（`sysinfo` 这类原生调用）自己停止增长"——
        #: 有内容 + 不再增长就是它的答案（与 session_manager 的原生探活同一口径）。
        #: ``None`` 保留非控制台执行器原来的语义（本地进程的 returncode 就是它的结局）。
        if self.read_stop not in (None, "end_marker", "quiet"):
            return "unconfirmed"

        if self.returncode is None:
            return "transport_error"
        if self.returncode in TRANSPORT_EXIT_CODES:
            return "transport_error"
        return "executed"

    def to_json(self) -> dict:
        payload = {
            "call_id": self.call_id,
            "skill": self.skill_id,
            "status": self.status,
            "argv": self.argv,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "tool_error": self.tool_error,
            "read_stop": self.read_stop,
            "started_at": self.started_at,
            "duration_s": round(self.duration_s, 3),
            "artifacts": self.artifacts,
        }
        if self.vantage:
            payload["vantage"] = self.vantage
        if self.detail:
            payload["detail"] = self.detail
        if self.material_kept:
            payload["material_kept"] = True
        return payload


def execute(
    argv: Iterable[str],
    *,
    run_dir,
    skill_id: str,
    timeout: float = 60.0,
    redactions: Iterable[str] = (),
    secret_flags: Iterable[str] | None = None,
    executor: Executor | None = None,
    call_id: str | None = None,
    keep_material: bool = False,
) -> CallResult:
    """Run one fixed argv and persist cmd/stdout/stderr under the call directory.

    ``keep_material=True`` is the one explicit exception to the redaction policy: a
    credential-producing method needs the material itself - a masked hash is not evidence.
    The argv is still redacted, and ``call.json`` records ``material_kept`` so a reviewer can
    see exactly which calls carry unmasked bytes.
    """
    runner = executor or subprocess_executor
    identifier = call_id or new_call_id()
    tokens = [str(token) for token in argv]
    audit = getattr(runner, "audit_argv", None)
    audit_tokens = audit(tokens) if callable(audit) else tokens
    safe_argv = redact_argv(audit_tokens, redactions, secret_flags)
    vantage = None
    label = getattr(runner, "label", None)
    if callable(label):
        vantage = label()
    call_dir = Path(run_dir) / identifier
    call_dir.mkdir(parents=True, exist_ok=True)
    started_at = timestamp()
    start = time.monotonic()
    outcome = runner(tokens, float(timeout))
    duration = time.monotonic() - start
    if keep_material:
        stdout = _text(outcome.stdout)
        stderr = _text(outcome.stderr)
    else:
        stdout = redact_text(outcome.stdout, redactions)
        stderr = redact_text(outcome.stderr, redactions)
    artifacts = {
        "stdout": str(call_dir / "stdout.txt"),
        "stderr": str(call_dir / "stderr.txt"),
        "call": str(call_dir / "call.json"),
    }
    result = CallResult(
        call_id=identifier,
        skill_id=skill_id,
        argv=safe_argv,
        returncode=outcome.returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=outcome.timed_out,
        tool_error=outcome.tool_error,
        started_at=started_at,
        duration_s=duration,
        call_dir=call_dir,
        artifacts=artifacts,
        vantage=vantage,
        material_kept=keep_material,
        detail=parse_exec_detail(stderr),
        read_stop=getattr(outcome, "read_stop", None),
    )
    #: 三件产物必须经 `Path.write_text` 落盘：脱敏断言就挂在该调用点上
    #: （tests/test_lean_kernel_evidence.py 先看写入内容再比对）。原子替换留给
    #: 下面的 intent/journal 边界，别把这条可观测的写入路径换掉。
    (call_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
    (call_dir / "stderr.txt").write_text(stderr, encoding="utf-8")
    (call_dir / "call.json").write_text(
        json.dumps(result.to_json(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def plan_payload(
    skill_id: str,
    argv: Iterable[str],
    *,
    redactions: Iterable[str] = (),
    secret_flags: Iterable[str] | None = None,
    steps: Iterable[Iterable[str]] | None = None,
    session_plan: Iterable[str] | None = None,
) -> dict:
    """``--plan`` output: the exact argv (and every further step) that would run."""
    payload = {
        "skill": skill_id,
        "mode": "plan",
        "status": "planned",
        "argv": redact_argv([str(token) for token in argv], redactions, secret_flags),
    }
    if steps is not None:
        payload["steps"] = [redact_argv([str(token) for token in step], redactions, secret_flags) for step in steps]
    if session_plan is not None:
        payload["session_plan"] = [str(value) for value in session_plan]
    return payload
