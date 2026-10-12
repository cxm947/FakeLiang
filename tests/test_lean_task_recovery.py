"""Lean HTTP and standalone dispatch run offline through the actual client bytes."""
import base64
from contextlib import redirect_stdout
from email.message import Message
import hashlib
import http.client
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from runtime import lean_http
from runtime.runner import ExecOutcome, observe_marker_frame
from scripts import run_lean_task as cli

from tests.test_lean_task_support import (
    SCOPE, REQUEST, native_client, collected, card, task, cli_args,
    CARD_FOR_CORRECTION, TASK_FOR_CORRECTION,
    _explicit_console_binding, _console_result,
)
from agents.executor import input as task_input
from agents.executor import driver as task_driver


def test_a_refused_conclusion_gets_one_correction_turn_and_no_calls_in_it(monkeypatch, tmp_path):
    """A quotation that names the wrong call is a bookkeeping mistake, not a failed step.

    The executor asks exactly once more, hands over the refusal plus the calls that may be quoted, and
    *runs nothing* in that turn: "only the claim and the citations may change" is enforced rather
    than stated. Both conclusions stay in the log, and a second refusal is final.
    """
    recorded, instances = [], []

    class FakeRun:
        def __init__(self, **kwargs):
            self.calls, self.corrections, self.conclusions = [], [], []
            instances.append(self)

        def record_decision(self, prompt, reply):
            recorded.append((prompt, reply))

        def call(self, request):
            self.calls.append(request)
            return {"call_id": "call-real", "status": "completed_transport"}

        def conclude(self, claim, citations, verdict, materials):
            self.conclusions.append(list(citations or []))
            if len(self.conclusions) == 1:
                return {"status": "uncertain", "reason": "LEAN_CITATION_INVALID", "citations": [],
                        "rejections": ["LEAN_CALL_UNKNOWN: call-made-up"], "pending_calls": []}
            return {"status": "model_reported", "claimed_verdict": verdict, "claim": claim,
                    "citations": [{"call_id": "call-real"}], "rejections": [], "pending_calls": [],
                    "reason": "MODEL_CLAIM_NOT_MACHINE_VERIFIED"}

        def citation_index(self):
            return [{"call_id": "call-real", "status": "completed_transport", "marker_complete": True}]

        def request_correction(self, feedback):
            self.corrections.append(feedback)

        @property
        def secrets(self):
            return ()

    monkeypatch.setattr(task_driver, "LeanRun", FakeRun)
    actions = [
        {"kind": "call", "request": dict(REQUEST)},
        {"kind": "finish", "claim": "done", "claimed_verdict": "pass",
         "citations": [{"call_id": "call-made-up", "quote": "anything"}]},
        {"kind": "call", "request": {"tool": "http", "method": "GET", "path": "/again"}},
        {"kind": "finish", "claim": "done", "claimed_verdict": "pass",
         "citations": [{"call_id": "call-real", "quote": "Quartz Portal"}]},
    ]
    result = cli.drive(CARD_FOR_CORRECTION, TASK_FOR_CORRECTION, SCOPE, lambda argv, timeout: None,
                       actions=actions, run_dir=tmp_path)
    assert result["status"] == "model_reported"
    assert len(instances) == 1
    run = instances[0]
    assert len(run.calls) == 1                      # the call attempted in the correction turn never ran
    assert len(run.corrections) == 1
    assert run.corrections[0]["quotable_calls"] == [
        {"call_id": "call-real", "status": "completed_transport", "marker_complete": True}]
    assert len(run.conclusions) == 2                # both conclusions are kept
    # Every action is recorded before it is interpreted; the refusal is recorded inside the turn
    # that tried it, so the log shows the attempt and why it was not run.
    assert [row[0].get("source") for row in recorded] == [
        "actions", "actions", "actions", "correction", "actions"]


def test_one_oversized_observation_is_bounded_in_the_prompt_but_kept_on_disk():
    """A huge dump must not crowd out everything else the model has to read.

    Measured 2026-10-05: a step whose first action dumped the mount table and disk list got an
    empty completion on the next turn, twice in a row. The full text stays in the call artifact
    (so a quotation is still checkable); what the model reads is a bounded excerpt that says so.
    """
    big = "x" * 20000
    event = {"kind": "receipt", "receipt": {"call_id": "call-1", "stdout": big,
                                          "stderr": "", "status": "completed_transport"}}
    trimmed = cli.trim_observation(event)
    body = trimmed["receipt"]["stdout"]
    assert len(body) < len(big)
    assert body.startswith("x" * 100) and "truncated 14000 chars" in body
    assert event["receipt"]["stdout"] == big, "the original event is untouched"
    small = {"kind": "receipt", "receipt": {"call_id": "call-2", "stdout": "ok"}}
    assert cli.trim_observation(small) == small


def test_a_refused_tool_comes_back_to_the_model_instead_of_ending_the_node(tmp_path, monkeypatch):
    """爷爷 2026-10-06: "this deployment does not offer that" is a refusal, not a node failure.

    The card below declares only ``shell``; the model asks for ``http`` first. The node must hand
    the refusal back (with the tools it does have) and let the model pick again - measured on node
    5, which otherwise ended on its first turn.
    """
    from agents._model.contract import ModelReply

    native, calls = native_client(monkeypatch)
    supplied = task()
    shell_card = dict(card(), tools=["shell"])
    turns = []

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            state = json.loads(kwargs["user"])
            turns.append(state)
            refusals = [event for event in state["history"] if event["kind"] == "refusal"]
            request = ({"tool": "http", "method": "GET", "path": "/"} if not refusals
                       else {"tool": "shell", "argv": ["echo", "agv-entry-ok"]})
            action = {"kind": "call", "request": request}
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")

    result = cli.drive(shell_card, supplied, SCOPE, native, client=Client(), run_dir=tmp_path,
                       max_steps=3)
    assert len(turns) >= 2, "the node must not end on the refused first turn"
    assert [event for event in turns[1]["history"] if event["kind"] == "refusal"], \
        "the refusal (and the tools this deployment does have) must reach the next prompt"
    # The node stopped for some *other* reason (the stubbed executor is an http fixture): what the
    # test proves is that a refusal no longer ends the turn by itself.
    assert "LEAN_TOOL_UNDECLARED" not in str(result.get("reason") or ""), result
    assert len(turns) >= 3, "the model kept working after the refusal"


def test_a_repeated_request_comes_back_with_the_observation_it_already_got(tmp_path, monkeypatch):
    """爷爷 2026-10-06: node 12 burned its whole budget re-asking one settled request."""
    from agents._model.contract import ModelReply

    native, calls = native_client(monkeypatch)
    supplied = task()
    seen = []

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            state = json.loads(kwargs["user"])
            refusals = [event["refusal"] for event in state["history"]
                        if event.get("kind") == "refusal"]
            seen.extend(refusals)
            action = ({"kind": "finish", "claim": "the earlier observation answers this",
                       "claimed_verdict": "uncertain", "citations": []}
                      if refusals else {"kind": "call", "request": REQUEST})  # same request
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")

    cli.drive(card(), supplied, SCOPE, native, client=Client(), run_dir=tmp_path, max_steps=4)
    assert seen, "a repeat of a settled request must not be silent - it is how node 12 looped"
    assert seen[0]["reason_code"] == "LEAN_CALL_ALREADY_RAN"
    # The refusal names the call that already ran: the model can look at that receipt instead of
    # re-asking (the merged observation is attached when it is read back, not at call time).
    assert seen[0]["already_ran"] and seen[0]["already_ran"][0]["call_id"], seen[0]
    # It also hands over the object to send again, with the two keys already in place. A tier that
    # does not re-read the note kept replaying the same request verbatim until the step died
    # (measured 2026-10-08, walk-173 node 19: the plant command ran *after* the upload, so the
    # upload had to be redone and the model never declared it).
    resend = seen[0]["resend"]
    assert resend["retry_of"] == seen[0]["already_ran"][0]["call_id"], resend
    assert resend["retry_reason"], resend
    assert all(resend.get(key) == value for key, value in REQUEST.items()), resend


def test_abandon_does_not_release_an_empty_capture(tmp_path, monkeypatch):
    """An empty capture remains unresolved after abandon and cannot be dispatched again."""
    from agents._model.contract import ModelReply

    sent, prompts = [], []

    def executor(argv, timeout):
        sent.append(list(argv))
        return ExecOutcome(None, "", "", timed_out=True, read_stop="deadline")

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            prompts.append(kwargs)
            history = json.loads(kwargs["user"])["history"]
            if len(prompts) == 1:
                action = {"kind": "call", "request": REQUEST}
            elif len(prompts) == 2:
                original = next(row for row in history if row.get("kind") == "intent")
                action = {"kind": "abandon", "call_id": original["call_id"],
                          "reason": "local waiting ended without a frame"}
            elif len(prompts) == 3:
                action = {"kind": "call", "request": REQUEST}
            else:
                action = {"kind": "finish", "claim": "the remote outcome remains unknown",
                          "claimed_verdict": "uncertain", "citations": []}
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")

    result = cli.drive(card(), task(), SCOPE, executor, client=Client(), run_dir=tmp_path,
                       max_steps=4)
    events = [json.loads(line) for line in
              (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    intents = [row for row in events if row["kind"] == "intent"]
    assert len(sent) == len(intents) == 1
    assert any(row["kind"] == "abandon" for row in events)
    assert not any(row["kind"] == "retry" for row in events)
    assert any(row["kind"] == "refusal" and row["refusal"]["reason_code"] == "LEAN_UNRESOLVED_CALL"
               for row in events)
    assert result["status"] == "uncertain"
    assert result["reason"] == "LEAN_UNRESOLVED_CALL"
    assert result["pending_calls"] == [intents[0]["call_id"]]


def test_an_empty_answer_is_retried_with_a_smaller_prompt_not_the_same_one(tmp_path, monkeypatch):
    """A provider that answered nothing is asked a *smaller* question, not the same one again.

    Measured 2026-10-06 (node 2): five identical empty completions in a row cost ~5 minutes and
    ended the node. Only a different prompt can change the answer, so the retry shows fewer events
    and shorter observations - the card, the task and the scope stay identical, which is what keeps
    it a retry. The failed first answer is still on the model log.
    """
    from agents._model.contract import EMPTY_CONTENT_ERROR, ModelReply

    monkeypatch.setattr(cli, "load_card", lambda *_: card())
    monkeypatch.setattr(task_driver, "OBSERVATION_LIMIT", 4000)
    monkeypatch.setattr(task_driver, "SHORT_OBSERVATION_LIMIT", 40)
    monkeypatch.setattr(task_driver, "SHORT_KEEP", 2)

    def runner(argv, timeout):
        return ExecOutcome(0, "page body " + "x" * 300, "")
    runner.label = lambda: "control-user@192.0.2.2"
    monkeypatch.setattr(task_input, "subprocess_executor", runner)

    prompts = []

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            prompts.append(kwargs)
            if len(prompts) == 1:
                action = {"kind": "call", "request": REQUEST}
                return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")
            if len(prompts) == 2:
                return ModelReply(ok=False, model="offline", attempts=5,
                                  error=EMPTY_CONTENT_ERROR + " (finish_reason='stop')")
            action = {"kind": "finish", "claim": "nothing further", "claimed_verdict": "uncertain",
                      "citations": []}
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")

    result = cli.drive(card(), task(), SCOPE, runner, client=Client(), run_dir=tmp_path,
                       max_steps=6)
    assert len(prompts) >= 3, "the empty answer is retried once, then believed"
    assert prompts[1]["retries"] == 4 and prompts[2]["retries"] == 2
    assert len(prompts[2]["user"]) < len(prompts[1]["user"]), \
        "the retry must show a smaller view of the same turn"
    assert json.loads(prompts[2]["user"])["card"] == json.loads(prompts[1]["user"])["card"]
    sources = [json.loads(line)["source"]
               for line in (tmp_path / "model.jsonl").read_text(encoding="utf-8").splitlines()]
    assert sources[:3] == ["lean", "lean_deform", "lean"], sources
    assert "no content" not in str(result.get("reason") or ""), result


@pytest.mark.parametrize("verdict", ["uncertain", "unsatisfied"])
def test_honest_stop_preserves_pending_without_writeoff_or_more_actions(monkeypatch, verdict):
    """Honest non-success stops once, retaining the unresolved call and all unmet delivery work."""
    recorded = []

    class FakeRun:
        secrets = ()

        def __init__(self, **kwargs):
            pass

        def record_decision(self, prompt, reply):
            recorded.append(reply)

        def delivery_pending(self):
            pytest.fail("an honest non-success must not be asked to perform more delivery work")

        def call(self, request):
            pytest.fail("no action may follow the terminal report")

        def request_correction(self, feedback):
            pytest.fail("an honest unknown outcome does not require abandonment")

        def conclude(self, claim, citations, claimed_verdict, materials):
            return {"status": "uncertain", "claimed_verdict": claimed_verdict,
                    "reason": "LEAN_UNRESOLVED_CALL", "pending_calls": ["call-stuck"],
                    "citations": [], "rejections": []}

    monkeypatch.setattr(task_driver, "LeanRun", FakeRun)
    actions = [
        {"kind": "finish", "claim": "outcome unknown", "claimed_verdict": verdict, "citations": []},
        {"kind": "call", "request": REQUEST},
    ]
    result = cli.drive(CARD_FOR_CORRECTION, TASK_FOR_CORRECTION, SCOPE,
                       lambda *args: pytest.fail("unexpected dispatch"), actions=actions,
                       run_dir="unused")
    assert len(recorded) == 1
    assert result["status"] == "uncertain"
    assert result["claimed_verdict"] == verdict
    assert result["pending_calls"] == ["call-stuck"]


def test_unresolved_refusal_does_not_offer_abandon_as_permission_to_dispatch():
    """Unresolved feedback permits an honest stop, never a different request or an automatic retry."""
    from scripts import run_lean_task as cli

    card, scope = {"tools": ["http"]}, {"vantage": "base", "host": "192.0.2.9"}
    for code in ("LEAN_CALL_UNRESOLVED", "LEAN_UNRESOLVED_CALL"):
        refusal = cli.refusal_record(code, code + ": call-1", card, scope)
        assert "no further dispatch or retry" in refusal["note"]
        assert "does not settle" in refusal["note"]
        assert "uncertain or unsatisfied" in refusal["note"]
    composite = cli.refusal_record("LEAN_SECRET_TOKEN_COMPOSITE", "composite", card, scope)
    assert "whole argument" in composite["note"]
    path = cli.refusal_record("LEAN_HTTP_PATH_INVALID", "path", card, scope)
    assert "percent-encoded" in path["note"]


def test_a_truncated_answer_is_retried_with_a_smaller_view(tmp_path, monkeypatch):
    """撞满输出上限之后换**小视图**重问，而不是拿着同一个大提示词问三遍。

    2026-10-06 walk-58 node 7 实测：同一节点前几次正常答复 1117/918/2323 token，撞满的三次都是
    6000 token 且**正文 0 字节** —— 预算全被供应商侧的"思考"吃掉，提示词 1.2 万 token。
    问题不在"这一步要写长脚本"（卡里路线是写死的，命令都是短 JSON），而在提示词大 + 模型话多。
    """
    from agents._model.contract import TRUNCATED_ERROR, ModelReply

    monkeypatch.setattr(task_driver, "OBSERVATION_LIMIT", 4000)
    monkeypatch.setattr(task_driver, "SHORT_OBSERVATION_LIMIT", 40)
    monkeypatch.setattr(task_driver, "SHORT_KEEP", 2)

    def runner(argv, timeout):
        return ExecOutcome(0, "page body " + "x" * 300, "")
    runner.label = lambda: "control-user@192.0.2.2"
    monkeypatch.setattr(task_input, "subprocess_executor", runner)

    prompts = []

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            prompts.append(kwargs)
            if len(prompts) == 1:
                action = {"kind": "call", "request": REQUEST}
                return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")
            if len(prompts) == 2:
                return ModelReply(ok=False, model="offline", error=TRUNCATED_ERROR)
            action = {"kind": "finish", "claim": "bounded", "claimed_verdict": "uncertain",
                      "citations": []}
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")

    result = cli.drive(card(), task(), SCOPE, runner, client=Client(), run_dir=tmp_path)
    assert len(prompts) >= 3, "撞满之后要再问一次（回喂），不是停"
    assert result.get("status") in ("model_reported", "uncertain"), result
    #: prompts[0] 第一次问；prompts[1] 是撞满的那次；**prompts[2] 才是撞满之后的回喂**。
    state = json.loads(prompts[2]["user"])
    receipts = [item for item in state["history"] if item.get("kind") == "receipt"]
    assert receipts and "<truncated" in json.dumps(receipts[0], ensure_ascii=False), \
        "撞满后的重试必须换小视图（观测被截断），否则就是把同一个大问题再问一遍"


def test_writing_off_a_call_tolerates_a_merged_extra_request(tmp_path):
    """Abandon remains auditable while an extra merged action is ignored rather than dispatched."""
    from agents._model.contract import ModelReply

    prompts = []

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            prompts.append(kwargs)
            if len(prompts) == 1:
                action = {"kind": "abandon", "call_id": "call-gone", "reason": "dispatch unconfirmed",
                          "tool": "shell", "cmd": "id -u"}
            else:
                action = {"tool": "finish", "claim": "写掉了那条未决调用", "verdict": "uncertain",
                          "citations": []}
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model="offline")

    def executor(argv, timeout):
        pytest.fail("the extra action merged into abandon must not be dispatched")

    result = cli.drive(card(), task(), SCOPE, executor, client=Client(), run_dir=tmp_path)
    events = [json.loads(line) for line in
              (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    codes = [event["refusal"]["reason_code"] for event in events if event.get("kind") == "refusal"]
    assert "LEAN_ACTION_UNSUPPORTED" not in codes, codes
    assert result.get("reason") != "LEAN_ACTION_UNSUPPORTED", result
    #: 核销要留痕（不是静默丢弃）
    assert "LEAN_ABANDON_HAS_EXTRA_KEYS" in codes, codes
    abandons = [event for event in events if event.get("kind") == "abandon"]
    assert abandons, "核销本身要落成事件"


def test_the_last_turns_say_how_much_budget_is_left_and_to_conclude(tmp_path):
    """快没回合时要明说"还剩几个、该写结论了"。

    2026-10-06 walk-64 node 12 实测：回包干干净净（PONG / OK / 写进去读回来一致，自证八遍），
    模型却用不同变体反复验证同一个效应，八回合烧光 → `LEAN_STEP_LIMIT`。引擎必须把预算讲明白，
    否则"给模型自由"就变成"让它撞墙"。（判据仍由模型判，引擎不替它判完成。）
    """
    assert cli.budget_hint(0, 8) == "", "开局不该催"
    assert cli.budget_hint(5, 8) == ""
    late = cli.budget_hint(7, 8)
    #: 最后一发更硬：只许给结论（2026-10-07 walk-87 node 7 实测：最后一发还在探索 → 整格没有结论，
    #: planner 连原因都拿不到）。
    assert "LAST turn" in late and "conclusion ONLY" in late
    only_two = cli.budget_hint(6, 8)
    assert "turn 7 of 8" in only_two and "only 2 turn" in only_two and "conclude NOW" in only_two
    assert cli.budget_hint(6, 8), "只剩两回合就该开始提示"


def test_a_truncated_answer_comes_back_as_a_budget_refusal(tmp_path):
    """撞满卡给的输出上限 -> 回喂「只输出 JSON」，同一上限重试，不许把整轮打死。

    2026-10-06 walk-57 实测：这条分支第一次真跑就抛了 NameError（TRUNCATED_ERROR 没导入），
    整个端到端进程当场死掉 —— 就是因为这条路径当时没有用例。
    """
    from agents._model.contract import ModelReply, TRUNCATED_ERROR

    prompts = []

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            prompts.append(kwargs)
            if len(prompts) == 1:
                return ModelReply(ok=False, model='offline', error=TRUNCATED_ERROR)
            action = {'kind': 'finish', 'claim': 'bounded', 'claimed_verdict': 'uncertain',
                      'citations': []}
            return ModelReply(ok=True, text=json.dumps(action), payload=action, model='offline')

    def executor(argv, timeout):
        return ExecOutcome(0, '', '')

    result = cli.drive(card(), task(), SCOPE, executor, client=Client(), run_dir=tmp_path)
    assert result.get('status') in ('model_reported', 'uncertain'), result
    assert 'reason' not in result or result['reason'] != 'LEAN_MODEL_REPLY_UNAVAILABLE'
    assert len(prompts) >= 2, '撞满之后要再问一次（回喂），而不是停'
    events = [json.loads(line) for line in
              (tmp_path / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
    reasons = [event['refusal']['reason_code'] for event in events if event.get('kind') == 'refusal']
    assert 'LEAN_OUTPUT_OVER_BUDGET' in reasons, reasons
    #: 上限是产品约束：重试用的是同一个上限，没有偷偷加倍。
    assert all(item['max_tokens'] == prompts[0]['max_tokens'] for item in prompts)
    #: 爷爷 2026-10-06 口径：别掐 token 量 —— 卡没显式声明上限时，请求里一个上限字段都不带
    #: （这条线上思考关不掉，推理与正文共享同一个上限，掐上限就会"思考吃光预算、正文 0 字节"）。
    assert prompts[0]['max_tokens'] is None


def test_compact_call_index_and_duplicate_feedback_keep_evicted_receipts(monkeypatch, tmp_path):
    from agents.executor.observation import show_run
    from runtime.lean import LeanRun

    execute, requests = native_client(monkeypatch, body=b"first printable observation")

    def both_streams(argv, timeout):
        result = execute(argv, timeout)
        return ExecOutcome(result.returncode, result.stdout, "printable stderr observation")

    run = LeanRun(tmp_path, card=card(), task=task(), scope=SCOPE, executor=both_streams)
    first = run.call(REQUEST)
    run.call(dict(REQUEST, path="/second"))
    run.call(dict(REQUEST, path="/third"))
    view, _, _ = show_run(card(), task(), run, "", KEEP=4, limit=100)
    assert len(view["calls"]) == 3 and view["calls"][0]["call_id"] == first["call_id"]
    assert view["calls"][0]["status"] == "completed_transport"
    assert not any(event.get("call_id") == first["call_id"] for event in view["history"])
    assert run.call(REQUEST) == first
    view, _, _ = show_run(card(), task(), run, "", KEEP=4, limit=100)
    refusal = next(event["refusal"] for event in reversed(view["history"])
                   if event.get("kind") == "refusal")
    saved = refusal["already_ran"][0]
    assert refusal["reason_code"] == "LEAN_CALL_ALREADY_RAN"
    assert saved["call_id"] == first["call_id"]
    assert "first printable observation" in saved["stdout"]
    assert "printable stderr observation" in saved["stderr"]
    assert saved["stdout_chars"] == len(first["stdout"])
    assert sum(item[0] == "request" for item in requests) == 3


def test_local_saved_read_preserves_the_last_conclusion_turn(monkeypatch, tmp_path):
    from agents._model.contract import ModelReply

    execute, requests = native_client(monkeypatch, body=b"header " + b"x" * 7500 + b" tail-proof")
    prompts = []

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            state = json.loads(kwargs["user"])
            prompts.append(state)
            if len(prompts) == 1:
                payload = dict(REQUEST)
            elif len(prompts) == 2:
                payload = {"tool": "evidence", "call_id": state["calls"][0]["call_id"],
                           "contains": "tail-proof"}
            else:
                assert "tail-proof" in state["evidence"][-1]["text"]
                payload = {"tool": "finish", "claim": "Printed tail proof.", "verdict": "pass",
                           "citations": [{"call_id": state["calls"][0]["call_id"],
                                          "quote": "tail-proof"}]}
            return ModelReply(ok=True, text=json.dumps(payload), payload=payload)

    report = cli.drive(card(), task(), SCOPE, execute, client=Client(),
                       run_dir=tmp_path, max_steps=2)
    assert report["status"] == "model_reported" and len(prompts) == 3
    assert sum(item[0] == "request" for item in requests) == 1 and report["citations"][0]["status"] == "checked"


def test_correction_can_retrieve_middle_stderr_without_target_dispatch(monkeypatch, tmp_path):
    from agents._model.contract import ModelReply

    execute, requests = native_client(monkeypatch, body=b"ordinary response")

    def both_streams(argv, timeout):
        result = execute(argv, timeout)
        return ExecOutcome(result.returncode, result.stdout,
                           "h" * 7500 + " stderr-middle-proof " + "t" * 7500)

    prompts = []

    class Client:
        def available(self):
            return True

        def complete(self, **kwargs):
            state = json.loads(kwargs["user"])
            prompts.append(state)
            number = len(prompts)
            if number == 1:
                payload = dict(REQUEST)
            elif number == 2:
                payload = {"tool": "finish", "claim": "An observation.", "verdict": "pass",
                           "citations": [{"call_id": state["calls"][0]["call_id"],
                                          "quote": "invented original quote"}]}
            elif number == 3:
                assert state["correction"]["quotable_calls"][0]["streams"]["stderr"]["chars"] > 15000
                payload = {"tool": "evidence", "call_id": state["calls"][0]["call_id"],
                           "stream": "stderr", "contains": "stderr-middle-proof"}
            else:
                assert state["correction"] and "stderr-middle-proof" in state["evidence"][-1]["text"]
                payload = {"tool": "finish", "claim": "Printed observation.", "verdict": "pass",
                           "citations": [{"call_id": state["calls"][0]["call_id"],
                                          "quote": "stderr-middle-proof", "stream": "stderr"}]}
            return ModelReply(ok=True, text=json.dumps(payload), payload=payload)

    report = cli.drive(card(), task(), SCOPE, both_streams, client=Client(),
                       run_dir=tmp_path, max_steps=3)
    assert report["status"] == "model_reported" and len(prompts) == 4
    assert sum(item[0] == "request" for item in requests) == 1 and report["citations"][0]["stream"] == "stderr"


def test_compact_saved_reads_pin_correction_and_bound_text(monkeypatch, tmp_path):
    from agents.executor.observation import show_run
    from runtime.lean import LeanRun

    execute, _ = native_client(monkeypatch, body=b"x" * 15000)
    run = LeanRun(tmp_path, card=card(), task=task(), scope=SCOPE, executor=execute)
    receipt = run.call(REQUEST)
    feedback = {"reason": "LEAN_CITATION_INVALID", "quotable_calls": run.citation_index()}
    run.request_correction(feedback)
    for start in range(0, 8000, 2000):
        run.read_evidence(receipt["call_id"], start=start)
    view, _, _ = show_run(card(), task(), run, "", KEEP=4, limit=1200)
    assert view["correction"] == feedback
    assert len(view["evidence"]) == 2
    assert all(len(item["text"]) <= 2000 for item in view["evidence"])
    assert not any(item.get("kind") in {"correction", "receipt_read"} for item in view["history"])


def test_saved_read_allowance_is_bounded_without_target_replays(monkeypatch, tmp_path):
    from runtime.lean import LeanRun

    execute, requests = native_client(monkeypatch, body=b"ordinary response")
    #: `driver.drive` builds its run with the driver default timeout (30); a resumed run
    #: must present the same binding, so this manual run uses the same value.
    run = LeanRun(tmp_path, card=card(), task=task(), scope=SCOPE, executor=execute,
                  timeout=30)
    receipt = run.call(REQUEST)
    actions = [{"tool": "evidence", "call_id": receipt["call_id"]}] * 9
    actions.append({"tool": "finish", "claim": "No fact established.",
                    "verdict": "uncertain", "citations": []})
    report = cli.drive(card(), task(), SCOPE, execute, actions=actions,
                       run_dir=tmp_path, max_steps=3)
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text(
        encoding="utf-8").splitlines()]
    assert report["status"] == "model_reported" and sum(item[0] == "request" for item in requests) == 1
    assert sum(row["kind"] == "receipt_read" for row in events) == 8
    assert any(row.get("refusal", {}).get("reason_code") == "LEAN_EVIDENCE_READ_LIMIT"
               for row in events)


def test_runtime_prompt_context_is_bounded_with_sixty_saved_calls():
    from agents.executor.observation import fit_context

    view = {"calls": [{"call_id": "call-" + str(i).zfill(59),
                       "request": "x" * 80, "status": "completed_transport",
                       "command_rc": 0, "read_stop": "marker"} for i in range(60)],
            "history": [{"receipt": {"stdout": "x" * 6000, "stderr": "y" * 6000}}
                        for _ in range(12)],
            "evidence": [{"text": "selected proof " + "e" * 1900} for _ in range(4)],
            "correction": {"quotable_calls": [
                {"call_id": "call-" + str(i).zfill(59), "status": "completed_transport",
                 "marker_complete": True, "excerpt": "x" * 160,
                 "streams": {"stdout": {"head": "h" * 320, "tail": "t" * 320},
                             "stderr": {"head": "h" * 320, "tail": "t" * 320}}}
                for i in range(60)]},
            "feedback": {"reason_code": "LEAN_CALL_ALREADY_RAN",
                         "already_ran": [{"stdout": "d" * 800, "stderr": "e" * 800}]}}
    fit_context(view, compact=True)
    assert len(json.dumps(view, ensure_ascii=False).encode("utf-8")) <= 18000
    assert len(view["calls"]) == 60
    assert "selected proof" in view["evidence"][-1]["text"]
    assert view["feedback"]["reason_code"] == "LEAN_CALL_ALREADY_RAN"
    assert view["correction"]
