"""Prompt text and turn-budget hints for the task executor."""
from __future__ import annotations

from agents._prompt_resources import read_prompt





SYSTEM = read_prompt(__package__, "templates/system.txt")

#: The one retry a refused conclusion gets. It is not "try again": the refusal and the list of calls
#: that may be quoted are handed over, so the second answer can actually be right. Nothing may be run
#: in this turn - the observation it needs is already on disk - and both conclusions stay in the log.
CORRECTION_HINT = read_prompt(__package__, "templates/correction.txt")

# An unknown outcome cannot justify success or another dispatch.
UNRESOLVED_HINT = read_prompt(__package__, "templates/unresolved.txt")


#: How little of the run the *deformed* retry shows (see the retry below): a provider that answered an
#: empty completion to one prompt is answering a different question, not the same one again.
SHORT_KEEP = 4

#: The observation bound the deformed retry uses, in characters.
SHORT_OBSERVATION_LIMIT = 1200

#: 撞满输出上限之后的视图尺寸。与"空答复"同一个道理，实测补一条：2026-10-06 walk-58 的
#: node 7 连着三次撞满 6000（提示词 1.2 万 token / 正文 0 字节 —— 预算全烧在供应商侧"思考"上），
#: 而同一节点前面几次正常答复的提示词也一样大：提示词越大，这类模型越想越多。所以撞满之后
#: 不再拿着原尺寸提示词重问（那是同一个问题问三遍），而是把视图压到"卡 + 最近几步 + 短观测"。
COMPACT_AFTER_TRUNCATION = True

#: 只剩这么多回合时，提示词里明说"该收手了"。为什么要有（2026-10-06 walk-64 node 12 实测）：
#: 那一步的回包干干净净（`PONG` / `OK` / 写进去读回来一致，自证了八遍），模型却一路用不同变体
#: 重复验证同一个效应，八个回合烧光、以 `LEAN_STEP_LIMIT` 收场 —— 引擎自己没有任何"预算要用完"
#: 的信号给它。给足上下文不等于什么都不说：把"还剩几个回合、什么时候该写结论"讲明白，
#: 是引擎该做的事（判据仍然由模型判，引擎不替它判完成）。
CLOSING_TURNS = 2


def budget_hint(step, turns):
    """快要没有回合时的收尾提示；不在收尾窗口里就返回空串。"""
    remaining = int(turns) - int(step)
    if remaining > CLOSING_TURNS:
        return ""
    if remaining <= 1:
        #: **最后一发只许给结论**（2026-10-07 walk-87 node 7 实测：模型上传两次、重复调用、写错路径，
        #: 最后一发还在探索 → 步数用尽、整格"没有结论"，planner 连原因都拿不到）。
        #: 有观测就给 pass/unsatisfied，没有就如实 uncertain —— 都比"没有结论"有用。
        return ("\nBUDGET: this is the LAST turn of this step. Answer with a conclusion ONLY: "
                "{\"tool\":\"finish\", ...} using the observations you already have "
                "(verdict pass / unsatisfied / uncertain). Any other action wastes the step and "
                "the node ends with no conclusion at all - which is strictly worse than an "
                "honest unsatisfied.")
    return ("\nBUDGET: this is turn %d of %d - only %d turn(s) left in this step. If the effect this "
            "card asks for is already visible in the observations above, conclude NOW with "
            "{\"tool\":\"finish\", ...} instead of verifying it again with another variant of the "
            "same command. Running out of turns fails the whole step; a conclusion you can support "
            "with what you already have does not."
            % (int(step) + 1, int(turns), remaining))



#: Added to the prompt only for cards that declare a fixed stage step: the model asks for the step,
#: the card owns the wire shape. Removing that guesswork is the point - a measured run burned three
#: steps rebuilding the same multipart request.
STAGE_HINT = read_prompt(__package__, "templates/stage_hint.txt")
