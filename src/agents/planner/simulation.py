"""Explicit offline fixture; never used to recover a failed real model call."""

import json
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import Field

from .schema import PlannerInput
from .validation import ready_nodes


class SimulationChatModel(BaseChatModel):
    responses: list[Any] = Field(default_factory=list)
    policy: bool = False
    calls: list[list] = Field(default_factory=list, exclude=True)

    @property
    def _llm_type(self):
        return "agv-offline-fixture"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        index = len(self.calls)
        self.calls.append(list(messages))
        if index < len(self.responses):
            response = self.responses[index]
        elif self.policy:
            context = PlannerInput.model_validate(json.loads(messages[1].content))
            eligible = ready_nodes(context)
            last = context.last_result
            next_ids = {e.dst for e in context.graph.edges if last and last.结果 == "通过" and e.src == last.node_id}
            ordered = sorted(eligible, key=lambda nid: (nid not in next_ids, not nid.isdigit(),
                                                       int(nid) if nid.isdigit() else nid))
            response = {"next_node_id": ordered[0] if ordered else None,
                        "status": "continue" if ordered else "finish",
                        "why": "离线模拟：优先延续成功路径。" if ordered else "没有可继续的节点。"}
        else:
            raise RuntimeError("Offline response fixture exhausted")
        if isinstance(response, BaseException):
            raise response
        if isinstance(response, dict):
            message = AIMessage(content="", tool_calls=[
                {"name": "PlannerDecision", "args": response, "id": f"offline-{index}", "type": "tool_call"}])
        else:
            message = AIMessage(content=str(response) if response is not None else "")
        return ChatResult(generations=[ChatGeneration(message=message)])
