"""Strict public contracts; schemas are generated from these models."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Node(Contract):
    id: str = Field(min_length=1)
    type: Literal["AND", "OR"]


class Edge(Contract):
    src: str
    dst: str


class Graph(Contract):
    nodes: list[Node]
    edges: list[Edge]
    final_goal: list[str]

    @model_validator(mode="before")
    @classmethod
    def upgrade_action_scope(cls, value):
        # Replay legacy snapshots, but send only one static action-node list.
        # Validate any old duplicate list before removing it; never filter by status.
        if isinstance(value, dict):
            value = dict(value)
            if isinstance(value.get("nodes"), list) and isinstance(value.get("final_goal"), list):
                nodes = [n for n in value["nodes"]
                         if not isinstance(n, dict) or n.get("id") not in value["final_goal"]]
                if "actions" in value:
                    actions = value.pop("actions")
                    if not isinstance(actions, list):
                        raise ValueError("actions must be a list")
                    old = sorted((Node.model_validate(n) for n in actions), key=lambda n: n.id)
                    expected = sorted((Node.model_validate(n) for n in nodes), key=lambda n: n.id)
                    if old != expected:
                        raise ValueError("actions must contain every non-goal node exactly once with its original type")
                value["nodes"] = nodes
        return value

    @model_validator(mode="after")
    def references(self):
        ids = {n.id for n in self.nodes}
        if len(ids) != len(self.nodes) or len(set(self.final_goal)) != len(self.final_goal):
            raise ValueError("duplicate node or goal")
        all_ids = ids | set(self.final_goal)
        if any(e.src not in ids or e.dst not in all_ids for e in self.edges):
            raise ValueError("unknown graph reference")
        return self


class Result(Contract):
    node_id: str
    结果: Literal["通过", "不通过", "未知"]


class PlannerInput(Contract):
    graph: Graph
    previous_results: list[Result]
    last_result: Result | None

    @model_validator(mode="after")
    def results_match_graph(self):
        ids = {n.id for n in self.graph.nodes} | set(self.graph.final_goal)
        results = {r.node_id: r for r in self.previous_results}
        if len(results) != len(self.previous_results) or not results.keys() <= ids:
            raise ValueError("duplicate or unknown result")
        if self.last_result is not None and results.get(self.last_result.node_id) != self.last_result:
            raise ValueError("last_result must match previous_results")
        return self


class PlannerDecision(Contract):
    why: str = Field(min_length=1)
    status: Literal["continue", "finish"]
    next_node_id: str | None

    @model_validator(mode="after")
    def nonblank_reason(self):
        if not self.why.strip():
            raise ValueError("why cannot be blank")
        if self.status == "finish" and self.next_node_id is not None:
            raise ValueError("finish requires next_node_id=null")
        if self.status == "continue" and (self.next_node_id is None or not self.next_node_id.strip()):
            raise ValueError("continue requires a nonblank action id")
        return self
