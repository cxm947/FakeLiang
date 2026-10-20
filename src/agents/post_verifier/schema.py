"""Post contracts: serializable access references, observations and conclusions."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.agents.executor.schema import Observation
from src.agents.pre_verifier.schema import StageExecutionRequest

#: Post's generate phase speaks the same ``{tool, target, arguments}`` contract as Pre.
ExecutionRequest = StageExecutionRequest


from src.session.carrier import CarrierReference


class Assessment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    node_id: str = Field(min_length=1)
    result: Literal["通过", "不通过", "未知"]
    reason: str = Field(min_length=1)


class EvidencePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    mode: Literal["live_observation", "evidence_review"] = "live_observation"
    require_nonce: bool = True

    @model_validator(mode="after")
    def review_is_not_fresh(self):
        if self.mode == "evidence_review" and self.require_nonce:
            raise ValueError("Evidence review cannot claim a fresh nonce observation")
        return self


__all__ = ["CarrierReference", "Assessment", "EvidencePolicy", "ExecutionRequest", "Observation"]
