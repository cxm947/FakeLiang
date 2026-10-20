"""Action task endpoints; creating a task never dispatches its command."""

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict

from src.agents.executor.schema import ActionObservation

router = APIRouter(prefix="/action/runs", tags=["Action"])


class CreateAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    graph: dict
    node_id: str
    execution: dict | None = None
    thread_id: UUID | None = None


class ResumeAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observation: ActionObservation | None = None
    confirm_environment: bool = False


@router.post("", status_code=201)
def create(body: CreateAction, request: Request):
    try:
        return request.app.state.action_service.create(body.graph, body.node_id,
            execution=body.execution, thread_id=str(body.thread_id) if body.thread_id else None)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(422, detail="Invalid graph node or Action execution input") from exc


@router.get("")
def list_runs(request: Request, limit: int = Query(50, ge=1, le=100)):
    return request.app.state.action_service.list(limit)


@router.get("/{thread_id}")
def inspect(thread_id: UUID, request: Request):
    return request.app.state.action_service.inspect(str(thread_id))


@router.post("/{thread_id}/resume")
def resume(thread_id: UUID, request: Request, body: ResumeAction | None = None):
    try:
        return request.app.state.action_service.resume(str(thread_id),
            observation=body.observation.model_dump() if body and body.observation is not None else None,
            confirm_environment=body.confirm_environment if body else False)
    except ValueError as exc:
        raise HTTPException(422, detail="Invalid Action reconciliation input") from exc
