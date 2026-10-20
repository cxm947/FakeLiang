"""Post task endpoints; creation persists references and does not observe."""

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict

from src.agents.executor.schema import Observation

router = APIRouter(prefix="/post/runs", tags=["Post"])


class CreatePost(BaseModel):
    model_config = ConfigDict(extra="forbid")
    graph: dict
    node_id: str
    action_state: dict | None = None
    carrier_inventory: dict | None = None
    current_carrier_ref: str | None = None
    no_carrier_reason: str | None = None
    proposition: str | None = None
    environment: dict | None = None
    run_id: str | None = None
    attempt_id: str | None = None
    thread_id: UUID | None = None


class ResumePost(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observation: Observation | None = None


@router.post("", status_code=201)
def create(body: CreatePost, request: Request):
    try:
        options = body.model_dump(exclude={"graph", "node_id", "thread_id"})
        return request.app.state.post_service.create(body.graph, body.node_id,
            thread_id=str(body.thread_id) if body.thread_id else None, **options)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(422, detail="Invalid graph node or Post handoff input") from exc


@router.get("")
def list_runs(request: Request, limit: int = Query(50, ge=1, le=100)):
    return request.app.state.post_service.list(limit)


@router.get("/{thread_id}")
def inspect(thread_id: UUID, request: Request):
    return request.app.state.post_service.inspect(str(thread_id))


@router.post("/{thread_id}/resume")
def resume(thread_id: UUID, request: Request, body: ResumePost | None = None):
    try:
        return request.app.state.post_service.resume(str(thread_id),
            observation=body.observation.model_dump() if body and body.observation is not None else None)
    except ValueError as exc:
        raise HTTPException(422, detail="Invalid Post reconciliation input") from exc
