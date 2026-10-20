"""Pre task endpoints; a returned Action route does not execute an action."""

from uuid import UUID
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict

from src.agents.pre_verifier.context import HostEnvironment
from .execution_session import ExecutionBinding

router = APIRouter(prefix="/pre/runs", tags=["Pre"])


class CreatePre(BaseModel):
    model_config = ConfigDict(extra="forbid")
    graph: dict
    node_id: str
    environment: dict[str, HostEnvironment] | None = None
    execution: ExecutionBinding | None = None
    run_id: UUID | None = None


class ResumePre(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm_environment: bool = False


@router.post("", status_code=201)
def create(body: CreatePre, request: Request):
    try:
        return request.app.state.pre_service.create(body.graph, body.node_id,
            environment={k: v.model_dump(exclude_none=True) for k, v in body.environment.items()} if body.environment else None,
            execution=body.execution.model_dump() if body.execution else None,
            run_id=str(body.run_id) if body.run_id else None)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(422, detail="Invalid graph node or Pre environment input") from exc


@router.get("")
def list_runs(request: Request, limit: int = Query(50, ge=1, le=100)):
    return request.app.state.pre_service.list(limit)


@router.get("/{run_id}")
def inspect(run_id: UUID, request: Request):
    return request.app.state.pre_service.inspect(str(run_id))


@router.post("/{run_id}/resume")
def resume(run_id: UUID, request: Request, body: ResumePre | None = None):
    return request.app.state.pre_service.resume(str(run_id), confirm_environment=body.confirm_environment if body else False)
