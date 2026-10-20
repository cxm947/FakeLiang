"""Local FastAPI service. Create is durable; execution is always explicit."""

from contextlib import asynccontextmanager
import os
from uuid import UUID

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from src.agents.planner.schema import PlannerInput
from .planner_store import PlannerStore, RunBusy, RunConflict
from .planner_service import PlannerService
from .pre_api import router as pre_router
from .pre_service import PreService
from .action_api import router as action_router
from .action_service import ActionService
from .post_api import router as post_router
from .post_service import PostService
from src.agents.pre_verifier.mcp_client import KaliMCP, load_mcp_config


class CreateRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: PlannerInput
    run_id: UUID | None = None
    workflow_id: UUID | None = None


class ResumeRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verified_context: PlannerInput | None = None


def create_app(service=None, *, pre_service=None, action_service=None, post_service=None):
    @asynccontextmanager
    async def lifespan(app):
        owned = service is None
        if owned:
            url = os.environ.get("AGV_DATABASE_URL")
            if not url:
                raise RuntimeError("Configure AGV_DATABASE_URL before starting the service")
            store = PlannerStore(url)
            try:
                store.setup()
                app.state.service = PlannerService(store)
                app.state.pre_service = pre_service or PreService(store,
                    gateway_factory=lambda state: KaliMCP(load_mcp_config("configs/pre-mcp.local.yaml")),
                    model_config=app.state.service.model_config)
                app.state.action_service = action_service or ActionService(store,
                    model_config=app.state.service.model_config)
                app.state.post_service = post_service or PostService(store,
                    model_config=app.state.service.model_config)
                yield
            finally:
                store.close()
        else:
            app.state.service = service
            app.state.pre_service = pre_service or PreService(service.store,
                gateway_factory=lambda state: KaliMCP(load_mcp_config("configs/pre-mcp.local.yaml")),
                model_config=service.model_config)
            app.state.action_service = action_service or ActionService(service.store,
                model_config=service.model_config)
            app.state.post_service = post_service or PostService(service.store,
                model_config=service.model_config)
            yield

    app = FastAPI(title="AGV Planner Tasks", version="1.0", lifespan=lifespan)
    app.include_router(pre_router)
    app.include_router(action_router)
    app.include_router(post_router)

    @app.exception_handler(KeyError)
    async def not_found(request, exc):
        return JSONResponse(status_code=404, content={"detail": "Task not found"})

    @app.exception_handler(RunBusy)
    @app.exception_handler(RunConflict)
    async def conflict(request, exc):
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(Exception)
    async def failure(request, exc):
        # Avoid exposing connection strings, provider response bodies or keys.
        return JSONResponse(status_code=503, content={"detail": "Operation interrupted; query task status", "type": type(exc).__name__})

    @app.post("/runs", status_code=201)
    def create(body: CreateRun, request: Request):
        return request.app.state.service.create(body.context.model_dump(),
            run_id=str(body.run_id) if body.run_id else None,
            workflow_id=str(body.workflow_id) if body.workflow_id else None)

    @app.get("/runs")
    def list_runs(request: Request, limit: int = Query(50, ge=1, le=100)):
        return request.app.state.service.list(limit)

    @app.get("/runs/{run_id}")
    def get(run_id: UUID, request: Request):
        return request.app.state.service.inspect(str(run_id))

    @app.post("/runs/{run_id}/resume")
    def resume(run_id: UUID, request: Request, body: ResumeRun | None = None):
        # ponytail: synchronous request in FastAPI's worker pool. Add a durable
        # queue only when execution moves beyond short Planner decisions.
        return request.app.state.service.resume(str(run_id),
            verified_context=body.verified_context.model_dump()
            if body and body.verified_context is not None else None)

    return app
