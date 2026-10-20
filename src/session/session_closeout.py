"""One post-action closeout entry, using official checkpoints for no-replay.

The registry connection belongs to the caller and must be committed as in
SessionRegistry's contract. Ports/receiver/payload are supplied by the owner;
neither Planner nor Pre participates in migration.
"""

from hashlib import sha256
import json
from typing import Annotated, Literal, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.errors import GraphInterrupt
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, ConfigDict, Field

from .execution_session import Nonempty, SessionRecord, SessionReference, SessionRegistration
from .planner_service import saved_state, update_run
from .session_migration import (AuthorizedConnectionEntry, CloseoutFailure,
                                RemoteCommandEntry, SessionMigration, CallbackPayload)
from .session_registry import SessionConflict, SessionRegistry


class UnifiedChannel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["unified"] = "unified"
    reference: SessionReference


class CloseoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    run_id: Nonempty
    operation_id: Nonempty
    host: Nonempty
    privilege: Nonempty
    identity_aliases: list[Nonempty] = Field(default_factory=list)
    #: The address the console reported for the claimed session, when it reported one.
    observed_address: str | None = None
    source_node_id: Nonempty
    source_attempt: int = Field(ge=1, strict=True)
    # Post attempt ids may be UUIDs; the registry's source_attempt is an ordinal.
    source_attempt_id: Nonempty
    child_id: str | None = None
    source_type: Nonempty = "unknown"
    source_provider: Nonempty | None = None
    source_reference: SessionReference | None = None
    channel: Annotated[UnifiedChannel | RemoteCommandEntry | AuthorizedConnectionEntry,
                       Field(discriminator="kind")]


class CloseoutState(TypedDict):
    request: dict
    migration_settings: dict | None
    reference: dict | None
    failure: str | None
    operationKey: str
    phase: str
    transitions: list
    destination_proof: dict | None
    postPassed: bool
    sessionReady: bool
    nodeComplete: bool
    migration_payload: dict | None


class DestinationProof(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    reference: SessionReference
    provider: Nonempty
    host: Nonempty
    privilege: Nonempty
    alive: bool
    managed: bool


class SessionCloseout:
    def __init__(self, store, registry: SessionRegistry, *, migration: SessionMigration | None = None,
                 verify_destination=None):
        self.store, self.registry, self.migration = store, registry, migration
        self.verify_destination = verify_destination

    @staticmethod
    def config_for(request: CloseoutRequest):
        key = sha256(json.dumps([request.run_id, request.operation_id]).encode()).hexdigest()
        return {"configurable": {"thread_id": "session-closeout:" + key},
                "metadata": {"agv_kind": "session-closeout"}}

    @staticmethod
    def _registration(request, reference):
        return SessionRegistration(**reference, **request.model_dump(exclude={
            "channel", "source_attempt_id", "child_id", "source_type", "source_provider", "source_reference",
            "identity_aliases"}))

    def _graph(self, saver):
        def intent(state):
            request = CloseoutRequest.model_validate(state["request"])
            adopt = isinstance(request.channel, UnifiedChannel)
            phase = "adopt" if adopt else "pending_migration"
            failure = None
            if not adopt:
                if self.migration is None:
                    failure = "migration_not_configured"
                elif not self.migration.supports(request.source_type):
                    failure = "migration_recipe_missing"
            return {"reference": request.channel.reference.model_dump() if adopt else None,
                    "failure": failure, "phase": phase, "transitions": [*state["transitions"], phase]}

        def migrating(state):
            request = CloseoutRequest.model_validate(state["request"])
            try:
                payload = self.migration.prepare(request).model_dump()
            except GraphInterrupt:
                raise
            except Exception as exc:
                return {"failure": exc.code if isinstance(exc, CloseoutFailure) else "migration_preparation_failed",
                        "phase": "pending_migration"}
            return {"phase": "migrating", "transitions": [*state["transitions"], "migrating"],
                    "migration_payload": payload}

        def migrate(state):
            request = CloseoutRequest.model_validate(state["request"])
            try:
                entry = request.channel.model_copy(update={"reference": request.source_reference,
                                                           "provider": request.source_provider})
                reference = self.migration.migrate(entry, run_id=request.run_id,
                    operation_id=request.operation_id, host=request.host, privilege=request.privilege,
                    payload=CallbackPayload.model_validate(state["migration_payload"]))
                return {"reference": reference.model_dump(), "phase": "destination_identified",
                        "transitions": [*state["transitions"], "destination_identified"]}
            except CloseoutFailure as exc:
                return {"failure": exc.code, "phase": "reconciling",
                        "transitions": [*state["transitions"], "reconciling"]}

        def verify(state):
            request = CloseoutRequest.model_validate(state["request"])
            try:
                if self.verify_destination is None:
                    raise CloseoutFailure("destination_verifier_missing")
                proof = DestinationProof.model_validate(self.verify_destination(
                    request, SessionReference.model_validate(state["reference"])))
            except GraphInterrupt:
                raise
            except Exception as exc:
                return {"failure": exc.code if isinstance(exc, CloseoutFailure) else "destination_verification_failed",
                        "phase": "reconciling", "transitions": [*state["transitions"], "reconciling"]}
            if (proof.reference.model_dump() != state["reference"] or proof.provider != "console"
                    or proof.host != request.host
                    or proof.privilege not in {request.privilege, *request.identity_aliases}
                    or not proof.alive or not proof.managed):
                return {"failure": "destination_verification_failed", "phase": "destination_identified"}
            return {"destination_proof": proof.model_dump(), "sessionReady": True, "failure": None,
                    "phase": "destination_verified",
                    "transitions": [*state["transitions"], "destination_verified", "registration_pending"]}

        graph = StateGraph(CloseoutState)
        graph.add_node("intent", intent)
        graph.add_node("migrate", migrate)
        graph.add_node("migrating", migrating)
        graph.add_node("verify", verify)
        graph.add_edge(START, "intent")
        graph.add_conditional_edges("intent", lambda s: END if s["failure"] else
                                    "verify" if s["reference"] else "migrating")
        graph.add_conditional_edges("migrating", lambda s: END if s["failure"] else "migrate")
        graph.add_conditional_edges("migrate", lambda s: END if s["failure"] else "verify")
        graph.add_edge("verify", END)
        return graph.compile(checkpointer=saver)

    def finish(self, post_state: dict, request: CloseoutRequest) -> SessionRecord:
        request = CloseoutRequest.model_validate(request)
        post = post_state.get("state", post_state)
        result, context = post.get("result") or {}, post.get("context") or {}
        if result.get("status") != "completed" or result.get("result") != "通过":
            raise CloseoutFailure("post_not_passed")
        if context.get("proposition") != "channel_liveness":
            raise CloseoutFailure("post_channel_not_verified")
        if request.source_type == "unknown":
            raise CloseoutFailure("candidate_type_unknown")
        if request.source_provider is None or request.source_reference is None:
            raise CloseoutFailure("candidate_reference_missing")
        if isinstance(request.channel, UnifiedChannel) and (
                request.channel.reference != request.source_reference or request.source_provider != "console"):
            raise CloseoutFailure("candidate_reference_mismatch")
        candidate = context.get("carrier_export")
        if not candidate:
            raise CloseoutFailure("post_source_unverified")
        if (candidate.get("reference") != request.source_reference.model_dump()
                or candidate["carrier"]["owner"] != request.source_provider
                or candidate["carrier"]["kind"] != request.source_type
                or candidate["carrier"]["target_host"] != request.host
                or candidate.get("channel") != request.channel.model_dump()
                or candidate.get("identity_aliases", []) != request.identity_aliases
                or candidate["privilege"] != request.privilege):
            raise CloseoutFailure("post_source_mismatch")
        if context.get("child_id") is not None and context["child_id"] != request.child_id:
            raise CloseoutFailure("post_source_mismatch")
        if (str(context.get("run_id")), str(context.get("node", {}).get("id")),
                context.get("target_host"), str(context.get("attempt_id"))) != (
                request.run_id, request.source_node_id, request.host, request.source_attempt_id):
            raise CloseoutFailure("post_source_mismatch")
        config = self.config_for(request)
        settings = (self.migration.settings.model_dump(mode="json") if self.migration is not None
                    and not isinstance(request.channel, UnifiedChannel) else None)
        with self.store.lock(config["configurable"]["thread_id"]), self.store.checkpointer() as saver:
            graph = self._graph(saver)
            snapshot = graph.get_state(config)
            state = saved_state(snapshot)
            if state:
                if CloseoutRequest.model_validate(state["request"]).model_dump() != request.model_dump():
                    raise SessionConflict("Closeout operation has different input")
                # Apply pending writes before deciding whether IO might have happened.
                if any(isinstance(task.result, dict) for task in snapshot.tasks):
                    update_run(graph, config, snapshot, {})
                    snapshot = graph.get_state(config)
                    state = saved_state(snapshot)
                if state.get("reference") and state.get("failure") and state.get("phase") == "reconciling":
                    graph.update_state(config, {"failure": None, "phase": "destination_identified",
                        "transitions": [*state["transitions"], "destination_identified"]}, as_node="migrate")
                elif (state.get("phase") == "pending_migration" and not state.get("migration_payload")
                        and state.get("failure") in {"migration_not_configured", "migration_recipe_missing"}
                        and self.migration is not None and self.migration.supports(request.source_type)):
                    graph.update_state(config, {"failure": None, "migration_settings": settings}, as_node="intent")
                elif "migrate" in snapshot.next:
                    graph.update_state(config, {"failure": "migration_unconfirmed_after_resume", "phase": "reconciling"},
                                       as_node="migrate")
                elif set(snapshot.next) & {"intent", "migrating"} and settings != state["migration_settings"]:
                    raise SessionConflict("Migration settings changed")
                if graph.get_state(config).next:
                    graph.invoke(None, config, durability="sync")
            else:
                graph.invoke({"request": request.model_dump(), "migration_settings": settings,
                    "reference": None, "failure": None, "operationKey": config["configurable"]["thread_id"],
                    "phase": "post_verified", "transitions": ["produced", "post_verified"],
                    "destination_proof": None, "postPassed": True, "sessionReady": False,
                    "nodeComplete": False, "migration_payload": None}, config, durability="sync")
            state = saved_state(graph.get_state(config))
            if (state["failure"] and not state.get("reference")
                    and state.get("phase") == "reconciling" and self.migration):
                reference = self.migration.reconcile(request)
                if reference is not None:
                    graph.update_state(config, {"reference": reference.model_dump(), "failure": None,
                        "phase": "destination_identified",
                        "transitions": [*state["transitions"], "destination_identified"]}, as_node="migrate")
                    graph.invoke(None, config, durability="sync")
                    state = saved_state(graph.get_state(config))
            if state["failure"]:
                raise CloseoutFailure(state["failure"])
            # Reuse the registry's single idempotency path, including after a
            # caller transaction rollback. Do not cache lifecycle or timestamp.
            if not state.get("destination_proof") or not state.get("sessionReady"):
                raise CloseoutFailure("destination_not_verified")
            # Registration is deliberately outside the migration graph. A failed
            # transaction leaves the exact destination and proof available for retry.
            if state["phase"] != "registered":
                graph.update_state(config, {"phase": "registration_pending"}, as_node="verify")
            # A migrated destination may share the logical run/host/privilege key with the
            # transient source carrier. The registry closes that exact source only when the
            # active-key insert collides, so a different active row is still a conflict.
            supersedes = (request.source_reference
                          if not isinstance(request.channel, UnifiedChannel) else None)
            try:
                record = self.registry.register_exact(
                    self._registration(request, state["reference"]), supersedes=supersedes)
            except UniqueViolation:
                # A second graph path can demand a fact this run already carries (node 19
                # demands execCode(pc1,system) after node 7 registered it). That is
                # satisfaction, not a conflict: reuse the registered session and point this
                # closeout at it, so the confirmation compares equal references.
                existing = self.registry.find(request.run_id, request.host, request.privilege)
                if existing is None or existing.status != "active":
                    raise
                graph.update_state(config, {"reference": existing.reference().model_dump(),
                                            "phase": "registered"}, as_node="verify")
                return existing
            return record

    def confirm_registration(self, request, record):
        """The caller acknowledges its registry commit before recording completion."""
        request = CloseoutRequest.model_validate(request)
        config = self.config_for(request)
        with self.store.lock(config["configurable"]["thread_id"]), self.store.checkpointer() as saver:
            graph = self._graph(saver)
            state = saved_state(graph.get_state(config))
            if (not state.get("destination_proof") or not state.get("sessionReady")
                    or state["reference"] != record.reference().model_dump()
                    or (record.run_id, record.host, record.privilege) !=
                       (request.run_id, request.host, request.privilege)):
                raise CloseoutFailure("registration_confirmation_mismatch")
            if record.status != "active":
                raise CloseoutFailure("registered_destination_inactive")
            graph.update_state(config, {"phase": "registered", "nodeComplete": True,
                "transitions": list(dict.fromkeys([*state["transitions"], "registered"]))}, as_node="verify")

    def inspect(self, request):
        with self.store.checkpointer() as saver:
            return saved_state(self._graph(saver).get_state(self.config_for(CloseoutRequest.model_validate(request))))
