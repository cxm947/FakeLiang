"""Live composition of the existing services. Construction performs no remote IO.

The deployment supplies its channel owner and receiver factory; the repository
does not implement that external session system. See docs/pipeline.md for the
small factory contract. Neither model output nor a VM login creates a session.
"""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
import json
from pathlib import Path
import traceback

import psycopg
from pydantic import BaseModel, ConfigDict, Field
import yaml

from run_action import RecordedModel, save
from run_post import load_factory
from src.agents._model.client import create_chat_model, load_model_config
from src.agents.pre_verifier.mcp_client import KaliMCP, load_mcp_config
from src.agents.pre_verifier.schema import ExecutionRequest
from src.agents.executor.tool_contracts import CONTROL_SIDE_TOOLS
from src.agents.pre_verifier.vmware_guest import VMwareGuest
from src.session.action_service import ActionService
from src.session.carrier import CarrierExport
from src.session.execution_session import ExecutionBinding, SessionRegistration
from src.session.pipeline_service import PipelineFailure, PipelineInput, PipelineService
from src.session.planner_service import PlannerService
from src.session.planner_store import PlannerStore
from src.session.post_service import PostService
from src.session.pre_service import PreService
from src.session.session_closeout import SessionCloseout
from src.session.session_migration import CallbackPayload, MigrationSettings, PortPool, SessionMigration
from src.session.session_registry import SessionRegistry
from src.graph.predicates import parse_parameters
from src.session.tunnel_registry import TunnelRegistry
from src.session.tunnel_service import TunnelService
from src.session.tunnel_system import LinuxSocatOwner
from deployment.materials import MaterialSpec, push as push_materials
from .pipeline_evidence import PipelineEvidence
from .pipeline_lab import validate_lab


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


class LiveConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request: Path
    initial_sessions: Path
    bindings: Path = Path("configs/vmware-lab.local.json")
    lab: Path = Path("configs/action-lab.local.json")
    storage: Path = Path("configs/storage.local.yaml")
    model: Path = Path("configs/model.yaml")
    mcp: Path = Path("configs/pre-mcp.local.yaml")
    owner_factory: str = Field(min_length=3)
    receiver_factory: str = Field(min_length=3)
    owner_options: dict = Field(default_factory=dict)
    #: Optional controller endpoint bring-up, run right after the rollback:
    #: {"vm", "command", "address", "port", "ready_timeout"?}
    console: dict | None = None
    #: Deployment files pushed to the execution point per run; each item is
    #: {"name", "source", "remote_path", "sha256"?, "mode"?}. Nothing is
    #: pre-staged on the target: a run pushes what it declares and verifies both ends.
    materials: list[dict] = Field(default_factory=list)
    migration: MigrationSettings
    port_directory: Path = Path("output/controller-ports")
    port_start: int = Field(default=42000, ge=1, le=65535)
    port_end: int = Field(default=42999, ge=1, le=65535)
    #: Optional deployment profile: VMs, CIDRs, controller paths, port pool and lab lock.
    #: The runtime refuses to start when the loaded request/lab config disagrees.
    capabilities: Path | None = None


class Transports:
    """The kali entry only. Every other node runs on its registered session.

    This class used to answer a second `vmware` surface. That surface no longer exists: an
    action either has a session or is refused, so this object only reaches the run's own
    starting point through the Kali MCP bridge.
    """

    def __init__(self, mcp):
        self.mcp = mcp

    def execute(self, binding, request):
        binding = ExecutionBinding.model_validate(binding)
        request = ExecutionRequest.model_validate(request)
        if binding.binding_kind != "controller_entry" or binding.via != "kali":
            raise PipelineFailure("会话没接上", "execution_entry_is_not_kali")
        if request.via != "kali":
            raise PipelineFailure("参数没给到", "Request changed the frozen execution entry")
        with KaliMCP(self.mcp) as gateway:
            result = gateway.execute(request.model_dump())
        from src.tools.receipt import make_receipt
        return make_receipt(confirmed=not result["is_error"], response=result)


class ActionTransports:
    """Interpret synchronous command receipts only at the Action boundary.

    The owner's asynchronous session observations bypass this adapter. Shared
    transports and BoundPre retain their existing error interpretation.
    """

    def __init__(self, transports):
        self.transports = transports

    def execute(self, binding, request):
        observation = deepcopy(self.transports.execute(binding, request))
        data = observation.get("response")
        if isinstance(data, dict) and "tool_name" in data:
            payload = data.get("response", {})
            data = payload.get("structuredContent")
            if data is None and len(payload.get("content", [])) == 1:
                try:
                    data = json.loads(payload["content"][0].get("text", ""))
                except (ValueError, TypeError):
                    pass
            if payload.get("isError"):
                data = None
        # Output alone can be partial. A command exit code plus captured output
        # confirms a terminal receipt, including a command-budget timeout.
        confirmed = (isinstance(data, dict)
            and not data.get("transport_error")
            and type(data.get("return_code")) is int
            and any(isinstance(data.get(key), str) for key in ("stdout", "stderr")))
        observation["effect_known"] = confirmed
        observation["receipt_confirmed"] = confirmed
        observation["command_succeeded"] = None
        return observation


class BoundPre:
    definitions = []

    def __init__(self, runtime, state):
        self.runtime, self.state = runtime, state
        self.binding = runtime.binding(state)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def execute(self, request):
        return self.runtime.record_execution("pre", request, lambda:
            self._execute(request))

    def _execute(self, request):
        # Pre delivers through the same entry every stage uses: the four fields decide the
        # channel and the command line. Handing the owner's backend in lets a session-bound
        # node run its checks on that session instead of on the VMware guest -- without it,
        # node 2's check for the pc1 premise ran on the guest (live 2026-10-17 run
        # pipeline-live-20261017-05/rounds/008, where the command surfaced as a staged .ps1).
        from deployment.request_dispatch import deliver

        # Call the legacy attribute so doubles that override it keep working; the new
        # name is the same function object and remains the documented entry point.
        self.runtime.check_session(self.binding)
        observation = deliver(self.binding, request,
                              backend=getattr(self.runtime.owner, "backend", None),
                              transports=self.runtime.transports)
        return {"is_error": not observation["effect_known"], "response": observation["response"]}


class MigrationAdapter:
    """Connect the existing migration protocol to deployment-owned resources."""

    def __init__(self, owner, receiver_factory):
        self.owner, self.receiver_factory = owner, receiver_factory

    def reserve_receiver(self, payload):
        return self.receiver_factory(payload=payload, owner=self.owner)

    def deliver(self, entry, payload, *, timeout):
        return self.owner.deliver(entry, payload, timeout=timeout)

    def lookup_migration(self, *, run_id, operation_id):
        lookup = getattr(self.owner, "lookup_migration", None)
        return lookup(run_id=run_id, operation_id=operation_id) if callable(lookup) else []


class LiveRuntime:
    def __init__(self, path, directory, *, initial_sessions=None):
        self.config = LiveConfig.model_validate(read_json(path))
        config = self.config
        self.directory = Path(directory)
        self.request = PipelineInput.model_validate(read_json(config.request)).model_dump()
        self.initial_sessions = (read_json(config.initial_sessions) if initial_sessions is None
                                 else deepcopy(initial_sessions))
        if not isinstance(self.initial_sessions, list) or (initial_sessions is None and not self.initial_sessions):
            raise ValueError("initial_sessions must contain real owner references")
        for row in self.initial_sessions:
            if "run_id" in row:
                raise ValueError("Initial sessions are registered under this run; omit run_id")
            SessionRegistration.model_validate({**row, "run_id": "validation"})
        self.lab = read_json(config.lab)
        self.guest = VMwareGuest(self.lab["guest_config"])
        validate_lab(self.guest, self.lab["snapshots"])
        if config.capabilities is not None:
            from .deployment_capabilities import (DeploymentCapabilities,
                                                  validate_deployment_capabilities)
            profile = DeploymentCapabilities.model_validate(read_json(config.capabilities))
            validate_deployment_capabilities(
                profile, request=self.request, lab=self.lab,
                materials=config.materials, owner_options=config.owner_options,
                port_start=config.port_start, port_end=config.port_end)
        self.bindings = read_json(config.bindings)["bindings"]
        for binding in self.bindings.values():
            if binding["platform"] != self.guest.platform(binding["vm"]):
                raise ValueError("Binding platform differs from guest profile")
        # Pre/Post cards are selected by the *target* platform, not only by the execution
        # entry. The graph's host map carries addresses; the deployment bindings carry the
        # platform. Merge them once so a Windows target selects the Windows card even when
        # the check is issued from a Linux session (and vice versa).
        self.request["environment"] = {
            **self.request.get("environment", {}),
            **{host: {**self.request.get("environment", {}).get(host, {}),
                      "platform": binding["platform"]}
               for host, binding in self.bindings.items()},
        }
        self.model_config = load_model_config(config.model)
        self.transports = Transports(load_mcp_config(config.mcp))
        url = yaml.safe_load(config.storage.read_text(encoding="utf-8"))["database_url"]
        if not url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise ValueError("Live mode requires PostgreSQL")
        self.store = PlannerStore(url)
        self.ports = PortPool(config.port_directory, config.port_start, config.port_end)
        self._deliveries: dict[str, dict] = {}
        # Resolve missing deployment modules before DB connection or lab rollback.
        self.owner_factory = load_factory(config.owner_factory)
        self.receiver_factory = load_factory(config.receiver_factory)
        validate_owner = getattr(self.owner_factory, "validate_options", None)
        if validate_owner is not None:
            validate_owner(config.owner_options)
        # Declared materials are validated (source readable, digest correct)
        # before any rollback, so a bad deployment binding fails fast.
        for item in config.materials:
            MaterialSpec.model_validate(item).digest()

    def entry_binding(self):
        """The declared controller entry, used only to reach the execution point."""
        rows = [SessionRegistration.model_validate({**row, "run_id": "resolve"})
                for row in self.initial_sessions]
        entry = next((row for row in rows if row.binding_kind == "controller_entry"), None)
        if entry is None:
            return None
        declaration = (self.config.owner_options.get("entries") or {}).get(entry.session_id)
        if not isinstance(declaration, dict):
            raise PipelineFailure("参数没给到", "materials_entry_not_declared")
        return {"session": {"session_id": entry.session_id, "instance_id": entry.instance_id,
                            "generation": entry.generation},
                "via": declaration.get("via", "kali"), "host": declaration.get("host"),
                "identity": declaration.get("privilege"), "platform": "linux",
                "binding_kind": "controller_entry", "tunnel_endpoints": []}

    def push_materials(self, directory):
        """Push the declared deployment files and expose their execution-point paths."""
        specs = [MaterialSpec.model_validate(item) for item in self.config.materials]
        if not specs:
            return {}
        binding = self.entry_binding()
        if binding is None:
            raise PipelineFailure("参数没给到", "materials_entry_not_declared")
        resolved = push_materials(self.transports, binding, specs, directory=Path(directory))
        self.request["environment"] = {**self.request.get("environment", {}),
                                       "materials": deepcopy(resolved)}
        return resolved

    def delivery(self, document, node_id, record, execution=None):
        """Reserve this run's receiver and hand its two commands to the Action.

        Only a node whose graph output demands a session gets a hand-over. The recipe is
        the selected Action card's own ``entry_setup``; there is no service-to-card table,
        so a new method is added by writing a card, not by editing deployment code. A card
        without an ``entry_setup`` uses the runtime-owned listener/artifact hand-over.
        The baseline is frozen here so the later claim can never mistake an older session
        for this attempt's.
        """
        node = next((item for item in document["nodes"] if str(item["id"]) == str(node_id)), None)
        facts = [child for child in (node or {}).get("dependencies", {}).get("children", [])
                 if str(child.get("description") or "").startswith("execCode(")]
        if node is None or not facts:
            return {}
        parameters = parse_parameters(facts[0]["description"])
        # The same deterministic selection the Action stage performs: predicate hard
        # filter, platform/carrier, then BM25. The card body and its ``entry_setup`` stay
        # one artifact, so the model and the runtime cannot disagree about the method.
        from src.agents.executor.retrieval import predicate_key, query_text
        children = node.get("dependencies", {}).get("children", [])
        selected = self.service.action.index.retrieve(
            query_text(node, children, execution),
            platform=(execution or {}).get("platform"),
            predicate=predicate_key(node, children),
            carrier=(execution or {}).get("carrier"),
            limit=1)
        card = selected[0] if selected else {}
        card_name = str(card.get("name") or "")
        # The card states where this node's channel comes from. This is a property of the
        # method, not of a service name: a new card changes this line only in its own
        # frontmatter. ``card`` builds the channel through its own ``entry_setup`` after
        # the Action; ``session`` uses the attempt's registered session and needs no
        # listener; ``runtime`` (also the default for older cards) asks the deployment to
        # arm the handler and build the artifact.
        handover = card.get("handover")
        if not handover:
            # Older cards predate the explicit field. Infer only from what the card
            # itself declares; a card with neither declaration uses its registered
            # session rather than silently opening a listener.
            handover = ("card" if card.get("entry_setup")
                        else "runtime" if card.get("delivery") else "session")
        handover = str(handover)
        if handover == "session":
            return {}
        if handover == "card":
            return {"delivery_mode": "card_entry"}
        try:
            self.owner.delivery_shape(card_name)
        except PipelineFailure as exc:
            # No target-side authorization recipe: the runtime arms the listener and
            # builds the artifact, and the card performs the delivery it describes.
            if exc.detail != "owner_delivery_card_missing_delivery":
                raise
            return self.card_owned_delivery(document, node, parameters)
        # The run may already hold the session this node demands: a later step then runs on
        # that registered session instead of handing over a second one (evidence: node 5
        # demands execCode(pc1,system) which node 7 had already registered, and the hand-over
        # loop left the action with nothing to do — output/pipeline-live-20261016-58/rounds/004).
        # A card-owned hand-over is different: its card still needs the runtime's artifact and
        # listener, so that path is decided above, before this shortcut (live 2026-10-18,
        # node 19: an empty delivery starved a card that expected the fetch service).
        sessions = getattr(self, "sessions", None)
        if (sessions is not None
                and sessions.find(self.run_id, parameters["host"], parameters["user"]) is not None):
            return {}
        target_port = str(node.get("port") or "")
        addresses = next((item.get("ips") or [] for item in document.get("hosts", [])
                          if item.get("host") == parameters["host"]), [])
        if not addresses:
            raise PipelineFailure("参数没给到", "delivery_target_address_missing")
        address = str(addresses[0])
        operation_id = "action:" + str(node_id)
        self.release_delivery(operation_id)
        payload = CallbackPayload(artifact_ref=self.config.migration.payload_ref,
            callback_host=self.config.migration.callback_host,
            callback_port=self.ports.allocate(), run_id=self.run_id,
            operation_id=operation_id, host=parameters["host"], privilege=parameters["user"],
            target_addresses=tuple(str(value) for value in addresses))
        plan = self.owner.reserve_action_delivery(payload, target_port=target_port, address=address)
        self._deliveries[operation_id] = plan
        try:
            inputs = self.owner.action_delivery_inputs(payload, target_port=target_port,
                                                       card_name=card_name, address=address)
        except BaseException:
            self.release_delivery(operation_id)
            raise
        return {"delivery_plan": plan, **inputs}

    def card_owned_delivery(self, document, node, parameters):
        """Prepare this run's listener and artifact, then hand the card their values.

        The runtime owns both halves of the hand-over: it arms the handler and builds the
        stager from the same payload name and the same port. A card only states where the
        file goes and how it runs; it never names a payload and never opens a listener.
        """
        addresses = next((item.get("ips") or [] for item in document.get("hosts", [])
                          if item.get("host") == parameters["host"]), [])
        payload = CallbackPayload(artifact_ref=self.config.migration.payload_ref,
            callback_host=self.config.migration.callback_host,
            callback_port=self.ports.allocate(), run_id=self.run_id,
            operation_id="action:" + str(node["id"]), host=parameters["host"],
            privilege=parameters["user"],
            # The console reports the address, the graph keeps the name; carry both so the
            # claim can recognise this operation's own session.
            target_addresses=tuple(str(value) for value in addresses))
        # Re-entering the same attempt must not leave two reservations behind.
        self.release_delivery(payload.operation_id)
        # A container target reports its own bridge address when it calls back, so the claim
        # falls back to the frozen baseline window for those hosts (declared by the lab).
        bindings = getattr(self, "bindings", None) or {}
        container_owned = bool((bindings.get(parameters["host"]) or {}).get("container"))
        plan = self.owner.prepare_action_delivery(payload,
            target_port=str(node.get("port") or ""),
            address=str(addresses[0]) if addresses else "",
            container_owned=container_owned)
        self._deliveries[payload.operation_id] = plan
        fetch_port = self.ports.allocate()
        stager_path = str(plan["stager_path"])
        stager_name = stager_path.rsplit("/", 1)[-1]
        if "/" not in stager_path:
            raise PipelineFailure("参数没给到", "delivery_work_dir_missing")
        work_dir = stager_path.rsplit("/", 1)[0]
        return {"delivery_plan": plan, "delivery_mode": "runtime",
                "delivery_callback_host": payload.callback_host,
                "delivery_callback_port": str(payload.callback_port),
                "delivery_payload": plan["payload"],
                "delivery_artifact_format": plan["format"],
                "delivery_fetch_port": str(fetch_port),
                "delivery_artifact_url": "http://{}:{}/{}".format(
                    payload.callback_host, fetch_port, stager_name),
                "delivery_stager_path": stager_path,
                "delivery_stager_name": stager_name,
                "delivery_remote_path": plan["remote_path"],
                "delivery_work_dir": work_dir,
                "delivery_key_path": plan["key_path"],
                "delivery_public_key_path": plan["public_key_path"]}

    def release_delivery(self, operation_id):
        """Release one reserved receiver; an accepted session is never closed here."""
        plan = self._deliveries.pop(operation_id, None)
        if plan is not None and getattr(self, "owner", None) is not None:
            self.owner.stop_action_delivery(plan)

    def release_deliveries(self):
        for operation_id in list(self._deliveries):
            try:
                self.release_delivery(operation_id)
            except Exception:
                pass

    @contextmanager
    def connect(self, run_id):
        self.run_id = run_id
        # The callback port cursor is per run. The lab is rolled back for every new run,
        # so no listener from an earlier run survives; a shared cursor only exhausted the
        # declared range after a few runs.
        self.ports = PortPool(Path(self.config.port_directory) / str(run_id),
                              self.config.port_start, self.config.port_end)
        with ExitStack() as stack:
            self.store.setup()
            connection = stack.enter_context(psycopg.connect(self.store.dsn))
            self.sessions = SessionRegistry(connection)
            self.sessions.setup()
            self.sessions.commit()
            tunnel_connection = stack.enter_context(psycopg.connect(self.store.dsn, autocommit=True))
            tunnel_registry = TunnelRegistry(tunnel_connection)
            tunnel_registry.setup()
            # This factory owns live accepted channels; exiting releases controller
            # resources according to that owner's contract, not by inventing handles.
            self.owner = stack.enter_context(self.owner_factory(
                transports=self.transports, options=deepcopy(self.config.owner_options)))
            # One encrypted store per deployment; the connection is the run's registry
            # connection, and the owner resolves references at execution time only.
            from src.session.credential_store import CredentialStore
            self.credentials = CredentialStore(connection)
            self.credentials.setup()
            delivery = (self.config.owner_options or {}).get("delivery") or {}
            user = str(delivery.get("domain_user") or "").strip()
            secret = str(delivery.get("domain_password") or "")
            default_ref = ""
            if user and secret:
                default_ref = str(delivery.get("credential_ref") or "deployment-domain")
                # The graph names credential materials in the fact descriptions; the
                # deployment supplies the one secret for this lab. Seed every declared
                # reference so the model only ever handles a name.
                from src.graph.predicates import credential_candidates
                keys = set(credential_candidates(self.request.get("document", {})))
                keys.add(default_ref)
                for key in sorted(keys):
                    self.credentials.put(credential_id=key, principal=user, secret=secret,
                                         secret_type="password", source_host="deployment",
                                         source_artifact="owner_options.delivery")
                    self.credentials.mark_validated(
                        key, target="*", evidence={"source": "deployment_config"})
            self.credentials.commit()
            if hasattr(self.owner, "bind_credentials"):
                self.owner.bind_credentials(self.credentials, default_ref=default_ref)
            for name in ("check_session", "action_executor", "post_gateway", "deliver"):
                if not callable(getattr(self.owner, name, None)):
                    raise PipelineFailure("参数没给到", "Owner lacks method: " + name)
            def options(stage):
                return {"model_config": self.model_config, "model_factory": lambda:
                    RecordedModel(create_chat_model(self.model_config),
                                  self.evidence.round_directory / "models" / stage)}
            planner = PlannerService(self.store, **options("planner"))
            pre = PreService(self.store, gateway_factory=lambda state: BoundPre(self, state), **options("pre"))
            action = ActionService(self.store, execute_factory=self.action_executor, **options("action"))
            post = PostService(self.store, gateway_factory=self.post_gateway, **options("post"))
            migration = SessionMigration(MigrationAdapter(self.owner, self.receiver_factory), self.ports,
                                         self.config.migration)
            closeout = SessionCloseout(self.store, self.sessions, migration=migration,
                                      verify_destination=self.owner.verify_destination)
            tunnels = TunnelService(tunnel_registry, self.sessions, self.ports,
                                    LinuxSocatOwner(self.tunnel_execute))
            self.service = PipelineService(planner, pre, action, post, closeout, tunnels,
                                           delivery_hook=self.delivery,
                                           session_alive=lambda session_id, instance_id:
                                               bool(self.owner.backend.get_session(
                                                   session_id, instance_id=instance_id)))
            self.evidence = PipelineEvidence(self.directory, self.service)
            self.service.evidence = self.evidence
            yield self

    def seed(self, run_id):
        for row in self.initial_sessions:
            self.sessions.register(SessionRegistration(**row, run_id=run_id))
        self.sessions.commit()
        save(self.directory / "sessions" / "initial.json", [r.model_dump(mode="json")
            for r in self.sessions.list_for_run(run_id)])

    def binding(self, state):
        binding = ExecutionBinding.model_validate(state["context"]["execution"])
        self.check_session(binding)
        return binding.model_dump(exclude_none=True)

    def validate_execution_binding(self, value):
        """The binding must name a recorded instance, and the owner must still hold it."""
        binding = ExecutionBinding.model_validate(value)
        # A run's own starting entry is named by its logical identity; an execCode key is
        # an exact host/privilege lookup. Mixing the two would let either path select the
        # other kind of record.
        record = (self.sessions.find_entry(self.run_id, binding.session.session_id)
                  if binding.binding_kind == "controller_entry"
                  else self.sessions.find(self.run_id, binding.host, binding.identity))
        if record is None or record.reference() != binding.session:
            raise PipelineFailure("会话没接上", "Pinned session is missing or stale")
        # The graph names a host logically; the console reports its address. Hand the
        # frozen addresses for that name to the owner so both readings are accepted.
        aliases = [address for host in self.request["document"].get("hosts", [])
                   if host.get("host") == record.host for address in host.get("ips") or []]
        # Owner doubles and stored wrappers may still expose the old spelling; prefer the
        # current contract but never fail a run because only the legacy name exists.
        validator = (getattr(self.owner, "validate_execution_binding", None)
                     or getattr(self.owner, "check_session", None))
        if validator is None or validator(binding, host_aliases=aliases) is not True:
            raise PipelineFailure("会话没接上", "Owner did not confirm the pinned session")

    #: Legacy spelling used by stored runs and older callers.
    check_session = validate_execution_binding

    def record_execution(self, stage, request, operation):
        directory = self.evidence.round_directory / "execution" / stage
        path = directory / f"{len(list(directory.glob('*.json'))) + 1:03d}.json"
        record = {"status": "dispatching", "request": request}
        save(path, record)
        try:
            result = operation()
        except BaseException as exc:
            save(path, {**record, "status": "interrupted", "error_type": type(exc).__name__,
                        "error": str(exc), "traceback": traceback.format_exc()})
            raise
        save(path, {**record, "status": "returned", "observation": result})
        return result

    def action_executor(self, state):
        binding = self.binding(state)
        execute = self.owner.action_executor(state=deepcopy(state), transports=ActionTransports(self.transports))
        bindings = deepcopy(getattr(self, "bindings", {}))
        def freeze_identity(value):
            candidate = CarrierExport.model_validate(value)
            declared = (bindings.get(candidate.carrier.target_host) or {}).get(
                "identity_aliases", {}).get(candidate.privilege, [])
            aliases = [declared] if isinstance(declared, str) else declared
            return CarrierExport.model_validate({**candidate.model_dump(), "identity_aliases":
                list(dict.fromkeys([*candidate.identity_aliases, *aliases]))}).model_dump()

        def invoke(request):
            self.check_session(binding)
            # Control-side tools (payload build, file service, peer service) run on the
            # runtime's own side: they have no target face to freeze.
            if (request["via"] != binding["via"]
                    and request.get("tool") not in CONTROL_SIDE_TOOLS):
                raise PipelineFailure("参数没给到", "Action changed the frozen entry")
            return self.record_execution("action", request, lambda: execute(request))
        # Export is a separate workflow node, after the saved command receipt and
        # assessment. Do not run it inside record_execution's dispatch boundary.
        if callable(getattr(execute, "export_carrier", None)):
            def export_carrier(observation):
                value = execute.export_carrier(observation)
                if value is None:
                    return None
                if "carrier" in value:
                    return freeze_identity(value)
                return {child: freeze_identity(candidate) for child, candidate in value.items()}
            invoke.export_carrier = export_carrier
        return invoke

    def post_gateway(self, state):
        gateway = self.owner.post_gateway(state=deepcopy(state), transports=self.transports)
        runtime = self
        class RecordedGateway:
            def observe(self, request, context, *, operation_id, nonce):
                return runtime.record_execution("post", {"request": request, "operation_id": operation_id},
                    lambda: gateway.observe(request, context, operation_id=operation_id, nonce=nonce))

            def lookup_observation(self, operation_id):
                return gateway.lookup_observation(operation_id)
        return RecordedGateway()

    def tunnel_execute(self, reference, command):
        if not any(r.status == "active" and r.reference() == reference
                   for r in self.sessions.list_for_run(self.run_id)):
            raise PipelineFailure("会话没接上", "Tunnel session is missing or stale")
        from deployment.request_dispatch import deliver_to_reference

        def send():
            # One sender for every session write; this boundary only maps its receipt onto the
            # tunnel system's own result contract.
            result = deliver_to_reference(
                reference, command, backend=getattr(self.owner, "backend", None),
                end_marker=self.config.owner_options.get("end_marker", "agv-call-end"),
                timeout=self.config.owner_options.get("command_timeout", 60.0))
            response = result.get("response") or {}
            output = str(response.get("output") or response.get("stdout") or "")
            return {"returncode": 0 if result["effect_known"] else 1, "stdout": output,
                    "effect_known": bool(result["effect_known"])}

        return self.record_execution("tunnels", {"session": reference.model_dump(), "command": command},
            send)
