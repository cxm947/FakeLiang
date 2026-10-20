"""Freeze one Post proposition and its run-wide borrowed carrier inventory."""

from copy import deepcopy
from hashlib import sha256
import json

from src.agents.pre_verifier.context import HostEnvironment
from src.graph.predicates import credential_candidates
from src.session.carrier import CarrierExport, child_candidates
from src.session.execution_session import ExecutionBinding
from src.session.tunnel import TunnelEndpoint
from .schema import CarrierReference, EvidencePolicy


def predicate(fact):
    return str(fact.get("description", "")).partition("(")[0].strip()


def account_scope_hint(fact):
    """Classify local vs domain without putting host or user into the query."""
    if predicate(fact) not in {"getAccount", "hasAccount", "leakAccount",
                               "weakAccount", "execCode"}:
        return None
    user = str(fact.get("user") or "").strip()
    domain = str(fact.get("domain") or "").strip()
    host = str(fact.get("host") or "").strip().casefold()
    if domain:
        return "domain"
    if not user:
        return None
    if user.casefold() in {"root", "system"}:
        return "local"
    if "\\" in user:
        qualifier = user.split("\\", 1)[0].strip().casefold()
        return "local" if qualifier in {".", "localhost", host} else "domain"
    if "@" in user or user.casefold().startswith("domain_"):
        return "domain"
    return None


def requires_carrier(children):
    """Output requirements come from graph predicates, never skill declarations."""
    if isinstance(children, dict):
        children = children.get("dependencies", {}).get("children", [])
    return any(predicate(child) == "execCode" for child in children)


requires_executable_carrier = requires_carrier


def validate_inventory(inventory):
    result = {}
    for ref, value in (inventory or {}).items():
        carrier = CarrierReference.model_validate(value).model_dump()
        if ref != carrier["ref"]:
            raise ValueError("Carrier inventory key must match its ref")
        result[ref] = carrier
    return result


def merge_inventory(existing, additions):
    """Accumulate references without silently replacing a different resource."""
    result = validate_inventory(existing)
    for ref, carrier in validate_inventory(additions).items():
        if ref in result and result[ref] != carrier:
            raise ValueError("A carrier reference cannot be rebound; use a new reference")
        result[ref] = carrier
    return result


def _fact(fact):
    # Credential-bearing graph descriptions are not model inputs.
    value = {key: deepcopy(item) for key, item in fact.items()
             if key not in {"credential", "password", "token", "dependencies"}}
    if "credential" in fact:
        value["description"] = predicate(fact)
    value["predicate"] = predicate(fact)
    return value


def freeze_execution(value):
    """Post accepts references only, including a closed tunnel endpoint schema."""
    try:
        binding = ExecutionBinding.model_validate(value)
        endpoints = [TunnelEndpoint.model_validate(item).model_dump(mode="json")
                     for item in binding.tunnel_endpoints]
        return deepcopy({**binding.model_dump(exclude_none=True),
                         "tunnel_endpoints": endpoints})
    except (ValueError, TypeError):
        # Local import avoids the pipeline -> runner -> Post import cycle.
        from src.session.pipeline_service import PipelineFailure
        raise PipelineFailure("参数没给到", "post_execution_binding_invalid") from None


def freeze_carrier_export(value, *, reference, inventory, target, node_id, attempt_id):
    """Freeze an owner receipt without deriving a channel from the Action entry."""
    try:
        exported = CarrierExport.model_validate(value).model_dump(mode="json")
        carrier = exported["carrier"]
        if (carrier["ref"] != reference or inventory.get(reference) != carrier
                or carrier["target_host"] != target
                or carrier["source_node_id"] != str(node_id)
                or carrier["source_attempt_id"] != str(attempt_id)):
            raise ValueError("Carrier receipt does not match the handoff")
        return deepcopy(exported)
    except (ValueError, TypeError):
        from src.session.pipeline_service import PipelineFailure
        raise PipelineFailure("参数没给到", "post_execution_binding_invalid") from None


def build_context(graph, node_id, environment=None, *, action_state=None,
                  carrier_inventory=None, current_carrier_ref=None,
                  no_carrier_reason=None, proposition=None, run_id=None,
                  attempt_id=None, evidence_policy=None, child_id=None):
    ids = [str(node["id"]) for node in graph["nodes"]]
    if len(ids) != len(set(ids)) or str(node_id) not in ids:
        raise ValueError("Expected a unique graph node id")
    node = next(node for node in graph["nodes"] if str(node["id"]) == str(node_id))
    terminal = str(node_id) in {str(value) for value in graph.get("final_goal", [])}
    children = node.get("dependencies", {}).get("children", [])
    # Final OR nodes project a fact already produced by their parent action.
    # They are not new actions and cannot lose the requirement through empty children.
    outputs = [node] if terminal else children
    if child_id is not None:
        outputs = [fact for fact in outputs if str(fact["id"]) == str(child_id)]
        if len(outputs) != 1:
            raise ValueError("Unknown Post child")
    required = requires_carrier(outputs)
    proposition = proposition or ("channel_liveness" if required else "target_state")
    if proposition not in {"target_state", "channel_liveness"}:
        raise ValueError("Unsupported Post proposition")
    environment = deepcopy(environment or {})
    # Deployment files are a flat name -> path map, not a host record; they arrive in the
    # same environment document and must not be validated as one (live 2026-10-18, node 28:
    # `poc_path` was rejected as an extra HostEnvironment field).
    materials = environment.pop("materials", {}) or {}
    for name in [key for key in environment
                 if key.startswith("delivery") or key == "must_deliver_session"]:
        environment.pop(name, None)
    execution = environment.pop("post_execution", {})
    if not isinstance(execution, dict) or set(execution) - {"lab_path", "bindings_path"}:
        raise ValueError("post_execution contains unsupported configuration references")
    if any(not isinstance(value, str) for value in execution.values()):
        raise ValueError("Post execution configuration references must be paths")
    host_environment = environment.pop("hosts", environment)
    host_environment = {host: HostEnvironment.model_validate(value).model_dump(exclude_none=True)
                        for host, value in host_environment.items()}
    state = action_state or {}
    try:
        candidate_state = state
        if terminal and state.get("session_candidates"):
            candidate_state = {**state, "session_candidate": None, "session_candidates": {
                key: value for key, value in state["session_candidates"].items()
                if key in {str(f["id"]) for f in outputs}}}
        candidates = child_candidates(candidate_state, outputs if terminal else children)
    except (ValueError, TypeError):
        from src.session.pipeline_service import PipelineFailure
        raise PipelineFailure("参数没给到", "post_execution_binding_invalid") from None
    selected = candidates.get(str(outputs[0]["id"])) if len(outputs) == 1 else None
    if selected is not None:
        if not state.get("session_candidates") and current_carrier_ref is not None and current_carrier_ref != selected["carrier"]["ref"]:
            from src.session.pipeline_service import PipelineFailure
            raise PipelineFailure("参数没给到", "post_execution_binding_invalid")
        current_carrier_ref = selected["carrier"]["ref"]
    elif not required:
        current_carrier_ref = None
    inventory = validate_inventory(carrier_inventory)
    if current_carrier_ref is not None and not isinstance(current_carrier_ref, str):
        raise ValueError("current_carrier_ref must be a reference string or null")
    if current_carrier_ref is None and not no_carrier_reason:
        no_carrier_reason = ("Action 未交付图中 execCode 输出所需的执行载体" if required
                             else "图输出不包含 execCode；通过既有入口观测目标事实，无需新执行载体")
    hosts = {item["host"]: set(item.get("ips") or []) for item in graph.get("hosts", [])}

    def same_source(left, right):
        """A logical source name and its operational alias can share one address.

        The graph may name the attacker side `attacker` while the runtime binds the kali
        entry as `kali`; both are the same machine. Compare addresses when the names differ,
        so an alias is not reported as a source-binding mismatch.
        """
        left, right = str(left), str(right)
        return left == right or bool(hosts.get(left, set()) & hosts.get(right, set()))
    target = next((child.get("target_host", child.get("host")) for child in outputs
                   if child.get("target_host", child.get("host"))),
                  node.get("target_host", node.get("host")))
    if not target:
        raise ValueError("Post target host is required")
    action_node = state.get("context", {}).get("node", {}).get("id")
    if action_node is not None and str(action_node) != str(node_id) and not terminal:
        raise ValueError("Action state belongs to another node")
    bindings = {}
    if "execution" in state.get("context", {}):
        bindings["execution"] = freeze_execution(state["context"]["execution"])
    for fact in outputs:
        origin = fact.get("source_host", node.get("source_host"))
        if predicate(fact) == "netAccess" and origin and bindings.get("execution") and not same_source(
                bindings["execution"]["host"], origin):
            from src.session.pipeline_service import PipelineFailure
            raise PipelineFailure("参数没给到", "post_source_binding_mismatch")
        candidate = candidates.get(str(fact["id"]))
        binding = bindings.get("execution")
        if (candidate is not None and binding is not None
                and binding["host"] != candidate["carrier"]["target_host"]
                and candidate["carrier"]["owner"] == "console"
                and candidate.get("reference") == binding["session"]):
            from src.session.pipeline_service import PipelineFailure
            raise PipelineFailure("参数没给到", "post_source_relationship_mismatch")
    candidate = selected or (state.get("session_candidate") if len(outputs) == 1 else None)
    if proposition == "channel_liveness" and candidate is not None:
        bindings["carrier_export"] = freeze_carrier_export(candidate,
            reference=current_carrier_ref, inventory=inventory, target=target,
            node_id=action_node, attempt_id=state.get("run", {}).get("id"))
    evidence = [{"step": item.get("step"), "attempt": item.get("attempt"),
                 "observation": deepcopy(item.get("observation"))}
                for item in state.get("history", []) if item.get("observation")]
    policy = EvidencePolicy.model_validate(evidence_policy or (
        {"mode": "evidence_review", "require_nonce": False} if terminal and not required else {})).model_dump()
    platform = host_environment.get(target, {}).get("platform")
    query = " ".join(str(value) for value in (
        *[predicate(fact) for fact in outputs],
        *[fact.get("perm") for fact in outputs],
        platform,
        *[account_scope_hint(fact) for fact in outputs]) if value not in (None, ""))
    return {**bindings, "node": _fact(node), "children": [_fact(child) for child in children],
            "outputs": [_fact(child) for child in outputs], "terminal_projection": terminal,
            "upstream_node_ids": [str(parent["id"]) for parent in node.get("dependencies", {}).get("parents", [])
                                  if parent.get("type") == "AND"],
            "graph_hash": sha256(json.dumps(graph, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
            "proposition": proposition, "requires_carrier": required,
            "child_id": str(child_id) if child_id is not None else None,
            "child_bindings": {str(f["id"]): ({"context": "S", "candidate": candidates.get(str(f["id"])),
                "relationship": "privilege_change" if bindings.get("execution", {}).get("host") ==
                    f.get("target_host", f.get("host")) else "lateral_movement",
                "source": bindings.get("execution", {}).get("session")}
                if predicate(f) == "execCode" else {"context": "P", "execution": bindings.get("execution")})
                for f in outputs},
            "target_host": target, "hosts": {target: {"ips": sorted(hosts.get(target, [])),
                **host_environment.get(target, {})}},
            "materials": deepcopy(materials),
            "environment": {"hosts": host_environment, "post_execution": execution},
            "carrier_inventory": inventory, "current_carrier_ref": current_carrier_ref,
            "no_carrier_reason": no_carrier_reason if current_carrier_ref is None else None,
            "run_id": str(run_id or state.get("run", {}).get("workflow_id") or
                          state.get("run", {}).get("id") or "standalone"),
            "attempt_id": str(attempt_id or state.get("run", {}).get("id") or "1"),
            "action_result": deepcopy(state.get("result")), "action_evidence": evidence,
            "prior_post_results": deepcopy(state.get("prior_post_results", [])),
            #: Credential names only; the owner resolves the secret during a test.
            "credential_candidates": credential_candidates(graph),
            "evidence_policy": policy,
            "query": query}
