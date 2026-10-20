"""Extract one action's direct LEAFs without reconstructing the source TXT."""

from copy import deepcopy
from hashlib import sha256
import ipaddress
import json
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from src.session.execution_session import ExecutionBinding


class HostEnvironment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    platform: Literal["linux", "windows"] | None = None
    access: str | None = None  # existing connection description/alias, never a password
    identity: str | None = None
    container_map: dict[str, str] = Field(default_factory=dict)

REQUIREMENTS = {
    "hacl": ("source_host", "protocol", "port"),
    "networkServiceInfo": ("host", "service", "protocol", "port"),
    "pathExists": ("host", "path", "writable", "perm"),
    "isFirewall": ("host", "state"),
    "isDocker": ("host", "docker"),
}
QUERIES = {
    "hacl": "hacl ping ICMP 网络可达",
    "networkServiceInfo": "networkServiceInfo service presence 服务存在",
    "pathExists": "pathExists path exists writable write 路径存在 可写",
    "isFirewall": "isFirewall firewall state 防火墙 状态",
    "isDocker": "isDocker container relation exists 容器 关系 存在",
}
ASSUMED = {"hasAccount", "attackerLocated"}
EXCLUDED = {"ttpExists"}
ACTION_FIELDS = ("id", "type", "description", "rule_desc", "attack_id", "host", "service", "protocol", "port")


def build_context(graph, node_id, environment=None, *, execution=None):
    """Freeze input; neither credentials nor unrelated graph nodes enter the LLM."""
    environment = dict(environment or {})
    # Deployment files are a flat name -> execution-point path map, not a host record; the
    # runtime merges them into the same environment document the Action stage reads. Keeping
    # them here would make `materials` validate as a host and fail every node whose card
    # consumes a pushed file (live 2026-10-18, node 28: HostEnvironment rejected `poc_path`).
    materials = deepcopy(environment.pop("materials", {}) or {})
    handover = {name: deepcopy(value) for name, value in environment.items()
                if name.startswith("delivery") or name == "must_deliver_session"}
    for name in handover:
        environment.pop(name, None)
    environment = {name: HostEnvironment.model_validate(value).model_dump(exclude_none=True)
                   for name, value in environment.items()}
    binding = (ExecutionBinding.model_validate(execution).model_dump(exclude_none=True)
               if execution is not None else None)
    if binding:
        environment[binding["host"]] = {**environment.get(binding["host"], {}),
            "platform": binding["platform"], "identity": binding["identity"],
            "access": "session:" + binding["session"]["session_id"]}
    nodes = graph["nodes"]
    ids = [n["id"] for n in nodes]
    if len(ids) != len(set(ids)) or node_id not in ids or node_id in graph["final_goal"]:
        raise ValueError("Expected a unique action node id")
    action = next(n for n in nodes if n["id"] == node_id)
    hosts = {h["host"]: h["ips"] for h in graph["hosts"]}
    if len(hosts) != len(graph["hosts"]):
        raise ValueError("Duplicate host mapping")
    facts, seen = [], set()
    for parent in action["dependencies"]["parents"]:
        if parent["type"] != "LEAF":
            continue
        fid = parent["id"]
        if not isinstance(fid, str) or fid in seen:
            raise ValueError("Duplicate or invalid direct LEAF id")
        seen.add(fid)
        predicate = parent["description"].partition("(")[0].strip()
        policy = ("assumed" if predicate in ASSUMED else "excluded" if predicate in EXCLUDED
                  else "check" if predicate in REQUIREMENTS else "unsupported")
        # The bound session already runs inside the container named by the fact. The
        # container relation is verified by the Action's local check; Pre does not need a
        # second connection to the host (live 2026-10-17: node 22 Pre refused with
        # "missing access to web2" while the binding was web2_docker).
        if (predicate == "isDocker" and binding is not None
                and binding["host"] == parent.get("docker")):
            policy = "assumed"
        # Accounts are assumed, so their credential-bearing description is never copied.
        fact = {"id": fid, "predicate": predicate, "policy": policy}
        if policy == "check":
            missing = [k for k in REQUIREMENTS[predicate] if parent.get(k) in (None, "")]
            if predicate == "hacl" and not (parent.get("target_host") or parent.get("host")):
                missing.append("target_host")
            if missing:
                raise ValueError(f"LEAF {fid} lacks fields: {', '.join(missing)}")
            fact["parameters"] = {k: deepcopy(v) for k, v in parent.items()
                                  if k not in {"credential", "id", "type", "description"}}
            fact["description"] = parent["description"]
            # `isDocker(host, container)` names the container in `docker`; it is a real
            # host the leaf must resolve, not display data.
            names = {parent[k] for k in ("host", "source_host", "target_host", "docker")
                     if parent.get(k)}
            fact["hosts"] = {}
            for name in sorted(names):
                ips = hosts.get(name)
                if not ips:
                    raise ValueError(f"Missing address for host {name}")
                for address in ips:
                    ipaddress.ip_address(address)
                fact["hosts"][name] = {"ips": list(ips), **environment.get(name, {})}
            target = parent.get("target_host", parent.get("host"))
            fact["platform"] = environment.get(target, {}).get("platform")
            # Query from the leaf's real parameters, not a fixed phrase; the hardcoded map
            # remains only as a fallback when a predicate has no parameters at all.
            values = [fact["parameters"].get(key) for key in
                      ("service", "protocol", "port", "writable", "path", "perm",
                       "state", "docker")]
            values.append(fact["parameters"].get("target_host")
                          or fact["parameters"].get("host"))
            terms = [predicate, *values, fact["platform"]]
            if not any(value not in (None, "") for value in values):
                terms.append(QUERIES.get(predicate))
            fact["query"] = " ".join(str(value) for value in terms
                                     if value not in (None, ""))
            if predicate == "pathExists" and parent["writable"] != "write":
                fact["policy"] = "unsupported"
        facts.append(fact)
    return {"node": {k: deepcopy(action[k]) for k in ACTION_FIELDS if k in action},
            "graph_hash": sha256(json.dumps(graph, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
            "leaves": facts, "execution_origin": binding["via"] if binding else "kali",
            "materials": materials,
            **({"execution": binding} if binding else {})}


def needs_target_access(leaf):
    return (leaf["predicate"] in {"pathExists", "isFirewall", "isDocker"}
            or leaf["predicate"] == "networkServiceInfo" and leaf["parameters"].get("protocol") == "local")
