"""Closed Post probe grammar. Model text is never an unrestricted shell program."""

from copy import deepcopy
from ipaddress import ip_address
import json
import re
import shlex

from src.graph.predicates import parse_parameters


IDENTITY_STATEMENTS = ("id -un", "hostname")
#: The same two facts, said the way a Windows command interpreter says them. The probe's
#: shape follows the claimed channel's own platform (evidence: a Windows session came back
#: with an empty receipt and the hand-over was reported unavailable,
#: output/pipeline-live-20261016-50/rounds/003).
IDENTITY_STATEMENTS_WINDOWS = ("whoami", "hostname")

#: The shells a probe may name. The dispatch rules say "name the platform's own interpreter",
#: so a Windows channel's probe names `cmd` and a POSIX one `sh`/`bash`; requiring `bash`
#: everywhere made a legal probe look illegal and the runtime answered with a bare nonce echo
#: (live 2026-10-17 run pipeline-live-20261017-03/rounds/003: the model wrote `name=cmd` and the
#: probe was refused, so Post saw only the marker and judged unknown).
SHELL_NAMES = frozenset(("bash", "sh", "dash", "zsh", "cmd", "cmd.exe"))


def _is_shell(request):
    return str(request.get("name") or "").strip().lower() in SHELL_NAMES

#: The conventional local-account checks. A credential fact (`getAccount(host,user,...)`) cannot
#: be shown by reaching a port, so the closed grammar also allows asking the machine about the
#: account itself: whether it exists (and, on Windows, whether it is a domain account). Using the
#: credential is a target-side action and never part of a read-only observation.
def identity_probe(request, nonce, *, via=None, platform=None):
    """The closed liveness probe for a claimed carrier: nonce echo plus identity.

    A carrier that answers these still runs work for us and reports who it is.
    The statements are a fixed set, each exactly once, in any order.
    """
    if (not isinstance(request, dict) or set(request) != {"tool", "name", "via", "content"}
            or request["tool"] != "cmd" or not _is_shell(request)
            or not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", nonce)
            or not isinstance(request["content"], str)):
        raise ValueError("Unsupported observation request")
    if via is not None and request["via"] != via:
        raise ValueError("Unsupported observation channel")
    statements = (IDENTITY_STATEMENTS_WINDOWS if str(platform).lower() == "windows"
                  else IDENTITY_STATEMENTS)
    #: The model may name either statement set; both mean "who am I, what host". The probe is
    #: rendered for the carrier's own platform, so a POSIX request against a Windows carrier
    #: still asks Windows the two questions (evidence: output/pipeline-live-20261016-53 and
    #: …-54 both came back unexecuted for exactly that reason).
    # Either separator is accepted and the probe is re-rendered for the channel's platform: the
    # dispatch rules tell the model to write the platform's own joiner (`&` on Windows), while
    # this grammar used to split on `; ` only -- a legal Windows probe was then read as one
    # statement and refused (live 2026-10-17 run -03/rounds/003).
    parts = [part for part in re.split(r"\s*;\s*|\s+&\s+", request["content"].strip()) if part]
    known = {frozenset(IDENTITY_STATEMENTS), frozenset(IDENTITY_STATEMENTS_WINDOWS)}
    if (parts[0] != "echo AGV_POST_NONCE=" + nonce
            or len(parts[1:]) != len(set(parts[1:]))
            or frozenset(parts[1:]) not in known):
        raise ValueError("Unsupported observation grammar")
    #: A Windows command interpreter does not treat `;` as a separator: the statements must be
    #: joined with `&`, or the whole line becomes one literal echo (evidence: the same Windows
    #: carrier that accepted the probe produced no identity output).
    joiner = " & " if str(platform).lower() == "windows" else "; "
    return joiner.join(("echo AGV_POST_NONCE=" + nonce, *statements))


def tcp_probe(request, context, binding, nonce, *, via=None):
    """Validate the entire request against a frozen netAccess endpoint and entry.

    Only the separators in this exact grammar are accepted. Reconstruct the
    command from validated operands instead of forwarding model source text.
    TCP connect observes reachability, not HTTP/Redis/application correctness.

    ``via=None`` keeps the frozen entry binding check; a carrier observation runs
    on the claimed channel, so it validates the endpoint only and passes its own
    execution handle instead.
    """
    if (not isinstance(request, dict) or set(request) != {"tool", "name", "via", "content"}
            or request["tool"] != "cmd" or not _is_shell(request)
            or not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", nonce)
            or not isinstance(request["content"], str)):
        raise ValueError("Unsupported observation request")
    if via is None:
        if binding is None or binding.platform != "linux" or request["via"] != binding.via:
            raise ValueError("Unsupported observation entry")
    elif request["via"] != via:
        raise ValueError("Unsupported observation channel")
    match = tcp_probe_shape(request["content"], nonce)
    if match is None:
        raise ValueError("Unsupported observation grammar")
    budget, address, port = match.groups()
    target = context["target_host"]
    addresses = context["hosts"][target]["ips"]
    if (not isinstance(addresses, list) or address not in addresses
            or ip_address(address).is_multicast or ip_address(address).is_unspecified):
        raise ValueError("Address outside frozen target")
    if not 1 <= int(port) <= 65535:
        raise ValueError("Invalid port")
    allowed = set()
    for fact in context["outputs"]:
        if fact.get("predicate") != "netAccess":
            continue
        params = parse_parameters(fact["description"])
        # Conflicting explicit fields must not broaden the description's endpoint.
        if (any(str(fact[key]) != value for key, value in params.items() if key in fact)
                or fact.get("target_host", params["host"]) != params["host"]):
            raise ValueError("Inconsistent frozen fact")
        if params["host"] == target and params["protocol"] in {"tcp", "http", "https"}:
            allowed.add(params["port"])
    if port not in allowed:
        raise ValueError("Port outside frozen netAccess facts")
    marker = "AGV_POST_NONCE=" + nonce
    return f"echo {marker}; nc -z -w {budget} {address} {port} && echo OPEN || echo CLOSED"


def tcp_probe_shape(content, nonce):
    """The port-probe shape alone: is this request a reachability probe at all?

    Kept separate from the endpoint authorization so a caller can tell "this is not a port
    probe" (deliver it generically) from "this is a port probe at an endpoint that was never
    declared" (refuse it).
    """
    if not isinstance(content, str) or not isinstance(nonce, str):
        return None
    return re.fullmatch(
        r"echo " + re.escape("AGV_POST_NONCE=" + nonce)
        + r"; nc -z -w ([1-9]|10) ([0-9A-Fa-f:.]+) ([1-9][0-9]{0,4})"
          r" && echo OPEN \|\| echo CLOSED", content)


def command_receipt(response, depth=0):
    """Unwrap a terminal command receipt, retaining every raw command field.

    This is local to Post; shared MCP/Pre error interpretation is unchanged.
    An MCP protocol error or transport failure is never a command receipt.
    """
    if (not isinstance(response, dict) or depth > 5 or response.get("transport_error")
            or response.get("isError") or response.get("error")):
        return None
    if type(response.get("return_code")) is int and isinstance(response.get("stdout"), str):
        if "stderr" in response and not isinstance(response["stderr"], str):
            return None
        return deepcopy(response)
    for key in ("structuredContent", "response", "result"):
        if response.get(key) is not None:
            return command_receipt(response[key], depth + 1)
    content = response.get("content")
    if isinstance(content, list) and len(content) == 1 and isinstance(content[0], dict):
        try:
            return command_receipt(json.loads(content[0].get("text", "")), depth + 1)
        except (TypeError, ValueError):
            pass
    return None


def console_capture(command, nonce):
    """Owner-owned capture wrapper: no files, model code, or new channel.

    The console has a combined text stream, not exit-code/stderr fields. Capture
    them on that same Linux session with Python's standard library. A missing
    interpreter or incomplete envelope remains unknown, never a synthetic rc=0.
    """
    prefix = "AGV_POST_RESULT=" + nonce + ":"
    program = ("import json,subprocess; "
               "r=subprocess.run(['/bin/sh','-c'," + repr(command) + "],"
               "capture_output=True,text=True,timeout=12); "
               "print(" + repr(prefix) + "+json.dumps(dict(stdout=r.stdout,stderr=r.stderr,"
               "return_code=r.returncode)))")
    return "python3 -I -S -B -c " + shlex.quote(program)


def console_receipt(response, nonce):
    prefix = "AGV_POST_RESULT=" + nonce + ":"
    matches = [line[len(prefix):] for line in str(response.get("output") or "").splitlines()
               if line.startswith(prefix)]
    if len(matches) == 1:
        try:
            return command_receipt(json.loads(matches[0]))
        except (ValueError, TypeError):
            pass
    return None
