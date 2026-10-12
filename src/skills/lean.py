"""Read the Markdown card and its optional JSON action permissions."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from agents._prompt_resources import read_prompt
from skills import layout
from runtime import dispatch

REQUIRED = frozenset({"name", "description", "id", "kind", "runs_at", "delivers",
                         "inputs", "tools"})
#: Optional fields declare node selection, fixed steps, the material output projection, and how a
#: later step may drive what the card produced.
OPTIONAL = frozenset({"when", "stage", "materials", "secret_patterns", "channel",
                      "entry_setup", "session", "speaks", "assets", "output_budget",
                      "max_turns", "provides_position"})
FIELDS = REQUIRED | OPTIONAL
STRUCTURED = frozenset({"delivers", "inputs", "tools", "when", "stage",
                        "materials", "secret_patterns", "channel", "entry_setup", "session",
                        "speaks", "assets", "output_budget", "max_turns", "provides_position"})
MATERIAL_FIELDS = ("realm", "user", "value", "kind", "source_call", "quote")
FRONTMATTER = re.compile(r"\A---\n(.*?)\n---\n(.*)\Z", re.S)
NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
IDENTITY = re.compile(r"[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+\Z")
TOOL = re.compile(r"[a-z][a-z0-9_-]*\Z")
PARAMETER = re.compile(r"[a-z][a-z0-9_]*\Z")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("LEAN_CARD_DUPLICATE_FIELD: " + key)
        result[key] = value
    return result


def parse(text: str, *, allowed_tools=None) -> tuple[dict, str]:
    """Flat strings plus strict JSON flow values, not a general-purpose YAML parser."""
    # ponytail: flat strings/JSON flow only; use a parser library if full YAML becomes necessary.
    match = FRONTMATTER.fullmatch(text)
    if match is None:
        raise ValueError("LEAN_CARD_FRONTMATTER_INVALID: expected LF-delimited --- header")
    fields = {}
    for line in match[1].splitlines():
        key, separator, value = line.partition(":")
        if not separator or key not in FIELDS or key in fields:
            raise ValueError("LEAN_CARD_FIELD_INVALID: " + key)
        value = value.strip()
        if key in STRUCTURED:
            value = json.loads(value, object_pairs_hook=_unique_object)
        fields[key] = value
    if allowed_tools is not None:
        # The runtime tools field is a projection of the JSON declaration.
        fields["tools"] = list(allowed_tools)
    #: `when` is optional: it writes "which node fields this card answers" into the card
    #: (the old selector's decisions are frozen there), so no machine table has to map a
    #: graph node onto a card. A card without it is simply not bound by the graph.
    if fields.get("when") is not None:
        when = fields["when"]
        if (not isinstance(when, dict) or not when
                or set(when) - {"case", "service", "technique"}
                or any(not isinstance(value, str) or not value.strip()
                       for value in when.values())):
            raise ValueError("LEAN_CARD_WHEN_INVALID")
    #: `stage` is the card's *fixed* step (wire shape owned by the card, one model decision):
    #: a measured failure was the model burning three steps guessing a multipart shape. A card that
    #: declares one must also offer it as a tool, so the runtime's "tool declared" check keeps meaning.
    stage = fields.get("stage")
    if stage is not None:
        if (not isinstance(stage, dict) or not str(stage.get("path") or "").startswith("/")
                or not str(stage.get("payload") or "").strip()
                or set(stage) - {"path", "fields", "file_field", "filename", "content_type", "payload"}):
            raise ValueError("LEAN_CARD_STAGE_INVALID")
        if not isinstance(stage.get("fields", []), list):
            raise ValueError("LEAN_CARD_STAGE_INVALID: fields must be a list")
        if "stage" not in (fields.get("tools") or []):
            raise ValueError("LEAN_CARD_STAGE_UNDECLARED: add stage to tools")

    #: `channel` is how the card says a later step drives what it produced: a kind, an argv
    #: recipe with exactly one command slot, and optionally the platform, the position it
    #: reaches, its own harmless probe, and the privilege it leaves behind. Declaring it is what
    #: makes the produced handle drivable *by construction* - the same field is read when the
    #: handle is registered and when it is used, so the three cannot drift apart.
    channel = fields.get("channel")
    #: `session` is how a card says the step ends by *handing over a live session* rather than by
    #: leaving a recipe: one driver name is all it declares - the port, the handler, the payload
    #: build and the registration are the runtime's, because those follow the deployment, not the
    #: method. A card that declares a session must also say what it proves (delivers).
    session = fields.get("session")
    if session is not None:
        #: `via` 是可选的一步：有的目标从执行点不可达，会话要靠跳板回程（relay）交回来。
        #: A card may also declare *what it hands over* instead of the whole plan: the payload
        #: it needs, the entry it leaves, and how that payload travels. The port, the handler,
        #: the run's own key and the registration stay the runtime's.
        if (not isinstance(session, dict)
                or set(session) - {"driver", "via", "payload", "entry", "transport",
                                   "capabilities", "platform", "remote", "command",
                                   "stage_payload"}
                or "driver" not in session
                or not TOOL.fullmatch(str(session.get("driver") or ""))):
            raise ValueError("LEAN_CARD_SESSION_INVALID: a driver, optionally via=relay, "
                             "or a declared delivery spec")
        if "via" in session and str(session.get("via")) not in ("relay",):
            raise ValueError("LEAN_CARD_SESSION_VIA_INVALID: only relay is implemented")
        payload = session.get("payload")
        if payload is not None:
            entry = session.get("entry")
            capabilities = session.get("capabilities")
            transport = str(session.get("transport") or "scp")
            if (not isinstance(payload, dict) or set(payload) - {"path", "kind", "format"}
                    or not str(payload.get("path") or "").strip()):
                raise ValueError("LEAN_CARD_SESSION_PAYLOAD_INVALID: a payload path")
            #: `relay` = 目标从执行点不可达，会话得**经跳板回程**交回来（引擎装回程门、把助手程序
            #: 预先放到跳板上；卡负责目标侧怎么放与怎么起）。
            if transport not in ("scp", "http", "relay"):
                raise ValueError("LEAN_CARD_SESSION_TRANSPORT_INVALID: scp, http or relay")
            if transport == "scp":
                if (not isinstance(entry, dict)
                        or set(entry) - {"driver", "username", "port", "authorize_command"}
                        or str(entry.get("driver") or "") != "ssh"
                        or not str(entry.get("username") or "").strip()):
                    raise ValueError("LEAN_CARD_SESSION_ENTRY_INVALID: an ssh entry")
            elif not str(session.get("command") or "").strip():
                raise ValueError("LEAN_CARD_SESSION_COMMAND_REQUIRED: how the target gets it")
            if "remote" in session:
                remote = session["remote"]
                if (not isinstance(remote, dict) or set(remote) - {"dir", "suffix"}
                        or not str(remote.get("dir") or "").strip()):
                    raise ValueError("LEAN_CARD_SESSION_REMOTE_INVALID: a directory and a suffix")
            if (not isinstance(capabilities, dict)
                    or set(capabilities) != {"capacity", "shell_ready"}):
                raise ValueError("LEAN_CARD_SESSION_CAPABILITIES_REQUIRED")
    position = fields.get("provides_position")
    if position is not None:
        #: 这一步在目标上留下一个**可以再次使用的执行入口**（例如 web 入口）：卡只声明"入口是什么形状、
        #: 用哪条配方说话"，运行层把它登记成一个位置，并**在每一次使用时重新观测**它 ——
        #: 入口没了就如实失败，绝不静默把入口链重打一遍（外部评审 2026-10-08：遗留资源与观测分开登记，
        #: 历史观测不能替代当前可用性）。
        if (not isinstance(position, dict)
                or set(position) - {"kind", "host", "logical", "recipe", "privilege"}
                or str(position.get("kind") or "") not in ("web",)
                or not isinstance(position.get("recipe"), dict)):
            #: `host` 可以省略：位置在哪是**图上的事**（这一步产出的 execCode 主机），
            #: 卡不该把某套部署的主机名写死（2026-10-08：泛化优先，运行层按图解析地址）。
            raise ValueError("LEAN_CARD_POSITION_INVALID: kind=web and a recipe")
        recipe = position["recipe"]
        if (set(recipe) - {"kind", "asset", "url_args", "command_flag", "platform"}
                or str(recipe.get("kind") or "") != "asset_command"
                or not str(recipe.get("asset") or "").startswith("/")
                or not isinstance(recipe.get("url_args"), list) or not recipe["url_args"]
                or any(not isinstance(part, str) for part in recipe["url_args"])
                or str(recipe.get("platform") or "") not in ("linux", "windows")):
            raise ValueError("LEAN_CARD_POSITION_RECIPE_INVALID: an asset_command recipe")
    #: `assets` is how a card says "this tool of mine has to be on the execution end": a map from
    #: the absolute path the card's own recipe names to the file inside the card that provides it.
    #: The runtime places them at dispatch (runtime/assets.py), because a tool that only exists
    #: because someone copied it there by hand is a deployment nobody can reproduce.
    assets = fields.get("assets")
    if assets is not None:
        if (not isinstance(assets, dict) or not assets
                or any(not isinstance(key, str) or not key.startswith("/") or not value
                        or not isinstance(value, str)
                        or value.startswith(("/", "\\"))
                        for key, value in assets.items())):
            raise ValueError("LEAN_CARD_ASSETS_INVALID: an absolute destination path to a "
                             "relative source file")
    if channel is not None:
        if (not isinstance(channel, dict)
                or set(channel) - {"kind", "recipe", "platform", "position", "probe",
                                   "privilege"}):
            raise ValueError("LEAN_CARD_CHANNEL_INVALID: kind, recipe and optional fields only")
        if not TOOL.fullmatch(str(channel.get("kind") or "")):
            raise ValueError("LEAN_CARD_CHANNEL_INVALID: kind")
        recipe = channel.get("recipe")
        if (not isinstance(recipe, list) or not recipe
                or any(not isinstance(part, str) or not part for part in recipe)
                or len([part for part in recipe if part == "{command}"]) != 1):
            raise ValueError("LEAN_CARD_CHANNEL_RECIPE_INVALID: an argv with exactly one "
                             "{command} argument")
        for name in ("platform", "position", "probe", "privilege"):
            if name in channel and not isinstance(channel[name], str):
                raise ValueError("LEAN_CARD_CHANNEL_INVALID: " + name)

    #: "I leave a reusable handle" is an assertion, and an assertion needs a source. A method card
    #: that claims one must say how that handle is built; a `session` card is the mechanism itself,
    #: so it is exempt, and importing a handle that came from elsewhere is a contract we do not have
    #: yet (when we add it, it will have to be declared too).
    #: `entry_setup` is the other way to leave an entry: a bounded action that *builds* one on a real
    #: host (the step reached the host but only through an isolated position, so the entry has to be
    #: constructed, verified through itself, and only then registered). It declares what it needs, the
    #: action, the marker that says the action finished, the candidate it produces, the check that
    #: proves the candidate is really on that host, and what it created.
    setup = fields.get("entry_setup")
    if setup is not None:
        allowed = {"action", "ready_marker", "candidate", "verify", "identity", "cleanup", "requires"}
        if not isinstance(setup, dict) or set(setup) - allowed:
            raise ValueError("LEAN_CARD_ENTRY_SETUP_INVALID: " + ", ".join(sorted(allowed)))
        if not {"action", "ready_marker", "candidate", "verify"} <= set(setup):
            raise ValueError("LEAN_CARD_ENTRY_SETUP_INVALID: action, ready_marker, candidate and "
                             "verify are required")
        if (not isinstance(setup["action"], list) or not setup["action"]
                or any(not isinstance(part, str) or not part for part in setup["action"])
                or not isinstance(setup["ready_marker"], str) or not setup["ready_marker"].strip()
                or not isinstance(setup["verify"], str) or not setup["verify"].strip()):
            raise ValueError("LEAN_CARD_ENTRY_SETUP_INVALID: an argv, a marker and a verify command")
        candidate = setup["candidate"]
        if (not isinstance(candidate, dict)
                or set(candidate) - {"driver", "username", "port", "become"}
                or str(candidate.get("driver") or "") != "ssh"
                or not str(candidate.get("username") or "").strip()
                or not str(candidate.get("port") or "").strip().isdigit()
                or ("become" in candidate and not isinstance(candidate["become"], str))):
            raise ValueError("LEAN_CARD_ENTRY_SETUP_INVALID: an ssh candidate is required")
        if "identity" in setup and not isinstance(setup["identity"], dict):
            raise ValueError("LEAN_CARD_ENTRY_SETUP_INVALID: identity must describe the baseline")
        if "cleanup" in setup and (not isinstance(setup["cleanup"], list)
                                   or any(not isinstance(part, str) or not part
                                          for part in setup["cleanup"])):
            raise ValueError("LEAN_CARD_ENTRY_SETUP_INVALID: cleanup must be an argv")

    if (fields["kind"] == "method" and "session" in fields["delivers"]
            and channel is None and setup is None
            and not (isinstance(session, dict) and session.get("driver"))):
        raise ValueError("LEAN_CARD_DELIVERY_UNBACKED: a method card that delivers a session must "
                         "declare how that handle is built (channel)")

    if "materials" in fields or "secret_patterns" in fields:
        if fields.get("materials") != list(MATERIAL_FIELDS):
            raise ValueError("LEAN_CARD_MATERIALS_INVALID")
        patterns = fields.get("secret_patterns")
        if (not isinstance(patterns, list) or not patterns
                or any(not isinstance(pattern, str) for pattern in patterns)):
            raise ValueError("LEAN_CARD_SECRET_PATTERNS_INVALID")
        for pattern in patterns:
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                raise ValueError("LEAN_CARD_SECRET_PATTERNS_INVALID") from exc
            if "value" not in compiled.groupindex:
                raise ValueError("LEAN_CARD_SECRET_PATTERNS_INVALID: missing value group")

    if fields.keys() - FIELDS:
        raise ValueError("LEAN_CARD_FIELD_INVALID: "
                         + ", ".join(sorted(fields.keys() - FIELDS)))
    if REQUIRED - fields.keys():
        raise ValueError("LEAN_CARD_FIELDS_MISSING: "
                         + ", ".join(sorted(REQUIRED - fields.keys())))
    if not NAME.fullmatch(fields["name"]) or len(fields["name"]) > 64:
        raise ValueError("LEAN_CARD_NAME_INVALID")
    if not IDENTITY.fullmatch(fields["id"]):
        raise ValueError("LEAN_CARD_ID_INVALID")
    if not 1 <= len(fields["description"]) <= 1024:
        raise ValueError("LEAN_CARD_DESCRIPTION_INVALID")
    if fields["kind"] not in {"method", "recon", "validation", "session"}:
        raise ValueError("LEAN_CARD_KIND_INVALID")
    if fields["runs_at"] not in {"base", "position"}:
        raise ValueError("LEAN_CARD_POSITION_INVALID")
    for key in ("delivers", "tools"):
        values = fields[key]
        if (not isinstance(values, list) or not values
                or any(not isinstance(value, str) or not TOOL.fullmatch(value) for value in values)
                or len(set(values)) != len(values)):
            raise ValueError("LEAN_CARD_LIST_INVALID: " + key)
    if not set(fields["delivers"]) <= {"evidence", "session", "fact"}:
        raise ValueError("LEAN_CARD_DELIVERY_INVALID")
    if not isinstance(fields["inputs"], dict):
        raise ValueError("LEAN_CARD_INPUTS_INVALID")
    for name, binding in fields["inputs"].items():
        if (not PARAMETER.fullmatch(name) or not isinstance(binding, dict)
                or not binding.keys() <= {"from", "optional"}
                or not isinstance(binding.get("from"), str)
                or binding["from"] not in {"graph", "runtime", "model", "config"}
                or ("optional" in binding and type(binding["optional"]) is not bool)):
            raise ValueError("LEAN_CARD_INPUT_INVALID: " + name)
    body = match[2]
    if not body.strip():
        raise ValueError("LEAN_CARD_BODY_MISSING")
    return fields, body


def _expand_execution_rules(text: str) -> str:
    """Expand the fixed body reference before parsing and identity binding."""
    match = FRONTMATTER.fullmatch(text)
    if match is None:
        return text
    body = match[2]
    marker = "[共享执行规则]"
    reference = marker + "(../../src/skills/templates/execution_rules.txt)\n"
    if marker not in body:
        return text
    if body.count(marker) != 1 or reference not in body.splitlines(keepends=True):
        raise ValueError("LEAN_CARD_EXECUTION_RULES_REFERENCE_INVALID")
    try:
        rules = read_prompt(__package__, "templates/execution_rules.txt")
    except (OSError, UnicodeError) as error:
        raise ValueError("LEAN_CARD_EXECUTION_RULES_RESOURCE_INVALID") from error
    if not rules.strip() or marker in rules:
        raise ValueError("LEAN_CARD_EXECUTION_RULES_RESOURCE_INVALID")
    return text[:match.start(2)] + body.replace(reference, rules, 1)


def load_card(skill_id: str, root=None) -> dict:
    """Consume only allowed_tools from JSON; keep all other card semantics in Markdown."""
    if not isinstance(skill_id, str) or not IDENTITY.fullmatch(skill_id):
        raise ValueError("LEAN_CARD_ID_INVALID")
    path = layout.skill_dir(skill_id, root) / "SKILL.md"
    raw = path.read_bytes()
    allowed = None
    try:
        declaration = path.with_name("skill.json").read_bytes()
    except FileNotFoundError:
        declaration = None
    if declaration is not None:
        try:
            metadata = json.loads(declaration.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, ValueError) as error:
            raise ValueError("LEAN_CARD_JSON_INVALID") from error
        if not isinstance(metadata, dict):
            raise ValueError("LEAN_CARD_JSON_INVALID: expected an object")
        if "allowed_tools" in metadata:
            allowed = metadata["allowed_tools"]
            names = set(dispatch.CATEGORIES) | {"http", "finish"}
            if (not isinstance(allowed, list) or not allowed
                    or any(not isinstance(item, str) or item not in names for item in allowed)
                    or len(set(allowed)) != len(allowed)):
                raise ValueError("LEAN_CARD_ALLOWED_TOOLS_INVALID: expected unique names from "
                                 + "/".join(sorted(names)))
    raw = _expand_execution_rules(raw.decode("utf-8")).encode("utf-8")
    fields, body = parse(raw.decode("utf-8"), allowed_tools=allowed)
    if fields["id"] != skill_id:
        raise ValueError("LEAN_CARD_ID_MISMATCH: " + fields["id"])
    binding = raw
    if allowed is not None:
        fields["allowed_tools"] = list(allowed)
        # Only consumed JSON data affects the binding; legacy keys remain inactive.
        binding = json.dumps([raw.decode("utf-8"), allowed], ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8")
    return dict(fields, body=body, digest=hashlib.sha256(binding).hexdigest(), path=str(path))

#: 没在卡里声明 output_budget 时的默认输出上限（按卡的形态分档）。
#: 依据（2026-10-06 D66 实测）：模型对「只要一个 JSON」的小问也会写 1.3k-1.7k，真机上单次动辄到 16.6k，
#: 其中大部分是解释、调用方只取 JSON。分档就是把「有用输出」的天花板写进产品约束：
#: 侦查/验证只要一行结论；利用卡可能要写长命令，给宽一点；会话/入口卡居中。
DEFAULT_OUTPUT_BUDGET = {'recon': 2500, 'validation': 2500, 'session': 4000, 'method': 6000}
OUTPUT_BUDGET_RANGE = (512, 48000)


def output_budget_of(card) -> int:
    """这张卡这次调用的输出上限（token）。卡声明优先，否则按 kind 默认；越界就具名拒绝。"""
    fields = card or {}
    declared = fields.get('output_budget')
    if declared is None:
        return int(DEFAULT_OUTPUT_BUDGET.get(str(fields.get('kind') or ''), 6000))
    if isinstance(declared, bool) or not isinstance(declared, int):
        raise ValueError('LEAN_CARD_OUTPUT_BUDGET_INVALID: output_budget must be an int')
    low, high = OUTPUT_BUDGET_RANGE
    if not low <= declared <= high:
        raise ValueError('LEAN_CARD_OUTPUT_BUDGET_INVALID: %d outside [%d, %d]' % (declared, low, high))
    return int(declared)

#: 回合预算（借 H-mmer/pentest-agents 的 maxTurns 思路，2026-10-06 查过：别人的卡里写的是
#: tools 白名单 + maxTurns；参数 schema 在工具层，卡里不写 I/O）。分档依据：侦查/验证两三步就够，
#: 利用卡要试-读-改，给宽一点。
DEFAULT_MAX_TURNS = {'recon': 4, 'validation': 4, 'session': 6, 'method': 8}
MAX_TURNS_RANGE = (1, 60)


def max_turns_of(card) -> int:
    """这张卡这次派发最多几个回合（模型的一次动作+观测算一个）。卡声明优先，否则按 kind 默认。"""
    fields = card or {}
    declared = fields.get('max_turns')
    if declared is None:
        return int(DEFAULT_MAX_TURNS.get(str(fields.get('kind') or ''), 8))
    if isinstance(declared, bool) or not isinstance(declared, int):
        raise ValueError('LEAN_CARD_MAX_TURNS_INVALID: max_turns must be an int')
    low, high = MAX_TURNS_RANGE
    if not low <= declared <= high:
        raise ValueError('LEAN_CARD_MAX_TURNS_INVALID: %d outside [%d, %d]' % (declared, low, high))
    return int(declared)
