"""模型输出的唯一分派表：五类工具，一处实现（爷爷 2026-10-06 口径）。

**为什么要有这个模块。** 在这之前，"模型说的到底是什么、该在哪跑、怎么组织成命令"被分散在
五处各判一遍：`flat_action`（形状）、`_flat_http`（curl 行）、`restore_action`（占位符宽严）、
`LeanRun.call`（分派 + `speaks` 岔路）、`prepare_shell`（套壳 + **扫命令里的 IP 做地址白名单**）。
同一件事实在多处各有一套规则，彼此不知道对方 —— 2026-10-06 一晚撞出八处事故，五处是这么来的。

**现在的规则（唯一一处）**：模型只回答两件事 —— **用什么（tool）+ 参数**；**在哪跑**由引擎已经
绑定好的执行位置决定（`platform` 由会话/载体给出，不是从命令文本里猜）。于是：

* ``msf``  —— meterpreter/msf 会话里的命令（不套 shell，整条作为一个参数 + 标记）；
* ``cmd``  —— 一条命令行；位置是 Windows 就套 ``cmd /c``，是 POSIX 就套 ``/bin/sh -c``；
* ``pws``  —— PowerShell（只在 Windows 位置成立，别的位置具名拒绝）；
* ``tool`` —— 具名工具 + 参数数组，原样成 argv（不套 shell，引号不会被再解释一次）；
* ``code`` —— 一段代码（``lang`` 决定解释器：python / php）；
* ``http`` / ``stage`` —— 引擎自带客户端与卡的固定上传步骤（不是自由命令，单独两条）。

**不再有的东西**：地址白名单。它的意图（别把弹药打到别的机器上）没错，但手段是"正则扫命令里的
IP"—— 用猜出来的东西否决确定的东西，必然误伤（`ping -n 8 127.0.0.1` 当"等八秒"被判成越界）。
执行位置由绑定的会话决定，目标地址由图的节点决定，这两件事都不需要从命令文本里猜。
"""
from __future__ import annotations

import shlex

from .markers import marker_script, shell_command

#: 模型可以直接用的五类。表只有这一份：新增工具 = 这张表加一行，不改任何调用点。
CATEGORIES = ("msf", "cmd", "pws", "tool", "code")
#: 引擎自带的两条（不是自由命令）：结构化 HTTP 客户端、卡的固定上传步骤。
ENGINE_TOOLS = ("http", "stage")
#: `code` 类支持的运行时。
CODE_LANGS = {"python": ("python3", "-c"), "php": ("php", "-r")}

#: 一条命令文本的上限（字符）。超了不硬发，具名拒绝，让模型落成文件再跑。
COMMAND_MAX = 16384
#: `tool` 类的参数上限：个数 / 单个长度。
ARGV_MAX = 64
ARG_MAX = 4096


def _windows(platform) -> bool:
    return str(platform or "").strip().lower().startswith("windows")


def _refuse(code, detail=""):
    raise ValueError(code + (": " + str(detail) if detail else ""))


def _tool_name(request) -> str:
    """`name` 段：具体用什么。必须是**一个**裸名字（不含空格/路径穿越），否则具名拒绝。"""
    name = str(request.get("name") or "").strip()
    if not name or " " in name or "/" in name or "\\" in name:
        _refuse("LEAN_TOOL_NAME_INVALID", "name must be one bare tool name, got %r" % name)
    return name


def _command_text(request) -> str:
    text = request.get("cmd")
    if not isinstance(text, str) or not text.strip():
        _refuse("LEAN_COMMAND_MISSING", "cmd must be a non-empty string")
    if len(text) > COMMAND_MAX:
        _refuse("LEAN_COMMAND_TOO_LONG", "%d > %d characters - land it as a file and run that"
                % (len(text), COMMAND_MAX))
    return text


def _proxied(inner, proxy, windows=False) -> list:
    """把一条**在控制端跑**的命令套进隧道：`proxychains4 -q -f <conf> <原 argv…>`。

    隧道只对"控制端直接到不了"的目标有意义；Windows 位置上的命令不套（那里的命令是会话在跑，
    路由由会话自己承担）。写入这里而不是让模型自己写 proxychains：模型不知道代理端口，
    也不该知道——那是引擎的事实。
    """
    if not proxy or windows:
        return list(inner)
    return [*[str(part) for part in proxy], *[str(part) for part in inner]]


def build(request, *, platform="", marker, python="python3", proxy=(),
          single_line=False) -> list:
    """Render one shell category into a framed argv for a base executor."""
    if not isinstance(request, dict):
        _refuse("LEAN_REQUEST_INVALID", "one object with a tool")
    tool = str(request.get("tool") or "").strip().lower()
    windows = _windows(platform)
    request = {key: value for key, value in request.items() if key != "via"}
    if tool == "msf":
        _refuse("LEAN_MSF_NEEDS_BOUND_SESSION", "native actions require an explicit console binding")
    if tool == "cmd":
        command = _command_text(request)
        if set(request) - {"tool", "cmd", "name"}:
            _refuse("LEAN_REQUEST_INVALID", "cmd takes tool/name/cmd")
        inner = (["cmd", "/c", command] if windows else
                 _proxied(["/bin/sh", "-c", command], proxy))
    elif tool == "pws":
        command = _command_text(request)
        if not windows:
            _refuse("LEAN_PWS_NEEDS_WINDOWS", platform or "unknown")
        if set(request) - {"tool", "cmd", "name"}:
            _refuse("LEAN_REQUEST_INVALID", "pws takes tool/name/cmd")
        inner = ["powershell", "-NoProfile", "-NonInteractive", "-Command", command]
    elif tool == "tool":
        name = _tool_name(request)
        args = request.get("args")
        if args is None:
            text = request.get("cmd")
            if not isinstance(text, str) or not text.strip():
                _refuse("LEAN_TOOL_ARGS_INVALID", "give args or cmd")
            args = shlex.split(text)
        if not isinstance(args, list) or len(args) > ARGV_MAX:
            _refuse("LEAN_TOOL_ARGS_INVALID", "args must be a bounded list")
        if any(not isinstance(item, str) or not item or len(item) > ARG_MAX for item in args):
            _refuse("LEAN_TOOL_ARGS_INVALID", "each argument is a bounded non-empty string")
        inner = _proxied([name, *args], proxy, windows=windows)
    elif tool == "code":
        lang = str(request.get("name") or request.get("lang") or "").strip().lower()
        if lang not in CODE_LANGS:
            _refuse("LEAN_CODE_LANG_UNSUPPORTED", ", ".join(sorted(CODE_LANGS)))
        code = request.get("code")
        if not isinstance(code, str) or not code.strip():
            _refuse("LEAN_CODE_MISSING", "code must be a non-empty string")
        if len(code) > COMMAND_MAX:
            _refuse("LEAN_CODE_TOO_LONG", "land it as a file and run that")
        runner, flag = CODE_LANGS[lang]
        interpreter = "python" if runner == "python3" else runner
        inner = _proxied([interpreter, flag, code], proxy, windows=windows)
    else:
        _refuse("LEAN_TOOL_UNSUPPORTED", ", ".join(CATEGORIES + ENGINE_TOOLS))
    if tool == "cmd" and windows:
        framed = marker_script(None, str(marker), merge_stderr=True, windows=True,
                               command=command)
    else:
        framed = marker_script(inner, str(marker), merge_stderr=True, windows=windows,
                               single_line=single_line)
    return ["/bin/sh", "-c", framed]


def bind_console(request, binding, *, marker, python="python3", proxy=()):
    """Bind a category to an exact console operation before transport."""
    if not isinstance(binding, dict):
        _refuse("LEAN_SESSION_BINDING_INVALID")
    session_type = binding.get("session_type")
    platform = binding.get("platform")
    if session_type in ("web", "entry"):
        #: 入口位置：入口是个**遗留资源**，命令按配方交给那个客户端发出去
        #: （每次使用都是一次新的观测；入口没了就如实失败，不重打入口链）。
        recipe = binding.get("recipe")
        if (not isinstance(recipe, dict)
                or str(recipe.get("kind") or "") not in ("asset_command", "argv_command")):
            _refuse("LEAN_WEB_RECIPE_MISSING")
        if not isinstance(request, dict):
            _refuse("LEAN_REQUEST_INVALID", "one object with a tool")
        if str(request.get("tool") or "").strip().lower() != "cmd":
            _refuse("LEAN_WEB_COMMAND_ONLY", str(request.get("tool") or ""))
        return {"operation": "asset", "text": _command_text(request),
                "completion": {"marker": marker}, "recipe": dict(recipe)}
    if session_type not in {"shell", "meterpreter"}:
        _refuse("LEAN_SESSION_TYPE_UNSUPPORTED", session_type)
    if not isinstance(request, dict):
        _refuse("LEAN_REQUEST_INVALID", "one object with a tool")
    tool = str(request.get("tool") or "").strip().lower()
    request = {key: value for key, value in request.items() if key != "via"}
    if tool == "msf":
        if session_type != "meterpreter":
            _refuse("LEAN_MSF_NEEDS_METERPRETER_SESSION")
        if set(request) - {"tool", "cmd", "name"}:
            _refuse("LEAN_REQUEST_INVALID", "msf takes tool/name/cmd")
        return {"operation": "native", "text": _command_text(request), "completion": None}
    if not isinstance(platform, str) or not platform.strip():
        _refuse("LEAN_POSITION_PLATFORM_MISSING")
    argv = build(request, platform=platform, marker=marker, python=python, proxy=proxy,
                 single_line=session_type == "meterpreter" and not _windows(platform))
    if session_type == "meterpreter" and not _windows(platform):
        #: The channel is already a shell and reads one command line at a time, so the framed
        #: script travels on one line with no `/bin/sh -c` wrapper (measured on the lab,
        #: 2026-10-08: the wrapped multi-line frame came back empty).
        text = argv[2] + "\n"
    else:
        text = argv[2] if _windows(platform) else shlex.join(argv) + "\n"
    return {"operation": "shell", "text": text, "completion": {"marker": str(marker)}}


def invoke(request, *, session=None, executor=None, platform="", marker, timeout,
           python="python3", proxy=()):
    """Dispatch one category at an explicitly selected execution position."""
    if session is not None:
        from .channels import console_call
        action = bind_console(request, session, marker=marker, python=python, proxy=proxy)
        return console_call(session, action, timeout)
    if not callable(executor):
        _refuse("LEAN_EXECUTOR_MISSING")
    argv = build(request, platform=platform, marker=marker, python=python, proxy=proxy)
    return executor(argv, timeout)


def command_request(argv, *, platform):
    """Render trusted argv as one shell command without interpreting its shape."""
    if not isinstance(platform, str) or not platform.strip():
        _refuse("LEAN_POSITION_PLATFORM_MISSING")
    if (not isinstance(argv, (list, tuple)) or not argv
            or any(not isinstance(part, str) or "\x00" in part for part in argv)):
        _refuse("LEAN_ARGV_INVALID")
    return {"tool": "cmd", "cmd": shell_command(argv, windows=_windows(platform))}


def known_tools(card) -> list:
    """Expose JSON permissions, or the unchanged aliases of an unmigrated card."""
    fields = card or {}
    if "allowed_tools" in fields:
        return list(fields["allowed_tools"])
    return [ALIASES.get(str(item).strip().lower(), str(item).strip().lower())
            for item in fields.get("tools") or []]


ALIASES = {"shell": "cmd", "python": "code"}


def declared(card, tool) -> bool:
    """Check the effective action declaration."""
    return str(tool or "").strip().lower() in known_tools(card)


def require_declared(card, tool) -> None:
    """Reject before dispatch, including explicit finish permissions on migrated cards."""
    fields = card or {}
    key = str(tool or "").strip().lower()
    if key == "finish" and "allowed_tools" not in fields:
        return
    if declared(fields, key):
        return
    allowed = known_tools(fields)
    if "allowed_tools" not in fields and "finish" not in allowed:
        allowed.append("finish")
    _refuse("LEAN_TOOL_UNDECLARED",
            "card %s only allows %s; requested %s"
            % (fields.get("id") or "<unnamed>", "/".join(allowed) or "<none>",
               key or "<missing>"))
