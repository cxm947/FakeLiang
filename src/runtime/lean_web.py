"""An entry as a position: one command line per request, every use re-observed.

The entry is a **leftover resource**, not a connection (external review 2026-10-08): the recipe
says which client this run placed and how it is called, and the command travels as that client's
own argument (``asset_command``: a script this run placed on the control end), or as the last
argument of a control-end argv it built itself (``argv_command``: an ``ssh`` line into a host this
run authorised, say). Nothing here replays the chain that planted the entry -- if the entry is
gone the client fails and the step reports that, instead of quietly making a new one.
"""
from __future__ import annotations

from runtime.markers import marker_script

PLATFORMS = ("linux", "windows")
RECIPES = ("asset_command", "argv_command")


def command_argv(recipe, command, marker, *, python="python3"):
    """Build the control-end argv that runs one command line through the entry."""
    if not isinstance(recipe, dict):
        raise ValueError("LEAN_WEB_RECIPE_MISSING")
    flag = str(recipe.get("command_flag") or "")
    platform = str(recipe.get("platform") or "linux")
    kind = str(recipe.get("kind") or "")
    if kind not in RECIPES or platform not in PLATFORMS:
        raise ValueError("LEAN_WEB_RECIPE_MISSING")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("LEAN_WEB_COMMAND_REQUIRED")
    windows = platform == "windows"
    #: 一条命令，交给入口自己的 shell 执行：给 `marker_script` 的必须是**参数表**，不是装着
    #: 参数表的元组（2026-10-08 真机 node 26 实测：写成 `[("cmd","/c",cmd)]` 后目标收到的是
    #: Python 元组字面量 `('/bin/sh', '-c', 'id -u')`，每条命令都 127）。
    framed = marker_script(["cmd", "/c", command] if windows else ["/bin/sh", "-c", command],
                           str(marker), merge_stderr=True, windows=windows, single_line=True)
    if kind == "argv_command":
        base = recipe.get("argv")
        if (not isinstance(base, list) or not base
                or any(not isinstance(part, str) or not part for part in base)):
            raise ValueError("LEAN_WEB_RECIPE_INVALID")
        return [str(part) for part in base] + ([flag] if flag.strip() else []) + [framed]
    asset = str(recipe.get("asset") or "")
    args = recipe.get("url_args")
    #: `command_flag` 可以为空：有些入口客户端把命令当**最后一个位置参数**（`... ps '<cmd>'`），
    #: 有些用开关（`-c '<cmd>'`）。两种都只是一次调用，形状由卡冻结。
    if (not asset.startswith("/")
            or not isinstance(args, list) or any(not isinstance(part, str) for part in args)):
        raise ValueError("LEAN_WEB_RECIPE_INVALID")
    return [str(python), asset, *[str(part) for part in args]] + ([flag] if flag.strip() else []) \
        + [framed]
