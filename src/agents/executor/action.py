"""Action translation and secret placeholder restoration."""
from __future__ import annotations

from copy import deepcopy

from runtime.redact import TOKEN_RE, rebind, residual_tokens



def restore_secrets(value, mapping, *, command_text=False):
    """Restore secret placeholders before either dispatch or conclusion.

    ``command_text`` 打开时允许占位符**嵌在一段命令里**（`/p «secret:x»`、`--password «secret:x»`），
    其余场合仍然要求"占位符独占整个值"。为什么必须分这两种：旧的嵌套形状里密码是 argv 的**独立一项**，
    "独占"成立；而扁平形状下**整条命令就是一个字符串**，密码必然嵌在命令中 —— 不分场合地要求独占，
    等于让模型永远无法带着密码发命令（2026-10-06 walk-65 node 2 实测：`schtasks … /p «secret:x» …`
    连吃三次 `LEAN_SECRET_TOKEN_COMPOSITE`，而 44/48 全靠这条路）。

    认不出的占位符（模型编的）在任何场合都拒，这条不放宽。
    """
    if isinstance(value, dict):
        if any(residual_tokens(str(key)) for key in value):
            raise ValueError("LEAN_SECRET_TOKEN_KEY_UNSUPPORTED")
        return {key: restore_secrets(item, mapping, command_text=command_text)
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [restore_secrets(item, mapping, command_text=command_text) for item in value]
    if isinstance(value, str) and residual_tokens(value):
        fragments = residual_tokens(value)
        if any(fragment not in mapping for fragment in fragments):
            raise ValueError("LEAN_SECRET_TOKEN_UNKNOWN")
        if command_text:
            return TOKEN_RE.sub(lambda match: mapping[match.group(0)], value)
        if not TOKEN_RE.fullmatch(value):
            raise ValueError("LEAN_SECRET_TOKEN_COMPOSITE")
        return rebind(value, mapping)
    return value


def restore_request(request, mapping):
    """一条调用请求：命令文本宽松（占位符可嵌入），其余字段严格（必须独占）。"""
    if not isinstance(request, dict):
        return restore_secrets(request, mapping)
    #: 命令文本类的字段：cmd（cmd/sh/pws/msf）、code（code 类）、tool 的 args 每一项。
    text_keys = {"cmd", "code"}
    out = {}
    for key, item in request.items():
        if key == "args" and isinstance(item, list):
            out[key] = [restore_secrets(part, mapping, command_text=True) for part in item]
            continue
        out[key] = restore_secrets(item, mapping, command_text=(key in text_keys))
    return out


#: 旧卡/旧脚本还在用 `shell` + `argv` 或 `shell` + `cmd`，统一映射到新的 `cmd` 类
#: （`argv` 形式转成 `tool` 类：名字 + 参数数组，语义一样）。
_LEGACY_TOOL = {"shell": "cmd", "python": "code"}


def flat_action(action, scope=None):
    """把扁平的 ``{"tool": …, "cmd"/"code": …}`` 翻译成执行器内部的调用形状（爷爷 2026-10-06 口径）。

    为什么要这一层：输出越像"一个工具 + 一段内容"，需要接住它的解析代码就越少。原来模型的每一条
    动作都是 ``{"kind":"call","request":{"tool":..,"method":..,"path":..,"headers":..,"body":..}}``
    这种嵌套形状，于是运行时要逐层校验 method / path 编码 / headers 白名单 / argv 形状 —— 而每一次
    校验都是一类"形状死亡"（2026-10-06 一晚就撞了四种：argv 多键、path 没编码、Host 头、6000 截断）。

    接受的扁平形状（就是爷爷给的例子那个样子）::

        {"tool": "shell",  "cmd":  "curl -sS http://10.0.0.5:8080/"}
        {"tool": "python", "code": "import socket; …"}
        {"tool": "http",   "cmd":  "curl -sS -X POST http://10.0.0.5/f -d 'UID=1'"}
        {"tool": "finish", "claim": "…", "verdict": "pass", "evidence": "…"}

    ``shell``/``http`` 走的是**执行位置自己的 shell**（Windows 位置就是 cmd），命令里出现的主机名
    仍然由 `prepare_shell` 按冻结端点检查 —— 形状简单了，边界没松。旧的嵌套形状继续接受：
    脚本化动作、离线用例与历史记录都靠它。
    """
    if not isinstance(action, dict):
        return action
    if isinstance(action.get("actions"), list):
        #: **默认：一次回答只发一个动作**（爷爷 2026-10-07 口径）。
        #: 实测对照（同一张图、同一批卡）：不启用批次时每个节点 1~6 发（pre 1 发、利用 2~5 发，
        #: 正好符合"pre 一发、利用 3-5 发"的标尺）；启用批次后同样的节点变成 8~12 发，而且
        #: 逐步观察被"一发多步"挤掉，node 7/19 直接炸掉。所以批次降级为**卡片显式声明才可用**
        #: 的能力，默认拒收并说明形状 —— 一次具名回喂，模型下一发就改回来了。
        _error = ("LEAN_ONE_ACTION_PER_ANSWER: send exactly one action per answer "
                  "(one tool object), then read its receipt before the next one")
        raise ValueError(_error)
    if "kind" in action:
        if "tool" not in action:
            return action                      # 老嵌套形状原样放行（脚本化动作/历史记录）
        if str(action.get("kind") or "").strip().lower() == "abandon":
            #: 核销优先：模型把"核销一条未决调用"和"下一条命令"塞进同一个对象时，先办核销
            #: （walk-64 node 26 实测：不这么做它会原样重发、白烧回合）。那条命令下一回合再发。
            return action
        #: 两个都给：以 `tool` 为准、丢掉多余的 `kind`。2026-10-06 walk-67 node 14 实测：
        #: 模型写 `{"tool":"finish","kind":"finish","claim":…}`，旧判据直接判"形状不认识"，
        #: 白烧一个回合（运行时对这类可回喂，但本可以根本不发生）。
        action = {key: value for key, value in action.items() if key != "kind"}
    tool = str(action.get("tool") or "").strip().lower()
    if tool == "http":
        #: 结构化 http（引擎自带客户端）：method / path / headers / body 原样交给运行时。
        #: 不再翻译 curl 行 —— 模型写 curl 会被运行时具名拒绝并回喂（"http takes method and path"）。
        request = {"tool": "http"}
        request.update({key: value for key, value in action.items() if key != "tool"})
        return {"kind": "call", "request": request}
    #: `via`（在哪执行）与 `name`（用什么）是模型的输出，构造请求时必须**带上** ——
    #: 2026-10-06 walk-67 实测：漏掉 `via` 等于那条"位置核对"根本没机会看到它
    #: （模型把 via 写成卡 id 也没人拦）。
    def _carry(request):
        #: `via`/`name` 与重发声明（`retry_of`/`retry_reason`）都是**模型的输出**，构造请求时必须带上：
        #: 2026-10-06 walk-67 实测漏掉 `via` = 位置核对根本没机会看到它；2026-10-08
        #: walk-174/175/177 实测漏掉重发声明 = 模型无法合法重跑一条已落定的调用（真机上它把
        #: 逐字节相同的调用 id 填进 `retry_of`，执行器翻译后字段消失，运行时只能回答"已经跑过"）。
        for key in ("via", "name", "retry_of", "retry_reason"):
            if key in action and key not in request:
                request[key] = action[key]
        return {"kind": "call", "request": request}

    if tool in ("shell", "cmd") and isinstance(action.get("cmd"), str) and action["cmd"].strip():
        return _carry({"tool": "cmd", "cmd": action["cmd"]})
    if tool == "shell" and isinstance(action.get("argv"), list) and action["argv"]:
        #: 旧形状 `{"tool":"shell","argv":[a,b,c]}` → `tool` 类（名字 + 参数数组），语义一致。
        head, *tail = [str(part) for part in action["argv"]]
        return _carry({"tool": "tool", "name": head, "args": tail})
    if tool in ("python", "code") and isinstance(action.get("code"), str) and action["code"].strip():
        return _carry({"tool": "code", "lang": str(action.get("lang") or "python"),
                       "code": action["code"]})
    if tool == "evidence":
        return {"kind": "evidence",
                **{key: value for key, value in action.items() if key != "tool"}}
    if tool == "finish":
        #: 结论也是扁平的：`{"tool":"finish","claim":…,"verdict":…,"citations":[…]}`。
        #: 只认这四个字段（外加 materials），其余键一律丢掉 —— 免得 `"type":"tool_call"` 这种
        #: 多余字段被运行时判成"形状不认识"（2026-10-06 walk-61 node 14/30：调用跑成了，结论这一步
        #: 却因为 finish 没被翻译而整节点停住）。`verdict` 在这里映射成运行时要的 `claimed_verdict`。
        claim = action.get("claim")
        if not isinstance(claim, str):
            return action
        verdict = action.get("verdict") or action.get("claimed_verdict") or "uncertain"
        citations = action.get("citations")
        settled = {"kind": "finish", "claim": claim,
                   "claimed_verdict": str(verdict).strip().lower(),
                   "citations": citations if isinstance(citations, list) else []}
        materials = action.get("materials")
        if isinstance(materials, list) and materials:
            settled["materials"] = materials
        return settled
    if tool == "abandon":
        #: 核销一条没用的调用（模型自己会用这条路把"没发出去/没用"的调用写掉再继续）。
        settled = {"kind": "abandon", "call_id": action.get("call_id"),
                   "reason": str(action.get("reason") or "")[:200]}
        return settled
    #: 写歪的 shell/http/python（缺 cmd/code/结构化字段）原样放行，由运行时具名拒绝并回喂。
    if tool in ("http", "shell", "python"):
        return action
    if tool:
        #: **工具面全覆盖**：卡片声明的任何工具都能用扁平形状写 —— `tool` 之外的字段原样作为请求
        #: 交给运行时，由运行时按卡片声明与字段形状去判（该拒绝就具名拒绝，回喂）。
        #: 这一条是被三次同类事故逼出来的（http 被写成 curl、finish 没翻译、stage 没翻译 ——
        #: 每次都是"手写白名单漏了一个工具"），所以这里不再逐个手写。
        request = {"tool": tool}
        request.update({key: value for key, value in action.items() if key != "tool"})
        return {"kind": "call", "request": request}
    return action


def restore_action(action, mapping):
    """引用与命令文本允许占位符嵌在更大的字符串里；其余字段要求它独占整个值。"""
    if isinstance(action, dict) and action.get("kind") == "call_batch":
        #: 批次的每个块都按单块那套还原（占位符要在**每一条命令文本**里各自生效）。
        settled = {key: item for key, item in action.items() if key != "requests"}
        settled["requests"] = [restore_request(item, mapping)
                               for item in action.get("requests") or []]
        if action.get("abandons"):
            settled["abandons"] = [restore_secrets(item, mapping)
                                   for item in action["abandons"]]
        return settled
    if not isinstance(action, dict) or action.get("kind") != "finish":
        if isinstance(action, dict) and isinstance(action.get("request"), dict):
            settled = {key: item for key, item in action.items() if key != "request"}
            settled["request"] = restore_request(action["request"], mapping)
            return settled
        return restore_secrets(action, mapping)
    prepared = deepcopy(action)
    quotes = []
    for name in ("citations", "materials"):
        items = prepared.get(name, [])
        if isinstance(items, list):
            for index, item in enumerate(items):
                if isinstance(item, dict) and isinstance(item.get("quote"), str):
                    quote = item.pop("quote")
                    if any(token not in mapping for token in residual_tokens(quote)):
                        raise ValueError("LEAN_SECRET_TOKEN_UNKNOWN")
                    # Evidence is checked against its source; this never constructs a request.
                    quotes.append((name, index, TOKEN_RE.sub(
                        lambda match: mapping[match.group(0)], quote)))
    restored = restore_secrets(prepared, mapping)
    for name, index, quote in quotes:
        restored[name][index]["quote"] = quote
    return restored
