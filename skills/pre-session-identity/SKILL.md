---
name: pre-session-identity
description: 观察一条既有会话的实际身份与所在主机，并交付带来源与时刻的观测。适用：只观察既有会话，不续租、不重连、不重建。检索关键词：会话身份查询、当前会话身份确认、会话执行身份观测
id: pre.session_identity
kind: recon
runs_at: position
delivers: ["evidence"]
inputs: {"session_ref":{"from":"runtime"}}
tools: ["cmd", "msf"]
---

# 既有会话的身份与主机观测

## 何时用

拿到会话后、用它执行动作前，或失败追溯时，只读观测该通道当前身份、主机及能力线索。
- **会话边界**：不续租、不重连、不重建。
session_ref 必须来自运行层，不得杜撰。
本卡只说明谁在何处执行，不判身份够不够；权限要求由需要它的节点或 post.identity 判断。常驻端点、SSH、web 等驱动只决定观察入口，不改解析口径。工具说明：skills/_tooling/posix-shell.md。

## 怎么做

命令用本卡声明的工具面交给绑定位置：`position_speaks=shell` 用位置自己的 shell；`position_speaks=meterpreter` 仍提交 `{"tool":"cmd","cmd":"…"}`，由引擎包装并回收回显。不要改用 `execute -f <shell> -a "<命令行>"`：`Process NNNN created.` 没有命令输出，不能作查询证据。

**Windows 与 Linux 模板按已绑定平台互斥选择，一次调用只选一个，不自行换模板追加查询。**
按平台取最小探针；分段标记便于从可能改写命令的 web 通道回显切片，优先单命令，避免复杂引号：

```
echo <marker>user ; whoami ; echo <marker>host ; hostname      :: Windows
echo <marker>user ; id -un ; echo <marker>host ; hostname      :: Linux
```

需要权限线索时可读 whoami /groups（Windows）或 id -Gn（Linux），仍只观察，不据此作达标结论。
- **动作边界**：只做本次身份/主机观察，不顺手扩展动作。

## 怎么判

- 成功：本次调用从指定会话读回身份与主机（session_identity_present）。
- 不确定：通道无回显，不能推断会话不存在；主机名与预期不符时按公共目标核对记不确定，交 host-map 或人工对齐。

证据字段：call_id、session_identity、session_host。保留本次原文；可核对引文不等于业务结论成立，身份是否足够仍由所需节点判断。
Windows 本地化只影响组名、不影响用户名，解析取用户名；容器 hostname 可能为短 ID，是观察事实，不当作错误。
- **观测边界**：同一通道在不同阶段身份变化可以正常，以本次调用为准，不借历史身份补结论。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
