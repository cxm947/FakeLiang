---
name: pre-tool-present
description: 观察指定工具在一个已绑定执行点上是否存在且可用，并交付带来源与时刻的观测。适用：绑定位置与工具名后查询；结论要区分「不存在」与「平台不适用」。检索关键词：工具在位检查、工具安装情况检查、可执行程序存在性检查
id: pre.tool_present
kind: recon
runs_at: position
delivers: ["evidence"]
inputs: {"tool":{"from":"runtime"},"session_ref":{"from":"runtime","optional":true}}
tools: ["pws","cmd","tool", "msf"]
---

# 绑定执行点的工具存在性检查

## 何时用

本卡要确认的事实是“指定外部程序或脚本入口在本执行点能按该名称解析到”，不是“已完成一次查询”；只读检查，不证明功能或版本，版本另观测，功能看实际使用步骤。
tool、session_ref 由运行层提供，不得杜撰。明确控制机本地才可缺省会话；远端会话缺失/不匹配或位置未定时 pending，不回退本地。
区分存在、不存在、平台不适用；后两项不能混同。工具与三平台原语见 skills/_tooling/posix-shell.md。

## 怎么做

命令用本卡声明的工具面交给绑定位置：`position_speaks=shell` 用位置自己的 shell；`position_speaks=meterpreter` 仍提交 `{"tool":"cmd","cmd":"…"}`，由引擎包装并回收回显。不要改用 `execute -f <shell> -a "<命令行>"`：`Process NNNN created.` 没有命令输出，不能作查询证据。

**一次调用只按绑定 shell 选定一个模板；不得换模板追加查询，shell 未定时 pending。**
<tool> 须校验并按对应 shell 引为单个字面名称，不含路径、通配符或命令片段：

```sh
# POSIX shell only; bind <tool> as one literal command name.
command -v <tool>
```

```cmd
rem cmd only; bind <tool> as one literal command name.
where.exe <tool>
```

```powershell
# PowerShell only; bind <tool> as one literal command name.
Get-Command -Name <tool> -CommandType Application,ExternalScript -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Path
```

三个模板是平台分支，不是三步；不启动被查工具取版本，tool_version 未获取就留缺值，不猜填。
**保留完成状态、查询自身退出状态/明确错误类型与原始输出；不得用外层 command_rc=0 或末尾 marker 命令状态代替查询状态。**
不安装、不执行工具、不改 PATH；非交互 PATH 与其他会话可能不同，未找到只说明本执行上下文未解析到。
空输出或任意非零退出码不能直接当作不存在，须按查询工具语义判断。

## 怎么判

**finish.verdict 判断本卡要求的事实是否成立，不是查询是否完成。** 只用 pass / unsatisfied / uncertain；传输成功、查询完成、引文可核对都不能把明确的负事实变成 pass。 明确反证已成立时，不因仅成功才有的字段缺失改判 uncertain。

- **pass（成功）**：freshness 通过，本次调用与执行点已核对，实际解析到指定外部程序或脚本入口，tool_present==true；版本不作通过条件。
- **unsatisfied（不满足）**：查询在适用平台完整完成，对指定名称明确返回不存在（如 result=command_not_found、tool_present=false），必须报 unsatisfied；query_complete=true、外层 command_rc=0 及引文真实都不使该负事实变成 pass。
- **uncertain（不确定）**：平台不适用、查询所需解释器或原语不可用、存在性缺值、未完成、错误不明，或仅别名/函数而不能确认外部入口；查询方法不可用不等于被查工具不存在，缺证据不转 false。

证据字段：call_id、tool、tool_present、tool_path、tool_version。本次可核对引文仅证明观测，仍按上述业务条件判断。

## 异常与恢复

- **停止边界：本次回执已给出当前上下文结论就 finish；仅查到别名/函数、外部入口仍未知时判 uncertain 并结束，不得自行用另一个模板补查。换模板属于下一次调用，须交编排决定。**
- **超时、断连或错误时，保留本次输出与状态；不自行重试、不换名字、不换执行点。**

[共享执行规则](../../src/skills/templates/execution_rules.txt)
