---
name: post-identity
description: 在一次动作之后观测实际执行身份，判断是否达到节点的权限等级要求，并交付带来源与时刻的观测。适用：就地或经会话读取；观察不到就是未知，不得由上下文推断。检索关键词：执行身份达标验证、提权后身份确认、操作后权限复核
id: post.identity
kind: validation
runs_at: position
delivers: ["evidence"]
inputs: {"session_ref":{"from":"runtime"},"required_level":{"from":"runtime","optional":true}}
tools: ["cmd", "msf"]
---

# 动作后实际执行身份的权限复核

## 何时用

在声称提权或系统级执行的动作后，只读复核实际身份是否达到节点要求；系统级/root 按权限等级等价，不要求标识符字面相同。
pre.session_identity 只在动作前观测，本卡判动作结果；凭据可用性归 pre.credential_valid，文件存在性归 post.file_present。
就地优先；经会话读取须记录 session_ref，且必须是动作后的那条通道。节点 required_level（user/admin/system）由运行层提供、判定侧读取，不得杜撰。工具说明：skills/_tooling/posix-shell.md。

## 怎么做

命令用本卡声明的工具面交给绑定位置：`position_speaks=shell` 用位置自己的 shell；`position_speaks=meterpreter` 仍提交 `{"tool":"cmd","cmd":"…"}`，由引擎包装并回收回显。不要改用 `execute -f <shell> -a "<命令行>"`：`Process NNNN created.` 没有命令输出，不能作查询证据。

按平台读取真实身份与主机；标记块切片，不凭输出包含 admin 字样判断：

```
echo <marker>user ; whoami ; echo <marker>host ; hostname      :: Windows
echo <marker>user ; id -un ; echo <marker>host ; hostname      :: Linux
```

辅助线索可选 Windows 的 whoami /groups、whoami /priv，或 Linux 的 id -u（uid=0）、非交互式提权检查返回；whoami/id -un 读取用户名。任一驱动都经绑定通道，等级映射在判定侧。
模型只选择探针/平台分支与必要组、特权线索，不改 marker 包裹、等级映射或判据。

## 怎么判

- 成功：本次实际身份达到或超过节点要求（observed_privilege_at_least_node_requirement）。
- 不满足：观测身份低于要求，交方法侧调整方法，不改判据。
- 不确定：无回显或不可解析，拿不到身份。

**观察不到就是未知，不得由上下文推断。**

证据字段：call_id、session_identity、session_host、observed_privilege，并保留原始身份字符串。本次可核对引文仅证明观测，仍须按权限条件判断。
按既有等级映射区分系统账户与服务账户，并沿用域管在成员机等价系统级的规则，不另加名称判断。
UAC/令牌过滤下，管理员组在高完整性与普通进程中的权限不同，须交代探针上下文。
**复核必须用动作后的那条通道；不能借其他通道或历史结果补证明。** 提权为会话级，换通道可能回到原身份。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
