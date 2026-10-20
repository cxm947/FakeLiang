---
name: post-identity
description: 在一次动作之后观测实际执行身份，判断是否达到节点的权限等级要求，并交付带来源与时刻的观测。适用：就地或经会话读取；观察不到就是未知，不得由上下文推断。
metadata:
  predicates:
  - execCode
  platforms:
  - any
  keywords:
  - 执行身份达标验证
  - 提权后身份确认
  - 操作后权限复核
  - post.identity
  - validation
  - position
  - cmd
  - msf
  - post
  - identity
  resources: []
  categories:
  - identity-verification
  aliases:
  - 身份
  - whoami
  - id
  - identity
  parameters:
  - session_ref
  - perm
  when:
    scope: identity
  requires: []
  excludes: []
---

## 适用场景

在声称提权或系统级执行的动作后，只读复核实际身份是否达到节点要求；系统级/root 按权限等级等价，不要求标识符字面相同。
pre.session_identity observes the session before action; this card judges the result. LEAF hasAccount/4 uses the unobserved assume_true policy, which proves no credential validity. File presence belongs to post.file_present.
就地优先；经会话读取须记录 session_ref，且必须是动作后的那条通道。节点 required_level（user/admin/system）由运行层提供、判定侧读取，不得杜撰。工具说明：skills/_tooling/posix-shell.md。

## 参数

- 输入 `session_ref`：来自 runtime
- 输入 `required_level`：来自 runtime（可选）
- 交付：evidence
- 执行位置：position
- 可用工具：cmd、msf

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"bash","command":"<本页方法里那一条探针>"}}
```


命令用本卡声明的工具面交给**本步绑定的执行面**，请求对象是四项形状（见下面那一条）；不要用只回一句 `Process NNNN created.` 的形式——它没有可引用的命令输出。

按平台读取真实身份与主机；标记块切片，不凭输出包含 admin 字样判断：

**平台看载体会话，不看节点执行面**：探针的形状由**载体（会话）自己的平台**决定（在 `carrier_export.carrier.platform` 里；节点执行面可能是另一台机器）。把 Windows 载体按 POSIX 写，语法会被观测文法当场拒绝、整步记"通道不可用"（真机第 53 轮就是这么死的）。

```
echo AGV_POST_NONCE=<本次 nonce>; whoami; hostname      :: Windows 载体
echo AGV_POST_NONCE=<本次 nonce>; id -un; hostname      :: POSIX 载体
```

这两句就是**观测文法接受的全部形状**：`echo AGV_POST_NONCE=<nonce>` 打头，两条身份语句各出现一次、用 `; ` 连接，**不追加任何别的命令**。

辅助线索可选 Windows 的 whoami /groups、whoami /priv，或 Linux 的 id -u（uid=0）、非交互式提权检查返回；whoami/id -un 读取用户名。任一驱动都经绑定通道，等级映射在判定侧。
模型只选择探针/平台分支与必要组、特权线索，不改 marker 包裹、等级映射或判据。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；复核模式下没有本次观测，材料是已保存的回执。nonce 必须由目标侧执行后返回，只出现在请求里不算观测。

**停止边界**：本卡一次调用只做本页方法里的一次观测或一次复核；不由本卡重试、追加探针或改换判据。


## 完成依据

- 成功：本次实际身份达到或超过节点要求（observed_privilege_at_least_node_requirement）。
- 不满足：观测身份低于要求，交方法侧调整方法，不改判据。
- 不确定：无回显或不可解析，拿不到身份。

**观察不到就是未知，不得由上下文推断。**

证据字段：call_id、session_identity、session_host、observed_privilege，并保留原始身份字符串。本次可核对引文仅证明观测，仍须按权限条件判断。
按既有等级映射区分系统账户与服务账户，并沿用域管在成员机等价系统级的规则，不另加名称判断。
UAC/令牌过滤下，管理员组在高完整性与普通进程中的权限不同，须交代探针上下文。
**复核必须用动作后的那条通道；不能借其他通道或历史结果补证明。** 提权为会话级，换通道可能回到原身份。

[共享执行规则](../../src/skills/templates/execution_rules.txt)

## 失败条件

- **不满足**：本次动作后的同一通道已观测到实际身份，按既有权限等级映射判定低于节点要求。保留原始身份字符串、主机及权限线索，交方法侧调整方法；不得改变等级判据或仅凭名称包含管理员字样判为通过。
- **不确定**：没有身份回显、回显无法解析，或无法确认观测来自动作后的同一通道，因而拿不到可信的实际身份。必须保留原始返回与缺失项，不得由上下文、另一通道或历史结果补证明。
- UAC 或令牌过滤使权限等级无法确认时，记录探针上下文并判为不确定；已有足够证据证明权限低于要求时判为不满足。

**停止边界**：本卡一次调用只做本页方法里的一次观测或一次复核；不由本卡重试、追加探针或改换判据。
