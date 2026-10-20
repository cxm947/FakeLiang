---
name: post-account-local
description: 核验本机账号事实（getAccount / hasAccount 的本地账号分支）：在节点绑定的通道上确认执行身份、主机与该账号在本机存在，并复核 Action 回执里的材料是否属于同一账号、同一主机、同一权限。只读，不做登录测试。
metadata:
  predicates: [getAccount, hasAccount, leakAccount, weakAccount]
  categories: [credential-existence]
  aliases: [本机账号, 本地账号, local account, net user, 账号存在, 凭据存在, 凭据核验]
  parameters: [host, user, perm]
  when:
    scope: local
    condition: 事实的账号不带域限定符，或限定符就是绑定主机本身
  requires: []
  excludes: [domain_account]
  platforms: [windows, linux]
  keywords: [getAccount, hasAccount, 本机账号, 本地账号, local account, net user, 账号存在, 凭据核验, identity, post]
  resources: []
---

# 本机账号核验

## 适用场景

节点输出是**本地账号**类事实：`getAccount(host,user,credential,perm)`、`hasAccount(...)` 的本地分支。

- 只回答：这条通道上的执行身份、主机，以及该账号在本机 SAM / passwd 里是否存在。
- **不回答**“这把凭据能不能登录”——那需要认证动作，不属于只读 Post。
- 账号带域限定符时改用 `post-account-domain`，不要在本卡里用 `net user` 猜域账号。

## 参数

- 输入 `session_ref`：来自 runtime（本节点绑定的那条通道）
- 输入 `account`：**以 Action 回执里的 `Username` 为准**；图里的 `user` 是符号名，不是真实账号
- 输入 `required_level`：来自 runtime（可选，取自节点的 `perm`）
- 交付：evidence
- 执行位置：position
- 可用工具：`cmd`

## 步骤

**进入条件（先看这条）**：本节点绑定的通道**已经登记**（`context.execution`）。缺通道就报告缺什么，**不要新建会话、不要换通道、不要起监听**。

**一条一个动作块**：只发一次观测请求。

观测报文的 `name` 与连接符都要跟绑定平台一致：

```text
Windows 绑定（platform=windows）：
{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"echo AGV_POST_NONCE=<本次 nonce> & whoami & hostname & net user <account>"}}

POSIX 绑定（platform=linux）：
{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"echo AGV_POST_NONCE=<本次 nonce>; id -un; hostname; getent passwd <account>"}}
```

把 POSIX 那行发到 Windows 会话（或反过来）会把整行变成一个 echo，标记不会单独成行 → 按“没拿到可确认观测”处理。

**回执读法**：`stdout` 是目标回显原文；`nonce_observed` 必须等于本次 nonce。身份行、主机行、账号行分别来自上面三条语句的输出。`effect_known=false` 或标记缺失 → 未知。

**判据**：

- 通道身份与主机对上节点目标，**且** Action 回执里出现能归到该账号（用户名一致）、该主机、该权限（system/root 等价口径）的材料 → **通过**；
- 机器明确回答账号不存在（`net user` 报“找不到”，且不是权限或工具问题），或 Action 回执明确给的是别的账号/别的主机 → **不通过**；
- 只有身份观测、没有账号结论，或材料缺失/对不上号 → **未知**。

**停止边界**：本卡一次调用只发一次观测；完成即结束，不由本卡重试、追加探针、改用凭据登录或改换判据。

## 完成依据

`finish.verdict` 判的是“这个本地账号的事实是否成立”，不是“命令是否跑完”。

证据字段：`call_id`、`nonce`、`session_identity`、`session_host`、`account_exists`、`credential_material_ref`；原始输出保留在 `stdout`。

三档：身份与主机对得上、且材料能归到该账号/该主机/该权限 → 通过；账号明确不存在、或材料明确属于别的账号/主机 → 不通过；只有其中一半 → 未知。

## 失败条件

- 通道缺失、观测未取回、标记缺失、报文形状不在闭集内 → **未知**；这些都不是“凭据不成立”的反证。
- 账号存在 ≠ 凭据有效；材料存在 ≠ 材料当前有效。两者都不能单独判通过，也不能反推不通过。
- 域账号、域控可达性、认证验证都不属于本卡；选错卡不会让事实变成不通过，只会判未知。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
