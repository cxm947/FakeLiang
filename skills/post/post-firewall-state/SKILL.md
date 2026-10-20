---
name: post-firewall-state
description: 核验防火墙状态类事实（disableFirewall / isFirewall）：在绑定通道上只读查询目标主机的防火墙状态，或复核 Action 的关闭回执，判断声明状态是否成立。
metadata:
  predicates: [disableFirewall, isFirewall]
  categories: [firewall-state]
  aliases: [防火墙, firewall, netsh advfirewall, ufw, firewall-cmd, 状态, 关闭防火墙]
  parameters: [host, state]
  when:
    scope: firewall
    condition: 事实谓词是 disableFirewall 或 isFirewall
  requires: []
  excludes: [execCode, getAccount, netAccess]
  platforms: [windows, linux]
  keywords: [disableFirewall, isFirewall, 防火墙状态, netsh advfirewall, ufw, firewall-cmd, post]
  resources: []
---

# 防火墙状态核验

## 适用场景

节点输出是防火墙状态事实：`disableFirewall(host)` 或 `isFirewall(host, state)`。

- 只回答：目标主机此刻的防火墙状态，与事实声明的状态是否一致。
- 不修改规则、不启停服务；关闭动作属于 Action。
- 绑定通道不在目标主机上时，只有 Action 回执能作为证据；不要凭空拼远程调用。

## 参数

- 输入 `session_ref`：来自 runtime（本节点绑定的那条通道）
- 输入 `target_host`：来自事实
- 输入 `state`：来自事实（`disabled` / `enabled`，可选）
- 交付：evidence
- 执行位置：position
- 可用工具：`cmd`

## 步骤

**进入条件（先看这条）**：本节点绑定的通道**已经登记**。缺通道就报告缺什么，**不要新建会话、不要换通道**。

**先判本次有没有观测**：读 `current.observation` 是否为空；运行层已按绑定与目标关系决定是否跳过观测。

- **为空** → 不执行任何探测命令，直接读 `context.action_evidence`。只有回执里明确回读到三个 profile 的 `状态 ... 关闭` 才判**通过**；只有 `[SC] CreateService 成功`、`agv-psexec-command-ok` 这类“命令已执行”的回执，判**未知**（已执行 ≠ 状态成立）。
- **不为空** → 执行下面的只读探测。

**一条一个动作块**：只发一次只读观测。

绑定通道就是目标主机时：

```text
Windows 绑定（platform=windows）：
{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"echo AGV_POST_NONCE=<本次 nonce> & netsh advfirewall show allprofiles state"}}

POSIX 绑定（platform=linux）：
{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"echo AGV_POST_NONCE=<本次 nonce>; (ufw status || firewall-cmd --state || iptables -S)"}}
```

绑定通道不是目标主机时：**不要自己拼远程 netsh / ssh**。只复核 Action 回执里关闭防火墙那条命令的真实输出；回执没有状态证据就判未知。

**回执读法**：`stdout` 是目标回显原文；`nonce_observed` 必须等于本次 nonce。Windows 看 `State ON/OFF`；Linux 看 `Status: active/inactive`、`running/not running` 或规则链。

**判据**：

- `disableFirewall`：目标主机所有 profile 均为 `OFF` / `inactive` → **通过**；任一 profile `ON` / `active` → **不通过**；
- `isFirewall(host, state)`：观测状态与声明状态一致 → **通过**；不一致 → **不通过**；
- 只有 Action 回执、没有当前状态观测 → **未知**（命令成功 ≠ 状态成立）。

**停止边界**：本卡一次调用只发一次观测；不由本卡重试、换远程方式或修改规则。

## 完成依据


**跳板情形的判定（最先看这条）**：当运行层判定本次绑定不能直接观测目标时，本步不会产生 `observation`，`current.observation` 为空是**预期行为**。此时只接受 `context.action_evidence` 中明确回读到的三个 profile `状态 ... 关闭`；仅有服务创建或命令成功标记时判**未知**。
`finish.verdict` 判的是“防火墙状态事实是否成立”，不是“命令是否跑完”。

证据字段：`call_id`、`nonce`、`target_host`、`observed_state`、`action_receipt_ref`；原始输出保留在 `stdout`。

三档：状态与声明一致 → 通过；明确相反 → 不通过；既没有状态输出也没有写入回执 → 未知。

## 失败条件

- 通道缺失、标记缺失、工具错误、权限不足 → **未知**。
- 远程命令没跑通不等于防火墙没关；不要把传输失败当成状态反证。
- 不得用“Action 说关了”替代当前状态观测；回执只证明当时执行过。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
