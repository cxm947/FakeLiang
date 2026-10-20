---
name: post-network-access
description: 核验 netAccess 事实：在节点绑定的来源通道上对目标地址与端口做一次只读连接观测，证明该网络路径此刻可达或不可达。只读，不改目标状态。
metadata:
  predicates: [netAccess]
  categories: [reachability]
  aliases: [网络可达, 连通性, net access, tcp connect, nc, test-netconnection, 端口可达]
  parameters: [source_host, target_host, protocol, port]
  when:
    scope: network
    condition: 事实谓词是 netAccess；绑定通道就是事实的来源主机
  requires: [bound_channel]
  excludes: [execCode, getAccount, pathExists]
  platforms: [windows, linux]
  keywords: [netAccess, 网络可达, 连通性, tcp, port, nc, test-netconnection, /dev/tcp, post]
  resources: []
---

# 网络可达性核验

## 适用场景

节点输出是网络可达性事实：`netAccess(source, protocol, port)`。

- 只回答：从**本节点绑定的来源通道**到目标地址与端口，此刻能不能建立连接。
- 不回答服务版本、认证、业务响应；也不判断目标服务是否健康。
- 绑定通道不是事实里的来源主机时，本卡不适用，按未知处理。

## 参数

- 输入 `session_ref`：来自 runtime（本节点绑定的那条通道，即事实的来源）
- 输入 `target_host` / `target_address`：来自 `context.hosts`
- 输入 `port`：来自事实参数
- 交付：evidence
- 执行位置：position
- 可用工具：`cmd`

## 步骤

**进入条件（先看这条）**：本节点绑定的通道**已经登记**，且它就是事实里的来源主机。缺通道或来源不一致就报告缺什么，**不要新建会话、不要换通道**。

**一条一个动作块**：只发一次连接观测。

```text
POSIX 绑定（platform=linux）：
{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"echo AGV_POST_NONCE=<本次 nonce>; nc -z -w 5 <target_address> <port> && echo OPEN || echo CLOSED"}}

Windows 绑定（platform=windows）：
{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"echo AGV_POST_NONCE=<本次 nonce> & powershell -NoProfile -Command \"if (Test-NetConnection -ComputerName <target_address> -Port <port> -InformationLevel Quiet) { 'OPEN' } else { 'CLOSED' }\""}}
```

地址必须用 `context.hosts` 里的真实值，不要写示例地址，也不要换成别的目标。

POSIX 的 `nc -z -w <1..10>` 形状是 Post 网关的闭式语法；不要改成 `/dev/tcp`、`timeout bash -c` 或别的组合，否则会被判“未执行”。

**回执读法**：`stdout` 是目标回显原文；`nonce_observed` 必须等于本次 nonce。`OPEN` / `CLOSED` 必须由目标侧执行后返回。

**判据**：

- `OPEN` 且身份/主机对得上 → **通过**；
- `CLOSED` 且观测本身有效（nonce 回读、无工具错误） → **不通过**（路径不可达）；
- 超时、工具缺失、标记缺失、`effect_known=false` → **未知**（不能把“没测成”当成“不可达”）。

**停止边界**：本卡一次调用只做一次连接观测；不由本卡重试、换端口、换工具或改用认证探测。

## 完成依据

`finish.verdict` 判的是“来源到目标的这条路径是否可达”，不是“命令是否跑完”。

证据字段：`call_id`、`nonce`、`source_host`、`target_address`、`port`、`result`（TCP_OPEN/TCP_CLOSED）；原始输出保留在 `stdout`。

三档：OPEN → 通过；CLOSED 且有有效观测 → 不通过；观测失败 → 未知。

## 失败条件

- 通道缺失、来源不一致、标记缺失、工具错误 → **未知**。
- `TCP_CLOSED` 可能是策略丢包，也可能端口未开；对 `netAccess` 这条事实，它就是“不可达”的有效反证，但不等于服务本身坏掉。
- 不得用 `ping` 代替端口连接；`netAccess` 判的是指定协议与端口。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
