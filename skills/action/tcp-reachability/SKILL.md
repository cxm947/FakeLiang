---
name: tcp-reachability
handover: session
description: 确认从本步执行面到目标主机某个 TCP 端口是否可达（netAccess 事实），并交付可引用的连接证据。适用：节点产出是"能连上某端口"；只做一次只读连接探测，不做协议交互、不发利用载荷。
metadata:
  predicates:
  - netAccess
  platforms:
  - any
  keywords:
  - netAccess
  - tcp
  - 可达
  - 连通
  - reachability
  - 端口探测
  - port
  - nmap
  - method
  - position
  resources: []
  categories:
  - reachability
  aliases:
  - TCP
  - 连通性
  - connect
  - nc
  parameters:
  - source_host
  - target_host
  - protocol
  - port
  when:
    scope: network
  requires: []
  excludes: []
  carriers:
  - kali
  - shell
serves:
- netAccess
---

# TCP 可达性确认

## 适用场景

节点产出是 `netAccess(host,protocol,port)`：要证明**从本步执行面能建立到目标端口的 TCP 连接**。

- 只读：只做一次连接探测（必要时代价最小的一次等价重试），不做协议握手、不发利用载荷、不改目标状态。
- 不适用：要证明"该服务是某产品/某版本"→ 用服务识别类方法；要拿到执行权限 → 那是别的节点。
- 连通性只说明"这个端口此刻能连上"，不说明服务正确、认证通过或存在漏洞。

## 参数

- 输入 `target_host`、`port`：来自图与本步上下文（**不得杜撰**）
- 交付：evidence
- 执行位置：position（本步绑定的执行面）
- 可用工具：cmd、code
- 图适用：predicate=netAccess

## 步骤

**进入条件（先看这条）**：目标地址与端口来自图（`context.children` 与 `hosts`），执行面就是本步绑定的入口。缺地址或端口就先说明缺什么，不要自己换目标或扩范围。

**一条一个动作块**：只发一次探测请求。

首选形状（POSIX 执行面，一条命令行）：

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"timeout 8 bash -c 'cat < /dev/null > /dev/tcp/<目标地址>/<端口>' && echo TCP_OPEN || echo TCP_CLOSED"}}
```

执行面没有 `/dev/tcp` 时用**它已有的**客户端，仍是同一次只读探测：

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"nc -z -w 5 <目标地址> <端口> && echo TCP_OPEN || echo TCP_CLOSED"}}
{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"nmap -n -sT -p <端口> --reason <目标地址>"}}
```

（Windows 执行面把 content 换成 `Test-NetConnection -ComputerName <地址> -Port <端口>` 之类的一次只读探测，`name` 写 `powershell`。）

**回执读法**：`stdout` 是执行面回显原文；出现 `TCP_OPEN`、`open`、`succeeded` 即连上；`TCP_CLOSED`、`Connection refused`、`filtered`、`Unreachable` 是没连上；`command not found`、超时、回执截断属**未知**（换一个等价客户端最多再试一次，仍不行就记未知，写明缺什么）。

**判据**：明确连上 → `passed`；明确拒绝或无路由 → `failed`；工具缺失、结果不可判读或预算耗尽 → `unknown`。

**停止边界**：本卡一次调用只做一次探测；不由本卡追加协议交互、换目标、扩端口范围或改用利用手段。

## 完成依据

`finish.verdict` 判的是"这个端口此刻是否可达"，不是"探测命令是否跑完"。

证据字段：`call_id`、`target_host`、`port`、`tool_used`、`connective_result`（`open` / `refused` / `filtered` / `unknown`）；原始输出保留在 `stdout`。

三档：明确建立连接 → 通过；明确拒绝/无路由/超时且重试后仍如此 → 不通过；工具缺失或结果不可判读 → 未知。

## 失败条件

- 工具缺失、参数写错、回执截断、执行通道没接上 → **未知**；这些都不是"端口不通"的反证。
- 单次超时不等于端口关闭（可能被过滤）；判"不通过"要写明依据（拒绝/无路由）而不是只凭超时。
- 端口开放不等于服务正确、认证通过或存在漏洞；本卡只为 `netAccess` 那条事实出证据。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
