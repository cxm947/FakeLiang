---
name: tcp-reachability
description: 从本步执行面确认到目标主机某 TCP 端口能否建立连接，用于 hacl/ netAccess 的端口级可达性事实。适用：事实带 protocol=tcp 与 port；只做一次只读连接探测，不做协议交互、不发载荷。ICMP 回应不能替代端口可达。
metadata:
  predicates:
  - hacl
  - netAccess
  platforms:
  - any
  keywords:
  - hacl
  - tcp
  - 端口
  - 可达
  - 连通
  - reachability
  - Test-NetConnection
  - nc
  - "port 445"
  categories:
  - reachability
  aliases:
  - tcp reachability
  - 端口可达
  - 端口连通
  - connect
  parameters:
  - source_host
  - target_host
  - protocol
  - port
  when:
    scope: network
    protocol: tcp
  requires: []
  excludes:
  - icmp_only
  carriers:
  - kali
  - shell
  - meterpreter
---

# TCP 端口可达性确认

## 适用场景

本步要证明的是 `hacl(源,目标,tcp,端口)` / `netAccess(目标,tcp,端口)`：**从本步绑定的执行面能建立到目标端口的 TCP 连接**。

- 只读：一次连接探测（必要时同价重试一次），不做协议握手、不发利用载荷、不改目标状态。
- ICMP 通不代表端口开；**不要用 ping 代替端口探测**。
- 不适用：要证明服务是什么产品/版本 → 服务识别类方法；要拿到执行权限 → 那是别的节点。
- 端口开放不说明服务正确、认证通过或存在漏洞。

## 参数

- 输入：`target_host`（图上的目标地址）与 `port`；来自图与本步上下文，**不得杜撰**
- 交付：evidence
- 执行位置：position（本步绑定的执行面）
- 可用工具：cmd、code

## 步骤

**进入条件**：目标地址与端口已由运行层给出；缺地址或端口就说明缺什么，不换目标、不扩端口范围。

**一条一个动作块**：只发一次探测。

POSIX 执行面（一条命令行）：

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"timeout 8 bash -c 'cat < /dev/null > /dev/tcp/<目标地址>/<端口>' && echo TCP_OPEN || echo TCP_CLOSED"}}
```

执行面没有 `/dev/tcp` 时用它已有的客户端，仍是同一次只读探测：

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"nc -z -w 5 <目标地址> <端口> && echo TCP_OPEN || echo TCP_CLOSED"}}
```

Windows 执行面按**目标端口**选一条，都是只读探测，`name` 一律写 `cmd`：

```text
445（SMB）：{"tool":"cmd","target":"session","arguments":{"interpreter":"cmd","command":"net view \\\\<目标地址>"}}
其它端口且 powershell 存在：{"tool":"cmd","target":"session","arguments":{"interpreter":"cmd","command":"powershell -NoProfile -Command \"$c=New-Object Net.Sockets.TcpClient; try { $c.Connect('<目标地址>',<端口>); 'TCP_OPEN' } catch { 'TCP_CLOSED: ' + $_.Exception.Message } finally { $c.Close() }\""}}
其它端口且没有 powershell：{"tool":"cmd","target":"session","arguments":{"interpreter":"cmd","command":"certutil -urlcache -split -f http://<目标地址>:<端口>/agv-probe %TEMP%\\agv-probe"}}
```

**Windows 判读**：`net view` 出现 `命令成功完成` 或共享列表 = 445 可达（SMB 客户端已建立连接）；出现 `找不到网络路径`、`系统发生 53`、`拒绝访问` 中的“网络路径不通”语义 = 不可达。
`certutil` 出现 `拒绝`/`无法连接` = 端口关闭；`超时` = 过滤或不可达；`%TEMP%\agv-probe` 写入成功 = 端口可达。
PowerShell 在这台镜像上可能不存在（`'powershell' 不是内部或外部命令`）——那是**工具缺失**，换下一条等价值，不算端口不通。

**回执读法**：`TCP_OPEN`、`open`、`succeeded` 即连上；`TCP_CLOSED`、`Connection refused`、`filtered`、`Unreachable` 是没连上；`command not found`、超时、回执截断属**未知**（可换一个等价客户端再试一次，仍不行就记未知并写明缺什么）。

**判据**：明确连上 → `passed`；明确拒绝或无路由 → `failed`；工具缺失、结果不可判读或预算耗尽 → `unknown`。

**停止边界**：一次调用只做一次探测；不追加协议交互、不换目标、不扩端口范围、不改用利用手段。

## 完成依据

`finish.verdict` 判"这个端口此刻是否可达"，不是"探测命令是否跑完"。

证据字段：`call_id`、`target_host`、`port`、`tool_used`、`connective_result`（`open` / `refused` / `filtered` / `unknown`）；原始输出保留在 `stdout`。

- 明确建立连接 → 通过。
- 明确拒绝/无路由/重试后仍超时 → 不通过。
- 工具缺失或结果不可判读 → 未知。

## 失败条件

- 工具缺失、参数写错、回执截断、执行通道没接上 → **未知**；这些不是"端口不通"的反证。
- 单次超时不等于端口关闭（可能被过滤）；判"不通过"要写清依据。
- 用 ICMP ping 的结果替代端口探测 = 证据类型不对，按未知处理。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
