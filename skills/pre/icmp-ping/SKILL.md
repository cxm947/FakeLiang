---
name: icmp-ping
description: 使用系统 ping 检查指定来源到目标是否存在 ICMP 回应，区分不可达与检查工具故障。
metadata:
  predicates:
  - hacl
  platforms:
  - any
  keywords:
  - ping
  - ICMP
  - 网络可达
  categories:
  - reachability
  aliases:
  - ping
  - icmp
  - 网络可达
  parameters:
  - source_host
  - target_host
  - protocol
  when:
    scope: network
    protocol: icmp
  requires: []
  excludes: []
---

# ICMP 回应检查

## 适用场景

- 需要明确的来源、目标主机或地址及地址族，目标从任务输入取得。
- 根据执行环境选择系统 ping 实现；目标操作系统不限，发起位置由运行上下文提供。
- 检查条件是“本次是否收到目标的 ICMP 回应”。本方法不验证 TCP/UDP 服务端口；如果任务要求端口连通，选择相应方法，不能以 ping 代替。

## 参数

- 输入：本页「适用场景」声明的目标、地址/端口、平台与执行面；由运行层给出，**不得杜撰**
- 交付：evidence
- 执行位置：position
- 可用工具：cmd、code（脚本类步骤用 code + python3，命令类步骤用 cmd）


## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"<本卡方法里那一条命令行>"}}
```

按绑定平台抄一条；**不要用 `tool=session`**（那是会话自己的控制台，不是系统 shell）：

```text
Windows 绑定：{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"ping -n 2 -w 2000 <target>"}}
POSIX 绑定  ：{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"ping -c 3 -W 2 <target>"}}
```

**不要用 PowerShell、`Test-NetConnection` 或 TCP 端口探针代替 ping**；hacl 只接受 ICMP echo reply。


1. 核对目标地址与任务目标 一致，选择 IPv4 或 IPv6 参数。
2. 发送少量 echo 请求（Windows 用 `-n 2`，避免首条一次性命令的输出窗口被长 ping 拖过），同时设置次数、单次等待和总等待上限。
3. 保留目标、回复来源、发送/接收数量、丢包率、错误及退出码。
4. 判断是否至少收到一次匹配目标的 echo reply，不要求零丢包。

以下为 iputils 参数，地址应替换为当前输入：

    ping -n -c 3 -W 2 -w 8 192.0.2.10
    ping -6 -n -c 3 -W 2 -w 8 2001:db8::10

-n 禁用反向解析，-c 限制次数，-W 限制单次等待，-w 限制总等待。
其他 ping 实现的参数含义可能不同，应按其帮助信息调整。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示预算内没有拿到可确认的结果，那是**结果未知**，不是通道失效，也不是命题不成立。

本步判 `通过` 需要出现上面判读表里那一行要求的证据；出现明确反证判 `不通过`；工具缺失、参数错误、输出截断、通道中断一律 `未知`。

**停止边界**：本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。


## 完成依据

| 实际返回 | 结论 |
|---|---|
| 正确目标有 echo reply，接收数量大于零 | 通过，包括部分丢包 |
| 正常完成但接收为零，或明确返回目标不可达/无路由 | 不通过：本次 ICMP 条件不满足 |
| 工具不存在、参数错误、套接字权限不足、输出截断或执行通道中断 | 未知：未完成可靠检查 |

无回应不等于主机关机，也不证明 TCP 服务不存在。退出码需结合输出解释。
未知时依据错误调整工具或参数，不用端口连接代替 ping，不修改网络配置。

## 失败条件

- 检查工具不存在、参数错误、输出被截断或执行通道中断 → 未知；这些都不是命题不成立的反证。
- 本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
