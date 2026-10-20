---
name: icmp-fping
description: 使用 fping 检查指定来源到目标的 ICMP 回应，支持有界的单目标可达性验证。
metadata:
  predicates:
  - hacl
  platforms:
  - any
  keywords:
  - fping
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

# 单目标 fping 检查

## 适用场景

任务指定的来源和目标 IP，以及检查环境中 fping 是否可用。
目标系统不限，执行位置由运行上下文决定。不使用 TCP/UDP 端口作为检查条件。

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
POSIX 绑定  ：{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"fping -r 1 -t 1000 <target>"}}
Windows 绑定：{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"ping -n 2 -w 2000 <target>"}}
```


1. 使用一个明确目标，不生成网段或目标清单。
2. 选择单目标存活检查模式，设置有限超时和重试。
3. 同时保留标准输出、错误输出和退出码，fping 的信息可能出现在错误输出。
4. 核对返回地址，识别 alive、unreachable 或程序级错误。

fping -r 1 -t 1000 192.0.2.10

-r 1 表示工具内部最多再发一次，-t 1000 的单位是毫秒。
这是一次检查内部的有界探测，不改变 Pre 的外层重试预算。
IPv6 使用当前版本支持的 IPv6 模式；不支持时换用系统 ping，不安装工具。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示预算内没有拿到可确认的结果，那是**结果未知**，不是通道失效，也不是命题不成立。

本步判 `通过` 需要出现上面判读表里那一行要求的证据；出现明确反证判 `不通过`；工具缺失、参数错误、输出截断、通道中断一律 `未知`。

**停止边界**：本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。


## 完成依据

| 实际返回 | 结论 |
|---|---|
| 匹配地址 is alive | 通过 |
| 完整单目标检查返回 is unreachable | 不通过 |
| 找不到程序、ICMP socket 权限不足、参数错误、通道中断 | 未知 |
| 只有退出码，没有目标及结果 | 未知，缺少可核对证据 |

未知时可以换用同条件的其他 ICMP 方法，不改成 TCP 握手。
不修改防火墙、路由或权限来获得回应。

## 失败条件

- 检查工具不存在、参数错误、输出被截断或执行通道中断 → 未知；这些都不是命题不成立的反证。
- 本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
