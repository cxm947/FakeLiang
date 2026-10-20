---
name: firewall-linux-state
description: 读取 Linux 防火墙状态及有效规则，判断是否符合任务要求。
metadata:
  predicates:
  - isFirewall
  platforms:
  - linux
  keywords:
  - isFirewall
  - firewall
  - state
  - nftables
  - iptables
  - 防火墙
  - 状态
  resources:
  - references/backend-state.md
  categories:
  - firewall-state
  aliases:
  - 防火墙
  - ufw
  - firewall-cmd
  - iptables
  parameters:
  - host
  - state
  when:
    platform: linux
  requires: []
  excludes: []
---

# Linux 防火墙状态检查

## 适用场景

需要目标系统、预期启用状态和查询范围，并取得对应系统的只读查询能力。
预期状态来自任务，不默认要求防火墙关闭。
本方法检查系统防火墙状态，不用某个业务端口能否连接代替。

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


1. 核对被查询系统与目标系统 一致。
2. 从已有环境信息确定管理器；未知时只读查询已安装/正在使用的管理器。
3. 选择 [后端状态查询](references/backend-state.md) 中适用的方法，保留状态及有效配置。
4. 区分管理进程运行、管理器启用、内核有效规则这几个不同事实。
5. 将能确认的有效状态与预期状态比较；输出存在矛盾时保持未知并说明缺口。

根据实际后端选择，不要求每个系统都执行全部命令：

    ufw status verbose
    firewall-cmd --state
    firewall-cmd --get-active-zones
    nft list ruleset
    iptables -S

使用当前身份已有的查询权限，不自动提权或安装管理器。
规则输出须保留相关默认策略、基础链及启用信息，不用截断后的一小段作全局结论。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示预算内没有拿到可确认的结果，那是**结果未知**，不是通道失效，也不是命题不成立。

本步判 `通过` 需要出现上面判读表里那一行要求的证据；出现明确反证判 `不通过`；工具缺失、参数错误、输出截断、通道中断一律 `未知`。

**停止边界**：本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。


## 完成依据

| 情况 | 结论 |
|---|---|
| 能确认有效开启/关闭状态，与声明一致 | 通过 |
| 能确认有效状态，与声明相反 | 不通过 |
| 某管理器不存在或未运行，但不知道其他后端状态 | 未知 |
| 无查询权限、返回不完整、管理器与规则含义不能对应 | 未知 |

未知时补查相应后端的只读状态；不得关闭防火墙、清空规则或改变策略。

## 失败条件

- 检查工具不存在、参数错误、输出被截断或执行通道中断 → 未知；这些都不是命题不成立的反证。
- 本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
