---
name: service-posix-process
description: 使用服务管理器或进程信息，判断 POSIX 环境中指定服务或程序是否存在并运行。
metadata:
  predicates:
  - networkServiceInfo
  platforms:
  - linux
  keywords:
  - service
  - presence
  - local
  - process
  - 服务存在
  - 进程
  categories:
  - service-presence
  aliases:
  - 进程
  - ss
  - netstat
  - systemctl
  parameters:
  - service
  - port
  when:
    platform: linux
  requires: []
  excludes: []
---

# POSIX 本地服务检查

## 适用场景

需要目标系统、预期服务或程序，以及已知的服务单元/进程名映射。
查询环境必须能观察目标系统 的服务或进程。执行位置与连接方式由运行层确定。
不验证版本、服务账号权限，不因软件已安装就视为服务在运行。

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

**`tool=session` 只用于会话自己的控制台命令，不是系统 shell。** 绑定 Linux 会话时，进程/服务检查用
`cmd`（sh）或 `code`（python3），`via=session`；第一次用错工具得到 `Unknown command` 时，换工具形状，
不要原样重发。


1. 判断检查对象对应服务管理器单元还是进程；名称不明确时先做只读识别。
2. 使用已有服务管理器，或在可见进程范围内按已知可执行名查询。
3. 记录精确名称、进程 ID 或 ActiveState/SubState，避免把查询命令自身匹配进去。
4. 确认查询范围完整后，区分未找到与权限受限造成的不可见。

有明确 systemd 单元映射时：

    systemctl show example.service --property=Id,LoadState,ActiveState,SubState

已有精确进程名映射时：

    pgrep -x -a example-process

这里的名称只是参数示意。pgrep 的名称匹配受进程名长度及平台行为影响，
较长名称应使用可验证的进程详情，不靠宽泛 grep 子串判断。
不要整份传回包含凭据的无关进程参数。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示预算内没有拿到可确认的结果，那是**结果未知**，不是通道失效，也不是命题不成立。

本步判 `通过` 需要出现上面判读表里那一行要求的证据；出现明确反证判 `不通过`；工具缺失、参数错误、输出截断、通道中断一律 `未知`。

**停止边界**：本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。


## 完成依据

| 观察 | 结论 |
|---|---|
| 匹配服务运行中，或精确对应的进程存在 | 通过 |
| 完整查询明确服务未运行/不存在，且没有等价运行实例 | 不通过 |
| 名称映射不明、进程可见性受限、工具查询错误 | 未知 |

systemctl 命令自身成功只说明查询完成，需看 ActiveState。
未知时根据错误选择其他只读观察方式，不安装、启动或修复服务。

## 失败条件

- 检查工具不存在、参数错误、输出被截断或执行通道中断 → 未知；这些都不是命题不成立的反证。
- 本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
