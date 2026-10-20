---
name: service-windows-query
description: 查询 Windows 服务管理器或进程信息，确认指定服务或程序是否存在并运行。
metadata:
  predicates:
  - networkServiceInfo
  platforms:
  - windows
  keywords:
  - service
  - presence
  - local
  - windows
  - 服务存在
  - lsass
  categories:
  - service-presence
  aliases:
  - Windows 服务
  - sc query
  - tasklist
  parameters:
  - service
  when:
    platform: windows
  requires: []
  excludes: []
---

# Windows 本地服务检查

## 适用场景

需要目标系统、预期服务或程序，以及已知服务名/进程名映射。
服务管理器管理的服务使用服务查询；普通系统进程使用进程查询。
例如 lsass 是进程，不应假定存在名为 lsass 的 Windows 服务。
本方法不校验版本或运行账号权限，执行载体由运行上下文提供。
远程 SCM 接口不属于本地服务名称，改用专门的 SCM RPC 接口技能。

## 参数

- 输入：本页「适用场景」声明的目标、地址/端口、平台与执行面；由运行层给出，**不得杜撰**
- 交付：evidence
- 执行位置：position
- 可用工具：cmd、code（脚本类步骤用 code + python3，命令类步骤用 cmd）


## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

**输出纪律**：`content` 只放一条最小命令；不要把本卡说明、示例全文、协议报文或字节数组复制进去。需要脚本时正文也要短。

**本步绑定的是已迁移的 MSF 会话时（默认）**，优先用通道自己的控制台命令，不要再开 PowerShell/cmd 子壳：

- 进程查询：`{"tool":"session_command","target":"session","arguments":{"command":"ps"}}`
- 主机确认：`{"tool":"session_command","target":"session","arguments":{"command":"sysinfo"}}`
- 身份确认：`{"tool":"session_command","target":"session","arguments":{"command":"getuid"}}`
- 一次只查一个对象；`ps` 输出里找到目标进程名/PID 即证据。控制台命令没有结束标记，运行层按静默间隔收口；不要因为“没有 agv-call-end”判未知。

**只有绑定不是 MSF 控制台（plain shell）时**，才用下面这些原生一次性命令（返回后立即退出）：

- 进程查询：`tasklist /FI "IMAGENAME eq <进程名>" /FO CSV /NH`（`tool=cmd`，`name=cmd`）。
- 服务查询：`sc query <服务名>`（`tool=cmd`，`name=cmd`）。
- 一次只查一个对象；不要加 `Select-Object`、`Format-List`、`Out-String` 或分页管道。
- 只有在原生命令不可用或需要额外字段时，才退回下面这条 PowerShell；退回时也只查一个对象。

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"powershell","command":"Get-Process -Name 'lsass' -ErrorAction Stop | Select-Object ProcessName, Id, SessionId | Format-List"}}
```

**`content` 写你声明的那门解释器自己的语法，`name` 写解释器名**（这里是 `powershell`）；运行层按 `name` 构造真正送到执行面的命令行，即上面这条会变成
`powershell -NoProfile -Command "Get-Process -Name 'lsass' …"`。**不要自己在 content 里再套一层 `powershell -Command`**（会变成双层包装）。

进程查询用 `Get-Process -Name '<进程名>' -ErrorAction Stop | Select-Object ProcessName, Id, SessionId | Format-List`；服务查询把 content 换成 `Get-Service -Name '<服务名>' | Select-Object Name, Status, StartType | Format-List`，`name` 仍是 `powershell`。**一次只查一个对象**，把回执里的 `ProcessName/Id`（或 `Name/Status`）留作证据。

**回执读法**：`stdout` 是回显原文，`return_code` 是命令终态。出现对象名与 Id/Status 即本步证据；`-ErrorAction Stop` 报"找不到"说明对象不存在（反证）；`拒绝访问`、命令不存在、回执截断属于未知，不是不存在。

**判据**：对象名与目标一致且状态/标识可读 → 通过；明确报不存在 → 不通过；权限或工具问题 → 未知。


1. 确认对象属于本地服务或进程。
2. 使用精确名称查询，保留对象名称、状态及可用标识。
3. 区分服务名称与显示名称，映射不明时先只读识别，不能随机替换。
4. 解释错误类别，区分不存在与访问拒绝。

Get-Service -Name 'ExampleService' -ErrorAction Stop |
        Select-Object Name, DisplayName, Status
    Get-Process -Name 'ExampleProcess' -ErrorAction Stop |
        Select-Object ProcessName, Id

示例名称应替换为输入及明确映射。输出太多时按对象过滤，不枚举无关程序详情。
认证或权限错误不能伪装成对象不存在。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示预算内没有拿到可确认的结果，那是**结果未知**，不是通道失效，也不是命题不成立。

本步判 `通过` 需要出现上面判读表里那一行要求的证据；出现明确反证判 `不通过`；工具缺失、参数错误、输出截断、通道中断一律 `未知`。

**停止边界**：本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。


## 完成依据

- 匹配服务为 Running，或明确匹配进程存在：通过。
- 完整、可靠查询明确对象不存在或未运行：不通过。
- 名称映射不明、访问拒绝、查询失败或返回不完整：未知。

未知时纠正名称或换适用的只读查询，不启动服务、不更改配置、不获取新凭据。

## 失败条件

- 检查工具不存在、参数错误、输出被截断或执行通道中断 → 未知；这些都不是命题不成立的反证。
- 本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
