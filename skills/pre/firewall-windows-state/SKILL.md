---
name: firewall-windows-state
description: 查询 Windows 防火墙有效策略及网络类别，判断是否符合预期启用状态。
metadata:
  predicates:
  - isFirewall
  platforms:
  - windows
  keywords:
  - isFirewall
  - firewall
  - state
  - windows
  - profiles
  - 防火墙
  - 状态
  categories:
  - firewall-state
  aliases:
  - 防火墙
  - netsh advfirewall
  - Get-NetFirewallProfile
  parameters:
  - host
  - state
  when:
    platform: windows
  requires: []
  excludes: []
---

# Windows 防火墙状态检查

## 适用场景

需要目标系统、预期启用状态和查询范围，检查环境应支持 Windows 防火墙只读查询。
检查对象是该系统的生效配置，不是执行入口或某个端口的可达性。

## 参数

- 输入：本页「适用场景」声明的目标、地址/端口、平台与执行面；由运行层给出，**不得杜撰**
- 交付：evidence
- 执行位置：position
- 可用工具：cmd、code（脚本类步骤用 code + python3，命令类步骤用 cmd）


## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

```text
Windows：{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"<本卡方法里那一条命令行>"}}
Linux：  {"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"<本卡方法里那一条命令行>"}}
```


1. 查询网络连接对应的 DomainAuthenticated、Private 或 Public 类别。
2. 查询有效策略存储中的 Domain、Private、Public 配置及 Enabled 值。
3. 将连接类别对应到配置文件，说明当前实际适用的配置。
4. 按任务要求比较；多接口或作用域不清时，不随意挑选一个有利结果。

Get-NetConnectionProfile |
        Select-Object InterfaceAlias, NetworkCategory
    Get-NetFirewallProfile -PolicyStore ActiveStore |
        Select-Object Name, Enabled

DomainAuthenticated 对应 Domain；Private/Public 对应同名配置。
ActiveStore 查询有效策略合并结果，不能只看本地持久配置而忽略组策略。
返回中应保留配置名称及 Enabled，不只输出一个没有归属的布尔值。
旧版 Windows 没有 NetSecurity 模块时，可在目标本机使用 `netsh advfirewall show allprofiles`，
保留每个配置的 STATE。若只关心当前网络，可补查 `netsh advfirewall show currentprofile`。

若执行上下文在另一台 Windows 主机，以上本地命令不能代替目标检查。
在已有远程管理通道下，可以让目标执行相同的只读有效策略查询。例如当前身份可使用 PowerShell Remoting 时：

    Invoke-Command -ComputerName $TargetName -ScriptBlock {
        Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled
    }

TargetName 使用已确认的目标主机名；不要为检查改变 TrustedHosts、启用远程管理或修改认证配置。
域环境中已有身份的远程调用优先使用已核实的 DNS 名称；IP 地址调用可能因认证约束失败。
若只有 IP，可在已有可用的只读管理通道查询目标自身 DNSHostName 后使用，不能凭逻辑别名猜测。
例如已允许且可用的 WMI 查询：`(Get-WmiObject -ComputerName $TargetIP -Class Win32_ComputerSystem).DNSHostName`。
也可使用已经具备能力的 CIM 客户端显式查询 ActiveStore。
普通 `Get-WmiObject ... MSFT_NetFirewallProfile` 返回的 Enabled 不单独证明有效策略，不能省略策略存储确认。
远程访问失败不能退回查询来源主机的防火墙再宣称目标通过。

**手工标准（远程 Windows 目标，已有目标凭据/管理通道）**：

- 若执行面就是目标：`netsh advfirewall show allprofiles state`，并用
  `reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\<Profile>" /v EnableFirewall`
  读取 `StandardProfile` / `DomainProfile` / `PublicProfile`。
- 若执行面是另一台 Windows 跳板且运行层已提供目标凭据或既有管理通道：
  1. `wmic /node:<target> /user:<domain>\<user> /password:<secret> process call create "cmd.exe /c netsh advfirewall show allprofiles state > C:\Windows\Temp\agv_fw.out 2>&1"`；
  2. 用 `type \\<target>\C$\Windows\Temp\agv_fw.out` 回读三个 profile 的 STATE；
  3. 本卡只读：不关闭、不修改防火墙；状态不符合预期时如实判“不通过”，交给后续动作阶段处理。
- `ProcessId` / `ReturnValue=0` 只证明进程创建，不能证明批处理执行或防火墙状态；必须回读输出里的三个 profile STATE。
- 没有目标凭据或既有管理通道：记未知，不要查执行面本机的防火墙再冒充目标。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示预算内没有拿到可确认的结果，那是**结果未知**，不是通道失效，也不是命题不成立。

本步判 `通过` 需要出现上面判读表里那一行要求的证据；出现明确反证判 `不通过`；工具缺失、参数错误、输出截断、通道中断一律 `未知`。

**停止边界**：本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。


## 完成依据

- 相关配置明确一致且符合预期状态：通过。
- 相关配置明确与要求相反：不通过。
- 所有配置同为开启或关闭，可支持相应的整体状态结论。
- 多个配置状态混杂、接口对应不明、没有足够作用域信息：未知，并说明差异。
- 查询失败、访问拒绝、缺少命令、返回截断：未知。

未知时补查缺失的网络类别或有效配置，不使用 Set-NetFirewallProfile、
服务启停或修改规则来验证，也不根据某端口超时反推防火墙开关。

## 失败条件

- 检查工具不存在、参数错误、输出被截断或执行通道中断 → 未知；这些都不是命题不成立的反证。
- 本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
