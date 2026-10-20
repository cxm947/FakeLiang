---
name: wmi-firewall-off
handover: session
description: WMI 进程创建 + 管理共享投递 — 从 Windows 主机远程关防火墙（T1562.001 · wmi/135 + smb/445）
metadata:
  predicates:
  - T1562.001
  platforms:
  - linux
  - windows
  keywords:
  - exploit.wmi_firewall_off
  - method
  - position
  - tool
  - cmd
  - pws
  - msf
  - T1562.001
  - wmi
  - firewall
  - 'off'
  resources: []
  categories:
  - action-method
  aliases:
  - wmic
  - firewall
  - netsh
  parameters:
  - host
  - credential
  when:
    method: wmi
  requires: []
  excludes: []
  carriers:
  - kali
  - shell
serves:
- scm
- remoteDisableDefenses
---

## 适用场景

目标为 Windows，135/WMI 可达、445 管理共享 `C$` 可写，凭据有远程 WMI 权限；执行点为已绑定的 Windows 源主机会话。
该路线适用于控制端不能直达目标网段的情况。没有 Windows 源主机、或目标只有 445 可达时不适用；原有另一方法是 `exploit.netexec_firewall_off`。
源主机须有 PowerShell、`net.exe`、`wmic`、`cmd.exe`，目标须有 `reg`、`netsh`。
`net use` 的 `IPC$` 认证需要明文口令，不支持把 NTLM 哈希当口令传入。
- 先按入口支持的表示排序：`mode: password` 在 `mode: ntlm` 前；同表示内 `order=1 / origin=derived` 优先于 `order=2 / origin=external`，来源不丢。
候选的 order 是运行侧实际排序后的序号；上述 derived / external 次序只用于同一表示的比较，不把来源固定绑定到序号。
- 哈希仅用于 `-H` / `--hashes` 等支持哈希的槽位，不能塞进 `net use`、`/password:`、`/p`、`/rp`、`-p` 的口令槽位；本路线不支持的材料类型在执行前说明，不冒充认证失败。
- 只有一份候选就只用该份；旧 `credential_ref` 指第一份。都没有时以 `CREDENTIAL_MISSING` 拒绝，不猜账号、默认口令或未提供材料。

## 参数

- 输入 `target_host`：来自 graph
- 输入 `credential_ref`：来自 graph
- 输入 `session_ref`：来自 runtime
- 交付：evidence
- 执行位置：position
- 可用工具：tool、cmd、pws、msf
- 图适用：technique=T1562.001

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

**一次回答一个动作，读取回执后再发下一动作。点火与输出回读必须分开发送；不得把点火、原地等待、回读塞进同一调用。**
Windows 命令写成 `{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"<一条命令行>"}}`；运行层在**本步绑定的那条会话**上执行并把回执原样带回，不发送 `actions` 数组。
不要用 `execute -f <shell> -a "<命令行>"` 代替可回显动作；`Process NNNN created.` 没有命令输出，不足以判断结果。
凭据与远程执行由运行层完成。需要认证时只发：
```text
{"tool":"remote_process","target":"kali","arguments":{"host":"<host>","command":"cmd /c netsh advfirewall set allprofiles state off","credential_ref":"<运行层给出的引用>","method":"wmic"}}
```
运行层解析凭据并执行；模型不写 `net use`、`wmic /password:`、`schtasks /p`
或任何明文/哈希。`credential_ref` 取 `context.node.credential`；没有就留空。

目标、凭据、会话使用入口已绑定值，marker 对应本次调用；关闭动作与回读分开，
回读交给 Post。

本步判 `passed` 需要出现本卡要求的证据；出现明确失败条件判 `failed`；证据不足或效果未确认判 `unknown`，不拿「请求已发出」代替证据。

**停止边界**：本卡一次调用只做本页列出的动作；完成即结束，不由本卡重试、追加动作、换通道或改变判据。


## 完成依据

本卡只判“关闭动作已经执行并拿到回执”：`remote_process` 返回
`effect_known=true`，且回执没有认证失败或参数错误。回执里的 `ReturnValue = 0`
只说明进程创建成功，**不说明防火墙已关闭**。

`firewall_state` 由 Post 的防火墙状态卡独立回读；本卡不把“命令已发出”或
“进程已创建”当成状态证据，也不在这里追加回读探测。

## 失败条件

**账号锁定立即停止，不再试第二份。结果尚未明确时遵守运行层停止要求；首次成功后不为用完候选列表追加认证。**
- 本次认证响应明确 `STATUS_LOGON_FAILURE`、`STATUS_WRONG_PASSWORD`、`STATUS_NO_SUCH_USER`、Windows 1326，或可核对的域/主体不匹配（例如请求域与目标返回的认证域明确冲突），才记录 call_id/原文并考虑下一候选；运行层不自动重试。
- 认证后的 `STATUS_ACCESS_DENIED` / Windows 错误 5 只说明权限不足，不触发换材料；类型不支持同样不属于错误口令证据。
- 用注册表 `0x0` / `0x1` 避免 `netsh … show … state` 本地化文本；目标非 UTF-8 输出按目标代码页（如 GBK）解码后回显，避免重复转码。
- 老系统 `sc create/start` 或 `schtasks /ru SYSTEM` 可能成功回报却不执行，表现为 1053 或无文件；保留本卡的 WMI 进程创建路线，不把成功回报当执行证据。
- 命令长度小于 8191 字符；被 `cmd` 静默吞掉时，即使退出码零且 stdout 为空也不是成功。PowerShell 数组元素内不拼接 `'echo x > ' + $path`，避免逗号与加号拆碎批处理行。
- 口令短暂出现在源端 `net use` / `wmic` 命令行；模型只见占位符，公共事件、摘要和模型日志写盘前掩码。

副作用包括目标临时 `.bat` / `.out`、防火墙状态变化与 WMI 进程事件。收尾删除目标临时文件、断 SMB 连接；不恢复防火墙状态，不删除源主机 WMI 回显文件，不能声称完整复原。

[共享执行规则](../../src/skills/templates/execution_rules.txt)

**停止边界**：本卡一次调用只做本页列出的动作；完成即结束，不由本卡重试、追加动作、换通道或改变判据。
