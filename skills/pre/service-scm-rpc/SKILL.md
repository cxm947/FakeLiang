---
name: service-scm-rpc
description: 验证 Windows SCM 远程服务控制接口是否存在；优先用系统客户端或已有库的短调用，只读绑定，不手写协议报文。
metadata:
  predicates:
  - networkServiceInfo
  platforms:
  - any
  keywords:
  - scm
  - scmr
  - svcctl
  - rpc
  - smb
  - tcp
  - windows
  - service
  - presence
  - 服务存在
  - 远程服务控制接口
  resources:
  - references/smb-bind.md
  categories:
  - service-presence
  aliases:
  - SCM
  - RPC
  - SMB
  - sc query
  - 服务控制管理器
  parameters:
  - service
  - protocol
  - port
  when:
    service: scm
  requires: []
  excludes: []
---

# SCM 远程接口存在检查

## 适用场景

需要确认目标 Windows 的 SCM / Service Control Manager 远程接口是否存在并响应。
本卡只做一次只读绑定/查询，不创建、启动、停止服务，也不修改配置。

## 参数

- 输入：本页「适用场景」声明的目标、地址/端口、平台与执行面；由运行层给出，**不得杜撰**
- 交付：evidence
- 执行位置：position
- 可用工具：cmd、code

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要新起监听或会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

**输出纪律**：`content` 只放一条最短调用；不要复制本卡说明、示例全文、协议报文或字节数组。**禁止手写 SMB/RPC 报文、`bytes.fromhex(...)`、长十六进制串或完整脚本模板。**

按执行面选第一条可用方法：

1. **Windows 执行面**（`context.execution.platform == windows`）：用系统 SCM 客户端做一次只读查询：
   ```text
   {"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"sc \\\\<目标主机> query SamSs"}}
   ```
   目标主机取自本 LEAF；只查一个必然存在的服务（`SamSs`），一条命令返回后立即退出，避免远程枚举或 PowerShell 管道继续挂住 shell。返回 `SERVICE_NAME: SamSs`/`STATE`，或返回明确的 SCM/访问拒绝错误，都说明接口有响应；超时、找不到主机、命令不存在记未知。`sc` 不可用时才退回一次短 `Get-Service -ComputerName <目标主机> -Name SamSs`，且不加 `Select-Object`/`Format-List`。

2. **Linux 执行面且已有 Impacket**：用一条短库调用只做 bind，不要展开报文：
   ```text
   python3 -c "from impacket.dcerpc.v5.transport import SMBTransport; from impacket.dcerpc.v5 import scmr; t=SMBTransport('<目标地址>',<端口>); d=t.get_dce_rpc(); d.connect(); d.bind(scmr.MSRPC_UUID_SCMR); print('SCMR_BIND_OK'); d.disconnect()"
   ```
   目标地址/端口取自本 LEAF；只 bind，不调用服务操作。

3. 以上都不可用：记 **未知（缺少 SCMR 客户端）**，不要临场拼 SMB/RPC 字节，也不要拿 445 端口开放冒充 SCMR。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示结果未知，不是通道失效，也不是命题不成立。

## 完成依据

- Windows 系统客户端返回服务列表，或返回明确的 SCM/访问拒绝响应：通过。
- Linux 短库调用出现 bind 成功（`SCMR_BIND_OK`）：通过。
- 仅端口开放、SMB 协商成功、本地服务列表或通用 RPC 响应：不足，未知。
- 客户端缺失、超时、访问拒绝且无法区分阶段、回复不完整：未知，写明具体缺项。
- 完整响应明确不提供指定接口，或目标通道明确拒绝：不通过。

## 停止边界

- 客户端缺失、超时、访问拒绝且无法区分阶段：记未知，不重试、不换目标、不扩大范围。
- 输入缺失：说明缺什么，不猜目标、端口或身份。
- 本卡一次调用只做一次检查；完成即结束。

## 失败条件

- 手写协议报文/长字节串、工具缺失、参数错误、输出截断、执行通道中断 → 未知。
- 本卡一次调用只做一次检查；不重试、不追加动作、不换目标、不扩大范围。
- 不查询 `Get-Service -Name scm`，不以 `RpcSs` 进程/服务正在运行代替远程接口绑定。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
