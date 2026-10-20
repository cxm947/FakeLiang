---
name: service-smb
description: 验证目标端点是否提供 SMB 服务；Windows 用 net view，Linux 用 smbclient，只发一次有界只读请求，不手写 SMB 协商字节。
metadata:
  predicates:
  - networkServiceInfo
  platforms:
  - any
  keywords:
  - smb
  - net view
  - smbclient
  - '445'
  - service
  - presence
  - 服务存在
  - SMB
  categories:
  - service-presence
  aliases:
  - SMB
  - '445'
  - smbclient
  - net view
  parameters:
  - service
  - protocol
  - port
  when:
    service: smb
  requires: []
  excludes: []
---

# SMB 服务存在检查

## 适用场景

需要确认目标端点是否提供 SMB 服务。检查从本步绑定的执行面发起；目标地址/端口取自当前 LEAF。
只做一次有界只读请求，不枚举共享内容、不挂载、不读写文件。

## 参数

- 输入：本页「适用场景」声明的目标、地址/端口、平台与执行面；由运行层给出，**不得杜撰**
- 交付：evidence
- 执行位置：position
- 可用工具：cmd、code

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入已经由运行层给出；缺输入先说明缺什么，不要换方法硬凑。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

**输出纪律**：`content` 只放一条最短调用；**禁止手写 SMB 协商字节、`bytes.fromhex(...)`、长十六进制串或完整脚本模板。**

按执行面选第一条可用方法：

1. **Windows 执行面**：
   ```text
   {"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"net view \\\\<目标主机>"}}
   ```
   返回共享列表、空列表、或明确的访问拒绝，都说明 SMB 有响应；命令不存在、超时、找不到主机记未知。

2. **Linux 执行面**：
   ```text
   {"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"smbclient -L //<目标主机> -N"}}
   ```
   无匿名访问时可加 `-U ''`；同样只发一次。

3. 以上都不可用：记未知（缺少 SMB 客户端），不要临场拼 SMB 报文，也不要拿 445 端口开放冒充 SMB。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示结果未知，不是通道失效，也不是命题不成立。

## 完成依据

- 返回共享列表、空列表或明确的 SMB/访问拒绝响应：通过。
- 仅 445 端口开放、TCP 连接成功或通用 Banner：不足，未知。
- 客户端缺失、超时、找不到主机、输出截断：未知，写明具体缺项。
- 完整响应明确不提供 SMB，或目标通道明确拒绝：不通过。

## 停止边界

- 本卡一次调用只做一次 SMB 检查；完成即结束，不重试、不追加动作、不换目标、不扩大范围。
- 客户端缺失、超时、访问拒绝且无法区分阶段：记未知并说明缺什么。
- 输入缺失：说明缺什么，不猜目标/端口/身份。

## 失败条件

- 手写协议报文/长字节串、工具缺失、参数错误、输出截断、执行通道中断 → 未知。
- 不用 `net use`/挂载/共享读写代替“服务存在”检查；本卡只判断 SMB 是否有响应。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
