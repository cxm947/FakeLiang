---
name: netexec-firewall-off
handover: session
description: 用一组管理员凭据远程关闭 Windows 防火墙，并把状态回读当作判定依据。适用：先确认可达、凭据与权限等级，再选路线改状态并回读状态。
metadata:
  predicates:
  - disable_firewall_credentialed
  - scm
  - T1562.001
  platforms:
  - linux
  - windows
  keywords:
  - 远程关闭防火墙
  - SCM服务禁用防火墙
  - sc远程关闭防火墙
  - exploit.netexec_firewall_off
  - method
  - base
  - msf
  - tool
  - cmd
  - disable_firewall_credentialed
  - scm
  - T1562.001
  - netexec
  - firewall
  - 'off'
  resources: []
  categories:
  - action-method
  aliases:
  - netexec
  - firewall
  - netsh
  - cme
  parameters:
  - host
  - credential
  when:
    method: credentialed
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

已有目标管理员凭据，目标 445 / RPC 可达，需要关闭防火墙并取得本次状态回读。
先确认执行位置：控制端能直达目标时可用 netexec；只有 Windows 会话能到目标时用原生命令。不要把 Linux 工具发入 Windows 会话。
会话令牌不等于显式管理员凭据；SYSTEM / 本机账号的 sc.exe 远程调用被拒，不能据此宣布所给凭据错误。

## 参数

- 输入 `target_host`：来自 graph
- 输入 `credential_ref`：来自 graph
- 输入 `source_ref`：来自 runtime（可选）
- 交付：evidence
- 执行位置：base
- 可用工具：msf、tool、cmd
- 图适用：case=disable_firewall_credentialed；service=scm；technique=T1562.001

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

凭据与远程执行由运行层完成。需要认证时只发：
```text
{"tool":"remote_process","target":"kali","arguments":{"host":"<host>","command":"netsh advfirewall set allprofiles state off & netsh advfirewall show allprofiles state","credential_ref":"<运行层给出的引用>","method":"msf_psexec"}}
```
运行层解析凭据并执行；模型不写 `schtasks /p`、`/rp`、`net use`、`netexec -p`
或任何明文/哈希。`credential_ref` 取 `context.node.credential`；没有就留空。

**本卡只有一步**：发完上面那条 `remote_process`、拿到回执，就判 `action_complete=true` 并 `finish`。不要再发任何回读、身份或会话命令：状态由 Post 在目标主机上重新观测，本卡在跳板机上做任何回读都不是目标证据。

回读由 Post 的防火墙状态卡完成；本卡只负责关闭动作，不把“进程已创建”当成
状态证据。

**本卡不要执行任何回读命令**：本步绑定的执行面通常是跳板机，在它上面跑 `netsh` 读到的是跳板机的状态，不能证明目标已关闭；状态由 Post 在目标主机上重新观测。

**停止边界**：本卡一次调用只做本页列出的动作；完成即结束，不由本卡重试、追加动作、换通道或改变判据。


## 完成依据

本卡只判“关闭动作已经执行并拿到回执”：`remote_process` 返回
`effect_known=true`，且回执没有认证失败或参数错误。回执里的 `ReturnValue = 0`
只说明进程创建成功，**不说明防火墙已关闭**。

`firewall_state` 由 Post 的防火墙状态卡独立回读；本卡不把“命令已发出”或
“进程已创建”当成状态证据，也不在这里追加回读探测。

## 失败条件

只有适配当前槽位的候选被本次认证明确以 STATUS_LOGON_FAILURE / STATUS_WRONG_PASSWORD / STATUS_NO_SUCH_USER / 原生 1326 拒绝，保存调用和逐字引文后才可考虑下一候选。
STATUS_ACCESS_DENIED、Windows 错误 5 或笼统 access denied 不能单独证明凭据错误，不触发候选切换；已认证而操作被拒属于权限问题。
超时、不可达、非零退出但无认证拒绝、参数或工具错误均不作为换凭据依据；哈希错填明文槽先纠正表示与工具适配。
认证首次成功即使用该材料，不追加认证尝试；运行层不会自动替本卡重试或选凭据。
工具发错平台可改正确执行位置；OpenSCManager 失败 5 可改显式凭据路线，不能循环重发同一失败命令。
连接超时先核对 vantage；回读缺失保持 uncertain。允许针对已观察原因修正，不另造无条件重试或禁止修正的规则。
副作用包括防火墙状态变化、计划任务、状态文件与日志；按实际任务名清理，不遗留常驻任务，保留清理回执；清理不等于恢复防火墙。

[共享执行规则](../../src/skills/templates/execution_rules.txt)

**停止边界**：本卡一次调用只做本页列出的动作；完成即结束，不由本卡重试、追加动作、换通道或改变判据。
