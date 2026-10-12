---
name: pre-netsecurity-firewall-state
description: 只读读取防火墙有效策略中三档配置的启用状态并识别当前活动档，交付带来源与时刻的观测。适用：有会话用就地路由，有凭据用远程路由；两者都只读。检索关键词：防火墙生效状态查询、防火墙ActiveStore查询、防火墙配置文件启用状态检查
id: pre.netsecurity_firewall_state
kind: recon
runs_at: position
delivers: ["evidence"]
inputs: {"target_host":{"from":"graph"},"expected_token":{"from":"graph"},"check_shape":{"from":"graph"},"session_ref":{"from":"runtime","optional":true}}
tools: ["pws","cmd", "msf"]
---

# 防火墙有效策略与活动配置档检查

## 何时用

只读查询 ActiveStore 的 Domain/Private/Public 启用状态及当前活动接口所属配置档；仅活动档参与 expected_token 比较，闲置档不拼结论。
本卡证明当前有效状态，不证明某行动曾改变它，也不用行动副作用代替本卡。禁止改注册表或调用设置命令。
查询须在绑定目标的 Windows PowerShell 执行点；有会话就地、有凭据可远程，两者只读。target_host、expected_token、check_shape 取图；session_ref 取运行层，缺省直达，不得杜撰。
expected_token 保留叶原文启用/禁用词，比较层固定映射；NotConfigured 不算启用或禁用。工具说明：skills/_tooling/windows-remote-admin.md。

## 怎么做

命令用本卡声明的工具面交给绑定位置：`position_speaks=shell` 用位置自己的 shell；`position_speaks=meterpreter` 仍提交 `{"tool":"cmd","cmd":"…"}`，由引擎包装并回收回显。不要改用 `execute -f <shell> -a "<命令行>"`：`Process NNNN created.` 没有命令输出，不能作查询证据。

一次调用读取 Name/Enabled 与 Get-NetConnectionProfile 的 NetworkCategory，映射 domain/private/public，压缩 JSON 输出并保留各步错误；提示词与记录只放占位符和投影结果：

```powershell
powershell -NoProfile -Command "$ErrorActionPreference = 'Stop'; $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled); $activeProfiles = $null; $complete = $false; try { $connections = @(Get-NetConnectionProfile -ErrorAction Stop); $byInterface = @{}; foreach ($connection in $connections) { if ([string]$connection.IPv4Connectivity -eq 'Disconnected' -and [string]$connection.IPv6Connectivity -eq 'Disconnected') { continue }; $name = switch ([string]$connection.NetworkCategory) { 'DomainAuthenticated' { 'domain' } 'Private' { 'private' } 'Public' { 'public' } default { throw 'Unknown network category' } }; $ifIndex = [string]$connection.InterfaceIndex; if ($byInterface.ContainsKey($ifIndex) -and $byInterface[$ifIndex] -ne $name) { throw 'Conflicting categories for one interface' }; $byInterface[$ifIndex] = $name }; $activeProfiles = @($byInterface.Values | Sort-Object -Unique); $complete = $true } catch { [Console]::Error.WriteLine($_.Exception.Message) }; $payload = [pscustomobject]@{ policy_store = 'ActiveStore'; profile_scope = 'active'; query_complete = $complete; active_profiles = $activeProfiles; profiles = $profiles }; [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 4) + [Environment]::NewLine)"
```

不改 -PolicyStore、不追加设置命令、不用其他枚举替代投影；原始 stdout 随调用留存。ActiveStore 与 PersistentStore 可能不同，本卡只看前者。

## 怎么判

- 成功：全部已观测活动档均有可解释布尔值，逐项符合预期（firewall_profiles_match），闲置档不比较。
- 不满足：完整观测中任一活动档明确与预期相反。
- 不确定：活动档未知/为空、未知类别、采集冲突、缺活动档策略、重复冲突、NotConfigured、权限不足、查询失败或字段不可解释。

身份与权限硬条件先行；查询者身份不是配置状态。
证据字段：call_id、observed_host、policy_store、profiles（每项 {name, enabled_raw, enabled}）、profile_scope、query_complete、active_profiles、observer_identity。
本次调用的可核对引文仅证明观测，仍须按上述业务条件判断。

## 异常与恢复

- **查询失败、超时或权限不足**：保留原输出与错误，不换通道、不提权、不用行动卡补齐。是否重试或换方法交编排，失败尝试留痕。
- **查询语义缺失 ⇒ 不确定**：无目标解释器、缺 Get-NetFirewallProfile/Get-NetConnectionProfile 语义或旧平台不支持时，保留原报错并记不确定，不用其他工具输出冒充证据。
- **查询不可信或未完成 ⇒ 不确定**：不用部分返回档拼结论。旧版仅三档输出只作策略观测，不推导活动档。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
