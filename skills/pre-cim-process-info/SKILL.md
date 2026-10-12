---
name: pre-cim-process-info
description: 只读查询一个精确名称的本地进程对象及其真实运行主体，交付带来源与时刻的观测。适用：就地优先；远程路由需凭据且只读。检索关键词：CIM进程信息查询、CIM进程属主查询、本地进程所有者查询
id: pre.cim_process_info
kind: recon
runs_at: position
delivers: ["evidence"]
inputs: {"target_host":{"from":"graph"},"service":{"from":"graph"},"expected_owner":{"from":"graph"},"check_shape":{"from":"graph"},"session_ref":{"from":"runtime","optional":true}}
tools: ["pws","cmd", "msf"]
---

# 本地进程对象与真实运行主体检查

## 何时用

只读查询目标上一个精确名称的本地进程及其 owner；不读内存、不转储、不转端口、不枚举服务，进程存在不构成攻击结论。
须有绑定 target_host 的查询通道与足够观察权限；service、expected_owner、check_shape 取冻结图输入。
就地优先，远程路由须有目标凭据且仍只读。
service 为图叶第 2 参，已有可执行后缀保留，否则补一次（lsass 与 lsass.exe 同一对象）。
expected_owner 为叶第 5 参主体词，比较层作固定映射。
session_ref 由运行层提供，缺省为直达通道，不得杜撰。
query_complete 与可见范围依据分开记录；空输出、权限不足都不等于不存在。工具说明：skills/_tooling/windows-remote-admin.md。

## 怎么做

命令用本卡声明的工具面交给绑定位置：`position_speaks=shell` 用位置自己的 shell；`position_speaks=meterpreter` 仍提交 `{"tool":"cmd","cmd":"…"}`，由引擎包装并回收回显。不要改用 `execute -f <shell> -a "<命令行>"`：`Process NNNN created.` 没有命令输出，不能作查询证据。

使用 Win32_Process 精确名称过滤，并在同一步取 GetOwnerSid。
**执行边界：不得追加第二步命令，不得改用模糊过滤；只查询指定的这一个对象。**
PowerShell JSON 用 [Console]::Out.Write 原样出流，避免默认格式化器按宽度折断：

```powershell
$svc = '<service>'; if ($svc -notmatch '\.exe$') { $svc = "$svc.exe" }; $p = Get-CimInstance -ClassName Win32_Process -Filter "Name='$svc'" | Select-Object -First 1; if ($p) { $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid; $o = [pscustomobject]@{ process = ($p | Select-Object ProcessId, CreationDate, Name, ExecutablePath, CSName); owner = ($owner | Select-Object ReturnValue, Sid) } | ConvertTo-Json -Compress -Depth 6; [Console]::Out.Write($o + [Environment]::NewLine) } else { [Console]::Out.Write('NO_PROCESS' + [Environment]::NewLine) }
```

仅目标缺 CIM cmdlet（Windows 7 / PowerShell 2.0）时使用 WMI 变体；同一对象、过滤、owner 投影与判据：

```powershell
$svc = '<service>'; if ($svc -notmatch '\.exe$') { $svc = "$svc.exe" }; $p = Get-WmiObject Win32_Process -Filter "Name='$svc'" | Select-Object -First 1; if ($p) { $owner = $p.GetOwnerSid(); Add-Type -AssemblyName System.Web.Extensions; $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer; $o = $ser.Serialize(@{ process = @{ ProcessId = $p.ProcessId; CreationDate = $p.CreationDate; Name = $p.Name; ExecutablePath = $p.ExecutablePath; CSName = $p.CSName }; owner = @{ ReturnValue = $owner.ReturnValue; Sid = $owner.Sid } }); [Console]::Out.Write($o + [Environment]::NewLine) } else { [Console]::Out.Write('NO_PROCESS' + [Environment]::NewLine) }
```

cmd 会话可能改写引号和反斜杠，按通道纪律用 powershell -EncodedCommand；服务名经环境变量传入：

服务名经环境变量传进脚本：`set AGV_SVC=<service>& powershell -NoProfile -NonInteractive -EncodedCommand <b64> < NUL`。


## 怎么判

- 成功：精确名称/对象绑定的进程存在，PID 与创建时间稳定关联，GetOwnerSid 成功且 owner 符合预期（local_process_service_matches）。
- 不满足：查询完成、可见范围充分时明确无该进程。
- 不确定：owner 缺失、被拒、不可见、不匹配，查询竞态或范围不明；不能用查询者身份代替进程 owner，也不能把问不出来写成主体反证。

证据字段：call_id、observed_host、process_name、pid、creation_time、cs_name、executable_path、owner_sid、owner_name、owner_return_code、query_complete、visibility_basis。查询者身份与进程 owner 分开。
本次调用的可核对引文仅证明观测，仍须按上述业务条件判断；固定输入不交给模型另造。

## 异常与恢复

- 模板只读，不改进程状态；原始 stdout 随调用留存，查询失败、超时或权限不足时一并保留错误。
- **不自行提权，不换第二种查询方式；是否重试或换方法交编排处理。**
- 仅目标缺 CIM cmdlet 时，按“怎么做”的平台分支选 WMI；不能把查询失败判为无进程。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
