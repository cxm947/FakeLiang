---
name: pre-impacket-scm-query
description: 经显式 SMB 端口到达服务控制管理接口做一次最小只读连接，证明接口在该端口上可用且本次认证有效。适用：绑定凭据后查询；不可用与权限不足是两种不同结论。检索关键词：SCMR连接验证、SCMR最小连接测试、SCM只读连接验证
id: pre.impacket_scm_query
kind: recon
runs_at: position
delivers: ["evidence"]
inputs: {"target_host":{"from":"graph"},"port":{"from":"graph"},"expected_service":{"from":"graph"},"credential_ref":{"from":"graph"},"credential_candidates":{"from":"runtime","optional":true},"check_shape":{"from":"graph"},"domain":{"from":"runtime","optional":true}}
tools: ["tool","cmd", "msf"]
---

# SCMR 最小查询 — 经 SMB 端口证明接口可达

## 何时用

卡片 ID：`pre.impacket_scm_query`。在已绑定执行点，用已绑定 SMB 凭据与实际主体，经图中显式 SMB 端口访问正确目标的 SCMR `svcctl` 命名管道；主机映射必须对齐。
本卡只证明接口在该端口可用、此次认证有效；`SC_MANAGER_CONNECT` 查询权不证明创建服务、关闭防护或远程执行能力。
图输入为 `target_host`、`port`、`expected_service`、`credential_ref`、`check_shape`；运行侧提供可选 `domain` 与 `credential_candidates`，模型不得杜撰。
不需要 `service_name`，不虚构同名服务、不枚举服务、不挑任意系统服务代证接口身份。工具用法见 `skills/_tooling/impacket.md`。

## 怎么做

使用成熟 Impacket 库与短固定序列，不直接运行宽权限工具，不搭通用 RPC 框架：
1. 连接图中指定的 `target_host` / `port`（实际 SMB 端口），使用绑定凭据完成认证；明文与哈希均可，材料不进卡片。
2. 在 `ncacn_np` / `svcctl` 上 bind SCMR。
3. 显式以 `SC_MANAGER_CONNECT` 打开服务管理器，覆盖 helper 默认宽权限；成功后立即关闭句柄。
4. 断开连接并输出一行结构化结果；脚本只报字段，不替判据判断真假。每步状态及超时、工具缺失、认证错误分别留痕。
Windows 命令在 `position_speaks=shell` 或 `meterpreter` 均使用 `{"tool":"cmd","cmd":"…"}`，由位置包装并返回回显；不用 `execute -f <shell> -a "<命令行>"`。只有 `Process NNNN created.` 而无输出时缺少证据，应判 `uncertain`。

派发前读取 `task.inputs.credential_candidates`：每项为 `{order, origin, credential_ref}`，引用内含 user、secret、domain、mode。按运行侧顺序使用：password 先于 ntlm，同表示内 derived 先于 external；仅两种来源同表示时，才是 `order=1 / origin=derived`、`order=2 / origin=external`。
哈希只进 `-H` / `--hashes` / 支持传哈希的库；不得填入 `schtasks /p`、`/rp`、`net use` 口令或 `-p` 槽。表示不支持应在执行前说明，不将槽位误用后的 1326 或拒绝访问当作凭据不适用。
只有一份候选就只使用该份；`task.inputs.credential_ref` 指向第一份。两份均缺失时以 `CREDENTIAL_MISSING` 拒绝，不猜账号、不填默认口令、不用未提供材料。
仅本次认证响应中的 `STATUS_LOGON_FAILURE`、`STATUS_WRONG_PASSWORD`、`STATUS_NO_SUCH_USER`、Windows 1326，或请求域与返回认证域明确冲突等可核对的域/主体不匹配，才能说明当前候选不适用；记录 call_id 与原文，再由本轮编排/模型决定是否使用下一份。
超时、拒绝连接、工具缺失、参数错误、RPC 不可用及非零退出本身不证明口令错误；认证后的 `STATUS_ACCESS_DENIED` 或 Windows 5 表示权限不足，不触发换材料。
**账号锁定立即停止：遇到 `STATUS_ACCOUNT_LOCKED_OUT` 或明确锁定，不再尝试第二份。首次成功不为用完列表追加认证。**
候选切换各自产生调用与证据，运行层不自动重试；模型只见 secret 占位符，公共事件、摘要与模型日志落盘前掩码。

## 怎么判

证据字段：`call_id`、`observed_host`、`peer_host`、`peer_port`、`transport`、`pipe`、`rpc_interface`、`bind_status`、`open_status`、`requested_access`、`close_status`、`authenticated_principal`、`error_code`。
`finish.verdict` 判断本卡要求的接口与最小连接事实，不判断查询是否完成；引文来自本次调用，引文可核对不等于业务结论成立。
- `pass`：正确目标、显式 SMB 端口及 `svcctl` 上 SCMR bind 与最小权限打开成功，句柄关闭可追溯。
- `unsatisfied`：目标正确、访问基础有效，本次完整回执明确接口不存在或不支持；查询成功不能抵消该否定事实。
- `uncertain`：拒绝访问、主体不匹配、仅 SMB 横幅、其它传输、超时、工具缺失或必要证据不全；不得把缺证据判成不满足。
端点不可用与权限不足分别记录，不合并为笼统结论。旧机器判据名只属历史材料，不代替本次有效证据。

## 异常与恢复

**只读与停止边界：不创建、不启动、不删除服务，不改配置、不留后台进程或长生命周期句柄。**
**超时或中断时保留本次输出和每步状态；不自行重试提权、不换传输。是否重试或换方法交编排处理，失败尝试如实留痕。**
其它端口/传输的连通或 SMB 横幅不能代证本卡结果。历史实机记录见 `docs/product/validation_runs.md`、`docs/product/adoption_evidence.tsv`；历史明细由库外索引保留。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
