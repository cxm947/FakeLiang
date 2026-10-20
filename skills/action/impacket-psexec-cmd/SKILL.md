---
name: impacket-psexec-cmd
handover: runtime
description: 用一组管理员凭据经 SMB 完成服务创建式远程执行，核对主机名、实际身份与 SID，并可交付一条会话引用。适用：凭据有效性按目标分别观察；同一方法覆盖两台目标主机，靠执行实例区分。
metadata:
  predicates:
  - T1021.002
  - smb
  platforms:
  - linux
  - windows
  keywords:
  - impacket psexec
  - msf psexec
  - native upload
  - 服务二进制上线
  - execCode
  - 会话交付
  - remote execution session
  - psexec远程执行
  - SMB凭据上线meterpreter
  - exploit.impacket_psexec_cmd
  - method
  - position
  - tool
  - cmd
  - msf
  - impacket
  - psexec
  resources: []
  categories:
  - action-method
  aliases:
  - psexec
  - impacket
  - smb exec
  parameters:
  - host
  - credential
  when:
    service: smb
  requires: []
  excludes: []
  carriers:
  - kali
  - shell
serves:
- smb
- windowsCredentialRemoteExecution
- execCode
---

## 适用场景

卡片 ID：`exploit.impacket_psexec_cmd`。目标为 Windows，SMB 可达且登录可用，持有目标管理员组明文口令或 NT hash；不需要目标已有会话。
执行点应能访问目标 SMB，并具备 Impacket 前端；工具用法见 `skills/_tooling/impacket.md`。只使用执行点上的路径，不把仓库相对路径当可执行路径。
本卡经 SMB 上传并启动服务，执行系统探针、回传 stdout/stderr，核对主机名、实际身份与 SID；服务创建路线会改变服务状态，WMI 路线不会。
SMB 不通或只开 WinRM 时本卡不适用；可交编排核对 `exploit.impacket_wmiexec_cmd` 或 Windows 执行点的 `exploit.wmic_remote_cmd`，不得假定替代卡前提成立。

## 参数

- 输入 `target_host`：来自 graph
- 输入 `credential_ref`：来自 graph
- 输入 `source_ref`：来自 runtime（可选）
- 交付：evidence
- 执行位置：position
- 可用工具：tool、cmd、msf

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

**凭据与远程执行由运行层完成。** 需要认证时只发：
```text
{"tool":"remote_process","target":"kali","arguments":{"host":"<host>","command":"<一条 Windows 命令行>","credential_ref":"<运行层给出的引用>","method":"psexec"}}
```
运行层解析凭据并执行 impacket-psexec；模型不写 `<password>`、`<nthash>`、`net use` 口令或任何明文/哈希。
Windows 命令一律用 `run_command`（本步绑定的会话）或 `remote_process`（需要凭据的远程执行）；回执里没有输出时判 `uncertain`。

**节点要求会话时（本节点产出 `execCode(...)`，必须交一条会话）**：命令回显只证明能执行，**不能替代会话**。一步一发：

**监听与弹头由运行层预置（本卡不再造子弹、不再起监听）**：端口取自本次投递预留的 `delivery_callback_port`。运行层决定弹头形态并负责接收端，本卡只发一条远程执行请求。

6. **交出会话（一发，`method=msf_psexec`）**：
```json
{"tool":"remote_process","target":"kali","arguments":{"host":"<host>","credential_ref":"<credential_ref>","method":"msf_psexec"}}
```
运行层用对端服务的 `exploit/windows/smb/psexec` 加 native upload 目标：本次分配的载荷**本身**就是服务二进制，不存在被服务 Job 回收的 helper 子进程。**不要**在本步再传 `certutil`、`start /b` 或自建监听——那样退化成 helper 路线。
7. **收尾**：引本次回执 → `finish`；**会话由运行层认领、登记并探活，本卡不自己登记**。

**本卡的完成依据是「交付段」最后一步的回执**（会话已交付）：命令回显、PoC 成功、文件读取、身份证据都只是**中间观察**，**不能**用来判 `action_complete=true`。拿到交付段最后一步的回执即判 `passed` 且 `action_complete=true`，**不要再追加任何「确认会话」的探测**（监听列表、连接数、端口都不是完成依据）；会话的认领、登记与探活由运行层负责，它认领不到会**如实记录未确认**，那不是让你在本卡里继续试的理由。

本步判 `passed` 需要出现本卡要求的证据；出现明确失败条件判 `failed`；证据不足或效果未确认判 `unknown`，不拿「请求已发出」代替证据。

**停止边界**：本卡一次调用只做本页列出的动作；完成即结束，不由本卡重试、追加动作、换通道或改变判据。


## 完成依据

本卡依次核对 freshness、target、identity；不另外声明效果事实，最终图事实仍由独立 verifier 核对。
- freshness：原始输出属于本次登记调用，并与运行层外层标记、回执对应；远端分段前缀不能单独证明新鲜性，不接受旧轮残留。
- target：marker 块内 `hostname` 与节点目标一致。
- identity：`whoami`、`whoami /user` 形成的 `identity_name`、`identity_sid` 达到节点要求；管理员凭据只是执行前提，不等于已观察到系统身份；节点要求 system 时按实际身份及独立 verifier 核对，不用域管标签代替。
证据字段为 `call_id`、`hostname`、`identity_name`、`identity_sid`、`exit_code`，原始输出为 `stdout`、`stderr`；引用本次材料，引文可信不等于业务事实成立。
`finish.verdict` 判本卡远程执行与身份事实，不判工具是否完成；退出码零不能单独证明通过。
- `pass`：三个阻断闸均通过。
- `unsatisfied`：完整、绑定正确的本次回执明确否定要求，例如实际身份低于节点要求；已有阻断闸明确不满足时不得被其它不确定项覆盖。
- `uncertain`：没有已确认的否定事实，但 marker/身份/绑定或其它必要证据缺失、不明，或权限不足使结果无法核对；不把缺证据当不满足，不猜填成功。

## 失败条件

服务会创建并随后删除；服务名与上传二进制名每次随机，从工具输出定位残留，不猜固定名。服务删除成功仍可能留下 `%WINDIR%` 的随机 exe；本卡通过只覆盖回显与身份，落盘文件另行复核清理。
安全/事件日志会留下痕迹；有 EDR 时优先交编排换卡，不增加噪声，不宣称跑完自动干净。
中文代码页可打断 `whoami /user` 表格；在 marker 块的原始输出中按 SID 形状及正则核对，不依赖表格排版。交互退格按 marker 行切段，不按 banner、提示符或行号匹配。
`-p` 歧义可在参数解析阶段报 usage、尚未触网；口令写目标串，哈希用专用参数。明文可能暴露于本地命令行，按 flag 与显式清单脱敏，产物不保留明文。
**快速重连的 SMB 会话竞态由编排决定重试，本卡不自行重试；失败调用与已有输出如实保留。**
回显可能晚于连接，等输出静默，不按经过时间猜结果。

[共享执行规则](../../src/skills/templates/execution_rules.txt)

**停止边界**：本卡一次调用只做本页列出的动作；完成即结束，不由本卡重试、追加动作、换通道或改变判据。
