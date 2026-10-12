---
name: session-msf-migrate
description: 会话托管迁移 — 把已建立的会话交到常驻控制台名下（会话生命周期 · 目标 msf 会话）
id: session.msf_migrate
kind: session
runs_at: position
delivers: ["session"]
inputs: {"session_ref":{"from":"runtime"},"lhost":{"from":"runtime","optional":true},"lport":{"from":"config","optional":true}}
tools: ["msf","tool","cmd"]
---

# 会话托管迁移 — 把已建立的会话交到常驻控制台名下（会话生命周期 · 目标 msf 会话）

卡片 ID：`session.msf_migrate`。本卡为 implemented、model 装配。

## 何时用

面向已经建立、正在应答的会话/通道，将其托管为常驻控制台上可复用、可保活的通道。执行点是**常驻控制台（`msfrpcd`）**：引擎在**本机**用 msf 的 python 客户端库直接调用它（`sessions.list` / `session.runsingle` / `read`），不使用交互式 `msfconsole`，也不再往控制端推任何发送端脚本。

在取得会话之后、登记为后续节点复用通道之前使用；会话帧寄生在易退出的进程中时，也用于换帧。产出必须是迁移后仍然应答的通道，且**宿主确实换了**：主机名与身份由本次探针读回，宿主 PID 迁移后必须等于目标进程 PID、且不同于迁移前——不能以迁移命令的返回值代替。

本卡不负责建立会话（`session.msf_via_credentials`）、通道身份观测（`pre.session_identity`）或通道可用性探针（`post.channel_echo`）。

## 怎么做

主路径使用 Meterpreter 自身命令；引擎把每条动词经本机库直接送进目标会话（`session.runsingle`），不在本地 shell 执行。本卡没有随卡脚本兜底，也没有固定入口调用形状。

- `getpid`：读回 `Current pid`，宿主证据来自它（迁移前基线、迁移后核对）。
- `ps`：列进程（PID、Name、Arch、User、路径），目标进程从它的输出里选定。
- `migrate <pid> -t 60`：把会话帧迁入目标进程；`-t` 是迁移自身的等待预算。
- `sysinfo`：读回 `Computer`、`Architecture`、`Domain`，主机名证据来自它。
- `getuid`：读回 `Server username`，身份证据来自它。
- 等价选法：`migrate -N <process>` 按进程名选择——上游只取枚举结果里的**第一个**匹配，不按属主/位数择优；多匹配时先自己确定唯一 PID，再用 `migrate <pid>`。`getsystem` 是命名管道提权的另一条手段，不混入本卡方法。

命令模板（前置基线 + 选宿主 + 迁移 + 后置复探三连）：

```text
getpid
ps
migrate <pid> -t 60
getpid
sysinfo
getuid
```

> **这些是独立动作块**：一行一个块。多步就在一次回答里用 `{"actions":[…],"gap":1}` 批量给出（引擎按顺序执行、每块各记一条回执、块间默认歇 1 秒）；**不要把几行用 `&` 拼成一条长命令** —— 一处坏、整条废，长行还会把回执尾巴弄丢。

沿用原有顺序要求：迁移前有基线，迁移后复探；判据只认**迁移后**的那次回显，后置复探必须包含 `getpid`（核对宿主）、`sysinfo`（主机名）、`getuid`（身份）三项。控制台转录没有 marker 分段，解析器按约定取每个字段**最后一次**读数——因此后置三连必须留在序列末尾。Meterpreter 不通过 shell 回显 marker，保留既有 marker 纪律的例外。

输入定义见 `skill.json`：`session_ref` 来自运行现场，端点按其会话 id 送达命令；模板内的 `<pid>` 从 `ps` 输出或现场选定，不增加为机器入参。`lhost` 来自运行现场、`lport` 来自配置，仅在掉线后需要重建传输时使用。

模型可选择目标进程、按 pid 或进程名迁移、探针顺序与等待窗口，并判断掉线后是否使用 `lhost` / `lport` 重建。是否另行使用 `getsystem` 仍由现场决定。marker 例外、判据口径、证据字段名及迁移后必须复探的要求不可更改。

宿主选择看夹具约定，不背「常见 PID」：进程生命周期由测试环境决定，单次 `ps` 看不出未来是否易退出；同属主是优先条件，但不保证拥有迁移所需的访问权；只有卡面要求 x64 宿主或后续能力需要位数时，才用 `ps -A x64` 排除 32 位。实测禁区：会话 1 的系统进程（如 `winlogon.exe`）不要迁——会把会话迁死；受保护进程不能仅凭管理员身份视为可用。

## 怎么判

沿用 freshness、target、effect 三个阻断闸，`identity_rule=null`；effect 使用注册规则 `target_echo_present`。核对本次调用、迁移后的宿主 PID、主机名与身份，以及命令实际落到的会话。

证据字段保持 `call_id`、`session_host_pid`、`session_host`、`session_identity`、`msf_session_id`，原始输出为 `console transcript`。`session_host_pid` 对应迁移后 `getpid` 的读数（必须等于目标进程 PID、且不同于迁移前），`session_host` 对应 `sysinfo` 的主机名，`session_identity` 对应 `getuid` 的身份；`msf_session_id` 对应端点 `--sid`，用于追溯本次调用所处会话。

- 通过：三个阻断闸均为 `pass`；方法要求本次调用读回迁移后的宿主 PID 与身份/主机名，不能只认迁移命令返回成功。
- 不满足：进程不存在、权限不足等迁移报错记为 `unsatisfied`，表示帧未迁入目标进程；迁移明确报错后，即便复探字段齐全也不覆盖错误。后置 `getpid` 仍等于迁移前宿主：记录「未观察到宿主转移」，不判通过。
- 不确定：没有阻断闸返回 `unsatisfied`，但端点未应答、会话无回显或缺少所需证据时为 `uncertain`；命令已发送不构成证据。

现有 `target_echo_present` 只检查 `session_identity` 或 `session_host` 是否有值，不解析迁移报错，也不单独证明迁移已经完成；须结合本次原始输出核对迁移后的探针（含宿主 PID），不能以 effect 单闸通过代替上述方法要求。

## 异常与恢复

- 换帧失败时保留原帧并如实报错；掉线后的传输重建使用既有可选输入，不作为默认路径。
- 帧的位数决定后续能力；迁入 32 位进程会限制注入与内存操作，迁入系统进程需要相应权限。
- `migrate` 返回成功后，新进程仍可能退出并使通道静默失效，必须核对迁移后的探针。
- 迁移结果未知（超时且旧响应可能迟到）：停止重发并记录「结果未知」，不要靠反复发送把回显归属碰对。
- 不要向会话发送 `sleep 2` 充当等待：该原生命令会关闭传输并在等待后恢复；等待窗口放控制器侧（可重试的暂时错误：等 2 秒、至多 3 轮）。
- 旧帧中已注入的内存、句柄、已加载模块不会随迁移保留，迁移后须重新确认。
- 新进程的 token 决定迁移后的身份；`getuid` 必须在迁移之后执行，不混用提权前后的观测。
- Meterpreter 只接受自身命令；要跑 `ipconfig` 这类命令行，**照旧写 `{"tool":"cmd","cmd":"ipconfig"}`** （引擎按位置包装并带回显）。自己发 `execute -f cmd.exe -a "…"` 只会得到 `Process N created.`、没有输出，拿不到证据（2026-10-08 实测）。
- 会话状态保存在端点进程中，端点重启后原会话编号不可信。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
