# 会话管理契约（台账 / 纳管 / 暂停 / 转介）

本文是四块能力的**单一出处**：各自的状态、接口、开关与验收。写它的原因是这四块在 2026-09-26/27
两轮里被反复讨论并落码，若不写下来，后来者只能从代码里猜边界。**四块都可独立关闭**，关闭时行为与
改动前一致（有测试与整图回归作证）。

## 0. 一页速览

| 块 | 组件 | 开关 | 默认 |
|---|---|---|---|
| 台账 | `runtime.run`（`state.sessions` / `register_session` / `session_rows`）| 无（始终生效）| — |
| 纳管 | `runtime.connection_management` + `runtime.adopt` + 三张 `session.<console>_adopt_*` 卡 | `state.connection_management` 或 `AGV_CONNECTION_MANAGEMENT=1` | 关 |
| 暂停 | `runtime.session_control` + `runtime.loop` 三处接入 | `state.session_management` 或 `AGV_SESSION_MANAGEMENT=1` | 关 |
| 转介 | `runtime.relay` + `clients/agv_socks5.py`（访问）+ `clients/agv_forward.py`（回程）| 无开关（纯能力，不被自动调用）| — |

## 1. 台账（谁在手里）

- **单一写入入口**：`runtime.run.register_session(state, host, session, probe=...)`。同键（driver/handle/entrance）就地更新，
  新键追加，重复产物不堆叠；**只有带探针证据（`probe_ref.result == "pass"`）的行才算"已验证"**。
- **读**：`runtime.run.session_rows(state, host)` 返回该主机的连接行（注册序即偏好序）。
- **不变量**：地址不是身份（地址来自部署表）；一行代表一次连接实例，不是一台机器；后来者不覆盖先前行。

## 2. 纳管（把连接交给常驻控制台）

**它不是技能卡**：触发条件、路由、判据都是确定的，因此按运行层的**条件判断 + 固定流程**实现
（写在卡里会与"卡必须可被检索"的仓库契约冲突，2026-09-26 两次实测均撞约束）。

- **路由表**（`ADOPT_CARDS` / `card_for(kind, console)`）：`native→session.<console>_adopt_native`、
  `web→..._adopt_web`、`mount→..._adopt_mount`、`managed→..._migrate`；未知类型如实报 `UNSUPPORTED`。
- **两段判定**：卡前 `plan_manage`（ADOPT / REUSE / UNSUPPORTED）、卡后 `assess_endpoint`
  （ACCEPT / REFRESH / REUSE / REJECT）。成功条件 = **控制台确认上线 + 设备身份匹配 + 实测权限满足**；
  "启动命令返回成功"不算。
- **幂等键** = hash(console, 稳定设备标识, 权限档, 排序后的能力集合) —— **不含**驱动、句柄、地址、时间。
- **操作生命周期**（`open_operation` / `settle_operation` / `find_operation`）：`PENDING / APPLYING / UNKNOWN /
  REGISTERED / PUBLISHED / UNSUPPORTED / REJECTED / FAILED`；**一 key 一操作**；副作用前先占位；
  超时/丢响应记 UNKNOWN **并查回**，不盲目重建。
- **组件包与注册契约（2026-09-27 落地）**：目标侧组件包＝**控制台自带的那份**（`runtime/adopt` 在执行主机上生成，
  本项目不自研端点）；注册契约＝**控制台确认登记号 + 只读核验读回身份与设备**。一条方法六步，三张卡只声明载体：
  `native`（已有原生登录）/ `web`（网页命令入口）/ `mount`（文件系统搬运 + 点名的启动通道）。检索永不提供它们
  （`status=program_only`），由路由表按名调用。
- **两处诚实闸门**：`ensure_resident` 没有可用的执行点 → `UNSUPPORTED(NO_ADOPT_RUNNER)`（有执行点则跑卡，
  候选经 `assess_endpoint` 评估后 `REGISTERED → PUBLISHED`；评估不过 → `REJECTED` 并带原因）；
  `ensure_deep_endpoint` 缺中继执行者 → `NO_RELAY_RUNNER`，缺深层执行点 → `NO_DEEP_ADOPTION_RUNNER`
  （中继后端本身**已具备**：访问方向 + 回程方向两个独立进程，实机双通）。
- 检索侧的对应事实：`session.msf_migrate` 状态为 **`program_only`**（由运行层固定步骤按名调用，检索永不提供它）。

## 3. 暂停（结果不明就不许重放）

**为什么**：运行对 `timeout` / `transport_error` 是**会重试**的，而**超时并不等于没执行**。

- 三个函数：`set_paused(state, slot, value)` / `is_paused(state, slot)` / `pick_session(state, host, privilege)`；
  **槽 = 本次实际使用的连接引用**（不是"主机+权限"，后者是"一类"连接）。
- **三处接入**（`runtime.loop`）：①发送前该连接已暂停 ⇒ **不发送**、不记 attempt、提交以 `unsatisfied_stop` 终结；
  ②真实结果属于可重试集合 ⇒ 暂停该引用；③`decide(..., connection_pause=True)` 里，受控连接的未知结果直接返回
  `uncertain_stop`，**禁止落入换卡或重试分支** —— **即使暂停随后被清除也不重放**。
- `Attempt.session_ref` 是**发送前捕获的快照**（换卡后当前候选已不是它的来源）；为空时**不写入序列化输出**（关闭时输出不变）。
- **传输层**：客户端"从未到达端点"用 **75（EX_TEMPFAIL）**，平台映射为 `transport_error` ⇒ 与"执行了但失败"分开。

## 4. 转介（够不着的目标）

实测结论（2026-09-26）：**框架内的"路由 + 代理"在当前配置下不可用**（`msfconsole` 与常驻服务是两套实例、
`route add` 报 `Invalid gateway`、代理模块加载失败）⇒ **独立中继是必需而非优化**。

- **访问方向**：`clients/agv_socks5.py`（最小 SOCKS5 服务端，仅 CONNECT、无认证、py2.7/3.x 兼容）跑在中间机上；
  控制端用 `runtime.relay.socks5_connect / probe_over_relay` 打开连接。
- **回程方向**：`clients/agv_forward.py`（中间机监听一个端口 → 交给控制端）承接深层设备主动发起的连接。
- **两者都是独立进程**：投递它们的命令通道断开后仍然存活（这正是"把转发从交互 shell 里拆出来"）。
- **语义三类分开**：`connected`（经中继建连成功）/ `refused`（**中继通了，目标回答不**）/ `relay_error`
  （**我们的入口坏了**）。混淆后两者正是"中继故障看起来像目标安静"的来源。
- 实测：经 PC1 的中继探 `192.168.93.40:445` 与 `192.168.93.30:445` = connected；`93.40:1` = refused；死中继 = relay_error；
  回程：kali 监听 5555，PC1 转发，深层侧发起 ⇒ 控制端收到并回包。

## 5. 开关与验收

## 4.5 测试后清理（靶场卫生 · 2026-09-27 业主指令）

**规则**：**每次实机测试结束都要清理自己留在靶机上的东西**；只有**声明为正式端到端演练**时才允许保留，
且收尾清单必须写明"留了什么、为什么留"。理由是实测教训：一次 mount 验收把端点程序留在目标上继续运行，
下一次同路径写入直接 `Text file busy`（启动的还是旧文件）；PC1 的 C 盘被历次残留与冗余副本推到 **100% 满**，
连带 OA 服务组挂掉、staging 报 `No space left on device`。

**清单（我们可能留下的东西）**：

| 位置 | 残留物 | 清理方式 |
|---|---|---|
| 控制点 | 接收器作业（`multi/handler` job 常驻监听） | `job-list` → `job-stop`（**注意**：停它不会断掉已建立的会话，但会关掉"端点将来重连"的入口） |
| 控制点 | `/tmp/agv_*`（端点程序本体、接收器日志、注入用的临时脚本） | 删除 |
| 控制点 | 中继/转发进程（`agv_socks5.py`、`agv_forward.py`）与转发端口 | 停进程、释放端口 |
| 目标（Windows） | `%TEMP%` / `C:\Windows\Temp` 下 `agv*`、`AGV-*`（端点程序、`.done`/`.run`/`.out` 回执、临时 `.ps1`/`.bat`） | 删除（被运行中的端点占用的会报"保留"，如实列出） |
| 目标（Linux） | `/tmp/agv_endpoint*`、上传的客户端脚本 | 删除 |
| 控制点 | 挂载点（如 `//<target>/C$` → `/mnt/...`） | `umount` |
| 目标 | 自恢复机制（常驻服务/计划任务/启动项） | 仅在声明"正式演练"时允许存在；收尾必须显式回收 |

**入口（一条命令）**：`python scripts/clean_lab_residue.py --remote <控制点> --password <pw> [--mount <挂载点>] [--dry-run]`
—— 只删"名字是我们的"且只动临时/落点目录；不碰靶场自带文件、服务与账号；不杀会话（是否保留会话是运行层的决定，不是清洁工的决定）。

**注意**：`job-stop` 只关监听的入口，**不会**断掉已建立的会话（2026-09-27 实测：停掉全部接收器作业后，
已登记的会话仍能执行命令并返回退出码）。所以"登记后退休接收器"对**当前会话的数据路径**是安全的，
影响的是**未来重连的入口**——要不要保留它，取决于是否承诺自动重连（见"会话失效后的两级恢复"规则）。

| 验收 | 命令/判据 |
|---|---|
| 全量测试 | `python -B -m pytest tests/ -q`（当前基线 1336 passed / 1 skipped）|
| 关闭时行为不变 | 整图仍 14/14（`output/runs/*-off-*`）；`session_control` 不建状态表；`Attempt` 序列化不多字段 |
| 打开时仍 14/14 | 整图 14/14（`*-on-*`）|
| 重复稳定性 | 连续 3 次整图全 14/14（见 `evidence/stability_20260927.txt`）|
| 中继三类语义 | 见 §4 的实测记录 |
| 纳管三卡实机 | 三张卡各一条真机调用，三闸全过：`native` / `web` / `mount`（见 [实机验证记录](validation_runs.md) 第 180 轮）|
| 改动后整图回归 | 14/14（`output/runs/E-adopt-recheck-1`）|

## 6. 尚未完成（如实）

1. **深层端的纳管**（`ensure_deep_endpoint`）：中继半已具备，深层的执行点仍未接线，闸门按名拒绝。
2. **`session-exec` 读回**：控制台会话执行系统命令时读回会卡满超时（本次 mount 卡的启动调用即如实记 `timeout`）；
   纳管不受影响（注册与核验走的是登记表与只读探针），但该通道本身仍是挂账缺口。
3. ~~**DC 上遗留的 OU/GPO**~~：**已清除**（2026-09-27）。第 163 轮的"不可撤销"结论针对的是
   `PC1 → DC` 那几条通道；后来中继把 `控制端 → 中间机 → DC` 打通，同一条 `impacket-wmiexec`（带输出回读）
   经中继即可操作。先只读清点：OU `AGV-Recovery`（内含**被移进来的 PC1 计算机账号**）+ GPO `AGV-FWOff`
   （2026-09-25 21:51 建，链接到该 OU）。安全顺序：**先把账号搬回 `CN=Computers`**（直接删 OU 会连账号一起删），
   再 `Remove-GPO`，最后删空 OU。事后清点：OU/GPO 均只剩系统默认项，PC1 账号在 `CN=Computers`，
   整图仍 14/14（`output/runs/I-post-dc-cleanup`）。


## 2026-10-04：进程退出后的原操作查询（010）

动作进程退出或超时不表示目标动作失败。长任务的 operation_ref/query_ref 与原 call_id 随不可覆盖的 intent/receipt 保存；恢复通过后端原操作查询回收迟到回执。查询缺失、回执身份不符或操作仍在执行时，副作用保持 unknown，不得改卡、改变体或重启动作绕过。`Stage.reconcile` 是调用方注入查询接口的接点，不会创建新通道、接管已有通道或重新执行原动作。本轮未提供通道纳管，也未虚构通用后端查询：没有适配器即 `ORIGINAL_OPERATION_QUERY_UNAVAILABLE`。

恢复原动作的副作用与消费该动作产物是两个步骤；即使回执已结清，也需按验证卡重新确认目标、身份和可用性。连接探针通过不能代替原任务完成回执，原任务成功也不能代替节点目标验证。
