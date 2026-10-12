# 红日 7 攻击图完成度审计

审计时间：2026-09-10。

本页只审计“冻结 `rules5.P` 下，为红日 7 建模并生成攻击图”这个目标。

> 路径说明：`data/inputs/hongri7/` 是本机靶场资料（不进 git）；`output/hongri7/` 为可重跑产物。VMware 部署、真实执行器、会话管理和多 Agent 调度属于后续运行系统，不作为本页完成判定。

## 目标拆解

| 要求 | 当前结论 | 证据 |
| --- | --- | --- |
| 使用用户指定红日 7 writeup 作为第一版目标 | 已满足 | `data/inputs/hongri7/MODEL_NOTES.md`（本机资料，不进 git）和 [攻击图大白话说明](hongri7_attack_graph_plain.md) 都以该 writeup 为基线，并说明官方页、原作者文章和本机部署证据的关系 |
| 不修改原 `rules5.P` | 已满足 | `data/inputs/hongri7/rules5.P` 与 `E:/Desktop/paper-动态评估攻击图/rules5.P` SHA-256 均为 `71D703B26423E84E742E8E91670CB31C81E50AAF984951F283430D961300B6A8` |
| 用现有规则写事实 `.P` | 已满足 | `data/inputs/hongri7/Hongri7.P` 与 `data/inputs/hongri7/Hongri7_compat.P`（本机资料）均只使用 `rules5.P` 已声明 primitive 与 `attackGoal/1` |
| 不预置派生结论 | 已满足 | [review_report.json](../../output/hongri7/review_report.json) 中两版均为 `derived_seeds=false` |
| 用 Mulval2 Docker 生成攻击图 | 已满足 | [generation.json](../../output/hongri7/generation.json) 记录 `container=Mulval2`、镜像 hash、容器工作目录和原始 run 目录；run 目录保留 `AttackGraph.txt/xml`、`ARCS.CSV`、`VERTICES.CSV`、`trace_output.P` |
| 生成可查看产物 | 已满足 | [Hongri7.action_graph.pdf](../../output/hongri7/pdf/Hongri7.action_graph.pdf)、[Hongri7_compat.action_graph.pdf](../../output/hongri7/pdf/Hongri7_compat.action_graph.pdf)、两份 JSON 和 DOT 均存在 |
| Docker 和宿主关系说清楚 | 已满足 | `isDocker(web2, web2_docker)` 固定表示“第一个参数是宿主，第二个参数是容器”；[拓扑图](../../output/hongri7/Hongri7.topology.png) 显示 `web2_docker` 属于 `web2` |
| 一个主机多个 IP 怎么表示 | 已满足 | 攻击图中的 host 是权限主体；多 IP 与连接端口放在 `data/inputs/hongri7/assets.json`（本机资料），不拆成多台 host |
| 说明规则冻结造成的语义缺口 | 已满足 | [攻击图大白话说明](hongri7_attack_graph_plain.md) 明确区分主图和兼容图；[review_report.json](../../output/hongri7/review_report.json) 记录主图缺 `pc2 system`、`dc system`，兼容图闭合但不是严格 writeup 等价 |

## 当前产物

主图：

- 输入：`data/inputs/hongri7/Hongri7.P`（本机资料）
- 原始 MulVAL 输出：[AttackGraph.txt](../../output/hongri7/runs/20260909_151919_9a3c379c/Hongri7/AttackGraph.txt)
- 投影 JSON：[Hongri7.action_graph.json](../../output/hongri7/json/Hongri7.action_graph.json)
- PDF：[Hongri7.action_graph.pdf](../../output/hongri7/pdf/Hongri7.action_graph.pdf)

兼容图：

- 输入：`data/inputs/hongri7/Hongri7_compat.P`（本机资料）
- 原始 MulVAL 输出：[AttackGraph.txt](../../output/hongri7/runs/20260909_151919_9a3c379c/Hongri7_compat/AttackGraph.txt)
- 投影 JSON：[Hongri7_compat.action_graph.json](../../output/hongri7/json/Hongri7_compat.action_graph.json)
- PDF：[Hongri7_compat.action_graph.pdf](../../output/hongri7/pdf/Hongri7_compat.action_graph.pdf)

辅助映射：

- 资产映射：`data/inputs/hongri7/assets.json`（本机资料）
- 拓扑图：[Hongri7.topology.png](../../output/hongri7/Hongri7.topology.png)
- 读图说明：[hongri7_attack_graph_plain.md](hongri7_attack_graph_plain.md)

## 推荐定案

把 `Hongri7.P` 定为论文和系统的第一版主输入。它不伪造协议语义，能自然暴露当前 `rules5.P` 表达不了 PsExec/SMB 横向的问题。

把 `Hongri7_compat.P` 定为对照输入。它用于说明“如果把旧规则里的 `winrm` 当成 Windows 凭据型远程执行分类，图可以闭合”，但这个结论要带着兼容标记展示。

这不是退让，恰好是研究价值：writeup 中看起来确定的攻击路径，进入逻辑规则以后，哪些步骤能被确定推导，哪些步骤会变成规则缺口，是系统应该显式给出的结论。

## 不属于本目标的未完成项

- 真实执行器还没有逐步复现攻击链。
- PC1 在本机部署里有 OA 内存证据，但当前网络不可达，未取得 HTTP 200 验收。
- Docker Desktop 在 2026-09-10 当前会话中启动后，Docker CLI 查询 engine 超时；因此没有做新一轮 Mulval2 复跑。由于 `.P` 输入未改，2026-09-09 的 Mulval2 run 仍是当前攻击图生成证据。
- 多 Agent Supervisor/Worker/Reviewer 的运行系统仍是后续工程任务，不影响本页对静态攻击图交付的完成判定。

> **补记（2026-09-16）**：本节列的四条「后续工程项」在此后各轮里都已有后续状态；本页结论不变，这里只留指针（详见 [实机验证记录](validation_runs.md)）——
> ① 真实执行器已逐步复现攻击链并最终整图全绿（`D32h-live3` 起 `run: succeeded via done_all`；D40 两跑同口径）；
> ② PC1 的 OA 通道已打通（D23 侦察证实「445 被拦」是误判、OA 通道可用，D24 起作为标准通道）；
> ③ 图侧已按 `rules5_v2` 重生成（`Hongri7_v2.action_graph.json` 自 D29 起为运行输入；RULE 12 于 D32-h 就地补凭据前提，编号位移见 [rules5_v2 说明](rules5_v2_windows_lateral.md)）；
> ④ 多 Agent 运行系统已落地（D32 契约 / D35 模型接缝 / D37 真机三接缝各问一次）。

