# AGENTS.md — attack-graph-validation-agent 宪章

本文件 = 项目 constitution。任何 Codex 会话在本仓开工前先读本文件（再读 `specs/` 下当前 feature 的 spec/plan/tasks）。
本文件优先于默认行为；与本文件冲突的临时说法以本文件为准，改本文件要有明确理由并落 `docs/decisions.md`。

## 1. 项目定位

- **阶段一（当前）**：确定性攻击图路径验证。输入 = 离线推理好的攻击图（+ 主机/IP 对账表），在红日 7 靶场按图的路径与前置条件逐节点复现，产出可审计证据（call 目录 + call_id）。
- **阶段二（未来）**：在此之上做自动渗透。**现在不为它预留接口**（YAGNI，见 §5 ponytail）。
- 不做：新攻击面发现/扫描探索、长期记忆、跨靶场迁移学习。

## 2. 质量线（不妥协）

1. 工程级，不交付玩具级工件：能上生产评审的目录结构、命名、错误语义、文档。
2. **证据落盘**：一切实机执行产出 call 目录（stdout/stderr/call.json），文档引用的 call_id 必须真实存在且为严格形状（`call-YYYYMMDDTHHMMSS-<6hex>[-suffix]`）。
3. **诚实失败**：uncertain 就是 uncertain，不粉饰、不吞异常、不把「工具跑了」当「节点被证明」。失败与事故原样记录（含修复过程）。
4. 不在运行层偷偷重试。重试属于 run/编排层；一次调用 = 一份证据。
5. 测试基线不可回退：`pytest -q` 必须全绿（当前基线：**187 passed**，口径只收 `tests/`）；一条命令跑全部检查：`python scripts/ci.py` —— 三项：`pytest tests/` + `--check cards`（每张卡面可读、id 唯一）+ `--check tree`（`docs/file_tree.md` 与 `scripts/README.md` 点名每个源码文件）。提交钩子 `scripts/hooks/pre-commit` 直接调它（`core.hooksPath` 已指向 `scripts/hooks`）。
6. 文本面一条纪律：UTF-8 不带 BOM（唯含非 ASCII 的 `.ps1` 必须带 BOM——PS 5.1 无 BOM 时按 ANSI 读它）；行尾一律 LF（唯 `.cmd` / `.bat` 留 CRLF）。写盘按字节与 LF 落（Python 传 `newline=""`，PowerShell 用 `[System.IO.File]::WriteAllText`）；守线见 `tests/test_project_layout.py`。

## 3. 开发流程（每个 feature 必走，Spec Kit 语义）

本机未安装 `specify.exe` / `openspec` CLI，按 spec-kit-workflow 的 fallback 条款**显式模拟各阶段并手写制品**；制品结构照抄 Spec Kit，将来装了 CLI 可直接接管。

```
0) 变更边界（OpenSpec 四件套）: problem / goal / scope / non-goals / acceptance
1) spec : specs/<NNN>-<slug>/spec.md   （问题、范围、非目标、验收标准、风险）
2) plan : specs/<NNN>-<slug>/plan.md   （架构、改动点、依赖、风险与回滚）
3) tasks: specs/<NNN>-<slug>/tasks.md  （有序、可测、每条含验证命令）
4) implement                            （ponytail full 档，见 §5）
5) verify : pytest -q 全绿 + index --check + 活面审计（`scripts/audit_markers.py`）+ 实机证据（涉实机时）
6) 落盘   : PROGRESS.md / CONVERSATION_LOG.md 追加 + docs 批同步 + 双仓 commit
```

- 样例（已闭环）：`specs/001-msf-endpoint-lane/`（D43，msf 常驻端点车道）。
- 先写制品再动代码；验收标准在实现前定稿，实现后逐条回填证据（call_id）。
- tasks 状态只有 `[ ]` / `[x]`；不许「差不多完成」。

## 4. 运行时纪律（本机）

- Python = `D:\Conda\python.exe`；运行前 `$env:PYTHONIOENCODING='utf-8'`；`from runtime import ...` 需 `$env:PYTHONPATH='src'`。
- 含非 ASCII 的脚本一律 `[System.IO.File]::WriteAllText($path,$t,[System.Text.UTF8Encoding]::new($false))` 落文件再跑（PS 5.1 管道按控制台代码页转码，会静默吃字符）。
- 跑卡骨架：
  `& D:\Conda\python.exe scripts/run_skill_remote.py --skill <id> --input <inputs.json> --run-dir <dir> --remote kali@192.168.52.128 --password kali --timeout 300 [--check --node N --graph <graph.json> --assets <assets.json> --host-map <map.csv>]`
  退出码：0 pass / 1 unsatisfied / 2 uncertain / 其它 = 出错。
- VM：用完即 `vmrun suspend`，不留 running；靶场操作全程 `nogui`。
- 不写 C 盘用户区；跨会话记忆只在 `$CODEX_HOME\work`（PROGRESS.md / CONVERSATION_LOG.md，实时追加）。
- `output/`、`tmp/` 不进 git；`docs/` 与 `skills/`、`src/`、`tests/` 是提交面。

## 5. ponytail 规则（full 档常驻，ACTIVE EVERY RESPONSE）

- ladder：需要存在吗 → 代码库已有吗 → stdlib/原生特性 → 已装依赖 → 一行 → 最小实现。
- 禁止：投机回落、防御性分支、为「不可能发生的输入」写修复路径、未要求的抽象/工厂/配置。
- 保留（不可简化清单）：信任边界校验、防数据丢失的错误处理、安全措施、诚实失败路径、用户明确要求的内容。
- 非平凡逻辑（分支/循环/解析器/安全路径）留**一条**可运行检查（assert 或小 test），不放框架。
- 刻意的简化用 `ponytail:` 注释标天花板与升级路径。
- 输出：代码优先 + ≤3 行说明；用户点名要的报告/讲解不受此限。

## 6. 分工地图（谁在哪层）

| 层 | 位置 | 职责 |
|---|---|---|
| 图/选择 | `src/graph/`、`src/skills/`（selector + index_builder） | 按图节点选卡（canonical 选择政策） |
| 技能卡 | `skills/<id>/`（SKILL.md 主工件 + skill.json 机器契约 + entry.py 适配器） | 攻击实现方法（002 八段模板：前提/工具功能/命令模板/判据/坑点/模型自由度）+ 参数契约 + 证据 |
| 运行时 | `src/runtime/`（session / adapter / runner / loop / run / supply / chain / checker） | 执行位置、会话引用、envelope、redaction、节点与整图循环、判定 |
| 端点客户端 | `src/runtime/clients/` | 会话驱动客户端（webshell plain：agv_http_cmd；msf 常驻端点：agv_msf_rpc） |
| agent 层 | `src/agents/` | 四角色契约与编排：planner 只读图、verifier 只读复核、session agent 会话账本、orchestrator 记账；模型只从三个接缝进（`--model`，默认关） |
| 输入包 | `src/inputs/` | 一次 run 的四份输入（图 / 部署表 / 对账表 / 上下文）+ 可选项体检（`scripts/check_inputs.py`，运行同款 loader） |
| 索引/注册 | `skills/index.json`、`skills/registry.json`（由脚本生成/校验） | 检索与状态 |
| 文档 | `docs/product/`、`docs/course/`、`docs/decisions.md` | 契约、矩阵、运行台账、决策 |

## 7. 作业纪律：不许自停（2026-10-04 爷爷拍板 · 永久）

- **有下一步就做下一步**：一轮结束时必须已经开工下一步；禁止以「要不要继续 / 请指示 / 需要我换 X 吗」收尾。
- **方案性决定自己裁**：口径冲突按「爷爷已拍 > 桥（GPT6.1）建议 > 我的判断」处理，并把裁定与理由写进
  `specs/<NNN>-<slug>/spec.md` 的裁定节或 `docs/decisions.md`，不逐条请示。
- **只有三种情况允许停下问**：① 不可逆的破坏性动作（删仓、格式化、覆盖生产数据、向陌生目标发请求）；
  ② 唯一技术前提缺失且无法降级（没靶场、没密钥、接口全挂）；③ 爷爷明确说「先给我看再动」。
- **其余情况一律做完再报**：新增字段、拆卡、改名、目录调整、写文档、跑真机、改 ci —— 都做完，把证据
  （测试输出、命令、产物路径、提交号）贴出来。
- **每轮收尾格式**：`做完 X（证据：…）→ 正在做 Y（下一步：…）`；不许只报计划不干活，不许空转。
- **遇到需要爷爷拍板的点**：写进交付说明的「待定项」，同时**继续把不依赖它的部分做完**，不卡在待定项上等。
- **跨轮目标**：persist 在 thread goal 里；未完成不缩小目标，接着干，直到要求全部满足并被证据证明。

## 8. 泛化自查（2026-10-04 爷爷拍板 · 每次动手与收尾都要问）

- 不管是自己写代码还是让桥出方案，做的时候**反复问同一个问题**：
  **换了靶场、换了 IP、换了服务名，这段代码还奏效吗？**
- 不奏效就是不够泛化：**停下来研究更泛化的方法**，不要先把"这次能跑通"的版本堆上去。
- 具体查：靶场地址 / 主机名 / 端口 / 服务名 / 卡 ID / 节点号 有没有被写进**代码**
  （它们应该是数据：host map / 图 / 卡）；有没有把"这次跑通了"当成"方法对了"。
- 交付时要能说明"换一份数据仍然可用"，并给出证据（例如另一份 host map、另一张图、另一个部署的用例）。
