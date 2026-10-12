# 术语表（AGV 的领域词，唯一口径）

这一页只做一件事：给每个领域词一个定义和一个真源。写代码、写文档、写提交信息时
都按这里的词来，避免同一个东西换着名字出现（历史词见文末）。

## 1. 目录与文件

| 词 | 定义 | 真源（唯一） |
| --- | --- | --- |
| **skill（技能）** | 一条固定方法：一个确定的工具模式或脚本入口 + 参数契约 + 结果判据。技能不是工具本身，也不是工具的全部功能。 | `skills/registry.json` 的一条 |
| **skill id** | 技能的稳定标识，同时是目录名、卡片 id、注册表 id：`<域>.<短语>` 恒两段，域固定九个
（`pre` / `post` / `exec` / `cred` / `evasion` / `exploit` / `priv` / `session` / `transfer`），如 `pre.nmap_tcp_probe`。 | 同上 |
| **registry（登记源）** | 手写的薄目录，一行一条技能；改技能先改这里。 | `skills/registry.json` |
| **index（派生索引）** | 从登记源生成的检索视图（分类、case、provides、关键词、status）。生成物，不手改。 | `skills/index.json`，由 `scripts/build_skill_index.py` 生成 |
| **card（机器契约）** | 一条技能的机器可读定义：输入参数、输出证据、判据闸门、入口脚本、状态、一行指针。 | `skills/<id>/skill.json` |
| **knowledge（知识层 / 技能卡）** | 一条技能的**主工件**（人和模型都读）：这类检查怎么做——何时用、怎么做、怎么判（旧八段卡随迁移收口）；靶场实测只在本卡末段。机器契约里不写长叙述。 | `skills/<id>/SKILL.md` |
| **adapter（适配器 / 装订器）** | 把卡片输入落成固定 argv、执行、解析成证据信封的脚本；不参与匹配与判定。只有 `assembly=fixed` 的卡才有（`model` 卡由模型装配命令行）。 | `skills/<id>/entry.py` |

## 2. 召回与绑定

| 词 | 定义 | 真源 |
| --- | --- | --- |
| **case** | 图词汇里的精确键（rule case id），面向**图节点**召回技能。 | 图节点的 `semantics.case_id` + 注册表 `case` 字段 |
| **aliases（检索别名）** | 同一对象的其他说法（`scm` 对 `smb/445`、`ms17-010` 对 `CVE-2017-0144`）：命中按弱票计入检索分（1 分/条、封顶 3），同时是弱召回通道；不得与自身精确字段重复。 | 注册表 `aliases` 字段；规则见 [007 检索规格](../../specs/007-skill-retrieval/spec.md) |
| **provides** | 运行时需求键（`session` / `credential` / `transfer` / `reachability`），面向**运行现场**召回供给技能；唯一的运行现场键（原 `purpose` 分类字段已于 D36 并入这里）。 | 注册表 `provides` 字段 |
| **fact（事实键）** | 检查卡（pre/post）回答的图 LEAF 事实键（snake_case：`hacl` / `exec_code` / `ttp_exists` / `network_service_info` / `leak_account` / `path_exists`）；面向**检查**召回，动作卡不得声明。 | 注册表 `fact` 字段；派生视图见索引 `by_fact` |
| **status** | 卡片状态：`implemented`（实机跑通并留调用记录）/ `planned`（代码就位但未验证）/ `deprecated`（退役，仅供历史）。只有默认口径下可选的才是 `implemented`。 | 卡片 `status` 字段；派生视图见索引 `by_status` |
| **assembly（装配方式）** | 命令行由谁装配：`fixed` = 装订器（`entry.py`）装配固定 argv，运行层只绑参数；`model` = 模型按技能卡模板与参数契约装配（载荷填装、参数取值、多步顺序）。判据与证据纪律两条路都一样，由确定性判定器收口。 | 卡片 `assembly` 字段；派生视图见索引 `by_assembly` |
| **brief（装配简报）** | 交给模型的「命令模板 + 参数契约 + marker 纪律」三件套。材料类参数只出现 `withheld` 与形状提示（明文 / NTLM），**值不在简报里**：模型填形，运行层在执行前替换。 | `runtime/assembly.py::brief`；接缝 `assemble_command` |
| **装配解析器（PARSERS）** | 每张 `model` 卡一个的确定性读数：把回显读成卡片声明的那几个证据字段。没回显（`observed is None`）不给正证据；「命令答了但没有」才是负事实。卡片字段与解析器字段由守线逐卡比对。 | `runtime/assembly.py::PARSERS` / `EVIDENCE_FIELDS` |
| **selection（选择）** | 选择器的输出：`locked`（锁定的技能）/ `candidates[]`（候选；形态不符的带 `not_applicable`）/ `excluded[]`（被状态挡下的卡）/ `inputs` / `missing` / `pending` / `notes`。 | `src/skills/selector.py` |
| **binding（绑定）** | 把取值来源（`from: graph` 图事实 / `runtime` 运行现场值 / `config` 运行配置）填进卡片入参；同一函数内比较 `const`（形态）。 | 卡片 `input` + 选择器 |
| **check_shape（形态常量）** | 检查卡里钉住本卡方法形态的输入（`const` 标量；如 `network_service` / `credential_auth`）：**不匹配＝本卡不适用**（永不锁定、不做备选），**缺值＝缺口可见**（不猜默认），`false` / `0` 是值不算缺。形态唯一来源＝卡面 `const`，不另存真源表。 | 卡片 `input.*.const`；规格 [004 §4.3](../../specs/004-orchestration-adoption/interface_table_v1.md) / R05 |
| **检索分（retrieval score）** | 候选排序的唯一依据：技术编号 / 服务名 / case / 漏洞号每类 4 分 + 别名 1 分/条（封顶 3）；同分回注册表顺序。分数只排序、不救活（可用性看绑定与硬门禁）。 | `index_builder.score_skill`；分区视图 `by_entry_kind` |
| **检索日志（retrieval log）** | 一行一次检索的 JSONL 记录：目标关键信息 / 大类（action / fact / supply）/ 候选与分数 / 锁定与原因。 | `src/skills/retrieval_log.py`；入口 `scripts/select_skill.py --log` |
| **missing** | 图没有建模这个事实 ⇒ 是图的问题，报 `graph_gap`。 | 选择器的 `missing` 列表 |
| **pending** | 运行现场还没提供这个值（会话、凭据、命令）⇒ 是运行的问题，报 `need`。 | 选择器的 `pending` 列表 |

## 3. 执行与判定

| 词 | 定义 | 真源 |
| --- | --- | --- |
| **attempt（尝试）** | 一张卡的一次调用尝试（含重试计数）。 | 节点循环的 attempts |
| **call（调用）** | 一次真实执行，`call_id` 是证据锚点，调用目录里落 inputs / envelope / judgement。 | `output/runs/<run>/` |
| **envelope（证据信封）** | 调用的机器可读返回：证据字段 + 原始输出 + 标记 + 时间。 | 适配器输出 |
| **judgement（判定）** | 判定器对一次调用的结论：`pass` / `unsatisfied` / `uncertain`（+ `value`）与理由。 | `src/runtime/checker.py`，入口 `scripts/check_call.py` |
| **gate（闸门）** | 判定报告的三行：`freshness` / `target` / 本卡判据行（`identity` 或 `effect`）；序列由判定器固定，卡只写一个判据名。 | 判定报告 `gates[]` |
| **runtime vocabulary（运行词表）** | 循环 / 运行 / 判定的状态与动作枚举（调用状态、节点状态、loop 与 run 决策动作）的唯一真源。 | `src/runtime/vocabulary.py` |

## 4. 图与运行

| 词 | 定义 | 真源 |
| --- | --- | --- |
| **node（节点）** | 攻击图里的一条攻击步骤；验证的对象。 | 攻击图 JSON |
| **run（运行）** | 一次整图验证：决定表逐节点推进，产物落一个 run 目录。 | `scripts/run_path.py` → `run_result.json` |
| **need（缺口）** | 运行现场缺的东西（一个会话、一份凭据）。 | run 决策的 `need` + `needs[]` |
| **supply（供给）** | 为满足 need 而跑的一次支撑类技能。 | `supply_runner` + `supplies[]` |
| **assumption（假设）** | 前提是参考不是闸门：低置信照跑时记下的「哪条前提没成立」。 | `assumptions[]` |
| **account alias（账户别名）** | 操作者自己的一笔登记：图上的**角色键**（`domain_administrator`）与素材实际按哪个**登录名**入账（`Administrator`）是同一个主体；**只从运行输入来，运行绝不自己猜**（D24-c：猜＝把「手里有个账号」升格成「手里有那个权限」）。 | 运行输入 `account_aliases`；`run.materialize_account_aliases`；`run_result.account_aliases[]` |
| **chain（链）** | 一个运行需求的分段供给路径：有序段，每段一张已注册的卡。链是数据（谁在第几步、什么角色），段间绑定是代码。 | 注册表 `chains`；派生视图 `index.by_chain` |
| **segment（段）/ role** | 链里的一步：`dump`（在目标身上落产物）/ `exfil`（把产物搬出去）/ `parse`（在执行端读出材料）。新角色必须同时带来绑定与测试。 | `src/runtime/supply.py` 的 `ROLES` / `CHAIN_BOUND_VALUES` |
| **段级超时下限** | 每个角色自己的执行下限（dump 120s / exfil 900s / parse 300s）：CLI 的 `--timeout` 是整次 run 的一个数，慢段不被它掐死。 | `supply.SEGMENT_TIMEOUT_FLOORS`，落到 `chain.trace[].timeout` |
| **channel（通道）** | 某台主机上「已经打得通的命令入口」这类运行现场资产（webshell 的 `base_url` + `include_path` 等）。卡片把通道状态留在信封里（`envelope.channel`，缺 id 时运行层按 `<host>-<driver>` 命名），运行循环登记；**用之前先复验**。 | `run_result.channels{}`；复验卡 `post.channel_echo`；描述符 `session.channel_descriptor` |
| **运行时别名（target_aliases）** | 运行层注入的「同一台执行主机的另一种拼写」（会话宿主自报的容器短 id、机器名）：仅当会话登记的逻辑名 == 节点 `target_graph_host` 时注入，target 闸据此对齐观测；容器对宿主不算同一台。 | `requirement.target_aliases`；`scripts/run_path.py` 的 `runtime_target_aliases` |
| **方法链锁定（locked_chain）** | case 注册了链时，运行层锁定链的哪一个段：locked 落在链外（如 `--include-planned` 带进来的试验卡）时，链的第一个就绪段接管。 | `supply.locked_chain`；节点结果的 `chain.locked` |
| **account_gap（账号缺口）** | 节点语义点名的账号里，这次供给没覆盖到的那些（`<host>:<account>`）。 | 供给记录的 `account_gaps[]` + `needs[].why` |
| **graph_gap** | 图缺口：图上缺事实，需要回攻击图侧补。 | `run_result.graph_gaps[]` |
| **skill_gap** | 卡缺口：没有可选的技能（含「只有 planned 卡」）。 | `run_result.skill_gaps[]` |

| **权限等级（privilege tier）** | 「谁在回答」的等级：`none` < `user` < `admin` < `system`（`root` 与 `system` 同级）。由观测身份推导，不由调用方随口声明。 | `src/runtime/identity.py`（`RANK` / `tier_of` / `satisfies` / `required_tier`，唯一词表） |
| **min_privilege（卡的等级要求）** | 卡片对 `session_ref` 提出的最低等级（`user` / `admin` / `system`）。等级不够**或未知**都算缺口，但记 `pending` + `privilege`（不是 `missing`）。 | `schemas/skill.schema.json`；选择器 `privilege_shortfall` |
| **escalate（提权包装）** | 通道上的一个**命令前缀**（`{"argv": [...]}`）：把命令送进更强身份执行。声明了却给不出可用 argv ⇒ 直接 `SystemExit`（不静默降权）；**marker 在提权之外**。 | `session.escalate_prefix` / `escalate_command`；`session.root_via_suid` 产出 |
| **通道升级（channel upgrade）** | 通道登记的例外规则：首个通道胜出，**等级更高者可以接管**（弱换强要留痕、同强不顶替）。 | `run._channel_upgrade` |
| **提权供给（第四条 session provider）** | 运行层已持有通道但等级不够时，跑 `session.root_via_suid` 把这条通道升上去——唯一「不新开东西」的 provider。 | `scripts/run_path.py` 的 `escalate_session` |

## 5. Agent 层（D32）

| 词 | 定义 | 真源 |
| --- | --- | --- |
| **agent 层** | 包在运行内核外面的角色契约层：planner / executor / verifier / session + orchestrator（壳）。不是第二个循环。 | `src/agents/`；入口 `scripts/run_agent.py`；契约 `docs/product/agent_contract.md` |
| **planner（规划）** | 图求值器：按图给出「下一步」（`StepSpec`）；只读图、不写图、不选工具。 | `agents/planner.py` |
| **StepSpec（步骤规格）** | 一步的说明书：动作 / 节点 / 目标 / 锁定的方法 / prechecks / 还缺哪些值。 | `agent_plan.json.steps[]`（干跑）/ `run_result.agent.steps[]`（实跑） |
| **precheck（最小必要验证）** | 开跑前登记的前置检查：五类（`reach` / `service` / `privilege` / `credential` / `method`）× 三模式（`program` / `logic` / `graph`）× 三态（`ok` / `missing` / `unknown`）。**永不阻断**（D31：前提是参考与追溯）。 | `agents/planner.prechecks_for` + `agents/orchestrator.make_precheck_runner` |
| **verifier（复核）** | 只读复核证据链的角色：四行 + 三值裁决 + 一个可执行的修复动作。不碰靶场、不补观测。 | `agents/verifier.py` |
| **review 四行** | `freshness`（是不是这次的证据）/ `target`（对的是不是这台）/ `identity`（身份够不够；无会话上下文写 `n/a`）/ `effect`（效果出没出来）。 | `verdict.json.checks[]` |
| **verdict（裁决）** | `go`（链成立）/ `repair`（还有下一手）/ `stop`（没什么可改）。`repair.action` 只有 `retry` / `next_method`（`contract.LOOP_REPAIRS`，每条都对应循环的一条决策；没有 `adjust_inputs`）。 | `agents/contract.py` |
| **suggestion（建议）** | 复核给出的自由文本建议，**不是命令**（例：`escalate: ...`）。实际驱动由 selector / supply 的等级缺口机制负责。 | `verdict.suggestions[]` |
| **session agent（会话 agent）** | 管「这台主机上我们持有什么」并选择供给路径的角色；决策顺序 escalate → verify → redis → webshell → none。 | `agents/session_agent.py` |
| **ProviderChoice（供给路径决策）** | 选了哪条 provider、为什么、要什么等级、跑哪张卡；**先记账后执行**。 | `run_result.agent.providers[]` |
| **ledger（会话账本）** | 当前 run 在每台主机上持有的会话 / 通道 / 身份 / 等级 / 来源——**视图**，从状态重算，不许反写状态。 | `session_agent.ledger()` |
| **handoff / pivot（迁移与跳板计划）** | 「这条会话可以交给 msf 管」「这台主机可以当跳板」的计划行；**只做计划，不假装执行过**。 | `SessionRecord.handoff` / `pivot` |
| **orchestrator（编排壳）** | 只负责顺序与记账的壳（不是角色）：干走、复核钩子、precheck 钩子、provider 记账、`agent_report`。 | `agents/orchestrator.py` |
| **dry-run（干跑）** | 默认模式：内存乐观模拟，写 `agent_plan.json`，每步 `simulated: true`，不建连 / 不发包 / 不写 state。 | `AgentPolicy.dry_run`；`--live` 才反过来 |
| **assumption note（干跑假设）** | 干跑里「假设成功」的留痕，词表三条：`supply assumed for node N: <值>` / `supply assumed for node N: <host>:<user>` / `graph gap crossed at node N: ...`。 | `agent_plan.json.notes[]` |
| **中间记忆 vs 证据** | 证据 = 调用目录里的原始材料（可细）；中间记忆 = 模型 I/O 用的精简行（不放原文）。两笔账分开放。 | `agent_contract.md` §6 |

## 6. 历史词（不作为当前口径）

| 历史词 | 现状 |
| --- | --- |
| **ability / abilities** | v3 期用词，现统一为 `skill`；旧工件在 `archive/legacy_v3_ability/`。 |
| **capability（当作技能用时）** | 同上。注意 `capabilities` 在 Linux 语境下是内核能力集（如容器逃逸的前提），那是另一个领域词，不冲突。 |
| **能力卡片 / 能力检索**（退役） | 分别对应现在的「技能卡片（card）」与「技能检索（recall）」。 |
| **能力**（当作注册单元时） | v3 期用词，现在写「技能」。「执行能力」「攻击能力」「身份和能力」这类泛用中文不是领域词，照常使用。 |
| **purpose（用途分类字段）** | 已并入 `provides`（D36）：它与 `provides` 同词表、没有独立召回消费者，注册表不再声明该字段。 |

`docs/decisions.md`、`docs/product/reference/`、`archive/` 里的旧词是历史记录，按原样保留；
当前契约、代码、技能卡与目录命名不用旧词，中文里也不再把「能力」当作注册单元
（`tests/test_terminology.py` 守这两条术语线：英文 `ability`，以及「能力注册表 / 能力卡 / 一条能力」这类写法）。
