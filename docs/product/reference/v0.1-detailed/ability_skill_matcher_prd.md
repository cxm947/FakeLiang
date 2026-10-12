# Ability / Skill 检索 PRD

状态：待实现的产品需求；本次仅交付本文，不新增或修改代码、Schema、registry 与 Skill。

| 文档元数据 | 值 |
|---|---|
| `prd_id`, `prd_version` | PRD-05，1.0 |
| `status`, `runtime_contract_version` | review_ready，0.1 |
| `depends_on` | overall_prd.md 的统一口径 v0.1；V1 图 Schema 1.0.0；GraphBundle、Executor/Supervisor、PostgreSQL 子 PRD 的同批共享契约 |
| `owned_files` | `docs/product/ability_skill_matcher_prd.md` |
| `updated_at` | 2026-09-09 |

## 共享契约引用 / DB Schema 对齐

本文采用 `runtime_contract_version=0.1`，共享定义以[总 PRD](overall_prd.md)、[PostgreSQL 运行状态 PRD](postgres_runtime_prd.md)及 [Executor / Supervisor PRD](executor_supervisor_prd.md)的统一口径为准。运行契约版本与 V1 图 Schema、Ability Schema 和匹配接口各自的版本独立，不互相替代。

| 共享约定 | 含义与使用边界 |
|---|---|
| `runtime_status=pending/ready/running/succeeded/failed/blocked/unsupported/uncertain` | 统一运行处理状态；Matcher 的检索 status/readiness 不直接转换为数据库运行状态 |
| `claim_verdict=proven/refuted/inconclusive/unassessed` | 对具体命题的证据结论；工具退出、匹配成功与候选建议均不能直接成为最终结论 |
| `truth_value=true/false/unknown` | 已提交事实的真值；不能由候选排名、模板预期产出或部分观察直接赋值 |
| 物理 schema `agv_runtime` | 本模块复用唯一运行数据 schema，不建立能力模块专用的同义运行表 |
| 固定六张表 `graphs/runs/run_steps/run_facts/evidence/events` | 分别承载图快照登记、运行、步骤状态、事实状态、证据与事件；具体字段、事务和写入校验沿用共享 DB 契约 |

Ability 只产出候选、参数绑定、观察和证据建议；不直接写这些表、不提交事实、不解锁 effect。所有持久化写入由 Supervisor/DB adapter 执行，由 Supervisor 核验后通过 DB adapter 按共享事务契约提交。接口中的图、事实和调用引用只定位共享数据，不引入另一套状态存储。

effect 解锁继续遵循 all-or-nothing：provider step 的全部必需检查通过并被 Supervisor 判定为 succeeded 后，才在同一事务中提交该步骤的 effect facts。`partial_observation` 只作为待核验观察与证据建议保留，不能提前解锁下游。

## 1. 产品目标与边界

输入一个已有攻击图步骤或一条待核对的 LEAF 事实，返回有依据、可解释的 ability 候选。结果必须回答：该能力能证明哪个具体命题、是否只能补充前提事实、缺少哪些参数、受哪些运行条件阻塞，以及为什么当前没有支持。

步骤判断以 **`case_id + effect_refs + ability template`** 为依据。`premise_refs` 提供绑定与前提，AND/OR 提供依赖结构；节点类型、规则标题、ATT&CK 编号、工具名称与自然语言相似度均不能代替能力语义匹配。

Matcher 负责注册表加载约束、匹配、字段绑定、候选排序、解释和待实例化模板，不执行 Skill/MCP。Ability 适配器在执行层调用后只产出 pre_check 或 action/post_check 所需的结构化观察、产物引用及候选判定，不直接修改 PostgreSQL 状态。编排器决定调度并实例化模板，执行器按模板调用，Supervisor 核验 `post_check` 并提交结果；这些职责可以在同一进程内完成。

用户可直接完成三个工作：

1. 查看某一步骤有哪些直接效果能力、辅助事实能力及不可用原因。
2. 为缺失的前提事实查找核对能力，再由编排器决定是否调用。
3. 新增一个 ability template 和对应结果样例，即可登记现有 Skill/MCP 的受控入口，无需让编排器理解工具自由文本。

“可以直接证明 effect”指能力的证据契约有资格支持目标命题，不表示当前已证明、调用后必然成功，或已经复现原图中的指定动作。

统一口径 v0.1 使用 `runtime_status` 表示处理进度，`claim_verdict=proven/refuted/inconclusive/unassessed` 表示证据结论，`truth_value=true/false/unknown` 表示已提交事实的真值。Matcher 的 `status/readiness` 只描述检索响应，不能直接赋给以上运行字段。工具错误属于调用/判定错误，不新增 `claim_verdict=error`。

`attempt_id` 标识一次节点尝试，覆盖 pre_checks、action、post_checks 三段。每次 Skill/MCP/MSF/Kali 调用使用 `atomic_call_id`，存储接口的 `operation_id` 对应同一次原子调用；模板中的 `atomic_step_key` 是稳定位置，`operation_ref` 是登记操作入口，均不等于调用 ID。传输重送保留 atomic_call_id，新的调用重试使用新 ID；节点重新尝试使用新的 attempt_id。

效果解锁采用 all-or-nothing：只有 Supervisor 确认 provider step 的全部三段成功、全部必需效果及上下文通过，并将该 step 提交为 `runtime_status=succeeded`，才能在同一事务中提交其 effect facts 的 `truth_value=true`。Ability 可以报告 `partial_observation`，但不得因此解锁下游。直接 LEAF 仍可由 Supervisor 在该事实全部必需子检查通过后单独提交。

## 2. 当前仓库依据与兼容约束

| 当前事实 | 本 PRD 的约束 |
|---|---|
| [V1 节点契约](../../../../schemas/attack_step.schema.json)已有 `semantics.case_id/case_status/premise_refs/effect_refs` | 直接消费这些字段，不新增第二套 case 猜测逻辑 |
| [case 匹配](../../../../src/graph/cases.py)结合签名、常量、共享变量和差异约束；[规则目录](../../../../src/graph/rule_catalog.py)有 35 个 case | `case_status=matched` 才能建立步骤能力关系；35 个规则可识别不等于 35 个执行能力可用 |
| [V1 图投影](../../../../src/graph/projector.py)保留 `source_graph.nodes/edges/graph_hash` | 事实引用使用原图 ID，步骤引用使用节点哈希，不能互换或跨图复用 |
| V1 `port` 是 `string|null`，可能为 `local/none/100005`；`protocol` 也保留原始字面值 | 原值保留。只有显式端点映射和模板约束允许时才生成运行参数 |
| 终点 OR 的 `case_id=null`、`effect_refs=[]`，目标保存在 `details.goal` | `match_step` 返回 `not_applicable`；编排器按目标及其提供者推进，不因 OR 类型自动检索外部动作 |
| [现有 ability schema](../../../../archive/legacy_v3_ability/ability.schema.json)和 [MSF](../../../../archive/legacy_v3_ability/registries/msf_core.yaml)、[Kali](../../../../archive/legacy_v3_ability/registries/kali_core.yaml)注册表是草案 | 旧 `produces` 字符串和 `success_criteria.output_contains_any/command_exit_code_zero` 不构成新证据契约 |
| V1 LEAF 固定为真属于离线逻辑假设 | 运行层须区分输入假设、观察事实、规则推导；原图声明本身不是本次执行证据 |

本 PRD 细化 [V3 计划](../../../../archive/legacy_v3_ability/v3_abilities.md)和[两层编排决定](../../../decisions.md)。旧计划中的 `action_class/cve` 不成为新接口的必需字段；沿用 V1 的 `vulnerability`。本文定义的接口、模板、Schema 版本与文件布局均为目标契约，当前仓库尚不可调用。

## 3. 核心语义与结果分类

### 3.1 事实与证明范围

事实的源图定位键为 `(graph_hash, fact_ref)`，步骤的源图定位键为 `(graph_hash, step_id)`。运行请求还必须绑定 `graph_snapshot_id/payload_hash`：同一源图在不同投影或化简配置下可能有相同 graph_hash，不能只靠它锁定完整输入快照。`fact_ref` 是原图数字字符串；`step_id` 是 V1 的 64 位哈希。运行观察另有 `evidence_id`，引用原图事实不会自动产生观察。

`effect predicate` 必须解析为名称、参数个数和保留类型的参数序列。匹配不能只比较 `execCode/2`：`execCode(H,admin)` 与 `execCode(H,system)` 是不同命题；相同权限在不同主机上也不同。

首版 `match_step` 要求唯一、可解析的 effect，并覆盖该步骤全部 `effect_refs`。空 effect、非单 effect 或未知谓词不允许自动选取其中一项。V1 当前 case 选择也要求单效果；未来多效果版本须明确逐项覆盖和完整提交条件后再开放。

每个证明声明都标记 `claim_scope`：

| 值 | 含义 | 可以支持的结论 |
|---|---|---|
| `state_observation` | 观察某命题在给定目标、时间和上下文成立 | 效果状态成立；不能声称某 case 的动作发生过 |
| `action_outcome` | 结果可关联到本次模板动作及其后置检查 | 指定 case 已执行且结果成立；同时保留动作与结果的关联证据 |
| `logical_derivation` | 已登记 case 的完整前提及变量绑定支持推导 | 模型中的推导成立；不得改写成真实工具观察 |

运行请求用 `goal_claim=effect_state|case_reproduction` 指定所需结论。后者只接受 `action_outcome`；已有 SYSTEM 会话的权限检查可以回答前者，不能证明本次执行了 WinRM 横向动作。`logical_derivation` 的结论始终显示为推导，并保留输入假设及有效性边界。

### 3.2 两个独立判断轴

| 字段 | 枚举 | 定义 |
|---|---|---|
| `semantic_role` | `direct_effect` | case、完整目标谓词及证明范围都兼容，契约可以直接支持该 effect |
| 同上 | `leaf_fact` | 只能证明该步骤某条直接 LEAF 前提；`covers_effect_refs=[]` |
| 同上 | `unsupported` | 无声明覆盖、契约缺失、不支持当前语义或模板版本；不能派发 |
| `readiness` | `ready` | 所需参数有效，运行前提满足，所选模板入口及执行器可用 |
| 同上 | `missing_fields` | 所需参数缺失、未解析或有冲突，需要补全后重新匹配 |
| 同上 | `blocked` | 参数齐全，但前提未成立、会话失效、模式不兼容或执行器暂时不可用 |
| 同上 | `unsupported` | 所需适配器、谓词证据契约或模板形式尚未支持 |

展示与机器输出必须同时保留两轴。例如“直接效果能力，缺目标会话”与“辅助 LEAF 检查，已就绪”不能混为同一种候选。没有模板时返回明确未支持原因；不能只返回空数组。

首版辅助候选仅覆盖 `premise_refs` 中 `source_graph.nodes.type=LEAF` 的事实。不能把派生 OR、祖先步骤事实或目标 effect 降格为 LEAF。只能发现服务名、不能证明完整 `networkServiceInfo/5` 的能力，不获得该事实的证明资格；其部分观察可以成为后续字段补全材料，但本轮不得标记 LEAF 成立。

## 4. Ability Schema 目标契约

### 4.1 顶层字段

目标 `ability.schema.json` 使用 JSON Schema 2020-12，条目 `schema_version=2.0.0`；与现有未版本化草案作不兼容升级。表中“必填”表示字段必须存在，允许空数组的字段另行说明；未知字段只可放入 `extensions`。

| 字段 | 类型 / 必填 | 要求 |
|---|---|---|
| `schema_version` | string / 是 | 固定 `2.0.0` |
| `ability_id` | string / 是 | 稳定唯一 ID，例如 `msf.session.identity.observe`；不能使用展示名称作键 |
| `version` | string / 是 | 语义版本；模板或证明含义变更必须发布新版本 |
| `name`, `description` | string / 是 | 中文或英文解释；不参与语义硬匹配 |
| `lifecycle` | enum / 是 | `draft/active/deprecated/disabled`；只有 active 可派发 |
| `category` | enum / 是 | `observation/action/derivation`；描述模板行为，不是 action_class 推断 |
| `executor_ref` | string / 是 | 指向锁定版本的适配器，种类为 `msf_rpc/kali/skill/mcp/internal` |
| `risk_level`, `side_effects` | enum、string[] / 是 | `low/medium/high` 和唯一副作用 ID 数组，ID 在 registry 中有具体说明；空副作用写 `[]`，供排序及模式检查 |
| `matches` | object / 是 | 见 4.2；声明步骤 case、事实入口和实体约束 |
| `required_fields` | object[] / 是 | 见 4.3；可以为空，不能用是否存在某个主机代替完整参数检查 |
| `prerequisites` | object[] / 是 | 会话、路由、平台、已接受事实、上下文有效性等，允许 `[]`；结构见 4.3 |
| `produces` | object[] / 是 | 至少一项；每项是完整谓词证明声明，见 4.4 |
| `template` | object / 是 | 见 4.5；有版本的入口、阶段顺序、参数映射和上下文传递 |
| `post_check` | object / 是 | 见第 7 节；必须引用已登记解析器和判定契约 |
| `cost` | object / 是 | `estimated_ms`、`max_calls`；前者允许 null，后者为非负整数 |
| `tags` | string[] / 否 | 仅帮助人工筛选与解释，不获得派发资格 |
| `extensions` | object / 否 | 命名空间扩展，不得覆盖以上字段语义 |

注册时必须检查 ID/版本唯一、引用存在、所有模板变量可解析、产出与 post_check 一一对应。`lifecycle=active` 还要求配套正例、反例、证据不足例通过契约检查。Schema 格式通过本身不代表能力已具备这些资格。

### 4.2 `matches`：case 与谓词分开索引

| 字段 | 要求 |
|---|---|
| `step.case_ids` | 显式 case ID 数组；步骤入口非空，禁止 `*`。例如 WinRM 的三个 case 必须逐个登记兼容性 |
| `step.effect_claim_ids` | 引用 `produces[].claim_id`；仅引用 `usage=effect` 的声明 |
| `fact.signatures` | LEAF 入口支持的 `predicate/arity` 数组；事实入口非空 |
| `fact.fact_claim_ids` | 引用 `usage=leaf_fact` 的声明 |
| `constraints` | 对 target/source/service/protocol/port/vulnerability/platform/privilege 的类型化约束 |

`step` 与 `fact` 至少存在一项。事实核对能力可以没有 `step`，由 `match_fact` 发现；同一 ability 若还要直接证明效果，必须另行声明 `step.case_ids` 和效果声明，不自动晋升。

约束仅使用可校验操作：`eq/in/range/exists/same_as`，每项包含字段路径、操作和值或引用。不执行任意表达式、正则证明谓词或自然语言条件。case 与 effect 是必须同时通过的硬条件，匹配一个不能补偿另一个。

### 4.3 `required_fields` 与字段绑定

每项包含 `name`、`type`、`source_paths`、`required_when`、`constraints`、`sensitive`、`description`。`type` 使用 `string/integer/boolean/endpoint/secret_ref/context_ref/typed_term` 的已登记类型；复合类型的结构由版本化输入契约固定，不能只写任意 object。

`required_when` 固定为 `{all_of: [{field, op, value}]}`，`op` 仅为 `eq/in`，条件字段限定为 `entry_id/run_mode` 或 Schema 中已声明的枚举字段；空 all_of 为恒真，不提供自由代码和嵌套逻辑。任一条件明确为假则不必填；全部为真则必填；其余情形为 unresolved，列出缺失/冲突的条件字段，不能当作“不必填”。

`source_paths` 是允许的绑定来源，不是发现线索。来源限定为本步骤直接事实、解析出的效果、显式运行映射、本轮有效证据、模板先前阶段的产物，以及契约明确列出的 generated 追踪字段。多个来源不一致时报告冲突，不按列表顺序静默覆盖。只有同值、同归属且证据有效时才能合并出处。

| 规范字段 | 来源与约束 |
|---|---|
| `target.host` | 目标谓词中的主机绑定；须与 V1 `target_host` 及相关直接事实一致 |
| `target.endpoint` | 显式运行目标映射；若 host 本身是可连接 IP，可经类型检查生成带来源的同值映射；主机名不自动 DNS 解析。语法可连接不代表实际资产身份已核验 |
| `source.host`, `source.context_ref` | 来自 case 中的源主机或已绑定运行位置；不能取任意祖先主机。连通性、代理与横向能力必须说明发起位置 |
| `service.name` | 同目标、同协议、同端点的服务事实；不能由端口名称反推 |
| `protocol` | 原始字面值及显式规范映射并存；`https/winrm/rpc` 不能直接改成 `tcp` |
| `port.raw`, `port.transport` | 前者保留 V1 字符串；后者仅在传输协议明确且值为 1–65535 整数时生成 |
| `vulnerability` | `null` 或 `{namespace,id,raw,source_ref}`；CVE 只是可能的命名空间，不把所有值强制认作 CVE |
| `account.user`, `credential_ref` | 同一账户绑定及独立凭据引用，核对目标、域/适用范围和材料类型；候选解释不返回密码/令牌正文 |
| `privilege.required` | 从完整效果命题绑定，不能从规则名称推断。system、root、admin 不自动互换 |
| `session_ref` | 指向明确目标/容器/执行源、平台、权限和有效期的会话；“存在任意会话”不满足要求 |

缺失条目统一返回 `{field, state, required_by, expected, allowed_sources, reason_code, next_action}`。`state=missing|unresolved|conflict|invalid`；实际无值才叫 missing，不能把不合法端口说成空值。已填但与能力约束明确不兼容的值排除该能力，见第 6 节。

`required_by` 指向具体阶段或证据要求。运行层自动生成的 `atomic_call_id/nonce` 等不是向用户索要的参数；来源声明为 `generated`，由 Supervisor 在派发前生成并锁定。模板前一步才能生成的产物属于 `deferred_bindings`：只有该前置步骤已登记、类型一致且位于当前入口内，才允许候选整体就绪；后续原子步骤必须收到有效产物后才能派发。

模板不能用常见端口、默认凭据、其他主机的服务信息或模型推测填写 required_fields。可选工具参数的默认值必须显式登记且不改变语义目标；任何目标、身份与端点关键字段不得静默默认。

每项 `prerequisites` 固定包含 `{prerequisite_id, kind, evaluator_ref, bindings, evaluation_stage, freshness_policy_ref}`。`kind=session|route|platform|fact|context`；`bindings` 是字段或事实/证据引用映射；`evaluator_ref` 锁定相应 kind 的判定器及版本；`evaluation_stage=entry|before_action|before_post_check`。列表各项均需成立，不由 AND/OR 节点类型决定组合关系。

前提判定器返回 `satisfied/unsatisfied/unknown/conflict` 及来源：satisfied 且有效才通过；必要绑定缺失或冲突归 missing_fields；绑定齐全但事实未知、反证、会话失效或上下文冲突归 blocked。未实现判定器归 unsupported。属于后续阶段且可由已登记、更早的原子步骤产生的证据列为 `deferred_bindings`，派发该阶段前重新判定；禁止向后引用、自证循环或用预期产物冒充当前已满足的条件。

### 4.4 `produces` 与 effect predicate

每个声明包含：

| 字段 | 定义 |
|---|---|
| `claim_id` | ability 内唯一 ID |
| `usage` | `effect` 或 `leaf_fact` |
| `predicate` | `{name, arity, args}`，必须覆盖全部参数 |
| `claim_scope` | `state_observation/action_outcome/logical_derivation` |
| `predicate_contract_ref` | 已登记谓词含义及全参数证明条件的版本引用 |
| `context_bindings` | 谓词未显式表达但证明需要的源位置、路由、容器、账户域等 |
| `post_check_ref` | 指向具体后置判定项 |

`args` 的每项使用 `{bind: "字段路径"}` 或 `{const: {kind: "atom|number", value: "原值"}}`。输入事实用同样的带类型常量结构；变量由已核验 case 绑定，匿名占位不能用作“已证明任意权限”。当前 `terms.py` 区分数字与带引号原子，匹配前不能把 `'2049'` 与 `2049` 合并。

例如 `execCode/2` 的第二项绑定到 `privilege.required`；一次普通用户身份输出不能证明 `execCode(H,system)`。`networkServiceInfo/5` 还包含运行身份，只有服务名/版本的扫描不能证明其第五参数。`hacl/4` 的策略含义、`netAccess/3` 的可达性含义及观察源必须由各自谓词契约明确，不能互换。

一个检查若只能回答“有服务指纹”而没有完整图事实契约，可以登记为模板内部观察阶段；不得伪造 `produces` 中的完整事实声明进入直接效果或 LEAF 证明候选。

### 4.5 `template`：Skill/MCP 的唯一调用通道

每个模板有 `template_id/version` 和一个或多个 `entries`。每个入口声明 `entry_id`、`run_modes`（`verify/reproduce`）、`claim_scopes`、`stages`。入口显式选择检查或动作，检查失败不自动切换到 reproduce。

入口固定包含 `pre_checks → action → post_checks` 三个有序列表，每段允许多个原子步骤。步骤模板的 action 非空：纯观察使用明确登记的观察/证据读取操作，推导使用内部规则判定操作；阶段名称 action 不代表必须触发外部动作。无直接 LEAF 时 pre_checks 可空，效果判定仍有明确 post_checks。独立 LEAF 能力实例化为当前节点 pre_checks 中的检查子模板，不把其内部 action 升格成图动作。

每个原子步骤至少声明 `atomic_step_key`、固定 `adapter_ref/operation_ref`、`input_bindings`、`output_contract_ref`、`timeout_ms`、`max_attempts`、`retry_policy`、`context_exports` 和 `side_effects`。首次实现只支持有限、有序步骤；失败、超时和证据不足停止当前入口并交回编排器，不支持模板内部动态分支、运行时生成自由命令或无限流程。

模板的重试字段仅提供上限及可重放约束，执行器不能据此自行重复动作。节点重新尝试由 Supervisor/调度器创建新 attempt 并按共享执行契约推进；同一调用的传输重送只复用 atomic_call_id，不计为新动作。

运行调用必须携带 `ability_id/version + template_id/version + entry_id + atomic_step_key + attempt_id + atomic_call_id + bound_parameters`。`request_id` 只用于匹配请求追踪，不替代工具调用身份。Skill 还锁定包/说明版本与可调用入口；MCP 锁定 server/tool 及输入、输出契约版本。Skill 标题相似、MCP 声明可用或大模型选中了一个工具，都不能绕过模板。

工具升级导致契约不兼容时该入口为 `unsupported`；工具暂时离线为 `blocked`。Skill 内部的后续外部调用也必须落在登记的原子步骤及适配器操作范围，不能由 Skill 自行扩展新目标或新的证明声明。

`category=derivation` 使用 `executor_ref=internal` 的已登记规则判定器；它核对完整前提、共享变量及约束，不因 AND 类型直接派发工具，也不因 V1 的完成集合直接生成真实证据。

## 5. `match_step` / `match_fact` 输入输出

### 5.1 共同输入与快照

两个接口均为只读、确定性调用，不发起网络、Skill 或 MCP 请求。接口请求/结果 `schema_version=1.0.0`，独立于 ability schema 版本。

| 请求字段 | 必填 | 含义 |
|---|---|---|
| `schema_version`, `request_id` | 是 | 接口版本与本次匹配追踪 ID |
| `graph_ref` | 是 | `{graph_snapshot_id, payload_hash, graph_hash, schema_version}`，引用可解析的 V1 不可变产物快照；有 GraphBundle 时另带其版本化 bundle 引用 |
| `registry_revision` | 是 | 已加载并锁定的注册表内容摘要 |
| `runtime_snapshot_ref` | 是 | 本次运行快照：run_id、revision、评估时间、环境类型、端点映射、事实证据、会话/路由、执行器可用性及证据接受策略 |
| `run_mode` | 是 | `verify` 或 `reproduce`；必须与运行快照一致 |
| `goal_claim` | 是 | `effect_state` 或 `case_reproduction`；`match_fact` 固定为 `effect_state` |
| `options` | 否 | 首版只接受 `include_unavailable`，默认 true；即便隐藏不可用条目，汇总原因仍须返回 |

引用必须能解析且摘要一致，否则 `invalid_input`，不以空上下文继续猜测。所有参数、环境可用性和 `now` 均来自快照，保证相同输入产生相同候选与排序；match 不从实时系统悄悄读取缺失状态。

运行快照中的事实使用 `basis=declared/observed/derived`，包含目标绑定、证据引用与有效期。哪些事实允许作为前提由运行策略显式给定。输入假设可以支持带 `assumption_refs` 的有条件推导，不能伪装成真实观察。变化后生成新 revision，旧候选在派发前必须重新核对。

### 5.2 `match_step(request)`

额外必填字段是 `step_id`，指向图快照中的完整 V1 节点。接口从原图解析 `case_id/case_status`、`premise_refs`、`effect_refs` 和实体，不接受调用者以一段自然语言覆盖这些信息。

处理约定：

1. 核对节点、图指纹、直接引用与原图边一致。传入节点概要与原图绑定冲突，返回 `invalid_input`。
2. `case_status=unknown/ambiguous` 时返回 `unsupported`，保留 `case_candidates` 和具体诊断；不能挑一个 case 继续。`not_applicable` 返回同名状态。
3. 对唯一 effect 建立完整命题，检索同时声明该 case 和效果的能力，并核对目标参数、证明范围与入口。
4. 对直接 LEAF 前提调用同一事实匹配规则，形成 `semantic_role=leaf_fact` 的辅助候选；内部事实查询固定 `goal_claim=effect_state`，不继承父步骤的 case_reproduction。派生 OR 前提交还编排器。
5. 输出全部相关候选、覆盖关系、缺字段、阻塞条件、排除原因及稳定排序。匹配完成不写入事实或节点成功状态。

case 无法确定时不返回直接效果能力；如某条直接 LEAF 本身可解析，调用方仍可独立使用 `match_fact` 核对它。该事实结果不修复 case 的歧义。

### 5.3 `match_fact(request)`

额外必填 `fact_ref`，可选 `consumer_step_id`。首版仅接受原图 LEAF；有 consumer 时必须属于其直接 `premise_refs`。查询凭据内容时使用保密引用，输出不得复制原始事实中的秘密。

输入命题从 `source_graph.nodes[fact_ref].description` 解析成完整 predicate，不按事实名称搜索相似 Skill 后直接调用。匹配依据是事实签名、全参数绑定、谓词契约、目标上下文和模板要求；不要求事实自己有 `case_id`。

输出中的 `query.kind=fact`，`consumer_case_id` 只作关联说明。所有合格能力 `semantic_role=leaf_fact`，`covers_fact_refs=[fact_ref]`、`covers_effect_refs=[]`。返回证据仅能更新这条 LEAF 的运行状态。OR、AND 或图外事实输入返回 `not_applicable`，附 `fact_not_leaf` 或 `fact_out_of_scope`。

### 5.4 统一结果与候选字段

| 结果字段 | 定义 |
|---|---|
| `schema_version`, `request_id` | 回显契约与追踪 ID |
| `graph_ref`, `registry_revision`, `runtime_revision` | 回显完整图快照引用及版本，作为精确复查和调用前复核依据 |
| `query` | `kind`、步骤或事实定位、`case_id/case_status`、已解析目标及直接引用；敏感参数替换为 secret 引用 |
| `status` | `ok/unsupported/not_applicable/invalid_input`；`ok` 仅表示匹配正常且至少有一个语义支持条目，可全部缺参数或阻塞 |
| `candidates` | 候选明细，见下表；无候选时仍返回诊断 |
| `rejected` | 已进入 case/谓词相关检索集合但被硬条件排除的 ability 及原因，不把无关全库条目全部展开 |
| `summary` | 按语义角色与 readiness 计数；含 `has_ready_direct_effect`、`has_ready_leaf_fact` |
| `diagnostics` | 机器码、中文说明、字段/事实定位、可采取的下一步 |

| 候选字段 | 定义 |
|---|---|
| `candidate_id` | 由查询定位、ability/version、入口、声明及绑定快照形成的稳定 ID |
| `ability_id`, `ability_version`, `template_id`, `template_version`, `entry_id`, `executor_ref` | 可追踪到注册内容，禁止仅返回 Skill 名称 |
| `semantic_role`, `readiness`, `claim_scope` | 分别回答证明能力、准备情况、结论范围 |
| `matched_case_id`, `matched_claim_ids` | 步骤候选的实际 case 及声明；fact 候选 case 为 null |
| `covers_effect_refs`, `covers_fact_refs`, `uncovered_effect_refs` | 完整、精确覆盖；当前唯一 effect 未覆盖就不能成为直接效果候选 |
| `bindings` | `{field,value或secret_ref,source_refs,normalization_ref}` 数组，绑定来源可回溯 |
| `missing_fields`, `deferred_bindings`, `blocked_by` | 所需补全项、模板内稍后产物、运行阻塞；即便多种问题并存也全部保留 |
| `explanation` | `matched_on/not_proven/reason_codes/next_actions`；文字解释从结构化判断生成 |
| `post_check_ref`, `evidence_requirements` | 该入口必须提交的谓词证据契约与必需观察项 |
| `dispatchable` | 只有 active、ready 且所有硬条件通过才为 true；仍须编排器复核依赖与 revision |
| `rank`, `rank_key`, `rank_explanation` | 排序位置、可复算排序键及规则说明；没有成功概率字段 |

候选去重单位为 `(ability_id, version, entry_id, claim_id, binding_key, query_fact_or_effect_ref)`。`binding_key` 为完整规范化绑定摘要，至少包含目标/端点、发起位置/路由、session_ref、容器/命名空间、账户域与凭据引用；不含秘密正文。不同目标、会话、凭据归属、执行源或事实引用不能因为工具相同合并。一个模板内部可生成多种观察，但不得把多项未完成声明拼成已完成证明。

### 5.5 结果片段示例

以下是约定字段的展示片段，省略通用快照字段，并非完整 Schema 测试样本。设合成 fixture 的步骤效果为 `execCode(host_b,system)`，直接 LEAF `17` 为 `networkServiceInfo(host_b,smb,tcp,445,system)`；完整身份核对能力缺少该目标会话，另有能够核对全部五个参数的已登记服务事实检查能力。

```json
{
  "status": "ok",
  "candidates": [
    {
      "ability_id": "fixture.service.full_fact.observe",
      "semantic_role": "leaf_fact",
      "readiness": "ready",
      "claim_scope": "state_observation",
      "covers_effect_refs": [],
      "covers_fact_refs": ["17"],
      "uncovered_effect_refs": ["20"],
      "missing_fields": [],
      "dispatchable": true,
      "explanation": {
        "matched_on": ["networkServiceInfo/5 的全参数契约"],
        "not_proven": ["execCode(host_b,system)", "WinRM 动作已发生"],
        "reason_codes": ["leaf_fact_only"],
        "next_actions": ["由编排器决定是否核对 LEAF 17"]
      }
    },
    {
      "ability_id": "fixture.session.identity.observe",
      "semantic_role": "direct_effect",
      "readiness": "missing_fields",
      "claim_scope": "state_observation",
      "covers_effect_refs": ["20"],
      "covers_fact_refs": [],
      "uncovered_effect_refs": [],
      "missing_fields": [
        {
          "field": "session_ref",
          "state": "missing",
          "required_by": "post_check.identity",
          "expected": "绑定 host_b 的有效会话",
          "allowed_sources": ["runtime.sessions"],
          "reason_code": "missing_target_session",
          "next_action": "提供或由已登记前置模板产生会话引用后重新匹配"
        }
      ],
      "dispatchable": false
    }
  ]
}
```

实际返回中即使辅助事实能力排第一，`has_ready_direct_effect=false` 仍必须明确显示。编排器不能把“取第一候选”实现为“本步骤已拥有直接证明能力”。fixture 能力名称仅用于离线验收，不表示现有 MSF/Kali 已实现相同契约。

## 6. 匹配流程、硬条件和排序

### 6.1 确定性流程

先校验请求与 registry 快照，再建立 `case_id`、效果签名、LEAF 签名索引。步骤直接能力按 case 与 effect 声明交集检索；辅助能力按直接 LEAF 谓词检索。对相关条目依次核对声明、完整绑定、证明范围、模板入口、字段、运行前提和执行器。

以下属于硬排除，进入 `rejected`：case 不在声明列表、已知效果参数不同、已知目标/协议/端口/服务不兼容、明确不同漏洞、事实不受声明覆盖，以及 `claim_scope_mismatch`。尤其仅提供 state_observation 的入口不能成为 case_reproduction 的 direct_effect/blocked 候选。它们不能通过工具偏好、低风险或相似度加分重新入选。声明范围合格而当前 run_mode 不允许的入口，才以 `mode_not_supported` 保留为 blocked。

以下仍有解释价值，留在 `candidates`：语义可能支持但参数缺失、证据暂缺、会话失效、执行器暂时离线；生命周期或契约不受支持的条目以 `unsupported` 展示。若同一候选存在多个问题，保留全部原因，主 readiness 优先级为 `unsupported → missing_fields → blocked → ready`。

关键细节：

- 已知漏洞与模块专用漏洞不同，硬排除；漏洞为空而模板要求确定漏洞，返回 missing_fields；不依赖漏洞的模板不要求填写 CVE。
- 主机 A 的服务、主机 B 的会话与主机 C 的账户不能拼成主机 D 的参数。目标/源/容器角色必须根据 case 和声明核对。
- `service=smbv1` 与 `smb` 只有版本化服务别名规则明确声明兼容时才可匹配；原值及映射来源一起返回。
- `port=local/none` 不生成 TCP 调用；`rpc/100005` 不能当作 TCP 100005。相关 TCP 能力硬排除并说明 token 语义；未支持的专用适配器另报 unsupported。
- `protocol=winrm, port=139` 原样保留。没有明确端点映射时，不改为 TCP 5985；若映射存在但与证据冲突，返回冲突。
- `isFirewall(H,flase)` 保留仓库字面值；语义翻译须有明确谓词契约，不能默默修改原图为 false。
- 会话匹配区分源主机与目标主机，核对平台、命名空间、权限、路由、有效期及最近有效性检查；多个兼容会话形成独立绑定候选并稳定排序。某个具体会话绑定到错误主机时排除该绑定；没有剩余兼容会话则保留无绑定的能力为 missing_fields；目标一致但会话过期的绑定为 blocked。
- 已证明目标状态只影响编排器是否还需工作，不表示 matcher 可以把节点标记为本次动作完成。

### 6.2 排序规则

首版所有候选按以下公开元组从小到大进行字典序比较，不使用模型评分或图 metric：

`(bucket, role_order, unresolved_count, alias_count, specificity_key, risk_order, side_effect_count, executor_order, max_calls, duration_unknown, estimated_ms_or_zero, ability_id, version, entry_id, claim_id, binding_key)`。

| 分量 | 唯一计算方式 |
|---|---|
| `bucket` | 0=ready 直接效果，1=ready LEAF，2=missing_fields 直接效果，3=missing_fields LEAF，4=blocked，5=unsupported |
| `role_order` | direct_effect=0、leaf_fact=1、unsupported=2；在所有桶中先比较角色，再比较未解决项数量 |
| `unresolved_count` | missing_fields 按不同 field 计数；blocked 按不同 prerequisite_id 或独立运行原因码计数；其他桶为 0 |
| `alias_count` | 绑定中应用过别名/语义转换的不同字段数量；规范的数字表示转换不计为别名 |
| `specificity_key` | 四元组，依次为 vulnerability、service、protocol、transport_port。每项为 0=满足显式 eq 常量约束，1=满足 in/range，2=仅类型或存在性约束；同字段重复约束不增加权重。没有该字段或不适用取 2；首版不比较范围宽度 |
| `risk_order`, `side_effect_count` | low=0、medium=1、high=2；副作用按注册的不同 side_effect ID 数量，Schema 要求唯一，禁止自由文本数量人为加分 |
| `executor_order` | manifest 固定整数偏好，相同条件下 MSF 优先；不能覆盖前面的语义、就绪及风险项 |
| `max_calls` | 当前选定入口的登记调用上限；包括内部阶段，非负整数 |
| `duration_unknown`, `estimated_ms_or_zero` | 已知耗时为 `(0, estimated_ms)`，未知为 `(1, 0)` |
| 其余字段 | 不透明 ID 按字典序，version 为锁定的登记版本，binding_key 使用完整绑定摘要 |

每项比较记录 `rank_explanation`。表中 side_effect ID 在 registry 中有对应具体副作用说明。registry manifest 为每个 ability 锁定唯一活动版本，禁止“最高分时临时换一个版本”。能力提供者相同也可能因入口和会话不同形成多个候选。`rank` 表示检索优先次序，绝不是利用成功率。

### 6.3 诊断机器码最低集合

`case_unknown`、`case_ambiguous`、`case_not_declared`、`effect_ref_missing`、`multiple_effects_unsupported`、`predicate_unsupported`、`effect_binding_mismatch`、`leaf_fact_only`、`partial_fact_coverage`、`field_missing`、`field_conflict`、`invalid_transport_port`、`endpoint_mapping_required`、`vulnerability_mismatch`、`session_target_mismatch`、`session_expired`、`prerequisite_unproven`、`claim_scope_mismatch`、`mode_not_supported`、`adapter_missing`、`adapter_unavailable`、`contract_version_unsupported`、`legacy_success_criteria_unsupported`、`registry_invalid`、`stale_runtime_snapshot`、`no_registered_ability`、`fact_not_leaf`、`fact_out_of_scope`。

诊断不能只写“匹配度低”。每条包含 ability/字段/事实定位、观察到的问题及下一步，例如“需要 host_b 的目标会话；当前 session-7 属于 host_a”。敏感值只输出引用。

## 7. `post_check` 证据契约

### 7.1 注册契约

`post_check` 必须包含 `contract_id/version`、`parser_ref/version`、`checks[]`、`freshness_policy`、`on_inconclusive`。每个 check 对应一个 `claim_id`，声明必需观察、参数和上下文等值核对、支持/反驳/不足条件、所需原始证据和允许的证据环境。首版 `on_inconclusive` 固定为 `return_to_supervisor`，不允许在检查器内切换动作模式或追加未登记调用。

判定器使用固定版本的结构化输出契约。命令退出码、HTTP 状态、MCP `isError=false`、非空文本、出现 “SMB/open/success/root” 只说明执行或输出特征，不能单独作为 predicate 成立条件。解析到结构化对象后仍须核对目标、操作关联、全参数和时效。

### 7.2 执行结果到证据记录

| 必需信息 | 约束 |
|---|---|
| `evidence_id`, `run_id`, `graph_hash` | 证据可唯一引用，不与其他图或运行混淆 |
| `step_id` 或 `fact_ref`, `claim_id`, `case_id` | 定位本次证明目标；独立 LEAF 核对允许 case_id/step_id 为 null |
| `ability_id/version`, `template_id/version`, `entry_id`, `atomic_step_key` | 所有外部或内部判定都能追到登记模板 |
| `attempt_id`, `atomic_call_id`, `operation_id`, `operation_ref` | attempt_id 为节点三段尝试，atomic_call_id/operation_id 关联同一次原子调用，operation_ref 指登记入口；核对重试归属。挑战值 nonce 在契约要求时必填 |
| `target_binding`, `source_context`, `session_ref` | 核对真实目标、发起位置、会话/容器/账户域；不适用字段可显式 null |
| `observed_at`, `valid_until`, `context_revision` | 有效期规则按谓词契约登记；会话失效、端点重映射等可使证据提前失效 |
| `environment` | `real/simulated`；模拟证据只用于模拟结果，不能计为真实验证通过 |
| `raw_artifacts` | 原始材料引用、摘要、内容类型和脱敏展示引用；保留可回查性，解释层不复制秘密 |
| `parser_ref/version`, `observations` | 解析器版本与结构化观察，记录解析失败、缺项和矛盾 |
| `fact_ref`, `predicate`, `claim_scope`, `dependency_evidence_refs` | 每项命题必须关联原图 fact_ref，effect 同样使用此字段；推导列出完整前提证据 |
| `observation_ids`, `support_observation_ids`, `uncovered_arguments`, `partial_observation` | 逐声明定位观察及覆盖缺口；部分观察不得激活 effect fact |
| `invocation_status`, `evaluation_status`, `claim_verdict`, `reason_codes` | 调用结束、判定是否正常完成、候选证明结论分别记录；不包含由 ability 自行写入的 runtime_status/truth_value |

`invocation_status` 使用执行器共享调用状态，正常结束为 succeeded；失败、超时、取消或执行结果未知保留原始调用原因。`evaluation_status=completed|error`。逐声明使用统一 `claim_verdict`：

- `proven`：必需观察完整、目标与参数一致、证据关联和时效通过，支持完整声明。
- `refuted`：契约定义的反证观察明确成立，范围仅限本次命题、时间和执行上下文；不能把一次动作失败扩大为目标永远不可达。
- `inconclusive`：超时、filtered、缺身份、只有横幅、源位置不明、会话已失效或证据相互矛盾；不能写成漏洞不存在。
- `unassessed`：尚未执行该声明的检查；已尝试但不足以判断时必须为 inconclusive，不能退回 unassessed。

结果格式不合法、解析器失败、缺必需关联引用或协议损坏时，`evaluation_status=error`、`claim_verdict=inconclusive`，附具体 reason_codes。匹配状态 invalid_input、调用错误及判定错误不是命题真假。

一个工具 failed 但留下完整有效观察，仍保存逐项候选判定和 partial_observation，但当前模板停止且不能发布 provider effects；一个工具 succeeded 但只输出说明文字，也可能 inconclusive。判定器不得用调用状态统一覆盖所有声明，也不得用局部观察掩盖调用失败。相互矛盾的有效观察必须显式记录 conflict 并返回 inconclusive，不选择最后一条成功文本。

### 7.3 典型谓词的证明强度

| 目标 | 最低证据要求 | 不能据此判为 proven 的情况 |
|---|---|---|
| `execCode(H,system/root/admin)` | H 上与本次检查关联的执行结果、身份和平台权限证据；身份到图权限的映射有版本，核对主机及容器边界 | 用户名包含 root、普通管理员未证明所需有效权限、另一主机/容器的会话、历史截图或示例输出 |
| `netAccess(H,P,Port)` | 明确源位置/路由、协议/端口、目标响应的结构化探测记录，符合该谓词契约 | filtered、全局退出码 0、别的主机端口开放、无法确定实际发起位置 |
| `networkServiceInfo(H,S,P,Port,U)` | 同端点的服务、协议、端口及运行身份 U 的完整观察链 | 仅发现服务或 banner；部分参数必须继续标记不足 |
| `getAccount(H,U,Material,Perm)` | 账户归属、材料类型/受保护引用及与声明权限的关联证据；完整含义由登记契约决定 | “找到凭据”文本、其他资产的账户、仅会话用户名称，不核对所声明材料 |
| `disableFirewall(H)` | 当前 case 明确的主机、组件和后置状态；要求动作复现时还须有本次 action 的关联证据 | 某端口可达、打印 Disabled 字符串、只核对了另一防火墙配置 |

以上是准入强度要求，首版没有实现某个谓词判定器时应返回 `predicate_unsupported`，不能用表格说明冒充已实现契约。

Ability/判定器返回逐事实候选结论，Supervisor 负责最后核验和唯一提交。LEAF 全部必需子检查通过后才能提交其 truth_value，不能直接完成父步骤。provider 的 effects 必须等该节点全部三段成功后一次性提交；任一必需检查失败、证据不足、调用状态未知或上下文失效，只保留 partial_observation，effect facts 不变为 true。效果状态成立与 case 动作复现分别记录。推导过程检查完整原始前提，不能在运行事实可撤销时直接沿用 V1 化简后的假设。

## 8. Registry 文件布局与加载规则

下列是拟议布局；本次不创建这些文件或迁移旧条目。

```text
schemas/
  ability.schema.json                  # 新 2.0.0 能力契约
  ability_match_request.schema.json    # match_step/match_fact 请求
  ability_match_result.schema.json     # 两接口统一结果
  ability_evidence.schema.json         # post_check 证据与判定契约
registries/
  manifest.yaml                        # registry 版本、条目列表、摘要、活动版本与工具偏好
  msf_core.yaml                        # MSF ability 条目
  kali_core.yaml                       # Kali ability 条目
  skill_core.yaml                      # Skill 包装 ability 条目
  mcp_core.yaml                        # MCP 包装 ability 条目
  internal_core.yaml                   # 逻辑推导 ability 条目
  executors.yaml                       # 固定适配器、操作入口和输入/输出契约版本
  predicates.yaml                      # 谓词签名、参数角色与证据含义
  mappings.yaml                        # 显式服务别名/协议/权限等版本化语义映射
  templates/<ability_id>/<version>.yaml
  post_checks/<contract_id>/<version>.yaml
skills/<skill_name>/
  SKILL.md                             # 工作流说明；不是能力注册与成功判断的替代品
tests/fixtures/ability_matcher/
  requests/                            # 固定图及运行快照引用、合成请求
  expected/                            # 候选、排序、诊断预期
  results/<ability_id>/                 # 正例、反例、证据不足和不合法结果
docs/product/ability_skill_matcher_prd.md
```

同一 Schema 适用于 MSF/Kali/Skill/MCP/internal 条目。registry 文件外壳使用 `schema_version`、`registry_version`、`abilities`；模板和 post_check 可内嵌，也可用显式版本路径引用，但一次加载必须展开并校验为完整对象，不能留下运行时不确定引用。

manifest 是唯一加载入口，显式列出文件、内容摘要及每个 ability 的活动版本。文件系统遍历顺序、后加载覆盖、网络临时搜索结果都不能决定能力版本。重复 ID/版本、缺失引用、变量无来源、claim 与 post_check 不对应或活动版本冲突使该次加载返回 `registry_invalid`；不发布部分有效快照。已有成功快照可继续被显式引用，不静默替换。

manifest 将 `ability_sources` 与 `legacy_sources` 分开：前者必须全部符合新 Schema，并执行原子加载；后者仅进入独立、只读的 legacy 诊断清单，不进入 case/谓词候选索引。当前旧 YAML 只能先归入 legacy_sources，列出 `legacy_success_criteria_unsupported`；若直接放入 ability_sources，则整次加载 registry_invalid。运行时只要相关 legacy 条目存在，可在 diagnostics 附其不可用原因，但它不是 candidate。

维护者也可手动把旧条目补全为符合新 Schema 的 draft；此时必须满足全部结构和引用要求，但不获得 active 资格。禁止将字符串 `produces` 自动翻译成谓词证明，禁止保留旧 success_criteria 作为后备判断。只有新契约及正反例验收通过后才能改为 active。

新增能力流程：确定可证明命题与 case → 登记 required_fields、前提和固定操作入口 → 声明产出与 post_check → 补离线结果样例 → 完成 Schema/引用/反例检查 → 发布新 revision。新增 Skill/MCP 工具也走相同流程，不增加绕过模板的搜索调用接口。

## 9. 验收正例、反例与预期

所有行为验收先使用固定图、固定 runtime 快照与 FakeExecutor 结果完成，不需要真实网络执行。本 PRD 本身不宣称以下测试已经实现或通过。

| 编号 | 场景 | 必须出现的结果 |
|---|---|---|
| A01 正 | 已匹配 WinRM case，effect 为 host_b 的 system，模板明确支持该 case，目标会话有效，身份契约完整 | `direct_effect/ready`；覆盖唯一 effect；状态检查只能声明 state_observation |
| A02 反 | A01 请求改为 `goal_claim=case_reproduction`，候选仍是既有会话检查 | 该入口进入 rejected，原因 claim_scope_mismatch；不得保留 direct_effect/blocked，需 action_outcome 入口 |
| A03 正 | 完整 `networkServiceInfo/5` 核对能力匹配直接 LEAF | `leaf_fact/ready`，covers_effect_refs 为空；其 proven 只更新该 LEAF |
| A04 反 | SMB banner 扫描匹配初始访问步骤，只有 service/version | `partial_fact_coverage`；不证明完整 networkServiceInfo/5，更不证明 execCode |
| A05 反 | 工具正常退出且错误信息包含 SMB/Windows/success/root | 无对应有效观察时 claim_verdict=inconclusive；格式错误另记 evaluation_status=error，不能 proven |
| A06 正反 | 同源、同目标、同协议端口的完整可达性记录；对照 filtered 或另一目标开放端口 | 前者按 netAccess 契约 proven；后两者不得 proven |
| A07 反 | 直接效果模板缺 target.endpoint、必需漏洞 ID 或目标 session_ref | 保留 direct_effect 语义角色，readiness=missing_fields，逐项说明来源与需求阶段 |
| A08 反 | effect 目标 B，输入却拿 A 的服务或 C 的会话 | 图与概要冲突为 invalid_input；错误目标的具体绑定进入 rejected，没有兼容会话时能力为 missing_fields；目标正确但过期才 blocked |
| A09 反 | 同名规则分别是 lsass_admin/lsass_system，或 WinRM firewall_state/after_firewall_disable | 只命中显式 case；不按同名描述、ATT&CK 编号或 AND 类型共用模板 |
| A10 反 | case_status=ambiguous/unknown，存在名称相似的 Skill | unsupported 并保留 case_candidates；不自动选择第一个 case 或调用 Skill |
| A11 反 | 已知漏洞 ID 与专用模板不符；另一模板不需要漏洞 | 前者硬排除；后者不被强制索要 CVE；缺漏洞的专用模板为 missing_fields |
| A12 反 | protocol=rpc、port=100005；或 port=local/none | TCP 模板不派发，不改写为常用端口，保留原始 token 与原因 |
| A13 正反 | 显式服务别名/端点映射完整；对照未登记映射的 winrm/139 | 前者带映射版本和出处；后者不得自动变 TCP/5985 |
| A14 反 | 任意会话存在，但目标/权限/容器不符，或者已失效 | 不 ready；分别解释 mismatch/expired；不能把容器 root 证明成宿主机 root |
| A15 反 | 终点 OR 传入 match_step；派生 OR 传入 match_fact | 都为 not_applicable，不新增动作；由编排器处理其提供者或目标状态 |
| A16 反 | 效果引用跨图、悬空、与原图边不符或出现多个效果 | 对损坏引用 invalid_input；首版多效果 unsupported；不得挑一个效果静默执行 |
| A17 正反 | 两个能力完整证明同一目标且均 ready；MSF 证据不足的对照条目 | 前者按公开 rank_key 稳定排序；后者不因 MSF 优先进入直接效果候选 |
| A18 反 | 有效效果检查与 ready LEAF 同时存在，或直接效果缺参数但 LEAF ready | 保留角色分组与 has_ready_direct_effect；辅助候选排第一也不能完成步骤 |
| A19 反 | Skill/MCP 存在但没有模板，或模型提出未登记 tool/operation | unsupported / adapter_missing；执行请求无法仅用工具名通过契约 |
| A20 反 | 旧 registry 只有 output_contains_any / command_exit_code_zero | legacy_sources 中只展示 legacy_success_criteria_unsupported，不进入候选；放入 ability_sources 则加载 registry_invalid |
| A21 正反 | internal 推导模板完整满足前提；对照只有 AND 标签或已完成前驱 ID | 前者返回带前提证据的 logical_derivation；后者不得直接 proven 或派发工具 |
| A22 反 | 超时、解析缺字段、历史结果、错误 atomic_call_id/attempt_id、已撤销会话或矛盾观察 | claim_verdict=inconclusive，契约损坏另记 evaluation_status=error；不记漏洞不存在，不接受已过期正证据 |
| A23 正反 | 相同图/registry/runtime revision 重复匹配；随后会话失效生成新 revision | 前者候选与排序完全相同；后者旧候选派发前失效并重新匹配 |
| A24 反 | 模拟结果具有完整成功观察 | 只生成 simulated 结论，不计入真实环境通过数 |
| A25 反 | registry 重复版本、缺 post_check、模板变量无来源或不兼容适配器升级 | 加载原子失败或入口 unsupported；不能靠文件顺序覆盖 |
| A26 正反 | 带引号数字原子与数字、system 与 admin、不同域同名用户 | 保留类型/权限/账户归属差异；不得为提高召回率合并 |
| A27 反 | 同一 LEAF 被多个步骤引用，或原图有同内容不同 ID 的事实 | 保留每个消费关系和 fact_ref；证据复用由有效性策略决定，matcher 不篡改原图 ID |
| A28 反 | required_fields 有多个冲突来源，或 required_when 尚不能确定 | missing_fields 中区分 conflict/unresolved，保留所有来源，不能采用默认值跳过 |
| A29 正反 | action 模板内前一步生成目标 session_ref；对照引用未登记后续产物 | 前者列为 deferred_bindings 并在阶段边界复核；后者 registry_invalid，不能先调用后补参数 |
| A30 反 | action 正常结束，但 post_check 仅有 partial_observation 或某个必需子检查未通过 | Supervisor 不提交 provider succeeded，effect facts 不变为 true，下游不解锁；ability 无 DB 写入 |
| A31 正反 | 同一节点三段共用 attempt_id，各调用有独立 atomic_call_id；对照重试/迟到结果 | 同次传输重送沿用调用 ID；新调用和新节点尝试分别创建对应新 ID，迟到结果不能写入其他 attempt |

真实仓库回归锚点采用 S1 IP 图节点 21：case 为 `winrm_system_after_firewall_disable`，效果引用 20 指向 `execCode('192.168.3.11',system)`，直接服务事实 29 为 `networkServiceInfo('192.168.3.11',winrm,winrm,139,system)`。期望保留原始协议和端口，若没有已登记端点映射与相应模板，准确报告缺口。旧主机名图节点 32 只作历史对照，fixture 必须绑定各自 graph_hash，不能用编号直接互换。

## 10. 完成标准与交付范围

后续实现满足以下条件才可声明本模块验收通过：

- Schema、引用、模板变量、版本与活动状态校验覆盖全部加载条目；所有 active 能力都有完整正例、反例和证据不足例。
- A01–A31 的离线验收及 S1 IP 回归全部符合预期；四类结果“直接效果、仅补 LEAF、参数不足、暂未支持”均有清晰机器状态与中文解释。
- 相同快照得到相同排序，所有候选给出完整匹配原因、覆盖引用、参数出处与 post_check 要求；任何 score/metric 都不能解释为成功概率。
- 所有 Skill/MCP 调用请求可追溯到具体 ability/template/entry/atomic_step；没有登记模板的调用不能进入执行接口。
- 反例中不得产生误报 proven；证据与图目标、请求、环境、时效及完整参数关联；运行完成和事实成立使用不同字段。
- 保持 V1 输出兼容，不改动原图引用、case 含义、节点哈希或原始端口/协议 token；当前不可执行的 case 有明确 unsupported 原因。

性能验收只测本地确定性检索：固定 1,000 条能力、35 个 case、固定图与运行快照，排除首次读取与 Schema 加载后记录单次 match 的 p50/p95 和候选数；首版目标 p95 ≤ 1 秒，验收记录附 CPU、Python 版本与输入规模。性能不达标应优化索引，不能跳过绑定或证据契约检查。

本次交付仅为本文。`src/abilities/matcher.py`、新 Schema、registry 迁移、解析器、执行适配器与测试均属于后续实现；不将本次文档审查算作这些功能的测试通过。
