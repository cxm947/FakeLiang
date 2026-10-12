# v0.3 最小数据契约

> 这是待实现的研究原型契约。替代 v0.2 的六表、八态和多层恢复协议；V1 图 Schema 现为 1.1.0。
> 只保存运行新增的信息。原图已有字段直接读取，能计算的状态不重复落库。

## 1. 三张表，分别回答三个问题

沿用 PostgreSQL，schema 名保留 agv_runtime。首版一个 run 由一个 Python 进程串行执行。

### runs：这次实验是什么，现在做到哪里

| 字段 | 类型 | 用途 |
| --- | --- | --- |
| run_id | UUID，主键 | 一次运行唯一编号 |
| graph_json | JSONB | 完整原样 V1 输出，创建后不修改 |
| config_json | JSONB | 本次模型、能力配置、预算、mock/real、实验初始条件及必要的主机/端点映射 |
| status | text | running / paused / finished |
| current | JSONB，可空 | 唯一当前工作指针，见第 3 节 |
| sessions | JSONB | 已核对的会话小目录（MSF / 自建 agent / webshell 通道），初始 []。通道由卡片信封 `envelope.channel` 声明（缺 id 时按 `<host>-<driver>` 命名），用之前先复验；当前实现在 `run_result.channels{}`。D31 起通道条目带**权限上下文**：`identity`（对面自报）/ `privilege`（等级，由 identity 推导）/ `escalate`（把命令送进更强身份的前缀），对应卡的 `session_ref.min_privilege`；`needs[].privilege` 记「值在、但不够强」（不进 sessions 表，属缺口） |
| created_at / updated_at | timestamptz | 创建和最近保存时间 |

不再建 graphs 表；每次实验保存自己的输入快照，接受这点小体积重复。
config_json 只在 run 创建时保存 data_version=0.3 和本次使用的模型/能力配置，不给每条消息增加协议版本、hash 或引用链。
source_graph.graph_hash 是原图摘要，不冒充完整投影 JSON 摘要；本版直接靠不可变 graph_json 固定输入。
红日 7 的 host 使用稳定主体名；将该场景 assets.json 的 IP 与发布端点映射作为本次配置保存。工具连接时解析映射，不能把 target_host 当作必为 IP，也不能把代理入口的地址误作取得权限的主体。容器自报的短 id 属于运行现场对照物（运行层按 `requirement.target_aliases` 注入，且容器对宿主不算同一台），不进表。

### node_runs：每个动作目前是什么结果

| 字段 | 类型 | 用途 |
| --- | --- | --- |
| run_id / node_id | UUID / text，联合主键 | node_id 原样使用 V1 nodes[].id（= 原图 ID） |
| status | text | pending / running / succeeded / failed / blocked / uncertain |
| reason | text，可空 | 未通过或阻塞的具体原因 |
| result_record_id | bigint，可空 | 指向最近一次已提交节点结论的 records.id |

只给 type=AND 建行。终点 OR 从图和成功节点推导，不建立重复节点状态。
原图 ID、主机、前提、效果、case_id 等由载入层（`src/graph/rehydrate.py`）从 graph_json + 规则导出，不复制进表。

### records：为什么得出这个结果

| 字段 | 类型 | 用途 |
| --- | --- | --- |
| id | bigint，自增主键 | 记录编号，也用于引用和排序 |
| run_id / node_id | UUID / 可空 text | 属于哪个 run、哪个原图节点 |
| kind | text | agent / tool / check / result |
| data | JSONB | 下表对应的结构化内容 |
| created_at | timestamptz | 记录创建时间 |

| kind | data 中保存什么 |
| --- | --- |
| agent | phase、实际模型输入 input、返回 output、可选用量 |
| tool | phase、tool、args、output；后端有查询句柄时附 handle |
| check | phase、fact_ref、value、evidence、reason |
| result | phase、status、reason、evidence；节点取得新入口时附 entry |

phase 使用 pre/action/post/session；运行级结果的 node_id 和 phase 可空。
value 是 true / false / null；null 表示证据不足。evidence 是本 run 的记录编号列表，通常指向原始工具记录。
agent/tool 调用前创建 output=null 的记录，返回后补一个输出对象。失败也写输出对象；不能用 null 同时表示“尚未收到”与“已完成但无输出”。超时回执不代表远端操作结束，不能只凭 output 非空清除待核对指针。
check/result 只追加，由程序在核对后写入；不能把模型返回的 checks 直接当成已接受事实。
大输出保存本地持久文件，在 output 中写路径；原始观察只保留一份。records 同时承担过程日志和证据，不另建 events/evidence。

## 2. 事实怎么存，哪些不存

| 信息 | 来源 |
| --- | --- |
| 事实文本与类型 | graph_json.source_graph.nodes |
| 节点依赖行（LEAF/OR/AND） | 文档 nodes[].dependencies（直接父，含 validation / produced_by） |
| case_id / details | 载入层从 graph_json + 规则重导（不落表、不回流文档） |
| 当前直接 LEAF 列表 | 载入层 premise_refs 中源节点类型为 LEAF 的项，启动时计算 |
| LEAF 检查结论 | records.kind=check 中程序接受的结果 |
| OR 是否成立 | 是否存在 status=succeeded 且 effect_refs（载入层派生）包含该事实的 provider |
| 终点是否达成 | 同一 OR 求值结果 |
| ready 节点列表 | 当前图（E5：全部直接前提组）、节点结果和资源现场计算 |

LEAF 没有有效检查记录时为 unknown。固定环境下，复用最近的明确 true/false 结论；后续检查缺证只记录缺口，不把旧证据自动改成 false。
若出现相互矛盾的明确观察，暂停运行并核对；首版不做 TTL、supports[]、事实版本或级联撤销。无法确认仍是同一实验条件时，保存本次结果并在恢复靶场后另开 run。

OR 没有成功 provider 时为 unknown，不能因为所有方法失败就写成 false。
只有全部必需 effects 获证，节点才能一次性变为 succeeded，因此一个成功节点同时提供全部效果；部分检查结果只留在 records，不提前解锁。

原图的 LEAF fixed true、effects persist 等是投影假设，不是实际验证记录。运行仍检查当前 direct LEAF；MSF 只是执行资源，不能凭已有会话绕开 provider。
本版采用单次实验内前提稳定、已证明效果持续的范围。会话掉线只影响资源；实质环境冲突暂停处理，不引入动态真值维护平台。

## 3. 中间态只有一个小指针

~~~json
{
  "node_id": "2",
  "phase": "post",
  "record_id": null
}
~~~

node_id 表示当前原图动作；phase 表示前检查、动作、后检查或节点成功后的会话准备。
record_id 仅指向当前尚未处理完的模型/工具调用，无调用时为 null。没有当前任务时，整个 current=null。
各阶段已经做过什么直接读这个节点的 records；不再复制检查点、计划版本、调用步骤树或完整聊天记忆。

- 节点领取：status=running，current 指向 pre。
- 工作中：更新 phase，调用前登记 record_id；确认原调用已结束且结果处理完成后才清空 record_id。
- 原节点成功：同一事务写节点 succeeded、结论记录，并将 current 改为 session；没有新入口则清空。
- 会话准备完成或明确失败：写记录，成功则登记 sessions，清空 current，再选下一个节点。
- 工具是否执行未知：run=paused，节点和 current 保留，先查原记录与后端，不盲目重发。
- 没有在途调用且本节点不再补证：提交 uncertain 并清空 current。uncertain 是本轮结论，不再兼任“等一会儿”的标记。

## 4. 会话目录

只登记已经核对过的 MSF 会话，每项保留：

~~~json
{
  "node_id": "2",
  "msf_id": "2",
  "host": "192.168.3.11",
  "user": "SYSTEM",
  "available": true,
  "evidence": [18]
}
~~~

示例记录编号仅示意，不代表已经执行过。host/user 是实际观察，不从节点目标或会话类型猜出权限；能力细节存在被引用的 MSF 观察记录，使用前核对。
来源节点和工具记录足够追溯入口。相同 MSF 会话复用目录项，不为每个 Agent 另造 session_ref。
源工具的入口保存在节点 result 记录的 entry={tool,handle} 中；Session Agent 直接读取，不建立 normalizations 目录。
所有新执行入口在节点成功后处理；已有合格 MSF 会话复用，无新入口跳过。归一化失败只写 session 阶段结果，不修改原节点成功。
运行固定一个 MSF 后端；后端重启时旧映射全部视为不可用，重新核对后才恢复，不仅凭旧数字 ID 接续。真实连接由 MSF 保存，数据库不能复活连接。

## 5. Agent 交接只用普通函数数据

每个角色是本地函数边界，不做 RPC 消息信封、独立任务对象存储或协议版本矩阵。
程序把实际输入输出记入 agent 记录，需要恢复时再从图和记录构建输入。

| 调用 | 输入 | 返回 |
| --- | --- | --- |
| execute_node | 原 V1 node、相关事实视图、可用会话、该节点已有记录 | status、reason、checks、可空 entry |
| prepare_session | 原节点、新入口、已有会话和相关记录 | 已核对会话，或失败原因与证据 |
| diagnose | 原节点、异常记录、剩余预算 | suggestion、reason |

execute_node 的 status 只提出 succeeded/failed/blocked/uncertain；每项 checks={fact_ref,value,evidence}，字段与 check 记录一致。
Checker 核对目标、来源、实际观察及全部必需效果后，才接受结论并写表；模型自报成功不能跳过此步。
diagnose 的 suggestion 仅为 retry_check/change_tool/stop，主控确认适用当前任务才执行。
任务完整目标和参数直接使用原 V1 node，不重新定义 TaskSpec/NodeExecutionPlan/NormalizeRequest/RecoveryAdvice 四套持久对象。

## 6. 状态含义、保存与恢复

| 节点状态 | 意义 |
| --- | --- |
| pending | 尚未开始，可能还在等前驱或资源 |
| running | 当前节点正在处理或暂停后等待续作 |
| succeeded | 原节点全部必需效果已获证 |
| failed | 原节点声明有实际反证 |
| blocked | 前提无法满足、资源无法取得或没有兼容方法；原因写 reason |
| uncertain | 已确认无在途工作，但证据不足，本轮不再继续 |

ready 只计算不保存，unsupported 放入 blocked 原因，claim_verdict/disposition 不再保存。
补检查和允许的方法修正都在 running 内完成；不再为每次模型调用、节点尝试、会话准备各造 ID，统一引用 records.id。
首版不自动重跑已结案节点；已知前驱/资源准备尚可推进时保持 pending，来源耗尽才 blocked。需要完整重验时另开 run。

每次关键保存使用一个短事务：更新 runs/node_runs，并保存对应记录。网络和模型调用在事务外。
特别是“节点成功 + 成功结论 + 下一步 session 指针”必须同事务，防止漏掉会话工作。OR 是派生值，无需另写效果表。
单进程串行，恢复前确认旧进程已停止；不实现分布式接管、租约、乐观版本和挂起队列。

重启读取三表即可：有未确认调用先对账；已有回执则从已完成记录续接，不重放动作；节点成功而 phase=session 时只继续会话准备。
对账期间保留 current.record_id 对原未知调用的引用；查询记录只补证，确认原操作结束后才清空该引用，不能用新动作覆盖它。
如果调用未完成、句柄失效或环境变化无法确认，就保持 paused 并说明原因。本版支持有记录的阶段续作，不承诺任意工具无损恢复或完整模型思考重放。

所有 AND 都有最终结论、current=null，才能 finished；还没开始的无解节点先标 blocked。paused 不能算完成。
最终报告分别统计节点成功/失败/阻塞/不确定及会话准备结果，不再把整次运行套一遍八态优先级。
记录可以重建过程和复核调度依据；“严格历史状态重建”不是本版已有保证，要用固定检查结果序列单独检验逻辑复现。

## 7. 本次删除了什么

删除独立 graphs/run_facts/evidence/events 表、终点状态行、supports/有效期/版本传播、disposition、租约、归一化队列、多层检查点及 attempt/work/normalization/agent_turn 等 ID。
保留 run_id、原 V1 node_id/fact_ref、一个 records.id、一个 current 指针。它们分别回答哪次运行、哪个图元素、哪条证据、当前做到哪。

与原 Schema 的逐项映射见 [V1 数据映射](graph_bundle_fact_index_prd.md)；运行例子见 [大白话说明](workflow_plain_language.md)。


## 2026-10-04：动作日志与跨进程对账补充（010）

本节覆盖此前与其冲突的恢复语义。每个 stage、proposal、decision、call 使用不可复用的唯一 ID。`stage-manifest.json` 固定原始节点、卡内容、工具绑定、任务输入及重建上下文；`dispatch-intent-*.json`、`receipt-*.json`、`decision*.json`、`reconciliation-*.json` 创建后不可覆盖，`stage-events.jsonl` 仅追加。`stage-checkpoint.json` 是可替换的派生快照，保存预算、阶段、未决副作用、义务、证据账本及观察 epoch/来源时间。恢复不得把观察时间改为恢复时间。

发出动作前必须持久化原调用 intent；收到回执后以原 call_id 落盘。超时、异常、unknown 和缺回执保持未决，连续重启不能清空，也不能重新发出变更动作。唯一的本地未派发证明是运行时明确返回 `dispatch_attempted=false`、`status=tool_unavailable`、`tool_status=rejected`、`effect=not_applied` 并持久化该回执；这种最终准入拒绝不需要原调用对账。若进程在拒绝回执落盘前退出，仅有 intent 仍按 unknown 恢复。跨尝试带入的未决副作用单独持久保存，当前 stage 的普通观察或单个回执不能清除它们。

`Stage.pending_operations()` 返回原操作引用；`Stage.reconcile(call_id, query)` 只调用后端的原操作查询接口，不能调用执行器重发动作。结清须同时提供匹配的 call_id、completed=true、明确 effect（applied/not_applied/partial）、终态 tool_status 和原始输出引用。迟到回执另存对账记录，不覆盖原超时证据。缺查询接口返回 `ORIGINAL_OPERATION_QUERY_UNAVAILABLE`；对不上原调用或仍未完成则继续未决。结清副作用不等于节点目标通过：必须继续独立验证。

节点结果需保留原 stage 的 action_dir（可位于 attempts[].v2.action_dir）。恢复入口读取该目录固定的原卡与绑定；不得重新选卡后把另一动作当作原动作恢复。


## 证据来源、主体与观测时效（010）

动态证据行必须保留采集器产生的 `call_id`、`tool_contract`、`event_schema_ref`、
`subject`、`observed_at`（UTC Unix 秒）、`epoch`、`raw_record_ref`、`evidence`。
`subject` 使用 endpoint/entity_id/execution_point 标识被观察实体，并按实际操作保留
port、protocol、vantage、namespace、resource、principal 等轴。消费者期望的地址、资源和
参数只能形成筛选约束，不能反填缺失的采集主体。

动作车道将运行绑定作为 `required_subject` 传入派生：endpoint、port、protocol
等已绑定轴即使技能卡的 subject_bindings 省略也必须逐轴匹配。vantage 默认取方法执行视角；
观察来源可以显式声明另一个固定视角（见第九轮），不能省略证据中的该轴。其他运行绑定
与卡声明冲突、来源缺轴或跨实体同名时均保持 unknown。事实来源时间不在派生、导入或恢复时刷新；
观测策略的 TTL 使用原始 `observed_at`，事件失效递增按运行主体共享的持久 epoch。
失效回调必须先原子持久化新 epoch，再更新本地缓存；持久化失败不能继续假定失效成功。
新尝试从共享 epoch 开始，快照恢复取共享代际与快照代际的较大值，每次派生/调度前同步
外部更新。快照同时保留原始时间和失效状态；旧 epoch 的证据即使仍在 TTL 内，跨目录
重试或重放旧快照也不能重新成为可用观察。

`accepted_evidence.all_of` 的每个槽位都必须有合格证据；非空 `any_of` 至少有一个合格
槽位，同时声明二者表示同时满足。槽位精确匹配工具契约、事件 schema 与 `select`
JSON Pointer；缺任一必需槽位不能由其他槽位的成功补足。卡作者需要表达替代来源时，
应放入 any_of，不得依赖先前将 all_of/any_of 合并成 OR 的行为。

读回相关性使用同一完整主体、同一 epoch、晚于写入的采集时间和实际读出的 `read_value`。
`expected_value` 只能结合写入被接受的 ACK 作为写侧预期值，不能当成读回；请求参数、
相等的请求指纹、缺少读值或先读后写都不证明读回成功。恢复比较也不能把缺失读值当成
资源不存在：只有明确的 `evidence.resource_absent: true` 才表示缺席；空字符串是实际值。

静态部署声明使用单独类型：

```json
{"kind":"run_configuration","value":"host","subject":{"endpoint":"host-a"},
 "source_ref":"run-config.json#/runtime_boundary","created_at":1700000000.0}
```

配置来源必须指向不可变运行快照，匹配完整消费主体并保留快照创建时间；它不包含伪造的
观测 observed_at/epoch，也不因观测 TTL 或服务重启失效。派生结果以 source_kind、
source_ref、source_created_at 保留该区别。运行侧裸布尔值不属于证明；动态 run-held
事实仍须包含原始证明引用、采集主体、时间、epoch 和原始记录位置。配置事实仅可经
run-held 规则读取，不能替代 TCP、服务身份、读回或其他要求实测的证据。

完成判定还必须将本次 attempt 中成功回执的 call_id 与合格采集证据行关联，按当前
运行主体、原始采集时间和共享 epoch 核验；只有前置证明、成功工具家族标签、空证据
或模型自报完成不能直接获得 pass。显式本地执行点可作为 execution_point 主体，不能
为缺失主体合成一个目标地址。


## 第五轮：原生 HTTP 证据与显式版本义务

应用观察保留实际响应中的标题、路径标记和原文 basis。产品别名与匹配标记来自固定消费卡，不能由调用方 expected_service 回抄成证据。HTTP charset 解码失败时保留原字节和错误，不产生可靠正文身份。

身份结论与版本结论分开：期望 token 的版本后缀仅参与名称规范化，不自动生成版本义务；显式 expected_version 和方法卡版本谓词仍要求同一应用的实测版本。名字成立且版本未测不等于满足带版本的准入条件。


## 第六轮：派生拒绝与采集信封分别记账

观察派生没有得到值时，记录 status=derivation_unavailable，保留 derivation 的 rule、gap、why、basis_refs、evidence_rejections 与 evaluation_context。此记录没有声称采集成功：envelope 为空、at/epoch 为 null、missing 为空；不能把空 envelope 重新校验后伪装成一条缺信封的采集。既有采集接口提交不完整 envelope 时，仍按 envelope_incomplete 记录真实缺字段并拒绝准入。

拒绝诊断逐行保留 call_id、工具契约及具体缺项、主体不符轴、时效或 epoch 原因；早先的不完整行不能掩盖后续行的失败原因。evaluation_context 保存本次派生共用的评估时刻、消费主体、epoch 与 TTL。诊断不生成原始证据引用，不更新采集时间，也不赋予事实。派生失败必须撤回先前缓存的真值，快照恢复后仍不可用；后续合格证据可重新建立观察。

图中的应用协议与证据中的传输协议分属两层。运行侧构造消费主体时复用叶映射已支持的 transport_protocol：图语义 http 在该契约下绑定 tcp；URL 和 selector 中的图原值保持不变。底层 subject_matches 仍严格比对传输轴，UDP、未知协议不降为 TCP。本轮没有新增 HTTPS、HTTP/3 或任意协议的推断支持。

## 第七轮：执行视角与采集解析边界

方法车道的默认 required_subject.vantage 来自该方法实际解析出的执行绑定，不从图 source_host 统一复制。图叶明确要求的 source_host 仍是独立的定向事实要求；卡 observation_sources 中显式绑定的 vantage 也不能被默认视角覆盖。观察提供者仍按其自己的实现卡选择 executor；来自不同视角的回执保持不同主体，不能为满足消费要求而改名。当前单一方法 scope 不代表多种执行位置的变体已具备逐动作 scope 支持。

assembly.observation_parse 保存本次原始输出到证据字段的解析边界：status=parsed/unavailable、framing=present/missing、reason_codes、evidence_fields 和 raw_output_ref。缺少运行时输出标记为 OUTPUT_FRAME_MISSING；取得标记内输出但未读出 call_id 以外的有效字段为 OBSERVATION_FIELDS_UNAVAILABLE。诊断不自动拆开客户端包装，不从命令参数、节点或承载 SSH 会话补造目标主体，也不把 stderr 或正文再次复制进理由。parsed 仅表示取得字段，不代表主体齐全、资格合格或判据通过。

动作车道收到 unavailable 时仍记 status=sent，tool_status=unknown、conforms=false，并将 observation_parse 保存在不可变 collection 与 ledger 中。只读调用保留 not_applied；已派发变更保留 unknown 副作用，不能因解析失败假称未派发。旧提供者没有该诊断字段时兼容原路径，但必须继续通过原有主体、时间、epoch 与来源资格检查。

## 第八轮：运行任务值与提供者必需参数

run_v2_attempt 在建立工具层前合并运行侧 task 值，Stage 的 binding_ref 和提供者调用消费同一份绑定；通过消费卡已有 compatibility.legacy_input_mapping 翻译输入名。地址解析仍在运行边界完成，提供者不猜逻辑主机。固定图期望与传输协议进入观察调用的输入，不因此成为观察证据。

提供者 input 中的 const 可以补入缺省参数；与固定图值或模型实参冲突时具名拒绝。模型可以提供尚未绑定的参数和允许变动的动作参数，但不能覆盖运行已固定的图目标、端口、协议及期望。规则与模型装配共用该输入对象。

装配的必需输入检查独立于启动命令是否含文本占位符：代码工件从 params.json 取值，也必须通过同一个检查。ASSEMBLY_REQUIRED_INPUTS_UNBOUND 携带缺失字段；在工件准备、远端落盘和探针执行前拒绝。车道将这一专用拒绝记为 tool_unavailable/rejected、dispatch_attempted=false、effect=not_applied，不制造未知变更。任意派发后异常不适用此分类。可选参数缺省和有效的 false/0 保持原语义；模型命令不能绕过必需输入门禁。

## 第九轮：观察要求与提供者执行位置分开声明

方法执行绑定是未声明观察视角时的默认要求。observation_sources.<name>.subject_bindings.vantage 可声明固定位置名称（例如 base），或 task.source_position。后者由图 source_host / 运行 requirement 固定；图约定的控制位与空源规范为 base，不接受候选输入或模型参数覆盖。卡及 task 输入进入 StageJournal 摘要，同 attempt 重启更换声明或图源会被 STAGE_BINDING_CHANGED 拒绝。

显式视角只替代方法默认 vantage；endpoint、port、protocol 等其余运行约束仍严格合并。显式 task.source_position 无值时为 SUBJECT_BINDING_UNAVAILABLE，不回退方法视角；未在 input_sources.task 声明的 source_position、model.*、runtime.* 及其他未实现 task 引用为同一 gap，并附 UNSUPPORTED_VANTAGE_BINDING 原因。evaluation_context 同时记录解析后的 subject 和 vantage_binding。提供者始终按实现卡派发，回执保持实际采集位置；不符合观察声明时，逐行 evidence_rejections 保留必需/实际主体与 mismatched_axes，不将回执改名。

应用观察从图源位置成立，不等于方法执行结果已成立，也不证明另一网络路径上的同一应用实例。方法完成证据继续要求方法主体；图叶的定向 source_host 要求独立保留。跨视角观察仍共用运行 epoch，失效时共同作废，不能通过换视角复活。
