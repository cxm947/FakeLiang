# V1 图数据与运行层映射

文档版本：0.3；对应 `runs.config_json.data_version="0.3"`；状态：开发基线，尚未实现。
本文说明现有 TXT 转换产物怎样直接交给运行层，不再定义需要持久化的 GraphBundle。
总体流程见 [整体方案](overall_prd.md)，字段以 [精简数据契约](runtime_data_contract.md) 为准，使用过程见 [大白话说明](workflow_plain_language.md)。

## 1. 原图保存一次，运行层只记变化

首版只有 `runs`、`node_runs`、`records` 三张表。完整 V1 JSON 原样存入 `runs.graph_json`，本次运行期间不修改。
只为 `nodes[]` 中 `type="AND"` 的节点建立 `node_runs`；终点 OR、事实、依赖和索引不单独建表。
运行状态固定为 `pending/running/succeeded/failed/blocked/uncertain`；派生面 `case_status`（载入层导出）与这些状态无关。
V1 现为 `schema_version="1.1.0"`（1.0.0 已退役）；运行契约升级不要求向文档加新字段。
Schema 使用 `additionalProperties:false`，不能把运行状态、会话或证据追加进现有 V1 节点。

## 2. 直接复用的真实字段

| 需要什么 | 现有 V1 路径 | 用法 |
| --- | --- | --- |
| 原图标识 | `source_graph.graph_hash` | 原图 archive 摘要；不是完整投影 JSON 的摘要 |
| 节点身份 | `nodes[].id` | 完整 SHA256，64 个十六进制字符；直接用作 `node_id` |
| 原始编号 | `nodes[].semantics.original_id` | 显示编号；转整数后排序 |
| 动作或终点 | `nodes[].type` | AND 可分派；OR 只展示目标是否达成 |
| 能力类别 | `nodes[].semantics.case_id`、`case_status` | 检索能力的依据；匹配到 case 不代表工具已支持 |
| 规则文本 | `nodes[].rule_desc`、`attack_id` | 给 Agent 解释当前任务 |
| 连接参数 | `nodes[].source_host`、`target_host`、`service`、`protocol`、`port` | 直接引用，允许空值；端口是字符串 |
| 特定参数 | `nodes[].semantics.details` | 按 case 读取权限、账户等，未定义的字段不能猜测 |
| 原始直接前提 | `nodes[].semantics.premise_refs` | 指向源图 OR 或 LEAF 的原始编号 |
| 动作依赖 | `nodes[].semantics.requires` | 各组同时满足，每组 `any_of` 任一提供者成功 |
| 动作效果 | `nodes[].semantics.effect_refs` | 指向原图 OR 事实编号 |
| 完整事实 | `source_graph.nodes[]` 的 `id/type/description` | OR 与 LEAF 的权威原文 |
| 原图关系 | `source_graph.edges[]` | `source → target`；保留提供者、前提与效果关系 |
| 化简记录 | `logic.removed_conditions[]` | 说明哪条 OR 前提被另一条事实蕴含 |
| 展示边 | `edges[]` | 可画图；调度不能只看扁平边而丢掉分组语义 |

当前 V1 没有顶层 `facts`、`direct_leaf_refs` 或全量结构化 `predicate/arguments`。
需要谓词与参数时，使用现有 `terms.parse_fact()` 解析事实 `description`；解析结果只作内存索引。
未知谓词保留原文和编号，交给能力检查报告缺口，不编造解释。

## 3. 不再重复保存的数据

启动时从 `runs.graph_json` 构建节点、事实和提供者的查询字典；重启重新构建即可。
当前节点的直接 LEAF = `premise_refs` 中源图类型为 LEAF 的项；不递归收集祖先 LEAF。
事实的提供者由各 AND 的 `effect_refs` 反向索引得到，消费者由 `premise_refs` 反向索引得到。
Agent 的节点参数、依赖、直接 LEAF 和效果从这些索引组装，不另存一份带独立版本的任务图。
终点 OR 是否达成也在查询时计算，不建立 `node_runs`，不分派 Agent，不保存第二个完成状态。

## 4. 事实怎样判定

LEAF 的值读取本次运行中该事实最近一条已接受、结论明确的 `records.kind="check"` 记录。
其 `data` 形状是 `{fact_ref, value, evidence:[record_id]}`；`value` 只能是 `true/false/null`。
没有明确检查结论时值为 `null`；新检查缺证仅记录缺口，不自动抹掉固定环境下已有的明确结论。模型解释和未经接受的观察不能直接改变事实。
OR 事实由成功提供者派生：任一 `node_runs.status="succeeded"` 的 AND 在 `effect_refs` 中包含它，即成立。
没有成功提供者时 OR 为未知，不因此判假；某条路径失败不能反驳所有路径。
提供者必须完成整节点验证及必需效果检查才可成功；零散输出不能提前发布效果。

首版采用固定实验前提、效果在单次运行内持续的假设，不设计支持撤销树、有效期或级联失效。
若新检查与既有已接受结论发生真实冲突，将运行置为 `paused`，保留记录并说明冲突，不静默覆盖后继续推理。
V1 的 `logic.assumptions` 是离线化简成立的条件：LEAF 固定为真、动作有图内依据、效果持续、无外部事实或会话导入。
运行验证仍须检查直接 LEAF，不能把图的“固定为真”假设当作已经取得的检查证据。
会话只作为执行资源；外部会话不能替代图内提供者，也不能凭会话存在直接解锁 OR。
MSF 会话断开属于资源变化，不自动抹掉已经证明的历史动作结果。

## 5. 调度只派生 ready

`ready` 是当前候选条件，不是数据库状态：从待处理节点计算依赖成立且可以开始前检查的候选。
`requires` 各组之间为 AND，每组 `any_of` 内为 OR；`any_of=[]` 不满足，`requires=[]` 仍须检查直接 LEAF。
尚未检查的 LEAF 不阻止进入前检查；真正执行动作前，直接 LEAF 必须全部为真，并有兼容工具与执行资源。
按 `semantics.original_id` 的数值顺序选择候选；模型不能更改依赖或自行挑选下一条路径。
被化简的原始 OR 前提仍保留在 `premise_refs`；执行前核对其派生成立状态，异常时暂停解释，不补造支持。
存在多个提供者时，一个成功即可满足该条件，但全图验证仍保留其他动作；无种子循环不能相互证明。

## 6. S1 的实际对应

节点 21 的 `case_id` 是 `winrm_system_after_firewall_disable`，来源 `.10`，目标 `.11`。
完整 `node_id` 为 `1f3fe6d8aef981bdb97ac7ff38870ff3f5eec840031a67c2f4b6099d1ab0bc89`。
`source_host="192.168.3.10"`、`target_host="192.168.3.11"`；`service/protocol="winrm"`，`port="139"`，不得擅自改成 5985。
`premise_refs=["6","11","22","23","28","29"]`，直接 LEAF 为 22、28、29；原始直接 OR 为 6、11、23。
`requires` 为事实 6 由节点 7 提供，且事实 23 由节点 24 提供；实际 `any_of` 保存完整节点哈希，不保存展示编号。
事实 11 的条件因被事实 6 蕴含而从 `requires` 化简掉，记录仍在 `logic.removed_conditions`。
`effect_refs=["20"]`，对应 `execCode('192.168.3.11',system)`；终点 20 由节点 21 成功派生，不再执行一次。
节点 31 的来源仍是 `192.168.3.10`，目标是 `.12`，不能默认使用节点 21 新建的 `.11` 会话。

## 7. 已核对的输入范围

S1/S2/S3 IP 产物均通过现有两套 Draft 2020-12 JSON Schema；投影节点数为 9/20/41，AND 数为 7/17/35。
`attack_step.schema.json` 去掉标题与 `$schema` 后，与 `action_graph.schema.json` 的 `$defs.node` 完全一致。
S1 有 35 个原始节点，其中 28 个 OR/LEAF 事实；运行层只新增 7 条节点状态，不重复保存这 28 个事实定义。
导入还须核对 ID 唯一性、引用存在和关系语义；JSON Schema 通过不代表这些跨对象条件自动满足。
本次只调整开发文档，没有修改 Schema、转换程序或已有 JSON 产物。
