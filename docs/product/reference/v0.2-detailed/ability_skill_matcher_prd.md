# Ability 检索与节点判据 PRD

> runtime_contract_version=0.2。上位契约见 [总 PRD](overall_prd.md)。这是 Execution/Session Agent 调用的工具模块，不设置独立 Matcher Agent。

## 1. 职责

检索工具回答：当前命题可以用哪些已登记方法、需要哪些参数、能取得什么证据。Execution Agent 在兼容候选中选择并完成节点；Session Agent 只选择当前归一化工作所需模板。选择方法不代表验证成功。

~~~text
读取当前任务与阶段
→ 字段过滤和稳定召回
→ Agent 选择已登记候选
→ 程序绑定并校验参数
→ Adapter 执行
→ Checker 对照原始观察判定
~~~

首版采用版本化 YAML registry、字段索引与固定候选排序。先不引入向量数据库。

## 2. 共享边界

- schema=agv_runtime；六表 graphs/runs/run_steps/run_facts/evidence/events。
- runtime_status=pending/ready/running/succeeded/failed/blocked/unsupported/uncertain。
- claim_verdict=proven/refuted/inconclusive/unassessed；truth_value=true/false/unknown。
- node_id 是 V1 完整哈希；original_id 只用于显示；fact_ref 是原图事实字符串 ID。
- 数据库写入经过程序内核；Matcher 和 Agent 不直接修改事实或节点。
- 原节点全部 effects 通过后才整体提交；session_normalization 是原节点成功后的辅助工作。

## 3. 能力的最小描述

| 字段 | 内容 |
| --- | --- |
| ability_id / version | 唯一能力与固定版本 |
| role | leaf_check / action / effect_check / inference / session_normalization |
| matches | case_id、完整命题、平台、运行模式、适用阶段 |
| required_inputs | 参数 Schema 及来源要求 |
| required_context | 来源/目标、实际权限、会话类型与能力要求 |
| adapter / operation | 已登记的具体执行接口 |
| observed_outputs | 返回的结构化观察及原始产物 |
| checker_id / version | 前提或效果判据；纯动作可引用配套 effect_check |
| side_effects / replay_policy | 本操作的影响与重试条件 |
| normalization_policy | 是否产生需要统一的新执行入口；已为 MSF 时可直接复用 |

session_normalization 的输出属于会话目录，不能伪装成另一个原图 effect。能力角色与候选可用性分别保存，不能把 parameter_incomplete 当作一种验证能力。

已有 schemas/ability.schema.json 不应被假定已满足本稿。实现阶段需增加或版本化运行层能力 Schema，保持 V1 action_graph Schema 不变。

## 4. 输入和返回

search_abilities 输入包含 run_id、node_id、phase、execution_mode、registry_version、case_id、当前 proof_targets、绑定事实与会话能力摘要。

返回每个候选的 ability_id/version、覆盖的 fact_ref、参数来源、缺失字段、排除原因和稳定 rank_key。缺失字段作为未知保留，不能从常见默认值猜出端点、凭据或权限。

get_ability 读取完整模板、参数 Schema、checker 和副作用说明。候选选择、替代方案及原因关联 agent_turn_id 写入 events。

## 5. 过滤、排序与参数绑定

1. 先过滤 case、阶段、平台、运行模式和完整命题明确不兼容的候选。
2. 比较完整效果要求，例如主机与权限；不能仅凭 execCode 字符串相同就认定匹配。
3. 绑定图参数、run 端点映射、事实引用、凭据引用和 session_ref。
4. 未知字段返回 parameter_incomplete；已有参数但当前会话不可用返回 context_unavailable。
5. 在当前阶段和角色内按命题覆盖、case 精确度、参数完整度、ability_id/version 稳定排序。
6. Agent 选择后程序再次核对版本、参数来源和副作用。

verify/reproduce 必须区分。首轮运行 reproduce：证明目标当前成立的只读方法不能替代必须复现的 action。effect_check 与 leaf_check 也不能互相替代。

选择不同工具可在当前任务边界内进行；调用计划修订必须记录版本。补检查允许有限本地调整，重新执行动作需按固定重试策略处理，未知原操作先对账。

## 6. S1 节点 21

~~~json
{
  "node_id": "<V1 完整节点哈希>",
  "original_id": "21",
  "case_id": "winrm_system_after_firewall_disable",
  "source_host": "192.168.3.10",
  "target_host": "192.168.3.11",
  "service": "winrm",
  "protocol": "winrm",
  "port": "139",
  "direct_leaf_refs": ["22", "28", "29"],
  "effect_refs": ["20"]
}
~~~

三个阶段可使用不同能力：

| 阶段 | 检索目的 |
| --- | --- |
| pre_checks | 取得 direct LEAF 22/28/29 所需证据 |
| action | 通过满足来源和身份条件的登记方法完成当前动作 |
| post_checks | 证明 effect20 所要求的目标与实际执行权限 |

post_checks 使用本次执行上下文，不能误用前驱 .10 主机上的 SYSTEM 结果证明 .11。账号材料、执行会话和网络路径分别绑定。

原图 winrm/139 保留原义；真实端点如有映射，在 run 配置中显式提供。不能根据协议名自动改写端口。

原节点提交后，如果新入口需要 MSF 统一，由独立 NormalizeRequest 检索归一化能力，不追加原节点的效果要求。

## 7. Checker 的判定职责

Checker 输入为固定 proof_target、原始工具观察、调用/会话身份、上下文与判据版本，输出逐项 verdict、依据和缺口。

- 有充分证据：proven。
- 有实际反证：refuted。
- 超时、材料缺失、解释冲突或仅有模型摘要：inconclusive。
- 未进行对应判定：unassessed。

Checker 应明确目标、来源、权限、时点和效果的对应关系。程序验证能覆盖的部分按规则判断；模型诊断不直接升级为 proven。复杂命题尚无可靠方法时保留不确定或在 action 前标明能力缺口。

## 8. 验收

- 同一图、registry 和上下文返回同一候选集及顺序。
- 方法匹配不能发布事实；工具退出码不能直接判节点成功。
- S1 节点 21 包含 LEAF22，不能只安排 28/29。
- 只有 LEAF 检查能力时不能宣布 effect 已覆盖。
- 未知来源、目标、权限、凭据或端点不能被静默补猜。
- 非 MSF 工具可以完成原节点；后续归一化另有调用与证据。
- 原节点已执行但缺 effect checker，结果不得倒写成“未执行”的 unsupported。
- 能力/判据版本和原始证据可支撑旧 run 的状态回放。
