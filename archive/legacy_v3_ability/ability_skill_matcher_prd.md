> **已弃用（2026-09-16）**：本文件是 v3「ability」命名期的最小方案稿，已整体移入 `archive/legacy_v3_ability/`。
> 现行契约见 [技能目录契约](../../docs/product/skill_contract.md)（术语 `skill`；登记源 `skills/registry.json`；
> 单条机器契约 `skills/<id>/skill.json`），检索与执行的工程流程见 [技能检索、适配与校验工程流程](../../docs/product/skill_retrieval_execution_flow.md)。
> 文内 `ability`/`capability` 均按当时口径书写，未改写以保留决策过程。

# 能力检索的最小方案（v0.3）

Matcher 保留为检索函数，不作为 Agent。运行数据引用 [最小数据契约](../../docs/product/runtime_data_contract.md)。

## 能力目录只需要什么

| 字段 | 用途 |
| --- | --- |
| id | 程序调用哪个登记方法 |
| case_id | 对应 V1 semantics.case_id |
| phase | pre / action / post / session |
| inputs | 参数要求，值从原 V1、配置或已取得的材料绑定 |
| adapter | 具体函数入口 |
| check | 程序检查返回观察的判据 |

首版用小型 YAML 或 Python 目录即可，不新增向量库、分类体系和多级版本。
模型选择兼容方法；参数与目标匹配由程序复核。一个阶段可以检索多次，实际选择与结果记 records。
source_host/target_host/port 等直接取原节点，不能只凭 case_id 相同就假定权限和来源兼容。

已有 schemas/ability.schema.json 是早期草案，字段偏向 action_classes，与当前 V1 的 case_id 不能直接等同。
实现时整理运行能力目录即可；本轮不修改它，更不改 action_graph/attack_step 的 V1 Schema。

无能力写节点 blocked 和具体原因。已执行却缺效果证据时为 uncertain，不能称为“没执行”。
