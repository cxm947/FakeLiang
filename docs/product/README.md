# 产品文档导航

当前运行使用技能卡驱动的验证流程。实际命令见 [脚本说明](../../scripts/README.md)，模块与文件职责见 [文件地图](../file_tree.md)。本页区分运行说明、设计材料和历史记录；设计目标及旧轮次中的通过结果，不自动成为当前实现状态。

文档与实现不一致时，应具名记录差异并修正文档。文档整理不改变函数语义、默认值、异常、重试、超时、阶段顺序、技能卡或验证判据。

## 当前运行的阅读入口

1. [任务边界（V0）](product_boundary.md)：系统交付与验证边界。
2. [阶段一验收契约](stage1_acceptance.md)：验收要求；实际通过情况由对应轮次记录提供。
3. [脚本入口与使用说明](../../scripts/README.md)：图编译、节点与整图运行、会话管理、回收、日志和离线检查。
4. [凭据供给](lean_credentials.md)：私有材料、图绑定、消费候选与跨运行引用。
5. [前置与后置卡说明](skill_card_spec.md)：pre/post 卡说明；具体卡正文见 `skills/<卡目录>/SKILL.md`。
6. [实机验证记录](validation_runs.md)：按运行目录、调用记录与证据核对结果。
7. [术语表](glossary.md)：查术语时同时核对对应实现与文档版本。

当前图编译入口为 `scripts/project_graph.py`，整图入口为 `scripts/run_plan.py`。节点判据由图依赖导出，待产出事实与已有证据分别核对。

## 红日 7 的事实与部署

- [红日 7 第一版建模](hongri7_modeling.md)：目标事实、多 IP、容器与图表达边界。
- [红日 7 攻击图大白话说明](hongri7_attack_graph_plain.md)：图的阅读方式。
- [红日 7 下载与 VMware 部署](hongri7_deployment.md)：镜像来源与部署资料。
- [rules5_v2：Windows 横向移动规则改进说明](rules5_v2_windows_lateral.md)：规则变更背景。
- [红日 7 攻击图完成度审计](hongri7_completion_audit.md)：对应审计时点的结论。
- [Hongri7 writeup 与攻击图路径核验](hongri7_writeup_validation_audit.md)：对应核验时点的证据与差异。
- [反向代理隧道运行手册](reverse_tunnel_runbook.md)：隧道操作资料，使用前核对本轮部署与现行参数。

S1 等样例用于解释图逻辑。红日 7 的实际运行以本轮输入、主机映射、部署画像及编译文档为准。

## 设计与审阅材料

以下材料用于理解设计意图和审阅意见。涉及接口、状态、默认行为或验收结论时，需要与当前代码及对应提交核对。

- [项目级状态机草稿（V0.1，待用户修改）](../plans/project_state_machine_draft.md)：按“图输入—Planner—前期验证—利用—验证—会话集成”讨论目标流程，尚未作为实现契约定稿。
- [执行器的大逻辑](executor_big_logic.md)。
- [执行器失败七分类处理表](executor_failure_handling.md)。
- [执行器智能层方案](executor_intelligence_layer.md)。
- [执行器架构审阅（2026-09-30）](executor_architecture_review_20260930.md)。
- [Planner 设计（v2 草案）](planner_design.md)。
- [会话管理契约](session_management_contract.md)。
- [技能层设计 · 同行对照](skill_design_prior_art.md)。

## 历史契约、迁移与证据

下列入口用于查历史设计、迁移依据或当时的验收证据。历史技能数量、实现状态、CI 闸数和通过率均属于各自记录的时点，不能直接用来说明当前运行接口。

| 主题 | 历史材料 |
| --- | --- |
| 早期整体方案与数据契约 | [一次任务怎么工作](workflow_plain_language.md)、[整体方案](overall_prd.md)、[最小数据契约](runtime_data_contract.md)、[V1 数据复用](graph_bundle_fact_index_prd.md) |
| 注册表、检索与适配器 | [技能目录契约](skill_contract.md)、[检索适配流程](skill_retrieval_execution_flow.md)、[检索三阶段讲解](skill_retrieval_walkthrough.md) |
| v2 卡契约与目录迁移 | [技能卡契约 v2](skill_card_contract_v2.md)、[技能目录适配](skill_folder_adaptation.md)、[迁移来源清单](skill_migration_source_list.md) |
| 当时的验收与能力统计 | [执行层验收证据](execution_layer_acceptance.md)、[首批技能复核快照](skill_matrix.md)、[技能补卡清单](skill_backlog.md)、[ATT&CK 技术覆盖](technique_coverage.md) |
| 旧 agent 与运行输入 | [agent 层契约](agent_contract.md)、[多 agent 编排 PRD](multi_agent_orchestration_prd.md)、[运行输入契约](run_input_contract.md) |
| 旧方案导航页 | [数据库](postgres_runtime_prd.md)、[调度](full_coverage_scheduler_prd.md)、[执行与监督](executor_supervisor_prd.md)、[报告](coverage_report_prd.md)、[开发顺序](agent_workflow_proposal.md) |
| 更早的参考 | [v0.1/v0.2 历史参考](reference/v0.2-detailed/README.md)、[旧研发协作指南](development_collaboration_prd.md)、[已归档能力检索](../../archive/legacy_v3_ability/ability_skill_matcher_prd.md) |

历史文档与产物用于追溯证据。离线测试使用受跟踪输入，并在测试临时目录生成所需产物；保留与清理规则见 [CONTRIBUTING.md](../../CONTRIBUTING.md)。
