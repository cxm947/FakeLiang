# 调度入口（v0.3）

当前规则统一见 [整体方案](overall_prd.md) 和 [V1 数据映射](graph_bundle_fact_index_prd.md)。

直接读取 semantics.requires 求值：组间 AND、组内 OR；按 semantics.original_id 数字排序。
ready 列表现场计算，数据库只保存节点实际进展和结论。
只执行 AND；OR 终点由成功 provider 推导。任何替代分支、孤立动作或未知 case 都不能从覆盖集合删除。
有前驱仍可能完成时保持 pending，来源耗尽或无种子循环才 blocked。全部 AND 结案后才能完成。
