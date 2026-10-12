# v0.3 简洁开发方案

> 当前设计基线，运行层尚未实现。Agent 分工沿用已确认方案；本次精简的是存储、状态和交接。
> 唯一字段定义在 [最小数据契约](runtime_data_contract.md)，先理解流程可读 [大白话说明](workflow_plain_language.md)。

实际首版靶场为 [红日 7](hongri7_modeling.md)。S1/S2/S3 保留为逻辑测试样例，真实接入阶段使用红日 7 的事实、地址映射和已说明的规则边界。

## 1. 研究目标

攻击图保存步骤及逻辑关系，程序按图推进，Agent 选择当前节点的具体方法。
相同图、配置和检查结果应得到相同逻辑判断；真实模型与环境仍可能产生不同观察，实验要记录这种差异。
MSF 会话统一是工程便利，比较实验两组时保持一致。

## 2. TXT 转换结果直接作为输入

现有链路是 TXT → projector → schema_version=1.1.0 的 action_graph.json。
原图节点、参数与直接依赖行都在文档里；前提 / 效果 / case 等派生面由载入层导出；不再另建图数据模型或持久事实索引。
完整 JSON 原样存 runs.graph_json，运行状态另存，不能往 V1 Schema 中追加字段。
实际字段映射与 S1 核对见 [V1 数据映射](graph_bundle_fact_index_prd.md)。

## 3. 分工与流程

| 组件 | 唯一主要职责 |
| --- | --- |
| 主控程序 | 求值依赖、固定排序、推进阶段、保存和结束 |
| Execution Agent | 当前节点的前检查、工具检索、动作、后检查和有限修正 |
| Session Agent | 原节点成功后的 MSF 会话准备 |
| Supervisor Agent | 规则无法解决时分析异常、提出当前任务内建议 |
| Checker，程序 | 按已登记判据核对原始证据 |
| Reporter，程序 | 从图、节点结果和记录生成报告 |

Matcher 是检索函数。正常成功没有必经 Reviewer；模型不改图、不改依赖，不靠一句“成功”写事实。

~~~mermaid
flowchart TD
    A[保存 V1 图并创建 run] --> B[按图选择可推进 AND]
    B --> C[Execution：前检查、动作、后检查]
    C --> D[程序核对并保存节点结论]
    D --> E{成功且有新执行入口}
    E -->|是| F[Session：复用或准备 MSF 会话]
    E -->|否| G[重新求值]
    F --> G
    G -->|还有工作| B
    G -->|全图结案| H[生成报告]
~~~

## 4. 存储只有三部分

| 表 | 一句话 |
| --- | --- |
| runs | 这次实验的图、配置、当前工作和会话目录 |
| node_runs | 每个 AND 节点的当前结果 |
| records | 模型输入输出、工具回执、检查结论和结果依据 |

原图只在 run 中保存一次，不逐表复制 case、主机、前提和效果。
LEAF 结论从已接受检查记录读取；OR 从成功 provider 推导；终点只展示，不再执行或建立状态行。
中间态只有 current={node_id,phase,record_id}。不再保存事实状态机、计划版本链、归一化队列和多套工作 ID。

## 5. 必须保留的逻辑

- 只执行 AND；按 semantics.original_id 数字升序选择当前可推进节点。
- requires 组间 AND、组内 any_of 为 OR，不能只看扁平 edges。
- requires 为空仍核对当前 direct LEAF；any_of 为空不成立。
- 只检查当前 premise_refs 的 LEAF，不递归重做祖先。
- 一个 provider 成功允许下游推进，其他分支仍保留全图覆盖。
- 全部必需效果通过才提交成功；部分检查记录不激活 OR。
- 没有成功 provider 表示未证明，不自动等于该事实为假。
- 前提稳定、效果持续是首版单次实验的范围。实质环境冲突暂停处理，不建设动态真值撤销系统。

## 6. MSF 与中断

所有新执行入口都在原节点成功后处理；已有合格 MSF 会话复用，没有新入口跳过。
原节点成功与 current.phase=session 同事务保存。之后会话准备失败，原成功仍保留。
当前只有一个会话准备工作，不需要独立 normalization_id、队列或状态机。

调用前保存记录，返回后补输出。外部操作是否发生未知时 paused 并先对账；不靠重跑猜测。
原节点已成功就不重做；中断在 session 阶段就只继续会话准备。实际连接仍由 MSF 保存。
本版不支持分布式接管和任意工具无损续作；无法核对时明确暂停。

## 7. 状态与完成

节点只保存 pending/running/succeeded/failed/blocked/uncertain。
ready 随用随算，无能力归 blocked 原因；不再另存 claim_verdict、disposition。
执行中的补证仍为 running，已确认无在途且停止补证才结案 uncertain。
run 只区分 running/paused/finished。全部 AND 结案且无当前工作才能 finished，完成不等于全部成功。
报告同时列图验证结果和会话准备结果，不再增加整体八态归约。

## 8. 实现顺序

Python + LangGraph + PostgreSQL 三表 + 本地记录文件 + MSF；单 run 串行。

1. 复用 V1，写内存索引和确定性调度，核对 S1/S2/S3。
2. 三表与 mock 工具跑通前检查、动作、后检查和保存。
3. 加入真实 Execution Agent 与按需 Supervisor，仍先使用 mock。
4. 加入 Session Agent 和 MSF，再接定案后的红日 7 实际能力。
5. 从记录生成报告，做逻辑复现和基线对照。

本轮只清理设计文档，没有改 TXT converter、V1 Schema、输出 JSON 或实现数据库。
