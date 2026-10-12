# 多 Codex 会话编排 PRD

> 读者：总控会话、各功能 PRD 会话、后续实现会话。  
> 目的：明确多会话怎样协作，而不是把所有上下文塞进一个会话。  
> 输出：会话职责、共享输入、交接包、冲突处理规则。

---

## 1. 一句话说明

多 Codex 会话不是运行时架构，而是研发组织方式：

```text
一个总控会话维护上位契约；每个功能会话只写和维护一个功能 PRD。
```

运行时首版仍然是单进程/单 writer/串行执行。

---

## 2. 共享契约引用

所有会话必须引用：

```text
runtime_contract_version=0.1
runtime_status=pending/ready/running/succeeded/failed/blocked/unsupported/uncertain
claim_verdict=proven/refuted/inconclusive/unassessed
truth_value=true/false/unknown
schema=agv_runtime
tables=graphs/runs/run_steps/run_facts/evidence/events
```

如果子 PRD 与总 PRD 冲突，以 `overall_prd.md` 的共享契约为准。

---

## 3. 会话拆分

| 会话 | 文件 | 只负责 |
|---|---|---|
| 总控会话 | `overall_prd.md` | 产品目标、边界、共享契约、研发顺序 |
| 图索引会话 | `graph_bundle_fact_index_prd.md` | GraphBundle 和 fact index |
| 数据库会话 | `postgres_runtime_prd.md` | 六表、接口、事务、恢复 |
| 调度会话 | `full_coverage_scheduler_prd.md` | ready queue、AND/OR、backlog |
| 能力会话 | `skill_contract.md`（原 `archive/legacy_v3_ability/ability_skill_matcher_prd.md`） | 技能注册表、选择器、候选与缺口 |
| 执行监督会话 | `executor_supervisor_prd.md` | 三段执行、判定、回流 |
| 报告会话 | `coverage_report_prd.md` | 报告结构、指标、证据展示 |

---

## 4. 每个会话拿什么上下文

每个功能会话只需要最小上下文包：

```json
{
  "runtime_contract_version": "0.1",
  "graph_samples": ["S1_ip", "S2_ip", "S3_ip"],
  "current_doc": "docs/product/<feature>.md",
  "shared_tables": ["graphs", "runs", "run_steps", "run_facts", "evidence", "events"],
  "known_examples": {
    "S1_node_21": "requires 7 AND 24; direct LEAF 22/28/29",
    "S3_node_92": "requires 78 AND (96 OR 101)"
  }
}
```

避免传入：

- 完整 raw graph。
- 大段工具日志。
- 凭据明文。
- 与当前功能无关的 PRD 全文。

---

## 5. 交接包格式

每个会话完成后，向总控回报：

```text
1. 修改文件
2. 本 PRD 的核心决策
3. 与共享契约的对齐点
4. 影响其他 PRD 的假设
5. 待确认问题
6. 自检结果
```

示例：

```text
文件：docs/product/full_coverage_scheduler_prd.md
决策：OR 任一 provider 成功解锁下游，其他 provider 进 coverage backlog。
对齐：只读 run_facts.truth_value 和 run_steps.runtime_status。
待确认：并发是否推迟到 v2。
```

---

## 6. 冲突处理

常见冲突和处理方式：

| 冲突 | 统一处理 |
|---|---|
| 状态字段名不同 | 统一为 `runtime_status` |
| 把工具成功当节点成功 | 改为 post_check 证明 effect 后才成功 |
| partial effect 解锁下游 | 改为 evidence-only |
| 子 PRD 新增运行表 | v0.1 先回到六表 |
| attempt 粒度不同 | attempt 是节点级；工具调用是 atomic_call |
| Scheduler 想判断证据 | 交给 Supervisor |

---

## 7. 修正回流

总控发现冲突后，向对应会话发补丁任务：

```text
请只更新你的 PRD，在前部加入共享契约引用，并删除与 v0.1 冲突的表述。
```

会话完成后，总控执行一致性检查：

```text
每份文档是否包含 runtime_status / claim_verdict / truth_value
是否包含 agv_runtime 六表
是否保留 all-or-nothing provider
direct LEAF 是否定义一致
```

---

## 8. 运行时 Agent 与研发会话的区别

研发会话：

```text
写 PRD、讨论接口、修正文档
```

运行时 Agent：

```text
Orchestrator / Scheduler / Matcher / Executor / Supervisor / Reporter
```

不要把研发会话直接设计成运行时微服务。v0.1 的运行时先保持简单：单进程、单 writer、模块化函数边界。

---

## 9. 产品验收

| 编号 | 场景 | 期望 |
|---|---|---|
| MA-01 | 每个功能有独立 PRD | 文件存在且职责清晰 |
| MA-02 | 共享契约 | 每份 PRD 都包含相同枚举和六表 |
| MA-03 | 冲突回流 | 总控能定位并发补丁任务 |
| MA-04 | 上下文包 | 子会话不需要完整 raw graph |
| MA-05 | 运行时边界 | PRD 不把多会话误写成多服务 |

---

## 10. 下一步使用方式

每进入一个实现阶段，就开一个新的实现会话或继续对应功能会话：

```text
输入：overall_prd.md + 当前功能 PRD + 必要样例
输出：代码 / 测试 / 文档更新
```

总控只维护顺序和一致性，不在一个会话里塞满所有实现细节。
