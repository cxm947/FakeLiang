# 执行层验收证据（技能卡 v2 · 检索）

> 范围：**执行层**。前提核验与成果核验按既定口径**后置**，本页不给出它们的结论权。
> 本页只记录**可复现的命令与当前结果**；没有跑过的东西不写在这里。

## 1. 四道门

| 门 | 命令 | 当前结果 |
|---|---|---|
| 卡契约 | `python scripts/check_skill_cards.py` | **32 张全部通过**（22 张仓库真卡 + 10 张检索语料） |
| 写作源同步 | `python scripts/author_contract_v2.py --check`、`python scripts/build_retrieval_suite.py --check` | **同步**（写作源与卡 / 语料逐字段一致） |
| 检索验收 | `python scripts/run_retrieval_acceptance.py` | **8 条用例全过；用例可达率 100%；已知适用候选召回率 100%** |
| 执行体验收 | `python scripts/run_execution_acceptance.py` | **6 条用例全过**（绑定 / 装载卸载 / 工具作用域 / 未知前提 / 未知效果 / AND 聚合） |
| 工具绑定 | `python scripts/check_v2_tool_bindings.py` | **46 个工具契约全部绑定**（逐条校验实现文件存在） |
| 图谱绑定 | `python scripts/check_graph_binding.py` | **8 个方法全部绑定**（每个方法恰好一张 v2 卡） |
| 仓库守线 | `python scripts/ci.py` | **4/4**（pytest / markers / index / coverage） |
| 迁移清单 | `python scripts/build_migration_source_list.py` | **35 张卡全部有去向，0 张未承接** |
| 迁移指标 | `python scripts/migration_metrics.py` | **门槛全过**（来源覆盖 35/35、记录完整 4/4、五个零容忍项为 0、未决状态有归属、检索两项达标） |
| 干跑接线 | `python scripts/run_v2_graph_dryrun.py` | **8 个方法全部绑定并选定变体跑通**（真图谱 → v2 卡 → 运行层协议 → 实例记录；记录标 `dry_run`，指标侧拒收为批次证据） |
| **汇总报告** | `python scripts/build_acceptance_report.py` | **`output/reports/execution_layer_acceptance.json`**（绑定提交号；十门数字 + 真机批次 + 未覆盖项） |
| **可执行就绪表** | `python scripts/check_live_readiness.py` | **3 张今天可跑**（键值存储 readback_probe / 可达性 direct_probe / 服务曝光 banner_probe）；21 张待接线并逐条列出缺哪些工具 |
| **真机方法单跑**（需 `--execute`，默认只出计划） | `python scripts/run_v2_live_method.py --execute` | 写唯一探针对象 → 同源回读 → 释放 → **再读验证**；释放未验证即 `blocked` 并点名遗留对象 |
| **真机观测批次**（别放进离线验收） | `python scripts/run_v2_live_observe.py` | **靶场 7 个端点全部连通并落证据**（记录标 `live`）；只覆盖观测半边 |
python scripts/run_v2_live_method.py            # 计划模式（不连任何东西）；真跑要加 --execute

复现：

```powershell
python scripts/acceptance.py          # 一键：执行层九道门 + 聚焦模块 + 仓库守线
python scripts/build_acceptance_report.py   # 单独出那份绑定提交号的汇总报告
python scripts/check_live_readiness.py      # 今天能跑哪些卡（缺口与基线比对）
```

单跑各道门：

```powershell
python scripts/check_skill_cards.py --report output/reports/skill_cards_v2.json
python scripts/author_contract_v2.py --check
python scripts/build_retrieval_suite.py --check
python scripts/run_retrieval_acceptance.py --report output/reports/retrieval_acceptance.json
python scripts/run_execution_acceptance.py --report output/reports/execution_acceptance.json
python scripts/check_v2_tool_bindings.py --report output/reports/v2_tool_bindings.json
python scripts/check_graph_binding.py --report output/reports/graph_binding.json
python scripts/build_migration_source_list.py --check
python scripts/migration_metrics.py --report output/reports/migration_metrics.json
python scripts/run_v2_graph_dryrun.py
python scripts/ci.py
```

## 2. 靶场的每个方法都有卡

图谱给出的方法（`ttpExists` 节点）与承载卡一一对应；会话交付作为**卡内变体**存在，不再单独成卡。

| 图谱方法 | 承载卡 | 变体 |
|---|---|---|
| 键值存储未授权键写入 | `exploit.redis_unauth_write` | `readback_probe`（证明写入）/ `session_delivery`（交付会话） |
| 容器内对外应用命令执行 | `exploit.laravel_ignition_rce` | `direct_command` / `session_delivery` |
| 主机对外办公应用命令执行 | `exploit.tongda_oa_include_rce` | `command_echo` / `session_delivery` |
| 特权容器到宿主 | `exploit.privileged_container_escape` | `host_mount_write` / `scheduled_route` |
| 本地路径劫持提权 | `exploit.suid_path_hijack` | `path_hijack_route` |
| 域凭据材料提取 | `exploit.kiwi_lsass_dump` | `in_place_dump` / `dump_then_transfer` |
| 远程关闭防御设置 | `exploit.netexec_firewall_off` | `service_manager_route` / `instrumentation_route` |
| 域凭据远程执行（两台目标同一方法） | `exploit.impacket_psexec_cmd` | `service_creation_route` / `instrumentation_route` / `session_delivery` |
| 会话接管 | `session.msf_adopt_native` | `native_route` / `web_route` / `mount_route` / `migrate_route` |

观察类（原 pre/post）十三个方法各有只读卡：可达性、服务曝光、凭据有效性、容器关系、防御状态、
路径权限、会话身份、工具存在、进程服务信息、服务控制端点、通道回声、文件存在、身份。
**只读卡不改变目标状态**：义务固定为 `not_applicable`，不存在自动恢复。

“操作者位置”按既定口径不建卡：它是执行起点，由运行层固定。

## 3. 检索侧：相关但不相同的十张卡

`data/retrieval_suite/cards/` 里十张近亲卡与真卡**共享同一个方法标识**，因此无法靠方法名过滤，
只能靠适用谓词区分：

| 类 | 条目 | 区分字段 |
|---|---|---|
| 同服务不同版本 | 旧版本线 / 下一大版本线 | 版本谓词区间 |
| 同技术不同平台 | Windows 路由 / 宿主边界 / ARM64 | 平台、运行边界、架构谓词 |
| 名称相近语义不同 | 版本探测（只观察）/ 配置导出快照 | `method_ref`、`promise.action`、`delivers` |
| 前提不满足 | 要求调试面开启（现场关闭）/ 要求起点直达（现场不可达）/ 凭据作用域只覆盖别组目标 | 条件谓词求值为假 |

四条纪律在语料里是可检查的：每条都能在某个合理现场成立（改版本/平台/前提即成为合法候选）；
每次只改一个主要区分因素；合法替代实现（例如同一方法的多个路由）用**允许集合**判定；
标签只存在验收 oracle 里 —— `tests/test_retrieval_acceptance.py` 会扫描语料，出现 `decoy` / `gold` /
`expected_reject` / `oracle` 之类字样即判失败。

## 4. 检索验收逐条

| 编号 | 检查 | 状态 |
|---|---|---|
| EX-01 | 已知适用候选可达（两项指标 100%） | 覆盖（8/8 用例） |
| EX-02 | 排序与选择分离（RT-05 首选更靠前但被按承诺与证据排除） | 覆盖 |
| EX-03 | 未知前提不等于成立（RT-04：版本未知 → 不选、记录 `needs_evidence`） | 覆盖 |
| EX-04 | 使用版本锁定（改内容不静默换绑，必须重新决策） | 覆盖 |
| EX-05 | 越权硬过滤（方法不符 / 阶段不符 / 交付不符） | 覆盖 |
| EX-06 | 零结果与后端错误区分 | 覆盖 |
| EX-07 | 截断、分页与预算可见 | 覆盖 |
| EX-08 | 新旧契约隔离（`legacy` / `v2` 显式选择，禁自动回退） | 契约层覆盖（校验器拒 `fallback_to_legacy`） |
| EX-09 | 混淆集质量与标签隔离 | 覆盖 |
| EX-10 | 现场变化后的调整 | 契约层覆盖（变体切换要新的决策与绑定记录） |
| EX-11 | 未知效果与资源责任 | 契约层覆盖（义务与账本字段必填） |
| EX-12 | 输出与记录完整 | 覆盖 |

“契约层覆盖”指该条由卡结构本身保证并会被 `check_skill_cards.py` 拒绝，而不是由运行器跑出来的；
运行器只跑**检索与选择**这一段。

执行体那一段现在跑的是**运行层代码本身**（`src/runtime/v2_exec.py`），不是验收脚本里的测试替身：
`run_execution_acceptance.py` 与 `run_v2_graph_dryrun.py` 都通过同一个协议模块驱动，`tests/test_v2_exec.py`
再对协议逐条打桩。

## 5. 明确没有做的事

- 没有真机执行：本页的结论来自离线校验与离线检索验收，**不含靶场实测**。
- 核验层（前提核验体 / 成果核验体）尚未接入：`evidence.final_verification` 与
  `submission.final_graph_satisfaction` 一律 `deferred`，校验器强制。
- 动作类卡片里 `assembly: fixed` 的旧执行入口仍在，V2 代际尚未接到运行层；
  迁移按 `docs/product/skill_card_contract_v2.md` 的分批口径走。

## 5.1 L1–L4 落定后的实测（2026-10-02）

按跨模型定稿的四项（生命周期三段 / 事实与需求分层 / 可靠性·副作用列 / 卡级门控）落地后，本轮实测：

| 项 | 命令 | 结果 |
|---|---|---|
| 契约扩展 | `python scripts/check_skill_cards.py` | **32/32**；新增强制项：三段阶段、还原规格、需求与门控、副作用、`required_features` |
| 事实与门控 | `python tests/… test_v2_facts.py` | **10 条**：三值、来源资格、过期、冲突不擅自裁决、空 all 是契约错误、门控与图许可分开 |
| 运行层阶段 | `python tests/… test_v2_exec.py` | **17 条**：装载前拒未知特性、阶段可进入性、基线锁定、还原比较三值、三列不塌缩 |
| 执行体用例 | `python scripts/run_execution_acceptance.py` | **11 条 PASS**（新增 L1 生命周期四条：还原不匹配 / 缺基线 / 第三方改动 / 豁免须留理由） |
| **真机 L1 全链路** | `python scripts/run_v2_live_method.py --execute --batch v2-method-batch5` | **claim=claimed_complete、还原比较=match、restoration_claim=restored、lifecycle=closure_claimed_pending_review**；基线在首次修改前取得，释放由二次读取比较证明；跑后 `KEYS agv-v2-*` → `*0` |

真机批次同时暴露并修掉一个契约级缺陷：`uncertain_write_effect` 这类**条件性义务**被当成恒定义务，会无端卡住收尾 —— 现在义务与还原项都必须显式登记「不适用 + 理由」，理由进记录。

## 6. 与全方案验收矩阵（V01–V26）的对应

三档：**契约层** = 由卡结构与校验器强制（跑一次 `check_skill_cards.py` 就能证伪）；
**运行器** = 由 `run_retrieval_acceptance.py` 的用例实际跑出；**运行层待接** = 需要 V2 执行体
真正跑现场才能证明，本夜不做，也不冒充。

| 项 | 检查 | 档位 | 证据 |
|---|---|---|---|
| V02 | 卡片粒度 | 契约层 | 一个方法一张逻辑卡：`duplicate_method_problems` 拒重复，写作源按方法规格生成 |
| V03 | 声明与引用 | 契约层 | 必填 27 项 + 引用形状（方法 / 工具 `name@x.y.z` / 验收用例） |
| V04 | 模型构造权 | 契约层（行为待运行层） | `construction_space.allowed` 与 `invariants` 必填且非空 |
| V05 | 检索来源与查询权 | 运行器 | EX-01 / EX-07（可达率、截断与游标可见） |
| V06 | 硬过滤与未知 | 运行器 | EX-03 / EX-05（未知不得当成立、越权被拒） |
| V07 | 排序与选择 | 运行器 | EX-02 / RT-05（首选更靠前仍按承诺与证据排除） |
| V08 | 阅读、激活与版本锁 | 运行器 + 契约层 | EX-04（改内容必须重新决策，不静默换绑） |
| V12 | 记录权威 | 契约层 + 运行器 | `recall/decision/binding` 三段记录 + `records_required` |
| V13 | 串行与并行例外 | 契约层 + 运行层 | `construction_space.sequencing` 固定逐动作构造；运行层引擎同步驱动，无并行通路（EX-V09 逐步调用可见） |
| V14 | 写入证据 | 契约层 | `evidence.complete_claim_requires` 要求同源回读并可归因本次写入 |
| V15 | 会话与材料关联 | 契约层 | 会话类义务（保留依赖、责任转移需接受记录）+ 变体 `delivers` |
| V16 | 运行状态与失败语义 | 契约层 | `tool_effect_states`、`decisions`、禁自动重试/自动换实现 |
| V17 | 幂等边界 | 契约层 + **真机探针** | `idempotency` 声明受校验；`run_v2_live_method.py --check-idempotency` 在真实提供方上验：同键同值重复不产生二次效果、同键不同值不会被静默去重、探针键删除并复核（v2-method-batch2 已跑，零残留） |
| V18 | 资源与责任 | 契约层 | `lifecycle.obligations` 四项齐全 + `transfer_requires` |
| V20 | 多命题检查 | 契约层 | 观察卡按分项结论输出，未知与假分别保留 |
| V21 | 停止检索 | 运行器 | EX-06 / EX-07：空集、后端故障、预算耗尽三者区分，中断不得包装成"能力齐备" |
| V22 | 旧引用兼容 | 契约层 | `compatibility.legacy_refs` + `fallback_to_legacy: false` |
| V23 | 内容与发布状态 | 契约层 | `content_id` / `catalog_entry_ref` / `card_version` 三者分离 |
| V25 | 回退与对照 | 契约层 | `restoration` 禁自动恢复；回退不等于恢复外部状态 |
| V26 | 版本兼容与测试方式 | 契约层 + 仓库守线 | `schema_version` + 四个脚本的 `--check` + `ci 4/4` |
| V01 | 图绑定、事实与聚合 | 运行器 | `check_graph_binding.py`（编译图 8 个方法各绑到恰好一张卡）+ EX-V01-method（换方法卡装载前被拒）+ EX-V01-aggregate（AND 要带证据的独立结论，未知子项同样不算）+ EX-V01-negative-fact（有证据的否定观察算完成的事实，不是失败） |
| V09 | 加载卸载效果 | 运行器 | EX-V09-load-unload：装载 `calls_so_far=0`；卸载后记录、产物、会话仍在，且不再可调用 |
| V11 | 阶段实际能力 | 运行器 | EX-V11-scope：未声明的工具被拒；未知前提只许观察 |
| V19 | 交接与返工 | 运行器 | EX-V19-unknown-effect：未知效果不重试、显式交接、完整主张被卡住 |
| V24 | 批次覆盖与指标 | **观测半边两窗口 + 首个方法已真机** | B0 清单 35 行 0 未承接 + 阈值机制有测试 + **真机只读观测两窗口 obs-w1/obs-w2（各 10 条 live：可达性 7 + 服务曝光 3，含真实横幅）** + 真机方法单跑 v2-method-batch1（键值存储：同源回读、释放后二次读取验证已消失、claim=claimed_complete、KEYS 复核零遗留）；--require-windows 2 门槛已通过。**未达**：迁移计划里「每窗口 ≥ max(30, 5×变体数) 个实例」是发布批次门槛，实验室规模不满足；其余方法卡批次待开跑 |
| V10 | 三体独立 | **不适用（附理由）** | 核验层按既定口径后置，本阶段只有执行体上下文；该项在执行层无法定义，等核验层接入时再验 |
