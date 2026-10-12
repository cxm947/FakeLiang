# 技能目录适配：对齐 Agent Skills 形态

> 依据：跨模型评审 2026-10-02（run318）+ Agent Skills 规范（agentskills.io/specification）。
> 目标：技能卡既能被通用 Agent 客户端**发现与阅读**，又能被本项目运行层**强制实施**；
> 这是两种兼容（内容兼容 / 执行兼容），分别验收，互不替代。

## 1. 三个身份，一张发布映射

| 身份 | 例子 | 用途 |
|---|---|---|
| 业务 ID | `exploit.redis_unauth_write` | 方法绑定、注册表、测试、历史引用 |
| 标准名 | `exploit-redis-unauth-write` | 前言 `name`、目录名、标准客户端发现 |
| 发布包 | `<card_id>@<card_version>` | 锁定正文、契约、脚本与资源的**确切版本** |

业务 ID 不改、也不叫废弃别名；新增的是标准名与目录定位。映射由 `python scripts/build_release_map.py` 生成到
`catalog/skill-release-map.json`，并做两条硬检查：标准名必须合规（`^[a-z0-9]+(?:-[a-z0-9]+)*$`，≤64）；
**不同业务 ID 压成同一个标准名即失败**（例如 `a.b_c` 与 `a.b-c`）—— 禁止运行时简单地替换点号与下划线。

## 2. 谁写什么：知识进 Markdown，机器约束留在 JSON

| 内容 | 唯一可编辑真源 | 其他位置的用法 |
|---|---|---|
| 业务 ID、方法引用 | `skill.json` | 注册表与前言元数据生成投影 |
| `name` / `description` | `SKILL.md` 前言 | 目录（迁移后）与索引从此生成 |
| 用途 / 原理 / 失败解释 / 证据说明 | `SKILL.md` 正文与 `references/` | JSON 只保留机器面摘要（`knowledge` 四段，供检索与校验用），不反向生成正文 |
| 输入三分、事实槽位、需求表达式 | `skill.json` | 正文只解释用途，不抄条件 |
| 变体、工具面、构造空间 | `skill.json` | 加载器给模型结构化视图 |
| 三段生命周期、门控、还原规格 | `skill.json` | 正文说明各阶段如何决策 |
| 证据要求、失败枚举、交回协议 | `skill.json` | 正文解释含义 |
| 运行能力要求 | `skill.json` | 前言生成摘要投影 |

正文与契约冲突时**不允许用「JSON 优先」悄悄糊过去**：发布期阻止冲突包发布，运行期发现冲突就停下受影响动作并记录。

正文自 2026-10-02 起是**手写真源**：从契约投影正文的那个生成器（原 `build_skill_md.py`）已从
`scripts/` 删除，两面改由 `scripts/check_skill_face.py` 核对——身份、骨架、`model` 卡的命令模板、检索关键词，以及
**正文里不得残留生成器留下的投影标记**（那条标记就是「这一页还是生成的」的迁移旗标）。
目录改名（B2 剩余项）**已完成**：22 张 v2 卡的目录改成标准名，前言的 `x-exec-naming-state` 由
`bridged` 变 `standard`；读卡的地方不再从目录名推业务 ID，一律走 `src/skills/layout.py`
（目录名 ↔ 业务 ID ↔ 卡目录的唯一翻译层），注册表的 `path` 两种拼法都接受（schema 同款）。
旧路径长期保留解析：发布映射的 `legacy_paths` 仍在，历史 run 的引用不被改名打断。

工具怎么用单独成层：`skills/_tooling/*.md` 是工具类 playbook 页（命令形状 / 输出读法 / 坑点），
方法卡只引用、不重复；该目录不进注册表、不进索引、不授予权限（目录守线里显式豁免，见
`tests/test_skill_catalog.py`）。

## 3. `allowed-tools`：扁平声明，分域留给运行层

标准字段是空格分隔的预授权工具名，没有阶段/变体/目标作用域的表达能力，所以：

- 前言只声明宿主网关：`skill_resource_read skill_runtime_dispatch`；
- 不把分域信息塞进假工具名，也不把所有底层工具展平；
- 实际权限恒为：宿主能力 ∩ 执行实例许可 ∩ 卡契约 ∩ 已选变体 ∩ 当前阶段 ∩ 本次调用门控；
- 模型自编内容的通用原语，其产物属**本次运行**，执行必须过同一网关并按代码摘要关联；只查脚本文本或模型自报效果，不足以证明分域成立。

## 4. 检索协议：先披露摘要，再按需加载

| 步 | 程序 | 模型 |
|---|---|---|
| ① 建索引 | 解析前言与完整契约，生成同一快照的目录/方法/变体索引 | — |
| ② 绑定步骤 | 绑定图给定方法、目标、阶段、访问上下文 | 拿到固定上下文 |
| ③ 初筛 | 过滤方法不符、版本不允许、运行能力缺失等硬项 | 拿到合法候选的 `name + description` 与句柄 |
| ④ 检索 | 返回排名/分页/过滤诊断，**不按第一名自动选择** | 改写查询、继续检索、请求检查候选 |
| ⑤ 加载 | 加载完整 `SKILL.md`、校验契约、提供契约视图与资源目录 | 阅读正文、比较变体、决定补观察 |
| ⑥ 重算 | 用事实、需求表达式与当前阶段门控重新求值 | 解释现场、选变体或继续观察 |
| ⑦ 绑定执行 | 锁定发布包、工具实现、变体与阶段 | 构造实际动作并逐次提交 |
| ⑧ 阶段切换 | 重查门控与绑定，保存旧资源义务 | 决定下一动作；不改图给定方法 |

五条限制：正文一次加载完整（超长材料放 `references/`，不能运行时截断）；契约不能对模型隐藏（投影须带来源版本与加载记录）；
未知条件保留为待观察；加载不执行（读正文、列脚本、读参考都不进 prepare）；停止检索要记录（零结果/截断/预算耗尽分别记）。

## 5. 目录布局：随包资源与本次产物分开

- `skills/<name>/`：`SKILL.md`、`skill.json`、`scripts/`、`references/`、`assets/`；
- `catalog/`：`skill-release-map.json` 与按发布快照生成的索引；
- `legacy/`：旧契约、旧手册、旧入口的不可变快照（不在扫描根内）；
- `output/runs/<run-id>/`：模型本次构造的脚本与请求、记录与证据。

固定流程入口不能只搬进 `scripts/` 就算完成迁移：原样跑整套固定流程仍标 legacy；执行一个已声明工具操作才可作新适配器；
解析返回可作确定性解析器；隐藏地自动重试/换实现/清理必须拆成明确的模型决定与调用。

## 6. 自描述：前言是入口，JSON 是完整要求

前言示例（`metadata` 内只允许字符串）：

```yaml
name: exploit-redis-unauth-write
description: 执行任务图已指定的键值存储写入与回读方法。适用：现场观察、实现变体选择、动作构造与生命周期处理。
compatibility: 需要支持本卡机器契约的运行层与受控工具网关；完整能力要求见 skill.json
metadata:
  x-exec-skill-id: exploit.redis_unauth_write
  x-exec-contract-path: skill.json
  x-exec-runtime-profile: method-card-runtime-v1
  x-exec-required-features: lifecycle_phases fact_requirements reliability_assessments side_effect_contracts card_gates
allowed-tools: skill_resource_read skill_runtime_dispatch
```

缺少执行能力时返回 `unsupported_runtime_features`，**不回退**到裸命令行或旧固定入口。

## 7. 迁移批次（22 个目录）

| 批次 | 数量 | 放行标准 |
|---|---:|---|
| B0 基线 | — | 22 项映射无冲突；每种旧引用有处理方式；旧内容可定位 |
| B1 试点 | 2 | 一个检查类 + 一个动作类：命名、知识迁移、加载、工具绑定、legacy 隔离、回退全通 |
| B2 简单项 | 6 | 新旧引用/路径/检索/基本运行用例通过；正文改为手写真源 |
| B3 复杂项 | 6 | 多变体、分阶段工具、通用原语、还原较复杂者：变体调整、未知效果、还原、越界调用测试通过 |
| B4 剩余项 | 8 | 全量 22 项回归、旧引用兼容、原子发布与回退演练 |

每批共同验收：格式合规 / 身份兼容（旧 ID、新标准名、历史包引用都要解析正确）/ 路径兼容 / 单一真源（重新生成投影与索引无漂移）/
知识迁移（不得残留旧指令）/ 渐进加载（初始无全量正文）/ 方法与变体（排名不决定选择、未知未放行）/
分域执行（越界动作**实际未发生**，而非仅告警）/ 加载无副作用 / 包锁定 / 生命周期 / 不支持的宿主明确拒绝 / 回退只切发布指针 /
模型执行语义（选择、构造、调整由模型，程序无隐藏重试换实现）。

旧引用规则：旧业务 ID 长期保留解析；带版本引用锁定原内容；无版本引用按明确策略解析并记录；旧路径逐项适配；旧运行不随目录迁移换包。

## 8. 当前工具

```powershell
python scripts/build_release_map.py      # 生成并审计身份映射（碰撞即失败）
python scripts/check_skill_format.py     # 格式合规（前言/名称/元数据/allowed-tools/正文）
python scripts/check_skill_face.py       # 卡面与契约不漂移（身份 / 骨架 / 手写真源 / 检索关键词）
python scripts/check_skill_cards.py      # 机器契约（执行兼容那一半）
```

## 9. 当前落地状态（必须如实读）

| 项 | 状态 | 证据 |
|---|---|---|
| B0 身份映射 | **已完成** | `catalog/skill-release-map.json`：22 项、0 冲突；`build_release_map.py --check` 已进验收总闸 |
| B1+B2 正文手写真源 | **已完成**（22/22） | 22 张 `SKILL.md` 由人手写；`check_skill_face.py` 报 `22 cards, 22 hand-written, PASS`（投影残留 0）；生成器 `build_skill_md.py` 已删除 |
| 工具类 playbook 分层 | **已落地** | `skills/_tooling/` 九页（nmap / impacket / metasploit / netexec / windows-remote-admin / posix-shell / redis-cli / docker-cli / http-client）；方法卡在 `## 怎么做` 里引用 |
| B2 剩余（目录改名） | **已完成**（2026-10-02） | 22 个目录改成标准名；`catalog/skill-release-map.json` 的 `naming_state` 22/22 = `standard`；读卡处全走 `src/skills/layout.py`；全量 pytest 1798 passed + acceptance 16 门 + ci 4/4；真机回归：node 12 三闸 pass、`pre.service_version` 由 deepseek-flash 写命令在 Kali 执行 pass |
| B3/B4 剩余卡 | 未开始 | 另 13 张（`program_only` 与未承接项）不在 v2 契约内，沿用旧面 |

### 这轮实际怎么落的（与上一版预计的差别）

上一版预计「先改四处测试契约、再铺开」。实际落法是：**保留本仓库被断言的契约面，正文整体重写**——

1. 章节骨架按各家族的既有模板原样保留（r99 三段 + 可选尾段 / 试点四段 / 八段），测试一条没动；
2. `## 怎么做` 里的**命令模板块原样保留**（`assembly.command_templates` 读的就是它们，`model` 卡的
   规则回退取第一块第一行）；只把旧「模型不出场 / 模型只填已声明输入」的口径清零；
3. H1 的技战术编号照旧（`tests/test_attack_index.py` 那条守线没动）；
4. 真正改动的测试契约只有两处：`tests/test_skill_catalog.py`（`skills/_tooling/` 目录豁免要写明理由）
   与 `tests/test_skill_format.py`（把「生成器渲染合规」换成「卡面与契约不漂移」的正反例）；
5. 验收门 `skill-face` 由 `build_skill_md.py --check` 换成 `check_skill_face.py`：**不写文件**，
   只判身份、骨架、真源旗标（无投影残留）与描述里的检索关键词。

评审这一层要如实说：**正文好不好读，程序判不了**。机器能判的是两面说的是不是同一个名字、同一个形状，
以及有没有生成器残留；业务质量仍由人来看。
