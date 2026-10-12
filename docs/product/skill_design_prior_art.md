# 技能层设计 · 同行对照（高 star 项目怎么解我们这两个问题）

> 目的：我们的技能卡方案里有两处一直靠"自己想"——**索引怎么组织**、**卡的前提条件怎么处理**。
> 这份文档只记录**读过的一手材料**（附链接与摘录），再给出可选项与取舍，供拍板。
> 读法：§1 各项目机制 → §2 对我们两个问题的选项 → §3 建议。

## 1. 同行mechanism（一手材料）

### 1.1 Metasploit：`check` 是一个**动词**，不是一句声明

模块可以实现 `check`，由它回答目标到底能不能打，并**带原因**：

```ruby
def check
  connect
  # they are only vulnerable if we can run the CONFIG command, so try that
  return CheckCode::Safe('Redis CONFIG command is not accessible; target is not exploitable') \
    unless (config_data = redis_command('CONFIG', 'GET', '*')) && config_data =~ /dbfilename/
  ...
```

来源：metasploit-framework `modules/exploits/linux/redis/redis_replication_cmd_exec.rb`（GitHub raw）。
要点：**"能不能打"先问一次只读探针**；探针给出 安全 / 可打 / 未知 三态 + 原因字符串。

### 1.2 Atomic Red Team：前提是**可执行的检查**，还附"怎么满足它"

每个原子测试可以声明：

```yaml
elevation_required: true
dependencies:
  - description: Invoke-Mimikatz.ps1 must be on disk
    prereq_command: |          # 检查是否满足（exit 0 = 满足）
      if (Test-Path "#{mimpath}") { exit 0 } else { exit 1 }
    get_prereq_command: |      # 不满足时怎么把它弄满足
      New-Item -Type Directory ...
```

来源：atomic-red-team `atomics/T1059.001/T1059.001.yaml`（GitHub raw）。
要点：前提**不是"一句人读的声明"**，而是 `prereq_command`（可跑、可判定）+ `get_prereq_command`（可选、怎么补齐）。

### 1.3 Nmap NSE：运行规则在**运行前**判定

脚本用 `prerule() / hostrule(host) / portrule(host, port) / postrule()` 决定自己什么时候跑。

来源：<https://nmap.org/book/nse-script-format.html>。
要点：**"该不该跑"由统一规则在入口处判定**，而不是靠使用者记。

### 1.4 Ansible：每个任务都有**预演模式**

`--check` / `check_mode: true|false`：不产生副作用地跑一遍，告诉你"会发生什么"。

来源：<https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_checkmode.html>。
要点：动作型能力**必须能预演**；预演与实施共用同一份声明。

### 1.5 OpenHands（技能/微代理）：按上下文**触发加载**，且**技能不授予权限**

> "Both the legacy `.openhands/skills/` and `.openhands/microagents/` directories remain supported,
> but use `.agents/skills/` for new skills. This location follows the Agent Skills standard…"
> "Skills guide the agent's behavior; **they do not grant permissions or install dependencies by
> themselves**. The agent can only use the files, tools, secrets, and network access available in its
> environment."

来源：<https://docs.all-hands.dev/usage/prompting/microagents-overview>。
要点：技能有两种触发（**关键词触发 / 路径触发**）；技能是"行为指引"，**权限属于运行环境**，不由技能授予。

### 1.6 MCP（工具契约标准）：目录可分页；**注解不可信**

`tools/list`（支持分页）返回每个工具的 `inputSchema`、可选 `outputSchema` 与 `annotations`；
规范明确：

> "For trust & safety and security, clients **MUST** consider tool annotations to be untrusted unless
> they come from trusted…"

来源：<https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/docs/specification/2025-06-18/server/tools.mdx>。
要点：**工具自带的行为注解只是提示**，客户端必须自己校验；目录变更可通过通知告知。

## 2. 对照我们的两个问题

### 问题 A：索引（技能目录怎么组织、怎么筛）

| 选项 | 抄谁 | 具体做法 | 代价 |
|---|---|---|---|
| A1 运行前需求进索引 | Metasploit（rank/platform/arch/session 需求） | 卡在 `applicability` 之外再声明**运行前需求**（需要哪种会话/身份/位置），索引按它硬筛 | 小：已有谓词，补一列 |
| A2 目录变更通知 | MCP（`listChanged`） | 卡发布/退役时让运行器知道，避免"绑定到已退役版本" | 小：扩发布目录 |
| A3 触发式技能 + 权限不随技能 | OpenHands | 卡里声明**检索触发条件**（关键词/路径/服务），并写明**卡不授予权限**（权限在执行环境） | 中：需要区分"检索触发"与"运行适用" |

### 问题 B：卡的前提条件（尤其**无法从外部核验**时）

| 选项 | 抄谁 | 具体做法 | 代价 |
|---|---|---|---|
| B1 每张方法卡必须有 `check` 变体 | Metasploit | 卡内固定一个**只读探针变体**，输出 安全/可打/未知 + 原因；真跑前先跑它 | 中：22 张卡各补一个变体（模型装配卡大多是只读，正好） |
| B2 前提写成可执行检查 + 满足方式 | Atomic | 卡声明 `prereq`（可跑、exit 0 判定）与可选"怎么满足"；**不允许只写一句人读的声明** | 中：改契约字段并回填 |
| B3 统一执行前守卫 | NSE | 把"该不该跑"收到运行器一处判定（所有卡共用），不散在卡里 | 小：我们已有谓词，只是要"一处判定" |
| B4 每个变体都要能预演 | Ansible | 变体必须声明**无副作用的预演**怎么做；未知前提时先预演 | 中：写卡时要多想一步 |
| B5 卡声明一律不可信 | MCP | 明文规则：**卡里的声明与注解只是提示，运行器必须自己验** | 小：我们已三值，补成明文纪律 |

## 3. 建议（按性价比排序）

1. **B2 + B5**：把"前提"从一句声明升级成 `prereq`（可执行检查，三值返回）；同时写死"卡声明不可信"。
   这条直接解决当前卡住的那件事：`session.ssh_via_redis` 的 `assumes_absent_file` **不该只是声明**，
   而应该是"**先跑一次检查：目标文件是否存在**"。
2. **B1**：给每张方法卡补 `check` 变体（只读、可独立运行、必须能在真实环境跑）——检索到的第一件事
   永远是"先 check"。
3. **A3 + B5 的组合纪律**：卡不授予权限；权限由运行环境给出（我们的 `tool_surface` 已经是"声明"，
   真正的可调用范围由运行层句柄决定，正好与 MCP/OpenHands 的口径一致）。
4. **B4**：预演模式；已有 `dry-run`/`method-plan`，缺的是"每个变体都要声明预演怎么做"。
5. **A1 / A2**：索引补"运行前需求"这一列与目录变更通知（工作量小，放到后面做）。

### 3.1 对当前卡点的直接影响

现状：`session.ssh_via_redis` 会 `SAVE` 覆盖 `/root/.ssh/authorized_keys`，而"该文件不存在"这个前提
**只能声明、无法核验**。按同行做法，有两条正路：

- **B2 路线**：给该变体补 `prereq`——"检查目标文件是否存在"（例如：先只在**专用新文件**上验证写入动作，
  或经既有只读通道确认目标路径状态）；检查不通过就不走这条变体。
- **换落点路线**（Metasploit 的 targets / Atomic 的 get_prereq 精神）：卡里再声明一个**落下点是新文件**
  的会话变体（不覆盖任何既有文件），让它成为默认路线，覆盖式路线降级为"确知无文件时才用"。

## 4. 自动渗透类项目对照（进攻方向的高 star 项目）

上一节是通用自动化/协议标准；这一节只看**自动渗透/对手仿真**这一类，回答两个问题：
**我们的技能卡逻辑跟他们像不像**、**能从他们身上学什么**。

### 4.1 一手材料

**Stratus Red Team**（DataDog，云攻击技术库）

每个技术是 warmup → detonate → revert/cleanup 三段，CLI 里就是独立动词：

> "Warm-up: Create the prerequisite EC2 instance and VPC (takes a few minutes)
> Detonation: Stop the instance; Use ModifyInstanceAttribute to inject a malicious script in user data…
> Cleanup/Revert …"

来源：<https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.ec2-user-data/>；命令参考含
`warmup / detonate / revert / cleanup`。

**MITRE Caldera**（对手仿真平台）：其术语中的 ability 声明 **requirements**，由 **facts / fact sources / parsers /
relationships** 满足；planner 依据 facts 选能力。

来源：<https://caldera.readthedocs.io/en/latest/Basic-Usage.html>（导航里的 Facts / Fact sources /
Parsers / Relationships / Requirements / Planners 一组页面）。

**Metasploit**：模块元数据里就有可靠性/副作用/披露日期等**索引列**（`'Reliability' => UNKNOWN_RELIABILITY,
'SideEffects' => UNKNOWN_SIDE_EFFECTS, 'DisclosureDate' => '2017-03-14'`），外加 `Rank`、`Targets`，
以及可选的 `check`（见 §1.1）。

来源：`modules/exploits/windows/smb/ms17_010_eternalblue.rb`（raw/镜像均可取）。

### 4.2 我们 vs 他们：骨架确实一样

| 维度 | 他们 | 我们 |
|---|---|---|
| 元数据与实现分离 | MSF 模块元数据 + Ruby 实现 / Nuclei `info` + 协议块 / Caldera 的 ability（术语）元数据 + executors+parsers | `contract_v2` 声明 + `entry.py` 或"模型装配" |
| 适用条件 | Caldera `requirements`（对 facts）/ Atomic `prereq_command` / MSF `check` / NSE 运行规则 | `applicability` 谓词（三值）+ `call_preconditions`（每次调用重查） |
| 参数与返回结构 | MCP `inputSchema`/`outputSchema`；Nuclei matchers/extractors | 输入三分 + `outputs.schema` + `evidence` |
| 生命周期 | Stratus warmup/detonate/revert；Atomic `cleanup_command`；MSF `SideEffects` | `lifecycle_obligations`（due/discharge）+ `restoration` |
| 索引/检索 | Nuclei tags/severity；MSF rank/platform/targets；Caldera tactic/technique；MCP `tools/list` 分页 | 方法/变体索引 + 谓词硬过滤 + 检索验收集 |

**结论：骨架同源**。我们的差异点不是"想错了"，而是**在这套骨架上少了几样别人有的列与阶段**。

### 4.3 具体能学什么（四条，都能落到我们的字段上）

| 编号 | 学谁 | 学什么 | 落到我们 |
|---|---|---|---|
| **L1** | Stratus | **把"准备工作"与"还原"升为独立阶段/动词**（warmup / revert），不是卡里附一句 cleanup | 卡的生命周期从"义务"升级为**可独立执行的三段**：`prepare` / `detonate` / `revert`，且 revert 要被验证。**直接解当前卡点**：authorized_keys 那条的 revert = "确认无痕/恢复原状"，而不是"no_automatic_restore"（等于放弃） |
| **L2** | Caldera | **fact 与 requirement 分成两类对象**（事实来自 fact sources + parsers，requirement 是事实上的表达式） | 我们的谓词显式拆两层：**fact 类型**（可追溯、带来源）与 **requirement 表达式**；索引里能写"这张技能卡需要哪些 fact 类型" |
| **L3** | Metasploit | 元数据里直接给 **可靠性 / 副作用** 列 | 卡加 `reliability` 与 `side_effects`，索引与选择界面直接展示（多实现之间可比较） |
| **L4** | Nuclei | **模板级 `pre-condition`**：门控可以是"另一张技能卡的结果" | 我们的图谱 AND/OR 已在做，但可把它明确成卡级声明：某张卡的前置可由**某个上游产出的 fact** 表达（对齐 fact/requirement 模型） |

### 4.4 我们比他们更严的地方（别丢）

- **三值前提**：MSF 的 `check` 有 Safe/Vulnerable/Unknown，但多数项目只有"满足/不满足"；我们的"未知只许观察"是明文纪律。
- **权限不随技能**：MCP/OpenHands 的口径我们已采用（`tool_surface` 只是声明，真正可调用范围由运行层句柄决定）。
- **变体级交付声明**（`delivers`）：他们的一张技术卡通常只有一种交付形态；我们区分"验证型/实施型/会话型"变体。
