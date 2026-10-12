# 设计决定

记录有实际影响的选择。区分此前已明确的方向、当前建议和待讨论问题。

## 此前已明确的方向

- 项目服务于授权靶场，输入已有 MulVAL/MAVO 攻击图，对节点验证结果及证据生成报告。
- MSF 为主要能力来源，保留必要的其他 Kali 能力。
- 通过 Python 将图转换成结构化数据，步骤与边分开存储；V1–V3 优先。
- AND 节点作为投影步骤来源，OR/LEAF 信息需要能关联回步骤。
- 以共同学习为主，逐步做成系统级项目。

## 本次采用的教学安排

- V4 先做模拟执行闭环，V5 接模型，V6 接真实靶场。理由：把编排错误与环境、模型错误分开验证。
- 每轮一个核心问题，以小例子、反例、实现和验收推进。
- V1 的图和节点 schema 已随实现更新为 1.0.0；能力 registry 仍为草案，随后续课程测试迭代。

以上是当前推进安排，可以依据学习反馈调整。

## 待在对应课程确定

当前用户明确的 V1 方向：运行时只输入 TXT；P 文件用于编写与验收 case。按 `rule_desc` 选择处理逻辑，再从原图事实中抽取参数。输出希望保留 AND 与终点 OR、节点哈希和必要业务信息，边尽量只有 source/target。当前先用实验确定原图逻辑可以怎样化简，再决定最终最小结构。

实验已证明参数数量可区分部分谓词布局，但不能区分全部同名 case；也已验证 S1 的两条冗余依赖可以在明确假设下去掉。参见 `archive/v1_logic_probe/README.md`。

2026-09-05 按用户“先给完整脚本”和“还要 PDF”的请求，采用以下 V1 实现选择，待共同读代码验收：

- `rule_desc` 分组后匹配谓词签名、关键值、共享变量与 dif 约束；35 个 case 可单独维护。
- 主图只保留 AND 与终点 OR；边保持 source/target，分组放在 `semantics.requires`。
- 原始图数据放在同一个 JSON 的 `source_graph`；每个行为的直接上下文通过引用查回。
- 哈希为图指纹加原始 ID 的实例标识，不承诺跨图业务去重。
- 只做可证明的保守 DAG 化简；循环保留并提示。
- JSON 是唯一绘图来源，PDF 不维护另一套压缩逻辑。

这些是本次可运行版本采用的具体取舍，不代表已经由用户独立解释或最终确认。字段说明见 `docs/v1/design.md`。

2026-09-05 按用户“图里的主机名如何对应实际目标”和“最小实现”的要求，新增一个本机 IP 预设流程：

- 先在 P 输入里把主机原子替换为带引号的 `192.168.3.x`，让 MulVAL/XSB 接受 dotted IP；TXT/JSON 阶段再还原成普通 IP 字符串。
- 如果规则文件中出现主机名常量，也必须使用同一映射。本机 `rules5.P` 中的 `dif(HOSTD, pc_1)` 已证明会影响 S1 推理，所以当前同步生成 `rules5_ip.P`。
- 当前不做 DNS、资产发现或自动扫描。`target_host` 只是来自 MulVAL TXT 的目标标识，后续执行器按它连接已授权靶场。
- 节点验证的停止点是证明节点声明成立：普通代码执行返回 `whoami` 级证据即可；声称 system/root/admin 的节点必须返回当前权限证据；拿到证据后停止，不继续破坏或扩大利用。

- 第 2 课：读代码核对现有字段、哈希与输入方向，完成小练习后确认或调整。
- 第 5–7 课：实际谓词签名、实体绑定及验证目标结构。
- 第 8–10 课：能力输入、运行前提和证据判据。
- 第 11–14 课：初始事实如何进入运行状态，如何处理暂不支持的循环依赖。
- 第 15–17 课：模型承担的具体决策、连接方式和调用预算。
- 第 18–20 课：真实靶场拓扑、版本、会话与目标映射。

此处未定内容不是前面课程的统一阻塞项，到使用它的阶段再解决。

## 2026-09-09：两层编排讨论稿（运行层尚未实现）

输入已有攻击图，执行范围由固定图、运行模式与登记能力共同约束。V1 保持离线转换职责；解析角色调用现有转换器。

- **图级顺序**：先确定目标与覆盖口径。目标导向模式选取所需依赖，AND 展开全部条件，OR 保留有顺序的候选，共享前置去重；以依赖就绪队列推进。DFS 可用于选路，单纯按遍历次序执行或把 OR 的全部入边计为必需都不符合语义。
- **同级顺序**：选定分支后的依赖关系决定偏序。无因果先后且无资源冲突的就绪节点可交换顺序。首版串行、同级稳定排序，不引入并发调度；全图覆盖时其余 OR 分支仍保留各自任务。
- **S1 对照**：旧节点 32 = IP 节点 21，依赖 7 AND 24；7 与 24 共同依赖 12，彼此无依赖路径。IP 图的一种首选动作序列为 `2 -> 14 -> 12 -> 7 -> 24 -> 21 -> 31`；20、30 是目标事实，不额外派发外部动作。
- **节点内顺序**：`case_id + premise_refs/effect_refs + 能力模板` 决定步骤类型与顺序。模板可以包含前置检查、登记动作、效果检查，每一阶段均可含多个原子步骤。逻辑推导节点使用事实判定。编排器实例化模板，执行器逐步调用 Skill/MCP；节点类型 AND/OR 不决定是检查还是动作。
- **模式明确**：验证模式使用已定义检查及已有证据；若纳入已知步骤的动作复现，由单次运行显式选择模式，模板声明动作入口与副作用。检查失败本身不触发模式切换。具体动作模板仍待逐 case 讨论。
- **最少状态**：节点状态、选定 OR 分支、当前原子步骤、上下文/产物引用、尝试次数与失败原因。连续步骤复用上下文；节点入口、效果提交、会话切换、超时/重试和状态变更处检查受影响条件，不逐原子步骤重新规划全图。
- **证据与依赖**：工具结束与所需事实成立分开。状态检查的完成不冒充原图动作产生了全部效果；V1 化简假设仍适用时才复用其蕴含关系，否则按原始前提核对。OR 备选、失败与变化通过局部重排处理。

扩展入口保持两处：新增规则补 case 验证/动作模板与案例；新增工具补语义能力适配器与结果契约测试。首版沿用单进程与轻量数据库方案。


## 2026-09-15 23:22：技能目录（skills）与索引派生

运行层的“能力（ability）”统一改名为“技能（skill）”，与王炸 `skills_data.json`/`SKILL.md` 和 kali-pentest 技能卡生态对齐；粒度规则不变：一条 = 一个固定方法。

- 目录：`skills/registry.json` 手写源（`id/name/desc/tactic/technique/service/vuln/purpose/path` 九字段）；`skills/<id>/skill.json` 机器契约（输入参数、输出证据、判据闸门、入口脚本）；`skills/index.json` 由 `scripts/build_skill_index.py` 生成，禁止手改。
- 支撑类不绑 ATT&CK：`tactic/technique` 为空、以 `purpose` 检索；动作类必须 tactic/technique 成对且声明服务。
- 召回主键与图节点字段一一对应（technique + service + vuln）；不引入来源（where）与平台（platform）字段，执行位置与通道由运行时决定。
- 判据口径：`system` 按权限等级等价（域管即够），不再强制 SID=S-1-5-18；证据不足一律 `uncertain`。
- 校验四规则：schema 合规、索引 sha256 对齐注册表、反向无悬空、正向全覆盖。覆盖核对 `--graph` 直接对红日 7 v2 图执行，当前 12/12 AND 节点覆盖。
- 旧 `registries/kali_core.yaml`、`msf_core.yaml` 保留为历史草案，不再扩展；旧 `schemas/ability.schema.json` 被 `registry/skill` 两个 schema 取代。


## 2026-09-15 23:45：运行层（runtime）与适配器（entry.py）

适配器层落地，回答「选定技能之后到底怎么执行、证据从哪来」。

- 分层：`src/runtime/` 是运行层（执行、产物、脱敏、信封），`skills/<id>/entry.py` 是适配器本身；适配器只做「绑定输入 → 固定 argv → 执行 → 解析证据」，判定交给 checker。
- 固定 argv：模型只能填目标与凭据引用（`--input`），其余参数写死在适配器里；`--plan` 只打印脱敏后的 argv，作为「过程固定」的核对入口。
- 每次调用一个目录：`<run_dir>/<call_id>/{call.json,stdout.txt,stderr.txt}`；证据只认这些产物，可逐字段回溯。
- 状态词表：`executed / timeout / tool_missing`。`tool_missing` 表示环境缺工具，不是证据不足，也不写假证据。
- 脱敏两层：显式凭据必清洗 + 形状兜底（NTLM 哈希对、`password=`/`token=` 片段、`Authorization`）。`-p` 一名两义，不全局清洗，由适配器显式声明（nmap 是端口，impacket 是口令）。
- executor 可注入：`execute(..., executor=...)`，适配器回归不需要靶场；生产用 Kali 上的 subprocess 执行器。
- status 口径：入口脚本存在 ≠ `implemented`；实机跑通并在 `output/runs/` 留下调用记录后才改。


## 2026-09-16 00:20：适配器 9/9 + 会话驱动 + 知识卡 9/9

承接运行层落地，把首批 9 条技能全部补到「可执行」：

- 新增 7 条适配器：远程关防火墙（netexec smbexec 两步：apply + 回读）、通达 OA（上传固定 PHP 载荷 + include 回显）、
  redis 写 key（`SET` + 可选 `CONFIG SET`/`SAVE` + `GET` 回读）、Laravel CVE-2021-3129（固定 PoC + marker 回显）、
  容器逃逸（挂载宿主根 + 宿主侧标记文件）、SUID PATH 劫持（发现 + helper + proof 读 `uid`）、
  LSASS 转储（meterpreter：`sysinfo` / `load kiwi` / `creds_all`）。
- 会话类技能用 `session_ref`（`msf:<id>` 或 `{"driver":"msf","id":"3","shell":"posix|cmd"}`）驱动：
  固定写 `<run_dir>/<call_id>/session.rc`，`msfconsole -q -r` 非交互执行，命令用 `<marker>start/end` 包裹，
  **目标回显标记才提取证据**；换驱动只改 `runtime/session.py`。
- 多步方法：主调用进顶层用于判定，其余进 `calls`；`--plan` 增加 `steps`（每步 argv）与 `session_rc`（会话将输入的控制台行）。
- 标记统一由 `call_id` 派生（`call_marker`），保证「标记 ↔ 调用」可追溯。修掉一个真坑：`-p` 在 nmap 是端口、
  在 impacket/netexec 是口令 → 清洗按适配器显式声明，不做全局替换。
- 知识卡 9/9：红日 7 实测坑点（OA `disable_functions` 与 popen、Laravel 尾斜杠 301、redis 复跑复原、
  SUID 直执行降权、逃逸靠宿主侧效果、Win7 SCM stdout 丢失、高并发扫描假超时等）。
- `status` 口径：9 条仍 `planned`；卡片 `notes` 写明「适配器与知识卡已就位，实机跑通后置 `implemented`」。
- 验证：`python -m pytest -q` → 152 passed, 1 skipped；`build_skill_index.py --check` ok；红日 7 v2 覆盖 12/12 不变。


## 2026-09-16 00:45：备选卡机制（wmiexec 作为 psexec 备选）

- 新增第 10 条技能 `exec.impacket_wmiexec_cmd`：与 psexec 同一验证目标（`T1021 + smb/445`）、
  不同机制（WMI/DCOM 135 + SMB 取回输出，不创建服务），证据形状与判据与首选卡一致。
- **优先级 = 注册表顺序**：同一召回键下的列表第一条首选、其余按序备选；索引与覆盖报告都保持该顺序
  （红日 7 节点 38/48 现在返回 `[psexec, wmiexec]`）。不新增 `priority`/`fallback` 字段，避免破坏九字段定稿。
- 失败回环口径：先跑首选；拿不到证据时按顺序换卡；失败原因（条件不满足 / 方法不对）落运行时 records，不进目录 json。
- 验证：`pytest -q` → 155 passed, 1 skipped；`build_skill_index.py --check` ok；红日 7 v2 覆盖仍 12/12（节点 38/48 双候选）。


## 2026-09-16 01:10：选择器（selector）——图节点 → 锁定技能 + 输入绑定

- 新增 `src/skills/selector.py` 与 CLI `scripts/select_skill.py`：`--graph --node [--context --config --host-map]`。
- 召回复用 `index_builder.match_skills`（与覆盖核对同一实现），避免「选择器说能打、覆盖核对说没覆盖」两套口径。
- 锁定规则：注册表顺序即优先级，第一个绑定得齐的候选被锁定，其余进 `alternatives`（失败回环按序换卡，见 00:45 决策段）。
- 绑定三分类（判定缺什么，而不是假装有值）：`from: graph` 缺 → `missing`（图要补事实）；`from: runtime` 缺 → `pending`（运行现场补给，不算失败）；`from: config` 可空（适配器有默认值）。
- 缺事实不臆造：`node_facts` 只拍平图里写明的事实（含 `semantics.details` 的 path/accounts/target_privilege）；`target_url` 仅在 http/https 协议时生成。
- 主机对账：`--host-map` 读 `host,ip` CSV（复用主机转换的口径），把逻辑主机名换成地址；映射不上保留原名并记 `notes`，不静默。
- 实测：节点 26 → `locked=priv.suid_path_hijack`、`inputs.path=/tmp`、`pending=[session_ref]`；节点 48 → 候选 `[psexec, wmiexec]`、`locked=psexec`、`pending=[credential_ref]`。
- 回归：新增 `tests/test_selector.py` 9 条（含跨目录 CLI）；全套 `pytest -q` → 164 passed, 1 skipped。契约新增第 11 节。


## 2026-09-15 23:51：D22 决策段（by_case / 会话双驱动 / OA 落盘 / 远程执行器）

### by_case：图词汇成为独立召回键
- 图节点的 `semantics.case_id`（如 `direct_network_access`）升级为**与 technique 平级的精确键**：技能在注册表声明 `case: [...]`（支撑类必填、行动类可选），索引生成 `by_case`。
- 召回顺序：technique 键（含 service/端口兼容）→ case 键（含对象兼容）→ 关键词只排序不裁决。命中来源写进覆盖报告 `via`，失败可追溯到「是哪一类键把它召回来的」。
- 防误召回：case 命中仍要过对象兼容（服务名不得张冠李戴），否则 redis 节点的 case 会把 laravel 卡拉进候选。
- `purpose` 退回技能自身分类，不再当检索主键（它与 case 重叠但语义更粗）。

### 会话驱动：msf → msf + agent
- `session_ref` 支持两个驱动（`DRIVERS = {"msf", "agent"}`），驱动契约三条硬约束：命令必须被标记包裹、目标输出必须原样回显、transcript 必须落盘到本次 call_id。
- agent 驱动走自建会话代理（`agv-session exec` / `agv-session rc`，可用 `AGV_SESSION_AGENT_CLI` 覆盖），为「新主机落代理 + 会话迁移」这条既定路线留出实现位；msf 仍是默认驱动。
- `plan_payload` 的 `session_rc` 更名 `session_plan`：会话类技能在 `--plan` 下给的是「会话里将输入什么」，与驱动无关。
- `CallResult.status` 增 `transport_error`（`returncode=None` 且非超时/缺工具）：传输没完成不许当证据，堵住「命令发出去了=节点被证明」这类假证据。

### OA 落盘路径推导（实机核对后固化）
- 实测上传响应 `+OK [vm]261@2609_578841424|shell.png|0[/vm]` → 落盘路径 = `attach/im/<YYMM>/<num>.<原始文件名>`，`num` 段前缀推 YYMM。
- `derive_include_path()` 三来源 `override / response / uploaded_name` 全部写进证据（`include_path_source`）；响应里没有 token 就**停在包含前**（SystemExit），不拿空路径硬打；文件名带路径分隔符视为恶意，退回我们自己的上传名。

### 远程执行器（实机验证地基）
- 实机验证控制端 = Kali（VMnet8，192.168.52.128），但适配器在 Windows 侧跑：`src/runtime/remote.py` + `scripts/run_skill_remote.py` 用 SSH 把 argv 送到远端，产物仍落本地同一套 runner 目录。
- status 映射：远端 127 → `tool_missing`；SSH 超时 → `timed_out` 且断开重连；连接层异常 → `transport_error`。
- 可测性：`SshExecutor` 可注入假 client，7 条回归全离线跑。

### 命名收尾：ability → skill
- 项目自身技能卡 `skills/attack-graph-validation/`（SKILL.md + references/workflow.md）里的 “ability” 措辞改为 “skill”。
- `docs/plans/v3_abilities.md` 加弃用抬头；`schemas/ability.schema.json` 加 `$comment` 弃用标记；`registries/*.yaml` 此前已带 DEPRECATED 头。旧 PRD 只在 `docs/product/README.md` 的「旧入口 → 当前去向」表里保留导航，不再作为契约。


## 2026-09-16 00:03：D23 决策段（执行器链 / 运行时供给 provides / 会话卡的前置诚实性）

### 执行位置是 run 的一等公民：执行器链（chain）
- 问题：图里带来源语义（`attacker → web1`、`web1 → pc1:8080`、`pc1 → dc`、`pc1 → pc2`），而原执行器只有「本机 → Kali」一跳。
  实机侦察后确认：剩下 7 条技能卡住的不是网络，是**执行位置**。
- 采用 `src/runtime/chain.py`：**第一跳 = 传输**（paramiko 连到执行段），**后续每一跳 = 命令包装**（上一跳执行 `ssh <target> '<quoted argv>'`）。
  链是**数据**（`{"hops": [...]}`）：`--chain spec.json`；`--remote` 退化为单跳链，两者共用同一实现。
- 内层跳**必须**给 `key`：外层 `BatchMode=yes` 下口令交互必然挂，所以链在**加载时**报错，不把失败留到执行中途。
- 每次调用把 `vantage`（`kali@192.168.52.128 -> root@192.168.52.10`）写进 `call.json`：这是图 source 语义在执行侧的落点（来源闸），
  证据从此能回答「从哪打的」。
- 边界：`SshHop` 只回答「怎么跳」，不碰技能逻辑；将来换传输（msf 通道、会话代理）＝ 新增一个 `kind`，适配器与判据都不动。

### 运行时供给：注册表 `provides` + 索引 `by_provides`（第二条检索路径）
- 两条检索路径明确分工：`case` 面向**图节点**（「哪个技能服务这条边」）；`provides` 面向**运行现场**（「这次 run 缺会话/凭据/传输/可达性，谁能给」）。
  混在一起会让「图词汇」变成语义垃圾桶，也让覆盖核对失去意义。
- 取值枚举四个：`reachability / session / transfer / credential`；规则：动作类不得声明；声明了 `provides` 时 `purpose` 必须包含在其中；
  支撑类 `case` 与 `provides` **至少声明其一**（否则召回永远够不到它）。
- 索引生成 `by_provides`，`--check` 双向校验（多余键 / 遗漏键 / 未知 id）——与 `by_case` 同一套口径。
- 选择器 `--need`：候选来自 `by_provides`；`--node` 只用来把「需要它的那台机器」推出来（取节点的 `source_host`，
  再按 `--assets` + `--from` 解析地址；地址解析与节点模式**共用同一段实现**），避免两条路径各写一套地址逻辑。
- 两条路径输出同形（`locked` / `inputs` / `ready` / `alternatives` / `providers[]`），`ready` 在两处同义：**无 missing 且无 pending**。

### 会话卡：`session.ssh_via_redis`（第 11 条，服务运行现场）
- 过程固定：未授权 redis（root 运行）→ `CONFIG SET dir /root/.ssh` + `CONFIG SET dbfilename authorized_keys` +
  `SET`（值 `"\\n\\n<公钥>\\n\\n"`）+ `SAVE` → SSH 登录**验证**会话 → 按需复原。
- **`verify` 才是判定调用**（`session_identity` / `session_host` / `ssh_key_fingerprint`），前面几步只提供条件；
  `restore` 必须在 `verify` 之后，否则等于拆掉自己的会话（测试锁定 `verify_index < restore_index`）。
- 诚实性写进卡片 `notes`：`SAVE` 是覆盖写，本能力**假定 `authorized_keys` 原本不存在**（lab 事实）；若原本存在且没有其它读取途径，
  请在 run 记录里写清楚，而不是假装能还原。
- 为什么不是「redis 卡加个开关」：redis 写文件（图节点 `public_application_initial`）与会话供给（运行现场需求）是两个验证目标，
  登记成两条方法卡，各自只回答自己的问题——这也是「一条注册记录 = 一个固定方法」的第一次实测。

### 实测逼出的方法替换：OA 卡的 HTTP 客户端（curl → stdlib python3）
- 首次真机跑 `D23-node7` 时，上传步回 `tool_missing`：图里的 source（web1，Ubuntu 18.04）**没有 curl**。
  这正是「工具跑了 ≠ 节点被证明」的反面情形——`status=tool_missing` 是执行环境事实，不是目标事实。
- 处理方式是**替换这条卡里的固定方法**，不是给卡加分支：步骤 0 把固定载荷与固定客户端
  （`client/agv_oa_http.py`，只用标准库，兼容 python3.6）一并以 base64 落到执行端，步骤 1/2 调它。
  过程、证据形状与判据都不变；`payload_path` / `client_path` 进 `markers`，复盘能看到落到哪。
- 换机器不等于换方法：如果将来某台源主机连 python3 也没有（例如 Windows 源），那是**另一种实现**，
  按「一个固定方法一条记录」再登记一张卡，而不是让现有卡在运行期猜。
- 首次真机结果：`call-20260916T001058-34fdaa-include`，`command_output="nt authority\system\nPC1"`
  （与节点 `target_privilege=system` 一致），`vantage=kali@192.168.52.128 -> root@192.168.52.10`。
- **同一条规则在 Windows 侧同样成立（D23 顺带查实）**：节点 2 的 source 是 pc1（Windows），而现有卡固定用 Kali 的 `netexec`——
  执行端根本没有这个工具（而且 Kali 侧也装不上：PyPI 没有该发行版、GitHub 源码安装会卡在需要 Rust 的 `aardwolf`；
  `crackmapexec` 虽在，但同样不在 pc1 上）。结论：**方法的实现必须与 vantage 的工具链匹配**，pc1 侧要单独登记一张
  Windows 方法卡（`net use` + `sc`/`schtasks`），与 Kali/netexec 那张共享同一验证目标、并存为备选。
- 前置侦察的副产品：用已跑通的 OA 卡当通道，从 pc1 实测出 `pc1 -> dc:445` 被拦（`SMB445=FAIL`）但 ICMP 通，
  即「不是主机不通，是端口被过滤」——与图上「域防火墙拦住横向」的前提一致（节点 2 的可信度提升）。
  探测命令必须只输出 ASCII：pc1 是 PowerShell 2.0，且 OA 页面的 charset 转换会把中文输出毁掉。

## 2026-09-16 D24-a：webshell 会话驱动（通道状态 ≠ 凭据）
- 背景：pc1 上已有可用的 OA http-include webshell（节点 7 判定调用 `call-20260916T001058-34fdaa-include`），
  而节点 2（关防火墙）/ 41（LSASS）/ 38 / 48（凭据）都要求「从 pc1 动手」——缺的不是武器，是**执行位置**。
- 选择：把 webshell 做成 `session.py` 的第三个驱动（`DRIVERS = {"msf", "agent", "webshell"}`），
  而不是给会话卡加分支、也不新造一层。理由：会话类技能的全部语义就是「在已有位置里跑固定命令」，驱动是位置，卡是命令。
- 两个关键契约：
  * **通道状态 ≠ 凭据**：`WEBSHELL_REQUIRED = ("base_url", "include_path")` 描述「这个 shell 在哪」，不是登录材料；
    缺任一项在 `parse_session_ref` 阶段直接 `SystemExit`（消息 `webshell session_ref needs ...`），不猜、不兜底。
    `client` 缺省 `/tmp/agv-payloads/agv_oa_http.py`——固定客户端是部署物，不是运行期参数。
  * **单命令，无控制台**：http-include 没有可喂行的控制台；`session_script` 传 webshell -> `SystemExit("...single commands...")`。
    多步动作由「一条卡多步调用」表达（每步一个请求），而不是在驱动里假装存在交互通道。
- vantage 语义：webshell 请求走**当前 executor**——单跳时从 Kali 发（请求从控制机访问 pc1:8080），
  经 chain 时从链末端（图里的 `source`）发；两种路径都不改变「命令在 pc1 上执行」这个事实。
- 新卡 `post.channel_echo`（第 12 条，`provides: ["session"]`）：与 `session.establish.*` 同 need、不同分工——
  「从零建立」vs「验证已有通道」。它是 webshell 驱动的第一个真实消费者，也是后续节点的「执行位置就绪」检查点：
  先验通道、再打节点；失败时能区分「通道死了」和「利用方法没成」。
- 回归：`tests/test_runtime_adapter.py::SessionDriverTests` +5（argv 形状 / 默认 client / 缺通道状态 / 拒 console 脚本 / plan 占位）
  + `tests/test_skill_adapters.py::ChannelEchoAdapterTests` +6 + `test_selector.py` 一条新用例（两个 session provider 的顺序），
  `python -m pytest -q` -> 227 passed, 1 skipped。
- 实机（2026-09-16 00:23，两条路径都跑通）：
  * 单跳 `D24-webshell-pc1` / `call-20260916T002330-8f7a99`：请求从 Kali 发（`client` 走缺省 `/tmp/agv-payloads/agv_oa_http.py`），
    `session_identity=nt authority\system`、`session_host=PC1`，0.39s；
  * 链 `D24-webshell-pc1b` / `call-20260916T002342-96698a`：`vantage=kali@192.168.52.128 -> root@192.168.52.10`，同判据复跑一致。
- 未做（顺延）：D24-b pc1 侧 Windows 关防火墙方法卡（`net use` + `sc`/`schtasks`）+ dc:445 错误码复核；
  D24-c web2/容器会话；D24-d 靶场清理。

## 2026-09-16 D24-b 侦察：通道 addslashes 推翻「445 被拦」，并找到 Windows 侧固定执行姿势
- 背景：D23 记录 pc1→dc `SMB445=FAIL`，据此推断「域防火墙拦住横向」。D24-b 用同一张 OA 卡复测，
  先发现**命令在通道里被改写**：`echo [\a\b]` 回来是 `[\\a\b]`、`'` → `\'`（`$` `%` `!` 不动）
  —— 通达 OA 对参数做了 **`addslashes`**。`\\host\share` 被改坏后在 SMB 客户端**解析阶段**就失败（67 / `sc` 1707），
  连本机 `\\127.0.0.1\ipc$` 都 67 —— 这就是「不是网络问题」的铁证。
- **绕开方式（已验证）**：`powershell -nop -EncodedCommand <base64(UTF-16LE)> < nul`
  * base64 不含 `\` `'` `"`：addslashes 无从下手；
  * **`< nul` 不可省**：popen 交给 PowerShell 的 stdin 是坏管道，不加则抛 ArgumentException（文本含 FileStream）
    且 `-EncodedCommand` 完全不执行 —— 这正是 D23「TcpClient 不可靠」的真因；
  * 加上后输出干净（噪音报错一起消失）。
- 重测结论（run/call_id 见 validation_runs.md）：
  * `D24-probe-nul` / `call-20260916T002837-b94718-include`：`DC445=OPEN`、`PC2445=OPEN`、`LOCAL445=OPEN`；
  * `D24-probe-smb` / `call-20260916T002920-29da97-include`：`net use` 假凭据 → **1219**（凭据冲突），
    `dir \\dc\c$` → **86**（密码不正确）→ SMB 已走到**认证层**。
  * ⇒ **pc1→dc / pc1→pc2 的 445 本来就是通的**；节点 38/48 无端口障碍，节点 2 缺的是**凭据**不是可达性。
- 工程影响（三条）：
  1. 「通道会改写命令」升级为**通道级已知特性**：写进 OA 卡 SKILL.md（坑点）与 validation_runs（推理链留档）；
     需要复杂命令（UNC/引号/PowerShell）的卡，一律用 `EncodedCommand < nul` 包装；
  2. D23 的前置侦察记录**保留原文 + 标注「已被 D24 推翻」**——不能让错误结论在文档里继续当事实引用；
  3. 「方法必须匹配 vantage」再添一例：pc1 到 dc/pc2 的物理路径只能从 93 网段内部走（Kali/web1 都不行），
     所以节点 2/38/48 的实现必须落在 pc1 侧（`net use` + `sc`/`schtasks`），而不是把 Kali 的工具搬过去。
- 下一步：节点 41（pc1 LSASS）：`comsvcs.dll MiniDump` 做 pc1 侧方法卡（不需要凭据），
  产出凭据材料后回头补节点 2/38/48；dump 外带候选 = 新 `transfer` 能力（pc1 → Kali HTTP 上传）。

## 2026-09-16 D24-c：节点 41 方法链（dump → 外带 → 解析）+ 一个具名脱敏例外 + 一条环境前置 leaf

- **一条 case 下可以有「相邻环节」，不只是「备选方法」**。节点 41 的 `lsass_system` 现在挂三条：
  `cred.kiwi_lsass_dump`（msf kiwi，备选）、`cred.comsvcs_minidump`（命令通道 dump，实测路径）、
  `cred.pypykatz_parse`（解析）。两条 dump 是**同一环节的备选**（运行期二选一），dump → parse 是**相邻环节**
  （运行期按序都做），中间「把产物从目标搬出来」这一段由支撑卡 `transfer.http_post_file` 以 `provides: ["transfer"]` 承接。
  注册表顺序同时覆盖这两种读法，不新增层级字段（契约第 5 节）。
- **`keep_material`：脱敏政策的一处具名例外，不是开关**。凭据解析卡首跑（`call-20260916T004658-dea471`）输出里是
  `NT: <redacted>` —— `redact.py` 的形状兜底把 32 位十六进制当成了秘密。被打码的哈希不是证据，所以
  `runtime.runner.execute(..., keep_material=True)` 只关掉**这一次**调用的 stdout/stderr 脱敏：argv 照旧脱敏，
  `call.json` 写 `material_kept: true`，复核者能一眼看出哪些调用带未打码字节。使用者只有两张凭据卡；别的卡要用，
  先说明它的证据为什么必须是材料本身。
- **外带判据必须双边**：`transfer.http_post_file` 只认「源端 `LOCAL <bytes> <sha256>`」与「接收端 `RECV OK <bytes> <sha256>`」
  **逐字一致**（`transfer_hash_match`）。首跑多出 199 字节（`WebClient.UploadFile` 发的是 multipart 包装）正是这条判据抓出来的；
  只报一边时写 `observations`、不写 `transfer_verified` ——「工具跑了」永远不等于「字节到了」。
- **诚实性：事实 42 是环境前置 leaf，方法创造不出它**。节点 41 的合取项含 `hasAccount(pc1,domain_administrator,…)`（**LEAF 42**），
  目标是 `getAccount(pc1,domain_administrator,…)`（事实 40）。实测解析出 6 个 LogonSession，**只有**域用户 `bunny` 与机器账户 `PC1$`；
  追加侦察里 `net group "Domain Admins" /domain` 也被 SAMR 拒。对照 writeup 取证记录：那次看到的「域管会话」里含**我方自己
  `net use` 建立的登录条目**。⇒ 方法链成立（dump / 外带 / 解析三段都有本次 run 的真证据），但**事实 40 没被产生**，
  节点 38/48 的凭据前提也不成立。这正是「leaf 作前置参考 + 追溯」该有的输出：说清是**环境前置**没成立，而不是笼统地「利用失败」。
- **图上省了的前提也要如实记**：节点 2 的合取项（`hacl(pc1,dc,445)` / `networkServiceInfo(dc,scm,445,system)` / `ttpExists(…)` /
  `execCode(pc1,system)`）在实测里全部成立，但远程 SCM 这条方法**本身要认证到 dc**（D24-b 的 1219/86 就是撞在这）。
  差异记进缺口表、**不擅自改图**：图是输入，执行结果是追溯材料。
- **通道级约束升级成卡片硬约束**：32 位上下文打 64 位 lsass 必须走 `sysnative` + `System32`（否则 0 字节）；
  单条通道命令 < 8191 字符（超了是**静默失败**：`returncode=0`、stdout 空），卡片在 7500 字符处主动报错；
  回显会把长哈希折行，解析前先压掉空白。三条都来自实测（run/call_id 见 validation_runs.md 的 D24-c 节）。
- 实机：`D24-node41-dump` / `D24-node41-exfil` / `D24-node41-parse2` 三段跑通；回归 `python -m pytest -q` -> 243 passed, 1 skipped。
- 未做（顺延）：D24-c2（web2/容器会话，解锁节点 19/22/26）；D24-d（靶场清理：pc1 两个 dump、Kali agv-loot、web1 authorized_keys、redis 复原）。

## 2026-09-16 D24-e：Windows vantage 的两条方法卡（域管凭据实测可用）+ 两个语言/通道层的坑

- **凭据这件事要分两层说**：D24-c 的诚实性发现是「pc1 的 lsass 里没有域管登录会话」（事实 42 这个 leaf 不成立），
  D24-e 实测的却是「域管明文凭据 `WHOAMIANONY\Administrator/Whoami2021` 对 dc 与 pc2 都有效」。
  两者不矛盾：**节点 41 要的是①「登录会话在 lsass 里」，节点 38/48 要的是②「手里有可用凭据」**。
  ②成立 ⇒ 节点 38/48 的凭据前提不再是缺口；①不成立 ⇒ 节点 41 的目标事实仍不产生。文档里这两条必须分开写，
  否则「凭据」一词会把两个不同的命题搅在一起。
- **通道选择由目标环境决定，不由工具偏好决定**：同一台 dc 上，`sc create` 成功但 `sc start` 回 1053、目标零产出；
  `schtasks /ru SYSTEM` 也说成功但零产出；`wmic process call create` 可用（`ReturnValue=0` + `ProcessId` + 目标落文件）。
  负结果写进卡片的 SKILL.md 与实机记录，**不是**「下次再试试」的待办，而是「别再试了」的结论。
- **「判状态」和「判变化」是两件事，卡片只判前者**：`evasion.wmi_firewall_off` 的证据是
  「本次调用之后三档 `EnableFirewall` 都是 `0x0`」。这台 dc 本来就关着防火墙，before/after 一样是 `0x0`，
  所以方法**不能**声称「是我们关的」——批处理把 before/after 两块都留在原始输出里，让复核者能自己看出这个差别。
  这条与 D24-c「dump 成立 ≠ 凭据成立」是同一种边界纪律。
- **秘密的脱敏要覆盖「编码后的载体」**：`net use`/`wmic` 需要明文口令，脚本里它 base64 编码后随 `EncodedCommand` 走。
  明文在参数里已不可见，但**编码片段本身是秘密**：`secret_span()` 把外层 base64 中承载口令字节的那一段整体登记为打码目标（redaction）
  （`build_command` 返回 `[secret, span]`），argv 其余部分照旧可读。测试里有一条断言：抹掉 span 后解码脚本里就再也找不到 inner。
- **PowerShell 数组字面量：逗号比 `+` 紧**（D24-e 的实测结论，写进契约第 10 节）。`@('echo x > ' + $path, …)` 会被拆成
  「每个操作数一个元素」，送到目标上的 `.bat` 变成十几行碎片、`cmd` 什么也不做（`D24-e-diag2` 铁证）。
  pc1 是 PS 2.0、本机 5.1，行为一致。⇒ 固定脚本里不再做字符串拼接，路径/名字用 `@@OUT@@` 占位符在适配器里绑定；
  `tests/test_skill_adapters.py` 加静态断言守住。
- **回显折行会折在 token 内部**：注册表路径以 `...Fi` + 换行 + `rewallPolicy\DomainProfile` 回来，行导向解析必然失配。
  ⇒ 新增 `runtime.adapter.squash()`（把换行整段去掉），所有基于命令通道回显的解析都在单行副本上做；
  卡 B 的 `probe_block` 还要带上尾部 `done` 标记（否则右边界找不到）。这是**通道**的特性，不是某张卡的私事，所以放 runtime。
- **注册表顺序 = 优先级，vantage 匹配排前**：节点 2 现在两条方法（WMI 版在前，netexec 版在后）、节点 38/48 三条
  （`wmi_process` 在前，`psexec`/`wmiexec` 在后）。图里这三条边的 source 都是 pc1，而 Kali/web1 到不了 93 网段，
  所以 Windows 侧方法优先。索引里 by_tactic / by_case 按 id 排序（确定性），**偏好顺序只活在注册表顺序与覆盖报告里**。
- 实机：`D24-e-fw` / `D24-e-wmi` / `D24-e-wmi-pc2` 三跑通过；回归 `python -m pytest -q` -> 258 passed, 1 skipped。
- 未做（顺延）：D24-c2（web2/容器会话）、D24-d（靶场清理，清单已按 D24-e 实测更新）。

## 2026-09-16 命名统一：ability → skill（旧工件整体归档）+ 文档导航补全

- **术语口径彻底统一为 `skill`**：登记源 `skills/registry.json`、单条契约 `skills/<id>/skill.json`、
  两个 schema `schemas/registry.schema.json` + `schemas/skill.schema.json`、选择器 `src/skills/selector.py`。
  `src/`、`tests/`、`scripts/` 本来就没有 `abilities` 标识符（此前一轮已改完），本轮收的是 schema / docs / registries 的尾巴。
- **弃用工件搬进 `archive/legacy_v3_ability/`，而不是就地留个弃用标记**：
  `schemas/ability.schema.json`、`docs/plans/v3_abilities.md`、`docs/product/ability_skill_matcher_prd.md`、`registries/`（3 个文件）。
  理由：`schemas/` 与顶层目录必须等于「当前生效的东西」；旧 schema 混在 `schemas/` 里会让「契约目录 = 权威」失效，
  顶层 `registries/` 与 `skills/registry.json` 撞概念，容易被后来者当成注册表本体。搬迁用 `git mv`，内容与行尾都未改。
  归档区自带 [README](../archive/legacy_v3_ability/README.md)：每个文件的原位置、弃用原因、现替代物一张表。
- **历史快照只修链接、不改内容**：`docs/product/reference/v0.1-detailed/` 里 3 个文件指向旧路径的链接改为指向归档位置；
  版本快照的正文（含当时 `ability` 写法）保持原样，因为它们是历史证据，不是现行口径。
  历史决策段落（本文档 71/78/159-161 行）同样保留原样，其路径引用指搬迁前的位置。
- **导航孤岛要补进目录**：`docs/product/skill_retrieval_execution_flow.md`（技能层工程流程稿，D28 更名前叫 `capability_retrieval_execution_flow.md`）此前**没有任何文件链接它**，
  已加进 `docs/product/README.md` 的阅读顺序（第 6 条），并加了术语对齐抬头（`ability_id` → `skill_id`，正文同步改名）。
  工程规矩：**新文档进来要么进 README 导航，要么进 archive**，不能悬在目录里没人认领。
- **课程路线里的「计划路径」要落到真实路径**：`docs/course/roadmap.md` V3 段原来写着 5 个从未创建的路径
  （`schemas/ability.schema.json`、`src/abilities/matcher.py`、`docs/ability_authoring.md`、`tests/test_ability_matcher.py`、
  `tests/fixtures/ability_results/`）。已改为实际交付物（`schemas/*` 两个契约、`skills/registry.json`、`src/skills/selector.py`、
  `docs/product/skill_contract.md`、`tests/test_selector.py`、`tests/test_skill_catalog.py`），并注明未采用独立夹具目录。
- **链接可达性是硬约束**：`tests/test_project_layout.py::test_local_markdown_links_resolve` 会遍历 `docs/`、`data/`、`scripts/`、`archive/`
  下所有 md 的本地链接。搬迁文档后必须同步该文件的所有引用（本轮共 7 个文件的引用点）。

## 2026-09-16 D24-c2：容器会话（webshell `plain` 模式）、SUID 提权，与「链路成立但卡保持 planned」

- **通道状态就是权限状态**：webshell 每次请求都是同一个低权身份（www-data、CapEff=0），没有「持续提权」这回事——
  每条命令都得把身份重新建立一遍。所以 webshell 的 session_ref 描述**通道**（base_url / include_path），
  这次新增的 `mode` 描述**通道怎么被使用**：`include` = 卡自带客户端走 LFI 型文件包含（路径指向已落盘文件）；
  `plain` = 路径本身就是命令 shell，命令直接进 `?cmd=<urlencoded>`。旧引用没有 `mode` → 缺省 `include`，零改动；非法 `mode` 解析期 `SystemExit`。
- **通用客户端放 runtime，卡自带客户端放 skills**：`runtime/clients/agv_http_cmd.py` 是「http 命令壳」这一类通道的**通用**客户端
  （不依赖具体靶场卡）；OA 卡自带的 `client/agv_oa_http.py` 属于那张卡（multipart 上传、落盘路径推导是卡的固定过程，换靶场就不一样）。
  判据：**两个以上不同场景会用到的客户端放 runtime，只有一个卡用的放卡目录**；`mode` 是客户端子命令，两者可互换。
- **「跑通」= 卡面声称的过程与判据独立成立，不是「目标被拿下了」**：`priv.privileged_container_escape` 的逃逸链路
  （SUID 提权 → 同请求内 mount → 宿主 marker 读写 + 宿主身份）在靶场**完全成立**，但卡保持 `planned`——
  卡的输入契约声明的前提是「容器内 root 会话」，而当前 session_ref 只能描述「裸 www-data 通道」（CapEff=0，mount 被拒）。
  把它标成 implemented 等于承认「任意 www-data 通道都能直接跑这张卡」，那是假的 ⇒ **证据先落 validation_runs、卡面与缺口如实写**。
  （同一种纪律的先例：D24-c「dump 成立 ≠ 凭据成立」、D24-e「只判状态不判变化」。）
- **webshell 单命令通道里的顺序依赖**：`plain` 没有控制台，一条命令 = 一个 shell；「先提权、再用新身份做事」只能写进**同一段** shell
  （`suid helper + mount` 在同一次请求里完成）。这正是 planner 要的形态：**node 26 → node 22 是顺序依赖，不是并列**——
  run 的推进必须能表达「上一节点的产物/身份是下一节点的前提」。
- **一次性维护脚本放 `tmp/`，不进注册表**：D24-d 用的 `tmp/d24d_cleanup.py` / `tmp/d24d_windows_cleanup.ps1` 是靶场维护工具，
  不是攻击能力（无 entry.py、无 skill.json、不进 `skills/` 与注册表）；但调用同样走 runtime（chain / session_command / runner.execute），
  落 `output/runs/D24-d-cleanup/<call_id>/`——**维护动作也留证据**。
- 实机：`D24-c2-*` 共 11 个 call（5 个跑 + 1 个失败样本 + 5 个环境探测），证据见 validation_runs.md D24-c2 节；
  回归 `python -m pytest -q` -> 265 passed, 1 skipped。
- **已完成（同日 01:57）**：D24-d 阶段 B —— web1 `authorized_keys`（redis RDB 产物，整文件删）+ `/tmp/agv-payloads`、Kali `~/.ssh/agv_session*` 与 /tmp 残留、pc1 的 32 个 OA 载荷、容器 webshell（curl → 404）、redis 复原（`dir=/root`、`dbfilename=dump.rdb`、`DBSIZE=0`）。保留项与副作用（`kali -> web1` 链失效，需要时重建）见 validation_runs 的「靶场清理 D24-d」小节。

## 2026-09-16 工程级审计：validation_runs 主表重复段事故与修复

- **事故**：D24-e 轮的编辑（提交 5727ded）在 `docs/product/validation_runs.md` 的主表 `D24-node41-parse2` 行处截断，
  紧跟插入了「正文 + 表头 + 前 11 行」的重复块，parse2 行的尾部残片落在重复块之后；文件结构损坏但未被发现
  （后续两轮只核对了新增小节与计数）。是本轮「结构完整性扫描」（代码块外标题计数 + 重复长行）抓出来的。
- **修复**：以最后一个正确版本（d3acd25）的 L1-22 为准恢复该行（`PC1$` 机器账户），删除 20 行重复块与残片；
  修复后与 d3acd25 的 L1-22 逐行一致（22/22），主表 17 行，标题/表头各出现一次。
- **编辑纪律**（本轮教训）：① 大改 md 之后跑一次结构扫描（代码块外 H1 计数 + 重复长行），不能只看新增段落；
  ② 插入内容用整块替换，禁止「在长行中间插入」；③ 提交信息覆盖不到的地方（主表内部结构）要单独核对。
- **同轮口径修正**：`schemas/registry.schema.json` 与 `skill_contract` §3 的 `case` 描述和校验器一致化
  （行动类可省略——有 `attack_id` 的节点按 technique+service 召回；支撑类须与 `provides` 至少声明一个）；
  示例 JSON 去掉行动类不会写出的 `"provides": []`；§10 `sensitive` 措辞改为「适配器把信封字段置 true」；
  `file_tree` 的 src/runtime 树形符号修正；`roadmap` 加「状态口径」并给 V4/V6/V8 补「实际落点」
  （`src/executors/*`、`src/planner/*`、`evals/` 等计划路径未采用）。
- 回归：`pytest -q` = 265 passed, 1 skipped；`build_skill_index.py --check` ok（17 条 @ 2b41399c6882）。

## 2026-09-16 D25 判定器（checker）落地：三闸、三判、证据落盘

- **背景**：契约第 4 节早就写好了闸门词表、17 张卡也各自声明了 `judge`，但**判定器一直没实现**——`docs/course/progress.md` 里那句「判定器（checker）未实现，因此『执行过』还不等于『已验证』」说的就是这件事。D25 把它落地。
- **决定一：判定是纯函数**。`src/runtime/checker.py::check(envelope, card, requirement, inputs, raw_text, host_map)` 不落盘、不调模型、不读时钟；IO 交给 `judge_call()`（读 `<call 目录>/envelope.json` + run 的 `inputs.json` + 原始产出）。理由：判定要能复跑、能进回归测试、能被第三方复核。
- **决定二：规则按卡片里的名字分派**，判定器只实现登记过的规则名；卡片声明了未实现的规则 → `uncertain` + 「卡与判定器漂移」。并用一条测试（遍历所有卡片）把漂移变成构建失败，而不是运行时才发现。
- **决定三：只有 `judge.gates` 里声明过的闸门阻塞**。声明了规则但不在 gates 里的（两张 session 卡）照样计算并写进结果，但 `blocking=false`——运行现场把「会话身份」这类观测留给需要它的节点判，不替节点下结论。
- **决定四：`freshness` / `target` 不过 = `uncertain`**（契约第 4 节口径），不判失败。marker 核对需要原始产出，拿不到也记 `uncertain`；目标对不上优先怀疑「名字↔地址对账缺口」（`--host-map` / assets 可解），不据此宣称事实为假。
- **决定五（顺带修掉一个真缺口）**：**信封此前没有落盘**——`run_skill_remote.py` 只把适配器 stdout 打到终端，`call.json` 里没有 `evidence` / `markers`，历史 run 根本无法复判。D25 起把信封写进 `<run_dir>/<call_id>/envelope.json`，`--check` 再写 `judgement.json`；旧 run 一律按「没有信封」处理（`uncertain` + note 说明），不假装判过。
- **决定六：`value`（true / false / null）与运行数据契约的 `records.kind=check` 对齐**，将来落库不需要再翻译一层。
- **证据**：`output/runs/D25-checker/call-20260916T021135-dd6fa5`（pass，节点 14，redis 6379 open）、`output/runs/D25-checker-neg/call-20260916T021213-44af65`（unsatisfied，3389 closed）；回归 `pytest -q` → **305 passed, 1 skipped**（新增 `tests/test_checker.py` 40 条）。
- **坑（记一笔）**：PowerShell 传内联 JSON（`--requirement '{"a": 1}'`）会被吞掉双引号，脚本报 JSON 解析错误——`check_common.py` 因此同时接受 `@文件` 与裸路径两种形式。


## 2026-09-16 D26 节点循环（loop）：决定表、重试/换卡边界与「产物即结论」

- **循环做成纯函数 + 注入**：`loop.decide(state)` 是一张写死的决定表（九行），`run_node` 只驱动它；
  执行（`attempt_runner`）与判定（judgement）都从外部传入。理由：验证 run 的控制流不允许模型参与，
  而注入让每一条分支都能离线测试（`tests/test_loop.py` 24 条）——模型的位置在「边内」，不在「边与边之间」。
- **`need` 是第三类停法**：缺运行现场值（`pending`）不算失败、也不执行任何命令，节点记 `blocked` 并报出缺什么；
  供给（会话/凭据/传输）是运行现场的事，不是该节点的方法问题。
- **重试给瞬时、换卡给方法**：`timeout` / `transport_error` 重试同卡（上限 `--max-retries`，默认 1 次）；
  `tool_missing` 直接换候选——「工具不在」不是能靠重试修复的东西。两种动作都会写进 attempts 轨迹。
- **节点结论取最保守**：任何一个尝试 `uncertain`（或没有判定）都让节点停在 `uncertain`，不写 `failed`；
  `failed` 只在全部候选都被 `unsatisfied` 证伪时出现。理由：未判明的方法可能才是能打的那个。
- **`node_result` 就是给运行数据契约的形状**：`status` 用 `node_runs.status` 的同一套词；
  `calls[]` 是证据锚点（每次尝试的 call 目录），`attempts[]` 是过程轨迹——落库时直读，不翻译。
- **退出码 = 节点结论**（0/1/2/3 = succeeded/failed/uncertain/blocked）：跟 checker CLI 同一哲学，管道消费不用解析 JSON。
- **run_node 允许「不连 VM 也能诊断」**：`SshExecutor` 惰性连接，`no_method` / `graph_gap` / `need` 三类结论
  在 select 之后就能得出，不发出任何命令（`D26-loop-node26-blocked` 是实测例）。

## 2026-09-16 D27 运行级路径循环：图定主线、供给补值、假设可追溯

- **决定一：run 是「顺序器 + 供给者」，不是第二个 planner**。决定表只回答「下一个走哪个节点」（provider 先行、
  effect 已证就跳、OR 事实一证即结算），每一步都能对回一行规则；「怎么打」仍留在节点循环的边内（模型将来
  可以进的位置是那里，本批仍未引入模型）。
- **决定二：前提是参考，不是闸门**（用户口径的落地）：provider 全部试过仍未证出事实时，下游节点**照常执行**，
  低置信记入 `assumptions[]`——洞没堵上既不会卡死路径，也不会消失在日志里，失败时可以顺着假设回看。
- **决定三：`getAccount` 型事实需要凭据背书**。节点跑完只给「工序完成」时，`getAccount` 不入库并记
  `unbacked-effect`；持有凭据时才由 `sweep_credentials` 直证。宁可少认事实，不把「dump 成功」当成「拿到账户」。
- **决定四：`identity_level` 不做 override**。原设计想用「max(图上 target_privilege, 现场 granted)」覆盖身份
  要求——语义未经实机暴露前不臆造；查证结果：全仓库只有 `remote_exec` 系卡依赖 `identity_level`，而节点
  38/48 的 `details.target_privilege` 均有值 ⇒ 不需要兜底。`granted` 只进运行状态与报告（追溯用），不参与判定。
- **决定五：供给是运行循环的一等公民**（会话 agent 的接缝）。v1 只接了「有 redis 服务事实的主机 → redis 写
  公钥建 SSH 会话（`restore=false`）」一条链；供给不了 ⇒ `blocked:need` + `needs[]` 记录，绝不假装值出现过。
- **决定六（两个真缺陷的修法）**：① OA 卡与判定器对 `command_output` 的证据形状理解不同 ⇒ 新增
  `wrapped_output_present`（完整 tag 对 + 区间非空），旧规则保留给 laravel / remote_exec 系；
  ② `call_marker` 取标签段导致 marker 漂移 ⇒ 改取 token 段 + checker 优先信 envelope 登记值。
  两条都补了回归测试（`pytest -q` → **365 passed, 1 skipped**）。
- **证据**：`output/runs/D27-path`（首跑，含 7 的首判失败与 2 的 graph_gap）、`output/runs/D27-path2`（复跑，
  含 `skip_node` 实例）；`check_call.py` 复判 pass 两条（`call-…f07418-include`、`call-…78cb76-include`）。
- **待办（显式清单）**：credential 自动供给链（dump → 外带 → 解析）、pc1 / web2 会话卡、节点 2 的图缺口
  （缺 `accounts`）、`planned` 卡是否进候选的选择器策略。

## 2026-09-16 D28 术语与契约工程化：一个词一个家、状态可执行、缺口会说话

- **决定一：领域词统一到 `skill`**。代码里早已没有 `ability/abilities` 标识符，但文案、文件名与提示语还没收口：
  新增[术语表](product/glossary.md)作为领域词的唯一口径（skill / card / knowledge / registry / index / case /
  provides / status / selection / need / supply / graph_gap / skill_gap …），`capability_retrieval_execution_flow.md`
  更名 `skill_retrieval_execution_flow.md`，代码提示语 `capability gap` → `skill gap`；`tests/test_terminology.py`
  守住这条线（机器面零容忍；当前契约页引用旧词必须显式标注「旧/历史/归档/v3」；历史文件的名字原样保留）。
  同时把 `scripts/vnc_console.py.bak_20260911` 迁进 `archive/tool_backups/`——备份属于归档区，不属于脚本目录。
- **决定二：机器契约瘦身，叙述归知识层**。`skill.json` 的 `notes` 定成 ≤200 字的一行指针（状态 + 证据锚点
  `call-…` + 去哪读），长叙述全部迁进同目录 `SKILL.md` 的「实测记录」；`implemented` 卡片必须有 `SKILL.md`，
  校验会核对。10 张超长卡片按这条迁移（内容零丢失，`git diff` 可核），registry 的 `note` 也从 814 字的批次叙述
  压成 4 句文件定位——批次叙述本来就有两个家（skill_matrix / validation_runs），登记源不该有第三个。
- **决定三：状态是执行语义，不是备注**。状态真源在卡片（`status`），索引提供派生视图（`by_status` / `status_counts`）。
  选择器默认只锁 `implemented`：`planned` / `deprecated` 不进候选，进 `excluded[]` 并在 notes 里点名；
  `--include-planned` 是显式逃生门，打开后候选仍带 `status` 供追溯。依据是实机基线：节点 22 之前锁的是
  `priv.privileged_container_escape`（planned）、节点 41 首选是 `cred.kiwi_lsass_dump`（planned，msf kiwi），
  而真正跑通过的是 `cred.comsvcs_minidump`——把未验证方法当计划，就是把「没验过」伪装成「要执行」。
- **决定四：case 召回的对象闸按端点判**。原来「技能声明了服务名就必须与节点服务名相同」会误杀：节点 2 写 `scm/445`
  （原 write-up 的方法），而为这个 case 写的 Windows-vantage 卡走 `smb/445` + `wmi/135`，被静默丢掉。
  新规则 = 服务名相同**或端口相同**即同一端点；跨端点的误召回照旧被挡（同一 case 下 `redis` 卡不会进 laravel 节点）。
  覆盖核对从「节点 2 → 1 条方法」变成 2 条方法，且仍 12/12 覆盖。
- **决定五：缺口要有名字，且分得清是谁的问题**。`run_result` 新增两个工作清单：`graph_gaps[]`（图上缺的事实，
  补图清单）与 `skill_gaps[]`（没有可选技能的节点，含被状态挡下的卡，补卡清单）；节点条目附 `selection`
  （locked / missing / excluded / notes）。运行不仅回答「哪一步没走通」，还回答「下一步该补什么」。
- **证据**：`pytest -q` → **376 passed, 1 skipped**；`build_skill_index.py --check` ok；`--graph --strict` 12/12 覆盖；
  真图选择基线（12 个 AND 节点）无一处锁到 `planned` 卡；本批不动靶场，故无新实机 run（VM 保持挂起）。
- **遗留（本批未做，仍在清单上）**：credential 自动供给链、pc1 / web2 会话供给卡——计划下一批与实机一起做。

## 2026-09-16 D29 方法链（chains）：链是数据、通道成资产、证据管道与按账号供给

- **决定一：链是数据**。第 13-15 条（dump → 外带 → 解析）此前只是「按顺序各跑一次」，D29 把顺序登记进注册表
  `chains`（`lsass_minidump`：`need=credential` / `case=lsass_system` / 三段），索引派生 `by_chain`，校验新增第 8 条
  （id 唯一、need 合法、段指向的卡必须已注册）。**段间绑定留在代码**（`src/runtime/supply.py`）并逐条配测试：
  「这一段的输出怎么变成下一段的输入」一旦静默，就是一条没人测过的假设。运行脚本里不再拼装顺序。
- **决定二：链自己会造的值不算节点的待补值**（真缺陷 A）。`parse` 段卡片要 `dump_path`，而 `dump_path` 正是链中段
  的产物 ⇒ 修复前节点被自己马上要造的值堵死。修法：`chain_dispatch` 声明 `chain_binds`，运行循环把这些名字从
  `pending` 里剔除；链真正缺的是**别人给的**东西（会话、接收端），那部分照旧问 `supply_runner`。
- **决定三：通道是运行现场资产**。卡片信封里的通道状态（`base_url` + `include_path`）由运行循环收进
  `state.channels[host]`（同一主机第一条胜出，绝不静默替换）；用之前先跑 `post.channel_echo` **复验**。
  D29 实机里节点 7 打出的 OA include 通道就是节点 41 链的执行位置来源——「曾经打通过」不等于「现在还通」，
  这条复验现在是程序动作，不是操作员记忆。
- **决定四：证据管道（真缺陷 C）**。适配器的观测在 `envelope.evidence`，判定只给结论；离线假 runner 曾把证据塞进
  `judgement`，把这层掩盖了 ⇒ 修：attempt payload 带 `evidence`，`supply.evidence_of` / `absorb_evidence` / 链的
  `_chain_result` 一律**优先读 payload evidence**，`judgement.evidence` 只作旧数据回落。测试改成真实 payload 形状之后，
  链的测试才真正有约束力。
- **决定五：凭据供给按账号点名核对**（真缺陷 B）。原实现只看节点绑定的那**一个**账号，而节点 38/48 实际要两个域管账号
  ⇒ 现在逐账号核对：`account_gaps[]` 记缺的账号（`<host>:<account>`），`needs[].why` 写明「the run holds: …」，
  部分覆盖就是部分覆盖。**同时不许猜**：凭据角色对不上时 `bridge_accounts` 只报「run 手里有 N 个人类账号、图的角色是 X」，
  绝不把 `bunny` 升级成 `domain_administrator`。
- **决定六：产物来源随链传递**（真缺陷 E）。`dump` 段 fold 时带出 `hostname`，`parse` 卡新增可选入参 `host`（runtime）
  并把 `hostname` 写进证据 ⇒ target 闸能对账「这份材料是从哪台机器来的」；没有来源就不造。
- **决定七：判定规则统一到 `wrapped_output_present`**（真缺陷 D）。laravel 卡的 `command_output` 是 between_markers
  切片（不含 marker），旧规则 `command_output_contains_call_marker` 对它的证据形状**永远判不出**；D27 只修了 OA 卡，
  这次把 include / exploit 两族统一，并把「只看到 marker 前缀 ⇒ `uncertain`（折行）」并进同一规则；旧规则从判定器
  退场（已无卡使用，卡里再写它就是漂移）。
- **决定八：段级超时下限**。dump 120s / exfil 900s / parse 300s（`supply.SEGMENT_TIMEOUT_FLOORS`），实际用的值写进
  `chain.trace[].timeout`：CLI 的 `--timeout` 是整次 run 的一个数，慢段（把 34 MB 从 Windows 搬出来）不该被它掐死。
  接收端由 run 起成 `--once` 的一次性服务，段后无论成败收尸。
- **证据**：`output/runs/D29-full`（首跑：host-map 缺口 + 28 撞 502）→ `D29-full2`（暴露缺陷 C：dump 段 pass 但链取不到
  产物）→ `D29-full3`（暴露缺陷 E：解析没有来源）→ **`D29-path`**（头条：节点 41 三段全 pass，`chain_done`；
  28/7/12/14/30 pass，19 skip；2 graph_gap、22 no_method、26 need、38/48 need 点名账号、37/47 or_unmet）。
  节点 41 三段 call：`call-20260916T033905-5f3d49`（dump，36,137,346 字节 MDMP）/ `call-20260916T033908-90b84a`
  （exfil，双边 sha256 `965e4999…` 一致）/ `call-20260916T033912-1685f1`（parse，`hostname=PC1`、
  `WHOAMIANONY\\PC1$` + `bunny`）；通道复验 `call-20260916T033905-73d95b`。
  `pytest -q` → **449 passed, 1 skipped**；索引 17 skills @ `7e0b527b7fc1` ok；靶场跑完四台全部挂起。
- **遗留**：web2 容器会话的供给卡（节点 26/22 卡在这里）、多 agent 编排（planner / verifier / session agent——`supply_runner`
  就是 session agent 的接缝）、节点 2 的图缺口（缺 `accounts`）。


## 2026-09-16 D30 容器会话供给卡（webshell via Laravel）· 通道声明 · 三个真缺陷修复

**背景**：D29 的遗留头条是「web2 容器会话供给卡」（节点 26 的 SUID 提权、节点 22 的容器逃逸都卡在「没有会话」）。
本批把这个缺口补上，顺手把运行循环里三处「会撒谎」的地方修掉，并用两次实机 run 把结论钉死。

**1. 新卡 `session.webshell_via_laravel`（`status=implemented`，2026-09-16）**

- 固定四步：`client`（把 `src/runtime/clients/agv_http_cmd.py` base64 推到执行端 `/tmp/agv-payloads/`）→
  `drop`（固定 Ignition PoC 写 173B 的 `popen($_GET['cmd'] . ' 2>&1')` webshell `/var/www/html/agv.shell.php`）→
  `probe`（判据调用：`<client> plain <base_url> /agv.shell.php "<marker 包住的 id -un; hostname>" <timeout>`，
  规则 `target_echo_present`）→ `restore`（仅 `restore=true` 时删 shell；默认 false，通道留存）。
- `provides: ["session"]`、`case: []`、`purpose: session`；payload 与 D24-c2 逐字节一致。

**2. 通道声明：`envelope.channel` → 运行状态**

- `adapter.envelope(..., channel=...)`：卡声明「我留下了一条可复用通道」——通道是**状态不是证据**；
- `session.channel_descriptor(value, host=)`：缺 id 时运行层按 `<host>-<driver>` 命名（卡不知道 run 管这台主机叫什么）；
- `run._absorb_supply`：`outcome.channel` → `state.channels.setdefault(host, ...)`（首个通道胜出，与节点信封路径同规则）；
- `run_path.channel_from_envelope` 优先读 `envelope.channel`（旧 OA markers 形状保留，D24/D29 记录仍可读）。

**3. 第三条 session provider：公开端点背后的容器**

- `build_supply_runner(..., include_planned=False)` 增加 endpoint provider：`published_endpoint_url(selection, logical)` 只在
  `selection.facts["target_execution_host"] == 目标图主机` 时给 URL；`webshell_session(...)` 先查卡状态（非 implemented 且未开
  `--include-planned` → blocked，理由点名卡名+状态），再 attempt；判据非 pass → blocked；无 channel → blocked。
- selector 侧：endpoint 解析时 `facts["protocol"] = assets 的 graph_protocol`，容器节点因此拿到 `target_url`（卡唯一的图输入）。

**4. 顺带修掉 D29 残留缺陷：provider 读错观测源（3 处）**

- 三个 provider 原从 `judgement["evidence"]` 取观测，而 checker 的 judgement 里根本没有该字段（D29-path 的
  `sessions[0].verified.identity=null` 就是现场证据）。统一改为 `observations(payload) = payload["evidence"]`。

**5. D30-path 实机首跑暴露三个缺陷（全部修复 + 回归测试）**

- **① target 闸不认容器身份**（node 26 uncertain_stop）：SUID 卡实机成功（uid 0）但观测 host=容器短 id `8e172820ac78`
  对不上节点 target（192.168.52.10 / http://…:81）。修法：运行层注入 `requirement.target_aliases`
  （`runtime_target_aliases`：仅当会话宿主登记的逻辑名 == 节点 `target_graph_host` 时，把会话自报的运行时身份补进要求；
  容器对宿主不算「同一台」——那要图的拓扑，不许运行层猜），checker `_equivalents` 并集。
- **② `--include-planned` 能悄悄替换节点的确定方法**（node 41 blocked:need(dump_path)）：planned 卡
  `cred.kiwi_lsass_dump` 被 selector 锁成 locked 后，运行层链判定（locked 须是链段）不成立 → 链不跑、binds 为空
  → parse 段的 `dump_path` 无人供给。修法：`supply.locked_chain(registry, selection)` —— case 注册了链时，链的
  第一个就绪段接管 locked；node runner 与 chain_dispatch 共用同一判定（`result.chain.locked` 记录实锁段）。
- **③ node 22（priv.privileged_container_escape, planned）如实不确定**：mount 段在容器内失败、`host_side_marker` 无观测 ——
  不在本轮修复范围；卡保持 planned（自述缺口=session_ref 表达不了容器内权限上下文）。

**6. D30-path2 实机（修复后重跑，带 --include-planned）**

- **node 26 succeeded**：三闸 pass（target 闸原文 "observed host=8e172820ac78 aligns with the node target"），
  **granted.web2_docker: www_data → root**；
- **node 41 succeeded / chain_done**：`chain.locked=cred.comsvcs_minidump`；三段全 pass
  （dump 36,337,890B MDMP / exfil 双边 sha256 `c581d11c…` 一致 / parse bunny + PC1$）；
- channels `{pc1, web2_docker}`；7/12/14/28/30 succeeded、19 skip；2 graph_gap、22 uncertain、
  38/48 need（点名 dc/pc2:domain_administrator）、37/47 or_unmet —— 与 D29 同口径。
- `pytest -q` → **481 passed, 1 skipped**（470 → 481，+11 条回归）；索引 18 skills ok。

**7. D30-path3 实机（卡转 implemented 后的默认路径，无逃生门）**

- node 26 succeeded（webshell 卡默认路径供给）、node 41 chain_done；**node 22 blocked/no_method**，
  理由点名 `held back by card status: priv.privileged_container_escape (planned)`（诚实缺口，回到 D29 决策）；
- 其余同 D30-path2；这就是「生产口径」的整图 run。

**8. 靶场清理与 VM**

- 脚本 `output/diag/D30/lab_cleanup_d30.py`：容器 shell 删除并 404 复核（200 → 404）/ Kali 三件（client、recv log、loot）/
  pc1（`agv_lsass.dmp` + `*.agv_oa.shell.png`）/ redis；**教训：node-context 的 cleanup 只复位 redis config、不删 key**
  （遗留 `agv_d29_key` 由清理脚本 DEL，DBSIZE=0）。四台 VM suspend（vmrun list → 0）。

**遗留**：node 22 的容器逃逸卡（缺「容器内权限上下文」表达）、节点 2 的图缺口（缺 `accounts`）、多 agent 编排（`supply_runner` 是 session agent 的接缝）。

## 2026-09-16 D31 会话权限上下文：一个词表、一条缺口、第四条供给（节点 22 实机闭环）

**背景**：D30 的遗留头条就是节点 22 —— `priv.privileged_container_escape` 在真靶场能逃逸（D24-c2 实测成立），但卡的
前提是「容器内 root 会话」，而 `session_ref` 只能描述「裸 www-data 通道」（`CapEff=0`，`mount` 被拒）。
缺的不是方法，是**权限上下文的表达**。本批把这个缺口补成三段：卡的声明（`min_privilege`）、选择器的缺口记录（`privilege`）、
运行层的供给（提权 provider），并用三次实机 run 钉死。

**1. 权限词汇唯一真源 `src/runtime/identity.py`**

- 三处问的是同一个问题，必须答得一样，否则会出现「选择器锁了卡、判定器又拒了它」：
  **selector**（这个会话够卡要求的等级吗）/ **run**（回来的比手上的强吗、该升级哪条通道）/ **checker**（identity 闸过不过）。
- 落成一份模块：`RANK`（报告序 `none<user<admin<system`）、`TIERS`、`REQUIRED_TIERS`（图/卡用的词 → 等级，`root` 与 `system` 同一级）、
  `tier_of(*candidates)`（账号名 / SID / `uid=` 见证 → `(tier, seen)`）、`satisfies(observed, required)`（**唯一的充分性判定**，
  含契约的 `admin ≡ system` 等价；`required=None` 不算通过）、`required_tier(requirement)`（依次看 `min_privilege` / `identity_level` / `target_privilege`）。
- 删除的重复：`checker.py` 的 `TIER_RANK` / `REQUIRED_TIERS` / `identity_tier()` / `required_tier()`、`run.py` 的 `TIER_ORDER`、
  `run_path.py` 的 `LEVEL_ALIASES` / `LEVEL_RANK`。checker 的 46 条测试全绿（行为不变，只是词表换了家）。

**2. 卡能声明等级：`session_ref.min_privilege`**

- `schemas/skill.schema.json` 的 `param` 新增可选 `min_privilege: user|admin|system`，**只对 `session_ref` 有意义**：
  卡说的是「我要多强的会话」，不是「我要哪个别的通道」。`priv.privileged_container_escape` 因此写上 `min_privilege=system`。
- 选择器的绑定规则：等级不够**或等级未知**都记 `pending` + `privilege` 记录（`{required, holds, identity}`）；
  **未知不当成够用**——`satisfies` 里 `none` 一律不通过。`pending` 仍然不算 `missing`：图缺口（图里没有这条事实）与
  现场缺口（事实在、只是不够强）两个口径不能混（D28 的「缺口会说话」的延伸）。

**3. 第四条 session provider：升级，而不是新开**

- `run_supply` 的判定顺序：**通道 + 等级缺口 → escalate；否则通道 → verify**；redis / webshell 两条不变。
- `escalate_session(...)` 交给 `session.root_via_suid` 一次 attempt，成功时交回「**同一条入口** + 提权包装 + 观测到的身份」：
  它不是漏洞利用的第二次登记，也不是新开一条通道——是把运行层已经握着的那条通道升上去。
- 状态政策与节点方法完全同一条：卡还是 `planned` 时默认 blocked 并点名卡名 + `--include-planned` 逃生门。

**4. 通道权限上下文与提权包装（`src/runtime/session.py`）**

- `session_ref` 多带 `identity` / `privilege` / `escalate` 三个字段；`channel_descriptor` / `with_privilege` 归一化：
  `privilege` **由 identity 推导**（两者不可能自相矛盾），畸形 `escalate` 丢弃（身份声明保留，等探针验）。
- `parse_session_ref`：声明了 `escalate` 却给不出可用 argv ⇒ **直接 `SystemExit`**。理由写进错误信息：
  「一条通道说自己是 root 却到不了 root，之后每一次调用都会变成谎话」。
- 五个驱动出口（msf `sessions -c` / agent `exec` / webshell plain / webshell include / `--plan` + 预览）统一：
  `wrap_command(escalate_command(command, ref), marker, ...)` —— **提权在里、marker 在外**：marker 证明通道回答了，
  卡自己要的 `user` / `host` 段落由提权后的 shell 产出。
- 通道登记规则随之改成 `_channel_upgrade`：**首个通道胜出，唯一例外是等级更高者接管**（同强不顶替——重复登记不是进展）。

**5. 运行层的两处「缺口要说清楚」**

- `_need_note`：`needs[]` 行可带 `privilege`（「值在、但不够强」可以直接被引用，不用翻日志）；
- `_with_seen_host`：通道本身只写地址与客户端，**不写对面自报的机器名**——那份拼写只在会话登记里（`session.host` / `verified.host`）。
  升级 provider 要用它做 `requirement.target_aliases`，理由和节点调用一样：target 闸比的是**观测**，不是图上的逻辑名。
  这条是本批唯一在首跑测试里被抓出来的缺陷（`KeyError: target_aliases`，487 passed → 1 failed → 修 → 488 passed）。

**6. 新卡 `session.root_via_suid`（D31 落，实机后转 implemented）**

- 固定三步：`find`（列 SUID）→ `probe`（现在的身份）→ `verify`（**判据所在调用**：经提权包装再问一次身份）；
- 包装固定成：把命令写进 `<helper_dir>/ps`，再 `PATH=<helper_dir>:$PATH <suid_binary>`——因为 SUID 程序以 root 运行时
  调用的是**相对程序名**（`ps`），PATH 决定谁被跑；helper **每次覆盖写**（命令内容随调用变化）；
- `judge.gates = [freshness, target, identity]`，`identity_rule = observed_privilege_at_least_node_requirement`；
  envelope 带 `channel = ref + escalate + identity`，evidence 带 `identity_before` / `session_identity` / `session_host` / `suid_binary` / `escalate_mode`；
- 边界：不判「这个身份够不够」（那是节点的事）、拒绝二次提权、找不到 SUID 就如实说没提权。

**7. 实机三跑（kali / Web 1 / Web 2 / PC 1）**

- **D31-path（回归口径，默认政策）**：与 `D30-path3` **逐行一致**（8 succeeded + 1 chain_done / 5 blocked，节点 22 = `no_method` 并点名 planned 的容器逃逸卡）。
  交接摘要里曾预期默认路径会变成 `blocked:need`——实测说明这条预期不准确：**没有可选候选就根本不会有 `pending`**，也就不会有 need 行。
- **D31-path2（逃生门口径）**：9 succeeded / 5 blocked，**节点 22 succeeded/done**。供给链两跳真跑：
  ① `supply-26` webshell 卡建立容器通道（www-data / host `8e172820ac78`）→ ② `supply-22` 提权卡（`call-20260916T045253-8698df`：
  `identity_before=www-data` → `session_identity=root`，三闸 pass）→ ③ 节点 22 本体（`call-20260916T045253-d27422`：mount 宿主根分区 + 宿主侧 marker 写读，
  `host_side_marker_present` pass）。`granted` 多出 `web2: root`。
- **D31-path3（生产口径，卡片转 implemented 之后）**：默认路径直接 **9 succeeded**，节点 22 `succeeded`——**不再需要逃生门**。
- 索引：19 条（13 行动 + 6 支撑）、`implemented 15 / planned 4`；`index check: ok`。

**8. 靶场清理（含宿主侧独立复核）与 VM**

- 脚本 `output/diag/D31/lab_cleanup_d31.py`：容器侧用**运行层自己的通道 + 与卡一致的提权包装**回去收尾
  （删宿主侧 marker → `umount /hello` → `rmdir` → 删 `/tmp/agv-esc` → 删 webshell → `HTTP_AFTER=404`）；
- Kali（loot 36.2MB / recv log / 两个 client）、PC1（`agv_lsass.dmp` + 三个 `*.agv_oa.shell.png`）、redis（`DBSIZE` 1→0，config 复原）；
- **宿主侧独立复核**（web2 `192.168.52.20` 直连，不经过容器）：`/tmp/agv_host_marker` 不存在、`/hello` 不存在、无 hello 挂载 ——
  D24 那次只在容器侧看，这次补上了宿主侧的一眼；
- 四台 VM 全部 suspend（`vmrun list` → 0，`vmware-vmx` 0 个进程）。

**遗留**：节点 2 的图缺口（缺 `accounts`）、节点 38/48 的凭据供给账号（等节点 41 的链产出域管凭据）、
多 agent 编排（planner / verifier / session agent —— `supply_runner` 就是 session agent 的接缝，D31 的提权 provider 是它第二个真实使用者）。

## 2026-09-16 D32 多 agent 编排（agent 层）落地：四角色契约、最小必要验证、干跑政策

**1. 分工为什么这么切（用户方向 3 + 三权分立）**

- executor 只做「打 + 取证」；verifier 只读复核（不碰靶场）；**「打之前能不能打」不归 verifier**，归最小必要验证
  （precheck，五类）；session agent 管会话账本 + provider 决策；orchestrator 只做顺序与记账。
- 这么切的判据：验证职责一分为二时，**能否打**的所有输入（图/运行状态/选择器输出）都在开跑前就绪，pure function 就能回答；
  而**打成没打成**必须在事后读证据。把两件事塞进同一个角色，裁决就会变成「猜」。
- verifier 不替代判定器：闸门仍是程序（`runtime.checker`），复核是在判定之上再写四行「这条链站不站得住」。

**2. 图定主线，LLM 只在边内**

- planner（`agents/planner.py`）是**图求值器**：调 `runtime.run.decide_run` 拿「下一步」，再翻译成 `StepSpec`；
  它只读图、不写图。新事实只能通过「改图 / 改对账表」进入系统。
- 「这条边怎么打」才是模型将来的地盘（当前是确定性规则 + 选择器）：输入输出已经固定成
  `StepSpec` / 四行复核 / `ProviderChoice` 三处，模型接进来不动内核。

**3. 最小必要验证（precheck）：五类、三模式、永不阻断**

- 五类：`reach`（真探针：执行主机上 `nc -z -w 3`）/ `service`（图声明，登记不探）/ `privilege`（逻辑：`identity.satisfies`）/
  `credential`（逻辑：账本比对）/ `method`（逻辑：候选与 `excluded`）。
- 三模式：`program`（唯一上线）/ `logic`（读状态）/ `graph`（读图）。三态：`ok` / `missing` / `unknown`——**不知道就写 unknown**；
  探针异常也记 unknown（`the probe failed: ...`），绝不写成 ok。
- 不阻断是 D31 定案的延续：前提是参考和追溯。`declared` 只标注「这条前提是图写的」还是「planner 派生的」。
- 为什么 reach 用探针而 service 不探：「端口通不通」一发 TCP 就能答，代价极低且与运行同视角；
  「漏洞在不在」只能由这次攻击自己回答，二次扫描既贵又引入新噪声。

**4. 复核四行 + 三值裁决 + 三个修复动作**

- 四行：`freshness`（证据是不是这次的）/ `target`（对的是不是这台）/ `identity`（身份够不够；无会话上下文写 `n/a`）/
  `effect`（效果出没出来）。
- 裁决：`go` / `repair` / `stop`。`repair.action` 只有 `retry` / `next_method` / `adjust_inputs`——**必须是循环能执行的**；
  其它一切（例如「升个权」）只写 `suggestions[]` 当建议文本，实际驱动留给 selector / supply 的等级缺口机制。
- 边界线：`retry` 只给 `timeout` / `transport_error`（网络的事）；其它执行失败一律 `next_method`（换方法，不空转重试）。
- `freshness` 失败 = **stop**：证据不是这一次的，没有「修一下再试」。

**5. 复核骑在 attempt 上**

- `loop.Attempt` 增 `review` 字段（`from_runner` 从 payload 读、`to_json` 写出），`next_method` 的理由带
  `_review_hint`（复核的 `repair.why` + 第一条 suggestion）。
- 理由：换方法的原因必须**由复核回答**，而不是事后从日志倒推。attempt 记录自己带理由，复盘才成立。

**6. 会话账本是视图，不是真源**

- `SessionRecord` 从 run 状态重算（`session_agent.ledger`），任何地方都不许把它反写回状态。
- `handoff` / `pivot` 是**计划**：能说「这条会话可以交给 msf 管」，不能说「已经迁过去了」。msf 迁移登记为
  planned 卡 `session.msf_migrate`（D46b 建卡在册；未实机），不假装。
- provider 决策（`choose_provider`）顺序固定五档：`escalate`（等级不够）→ `verify`（有通道先复验）→ `redis`（图声明 redis 服务）→
  `webshell`（容器经发布端点可达）→ `none`（如实说没有路径）。决策**先记账后执行**（`agent.providers[]`）。

**7. 干跑是默认，模拟必须标记**

- `run_agent.py` 默认 plan：走内存乐观模拟、写 `agent_plan.json`、每步 `simulated: true`、不建连不发包不写 state；
  `--live` 才真打（`--no-precheck-live` 可关掉线上探针，只登记）。
- 干跑的假设必须留痕，词表三条：`supply assumed for node N: <值>` / `supply assumed for node N: <host>:<user>` /
  `graph gap crossed at node N: the candidate misses <事实>`。
- 理由：一个 run 的价值在证据；干跑的价值在「开跑前就能看见每一步」——两者混在一起就都不可信。

**8. 证据与中间记忆分账；D32 不做长期记忆**

- 证据（`call*/` 里的 call/envelope/judgement/stdout/stderr/verdict）可以很细；中间记忆（StepSpec / 四行 / precheck 行 /
  provider 行）只留结论、理由、缺口名，不放原文——它要喂给模型。
- **决定：本阶段不做跨 run 长期记忆。** 跨靶场要复用的事实应该是**图上的事实**（或 `assets.json` / `host_ip_map.csv` 对账表），
  不是模型脑内的记忆。等真有需求时再讨论，免得先给系统一个会撒谎的「经验库」。

**9. 接缝怎么接（不改内核语义）**

- `runtime.run.drive_node / run_graph` 增**可选** `precheck_runner`：默认 `None` ⇒ 与 D31 行为逐字一致；给了才在 attempt 之前记录一次前置。
- `run_path.build_node_runner(attempt_reviewer=)`：有复核器时把 attempt 包一层，复核随 payload 走。
- `run_path` 里六段会话/供给逻辑（`_fact_rows` / `_service_row` / `_with_seen_host` / `held_channel` /
  `published_endpoint_url` / `planned_privilege`）**全部搬进 `agents/session_agent.py`**，`run_supply` 只留「怎么打」。
  理由：同一个决策不允许有两份实现——否则改了 agent 不改 run_path，就会出现「文档说的和跑的不是一回事」。
- `pyproject.toml` 的 packages 加 `agents*`。

**10. 本批验证（离线）**

- `tests/test_agents.py` 34 条（契约 / 规划 / 复核 / 会话 / 编排，全离线）；全量 **542 passed, 1 skipped**（D31 基线 508）。
- 真图干跑：`output/runs/D32-plan/agent_plan.json` = 14 步（11 `run_node` + 1 `skip_node` + 2 `aggregate`）、16 条 note、
  `walk stops: done_all`；节点 2 的 note 明确写出「跨过图缺口（缺 credential_ref）」。
- verifier 用真证据复核：D29-full3 节点 41 第三次 attempt（pypykatz 解析）→ 四行 `freshness pass / target unknown /
  `identity n/a / effect pass` → repair + `next_method`，聚合模式 `method_short`。

**11. 实机三跑（Kali / Web 1 / Web 2 / PC 1）**

- `D32-live`（首次接线）/ `D32-live2`（修缺陷 ① 后）/ `D32-live3`（修缺陷 ② 后，头条 run，46 秒）三跑结果一致：
  9 succeeded（含 1 `skip_node`）/ 5 blocked，**与 `D31-path3` 逐节点相同**；`granted`、凭据、`graph_gaps[]`、`needs[]` 全部一致。
- `agent` 段（`D32-live3`）：15 条决定、9 个节点 30 行前置、10 条复核（**全 `go`**）、5 条 provider 决策、8 个节点 `holds`。
- **两个真缺陷**：① `verifier.summarize` 把「全部 attempt 都 go」的节点标成 `method_short`（首跑 `D32-live` 暴露）；
  ② `reach` 前置对图里的端口字符串 `none` 也发探针，判成 `missing`（复盘 `D32-live2` 数据暴露）。两处都修了并各带回归测试（545 passed）。
- 清理：容器 200→404、Kali `KALI-LEFT-NONE`、PC1 `TEMP 1→0 / OA 1→0`、redis `DBSIZE 1→0`（config 复原）；四台 VM suspend。

**遗留（D32-h，未决）**：① 节点 2 缺 `accounts`（图缺口，需回图侧补事实并写明口径）；② 节点 41 的解析链在实机上只拿到
bunny / PC1$，没有域管材料（38 / 48 的 `need credential` 真根因），要么补解析能力，要么把域管作为**显式的运行输入**并在文档里写清来源。

## 2026-09-16 D32-h 节点 2 图缺口落地：就地改规则、显式运行输入，与两个真缺陷

D32-g 收尾时点名的两条输入侧口子，这一批处理完第一条、把第二条转成「显式输入 + 能力缺口记录」。

**1. 为什么改 `RULE 12` 的 body，而不是新增一条规则**

原计划是「新增一条 `interaction_rule` 包一层」。放弃它的依据是两条实证：① 本 MulVAL 构建里 `rule_desc(Desc, Priority)` 的优先级
**不被使用**（`grep -rni prior src/ lib/ kb/` 只命中 lexer 注释）；② 因此同一结论的两条规则会各自生成一个 AND 节点（`RULE 21` 在节点 7/19 两处、
`RULE 4` 多处为证），旧的「无凭据也能关防火墙」路径会继续留在图里。就地改 body 才能把它消掉。

改完的三个可核对结果：sha `615FF9BE…FB52 → 8DD7B85D…0D8F`（`generate_hongri7.ps1` 同步；frozen `rules5.P` 不动）、
三 profile `unmatched_and_nodes=[]`、v2 图 `input_edges 59→61`。**规则一变必须同步登记 case**：
`cases.py::_match_case` 要求节点前提签名多重集与 case 模式精确相等，否则节点会掉进 `unmatched_and_nodes` —— 所以新增 `disable_firewall_credentialed`，
并保留旧 `disable_firewall` 供冻结规则的三份图匹配。

**2. 编号位移是这一批最容易被忽略的工程事实**

MulVAL 节点号来自 `AttackGraph.txt` 导出顺序，规则体一变编号整体位移：**lsass 41→5、pc1→dc 横向 38→44、`execCode(dc,system)` 聚合 37→43**，
其余 10 个输出节点不变。所有硬编码节点号的测试同步更新，`FULL_ORDER` = `14,12,7,skip19,5,2,30,28,26,22,44,agg43,48,agg47`。
实测两种 body 顺序（凭据放最前 / 放最后）都拿不回旧号，按「与 T1021 及 fixture 模板一致」定稿为放最后。

**3. 为什么域管凭据走「显式运行输入」，而不是继续指望解析链**

节点 41 的解析链（`cred.pypykatz_parse`）在实机上只拿到 `bunny` 与 `PC1$`，域管明文的唯一证据是 2026-09-11 writeup 复刻的
`sekurlsa::logonpasswords`。两条选择：伪造一次解析成功（绝对不行），或把域管作为**显式运行输入**并在 `provenance` 里写清来源、
在 `assumptions[]` 里留痕。选了后者：它是诚实的，而且它让「能力缺口」这件事在运行记录里可见 —— 解析链拿不到域管这件事，本身就是待补的能力。
运行输入分两份：真实口令版留在 `data/inputs/hongri7/`（`.gitignore`），可提交的合成模板在 `data/samples/hongri7_run/`。

**4. 缺陷①：会话探针瞄的是节点目标，而不是通道宿主**（`D32h-live` 暴露）

现象：节点 2/44/48 全卡在 `need`，理由是 `observed target (session_host=PC1) cannot be aligned with the node target (target_host=192.168.93.30)`。
根因：`run_supply` 把 `selection.facts["target_host"]`（= dc 的地址）当作探针要求的 `target_host`，而一条通道的探针**只能观测到它自己的对端**（pc1）。
以前没暴露是因为 D32-live3 的节点 41 是同主机（pc1→pc1），通道宿主恰好等于节点目标 —— 这类「侥幸对齐」只有跨主机才现形。
修法：`channel_address()`（host map → 选择器已解析的 `facts.source_ip` → 调用方 fallback）+ `session_requirements()`（`target_host` = 通道宿主地址，
`target_graph_host` = 通道宿主逻辑名，只有运行层**已经观测过**的拼写才进 `target_aliases`），`verify_channel` / `escalate_session` 共用；
容器这类「自己没有地址」的宿主保留旧 fallback，不被这次修改波及。回归 +3 条。

**5. 缺陷②：交给卡的凭据里，登录名被图角色名顶替**（`D32h-live2` 暴露）

现象：节点 44/48 真跑起来后 `AUTH_RC=2` + 「未知的用户名或错误密码」——卡拿 `net use /user:WHOAMIANONY\domain_administrator` 去登录。
根因：`selector._credential_from_facts` 用 `facts["account_user"]`（MulVAL 的**角色名**）当 `credential_ref.user`，丢掉了凭据条目自带的登录名。
修法：`login = str((entry or {}).get("user") or user)` ——「条目自己声明的登录名优先，图角色名兜底」；图角色名仍然是 run 查表的 key，
`credential_entry` / `sweep_credentials` 的语义完全不变（所以旧测试里「条目不带 user」的用例仍然绑角色名）。回归 +1 条。

这一条的产品含义值得单独记：**「账户名」在 MulVAL 里是角色，在 Windows 上是登录名，两者不是一回事**。图上写 `domain_administrator`，
目标端只认 `WHOAMIANONY\Administrator`；把两者混为一谈的行为在离线干跑里完全看不出来（干跑只检查「有没有」），只有真机才会以「登录失败」的形式暴露。

**6. 本批验证**

- 实机三跑：`D32h-live`（卡在会话供给）→ `D32h-live2`（暴露凭据缺陷）→ **`D32h-live3` = `run: succeeded via done_all`（45.8 秒，exit=0）**，
  `graph_gaps=[]`、`skill_gaps=[]`，节点 2 实机 24.3s 拿到 `EnableFirewall=disabled`，节点 44/48 分别 8.9s / 9.0s 拿到 `hostname=DC` / `PC2` + 域管 SID；
- 域管凭据用 `crackmapexec` 独立核验过（dc / pc2 都 `(Pwn3d!)`），不是从文档抄来的假设；
- `pytest -q` = **549 passed, 1 skipped**；三 profile 图 `unmatched_and_nodes=[]`；索引 `--check` ok（cases 10）；
- 靶场清理 + 六台 VM 全部 suspend（`vmrun list` = 0）。

## 2026-09-16 D35-b：词表收口 —— 循环执行不了的修复动作不入词表（`adjust_inputs` 出列）

**问题**：`contract.REPAIR_ACTIONS` 写着 `retry` / `next_method` / `adjust_inputs`，而内核 `runtime.loop` 的决策表只有
`run` / `retry_run` / `next_method` / `done` / `_stop` —— `adjust_inputs` **没有任何分支消费它**。模型的裁决菜单由
`verifier.repair_options` 算：`adjustable` 为真（这一步声明了运行时依赖）时它就把这个动作摆上菜单，可循环里没人接 ——
模型选了它，跑法与选 `next_method` 完全一样（`has_alternatives=False` 时它甚至是空转）。这违反本仓的硬不变量
**词表只包含循环能执行的动作**（本文件 D32 节第 4 条写下过这条，代码却漂了），也让 `model.validate_prefer_repair` 的
报错文案（"is not one the loop can execute"）说了假话。

**定案：删掉 `adjust_inputs`，本版不提供「同一方法换一套输入」。** 依据是它在本架构里**没有可执行的语义**：输入值只有两个来源 ——
图事实（selector 绑定）与运行输入（显式 run inputs / 供给值），run 内部不存在「同一张卡换值重跑」的合法来源。三种看起来像这个动作的
情况各有各的家：① 卡绑不到图事实 → 已经是 `graph_gap`（图侧的活）；② 值后来才到手（凭据 / 会话被供给出来）→ 由 supply
重开节点接管（`runtime.run.MAX_REOPENS = 3`）；③ 运行输入本身写错 → 改 run 配置重跑，是 run 层的事。真要做这一手，要么让模型能写输入
（越出「边内」，破坏 D25 三权划分），要么造一条与 `retry` 等价的动作（假动作、假菜单）—— 两条都不做，把边界写清楚。

**做法**：
1. 词表**只留一份**：`agents/contract.py::LOOP_REPAIRS = {"retry": "retry_run", "next_method": "next_method"}`
   （动作 → 循环决策的映射写在契约里，而不是散在两处），`REPAIR_ACTIONS = tuple(LOOP_REPAIRS)`；`agents/model.py`
   不再自带一份，改成 `from .contract import REPAIR_ACTIONS`（两处各写一份正是这次漂移的温床）。
2. `verifier.repair_options` 去掉 `adjustable` 参数，菜单只由规则算出；`orchestrator._add_model_repair` 不再传
   `adjustable=spec.needs`。
3. 新增守线 `tests/test_agents.py::RepairVocabularyTests`（5 条）：词表同一份（`assertIs`）+ **每条都能被真内核决策表产出**
   （驱动 `loop.decide` 得到 `retry_run` / `next_method`，而不是断言两串常量相等那种自证）+ 菜单矩阵 ⊆ 词表 +
   `adjust_inputs` 已被 `validate_prefer_repair` 拒绝 + `prefer_repair` 的系统提示词只宣传词表里的动作
   （提示词也是菜单的一部分：写进去的动作，模型就会照着答）。

**同批修掉另一处真缺陷：provider 菜单是橡皮图章。** `session_agent.provider_options` 的文档说「每个前提成立的 provider 一行」，
代码却用 `if channel and not options` / `if not options and redis` 这类短路写法把关，结果菜单最多只有一个真选项 ——
模型接缝在 provider 上等于没得挑（`choose_provider` 只能选到规则本来就会选的那一个）。改成每条前提独立成行
（顺序仍是 escalate → verify → redis → webshell → none）：`strong channel + redis fact` 现在给出 `["verify", "redis"]`，
`weak channel + redis fact` 给出 `["escalate", "redis"]`。无模型时行为不变（仍取 `options[0]`），补 2 条菜单测试 +
3 条**内核级**模型接缝测试（真 `run_graph` + 假 runner：模型选的卡就是内核跑的卡；被拒答案与纯规则跑逐项相同；
模型选的 provider 就是内核供给用的那条）。

**验收**：`pytest -q` = **609 passed, 1 skipped**（604 + 5）；`build_skill_index.py --check` ok（19 skills @ a112377cda05）；
干跑回归 `output/runs/D35b-plan/agent_plan.json` 与 `output/runs/D35-plan/agent_plan.json` 的 `steps` / `notes` **全等**
（只有 `run_dir` 不同）—— 收口没动内核。

## 2026-09-16 D36：`purpose` 并入 `provides`；内核词表一表（`runtime/vocabulary.py`）

**决策 1：注册表不再有 `purpose` 字段，运行现场只认 `provides`。**

- 事实：`purpose` 与 `provides` 是**同一个词表**（`index_builder.PURPOSES = PROVIDES` 是别名），单值、强制 ⊆ `provides`，
  且**没有任何召回消费者** —— 运行现场模式只读 `provides`（`selector.find_providers`），`purpose` 只进关键词分词与形状校验。
- 危害有实证：`pre.nmap_tcp_probe` 把类别写进 `purpose` 却没写 `provides` → `select_skill.py --need reachability`
  一直报 `no registered skill provides 'reachability' (skill gap)`，而那张卡就在注册表里。同一个概念开两个字段，
  就会出现「字段按文档写了、运行期找不到卡」这类洞。
- 定案：字段删除；`pre.nmap_tcp_probe` 补 `provides: ["reachability"]`（它确实供给可达性事实，判据就是 `state==open`）；
  索引 `by_purpose` 派生视图退场，`by_provides` 成为唯一运行现场视图。
- 做法：`SKILL_FIELDS` 收成八字段；`schemas/registry.schema.json` 的 required / properties 同步；`validate_skill` 删去三条
  purpose 规则（其中一条「带 service 的支撑卡必须 purpose=reachability」本来就是 `pass` 占位、没有语义）；索引覆盖检查从
  「by_tactic + by_purpose」改为 `_index_groups`（`by_tactic` / `by_case` / `by_provides` **逐段查重** + 并集全覆盖 ——
  掉出所有召回段 = 永远召不到；旧写法允许段名互相重叠，还叫「duplicate ids across sections」，名实不符）。
- 验收：`pytest -q` = **616 passed, 1 skipped**；`build_skill_index.py --check` ok（19 skills @ 0a1b639c5a2c，
  counts `provides: 3`）；`select_skill.py --need reachability` 从「skill gap」变为召回 `pre.nmap_tcp_probe`（现场参数缺失时如实报 `missing`）。

**决策 2：内核词表一表（`src/runtime/vocabulary.py`）。**

- 词表写两处，就会漂：四个节点状态写两处；不完整状态集写两处 —— loop 与 checker **靠注释同步**；可重试集写两处
  （loop 与 verifier）。D28「一个词一个家」这次落到内核：调用状态 / 节点状态 / loop 动作 / run 动作四组枚举收敛进一个模块，
  `Decision.__post_init__` 在**构造点**校验动作词表（写错动作 = 崩在构造，而不是悄悄进产物）。
- 词表还有一条隐性契约：`NODE_ENTRY_ACTIONS`（进 `run_result.nodes[].action` 的全部词）必须覆盖 loop 与 run 两侧的发出点。
  `skip` 曾只出现在 run 层而 loop 词表没有它 —— 新词表用 `LOOP_ACTIONS + ("skip", "aggregate", "or_unmet")` 显式写清。
- 派生关系用测试钉住（`tests/test_contract_vocabulary.py` 7 条）：状态视图同一份（`loop.INCOMPLETE == checker.DEAD_STATUS
  == set(vocabulary.INCOMPLETE_STATUSES)`）；AST 扫描 `Decision(...)` / `_settle(...)` 的字面量必须落在发布词表内
  （新增动作只能从词表进）；`ib.GATES` / `checker.GATE_ORDER` / `skill.schema.json` 的 gates 枚举三方对齐；
  `ib.STATUSES` 对齐卡片 status 枚举；`ib.PROVIDES` 对齐 `registry.schema.json` 的 `provides` 与 `chain.need` 两处枚举；
  术语表指向该模块。

**决策 3：`abilities → skills` 审计结论（回答「abilities 是不是改成 skills 好一些」）。**

- 该改名已在 D28–D33 完成：机器面（`src` / `scripts` / `schemas` / `tests` / 卡片）与现行文档统一用 `skill`；
  `ability/abilities`、`capability`（当技能用时）、「能力注册表 / 能力卡」被 `tests/test_terminology.py` 四条规则拦下，
  旧工件在 `archive/legacy_v3_ability/`，历史词表见 `docs/product/glossary.md` §6。
- 本轮全仓复核：活跃面没有把 ability 当注册单元的遗留；命中只剩历史标记行、本文件的历史段与 Linux capabilities /
  reachability / vulnerability 这类别的领域词。**结论：命名已收口，不需要再改；`skills` 就是唯一口径。**

## 2026-09-16 D37：真机端到端跑模型接缝 —— 菜单闸门、空回答重试、退出码复核

**决策 1：三个接缝共用一条闸门 —— 菜单只有一行时不问模型。**

- 现场：`D37-live`（模型接缝首跑，真机整图 64.4 s）里 `choose_provider` 被问了 **5 次，菜单全是单选项**
  （`['none'] ['none'] ['verify'] ['webshell'] ['escalate']`），模型每次只能回答规则本来就会选的那一个 ——
  这正是 D35-b 点过名的橡皮图章，只是那次修的是**菜单构造**，闸门没补。5 次问答占 12.8 s
  （5 233 / 2 640 / 2 641 / 2 281 ms），信息量 0：规则算出的 `why` 本来就写在 provider 行上。
- 定案：`make_model_selector` 里的 `len(ready) >= 2` 是**三个接缝的共同规则**；`make_provider_chooser` 与
  `_add_model_repair` 补齐同一个闸门（`len(options) >= 2` / `len(available) >= 2`）。一行菜单是**被迫的选择**，
  不是模型决策；把它记成模型决策，报告就开始说谎。
- 验收：`D37-live2`（补闸门后、真机整图、带 `--include-planned`）provider 提问 **0 次**，节点结论与 `D37-live` 逐节点一致；
  新增 3 条测试（provider 单选项不问 / repair 单行不问 / 内核级：单行菜单下模型连问都问不到，`seam.report()["calls"] == 0`）。
- 不做的：在全被迫的菜单上「让模型给个理由」是解释功能，不是选择功能，本版不做。

**决策 2：`--include-planned` 下未验证卡可以拿走锁定（保持现状）；节点侧与供给侧不是一回事。**

- 现场（`D37-live2` 节点 2）：菜单两行 —— `evasion.netexec_firewall_off`（planned，召回键 technique+case）
  与 `evasion.wmi_firewall_off`（implemented，召回键 case）。规则把 planned 那张锁给了节点，
  模型被问到时也选了它（`accepted`）。内核真跑了它：attempt-1 `tool_missing`（rc=127，执行主机没有 `netexec`）→
  freshness 闸拦下（「命令没跑完，字节不算证据」）→ 循环换下一张卡 → attempt-2 的 implemented 卡 pass，节点 `done`。
- 为什么不改：召回键强度是契约里的排序规则（technique 命中先于 case 命中，D22）；`planned` 说的是「这条方法还没有实机记录」，
  不是「它更差」。逃生门打开时让未验证方法按它真实的召回归位竞争，正是拿到它第一条实机记录的唯一入口 —— 这次就是。
- 与 D30 的区别：D30 的缺陷 ② 是**链**被链外 planned 卡抢锁（链判定依赖 locked 是链段），修法是 `supply.locked_chain`；
  节点侧没有这种判定依赖 —— 锁哪张就判哪张，`status` 全程可见（`selection.json` / 模型菜单 / `agent.model.rows`）。
- 备选（不采纳）：排序上「implemented 恒先于 planned」。它会让逃生门在节点侧几乎失去意义（计划卡要等已实现卡失败才轮到），
  而那时的语义已经由 `alternatives`（失败换下一张卡）承担 —— 两层叠加等于把逃生门降级成重试。

**决策 3：空回答（推理模型把预算烧在思考上）= 可重试的传输故障；预算 900 → 1600。**

- 现场：`deepseek-v4-pro` 在真机跑里 7 次提问有 2 次 `content` 为空（`D37-live2` 的 model-004、`witness-prefer-repair` 的 model-001），
  两次都满足 `completion_tokens == max_tokens == 900`。A/B（同一 prompt、三档预算）：
  900 → 答（409 tokens）、1600 → 空（1600）、2400 → 答（317）—— 同一 prompt **概率性**复现，说明这是 provider 行为，不是提示词问题。
- 定案：`HttpModel.complete` 把空 content 当作可重试状态（与 429 / 5xx / 传输错误同一预算，最多 `--model-retries` 次）；
  判据串只有一份（`EMPTY_CONTENT_ERROR`），重试次数落在 transcript 的 `reply.attempts` 上。
  预算默认提到 `MAX_COMPLETION_TOKENS = 1600` 并新增 `--model-max-tokens`（零新依赖）。
- 验收：新增 2 条传输测试（第一次空、第二次答 → `attempts=2`；一直空 → 仍是被拒的答案且 `attempts=retries+1`）+ 1 条预算测试。
  实机：`witness-prefer-repair3` 的 model-002 `attempts=3` 恢复正常答案；model-003/004 连空三次 → **被拒 → 规则的动作照跑**（`ran_from_rules=2`）。
  修完后用同一 prompt 连打 3 次：3/3 答，completion 285–565。

**决策 4（复核，不是改动）：`run_agent.py` 的退出码 = 运行结论，`succeeded` → 0。**

- 代码：`EXIT = {"succeeded": 0, "failed": 1, "uncertain": 2, "blocked": 3}`，`return EXIT.get(status, 3)`。
- 复核：plan 模式同一张图 `$LASTEXITCODE=0`；`D37-live2` 真机跑 `EXITCODE=0`（`succeeded/done_all`，stdout 重定向到文件）。
  D37-live 期间观测到过一次「退出码 1 而 run 是 succeeded」，**本 turn 复现不出来**；按未复现的观察记录，
  并把复核入口写死：真机跑完显式 `"EXITCODE=$LASTEXITCODE"`（stdout/stderr 都重定向到文件再回读）。
- 顺带复核：`run_result.nodes[].skill` 恒为空**不是回退** —— `D32h-live3` 同样为空。方法名在三处：`reason` 前缀、
  `attempts[].skill_id`、`node-<id>/selection.json` 的 `locked`。

**本批回归**：`pytest -q` = **622 passed, 1 skipped**；`build_skill_index.py --check` ok（19 skills @ 0a1b639c5a2c）。


## 2026-09-16 D38：运行输入契约与体检入口 —— 输入包独立成层，用运行同款 loader 判

**决策 1：输入包放进独立的 `src/inputs/`，不塞进 runtime / skills。**

- 依赖方向现状：`skills → runtime` 已存在，且 runtime 全层不 import skills（已核对）。体检要同时用
  `skills.selector` 的 loader、`runtime.chain` 的 hop 词表、运行入口的 `@path` 口径 —— 塞进任何一层都会反向依赖或制造环。
  `inputs → {graph, skills, runtime}` 单向无环，是唯一干净的位置。
- 落地：`src/inputs/bundle.py` + 薄壳 `scripts/check_inputs.py`（与 `build_skill_index.py` 同一姿势）；
  `pyproject.toml` 的 `include` 加 `inputs*`；入口守线（`test_project_layout.py` 的「换目录也能 `--help`」清单）把它收进去。

**决策 2：体检必须用运行自己的 loader，不另写解析。**

- 理由：本项目反复吃过「两个实现漂移」的亏（覆盖核对 vs 选择器、词表双字段）。体检若自带一套 CSV/JSON 解析，
  最坏情况正是「体检全绿但运行读不到」，那比没有体检更糟。
- 做法：`selector.load_assets` / `selector.load_host_map` / `chain.HOP_KINDS` / `load_json_argument` 的 `@path` 口径**直接引用**；
  体检只**加**运行没有的检查（地址合法性、引用完整性、跨文件对账、模板值、`provenance`），不改读法。

**决策 3：把「输入契约」与「技能覆盖」分开，体检不假装能证明攻击可打通。**

- 体检全绿只说「运行会按你以为的方式读到这些文件」；第二靶场干跑里的 `method.candidates = 0` 说明的是技能面缺口。
- 所以退出码只有 0/2/3 三态，没有「通过但危险」这种模糊态；`--strict` 让接入新靶场时把每条 warn 变成决定
  （模板值、多网段挑址、表头口径这一类的 note 必须在接入时被人看过一遍）。

**决策 4（发现，记录但不改码）：同名 `host_ip_map.csv` 两个消费方两套表头规则。**

- `selector.load_host_map`（run 与判定器）无表头概念 → 表头行会变成 `host -> ip` 的幽灵映射；
  `graph.host_identifiers.load_mapping`（转换工具）要求首行正好 `host,ip`。
- 本版**不改 loader**：改了就同时得说清转换工具那条路的兼容与迁移，而现实里两个消费方各拿一份表是可行的。
  体检对表头行报 warn 并把两条规则写进契约 §2.3（含「给 --host-map 的那份不写表头」）。

**证据**：`docs/product/validation_runs.md` 的 D38 节 —— 红日 7 六输入全绿（6 ok / 0 warn / 0 error）、
第二靶场 `data/samples/lab_demo/` 干跑 3 步且地址解析正确、故意打破的整包读数 4 error / 5 warn / EXITCODE=2。
回归：`pytest -q` = **653 passed, 1 skipped**（622 → 653，新增 31 条；`build_skill_index.py --check` 不受影响）。

## 2026-09-16 D39：B 路线闭环（目标状态）+ 账本键名缺口 + 术语守线边界定案

**决策 1：域管能不能从 dump 里读出来，是「目标状态」问题，不是「方法」问题 —— B 路线已证。**

- 做法：dump 之前让域管在 pc1 控制台做一次**交互式登录（Type 2）**，其余一切不动（技能卡、图、复现命令口径全不改），
  重跑整图 = `output/runs/D39-live1`。
- 读数：`node-5/attempt-3-cred.pypykatz_parse/call-20260916T082601-663b1e/` 的 `stdout.txt` 出现
  `username Administrator` / `session_id 2` / `logon_server DC` / SID `…-500` / `WDIGEST password Whoami2021`；
  对照两次 dump 都在的 `bunny` / `PC1$`，唯一自变量就是这条交互式会话。
- 口径不变：**运行默认仍走 A**（域管凭据是显式运行输入，`provenance` 指向 writeup 复刻）。
  B 只证明「有交互式会话就有域管」；这与 D34 的「目标状态缺口」定案相容 —— 当时定性是对的，D39 补的是场景。
  这条在 `skill_backlog.md` 第 1 条记闭环，不再挂「待补」。

**决策 2（本轮抓到的真缺口）：凭据账本的「角色键 ⇄ 登录名」之间没有登记映射。**

- 现象：D39-live1 的 `credentials[]` 已经有 `Administrator`（`source: "node 5"`、`has_secret: true`），
  节点 2/44/48 仍报 `blocked/need`，原文 `the run holds no usable credential for dc:domain_administrator; … the run holds: Administrator, PC1$, bunny`。
- 根因（已定位到代码）：显式运行输入把凭据存在**图上的角色键**下（`run_context.domain_admin.json` 的
  `credentials.domain_administrator.user = Administrator`），供给查找按同一个键；而 `run.absorb_evidence` 只按**登录名**入账
  （`Administrator` + `WHOAMIANONY\Administrator` 别名），查找 `domain_administrator` 对不上。**不是凭据不存在，是两个名字之间没有映射登记。**
- 定案照旧：`run.bridge_accounts` 明确**不猜**这种映射（猜 = 把「手里有个账号」升格成「手里有这个权限」，D24-c 拒绝过的伪证据），
  D39-live1 的 `assumptions[]` 里那条 `kind=bridge`（node 5，`pc1:domain_administrator`）就是平台自己点出来的。
- 下一步（运行层，不在技能卡范围）：运行输入里**显式**登记 `domain_administrator → WHOAMIANONY\Administrator`
  （等价于现在 A 路线的动作，只是把材料来源记成「链产出」）。落地前，B 路线闭环的准确表述是
  **「环境前置成立 + 解析链能读出域管」**，不是「凭据自动供给已闭环」。
- 证据：`docs/product/validation_runs.md` 的 D39 节 §4（三条 blocker 原文 + bridge 假设原文）。

**决策 3：术语守线（abilities → skills）的覆盖边界定案。**

- 审计读数（用 `tests/test_terminology.py` 自己的规则复跑）：**机器面 167 个文件命中 0**；
  **现行契约页（`docs/product` / `docs/course` / `docs/plans` / `file_tree.md`）未标历史的命中 0**。
  残余命中全部落在有意保留历史的位置：`docs/decisions.md`、`docs/product/reference/v0.1|v0.2-detailed/**`（冻结基线）、
  `tests/test_terminology.py`（守线自己要点名旧词）、`docs/product/glossary.md`（定义词）、`archive/**`。
- **边界是有意的，而且现在可执行**：`current_contract_docs()` 用非递归 glob，`docs/product/reference/**` 不在守线内 ——
  那是 v0.1 / v0.2 的冻结基线，每个版本目录的 README 自己声明「历史设计」。新增
  `test_reference_baselines_declare_themselves_as_history`：基线 README 少了历史声明就红，避免「排除」变成本来就不该有的口子。
- 顺手修掉现行页面的过期陈述（D39 证伪了「leaf 不成立」的绝对说法；编号位移见 D32-h 第 2 条）：
  `docs/product/skill_matrix.md`（方法链那条待办 + 链表 + parse 段行）、`docs/product/skill_contract.md`（实机验证第 6 条 + 链小节标题 + `case` 字段说明）、
  `README.md` 第 5 行（现行状态句里的旧编号）、`docs/product/validation_runs.md`（D24-c 加 D39 指针 + 缺口表两行 + D39 节 §4）、
  `skills/registry.json` 的链 `note`（改按节点角色称呼，不再写死编号）。
- 跟随动作：`skills/index.json` 按注册表源摘要重建（`build_skill_index.py`，只动 `source_sha256` 两行）。

**回归**：`pytest -q` = **654 passed, 1 skipped**（653 → 654，新增守线 1 条）；`build_skill_index.py --check` = ok（19 skills @ `0e1bdb3e01fe`）。

## 2026-09-16 D40：账户别名输入（运行输入侧）+ 防火墙转变证据 + 两条 kali-vantage 备选卡转正

**决策 1：`account_aliases` 进运行输入；映射由操作者显式给出，平台继续「不猜」。**

- 背景：D39 §4 的账本键名缺口（图上槽位是角色键 `domain_administrator`，链产出按登录名 `Administrator` 入账）。
- 定案：不做任何形状的自动推断（不做「唯一候选自动认领」、不做后缀 / 大小写近似匹配）。新增运行输入字段
  `account_aliases: {<角色键>: {user, domain, provenance, note?}}`：`provenance` **必填**（缺了就是 error），
  可以只声明映射、不带 secret —— 材料仍要由运行现场产生。
- 生效方式：`run.materialize_account_aliases` 把已持有的登录名条目**复制**到角色键下（带 `bridged_from` / `alias_provenance`），
  并记一条 `kind=alias` 假设；已登记过就幂等跳过（不重复记假设）。`run_result.account_aliases[]` 报 `target_held` / `filed`，
  让「声明了但材料没到」在产物里看得见；`bridge_accounts` 在那种情况下改说「operator declared X -> Y but the run holds nothing
  under that login yet」。
- 兜底：`run_result()` 是**唯一出口**，进报告前再 materialize 一次 —— 无论 run 是 `done_all` 还是 `aborted` / `unsupported`，
  报告里的别名行不会落后于账本。
- 证据：D40-live1 / D40-live2 两跑，节点 2/44/48 从 `blocked/need` → `succeeded/done`，`blockers: null`，`graph_gaps` / `skill_gaps` 空。

**决策 2：方法卡判据里的「状态证据」与「转变证据」分开写。**

- `evasion.wmi_firewall_off` 的 effect 闸是 **state-only**（卡片自己声明 `no change claimed`）：
  它证明「调用之后是关的」，不声称「是它关的」——判据必须能从证据里读出来，这条不改。
- 但 D40-live1 里 DC 的防火墙在 D24-e 就已经被关掉 → 那次读数**不构成转变证据**。补法不是改判据，而是**改靶场初始状态**：
  D40-live2 前先把三个 profile 恢复成 `0x1`，于是同一次 call 的 stdout 里 before=`0x1` / after=`0x0` 两段都在（目标自己回显）。
- 定案：凡是「关掉 / 打开某状态」的方法卡，复验前都先恢复初始状态再取证；这条口径写进 `validation_runs.md` D40 节 §4。

**决策 3：备选卡的「实机跑通」标准不放宽；路上抓到的缺陷按缺陷处理。**

- 两张 kali-vantage 备选卡在 D40 各拿到一条三闸全过的实机 call → `planned → implemented`（19 条里 17 条 implemented）。
- 顺带修掉三个真缺陷：① impacket 无 `-p`（歧义前缀，解析阶段退出）→ 新增共享 `runtime.adapter.impacket_arguments`；
  ② wmiexec 的 `&` 链重定向只覆盖链尾 → 探针自带一层 `cmd /c "..."`；③ 交互式 shell 的 `\x08` 遮住 marker →
  共享 `split_sections` 的**标记判定**容忍 C0 控制字节（内容不动）。
- `evasion.netexec_firewall_off`（netexec 版）仍 `planned`：前提是控制点有 netexec，而 PyPI 上没有该发行版（404）。
  缺口写清楚，等环境具备再验 —— 不为了让状态好看去改方法。

**决策 4：两条靶场事实入库（旧记录与新读数冲突时以新读数为准，并改正旧注释）。**

- D24-e 记的「Kali 到不了 192.168.93.0/24」在 D40 实测**不成立**：kali → dc / pc2 的 445 与 135 都通（`output/diag/D40/d40_reach.json`）。
  默认路径的锁定因此不能用「可达性」当理由 —— 锁的是**图里的 source 门**（node 2/44/48 的 source = pc1）与注册表顺序；
  `tests/test_selector.py` 里那两行旧注释已按这条改正（断言不变：锁定仍是 `wmi_process`）。
- pc1 与 DC 的**安全通道断裂**：域管凭据打 pc1 的 SMB 回 `STATUS_TRUSTED_RELATIONSHIP_FAILURE`；这与 D39
  「AD 里 pc1 的机器账号是补建的」互证。对整图复验无影响（pc1 的执行位置走 OA 通道，44/48 的认证目标是 dc / pc2）。

**决策 5（离线批）：术语守线扩容 + 索引换行确定性。**

- 守线从「非递归扫描 + 显式白名单」改成**递归扫描 `docs/` 与 `data/samples/`**，唯一豁免清单
  `HISTORY_SURFACES = ('docs/decisions.md', 'docs/product/reference', 'archive')`；新增两条守线：豁免面必须存在 +
  每个豁免面 README 自己声明历史。全仓 105 个 md 审计：豁免面之外 **0** 未标历史命中（脚本 `output/diag/D40/scope_probe2.py`）。
- `skills/index.json` 的换行由构建脚本定死（index 与 report 两处 `newline="\n"`），连跑两次 sha256 稳定 → git 不再有幽灵 diff。

**回归**：`pytest -q` = **672 passed, 1 skipped**（667 → 672：别名出口、agent 别名断言、`impacket_arguments`、psexec argv、splitter 控制字节）；
`build_skill_index.py --check` = ok（19 skills @ `0e1bdb3e01fe`，`status_counts = {"implemented": 17, "planned": 2}`）。

## 2026-09-16 D41：netexec 版关防火墙卡转正 —— 回读改走注册表（语言无关）

**决策 1：回读证据从「本地化文本」改成「注册表值」。**

- 背景：中文 DC 的 `netsh advfirewall show allprofiles state` 输出经 smbexec 到达是 cp437 乱码（`╫┤╠¼ ╣╪▒╒`）；
  按「状态 / 关闭」字面匹配的解析会**静默失手** —— 证据看得到、判定读不出，比报错更危险。
- 定案：readback 固定走 `reg query ...\FirewallPolicy /s /v EnableFirewall`，`EnableFirewall REG_DWORD` 的 `0x0/0x1`
  与系统语言无关；判定口径不变（三 profile 全 `0x0` 才算 `disabled`，读不到记 `uncertain`）。
- 回归锁死两条：注册表读数判定 + 「本地化文本不进判定」（含 cp437 乱码样例）。

**决策 2：转变证据按 D40 §4 口径执行（先 rearm、再取卡读数）。**

- 跑卡前先把 DC 三 profile 复位 `0x1`（`output/diag/D41/rearm_run.txt` 留读数），卡 apply 后 readback 读到 `0x0`
  （`call-20260916T093251-5a540f`）——「开 → 关」两段证据留档；apply 段只记录、不判定（可能只是幂等重放）。

**决策 3：netexec 装法只写进卡片 SKILL.md；边界如实留档。**

- 可复现路径（codeload tarball / dunamai 需 git tag / 删 4 条 `git+https` 依赖 / 清华镜像 + `--no-deps` / aardwolf 跳过 /
  `dploot<4` / user 级 `pyOpenSSL>=24` / `/usr/local/bin` 软链）全部落在
  `skills/evasion.netexec_firewall_off/SKILL.md`；validation_runs 只留读数与指针。
- 边界：rdp/vnc 协议因跳过 aardwolf 不可用；SMB 链路完整（与仓库现有技能无关）。

**决策 4（收尾实测）：`--exec-method smbexec` 对复合命令（含 `&` / `2>&1`）取不回输出。**

- 收尾复查残留时实测：`cmd /c dir ... & echo ...` 与 `sc query ... 2>&1` 经 netexec smbexec 均报
  `Could not retrieve output file`（单命令、无重定向的 `netsh` / `reg query` 正常）。这不是目标故障：换 impacket
  wmiexec 通道即取回（`output/diag/D41/final_state3.txt`）。
- 口径：本卡的固定命令（netsh / reg query）不受影响；**检查类复合命令不要走 netexec smbexec**，走 wmiexec 系工具。

**回归**：`pytest -q` = 672 passed, 1 skipped（D41 刷新 3 条防火墙适配器测试，总数不变）；
`build_skill_index.py --check` = ok（19 skills @ `0e1bdb3e01fe`，`status_counts = {"implemented": 18, "planned": 1}`）。

## 2026-09-16 D42：审计收口 —— OA 卡粒度定案（不拆）+ restore 清理回合 + lab 清理补口

**决策 1：OA 卡不拆（定案，驳回「拆成上传/包含两张卡」的倾向）。**

- 反方（拆分）论据是「一条技能 = 固定验证方法」的狭义解读；本方证据更强：① 契约第 10 节把「先上传再包含」明确列为
  合法多步固定过程（多步只认主调用判定）；② 红日 7 图 14 个节点里没有「文件上传」语义的独立边（逐节点 case_id 实测），
  拆出的上传卡对图没有覆盖价值；③ 拆分**不改变运行层行为**（一条链仍是一次选择 + 一次运行，观测取最后一段），
  却要新增 supply 段角色 + 绑定 + 测试、两张卡各自实机复验、改契约范例——成本是实打实的，收益只是语义纯度。
- 触发条件写进 `skill_matrix.md`：当某个图的边需要独立「文件上传」或「OA 登录态」能力（对应 case 的节点出现）时，
  再从本卡拆出独立卡 + 链；材料现成。**不为假想需求建模，但为拆分留好判据。**

**决策 2：给 OA 卡补 `restore` 可选清理回合（默认 false），对齐既有先例而非新发明。**

- 现状是真缺口：本卡每次跑都在目标 `C:\MYOA\attach\im\<YYMM>\` 落一个 webshell，卡片自身没有任何清理手段
  （历次靠 lab 脚本外清）。`session.webshell_via_laravel` 的 `restore`（默认 false）与 redis 卡的 `cleanup`
  是现成先例；本卡按同款契约落：`restore=true` 时主调用证据照旧、随后经同一通道删除落盘文件、`markers.restore_status`
  记 `gone`/`failed`/`unknown`、**markers 不写 `include_path`**（文件已删，`channel_from_envelope` 就注册不出通道——
  这正是「通道留存是资产、证据运行不留通道」两种意图的分流）。
- 删除命令必须绕开通道 `addslashes`（路径满是反斜杠）：UTF-16LE base64 -> `powershell -nop -EncodedCommand <blob> < nul`
  （同 D24 绕行方案）；路径用 `stored_windows_path()` 从 include URL 折叠 `.`/`..` 后拼 `web_root`（默认 `C:/MYOA`）。
- **实机读数**：默认批两跑 pass；restore 批 `AGV_RESTORE_GONE`（目标侧 Test-Path 自检）+ 独立 probe 对照（已删无回显、
  存活有回显）——「包含自己时删除自己」成立。

**决策 3：lab 清理脚本补口（`output/diag/D31/lab_cleanup_d31.py`）。**

- kali 步原来只按名删 `agv-payloads/agv_oa.shell.png` + 客户端，`agv_oa_http.py` 与目录本身无覆盖（D41 手工清过）；
  改为整目录 `rm -rf /tmp/agv-payloads` + 验证行同集合。pc1 步的 `C:\MYOA` 扫描保持不变（D42 实测覆盖有效：2 → 0）。
- 长期化（把脚本挪进 `scripts/`）不在本轮范围；触发条件：lab 维护脚本再次因为 gitignore 丢版本语义时。

**决策 4：两条操作纪律（写死）。**

- **给 authorized_keys 写 key 必须走卡（argv 直传），不要手搓经 shell 的 `redis SET` 值**：换行/引号多层引用不可靠
  （D42 实测手搓自举失败、卡一跑就通）。卡内 `restore=true` 路径本轮首次实机（verify + 拆除三步全执行）。
- **PowerShell 管道的 exit 读数不作为判定输入**：D42 首跑 shell 显示 `Exit code 1`，但 `judgement.json`=pass、
  离线复判=pass、重跑=EXIT 0——判定结果三通道一致；读数异常如实记录（validation_runs D42 §6），不掩盖、不据它改代码。

**回归**：`pytest -q` = 675 passed, 1 skipped（+3 条 restore 用例）；`build_skill_index.py --check` = ok（19 skills）。

## D43：msf 车道改用常驻端点（会话是进程内状态）

**背景**：`cred.kiwi_lsass_dump`（kiwi）与「凭据建会话」都要在 meterpreter 会话里执行，而旧的 `msfconsole -q -r <rc>` 驱动一次调用一个进程——
会话是进程内状态，上一次调用建的会话，下一次调用看不见。

**决策 1：常驻 msfrpcd 端点 + 固定客户端 `runtime/clients/agv_msf_rpc.py`。**

- 协议：HTTP POST `<url>`，`Content-Type: binary/message-pack`，body = msgpack `[method, *params]`；回复里的字符串以 bin 到达，客户端统一解码
  （`strict_map_key=False`）。子命令：`session-list` / `session-run` / `session-script` / `exploit-run`；`--*-b64` 只为穿过多层引用的 argv
  （**密码不走 `--options-b64`**：base64 藏掉子串，redaction 会失效）。
- `msfrpcd -S` 在本版是 **Disable SSL**（`msfrpcd -h` 原文），端点跑明文 HTTP，客户端默认 URL 也是 `http://…`；拿 https 探它只会「超时」——
  D43 曾据此误判「端点挂死」并重启，复核后确认是探针错协议（更正与台账见 `validation_runs.md` D43 节）。
- 端点会话随进程消亡：重跑/重启即清零；本车道只负责「建 + 探针」，保活与迁移另说。

**决策 2：`exploit-run` 的判据——不认 `result`，也不认 `job_id`。**

- 成功回复 `{"job_id": N, "uuid": ...}` **没有 `result` 键**；`job_id` 只是信息量（实测成功建了 3 个会话却回 `job_id 0`，`job.list` 为空——
  跑模块的 job 已结束，会话活得比 job 长）。失败回复是 `{"error": true, "error_class": ..., "error_string": ...}`。
- 判据 =「回复无 error」+「新 sid 的 `exploit_uuid` == 回复 uuid」。**为什么按 uuid 认领**：复用过的靶场里，上一次运行留下的 payload
  会在新 handler 起来时自己重连，只看「窗口内多出来的 sid」会把别人的会话记到自己账上；旧端点不报 `exploit_uuid` 时退回窗口口径（stderr 写明规则）。

**决策 3：msf 驱动 = meterpreter 命令通道（`runtime/session.py` 的唯一例外条款）。**

- meterpreter 没有 shell 可回显 marker：新鲜度改由读协议满足——客户端「先 drain 会话积压 → 读到输出静默（`--idle`，默认 2.0s）」，全局仅此一处例外。
- 控制台行只认 meterpreter 自己的命令（`sc query` 会得 `[-] Unknown command`）：**shell 命令卡走 agent/webshell 通道**，不指望这条车道兜底。

**决策 4：间歇性失败不藏在卡里。**

- psexec 在本靶场实测 2/5 次 `Login Failed: closed stream`（真因在 `~/.msf4/logs/framework.log`，不在 RPC 回复里），同进程稍后重试即通。
- 卡保持「无新会话 → 不登记通道 + observations 写清」（judgement `uncertain`）；**重试属于 run 层**（编排按图再发起一次）——
  卡里偷偷多打几发会把「一次调用的证据」与「目标此刻的状态」搅在一起。

**决策 5：kiwi 表格列按表头偏移切片（实测缺陷的第二版修复）。**

- 真 transcript 上第一版修复仍错：按**分隔线宽度**切列 → `Administrator` 读成 `Administ`、secret 读成 `ab89`。
- 根因：kiwi 是左对齐定宽表，分隔线 dash 数 = **表头词宽**（`LM` 下面是 `--`）而非数据宽；且机器账号 LM 单元格为空，空白分割会让 NTLM 顶进 LM 列。
  口径定稿：列起点 = 表头词起点，区间 = [本列起点, 下一列起点)，末列到行尾；分隔线不参与解析（frag7 清理时删掉原先的词数交叉校验——冗余第二道闸）。
- 测试样本改由 `kiwi_table()` 生成器产出（列宽 = 该列最宽单元格、2 空格分隔、分隔线 = 表头词 dash 补空格到同偏移），
  手工空格对不齐这类错误不再可能混进样本；解析器另配真 transcript 断言脚本（`output/diag/D43/verify_parser.py`，10 条断言全过）。

**决策 6：node-5 的首选方法换成 kiwi 卡（状态转换的语义后果）。**

- 注册表顺序即优先级：kiwi 卡一直在 comsvcs 链之前，但此前是 `planned`、被状态政策挡下，锁才落到链上；D43 实机跑通转 `implemented` 后它接管锁定，
  comsvcs 链保留为备选。这是「状态是真的」而不是回归：选择器没变，被挡下的方法回来了——测试同步按新事实改写（node-5 锁定项、`need=session` 备选列表、
  状态政策改为对 msf 卡下状态替身钉住该分支）。

**回归**：`pytest -q` = 690 passed, 1 skipped（+4 客户端用例 +1 空 LM 用例）；`build_skill_index.py --check` = ok（20 skills @ `4926fbe466ea`）。

## 2026-09-16 D44：命名守线扩面 + 活面欠账词审计工具化

**背景**：goal 要求「命名与各处细节做到工程级」。上一轮引入两份新面：`AGENTS.md`（宪法）与 `specs/**`（per-feature 制品），但术语守线（`tests/test_terminology.py`）没有覆盖它们——新面落地当天不受守。

**决策 1：守线扩面，而不是再写一条新守线。** `MACHINE_FILES` 加 `AGENTS.md`、`CURRENT_DOC_DIRS` 加 `specs`：宪法与每个 feature 的 spec/plan/tasks 从落地当天受同一条术语线约束（扩面后 8 条用例即过，说明存量干净）。

**决策 2：欠账词审计工具化 + 守线，而不是一次性扫描。** `scripts/audit_markers.py`：词边界匹配英文 `TODO`/`FIXME`/`TBD`/`HACK` 与中文两词（见脚本词表；`未定` 刻意不在表内，避免吃掉「未定义」这类正常词）；豁免 = 行内 `marker-ok` 加理由（就地可见，不是集中白名单）；历史面（decisions / glossary / reference）与产物目录跳过。守线 `tests/test_marker_audit.py`：审计必须 0 命中。

**决策 3：存量命中逐条处置，而不是批量豁免。** `hongri7_modeling.md`（建模快照）加时点注记，并把三项未结差异各自指向后续定案（容器细链 → 主图压成 `container_escape` 一步；SMB 分类 → v2 规则库 `windowsCredentialRemoteExecution`；防火墙凭据 → D32-h 补进 `rules5_v2.P`）；`skill_matrix.md` 的原「已知待办」标题改「跨卡决策收账」（内容全是已结项）；`src/inputs/bundle.py` 的占位值检测表加 `marker-ok`（词是数据，不是欠账）。

## 2026-09-16 D46c：文本面一条编码规则 + 一条行尾规则（含守线与 .ps1 行尾政策修正）
**背景**：goal 要求「命名与各处细节工程级」。D46c 侦查（`output/diag/D46/`，不进 git）扫活面文本，抓到两类同源问题：① **编码**——7 个文件带 BOM，其中 6 个是 `.py` / `.md` 首版入库的脏点（`skill_contract.md` 带了 **3 个** BOM 字符；JSON 带 BOM 会让标准解析器直接拒绝），反向漏的是 `ensure_docker.ps1`（含中文注释、没有 BOM，PS 5.1 无 BOM 时按 ANSI 读 → 乱码）；② **行尾**——`.gitattributes` 早声明 `* text=auto eol=lf`、索引侧也一直干净，但 11 个活跃文件的**工作副本**仍是 CRLF；同时 `.ps1` 声明 `eol=crlf` 而实盘是 LF，声明与现实不符且没有任何东西会发现。
**决策 1：编码一条规则，而不是「编辑器各写各的」。** 非 `.ps1` 文本一律 UTF-8 不带 BOM；含非 ASCII 的 `.ps1` 必须带 BOM（PS 5.1 的读取行为逼出来的唯一例外）。外部输入侧保持宽容（`src/runtime/adapter.py::load_inputs` 用 `utf-8-sig`），自有源文件严格——两条方针不冲突。守线 `test_text_sources_keep_one_encoding_discipline`。
**决策 2：行尾一条规则；`.ps1` 从 CRLF 改为 LF。** 理由：`*.ps1 text eol=crlf` 只影响检出，而实盘是 LF——「声明一句、现实另一句」正是最典型的静默漂移，不会被任何工具抓住。PS 5.1 解析 LF 没有问题，非 ASCII 的编码风险已由决策 1 的 BOM 覆盖，于是 `.ps1` 不再需要第二套行尾规则。保留的例外只有两个：`.cmd` / `.bat`（LF 会让标签 / goto 在部分解释器下解析出错）与 `archive/**`（`-text`，按原字节保存）。
**决策 3：守线从 `.gitattributes` 的有效属性推期望值，而不是在测试里抄一份政策。** 新增 `test_text_files_follow_the_declared_newline_policy`：`git ls-files --eol` 给出每个在册文件的 `i/` `w/` 状态与有效属性，`-text` / `binary` 跳过，其余要求索引 `i/lf`、工作副本按属性落（默认 `w/lf`，`eol=crlf` 的 `w/crlf`）。改政策只改一处，守线跟着走；drift 的修法写在断言消息里（`git add --renormalize .`）。
**决策 4：根因与时点。** 漂移的真来源是补丁脚本在 Windows 上按默认换行写字（Python `write_text` 把 `\n` 翻成 `\r\n`）。纪律：写盘按字节 / LF（Python 传 `newline=""`，PowerShell 用 `[System.IO.File]::WriteAllText`）。本次 11 个文件重写工作副本后与索引**内容全等**（`git hash-object` 两侧同哈希），所以行尾归一本身没有产生任何提交内容；本批提交的是政策修正、守线与文本面小瑕疵（两处方法间缺空行）。
**回归**：`pytest -q` = 695 passed, 1 skipped；`build_skill_index.py --check` = ok（21 skills @ `3ed757c699e1`）；`audit_markers.py` = 0 命中。

## 2026-09-16 下午：pre/post 检查卡 + 事实键轴（D48）

**决策 1：检查卡按「图 LEAF 事实」召回，不借 technique、也不借 provides。** 注册表新增 `fact` 字段
（取值 = 图 LEAF 谓词的蛇形名：`hacl` / `exec_code` / `ttp_exists` / `network_service_info` / `leak_account` /
`path_exists`），索引新增 `by_fact`，选择器新增 `--fact` 模式。理由：检查卡回答的是「这条事实成不成立」，
不是「这条边用哪个方法」，也不是「这次 run 缺什么资产」；塞进 `provides` 会让「供给」与「核验」同义化，
塞进 `case` 会假装它服务某条攻击边。三条召回路径互不重叠，各自的校验（双向一致）都进索引守线。

**决策 2：检查卡的判据写成「真负事实 = unsatisfied，缺观测 = uncertain」。** 新增 4 条确定性规则
（`tool_present==true` / `service_version_observed` / `auth_state==ok` / `file_present==true`）：
工具不在、凭据被拒、产物没落，都是**确定事实**，判 unsatisfied 供编排换方法；通道没应答、输出不可解析
才是 uncertain。理由：「最小必要验证」的价值在追溯——失败时要能分清是「前提不成立」还是「这次没测到」。

**决策 3：6 张检查卡先落方法卡与契约，状态如实 `planned`。** 适配器与实机记录随阶段 C 补齐；
`planned` 卡默认被选择器挡下并在 `excluded[]` 点名，`--include-planned` 是显式逃生门——沿用 D46b 的口径。

## 2026-09-16 D49：id 定名（域.短语）+ `assembly` 字段 + 证据路径不可改写

**决策 1：id = `<域>.<短语>`，恒两段，域固定九个，不用三段式。** 三段式（`exec.impacket_psexec.cmd`）在
「第二段是工具还是生命周期阶段」上必然分叉，规则会退化成口头约定，第四个人写卡就各写各的；两段式能用一条正则钉死，
并且把「工具/对象归属」交回检索轴（`tactic+technique` / `service` / `vuln` / `case` / `provides` / `fact`），
而不是从字符串里猜。规则写在三处（`index_builder.SKILL_ID_RE` + 两份 schema），守线逐字比对，一处漂移就红。
20 条旧 id 按迁移表改名（`specs/002-generic-skill-methods/plan.md`）；6 张检查卡按新规则落卡，零改动。

**决策 2：`assembly` 落在卡片上，不在注册表。** `assembly: fixed | model` 与 `status` 是同一种事实——
「这张卡现在长什么样、怎么执行」；status 的先例是注册表薄、卡片厚、索引给派生视图，assembly 照此办理。
副作用是注册表契约示例（`skill_contract.md` §3）不受影响，`test_contract_example_matches_the_real_registry_entry` 仍咬得住。
配对是硬约束：schema 管形状（fixed 必须有 `entry`、model 禁止 `entry`，if/then/else），`validate_card` 管磁盘
（fixed 卡的 `entry.py` 必须在位）。当前 20 fixed / 7 model。

**决策 3：证据路径不可改写。** 历史 run 里 `attempt-N-<旧 id>` 的目录名是产物的真名：引用一旦写成 `output/runs/` 前缀（守线要求逐字可核对），改名后就要还原成磁盘上的真名，而不是把产物改名来迁就文档，
而不是把产物目录改名来迁就文档——证据锚点的价值在于「按它去找，东西真的在」（守线 `test_evidence_references.py`）。
同理，卡片首行保留「D49 更名自 `<旧 id>`」一行曾用名。

**决策 4：改名机制按「长 id 先替」全仓 token 替换（814 处 / 96 文件），生成物重建。** 旧 id 互为前缀
（`credential.dump.lsass` ⊂ `credential.dump.lsass_comsvcs`），按长度降序替换是唯一安全的做法；
`skills/index.json` 跳过替换、直接重建（它是派生视图）。

**回归**：`pytest -q` = 718 passed, 1 skipped；`build_skill_index.py --check` ok；`audit_markers.py` 0 命中。
反向验证 `output/diag/D49/verify_guards.py`：三条守线（磁盘装订器 / 域规则 / 索引陈旧）各自被拆掉时，对应用例失败。

## 2026-09-16 D50：装配通道（`assembly=model` 的确定性半边）

**决策 1：模型的自由度只落在「占位符 → 值」，命令行结构与执行面仍是确定性层。** 执行器给出三件套
（`brief()`：卡片 §命令模板 的栅栏块 + 参数契约 + marker 纪律），模型只填值；装配结果回来先过 `validate()`
六类拒绝（空命令 / 长度上限 2000 / 未绑定占位符 / 自造 marker `agv[0-9a-z]{6,}` / 会话通道多行 /
msf 通道带 `<marker>`），过了才执行。理由：命令行拼接是模型真正比规则强的地方（现场形态千变万化、
模板覆盖不到的分支要靠理解），而「哪些字节能进命令、什么算证据」是可以钉死的——两半分开，各自才不拖累对方。

**决策 2：材料不出门。** `cred_ref` 这类参数进 brief 时只留 `withheld` + 形状提示（明文 / NTLM），
值在执行端按引用查表拼接；模型看到的永远是引用名。argv 与 stdout 的脱敏沿用既有那一套。

**决策 3：规则回退不假装能跑。** `fallback_command()` 取模板首个 `template` 块的首行替换占位符；
替换不出来的（如 `session.msf_migrate` 的 `migrate <pid>`，pid 要现场读）直接返回 `None` ——
无模型时这张卡就是「不开跑 + 记为一次失败尝试」，而不是拼一条假命令去换一个假读数。
信封里的 `assembly.source`（`model` / `rules`）与 `rejected[]` 把这件事写进证据。

**决策 4：卡-解析器守线：证据字段 ⊆ 解析器字段、且无孤儿解析器。** 每张 `model` 卡声明什么证据，
就必须有一个解析器产出它；反过来解析器不许产出没人声明的字段。`observed is None`（命令没回显 marker 段）
绝不给正证据——与 D48「缺观测 = uncertain」同一条口径，`tests/test_assembly.py` 守着这条线。

**回归**：`pytest -q` = 760 passed, 1 skipped；`build_skill_index.py --check` ok；`audit_markers.py` 0 命中。

## 2026-09-16 D51+D53：ATT&CK 索引钉 16.1——锁版、编号回改与别名层收口

**背景**：A 段（图与选择层的 ATT&CK 面）由 D51 首次落地：抓 ATT&CK 集合为 `data/attack/techniques.json`、
手写别名表 `aliases.json`、`src/attack/techniques.py` 的加载与校验、卡片编号更正。爷爷随后拍板「固定
ATT&CK 版本、锁定后一起入库」。官方发布线是 15.1 → 16.0 → 16.1 → 17.0，**没有 16.2**（爷爷记的是 16.x
这条线），锁定 **16.1**：`fetch_attack_index.py` 的 `PINNED_VERSION = "16.1"` 钉 URL 模板，`--version`
换版是一次显式再钉，`--url` 只作镜像/离线逃生门。抓取实测：46,485,155 字节，sha256 `8423d8dac3fc…`，
collection version 16.1，799 条技术 id / 656 live / 14 战术。

**决策 1：编号一律按 16.1 口径，卡跟图走。**
- 两张防火墙卡回改 `T1686` → **`T1562.001`**（16.1 live：Disable or Modify Tools）。理由：v2 图节点
  `disable_firewall_credentialed` 与规则文件 `rule_catalog.py` 都在 `T1562.001`；16.1 里动作更贴的
  子技术是 `T1562.004`，但「卡跟图口径走」优先——否则节点静默召回不到卡（D41 的教训）。D51 曾按
  19.2 口径试挂 `T1686`（该编号在 16.1 不存在），已回改。
- 通达 OA 卡保持 `T1059`：写-up 里的 `T1623` 经官网复核（attack.mitre.org/techniques/T1623/ 标题标注
  Mobile）是 Mobile 矩阵技术，不在 Enterprise 16.1 集合；别名层归一为 Enterprise 同名技术 `T1059`。
- suid 卡战术回改 `TA0004`：16.1 里 `T1574.007` 的战术 = persistence / privilege-escalation /
  defense-evasion，没有 execution。
- 三张 exec 卡按卡面 H1 收口：`T1021`（wmic）/ `T1021.002`（psexec）/ `T1021.006`（wmiexec）。
  父技术节点（图 44/48）上的备选由 case 键兜住——覆盖报告逐节点记「命中键」，wmic 另有 technique 键。

**决策 2：别名层只留一条，规则收紧为「只许退役」。**
- `T1562.001 → T1686` 删除：16.1 下源号本身 live，别名的源必须「不在集合里或已退役」，影子 live
  技术 = 缺陷，`TechniqueIndex.validate` 明确拒绝（反例五则固化在 `tests/test_attack_index.py`）。
- 剩下 `T1623 → T1059`；reason ≥ 20 字符、evidence 必填，由校验守着。
- 显示名不再有第二份手维护清单：`index_builder` 的 `TACTIC_NAMES` / `TECHNIQUE_NAMES` 两个硬编码表
  删除，战术/技术名直接读钉住的索引——消灭「卡改名、表没改」的漂移面（本次即抓到 T1574.007 等三个
  名字还是别的版本口径）。

**决策 3：历史快照不改写。** `docs/v1/*`（closure / acceptance / design / ip_preset，09-08~09-11）里
的「35 个规则 case」是交付时点真值，保留；现行数字看代码自述（`rule_catalog.py` 与 `docs/file_tree.md`
已对齐 39）。`README.md` 的「34/35 真实样本覆盖」同属 V1 叙述，留待重跑样本时再更新。

**守线**：`tests/test_attack_index.py` 11 条（钉版 16.1 / 卡与图引用的技术必须 live / H1 ↔ registry
技术号一致 / 别名反例五则）；`test_skill_catalog.py` 的 T1021 断言按子技术拆分更新；契约示例与新结构
逐字同步（`test_contract_example…` 抓到示例过期一次，已修）。覆盖报告为生成物：
`scripts/attack_coverage.py` → `docs/product/technique_coverage.md`（13 张动作卡 × 9 个技术 × 12 个
图节点，命中键逐节点可查）。

**回归**：`pytest -q` = 771 passed, 1 skipped（D53 新增 11 条）；`build_skill_index.py --check --graph
… --strict` 全绿（12/12 节点、无缺口）；`audit_markers.py` 0 命中。

## 2026-09-17 D54：V1 文档切 1.1.0（E2 如实映射）——落地开工 + 集中派生载入层（方案 A 修订）

**定稿链**：E2 形态经 run15（裁定）→ run16（定稿通过）→ run17（落地策略复核，GPT6 ultra）
三级确认：文档 = 原图保真 + 直接依赖三形态（LEAF/OR/AND）+ LEAF 验证要素 + OR 产出者；
`semantics/logic/case/details/edge_refs` 全下线；`requires` 的「简化组 + omitted」退役。

**落地架构（run17 裁定：方案 A 修订）**：**集中派生 + 消费者最小必要适配**——
新增载入层（拟 `src/graph/rehydrate.py`）从文档 `source_graph` 重建内部图对象、复用生成期同一套
纯函数（cases/logic）导出内存派生面（requires=E5 全直接前提组 / premise·effect refs / case_id /
details / validation 透传）；出口唯一、下游不再直读 `semantics`；派生面**不回流文档**（文档对象与
运行对象异型 + 保存白名单守线）；派生与文档携带信息冲突时**报一致性错误**，不静默覆盖。

**本次同时冻结的制品**（`specs/003-action-graph-1-1-0/`）：
`action_graph.schema.1.1.0.json`（已用红日 v2 真实样例 jsonschema 全量校验 PASS）+ `spec.md`
（四件套 + 冻结契约 + E5/E6 执行语义 + 版本/身份 + 1.0.0→1.1.0 差异清单 + 验收矩阵 + 六风险对策）
+ `plan.md`（架构 / 17 项改动点 / 派生字段定义 / 测试迁移表 / 回滚）+ `tasks.md`（T1–T12 含验证命令）。

**run17 加码约束（验收门槛）**：①771 基线不降覆盖（旧断言逐项迁移，不许只刷快照）；②四输入
重生成 + 离线复核（原图到属性/边关系、派生面、就绪落定、成功入账、覆盖统计、PDF 逐项、schema）；
③仓内样件同步再生；④schema 同名升级、旧版归档且不被发现逻辑选中（1.0.0 直接拒绝）；⑤文档批同步
（含消费者字段迁移表、运行时派生契约、旧状态处置规则）；⑥回流守线（载入→派生→保存无派生字段）。

**边界**：不双读、不为阶段二预留接口；E5 是显式运行语义变更（旧就绪/阻塞/落定派生状态一律重算，
无法解释的恢复状态作废）；旧账本历史事实可留。

**施工结论（2026-09-17，T1–T12 完成）**：

- schema 同名升级：`schemas/action_graph.schema.json` = 1.1.0；旧版归档 `archive/schemas/action_graph.1.0.0.schema.json`；1.0.0 被载入层与输入体检双双拒绝（含指路提示）。
- 载入层落地：`src/graph/rehydrate.py` + `validations.py` + `host_map.py`；消费者（run / loop / supply / chain / checker / selector / index_builder / 各 scripts / verify / review）全部改走载入层；文档对象与派生对象异型，回流守线生效（保存白名单 + 写入拒绝）。
- 测试迁移：旧断言逐项换到新契约（不许只刷快照）；新增 `tests/test_rehydrate.py`（10 条）+ `tests/test_graph_1_1_0_contract.py`（12 条）。全量基线 **793 passed / 1 skipped**（1.0.0 时为 771；该数为当时全仓收集口径，含 archive 23 + tmp 1；D56 起基线只收 `tests/` = 775 passed / 1 skipped（口径 776 条））。
- 四输入重生成回归（S1/S2/S3/红日 v2）：`fidelity_replay_equal=true`、E10 闭合全等、AND 无未匹配、LEAF 无 unknown；数值：S1 32+5=37、S2 65+9=74、S3 137+23=160、红日 v2 51+10=61（hosts 7 / ips 10）。
- 仓内样件全部切 1.1.0；`verify_v1.py` / `review_hongri7.py` / `check_inputs.py`（红日六输入 6 ok / 0 warn / 0 error）/ `build_skill_index --check --strict`（12/12 覆盖）/ `audit_markers.py`（0 命中）全部通过。
- 回滚口径：落地为单原子提交（schema + src + tests + 样件 + docs）；证据副本在 `tmp/regression/`（不进 git）。

## 2026-09-17 D55：V0 修订版定稿（爷爷八条拍板）——交付面、两级判定、"三次"、恢复、泛化、本地化、阶段一验收

**拍板（2026-09-17，爷爷逐条）**：

1. 完整系统交付先写成：**交付一套自动化攻击路径验证 agent**，按输入的**攻击图 + 主机–IP 映射表**
   完成**本地靶场**的攻击路径验证；**前端与报告不着急**。
2. 前端契约缓行（不定义、不阻塞）。
3. 恢复语义按工程惯例（run6 方案）写入 V0：恢复现场 / 审核重试 / 剪枝 / 重规划四机制分离；
   派发前落意图、重启先核对在途、不确定且有副作用停发记「结果未知」。
   **同日修正（爷爷口径）**：前端掉线**不管**（不纳入恢复语义）；**进程重启要管**；
   **Kali 开工前检查在线、中途检测到掉线即停**（不自动重连）；靶场其他虚拟机（靶机）不在本 agent 职责内。
4. 三态收口：对外 **成功 / 没成功（未成功 + 待尝试）**；成功判据写在各**技能卡**上
   （例：LSASS 出凭据 = 成功，报错/空 = 没成功）；机械判定，**不需人工介入**。
5. 「三次」语义：**一次 run 内同一节点最多 3 次**（首次 + 两轮）；首次失败后把命令 + 节点结构化数据
   交给**审核 agent** 判断脚本/参数问题并给修改意见，**执行 agent** 带意见重做；3 次不过停该节点
   （含下游）+ 编排找剩余路径；预算归节点、重启不清零。
6. 泛化可测试边界：**从输入数据处理到自动攻击全流程（含技能卡与适配器）不得针对红日写死**；
   技能集可只覆盖红日所需能力，但不得出现具体 IP / 主机名 / 红日专属情形；变体测试 + 代码审查。
7. 本地化：靶场 + Kali 本机虚拟机、agent 项目本地、**调用的模型本地**；离线 CI 不依赖外部云。
8. 阶段一验收契约（15 项 + 必达路径）写入 V0 体系。

**落地**：`docs/product/product_boundary.md` 修订版 + 新增 `docs/product/stage1_acceptance.md`
（15 项表，第 11/13 项前端与报告缓行）；`docs/product/README.md` 入口与版本行同步。
**口径**：修订版 V0 = 其后一切对照复核（V1/V2/V3）的条款基线（run18 裁定）。

## 2026-09-17 D56：本地 CI 收编——已有检查一条命令、结果绑定修订，提交自动跑

**背景**：检查早已存在（pytest / `audit_markers.py` / `build_skill_index.py --check` / 图谱覆盖率），
但它们各自为战：散在文档与记忆里，跑没跑、跑在哪个修订上，事后说不清。爷爷口径：
**CI 收编 = 把已有检查收进一条本地流水线，提交自动跑、结果绑提交、不上云**——不新造测试，不改质量线。

**落地**：

- `scripts/ci.py`：一次跑四项——① `pytest tests/ -q`；② `scripts/audit_markers.py`；
  ③ `scripts/build_skill_index.py --check`；④ `--check --strict --graph output/hongri7/json/Hongri7_v2.action_graph.json`
  （生成图在仓库里时才跑）。全部离线：不碰网络、靶场、模型。每次运行落
  `output/reports/ci/<commit>[-dirty].json` + `latest.json`：修订号、分支、脏标志、`staged_tree`、
  逐项退出码 / 秒数 / 输出尾巴；`--label` 标来源（manual / pre-commit），`--no-record` 只跑不落盘；
  退出码 0 全绿 / 1 有红 / 2 用法错。
- `scripts/install_git_hooks.py` + `scripts/hooks/pre-commit`：一次安装
  （`core.hooksPath -> scripts/hooks`、`ci.python` 钉住 `sys.executable`）；提交时跑的就是人工那条
  `scripts/ci.py --label pre-commit`，不存在第二份检查表；红即拦；显式豁免一次用
  `git commit --no-verify`（豁免字样写在钩子自身）；`--uninstall` 还原。
- 基线与历史面分离：基线只收 `tests/`（`pyproject.toml` 的 `testpaths`）；`archive/v1_logic_probe`
  （23 条历史）不再进默认收集；本机遗留探针 `tmp/test_probe.py` 同日删除。数字对齐：1.1.0 提交时
  全仓收集 794（tests 770 + archive 23 + tmp 1）、运行 793 passed / 1 skipped；D56 起
  `pytest -q` = **775 passed / 1 skipped**（口径 776 条，含 `tests/test_ci.py` 6 条）。

**守线**（`tests/test_ci.py`，6 条）：清单钉三项 + 条件覆盖项与两个脚本名；`--no-record` 不留痕；
绿 / 红各自落记录、含修订与秒数、退出码 0/1；钩子必须调同一入口、带 `ci.python` 与豁免字样、
索引内带可执行位（`git add --chmod=+x`）；安装器 `--help` 带 `--uninstall` 且钉
`core.hooksPath` / `ci.python`。

**口径**：CI 是已有质量线的**执行者与存档者**，不是新规则来源；它红 = 照旧规则修，不许在 CI 层加豁免。

## 2026-09-18 D57：开工前盘点——采纳证据索引（114 个历史运行目录 → A/B/C）

**背景**：并行开工前先盘清历史资产（爷爷口径：整理 114 个历史运行目录、做成「哪些还能用」的索引；
该职责并入总管会话）。索引回答一件事：每个 run 目录现在还能说明什么。

**落地**：`scripts/build_evidence_index.py` → `docs/product/adoption_evidence.tsv`，每目录一行 10 列：
evidence_id / run_dir / date / code_version / inputs_fingerprint / skills / coverage_nodes / outcome /
adopt_status / notes。code_version 按目录最后写入时刻在 git 历史里反推（推定值）；inputs_fingerprint
为图名@sha256 前 12 位。

**口径（三档，机械可查）**：

- A：整图 live 运行（有 run_result.json、非 dry run）+ 技能名可解析 + 图可解析 → 可进采纳流程；
- B：有结构化判定但缺一项——干跑 / 只有调用级判定（无整图结果）/ 图缺失 / 名不可解析 → 先做影响分析；
- C：无结构化判定（只有调用日志）→ 仅历史。

技能名解析用两个来源：现行注册表 + 002 迁移表（specs/002-generic-skill-methods/plan.md §2，20 条旧名→现名），
生成时按单一来源解析；旧名可映射的 run 在 notes 里如实标注。

**过程中的两处修正**：① 最初按平铺 call-* 匹配，漏掉 node-N/attempt-*/call-*/ 嵌套结构，改为递归匹配；
② 初版 A 条件会放行「无图引用」并把 judgement-only 目录当 live，A 虚高——现口径 A 必须有 run_result.json 且图可解析。

**当前分布（2026-09-18 快照）**：A=23（D27–D40 整图 live 系列；D40-live2 全 14 节点 succeeded）、
B=19（D25/D26/D40–D43 单卡实机验证与复判）、C=72（早期探索）；114 = 候选池，不是验收计数。

**守线**：tests/test_evidence_index.py（分类契约 / TSV 形状 / 迁移表解析 / --check 漂移 / 缺根退出码 2）。
--check 不进 ci.py 主名单：索引绑定本机 output/runs 快照，跨机器必假红；批量新运行后手动重生成再提交。

**边界**：索引只记录机械可查的事实；采纳决定（哪条证据进哪张卡 / 哪条路径的验收）仍由人做。

## 2026-09-18 D58：验收口径修正——终验 = 全图打穿（爷爷口径）

**口径**：验收不指定单条「代表路径」——「必达」= 输入攻击图的**全部攻击节点**取得真实效果证据；
planner 需要有策略地自主选择每一步动作（顺序 / 方法 / 失败替换）。首包含义保留（先跑一条最小纵向
链路做演示）；阶段一终验 = 全部攻击节点打穿 + 15 项条件 + 约定环境的必需技能。

**落地**：`docs/product/stage1_acceptance.md`（第 2 项 → 全图打穿；§2 → 必达范围）、
`product_boundary.md` 与 `docs/product/README.md` 导航语同步。planner 策略属编排会话范围（规格与内核）。

## 2026-09-28 D59：容器不算独立主机——不为容器单独落纳管会话（爷爷口径）

**口径**：docker 容器**不是主机**，它属于它的宿主。容器上的执行位置由**宿主的通道**提供即可，
**不为容器单独纳管一条会话**（不给容器建"受管端点"）。

**依据（真机 2026-09-28 同一次整图运行）**：

```text
台账里那条 hostmount 行：graph_host=web2  via_host=<容器 id>  mountpoint=/hello   ← 就是容器的挂载视图
容器上的两个节点（逃逸 / 提权）：execution_position.session = {driver: webshell, id: <容器>-webshell}
  它们的 session_ref 输入为 null，位置来自宿主的网页通道；两个节点都 succeeded
```

**落地**：纳管层保持现状即可——遇到容器挂载行会如实报 `needs launch_ref`（容器视图没有独立启动通道），
这是**范围外**而不是缺陷；不新增"容器会话"的代码路径。若将来真出现"只有文件通道能到的**独立主机**"，
再单独讨论（那时它是主机，不是容器）。


## 2026-10-05 D60：推导材料与计划材料按来源供给（023）

推导材料继续用私有文件引用链；模型只读取占位符化观察，提交账号、类型、值 token 和本次 call 原文引用，由运行时核验后登记。公共账本保存掩码引用和材料摘要。消费节点只沿图绑定取材料，优先推导、其次计划 symbol 对应外部条目（兼容既有 graph_user 键）。两类各一份允许并存，同类歧义或源篡改仍拒绝；不按网络失败自动换材料。私有保存目录显式由 --materials-dir 提供，不改变会话和句柄。用户要求测试自行运行，此轮补测试并静态审阅，不提交未验证代码；细节见 specs/023-derived-materials。

## 2026-10-06 D61：全图 14 节点首次全绿 —— 引擎只留「形状错误回喂」，卡只留 knowledge，靶场基线钉死

**口径（爷爷 2026-10-06 的 5 条）**：① 每轮跑前按上一轮账本清场；② 14 节点端到端且泛化；③ 卡瘦到红队工具水准（skill.json 只存 I/O schema、去掉随卡 py、md 瘦身）；④ output 里固化的测试物删掉；⑤ 引擎只用公用代码，节点专属的东西留在卡里。

**结果（e2e-full-37，可复核）**：
```text
order   : 14 → 12 → 7 → 5 → 2 → 44 → 48 → 30 → 28 → 26 → 22 → 19
proved  : 12, 14, 19, 2, 22, 26, 28, 30, 44, 48, 5, 7   ← 12 个 AND 步骤全部 proved
stopped : 空      blocked_upstream: 空      not_attempted: 空
```
图谱 14 个节点 = 12 个 AND 步骤 + 2 个 OR 事实（execCode(dc,system)=43 由 44 产出、execCode(pc2,system)=47 由 48 产出）。**DC 支线（2 → 44）与 PC2 支线（48）此前 30+ 轮从未通过**，本轮同时打通。

**四条引擎改动（共同病根：把形状错误当成致命错误）**：
1. 空答复 → 变形重试（第二次换成更小视图：4 条事件 + 1200 字符观测；失败留在 model.jsonl 的 source=lean_deform）；
2. 未决调用的结论 → 给一轮 correction，提示「写 off 再继续」（此前提示语是错的：「换个请求」，而新请求必然再被拒）；
3. 凭据占位符粘在长参数里 / 请求形状错（未编码的 query、stage 形状）→ 回喂，不再整步报废；
4. 控制台读操作三次重试（msfrpcd 掉一次连接曾让整条 carrier traceback，命令回执 unknown）。

**卡侧（bf8f178）**：删 23 个 entry.py + 12 个它们调用的随卡 helper + 全部 __pycache__（4,612 行）；只留三份「卡自己声明的部署物」（laravel 的 poc/CVE-2021-3129.py、suid 的 client/agv_suid_run.py、http_post 的 client/agv_http_recv.py）。35 个 skill.json 只留 input/output/judge（status/assembly/runs_at 与旧通道参数删掉），19 张卡的正文去掉「旧装配通道用 entry.py」的段落。两张卡按实测重写路线：防火墙卡与凭据远程执行卡都以显式凭据的 schtasks 为主（/ru+/rp 不能省——少了它 /run 回成功但目标上什么都不执行），netexec/impacket 作备选。

**靶场基线（真凶）**：DC 与 PC2 必须在 WRITEUP-READY-20260929。AGV-CLEAN-20261005-v1 的 DC 清理脚本最后一步是 netsh advfirewall set allprofiles state on，那个状态下 DC 的 445/135/139/5985 从 PC1 全不可达 —— 整条 DC 支线物理上不可能通。清场纪律因此多一条：跑完要删目标上本轮建的 schtasks、把 DC 防火墙恢复为「启用」（回读确认）。

**边界**：output/ 只留图谱源（hongri7）、本轮证据（runs）、CI 结果（reports/ci）；catalog/ 只留 layout 真正读的 skill-release-map.json。runtime/adapter.py 那套固定装配机（19KB，只有两个 marker 函数还有人 import）已删，marker 助手搬到 runtime/markers.py。

---

## 2026-10-06 D62：验证层 —— 判据从图上来、验证动作由模型做、机器判定只兜底（爷爷口径）

**爷爷原话：**「机器判定这个，我觉得还是要弱一点。其实可以说，我想的就是有一个验证 agent，根据 AND 节点的
子 OR 节点（execode 这种），去让大模型自己测试是不是真的成功了。这里感觉不需要机器判定，或者说，
机器判断可以用来兜底。这个也是要看一下大模型红队测试的常规做法再说怎么搞。」

**现状（先看清楚再改）：** 攻击图**已经**给每条 LEAF 依赖带了机器判据：

- node 44 的依赖里：`hacl(pc1,dc,tcp,445)` → `validation.kind = network_reachability`（fields: from/to/protocol/port）；
  `networkServiceInfo(dc,smb,tcp,445,system)` → `service_exposure`；`ttpExists(...)` → `capability`；
  `hasAccount(dc,...)` → `credential`；`isFirewall(pc2,flase)` → `environment_fact`。
- 但**运行时没有任何地方读它**：全仓只有 `graph/projector.py` 在编译时数了一遍（写进 summary），
  执行层一次都没用过。于是"这一步成没成"实际是**卡片自己的 post 段说了算 + 模型自称**，
  账本上那行 `MODEL_CLAIM_NOT_MACHINE_VERIFIED` 就是这件事的诚实写法。

**决定（三层，判据来自图、动作来自模型、机器兜底）：**

1. **判据从图上来。** 一步（AND 节点）要证明的事实清单，就是它的直接依赖：
   - `type=OR` 的依赖 → 本步要产出的那个子 OR 事实（如 node 44 的 `execCode(pc1,system)`）；
   - `type=LEAF` 的依赖 → 它自带的 `validation`（kind + fields），有判据的带上判据。
   这份清单是**引擎算出来的**，不靠卡自称。

2. **验证动作由模型做（验证 agent）。** 利用段结束后，引擎把这清单交给模型做一次**验证任务**：
   给它"要证明的事实 + 结构化字段 + 本轮已登记的收获（壳 / 凭据）+ 它能在哪台机器上用什么手段观测"，
   由它自己设计观测（跑一条命令 / 发一个请求 / 看会话回显），结论必须引用**本次调用的原始输出**。
   这就是爷爷说的"让大模型自己测是不是真的成功了"。

3. **机器判定只兜底（"弱一点"的落法）。** 对**有 kind 且可机械复核**的 LEAF（可达性 / 服务暴露 /
   凭据有效 / 环境事实 / 能力），引擎用一个固定探针复核模型的结论：
   - 模型说成、机器探针说不成 → **以机器为准**，并把分歧写进记录（模型看错，或环境在这中间变了）；
   - 机器探针需要现场上下文、做不了 → **以模型结论 + 引用为准**（不因为"判不了"就把节点判死）。
   结论码随之改语义：`MODEL_CLAIM_NOT_MACHINE_VERIFIED` → 分层写明"模型验证 + 有无机器兜底"。

**为什么不是"机器判定拉满"：** 大模型红队/自动渗透类工具的常规做法也是这个形状 ——
**工具只负责把事实收集回来，判定交给模型；确定性规则只在它能真正证伪的地方兜底**。
把判定全塞进确定性代码，遇到换靶场/换漏洞就会变成"规则不认识 → 判死"，那正是爷爷一直在反对的玩具形态。

**边界（这一条不做的事）：** 不改攻击图、不新增图格式；`validation` 仍然只是**判据**，不是"必须机器判"的开关；
卡片里已有的 post 段保留（它们是"怎么观测"的知识），新增的验证层负责"观测什么、谁说了算"。


**现状清单（2026-10-06 开工时）：**

- 已存在的验证知识：三张后置卡 —— `post.identity`（实际执行身份是否达到要求的权限等级）、
  `post.file_present`（声称落盘的产物是否真的在，路径/大小/可选摘要）、`post.channel_echo`（复用一个会话前，
  它此刻答不答、答的是什么）。它们的形态是"**怎么观测** 的知识"，直接可被验证回合复用。
- 缺的是**引擎级的验证回合**：没有任何地方按节点把"要证明的事实 + 判据"算出来，也没有"模型先判、
  机器兜底"的次序。
- 已落地两步（本次提交）：
  1. `src/graph/criteria.py` —— 判据清单（node_criteria / to_produce）：图上 LEAF 的 `validation`
     运行时**第一次**被读到；"本步要产出的 OR 事实"从 OR 节点那侧算（图上关系写在那里）。
  2. `src/runtime/verify.py` —— 验证任务的输入负载 + 答复的读取：每条事实都要有结论
     （satisfied/unsatisfied/uncertain），**非 uncertain 的结论必须引用本次真实调用 + 原文**，
     少一条事实、引用一条不存在的调用，一律具名拒绝。
- 还没做：跑批里的验证回合（发起调用、把结论写进节点记录）、机器兜底探针（对
  `machine_checkable` 的判据用固定探针复核模型结论）、以及"换靶场时判据种类不认识"时的降级规则。


**机器兜底不另起一套：复用现有的前置卡（2026-10-06 盘点）。** 判据种类到"用哪张卡去复核"的映射：

| 判据 kind | 兜底用哪张卡 | 说明 |
|---|---|---|
| `network_reachability` | `pre.nmap_tcp_probe` | 图上唯一带 `when.case=direct_network_access` 的卡；观测位置+端口的有向可达性 |
| `service_exposure` | `pre.service_version` | 顺带给出可用的 `target_url`（观察时刻的服务地址） |
| `credential` | `pre.credential_valid` | 绑目标+凭据做一次登录尝试；"不可用"与"权限不足"分开 |
| `environment_fact` | `pre.netsecurity_firewall_state` / `pre.docker_inspect` / `pre.cim_process_info` | 按谓词选（防火墙状态 / 容器归属 / 进程与运行主体） |
| `capability` | `pre.tool_present`（能表达时） | 工具是否存在且可用；表达不了的这类判据**不做机器兜底**，交模型 |

这张表是"兜底"的全部：**判据种类认识 → 有卡 → 探一遍复核；认不出/表达不了 → 不硬判，交模型并标记未兜底**。

---

## 2026-10-06 D63：轮次之间的干净起点 = 快照回滚（回收后置）

**爷爷口径（原话）：**「那就用快照回滚吧，其实项目不用做回收的。等所有的都搞定之后，再去做回收。」
「后面每一轮都要端到端重跑之前，都要回滚干净快照。这样就可以很方便的验证真机结果了。」

**决定：**

1. **每轮端到端重跑之前，先把六台 VM 回滚到干净快照**（`tmp/revert_to_clean.py <快照名>`，**必须串行**：
   vmrun 并发会互相锁死 —— 2026-10-06 实测 6 个并发把一条 15 分钟的超时跑满，而串行 45 秒就全好了）。
2. **回收（reclaim）后置**：功能全部跑通之后再做；在此之前不把时间花在"清得干不干净"上。
3. **干净快照 `AGV-CLEAN-20261006-v2`**（六台都有）。它之前的 v1 **并不干净** —— 实测回滚到 v1 后，
   kali 还躺着 10 个 `agv*` 和一个我们起的 1091 监听，PC1 上还留着 5 个跑 payload 的 cmd 与
   `agvclean`/`agvs`/`agvsess` 三个计划任务（跨了好几轮）。v2 是"清完再带外核实"之后打的：
   - kali：无 `agv*`、无我们的监听、msfrpcd 在跑；
   - PC1 / DC / PC2：我们的进程 0 / 计划任务 0 / Temp 里 `agv*` 0 / portproxy 0（DC 防火墙=启用，PC1 与 PC2=关闭，这是基线）；
   - Web1 / Web2：**没有带外凭据**（writeup 里的 `ubuntu/ubuntu1` 在这套镜像上认证失败），只能记"同代快照；
     残留（一条旧的 authorized_keys 行、`/tmp` 文件）不影响跑批 —— 引擎每轮自己重建入口"，留到回收阶段再补。

**实测到的基线状态（跑批依赖）：** DC 防火墙三档=启用、PC1 能写 DC 的 `C$`（⇒ SMB/445 通）；
web1:81 开（node 14 的靶点）、pc1:8080 开（node 7 的靶点）、web1:8080 关（图上不用）。
---

## 2026-10-06 D64：跨网段会话交付的验收口径（目标第 3 条"必须产出并登记一条会话才算成立"）

**要验的不是"命令跑过了"，而是五件一起成立：**

1. **两扇回程门都装上了，而且被回读确认**：`<run>/relay/relay-<port>.json` 里 `ok=true`、`route` 写明走的是
   会话原生反向转发（`meterpreter-portfwd`）还是系统转发（`netsh-portproxy`），每一步的 argv/rc/输出都在里面；
2. **交付命令是真的**：节点任务输入里的 `delivery_command` 必须是"在目标上取回 stager 并把它起起来"的那一条，
   而不是占位符（2026-10-06 walk-51 就是拿到 `echo agv-entry-ok` 而失败的）；
3. **回调地址落在跳板在目标侧的地址上**：stager 的 `LHOST` 与取件 URL 都指向那里（不是控制端）；
4. **控制台真的接到了**：`finish_session_delivery` 返回 `state=completed`，且给出一个**新的**会话号；
5. **收获表里出现那台目标的会话行**：`row_type=session`、`logical` 是该目标、`session_type` 是可用类型；
   没有这一行，节点一律按未成立记（`SESSION_DELIVERY_FAILED`），不准拿"模型说成了"顶替。

**失败时的取证顺序**（先证据、后改动）：`relay/relay-*.json`（门装没装上）→ 节点任务输入（交付命令对不对）→
节点的 `calls/*/stdout.txt`（目标上真的动了没有）→ `session.list`（有没有新会话）→ 最后才改代码。
---

## 2026-10-06 D65：验证层按外部评审细化（GPT6.1 ultra）—— 三种权力分离 + 判据按"能否明确观测"分 + 冲突按证据适用性裁决

**送审题**（换域改写后送 GPT6.1 ultra，run 20261006_181047_1257，exit 0）：多步骤自动化流水线里"这一步到底成功了没有"该由谁判、怎么判。

**它的结论（要点，原话为主）：**

1. **协调器掌握"写入事实、放行下游"的最终权力**；可明确验证的命题交给适用的验证器；模型负责补观测、解释复杂证据、处理未覆盖的判据。
   证据不足或冲突无法解决时，**正式输出 UNKNOWN**。执行 agent 不直接修改事实状态。
2. **完整证据链是四步**：原文确实存在 → 原文对应这个目标和条件 → 原文足以支持结论 → 结论在下游使用时仍然有效。
   "引文校验"只解决第一步；我们现在的形态是"执行模型自判 + 证据来源检查"。
3. **机器校验的边界按"能否明确观测和解释"划分，不能只按五个类型名划分**：可达性要在**指定执行位置**发起指定协议的连接、
   并限定来源/目标/协议/端口/时间窗；凭据有效要**实际认证**并核对身份与上下文；能力成立要做**符合范围的挑战操作**；
   环境事实要读**对应的状态源**并区分"配置值"与"运行时生效值"。常见误判写进表里（例如"从控制机可达"不能推出"从 A 可达"）。
4. **验证器必须声明自己的证据能证明什么**：充分条件通过（支持成立，未通过未必否证）／必要条件失败（支持不成立，通过未必证明整体）／
   局部条件（只更新子条件，不能宣布整体成功）。
5. **冲突按证据适用性裁决，不规定"模型永远优先"或"探针永远优先"**：先看双方是不是在判断**同一个命题**（目标/主体/视点/协议/能力范围/时间窗）；
   探针超时、解析失败、权限不足、视点不符时**不取得决定权**；双方都有可信矛盾观测 → UNKNOWN / UNRESOLVED_CONFLICT + 有界补观测；
   双方一致但依赖同一份不充分日志 → 一致性不能补足证据，仍是 UNKNOWN。
6. **模型不能"补出"没观测到的事实**：根本没有观测到目标状态时，返回 UNKNOWN。

**据此对我们 D62 的细化（待落地）：**

- 判据块（`graph.criteria`）除 kind/fields 外，还要能给出"这条命题的范围"（主体/视点/协议/端口/时间窗），冲突裁决才有共同的比较面；
- 验证结论词表从 satisfied/unsatisfied/uncertain 扩成：`TRUE` / `FALSE` / `UNKNOWN` / `UNRESOLVED_CONFLICT`，并要求**每个验证器说明它的证据是充分/必要/局部**；
- 机器兜底探针必须记下自己的**视点/目标/时间窗**（否则"从哪测的"丢了，冲突就没法判）；
- "双方一致"不构成充分证据（同源日志不算两次观测）。
---

## 2026-10-06 D66：模型为什么会慢（实测归因，不是猜）

**现象**：跑批里单个节点的模型调用要 30–150 秒、输出 3k–21k tokens（爷爷之前就问过"你不会是用的 pro 模型吧"）。

**实测**（同一问、同一模型，只改 reasoning 档位）：

| 档位 | 墙钟 | 输出 tokens |
|---|---|---|
| none | 6.7s | 1539 |
| low | 7.5s | 1650 |
| high | 6.3s | 1295 |

**结论：慢的主因不是 reasoning 档位**（三档几乎一样），而是两件事：

1. **提示词规模**：真机调用里 prompt 2.6k→8k tokens（卡正文 + 本步历史 + 图上下文都在里面）；
2. **模型本身话多**：一个"只要一个 JSON"的小问题也要 1.3k–1.7k 输出 tokens。

**可动的杠杆**（都还没动，留给项目方定，因为它直接关系到"给大模型多少空间"）：

- 减材料（卡正文里对模型没用的段落、历史里已被引用过的调用）；
- 给 action 类调用设一个输出上限（风险：要写长命令的步骤会被截断 —— node 7 的 tongda 链就撞过 12k 上限，
  现在的办法是撞满就加倍重试）；
- 换更"话少"的模型跑 action 类调用。
---

## 2026-10-06 D67：会话/收获/回收/传输的八条口径落到哪了（逐条对账）

**背景**：爷爷 2026-10-06 就"会话管理与回收"给了八条口径（A/B 选项）。这一条把"每条口径落在代码哪里、
证据是什么、还差什么"一次写清，避免下一轮又靠记忆。

| # | 口径 | 落点 | 证据 | 还差什么 |
|---|------|------|------|----------|
| 1 | **直接 A 常驻进程** | `scripts/session_manager.py daemon` + `run_plan.start_session_daemon` | `5b8505c`：跑批起手拉起探活进程（看本轮收获表、走本轮控制端、默认 300 秒一轮），收尾 `finally` 收回；日志 `<run>/session-daemon.log` 与 `.out` | 真机上还没看过一整轮（walk-59 起才有） |
| 2 | **A planner 只看节点成败** | `run_plan.planner_board` | 给 planner 的只有 `completed_node_ids` / `node_states`(success/blocked/failed) / `last_step_result` / `handoffs`；**不带**会话活跃度 | —— |
| 3 | **凭据→会话：B 必须登记一条会话才算成立** | `run_plan` 的 `must_deliver_session` + `finish_session_delivery` | 卡声明 `session` 时，交付不是 `completed` 就把 `proved` 打回 False、理由 `SESSION_DELIVERY_FAILED`（D64 五条） | 44/48 仍未真机上交付成功 |
| 4 | **会话表升级成收获表** | `src/runtime/harvest.py`（`harvest.jsonl`） | `row_type` ∈ session/credential/artifact；旧目录 `channels.jsonl`/`credentials.jsonl` 只读兼容（`926edcd`） | —— |
| 5 | **产物表 + 逆着表回收** | `src/runtime/artifacts.py` + `scripts/reclaim.py` | 引擎自己动过的（上传文件/stager/取件服务/监听/入口密钥）记一行并带 `undo` argv；`reclaim` 倒序执行并把结果写回（`458ba8f`） | 模型下发动作只有 5 条正则（声明的，不是确认的）；回收本身后置未真跑 |
| 6 | **A 现在补（为"换靶场"泛化）** | 本轮补的两处：常驻探活不认靶场（认会话类型）+ 传输不分叉 | 见 1 与 8 | 需要爷爷确认这一条具体指的是哪一处；`bind.py` 的检索仍是"精确 case"硬门槛（换图即断，见对抗评审第 3 条） |
| 7 | **"会话级暂定"是什么意思** | 见下方问答 | —— | —— |
| 8 | **B 三级 + 引擎按会话类型自动选（卡不用操心传输）** | `src/runtime/channels.py`：`DELIVERY_TIERS = (direct, short, file)` / `delivery_tier()` / `prepare_delivery()`，发命令前统一过一遍（`6c55c8e`） | 行限来自会话类型（`CARRIER_LINE_LIMIT`，实测控制台会话 ~800 字符/行）；`file` 级落下的脚本记进产物表 | 三级只覆盖"发命令"；跨网段交付的 stager 取回另算 |

### 关于第 7 条「会话级暂定」

在我们的实现里，这条的对应物是**句柄（会话）自己的可用性只是一个"暂定"结论**：

- 登记一行句柄时，`alive` 只代表"登记那一刻探通了一次"，不是长期承诺；行里留着 `probed_at` 与
  `probe_command`（探的是什么、什么时候探的），所以任何人拿到这行都知道它的成色；
- 每次要用之前，`run_plan` 还会再探一次（`session_manager.probe`，控制台会话走 `session.list` 不打扰，
  ssh/web 各发一条无害命令），**探不通就换下一个候选**，不拿暂定当事实；
- 常驻探活进程（第 1 条）负责把"暂定"维持住：活的刷新、死的按类型重连一次、仍不通才写关闭事件；
- 结论：**暂定 = 记录下来的那次探测结果 + 一个会持续刷新它的进程**，不是"先当它活着用着"。

如果爷爷当时指的是**回收**粒度上的"会话级暂定"（回收先按会话暂缓、等整轮跑完再收），
那我们现有的对应物是 D63 的"回收后置 + 快照回滚"；两种读法我按第一种实现了，若你指的是第二种，说一声我改。


---

## 2026-10-06 D68：模型输出形状 = 扁平 + 工具面全覆盖（三次同类事故的总结）

**爷爷口径**：输出该像 `{"tool":"python","code":"…"}` 那样 —— **工具 + 一段内容**；形状越复杂，
接住它的代码就越复杂，而**每一层校验都是一个新的死亡方式**。

**三次同类事故（都是"手写白名单漏了一个工具"）**：

| 事故 | 现场 | 死法 | 修 |
|---|---|---|---|
| http 被写成 curl | walk-62 node 7：`{"tool":"shell","cmd":"curl …"}` | 位置机（web1）没有 curl → rc 127 | 扁平 `http` 由**引擎自己的客户端**发（目标上只要有 python3）；模型若写 curl 行，翻译回结构化请求；URL 主机与本步目标不符则具名拒绝 |
| finish 没翻译 | walk-61 node 14/30：`{"tool":"finish","verdict":…}` | 车道要 `{"kind":"finish","claimed_verdict":…}` → `LEAN_ACTION_UNSUPPORTED` | 扁平 finish 翻译（`verdict`→`claimed_verdict`，多余键丢掉）；**顺序改为先翻译再还原占位符**（finish 的引文有专门处理） |
| stage 没翻译 | walk-62 node 7：`{"tool":"stage"}` | 同上，两个回合白烧 | **工具面全覆盖**：不再逐个手写 —— `tool` 之外的字段原样交给车道，按卡片声明判 |

**现在的规则（`scripts/run_lean_task.py::flat_action`）**：

* `{"tool":"shell","cmd":"…"}` → 整条命令交给**执行位置自己的 shell**（POSIX `/bin/sh -c`、Windows `cmd /c`）；
* `{"tool":"http","method":…,"path":…,"headers":…,"body":…}` → 引擎客户端（不需要目标上有 curl）；
* `{"tool":"python","code":"…"}` → `python3 -c`（长了由 channels 的文件化投递接住）；
* `{"tool":"finish",…}` / `{"tool":"abandon",…}` → 车道形状；
* **其余任何 tool** → 原样交给车道（卡片新增工具不必改引擎代码）。

**两条硬边界保持不变**：命令里出现的主机必须落在冻结端点（或引擎自己写进这一步输入的地址）内；
`Host`/`Content-Length` 等传输层头不许手设。

**教训（写给下一轮的我）**：同一个错误犯三次，说明**不是漏了一个工具，而是"白名单"这个做法本身错了**。
改法要改到"新增工具不需要改这层代码"为止。


### D68 补记（2026-10-06 晚，第四处同类）：meterpreter 分支不认扁平 `cmd`

第四处仍在同一条线上：`speaks: meterpreter` 的分支只读 `request["argv"]`，把扁平的
`{"tool":"shell","cmd":"sysinfo"}` 直接丢成空命令 —— 回包只剩两行传输标记、rc=0，
`sysinfo/load kiwi/creds_all` 一条都没进会话；模型因此诚实地写"没有观测到凭据"，又被
"卡声明了 materials 却没带材料"判成 `LEAN_MATERIALS_INVALID`（这是第五处，见 `1deadd6`）。

**因果链（时间线可核）**：walk-59（21:00–21:10，老代码）node 5 ✅ 成立、`agv_materials` 里留下凭据文件；
21:05 左右提交 f19fd23（拍平输出形状）；walk-63（21:52）node 5 三次调用全部空回包 → 停。

**教训升级**：前三次是"给工具手写白名单"，第四次是**在另一个层（车道的 speaks 分支）重复了同一个错误**
—— 适配点分散在多处时，只补一处的白名单永远不够。所以规则补一句：
**新增/改动输出形状时，先把"谁在消费 action 的哪些字段"列全（车道分派、载体选择、平台包装、
控制台发送器），再动形状；只改一处就是留一个坑。**


### D68 补记二（2026-10-06 晚，形状改动的完整代价清单：六处）

"拍平输出形状"这一次改动，真机上撞出**六处**同类问题。逐条记全，供以后任何"改输出形状"参考：

| # | 现象 | 病根层 | 修 |
|---|---|---|---|
| 1 | walk-60 node 14/30：`/bin/sh: nmap …: not found`（rc 127） | 扁平 `cmd` 被塞进 `argv[0]`，`shlex.join` 把它引成一个词 | 整条命令交给位置自己的 shell（`/bin/sh -c` / `cmd /c`）（`212a84a`） |
| 2 | walk-61 node 14/30：命令跑成了，结论那一步却停整节点 | `flat_action` 只认 shell/http/python，漏了 `finish` | 扁平 `finish` 翻译 + 顺序改为先翻译再还原占位符（`86a319e`） |
| 3 | walk-62 node 7：位置机没有 curl → rc 127 | 我把 http 写成"发 curl 命令"（原来是引擎自带客户端） | 扁平 http 走引擎客户端；curl 行翻译回结构化（`ec07d70`） |
| 4 | walk-62 node 7：`{"tool":"stage"}` 被判形状不认识 | 手写白名单又漏了 stage | **工具面全覆盖**：其余 tool 原样交给车道（`c6e9c4b`） |
| 5 | walk-63 node 5：三条 meterpreter 命令一个字没发出去 | `speaks: meterpreter` 分支只读 `argv` | 该分支同样接受扁平 `cmd`（`001890e`） |
| 6 | walk-65 node 2/48：`schtasks … /p «secret:1» …` 连吃三次拒绝 | "占位符必须独占整个值"是给旧形状（密码=独立 argv 项）定的；扁平整条命令一个字符串 | 命令文本允许嵌入、其余字段仍要求独占（`2da1d92`） |

**结论（写给任何一次形状改动）**：形状不是"一处的字段名"，它会被至少五处消费 —— 车道分派、
载体/平台包装、控制台发送器（含 `speaks` 分支）、占位符还原、以及卡片里写好的命令模板。
**改形状前先把这些消费点列全，改完每处都要有用例钉住**；只改一处等于给下一轮埋一颗雷。

## D69 · 两个"事实由代码算、值交给模型"的口径（爷爷 2026-10-07）

### 一、落地文件名：**代码从回包里取号，作为下一步的输入发下去**

node 7（通达包含链）walk-70 翻车实录：

| | 上传回包 | 包含执行用的路径 | 结果 |
|---|---|---|---|
| walk-69（过） | `+OK [vm]459@2610_2022130988\|agv.png\|0[/vm]` | `/general/../../attach/im/2610/2022130988.agv.png` | 命中，会话交回来 |
| walk-70（不过） | `+OK [vm]459@2610_2022130988\|agv.png\|0[/vm]`（同一个） | `/general/../../attach/im/2610/2610_1821511781.agv.png` | **空回显、零回连** |

`2610_1821511781` 那一轮**任何一次上传回包里都没有出现过** —— 子弹上了膛，扳机扣向空气。

**落地名每次都不一样**（带时间戳），所以"照抄"这件事不能指望模型：**引擎从上传回包里解析出
落地路径，作为 `from: runtime` 的输入交给下一次调用**（`landed_file`），模型只负责照用。

### 二、长命令分级：**代码提前算长度，给出"用哪一级方式"的参数**

walk-70 node 19 实录：模型往控制台会话里发了一条 1537 字符的 multipart，载体行长上限 800 →
`CHANNEL_CANNOT_CARRY`；模型随后改用 `stage`（卡里给的第二条路，**选对了**），却被批次实现挡死。

长度是引擎**提前能算**的事实，所以不该让模型撞墙：

* 引擎在任务输入里给 `command_tier`（`inline` / `file`）、`carrier_line_limit`；
* 卡允许有两条路（命令行 / 落文件），但**选哪条由这个参数说**，不由模型试；
* `file` 级时，引擎自己走文件通道（`stage` / `put_file`），别让长行到载体那里才失败。
## D70 · 执行层只有两件**通用**的事（爷爷 2026-10-07 定案 · 总纲）

执行层的任务本身不复杂：**它只有两件事，而且都是通用的**。

1. **解析大模型输出**：把模型这一次的动作读成固定形状 —— **用什么 / 在哪个位置 / 干什么** ——
   然后**按"类别"派给一个通用执行函数**。类别指**执行方式**（命令行 / 脚本 / 工具 / 代码 / 原生动作），
   **不是节点编号、不是卡名**。类别由**模型输出**决定。
2. **一套会话管理**：登记 / 探活 / 迁移 / 取用 / 回收 —— 对**任何节点**都是同一套代码。

**禁止**（出现即视为没做到）：

* 按节点或按卡分叉（`if node == …` / `if skill_id == …` / "这张卡走那条特殊路"）；
* 每个动作一套完成判据、每张卡一套收尾/回收；
* 为了"稳"新增旋钮（没有依据的默认值一律不给默认）。

**允许且仅允许**的差异来自两处：① 模型输出说"用哪一类"，于是派给哪个通用函数；
② **声明给出的场景事实**（平台、会话形态、行长上限、该载体的完成协议、解释器）。

**验收口径**：换节点、换卡、换设备、换拓扑 —— 只要"类别"没变，就必须走**同一条代码路径**
（同一套解析、同一套会话管理、同一套判据）。做不到就说明形状不对，要按这条重做。

## D71 · 执行层"谁做什么"（爷爷 2026-10-07 定案 · 与 D70 配套）

**代码做（固定的机械动作 + 底线，不许交出去）：**

* **探活**：节奏、探针命令、三态判定（活 / 未确认 / **明确不存在**）；
* **会话登记、迁移进常驻控制台、回收**：按固定流程；
* **执行位置候选的计算**：谁在目标主机上、权限够不够、通道通不通 —— 代码算；
* **资源**：占用与释放、端口与文件的分配与回读、独占（防探活抢走业务回显）；
* **管道**：把动作送进正确的会话、把回执原文带回、登记归属（这条回执属于哪次调用）；
* **证据底线**：完成判据（只有完整有序帧算数）、引用**逐字**核验、终点**必须有证据**、
  "不存在"要有直接证据、"失败"不许伪装成空；
* **边界**：超出声明立刻拒（不许自动挑"权限最高"的句柄、不许猜地址/端口）。

**模型做（只有"现场判断与取舍"）：**

* 打**哪个**节点（看未完成清单、上一步结果、依赖状态、失败原因）；
* 这一步**动作怎么写**（用什么、在哪跑、干什么）；
* **失败怎么改**（看拒绝原因 + 本次回执；代码不自动重投）；
* 预算内**还要不要继续**；
* **结论怎么下**（必须依据**本次**回执原文；缺证保持未确认）。

**灰色地带（爷爷 2026-10-07 拍板）：选执行位置**

1. **候选由代码算**（同主机、权限够、通道通）；
2. **唯一候选 → 代码直接定**（不进模型）；
3. **多候选且需要取舍 → 才问模型**。


## D72 · 会话/隧道/凭据/验收等十条口径（爷爷 2026-10-07 逐条拍板）

1. **会话管理模块只管"会话"**：登记 / 探活 / 迁移 / 回收 / 多会话并存；
   对外只给执行器一个参数 —— **会话 id**。
2. **隧道：拿到会话就由代码自动搭**（控制台自带的转发 + 路由，**端口自增 + 占用检查 + 记账**）；
   **"连隧道"是执行器的事**（执行器自己判断这条命令要不要带隧道前缀）；**不交给模型判断**。
3. **访问材料（凭据）**：取到后**格式化登记**（谁 / 什么值 / 来源调用）；
   后续节点**优先用挖出来的**，图上写的当**兜底**。
4. **验收口径**：**所有节点"要么 proved、要么试过没成"**（planner 自己判断该不该停）；
   不以"跑完一圈"为通过。
5. **失败按依赖闭包传播**（a 失败 → 依赖它的 b/c/d 都不许做）；**去掉程序兜底**，
   模型不可用就**如实报**（不许程序自己按图顺序选点）。
6. **端点固定**：只在一处解析、解析后冻结；**连不上就如实报错停住**，不许悄悄换对象/换模型线；
   "本次用的哪个端点/哪条线"要记进账本。
7. **回收**：先做**落物台账**（谁、在哪、怎么删）；平时靠**快照回滚**；**回收脚本先不做**。
8. **离线门槛**：改代码必须配**离线断言 + 一次回放**（"离线全绿、真机失效"不允许再发生）。
9. **术语守线只管公开契约**（字段名/枚举/当前文档）；**原始证据一个字都不许动**
   （否则"引用必须来自本次回执原文"就是假的）。
10. **Web1 / Web2 的干净快照**：补一次核验（**由我们自己核**，不走桥）。



## D73 · 调度给模型什么（爷爷 2026-10-07 拍板 · 与 D70 配套）

**调度的输入 = 现场清单，不是候选表。**

给模型的东西：

* 处理后的**图 JSON**；
* **已完成的节点列表**；
* **每个节点"成了 / 没成"**（节点状态表）；
* **上一步的结果**（哪个节点、成功 / 失败 / 阻塞、失败原因）；
* 执行器交回来的**结构化交代**（哪些节点没做完、为什么、还剩什么没解决）。

**去掉的"缰绳"**：不再由程序算"现在哪些节点能选"再交给模型挑。

**程序只做一件事**：**拒绝不合法选择**，并给**具名原因** ——
节点不存在 / 已经做过 / 落在失败的依赖闭包里。

**失败按依赖闭包传播**（a 失败 → 依赖 a 的 b/c/d 都不许做）：这条**信息给模型**，让它别选；
不再写第二套候选算法来兜。

**模型不可用**：如实报，不许程序自己按图顺序选点。

**事实可用性**：若某条被用到的事实验证不过，**要回给调度**，并说清不对的原因。



## D74 · 入口位置与"自己造入口"（王炸 2026-10-08 落地 · 待爷爷复核）

**一句话**：**入口是一种位置，不是一条连接。** 登记的是"遗留资源在哪 + 怎么呼它（冻结配方）"，
**每次使用都重新观测**；入口没了就**如实失败**，绝不把"种入口"的那条链重放一遍。

1. **形状**：`entry_setup`（卡声明"我在目标上造一个入口"）与 `provides_position`（卡声明"我留下一个可用入口"）
   都只在**步骤成立**之后生效；运行层把地址按图 + 主机表解析后**冻结进配方**，卡里不写部署主机名。
   位置行**不占端口、不参与租约**（它不是连接，没有可泄漏的句柄）。
2. **配方两种形态**（都由控制端的同一条通道发出去）：`asset_command`（命令作为**已放置脚本**的参数，
   如 web 入口客户端）/ `argv_command`（命令作为运行层自建 argv 的**最后一项**，如自授权后的 ssh）。
   行的 `session_type` 统一是 `entry`，`position_kind` 说它是哪种。
3. **"自己造入口"的顺序**（缺一不可）：运行层生成**自己的**密钥 → 用**当前位置**执行卡声明的固定动作
   （只认**帧内**的完成标记）→ 用同一条配方**通过它自己**回读身份（卡声明要求，例：uid=0 且不得含容器标记）
   → 通过才登记成新位置。身份不符/没回帧 = **具名失败 + 交回卡的 cleanup**。
4. **探针要退出码**：入口"回帧了"不等于"能用"——探针要求**自己的命令码为 0**，
   否则记 `unconfirmed` 并**拦住**要用它的那一步（2026-10-08 真机 node 26 实测：只看帧齐就放行，
   进去每条命令 127，白烧 9 个回合）。
5. **常驻探活不许越权判断**：没有入口客户端的进程（常驻探活）**不写账本**，只如实回报"我看不见它"。
6. **运行层放好的工具要把路径交出去**（`placed_assets`），并说明"用这些、别另写一份"；
   实测同一格：用现成工具→过，自己重写一遍→不过（2026-10-08 walk-156 node 28）。

### D74 补充（桥 GPT6.1 ultra 2026-10-08 评审批次）

7. **身份证据要正面**：`uid=0` + "没看到容器标记"**不是**宿主身份的证明（用户命名空间里 uid 0 很普通，
   缺标记也不是正面证据）。所以入口身份现在由**回答来自哪条连接**成立（连的就是图上那台主机的地址/端口/账号），
   卡还可以要求**必须看到**某个标记（`identity.must_contain`），不只有"不许出现"。
8. **落物要有状态**：运行层把自己造的东西写进 `leftovers.jsonl`（谁造、在哪、怎么删、现在什么状态），
   `cleanup_state` 默认 `pending`——**"请求过"不等于"已经清掉"**；`plan_result` 里运行结算与目标验证**分开报**，
   "终点为真"不许抹掉未决的清理缺口。
9. **共用入口：只共享使用权，不复制所有权**；历史观测不算活动占用；**并发不作为已支持能力**
   （我们全程串行，一次只跑一步）。
10. **固定工具钉的是制品身份**（路径 + 内容摘要），不是只有路径；用不了就说清哪一件、为什么，
    **不许把自制替代静默算成同一件事**。
11. **权限是入口的执行事实，不是它的名字**：位置行记 `privilege`；卡声明了权限，登记前先问这条入口
    "你的命令以什么身份跑"——答出别的身份就**具名拒绝登记**，答不出来（入口一时不答）则登记但观测留
    `unknown`。选择位置时，这一步前提写哪个权限就先取哪一条（同一主机两条入口不再让模型猜）。
12. **冻结不了的配方不许登记**：`{host}`/`{port}` 这类占位答不出来时具名拒绝
    （`POSITION_PORT_UNRESOLVED` / `POSITION_RECIPE_UNBOUND`）——登记成 `http://host:` 会比失败更坏，
    因为它看着能用、每次用都失败。
13. **清理要有状态**：`leftovers.jsonl` 只追加；运行自己在 `finally` 里收**控制端**的落物（入口密钥），
    结果记 `confirmed` / `failed`；够不着的（宿主上的授权、容器里的挂载）**如实留 `pending`**，
    由快照回滚负责。台账回放"结算行"，报表给的是每件东西的**当前**状态，不是写过几次。
14. **调度放弃也要结算**：`PLANNER_ATTEMPTS_EXHAUSTED` 时同样写一份 `plan_result.json`（已跑的节点、
    落物状态、未派发清单 + 具名原因），并明写"这是结算，不是通过"。
15. **"通过"要单独说**：结算 ≠ 通过。总结里要带**计划身份**（哪一版、哪些必做步骤、各自必须产出什么）、
    每步**前提由哪个上游节点本轮产出**（`linkage`）、以及**未决与遗留清单**（`undecided`）。
    缺证据**不是**没有缺失 —— 验收器第一版就把"没有计划身份"读成"没有缺失"而误判过。
16. **"这个部署在这里不提供那种问法"是回喂，不是停格**：新加的拒绝码要进 `REFUSABLE`
    （`LEAN_ENTRY_POSITION_COMMAND_ONLY` 第一版漏了 → 整格首轮就死）。致命与否看**性质**：
    "换个问法还能继续"的一律回喂。
17. **收回要走写它的那条入口**：落物台账里记的必须是**能到达它**的入口（宿主授权记容器入口，
    不是刚建出来的 ssh 入口）；失败也要记下"用了哪条入口、回执什么"，不能只有一个 `failed`。
18. **重试的边界（桥 2026-10-08 纠正）**：引擎**不自动重试** —— 非零退出码不等于没有副作用
    （可能半写），无关调用成功也不等于前提变了。要重发同一条请求，必须由执行者**显式点名**
    （`retry_of` + `retry_reason`），引擎只登记一行、照发一次。**但这只是可追责的声明，不是幂等保证**：
    目标侧（一个 web 服务、一条命令入口）通常认不出幂等键，所以"重发过"的这一步其副作用**可能发生两次**
    —— 记录里必须看得出"这回是重发"，结论里不许把重试过的动作当成只发生过一次。

## D75 · 结构治理：工程管理与功能变更分开（桥主导 · 2026-10-09）

**状态**：B1 管理正文定稿。本条替换此前明确待定稿的 D75 正文，既有版本保留在 Git 历史中。替换后的离线检查结果与本轮结构治理最终真机结论，按实际被测修订另行登记。

**决定**：将工程管理与功能变更分开。本轮治理目录职责、文档导航、迁移过程和验收证据；后续源码分片按明确的职责边界逐批实施。函数语义、参数默认值、异常处理、重试、超时、阶段顺序及机器判据保持原样，功能变更另立批次。

**目标骨架与兼容边界**：保留现有顶层分区、公开导入路径、脚本入口及既有调用方式。`src/` 保留 `agents`、`graph`、`orchestration`、`runtime`、`skills` 的顶层包边界，`verification/` 保留在 `orchestration` 内；`scripts/` 承担入口与操作脚本职责，并保留 `hooks/pre-commit`；`tests/` 保持离线封闭，本轮暂不搬目录。

`skills/` 保留每张卡原有文件组合、目录命名与业务 ID；`specs/` 保留编号和既有目录结构；`docs/` 承担人读的说明、导航和记录职责；`data/`、`schemas/`、`catalog/` 分别保留既有职责；`archive/` 与 `IO协议/` 原位保留；`output/` 与 `tmp/` 保持忽略。不新套统一顶级包，不建立没有明确职责的 `common/`、`utils/`、`services/`。

**B1 定稿范围**：

- [`CONTRIBUTING.md`](../CONTRIBUTING.md)：规定本轮边界、批次实施、迁移检查、离线检查与证据绑定。
- [`docs/README.md`](README.md)：规定说明材料的阅读入口、分区职责与维护方式。
- [`specs/README.md`](../specs/README.md)：索引既有编号规格，说明阅读方法、适用范围与维护规则。
- 根 `README.md`：提供运行、修改、现行说明、编号规格、文件地图五类入口。
- [`docs/file_tree.md`](file_tree.md)：同步上述三份管理文件的职责条目。
- 本条 D75：记录结构治理决定、B1 范围、后续审查顺序与证据边界。

B1 不包含源码搬迁、符号分片、导入接线或测试替换点调整，不宣称后续源码治理已经完成。

**历史提交与既有检查**：`1fff98f` 是三份管理文件及导航、地图的初版提交；`3fbe4e4` 是 D75 初版提交。两者记录初版内容的来源，不作为本次替换后修订的验收绑定。

维护者报告的替换前离线结果为 `976 passed`、`ci 3/3`，其中 tree 检查点名 147 个源文件。本条登记时尚未注明这组结果对应的被测完整提交号，因此保留为维护者报告的历史结果；本次替换后应重新检查并绑定实际被测修订。这些数字不构成后续批次的固定验收阈值。

**批次与实施规则**：一次处理一个职责边界。纯文件移动逐文件使用 `git mv`，与文件内符号分片分批实施；不混入格式化、参数改名或顺手修复。符号分片先列旧路径与符号、新路径与符号、调用方、公开路径兼容方式和测试替换点，再按迁移单执行。

函数体原样移动仍须核对全局名查找、模块初始化与缓存、路径定位、导入关系和测试替换点。`__init__.py` 保持既有行为，不新增自动注册。每批核对文件地图、脚本清单、包发现配置和受影响文档；不涉及的项目记录为“不涉及”。

B1 的管理正文与决策台账可以分提交，共同归入同一批次。批次完成依据是范围落实和检查结果，不是提交数量。

**离线检查**：沿用 `pytest`、`scripts/ci.py` 与差异检查流程，具体操作见贡献规则。“离线三闸”固定指 `scripts/ci.py` 的 `pytest`、`cards`、`tree`，差异检查单列。失败批次修复并复跑后才能进入下一批；不得通过放宽断言、增加跳过项或改变机器判据取得通过结果。

原有测试及其断言逐项保留，不以测试总数相同代替覆盖核对，不把离线通过宣称为行为等价证明。正式证据记录实际被测完整提交号及工作区状态；存在未提交相关改动时只记工作区结果。后续验收记录提交引用实际被测提交，不自动继承被测提交的结论。

**后续源码审查顺序**：首个分片审查对象为 `scripts/run_lean_task.py`，其次为 `src/runtime/lean.py`。先依据源码确认职责与依赖，再形成逐符号迁移单；本条不直接指定待迁出的符号。其他文件不因篇幅长而自动列入拆分。

行数只作评审提示，不进入机器验收，不为满足行数提示改写逻辑。需要记录行数时，附统计命令与统计修订。

**本轮不做**：不引入阻断式 lint、format、type 检查，不做全库格式化或 import 排序；不新增 `CHANGELOG`，沿用决策台账与提交记录；不改变 CI 验收语义、卡前言、`skill.json`、Schema、验收规则或真机脚本语义；不重排规格编号，不凭年代或版本名宣告材料失效，不借结构治理削减能力或删除材料。

**未决事项**：

- 核实 `pyproject.toml` 包发现白名单中的 `inputs*` 与实际安装内容是否一致；核实前不作删除或扩大匹配范围的决定。
- 按实际正文核对 `docs/product/` 材料的职责与适用范围，再安排归类；本条不固定材料数量，也不提前批准批量搬迁。
- 补齐编号规格与现行产品说明之间必要的交叉链接，保留各自职责，避免复制正文形成重复维护。
- 登记本次正文替换后的被测完整提交号、离线检查结果与日志位置。

**最终真机验收**：本轮结构治理最终证据仍为同一轮、同一修订真机 `12/12 PASSED`，由维护者在干净快照上执行并保存轮次、快照、逐节点结果、被测提交号及日志位置。不同轮次的通过节点不得拼接；代码或执行条件改变后重新验收。

本决定之前的 walk-211、walk-212、walk-213 三轮 `12/12` 保留为历史证据，不作为本次正文替换或后续结构变更的验收结论。B1 的离线检查与本轮结构治理最终真机验收分别记录。

**正文分工**：B1 管理正文及本条决定正文由外部评审提供；维护者逐字落盘、执行检查并记录实际证据。正文来源说明不代表外部评审已经执行本地检查或真机验收。
