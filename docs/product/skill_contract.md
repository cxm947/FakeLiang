# 技能目录契约（skills：注册表 + 技能卡 + 派生索引）

本页是运行层"技能目录"的唯一契约。目标只有一个：**拿攻击图节点的字段，确定性找到对应技能，并知道它要什么参数、产出什么证据、怎么判定。**

## 1. 分工（谁写、谁读、谁生成）

| 文件 | 角色 | 谁写 | 谁读 |
| --- | --- | --- | --- |
| `skills/registry.json` | 手写源（唯一手写件）：薄目录 | 人 | 索引生成器、选择器、人 |
| `skills/index.json` | 派生检索表 | `scripts/build_skill_index.py`（禁止手改） | 选择器（召回） |
| `skills/<id>/skill.json` | 机器契约：输入/证据/判据/入口 | 人 | 选择器（门控）、适配器、校验器 |
| `skills/<id>/SKILL.md` | **主工件**：方法卡——这类检查怎么做（r113 骨架：何时用 / 怎么做 / 怎么判，可选尾段；旧八段卡随各相位逐张收口）。模型必须看到的约束写进「怎么做」的围栏块（提取器只摘围栏及标签） | 人（模型可起草） | 模型（锁定之后装配命令）、人 |
| `skills/<id>/entry.py` | 固定 argv 装订器（**可选**）：声明式直通用 `run.command`；没有 `run.command` 的 fixed 卡按同目录约定读取 `entry.py`（`prepare_call` / `parse_call` 两接口）——卡里不写任何入口声明（r114） | 人 | 运行器 |

运行中的一切结论（锁定、观测、pending、四态）都不进这些文件——那是运行库 `records` 的事。

技能卡的成文模板与「不绑单一靶场」口径见 [002 技能卡改造](../../specs/002-generic-skill-methods/spec.md)：迁移后的卡按 r113 骨架成文——前三段固定（`何时用` / `怎么做` / `怎么判`）＋可选尾段；正文不出现靶场专有词（守线 `tests/test_skill_cards.py`）。

## 2. 命名与格式规则

- **id**：`<域>.<短语>`，恒两段点分、全小写：`^(?:pre|post|exploit|session)\.[a-z][a-z0-9_]*$`。
  域固定四个（`pre` 前置检查 / `post` 后置验证 / `exploit` 动作行为：漏洞利用、远程执行、
  凭据材料、防护规避、提权与逃逸、文件流转 / `session` 会话生命周期）——2026-09-23 前缀统一：
  凡写「具体攻击行为」的卡一律用 `exploit.`，原 `exec` / `cred` / `evasion` / `priv` / `transfer` 五个域随之撤销
  （历史记录不改写；更名对照见 [002 plan](../../specs/002-generic-skill-methods/plan.md) 置顶注记）。
  短语是 `<主体>_<动作>`：
  主体优先写工具（`impacket_psexec` / `comsvcs` / `pypykatz`），没有单一工具可指时才写对象（`redis` / `laravel` / `suid`）。
  示例：`exploit.impacket_psexec_cmd`、`exploit.comsvcs_minidump`、`pre.nmap_tcp_probe`。规则与迁移表见 [002 plan](../../specs/002-generic-skill-methods/plan.md)；同一规则写在 `index_builder.SKILL_ID_RE` 与 registry schema 里（卡 schema 自 r121 起不再声明 id——身份来自注册表行），守线逐字比对。
- **service**：`名称[/端口]`，小写。例：`smb/445`、`redis/6379`、`tongda_oa_v11_3/8080`、`lsass`（无端口）。支撑类可为空数组。
- **tactic / technique**：动作类成对出现（`TA0008` / `T1021`）；支撑类为 `null`。
- **vuln**：CVE 或配置类弱点名，同一个列表。例：`CVE-2021-3129`、`redis_unauth_key_write`。
- **path**：必须等于 `skills/<id>/`（校验会核对目录与卡片存在）。
- **目录豁免只有一条**：`skills/attack-graph-validation/` 是项目自身的元卡（V8 交付物：告诉别的 agent 什么时候用本系统），没有 `skill.json`、不进注册表、不进索引；守线 `tests/test_skill_catalog.py::RegistryTests::test_every_directory_under_skills_is_a_card_or_the_meta_card` 把这条豁免写成显式一例，其余 `skills/` 下的目录必须是在册卡。

## 3. registry.json（八字段必填 + case + provides + aliases）

```json
{
  "schema": 1,
  "version": "0.2.0",
  "updated_at": "2026-09-16 07:06:08",
  "skills": [{
    "id": "exploit.impacket_psexec_cmd",
    "name": "psexec 远程执行·系统级探针（首选）",
    "desc": "以凭据经 SCM 服务创建在 SMB/445 远程执行固定探针（hostname/whoami/whoami /user 分段标记），验证命令执行并记录实际身份",
    "tactic": "TA0008",
    "technique": "T1021.002",
    "service": ["smb/445"],
    "vuln": [],
    "case": ["windows_credential_remote_system_after_firewall_disable", "windows_credential_remote_system_firewall_state"],
  "path": "skills/exploit-impacket-psexec-cmd/",
    "aliases": ["psexec", "admin_share", "impacket psexec", "psexec远程执行"]
  }]
}
```

字段消费方（没有消费者的字段不加）：

| 字段 | 谁在用 |
| --- | --- |
| `id` / `name` / `desc` | 人读；records 与锁定记录引用 |
| `tactic` / `technique` | 召回主键（生成索引两层树） |
| `service` / `vuln` | 对象适配（与图节点字段直接比对） |
| `case`（可选；支撑类须与 `provides` / `fact` 至少声明一个） | 图词汇精确键：本技能服务的 rule case id（见第 6 节）；行动类可省略——有 `attack_id` 的节点按 technique+service 召回 |
| `aliases`（可选；检索别名；2026-09-20） | 同一对象的其他说法（`scm` / `ms17-010` / `psexec`）：命中按弱票计 1 分/条（封顶 3），同时是弱召回通道；构建期校验不得与自身精确字段重复。规则见 [007 检索规格](../../specs/007-skill-retrieval/spec.md) |
| `provides`（可选，运行时键；唯一） | 运行现场需求键，取值 `reachability/session/transfer/credential`（例：`["session"]`）；动作类不得声明。支撑类的用途分类曾用独立 `purpose` 字段表达，D36 起并入这里 |
| `fact`（可选，检查卡键；D48） | 检查卡（pre/post）回答的图 LEAF 事实键：`hacl`（可达）/ `exec_code`（执行与身份）/ `ttp_exists`（工具在位）/ `network_service_info`（服务与版本）/ `leak_account`（凭据可用）/ `path_exists`（产物存在）（例：`["exec_code"]`）；动作类不得声明。三条召回路径互不重叠：case 面向图节点、provides 面向运行现场、fact 面向检查 |
| `path` | 指向技能卡与入口 |

- **`note` 只写文件定位**（登记源 vs 生成物、字段语义去哪看），不写状态叙述与批次记录：状态在卡片上、
  批次在 [技能复核快照](skill_matrix.md) 与[实机验证记录](validation_runs.md) 里——同一件事不留两个会过期的副本。
- **`updated_at` 手写、不参与校验**：真正的一致性由 `index.json.source_sha256` 保证（改过注册表就重建索引）。

### chains（注册表的第二个顶层数组，D29）

`skills` 之外，注册表还有 `chains`：它把**一条要分几段才能做完的方法**写成**有序段**。链是数据
（第几步、用哪张卡、什么角色），段间绑定是代码（`src/runtime/supply.py`）——「这一段的输出怎么变成
下一段的输入」如果静默，就是一条没人测过的假设。

| 键 | 谁在用 |
| --- | --- |
| `id` | 链的稳定标识（run 结果里的 `chain.id`）；重复即校验失败 |
| `need` | 这条链供给哪个运行需求（取值同 `provides` 四键；当前只有 `credential`） |
| `case`（可选） | 这条链服务哪个图 case——节点的方法本身就可以是一整条链（例：`lsass_system` 的 `lsass_minidump` 链；旧编号节点 41） |
| `segments[]` | 有序段：`role`（`dump` / `exfil` / `parse`；新角色必须同时带来绑定与测试）+ `skill`（必须在 `skills` 里注册，否则校验失败） |

段与卡的边界：**卡只描述自己在做什么，链描述它们按什么顺序接起来**。所以同一张卡可以既出现在链里、
又作为独立方法存在（`exploit.http_post_file`、`exploit.pypykatz_parse` 都是这样）。
当前唯一一条链（`lsass_minidump`）见第 9 节「方法链」。

## 4. skill.json（机器契约）

```json
{
  "status": "implemented",
  "assembly": "fixed",
  "input": {
    "required": [
      {"name": "target_host", "type": "host_ref", "from": "graph"},
      {"name": "credential_ref", "type": "cred_ref", "from": "graph"}
    ],
    "optional": [{"name": "source_ref", "type": "session_ref", "from": "runtime"}]
  },
  "judge": "observed_privilege_at_least_node_requirement"
}
```

- `status`：`planned | implemented | deprecated`；`implemented` 时方法卡 `SKILL.md` 必须存在（校验会核对）。
- `assembly`：**命令行由谁装配**——`fixed` = 声明式 `run.command`（模板 + 程序绑定 `{name}` 占位）或随卡装订器 `entry.py`（文件名即约定，卡里不写入口声明，r114），运行层只绑参数；
  `model` = 模型按方法卡 §怎么做 + 本卡参数契约装配（载荷填装、参数取值、多步顺序）。
  配对是硬约束：`fixed` 必须有 `run.command` 或同目录 `entry.py`（无 `run.command` 时按约定查盘，`validate_card` 管这一步）；`model` 不得声明 `run`（顶层 `entry` 字段自 r114 起已删除；模型卡的入口声明在 `execution.entry`）。
  两者都属于「这张卡现在长什么样」的事实，所以落点在**卡片**而不是注册表；派生视图见索引 `by_assembly`（第 5 节）。
  `model` 卡的执行面（三件套、装配与解析）见第 10 节「装配通道」。
- `input.from`：`graph`（来自图/事实）、`runtime`（运行现场补给）、`config`（本次运行配置）。**参数填不满就是 pending，不是失败。**
- `input.const`（可选；规格 [004 接口对表](../../specs/004-orchestration-adoption/interface_table_v1.md) §4.3 / R05）：把某个输入**钉成常量**，即本卡的方法**形态**（约定名 `check_shape`；如 `network_service` / `credential_auth`）。只许标量且须匹配声明类型；引用型输入（`host_ref` / `url` / `cred_ref` / `session_ref`）不得声明（schema 管形状，`validate_card` 管类型配合）。绑参时逐字比较：**不匹配 = 本卡不适用**（候选进 `not_applicable`，永不锁定、不做备选）；**缺值 = 缺口可见**（不猜默认）；`false` / `0` 是值，不算缺。形态唯一来源＝卡面 `const`，不另存形态真源表：同事实多形态时先形态过滤、再绑参（R05）。
- `judge`：**单个判据名（字符串）**——解析到判定器 `RULES`（别名经 `RULE_ALIASES` 归一）；报告序列（`freshness` → `target` → 本判据）由判定器固定，卡里不写闸门子集、不写缺证据策略。判据属于 `IDENTITY_RULES` 时报告行走 `identity` 行，否则走 `effect` 行（r112/r118）。
- `notes`：**≤200 字的一行指针**（状态 + 证据锚点 `call-…` + 去哪读细节）。长叙述不进卡片：
  方法说明与实机记录写同目录 `SKILL.md`。卡片是机器契约，让它随时间发胖就是把叙述和契约混在一起。
- `SKILL.md`（方法卡 / 知识层）：`implemented` 的卡片必须有（校验会核对）；按 r113 骨架成文（`何时用` / `怎么做` / `怎么判`；旧八段卡随各相位迁移收口，迁移前保留既有尾段）。
  方法与判据是通用知识（不绑靶场），靶场记录只出现在末段；**模型必须看到的约束写进「怎么做」的围栏块**（提取器只摘围栏及标签）。术语见[术语表](glossary.md)。

### 闸门词表

| 闸门 | 验证什么 | 不过时 |
| --- | --- | --- |
| `freshness` | 证据来自本次调用（call_id / 通道 / 时间戳） | `uncertain` |
| `target` | 目标对齐（hostname / url / 会话主机） | `uncertain` |
| `identity` | 实际身份满足节点要求（规则见下） | `unsatisfied` |
| `effect` | 目标效果成立（规则见下） | `unsatisfied` |

判据名取值（checker `RULES`；报告行走 `identity` 还是 `effect` 由 `IDENTITY_RULES` 决定）：

- `observed_privilege_at_least_node_requirement`：身份按**权限等级等价**判定（域管在成员服务器上即算系统级），不强制 `S-1-5-18`。
- 效果类：`uid_after==0`（identity 侧）、`state==open`、`firewall_state==disabled`、`readback_value==value`、`command_output_contains_call_marker`、`host_side_marker_present`、`target_echo_present`（通道成立）、`dump_magic_mdmp`（产物成立，**不等于**凭据成立）、`credential_material_present`（凭据材料成立）、`transfer_hash_match`（双边字节数与 SHA-256 逐字一致）、`session_identity_present`。

### 证据字段词表（evidence）

按用途分组（新增字段先在这里登记，再进卡片）：

| 组 | 字段 |
| --- | --- |
| 通用 | `call_id`、`hostname`、`host`、`target_host`、`target_url`、`port`、`state`、`exit_code` |
| 执行位置 / 通道 | `channel`、`session_identity`、`session_host`、`session_user`、`ssh_key_fingerprint` |
| 身份与效果 | `identity_name`、`identity_sid`、`firewall_state`、`command_output`、`write_accepted`、`readback_value`、`uid_after`、`suid_binary`、`container_id`、`host_side_marker` |
| 凭据材料 | `credential_material`、`credential_accounts`、`dump_path`、`dump_size`、`dump_magic`、`dump_sha256` |
| 传输 | `source_bytes`、`sha256`、`receiver_bytes`、`receiver_sha256`、`transfer_verified` |
| 检查卡（D48 落卡 / D50 解析器） | `tool_present`、`tool_path`、`tool_version`、`service_product`、`service_version`、`service_banner`、`auth_state`、`auth_detail`、`file_present`、`size_bytes`、`observed_privilege`、`msf_session_id` |

外加一个**保留键** `observations`：人读的降级/放弃解释（例：「外带没收到应答，字节到没到无法判断」）。**任何判据都不许读它**——它只在证据不足时解释为什么不足。原始输出一律存 `raw`（`stdout`/`stderr`/`http_response`），落盘只留一份。

## 5. index.json（派生检索表）

```json
{
  "schema": 1,
  "generated_at": "2026-09-15 23:00:00",
  "source": "skills/registry.json",
  "source_sha256": "<64 hex>",
  "counts": {"skills": 32, "action": 13, "support": 19, "tactics": 6, "techniques": 9, "cases": 10, "provides": 3, "facts": 8, "chains": 1, "keywords": 275, "entry_kinds": {"action": 14, "fact": 13, "supply": 8}},
  "by_status": {"implemented": ["pre.nmap_tcp_probe", "..."], "planned": ["pre.tool_present", "pre.session_identity", "post.file_present", "post.identity", "session.msf_migrate"]},
  "status_counts": {"implemented": 27, "planned": 5},
  "by_assembly": {"fixed": ["exploit.impacket_psexec_cmd", "..."], "model": ["pre.tool_present", "..."]},
  "assembly_counts": {"fixed": 21, "model": 11},
  "by_tactic": {"TA0008": {"name": "Lateral Movement", "techniques": {
      "T1021": {"name": "Remote Services", "skills": ["exploit.wmic_remote_cmd"]},
      "T1021.002": {"name": "SMB/Windows Admin Shares", "skills": ["exploit.impacket_psexec_cmd"]},
      "T1021.006": {"name": "Windows Remote Management", "skills": ["exploit.impacket_wmiexec_cmd"]}}}},
  "by_case": {"direct_network_access": ["pre.nmap_tcp_probe"]},
  "by_chain": {"credential": [{"id": "lsass_minidump", "case": "lsass_system", "segments": [
      {"role": "dump", "skill": "exploit.comsvcs_minidump"},
      {"role": "exfil", "skill": "exploit.http_post_file"},
      {"role": "parse", "skill": "exploit.pypykatz_parse"}]}]},
  "by_provides": {"reachability": ["pre.nmap_tcp_probe"],
                  "session": ["post.channel_echo", "session.msf_migrate", "session.msf_via_credentials",
                              "session.root_via_suid", "session.ssh_via_redis", "session.webshell_via_laravel"],
                  "transfer": ["exploit.http_post_file"]},
  "by_fact": {"exec_code": ["post.channel_echo", "post.identity", "pre.session_identity"],
              "hacl": ["pre.nmap_tcp_probe"], "network_service_info": ["pre.service_version"]},
  "by_entry_kind": {"action": ["pre.nmap_tcp_probe", "..."], "fact": ["pre.nmap_tcp_probe", "..."], "supply": ["pre.nmap_tcp_probe", "..."]},
  "by_keyword": {"445": ["exploit.netexec_firewall_off", "exploit.wmi_firewall_off", "exploit.impacket_psexec_cmd", "exploit.impacket_wmiexec_cmd", "exploit.wmic_remote_cmd"]}
}
```

- **三条召回路径，别混**：`by_case` 面向**图节点**（「哪个技能服务这条边」），`by_provides` 面向**运行现场**（「这次 run 缺一个会话/凭据/传输，谁能给」），`by_fact` 面向**检查卡**（「谁能把这条 LEAF 事实核出来」——pre/post 卡按事实键召回，不靠技术猜）。三条路径的锁定语义一致（见第 11 节）。
- 检索顺序（2026-09-20 起）：候选集 = 技术编号+服务、`case`（对象兼容闸门）、别名三条通道的并集；排序 = 检索分降序、同分回注册表顺序。检索分 = 技术编号 / 服务名 / case / 漏洞号每类 4 分（同类不叠加）+ 别名 1 分/条、封顶 3——分数只排序、不救活（可用性看绑定与硬门禁）。运行现场需求走 `by_provides`，事实检查走 `by_fact`；完整规格见 [007 检索规格](../../specs/007-skill-retrieval/spec.md)。
- 关键词由 id/name/service/vuln/provides/aliases 分词生成（NFKC + 小写，ASCII 长度 ≥ 2），不收录自由描述；关键词索引只排序不裁决、不参与计分（计分只来自显式 `aliases` 与精确字段）。
- 树里的战术/技术**显示名**直接读自钉住的 ATT&CK 索引（`data/attack/techniques.json`，当前 16.1）——
  不是第二份手维护清单，换版本就是换数据（D53）。
- `by_status` / `status_counts`：卡片状态的**派生视图**（`implemented` / `planned` / `deprecated` 三类 id 列表与计数）。
  状态真源是每张卡片的 `status`，索引只是把它聚合成「哪些方法真的验证过」的一次读取；**只有 `implemented` 默认可选**（第 11 节）。
- `by_assembly` / `assembly_counts`：装配方式的派生视图（`fixed` / `model`，D49）——运行层据此决定
  「直接调用装订器」还是「按方法卡模板装配命令行」。真源同样是卡片 `assembly`，同一召回键下的 id 仍按注册表顺序（优先级）。
- 两层与 gap：`by_tactic` 只收注册表里的技能；**缺口不写在索引里**，由覆盖核对实时计算（避免索引绑定某一张图）。
- **同一召回键下多条技能**：候选按检索分降序，同分回注册表顺序（2026-09-20 起；此前为纯注册表顺序），列表第一条首选、其余按序备选（例：图节点 `T1021 + smb/445` → `[exploit.wmic_remote_cmd, exploit.impacket_psexec_cmd, exploit.impacket_wmiexec_cmd]`——wmic 12 分（技术+服务+case），另两张 8 分（服务+case））。索引与覆盖报告都保持这个顺序；失败回环换下一张卡，不改上一张卡里的方法。排序不发明 `priority`/`fallback` 字段：分数来自声明式字段（`technique`/`service`/`case`/`vuln`/`aliases`）。
- **两种形态，同一个顺序**：同一**环节**的备选（node41 的两条 dump 方法，运行期二选一）与同一目标的相邻**环节**（dump → 外带 → 解析，运行期按序都要做）。同一个排序（检索分降序、同分回注册表顺序）同时满足这两种读法，靠 `provides` 把环节之间缺的那一段（外带/会话）补上——见第 9 节第 13-15 条。
- **`by_chain`**：链的派生视图（`need → [{id, case, segments:[{role, skill}]}]`）。它回答「这个需求有哪些**现成供给路径**」，
  与 `by_provides`（单卡供给）并存：一张卡能给的走单卡，要分段才能给的走链；两者都是数据，选中之后运行期不再拼装。

### 校验规则（`--check` 与测试都会跑）

1. `registry.json` 与每个 `skill.json` 通过 `schemas/*.schema.json`。
2. `index.json.source_sha256` 必须等于当前注册表哈希（改过注册表就要重建）。
3. 反向：索引里出现的每个 id 都在注册表中（无悬空）。
4. 正向：注册表里每条技能都出现在索引的**召回段**里（`by_tactic` / `by_case` / `by_provides` / `by_fact` 的并集全覆盖，段内不重复）
   ——一张卡掉出所有召回段 = 永远召不到。
5. `by_case` 与注册表声明双向一致：多余键/遗漏键/未知 id 都报错。
6. `by_provides` / `by_fact` 同样双向一致（多余键/遗漏键/未知 id），且 `provides` 的取值只能在四个需求键里、`fact` 的键必须是小写蛇形。
7. 卡片规则：`notes` ≤200 字（`skill.schema.json` 的 `maxLength`）；`implemented` 卡片必须有 `SKILL.md`（入口配对见第 9 条）；
   `by_status` 覆盖全部注册表 id 且不重复，`status_counts` 与之一致。
8. `chains` 校验：`id` 唯一、`need` 必须落在 `provides` 四键里、每个 `segments[].skill` 必须在注册表里
   （段的顺序就是执行顺序；段指向不存在的卡 = 一条缺步骤的计划）；`index.by_chain` 必须与注册表一致（否则重建索引）。
9. `assembly` 配对（r114 起卡里不写入口声明）：schema 管形状（`fixed` 不得声明 `output`；`model` 必须声明 `output`、不得声明 `run`），`validate_card` 管磁盘
   （`fixed` 无 `run.command` 时同目录 `entry.py` 必须在位，`run.command` 必须配 `parse`）；`by_assembly` 覆盖全部注册表 id、不重复、且与卡片现值一致（否则重建索引）。

## 6. 覆盖核对（--graph）

```powershell
python scripts/build_skill_index.py --check
python scripts/build_skill_index.py --graph output/hongri7/json/Hongri7_v2.action_graph.json --strict --report output/reports/skill_coverage.json
```

匹配规则（两条精确键，一个实现）：

1. **technique 键**：节点 `attack_id` 相同，且 `service` 兼容（技能未写服务则不限；都写端口时端口必须一致）。
2. **case 键**：节点 `semantics.case_id` 在技能声明的 `case` 里，且**对象兼容**。对象由端点识别：
   技能声明的服务名与节点一致，**或端口一致**（节点写的服务名来自原 write-up 的方法——节点 2 写 `scm/445`，
   而解决同一 case 的 Windows-vantage 卡走 `smb/445` + `wmi/135`：同一个 445 端点，不该因为它换了传输就丢掉）；
   端点不同的卡仍然被挡下（同一 case 下 redis 卡不会召回给 laravel 节点）。支撑节点（无 `attack_id`）只走这一条。
3. 排序：检索分降序（4 分/类 + 别名 ≤3），同分回注册表顺序；命中原因写进报告的 `via` 字段，供追溯。

`--strict` 有缺口时退出码非 0。当前红日 7 v2：**12/12 AND 节点覆盖**。

## 7. 与攻击图字段的对应（为什么注册表这么薄）

| 攻击图节点字段 | 注册表用途 |
| --- | --- |
| `attack_id`（如 T1021） | 召回 |
| `service` / `port`（如 smb / 445、lsass） | 对象适配 |
| `vulnerability`（CVE 或弱点名） | 对象适配 |
| `semantics.case_id`（如 `direct_network_access`） | 图词汇精确键（技能声明 `case`） |
| `details`（如 `path=/tmp`、容器名） | 进 `skill.json` 的输入参数（`from: graph`） |

图给事实、注册表找工具、skill.json 管参数与判据——三件事不重叠。

## 8. 与王炸的对照

| 王炸 | AGV |
| --- | --- |
| `skills_data.json`（自动生成菜单） | `skills/registry.json`（手写源，多 tactic/technique/service/vuln） |
| `commands_data.json` / `command_aliases.json` | `skills/index.json`（两层树 + support + 关键词） |
| `SKILL.md`（薄入口知识 + 真实命令行） | `skills/<id>/SKILL.md`（**主工件**：攻击实现方法卡，现行骨架见 002） |
| 技能脚本 | `skills/<id>/entry.py`（固定 argv 装订器；可选——声明式直通卡没有此文件） |
| 路由打分（4/1 加权） | 召回匹配 = `index_builder.match_skills`（selector 与覆盖核对共用同一实现；关键词只排序，不裁决） |

## 9. 当前批次与后续

首批 10 条（覆盖红日 7 v2 图 12 个 AND 节点）：`pre.nmap_tcp_probe`、`exploit.netexec_firewall_off`、`exploit.tongda_oa_include_rce`、`exploit.redis_unauth_write`、`exploit.laravel_ignition_rce`、`exploit.privileged_container_escape`、`exploit.suid_path_hijack`、`exploit.kiwi_lsass_dump`、`exploit.impacket_psexec_cmd`（首选）、`exploit.impacket_wmiexec_cmd`（备选）。

第 11 条（D23 增补，服务**运行现场**而不是某个图节点）：`session.ssh_via_redis`（`provides: ["session"]`、`case: []`）——未授权 redis（`CONFIG SET dir/dbfilename` + `SAVE`）落 `authorized_keys` → SSH 登录验证会话 → 按需复原。图上任何「必须从源主机动手」的节点，先由它把**执行位置**补齐。

第 12 条（D24-a 增补，同样服务**运行现场**）：`post.channel_echo`（`provides: ["session"]`、`case: []`）——在**已经存在**的通道/会话里跑一条固定探针（posix `id -un; hostname` / cmd `whoami & hostname`），marker 切片非空即通道成立，产出 `session_identity` / `session_host`。它与第 11 条共享同一个 need（`session`），但分工是「从零建立」vs「验证已有通道」：运行现场选哪张由**条件**决定，注册表顺序仍是优先级（先试建立，建不了就换验证）。

第 13-15 条（D24-c 增补，节点 41 的方法链 + 中间那一段外带）：

| # | 技能 | 角色 | 固定过程与证据 |
| --- | --- | --- | --- |
| 13 | `exploit.comsvcs_minidump` | 节点 41 的**第二条 dump 方法**（`case: ["lsass_system"]`，与第 8 条同一验证目标） | 在**已有命令通道**里落 dump：`sysnative\rundll32.exe "System32\comsvcs.dll,MiniDump" <pid> <path> full`；证据只到产物本身（`dump_path` / `dump_size` / `dump_magic=MDMP`），不冒充凭据 |
| 14 | `exploit.http_post_file` | 支撑（`provides: ["transfer"]`、`case: []`） | 会话主机上的 `WebClient.UploadFile` → 固定接收端；**双边核对**：源端 `LOCAL <bytes> <sha256>`、接收端 `RECV OK <bytes> <sha256>`，两边逐字一致才写 `transfer_verified=true`，只报一边不算 |
| 15 | `exploit.pypykatz_parse` | 节点 41 的**解析环节**（`case: ["lsass_system"]`） | `sha256sum`（把产物和这次解析绑在一起）→ `pypykatz lsa minidump`；产出 `credential_accounts` / `credential_material`，是唯一一处输出不脱敏的调用（第 10 节「脱敏的例外」） |

**运行顺序就是这三条的顺序**：dump（在目标身上）→ transfer（从目标出去）→ parse（在解析端）。第 14 条不进 `by_case`（它服务的是运行现场），所以覆盖报告里节点 41 仍是「两条 dump 方法 + 一条解析方法」，中间缺的那一段由 `--need transfer` 补——这正是 `provides` 与 `case` 两条召回路径分工的样子。

第 16-17 条（D24-e 增补：同一验证目标在 **Windows vantage** 上的方法。红日图里 node 2/38/48 的 source 是 pc1，而 Kali 与 web1 到不了 192.168.93.0/24）：

| # | 技能 | 角色 | 固定过程与证据 |
| --- | --- | --- | --- |
| 16 | `exploit.wmi_firewall_off` | 节点 2 的**第二条关防火墙方法**（`case: ["disable_firewall", "disable_firewall_credentialed"]`，与第 2 条同一验证目标；两个 case 都留：冻结 `rules5.P` 的三份图用 `disable_firewall`，`rules5_v2` 线用补了凭据前提的 `disable_firewall_credentialed`，见 [rules5_v2 说明](rules5_v2_windows_lateral.md) 的 D32-h 节） | 从 pc1：`net use \\<t>\ipc$` → 往目标 `C$` 落一个固定批处理 → `wmic /node: process call create` 启动它（`netsh advfirewall set allprofiles state off`）→ 回读批处理自写的三档 `EnableFirewall`（0x0/0x1，语言无关）→ 自清。证据 `firewall_state=disabled` 判的是**本次调用之后的状态**；这台 dc 本来就没开防火墙，所以方法不能声称「是我们关的」——批处理把 before/after 都留在原始输出里，就是为这条诚实性 |
| 17 | `exploit.wmic_remote_cmd` | 节点 38/48 的**第三条远程执行方法**（`case: ["windows_credential_remote_system_after_firewall_disable", "windows_credential_remote_system_firewall_state"]`，与 psexec / wmiexec 同一验证目标） | 同一三段式（net use → 目标 `C$` 落探针批处理 → WMI 启动 → 回读）：探针写 `<marker>host/user/sid/done` 块（`hostname` / `whoami` / `whoami /user`），回读成 `hostname` / `identity_name` / `identity_sid`。身份是否够用**不在卡里判**，由节点的 identity rule 判 |

为什么必须是这两条：Kali 与 web1 都路由不到 93 网段（实测），node 2/38/48 的 source 是 pc1，所以方法只能建立在「Windows 自带工具 + 已有命令通道」上。同一台 dc 上的通道对照（D24-e 实跑）：`sc create` 成功但 `sc start` 只回 1053、目标**没有任何产出**；`schtasks /ru SYSTEM` 同样没有产出；`wmic process call create` 可用（`ReturnValue=0` + `ProcessId` + 目标落文件）。负结果留在 `validation_runs.md`，避免有人再试。

第 16/17 条与第 2/10/11 条共享 `by_case`，所以覆盖报告里节点 2 有两条方法、节点 38/48 有三条方法；排序 = 检索分降序（同分回注册表顺序），**Windows 侧方法排前**（vantage 匹配优先），这正是第 5 节「同一召回键下多条技能」的实际用法。

D24-c2 增补（无新卡，通道 + 状态更新）：容器侧通道是 **webshell 驱动的第二种模式** `plain`（第 10 节），卡面不动；`exploit.suid_path_hijack` 经该通道跑通（节点 26，`uid=0(root)`）转 `implemented`；`exploit.privileged_container_escape` 的逃逸链路在靶场**实测成立**（SUID 提权 → 同一请求内 `mount /dev/sda1` → 宿主侧 marker 读写 + 宿主身份），但卡片保持 `planned`：它的前提是「容器内 root 会话」，而当前 `session_ref` 只能描述「裸 www-data 通道」（`CapEff=0`，`mount` 被拒）——缺的是权限上下文建模，不是方法本身（证据与缺口见 `validation_runs.md` D24-c2 节）。该缺口 **D31 已关闭**：`session_ref.min_privilege` 落地、提权供给（同页第 19 条）把通道升到 root，卡片随节点 22 实机闭环转 `implemented`（见 `validation_runs.md` D31 节）。

第 18 条（D30 增补，服务**运行现场**；第一个「容器类」供给位置）：`session.webshell_via_laravel`（`provides: ["session"]`、`case: []`、`status=implemented`）——容器（web2_docker）没有自己的地址，只有「web1:81 转发进来的入口」：用与 laravel 卡同一份固定 Ignition PoC，把 173B 的 `popen($_GET['cmd'] . ' 2>&1')` webshell 写进容器 webroot，再用通用 plain 客户端（`runtime/clients/agv_http_cmd.py`）探针验证会话应答（`target_echo_present`）。四步固定过程 `client → drop → probe → restore`；`restore` 默认 false——通道留存才是资产，登记进 `run_result.channels{}` 给后续节点复用（节点 26 的 SUID 提权就是它的第一个下游）。实机：`D30-path3`（默认路径）节点 26 `succeeded`、`granted.web2_docker=root`。

第 19 条（D31 增补，服务**运行现场**；第一个「提权」供给位置）：`session.root_via_suid`（`provides: ["session"]`、`case: []`、`status=implemented`）——运行层已经握着一条通道、但通道的身份达不到节点卡要求的等级时，把这条通道**升上去**：固定三步 `find`（列 SUID）→ `probe`（现在的身份）→ `verify`（判据所在调用：经提权包装再问一次身份）。包装是**命令级**的（`sh -c "<覆盖写 helper> && PATH=<helper_dir>:$PATH <suid_binary>" agv "<command>"`），因为容器里的会话是一次请求一个命令的 http shell，升级只能落成「这条命令怎么发」，不能落成一个进程。它带出 `identity_before` / `session_identity` / `session_host` / `suid_binary` / `escalate_mode`，并把 `envelope.channel` 更新成「同一条入口 + 提权包装 + 观测到的身份」；**已经带 `escalate` 的通道会被拒绝**（二次提权会掩盖运行层正在信任哪个包装）。D24-c2 记的「`session_ref` 表达不了容器内权限上下文」缺口到此关闭：`exploit.privileged_container_escape` 的 `session_ref` 声明 `min_privilege=system`（第 10 节的字段，绑定规则见第 11 节），运行层在供给阶段把 www-data 通道升成 root 通道，节点卡再原样执行。实机 `D31-path3`（默认路径）：节点 22 `succeeded`、`granted.web2=root`（证据链见 `validation_runs.md` D31 节）。

### 方法链（chains）：`lsass_system` 的 dump → 外带 → 解析（D29 登记为注册表数据；旧编号节点 41 = 新图 `node-5`）

第 13-15 条此前只是「按顺序各跑一次」，D29 把这条顺序登记成注册表里的**链**（第 3 节 `chains`），
节点 41 的 `lsass_system` 因此由**一条方法**（而不是三次互不相干的调用）完成：

| 段 | 角色 | 卡 | 段间绑定（`src/runtime/supply.py`，每一条都有测试） |
| --- | --- | --- | --- |
| 1 | `dump` | `exploit.comsvcs_minidump` | 证据 `dump_path`（+ `hostname`）→ 下一段的 `source_path`；缺 `dump_path` ⇒ 链停在这一段并说清原因（`chain_unfolded`） |
| 2 | `exfil` | `exploit.http_post_file` | run 提供接收端 URL 与落点目录；由落点反推 `local_path` → 下一段的 `dump_path` |
| 3 | `parse` | `exploit.pypykatz_parse` | 读 `local_path`；产物来源 `hostname` 随段传下去并写进解析证据（target 闸因此能对账） |

- **角色有语义，不是标签**：`dump` 在目标身上落产物、`exfil` 把产物搬出去、`parse` 在执行端读出材料；每个角色带**段级超时下限**
  （dump 120s / exfil 900s / parse 300s）——探针很快，把 34 MB 从 Windows 搬出来不快，而 CLI 的 `--timeout` 是整次 run 的一个数，
  段级下限保证慢段不被统一超时掐死（实际用的值写进节点结果的 `chain.trace[].timeout`）。
- **链也不发明事实**：段只吃上一段真的交出来的值，拿不到就停（`chain_unbound` / `chain_unfolded`），绝不拿默认值往下跑；
  链自己会产生的值（`chain_binds`）不算节点的待补值——否则节点会被自己马上要造出来的值堵死（D29 实机暴露后修）。
- **一次链 = 一个节点结果**：`chain_done`（末段通过）/ `chain_segment_unsatisfied|uncertain`（停在哪段、为什么）/
  `chain_unbound`（段输入拼不齐）/ `chain_unfolded`（段跑通但取不到下一段要的字段）；每段留各自 `attempt-N-<skill>/`。

首批已落地（2026-09-16）：

1. ✅ 适配器：20/20 条行动与支撑卡 `entry.py` 就位（argv 固定、脱敏、原始输出落盘）；20 条 `status=implemented`（实机跑通并留下 `output/runs/` 调用记录；D40 追加 `exploit.impacket_psexec_cmd` / `exploit.impacket_wmiexec_cmd`，D41 追加 `exploit.netexec_firewall_off`，D43 追加 `session.msf_via_credentials` / `exploit.kiwi_lsass_dump`）—— 状态只跟着实机证据走（见第 10 节）。D48 起在册 27 条、r2 批次五张新检查卡登记后 32 条：**27 implemented + 5 planned**（`session.msf_migrate` 会话迁移 + `pre.tool_present` / `pre.session_identity` / `post.file_present` / `post.identity` 四张检查卡；planned 不要求 `entry.py`）。D60 批次把 7 张 `model` 检查卡实机跑通转 `implemented`（见 `validation_runs.md` 的 D60 节）。
2. ✅ 方法卡（D47）：20/20 条 `SKILL.md` 按 [002 模板](../../specs/002-generic-skill-methods/spec.md) 八段重写——主体是「这类攻击用 Kali 的哪个工具、哪个功能、怎么做」，命令模板/判据/模型自由度分开写；正文靶场专有词 0 行（守线 `tests/test_skill_cards.py`），红日 7 实测记录只留在各卡末段。
3. ✅ 备选卡（同一验证目标、多条方法卡，注册表顺序即优先级）：节点 2 有 `exploit.wmi_firewall_off`（Windows vantage）与 `exploit.netexec_firewall_off`；节点 38/48 有 `exploit.wmic_remote_cmd` / `exploit.impacket_psexec_cmd` / `exploit.impacket_wmiexec_cmd`；节点 41 有 `exploit.comsvcs_minidump` 与 `exploit.kiwi_lsass_dump`。规则见第 5 节「同一召回键下多条技能」。
4. ✅ 选择器：`src/skills/selector.py` + CLI `scripts/select_skill.py`（第 11 节）；红日 7 节点 26 已能自动解出 `path=/tmp`，缺的只有 `session_ref`（`pending`）。
5. ✅ 索引扩展：`by_case`（图词汇精确键）已启用；21 条在册里 14 条声明了所服务的 case，共 10 个 case（8 条支撑类全部走 `provides` 召回——其中 1 条同时绑 case（`pre.nmap_tcp_probe`）；D36 起没有单独的 `purpose` 字段）。
6. ✅ 实机验证：靶场在线，`pre.nmap_tcp_probe` / `exploit.redis_unauth_write` / `exploit.laravel_ignition_rce` / `exploit.tongda_oa_include_rce` / `session.ssh_via_redis` / `post.channel_echo` / `exploit.comsvcs_minidump` / `exploit.http_post_file` / `exploit.pypykatz_parse` / `exploit.wmi_firewall_off` / `exploit.wmic_remote_cmd` / `exploit.suid_path_hijack` / `session.webshell_via_laravel` / `session.root_via_suid` / `exploit.privileged_container_escape` / `exploit.netexec_firewall_off`（netexec 版，D41）/ `session.msf_via_credentials` / `exploit.kiwi_lsass_dump`（D43 msf 常驻端点车道）**二十条**已跑通并转 `implemented`（run → call_id 见 `validation_runs.md`）；`skills/index.json` 的 `status_counts` 是派生视图（当前 **27 implemented + 5 planned**；D60 批次 7 张 `model` 检查卡实机转正，见 `validation_runs.md` 的 D60 节）。节点 41 的方法链（dump → 外带 → 解析）已整条跑通；它依赖的 leaf（域管凭据）此前因靶场没有域管交互登录而**不成立**（环境前置，不是方法缺陷）——**D39 已补齐目标状态并读出域管**：pc1 上一次域管交互式登录后跑同一条链，解析段给出 `username Administrator` + `WDIGEST password`（`output/runs/D39-live1/node-5/attempt-3-credential.parse.minidump_pypykatz/`）；该材料与图上 `domain_administrator` 槽位之间的映射仍需运行输入显式给出（运行层不猜，见 `validation_runs.md` 的 D39 节 §4）。D29 整图 run（`D29-path`）里第 13-15 条已按**链**整条自动跑完（`chain_done`，三段各留 call），不再是手工三次调用。
7. ✅ 执行器链：`src/runtime/chain.py`（第 10 节「多跳执行位置」）——第一跳是传输，后续每跳都是命令包装，解决「图说谁动手，命令就在谁身上跑」。
8. ✅ 运行时供给检索：注册表 `provides` + 索引 `by_provides` + 选择器 `--need`（第 11 节「运行现场模式」）。
9. ✅ 方法链（D29）：注册表 `chains`（第 3 节）+ 索引 `by_chain`（第 5 节）——节点 41 的 dump → 外带 → 解析成为**一条**方法，
   段间绑定有测试、段级超时写进 trace、每段各自可复判；「顺序」从运行脚本挪进数据，运行期不再拼装。
10. ✅ 容器会话供给（D30）：第三类 session provider -- 「公开端点背后的容器」（第 14 节）；通道声明 envelope.channel 让卡片留下的通道成为运行资产；
    链的锁定改为 supply.locked_chain（--include-planned 不能替换节点已注册的方法链）；target 闸接受运行层注入的运行时别名（容器短 id 与图主机的另一种拼写）。
    实机 D30-path2（修复验证）/ D30-path3（默认路径）连续跑通：节点 26 由 need 变 succeeded、节点 41 保持 chain_done（见 validation_runs.md 的 D30 节）。
11. ✅ 会话权限上下文（D31）：权限词汇唯一真源 `src/runtime/identity.py`（`RANK` / `tier_of` / `satisfies` / `required_tier`，checker / run / run_path 三处各写一份的词表全部退场）；卡能声明 `session_ref.min_privilege`，选择器把「值在、但不够强」记成 `pending` + `privilege` 缺口；运行层第四条 session provider（`session.root_via_suid`）把弱通道升成够强的通道；通道登记规则改为「首个胜出，等级更高者可接管」（`_channel_upgrade`）。实机 D31-path / D31-path2 / D31-path3 三跑：默认路径下节点 22 由 `blocked:no_method` 变 `succeeded`，`granted.web2=root`（见 validation_runs.md 的 D31 节）。

有节点但没有方法、或方法跑通了却拿不到目标材料，都是**缺口**：登记到[技能补卡清单](skill_backlog.md)，补上之后按本契约加卡，不在这里编条目。

## 10. 适配器运行约定（首批已落地）

适配器就是 `skills/<id>/entry.py`，只做四件事：绑定输入 → 固定 argv → 执行 → 解析成证据。匹配、优先级和判定都不在这里。

### 统一 CLI

```powershell
python skills/<id>/entry.py --input inputs.json --run-dir output/runs/<run_id> --plan
python skills/<id>/entry.py --input inputs.json --run-dir output/runs/<run_id> --timeout 60
```

- `--input`：JSON 对象（图事实 + 运行现场补给），`-` 表示读 stdin；按 `utf-8-sig` 读，容忍 Windows BOM。
- `--run-dir`：本次 run 的产物根目录，**每次调用一个子目录**。
- `--plan`：只打印将要执行的 argv（同样脱敏），不执行也不落盘——这是「适配器固定过程」的核对入口。多步方法会额外给出 `steps`（每一步的 argv）或 `session_plan`（会话里将要输入的控制台行，驱动无关命名）。
- `--timeout`：执行器超时秒数（各适配器有自己的默认值）。

### 每次调用落什么盘

```text
<run_dir>/<call_id>/
├─ call.json     # call_id、技能、脱敏后的 argv、returncode、状态、耗时、产物路径
├─ stdout.txt    # 脱敏后的原始输出
└─ stderr.txt
```

证据只认这些产物：后来复盘时，任一 `evidence` 字段都能追回到产生它的那一次调用。

### 返回信封（stdout JSON）

| 字段 | 含义 |
| --- | --- |
| `skill` / `call_id` | 技能与调用标识；`call_id` 是 freshness 的证据来源 |
| `status` | `executed` / `timeout` / `tool_missing` / `transport_error`；`tool_missing` = 执行环境没有该工具（不是证据不足）；`transport_error` = 命令没跑完（连接/传输失败），**绝不允许当证据** |
| `evidence` | 只放技能卡 `output.evidence` 声明的字段；没观测到就不出现（例：nmap 没报告端口状态时没有 `state`） |
| `raw` | 原始输出对应的产物文件（stdout/stderr） |
| `markers` | 本次调用带下去的标记（如 psexec 探针的 host 侧回显），供 freshness 判定 |
| `channel` | 卡片声明「我留下了一条可复用通道」（`driver` / `mode` / `base_url` / …）——通道是**状态不是证据**（第 14 节）；缺 `id` 时运行层按 `<host>-<driver>` 命名，卡片不需要知道 run 管这台主机叫什么 |
| `argv` / `returncode` / `started_at` / `duration_s` / `artifacts` | 调试与追溯 |
| `calls` | 多步方法的每一步调用（`call_id`、argv、状态、耗时）；只在超过一步时出现 |
| `sensitive` | 产物含明文凭据（如 LSASS 转储），调用目录按敏感产物处理 |
| `notes` | 降级/放弃时的解释（如「发现候选为空，未做劫持」），不参与判定 |

### 脱敏

显式凭据（当次解析出的口令/哈希）一律替换为 `<redacted>`；再按形状兜底：NTLM 哈希对、`password=` / `token=` 片段、`Authorization:` 头。`-p` 这类一名两义的短旗标不全局清洗，由适配器显式声明（nmap 的 `-p` 是端口，impacket 的 `-p` 是口令）。

### 可测性

`runtime.runner.execute(..., executor=...)` 允许注入假执行器，所以适配器不接靶场也能回归（见 `tests/test_runtime_adapter.py`）。生产用本机/Kali 上的 subprocess 执行器。

### Windows 命令通道的硬坑（D24-b / D24-e 实测，改适配器前先看）

1. **回显会折行，而且折在 token 内部**：通达 OA 这条通道按约 78 列硬折行，一个注册表路径会以
   `...Fi` + 换行 + `rewallPolicy...` 的形式回来（run `D24-e-fw` / `call-20260916T010730-207194`），
   任何「按行读」的解析都会静默失败。解析前先过 `runtime.adapter.squash()`（把换行整段去掉），
   再在单行副本上做正则；卡 A / 卡 B 的 `probe_block` 都建立在这上面，卡 B 还要把尾部 `done`
   标记一起切进来，否则 `_between` 找不到右边界。
2. **PowerShell 数组字面量里不要拼字符串**：`@('echo x > ' + $path, ...)` 在 PS 2.0（pc1）与 5.1
   （本机）上行为一致——**逗号比 `+` 紧**，一个元素被拆成「每个操作数一个元素」，送到目标上的
   `.bat` 就成了十几行碎片，`cmd` 什么也不做（run `D24-e-diag2` 是铁证）。固定脚本里的路径/名字
   一律用 `@@OUT@@` 这类占位符在适配器里绑定；`tests/test_skill_adapters.py` 有静态断言守住这条。
3. `powershell -nop -EncodedCommand <b64(UTF-16LE)> < nul` 是这条通道上唯一可靠的姿势（`< nul` 不可省，
   否则 PS 的 stdin 是坏管道、完全不执行）；单条命令长度按 7500 字符卡住（`cmd.exe` 8191 / 请求行），
   超了在**发之前** `SystemExit`。

### 远程执行器（实机验证用）

实机验证的既定口径是「**控制端 = 本机里的 Kali**」，但适配器要在 Windows 控制机上跑（它负责固定 argv、解析证据、落盘）。两者靠 `src/runtime/remote.py` 的 SSH 执行器缝合：

```powershell
python scripts/run_skill_remote.py --skill pre.nmap_tcp_probe --input inputs.json --run-dir output/runs/<run_id> --remote kali@192.168.52.128 --password kali
```

- `--remote user@host[:port]`；口令走 `--password` 或环境变量 `AGV_SSH_PASSWORD`，也可用 `--key`。
- 相对路径按**项目根**解释（`--input` / `--run-dir` / `--chain`，与其他入口脚本同一口径）：从任何目录调用，读到的都是同一份输入、写出同一份产物。
- 适配器进程在本地，`argv` 通过 paramiko 在 Kali 上执行；产物仍落本地 `<run_dir>/<call_id>/`，与本地执行**同一套** runner 契约（call.json / stdout.txt / stderr.txt）。
- 工具缺失（远端 127）→ `tool_missing`；SSH 超时 → `timed_out` 并断开重连；连接层异常 → `transport_error`（`returncode=None`，绝不当证据）。
- 凭据不回显：命令在 `command_line` 里做 shlex 引号，日志按第 10 节脱敏规则处理。

#### 多跳执行位置（执行器链）

攻击图里说「谁动手」：`attacker → web1:6379`、`pc1 → dc:445`、`web1 → pc1:8080`（OA）、`pc1 → pc2`。执行位置因此是 run 的一等公民，`src/runtime/chain.py` 用**链**表达：

```powershell
python scripts/run_skill_remote.py --skill <id> --input inputs.json --run-dir output/runs/<run_id> \
    --chain data/inputs/hongri7/chains/kali_to_web1.json
```

```json
{"hops": [{"kind": "ssh", "target": "kali@192.168.52.128", "password_env": "AGV_SSH_PASSWORD"},
          {"kind": "ssh", "target": "root@192.168.52.10", "key": "/home/kali/.ssh/agv_session"}]}
```

- **第一跳是传输**（paramiko 连到执行段），**后续每一跳是命令包装**：上一跳执行 `ssh <target> '<引号后的 argv>'`。`--chain` 与 `--remote` 二选一；`--remote` 就是单跳链的简写。
- 内层跳**必须**给 `key`：外层 `BatchMode=yes` 下口令交互会挂，所以链在**加载时**就报错，而不是跑到一半才发现跳不进去。
- 每次调用把 `vantage`（如 `kali@192.168.52.128 -> root@192.168.52.10`）写进 `call.json`：证据可追到「从哪打的」——这是图的 source 语义在执行侧的落点（来源闸）。
- `SshHop` 只回答「怎么跳」，不碰技能逻辑；将来换传输方式（msf 通道、会话代理）＝ 新增一个 `kind`，适配器与判据不动。


#### 方法链的段（chain segment）运行约定（D29）

链的段复用同一套适配器契约，三处运行期约定写在这里：

- **段输入由 run 绑定**，不是模型拼的：`session_ref`（run 在目标主机上持有的会话）、接收端 URL（run 自己起的接收口）、
  上一段的产物路径，全部由 `supply.segment_inputs` 生成；链缺东西时在**发命令之前**就报错（节点记 `chain_unbound`）。
- **接收端是 run 起的一次性服务**：`exfil` 段前起 `agv_http_recv.py --once`（收完一个请求就退出），段后无论成败收尸；
  落点目录与文件名由 run 决定，`parse` 段读的正是那个 `local_path`（`receiver_plan` 一处推导，两段共用）。
- **证据归属链清楚**：每段各自一次 `call_id`、各自三闸判定；链只决定「下一段拿什么当输入」。链结束时节点的观测取
  **最后一段**（失败时取停下的那一段），全部 `attempt-N-<skill>/` 目录照旧保留，逐段可复判。

### status 何时改成 implemented

入口脚本存在只是必要条件。`implemented` 要等实机跑通、并在 `output/runs/` 留下调用记录之后再改；在那之前保持 `planned`（卡片 `notes` 里写明这一点），避免把「代码写了」当成「验证过」。

### 一次方法多步调用

一条技能内部可以多步（「先关防火墙再回读」「先上传再包含」），但只有**主调用**进入顶层字段用于判定；其余步骤出现在 `calls` 里，`--plan` 用 `steps` 给出全部 argv。判定用的 `call_id` 始终是主调用。

### 会话类技能：`session_ref` 与三个驱动

容器逃逸、PATH 劫持、LSASS 转储这三条不对目标直接发命令，而是**在已有会话里执行**：

- 输入：`session_ref`，字符串 `msf:<id>` / `agent:<id>`，或对象 `{"driver": "msf|agent", "id": "3", "shell": "posix|cmd"}`；`webshell` 只以对象形式出现，见下。
- 驱动契约（三个驱动都必须满足，缺一不可）：① 每条命令包在 `<marker>start ... <marker>end` 之间；② 目标回显**原样**打印（驱动不得吞掉或改写目标输出）；③ 整段 transcript 落盘到本次 `call_id` 目录。
- `msf` 驱动（默认，D43 起重写）：会话在**常驻 msfrpcd 端点**里（会话是进程内状态，一次一进程的 `msfconsole -r` 看不到上一次建的会话）。适配器调固定客户端（`runtime/clients/agv_msf_rpc.py`，部署在执行端 `/opt/agv/tools/`）：单命令 `session-run --sid <id> --command[-b64]`、脚本行 `session-script --sid <id> --lines-b64`。命令一律走 base64 argv（穿多层引用），密码不进 `--options-b64`（会破坏脱敏）。
  - **新鲜度的唯一例外条款**：meterpreter 没有 shell 可回显 marker，驱动契约的第 ① 条在这条车道上改由**读协议**满足——每次调用先 drain 会话积压、再读到输出静默（默认 `--idle 2.0`）才收；`runtime/session.py` 里明写这是唯一一处例外。
  - 控制台行只认 meterpreter 自己的命令（`sc query` 会得 `[-] Unknown command`）：**shell 命令卡走 agent/webshell 通道**。
- `agent` 驱动（自建会话代理）：命令走代理自己的 exec 接口——单命令 `agv-session exec --session <id> --shell <posix|cmd> -- <wrapped>`，脚本行 `agv-session rc --session <id> --file <rc>`；CLI 可用环境变量 `AGV_SESSION_AGENT_CLI` 覆盖（空格分隔）。
- `webshell` 驱动（http-include 通道，D24 增补）：shell 是**一个地方，不是一个进程**，所以描述符是**通道状态不是凭据**——对象必须带 `base_url` 与 `include_path`（缺任一项在解析阶段直接 `SystemExit`），`client` 缺省 `/tmp/agv-payloads/agv_oa_http.py`（执行端上的固定客户端）。单命令调 `python3 <client> <mode> <base_url> <include_path> <wrapped> <timeout>`；**不支持 console 脚本**（没有控制台可喂行，`session_script` 直接报错）。请求经**当前 executor** 发出：走 chain 时从链末端出去，也就是图里 `source` 那台机器，而不是控制机——与 `msf`/`agent` 的 vantage 语义一致。
  - 两种模式（D24-c2）：`mode` 缺省 `include`（LFI 型：命令经已落盘文件执行，客户端是卡自带的 OA 客户端）；`plain` 用于「路径本身就是命令 shell」的落地点（如容器里自己落的固定 webshell）：命令直接进 `?cmd=<urlencoded>`，客户端用**通用的** `runtime/clients/agv_http_cmd.py`（stdlib、python3.6 兼容；不做 200 判定、不重试——成败留给判据，连接失败由 runner 映射成 `transport_error`）。`mode` 是客户端子命令，所以卡自带客户端与通用客户端可以互换；非法 `mode` 在解析阶段直接 `SystemExit`。
  - D30 起，这种 plain 通道也可以由**供给卡主动建立**（第 9 节第 18 条 `session.webshell_via_laravel`），并把通道状态声明在 `envelope.channel`：运行层登记进 `state.channels[host]`（第 14 节），下游节点直接复用；「曾经打通过」与「现在还能用」仍由复验卡（`post.channel_echo`）分开管。
  - **权限上下文随通道走（D31）**：`session_ref` 可以多带三个字段——`identity`（对面自报的身份）、`privilege`（等级，由身份推导；词表在 `src/runtime/identity.py`）、`escalate`（把命令送进更强身份的**前缀**，形如 `{"argv": ["sh", "-c", "...", "agv"]}`）。解析阶段：`escalate` 声明了却给不出可用 argv ⇒ 直接 `SystemExit`（声明了强身份却到不了，宁可不发这条命令，也不静默降权）；畸形声明被丢弃，但**身份声明保留待验**。发送阶段：**五个驱动出口**（msf `sessions -c` / agent `exec` / webshell plain|include / `--plan` / 预览）统一把命令套进前缀（`shlex.join(prefix + [command])`）——**marker 仍在最外层**：marker 证明通道回答了，中间的 `user` / `host` 段落由提权后的 shell 产出。
  - **卡能要求等级**：`skill.json` 的 `session_ref` 输入可写 `min_privilege: user|admin|system`（D31 起进 schema）。等级不够**不算 `missing`**（值确实在），而是 `pending` + `privilege` 记录（`{required, holds, identity}`），运行层据此去升级通道（第 14 节第四条 provider）——「图缺口」与「现场缺口」两个口径不能混。
- 证据只认目标回显：transcript 会连命令本身一起回显，所以取**最后一个** `start` 标记及其之后的**第一个** `end`；只看到命令回显、没看到目标输出 → 不算证据。
- `--plan` 输出 `session_plan`（会话里将要输入的内容，驱动中立），不是 `argv`。
- 换驱动只改 `src/runtime/session.py`：适配器、判据、注册表都不动（新增驱动 = 在 `DRIVERS` 里加一个实现 + 一条驱动契约回归测试）。

### 备选卡与失败回环

同一条边可能需要第二种打法（服务创建被拦 → 换 WMI）。落法是**再登记一条方法卡**，不是给第一条卡加分支：

- 两条卡共享同一个验证目标（`technique + service` 相同），因此召回时作为同一键下的候选列表返回；
- 顺序即优先级，运行时先跑第一条；第一条拿不到证据（工具缺失/前提不成立/证据不足）时，按顺序换下一条；
- 换卡时把失败原因落在 records 里（属运行时数据，不进目录 json）：是"条件不满足"就补条件，是"方法不对"才换卡。

### 敏感产物

`exploit.kiwi_lsass_dump` 的产物**就是**凭据材料，脱敏掉就没有证据了。这类技能的适配器把信封字段 `sensitive` 置 `true`，调用目录里的原始输出就是未打码材料，复核与分享时按敏感产物处理；其余技能一律按本节前面的脱敏规则执行。

### 脱敏的唯一例外：`keep_material`

`runtime.runner.execute(..., keep_material=True)` 会关掉这一**次**调用的 stdout/stderr 脱敏，给的是同一种理由：被打成 `<redacted>` 的 NT 哈希不是证据，脱敏会把卡片存在的意义一起删掉（D24-c 实测：凭据解析卡首跑输出 `NT: <redacted>`，只有明文口令活下来——`redact.py` 的形状兜底把 32 位十六进制当成了秘密）。

- **argv 照旧脱敏**：例外只覆盖输出正文；
- `call.json` 写 `material_kept: true`，复核者一眼能看出哪些调用带未打码字节（`output/runs/` 不进 git，仓库里只留索引表）；
- 目前只有两张卡用它：`exploit.pypykatz_parse`（凭据行就是产物）与 `exploit.kiwi_lsass_dump`（kiwi 控制台输出同理）；`exploit.http_post_file` 只搬文件字节、不打印凭据，因此**不用**这个开关；
- 它是**具名例外，不是开关**：别的卡需要未打码输出时，先说明它的证据为什么必须是材料本身，再改卡片。

### 装配通道（`assembly=model`，D50）

`fixed` 卡的命令行由装订器装配；`model` 卡交给执行面 `src/runtime/assembly.py`。它做四件事，全部确定性：

1. **brief（三件套）**：从 `SKILL.md` §怎么做抽出的模板块（带 `label` 与 `template` / `example` 分类）、参数契约
   （声明 / 是否绑定 / **材料类只给 `withheld` + 形状提示**）、marker 纪律（`<marker>` 占位、会话通道的
   `<marker>host` 段、msf 通道「没有 shell 可回显 marker」的例外条款）。**材料值不进 brief**——模型填形，运行层填材料。
2. **装配**：模型的答案先过 `validate()` —— 空命令 / 超长 / 未绑定占位符 / 自造 marker / shell 通道多行命令 /
   msf 通道带 `<marker>`，六类拒绝；过了就用它，没过就用**规则答案**（模板首个 `template` 块的第一行并替换占位符；
   msf 通道是全部命令行）。规则也装配不出来时**不开跑**（`SystemExit`，循环记成失败尝试），不发半截命令。
3. **执行**：直连 = `sh -c` + `<marker>start … <marker>end`（stderr 一并折进观测区）；会话通道（`agent` / `webshell` 驱动）
   = `session.session_command`，运行层自动补 `<marker>host ; hostname` 段（**追加在命令后**：它后面的行才归下一个段）；
   msf 通道 = `session.session_script` 逐行送达。argv / stdout 的脱敏与 `fixed` 卡同一套，`keep_material` 的例外条款不变。
4. **解析**：`PARSERS`（每张 model 卡一个）把回显读成卡片声明的那几个证据字段。`observed is None`（目标没回显 marker 块）
   一律不给正证据（判 `uncertain`）；「命令答了但没有」才是确定负事实（如 `tool_present=false` → `unsatisfied`）。
   卡片声明的证据字段与解析器产出由守线逐卡比对（`tests/test_assembly.py`），声明了没人读的字段就红。

信封比 `fixed` 卡多一段 `assembly`：`source`（`model` / `rules`）、`driver`、`command`（**替换前的占位形式**，
材料不在其中）、`rejected[]`（模型答案被拒的原因）、`unbound[]`。判定仍由第 12 节的判定器按固定序列（`freshness` → `target` → 本卡判据）给出。

入口侧：`scripts/run_node.py` 按卡上的 `assembly` 分路（`model` → `runtime.assembly.run`），
`--model` / `--model-base-url` / `--model-api-key-env` / `--model-timeout` 打开模型接缝的第四个任务
`assemble_command`（不给 `--model` 就是规则装配）。

## 11. 选择器：图节点 / 运行需求 → 锁定技能（selector）

`src/skills/selector.py`，入口 `scripts/select_skill.py`：

```powershell
python scripts/select_skill.py --graph output/hongri7/json/Hongri7_v2.action_graph.json --node 48
python scripts/select_skill.py --graph output/hongri7/json/Hongri7_v2.action_graph.json --node 26 --context runtime.json --host-map hosts.csv
python scripts/select_skill.py --need session --node 7 --graph output/hongri7/json/Hongri7_v2.action_graph.json --assets data/inputs/hongri7/assets.json --from 192.168.52.128
python scripts/select_skill.py --need session --context runtime.json
python scripts/select_skill.py --fact exec_code --context runtime.json
```

- **需求投影**：节点 `attack_id` + `service`（+ 端口）→ `technique` + `service` 需求；支撑节点按 `case`（面向图）或 `provides`（面向运行现场）召回（D36 起没有单独的 `purpose` 字段）。
- **召回只有一个实现**：复用 `index_builder.match_skills`（第 6 节的覆盖核对用同一个函数），避免「选择器说能打、覆盖核对说没覆盖」两套口径。
- **锁定 = 第一个绑定得齐的候选**（候选按检索分降序，同分回注册表顺序）；其余候选进 `alternatives`，失败回环按序换卡（第 10 节「备选卡与失败回环」）。
- **绑定规则**（`skill.json` 里每个输入声明 `from`）：

  | `from` | 找不到时记什么 | 含义 |
  | --- | --- | --- |
  | `graph` | `missing` | 图没有这个事实——要补图，不是换工具 |
  | `runtime` | `pending` | 运行现场还没给（会话、口令），等着，不算失败 |
  | `config` | 不记 | 运行配置可空，适配器有自己的默认值 |

- **缺事实不臆造**：图里没写的参数不猜、不兜底；缺什么报什么，喂给 planner 和追溯。
- **主机对账**：`--host-map` 提供 `host,ip` CSV（攻击图只写逻辑主机名）；映射不上时保留原名并记 `notes`，不静默。
  红日 7 的本地表是 `data/inputs/hongri7/host_ip_map.csv`（`pc1,192.168.52.30` 这样的两列；`data/inputs/` 不进 git）。
  D29 首跑就是靠它把观测里的 `PC1` 与节点目标 `192.168.52.30` 对上；缺这一环时判定器会自己点名：
  `observed target (session_host=PC1) cannot be aligned with the node target (target_host=192.168.52.30) … supply --host-map to settle it`。
- **运行现场模式（`--need <reachability|session|transfer|credential>`）**：问的不是「这条边用哪个技能」，而是「这次 run 缺一个会话/凭据/传输/可达性，谁能给」。候选来自索引 `by_provides`；`--node` 只用来把「需要它的那台机器」推出来（取节点的 `source_host`，再按 `--assets`/`--from` 解析成地址），地址解析与节点模式**共用同一段实现**，两条路径不会各写一套。
- **检查模式（`--fact <hacl|exec_code|ttp_exists|network_service_info|leak_account|path_exists>`，D48）**：问的是「这条 LEAF 事实谁能核出来」——pre 卡回答「打之前成不成立」（程序在不在、通不通、凭据能不能登、我是谁），post 卡回答「打之后是不是真的」（产物在不在、身份够不够）。候选来自索引 `by_fact`，输出形状与 `--need` 相同（`locked` / `inputs` / `ready` / `pending` / `providers[]`），状态政策一致：`planned` 检查卡默认被挡下并在 `excluded[]` 点名，`--include-planned` 是逃生门。
- **两种模式输出同形**：`locked`（检索分排序里的第一条可用者；需求/事实模式仍按注册表顺序）/ `inputs` / `ready`（无 `missing` **且**无 `pending`）/ `alternatives` / `providers[]`（= 节点模式的 `candidates[]`）+ `notes`。`--inputs-out` 两种模式都能写出「可直接喂适配器」的 `inputs.json`。
- **输出**：`locked` / `inputs` / `ready` / `alternatives` / `candidates[]`（每个候选带 `missing`、`pending`）/ `excluded[]`，可直接喂给执行器或落进 records。
- **状态策略（D28）**：默认只锁 `implemented` 卡片。`planned`（还没有任何实机跑通过的记录）与 `deprecated`（退役）
  **不进 `candidates`**，而是进 `excluded[]`（`id` / `status` / `reason`）并在 `notes` 里点名。于是「这个节点只有未验证的方法」
  报的是 `no_method` + 被挡下的卡名，而不是伪装成「缺一个会话」；缺口不会被状态策略掩盖。操作员确实要用未验证方法时
  显式打开 `--include-planned`（`select_skill.py` / `run_node.py` / `run_path.py` 同一开关），此时候选 JSON 仍带 `status`，
  证据里看得出它不是已验收的方法。
- **等级缺口（D31）**：`session_ref` 的 `min_privilege` 由选择器比对**运行现场持有的会话等级**：不够 **或等级未知** 都记 `pending`（未知不当成够用），同时在该候选上写 `privilege` 记录（`{required, holds, identity}`）。写进 `run_result.needs[].privilege`，运行层据此决定「要不要先升级通道」。比较规则只有一份：`runtime/identity.py` 的 `satisfies()`（含契约的 `admin ≡ system` 等价；`required=None` 不算通过）；`RANK` 只用于报告排序。

## 12. 判定器（checker）：固定序列、三判、可复判

`src/runtime/checker.py`，入口 `scripts/check_call.py`（复判已落盘的调用）与 `scripts/run_skill_remote.py --check`（跑完即判）：

```powershell
python scripts/check_call.py --call output/runs/D25-checker/call-20260916T021135-dd6fa5 --node 14 --graph output/hongri7/json/Hongri7_v2.action_graph.json --assets data/inputs/hongri7/assets.json --control 192.168.52.128
python scripts/check_call.py --call <call 目录> --requirement '@output/runs/<run>/requirement.json' --write
python scripts/run_skill_remote.py --skill pre.nmap_tcp_probe --input inputs.json --run-dir output/runs/demo --remote kali@192.168.52.128 --check --node 14 --graph output/hongri7/json/Hongri7_v2.action_graph.json
```

- **分工不变**：适配器只解析，判定只归 checker；模型不能自证成功，`tool_missing` / `transport_error` / `timeout` 永远不算证据。
- **输入**：调用信封（`evidence` / `markers` / `status` / `call_id`）+ 卡片 `judge` + requirement（节点 facts：目标、端口、要求的身份等级）+ 绑定输入（`value` 类规则要用，例如 `readback_value==value`）+ 原始产出文本（核对 marker）。
- **固定序列、三判**（卡只写一个判据名；与第 4 节词表一致）：

  | 闸门 | 判什么 | 不过时 |
  | --- | --- | --- |
  | `freshness` | 证据来自**本次调用**：`call_id` 锚定、`status` 说明命令跑完、卡里带下去的 marker 出现在原始产出里（没有 marker 的卡只锚 `call_id`） | `uncertain` |
  | `target` | 观测目标（`hostname` / `target_host` / `target_url` / `host` / `session_host`）+ 端口对齐节点目标（`--host-map` / assets 的名字↔地址对账；图里的逻辑主机名也在对账集合里；**运行时别名** `requirement.target_aliases` 同样参与：会话宿主自报的容器短 id 由运行层在「宿主就是节点指向的图主机」时注入，D30） | `uncertain`（对不上多是「对账缺口」，不是「事实为假」） |
  | `identity` / `effect` | 卡片声明的**单个判据名**（`IDENTITY_RULES` 里的走 `identity` 行，其余走 `effect` 行；见下表） | `unsatisfied`；缺证据固定 `uncertain` |

- **聚合**：阻塞闸门只要有一条 `unsatisfied` → 总判定 `unsatisfied`；否则有 `uncertain` → `uncertain`；全过才是 `pass`。结果里的 `value`（`true` / `false` / `null`）与运行数据契约的 `records.kind=check` 对齐，落库不用再翻译。
- **规则登记表**（判定器实现的全部规则名；卡片写别的名字 = 卡与判定器漂移，判 `uncertain` 并写明）：

  | 规则（卡片里写的名字） | 判什么 |
  | --- | --- |
  | `observed_privilege_at_least_node_requirement` | 观测身份（`identity_name` / `identity_sid`）按**权限等级**与节点要求比较：在成员机上域管算 system 级，不强制 `S-1-5-18`；节点没写等级时只报观测（`uncertain`） |
  | `uid0_when_node_requires_root`（卡里是散文口径） | 节点要求 root/system 时，会话身份必须是 root 级；节点没要求时只登记观测 |
  | `uid_after==0` | 提权后的 `uid_after` 必须是 0 |
  | `state==open` / `firewall_state==disabled` | 端口状态 / 防火墙状态（防火墙只判「调用之后的状态」，不声称变化过程） |
  | `readback_value==value` | 回读值等于**绑定输入**里的写入值，且写入被接受 |
  | `wrapped_output_present` | 回显被 marker 块包裹时（卡片自己切出 `command_output`）：marker 在块内兼容旧形状；否则要求 raw 里有完整 tag 对 `<m>start`…`<m>end` 且区间非空；raw 不可读、或只看到 marker 前缀（≥6 字符，回显折行会切进 token——D24-e 实测）⇒ `uncertain` |
  | `dump_magic_mdmp` | 产物头 `MDMP`（**只证明产物成立**，不冒充凭据成立） |
  | `credential_material_present` | 有凭据材料 / 账号；解析出 0 个账号判不成立 |
  | `transfer_hash_match` | 双边字节数与 SHA-256 逐字一致；只有一边的账目判 `uncertain` |
  | `host_side_marker_present` / `session_identity_present` / `target_echo_present` | 宿主侧 marker / 会话身份 / 通道回显成立 |
  | `observation_only`（卡里是散文口径） | 只登记观测（会话身份、会话主机）；够不够由需要它的节点判 |

- **规则退场也是契约变更（D29）**：OA 与 laravel 两族卡统一到 `wrapped_output_present` 之后，旧规则
  `command_output_contains_call_marker` 已无卡使用，从判定器注册表退场；卡里再写它 = 卡与判定器漂移，判 `uncertain` 并写明。
- **声明即契约**：`tests/test_checker.py` 有一条测试遍历所有卡片，卡里出现的规则名必须在判定器里实现——漂移让测试失败，而不是悄悄放过。
- **权限词表只有一份（D31）**：`identity` 闸用到的等级词表（`TIER_RANK` / `REQUIRED_TIERS` / `tier_of` / `required_tier`）已全部迁到 `src/runtime/identity.py`——checker、run 的 `granted{}`、run_path 的来源等级三处**同一份**。`satisfies(observed, required)` 是唯一的充分性判定（`admin` 与 `system` 对 `admin`/`system` 级要求等价）；`RANK` 只是报告排序，不参与「够不够」的结论。`tests/test_identity.py` 钉住词表与比较规则。
- **会话族卡只登记观测**：两张 session 卡把判据写成 `observation_only`——规则照常计算并落盘，「够不够」留给需要它的节点判，不替它下结论（旧 `judge.gates` 子集声明随 r112 退场）。
- **证据落盘（D25 起）**：`run_skill_remote.py` 把信封写进 `<run_dir>/<call_id>/envelope.json`，`--check` 再写 `judgement.json`；`check_call.py` 的退出码就是判定（`0` pass / `1` unsatisfied / `2` uncertain）；`run_skill_remote.py --check` 也一样（不写 `--check` 时仍只落信封、退出码只看执行）。**D25 之前的 run 没有信封**：那些调用只判 `freshness` / `target`，其余记 `uncertain` 并在 `notes` 里说明原因，不假装复判过。



## 13. 节点循环（loop）：决定表与 node_result

判定器回答「这一次调用证明了什么」；节点循环回答「这个节点接下来该做什么」。循环是纯逻辑
（`src/runtime/loop.py`：无 IO、无时钟、无模型），执行与判定都从外面注入，所以决定表每一行都能离线测试；
CLI 入口 `scripts/run_node.py` 只负责把真实世界接进去（选择器选卡 → 适配器执行 → 判定器判定）。

决定表（从上往下第一条命中生效）：

| 条件 | 动作 | 节点状态 |
| --- | --- | --- |
| 没有可选候选（被状态挡下的卡会在原因里点名） | `no_method` | `blocked` |
| 有候选但都缺图事实（`missing`） | `graph_gap` | `blocked` |
| 当前候选还缺运行现场值（`pending`） | `need` | `blocked` |
| 当前候选没试过 | `run` | — |
| 上次没跑成且可重试（`timeout` / `transport_error`），重试额度未耗尽 | `retry_run` | — |
| 上次判定 `pass` | `done` | `succeeded` |
| 上次判定 `unsatisfied` / `uncertain`，还有未试候选 | `next_method` | — |
| 候选用尽，全部尝试都是 `unsatisfied` | `unsatisfied_stop` | `failed` |
| 候选用尽，存在 `uncertain`（或没有判定） | `uncertain_stop` | `uncertain` |

表里编码的四条规则（这四条才是契约）：

- **一条方法被证伪不等于节点被证伪**：卡片锁的是一种固定方法，节点可能有多张卡，循环按顺序换（`next_method`）。
- **执行过不等于已验证**：`status=executed` 只说明命令跑完了；节点只有在判定 `pass` 时才 `succeeded`。
- **重试给瞬时，换卡给方法**：`timeout` / `transport_error` 重试同一张卡（`--max-retries`，默认 1 次）；
  `tool_missing` 说明这张卡的工具链不在，直接换下一个候选。
- **候选没试完不停**；停下时节点结论取最保守的读法（任何 `uncertain` 都活着，不写 `failed`）。
- **「没有方法」要说清是哪一种没有**：被状态挡下的卡片进 `LoopState.excluded`，`no_method` 的原因里带
  `<id> (<status>)`，所以「没有技能服务这条边」与「有卡但从来没验证过」在日志里是两句话（第 11 节状态策略）。

**产物与退出码**（`scripts/run_node.py`）：

```powershell
python scripts/run_node.py --node 14 --graph output/hongri7/json/Hongri7_v2.action_graph.json --run-dir output/runs/<run> --remote kali@192.168.52.128 --assets data/inputs/hongri7/assets.json --control 192.168.52.128
```

- 每次尝试落 `<run-dir>/attempt-<n>-<skill>/`：`inputs.json`（绑定输入，跑之前先落盘，复判要用）+
  `call-*/`（`call.json` / `stdout.txt` / `stderr.txt` / `envelope.json` / `judgement.json`）。
- 节点结论落 `<run-dir>/node_result.json`：`status` / `action` / `reason` / `attempts[]` /
  `calls[]`（证据锚点）/ `decisions[]`（决策轨迹）/ `judgement`（最后一次全文）/ `node_id`（图 sha1）/
  `graph_host` / `requirement`。`status` 与运行数据契约的 `node_runs.status` 同一套词，落库不用翻译。
- 退出码 = 节点结论：`0` succeeded / `1` failed / `2` uncertain / `3` blocked（与 checker CLI 同一哲学）。
- 适配器自身抛异常时记 `adapter_error`（没有 judgement）——按未判定处理，绝不按通过处理。
- `no_method` / `graph_gap` / `need` 三类结论在 select 之后就能得出，不发出任何命令（SshExecutor 惰性连接）。

## 14. 运行循环（run）：决定表、供给与 post 贡献

节点循环回答「这个节点接下来该做什么」；运行循环回答「整张图接下来该走哪个节点、缺的东西谁来供」。
`src/runtime/run.py` 仍是纯逻辑（无 IO、无时钟、无模型），三个协作者从外面注入：
`selection_builder(node, state)`（真实实现 = 选择器 + 由运行状态重建的 context）、
`node_runner(node, selection, state)`（真实实现 = `loop.run_node` + 适配器 + 判定器）、
`supply_runner(need, node, selection, state)`（真实实现 = 按 need 找提供者卡跑一次——这就是「会话 agent」的接缝）。
CLI 入口 `scripts/run_path.py` 只负责把真实世界接进去。

决定表（从上往下第一条命中生效）：

| 条件 | 动作 | 节点状态 |
| --- | --- | --- |
| 没有 open 节点，且所有 AND 节点都 succeeded | `done_all` | — |
| 没有 open 节点，但有 AND 节点未成功 | `blocked` | — |
| 某个 open 节点的 `effect_refs` 已全部在 inventory 里 | `skip_node` | `succeeded` |
| 某个 open 的 OR 聚合节点，其 provider 已全部关闭 | `aggregate`（事实已证）/ `or_unmet`（没证出来） | `succeeded` / `blocked` |
| 某个 open 的 AND 节点，其 `requires` 已决（已证，或 provider 全部试过） | `run_node` | — |
| 还有 open 节点，但没有任何一个能推进 | `gaps` | — |

表里编码的规则（这几条才是契约）：

- **provider 先行**：节点的 `requires[].fact_ref` 要么已在 inventory（已证），要么它的 `any_of` 提供者节点
  **全部试过**。「试过但没证出来」**不阻塞**——图的前提是参考，不是闸门：运行现场低置信地照试，并把这条
  前提记进 `assumptions[]`（`kind=low-confidence`），失败时可以顺藤摸瓜追溯到哪条前提没成立。
- **零成本先行**：成果已证就不重复劳动。open 节点的效果全在 inventory ⇒ `skip_node`；OR 聚合节点本身没有
  攻击动作，事实一证就结算（`aggregate`），provider 全试过还没证 ⇒ `or_unmet`（诚实收尾，不悬空）。
- **图的顺序由规则定，缺的东西由供给补**：卡片还有 `pending`（缺运行现场值）时，运行循环把缺的东西交给
  `supply_runner`；供给成功 ⇒ 值注入运行状态 ⇒ 重建 selection 重试该节点；供给不了 ⇒ 节点记 `blocked`
  （action=`need`）并写进 `needs[]`。供给成功后，此前 `need` 挂起的节点会被重开（每节点上限 `MAX_REOPENS=3`）。
- **链是节点的一种执行形态**（D29；D30 收紧）：节点的 case 若在注册表 `chains` 里，链就是这个节点的方法——`supply.locked_chain(registry, selection)`
  决定运行层锁定链的哪一段（选择器落在一张**链外**卡上时，链的第一个就绪段接管锁定；`--include-planned` 可以带进一张试验卡，但不能悄悄替换
  已注册的方法），节点运行器与 `chain_dispatch` 共用这一判定，实际锁定的段写进结果的 `chain.locked`。**链运行器**只回答两件事：
  是不是链、这条链自己会造哪些值（`chain_binds`）；链自造的值从待补值里剔除——否则节点会被自己马上要造出来的值堵死（D29 实机暴露后修）；
  链仍然供不上的需求（例如「一个有会话的通道」）照旧走 `supply_runner`。
- **通道是运行现场资产，跑出来就登记**（D29）：卡片信封里的通道状态（`envelope.channel`，如 OA include 的 `base_url` + `include_path`、
  容器 plain 的固定 webshell URL）由运行循环收进 `state.channels[host]`（同一主机的第一条通道胜出，绝不静默替换），
  以后要用会话时先拿它跑一次 `post.channel_echo` **复验**（D29 实机：节点 7 打出来的通道，节点 41 复验后才用来跑链）——
  「曾经打通过」不等于「现在还通」。
- **session provider 有四条，按条件选、不靠猜**（D30 补齐第三条、D31 补齐第四条）：① 运行已持有的通道**且等级够** → 复验卡（`post.channel_echo`）；
  ② 图/上下文给出 redis 服务事实 → `session.ssh_via_redis`；③ 节点指向的容器图主机在 assets 里登记了**公开端点**
  （selector 解出 `target_execution_host` 与 `target_url`）→ `session.webshell_via_laravel` 从入口打进去；④ 运行已持有的通道**但等级不够**
  （selector 记了 `privilege` 缺口）→ `session.root_via_suid` 把这条通道升上去——唯一不新开东西的 provider，交回的是「同一条入口 + 提权包装 + 观测到的身份」。
  四条共用同一张状态政策：未实机验证过的卡默认不启用，`--include-planned` 打开时卡名与状态仍然写在产物里。
- **通道登记：首个胜出，唯一例外是等级更高者接管**（`_channel_upgrade`，D31）：同强的再一次登记不顶替（重复登记不是进展），弱换强要留痕——
  升级出来的通道就是节点 22 往后所有调用用的那一条。
- **「值在、但不够强」也是一种缺口**（D31）：`needs[]` 行除了 `need` / `fact` / `text` / `why`，还可以带 `privilege`
  （`{"session_ref": {"required": "system", "holds": "user", "identity": "www-data"}}`）——「这一条东西就在手上、只是不够强」不用翻日志就能引用；
  `run_result.granted{}` 是运行层认为已经拿到的等级（按主机）。
- **运行层注入「运行时别名」**（D30）：图写逻辑主机，而卡在目标上自报的身份（容器短 id、机器名）只有运行层见过——当
  `state.sessions[<节点 target_graph_host>]` 自报的 host 与本次会话的 `session_ref.host` 一致时，运行层把它作为
  `requirement.target_aliases` 注入（同一台执行主机的两种拼写；容器对宿主不是同一台，不许在这条规则里替图做拓扑判断），target 闸据此对齐观测。
- **凭据供给按账号点名核对，不按「有凭据」算**（D29）：节点语义里的 `accounts[]` 逐个核对，缺哪个报哪个——`needs[].why` 里写
  `<host>:<account>` 与「the run holds: …」；供给记录带 `account_gaps[]`，覆盖一半就是一半，剩下的一半留在缺口里。
- **运行循环不发明事实**：节点成功时 `effect_refs` 进 inventory；`getAccount(...)` 型事实只有在**真的拿到凭据**
  时才进（本次吸收到凭据材料，或本来就持有——`sweep_credentials`）；图上 `accounts` 的 `credential_fact_ref`
  在「手上真有该凭据」时视为已证；证据里的凭据材料 / 会话身份被吸收进运行状态供下游节点使用。节点跑完但没带
  凭据材料时，`getAccount` 型效果**不入库**并记 `unbacked-effect`（宁可少认，不多认）。

**产物与退出码**（`scripts/run_path.py`）：

```powershell
python scripts/run_path.py --graph output/hongri7/json/Hongri7_v2.action_graph.json --run-dir output/runs/<run> --remote kali@192.168.52.128 --assets data/inputs/hongri7/assets.json --control 192.168.52.128 --host-map data/inputs/hongri7/host_ip_map.csv --node-context output/runs/<node-context>.json
```

- run 的常用开关：`--assets`（部署事实表）/ `--control`（多宿主机用哪个地址）/ `--host-map`（观测名称对账）/ `--node-context`（按节点的运行现场值）/ `--context`（全局现场：凭据 / 会话 / 通道）/
  `--include-planned` / `--max-retries` / `--max-steps`；接收端 `--receiver-url`（缺省 `http://<control>:9090/`）、`--receiver-dir`（执行端目录，缺省执行端 `/tmp`）、
  `--receiver-script`（缺省 `/opt/agv/tools/agv_http_recv.py`）、`--receiver-name`、`--receiver-log`。
- 每个节点落 `<run-dir>/node-<id>/`：`selection.json`（选卡时的绑定）、`attempt-*`（同节点循环）、`node_result.json`。
- 供给落 `<run-dir>/supply-<node>-<skill>/`（与节点同构的 attempt 目录）。
- 运行结论落 `<run-dir>/run_result.json`：`status` / `action` / `reason` / `nodes[]`（每个节点的
  status/action/reason/calls/gained）/ `decisions[]`（决定轨迹）/ `assumptions[]`（假设与低置信前提）/
  `needs[]`（供不上的缺口）/ `supplies[]`（供给记录）/ `graph_gaps[]`（图缺口工作清单）/ `skill_gaps[]`（卡缺口工作清单）/
  `sessions[]`（一机多连接的台账行、按登记顺序：每行带 `graph_host` 与该连接的 driver/id 等字段，`probe_ref` = 最近一次探活尝试——`unknown | pass | fail`，失败也保留；派发前先落 `unknown`、结果只结算本次调用，失败/未完成的行仍是候选但不得直接派发）/ `channels{}`（按主机登记的通道资产）/ `credentials[]`（手上的凭据，只记 user / domain / 来源，不记 secret）/ `granted{}` /
  `calls[]`（全部证据锚点）。每个节点条目还带 `selection`（locked / missing / excluded / notes）与 `chain`（链节点才有：`id` / `case` / `locked` —— 实际锁定的段），
  所以「这个节点为什么停 / 为什么是按链跑的」不用重跑选择器就能读出来。

- **两个缺口清单是运行给上游的工作量回执**：`graph_gaps[]` = 图上缺的事实（补图清单：节点 / case / 哪个技能的哪个参数没绑定），
  `skill_gaps[]` = 没有可选技能的节点（补卡清单，含被状态挡下的卡）。两个清单都只陈述缺口，不执行任何动作。
- `--node-context` 传一份按节点的运行现场值 JSON（`{"12": {"key": "...", "value": "..."}}`）：命令、key/value 等。
- 退出码 = 运行结论：`0` succeeded / `1` failed / `2` uncertain / `3` blocked。

## 15. agent 层（D32）：四角色、最小必要验证、干跑与复核

运行内核（第 13、14 节）不变；agent 层是包在它外面的**角色契约**。完整契约在
[agent 层契约](agent_contract.md)，需求与设计在 [多 agent 编排 PRD](multi_agent_orchestration_prd.md)。这一节只写
和技能目录 / 运行记录直接相关的四条：

**15.1 谁问技能目录什么问题**

| 角色 | 与技能目录的关系 |
| --- | --- |
| planner | 只读图（节点语义 / 事实）；不选卡——选卡仍是选择器（第 11 节），planner 引用它的输出 |
| executor | 跑被锁定的卡 / 链（第 10、14 节），落调用目录与判定 |
| verifier | 只读调用目录里的执行状态 / 证据 / 判定，写四行复核；不新增调用 |
| session agent | 按 `provides=session` 的卡（第 3 节）选供给路径：`escalate` → `verify` → `redis` → `webshell` → `none` |

**15.2 最小必要验证（precheck）与卡的关系**

- `method` 家族直接读选择器的 `candidates[]` / `excluded[]`：没有可选卡 ⇒ `missing` 并点名「被状态挡下的卡」；
- `credential` 家族逐个核对节点 `details.accounts` 点名的账号（`<host>:<user>`），与第 14 节的按账号供给同一份口径；
- `privilege` 家族用第 13 节的权限词汇（`identity.satisfies`），节点声明 `target_privilege` 时才有这一行；
- `reach` 是真探针（`nc -z`），`service` 是图声明登记——**两类都不阻断**，只在节点失败时被引用。

**15.3 新的运行记录字段（兼容旧读法）**

| 文件 | 新字段 | 含义 |
| --- | --- | --- |
| `node_result.json` / `run_result.nodes[]` | `prechecks[]` | 该节点开跑前登记的前置行（kind / key / target / why / mode / declared / status / observation） |
| `run_result.json` | `agent{}` | `policy` / `steps` / `prechecks` / `verdicts` / `providers` / `node_reviews`（跑 `run_agent.py --live` 才有） |
| 每个调用目录 | `verdict.json` | 这次 attempt 的复核与裁决（四行 + go/repair/stop + repair 动作） |

旧字段一个都没改名、没删：`calls` / `needs` / `supplies` / `graph_gaps` / `skill_gaps` / `channels` / `granted` 语义不变。

**15.4 干跑（默认）**

`scripts/run_agent.py` 不给 `--live` 就是干跑：内存乐观模拟整图，写 `agent_plan.json`（每步 `simulated: true` + 固定词表的假设 note），
**不建连、不发包、不写 state**。干跑同样会引用技能目录（选择器照跑），所以「图上这一步会锁哪张卡」开跑前就能看见 —— 这也是补卡 / 补图的工作量清单来源。

**15.5 两条 D32-h 口径（会话供给与凭据绑定）**

这两条都是实机跑出来的口径，改代码前先读：

1. **会话 provider 的 requirement 指向「通道宿主」，不是节点目标。** 一条通道的探针只能观测到它自己的对端：
   节点 2/44/48 是 `pc1 → dc / pc2`，探针能回报的只有 pc1（`session_host=PC1`）。所以 `verify` / `escalate` 送给卡的 requirement 是
   `target_host` = 通道宿主地址、`source_host` / `target_graph_host` = 通道宿主逻辑名（地址解析顺序：host map → 选择器已解析的 `facts.source_ip` → 调用方 fallback）。
   节点自己的卡才去对齐节点目标。**「探针能看见谁」和「这一步要打谁」是两件事，混起来会让所有跨主机节点永远核不过。**
2. **`credential_ref.user` 绑的是登录名，不是图上的账户名。** MulVAL 的事实写的是角色（`domain_administrator`），
   Windows 认的是登录名（`WHOAMIANONY\Administrator`）。选择器按「凭据条目自己声明的 `user` 优先、图角色名兜底」绑定；
   图角色名继续当 run 查表的 key（`credential_entry` / `sweep_credentials` 不变）。**这条在离线干跑里看不出来**——干跑只查「有没有」，
   只有真机会以「登录失败」的形式暴露，所以凭据类改动必须真机验证一次。
