# 技能检索三阶段讲解：前置检查 / 利用 / 收尾复核（含运行实录正反例）

状态：生效（2026-09-20 成文）。依据：检索规格 `specs/007-skill-retrieval/spec.md`、技能目录契约 `skill_contract.md`、注册表 `skills/registry.json` v0.2.0（32 卡），运行证据取自 `output/runs/`（L8 全图合练、D60/D66 检查卡批次、D29 早期演练）。
目标：用**真实跑过的正例与反例**讲清一件事——一次检索是怎么从「图上的需求」走到「锁定哪张卡、为什么是它」。机制细节以 `specs/007` 与 `skill_contract.md` 为准，本文负责把机制放回真实业务流程里演示。

## 0. 检索只做一件事

拿当前需求（图节点或事实检查项或现场缺口），选出**门票命中、输入绑得上、硬门禁放行**的卡；分数只用来排序，不负责放行。

三步：**分流（三张表）→ 召回（门票=精确键）→ 打分排序（4 分/类 + 别名 ≤3）**。

| 表（`by_entry_kind`） | 什么时候走 | 门票 |
| --- | --- | --- |
| `action`（攻击行为） | 图上的攻击节点（带技术编号或 case 的节点） | 技术编号+服务/端口、case 词、别名 |
| `fact`（事实验证） | 图上的 LEAF 事实（hacl / exec_code / ttp_exists / network_service_info / leak_account / path_exists / is_docker / is_firewall） | 事实键 |
| `supply`（供给） | 运行现场缺东西（session / credential / transfer / reachability） | 需求键 |

分流由调用方（执行器）声明——手里拿的是节点还是事实，它自己知道，不靠内容猜。

想把上面的机制直接对着代码和真实输入看：`python scripts/explain_retrieval.py --graph output/hongri7/json/Hongri7_v2.action_graph.json --node 44` 会把该节点一次检索的**输入（节点 row / 绑定事实 / runtime 与 config）→ 候选门票命中与逐项给分 → 逐参数绑定结局 → 锁定**逐步打印出来；`--fact hacl` / `--need session` 是另外两张表的同款讲解，`--json` 出机器可读版。讲解与选择器走同一条 `select` / `bind_card` 调用路径，锁定卡与绑定输入由 `tests/test_retrieval_explain.py` 对拍守线。

## 1. 前置检查（pre）：把图上的「说法」变成「事实」

这一阶段回答的是：后续操作依赖的条件是否真的成立（能直连吗？凭据能用吗？防火墙什么状态？）。

### 1.1 正例：node-14 直连可达（案例词通道，4 分锁定）

- **需求从哪来**：Hongri7_v2 图上 node-14 的规则「Direct Network Access」，`case_id = direct_network_access`，目标端口 6379（node-30 是同类，端口 81）。
- **门票**：执行器声明走 `action` 表；拿案例词召回。
- **命中与分数**：`pre.nmap_tcp_probe` 精确命中案例词 = 4 分，唯一候选，锁定。
- **真实结果**：`output/runs/L8-live2/node-14/`，`call-20260920T215240-c422ce`——判定 `pass`，理由原文「the port answered open from the declared vantage」。图上写的「能直连」，到这一步有了证据。
- **顺手的机制注脚**：同一张卡同时挂在三张表下——`action` 表的 case 词、`fact` 表的 `hacl` 键、`supply` 表的 `reachability` 键。同一个方法三个入口；拿节点进来走案例词，拿事实进来走事实键。

### 1.2 反例：`pre.credential_valid` 的「归属不对不算数」

- **事实（三次记录）**：一组域管理凭据首验在成员机（PC1）——第一次 `call-20260920T175139-806763` 是网络瞬态（NETBIOS 超时）判 `uncertain`（证据没读全）；第二次 `call-20260920T175227-1a50f7` 判 `uncertain`，理由原文「local/other-domain acceptance is not this credential's success」（本机/其他域的接受不算这张凭据的成功）——后查明是 `DOMAIN\user` 归因缺陷把一次真实接受读错了。
- **触发的是哪条规则**：检查卡是「对照叶期望判真假」，不是「确认现状」。叶绑定的是域账号，那么「某处接受了」不构成「本凭据在目标上被接受」——哪怕它其实接受了，也要先把归因修对。
- **修复后重验**：缺陷修复后 —— 域控上 `call-20260920T180215-112e72` 判 `pass`（「被接受 + 观测特权 SYSTEM 满足叶」）；成员机上 `call-20260920T182831-6c315c` 也转 `pass`。
- **如果硬用会怎样**：拿一次「本机账户接受」当「域凭据验证通过」，后面所有依赖该凭据的节点全部悬空——这正是我们坚持「输入里写了凭据也要真验」的原因。

### 1.3 反例：`pre.netsecurity_firewall_state` 的「与叶期望相反也如实报」

- **事实**：域控上的检查 —— `call-20260920T180651-ed8545`，判定 `unsatisfied`。实测三档 `Enabled=0`（关闭），而叶期望是「启用（enabled）」。
- **判词**：「profile(s) domain, private, public are explicitly the other way: the effective policy does not match the leaf」——检查做成了、检查项没达成，如实入账。
- **同卡的另一条记录**：PC1 上两次 `uncertain`（`call-20260920T174835-6e340c` / `-8a1028`）——旧版 PowerShell 缺该 cmdlet（平台下限），原始报错留档；之后同一事实需求改由 CIM 通道的卡完成。
- **要点**：`pass / unsatisfied / uncertain / not_applicable` 是四个合法结论。系统从不把「说不上」伪装成「没问题」。

### 1.4 反例：形态门（`not_applicable` 永不锁定、不做备选）

- **机制**：检查卡上岗时带着形态锁（`check_shape` `const`）——「策略状态」要 `firewall_profiles` 形态、「本机进程事实」要 `windows_process` 形态。请求声明的形态与卡不符 → 候选进 `not_applicable`，连备选都不做。
- **真实守线**：`tests/test_const_shape.py` 把三态钉死：形态对 → 绑定（ready）；形态错 → 候选记 `not_applicable=["check_shape"]`、永不锁定、不做备选；缺形态值 → 仍是缺口，**不猜默认值**（`false`/`0` 是值，不算缺）。
- **如果硬用会怎样**：拿进程查询的回答去回答策略状态问题——证据对不上问题，结论必错。跨形态不是「备选」，是「挂错科室」。

## 2. 利用（action）：先看能不能上场，再看谁更匹配

打分公式（`action` 表）：

```
分数 = 4 × [技术编号命中] + 4 × [服务名命中] + 4 × [case 命中] + 4 × [漏洞编号命中]
        + min(3, 别名命中数)
```

每类最多计一次；**精确命中永远压过一堆说法**（别名 1 分/条、封顶 3）；同分回注册表顺序。
硬门禁先于分数：**绑定门**（缺输入 → 挂起/淘汰）、**状态门**（`planned` 不进候选）、**形态门**（见 1.4）。

### 2.1 正例：node-2 双卡擂台（12 分 vs 8 分）

- **需求**：`T1562.001` + `scm/445` + case `disable_firewall_credentialed`（「关闭域控防火墙」）。
- **擂台**：

| 候选 | 命中 | 分数 | 去向 |
| --- | --- | --- | --- |
| `exploit.netexec_firewall_off` | 技术 T1562.001 + 服务 scm/445 + case | **12** | 锁定 |
| `exploit.wmi_firewall_off` | 技术 + case（服务字段是 smb/445+wmi/135，与门票 scm/445 对不上） | 8 | 备选 |

- **真实结果**：`output/runs/L8-live2/node-2/`——`call-20260920T215241-0fbfa6` 执行 `netsh advfirewall set allprofiles state off`（1.44s），`call-20260920T215242-56872d` 注册表回读复核（1.14s）。合练收尾用同一凭据把三档复原并复核（复位记录在库外 `output/diag/D60/recovery_20260920.md`）。
- **要点**：两张卡做同一件事、技术编号与 case 都一样，胜负手就是服务名对不对得上——先精确命中，再谈其他。

### 2.2 反例：node-44/48 的 8 分备选（「没选中 ≠ 不能用」）

- **需求**：`T1021` + `smb/445` + case（两条同族规则），`output/runs/L8-live2/node-44/`、`node-48/`。
- **三个候选同台**：`exploit.wmic_remote_cmd`（技术号 `T1021`）12 分 → 锁定；`exploit.impacket_psexec_cmd`（`T1021.002`）8 分；`exploit.impacket_wmiexec_cmd`（`T1021.006`）8 分。
- **触发的是哪条规则**：技术编号必须**精确相等**——`T1021.002 / T1021.006 ≠ T1021`，不补技术分（确定性规则，不靠猜「同族」）。
- **真实结果**：两节点都由 12 分卡一次通过（node-48 用时 8.6s）。两张 8 分卡留在 `alternatives`（备选）里；卡名里的「首选/备选」是家族内排位（psexec 先于 wmiexec），跨家族同台时排序仍由分数定。
- **如果硬用会怎样**：把「看起来同族」当命中，排序回答的就不再是「谁与图上的明确要求匹配」——规则失去可解释性。

### 2.3 反例：D29 淘汰实录（连上场资格都没有的卡）

早期演练（`output/runs/D29-full/node-2`、`node-22`）里，同一个「关防火墙」节点：

- 一张候选卡当时是 `planned` 状态 → 进 `excluded`，理由原文「planned card: no real run has validated this method yet」（没实机验证过的方法不能上场）；
- 另一张候选缺 `credential_ref` 绑定（图里没有凭据事实）→ 挂起，`locked=null`；备注「every candidate is missing a graph fact; the graph needs more facts」。

后来相关卡全部完成实机验证转 `implemented`——新图（Hongri7_v2）+ 新命名体系下，同一节点 node-2 在 L8 合练成功锁定 `exploit.netexec_firewall_off`（见 2.1）。**回去补图、补验证，而不是硬猜。**

### 2.4 反例：别名封顶与词边界（说法不能压过对键）

- **封顶**：别名 1 分/条、最多计 3 分——三条别名全中（3 分）也压不过一个精确类别（4 分）。
- **词边界**：ASCII 别名 `smb` 命中 `smb/445`、不命中 `smbserver`；中文别名按子串。
- 守线：`tests/test_retrieval_scoring.py`（案例词精确命中 + 别名 = 5 分；别名封顶 3；精确类别永远胜别名堆）。

## 3. 收尾复核（post）：验过，才准复用

这一阶段回答：刚拿到的通道 / 身份 / 产物，够不够支撑后面的节点。**命令能回显，只证明一部分条件。**

### 3.1 正例：`post.channel_echo` 通道验活 → 供给复用

- **场景**：node-44/48 需要「Windows 执行点」，现场已有一条历史通道（PC1 的 OA include 通道）。执行器声明走 `supply` 表，门票 = 需求键 `session`；若手里拿的是回显事实检查项，则走 `fact` 表 `exec_code` 键。
- **锁定与执行**：`post.channel_echo`——从已完成节点的信封取回通道，发带标记的探针。`output/runs/L8-live2/supply-2-post.channel_echo/`，`call-20260920T215241-580ec5`：回显三段闭合（标记 / `nt authority\system` / PC1），三闸（freshness / target / identity）全过判 `pass`，通道记 `verified`。
- **复用结果**：node-44/48 的 `session_ref.source` 直接写 `supply via post.channel_echo`——**验过才复用，不再二次确认**。
- **同批另一条链**：`session.webshell_via_laravel`（容器内 www-data 会话，`call-20260920T215244-cd8c80`）→ `session.root_via_suid`（升 root 会话，`call-20260920T215248-a014f5`）——每升一级、验一级。

### 3.2 反例：`post.identity` 在攻击机上的一枪（身份不足）

- **正例（成员机）**：`output/runs/D66-cards-live/post-identity-pc1/`，`call-20260920T214444-698070`——三闸全过判 `pass`（新鲜度：标记出现；目标：主机名对齐；身份：system 达到节点要求）。
- **反例（攻击机）**：`post-identity-neg/`，`call-20260920T214418-07f4bc`——通道活着、标记自洽、目标自洽，**但身份只有 user 级，低于节点要求的 system** → `unsatisfied`，判词「observed kali is the user tier, below what this node asks for (system)」。
- **如果硬用会怎样**：拿「通道通了」当「权限达标」——后面要求系统级的节点拿到的执行条件是假的。

### 3.3 反例：`post.file_present` 的「产物没落地」

- **正例**：`D66-cards-live/file-present-pc1/`——产物在（65 字节），判 `pass`。
- **反例**：`file-absent-pc1/`，`call-20260920T214429-fde712`——命令通道没问题，但文件**根本没落地** → `unsatisfied`，判词「the artifact did not land」。
- **要点**：「命令说写了」与「文件真的在」是两回事；依赖产物路径的后续步骤，绑不上真实输入就不许开跑。

### 3.4 机制注脚：一把钥匙多张卡

`fact` / `supply` 表门票命中后按注册表顺序先试第一张、其余备选。多卡实数：`exec_code` 3 张 / `network_service_info` 3 张 / `path_exists` 2 张 / `session` 6 张。实际跑时多数先被绑定状态或形态筛出唯一——例如 Windows 场景里 `pre.posix_path_access` 会因绑不上直接出局；`session` 多卡场景里 `session.msf_migrate` 只在需要迁移时才被选中。

## 4. 日志、同分与确定性

- **检索日志**（一行一次，JSONL；写入器 `src/skills/retrieval_log.py`，入口 `scripts/select_skill.py --log <path>`，示例产物 `output/.runtime/skill_retrieval_test.jsonl`）。真实样例行（node-44）：

```json
{"ts": "2026-09-20 16:34:14", "kind": "action", "target": {"node": "44", "technique": "T1021", "service": "smb", "port": "445", "case": "windows_credential_remote_system_after_firewall_disable", "target_privilege": "system"}, "candidates": [{"id": "exploit.wmic_remote_cmd", "score": 12}, {"id": "exploit.impacket_psexec_cmd", "score": 8}, {"id": "exploit.impacket_wmiexec_cmd", "score": 8}], "locked": "exploit.wmic_remote_cmd", "reason": "score order, first bindable candidate"}
```

- **同分不掷骰子**：按注册表登记顺序。真实场景：LSASS 节点的三张同族卡（`exploit.kiwi_lsass_dump` / `exploit.comsvcs_minidump` / `exploit.pypykatz_parse`）同分候选取登记顺序；该事实的 `chains.lsass_minidump` 把完整方法定义成三段链：dump（目标上转储）→ exfil（文件外带）→ parse（解析端读出凭据），段间用产物路径绑定。
- **可回放**：同一注册表 + 同一张图 → 同一顺序、同一锁定。
- **为什么不加向量/大模型**：先有评测证据（命中率、硬违规为零、同一快照决策一致率）再升级；规模算例 47 节点 × 3000 卡 ≈ 14 万次比较，纯程序毫秒级。每一分都能说清来处（哪一类命中），这是可解释性的底线。

## 5. 三个最常被追问的问题

1. **分数一样怎么办？** 回注册表登记顺序（先登记的先用）——同一张图两次跑结果一致。
2. **为什么不用向量或大模型检索？** 检索环里不放过模型：确定性、可回放、可解释；升级要先拿评测证据（见 §4）。
3. **没有卡达标 / 备选都失败？** 缺输入就保留缺口，`planned` 继续排除，形态不符不补位；如实记 `skill_gap` / 挂起，**不把依赖它的节点记成通过**。

## 附录 A：证据索引（本文引用的运行原件）

| 例子 | run 目录 | call_id |
| --- | --- | --- |
| node-14 直连 pass | `output/runs/L8-live2/node-14/` | `call-20260920T215240-c422ce` |
| node-30 同类（81） | `output/runs/L8-live2/node-30/` | `call-20260920T215244-9e7923` |
| credential_valid PC1 uncertain（前） | `output/runs/D60-const-live1/03-credential-valid/` 与 `output/runs/D60-const-live1/03b-credential-valid/` | `-806763` / `-1a50f7` |
| credential_valid DC pass（修后） | `output/runs/D60-const-live1/03d-credential-valid-dc/` | `call-20260920T180215-112e72` |
| credential_valid PC1 pass（修后） | `output/runs/D60-const-live1/03f-credential-valid-pc1/` | `call-20260920T182831-6c315c` |
| firewall @DC unsatisfied | `output/runs/D60-const-live1/06c-firewall-dc-exit/` | `call-20260920T180651-ed8545` |
| firewall @PC1 uncertain（平台下限） | `output/runs/D60-const-live1/06-firewall-pc1-exit/` | `-6e340c` / `-8a1028` |
| node-2 关防火墙 + 复核 | `output/runs/L8-live2/node-2/` | `-0fbfa6` / `-56872d` |
| node-44 / node-48 一次通过 | `output/runs/L8-live2/node-44/`、`node-48/` | `-fe2abc` / `-f826ac`（8.6s） |
| D29 淘汰实录 | `output/runs/D29-full/node-2/`、`node-22/`（selection.json） | — |
| channel_echo 验活 | `output/runs/L8-live2/supply-2-post.channel_echo/` | `call-20260920T215241-580ec5` |
| 容器会话链 | `output/runs/L8-live2/supply-26-session.webshell_via_laravel/` 与 `output/runs/L8-live2/supply-22-session.root_via_suid/` | `-cd8c80` / `-a014f5` |
| identity 正/反 | `output/runs/D66-cards-live/post-identity-pc1/`、`post-identity-neg/` | `-698070` / `-07f4bc` |
| file 正/反 | `output/runs/D66-cards-live/file-present-pc1/`、`file-absent-pc1/` | `-2fb49c` / `-fde712` |
| 检索日志样例 | `output/.runtime/skill_retrieval_test.jsonl` | — |

## 附录 B：成文说明

- 本文由技能库线依据上述运行原件合成；成文前经一轮跨模型交叉评审与核事实，修正 1 处方向表述（§1.3 的 `06c` 实例：实测为三档关闭、叶期望启用），一切以运行原件为准。
- 机制表述的权属：三表分流 / 门票 / 打分公式 / 硬门禁 / 同分规则 / 日志字段以 `specs/007` 为准；卡片字段语义以 `skill_contract.md` 为准；本文只负责业务流程示例化。
