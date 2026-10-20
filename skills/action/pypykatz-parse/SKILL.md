---
name: pypykatz-parse
handover: session
description: pypykatz — 离线解析 LSASS minidump（T1003.001 · lsass）
metadata:
  predicates:
  - T1003.001
  platforms:
  - any
  keywords:
  - exploit.pypykatz_parse
  - method
  - position
  - code
  - cmd
  - msf
  - T1003.001
  - pypykatz
  - parse
  resources: []
  categories:
  - action-method
  aliases:
  - pypykatz
  - parse
  - minidump
  - 离线解析
  parameters:
  - dump_path
  when:
    method: parse
  requires:
  - dump_file
  excludes:
  - direct_dump
  carriers:
  - kali
  - linux
serves:
- T1003.001
---

## 适用场景

输入是一份**已经存在的** LSASS minidump（`MDMP` 头，见 `exploit.comsvcs_minidump`）。执行点是解析端 Linux 工具机（如 Kali），需具备 `python3`、`sha256sum` 与 `pypykatz`；不需要 Windows 或 mimikatz。

- 解析的文件必须与转储、传输侧核对过的产物是**同一份**，用 SHA256 绑定；不能把另一份 dump 的凭据当作本次证据。
- 输入见 `skill.json`：`dump_path` 来自运行现场，是解析端的落地路径（通常来自 `exploit.http_post_file` 的接收落点）；可选 `host` 是产物来源主机，由转储侧观测绑定，写入证据的 `hostname`。`dump_sha256` 是**输出证据**，不是入参。
- 原有等价实现为 Windows 侧 mimikatz 的 `sekurlsa::minidump` + `sekurlsa::logonpasswords`；**本卡不自动切换到它**。
- 命令一律写成 `{"tool":"run_script","target":"session","arguments":{"interpreter":"bash","body":"<一条命令行>"}}`（解析端是 Linux 工具机，控制面步骤的 `target` 写 `kali`）；运行层跑这一条命令行并把回执原样带回，本卡不要求目标侧执行。

## 参数

- 输入 `dump_path`：来自 runtime
- 输入 `host`：来自 runtime（可选）
- 交付：evidence
- 执行位置：position
- 可用工具：code、cmd、msf
- 图适用：technique=T1003.001

## 步骤

**进入条件（先看这条）**：本卡需要**已经存在一个 dump 文件**（由导出卡产生，路径来自那一步的回执）。**没有 dump 文件就先走导出卡，不要在本卡起监听、新建会话或查作业列表**；真机第 59 轮把这一步误当成"起监听"，烧光了整轮预算。解析本身在**控制面**跑（`via=kali`）。

主路径先用 `sha256sum` 绑定唯一产物，再用 `pypykatz lsa minidump` 解析 LSA 秘密（MSV / WDIGEST / Kerberos / TSPKG / DPAPI）：

```sh
sha256sum <dump_path>
pypykatz lsa minidump <dump_path>
```

**一条一个动作块；不要把几行用 `&` 拼成一条长命令，也不要用批量动作写法**——当前执行器只接受单动作，拼长行会一处坏、整条废。

方法层可按任务选择是否另取 DPAPI masterkey、机器账户、Kerberos 票据，以及输出过滤与呈现方式；当前固定装配仍以已声明输入和既有入口为界，不扩展步骤或参数。SHA256 绑定要求、账号行解析口径与判据**不可更改**。


## 完成依据

**`finish.verdict` 判本卡要求的事实是否成立（这份产物是否解析出可登记的材料），不是“解析命令是否跑完”。**

证据字段：`call_id`、`dump_path`、`hostname`、`dump_sha256`、`credential_accounts`、`credential_material`；原始输出为解析调用的 `stdout`。凭据材料包含域、用户、秘密类型与值，可能含明文；**当前流程中的原值只在内存与显式指定的库外私有材料文件中保留**，模型、公共证据和日志均先脱敏。

解析口径只看 pypykatz 打印的行：`username` / `Username:` 与 `domainname` / `Domain:` 决定归属；`NT: <hex>` 记为 `nt`；`password <value>` 记为 `plaintext`，**排除 `password (hex)`**；同（域、用户、值、类型）去重。

三个阻断闸为 freshness、target、effect，`identity_rule=null`：

- **freshness**：解析输出属于本次调用，证据 `call_id` 与解析调用一致，并核对执行状态。
- **target**：核对 `hostname` 与节点目标；无节点目标时与绑定输入对照。该字段来自可选 `host`，**不是解析器独立探测的主机身份**；缺失或无法对齐时为 uncertain。调用方仍须核对 `dump_sha256` 与传输侧摘要一致——现有 target 闸**不自动比对摘要**。
- **effect**：沿用注册规则 `credential_material_present`，以本次账号凭据行为依据；没有账号行就如实记录，不猜填、不引用历史 dump。

- **pass**：三个阻断闸都通过，并满足上述同一产物核对要求。
- **unsatisfied**：明确是空账号列表，或列出账号却没有凭据材料——事实被明确否定。
- **uncertain**：没有阻断闸返回 unsatisfied，但某闸缺证据或返回 uncertain；当前入口在**没有账号行**时不写入两个凭据字段，按 `on_missing_evidence=uncertain` 处理。

### 材料完成协议

本卡 `materials` 声明了模型必须整理的六个字段；`secret_patterns` 只标出原始输出中的秘密值，**不解析账号归属**。模型必须从**本次解析调用的观察文本**推导具体 `realm`、`user` 与 `kind`：`username` / `Username:` 与 `domainname` / `Domain:` 须来自同一账号区块；`NT:` 的材料为 `ntlm`，非 `password (hex)` 的口令行为 `password`。不要把 LM、SHA1、masterkey、hex 编码口令或 `None` / `(null)` 当作这两类材料。

完成消息除 verdict 与 evidence 外必须给出 `materials`，每条仅含以下字段（`kind` 只能是 `password` 或 `ntlm`）：

```json
{"materials":[{"realm":"<观察到的域或空字符串>","user":"<观察到的用户>","value":"<观察中的整值秘密占位符>","kind":"password","source_call":"<本次解析 call_id>","quote":"<同时包含账号归属与该值占位符的连续原文>"}]}
```

`value` 原样回填观察中的整值占位符，**模型不接触、猜测或反解明文**；`quote` 保留观察中的原文与占位符，不改写、不拼接不同账号或调用。域缺失只填空字符串，不借目标主机名补域；缺用户、值或归属证据的条目不得登记。确实没有可用材料时给 `materials: []`，并按证据判为不满足或不确定。编排器核对 call、原文、账号和值，只有 proved 后才登记来源引用、掩码引文和材料摘要；具体值由内存解析并保存到 `--materials-dir` 指定的库外私有文件，供后续派发前恢复。

## 失败条件

- **停止边界：本卡一次调用只做绑定与解析两步；完成即结束，不由本卡追加动作或改换实现。**
- dump 中缺少某个账号，多半与目标会话状态有关：LSASS 只缓存活着的会话；Type 3 网络登录（`net use` / WMI / SMB）不落 WDIGEST/MSV 缓存，不能据此直接归咎解析器。
- 机器账户（`HOST$`）与失效会话（`session_id 0`）会混在结果里；可以按需过滤，但过滤规则须事先写进判据，不能事后挑选结果。
- 明文是否出现取决于目标的凭据缓存策略（Windows 版本、补丁、WDigest 开关）；没有明文不等于解析失败。
- 解析是纯离线动作，只读已落地的产物，不修改目标，无目标侧复原动作；解析材料与调用记录仍按既有机制留存。超时或工具异常时保留本次记录与部分输出，不由本卡追加重试，交编排处理。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
