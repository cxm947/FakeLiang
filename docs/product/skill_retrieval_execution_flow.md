# 技能检索、适配与校验工程流程

> **术语对齐（2026-09-16，D28 更名）**：本文原名 `capability_retrieval_execution_flow.md`，写作时用的是 v3「ability」口径；
> 现已统一为 `skill`（`skill_id` = 注册表条目 ID，`skills/registry.json` 为唯一登记源），文件名同步改成 `skill_retrieval_execution_flow.md`。
> 词表见 [术语表](glossary.md)；现行契约见 [技能目录契约](skill_contract.md)；本文保留为技能层工程流程的设计说明。
>
> 本文是 v0.3 运行契约上的技能层方案。目标是把“漏洞复现和验证”做成可检索、可执行、可审计的工程流程，而不是让模型临时猜工具、猜命令、猜成功条件。

## 1. 总体结论

主线固定为六步：

```text
攻击图节点需求
  -> 查索引表，召回候选技能
  -> 读技能注册表，选择一条具体技能
  -> 参数绑定，形成一次 locked invocation
  -> 适配器执行固定工具模式
  -> 校验器检查证据，写入 records
```

索引表负责“找到可能相关的技能”。技能注册表负责“说明每条技能到底能做什么、适用于什么、需要什么、怎么执行、怎么判定”。适配器负责“把已经绑定好的参数转成真实工具调用”。校验器负责“把工具输出变成可接受或不可接受的证据”。

这不是三套范式，而是一条流水线。索引和注册表是数据面，适配器和校验器是执行面。

## 2. 四个工程对象

### 2.1 技能注册表：唯一事实源

注册表是源文件，逐条人工维护或由技能包生成。每条技能是一种固定方法，不是一整个工具。

技能粒度规则：

```text
一条技能 = 固定验证方法 + 固定入口 + 参数契约 + 固定校验逻辑
```

如果选中这条之后，模型还要临时决定“用工具的哪个模式、执行什么验证、怎样算成功”，说明这条太宽，应该拆。

首版字段建议分成三档。

第一档是检索摘要，供索引和人工理解：

```yaml
skill_id: windows.psexec.remote_exec.identity_probe
name: PsExec remote command identity probe
description: >
  从已核对的 Windows 来源会话发起 PsExec 远程执行探测，
  在目标主机运行固定身份采集命令，用于证明目标命令执行是否成立，
  并观察实际身份是否满足节点要求。
keywords: [remote_exec, lateral_movement, smb, psexec, identity_probe]
task_type: remote_execution_validation
phase: action
tactic_ids: [TA0008]
technique_ids: [T1021]
cve_ids: []
platforms:
  source: [windows]
  target: [windows]
services: [smb]
proof_scope: behavior
```

第二档是选择约束，供选择程序筛选：

```yaml
applies_to:
  source_host_required: true
  target_service: smb
  protocol: tcp
  port: 445
requires:
  source_session:
    host_must_match_graph_source: true
    min_identity: local_admin_or_system
  credential_ref:
    required: true
    accepted_forms: [password, ntlm_hash]
  tool:
    name: PsExec64.exe
    location: source_session_or_staged_tool
proves:
  statement: >
    条件命题：如果本次固定探测在目标主机完成，并且目标与身份校验通过，
    则证明目标主机命令执行成立，并记录实际身份。
  propositions: [command_execution_confirmed, identity_observed]
not_prove:
  - 不预先承诺任何固定权限等级
  - 不证明持久化、数据外带或后续横向移动
```

第三档是执行契约，供适配器和校验器使用：

```yaml
inputs:
  - {name: source_session_ref, type: session_ref, required: true}
  - {name: target_host, type: host_ref, required: true}
  - {name: credential_ref, type: cred_ref, required: true}
  - {name: expected_identity, type: identity_requirement, required: true}
entry:
  runner: source_session
  stage: action
  adapter: adapters/windows/psexec_identity_probe
  adapter_version: "1.0.0"
  fixed_inside_adapter: [tool_path, argv_template, timeout, parser]
check:
  type: three_gate_identity
  checker: checkers/remote_exec_three_gate
  on_missing_evidence: uncertain
```

这份结构比“名称、描述、执行位置”多，但没有失控。核心是：检索字段少而清楚，选择字段只保留决定能不能用的硬条件，执行细节封装到适配器。

### 2.2 索引表：注册表派生出来的多入口目录

索引表不是另一份真相。它从注册表生成，用来快速召回技能。

首版可以生成三类索引：

```yaml
by_technique:
  T1021:
    - windows.psexec.remote_exec.identity_probe
    - kali.impacket.wmiexec.identity_probe
    - kali.netexec.smb.command_probe

by_task_type:
  remote_execution_validation:
    - windows.psexec.remote_exec.identity_probe
    - kali.impacket.wmiexec.identity_probe

by_keyword:
  smb:
    - windows.psexec.remote_exec.identity_probe
    - kali.impacket.wmiexec.identity_probe
  psexec:
    - windows.psexec.remote_exec.identity_probe
  identity_probe:
    - windows.psexec.remote_exec.identity_probe
```

同时保留一个轻量描述检索，用 `name + description + keywords` 做兜底召回。这个兜底不是为了决定成功，只是避免索引词没设计好时漏掉候选。

检索规则：

```text
分类索引命中 + 描述检索命中 -> 合并去重 -> 读取注册表详情 -> 选择程序筛选
```

不能只在“分类索引完全没命中”时才搜描述，因为分类命中了一个弱候选时，描述检索可能还能找到更合适的方法。

### 2.3 适配器：固定工具模式，不让模型拼命令

适配器的输入是已经锁定的技能和参数，不接收自由命令。

适配器固定做四件事：

```text
解析引用 -> 构造工具调用 -> 执行 -> 解析原始输出
```

以身份探测为例，适配器内部固定采集：

```text
whoami /user /fo csv /nh
hostname
```

它返回结构化观察：

```json
{
  "call_id": "call-20260916T031502-b7d3e9",
  "skill_id": "windows.psexec.remote_exec.identity_probe",
  "target_host": "pc2",
  "target_ip": "192.168.93.40",
  "runner": {"type": "source_session", "host": "pc1"},
  "tool": "PsExec64.exe",
  "exit_code": 0,
  "parsed": {
    "hostname": "PC2",
    "identity_name": "NT AUTHORITY\\SYSTEM",
    "identity_sid": "S-1-5-18"
  },
  "raw": {
    "stdout_ref": "artifacts/run-x/node-48/stdout.txt",
    "stderr_ref": "artifacts/run-x/node-48/stderr.txt",
    "sha256": "..."
  },
  "errors": []
}
```

> 示例里的 `call_id` 与 `artifacts/...` 都是占位值。真实 `call_id` 由 `src/runtime/runner.py::new_call_id()` 生成，
> 形如 `call-YYYYMMDDTHHMMSS-<6 位十六进制>`（多步适配器再补 `-<标签>`，例如 `-include`），
> 落盘位置是 `output/runs/<run>/…/<call_id>/`。

注意这里的 `runner` 很关键。Kali 可以是控制端，但图里如果要求 `pc1 -> pc2`，那就不能把“从 Kali 直连 PC2”的结果直接当成这条边的证明。除非注册表里明确声明该技能能够通过 PC1 的路由、代理或会话作为来源执行，并且校验器能证明来源一致。

### 2.4 校验器：把输出变成证据，不看关键词拍脑袋

你给的三闸模型是对的，建议保留，并扩成统一接口。

```yaml
check:
  type: three_gate_identity
  gate_1_freshness:
    require_call_id: true
    require_current_record: true
  gate_2_target:
    match_bound_target: true
    accept_evidence: [target_ip, hostname, session_host]
  gate_3_identity:
    compare_to_node_requirement: true
    system_sid: S-1-5-18
  on_missing_evidence: uncertain
```

判定语义：

```text
pass        证据完整，目标对齐，身份满足节点要求
unsatisfied 执行成立、目标对齐，但身份明确不满足节点要求
uncertain   证据缺失、目标无法对齐、输出解析异常、调用归属不明
error       适配器或工具执行异常；通常先进入诊断，不直接证明节点失败
```

在 v0.3 数据契约里，最终写入 `records.kind=check` 时仍然落成 `value=true/false/null`：

```text
pass        -> value=true
unsatisfied -> value=false
uncertain   -> value=null
```

`unsatisfied` 只表示“本技能本次尝试未满足该节点要求”，不等于漏洞不存在，也不等于其他技能不可行。

## 3. 运行时完整流程

### 3.1 从攻击图生成需求

以红日 7 的节点 48 为例，原图含义是：

```text
RULE 30 Remote Services - Windows Credential Remote Execution - T1021
目标效果：execCode(pc2, system)
来源主机：pc1
目标主机：pc2
服务：smb/tcp/445
凭据事实：lab_domain_credential
技术：windowsCredentialRemoteExecution / lateralMovement
```

主控程序从 V1 `action_graph.json` 读取这些字段，形成内部需求：

```json
{
  "node_original_id": "48",
  "task_type": "remote_execution_validation",
  "tactic_ids": ["TA0008"],
  "technique_ids": ["T1021"],
  "source_host": "pc1",
  "target_host": "pc2",
  "target_ip": "192.168.93.40",
  "service": "smb",
  "protocol": "tcp",
  "port": 445,
  "expected_effect": "execCode(pc2, system)",
  "expected_identity": {"type": "windows_sid", "sid": "S-1-5-18"},
  "credential_ref": "fact:40"
}
```

这一步不选工具，只把图里的要求翻译成可检索的需求对象。

### 3.2 查索引召回候选

选择程序用多个入口查索引：

```text
technique_ids=T1021
task_type=remote_execution_validation
keywords=[smb, windowsCredentialRemoteExecution, lateralMovement, identity_probe]
description_query="pc1 to pc2 smb remote execution system"
```

可能得到：

```json
[
  "windows.psexec.remote_exec.identity_probe",
  "kali.impacket.wmiexec.identity_probe",
  "kali.netexec.smb.command_probe",
  "support.smb.port_reachable"
]
```

这里还没选定技能，只是得到候选集合。

### 3.3 读注册表过 gate

选择程序读取每条技能的注册表记录，按 gate 筛。

```text
Gate A: 证明目标是否匹配
  需要证明 execCode(pc2, system)，只证明端口可达的 support.smb.port_reachable 淘汰。

Gate B: 图中来源是否匹配
  图要求 pc1 -> pc2。直接从 Kali 到 pc2 得到的结果不能直接通过，除非它声明并证明来源等价。

Gate C: 前提是否满足
  是否有 pc1 的来源会话、是否有凭据引用、目标端口和服务是否匹配、工具是否可用。

Gate D: 输出能否喂给校验器
  必须能产生 hostname、identity、call_id、原始输出引用。
```

筛选结果可能是：

```json
{
  "selected": "windows.psexec.remote_exec.identity_probe",
  "usable": true,
  "pending_inputs": [],
  "rejected": [
    {
      "skill_id": "support.smb.port_reachable",
      "reason": "only proves connectivity, not command execution or identity"
    },
    {
      "skill_id": "kali.impacket.wmiexec.identity_probe",
      "reason": "direct attack_box execution does not prove graph source pc1 -> pc2"
    }
  ]
}
```

如果缺 `source_session_ref` 或 `credential_ref`，该技能不应该消失，而是进入 `pending_inputs`。这叫“技能存在但本次参数不足”，不是“没有技能”。

### 3.4 锁定调用

一旦选中技能，就生成 locked invocation。锁定之后，模型不能再换工具、换命令或换判据。

```json
{
  "node_id": "48",
  "skill_id": "windows.psexec.remote_exec.identity_probe",
  "skill_version": "1.0.0",
  "adapter": "adapters/windows/psexec_identity_probe",
  "checker": "checkers/remote_exec_three_gate",
  "bound_inputs": {
    "source_session_ref": "session:pc1:system:verified",
    "target_host": "pc2",
    "target_ip": "192.168.93.40",
    "credential_ref": "fact:40",
    "expected_identity": {"sid": "S-1-5-18"}
  }
}
```

这条锁定记录应写入 `records.kind=agent` 或作为工具记录的 `args` 一部分，方便复盘。

### 3.5 适配器执行

适配器解析 `credential_ref`，从凭据库取出真实凭据，组装固定调用。日志中只保存脱敏参数。

示例命令形态：

```text
PsExec64.exe \\192.168.93.40 -accepteula -nobanner -n 10
  -u LAB\domain_administrator -p <redacted>
  -s cmd.exe /d /c "whoami /user /fo csv /nh && hostname"
```

程序实现上不要拼 shell 字符串，应该传 argv 数组，由 runner 负责正确转义：

```python
argv = [
    tool_path,
    r"\\192.168.93.40",
    "-accepteula", "-nobanner", "-n", "10",
    "-u", credential.qualified_username,
    "-p", credential.secret,
    "-s",
    "cmd.exe", "/d", "/c",
    'whoami /user /fo csv /nh && hostname',
]
result = source_session.run_argv(argv, timeout_seconds=60)
```

适配器返回结构化观察，并把原始输出作为证据文件或记录引用保留下来。

### 3.6 校验器检查

校验器不看“工具说 success”就放行，它按三闸检查。

```text
第一闸：freshness
  call_id 是本次调用生成的吗？
  输出来自当前 tool record 吗？
  时间和通道对得上吗？

第二闸：target
  绑定目标是 pc2 / 192.168.93.40 吗？
  解析到的 hostname 是否能和 pc2 对齐？
  如果 hostname 是 PC1 或解析不出目标，返回 uncertain。

第三闸：identity
  解析到的 SID 是 S-1-5-18 吗？
  是则满足 system；不是则 unsatisfied。
```

三个典型结果：

```text
PC2 + S-1-5-18 + 本次 call         -> pass
PC2 + LAB\alice + 本次 call        -> unsatisfied
PC1 + S-1-5-18 + 本次 call         -> uncertain
```

检查通过后写 `records.kind=check`，再由主控根据节点全部必需效果决定 `node_runs.status`。

## 4. 与 v0.3 运行契约的衔接

本方案不新增大而全的数据平台。落库仍用三张表。

```text
runs
  保存 graph_json、config_json、current、sessions。

node_runs
  保存每个 AND 节点当前状态。

records
  保存检索选择、工具调用、校验结果和最终结论。
```

建议记录映射：

```text
候选召回和选择说明       -> records.kind=agent
适配器实际调用和输出     -> records.kind=tool
三闸校验结论             -> records.kind=check
节点最终 succeeded 等结论 -> records.kind=result
```

节点成功的条件不是“工具执行过”，而是：

```text
该 AND 节点声明的必需 effect 全部有程序接受的 check/result 证据。
```

OR 事实不单独写表，由成功的 provider 节点推导。

## 5. 反例

### 反例 1：索引命中了 T1021，但技能不合适

`kali.impacket.wmiexec.identity_probe` 命中 T1021，不代表它能验证节点 48。

如果它从 Kali 直接打 PC2，只能证明“attack_box 到 PC2 的一次远程执行尝试”，不能证明图里的 `pc1 -> pc2`。除非它额外声明并证明“通过 PC1 代理或会话作为来源执行”。

### 反例 2：端口通了，不等于命令执行成立

`support.smb.port_reachable` 能证明 SMB 端口可达，不能证明 `execCode(pc2, system)`。

它可以作为前检查技能，不能作为 action 技能给节点 48 结案。

### 反例 3：用户名看起来像管理员，不等于 SYSTEM

`LAB\domain_administrator` 说明账户名，不能直接证明本次远程进程是 SYSTEM。

节点要求 `system` 时，应核对实际 SID `S-1-5-18` 或等价的强证据。

### 反例 4：输出里有关键词，不等于本次成功

历史日志、错误消息或 banner 里都可能出现 `SYSTEM`、`PC2` 这些词。

所以要检查 call_id、当前通道、原始输出引用和解析结果，不能按字符串命中直接判成功。

## 6. 首版落地任务

第一步，确定技能注册表 schema。字段不用多，但必须覆盖：

```text
id/name/description/keywords
task_type/phase/tactic_ids/technique_ids/cve_ids
platforms/services/proof_scope
applies_to/requires/proves/not_prove
inputs/entry/check
```

第二步，写索引生成器。从注册表生成：

```text
by_technique
by_task_type
by_keyword
description corpus
```

第三步，写 selector。输入图节点需求，输出：

```text
selected skill
rejected candidates with reasons
pending inputs
locked invocation
```

第四步，写 adapter runner。先做两类：

```text
support 前检查：端口可达、服务识别、HTTP 响应、会话身份核对
action 验证：固定命令执行身份探测、漏洞行为验证、凭据效果验证
```

第五步，写 checker。首批不要写十种散乱规则，先统一三类：

```text
reachability checker
service/fingerprint checker
three_gate_identity checker
```

第六步，补测试。每一条技能至少要有：

```text
正例：证据完整，应该 pass
反例：目标不对或身份不够，应该 unsatisfied 或 uncertain
边界例：输出缺字段、call_id 不对、工具 exit=0 但内容异常
```

## 7. 最重要的工程要点

注册表是源，索引是派生。不要手写两份互相漂移的数据。

索引用来召回，注册表用来筛选，适配器用来执行，校验器用来接受证据。四者边界不要混。

描述检索要常规参与候选召回，不只在完全没命中时兜底；但描述相似度只决定先看谁，不决定能不能执行。

技能卡不要粗到“nmap”或“impacket”，要细到“用某工具某模式证明某个命题”。

`proves` 写条件命题，不预设结果。技能能检查 SYSTEM，不代表每次执行都会拿到 SYSTEM。

执行位置要拆成两个概念：控制端在哪里、实际来源在哪里。Kali 常常是控制端，但图里的来源可能是 PC1、web1 或已有 session。

选定即锁定：锁定技能 ID、版本、适配器、检查器、参数来源和脱敏后的调用形态。

校验时先证明“这是本次调用”，再证明“目标对”，最后证明“身份或效果满足”。这比关键词匹配稳得多。

失败要分层：没有可用技能是 blocked，缺参数是 pending/blocking reason，执行了但证据不足是 uncertain，执行成立但不满足要求是 unsatisfied/check false。

v0.3 里不要急着新增一堆表。把技能选择、工具输出和校验结论都先放进 `records`，等数据真的复杂了再拆。

