# 技能补卡清单

「验证现场暴露了、但还没有接入技能」的缺口登记在这里。这是 backlog，不是状态表：技能的状态只看 `skills/<id>/skill.json` 的 `status`（见 [技能目录契约](skill_contract.md) §10）。

每条缺口写四样东西，缺一不可：

1. **现场证据**：run 目录 + call id + 判定原文，能复核；
2. **已知根因**：区分「采集面」（数据没进产物）与「解析面」（产出了但没读出来），没确认的写「待证」；
3. **候选路线**：每条都落到具体工具模式或脚本入口，不写「研究一下」；
4. **验收标准**：补到什么程度算闭环。

缺口没补上之前，运行记录只能写「缺口 + 假设」（`run_result.json` 的 `graph_gaps` / `skill_gaps` / `assumptions[]`），不能写成功；也不为了让链条好看去改图、改判据，或把「显式输入」伪装成解析结果。

## 1. exploit.pypykatz_parse 拿不到域管明文 —— **B 路线已闭环**（D39-live1，2026-09-16；A 路线仍是默认口径）

- **现场证据**（全部落在本机 `output/runs/` 里，可直接复核）：
  `output/runs/D32-live3/node-41/attempt-3-credential.parse.minidump_pypykatz/call-20260916T053306-7d475b/`
  - `stdout.txt`（8 620 B）：`pypykatz lsa minidump /home/kali/agv-loot/lsass-pc1.dmp` 全文，`returncode=0`；
  - `envelope.json`：`credential_accounts = ["WHOAMIANONY\\PC1$", "WHOAMIANONY\\bunny"]`、`dump_sha256=d6355851…3dc25`；
  - `judgement.json` / `verdict.json`：`effect` 闸要求「凭据材料存在」——材料在，但**不是域管**。
- **证据读数（决定性）**：
  - dump 里 **6 个 LogonSession**：`bunny`、`ANONYMOUS LOGON`、`LOCAL SERVICE`、`PC1$`、一个空用户名、`PC1$`；
  - 全文搜 `dministrator` = **0 次命中**；
  - 解析器本身正常：`WDIGEST` 6 块 / `MSV` 3 块 / `Kerberos` 4 块 / `TSPKG` 1 块 / `DPAPI` 2 块，`bunny` 的 `Bunny2021` 明文就是 WDIGEST 块读出来的。
- **根因（已定性）**：**不是** dump 覆盖不全，也**不是** pypykatz 覆盖集小 —— 这两个假设已被上面的读数排除（解析器能读 WDIGEST 明文，dump 里就是没有域管会话）。真正的约束是 **LSASS 只缓存「当时活着」的登录会话**：我们的 run 对 dc / pc2 只用过**网络登录**（`net use` + WMI 进程创建 / SMB），网络登录（Type 3）不在目标上留下 WDIGEST / MSV 缓存；writeup 复刻里那次 `sekurlsa::logonpasswords` 有域管明文，是因为当时域管在目标上有**交互式**登录（RDP / 控制台，Type 2 / 10）。
- **已排除的假设（别重复做）**：
  - ~~换解析器（再加一条 minidump 解析卡）~~：解析器不是瓶颈；impacket `secretsdump` 面向注册表 hive / NTDS，本来也不解析 LSASS minidump；
  - ~~dump 更全（换 MiniDump 参数）~~：`full` 已是全量转储，缺的是**会话**，不是区域。
- **候选路线（按代价排序）**：
  - **A（保持现状 · 推荐）**：域管凭据走**显式运行输入**（`run_context.domain_admin.json` 的 `provenance` 指向 writeup 复刻原文），链只负责把 dump 里**真实存在**的东西取出来。这是正确做法而不是权宜：图上要求的 leaf 是「域管凭据可用」，它由另一条路径证明存在，运行层如实记录来源与假设。
  - **B（时序 / 场景 · 想真的从 dump 读出来就走这条）**：dump **之前**让域管在 pc1 上有一次交互式登录（RDP 或控制台），再跑链。这是**运行场景**，技能卡不创造它；要落地得在 run 输入里写清这一步（谁、何时、怎么登录），并把「登录这一步」记成假设。
  - **C（位置）**：把采集点换到域管经常交互登录的主机（例如 DC）。这会动图（节点 41 的 source 是 pc1），属**图侧**决策，不在本卡范围。
  - **D（交叉验证 · 保底）**：拿同一份 dump 用另一个解析器复判（MSF / Meterpreter `kiwi` 的 `lsa_minidump`，或 Windows 端 mimikatz `sekurlsa::minidump` → `sekurlsa::logonpasswords`）。用途只有一个：证明解析器没漏读（本轮已用 WDIGEST 明文间接证明）。它**不修复**缺口。
- **验收标准**：
  - 走 A：本条保持「已定性」状态，运行记录里那条显式输入的 `provenance` 可复核（现在就是）；
  - 走 B / C 想闭环：`output/runs/` 里至少一次 run 的解析段证据出现 `username Administrator` 的 WDIGEST / MSV 行（带 call_id），并把 call id 写进解析卡 `notes`；否则保持打开。

### 1-b. D39 闭环记录（B 路线：目标状态补齐后复跑，2026-09-16）

- **做了什么**：dump 之前，让域管在 pc1 控制台做一次交互式登录（`WHOAMIANONY\Administrator` + `Whoami2021`，VMware VNC 控制台，Type 2），
  然后按复现命令重跑一遍整图（`output/runs/D39-live1`，约 45 秒）。技能卡一条没改、输出契约一个字没改。
- **验收读数**（满足本节「走 B」的验收标准）：
  `output/runs/D39-live1/node-5/attempt-3-credential.parse.minidump_pypykatz/call-20260916T082601-663b1e/`
  - `stdout.txt`：`username Administrator` / `domainname WHOAMIANONY` / `session_id 2` / `logon_server DC` /
    `logon_time 2026-09-16T00:23:12Z` / `sid …-500`；`MSV NT: ab89b1295e69d353dd7614c7a3a80cec`、
    `WDIGEST password Whoami2021`、`Kerberos Password: Whoami2021`、`TSPKG`、`DPAPI`；
  - `envelope.json`：`dump_sha256=bec54676e5534880c1857e5fcd857645fbbc4a182a55f522de745bae6ef0d057`，
    `credential_material` 里 `Administrator` 有 `nt` 与 `plaintext` 两条；
  - call id 已写进 `skills/exploit.pypykatz_parse/SKILL.md` 末段「实机验证记录」（D39 条目）。
- **节点编号说明**：图在 D32-h 之后按新导出顺序重生成过（已记录事实：lsass `41 → 5`、pc1→dc 横向 `38 → 44`、dc 聚合 `37 → 43`），
  所以 D39 的读数落在 `node-5`，与 D32-live3 的 `node-41` 是同一条链。
- **顺带取证的环境缺陷（不是技能缺口）**：pc1 的机器账号在 AD 里**不存在**（`CN=Computers` 只有 `DC$` / `PC2$`），
  `nltest /sc_query` 报 1787；用域管凭据经 LDAP 补建 `PC1$`（`output/diag/D39/ad_pc1.ps1`）后变为 5（ERROR_ACCESS_DENIED）。
  `netdom` 在本通道不可用（`/?` 即挂死：服务会话 + stdout 是管道），WMI `JoinDomainOrWorkgroup` 返回 `2691`（已入域、拒绝重入）。
  **结论**：修信任不是本轮必需路径 —— 登录用的是 DC 上已存在的域账号，交互式会话照样落 LSASS。
- **本条的最终口径**：B 路线证明「有交互式会话就有域管」；但**运行默认仍走 A**（域管凭据是显式运行输入，
  `provenance` 指 writeup 复刻原文）。本条不再挂「待补」；往下若要闭环，只是把「dump 前先登录」写进 run 输入。

### 1-c. D40 更正与闭环记录（凭据供给链：角色键 <-> 登录名映射，2026-09-16）

- **更正 1-b 末句**：运行层真正要补的不是「dump 前先登录」写进 run 输入（那是**环境前置**，D39 已证明其成立后 2/44/48 仍 blocked），
  而是把**已有材料与图上角色键的对齐**显式登记进运行输入。
- **D40 落地**：`account_aliases`（操作者显式声明 `domain_administrator → WHOAMIANONY\Administrator` + provenance，**不含 secret**；
  材料由链现场产出）→ `run.materialize_account_aliases` 入账；`data/inputs/hongri7/run_context.alias_only.json` 体检 6 ok / 0 warn / 0 error。
- **验收读数**（`output/runs/D40-live1`、`D40-live2`，各 25 calls）：`account_aliases[0]` `target_held=true` + `filed=true`；
  `kind=bridge` 假设 0 条（替以 `kind=alias` 1 条）；节点 2/44/48 由 `blocked/need` → `succeeded/done`。
- **本条不再挂账**：凭据供给链（角色键 <-> 登录名）已闭环；换靶场时操作者按 `run_input_contract.md` §2.4 声明映射即可。

## 怎么加下一条

从一次真实 run 里带证据进来：先确认它不是**图缺口**（图缺事实走 `graph_gaps`，改图或改运行输入，见 [rules5_v2 说明](rules5_v2_windows_lateral.md) 的 D32-h 节），再按上面四样写一节；候选路线要能直接开工，不写「可能会用到」的猜测。
