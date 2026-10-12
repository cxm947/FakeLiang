# rules5_v2：Windows 横向移动规则改进说明

这次改进解决的是一个很具体的问题：原 `rules5.P` 把 Windows 横向移动绑定在 `winrm` 这个服务名上，导致 Hongri7 里真实走 SMB/445 的凭据远程执行无法被规则自然推导。之前的 `Hongri7_compat.P` 只能额外写 `networkServiceInfo(..., winrm, tcp, 445, system)` 来“借壳闭合”，这在论文里可以作为对照，但不适合作为正式建模。

新的做法不是把 `winrm` 简单改成大写变量。大写变量如果没有约束，会让规则匹配任意服务，HTTP、SMB、RDP 甚至本地服务都有机会误触发。`rules5_v2.P` 采用的是“参数化服务名 + 技术标签约束”：

```prolog
ttpExists(HOSTD, RemoteService, _, windowsCredentialRemoteExecution, lateralMovement),
networkServiceInfo(HOSTD, RemoteService, Protocol, Port, _)
```

这里 `RemoteService` 可以是 `winrm`、`smb`、`wmi` 等具体服务，但必须先由事实文件声明它属于 Windows 凭据型远程执行。变量负责通用性，`ttpExists` 负责门禁。

## 文件关系

| 文件 | 用途 |
| --- | --- |
| `data/inputs/hongri7/rules5.P` | 原冻结规则，保持不动，用来复现旧结果 |
| `data/inputs/hongri7/rules5_v2.P` | 面向 Hongri7 和后续真实靶场建模的规则改进版 |
| `data/inputs/ip_preset/rules5_ip.P` | S1/S2/S3 旧 IP 预设规则，保持不动 |
| `data/inputs/ip_preset/rules5_ip_v2.P` | 如果以后要用 v2 重跑 S1/S2/S3，可用这个版本 |
| `data/inputs/hongri7/Hongri7_v2.P` | Hongri7 的 v2 事实文件，用 SMB + `windowsCredentialRemoteExecution` 表达 PC2/DC 横向 |

## 投影器与生成状态

2026-09-10 已在 `src/graph/rule_catalog.py` 为 `Remote Services - Windows Credential Remote Execution - T1021` 增加三个 case：

- `windows_credential_remote_system_firewall_state`
- `windows_credential_remote_admin_firewall_state`
- `windows_credential_remote_system_after_firewall_disable`

测试 fixture 已同步到 38 个 case，`pytest` 当时读数 `105 passed, 1 skipped`（现行回归基线见 [AGENTS.md](../../AGENTS.md)）。`scripts/generate_hongri7.ps1` 也已经改成三 profile：`Hongri7` 和 `Hongri7_compat` 继续使用 frozen `rules5.P`，`Hongri7_v2` 使用 `rules5_v2.P`。

**2026-09-11 已正式生成 `Hongri7_v2` 三件产物**（JSON/DOT/PDF），容器实例 `Mulval2`（镜像 `wilbercui/mulval:latest`，image id `7bc050763812`），rules 哈希校验通过（`rules5_v2.P` = `615FF9BE…FB52`）。投影结果：输入 53 节点 / 59 边，12 个 AND 节点全部匹配，`unmatched_and_nodes=[]`，`observed_cases=9 / catalog_cases=38`；其中 `windows_credential_remote_*` 三个 case 均被实际命中。原始 run 目录：`output/hongri7/runs/20260911_082231_276871d0/`。

## Hongri7 里怎么表达

`Hongri7_v2.P` 不再添加假的 `winrm` 服务，而是写成：

```prolog
hasAccount(pc2, domain_administrator, lab_domain_credential, system).
ttpExists(pc2, smb, remoteClient, windowsCredentialRemoteExecution, lateralMovement).
networkServiceInfo(pc2, smb, tcp, 445, system).

hasAccount(dc, domain_administrator, lab_domain_credential, system).
ttpExists(dc, smb, remoteClient, windowsCredentialRemoteExecution, lateralMovement).
networkServiceInfo(dc, smb, tcp, 445, system).
```

这句话的大白话是：我们已经有域管凭据，目标机器有 SMB/445 管理入口，这个入口在本实验中被视为 Windows 凭据型远程执行能力，所以可以由规则推导到目标主机的 `system` 执行状态。

## 对 S1、S2、S3 的影响

旧文件没有被覆盖，所以历史结果不会变。

如果以后用 `rules5_ip_v2.P` 重跑旧的 S1/S2/S3，预期也不会破坏主路径：

- S1 里的 WinRM 服务本来就有 `ttpExists(..., winrm, ..., windowsRemoteManagement, lateralMovement)`，v2 只是把这条事实从注释里的建议变成真实前提。
- S2 没有走 WinRM 横向移动，基本不受这次变化影响。
- S3 里的 WinRM 节点也有对应 `windowsRemoteManagement` 事实；SMB 的 pass-the-hash 规则仍保留，不需要迁移到新标签。

唯一需要注意的是：如果某个旧场景只有 `networkServiceInfo(..., winrm, ...)`，但没有对应 `ttpExists(..., windowsRemoteManagement, lateralMovement)`，原规则会放行，v2 不会。这不是退化，而是把“只要端口名像 WinRM 就能横向”的隐含假设改成显式事实。

## 论文里的推荐口径

正式主线可以这样写：

> 原规则库把 Windows 横向移动硬编码为 WinRM 服务名，无法自然表达 Hongri7 中基于 SMB/445 的凭据远程执行。改进后的 `rules5_v2` 将远程服务名参数化，并使用 MITRE 技术语义标签进行约束，使 WinRM、SMB/PsExec、WMI 等白盒验证路径可以共享同一类逻辑规则，同时保留原规则库作为历史复现实验基线。

## D32-h 追加（2026-09-16）：节点 2 的凭据前提，与一次真实的编号位移

`assets.json` 的抽象 A4 原本写着「frozen `disableFirewall` 规则缺凭据前提，生成的图必须披露这条捷径」。
D32-h 把这条捷径在 v2 线上补掉了 —— 但补的方式不是「再加一条规则」，而是**就地改 `RULE 12` 的 body**。

### 为什么不新增一条 interaction_rule 包一层

两个实证理由：

1. **本 MulVAL 构建里 `rule_desc(Desc, Priority)` 的优先级不被使用**。`grep -rni prior src/ lib/ kb/` 只命中 lexer 的一行注释，
   也就是说同一结论的两条规则不会「择一」，而是各自生成一个 AND 节点；
2. 于是旧路径会**留在图里**：新增一条带凭据的规则，图上会同时存在「无凭据也能关防火墙」和「需要凭据」两个 AND 节点，
   而我们要的正是把前者消掉。对照证据：`RULE 21` 在本图里确实生成了两个 AND 节点（节点 7 与节点 19），`RULE 4` 同理。

### 改了什么

`data/inputs/hongri7/rules5_v2.P`（**不进 git**，备份 `rules5_v2.P.bak_20260916_preD32h`）：`RULE 12` 的 body 末尾追加两行，
写法与 T1021 系列、以及 fixture 里的既有模板一致（凭据对放在 body **最后**，理由见下面的位移表）：

```prolog
getAccount(HostS, User, Passwd, system),
hasAccount(HostD, User, Passwd, system)
```

- 新 `sha256` = `8DD7B85D25BECAE581BD55013A508364100FF4359604F25358A3523A73E10D8F`（原 `615FF9BE…FB52`）；
  `scripts/generate_hongri7.ps1` 的 `expectedHash` 已同步。**frozen `rules5.P` 不动**（仍 `71D703B2…B6A8`），历史三份图可复现。
- 投影器侧新增 case `disable_firewall_credentialed`（同 `rule_desc` / head，body 多凭据对），**旧的 `disable_firewall` 保留**，
  因为冻结 `rules5.P` 生成的三份图仍然靠它匹配。`cases.py::_match_case` 要求「节点前提签名多重集 == case 模式签名多重集」精确相等，
  所以规则一变**必须**同步登记 case，否则节点 2 会掉进 `unmatched_and_nodes`。
- fixture 可复现化：`scripts/prepare_rule_fixtures.py` 新增 `--extension <rules5_v2.P>` 与 `EXTENSION_PICKS`，并与运行时目录逐条校验 head/rule_desc；
  输出 CRLF。实跑结果 **39 条模板**（38 条旧模板零改动 + 新增一条 + v2 sha 更新），`tests/test_cases.py` 同步 38→39。
- 登记表：`skills/registry.json` 里两张关防火墙卡（`exploit.wmi_firewall_off` / `…_firewall`）的 `case` 数组各加 `disable_firewall_credentialed`；
  索引重建 → `cases 9→10`，`python scripts/build_skill_index.py --check` → ok。

### 图侧结果

- 三 profile 全部 `unmatched_and_nodes=[]`；v2 图：`input_edges 59→61`、`and_nodes=12`、`catalog_cases=39`、`observed_cases=9`；
- 节点 2（`pc1 → dc`，T1562.001）`details.accounts` = `dc:domain_administrator`（LEAF 3）+ `pc1:domain_administrator`（OR 4，由 `RULE 6` / 新节点 5 产出），
  `premise_refs=[3,4,6,39,40,41,42]`；
- 冻结 profile 不变（`Hongri7` 10 AND / `Hongri7_compat` 12 AND）。

### 编号位移表（改规则后必须核对的事实）

MulVAL 的节点号来自 `AttackGraph.txt` 的导出顺序，规则体一变，**编号会整体位移**。v2 新编号与旧编号的对照：

| 语义 | 旧号 | 新号 |
| --- | --- | --- |
| LSASS 转储（pc1，T1003.001） | 41 | **5** |
| pc1 → dc 凭据横向（T1021） | 38 | **44** |
| `execCode(dc,system)` 聚合 | 37 | **43** |
| 其余 10 个输出节点 | 14 / 12 / 7 / 2 / 30 / 28 / 26 / 22 / 47 / 48 | 不变 |

位移不是文档噪声：`tests/test_run.py`、`tests/test_run_path_chain.py`、`tests/test_selector.py`、`tests/test_skill_catalog.py` 里所有硬编码的 41/38/37
都跟着改成了 5/44/43（`FULL_ORDER` = `14,12,7,skip19,5,2,30,28,26,22,44,agg43,48,agg47`）。
顺带记一条实证：把凭据对放到 body **最前**曾得到 lsass=39 / dc=44 / agg=43，放**最后**得到 lsass=5 / dc=44 / agg=43 —— 两种顺序都拿不回旧号，
所以按「与 T1021 和 fixture 模板一致」定稿为放最后。

### 实机验证

`output/runs/D32h-live3`：`run: succeeded via done_all`，节点 2 实机 `done`（24.3 秒，目标自报 `EnableFirewall=disabled`），
节点 44/48 随后 `done`（见 [validation_runs](validation_runs.md) 的 D32-h 节）。
