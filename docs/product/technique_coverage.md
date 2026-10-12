# ATT&CK 技术覆盖（钉 16.1）

> 生成物：`python scripts/attack_coverage.py --out docs/product/technique_coverage.md`。别手改；改卡或换版本后重跑。
> 数据源：`skills/registry.json` + `data/attack/techniques.json`（ATT&CK Enterprise 16.1，sha256 `8423d8dac3fc`，抓取 2026-09-16 15:31:28+0800）+ `output/hongri7/json/Hongri7_v2.action_graph.json`。

## 1. 版本口径

- 钉住版本：**16.1**（`data/attack/techniques.json` 的 `source.attack_version`；锁版决策见 `docs/decisions.md` D53）。
- 集合全量：799 条技术 id / 656 live / 14 个战术（企业矩阵）。
- 别名层：1 条（`T1623` → `T1059`）：写-up 里的历史 id 在这里归一，图的原文不改写。

## 2. 卡 × 技术（动作类）

卡片按注册表顺序 = 优先级；技术名读自钉住的索引，战术按矩阵顺序。

| 战术 | 技术 | 16.1 名 | 卡片（注册表顺序） |
| --- | --- | --- | --- |
| TA0001 Initial Access | `T1190` | Exploit Public-Facing Application | `exploit.redis_unauth_write`、`exploit.laravel_ignition_rce` |
| TA0002 Execution | `T1059` | Command and Scripting Interpreter | `exploit.tongda_oa_include_rce` |
| TA0004 Privilege Escalation | `T1068` | Exploitation for Privilege Escalation | `exploit.privileged_container_escape` |
| TA0004 Privilege Escalation | `T1574.007` | Path Interception by PATH Environment Variable | `exploit.suid_path_hijack` |
| TA0005 Defense Evasion | `T1562.001` | Disable or Modify Tools | `exploit.wmi_firewall_off`、`exploit.netexec_firewall_off` |
| TA0006 Credential Access | `T1003.001` | LSASS Memory | `exploit.kiwi_lsass_dump`、`exploit.comsvcs_minidump`、`exploit.pypykatz_parse` |
| TA0008 Lateral Movement | `T1021` | Remote Services | `exploit.wmic_remote_cmd` |
| TA0008 Lateral Movement | `T1021.002` | SMB/Windows Admin Shares | `exploit.impacket_psexec_cmd` |
| TA0008 Lateral Movement | `T1021.006` | Windows Remote Management | `exploit.impacket_wmiexec_cmd` |

## 3. 图节点命中（AND 节点）

图上写的 id 一律不改写；`raw → canonical` 一列只在别名表翻译过时出现差异。「命中键」= 选定卡在这条节点上的召回来源（technique / case）。

| 节点 | 图 id | 归一后 | 服务/端口 | 召回卡（命中键） |
| --- | --- | --- | --- | --- |
| 2 | `T1562.001` | `T1562.001` | scm/445 | exploit.netexec_firewall_off（technique/case）、exploit.wmi_firewall_off（case） |
| 5 | `T1003.001` | `T1003.001` | lsass/- | exploit.kiwi_lsass_dump（technique/case）、exploit.comsvcs_minidump（technique/case）、exploit.pypykatz_parse（technique/case） |
| 7 | `T1623` → `T1059` | `T1059` | tongda_oa_v11_3/8080 | exploit.tongda_oa_include_rce（technique/case） |
| 12 | `T1190` | `T1190` | redis/6379 | exploit.redis_unauth_write（technique/case） |
| 14 | - | - | -/6379 | pre.nmap_tcp_probe（case） |
| 19 | `T1623` → `T1059` | `T1059` | tongda_oa_v11_3/8080 | exploit.tongda_oa_include_rce（technique/case） |
| 22 | `T1068` | `T1068` | privileged_container/- | exploit.privileged_container_escape（technique/case） |
| 26 | `T1574.007` | `T1574.007` | suid_path_helper/- | exploit.suid_path_hijack（technique/case） |
| 28 | `T1190` | `T1190` | laravel/81 | exploit.laravel_ignition_rce（technique/case） |
| 30 | - | - | -/81 | pre.nmap_tcp_probe（case） |
| 44 | `T1021` | `T1021` | smb/445 | exploit.wmic_remote_cmd（technique/case）、exploit.impacket_psexec_cmd（case）、exploit.impacket_wmiexec_cmd（case） |
| 48 | `T1021` | `T1021` | smb/445 | exploit.wmic_remote_cmd（technique/case）、exploit.impacket_psexec_cmd（case）、exploit.impacket_wmiexec_cmd（case） |

- 全图覆盖：**12/12 AND 节点有卡**；无缺口。

## 4. 口径说明

- 32 张卡 = 13 张动作类（挂技术号，本页第 2 节）+ 19 张支撑类（不挂技术号，按 case / provides / fact 召回，不在本表）。
- 战术面：6/14（图上用到的都覆盖了；其余战术暂无卡，不是缺口而是范围）。
- 别名实际使用：`T1623 → T1059`（原文保留在图上，召回按归一后的 id 走）。
- 判定口径：版本锁死一个 release，所以「卡引用的技术是否存在、是否退役」是确定性检查（`tests/test_attack_index.py`），不随上游漂移。
