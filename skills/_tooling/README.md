# 工具类 playbook 页

这里放的是**工具怎么用**的公共页，不是技能卡。

## 为什么单独一层

技能卡按**方法粒度**成文：一张卡 = 一个方法（一次必做步骤）。一个方法在靶场里往往只用到某个工具的
某一小段能力，而同一段工具用法会被好几张卡重复讲到。写进卡里就是三份会各自漂移的副本；抽到这里
就只剩一份，卡只留「这个方法要工具做到什么」和「哪条命令形状属于本卡」。

这里的每一页回答三个问题：**这个工具能回答什么 / 调用形状长什么样 / 输出怎么读、哪里有坑**。
它**不**回答：这一步算不算达成、证据够不够、能不能推进 —— 那些是卡的判据与判定层的事。

## 规矩

| 是 | 不是 |
|---|---|
| 技能卡可以在 `## 怎么做` 里写「工具用法见 `skills/_tooling/<page>.md`」 | 本目录里的页不进注册表、不进索引、不参与检索排序 |
| 本目录的页可以放命令形状、输出样例、坑点 | 本目录**不授予权限**，也不声明 allowed-tools；权限在运行环境与卡契约 |
| 页里出现的命令是**形状**，不是某张卡要照抄的顺序 | 页里不写靶场专有信息（地址、主机名、实例名、运行编号） |

## 目录

| 页 | 覆盖的工具 | 主要引用它的技能卡 |
|---|---|---|
| `nmap.md` | nmap（端口状态、服务标识） | `pre.nmap_tcp_probe`、`pre.service_version` |
| `impacket.md` | impacket 套件（psexec / smbexec / scmr / wmiexec） | `exploit.impacket_psexec_cmd`、`pre.impacket_scm_query` |
| `metasploit.md` | msfconsole、meterpreter 会话与扩展 | `exploit.kiwi_lsass_dump`、`session.*` |
| `netexec.md` | netexec（smb / ssh / winrm 协议前端） | `exploit.netexec_firewall_off`、`pre.credential_valid` |
| `windows-remote-admin.md` | wmic / WinRM / PowerShell 远程查询 | `exploit.wmi_firewall_off`、`exploit.wmic_remote_cmd`、`pre.cim_process_info`、`pre.netsecurity_firewall_state` |
| `posix-shell.md` | POSIX shell 原语（身份、文件、存在性） | `pre.tool_present`、`pre.posix_path_access`、`pre.session_identity`、`post.identity`、`post.file_present`、`post.channel_echo`、`exploit.suid_path_hijack` |
| `redis-cli.md` | redis-cli（未授权写入与回读） | `exploit.redis_unauth_write`、`session.ssh_via_redis` |
| `docker-cli.md` | docker CLI（容器与宿主关系） | `pre.docker_inspect`、`exploit.privileged_container_escape` |
| `http-client.md` | HTTP 客户端（应用层观察与命令通道） | `exploit.tongda_oa_include_rce`、`exploit.laravel_ignition_rce`、`pre.service_version` 的响应路由 |
