# 红日 7：来源核对与本机部署

更新时间：2026-09-10。本机已下载、解压并启动全部五台虚拟机，VMware 清单中已登记五台。网络已配置，Web1 → Web2 的 Laravel 入口、Redis、DC 域服务及 PC2 域成员身份已验证；PC1 的域身份和 OA 组件痕迹已通过只读内存证据确认，但当前网络服务与 VMware Guest Operations 不可达，尚不能做 HTTP 级验收。

现在可以从宿主浏览器打开 [Laravel 外侧入口](http://172.30.97.45:81/)；宿主也能通过 [Web1 内侧地址](http://192.168.52.10:81/)访问同一页面，两者实测均返回 HTTP 200。外侧地址由 DHCP 分配，重启后可能变化。

## 是不是同一套靶场

是同一套环境，但不是同一条复现路线。

- [用户指定 writeup](https://www.cnblogs.com/hellobao/articles/17247190.html)：2023 年的红日 7 复现记录。
- [VulnStack 发布页](http://vulnstack.qiyuanxuetang.net/vuln/detail/9/)：明确称为第七套靶场，发布日期为 2021-03-07，提供五台虚拟机的网络、服务和公开管理账户说明。
- [原作者文章](https://www.freebuf.com/articles/network/264560.html)：由发布页直接链接，作者也在正文链接回同一发布页。

三者对应五台 VM：Web1、Web2、PC1、PC2、DC。Laravel 位于 Web2 内的 Docker 容器，由 Web1 的 nginx 发布入口；指定 writeup 中 PC1 运行通达 OA，PC2 与 DC 位于第三层网络。

需要保留的区别：

| 项目 | 核对结论 |
| --- | --- |
| 外层地址 | 原作者 Web1 是 192.168.1.8，指定 writeup 是 192.168.1.103；属于各自实例地址，不是两台 Web1 |
| 混杂地址 | 指定 writeup 个别命令出现 192.168.0.102 / 192.168.0.104，不能原样套用，也不能据此新增主机 |
| 容器逃逸 | 指定 writeup 的计划任务尝试失败，转为宿主 ubuntu 用户 SSH 登录，再做 CVE-2021-3493 提权；不能与原作者的成功观察拼成同一次结果 |
| PC2 路径 | 原作者演示 MS17-010；指定 writeup 使用已经取得的域凭据走 PsExec。部署时不预先执行任何一条路线 |
| PC1 网卡 | 官方服务说明称“第三层 PC1”，但官方网卡说明明确 PC1 同时接第二、第三层；按双网卡关系核对镜像 |
| 第二层出网 | 官方要求第二层 NAT，可出网；某次容器回连失败不能等同于整个第二层禁止出网 |
| DC 防火墙 | 保留初始配置；writeup 后续关闭 DC 防火墙属于验证动作，不是部署时提前完成的动作 |

## 发布包识别

官方名称：`ATT&CK实战系列-红队评估（七）`，标注大小 27 GB。

- MD5：`e16fd0f6a5104aef0dfa73460afff0e0`
- SHA1：`078ce02d01298fe40a1feb8260fde79d5fb06bc6`

原页面保存于 [official.html](E:/Desktop/ai/skill/attack-graph-validation-agent/output/hongri7/deployment/sources/official.html) 和 [original-author.html](E:/Desktop/ai/skill/attack-graph-validation-agent/output/hongri7/deployment/sources/original-author.html)。

2026-09-10 已通过发布页的正常验证码表单取得官方网盘分享：

- 分享地址：[红日 7 官方分享](https://pan.baidu.com/s/1ZGni7v0RMmQWoqBtspIUQA)
- 提取码：`u4j7`
- 原始响应：`E:/VMwareLabs/Hongri7/evidence/publisher-download-response.json`。

2026-09-10 11:25 已确认五个 ZIP 全部下载完成，总计 **29,892,757,129 字节，约 27.84 GiB**。五包均已通过 7za 解压及 CRC 检查，全部 VM 已导入并开机。每个原始 ZIP 的 SHA256、MD5、SHA1 已分别留档，见 [archive-hashes.json](E:/VMwareLabs/Hongri7/evidence/archive-hashes.json)。

当前分享分为 `Web 1.zip`、`Web 2.zip`、`PC 1.zip`、`PC 2.zip`、`Windows Server 2012 (DC).zip`，附 `WHOAMI Penetration.pdf`。五个 ZIP 均未匹配官网那一对 MD5/SHA1；官网没有说明这对摘要对应哪个文件或旧版总包，因此**不能据此判定下载损坏，也不能声称已与官网摘要完全一致**。

随包 PDF 的拓扑和网卡说明与发布页相符，直接指向同一原作者文章；但服务段写“第三层 PC 2 运行 OA”，与指定 writeup 的 PC1/OA 描述存在冲突。实机 PC2 确实存在 `C:\MYOA` 和注册的 OA 服务，但缺少多项核心配置及网页文件，不能正常启动。PC1 的 live memory 中能看到 `C:\MYOA\bin\AutoConfig.exe`、`OfficeWeb.exe`、`OfficeNginx.exe`、`php-cgi.exe`、`MySQL5_OA`、`nginx.conf` 和 `webroot\index.php` 等痕迹，因此更接近 writeup 的 PC1/OA 描述；不过 PC1 当前网络不可达，不能把它写成“HTTP 已验收”。

## 文件放在哪里

- VMware Workstation：`25.0.1.25219725`，安装路径 `D:/常用软件安装/Vmware`。
- 部署根目录：`E:/VMwareLabs/Hongri7`。
- 原始下载目录：`H:/BaiduNetdiskDownload/【启元】VulnStack-ATT&CK红队七`，五个 ZIP 和随包 PDF 保留在这里。
- 展开的虚拟机位于 `E:/VMwareLabs/Hongri7/vms/`；`E:/VMwareLabs/Hongri7/evidence/` 保存检查结果，`E:/VMwareLabs/Hongri7/backups/` 保存修改前配置。

五台虚拟机的 VMX 文件如下，VMware 中已登记这些路径：

| 虚拟机 | VMX 文件 |
| --- | --- |
| Web1 | [E:/VMwareLabs/Hongri7/vms/Web 1/Ubuntu 64 位 (Web 1).vmx](<E:/VMwareLabs/Hongri7/vms/Web 1/Ubuntu 64 位 (Web 1).vmx>) |
| Web2 | [E:/VMwareLabs/Hongri7/vms/Web 2/Ubuntu 64 位 (Web 2).vmx](<E:/VMwareLabs/Hongri7/vms/Web 2/Ubuntu 64 位 (Web 2).vmx>) |
| PC1 | [E:/VMwareLabs/Hongri7/vms/PC 1/Windows 7 x64.vmx](<E:/VMwareLabs/Hongri7/vms/PC 1/Windows 7 x64.vmx>) |
| PC2 | [E:/VMwareLabs/Hongri7/vms/PC 2/Windows 7 x64.vmx](<E:/VMwareLabs/Hongri7/vms/PC 2/Windows 7 x64.vmx>) |
| DC | [E:/VMwareLabs/Hongri7/vms/Windows Server 2012 (DC)/Windows Server 2012.vmx](<E:/VMwareLabs/Hongri7/vms/Windows Server 2012 (DC)/Windows Server 2012.vmx>) |

## 现在网络怎么连

第二层和第三层已按原说明配置完成，见 [network-setup-result.json](E:/VMwareLabs/Hongri7/evidence/network-setup-result.json)：

| 网络 | 本机配置 | 用途 |
| --- | --- | --- |
| Web1 外侧 | VMware 自动桥接实际选中了 Hyper-V Default Switch；Web1 为 `172.30.97.45/20`，网关为 `172.30.96.1` | 当前外侧实验入口，保留了镜像原有 DHCP 配置 |
| VMnet8 | NAT，`192.168.52.0/24`；宿主 `192.168.52.1`，NAT 网关 `192.168.52.2` | 第二层网络 |
| VMnet14 | Host-only，`192.168.93.0/24`；宿主 `192.168.93.1` | 第三层网络 |

外侧地址与 writeup 的 `192.168.1.*` 不同，宿主物理网卡仍是 `192.168.3.5/24`。目前验证的是宿主可以访问 Web1；尚未把单独的实验执行机接入并验收整条路径。宿主通过 VMnet 网卡能直接访问内层，后续攻击路径实验不能把这种管理连通性当作攻击者已经取得的访问能力。

VMnet1 保持 `192.168.161.0/24`。原有 VMnet8 从 `192.168.137.0/24` 改成了 `192.168.52.0/24`，这会影响共用 VMnet8 的其他虚拟机。第一次网络调整前的配置在 `E:/VMwareLabs/Hongri7/backups/network-20260910_114306/`；`network-20260910_114925/` 是修正服务配置前的中间备份，不能当作最初网络状态。

## 服务验收到哪一步

| 主体 | 地址与连接 | 已验证状态 |
| --- | --- | --- |
| Web1 | 外侧 `172.30.97.45`；内侧 `192.168.52.10` | SSH、nginx 已运行；Redis 已按原配置以 root 启动，宿主收到 `PONG`；内外侧 `:81` 均返回 Laravel 页面 |
| Web2 | `192.168.52.20` + `192.168.93.10` | 原 Docker 容器 `8e172820ac78` 已启动；Web2 的 `8000` 映射到容器 `80`，经 Web1 验证上游 HTTP 200 |
| PC1 | `192.168.52.30` + `192.168.93.20` | 两个地址的 ARP 与原网卡 MAC 一致；DC DNS 可解析 `PC1.whoamianony.org -> 192.168.93.20`；live memory 确认域身份与 OA 组件/运行痕迹；宿主与 DC 都无法 ping 或连接 OA、SMB、WinRM 等端口 |
| PC2 | `192.168.93.40`，DNS `192.168.93.30` | 已确认是 `whoamianony.org` 域成员，Netlogon 正常；存在 OA 目录及服务，但核心文件不全，不能将其标为 OA 可用 |
| DC | `192.168.93.30`，域 `whoamianony.org` | 已通过原有 WinRM 登录；DNS、NTDS、Netlogon、WinRM 均运行；三个防火墙配置均保持启用 |

大白话理解入口：浏览器先访问 **Web1 的 81 端口**，Web1 的 nginx 再转发给 **Web2 的 `192.168.52.20:8000`**，最后由 **Web2 内的 Docker 容器**返回 Laravel 页面。容器当前地址是 `172.17.0.2`，它属于 Web2，不是第六台 VMware 虚拟机。

Web1 的 80 端口代理的是原作者外部博客，本次请求超时；实验应用入口是 81。Web1 内已按随包说明执行一次 `iptables -F`，没有把此操作应用到其他虚拟机。DC 未安装 VMware Tools，因此不能依赖 VMware Tools 的来宾命令接口检查它；现有 WinRM 已可用于管理。

详细结果见 [Web1 检查](E:/VMwareLabs/Hongri7/evidence/web1-service-check.json)、[Web2 检查](E:/VMwareLabs/Hongri7/evidence/web2-service-check.json)、[DC 检查](E:/VMwareLabs/Hongri7/evidence/dc-service-check.json)。Web2 单机记录生成较早，其 HTTP 标记尚未更新；上表的 HTTP 结论来自后续 Web1 检查记录。

Windows 的补充检查见 [PC1 记录](E:/VMwareLabs/Hongri7/evidence/pc1-service-check.json)、[PC1 内存证据](E:/VMwareLabs/Hongri7/evidence/pc1-memory-observations.json) 和 [PC2 记录](E:/VMwareLabs/Hongri7/evidence/pc2-service-check.json)。PC1 的内存证据显示 `PC1.whoamianony.org`、`C:\Users\bunny`、`C:\Users\administrator.WHOAMIANONY` 以及完整 OA 组件路径，并出现 MySQL `3336` 端口 ready-for-connections、`Office_Web`、`OfficeFPM/php-cgi` 等运行痕迹；但宿主和 DC 对 PC1 的 HTTP/OA/SMB/WinRM 端口探测均失败，VMware Guest Operations 也返回 `Unknown error`，所以这里仍不能给出 live service list 或 HTTP 200 结论。PC2 缺失的文件包括 `C:\MYOA\bin\AutoConfig.exe`、`mysql5\my.ini`、`nginx\conf\nginx.conf`、`webroot\index.php` 和 `webroot\inc`。原服务的启动尝试未形成可用 OA，未用新版软件替换原环境。

发布资料中的 `bunny / Bunny2021`、`Administrator / Whoami2021` 明确列在“域用户”下，不能直接当作 PC1 的本地账户。PC1 的本地账户认证失败也不能证明相应域账户口令无效。当前 DC 的计算机对象只有 DC 和 PC2，PC1 的实际系统身份仍需确认。宿主用 Python WinRM 管理 DC 时，需要将 `192.168.93.30` 加入该进程的 `NO_PROXY`，避免本机代理干扰认证。

## 下次开机与恢复

五台虚拟机首次开机前都创建了关机快照 **`Imported-clean`**，记录在 [baseline-snapshots.json](E:/VMwareLabs/Hongri7/evidence/baseline-snapshots.json)。它用于回到导入后的初始磁盘状态，早于本轮服务启动；它不包含宿主 VMnet 配置，也不是“所有服务已经运行”的快照。

日常重新开机时先启动 DC，再启动域成员及 Web1、Web2，等待系统启动后检查应用。两个需要留意的启动项是：

- Web2 的原容器重启策略为 `no`。如容器未运行，在 Web2 内执行 `sudo service docker start`，再执行 `sudo docker start 8e172820ac78`。
- Web1 的 Redis 本次为手动启动，未添加开机自启。如 Redis 未运行，在 Web1 内执行 `sudo redis-server /etc/redis.conf --daemonize yes`。nginx 未运行时，按原说明执行 `sudo /usr/sbin/nginx -c /etc/nginx/nginx.conf`。

资料给出的 OA 启动入口为 `C:\MYOA\bin\AutoConfig.exe`；该文件在 PC2 实机中不存在，但 PC1 的内存中存在该路径和多项 OA 运行痕迹。恢复 `Imported-clean` 后，需要重新进行这些服务检查，并重新确认 Web1 外侧 DHCP 地址。若要把 PC1 标为“OA 可访问”，还需要在控制台登录后查看服务状态，或修复 PC1 网络/防火墙后取得 HTTP 响应。

[网络初始化脚本](../../scripts/configure_hongri7_network.ps1)和 [VMX 初始化脚本](../../scripts/configure_hongri7_vmx.py)只用于相关虚拟机全部关机时的部署初始化。当前五台正在运行，不要重跑它们；日常开机不需要重新配置 VMnet 或改写 VMX。

## 与攻击图的关系

攻击图的符号 host 继续保持 `web1/web2/web2_docker/pc1/pc2/dc`，同一主机的多个 IP 不拆成多个权限主体。实际接口、代理端口与 Docker 归属应作为环境映射记录，宿主管理权限和直达内层网络的能力不能预先写成攻击者事实。

本页确认的是下载、部署和已列出的服务状态，尚未复现完整攻击链。既有图模型对容器到宿主的权限变化、Windows 凭据使用协议等步骤仍有抽象差异，不能因为虚拟机已启动就宣称与指定 writeup 严格等价；详见 `data/inputs/hongri7/MODEL_NOTES.md`（本机建模笔记，不进 git）。
