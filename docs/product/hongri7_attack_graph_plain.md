# 红日 7 攻击图怎么读

这份说明的目标不是逐字复刻 writeup 的每条命令，而是把红日 7 的关键攻击路径压进可推理的 MulVAL 谓词里。冻结规则基线保持 `rules5.P` 不动，v2 规则单独表达 SMB/445 上的 Windows 凭据型远程执行。它回答三个建模问题：谁是执行主体，Docker 怎么归属，多网卡主机怎么表示。

> 路径说明：本文引用的 `data/inputs/hongri7/` 文件是本机靶场资料（不进 git）；`output/hongri7/` 下的图与报告是可重跑产物。

## 最终口径

冻结规则主图用 `data/inputs/hongri7/Hongri7.P`（本机资料，不进 git），对应 [Hongri7.action_graph.pdf](../../output/hongri7/pdf/Hongri7.action_graph.pdf)。这是更诚实的 rules5 基线：Windows 横向只写实际 SMB 服务，不用假 WinRM 分类凑闭合。它能推出 `web1 root`、`web2 root`、`pc1 system` 和 `dc disableFirewall`，但推不出 `pc2 system`、`dc system`。

兼容演示图用 `data/inputs/hongri7/Hongri7_compat.P`（同上），对应 [Hongri7_compat.action_graph.pdf](../../output/hongri7/pdf/Hongri7_compat.action_graph.pdf)。它额外加了两条 `networkServiceInfo(..., winrm, tcp, 445, system)`，本质是把旧规则里的 `winrm` 当成“Windows 凭据型远程执行”分类，用实际 SMB 445 端点承载。这个版本能闭合五台主机最终目标，但不能声称靶场真实开了 WinRM，也不能直接指导执行器调用 WinRM 客户端。

v2 建模图用 `data/inputs/hongri7/Hongri7_v2.P` 和 `data/inputs/hongri7/rules5_v2.P`（同上）。它不再伪造 `winrm@445`，而是用真实 `smb/tcp/445` 加 `ttpExists(..., windowsCredentialRemoteExecution, lateralMovement)` 表达 PC2/DC 横向。投影器已经支持这个新 case；正式 JSON/PDF 还要等 Docker/MulVAL 恢复后生成。

辅助图是 [Hongri7.topology.png](../../output/hongri7/Hongri7.topology.png)。它只讲网络接口和容器归属，不是攻击依赖图。

## 主体与地址

攻击图里的 `host` 表示权限归属和执行位置，不表示单个 IP。红日 7 里 `web1`、`web2`、`pc1` 都有多个网卡，如果按 IP 拆成多个 host，会制造假的重复攻陷问题：拿到 `pc1@192.168.52.30` 和拿到 `pc1@192.168.93.20` 在权限上其实是同一台 Windows。

所以图里使用稳定主体：

| 主体 | 含义 |
| --- | --- |
| `web1` | DMZ Ubuntu 18，Redis/nginx 入口 |
| `web2` | Ubuntu 14 宿主机 |
| `web2_docker` | Web2 上的 Laravel 容器 |
| `pc1` | 双网卡 Windows 7，通达 OA 位于这里 |
| `pc2` | 第三层 Windows 7 |
| `dc` | 域控 |

IP、端口、代理入口放在 `data/inputs/hongri7/assets.json`（同上）。例如本机部署观测到的 Web 入口是 `172.30.97.45:81 -> 192.168.52.20:8000 -> 172.17.0.2:80`，但攻击图里仍写：

```prolog
hacl(attacker, web2_docker, http, 81).
networkServiceInfo(web2_docker, laravel, http, 81, www_data).
```

这里的 `81` 是“攻击者看到的发布入口”，不是容器内部监听端口。

## Docker

Docker 容器是单独主体，因为容器里的 `www_data/root` 和宿主机上的 `ubuntu/root` 不是同一件事。归属关系用原规则已有的谓词：

```prolog
isDocker(web2, web2_docker).
```

第一个参数是宿主，第二个参数是容器。这样图里可以表达两层权限：

| 事实 | 含义 |
| --- | --- |
| `execCode(web2_docker,www_data)` | Laravel RCE 后先在容器里执行 |
| `execCode(web2_docker,root)` | 容器内提权到 root |
| `execCode(web2,root)` | 通过容器逃逸获得宿主 root |

限制也在这里：原 writeup 的细链是“容器文件写入/计划任务尝试、ubuntu 登录、CVE-2021-3493 内核提权”。冻结规则里没有这些中间谓词，所以当前主图只能把它压成 `container_escape` 一步，不能声称等价复刻了每个中间阶段。

## 主图动作

主图 `Hongri7.P` 生成 10 个 AND 动作，可以按这个意思读：

| 动作 | 图中 case | 大白话 |
| --- | --- | --- |
| 访问 Redis | `direct_network_access` | 攻击者能访问 Web1 的 Redis |
| 利用 Redis | `public_application_initial` | Web1 上获得 root 级执行能力 |
| 访问 Laravel | `direct_network_access` | 攻击者通过 Web1 发布入口访问 Laravel |
| 利用 Laravel | `public_application_initial` | 在 `web2_docker` 获得 `www_data` |
| 容器内提权 | `path_hijack_root` | 在容器内获得 root |
| 容器到宿主 | `container_escape` | 从 `web2_docker` 推到 `web2 root` |
| 从 Web1 打 PC1 OA | `command_interpreter` | Web1 已取得权限后访问 PC1 OA，获得 `pc1 system` |
| 从 Web2 打 PC1 OA | `command_interpreter` | Web2 宿主已取得权限后访问 PC1 OA，获得 `pc1 system` |
| 抓域凭据 | `lsass_system` | 在 PC1 上取得域管理员凭据符号 |
| 关闭 DC 防火墙 | `disable_firewall` | 从 PC1 对 DC 做远程防护关闭动作 |

PC1 OA 在 writeup 中是 `192.168.52.30:8080`，本机部署中 PC1 内存也能看到完整 OA 组件和运行痕迹，但当前 PC1 网络不可达，所以部署证据只能支持“PC1/OA 存在”，不能支持“本机 HTTP 200 已验收”。

## 为什么主图不闭合 PC2/DC

普通版事实里写的是实际服务：

```prolog
networkServiceInfo(pc2, smb, tcp, 445, system).
networkServiceInfo(dc, smb, tcp, 445, system).
```

但 `rules5.P` 里能做凭据型 Windows 横向的规则绑定在 `winrm` 这个服务名上。它没有一条“从 PC1 system + 域管理员凭据 + SMB 445 -> PC2/DC system”的精确规则。因此普通版不能推出 PC2/DC system，这不是事实没写够，而是冻结规则表达不了 PsExec/SMB 语义。

兼容版加的两条 `winrm` 分类事实就是为了演示闭合：

```prolog
networkServiceInfo(pc2, winrm, tcp, 445, system).
networkServiceInfo(dc, winrm, tcp, 445, system).
```

这两条应该看成“旧规则兼容标签”，不是服务扫描结果。

## 我建议怎么定

第一版论文/系统演示可以把 `Hongri7.P` 定为 frozen-rule 基线，把 `Hongri7_compat.P` 放进附录或对照实验，把 `Hongri7_v2.P` 作为规则改进后的推荐主线。这样三者关系很清楚：基线暴露 rules5 的语义缺口，兼容版展示旧规则怎样被借壳闭合，v2 版给出更干净的长期方案。

这正好服务你的研究点：把 writeup 里的长期记忆式攻击路径，转成可重复推理的攻击图。不能推出来的地方不是失败，反而是模型发现的语义缺口。
