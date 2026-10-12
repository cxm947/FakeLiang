---
name: session-root-via-suid
description: 会话提权（SUID + PATH 包装）— 把弱通道升成 root 通道（支撑类 · provides=session）
id: session.root_via_suid
kind: session
runs_at: position
delivers: ["session"]
inputs: {"session_ref":{"from":"runtime"},"suid_binary":{"from":"runtime","optional":true},"helper_dir":{"from":"config","optional":true},"helper_name":{"from":"config","optional":true}}
tools: ["cmd","code","http", "msf"]
---

# 会话提权（SUID + PATH 包装）— 把弱通道升成 root 通道（支撑类 · provides=session）

卡片 ID：`session.root_via_suid`。

## 何时用

已有弱权限会话，而后续节点要求更强权限；目标须存在可劫持的 SUID 程序（见 `exploit.suid_path_hijack`），且每条命令的执行环境可控制 `PATH`。执行点为该会话内的 POSIX 环境；一次请求执行一条命令的 HTTP shell 也可使用，不需要保持提权进程。会话已是 root 或本身可用 `sudo` 时不需要此包装。

标准工具机需 `python3` 及绑定会话的既有客户端；目标会话需 `sh`、`find`、`head`、`id`、`hostname`、`mkdir`、`printf`、`chmod`、`echo`。输出为沿用原入口、带 `escalate.argv` 和本次观测身份的通道描述符，不预填 `identity=root`。

**先弄清"怎么把一串 Windows 命令行送进去"**：`position_speaks=shell` 时，命令行直接交给位置自己的 shell；`position_speaks=meterpreter` 时**照旧写 `{"tool":"cmd","cmd":"…"}`**（引擎按位置包装并**把回显带回来**）。**不要用 `execute -f <shell> -a "<命令行>"` 去跑命令**：它只回一句 `Process NNNN created.`、没有命令输出，你拿不到可引用的证据，最后只能判"不满足"，而命令其实跑了（2026-10-08 实测，两格因此把已经干成的活判成没成）。

## 怎么做

优先使用现有工具完成 find → probe → verify：发现 SUID 候选，记录当前身份与主机，再通过 PATH 包装执行同一身份探针。以下为既有入口的工具调用形状；分段 marker 与外层 marker 由入口和运行层生成。

```sh
# find
find / -perm -u=s -type f 2>/dev/null | head -n 50
# probe
id -un; hostname
# verify：包装体固定，<command> 为带分段 marker 的身份探针
sh -c 'mkdir -p <helper_dir> &&
printf "%s\n" "#!/bin/sh" "$1" > <helper_dir>/<helper_name> &&
chmod +x <helper_dir>/<helper_name> &&
PATH=<helper_dir>:$PATH <suid_binary>' agv '<command>'
```

> **这些是独立动作块**：一行一个块。多步就在一次回答里用 `{"actions":[…],"gap":1}` 批量给出（引擎按顺序执行、每块各记一条回执、块间默认歇 1 秒）；**不要把几行用 `&` 拼成一条长命令** —— 一处坏、整条废，长行还会把回执尾巴弄丢。

输入定义见 `skill.json`。`session_ref` 由运行现场绑定；`suid_binary` 可显式指定，否则沿用入口的候选选择。`helper_dir` 为可写目录，`helper_name` 须与 SUID 内部调用的相对命令同名；省略时使用入口既有默认。

；当前流程按本页流程由现场给出命令。


模型可按现场选择已声明的 SUID、helper 目录与名字，并调整调用超时；当前 verify 探针固定，不增加 `command` 入参。后续节点的命令由调用方提供，经通道包装时每次重写 helper。身份读法、通道字段语义、固定流程和判据不可更改。

## 怎么判

沿用 `skill.json` 的 freshness、target、identity 三个阻断闸，`effect_rule=null`。

- freshness：核对 verify 主判调用的 `call_id`、执行状态及所携带 marker 与原始输出的对应关系。
- target：核对 `session_host` 与节点目标；容器场景沿用主机映射中的别名对齐。
- identity：沿用注册规则 `observed_privilege_at_least_node_requirement`，将本次 `session_identity` 与节点要求比较。入口只交付观测，身份是否足够由判定器按节点要求判断。

证据字段为 `call_id`、`session_identity`、`session_host`、`suid_binary`、`escalate_mode`、`identity_before`；`stdout` 保留主判原始输出，find 与 probe 各自留证。

通过：三个阻断闸均为 `pass`。不满足：观测身份低于节点要求，或任一阻断闸返回 `unsatisfied`。不确定：没有阻断闸返回 `unsatisfied`，但证据缺失、目标无法对齐或节点未给出身份要求，沿用 `uncertain`；不猜填身份。

## 异常与恢复

helper 每次使用 `>` 覆盖写入，避免重放上一条命令；这是文件副作用，既有入口没有清理或恢复步骤。已带 `escalate` 的通道会被拒绝，避免二次包装掩盖当前受信任的包装。

提权包装必须将通道 marker 放在外层，不能包进被劫持的程序；复用通道前由 `post.channel_echo` 复验身份，缓存身份不能代替本次观测。

发现输出中没有 SUID 候选时，只保留发现与提权前探针记录，如实说明没有提权成功，不生成提权通道或不存在的身份；缺少判定证据沿用 `uncertain`。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
