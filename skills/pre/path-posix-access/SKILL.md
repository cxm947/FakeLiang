---
name: path-posix-access
description: 使用 POSIX 路径测试核验指定路径存在且要求身份可写，适用于文件和目录。
metadata:
  predicates:
  - pathExists
  platforms:
  - linux
  keywords:
  - pathExists
  - path
  - exists
  - writable
  - write
  - 路径存在
  - 可写
  categories:
  - path-access
  aliases:
  - 路径
  - 可写
  - stat
  - test -w
  parameters:
  - host
  - path
  - perm
  when:
    platform: linux
  requires: []
  excludes: []
---

# POSIX 路径写权限检查

## 适用场景

需要目标路径、要求的写访问能力、预期身份及实际观察身份。
检查环境必须对应被检查的文件系统，并已具备要求身份；连接、容器或会话的选择由运行层提供。
不通过技能自行改变身份或获取新访问。

## 参数

- 输入：本页「适用场景」声明的目标、地址/端口、平台与执行面；由运行层给出，**不得杜撰**
- 交付：evidence
- 执行位置：position
- 可用工具：cmd、code（脚本类步骤用 code + python3，命令类步骤用 cmd）


## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"<本卡方法里那一条命令行>"}}
```


1. 核对实际身份与预期身份，保留用户和组信息。
2. 对原始路径进行完整引用，不展开通配符，不拼接未经引用的 shell 内容。
3. 分别检查存在性与**要求身份**的有效可写性，保留两项结果：
   - 当前身份 == `perm`：`test -w` 可以回答；
   - 当前身份 != `perm`（例如当前 www-data、要求 root）：`test -w` 只代表当前身份，**不能**回答 root 是否可写；改用 `stat -c '%A %U %G %a %n'` 读 mode/owner/group，按 `perm` 对应的 owner/group/other 写位判断。目录还要求执行位；有 ACL 时用 `getfacl` 补充。
4. 若路径不可见，区分确实不存在与上级目录不可访问；无法区分时保持未知。
5. 文件与目录使用相同条件，不额外要求 SUID、所有权或固定路径类型。

以下是检查环境内的 POSIX shell 片段；path 必须由参数传入：

    path='<path>'; perm='<perm>'; me=$(id -un)
    stat -c '%A %U %G %a %n' "$path" 2>&1
    mode=$(stat -c '%A' "$path"); owner=$(stat -c '%U' "$path"); group=$(stat -c '%G' "$path")
    owner_w=$(printf '%s' "$mode" | cut -c3)
    group_w=$(printf '%s' "$mode" | cut -c6)
    other_w=$(printf '%s' "$mode" | cut -c9)
    if [ "$owner" = "$perm" ]; then perm_w=$owner_w
    elif [ "$group" = "$perm" ]; then perm_w=$group_w
    else perm_w=$other_w
    fi
    [ "$perm_w" = "w" ] && echo perm_writable=true || echo perm_writable=false
    echo "mode_check_for=$perm"

`test -w` 查询当前有效身份的访问能力，不创建文件；它不能代替 `perm` 身份的可写性。
**`perm=root` 且 `stat` 显示 owner=root 时，只看 owner 的 `w` 位（`-rw...`/`-rws...`）：有 `w` 就是 root 可写，
不要再以当前 www-data 跑 `test -w` 来否定 root 的写权限。** 当前身份的 `test -w` 只回答当前身份，不是本 LEAF 的反证。
容器里可能没有 python3：优先用上面的 `sh` + `stat` 片段，不要先试 `code/python3`。
判据以 `perm_writable=true/false` 为准；`writable_current=false` 不是反证。
exists_or_visibility=false 不能独立证明路径缺失；先确认上级目录可访问，
或用能明确区分 ENOENT 与 EACCES 的路径查询方法。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示预算内没有拿到可确认的结果，那是**结果未知**，不是通道失效，也不是命题不成立。

本步判 `通过` 需要出现上面判读表里那一行要求的证据；出现明确反证判 `不通过`；工具缺失、参数错误、输出截断、通道中断一律 `未知`。

**停止边界**：本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。


## 完成依据

| 观察结果 | 结论 |
|---|---|
| 身份符合要求，路径存在且按 `perm` 的 mode/ACL 可写 | 通过 |
| 可靠查询明确路径不存在，或存在但要求身份不可写 | 不通过 |
| 身份不符、路径可见性不明、查询权限不足或输出不完整 | 未知 |

root 所有权、SUID 位和“脚本执行成功”都不能代替上述两项结果；当前身份的 `test -w` 也不能代替 `perm=root` 的可写性。
未知时补查身份或路径查询错误，不创建试写文件、不修改权限、不切换账号。
可写权限检查不承诺磁盘空间、配额或随后实际写入一定成功。

## 失败条件

- 检查工具不存在、参数错误、输出被截断或执行通道中断 → 未知；这些都不是命题不成立的反证。
- 本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
