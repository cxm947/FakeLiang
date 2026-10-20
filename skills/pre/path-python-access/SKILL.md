---
name: path-python-access
description: 使用 Python 在 POSIX 文件系统上区分路径缺失、权限错误及有效写权限。
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
  - python
  - 路径存在
  - 可写
  resources:
  - scripts/check_path.py
  categories:
  - path-access
  aliases:
  - 路径
  - 可写
  - python
  - os.access
  parameters:
  - host
  - path
  - perm
  when:
    platform: linux
  requires: []
  excludes: []
---

# Python 路径写权限检查

## 适用场景

需要目标路径、预期身份和写访问要求。方法要求检查环境有 Python 3，
支持有效身份访问检查，并能看到被检查路径。
运行在哪台机器、如何传入脚本由执行层解决，本技能不假定脚本已经部署。

## 参数

- 输入：本页「适用场景」声明的目标、地址/端口、平台与执行面；由运行层给出，**不得杜撰**
- 交付：evidence
- 执行位置：position
- 可用工具：cmd、code（脚本类步骤用 code + python3，命令类步骤用 cmd）


## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

```text
{"tool":"run_script","target":"session","arguments":{"interpreter":"python3","body":"<本卡方法里那段脚本>"}}
```


1. 使用 [只读路径检查脚本](scripts/check_path.py)，将原路径作为一个参数传入。
2. 脚本记录有效 UID 和用户名，再用 stat 区分存在、缺失、访问拒绝。
3. 对存在路径调用有效身份模式的 os.access，保留 writable 布尔值。
4. 核对脚本返回的身份是否符合预期身份，再判断条件。

脚本可通过执行层提供源码或已部署路径；下面只展示参数约定：

    python3 check_path.py --path '/srv/example file'

成功查询可能返回：

    {"path":"/srv/example file","identity":"worker","uid":1000,"exists":true,"writable":true,"error":null}

error 字段不为空时，该项查询不完整。脚本退出零仅表示完成输出，不代表路径条件通过。
用户名示例仅说明字段，不代表实际运行身份。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示预算内没有拿到可确认的结果，那是**结果未知**，不是通道失效，也不是命题不成立。

本步判 `通过` 需要出现上面判读表里那一行要求的证据；出现明确反证判 `不通过`；工具缺失、参数错误、输出截断、通道中断一律 `未知`。

**停止边界**：本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。


## 完成依据

- 身份正确，exists=true 且 writable=true：通过。
- 身份正确，可靠查询 exists=false，或存在但 writable=false：不通过。
- PermissionError、不支持有效身份模式、身份不符合、运行环境缺失：未知。
- 符号链接跟随到最终对象；失效链接不能证明目标路径存在。
- 不修改文件、权限或属主，不执行试写。

未知时依据 error 和实际身份调整检查方法，不把权限拒绝转换成“不存在”。

## 失败条件

- 检查工具不存在、参数错误、输出被截断或执行通道中断 → 未知；这些都不是命题不成立的反证。
- 本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
