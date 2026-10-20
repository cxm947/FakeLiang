---
name: path-windows-access
description: 核验 Windows 指定路径存在及指定身份的有效写权限，区分 ACL 声明与有效访问。
metadata:
  predicates:
  - pathExists
  platforms:
  - windows
  keywords:
  - pathExists
  - path
  - exists
  - writable
  - write
  - windows
  - acl
  - 路径存在
  - 可写
  resources:
  - references/effective-access.md
  categories:
  - path-access
  aliases:
  - 路径
  - 可写
  - Test-Path
  - ACL
  parameters:
  - host
  - path
  - perm
  when:
    platform: windows
  requires: []
  excludes: []
---

# Windows 路径写权限检查

## 适用场景

需要目标路径、预期身份、写访问要求和实际观察身份。
本方法使用 Windows 路径查询及有效访问证据，执行载体由运行层提供。
只有身份和对象对应正确时，结果才能回答本次检查要求。

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


1. 记录当前身份及影响权限的组/令牌信息。
2. 使用 LiteralPath 语义查询原路径，避免通配符被展开。
3. 区分对象不存在、访问被拒绝和其他查询错误。
4. 查询指定身份的有效写权限，按 [有效权限说明](references/effective-access.md) 解释。
5. 将路径存在、实际身份和有效权限证据一起交给结果判断。

PowerShell 中通过参数传入 Path，不把路径当作表达式执行：

    param([string]$Path)
    whoami
    Get-Item -LiteralPath $Path -Force -ErrorAction Stop |
        Select-Object FullName, PSIsContainer, Attributes
    Get-Acl -LiteralPath $Path -ErrorAction Stop |
        Select-Object Owner, AccessToString

这些查询用于存在性及权限上下文，Get-Acl 本身不计算完整有效访问。
不能直接把 AccessToString 中的某条 Allow 当作最终可写结果。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示预算内没有拿到可确认的结果，那是**结果未知**，不是通道失效，也不是命题不成立。

本步判 `通过` 需要出现上面判读表里那一行要求的证据；出现明确反证判 `不通过`；工具缺失、参数错误、输出截断、通道中断一律 `未知`。

**停止边界**：本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。


## 完成依据

| 证据 | 结论 |
|---|---|
| 路径存在，要求身份具有对应对象类型的有效写权限 | 通过 |
| 可靠确认路径不存在，或有效权限明确不允许写入 | 不通过 |
| 只有 ACL 文本、身份不明、访问拒绝、查询不完整 | 未知 |

不因用户是管理员就直接通过，不通过创建文件或修改 ACL 来验证。
未知时补充有效权限证据；缺少相应方法就说明缺口，不猜测结论。

## 失败条件

- 检查工具不存在、参数错误、输出被截断或执行通道中断 → 未知；这些都不是命题不成立的反证。
- 本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
