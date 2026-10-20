---
name: container-podman-inspect
description: 使用 Podman 元数据确认容器存在及宿主、用户存储的对应关系。
metadata:
  predicates:
  - isDocker
  platforms:
  - linux
  keywords:
  - isDocker
  - podman
  - container
  - relation
  - exists
  - 容器
  - 关系
  categories:
  - container-relation
  aliases:
  - podman
  - 容器
  - container
  parameters:
  - host
  - docker
  when:
    container: podman
  requires: []
  excludes:
  - docker
---

# Podman 容器关系检查

## 适用场景

需要预期宿主、容器名称或标识、必要的名称映射，以及已知运行时和所属用户。
当任务要求检查容器存在或归属、且对象由 Podman 管理时使用。
若条件确实要求 Docker 引擎，不得用 Podman 结果替代；选其他技能。

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


1. 确认 Podman 查询范围对应声明宿主和用户存储。
2. 使用明确映射的容器名/ID，不按部分名称猜测。
3. 查询容器元数据，保留 ID、名称、状态及已知宿主对应关系。
4. 区分容器不存在与查错用户存储，尤其是 rootless Podman。
5. 对照声明关系返回结果，不以软件安装状态代替容器存在。

podman container inspect --format '{"id":{{json .Id}},"name":{{json .Name}},"status":{{json .State.Status}}}' example-container

替换当前映射；取必要的 Id、Name、State 字段，完整环境变量不属于检查证据。
实际运行用户由上下文确定，不擅自切换用户或加 sudo。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示预算内没有拿到可确认的结果，那是**结果未知**，不是通道失效，也不是命题不成立。

本步判 `通过` 需要出现上面判读表里那一行要求的证据；出现明确反证判 `不通过`；工具缺失、参数错误、输出截断、通道中断一律 `未知`。

**停止边界**：本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。


## 完成依据

- 对应宿主和用户存储返回明确匹配的容器：通过。
- 已确认查询范围且可靠返回不存在：不通过。
- 不清楚条件是否允许 Podman、用户存储不明、权限错误或映射缺失：未知。
- 停止的容器仍可满足存在条件，不附加运行要求。

未知时补齐元数据或纠正查询范围，不创建/启动容器，也不把另一个用户看不到容器判为不存在。

## 失败条件

- 检查工具不存在、参数错误、输出被截断或执行通道中断 → 未知；这些都不是命题不成立的反证。
- 本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
