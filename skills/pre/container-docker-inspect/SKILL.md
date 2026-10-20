---
name: container-docker-inspect
description: 通过 Docker 元数据确认容器存在、身份及其与宿主的对应关系。
metadata:
  predicates:
  - isDocker
  platforms:
  - linux
  keywords:
  - isDocker
  - docker
  - container
  - relation
  - exists
  - 容器
  - 关系
  categories:
  - container-relation
  aliases:
  - docker
  - 容器
  - container
  parameters:
  - host
  - docker
  when:
    container: docker
  requires: []
  excludes:
  - podman
---

# Docker 容器关系检查

## 适用场景

需要预期宿主、容器名称或标识，以及必要的逻辑名称映射。
**优先用容器内视角：绑定会话就在容器上时（`execution.host == docker`），不需要宿主 Docker daemon。**
只有绑定在宿主上、要查宿主 daemon 时，才需要能查询与预期宿主对应的 Docker daemon。
本方法只查身份、存在性及宿主对应关系，不查可利用性或容器逃逸。

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

**优先用容器内视角**：绑定主机就是事实里的容器（例如 `<host>_docker` 这类容器标识）时，不需要宿主 Docker daemon：

**判定“绑定主机就是容器”看 `context.execution.host` 与事实的 `docker` 参数是否相等**；不要因为事实的 `host`
是宿主名就认定缺少访问。两者相等时直接在该会话执行，不需要另建到宿主的连接。

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"hostname; test -f /.dockerenv && echo DOCKER_ENV=present || echo DOCKER_ENV=absent; head -20 /proc/1/cgroup"}}
```

`DOCKER_ENV=present` 或 `/proc/1/cgroup` 出现 `docker`/`containerd` 即证明本机是容器；hostname/地址再与事实里的容器名对应。
只有绑定在**宿主**上、且确实能访问 Docker daemon 时，才用下面的 `docker container inspect`。


1. 确认查询上下文对应声明宿主，不凭客户端本机名称推断。
2. 将任务中的逻辑名称解析到明确的容器名称/ID；映射缺失不猜测匹配。
3. 用 container inspect 查询一个明确对象，避免同名镜像或卷混入。
4. 记录完整容器 ID、名称和状态，核对结果对象与映射一致。
5. 依据存在关系作结论，不把“已安装 Docker”当容器存在。

docker context show
    docker container inspect --format '{"id":{{json .Id}},"name":{{json .Name}},"status":{{json .State.Status}}}' example-container

example-container 是示例，应替换已知映射。保留 Id、Name、State 等必要字段即可，
不要把完整容器环境变量或挂载内的内容作为模型证据，避免带入无关敏感信息。
context show 仅帮助识别客户端配置，仍须与运行上下文的宿主映射核对。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；`cmd`/`code` 落在已登记会话上时字段是 `output` 与 `operation_confirmed`。`timed_out=true` 或 `effect_known=false` 表示预算内没有拿到可确认的结果，那是**结果未知**，不是通道失效，也不是命题不成立。

本步判 `通过` 需要出现上面判读表里那一行要求的证据；出现明确反证判 `不通过`；工具缺失、参数错误、输出截断、通道中断一律 `未知`。

**停止边界**：本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。


## 完成依据

| 证据 | 结论 |
|---|---|
| 容器内 `/.dockerenv` 存在，或 cgroup 显示 docker/containerd，且 hostname/地址对应 | 通过 |
| 对应宿主的 daemon 返回匹配容器身份 | 通过 |
| 宿主和查询权限已确认，明确 No such container | 不通过 |
| daemon 不可达、无权限、映射缺失、宿主对应不明，且容器内标记也取不到 | 未知 |

停止状态的容器仍然存在，不额外要求 running，除非本条条件明确要求。
未知时修正查询参数或补充对应关系，不创建、启动、进入或删除容器。

## 失败条件

- 检查工具不存在、参数错误、输出被截断或执行通道中断 → 未知；这些都不是命题不成立的反证。
- 本卡一次调用只做本页方法里的一次检查；不由本卡重试、追加动作、换目标或扩大范围；首选实现不可用时走本页声明的等价路径，路径耗尽就记未知并写明具体原因。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
