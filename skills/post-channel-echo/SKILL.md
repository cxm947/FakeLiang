---
name: post-channel-echo
description: 在复用已有会话前，用一次标记回声观察确认该通道此刻有可核对的回显，并记录当前身份与主机。适用：标记由任务给定，工具只回读；没有回声就是没有回声，不得推断。检索关键词：通道回显验证、通道的回显验证、会话应答验证
id: post.channel_echo
kind: validation
runs_at: position
delivers: ["evidence"]
inputs: {"session_ref":{"from":"runtime"}}
tools: ["cmd", "msf"]
---

# 既有会话的通道回显复验

## 何时用

复用已有会话前，只读核对它此刻是否有可核对回显并记录身份、主机；不建立会话，不判通道整体可用性或下游权限。
session_ref 由运行层提供，不得杜撰；缺失或无法绑定时 pending。目标取本次节点上下文；标记由任务给定，工具只回读，没有回声不推断。工具说明：skills/_tooling/posix-shell.md。
命令现场按本页方法组织，只使用执行点路径，仓库相对路径不算。

## 怎么做

命令用本卡声明的工具面交给绑定位置：`position_speaks=shell` 用位置自己的 shell；`position_speaks=meterpreter` 仍提交 `{"tool":"cmd","cmd":"…"}`，由引擎包装并回收回显。不要改用 `execute -f <shell> -a "<命令行>"`：`Process NNNN created.` 没有命令输出，不能作查询证据。

参数定义见 skill.json；按绑定的 session_ref.shell 选一个固定探针，运行期不换 shell：

```sh
id -un; hostname
```

```cmd
whoami & hostname
```

marker 由执行器按本次调用生成并包裹；保留既有边界空白处理，首行解析为 session_identity、次行为 session_host，channel 记录驱动，stdout 原样留存。
不得追加命令、增删/重排观测行或改变解析；额外环境观察须另行调用留证。探针保持 ASCII，输出按既有通道编码处理，无法可靠解析不猜填。

## 怎么判

阻断闸：freshness 核对调用与 marker；target 对照主机与节点目标；identity 用 observation_only，任一身份或主机观测在场即可通过该单闸。effect_rule=null，不再跑非阻断效果检查。
- 成功：三个阻断闸全部 pass，identity 单闸通过不等于整卡通过。
- 不满足：任一阻断闸 unsatisfied，按既有聚合规则处理；身份权限较低不自行判本卡不满足。
- 不确定：**没有其他阻断闸 unsatisfied 时，缺证据或 uncertain 就判不确定**。marker 区块缺失或为空仅有 observations 说明，不构成身份或主机观测；不能据此判成功，也不能把缺证据改判不满足。

session_identity 与 session_host 仅为观测；通过只证明本次通道复验，下游仍独立判断权限和效果。引文须来自本次调用，可核对不等于业务结论成立。
## 异常与恢复

- **本卡只执行一次固定探针；完成本次调用后即结束，不得由本卡重试或追加探针。**
- 超时或断连保留调用及部分输出，交编排按通用核对与停止契约处理；不得为了补齐回声、身份或主机再次执行命令。
- 固定探针不改远端配置，日志沿用运行层。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
