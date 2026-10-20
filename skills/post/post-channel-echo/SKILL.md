---
name: post-channel-echo
description: 在复用已有会话前，用一次标记回声观察确认该通道此刻有可核对的回显，并记录当前身份与主机。适用：标记由任务给定，工具只回读；没有回声就是没有回声，不得推断。
metadata:
  predicates:
  - execCode
  platforms:
  - any
  keywords:
  - 通道回显验证
  - 通道的回显验证
  - 会话应答验证
  - post.channel_echo
  - validation
  - position
  - cmd
  - msf
  - post
  - channel
  - echo
  resources: []
  categories:
  - channel-liveness
  aliases:
  - 通道回显
  - echo
  - nonce
  - channel
  parameters:
  - session_ref
  when:
    scope: channel
  requires: []
  excludes: []
---

## 适用场景

复用已有会话前，只读核对它此刻是否有可核对回显并记录身份、主机；不建立会话，不判通道整体可用性或下游权限。
session_ref 由运行层提供，不得杜撰；缺失或无法绑定时 pending。目标取本次节点上下文；标记由任务给定，工具只回读，没有回声不推断。工具说明：skills/_tooling/posix-shell.md。
命令现场按本页方法组织，只使用执行点路径，仓库相对路径不算。

## 参数

- 输入 `session_ref`：来自 runtime
- 交付：evidence
- 执行位置：position
- 可用工具：cmd、msf

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"bash","command":"<本页方法里那一条探针>"}}
```


命令用本卡声明的工具面交给**本步绑定的执行面**，请求对象是四项形状（见下面那一条）；不要用只回一句 `Process NNNN created.` 的形式——它没有可引用的命令输出。

参数定义见 skill.json；按绑定的 session_ref.shell 选一个固定探针，运行期不换 shell：

```sh
echo AGV_POST_NONCE=<本次 nonce>; id -un; hostname
```

```cmd
echo AGV_POST_NONCE=<本次 nonce>; whoami; hostname
```

**选哪一条看载体会话自己的平台**（`carrier_export.carrier.platform`），不是看节点执行面：节点执行面可能在另一台机器上（真机第 53 轮用 Linux 形状去打 Windows 载体，被观测文法当场拒绝）。上面的形状就是文法接受的全部内容：`echo AGV_POST_NONCE=<nonce>` 打头、两条身份语句各一次、用 `; ` 连接，**不追加别的命令**。

marker 由执行器按本次调用生成并包裹；保留既有边界空白处理，首行解析为 session_identity、次行为 session_host，channel 记录驱动，stdout 原样留存。
不得追加命令、增删/重排观测行或改变解析；额外环境观察须另行调用留证。探针保持 ASCII，输出按既有通道编码处理，无法可靠解析不猜填。

回执里 `stdout` 是执行面回显原文、`return_code` 是命令终态；复核模式下没有本次观测，材料是已保存的回执。nonce 必须由目标侧执行后返回，只出现在请求里不算观测。

本节点判 `通过` 需要证据支持本节点 outputs 里那条事实；明确反证判 `不通过`；证据不足、目标绑不上、观测未取回一律 `未知`。

**停止边界**：本卡一次调用只做本页方法里的一次观测或一次复核；不由本卡重试、追加探针或改换判据。


## 完成依据

阻断闸：freshness 核对调用与 marker；target 对照主机与节点目标；identity 用 observation_only，任一身份或主机观测在场即可通过该单闸。effect_rule=null，不再跑非阻断效果检查。
- 成功：三个阻断闸全部 pass，identity 单闸通过不等于整卡通过。
- 不满足：任一阻断闸 unsatisfied，按既有聚合规则处理；身份权限较低不自行判本卡不满足。
- 不确定：**没有其他阻断闸 unsatisfied 时，缺证据或 uncertain 就判不确定**。marker 区块缺失或为空仅有 observations 说明，不构成身份或主机观测；不能据此判成功，也不能把缺证据改判不满足。

session_identity 与 session_host 仅为观测；通过只证明本次通道复验，下游仍独立判断权限和效果。引文须来自本次调用，可核对不等于业务结论成立。

## 失败条件

- **本卡只执行一次固定探针；完成本次调用后即结束，不得由本卡重试或追加探针。**
- 超时或断连保留调用及部分输出，交编排按通用核对与停止契约处理；不得为了补齐回声、身份或主机再次执行命令。
- 固定探针不改远端配置，日志沿用运行层。

[共享执行规则](../../src/skills/templates/execution_rules.txt)

**停止边界**：本卡一次调用只做本页方法里的一次观测或一次复核；不由本卡重试、追加探针或改换判据。
