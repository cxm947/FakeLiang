---
name: session-msf-adopt-web
description: 网页命令入口 → 受控端点纳管（会话生命周期 · 控制台自带端点）
id: session.msf_adopt_web
kind: session
runs_at: position
delivers: ["session"]
inputs: {"target_host":{"from":"graph"},"session_ref":{"from":"runtime"},"lhost":{"from":"runtime","optional":true},"lport":{"from":"config","optional":true},"shell":{"from":"config","optional":true},"payload":{"from":"config","optional":true},"payload_format":{"from":"config","optional":true},"remote_dir":{"from":"config","optional":true},"client_path":{"from":"config","optional":true},"session_wait":{"from":"config","optional":true},"poll_interval":{"from":"config","optional":true},"receiver_log":{"from":"config","optional":true}}
tools: ["msf"]
---

# 网页命令入口 → 受控端点纳管（会话生命周期 · 控制台自带端点）

实现与另外两张纳管卡共用一份（`runtime/adopt.py`），本卡只声明载体 `web`。

## 何时用

运行已持有一条**网页命令入口**（一次请求执行一条命令的一类通道），而这条入口落在的**真实主机**
就是端点要落上去的目标。控制台是常驻的，端点由控制台自带。本卡只做这一条载体，不含建立连接与探测。

入口的连接状态必须由调用方给全（驱动、地址、路径、客户端、模式）：壳是一个**地方**，不是一个本地
进程，谁也查不出来。回连地址优先用 `lhost`；没给就在执行主机上量，量不出就如实拒绝。

## 怎么做

一条纳管方法六步，三张卡共用，只有「字节怎么走」不同：

```text
量回连地址 -> 生成端点（控制台自带）-> 先架好接收器（脱离通道后台运行）
-> 把字节搬上去并启动 -> 等控制台确认新会话 -> 只读探针（getuid / sysinfo）
```

> **这些是独立动作块**：一行一个块。多步就在一次回答里用 `{"actions":[…],"gap":1}` 批量给出（引擎按顺序执行、每块各记一条回执、块间默认歇 1 秒）；**不要把几行用 `&` 拼成一条长命令** —— 一处坏、整条废，长行还会把回执尾巴弄丢。

本卡绑定的载体是 `web`：每一段字节都是一次请求，所以搬运是有预算的——

- 端点按 base64 分片写入（首片覆盖、后续追加），最后一段才解码并给执行位；半截文件永远不可执行；
  落地路径每次调用各不相同，打包失败就**拒绝启动**；
- 每段都是一条单行命令，因为这类入口一次只收一条命令，多行命令会被截断；
- 通道的标记纪律照旧：入海口回显里的标记块才是证据，请求发出去不等于命令跑了。

## 怎么判

三条同时成立才算纳管：**接收器日志认领了这个会话号**、**只读探针读回身份与主机**、
**端点确实跑在目标上**。请求返回 200、文件落地、进程存在，都不算纳管。

判据 `target_echo_present`：探针读回身份或主机才算数。证据字段：`call_id` /
`console_session_id` / `session_identity` / `session_host` / `payload_sha256` /
`attribution` / `receiver_uuid` / `console_uuid`。归属按两路核对如实记录：
`receiver_log`＝本次接收器认领；`console_uuid`＝控制台自己指向本次调用铸的关联值；
`observed_new_sid`＝新会话出现但控制台记在别的模块运行名下（两个关联值都留档、并说明不认领的理由）。

## 异常与恢复

- 入口在一次请求里改不了文件（只读、配额、超长被截）：如实记在哪一片失败，**不假装端点已上线**；
- 接收器没架起来：记退出状态与日志路径，**不盲目重发搬运**；
- 等不到新会话：记「未登记」并保留日志路径；迟到的登记靠**查回控制台**发现，不是重跑一次；
- 结果交给 `assess_endpoint` 评估，通过才进台账；启动命令的退出码从来不是证据。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
