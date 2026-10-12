---
name: session-msf-adopt-native
description: 把一条既有原生远程登录纳管成受控会话账本里的会话，交付会话引用与可用性证据。适用：先观察控制台与既有会话，再由模型选择路由；接管后必须重新观察可用性。检索关键词：原生登录纳管、受控端点纳管、原生登录
id: session.msf_adopt_native
kind: session
runs_at: position
delivers: ["evidence","session"]
inputs: {"target_host":{"from":"graph"},"lhost":{"from":"runtime","optional":true},"lport":{"from":"config","optional":true},"shell":{"from":"config","optional":true},"payload":{"from":"config","optional":true},"payload_format":{"from":"config","optional":true},"remote_dir":{"from":"config","optional":true},"client_path":{"from":"config","optional":true},"session_wait":{"from":"config","optional":true},"poll_interval":{"from":"config","optional":true},"receiver_log":{"from":"config","optional":true}}
tools: ["msf"]
---

# 原生登录 → 受控端点纳管（会话生命周期 · 控制台自带端点）

实现与其他两张纳管卡共用一份，本卡只声明载体 `native`。

## 何时用

运行已持有一条**原生远程登录**（能在这条登录的落点上执行命令），控制台是常驻的，端点由控制台自带。
本卡把端点送上去并令其登记，**只做这一条载体**，不含建立连接与通道探测。

- 路由由程序固定：运行在「连接登记成功」之后按接入类型查表命中本卡，检索永不提供它；
  这是「程序按现场选载体」，不是「模型挑一个更顺手的」。
- 回连地址优先用调用方给的 `lhost`；没给就在执行主机上量，量不出就如实拒绝——目标在跳板后面时，
  要填**跳板可达**的那个地址。
- 三条载体（原生登录 / 网页入口 / 挂载接管）共用同一条纳管方法，只有「字节怎么走」不同。
- 工具用法与坑点见 `skills/_tooling/metasploit.md`。

## 怎么做

- 输入与工具面：图给 `target_host`；运行侧给 `lhost`（**不得杜撰**）；模型现场决定的输入：无；工具面 `shell`；工具用法与坑点见正文。

一条纳管方法六步，三张卡共用，只有「字节怎么走」不同：

```text
量回连地址 -> 生成端点（控制台自带）-> 先架好接收器（脱离通道后台运行）
-> 把字节搬上去并启动 -> 等控制台确认新会话 -> 只读探针（getuid / sysinfo）
```

> **这些是独立动作块**：一行一个块。多步就在一次回答里用 `{"actions":[…],"gap":1}` 批量给出（引擎按顺序执行、每块各记一条回执、块间默认歇 1 秒）；**不要把几行用 `&` 拼成一条长命令** —— 一处坏、整条废，长行还会把回执尾巴弄丢。

本卡绑定的载体是 `native`：字节就是几条命令，跑在已有远程登录的落点上（即目标本身）。

- 端点：生成工具在执行主机上生成，字节的 sha256 随证据走；
- **落地路径每次调用各不相同**（带本次调用的短号）：同名路径会被上一次仍在运行的端点占住，
  写入报「文本文件忙」，随后启动的其实是旧文件（实测踩到过）。打包失败就**拒绝启动**；
- 搬运：base64 分片写入 → 解码 → 给执行位 → 脱离启动（POSIX 壳）；cmd 壳走证书工具解码加后台启动；
- 接收器：控制台的 handler 模块，保持「一次纳管不把控制台的下一次接收关掉」；**先等它在自己的日志里
  自报家门**才允许搬字节，端点登记后**立刻退休**这个接收器，不留一个能接住「别人回连」的端口。

## 怎么判

三条同时成立才算纳管：**接收器日志认领了这个会话号**、**只读探针读回身份与主机**、
**端点确实跑在目标上**。启动命令返回成功、文件落地、进程存在，都不算纳管。

判据 `target_echo_present`：探针读回身份或主机才算数，读不到就是没有证据。证据字段：
`call_id`、`console_session_id`、`session_identity`、`session_host`、`payload_sha256`、`attribution`、
`receiver_uuid`、`console_uuid`、`receiver_retired`。

`attribution` 是两路核对的结果，不是一句话：`receiver_log`＝本次调用的接收器日志认领了它；
`console_uuid`＝控制台自己的记录把该会话指向本次调用铸的关联值（只对**没**留下旧接收器的控制台成立）；
`observed_new_sid`＝新会话出现了但控制台把它记在**别的**模块运行名下——这时两个关联值都写进证据，
并附一句说明为什么不认领；`staging_failed` / `receiver_not_ready` / `digest_mismatch` 分别表示
「没打成包」/「接收器没就绪」/「启动侧读到的文件不是我们写的那份」。

会话可用性由**接管后的只读探针重新观察**得到，不由接管动作本身推出。

## 异常与恢复

- 接收器没架起来：如实记 `arm` 的退出状态与日志路径，**不盲目重发搬运**；
- 等不到新会话：记「未登记」并保留日志路径；迟到的登记靠**查回控制台**发现，不是重跑一次；
- 登录通道不足以落地或启动：如实返回不支持，**不降级为「继续借用原连接」**；结果交给端点评估，通过才进台账：候选只说证据里真的有的能力；
- 纳管过程会在目标上留下端点文件与进程：这是真实的副作用，按本卡的资源与义务账本记录，
  需要留存还是清理由声明决定，不默认「反正跑完了」。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
