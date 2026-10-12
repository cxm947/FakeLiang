---
name: session-msf-adopt-mount
description: 文件系统搬运 → 受控端点纳管（会话生命周期 · 控制台自带端点）
id: session.msf_adopt_mount
kind: session
runs_at: position
delivers: ["session"]
inputs: {"target_host":{"from":"graph"},"launch_ref":{"from":"runtime"},"lhost":{"from":"runtime","optional":true},"lport":{"from":"config","optional":true},"shell":{"from":"config","optional":true},"payload":{"from":"config","optional":true},"payload_format":{"from":"config","optional":true},"remote_dir":{"from":"config","optional":true},"client_path":{"from":"config","optional":true},"session_wait":{"from":"config","optional":true},"poll_interval":{"from":"config","optional":true},"receiver_log":{"from":"config","optional":true},"session_ref":{"from":"runtime","optional":true},"stage_path":{"from":"config","optional":true},"launch_path":{"from":"config","optional":true},"stage_shell":{"from":"config","optional":true}}
tools: ["msf","cmd"]
---

# 文件系统搬运 → 受控端点纳管（会话生命周期 · 控制台自带端点）

实现与另外两张纳管卡共用一份（`runtime/adopt.py`），本卡只声明载体 `mount`。

## 何时用

运行够得着一个**目标看得见的文件系统**（挂载出来的宿主目录、可写共享、落在两侧的同一条路径），
并且另有一条**在目标上执行**的通道（`launch_ref`）。控制台是常驻的，端点由控制台自带。

两个前提缺一不可，而且第二个是硬前提：只有文件写进去、没有真实目标启动动作时，本卡在**写第一个字节之前**就拒绝（`UNSUPPORTED(NO_TARGET_STARTER)`）——在宿主机上启动了进程，不能算目标已纳管；挂载两侧的路径可以不同（`stage_path` 是写入端看到的那条，`launch_path` 是启动端看到的那条，缺省时两者相同）。

## 怎么做

一条纳管方法六步，三张卡共用，只有「字节怎么走」不同：

```text
量回连地址 -> 生成端点（控制台自带）-> 先架好接收器（脱离通道后台运行）
-> 把字节搬上去并启动 -> 等控制台确认新会话 -> 只读探针（getuid / sysinfo）
```

> **这些是独立动作块**：一行一个块。多步就在一次回答里用 `{"actions":[…],"gap":1}` 批量给出（引擎按顺序执行、每块各记一条回执、块间默认歇 1 秒）；**不要把几行用 `&` 拼成一条长命令** —— 一处坏、整条废，长行还会把回执尾巴弄丢。

本卡绑定的载体是 `mount`，它把两个动作分开走：

- **写入**：字节作为**文件**落到那个文件系统上（看得见它的通道可写，或执行主机直接写），
  落地路径每次调用各不相同（同名会被上一次仍在运行的端点占住，写入报 `Text file busy`）；
- **核对**：两侧路径不同时，**启动之前**由启动侧读回该文件的 sha256 与本次生成的字节比对；
  不一致就**拒绝启动**（路径看起来一样不等于就是同一个文件）；
- **启动**：由 `launch_ref` 那条通道在目标上运行同一个文件——这就是「挂载只搬字节、
  启动必须点名」的分工。

## 怎么判

三条同时成立才算纳管：**接收器日志认领了这个会话号**、**只读探针读回身份与主机**、
**端点确实跑在目标上**。文件写成功、路径存在，都不算纳管。

判据 `target_echo_present`（探针读回身份或主机才算数）。证据字段：`call_id` / `console_session_id` / `session_identity` / `session_host` / `payload_sha256` / `attribution` / `receiver_uuid` / `console_uuid`（外加 `payload_path` 与 `launch_path` 记两侧路径）。

## 异常与恢复

- 没有启动通道：**零写入**直接拒绝，不留下一个永远不会运行的文件；
- 写入成功而启动通道不可用：如实记「已落地、未启动」，不把文件当成端点；
- 接收器没架起来或等不到新会话：同另外两张卡——记日志路径、靠查回控制台找迟到登记，不盲目重发；结果交给 `assess_endpoint` 评估，候选只声称探针真的观察到的设备与能力。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
