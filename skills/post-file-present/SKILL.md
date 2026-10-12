---
name: post-file-present
description: 在指定位置确认一个文件是否真实存在，并交付带来源与时刻的观测（路径、大小、可选摘要）。适用：就地优先；经既有会话读取时须记录该会话引用。检索关键词：产物落盘核验、落地文件存在性检查、文件落盘确认
id: post.file_present
kind: validation
runs_at: position
delivers: ["evidence"]
inputs: {"path":{"from":"runtime"},"session_ref":{"from":"runtime"},"expect_sha256":{"from":"runtime","optional":true}}
tools: ["cmd","pws", "msf"]
---

# 落盘产物的文件存在性检查

## 何时用

在声称产物落盘的动作后，只读确认目标或落点的文件、大小和可选摘要，区分命令声称与实际存在；适用于转储、上传、外带接收、落地载荷后的检查。
本卡不判内容正确性或可用性。执行点须可读该路径，就地优先；path 取上一步证据，不猜；session_ref、可选 expect_sha256 由运行层提供，不得杜撰，经会话读取须记录引用。
容器/宿主文件系统与写入时工作目录须对齐；优先绝对路径，含空格/特殊字符要引用并保持同一拼写，避免通配改写。工具说明：skills/_tooling/posix-shell.md。

## 怎么做

命令用本卡声明的工具面交给绑定位置：`position_speaks=shell` 用位置自己的 shell；`position_speaks=meterpreter` 仍提交 `{"tool":"cmd","cmd":"…"}`，由引擎包装并回收回显。不要改用 `execute -f <shell> -a "<命令行>"`：`Process NNNN created.` 没有命令输出，不能作查询证据。

按平台和已绑定通道选命令读取属性，可决定是否算摘要；任何可读属性的入口都沿用相同判据。Linux 可用 ls -l、stat -c '%s'、sha256sum、test -f：

```sh
ls -l <path> && stat -c '%s' <path> && sha256sum <path>
```

Windows 可用 dir、Get-Item -LiteralPath、Get-FileHash -Algorithm SHA256：

```cmd
dir <path> & powershell -NoProfile -Command "(Get-Item -LiteralPath '<path>').Length"
```

cmd 的串联符是 &，不是字面分号；不改 marker 包裹、证据字段名和判据。摘要沿用 sha256sum / Get-FileHash -Algorithm SHA256 的小写十六进制口径，有源端 expect_sha256 时用于比对。

## 怎么判

**finish.verdict 判断本卡要求的事实是否成立，不是查询是否完成。** 只用 pass / unsatisfied / uncertain；传输成功、查询完成、引文可核对都不能把明确的负事实变成 pass。 明确反证已成立时，不因仅成功才有的字段缺失改判 uncertain。

- **pass（成功）**：本次在正确机器确认同一路径存在且为常规文件（file_present==true），尽量带 size_bytes；有源端摘要时带 sha256。
- **unsatisfied（不满足）**：正确机器、同一路径的完整查询明确证明文件不存在，例如 stat_errno=ENOENT、file_present=false；即使 query_complete=true 也必须报 unsatisfied。先核对容器/宿主落点和相对路径，不能拿另一文件系统的结果顶替目标。
- **uncertain（不确定）**：权限或通道异常导致读不到、查询未完成或路径归属不明；这些不是文件不存在的反证。

证据字段：call_id、path、session_host、file_present、size_bytes、sha256。0 字节仍是存在，是否可用交后续解析；不因命令成功就判文件在。
本次调用的可核对引文仅证明观测，仍须按上述业务条件判断。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
