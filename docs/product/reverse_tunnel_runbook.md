# 反向代理隧道：从零到"两跳"的可重复步骤（2026-09-28 修订）

本页是「一条通路怎么搭出来、怎么判定它真的通了」的可执行清单，不是设计讨论。
件是 `src/runtime/clients/agv_socks_reverse.py`（**纯标准库、py2.7 与 py3.x 通用**），两种角色：

```text
serve   控制端：本地 SOCKS 口（默认只绑 127.0.0.1）+ 控制口 + 数据口
client  中转节点：主动连回控制口；按控制面的 CONNECT 指令连接目标，并为每条请求新开一条数据连接
```

## 0. 协议（v2，2026-09-27 定稿；2026-09-28 补分帧修复）

控制面带三条短文本行，数据面每条连接带一行自己的开头：

```text
server -> client : CONNECT <token> <host> <port>
client -> server : ERR <token> <code>          （对端连不上）
client -> server : OK <token>                  （连上了，且它的数据连接已经打开）
data  -> server : DATA <token>                 （随后才是原始字节）
```

三条硬规则（每一条都对应一次真机事故，见第 5 节）：

1. **请求按 token 配对**，不是按到达顺序 —— 某条请求的数据腿迟到时，FIFO 会把腿配给下一条请求。
2. **成功应答要等数据面就绪之后才回** —— "目标连上了"不等于"路已经通了"。
3. **控制面的应答按"完整一行"读**，且**一条控制连接只有一个读者**：一次 `recv()` 就按换行切分解析，
   遇到 TCP 分片会把残留的半行留给下一条请求，整条链从此错位（互抢应答 → 尾部请求永远等不到回复）。

## 1. 单层（控制端 K ⇄ 中转 A）

```sh
# K 上（控制端）
python3 -u agv_socks_reverse.py serve --bind 0.0.0.0 --socks-bind 127.0.0.1 \
    --socks-port 1080 --control-port 7001 --data-port 7003

# A 上（中转节点）：POSIX 用上一行；Windows 用下面这一行（cmd 一行写完，没有续行符）
python3 -u agv_socks_reverse.py client --host <K> --control-port 7001 --data-port 7003
C:\Python27\python.exe -u C:\OpsTunnel\app\agv_socks_reverse.py client --host <K> --control-port 7001 --data-port 7003
```

判定（"K 到不了、A 到得了"的地址）：从 K 直连该地址应失败；把 `127.0.0.1:1080` 当 SOCKS5 用请求它应得 `rep=0`。

## 2. 两跳（K → A → B）：外层隧道 + 在 A 上再起一个服务端

```sh
# A 上再起一个服务端（它的"本地代理口"只绑回环：K 经外层隧道来访问它）
python3 -u agv_socks_reverse.py serve --bind 0.0.0.0 --socks-bind 127.0.0.1 \
    --socks-port 1081 --control-port 7002 --data-port 7004
# Windows（cmd 一行）：
C:\Python27\python.exe -u C:\OpsTunnel\app\agv_socks_reverse.py serve --bind 0.0.0.0 --socks-bind 127.0.0.1 --socks-port 1081 --control-port 7002 --data-port 7004

# B 上（第二个中转节点）：连的是 **A 的地址**
python3 -u agv_socks_reverse.py client --host <A> --control-port 7002 --data-port 7004
```

K 侧的使用方式（**同一条连接里做两次握手**）：

```text
1) 连 K 自己的 SOCKS 入口        127.0.0.1:1080
2) CONNECT 127.0.0.1:1081        <- 这个 127.0.0.1 是"从 A 看"的地址（由 A 解析）
3) 在上一步建立的那条流里，再做一次 SOCKS 握手
4) CONNECT <目标>:<端口>          <- 这个目标由 B 解析（链尾出口）
```

**地址视角规则**：每一跳的地址都由"上一跳的出口"解析。第 2 条的地址按 A 的视角写，第 4 条按 B 的视角写；
`0.0.0.0` 只能当绑定值，不能当连接目标。域名按 SOCKS5 的 `ATYP=3` 原样透传，**不要在 K 上先解析成 IP**。

## 3. Windows 中转节点（只有 Python 2.7 / 甚至没有 Python）怎么落地并常驻

已验证可行的最小形态是"**共享目录投放 + 远程管理接口只执行一条命令 + 任务调度器常驻**"：

```text
a) 经共享目录投放：程序、启动包装 .cmd、任务定义 .xml
b) 远程管理接口只执行一条命令：cmd.exe /d /c <投放目录>\bootstrap.cmd
c) bootstrap 里用 schtasks /Create /TN <名> /XML <文件> /RU SYSTEM 注册任务、/Run 触发
d) 命令输出不可靠 ⇒ 让脚本自己写回执文件（或由 .cmd 重定向），并保留退出码
```

投放目录里那份包装（`bootstrap.cmd`）实测可用形态：每个实例一个任务名、创建与启动各留一份回执，
`.cmd` 自己做的重定向是可靠的（远程执行接口的重定向会顶掉外层的 `>`）：

```bat
@echo off
setlocal
set "R=C:\OpsTunnel\runs\R01"
>"%R%\bootstrap.entered" echo R01
ver >"%R%\windows-version.log" 2>&1
C:\Windows\System32\whoami.exe >"%R%\identity.log" 2>&1
C:\Python27\python.exe -V >"%R%\python-version.log" 2>&1
call :launch A-L2
if errorlevel 1 exit /b 1
call :launch A-L1
if errorlevel 1 exit /b 1
>"%R%\bootstrap.done" echo R01
exit /b 0
:launch
C:\Windows\System32\schtasks.exe /Create /TN OpsTunnel_%~1 /XML "%R%\%~1.xml" /RU SYSTEM >"%R%\%~1.create.log" 2>&1
set "rc=%errorlevel%"
>"%R%\%~1.create.rc" echo %rc%
if not "%rc%"=="0" exit /b %rc%
C:\Windows\System32\schtasks.exe /Run /TN OpsTunnel_%~1 >"%R%\%~1.run.log" 2>&1
set "rc=%errorlevel%"
>"%R%\%~1.run.rc" echo %rc%
if not "%rc%"=="0" exit /b %rc%
exit /b 0
```

任务定义（**本环境验证通过的模板**：`UTF-16LE + BOM，声明与文件字节一致`；其它编码/声明组合未在本环境验证）：

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId>
    <RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="System"><Exec>
    <Command>C:\Windows\System32\cmd.exe</Command>
    <Arguments>/d /c C:\OpsTunnel\runs\R01\run-A-L1.cmd</Arguments>
    <WorkingDirectory>C:\OpsTunnel\app</WorkingDirectory>
  </Exec></Actions>
</Task>
```

三条边界，别当保证用：

- `MultipleInstancesPolicy=IgnoreNew` **只约束同一个任务**：另建一个任务、或手工再起一个进程，它管不住 —— 单实例要在启动侧保证。
- `schtasks /Create /F` 可以覆盖同名定义，但**覆盖不等于停掉正在跑的实例**；换一个 `run_id` 标签也不能替代停旧实例。更新定义前先 `/End`。
- 没有 Python 的 Windows 节点：**cmd / PowerShell / WMI 都不能直接运行 Python 源码** —— 要么随包投一份匹配架构的运行时，要么写另一份实现。

### 3.1 控制槽的"验活"到底验了什么（别把它当健康检查）

一条隧道只服务一个跳板机：**新来者不顶掉在任者**，但在任者必须先被验活，否则一条死连接会永久占槽。
验活的实际判据（`_alive`）是：向在任连接写一行无害的 `PING`（客户端忽略不认识的行），
然后 `select` 等 **0.2 秒** ——

- 这 0.2 秒内**没有**可读事件 ⇒ 认为"还活着"（安静，但没有证据说明它死了）；
- 有可读事件，且 `MSG_PEEK` 探到字节 ⇒ 还活着；
- 有可读事件，却探到 EOF（或写入直接失败）⇒ 死连接，释放该槽，让新来者接管。

**诚实边界**：这只能发现"对端 TCP 已经关了/写不进去"。对端进程还活着但应用已经卡死、或者网络黑洞，
在这里都会读成"还活着" —— 所以它不是健康检查，消费方在真正发命令前仍应自己做一次轻探（第 4 节的验收也是这么做的）。

## 4. 验收（两跳）：四个格子 + 一条负对照

判分脚本与链尾服务都在仓库里（纯标准库、与隧道件同样不假设一次读全）：
`scripts/accept_reverse_tunnel.py`（判分）、`scripts/accept_challenge_service.py`（链尾挑战服务：只绑回环，回执带 `NONCE/HOST/LOCAL/PEER`）。
库内 `tests/test_accept_probe.py` 用这两件在回环上重演了「两跳 + 内层停摆负对照」，读者不必先有实验网就能先验证判据本身。

目标服务放在**链尾节点 B 上、只绑回环**（示例 `127.0.0.1:18080`）：这样 K 直连与经单跳都必然失败，
只有经两跳能到 —— 回执里带 `NONCE/HOST/LOCAL/PEER`，其中 `LOCAL=["127.0.0.1",18080]`、`HOST` 是 B 自己的名字。

| 格子 | 命令 | 预期 |
|---|---|---|
| DIRECT | `... DIRECT --direct-host <B> --direct-port 18080` | 打不开（拒绝/超时都算；报文里给出 `error_kind`） |
| ONE | `... ONE --challenge-host 127.0.0.1 --challenge-port 18080` | 被拒：`rep=5`（第一跳答不了链尾的回环） |
| TWO | `... TWO --inner-socks-port 1081` | **成功**：`rep=0`、`rep=0`、HTTP 200，回执 `NONCE` 与本次一致 |
| BASELINE | `... BASELINE --baseline-host <A 到得了的地址> --baseline-port 445` | `rep=0`（单层回归） |
| 负对照 | 先停掉 A 上的内层服务端，再跑 TWO | **必须失败**（外层连不到内层入口，`rep=5`）；恢复后 TWO 再次成功 |

自证顺序：先在 B 上本机请求一次挑战服务（HTTP 200 + 回执逐项核对），再跑上面五格；否则"两跳失败"可能只是链尾服务没起来。

两个前提要写清楚，别把弱证据当强证据：

- 挑战服务只绑 B 的回环 ⇒ 证明"到达 B 的回环"；它**不能单独证明** A 的回环上没有别的服务在听 18080 —— 所以 ONE 那一格必须同时看到 `rep=5`。
- 重跑前确认链上每个端口**只有一个实例**（第 5 节"重复监听"一行）；多实例会让判分结果无法归因。

## 5. 坑（每一条都是实测踩出来的）

| 现象 | 真因 | 修法 |
|---|---|---|
| 内层握手直接 EOF，且**只在 py2.7 那台机上** | Python 2 里 `b"\x05"[0]` 是**字符串**不是整数，`header[0] != 5` 恒为真 ⇒ 每个请求都被判非法 | 字节比较一律用切片（`header[0:1] != b"\x05"`），取整用 `int`/`ord` 兼容的 `_byte()` |
| 一次失败的 connect 把整个客户端带走，之后全拒 | Python 2.7 里 `socket.error` **不是** `OSError` 的子类（属 `IOError`） | `except (OSError, IOError)`（或统一常量 `SOCKET_ERRORS`） |
| 内层 CONNECT 无应答、连接被无声关闭 | py2 里 `os.urandom(16)` 是 `str`、没有 `.hex()`；该异常逃出了 SOCKS 处理函数，线程死亡 | `binascii.hexlify(os.urandom(16)).decode("ascii")` |
| **一条请求被拒、随后整条链错位**（B07） | 控制面应答被 TCP 分片：一次 `recv()` 把半个行当完整行解析，残留字节毒化下一条请求；并发请求还会互抢应答 | 应答**按完整行读**（读到换行才算一行）；一条控制连接**只有一个读者**（CONNECT/应答事务串行化） |
| 隧道"抖动"：反复 up/down | 同一端口上跑了**多个客户端/服务端实例**，互相把对方的槽顶掉 | 服务端"新来者不顶掉在任者"，但**在任者必须先验活**（发无害行 + peek）；启动侧保证单实例 |
| 死连接永久占槽，真客户端进不来 | 只做了"不顶掉"，没有"验活后释放" | 同上 |
| 目标端口没人听却回"成功" | 成功应答发得太早（目标连上就回） | 必须等**数据面就绪**再回成功 |
| 慢的数据连接被配给下一个请求 | 按到达顺序配对 | 请求带 token，数据连接带 `DATA <token>` |
| 转发线程退出后 socket 还留着 | 没有统一的资源归属 | 所有 socket/线程归一个资源组管，`close()` 里统一 shutdown+close 并 join；转发两端超时显式置 `None`（连接超时不得沿用到已成数据流） |
| `schtasks /Create /XML` 报"XML 格式不正确" | 任务 XML 的编码/声明与本环境模板不一致 | 用第 3 节的 UTF-16LE+BOM 模板（本环境验证通过；不要把一次导入故障推广成"所有 XML 必须 UTF-16"） |
| 远程执行接口取不到命令输出 | 它会把自己的 `1> \\127.0.0.1\ADMIN$\…` 重定向追加到命令行末尾，**顶掉**我们写的 `> 文件` | 回执由脚本内部写文件，或包一层 `.cmd`（cmd 自己做的重定向生效）；同时保留退出码 |
| A 上 PowerShell 一启动就报 `8007000e` | 该节点内存吃紧（2GB 里只剩 ~119MB） | 该节点的落地/常驻/回执**一律走 cmd 与 Python 2.7**，不把"恢复 PowerShell"当前置条件 |
| "登记后退休接收器"后重连失败 | 退休的是"未来重连入口" | 会话退休 / 取消恢复资格 / 销毁资源是三件独立的事，按是否承诺自动重连决定 |
| 清理脚本把正在用的东西删了 | `pkill -f <名字>` / `pgrep -f <名字>` 会**匹配到执行它的那条命令自己** | 用中括号模式（`[a]gv_...`）避开"命令行里写着同样字符串"的自匹配 —— 这**只**解决这一种自匹配，不等于安全：停机前仍要按**路径 + 参数 + 启动时间**核对身份，再定向终止 |

## 6. 收尾（靶场卫生）：对象清单 + 自证 + 延迟复查

按"归档 → 停自动拉起 → 停进程 → 删任务与文件 → 延迟复查 → 最后卸挂载"的顺序做。停止前**逐个核对身份**
（可执行文件路径、完整参数、启动时间、父进程），不要只凭 PID 或名字。本环境的实测清单：

| 机器 | 停止 | 删除 |
|---|---|---|
| 控制端 K | 两个 `serve` 实例（本次 `--socks-port 1080` 与历史 `--socks-port 1090`） | 运行副本与对应日志、本次诊断临时文件 |
| 中转 A（Windows） | 两个计划任务实例、其 cmd 包装与 python 子进程；`C:\Windows\Temp` 下历史遗留的转发/代理脚本进程 | 已核实的任务定义、部署目录 `C:\OpsTunnel`、投放的临时脚本 |
| 链尾 B | 隧道 client、挑战服务 | 运行副本、`/tmp/ops-batch03`、历史 `b_challenge.*` 等明确归属的临时文件 |
| 最后 | —— | 卸载控制端上的共享挂载（不删系统共享本身） |

自证（缺一格的都不算清干净）：任务名 `GetTask` 报"不存在"；进程按身份复列为空；端口无监听；
文件不存在；卸载后 `mountpoint` 为空。**延迟复查**：隔几分钟再看一次上面的进程/监听/任务，确认没有自动拉起。

## 7. 验收记录（2026-09-27，与本文档第 0/4 节的协议一致）

拓扑：控制端 K（Linux）→ 中转 A（Windows，**仅 Python 2.7、PowerShell 不可用**）→ 中转 B（Ubuntu）；
挑战服务只绑 `127.0.0.1:18080`（B 本机自证 HTTP 200 + 回执逐项核对通过）。

| 用例 | 结果 |
|---|---|
| K 直连 `B:18080` | 失败（负对照通过） |
| K 经单跳（出口 A）请求 `127.0.0.1:18080` | SOCKS `rep=5`（负对照通过） |
| K 经两跳 → 内层再握手 → 请求 `127.0.0.1:18080` | **成功**：HTTP 200，回执 `NONCE` 与本次一致、`HOST=ubuntu`、`LOCAL=["127.0.0.1",18080]` |
| K 经单跳请求 `192.168.93.40:445` | 成功（单层回归基线） |
| 停掉 A 的内层服务端后重跑两跳 | 失败于 `OUTER_CONNECT rep=5`；重启后两跳再次成功 |
| A 上 `1081` 监听数 | 1（单实例） |
| 三机部署副本 sha256 | 与提交内的一致（`78ee8d20…`） |

过程里修掉的 bug（都有提交与证据）：py2 字节索引比较 `b6f0945`、`socket.error` 非 `OSError` `45c7264`、
`os.urandom(...).hex()` 在 py2 抛异常 `f2c9800`、控制面分帧/单读者/资源收尾 `4b51950`；
对应回归在 `tests/test_socks_reverse.py`（含分片、并发、取消、连接替换、短字段、EOF 半行）与 `tests/test_accept_probe.py`。

**门禁**：`pytest tests/ -q` 全绿（1 skipped = 未设 `AGV_GRAPHVIZ_DOT`，跳过 PDF 渲染检查）；`python scripts/ci.py` = PASS 4/4。