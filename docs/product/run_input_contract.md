# 运行输入契约：一次 run 吃什么、哪些是靶场特有的

> 目的：把「换一个靶场」从口头约定变成**可校验**的契约。
> 校验入口 `scripts/check_inputs.py`（实现 `src/inputs/bundle.py`），退出码 **0 通过 / 2 有问题 / 3 用法错误**。
> 它用**运行自己那套 loader** 判（`skills.selector`、`runtime.chain`、`check_common.load_json_argument`），
> 所以「全绿」的含义是：**运行会按你以为的方式读到这些文件**。

一句话口径：**图的形状是发布契约、部署表的内容是靶场事实、凭据是显式输入。**

体检全绿**不等于**攻击能打通：它只证明输入侧没有静默回退（缺地址、错名字、漏字段），
能力面（有没有登记卡、卡能不能打）由 [技能目录契约](skill_contract.md) 与实机证据负责，两件事分开说。

## 1. 一张表看清四个输入 + 三个可选项

| 输入 | 提交？ | 谁读 | 形状真源 | 通用 / 靶场特有 |
| --- | --- | --- | --- | --- |
| 图 JSON | 产物（`output/`，不进 git；源 TXT 在 `data/inputs/<lab>/`） | `scripts/run_agent.py --graph` → 运行循环 | `schemas/action_graph.schema.json`（V1，`schema_version=1.1.0`）+ `scripts/project_graph.py` | **形状通用**，事实内容属该靶场 |
| `assets.json` | 靶场本地（`data/inputs/<lab>/`，`.gitignore`） | 选择器 `skills/selector.py`（`load_assets` / `assets_host_map` / `find_endpoint`） | §2.2 | **形状通用，内容靶场特有**（部署表） |
| `host_ip_map.csv` | 靶场本地 | `--host-map`：`selector.load_host_map`；判定器 target 闸（`checker.py`） | §2.3 | 同上（对账表） |
| `run_context*.json` | 真实件不提交，模板提交 | `check_common.load_json_argument` → `RunState.credentials/sessions/channels/account_aliases` | §2.4 | 形状通用；内容 = 本 run 的显式输入 |
| `node-context.json`（可选） | 靶场本地 | `state.node_values[str(node_id)]` | §2.5 | 形状通用 |
| executor `chain` JSON（可选） | 靶场本地 | `runtime/chain.py::load_chain` | §2.5 | 形状通用 |
| `config` JSON（可选） | 靶场本地 | 选择器 `from: config` 绑定 | 自由格式 | — |

## 2. 逐个字段

### 2.1 图 JSON：V1 行动图（形状通用）

* 顶层必填（1.1.0，7 块）：`schema_version` / `inputs` / `source_graph` / `hosts` / `nodes` / `diagnostics` / `summary`；
  `schema_version` 必须等于 `1.1.0`，否则 `check_inputs.py` 直接报错并指向 `scripts/project_graph.py`（1.0.0 明确拒绝）。
* 节点的**靶场事实**（选择器与判定器读的就是这几个）：`source_host` / `target_host` / `service` / `protocol` /
  `port` / `vulnerability` / `attack_id`。
* 节点的**依赖**：`dependencies[]` = 直接父行（LEAF / OR / AND 三形态）；LEAF 带 `validation`，OR 带 `produced_by`。
* 节点的**派生面**（召回键与引用）：`case_id` / `case_status` / `case_candidates`、`premise_refs` / `effect_refs` /
  `requires[].any_of`、`details.accounts` —— **文档里没有**，由载入层 `src/graph/rehydrate.py` 从 `source_graph` + 规则重导；
  引用指向原图节点 id（= 节点 id，如 `"3"`），悬空引用会被体检抓出来。
* 节点的**账户**（载入层派生面）：`details.accounts[].user` 是图上的角色名（`domain_administrator`），
  `credential_fact_ref` 指向凭据事实；这两者是 `run_context.credentials` 的**合法键**（见 §2.4）。
* 一份图 = 一次实验的冻结输入：`run_agent.py` 启动即读完整份 JSON，中途不改。

**靶场特有的是什么**：事实内容（主机名、端口、服务、账户）。**通用的**是字段与引用语义。

### 2.2 `assets.json`：部署表（形状通用，内容靶场特有）

唯一负责回答「图上的逻辑名，在这套部署里是哪个地址」的地方。红日 7 用两个网络段 + 一个容器，
所以它同时演示了多网段与发布端点两种形状：

| 字段 | 必填 | 含义 |
| --- | --- | --- |
| `hosts.<name>.kind` | 是 | `vm` / `attacker` / `container` / …（自由串，`container` 有特殊语义） |
| `hosts.<name>.ips` | 非容器必填 | 该主机的地址表（多网段就多写几个，如 `["192.168.1.103","192.168.52.10"]`） |
| `hosts.<name>.parent` | 容器必填 | 容器没有自己的地址，按父主机解析（`web2_docker.parent = web2`） |
| `endpoints.<name>.execution_host` | 是 | 代码在哪台主机上执行（可以是容器名） |
| `endpoints.<name>.connect_ip` / `connect_port` | 端点必需 | 从控制点实际连的地址/端口（容器场景 = 发布在父主机上的那个） |
| `endpoints.<name>.graph_port` | 否 | 图上写的端口，用于和节点端口对齐（`find_endpoint` 用它消歧） |
| `endpoints.<name>.observed_local` / `explanation` | 否 | 现场核对记录（人读，运行不读） |

多网段用 `--control` 消歧：选择器取**与控制点同 /24**的那个地址；一个都没有时取第一个并留 note
（`assets:first` —— 体检会把这条 note 提前报出来，而不是等运行中途才发现瞄错主机，见 D32-h 缺陷①）。

红日 7 的 `assets.json` 还带 `sources` / `abstractions` / `unknowns` / `source_conflicts` /
`expected_final_goals` / `detailed_milestone_not_equivalent_to_host_root`：**建模说明，运行不读**，
可以照抄、可以省略；体检不会因为多这些键报警。

### 2.3 `host_ip_map.csv`：对账表（两个 loader，两套表头规则）

格式：一行 `host,address`，`#` 开头是注释（红日 7 那份就带两行注释、没有表头）。

**已知坑（本项目里同名文件有两个消费方，规则不同）**：

| 消费方 | loader | 表头 |
| --- | --- | --- |
| 运行与判定器（`--host-map`） | `skills.selector.load_host_map` | **没有表头概念**：`host,ip` 那一行会被当成一条映射 `host -> ip` |
| 转换工具（`scripts/convert_hosts.py --mapping`） | `graph.host_identifiers.load_mapping` | **要求**首行正好是 `host,ip` |

所以：**交给 `--host-map` 的那份不要写表头**。体检对表头行只报 warn（它可能是给转换工具的那份），
并把 `host -> ip` 这条幽灵映射一起点出来。`data/inputs/hongri7/host_ip_map.csv` 与
`data/samples/lab_demo/host_ip_map.csv` 都是「无表头」写法。

对账表的用途是**判定器 target 闸**：观测到 `PC1` 这类主机名时，能对齐节点目标 `192.168.93.30`。
它不参与地址解析（那是 `assets.json` 的活）；一张主机多地址时，对账表只写「判定要用的那一个」。

### 2.4 `run_context*.json`：显式运行输入（形状通用）

```json
{
  "credentials": {
    "domain_administrator": {
      "user": "Administrator", "domain": "WHOAMIANONY", "secret": "…", "mode": "password",
      "role": "domain_administrator", "source": "operator input (D32-h)",
      "provenance": "writeup replication 2026-09-11: mimikatz sekurlsa::logonpasswords …（指向审计文档行）"
    }
  },
  "sessions": {}, "channels": {}
}
```

* **键 = 图上的账户名**（载入层派生面 `details.accounts[].user`），或该账户的 `credential_fact_ref`。
  运行**不猜**角色与真人的映射：拿不到就记缺口（D32-h 的教训 —— 也正因为这条，`user` 才是真登录名）。
* 运行真正读的字段只有 `user` / `domain` / `secret` / `mode`（`selector._credential_from_facts`）；
  `role` / `source` / `provenance` 是**纪律字段**：材料必须写明出处，**从不编造**。体检对缺 `provenance` 直接报 error。
* `sessions` / `channels` 是运行开始时就已经核过对的会话/通道小目录（一般留空，让运行自己建立）。
* 顶层只有这几个键会被转发；别的键（含 `credential` 这类拼写错误）体检报 warn。

#### 平台声明：`host_platforms`（可选，2026-09-23 run108）

`{ "pc1": "windows", "web2_docker": "posix" }`：逐主机的**机器族**声明，键与图上的主机名一致。
叶子形态里有两处只在一种机器上成立（`networkServiceInfo(...,local,...)` 的本机进程检查、
`pathExists` 的 POSIX 权限检查）——谓词本身只说「东西在哪」，从不说机器是什么，
所以程序**不猜**：缺这条声明的对应叶子如实记 `shape_needs_platform` 缺口，
补上声明后同一份图就能取到方法卡。写错族名（比如 `window`）体检按未读键报 warn，运行按缺口处理。
* 模板：`data/samples/hongri7_run/run_context.demo.json`、`data/samples/lab_demo/run_context.demo.json`；
  真实件放 `data/inputs/<lab>/run_context.<name>.json`（`.gitignore` 已挡 `data/inputs/*`）。

#### 账户别名：`account_aliases`（可选，D40）

图上的账户槽位是**角色键**（`domain_administrator`），而素材往往只带**登录名**（`Administrator`，
dump 里就是这样）。运行**绝不把这两者自动当成一个主体** —— 那是操作者自己的一笔登记，写在这里：

```json
{
  "credentials": {},
  "account_aliases": {
    "domain_administrator": {
      "user": "Administrator",
      "domain": "WHOAMIANONY",
      "provenance": "这条登录会话就是域管（见 D39 解析读数）；别名由操作者登记，不是运行推断"
    }
  }
}
```

| 字段 | 必填 | 含义 |
| --- | --- | --- |
| 键 | 是 | 图上的账户名（`details.accounts[].user`）或它的 `credential_fact_ref` |
| `user` | 是 | 素材实际入账的**登录名**（`credentials` 与 `state.credentials` 用的那个名字） |
| `domain` | 否 | 记录用 |
| `provenance` | 是 | 这笔映射从哪来（体检缺它直接 error，与凭据一个纪律） |

行为：素材（显式输入的，或运行自己产出的）一旦按 `user` 存在，运行就把它**按角色键再入账一条**，
条目里写 `bridged_from`；`run_result.account_aliases[]` 逐笔报有没有被素材兜住（`target_held` / `filed`），
`assumptions[]` 里那行 `kind=alias` 写清「这是操作者的登记，不是运行的推断」。
**先声明别名、素材后到是正常用法**（例如先声明，再等 dump 链把材料带回来）：
在那之前它只是一条点名缺口（`bridge` 假设会说：声明了这笔别名，但那个登录名下还没东西）。

### 2.5 可选项

* `node-context.json`：`{"<节点 id（= 原图 ID）>": {"<键>": <值>}}` —— 逐节点的运行时值（例如某节点要用的命令）。
  键必须是该图里真实存在的节点 id（= 原图 ID），否则体检报 error。
* `chain` JSON：`{"hops": [{"kind": "ssh", "target": "kali@…", "password_env": "AGV_SSH_PASSWORD"}]}`；
  第一跳是传输（本机 SSH 到攻击盒），后续每跳是命令包装。**内层跳必须给 `key`**（外层用 `BatchMode=yes`，
  密码提示会挂住而不是失败）——体检按这条规则报 error。
* `config` JSON：喂给选择器 `from: config` 的绑定值（卡自己带默认值），自由格式，只要求是个对象。

## 3. 校验入口怎么用、报什么

```bash
python scripts/check_inputs.py --graph output/hongri7/json/Hongri7_v2.action_graph.json \
  --assets data/inputs/hongri7/assets.json --host-map data/inputs/hongri7/host_ip_map.csv \
  --context @data/inputs/hongri7/run_context.domain_admin.json \
  --node-context output/runs/D29-node-context.json --control 192.168.52.128
```

红日 7 当前读数（六个输入全绿）：

```text
OK    graph         12 AND / 2 OR node(s), 51 dependency row(s), 7 host name(s), 1 graph role(s)
OK    assets        7 host(s), 5 endpoint(s)
OK    host-map      5 mapping(s)
OK    context       1 credential(s), 0 account alias(es), 0 session(s), 0 channel(s)
OK    node-context  3 node value set(s)
OK    control       address resolution starts from 192.168.52.128
-- 6 ok / 0 warn / 0 error
```

故意打破的读数（4 error / 5 warn，退出码 2）：

```text
ERROR assets    host 'host_b' (vm) has no ips - give it at least one address, or the run keeps the logical name and the target gate cannot align
ERROR assets    endpoint 'synthetic_service' executes on 'host_c', which is not a host in this table
ERROR assets    endpoint 'synthetic_service' has a bad connect_port: 'twenty-two'
WARN  assets    the graph names host(s) this table does not define: internet …
ERROR host-map  line 3: 'host_b' -> 'not-an-ip' is not an IPv4 address
WARN  host-map  line 1 is the converter's header ('host,ip'): scripts/convert_hosts.py requires it, while the run's loader would keep it as the mapping host -> ip
WARN  context   top-level key(s) the run never reads: credential (it forwards credentials, sessions, channels, account_aliases)
WARN  context   the graph asks for account(s) with no credential here: synthetic_user - … the run does not guess the mapping (D32-h)
```

常用开关：`--strict`（把 warn 也当失败：接入新靶场时用它把每条 note 变成决定）、`--json`（机器可读，含 counts 与逐条 findings）。

每条报文的修法：

| 报文 | 修法 |
| --- | --- |
| `missing top-level key(s): …` / `schema_version is …` | 不是 1.1.0 图（1.0.0 已退役）：用 `scripts/project_graph.py` 重新生成 |
| `node … carries semantics - derived facts must not live in the document` | 手改 JSON 或旧版产物：重新投影；派生面由载入层重导，不回流文档 |
| `node …: dependencies …` / `produced_by …` 一致性错误 | 文档与解码结果对不上：重新投影；不要手改 JSON |
| `AND node … derives no rule case` | 规则目录缺该 case：在 `src/graph/rule_catalog.py` 补，再投影 |
| `host '…' (vm) has no ips` | 部署表漏地址：补 `ips`，或给它写一行 `host_ip_map.csv` |
| `endpoint … executes on '…', which is not a host` | 名字拼错或漏建主机条目 |
| `runs inside container …: add connect_ip/connect_port` | 容器端点要写「发布在父主机上」的地址 |
| `the graph names host(s) this table does not define: …` | 补 host（容器也要建条目，`kind=container` + `parent`） |
| `line N is the converter's header ('host,ip')` | 这份是给 `--host-map` 的：删表头（转换工具那份另存） |
| `credential '…' has no user` | 写**真登录名**（角色名不是登录名，D32-h） |
| `credential '…' has no provenance` | 写清材料出处，指向可复核的文档/记录 |
| `credential '…' carries the template value …` | 模板没替换：换成实测材料（`--strict` 下直接失败） |
| `the graph asks for account(s) with no credential here: …` | 按图上的名字补凭据；材料只有登录名时补 `account_aliases` 别名；或如实接受这个缺口（运行会记 `needs[]`） |
| `account alias '…' has no user` | 写素材实际入账的**登录名**（角色名不是登录名，D32-h） |
| `account alias '…' has no provenance` | 写清这笔映射从哪来（它是操作者的登记，运行不猜） |
| `account alias '…' is not an object` | 写成 `{"user": …, "provenance": …}`，不要写成一个字符串 |
| `node '…' is not an original_id in this graph` | `node-context` 的键写成别的东西了：用节点 id（= 原图 ID） |
| `hop N has no key` | 内层跳补 `key`（`ssh` 免密私钥） |

## 4. 新靶场接入清单

1. **出图**：把导出的 MulVAL TXT 放 `data/inputs/<lab>/<Lab>.txt`，跑
   `python scripts/project_graph.py data/inputs/<lab>/<Lab>.txt --output-dir output/<lab> --json-only`；
   需要 IP 别名往返时先过 `scripts/convert_hosts.py`（它要求 `host,ip` 表头的映射文件）。
2. **写部署表**：`data/inputs/<lab>/assets.json` —— 图上的每个主机名都要有条目（含攻击者位置），
   多网段写全 `ips`，容器写 `parent`，端点写 `execution_host` + `connect_*`。
3. **写对账表**：`data/inputs/<lab>/host_ip_map.csv` —— 无表头、`#` 注释随意，只写判定要对齐的地址。
4. **写运行输入**：`data/inputs/<lab>/run_context.<name>.json` —— 从模板
   `data/samples/lab_demo/run_context.demo.json` 抄形状，凭据键用图上的账户名，`provenance` 写实。
5. **体检**：`python scripts/check_inputs.py … --strict`，把每条 warn 变成决定（补数据或写下「接受」的理由）。
6. **干跑**：`python scripts/run_agent.py …`（默认 plan，不触网）读 `agent_plan.json`：
   每一步的目标地址应该正好是你部署表里的地址；`method.candidates = 0` 如实说明技能缺口。
7. **实机**：起靶场 → `--live`（配 `--remote`/`--chain`）→ 跑完按 [实机验证记录](validation_runs.md) 的格式留证。
8. **清理**：靶场回到可复跑状态（临时文件、shell、监听、DB 都要清），VM 用完 suspend。

## 5. 已知边界（如实记录）

* **一张主机多地址**：`assets.json` 用 `ips[]` 表达，`--control` 消歧；`host_ip_map.csv` 只写判定要用的那一个地址
  （红日 7 的 5 行不含 93.10 / 93.20 / 1.103，就是这个边界）。
* **同名文件两个 loader**：见 §2.3，表头规则不同，体检只报 warn（不替你做决定）。
* **容器短 id**：属运行现场对照物，不进表（运行层按 `requirement.target_aliases` 注入）。
* **`observed_local` / `evidence` 这类现场字段**：路径指向操作者本机证据，换机器会失效；运行不读，删掉不影响体检。
* **体检不做的事**：不验证凭据是否真的能用、不验证端口是否真的开着（那是实机 prereq 与 precheck 的活）。

## 6. 参照物与证据

* 红日 7（真实部署，本地不进 git）：`data/inputs/hongri7/`；读数 = §3 六行全绿。
* 第二个靶场（虚构、进 git）：`data/samples/lab_demo/`（`README.md` 里写了来源与再生成命令）；
  干跑读数见 [实机验证记录](validation_runs.md) 的 D38 节。
* 单元/集成测试：`tests/test_inputs_bundle.py`（36 条：每个输入的「干净 / 缺字段 / 写错名字」各一组 + CLI 退出码 + `--strict`；1.1.0 起含「旧版本拒绝 / 被删字段拒绝 / 载入层一致性」守线）。