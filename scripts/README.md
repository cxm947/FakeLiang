# scripts/：运行入口与使用说明

本页说明当前验证流程的运行、调试、会话管理、回收和离线检查入口。

下表说明常用入口的用途。各入口的退出码分别解释：例如 `run_node.py` 返回 0 表示收到模型报告，节点或整轮是否通过仍需核对运行结果与证据。

常用入口如下：

| 脚本 | 谁用 | 干什么 |
|---|---|---|
| `lab_round.py round --name <本轮名> --start` | 每轮一条命令 | 先**串行回滚**到干净快照、核基线，再按标准参数发起端到端（模型 token 从本机 config.toml 读；不带 `--start` 就只打印命令） |
| `check_delivery.py` | 一轮跑完 | 人工诊断 CLI（D64）：汇总四扇回执、交付命令、44/48 的结论与收获表里的会话；不是自动验收闸，退出码不表示交付通过 |
| `lab_round.py` | 每轮起跑前 | 轮次地基：**串行**回滚六台 VM 到干净快照（vmrun 并发会互锁）+ 核基线（kali 无残留/无我们的监听/msfrpcd 在跑/web1:81 与 pc1:8080 开）；`verify` 在验证期间报"基线不对"是正常的 |
| `project_graph.py` | 起手第一步 | 图编译入口：**攻击图 TXT + 主机映射表**（+ 可选 `--assets` 部署画像）-> 1.2.0 JSON（`output/<名字>/json/<名字>.action_graph.json`），唯一的图生成来源；`--json-only` 跳过 Graphviz |
| `run_node.py` | 真机验收 | 图节点入口：读图 -> 按 `when` 选卡 -> 交给执行器循环；退出码 0 表示收到模型报告 |
| `run_plan.py` | 整图串起来 | 轻量 planner：按 `produced_by` 顺序驱动技能卡任务；pass 且引用可核后登记成果，派发前按推导材料、计划材料顺序供给候选；`--carry-from` 同时续接凭据引用与既有句柄 |
| `session_manager.py` | 会话管理 | 从账本的 `carry` 句柄接管会话：逐个探活、按类型重连一次、把能迁的迁进 console（`migrate_to_console`）；`daemon` 模式每次动作写一行 `session-daemon.log` |
| `reclaim.py` | 清场 | 按产物表的逆操作倒序回收：先停 payload，再停会话与 job，删我们的文件，撤转发与防火墙规则，最后关账本行；默认只演算，`--apply` 才真做 |
| `run_lean_node.py` | 真机验收 | 同上，但卡由命令行指定（对照/调试用） |
| `run_lean_task.py` | 单任务调试 | 绑定既有执行器跑一张卡的单个任务（`--actions` 或 `--model`）；任务秘密仅在内存恢复，模型与写盘产物脱敏；内核公开入口仍为 `runtime.lean.LeanRun`，账本、运输、证据实现分别位于 `lean_journal.py`、`lean_transport.py`、`lean_evidence.py` |
| `ci.py` | 每次提交 | 本地 CI：`pytest` + `--check cards` + `--check tree`，结果写 `output/reports/ci/` |
| `journal.py` | 人读记录 | 把一轮验证写成人读的 txt：每节点 planner 给的下一步 / 前置是否成立 / 利用段每次调用 / 验证结果 / 会话管理；`--journal` 追加到跨轮汇总 |
| `node_transcript.py` | 人读记录 | 每个节点的模型输出转录（模型原文 + 动作 + 回执 + 拒绝 + 结论），并支持 `--diff <A> <B>` 逐发对齐两轮：改了 A 会不会影响 B |

整轮规划由 `src/agents/planner/service.py` 承担；独立看板入口为 `src/agents/planner/io.py`。两段系统提示词位于 `src/agents/planner/templates/walk_system.txt` 与 `src/agents/planner/templates/io_system.txt`，由 `src/agents/planner/prompts.py` 读取。

节点验证由 `src/agents/verifier/service.py` 承担；任务组装与答复解析位于 `src/agents/verifier/runner.py`。主提示词和两段重试静态片段由 `src/agents/verifier/prompts.py` 读取同目录 `templates/` 的三份资源，动态错误信息仍在 Python 拼接。

选卡实现位于 `src/skills/bind.py`；同分候选的模型选择提示词由 `src/skills/bind_prompts.py` 读取 `src/skills/templates/bind_system.txt`。

## 单任务实现

`run_lean_task.py` 使用 `src/agents/executor/` 中的实现；下列模块没有独立 CLI 或 `--help`。
这些实现随 `src/` 包分发；单任务命令仍使用源码检出的 `scripts/run_lean_task.py`。

| 模块 | 职责 |
|---|---|
| `src/agents/executor/prompts.py` | 提示文本与回合预算提示 |
| `src/agents/executor/observation.py` | 观测裁剪与拒绝反馈 |
| `src/agents/executor/input.py` | 输入校验与执行器选择 |
| `src/agents/executor/action.py` | 动作翻译与秘密占位符恢复 |
| `src/agents/executor/driver.py` | 单任务动作与结论循环 |

## 回收库模块

`scripts/reclaim_hosts.py` 负责主机清理和残留复核，是库模块，无独立 CLI 或 `--help`；回收命令继续使用 `reclaim.py`。

## 常见用法

```powershell
# 端到端一条命令：攻击图 TXT + 主机映射表 -> 逐节点走完（进度实时写 <run>/walk.txt，标准输出也回一行）
$env:AGV_MODEL_API_KEY = "<本机 router 的 bearer token>"
python scripts/run_plan.py `
    --graph data/inputs/hongri7/Hongri7_v2.txt `
    --graph-assets data/inputs/hongri7/assets.json `
    --host-map data/inputs/hongri7/host_ip_map.csv `
    --run-root output/runs/walk-1 `
    --remote kali@192.168.52.128 --password $env:AGV_SSH_PASSWORD `
    --control 192.168.52.128 --msf-rpc msf:agvpass@127.0.0.1:55553 `
    --model deepseek-flash --model-base-url http://127.0.0.1:7789/v1 --model-wire responses `
    --credentials $env:AGV_CREDENTIALS_FILE --max-nodes 14 --max-steps 12

# 说明：--graph 给 .json 直接读；给 .txt 就现场编译到 <run-root>/graph/ 下再走，
#       所以"用的是哪张图、哪份映射表"跟着这一轮走。--model-wire 默认 chat（OpenAI 兼容），
#       本机 router 只认原生 responses，所以这里显式给 responses（也可用 AGV_MODEL_WIRE）。

```

```powershell
# 验证结束后查看人读日志（也可在验证期间随时重算）
python scripts/journal.py --run output/runs/e2e-full-39 --journal output/runs/WALK-JOURNAL.txt

# 离线检查（提交时 hooks/pre-commit 会自动跑 ci.py --label pre-commit）
python scripts/ci.py
python scripts/ci.py --check cards
python scripts/ci.py --check tree

# 通过执行器验证一个图节点（需要一台攻击机、一个真实端点）
python scripts/run_node.py --node 14 --graph output/hongri7/json/Hongri7_v2.action_graph.json `
    --run-dir output/runs/lean-node14 --remote kali@192.168.52.128 `
    --password $env:AGV_SSH_PASSWORD --model deepseek-flash

# 一张卡的单个任务（脚本化动作，不调模型）
python scripts/run_lean_task.py --card pre.service_version --task tmp/task.json `
    --run-dir output/runs/lean-smoke --actions tmp/actions.json --remote kali@192.168.52.128

# 把整张图串起来跑（依赖顺序，逐节点；缺少所需会话或凭据时具名记录）
python scripts/run_plan.py --graph output/hongri7/json/Hongri7_v2.action_graph.json `
    --host-map data/inputs/hongri7/host_ip_map.csv --run-root output/runs/plan-1 `
    --remote kali@192.168.52.128 --password $env:AGV_SSH_PASSWORD --model deepseek-flash `
    --credentials $env:AGV_CREDENTIALS_FILE
```

## 凭据输入与跨运行引用

### 主机对账表的两个约定（部署数据，不是代码）

`--host-map` 的前两列是「逻辑名 → 现场地址」。另有两条可选约定，供需要它的部署写，不写也能跑：

* 第三列写这个逻辑名是什么性质的**位置**：`container`（或 `isolated`）表示常驻控制台无法持有的
  隔离位置 —— 进入它的那个入口本身就是承载，所以不从它往外迁会话；没写的一律当普通主机。
* 一行 `control,<地址>` 指出控制端。不写就要求 `--control <地址>` 显式给出：控制端是**角色**，
  不该靠某个靶场的机器名去猜。

`run_plan.py --credentials <私有 JSON 路径>` 优先读取 `credentials.<材料 symbol>`，兼容已有
`credentials.<图 user>` 显式绑定：`user` 是真实登录名，
`domain` / `realm` 是可选域，`secret` 是秘密材料，`mode` 是材料类型。图里的角色名与材料符号
不能用作登录名或口令。私有文件必须在仓库、`output/`、本次运行目录和被 carry 的运行目录之外；
传入路径即可，程序不复制秘密源。具体绑定规则见 [凭据供给](../docs/product/lean_credentials.md)。

产出材料的卡在完成消息中返回 `materials`；模型只见值占位符，由运行时核验来源调用和原文。
用 `--materials-dir <私有目录>` 指定验证后材料的保存位置，同样须在仓库及运行目录之外。
公共账本只保留私有引用、掩码引文和摘要；消费端收到按 `order` 排列的 `credential_candidates`，
1 是前序推导材料，2 是计划声明的外部材料；只存在一份时只给一份，两份均无则 `CREDENTIAL_MISSING`。

新运行加 `--carry-from <旧运行目录>`，会并行续接 `credentials.jsonl` 的两类私有引用和既有句柄；
外部材料仍需存在且与登记时一致。仅凭据可恢复不表示前置图节点已证明，也不改变会话探测和 ready 规则。
模型收到秘密占位符；请求中需要秘密时使用独立 argv 参数或 HTTP 数据值，不把占位符拼进复合字符串。

## 约定

* 相对路径以检出根为基准（`src/graph/paths.py`），从任何目录运行都一样。
* 工具与执行器的凭据只从环境变量或命令行参数进来，不写进日志。
* `output/` 与 `tmp/` 不入库；运行证据落 `output/runs/<名字>/`。
* 离线测试使用受跟踪输入，在测试临时目录生成所需产物，不依赖预先存在的运行目录。
* 新增、删除或迁移文件时，同步本页的目录文件清单与 [文件地图](../docs/file_tree.md)。
* 运行产物保留与清理遵循 [CONTRIBUTING.md](../CONTRIBUTING.md)；真机结论与离线检查分别记录。

用途表介绍人工入口；目录文件清单还包括辅助模块、PowerShell 脚本、hook 和其他随目录维护的文件。列入清单不表示该文件可以单独运行。

package_release.py: deterministic source release / --verify.

<!-- agv:file-list:start -->
```json
[
  "scripts/README.md",
  "scripts/check_delivery.py",
  "scripts/check_memory_postgres.py",
  "scripts/check_model_package.py",
  "scripts/check_recovery.py",
  "scripts/ci.py",
  "scripts/configure_hongri7_network.ps1",
  "scripts/ensure_docker.ps1",
  "scripts/generate_hongri7.ps1",
  "scripts/hooks/pre-commit",
  "scripts/install_git_hooks.py",
  "scripts/journal.py",
  "scripts/lab_round.py",
  "scripts/node_transcript.py",
  "scripts/package_release.py",
  "scripts/project_graph.py",
  "scripts/reclaim.py",
  "scripts/reclaim_hosts.py",
  "scripts/run_lean_node.py",
  "scripts/run_lean_task.py",
  "scripts/run_node.py",
  "scripts/run_plan.py",
  "scripts/session_manager.py"
]
```
<!-- agv:file-list:end -->
