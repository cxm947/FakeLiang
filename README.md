<p align="center">
  <img src="docs/assets/readme/banner.svg" alt="FakeLiang：从攻击图路径到可核对证据，Planner、Executor 与 Verifier 协作" width="900">
</p>

<h1 align="center">攻击图自动验证 Agent</h1>

<p align="center">
  <strong>沿图推进，逐步验证，让每个结论都有据可查。</strong><br>
  MulVAL / JSON 攻击图 · 技能卡驱动 · 多 Agent 协作 · 调用证据落盘
</p>

<p align="center">
  <a href="#requirements"><img src="docs/assets/readme/python.svg" alt="验收环境 Python 3.12" height="32"></a>
  <a href="#workflow"><img src="docs/assets/readme/multi-agent.svg" alt="Planner、Executor、Verifier 多 Agent 协作" height="32"></a>
  <a href="#quick-start"><img src="docs/assets/readme/graph-input.svg" alt="支持 MulVAL TXT 与已编译 JSON" height="32"></a>
  <a href="#evidence"><img src="docs/assets/readme/evidence.svg" alt="按调用保存可核对证据" height="32"></a>
</p>

<p align="center">
  <a href="#overview">🧭 项目简介</a> &nbsp;·&nbsp;
  <a href="#quick-start">🚀 快速开始</a> &nbsp;·&nbsp;
  <a href="#evidence">🧾 运行产物</a> &nbsp;·&nbsp;
  <a href="#checks">🧪 离线检查</a> &nbsp;·&nbsp;
  <a href="#docs">📚 文档导航</a>
</p>

---

<a id="overview"></a>

## 🧭 FakeLiang 是什么？

FakeLiang 读入一张**已有攻击图**（MulVAL TXT 或已编译 JSON）、资产信息与主机-IP 映射表，按技能卡驱动大模型，在靶场上逐节点验证图中的路径：**先做前期验证，再执行利用，最后核对产出事实**，全程保存可复核的调用记录。

当前聚焦于确定性攻击图的路径验证。结论以本轮证据为准：命令是否执行完毕、模型报告了什么、节点事实是否成立、整图是否通过，分别按各自的判据解释。

| 核心能力 | 具体做什么 |
| :--- | :--- |
| 🗺️ **图驱动推进** | 从图中的节点、依赖与目标事实出发，结合已有结果安排下一步 |
| 🧩 **技能卡驱动** | 每张卡提供适用条件、输入、操作知识与判据，供执行过程使用 |
| 🤝 **多 Agent 协作** | 规划、执行、核验各有职责，运行时负责依赖、会话和调用记录 |
| 🧾 **证据可追溯** | 保存调用参数、标准输出、错误输出与模型转录，支持逐步复核 |

<a id="workflow"></a>

## 🔄 三个 Agent，怎样协作？

**攻击图与映射 → 规划节点 → 前期验证 → 执行 → 事实核验 → 登记收获 → 下一节点**

| 角色 | 职责 |
| :--- | :--- |
| 🗺️ **Planner · 规划** | 读取图、已有结果与上一节点状态，选择下一节点；运行时核对依赖条件 |
| ⚙️ **Executor · 执行** | 按技能卡完成节点任务，逐步提交动作，并记录每次调用的回执 |
| 🔍 **Verifier · 核验** | 核对本轮调用证据、前置事实与待产出事实，分别保留模型判断和机器判据 |

遇到阻断、未满足或不确定的结果时，按实际状态记录。调用完成本身不等于节点已被证明，历史运行通过也不自动成为当前修订的验收结论。

<a id="requirements"></a>

## 🧰 运行前需要准备什么？

| 项目 | 要求 |
| :--- | :--- |
| **控制端** | Windows + CPython 3.12；发布验收环境为 Windows x64 / Python 3.12 |
| **执行端** | 一台可 SSH 的 Kali，且 Metasploit RPC 可达 |
| **靶场与输入** | 主机、路由、资产信息与主机-IP 映射需和攻击图一致 |
| **模型服务** | OpenAI 兼容端点与自己的 API key |
| **图形输出** | 默认输出 JSON、DOT 与 PDF；PDF 需要 Graphviz。使用 `--json-only` 可跳过 PDF，仍保留 JSON / DOT |
| **离线检查** | Git 用于核对文件地图，测试依赖随 `requirements.txt` 安装 |

`pyproject.toml` 中的 `>=3.10` 是包元数据下限；本项目的发布验收口径仍是 **Python 3.12 / Windows**。

<a id="quick-start"></a>

## 🚀 快速开始

### 1 · 获取项目并安装

在 PowerShell 中执行：

```powershell
git clone https://github.com/cxm947/FakeLiang.git
cd FakeLiang
py -3.12 -m venv .venv312
.\.venv312\Scripts\python.exe -m pip install -r requirements.txt
.\.venv312\Scripts\python.exe -m pip install -e .
```

[`requirements.txt`](requirements.txt) 包含运行、靶场和离线验收的全部直接依赖。`-e .` 安装本项目自身，`agv-project`、`agv-visualize` 与 `python -m agents.*` 等入口由它提供。

### 2 · 准备模型与图输入

模型 key 默认从 `AGV_MODEL_API_KEY` 读取，也可用 `--model-api-key-env` 指定其他变量名：

```powershell
$env:AGV_MODEL_API_KEY = "<your-model-api-key>"
```

示例使用仓库自带的 [Hongri7 输入](data/inputs/hongri7/)：

| 输入 | 文件 |
| :--- | :--- |
| 攻击图 | [`Hongri7_v2.txt`](data/inputs/hongri7/Hongri7_v2.txt) |
| 资产信息 | [`assets.json`](data/inputs/hongri7/assets.json) |
| 主机-IP 映射 | [`host_ip_map.csv`](data/inputs/hongri7/host_ip_map.csv) |

实际运行前，按自己的部署核对这三份输入。凭据文件与私有材料目录放在仓库外；供给方式见[凭据说明](docs/product/lean_credentials.md)。

### 3 · 编译预览与运行

图编译可单独用于预览；整图入口也支持直接读取 TXT 并现场编译，无需先手动编译。

```powershell
# 1) 可选：预览图编译结果（JSON / DOT / PDF）
.\.venv312\Scripts\python.exe scripts\project_graph.py data\inputs\hongri7\Hongri7_v2.txt --output-dir output\hongri7

# 2) 端到端跑图（可直接读取 TXT；示例参数按自己的靶场替换）
.\.venv312\Scripts\python.exe scripts\run_plan.py `
  --graph data\inputs\hongri7\Hongri7_v2.txt `
  --graph-assets data\inputs\hongri7\assets.json `
  --host-map data\inputs\hongri7\host_ip_map.csv `
  --run-root output\runs\demo `
  --remote kali@<kali-ip> --password <kali-password> `
  --control <kali-ip> --msf-rpc msf:<rpc-password>@<kali-ip>:55553 `
  --model deepseek-flash --model-base-url <endpoint> --model-wire chat
```

将示例中的 Kali 地址、密码、RPC 信息和模型端点替换为本轮配置。完整参数与其他入口见 [scripts/README.md](scripts/README.md)。

<a id="evidence"></a>

## 🧾 跑完以后，看哪些结果？

运行结果保存在 `--run-root` 指定的目录。通常先看整轮摘要，再沿节点和调用记录核对证据。

| 产物 | 用途 |
| :--- | :--- |
| `plan_result.json` | 查看节点状态、阻断与未尝试项、终点事实和整轮判定 |
| `walk.txt` | 阅读按步骤整理的运行过程 |
| `planner.jsonl` | 追溯规划选择与规划调用记录 |
| `model_outputs.md` | 查看脱敏后的逐节点模型转录 |
| 节点目录中的 `calls/<call_id>/` | 核对该次调用的 `call.json`、`stdout.txt` 与 `stderr.txt` |
| 节点目录中的 `events.jsonl` | 追溯节点事件 |
| `harvest.jsonl` | 查看会话、凭据引用与产物的统一收获记录 |

判读结果时，将**执行回执、模型结论、事实证据与整图判定**分别核对。

<a id="checks"></a>

## 🧪 离线检查

在仓库根目录执行：

```powershell
.\.venv312\Scripts\python.exe -m pytest -q
.\.venv312\Scripts\python.exe scripts\ci.py
```

`scripts/ci.py` 包含三项检查：**测试、技能卡检查、文件地图检查**，均不连接靶场、不调用模型。

离线预览装配好的提示词：

```powershell
.\.venv312\Scripts\python.exe -X utf8 -m agents.prompting.preview
```

<a id="docs"></a>

## 📚 按任务找到入口

| 你想做什么 | 阅读入口 |
| :--- | :--- |
| 了解参数、整图运行与各类命令 | [脚本说明](scripts/README.md) |
| 运行单个节点或单张技能卡 | [`run_node.py`](scripts/run_node.py) · [`run_lean_task.py`](scripts/run_lean_task.py) |
| 管理会话与回收资源 | [`session_manager.py`](scripts/session_manager.py) · [`reclaim.py`](scripts/reclaim.py) |
| 阅读日志与模型转录 | [`journal.py`](scripts/journal.py) · [`node_transcript.py`](scripts/node_transcript.py) |
| 了解现行说明、设计和历史记录 | [产品文档导航](docs/product/README.md) |
| 查阅技能卡约定 | [技能卡说明](docs/product/skill_card_spec.md) · [技能卡目录](skills/) |
| 查文件职责或参与修改 | [文件地图](docs/file_tree.md) · [贡献约定](CONTRIBUTING.md) |

### 🗂️ 目录速览

| 目录 | 内容 |
| :--- | :--- |
| [`src/`](src/) | 图编译、运行层、Planner / Executor / Verifier、会话与证据 |
| [`skills/`](skills/) | 技能卡正文、机器描述与随卡资源 |
| [`scripts/`](scripts/) | 命令行入口与离线检查 |
| [`data/`](data/) | 图输入、映射与示例数据 |
| [`tests/`](tests/) | 离线测试与夹具 |
| [`docs/`](docs/) | 现行说明、设计文档、历史记录与文件地图 |
| [`requirements/`](requirements/) | 环境约束、发布锁文件与随包 wheel |

<a id="release"></a>

## 📦 发布包与复现说明

仓库提供代码、技能卡与离线验收输入；运行历史、私有凭据、模型密钥和靶场镜像需另行准备。

<details>
<summary><strong>展开：干净机器安装、夹具与发布范围</strong></summary>

原发布包源提交：`fbf9de451d446c5d81217f2fdfe2508f837cadb1`。发布验收使用 **Python 3.12 / Windows x64**，Git 用于文件地图检查。

锁文件仅适用于 **Windows AMD64 / CPython 3.12**，随包 wheel 不是完整离线轮子库：

```powershell
py -3.12 -m venv .venv312
.\.venv312\Scripts\python.exe -m pip install --require-hashes --find-links requirements/wheels -r requirements/runtime-win-py312.lock
.\.venv312\Scripts\python.exe -m pip install --find-links requirements/wheels ".[test,lab,rpc,native]"
```

逐步验收命令见上面的[离线检查](#checks)。

Hongri7 离线夹具已随包提供：

- [`data/inputs/hongri7/`](data/inputs/hongri7/) 中的三份输入。
- [`reference.action_graph.json`](tests/fixtures/hongri7/reference.action_graph.json) 基准图。
- [`manifest.json`](tests/fixtures/hongri7/manifest.json) 中的字节哈希。

本包不含 run 历史，因此核对历史引用产物的用例会合理跳过，其余用例应通过；实际结果以对应修订的检查记录为准。

发布包未包含：运行日志与历史产物、`output/`、`tmp/`、`build/`、虚拟环境与缓存、密钥与私有配置、靶场镜像、`specs/`、IO 历史协议、旧实验与迁移数据。`tests/`、`AGENTS.md` 和少量历史文档为原验收保留。

原发布快照的逐文件去留与摘要见 [RELEASE-MANIFEST.json](RELEASE-MANIFEST.json)，当前跟踪文件见[文件地图](docs/file_tree.md)。

</details>

---

<p align="center">
  <strong>从一张攻击图，到一份可核对的验证记录。</strong><br>
  <a href="#quick-start">开始运行 →</a> &nbsp;·&nbsp; <a href="docs/product/README.md">深入了解设计 →</a>
</p>
