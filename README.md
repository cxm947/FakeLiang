# 攻击图自动验证 Agent

读入一张攻击图（MulVAL TXT 或已编译 JSON）和主机-IP 映射表，按技能卡驱动大模型，在靶场上逐步验证图上每条路径：
每一步先做前期验证，再执行利用，最后核对产出事实，全程落盘、可逐发复核。

结论只认本轮可核对的证据 —— 命令是否执行完毕、模型报告了什么、整图验收是否成立，各按自己的判据解释。

## 运行需要

- Windows + CPython 3.12（本项目按 3.12 验收）
- 一台可 SSH 的 Kali，且 Metasploit RPC 可达
- 靶场主机与路由，需与攻击图一致
- 模型 API key（OpenAI 兼容端点，随包不提供）
- Graphviz：图编译默认还出 DOT/PDF，只要 JSON 就加 `--json-only`

## 安装

```powershell
py -3.12 -m venv .venv312
.\.venv312\Scripts\python.exe -m pip install -r requirements.txt
.\.venv312\Scripts\python.exe -m pip install -e .
```

`requirements.txt` 是运行、靶场和离线验收的全部直接依赖；`-e .` 装上本项目本身，`agv-project`、
`agv-visualize` 和 `python -m agents.*` 这类入口都来自它。

## 跑一轮

```powershell
# 1) 把攻击图编译成运行用的 JSON
.\.venv312\Scripts\python.exe scripts\project_graph.py data\inputs\hongri7\Hongri7_v2.txt --output-dir output\hongri7

# 2) 端到端跑图（示例参数，按自己的靶场替换）
.\.venv312\Scripts\python.exe scripts\run_plan.py `
  --graph data\inputs\hongri7\Hongri7_v2.txt `
  --graph-assets data\inputs\hongri7\assets.json `
  --host-map data\inputs\hongri7\host_ip_map.csv `
  --run-root output\runs\demo `
  --remote kali@<kali-ip> --password <kali-password> `
  --control <kali-ip> --msf-rpc msf:<rpc-password>@<kali-ip>:55553 `
  --model deepseek-flash --model-base-url <endpoint> --model-wire chat
```

模型 key 从 `AGV_MODEL_API_KEY` 读（或用 `--model-api-key-env` 指定别的变量名）；凭据文件与材料目录放在仓库外。

单个节点/单张卡也可以直接跑：`run_node.py`、`run_lean_task.py`；会话管理、资源回收、人读日志、模型转录分别是
`session_manager.py`、`reclaim.py`、`journal.py`、`node_transcript.py`。

## 离线检查

```powershell
.\.venv312\Scripts\python.exe -m pytest -q
.\.venv312\Scripts\python.exe scripts\ci.py
```

三闸＝测试、技能卡检查、文件地图检查，都不连靶场、不调模型。

离线预览装配好的提示词（不调模型）：

```powershell
.\.venv312\Scripts\python.exe -X utf8 -m agents.prompting.preview
```

## 目录

- `src/` 图编译、运行层、三个 agent（规划 / 执行 / 验证）、会话与证据
- `skills/` 技能卡：每张卡声明适用条件、输入与判据
- `scripts/` 命令行入口（另有 `agv-project`、`agv-visualize` 两个控制台命令）
- `tests/` 离线测试与夹具
- `docs/` 设计与产品文档

入口开关见 `scripts/README.md`，改动与验收规则见 `CONTRIBUTING.md`，文件职责见 `docs/file_tree.md`。

## 不包含

运行历史与产物（`output/`）、临时文件（`tmp/`）、私有凭据与材料、靶场镜像、模型密钥。

## 发布包：从干净机器开始

源提交：fbf9de451d446c5d81217f2fdfe2508f837cadb1。发布验收使用 Python 3.12 (Windows x64)；pyproject 的 >=3.10 是元数据下限。Git 用于 tree 闸。

本包安装（锁文件仅适用 Windows AMD64 / CPython 3.12，不是完整离线轮子库）：

```powershell
py -3.12 -m venv .venv312
.\.venv312\Scripts\python.exe -m pip install --require-hashes --find-links requirements/wheels -r requirements/runtime-win-py312.lock
.\.venv312\Scripts\python.exe -m pip install --find-links requirements/wheels ".[test,lab,rpc,native]"
```

逐步验收命令见上面的「离线检查」。

离线验收所需的 Hongri7 夹具随本包提供：data/inputs/hongri7/ 的三份输入，以及 tests/fixtures/hongri7/reference.action_graph.json 基准图；字节哈希记录在 tests/fixtures/hongri7/manifest.json，无需另行索取。本包不含 run 历史，因此核对引用产物的用例会合理跳过，其余用例应全绿。

未包含：运行日志与历史产物、output/、tmp/、build/、虚拟环境与缓存、密钥与私有配置、靶场镜像、specs/、IO 历史协议、旧实验与迁移数据。tests/、AGENTS.md 和少量历史文档为原验收保留。逐文件去留与摘要见 RELEASE-MANIFEST.json。
