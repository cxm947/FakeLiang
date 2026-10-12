# lab_demo：第二个靶场的输入包（虚构）

这是**新靶场接入的参照物**：同样的四个文件、同样的命令形状，换一个靶场只需要换内容。
数据全是 RFC 5737 文档地址（`192.0.2.0/24`）与虚构主机名，不含任何真实环境信息。

| 文件 | 角色 | 谁读 |
| --- | --- | --- |
| `demo.action_graph.json` | V1 行动图（`schema_version=1.1.0`） | `scripts/run_agent.py --graph` |
| `assets.json` | 部署表（逻辑名 → 地址、发布端点） | 选择器 / 判定器（`--assets`） |
| `host_ip_map.csv` | 主机对账（观测名 → 地址） | `--host-map`、判定器 target 闸 |
| `run_context.demo.json` | 显式运行输入（凭据 + `provenance`；可选 `account_aliases` 别名，见契约 §2.4） | `--context` |

来源与再生成：

```bash
# 图：由虚构导出 data/samples/host_demo/demo.txt 现场生成（源文件在 ../host_demo/）
python scripts/project_graph.py data/samples/host_demo/demo.txt --host-map data/samples/lab_demo/host_ip_map.csv --output-dir output/lab_demo --json-only --force
# 产物 output/lab_demo/json/demo.action_graph.json 复制为本目录的 demo.action_graph.json
```

体检与干跑（不触网）：

```bash
python scripts/check_inputs.py --graph data/samples/lab_demo/demo.action_graph.json \
  --assets data/samples/lab_demo/assets.json --host-map data/samples/lab_demo/host_ip_map.csv \
  --context @data/samples/lab_demo/run_context.demo.json --control 192.0.2.10

python scripts/run_agent.py --graph data/samples/lab_demo/demo.action_graph.json \
  --run-dir output/runs/D38-labdemo-plan --assets data/samples/lab_demo/assets.json \
  --host-map data/samples/lab_demo/host_ip_map.csv \
  --context @data/samples/lab_demo/run_context.demo.json --control 192.0.2.10
```

预期读数：

* 体检 **0 error**：唯一一条 warn 是 `credential 'synthetic_user' carries the template value 'PLACEHOLDER'` —— 模板值本来就该报；
* 干跑能按部署表解析出每一步的目标地址（`host_a → 192.0.2.10:443`、`host_b → 192.0.2.11:22`），
  同时**如实报技能缺口**（`valid_accounts` / `remote_services_without_cve` 两个 case 在 `skills/index.json` 里 `candidates: 0`）。
  输入契约通、能力面缺——这两件事必须分开说。

契约与逐字段说明见 [运行输入契约](../../../docs/product/run_input_contract.md)。