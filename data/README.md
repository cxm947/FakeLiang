# 输入数据放这里

- `samples/`：S1、S2、S3 教学和回归样本。正式测试与日常演示共用这一份，不再在 tests 下复制一份 TXT。
- `samples/host_demo/`：完全虚构的双主机 P/TXT 和 IPv4 映射，用于[转换与还原演示](../docs/v1/host_identifiers.md)。TXT 来自本机断网 MulVAL 生成。
- `inputs/`：你之后新增的 TXT 可放这里。除占位文件外已加入 `.gitignore`，避免把靶场资料误提交。

历史规则夹具 `rule_templates.json` 保留在 `tests/fixtures/`；当前代码与测试未读取它，详见下方历史材料登记。

从项目根目录运行：

```powershell
python scripts/project_graph.py data/samples/S3.txt --json-only
python scripts/project_graph.py data/inputs/my_graph.txt --json-only
```

第二条需先放入你自己的文件。也可直接传外部 TXT 的绝对路径，不必复制到项目。

这些样本源自用户本地数据，可能包含账户材料；公开分享前需要脱敏。转换结果统一写入 `output/`，不写回输入目录。

## IP 预设样本

`inputs/ip_preset/` 是本机临时样本目录，当前已生成：

- `host_ip_map.csv`：原主机名到 `192.168.3.x` 的预设映射。
- `S1_ip.P`、`S2_ip.P`、`S3_ip.P`：把 P 文件中的主机项替换为带引号 IP，例如 `'192.168.3.10'`。
- `rules5_ip.P`：同一套映射后的规则文件。当前 `rules5.P` 里有 `dif(HOSTD, pc_1)` 这样的主机常量，规则文件不同步会改变 S1 推理结果。
- `S1_ip.txt`、`S2_ip.txt`、`S3_ip.txt`：用本机 MulVAL Docker 生成的 TXT，可直接交给现有转换器。

带点 IP 在 P 文件中用单引号包住；转换后的 JSON 会把 `target_host`、`source_host` 还原成普通 `192.168.3.x` 字符串。以后真实输入如果已经是 TXT，直接读取即可。

上述地址只是预设，原 P/TXT 不提供实际资产归属证据。当前最小转换器仅支持 IPv4；本机 MulVAL 导出器不能正确保留 IPv6 冒号。

## 历史材料与夹具

按结构治理基线 `d261f3d` 的受跟踪代码扫描，以下 24 个文件未发现现行 `src/`、`scripts/` 或 `tests/` 代码消费者；原位保留历史材料及其来源记录，不计入当前运行或测试输入。

| 文件 | 数量 | 保留用途 |
|---|---:|---|
| `attack/aliases.json`、`attack/techniques.json` | 2 | 冻结的 ATT&CK 来源与版本材料 |
| `migration/source_list.json`、`migration/records_sample.json`、`migration/live_readiness.json` | 3 | 旧迁移、就绪与指标工件 |
| `retrieval_suite/cards/*.json` | 10 | 旧检索验收语料 |
| `retrieval_suite/cases/RT-01.json` 至 `RT-08.json` | 8 | 旧检索验收案例 |
| [`tests/fixtures/rule_templates.json`](../tests/fixtures/rule_templates.json) | 1 | 旧规则夹具及来源指纹 |

现行样例 `samples/` 与可执行回放 `tests/replays/` 不属于上述登记范围。
