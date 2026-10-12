# 第一版真实目标：红日 7

用户指定目标为 [红日靶场 7](https://www.cnblogs.com/hellobao/articles/17247190.html)。
原 S1/S2/S3 保留作为图解析和逻辑测试样本，不再把 S1 当作该靶场的事实描述。

> 时点注记：本文写于 V1 建模阶段（2026-09-09/10），文内「当前 / 后续」是当时的快照；
> 后续进展以 [decisions](../decisions.md) 与 [实机验证记录](validation_runs.md) 为准。

本轮产出与待讨论限制见 `data/inputs/hongri7/MODEL_NOTES.md`（本机建模笔记，不进 git）。
输入是原规则 rules5.P 的字节快照和两份事实 .P；已用 Mulval2 生成 TXT，再进入现有 V1。
规则、V1 Schema 和核心转换器保持不变。

当前解决了 host 与多 IP 的分离、容器独立主体及 isDocker 父子关系。
本机部署证据已经补进资产映射：Web1:81 实测转到 Web2:8000，再到容器 172.17.0.2:80；PC1 内存证据支持 PC1/OA 的存在。（建模时 PC1 网络不可达，故当时未把本机 HTTP 验收写成已完成；部署校准后 PC1 已可达，相关实机验证见[实机验证记录](validation_runs.md)。）
当时未结的三项差异后来各自定案：容器细链在主图里压成 `container_escape` 一步、不声称等价复刻中间阶段（见[大白话说明](hongri7_attack_graph_plain.md)）；Windows SMB 分类由 v2 规则库表达（`Hongri7_v2.P` + `rules5_v2.P` 用 `windowsCredentialRemoteExecution` 表达真实 smb/tcp/445，不再借 `winrm` 服务名）；防火墙凭据依赖在 D32-h 把凭据前提补进 `rules5_v2.P`。
生成图证明的是规则推理可运行，不等于实机验证；实机侧进展见[实机验证记录](validation_runs.md)。

后续真实能力开发和实验应以定案后的红日 7 数据为基线；现有模拟 S1 仍可用于三表与调度内核的第一轮测试。
