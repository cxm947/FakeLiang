# 节点执行入口（v0.3）

完整数据约定见 [最小数据契约](runtime_data_contract.md)，S1 过程见 [大白话说明](workflow_plain_language.md)。

一次节点工作是前检查 → 动作 → 后检查 → 程序核对并保存。
前检查只针对当前直接 LEAF；全部必需 effects 获证才能成功，工具退出码不能代替判据。
有限补检查在 running 内进行。规则不足时才调用 Supervisor，其建议不能改变图或降低验收要求。
节点成功后另做会话准备；current.phase=session 表达此工作，不再增加归一化 ID 或队列。
中断先读 current 和已有 records，未知原调用先核对，不直接重跑。
