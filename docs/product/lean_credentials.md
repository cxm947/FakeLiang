# 凭据供给（022 / 023）

本页说明 `run_plan.py` 的凭据接缝；设计真源为 [022 规格](../../specs/022-lean-credentials/spec.md) 与 [023 规格](../../specs/023-derived-materials/spec.md)。旧运行输入文档中的凭据账本、别名桥和 `keep_material` 落盘方式不属于本页所述凭据流程。

## 两类私有来源

`--credentials` 指向外部私有 JSON。顶层 `credentials` 中先查计划声明的材料符号；兼容上一轮以图中 user 为键的显式条目绑定。条目用 `user` 指明真实登录名，`domain` 或 `realm` 指明可选域，`secret` 提供秘密材料，`mode` 声明类型。图事实 `getAccount(host,user,material,privilege)` 中角色和材料符号不能当作真实账号或口令。

`--materials-dir` 指向保存推导材料的私有目录；只消费外部材料时可省略，需要登记推导材料时必须提供。卡声明 `materials` 的六个字段和带命名 `value` 捕获组的 `secret_patterns`。后者只定位原始输出中的秘密跨度，不替模型解析账号。模型依据占位符化的账号区块推导 realm、user 和 kind，以完成消息中的 `materials` 返回结构化结果：

```json
{"materials":[{"realm":"<观察到的域或空字符串>","user":"<观察到的用户>","value":"<观察中的整值秘密占位符>","kind":"password","source_call":"<本次 call_id>","quote":"<含账号归属与该值占位符的连续原文>"}]}
```

`kind` 仅接受 `password` 或 `ntlm`。模型不得猜值、把符号当口令或拼接不同账号的证据；无可用材料则返回空列表并按证据给出结论。运行时核对声明字段、来源调用、原文、账号和值，在内存中恢复占位符；通过验证的具体值与原始引用保存到私有文件。公共账本保留来源种类、文件引用、掩码引文和材料摘要。

两类来源均须位于仓库、`output/`、本次运行目录以及被 carry 的运行目录之外。外部来源只读，推导来源只写入显式指定的私有目录；秘密不复制到公共运行目录或图中。移动、删除私有文件或改变被引用条目都会使引用不可恢复，须用当前材料重新证明、登记。

## 从成果到有序候选

1. 仅在节点被判为 `proved` 后登记其 `getAccount/4` 成果。OR 节点与消费者 `produced_by` 中的同一事实去重；提供私有来源本身不证明图事实成立。推导来源与外部来源可对同一事实分别登记。
2. `credentials.jsonl` 只保存图身份、主机绑定、来源与父引用、私有条目路径、掩码引文和材料摘要。实际秘密不进入 JSONL。元数据若与已知秘密冲突，以 `CREDENTIAL_METADATA_CONTAINS_SECRET` 拒绝，避免掩码破坏路径或摘要。
3. 消费节点派发前按图绑定选择每种来源唯一的一份记录，恢复到内存中的 `task.inputs.credential_candidates`：`{order:1, origin:"derived", credential_ref:{user,secret,domain,mode}}` 在前，`{order:2, origin:"external", credential_ref:{user,secret,domain,mode}}` 在后。外部候选对应计划声明的材料符号；只有一份时只提供该项并保留原 order。兼容输入 `task.inputs.credential_ref` 指向列表第一份。
4. 两份都没有以 `CREDENTIAL_MISSING` 具名拒绝。每种来源自身多匹配、来源主机映射陈旧、realm/user 冲突、私有引用缺失或被篡改仍独立具名拒绝；不靠降级到另一份掩盖坏引用。登记失败记入 `credential_error`，既有证明仍保留，需要凭据的消费者独立阻断。

允许同主机消费，或由直接 `getAccount(source,U,S,P)` 与 `hasAccount(target,U,S,P)` 建立跨主机绑定；用户名相同本身不能跨主机复用。`--carry-from <旧运行目录>` 只带凭据引用并保留来源与父引用；新进程从对应私有文件恢复材料。凭据 carry 与句柄 carry 各自运行。

消费卡明确先使用推导候选。只有本次认证响应的 `STATUS_LOGON_FAILURE`、`STATUS_WRONG_PASSWORD`、`STATUS_NO_SUCH_USER`、Windows 登录失败错误 1326 或可核对的域/主体冲突才支持判定候选不适用；不支持的材料类型可在执行前识别。超时、连接故障、工具错误或非零退出码不能证明口令错误，认证后的权限不足也不触发换材料。明确账号锁定立即停止。切换下一份由编排/模型依据证据决定，每次调用单独留证；运行层不新增自动重试。

## 模型与写盘边界

执行器的 `drive` 收集任务中命名秘密及卡声明的输出秘密；模型只见占位符。模型返回的嵌套请求逐值恢复整串 token，未知 token 或包含 token 的复合命令字符串在派发前具名拒绝。材料 `quote` 是引用核验字段，可含观察中的 token，不能拿来拼接命令。

summary、manifest、模型流水、事件与 call 产物都先掩码再写盘，覆盖短值、`materials.value` 及 Cookie / Authorization 等文本和结构化头部。输出引用摘要按实际掩码后的字节计算；原始观察保留在内存供验证，具体材料只按私有文件契约保存。内存判定保留原始状态值，避免秘密与 verdict 相同时改变 proved 判断。错误路径同样先掩码，不能先写明文再依赖结束时清扫。

## 实现接缝

| 位置 | 职责与边界 |
|---|---|
| `src/skills/lean.py` | 校验可选的成对 materials / secret_patterns 声明，不绑定账号 |
| `src/runtime/credentials.py` | 图绑定、两类来源引用、材料摘要、账本/carry 与按来源有序选择 |
| `scripts/run_plan.py` | proved 后登记；派发前注入候选；公共写盘前掩码 |
| `src/runtime/lean.py` / `scripts/run_lean_task.py` | 原始观察的秘密投影、模型完成协议核验及调用/结果/错误脱敏 |
| `skills/*/SKILL.md` | 生产卡规定字段与原文依据，消费卡规定顺序与可观察的不适用特征 |
| 会话、端点客户端与旧 adapter | 沿用既有职责，不承担本轮材料来源或候选选择 |

本轮不增加扫描、自动加密、新依赖或运行层重试。新增离线用例覆盖两份次序、两种单份、双空拒绝、不同图/账号/主机绑定、来源核验和短秘密/头部脱敏；按用户要求不运行测试，验收由用户执行。
