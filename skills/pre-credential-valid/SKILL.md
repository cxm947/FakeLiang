---
name: pre-credential-valid
description: 核对已有访问材料在指定目标与认证入口上的实际认证结果；区分尝试身份、认证身份及权限证据。
id: pre.credential_valid
kind: recon
runs_at: position
delivers: ["evidence"]
inputs: {"target_host":{"from":"graph"},"username":{"from":"runtime"},"secret_ref":{"from":"runtime"},"check_shape":{"from":"graph"},"domain":{"from":"runtime","optional":true},"expected_privilege":{"from":"graph","optional":true},"observed_privilege":{"from":"runtime","optional":true},"privilege_basis":{"from":"runtime","optional":true}}
---

# 已有访问材料在指定目标上的认证检查

## 何时用

核对指定已有材料能否按指定认证方式在指定目标建立要求的身份；不猜口令、不枚举账号，登录成功不等于管理权限或可复用会话。
目标、username、secret_ref、check_shape 取任务；domain 指认证命名空间，缺失不擅补域。secret_ref 是运行层材料引用，不是直接发给服务端的口令。材料表示、服务、入口和位置须能确定，缺项就报告，不猜协议与端口。
卡服务于被检查的 AND 步骤；when.technique 若声明指该步骤 job_id，当前未声明就留空。check_shape 只是类型；observed_privilege、privilege_basis 无本次证据关联时不作已确认权限。

## 怎么做

先对齐目标、账号命名空间、协议、材料表示。明文密码、NTLM 摘要和密钥不能互换；无匹配的已提供工具就报告不可用。
已绑定 SMB 入口且有 netexec 时，密码用密码参数、NTLM 用摘要参数，两者互斥，不前后都试；域/本地参数按已确认命名空间填写，不轮换域名、用户名形式或协议碰撞结果。
工具须能指向绑定入口；固定端口与任务不符不得静默改目标。域信息、密钥文件等只用运行层给定材料，不从其他账号、历史回执或示例补齐。
SSH 等路径须排查默认密钥、agent 中其他材料及旧连接复用；批处理模式不证明来源隔离。不能将成功归属于指定材料时，只能说连接或某身份可用，不能判这份材料有效。

使用允许的 cmd/tool 和引擎固定输出形状；一次一个认证动作，读回执再处理错误，不发数组、不批量轮换账号/目标/材料、不设猜测式重试。
认证可能产生审计、失败计数或临时会话，不能声称无副作用；会话登记与回收归运行层。
分清 attempted_principal 与 authenticated_principal：用户名回显不等于服务端接受，来宾、匿名、旧身份回退不算指定账号成功。保留认证阶段、服务端状态、实际身份原文；敏感值由运行层处理，不在公开结论复述材料。
若要求 expected_privilege，须另有本次身份的有效权限观察；只读身份只证明主体，不顺手创建服务、计划任务或改配置来制造权限证据。

## 怎么判

**finish.verdict 判断本卡要求的事实是否成立，不是查询是否完成。** 只用 pass / unsatisfied / uncertain；传输成功、查询完成、引文可核对都不能把明确的负事实变成 pass。 明确反证已成立时，不因仅成功才有的字段缺失改判 uncertain。

- **pass（成功）**：本次指定目标与入口明确接受材料绑定账号，原文及调用归属足以排除匿名、来宾、旧身份复用；有权限要求还须有本次同主体、同目标的权限证据。
- **unsatisfied（不满足）**：目标、入口、账号、材料均对应的服务端明确认证拒绝（如 STATUS_LOGON_FAILURE）否定本次认证，必须报 unsatisfied，不报 pass 或 fail。明确权限不足只否定权限条件，不写成口令错误。
- **uncertain（不确定）**：超时、工具失败、身份不明、材料来源无法归属、认证阶段不明或权限证据不足。登录后操作被拒不等于认证失败。

服务端认证拒绝是已执行认证的目标侧结果，区别于引擎拒绝派发或根本未执行；收到拒绝回执不等于要求的认证事实成立。
- 锁定、过期、策略拒绝按原文说明，区分“当前可登录”与“材料内容正确”，不可用不证明秘密值错误。
- 退出码 0、通用成功标记、用户名回显、孤立管理权限标签、完整执行标记，都不足以证明认证与权限事实。

用引擎 finish 形状交代账号、目标、认证与权限范围，逐字引用本次允许且已处理敏感值的回执；unknown、已 abandon、其他目标成功不补作证明。无支撑原文就写 uncertain。
