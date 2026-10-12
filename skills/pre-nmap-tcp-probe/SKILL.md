---
name: pre-nmap-tcp-probe
description: 核对从绑定执行位置到指定 TCP 端口能否建立连接；区分连接拒绝、未确认与服务身份，不扩大观察范围。
id: pre.nmap_tcp_probe
kind: recon
runs_at: position
delivers: ["evidence"]
inputs: {"target_host":{"from":"graph"},"port":{"from":"graph"},"protocol":{"from":"graph"},"source_ref":{"from":"runtime","optional":true}}
when: {"case":"direct_network_access"}
---

# 指定位置到指定 TCP 端口的连接检查

## 何时用

核对从绑定执行位置到指定目标、指定 TCP 端口的建连事实。hacl 等谓词须先核对绑定与判据；只有要求这条有向 TCP 建连事实时，本卡才足以回答，不推广为整机或网段可达。
目标、端口、协议来自 target_host、port、protocol；协议须为 TCP。source_ref 只指认运行层已绑定位置，不得改为控制端。缺目标、端口或来源绑定就报缺项，不猜默认端口、不扩扫。
运行层提供会话、平台、工具和回执范围；图中可达声明是待核对假设。卡挂在被检查的 AND 步骤上，when.technique 若有值指该步骤 job_id；当前未声明，不补扫描方法编号。

## 怎么做

按绑定位置的工具与会话选择一个允许动作；有 nmap 时使用单端口 TCP connect 检查，占位符取任务值：

~~~text
nmap --unprivileged -Pn -n -sT --reason -p {port} -oX - {target_host}
~~~

-Pn 跳过主机发现，-n 不解析名称。IPv6 使用工具对应参数，保持同一目标地址。缺 nmap 可用运行层提供的等价连接观察；无可用方法就报限制，不判端口关闭。
动作类别为 tool 或 cmd；shell 载体由引擎处理，不迁移会话、不建中继、不换主机。
一次答复只给一个动作，读完回执再继续；不发动作数组、不在单条命令枚举端口或重复探测。时限与资源预算沿用运行层，不另设等待阈值或重试次数。
只读取地址、协议、端口同时相符的 XML 记录，保留状态与原因原文；来源位置由调用记录核对，不能从输出主机名推定。
提示符、命令回显、历史扫描与不完整回执都不替代本次连接观察。

## 怎么判

**finish.verdict 判断本卡要求的事实是否成立，不是查询是否完成。** 只用 pass / unsatisfied / uncertain；传输成功、查询完成、引文可核对都不能把明确的负事实变成 pass。 明确反证已成立时，不因仅成功才有的字段缺失改判 uncertain。

- **pass（成功）**：正确位置上的本次 TCP connect 明确显示指定端口 open；只支持连接可建立，不证明服务、认证权限或可复用会话。
- **unsatisfied（不满足）**：绑定来源、目标地址、TCP 协议和端口相符，本次端口明确 closed 且原文记录连接拒绝（如 conn-refused），必须报 unsatisfied，不报 pass 或 fail。只否定所需建连，不扩写为整条网络不可达或主机不存在。
- **uncertain（不确定）**：filtered、超时、输出缺失/不完整、来源不符、工具错误或无法定位指定端口；未见成功不等于网络断开。

已执行连接得到的明确拒绝是目标侧反证，区别于引擎拒绝派发或根本未执行；不能因探测完成而把连接未建立判为 pass。
- -Pn 下的 Host is up 不单独证明主机响应；按端口号给出的服务名不证明身份。退出码 0、执行完成、SUCCESS 都不是建连证据。

用引擎 finish 形状说明前提、结论与覆盖范围。引文逐字取本次允许回执并带调用归属；unknown、已 abandon 的来源不作证明。没有原文就写 uncertain。
