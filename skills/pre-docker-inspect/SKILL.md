---
name: pre-docker-inspect
description: 在一台已绑定 daemon 的宿主上只读查询容器对象，证明宿主与指定容器的归属关系。适用：优先就地观察；只能经端点观察时须注明位置差异。检索关键词：Docker容器归属核验、Docker容器所属宿主查询、Docker容器宿主关系核验
id: pre.docker_inspect
kind: recon
runs_at: position
delivers: ["evidence"]
inputs: {"target_host":{"from":"graph"},"container_id":{"from":"runtime"},"check_shape":{"from":"graph"},"container_ref":{"from":"graph","optional":true},"daemon_context":{"from":"runtime","optional":true},"session_ref":{"from":"runtime","optional":true},"daemon_host_binding_ref":{"from":"runtime","optional":true},"daemon_aligned":{"from":"runtime","optional":true}}
tools: ["cmd","code", "msf"]
---

# Docker 容器归属查询

## 何时用

只读证明指定宿主与指定容器的归属；不启动、不进入、不挂载容器，不读特权位、挂载、安全策略或环境变量。名称匹配、容器地址、running 状态都不能替代归属证据。
container_id 须为已绑定完整稳定 ID；daemon 与宿主须已独立对齐，daemon_context 是 CLI context 名，只定位入口。target_host、check_shape、container_ref 取图；container_id、daemon_context、session_ref、daemon_host_binding_ref、daemon_aligned 取运行层，不得杜撰。
有宿主执行通道就地优先；只能从服务端点观察时注明位置差异，所见属于该端点所在宿主。session_ref 缺省为直达 daemon 通道。工具说明：skills/_tooling/docker-cli.md。

## 怎么做

命令用本卡声明的工具面交给绑定位置：`position_speaks=shell` 用位置自己的 shell；`position_speaks=meterpreter` 仍提交 `{"tool":"cmd","cmd":"…"}`，由引擎包装并回收回显。不要改用 `execute -f <shell> -a "<命令行>"`：`Process NNNN created.` 没有命令输出，不能作查询证据。

固定只读查询，只投影 Id、Name，并记录对象类型，其余字段丢弃：

```sh
docker --context <daemon_context> inspect --type container <container_id>
```

不得省略 --type，不用名称、别名或短 ID 代替完整 ID；不改用 start/exec/mount，不把查询成功写成容器正在运行。原始 stdout 随调用留存。
hostname 可改名，不能当容器身份；已有 hostname 与 cgroup 路径都留存，后者更可靠，仍不代替完整 ID 和 daemon 归属。

## 怎么判

**finish.verdict 判断本卡要求的事实是否成立，不是查询是否完成。** 只用 pass / unsatisfied / uncertain；传输成功、查询完成、引文可核对都不能把明确的负事实变成 pass。 明确反证已成立时，不因仅成功才有的字段缺失改判 uncertain。

- **pass（成功）**：daemon 已独立对齐预期宿主，对象类型为 container，Id 等于绑定完整 ID（docker_relation_matches）。
- **unsatisfied（不满足）**：正确 daemon、查询范围和权限完整时，对精确完整 ID 得到权威不存在（如 inspect_status=NO_SUCH_CONTAINER）；即使查询完整结束也必须报 unsatisfied。
- **uncertain（不确定）**：daemon 错误/未知、归属证据缺失、权限拒绝、仅名称匹配、绑定冲突或连接失败；问不到不等于不存在，缺证据不转 false。

证据字段：call_id、observed_host、daemon_ref、daemon_host_binding_ref、container_id、container_name、object_type、inspect_status。
本次调用的可核对引文仅证明观测，仍须按上述业务条件判断。

## 异常与恢复

- **查询失败、超时或重试**：保留每次原始输出与错误；不换 daemon、不重试写操作、不绕第二种查询方式。是否重试或换方法交编排。
- **归属证据缺失 ⇒ 不确定**：缺 daemon_host_binding_ref 时整卡不确定，不许拿 inspect 成功补足关系证明。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
