---
name: pre-posix-path-access
description: 以指定身份只读检查目录是否存在，以及是否允许写入和进入，交付带来源与时刻的观测。适用：默认只读；需要写入探测时，探测对象属于本次创建并须按义务释放。检索关键词：POSIX目录访问权限检查、目录写入和遍历权限检查、POSIX目录可写可遍历检查
id: pre.posix_path_access
kind: recon
runs_at: position
delivers: ["evidence"]
inputs: {"target_host":{"from":"graph"},"path":{"from":"graph"},"subject":{"from":"graph"},"check_shape":{"from":"graph"},"write":{"from":"graph"},"session_ref":{"from":"runtime","optional":true},"namespace_ref":{"from":"runtime","optional":true},"mount_readonly":{"from":"runtime","optional":true}}
tools: ["cmd","code", "msf"]
---

# POSIX 目录存在性与写入、进入权限检查

## 何时用

仅检查指定身份的目录写入与进入权限，write 固定为真；纯存在、只读或其他对象语义不适用。默认只读，不创建文件、不改权限；写入探测变体仅能创建本次自己的可回收对象，并按义务释放。
须确认实际有效用户、主组、附加组，且支持按有效身份检查。target_host、path、subject、check_shape、write 取图；session_ref、namespace_ref、mount_readonly 取运行层，不得杜撰。工具说明：skills/_tooling/posix-shell.md。

## 怎么做

命令用本卡声明的工具面交给绑定位置：`position_speaks=shell` 用位置自己的 shell；`position_speaks=meterpreter` 仍提交 `{"tool":"cmd","cmd":"…"}`，由引擎包装并回收回显。不要改用 `execute -f <shell> -a "<命令行>"`：`Process NNNN created.` 没有命令输出，不能作查询证据。

在目标执行点组织单文件 Python 探针：绑定参数写入 params.json，以 python3 probe.py params.json 启动，输出一行 JSON；目标不能落盘或无兼容 Python 3 就报缺口，不把路径搬到控制器查。
固定只读样例；写入与进入权限分别按有效身份判断：

```python
import errno, json, os, stat, sys

params = json.loads(open(sys.argv[1], encoding="utf-8").read())
path = str(params.get("path") or "")
out = {"path": path}
try:
    st = os.stat(path)                  # follows symlinks: the object being checked
    out["resolved_path"] = os.path.realpath(path)
    out["st_dev"] = st.st_dev
    out["st_ino"] = st.st_ino
    if stat.S_ISDIR(st.st_mode):
        out["file_type"] = "dir"
    elif stat.S_ISREG(st.st_mode):
        out["file_type"] = "reg"
    else:
        out["file_type"] = "other"
except OSError as exc:
    out["stat_errno"] = errno.errorcode.get(exc.errno, "E%s" % exc.errno)
out["effective_uid"] = str(os.geteuid())
out["effective_gid"] = str(os.getegid())
out["supplementary_groups"] = [str(group) for group in os.getgroups()]
if os.access in getattr(os, "supports_effective_ids", set()):
    out["access_api"] = "effective_ids"
    out["write_access"] = os.access(path, os.W_OK, effective_ids=True)
    out["search_access"] = os.access(path, os.X_OK, effective_ids=True)
else:
    out["access_api"] = "unsupported"
print(json.dumps(out, sort_keys=True))
```

必须使用 os.access(..., effective_ids=True) 一类有效身份接口，test -w 会丢错误号，不能替代。

## 怎么判

- 成功：目录存在且确为目录，实际身份符合指定身份，写入和进入均允许，结果完整。
- 不满足：排除下列不确定情形后，明确不存在/不是目录，或写入、进入任一项明确不允许。
- 不确定：EACCES/EPERM 阻止检查、实际身份不符、有效身份接口不支持或结果缺项。

存在与不可访问分开；父目录不可进入、挂载只读等导致查不下去时不报不存在，stat_errno 原样保留。
符号链接以解析后对象为准：file_type、resolved_path、st_dev、st_ino 都对应解析结果；写入与进入分别判断，退出成功不抵消任一失败。
结论只对本次目录、身份与检查时刻成立；权限通过不保证后续写入成功，尤其网络文件系统，实际创建另行验证。
证据字段：call_id、observed_host、path、resolved_path、st_dev、st_ino、file_type、effective_uid、effective_gid、supplementary_groups、namespace_ref、write_access、search_access、stat_errno、access_api、mount_readonly。
本次调用的可核对引文仅证明观测，仍须按上述业务条件判断。

## 异常与恢复

- **只读边界**：不掩错误号，不顺手 touch/mkdir/chmod；本路由不得创建文件或改权限。
- **接口或身份缺口 ⇒ 不确定**：不支持有效身份、拿不到身份、错误号无法分类或解释器/模块不可用时记不确定，不换解释器或工具顶替；平台变体另按会话执行通道接入。
- **结果不完整 ⇒ 不确定**：查询失败、超时或重试均保留每次原始输出和错误；未完整取得结果就记不确定。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
