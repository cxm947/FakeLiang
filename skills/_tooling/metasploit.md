# metasploit / meterpreter —— 会话与内存内作业

## 这个工具能回答什么

本仓把 msf 当**会话账本**用，而不是当漏洞库用：

- 把已经拿到的通道**纳管**成受管会话，并交付可核对的会话引用（`session.msf_adopt_*`）。
- 在既有会话上跑**内存内**作业：例如加载 `kiwi` 扩展读 LSASS 登录会话缓存（`exploit.kiwi_lsass_dump`）。
- 会话迁移（把一个会话挪到另一个进程）并重新观察可用性（`session.msf_migrate`）。

## 调用形状

控制台按行下发，一次调用一条链；`meterpreter` 没有 shell 层，因此**没有 marker 可回显**，
新鲜度靠端点先把积压 drain 掉再读输出：

```text
sysinfo
load kiwi
creds_all
```

接管既有会话（三条路由只有「字节怎么走」不同，六步骨架一致）：

```text
量回连地址 -> 生成端点（控制台自带）-> 先架好接收器（脱离通道后台运行）
-> 把字节搬上去并启动 -> 等控制台确认新会话 -> 只读探针（getuid / sysinfo）
```

会话迁移后必须重新观察：

```text
migrate <pid>
getpid
sysinfo
getuid
```

## 输出怎么读

- 控制台 transcript 是**合并**输出、没有 marker：同一字段的**最后一次**读数才是迁移后的读数，
  所以重观察探针要放在序列尾部。
- 身份从 `Running as: <identity>` 一类行核对，两种写法（带不带 `[+]`）都要认。
- 扩展**已加载**的提示不是失败；`load` 只有在真出错时才算失败。
- 会话可用性是**接管后重新观察**出来的，不是接管动作本身推出来的。

## 已知坑

- **定宽表格不能按空白切**：凭据输出按表头列偏移取字段；LM 单元格为空时按空白分割会错移列。
- **banner 与结果不同步**：读窗口以输出静默为准，输出被截断时先回到读窗口，而不是换工具。
- **会话迁移会动目标进程关系**：属于改状态的动作，重观察是必需项，不是可选项。
- **产物可能是敏感材料**：内存作业的原始输出按敏感产物处理，落盘与引用都要带来源。

## 引用它的技能卡

- `exploit.kiwi_lsass_dump`、`exploit.comsvcs_minidump`、`exploit.pypykatz_parse` —— 凭据材料三条路。
- `session.msf_adopt_native` / `_web` / `_mount`、`session.msf_migrate` —— 纳管与迁移。
