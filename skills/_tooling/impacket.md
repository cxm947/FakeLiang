# impacket —— Windows 远程管理与服务控制

## 这个工具能回答什么

impacket 是一组协议的 Python 实现，本仓用到的是它的三个面：

- **远程执行**：经服务创建（`smbexec` / `psexec`）或经主机管理接口（`wmiexec`）在目标上跑一条命令，
  把回显带回来（`exploit.impacket_psexec_cmd`）。
- **服务控制端点**：最小代价地问一句「这个端点通不通、我这些权限够不够」（`pre.impacket_scm_query`）。
- **凭据形态**：明文口令与 NTLM 哈希走不同的参数，工具用法不同，卡的判据也不同。

## 调用形状

服务创建式远程执行（同一工具的脚本名是 `psexec.py`，命令名视安装方式为 `impacket-psexec` 或
`psexec.py`）：

```sh
impacket-psexec [-hashes <LMHASH>:<NTHASH>] [-target-ip <ip>] <domain>/<user>[:<password>]@<host> "<command>"
```

主机管理接口式远程执行：

```sh
impacket-wmiexec '<domain>/<user>:<password>@<host>' "<command>"
```

哈希凭据（口令那一格换成哈希，参数名跟着换）：

```sh
impacket-psexec -hashes ':<nthash>' '<domain>/<user>@<host>' 'cmd /c whoami'
```

服务控制端点的最小连接测试：

```sh
impacket-scmr '<domain>/<user>:<password>@<host>' '<service>'
```

## 输出怎么读

- 回显、错误、身份三条分开读：**命令跑出来了**不等于**以目标身份跑出来了**，身份要单独观察。
- `psexec` 会往目标上传一个服务可执行体并创建/删除服务；`wmiexec` 不留服务，但会在 WMI 里留痕。
  这条差别决定副作用列与还原规格，不决定「哪个更好」。
- `scmr` 的两种坏结果要分开：**端点不可用**（协议/端口/认证被挡）与**权限不足**（连上了但被拒）。
  这两句话对应两种不同的后续，不能合并成一句「失败」。
- 哈希与明文是两种材料：拿哈希机器去套口令参数只会得到认证失败，那不是「凭据无效」。

## 已知坑

- **服务创建式执行会改目标状态**：上传与建服务是真实的副作用，卡必须声明并给出还原/清理要求。
- **回显可能滞后于连接**：会话建立失败但命令已下发的情形存在，读输出要等静默，不要按时间猜。
- **凭据材料不进提示词**：`cred_ref` 这类入参只以占位符出现在装配输入里，运行层在执行时替换真值。
- **别用 exec 家族去「试一下」**：本仓的候选装配只接受卡声明的输入与形状，越界命令拿不到证据。

## 引用它的技能卡

- `exploit.impacket_psexec_cmd` —— 服务创建式/主机管理式远程执行，含会话交付变体。
- `pre.impacket_scm_query` —— 服务控制端点的只读可达性与权限观察。
