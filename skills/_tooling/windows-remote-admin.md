# Windows 远程管理面 —— wmic / WinRM / PowerShell

## 这个工具能回答什么

Windows 的三种「远程问一句」通道，本仓按现场有没有会话、有没有凭据来选：

- **就地 PowerShell**：已经在这台机器上有执行通道时，直接查（`pre.cim_process_info`、
  `pre.netsecurity_firewall_state` 的就地路由）。
- **WinRM（`5985`/`5986`）**：有凭据、没有会话时的只读查询入口。
- **wmic / WMI（`135` 加动态端口）**：老系统上仍在用的进程与防御状态入口
  （`exploit.wmic_remote_cmd`、`exploit.wmi_firewall_off`）。

三者回答的都是**观测**；改状态的动作（关防火墙）属于技能卡，不属于这一页。

## 调用形状

进程与属主（CIM 一步投影，压缩 JSON 出流）：

```powershell
Get-CimInstance -ClassName Win32_Process -Filter "Name='lsass.exe'" |
  Select-Object -First 1
```

防御状态（一次读三档配置与活动档）：

```powershell
Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled
Get-NetConnectionProfile
```

老系统（PowerShell 2.0、没有 CIM cmdlet）用 WMI 等价物：

```powershell
Get-WmiObject Win32_Process -Filter "Name='lsass.exe'"
```

```bat
wmic /node:<host> /user:<user> /password:<password> process where name='lsass.exe' get ProcessId,ExecutablePath
```

## 输出怎么读

- **JSON 一律经 `[Console]::Out.Write` 原样出流**：默认格式化器会按控制台宽度折断长行，被折断的
  JSON 解析不出来（实机上量到过 80 列折断）。
- 进程查询要的是「**这一个**对象的投影」：进程号、创建时间、可执行路径、属主 SID。字段少而准，
  好过把整个对象倒出来。
- 防御状态要**如实报完整性**：活动档读不到时是「读不全」，不是「已关闭」。
- 远程通道上的**身份**要单独观察：`whoami` 的结果决定这次读到的是不是你以为的那个人看到的。

## 已知坑

- **WinRM 与 WMI 的可用性互不等价**：一个通不代表另一个通，两个都要单独观察。
- **策略存储要指明**：`ActiveStore` 与 `PersistentStore` 可能不一致，看的是哪一个要说清楚。
- **老系统缺 CIM**：`Get-CimInstance` 不存在时退 WMI，而不是把失败读成「没有这个进程」。
- **动态端口**：WMI 依赖 `135` 之后的高位端口，只测 `135` 会得出错误的可用性结论。

## 引用它的技能卡

- `pre.cim_process_info` —— 进程与服务信息（就地 / 经凭据远程两条路由）。
- `pre.netsecurity_firewall_state` —— 防御配置只读查询。
- `exploit.wmi_firewall_off`、`exploit.wmic_remote_cmd` —— 经管理共享/WMI 改状态与远程命令。
