# redis-cli —— 未授权键值写入与回读

## 这个工具能回答什么

- **在没有鉴权的键值服务上，写进去的东西读得回来吗**（`exploit.redis_unauth_write` 的回读路由）。
- **一次写入能不能承载会话需要的材料**，读回证明后再把它变成一条真实的会话引用
  （`session.ssh_via_redis`）。

「命令里没写密码」**不等于**「这个实例没有鉴权」：未授权前提要单独核实。

## 调用形状

```sh
redis-cli -h <host> -p <port> SET <key> <value>
redis-cli -h <host> -p <port> GET <key>
```

可选的两格配置（只在确实需要落盘时用）与释放：

```sh
redis-cli -h <host> -p <port> CONFIG SET dir <target_dir>
redis-cli -h <host> -p <port> CONFIG SET dbfilename <file>
redis-cli -h <host> -p <port> SAVE
redis-cli -h <host> -p <port> DEL <key>
```

## 输出怎么读

- `SET` 回到 `OK` 只说明服务接受了这条命令，**不能单独让它成为结论**；结论要靠在同一次调用里
  `GET` 回来的值与写入值相等。
- `(nil)` 按**缺值**处理，不按空字符串处理。
- 回读值与写入值都必须在场且非空才能比较；缺一边就是「不确定」，不是「通过」也不是「不满足」。
- 解析只取 `GET` 的首个非空行并去掉首尾空白与引号：多行值、转义文本不在可信比较范围内。

## 已知坑

- **键可能已存在**：写入会覆盖同名键。用本次调用专用、无首尾空白的键，并在调用前核实不会覆盖。
- **`SAVE` 会落盘**：它写出数据库快照，可能覆盖同名文件；`CONFIG SET` 会改实例配置。
  这两条都是真实副作用，卡必须声明，还原要求要在运行层能证明。
- **`DEL` 不撤销落盘**：删掉键不等于把写出去的文件拿回来。
- **别猜填回读值**：回读与输入对不上就是不满足，改原值或猜读来「取得通过」是本仓明令禁止的。

## 引用它的技能卡

- `exploit.redis_unauth_write` —— 键值写入与同源回读。
- `session.ssh_via_redis` —— 用同一次写入承载会话材料，读回证明后交付会话引用。
