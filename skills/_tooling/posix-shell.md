# POSIX shell —— 身份、文件与存在性

## 这个工具能回答什么

shell 不是「一个工具」，而是本仓最常用的一组**只读原语**：

- **这条通道上我是谁**（`pre.session_identity`、`post.identity`）。
- **某个程序在不在**（`pre.tool_present`）。
- **某个路径在不在、能不能写、能不能进入**（`pre.posix_path_access`、`post.file_present`）。
- **通道还活着吗**（`post.channel_echo`：标记回声）。

## 调用形状

身份与宿主（marker 分段，便于程序切块读）：

```sh
echo <marker>user ; id -un ; echo <marker>host ; hostname
```

工具存在性（POSIX 只认字面命令名）：

```sh
command -v <tool>
```

```bat
where.exe <tool>
```

文件状态与摘要：

```sh
ls -l <path> && stat -c '%s' <path> && sha256sum <path>
```

## 输出怎么读

- **身份要分两层**：内核给的 `uid/gid` 与规范化后的名字可能对不上（容器、域映射），两个都记。
  `id -un` 只给名字，`id` 才同时给数字与附加组。
- **存在性有三种答案**：存在、不存在、**平台不适用**。把后两种混成一种，会把「这台机器上没这个
  工具」误读成「这个方法不适用」。
- `os.access` 这类判定按**有效身份**算，不是按拥有者；比较时要用同一个身份基准。
- 写入探测只允许创建**本次调用自己的、可释放的**对象；释放后要能证明它确实没了。

## 已知坑

- **`command -v` 只认字面命令名**：`<tool>` 里塞路径、通配符或命令片段就不是「存在性检查」了。
- **只读观察不要顺手动状态**：`echo` 只是回声，别顺手 `touch`、`mkdir`、`chmod` 去「顺便验证」。
- **网络可达性别在 shell 层拍板**：那是可达性卡的判据，shell 层越权下结论会拿不到证据。
- **通道静默不等于断开**：读窗口以输出静默为准，先 drain 再判。

## 引用它的技能卡

- `pre.session_identity`、`post.identity`、`pre.tool_present`、`pre.posix_path_access`、
  `post.file_present`、`post.channel_echo`。
- `exploit.suid_path_hijack`、`session.root_via_suid` —— 相对路径劫持要用同一套 shell 原语。
