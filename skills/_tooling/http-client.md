# HTTP 客户端 —— 应用层观察与命令通道

## 这个工具能回答什么

- **这个 Web 应用自称是什么、回包长什么样**（`pre.service_version` 的响应路由）。
- **能不能借应用的入口执行一条命令，并把回显拿回来**（`exploit.tongda_oa_include_rce`、
  `exploit.laravel_ignition_rce`）。
- **能不能把落地的材料再取回来**（会话交付类变体的取回步骤）。

## 调用形状

最朴素的观察（不带任何利用载荷）：

```sh
curl -sS -i -H 'User-Agent: agv-probe' 'http://<host>:<port>/'
```

文件上传式入口与包含式入口（形状示意，参数以各卡声明为准）：

```sh
python3 <client_file> upload <target_url> <payload_file> <timeout>
python3 <client_file> include <target_url> <include_path> <wrapped_command> <timeout>
```

## 输出怎么读

- **状态行 + 响应头 + 正文**三块都要留：只留正文会把「谁答的、怎么答的」丢掉。
- 应用身份要有**原文支撑**：期望的产品名出现在正文/头里时，把出现的那一行一起记下来，
  不能只记「我认出来了」。
- 命令回显要能被切块（marker 分段），否则模型只能靠猜哪一段是命令输出。
- 传输层长度、编码、分块会改写正文；对二进制或压缩响应先确认拿到的确实是完整正文。

## 已知坑

- **命令通道会被产品版本与调试开关决定**：同一条 URL 在不同版本上行为不同，先观察再动手。
- **写马会改目标状态**：上传与落地是真实副作用，必须有还原或留存声明，别当只读观察处理。
- **响应可能被前端缓存或改写**：拿到 200 不等于拿到了应用自己的回包，注意中间件与代理。
- **超时是「不知道」**：别把一次超时读成「没有这个接口」；要么换探针，要么如实记未知。

## 引用它的技能卡

- `pre.service_version` —— 服务曝光的应用层响应路由。
- `exploit.tongda_oa_include_rce`、`exploit.laravel_ignition_rce` —— 公网应用的命令执行面。
- `session.webshell_via_laravel` —— 落地材料的会话交付。
