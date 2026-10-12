# docker CLI —— 容器与宿主的关系

## 这个工具能回答什么

- **这个容器属于哪个宿主、是不是特权、挂了什么**（`pre.docker_inspect`）。
- 反过来，从容器里往外看时：**宿主的根分区在不在我手上**（`exploit.privileged_container_escape`
  的前置观察）。

它回答「关系」，不回答「能不能逃出去」——后者要靠宿主侧的实际观察来证明。

## 调用形状

```sh
docker --context <daemon_context> inspect --type container <container_id>
```

容器内部看自己的挂载与身份：

```sh
cat /proc/mounts
fdisk -l
cat /proc/self/cgroup
hostname
```

## 输出怎么读

- 只投影需要的字段：容器 `Id`、`Name`、对象类型；其余字段丢弃，**别把整个 inspect 倒进证据**。
- 「宿主侧的效果」必须由**宿主边界上的观察**证明：容器里 `cat` 到不等于宿主上真的落了东西。
- 特权位、挂载读写属性、cgroup 路径三件事要分别记录，它们是三条不同的前提。
- daemon 上下文是**连接关系**的一部分：经哪个 daemon 看到的，属于该 daemon 所在的那台宿主。

## 已知坑

- **`inspect` 只在 daemon 上说话**：daemon 不可达时是「问不到」，不是「不存在这个容器」。
- **写宿主路径会改宿主状态**：挂载点写入是真实副作用，必须声明还原规格并能证明已还原。
- **别把 `hostname` 当容器身份**：它可被改名，cgroup 路径更可靠，但两者都要留。
- **标记读回要同一来源**：容器里写、容器里读只能证明容器里的事。

## 引用它的技能卡

- `pre.docker_inspect` —— 容器归属与元数据只读观察。
- `exploit.privileged_container_escape` —— 经挂载点或调度路径把效果落到宿主侧。
