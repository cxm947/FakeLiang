# 防火墙后端状态的解释

## UFW

    ufw status verbose

Status: active 是 UFW 启用的证据；Status: inactive 只说明 UFW 未启用。
若运行上下文未确认 UFW 是唯一管理者，inactive 不能证明系统所有防火墙均关闭。

## firewalld

    firewall-cmd --state
    firewall-cmd --get-active-zones
    firewall-cmd --list-all --zone=public

zone 参数要替换为实际活动 zone。running 说明管理器运行，还需活动 zone/策略上下文。
not running 不能排除残留内核规则或其他管理器；查询失败也不能解释为关闭。

## nftables

    nft list ruleset

观察有 hook 的基础链、默认 policy 及实际规则，不以任意非空表代表有效过滤。
空 ruleset 只说明当前 nftables 查询范围中没有规则；其他网络命名空间或
iptables legacy 后端可能不同。不通过单一片段给系统全局关闭结论。

## iptables

    iptables -S
    ip6tables -S

关注 INPUT/FORWARD/OUTPUT 策略和规则，区分 IPv4/IPv6。
默认 DROP 即使没有附加规则也不是关闭；所有 ACCEPT 且空规则仅描述该后端。
命令可能连接 nft 或 legacy 实现，版本/后端不清时明确记录未知。

## 状态不能对应时

图里只有开启/关闭，实际返回却只有部分策略或某个管理进程状态时，
说明缺少哪一层证据。可补只读查询，不以修改开关、刷新规则或主动放通端口试验。
