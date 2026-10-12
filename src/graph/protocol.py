"""图里写法与传输写法之间唯一的换算：`http` 是跑在 tcp 上的服务写法，不是另一种传输。

爷爷 2026-10-04："http 也是 tcp 的嘛，只需要在处理攻击图的时候统一成 tcp 就好了。"

只折这一个已知写法；别的拼写原样通过——未知拼写保持缺口，UDP 事实也永远不会锁住只吃 TCP 的卡。
放在图这一层，是因为它处理的是**图的词汇**；读图的代码不必因此拖进整个技能层。
"""
from __future__ import annotations


def transport_protocol(value):
    """Fold exact http/https spellings to tcp; preserve every other spelling."""
    text = "" if value is None else str(value)
    return "tcp" if text in ("http", "https") else text
