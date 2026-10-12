"""技能卡形态守线（D47；2026-09-18 试点批次：试点卡改 4 段 + 场景词全文禁用）。

一张卡是「一类攻击（或验证）行为的实现方法」：用哪个工具的哪个功能、怎么调用、
判什么证据、哪些部分交给模型。靶场只是验证场地 —— 试点卡（pre.tool_present /
post.channel_echo / exploit.tongda_oa_include_rce /
exploit.redis_unauth_write / exploit.laravel_ignition_rce /
exploit.wmi_firewall_off / exploit.wmic_remote_cmd /
exploit.netexec_firewall_off / exploit.kiwi_lsass_dump /
exploit.comsvcs_minidump / exploit.pypykatz_parse /
exploit.privileged_container_escape /
exploit.suid_path_hijack / exploit.impacket_psexec_cmd /
exploit.impacket_wmiexec_cmd /
session.ssh_via_redis / session.webshell_via_laravel /
session.msf_via_credentials /
session.root_via_suid / exploit.http_post_file /
session.msf_migrate）已把历史记录迁到库外索引
（docs/product/adoption_evidence.tsv），正文与 notes 全文禁用场景专有信息；
其余 6 张暂留原八段模板与「实机验证记录」豁免段，随迁移逐张收紧（裁定与
落地见 specs/005 试点批次）。

形态与理由见 `specs/002-generic-skill-methods/spec.md`。
"""

import json
import re
import unittest

from skills import layout, lean
from tests.support import ROOT

#: 项目自身的 Codex 元卡（给别的 agent 读，不承载验证方法），显式豁免。
META_CARD = "attack-graph-validation"

#: 全部方法卡统一使用三节（+ 可选异常与恢复）；r121 起方法段标题固定为 `## 怎么做`。
SECTIONS = ("何时用", "怎么做", "怎么判")
#: 试点卡：全文与 notes 不允许出现场景专有信息（历史锚点已迁库外索引）。
PILOT_IDS = {"pre.tool_present", "post.channel_echo", "exploit.tongda_oa_include_rce",
             "exploit.redis_unauth_write", "exploit.laravel_ignition_rce",
             "exploit.wmi_firewall_off", "exploit.wmic_remote_cmd",
             "exploit.netexec_firewall_off", "exploit.kiwi_lsass_dump",
             "exploit.comsvcs_minidump", "exploit.pypykatz_parse",
             "exploit.privileged_container_escape", "exploit.suid_path_hijack",
             "exploit.impacket_psexec_cmd", "exploit.impacket_wmiexec_cmd",
             "session.ssh_via_redis", "session.webshell_via_laravel",
             "session.msf_via_credentials", "session.root_via_suid",
             "exploit.http_post_file", "session.msf_migrate",
             "pre.netsecurity_firewall_state", "pre.docker_inspect",
             "pre.cim_process_info", "pre.posix_path_access", "pre.impacket_scm_query",
             # 纳管三卡（2026-09-27）：同一份方法三种载体，随卡不写场景专有内容
             "session.msf_adopt_native", "session.msf_adopt_web", "session.msf_adopt_mount"}

EVIDENCE_SECTION = "实机验证记录"

#: 靶场专有词：出现即说明卡片被某个场地绑住了。
LAB_WORDS = re.compile(r"红日|hongri|靶场|PC1|PC2|DC\b|192\.168\.", re.IGNORECASE)
#: 试点卡的禁词（在 LAB_WORDS 上最小扩展）：实例名、地址字面值、决策/运行编号、调用锚点。
INSTANCE_RE = re.compile(
    r"红日|hongri|靶场"
    r"|(?<!\w)(?:S1|S2|S3|PC1|PC2|DC)(?!\w)"
    r"|(?<!\w)(?:\d{1,3}\.){3}\d{1,3}(?!\w)"
    r"|\bD\d+(?:-[A-Za-z0-9_-]+)?\b"
    r"|\bcall-\d{8}T\d{6}-[A-Za-z0-9_-]+",
    re.I,
)


def card_id(folder):
    """The business id behind a card folder (the folder is the standard name since B2)."""
    return layout.business_id(folder.name, ROOT)


def method_cards():
    return sorted(path.parent for path in (ROOT / "skills").glob("*/SKILL.md")
                  if card_id(path.parent) != META_CARD)


def effective_card_text(folder):
    """Keep shape and scenario checks on the complete model-visible card."""
    raw = (folder / "SKILL.md").read_text(encoding="utf-8")
    match = lean.FRONTMATTER.fullmatch(raw)
    if match is None:
        raise ValueError("method card front matter missing")
    return raw[:match.start(2)] + lean.load_card(card_id(folder), ROOT)["body"]


def h2_titles(text):
    """## headings outside code fences: a fenced ``## ...`` is content, not a section."""
    titles, fence = [], None
    for line in text.splitlines():
        if fence:
            closing = (r" {0,3}" + re.escape(fence[0]) + "{" + str(fence[1]) + r",}[ \t]*")
            if re.fullmatch(closing, line):
                fence = None
            continue
        mark = re.match(r" {0,3}(`{3,}|~{3,})", line)
        if mark:
            token = mark.group(1)
            fence = (token[0], len(token))
            continue
        heading = re.fullmatch(r"##[ \t]+(.+?)[ \t]*", line)
        if heading:
            titles.append(heading.group(1))
    if fence is not None:
        raise ValueError("unclosed code fence")
    return tuple(titles)


def migrated_problem(titles):
    """Only the migrated three sections and an optional recovery section."""
    if tuple(titles) not in (SECTIONS, (*SECTIONS, "异常与恢复")):
        return "expected the migrated three sections with optional recovery only"
    return ""


PRE_TEMPLATE_BOUNDARIES = {
    "pre.tool_present": (
        ("怎么做", ("一次调用只按绑定 shell 选定一个模板", "不得换模板追加查询")),
        ("异常与恢复", ("停止边界", "别名/函数", "外部入口仍未知", "uncertain", "finish", "不得自行用另一个模板补查", "须交编排决定")),
    ),
    "pre.session_identity": (
        ("怎么做", ("Windows 与 Linux 模板", "互斥选择", "一次调用只选一个", "不自行换模板追加查询")),
    ),
    "pre.service_version": (
        ("怎么做", ("一次答复只给一个动作", "一次调用只选一个", "不在该调用内换模板追加查询")),
    ),
}

#: R4 四张材料卡：单动作、单次点火/接收、绑定与解析两步，且停止边界必须独立成行。
R4_TEMPLATE_BOUNDARIES = {
    "exploit.kiwi_lsass_dump": (
        ("怎么做", ("一次答复只给一个动作块", "不要把几行用 `&` 拼成一条长命令")),
        ("异常与恢复", ("停止边界", "一次调用只做上面那三条动作")),
    ),
    "exploit.comsvcs_minidump": (
        ("怎么做", ("点火到这里为止", "不在同一条命令里等待")),
        ("异常与恢复", ("停止边界", "一次调用只点火")),
    ),
    "exploit.pypykatz_parse": (
        ("异常与恢复", ("停止边界", "一次调用只做绑定与解析两步")),
    ),
    "exploit.http_post_file": (
        ("异常与恢复", ("停止边界", "一次调用只做一次接收")),
    ),
}


def _assert_pre_template_boundary(skill_id, text):
    """Keep platform branches explicit without forbidding permitted follow-up work."""
    boundaries = PRE_TEMPLATE_BOUNDARIES.get(skill_id, ()) + R4_TEMPLATE_BOUNDARIES.get(skill_id, ())
    for section, words in boundaries:
        content = text.split("\n## " + section + "\n", 1)[1].split("\n## ", 1)[0]
        assert any(
            line.startswith(("**", "- **")) and line.endswith("**")
            and all(word in line for word in words)
            for line in content.splitlines()
        ), (skill_id, section, "explicit template boundary")
    if skill_id == "pre.service_version":
        assert "读原文后仍可决定是否补针对性观察" in text
        assert "针对性观察另起下一次调用" in text
    elif skill_id == "pre.session_identity":
        assert "需要权限线索时可读 whoami /groups（Windows）或 id -Gn（Linux）" in text


class SkillCardShapeTests(unittest.TestCase):
    def test_every_method_card_follows_its_section_template(self):
        offenders = []
        for card in method_cards():
            text = effective_card_text(card)
            _assert_pre_template_boundary(card_id(card), text)
            try:
                titles = h2_titles(text)
            except ValueError as error:
                offenders.append(f"{card.name}: {error}")
                continue
            problem = migrated_problem(titles)
            if problem:
                offenders.append(f"{card.name}: {problem} | {' | '.join(titles)}")
        self.assertEqual([], offenders,
                         "技能卡统一为三节（何时用 / 怎么做 / 怎么判）+ 可选异常与恢复")

    def test_lab_specifics_stay_out_of_the_cards(self):
        offenders = []
        for card in method_cards():
            text = effective_card_text(card)
            if card_id(card) in PILOT_IDS:
                notes = json.loads((card / "skill.json").read_text(encoding="utf-8")).get("notes", "")
                for number, line in enumerate(text.splitlines(), 1):
                    if INSTANCE_RE.search(line):
                        offenders.append(f"{card.name}:{number}: {line.strip()[:90]}")
                if INSTANCE_RE.search(notes):
                    offenders.append(f"{card.name}:notes: {notes[:90]}")
                continue
            body = text.split("\n## " + EVIDENCE_SECTION, 1)[0]
            for number, line in enumerate(body.split("\n"), 1):
                if LAB_WORDS.search(line):
                    offenders.append(f"{card.name}:{number}: {line.strip()[:90]}")
        self.assertEqual([], offenders,
                         "场景专有内容：试点卡全文与 notes 禁用；其余卡只允许在「实机验证记录」段")


if __name__ == "__main__":
    unittest.main()
