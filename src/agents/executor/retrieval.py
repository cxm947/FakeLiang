"""Action-only BM25. Index frontmatter; load selected bodies at runtime."""

from hashlib import sha256
from pathlib import Path

import yaml

from src.agents._skill_registry import SkillRanker
from .schema import ActionSkillCard, ActionSkillHeader

DEFAULT_ROOT = Path(__file__).resolve().parents[3] / "skills" / "action"


def fact_predicate(fact):
    """The rule a graph fact names, independent of its display text."""
    return str(fact.get("predicate")
               or str(fact.get("description", "")).partition("(")[0]).strip()


def predicate_key(node, children):
    """One deterministic predicate key for the exact-match filter.

    The key comes from the graph, never from which cards happen to exist.
    """
    if node.get("predicate"):
        return str(node["predicate"])
    if node.get("attack_id"):
        return str(node["attack_id"])
    keys = list(dict.fromkeys(key for key in (fact_predicate(child) for child in children)
                              if key))
    return keys[0] if len(keys) == 1 else "action"


def query_text(node, children, execution=None):
    """Everything a selection may look at, without naming a node or a host."""
    execution = execution or {}
    return " ".join(str(value) for value in (
        node.get("rule_desc"), node.get("attack_id"), node.get("service"),
        *(fact_predicate(child) for child in children),
        execution.get("platform"), execution.get("carrier")) if value not in (None, ""))


class ActionSkillIndex:
    def __init__(self, root=DEFAULT_ROOT):
        self.root = Path(root).resolve()
        self.cards = []
        self._headers = {}
        for path in sorted(self.root.glob("*/SKILL.md")):
            if not path.resolve().is_relative_to(self.root):
                raise ValueError("Skill must stay inside the Action directory")
            # Do not load command-bearing bodies merely to build the registry.
            with path.open(encoding="utf-8") as stream:
                if stream.readline().strip() != "---":
                    raise ValueError("Missing skill YAML frontmatter")
                lines = []
                for line in stream:
                    if line.strip() == "---":
                        break
                    lines.append(line)
                else:
                    raise ValueError("Unclosed skill YAML frontmatter")
            header = ActionSkillHeader.model_validate(yaml.safe_load("".join(lines)))
            card = header.model_dump(exclude={"delivery"})
            if card["name"] != path.parent.name:
                raise ValueError("Skill name must match folder")
            self.cards.append(card)
            self._headers[card["name"]] = header.model_dump()
        self.ranker = SkillRanker(self.cards)
        self.index = self.ranker.index

    def search(self, query, *, platform=None, limit=3, predicate=None, carrier=None,
               serves=(), service=""):
        """Return metadata only; no fallback to unrelated or other-stage skills.

        ``serves`` is the child fact this node must produce. A card that declares it is
        preferred over neighbours that only share the rule: an SMB command-execution card and
        an SMB session-delivery card both mention T1021, but only the second one can hand over
        the `execCode` this node owes (live 2026-10-18, node 44).
        """
        predicates = (predicate,) if predicate else ()
        # One selection rule: TTP/predicate hard filter, platform/carrier filter, then
        # BM25 over the remaining cards. Service and `serves` are query terms only; they
        # never narrow the candidate set (a hard `serves` filter sent every execCode node
        # to the one psexec card, regardless of its TTP).
        return self.ranker.rank(query, predicates=predicates, platform=platform,
                                carrier=carrier, limit=limit)

    def load(self, name):
        """Explicit runtime load, only for a registered Action card."""
        registered = next((c for c in self.cards if c["name"] == name), None)
        if registered is None:
            raise KeyError(name)
        path = (self.root / name / "SKILL.md").resolve()
        if not path.is_relative_to(self.root):
            raise ValueError("Skill must stay inside the Action directory")
        text = path.read_text(encoding="utf-8")
        card = ActionSkillCard.from_markdown(text)
        if card.model_dump(exclude={"sections"}) != self._headers[name]:
            raise ValueError("Skill metadata changed; rebuild the index")
        return {**card.model_dump(), "digest": sha256(text.encode()).hexdigest()}

    def retrieve(self, query, *, platform=None, limit=3, predicate=None, carrier=None,
                 serves=(), service=""):
        return [{**self.load(card["name"]), "score": card["score"],
                 "unmatched_predicate": card["unmatched_predicate"]}
                for card in self.search(query, platform=platform, limit=limit,
                                        predicate=predicate, carrier=carrier,
                                        serves=serves, service=service)]
