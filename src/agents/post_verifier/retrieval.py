"""Post-only BM25 metadata retrieval. Frozen skill bodies are never opened."""

from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import yaml

from src.agents._skill_registry import SkillRanker
from src.agents.pre_verifier.retrieval import Card

DEFAULT_ROOT = Path(__file__).resolve().parents[3] / "skills" / "post"


class PostSkillIndex:
    def __init__(self, root=DEFAULT_ROOT):
        self.root = Path(root).resolve()
        self.cards = []
        for path in sorted(self.root.glob("*/SKILL.md")):
            if not path.resolve().is_relative_to(self.root):
                raise ValueError("Skill must stay inside the Post directory")
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
            metadata = "".join(lines)
            card = Card.model_validate(yaml.safe_load(metadata)).model_dump()
            if card["name"] != path.parent.name:
                raise ValueError("Skill name must match folder")
            self.cards.append({**card, "digest": sha256(metadata.encode()).hexdigest(),
                               "material_scope": "frontmatter_only"})
        self.ranker = SkillRanker(self.cards)
        self.index = self.ranker.index

    def registry(self):
        return deepcopy(self.cards)

    def load(self, name):
        """Return the selected card's frontmatter plus its method body.

        The index ranks frontmatter only, but the model needs the steps to follow the
        card. Loading the body after selection keeps the corpus small and does not
        change ranking.
        """
        card = next((item for item in self.cards if item["name"] == name), None)
        if card is None:
            raise KeyError(name)
        path = (self.root / name / "SKILL.md").resolve()
        if not path.is_relative_to(self.root):
            raise ValueError("Skill cannot escape the Post directory")
        text = path.read_text(encoding="utf-8")
        parts = text.split("---", 2)
        if len(parts) != 3:
            raise ValueError("Missing skill body: " + name)
        return {**deepcopy(card), "body": parts[2].strip(),
                "material_scope": "body_included"}

    def search(self, context, *, platform=None, limit=3, predicate=None):
        query = context.get("query", "") if isinstance(context, dict) else context
        predicates = (predicate,) if predicate else ()
        if not predicates and isinstance(context, dict):
            predicates = tuple(str(fact.get("predicate") or "")
                               for fact in context.get("outputs", [])
                               if str(fact.get("predicate") or "").strip())
        scope = None
        if isinstance(context, dict):
            for fact in context.get("outputs", []):
                if str(fact.get("predicate") or "") in {
                        "getAccount", "hasAccount", "leakAccount", "weakAccount", "execCode"}:
                    user = str(fact.get("user") or "")
                    domain = str(fact.get("domain") or "")
                    scope = ("domain" if (domain or "@" in user
                                          or user.casefold().startswith("domain_"))
                             else "local" if user else None)
                    break
        if isinstance(context, dict) and platform is None:
            platform = context.get("hosts", {}).get(context.get("target_host"), {}).get("platform")
        ranked = self.ranker.rank(query, predicates=predicates, platform=platform,
                                  prefer={"scope": scope} if scope else None, limit=limit)
        return [{**self.load(card["name"]), "score": card["score"],
                 "unmatched_predicate": card["unmatched_predicate"]}
                for card in ranked]

    retrieve = search
