"""Shared skill-card ranking: exact predicate filter, then BM25.

Each stage keeps its own cards and its own predicate namespace. This module only owns the
selection algorithm and the searchable card document, so Pre, Action and Post cannot drift
apart while remaining isolated registries.
"""

from copy import deepcopy
import re

from rank_bm25 import BM25Plus


def tokenize(text):
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", str(text)).lower()
    english = re.findall(r"[a-z0-9_]+", text)
    chinese = re.findall(r"[\u4e00-\u9fff]+", text)
    return english + [part[i:i + 2] for part in chinese for i in range(max(1, len(part) - 1))]


def normalize(value):
    return str(value).strip().casefold()


def predicate_match(requested, declared):
    """A card written for a sub-technique serves the parent rule, and the reverse.

    The graph carries the rule's own id (for example `T1021`), while a method card usually
    names the sub-technique it implements (`T1021.002`). Treating those as different
    excluded every psexec card from a T1021 node and left only unrelated neighbours
    (live 2026-10-18, node 44). Matching is on dotted segments, so `T1021` never matches
    `T10210`.
    """
    for left in requested:
        for right in declared:
            if left == right:
                return True
            if right.startswith(left + ".") or left.startswith(right + "."):
                return True
    return False


def card_document(card):
    """Everything a card may be matched on; bodies are never part of the index."""
    metadata = card.get("metadata") or {}
    return " ".join(str(value) for value in (
        card.get("name", ""),
        card.get("description", ""),
        *metadata.get("predicates", []),
        *metadata.get("keywords", []),
        *metadata.get("platforms", []),
        *metadata.get("aliases", []),
        *metadata.get("categories", []),
        *metadata.get("carriers", []),
    ) if value)


def validate_cards(cards):
    """Reject a registry that cannot be selected deterministically."""
    names = set()
    for card in cards:
        name = str(card.get("name") or "").strip()
        if not name:
            raise ValueError("Skill card has no name")
        if name in names:
            raise ValueError("Duplicate skill name: " + name)
        names.add(name)
        metadata = card.get("metadata") or {}
        if not metadata.get("predicates"):
            raise ValueError("Skill card declares no predicate: " + name)
        if not metadata.get("platforms"):
            raise ValueError("Skill card declares no platform: " + name)
    return True


class SkillRanker:
    """One BM25 model per isolated registry, plus the shared selection rules."""

    def __init__(self, cards):
        self.cards = list(cards)
        validate_cards(self.cards)
        corpus = [tokenize(card_document(card)) for card in self.cards]
        # delta=0 keeps unrelated documents at zero, including a one-card registry.
        self.index = BM25Plus(corpus, delta=0) if corpus else None

    def rank(self, query, *, predicates=(), platform=None, carrier=None, prefer=None, limit=3):
        """Exact predicate membership, platform filter, then BM25 ranking.

        When no card declares a requested predicate the result is explicitly marked as a
        lexical fallback. A platform filter never broadens the set: if exact matches exist
        but the platform removes them, the answer is empty rather than unrelated cards.
        """
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 3:
            raise ValueError("Retrieves one to three skills at most")
        if self.index is None:
            return []
        requested = {normalize(value) for value in predicates if str(value).strip()}
        exact = [position for position, card in enumerate(self.cards)
                 if predicate_match(requested, {normalize(value)
                                                for value in card["metadata"]["predicates"]})]
        unmatched = bool(requested) and not exact
        positions = exact if exact else list(range(len(self.cards)))
        if platform:
            key = normalize(platform)
            positions = [position for position in positions
                         if key in {normalize(value) for value
                                    in self.cards[position]["metadata"]["platforms"]}
                         or "any" in {normalize(value) for value
                                      in self.cards[position]["metadata"]["platforms"]}]
        if not positions:
            return []
        if carrier:
            key = normalize(carrier)
            preferred = [position for position in positions
                         if key in {normalize(value) for value
                                    in self.cards[position]["metadata"].get("carriers", [])}]
            # A method that names the current carrier wins over a generic neighbour; only
            # when no candidate names it does the original set stay.
            if preferred:
                positions = preferred
        if prefer:
            for key, value in prefer.items():
                if value in (None, ""):
                    continue
                key, value = normalize(key), normalize(value)
                matched = [position for position in positions
                           if normalize(self.cards[position]["metadata"].get("when", {})
                                        .get(key, "")) == value]
                if matched:
                    positions = matched
        scores = self.index.get_scores(tokenize(query))
        matches = [{**deepcopy(self.cards[position]), "score": float(scores[position]),
                    "unmatched_predicate": unmatched}
                   for position in positions if scores[position] > 0]
        return sorted(matches, key=lambda card: (-card["score"], card["name"]))[:limit]
