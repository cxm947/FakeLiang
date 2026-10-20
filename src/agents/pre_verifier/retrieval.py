"""A Pre-only registry generated from SKILL.md; BM25 is the only ranking score."""

from hashlib import sha256
from pathlib import Path

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
import yaml

from src.agents._skill_registry import SkillRanker, tokenize

DEFAULT_ROOT = Path(__file__).resolve().parents[3] / "skills" / "pre"


ALLOWED_CATEGORIES = frozenset({
    "action-method",
    "channel-liveness",
    "container-relation",
    "credential-existence",
    "credential-use",
    "file-presence",
    "firewall-state",
    "identity-verification",
    "path-access",
    "reachability",
    "service-presence",
})

#: Application protocols that ride TCP. A reachability fact may name the application
#: (`hacl(web1, pc1, http, 8080)`) instead of the transport, while method cards declare
#: the transport they actually probe. Keeping that mapping here means a new service name
#: does not need a new card or a branch: unless the fact names a non-TCP transport, the
#: probe is a TCP connect.
UDP_PROTOCOLS = frozenset({"icmp", "udp", "snmp", "ntp", "dhcp", "tftp"})


def transport_for(protocol):
    """Map an application protocol to the transport a probe must use."""
    value = str(protocol or "").strip().casefold()
    if not value:
        return None
    return value if value in UDP_PROTOCOLS else "tcp"


class Metadata(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    predicates: list[str] = Field(min_length=1)
    platforms: list[str] = Field(min_length=1)
    keywords: list[str] = Field(min_length=1)
    resources: list[str] = Field(default_factory=list)
    #: Method family used by retrieval, never a host name.
    categories: list[str] = Field(default_factory=list)
    #: Synonyms that make lexical matching work across languages and tool names.
    aliases: list[str] = Field(default_factory=list)
    #: Fact parameters this card consumes (host, user, perm, ...).
    parameters: list[str] = Field(default_factory=list)
    #: Selection conditions, e.g. {"scope": "local"}.
    when: dict[str, Any] = Field(default_factory=dict)
    #: Environment prerequisites, e.g. domain_joined.
    requires: list[str] = Field(default_factory=list)
    #: Explicit non-applicable cases.
    excludes: list[str] = Field(default_factory=list)
    #: Execution carriers this method actually runs on (meterpreter, shell, kali, ...).
    carriers: list[str] = Field(default_factory=list)

    @field_validator("categories")
    @classmethod
    def known_categories(cls, values):
        unknown = set(values) - ALLOWED_CATEGORIES
        if unknown:
            raise ValueError("Unknown categories: " + ", ".join(sorted(unknown)))
        return values

    @field_validator("aliases")
    @classmethod
    def non_empty_aliases(cls, values):
        if any(not str(value).strip() for value in values):
            raise ValueError("Aliases must be non-empty strings")
        return values


class Card(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=64)
    description: str = Field(min_length=1)
    metadata: Metadata


class PreSkillIndex:
    def __init__(self, root=DEFAULT_ROOT):
        self.root = Path(root).resolve()
        self.cards = []
        for path in sorted(self.root.glob("*/SKILL.md")):
            if not path.resolve().is_relative_to(self.root):
                raise ValueError("Skill cannot escape the Pre directory")
            text = path.read_text(encoding="utf-8")
            parts = text.split("---", 2)
            if len(parts) != 3 or parts[0].strip():
                raise ValueError(f"Missing YAML frontmatter: {path.name}")
            card = Card.model_validate(yaml.safe_load(parts[1]))
            if card.name != path.parent.name or not parts[2].strip():
                raise ValueError("Skill name must match folder and have a nonempty body")
            self.cards.append({**card.model_dump(), "body": parts[2].strip(),
                               "digest": sha256(text.encode()).hexdigest()})
        self.ranker = SkillRanker(self.cards)
        self.index = self.ranker.index

    def registry(self):
        return [{k: v for k, v in c.items() if k != "body"} for c in self.cards]

    def search(self, leaf, limit=3):
        if not 1 <= limit <= 3:
            raise ValueError("Pre retrieves at most three skills")
        if self.index is None or leaf["policy"] != "check":
            return []
        parameters = leaf.get("parameters") or {}
        service = parameters.get("service")
        # A reachability fact names its protocol; ICMP answering does not prove a TCP port
        # is open, so the card that matches the fact's protocol wins over a neighbour.
        protocol = transport_for(parameters.get("protocol"))
        # Protocol is the harder constraint: a named TCP port must never fall back to an
        # ICMP card just because a service word also matched somewhere in the corpus.
        prefer = {key: value for key, value in
                  (("protocol", protocol), ("service", service)) if value}
        selected = self.ranker.rank(leaf["query"], predicates=(leaf["predicate"],),
                                    platform=leaf.get("platform"),
                                    prefer=prefer or None,
                                    limit=limit)
        loaded = []
        for card in selected:
            resources = {}
            base = (self.root / card["name"]).resolve()
            for relative in card["metadata"]["resources"]:
                path = (base / relative).resolve()
                if not path.is_relative_to(base) or path.suffix not in {".md", ".py"}:
                    raise ValueError("Skill resource must be a local Markdown or Python file")
                resources[relative] = path.read_text(encoding="utf-8")
            # Snapshot the materials actually sent to the model, including helper source.
            digest = sha256(card["digest"].encode())
            for relative, content in sorted(resources.items()):
                digest.update(relative.encode())
                digest.update(content.encode())
            loaded.append({**card, "resources": resources, "digest": digest.hexdigest()})
        return loaded
