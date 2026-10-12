"""A small, non-executing reader for ground predicate labels, not a Prolog VM."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal


def split_arguments(text: str) -> tuple[str, ...]:
    parts, stack = [], []
    start, index, quote = 0, 0, None
    pairs = {")": "(", "]": "[", "}": "{"}
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\" and index + 1 < len(text):
                index += 2
                continue
            if char == quote:
                if index + 1 < len(text) and text[index + 1] == quote:
                    index += 2
                    continue
                quote = None
        elif char in "\"'":
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack.pop() != pairs[char]:
                raise ValueError("unbalanced predicate arguments")
        elif char == "," and not stack:
            parts.append(text[start:index].strip())
            start = index + 1
        index += 1
    if quote or stack:
        raise ValueError("unbalanced predicate arguments")
    if text.strip():
        parts.append(text[start:].strip())
    if any(not part for part in parts):
        raise ValueError("empty predicate argument")
    return tuple(parts)


@dataclass(frozen=True)
class Fact:
    name: str
    args: tuple[str, ...]

    @property
    def signature(self) -> str:
        return f"{self.name}/{len(self.args)}"


def parse_fact(text: str) -> Fact:
    match = re.fullmatch(r"\s*([a-zA-Z_]\w*)\s*\((.*)\)\s*\.?\s*", text, re.S)
    if not match:
        raise ValueError("unsupported predicate label")
    return Fact(match[1], split_arguments(match[2]))


def atom_value(term: str) -> str:
    """Unquote atoms; keep numeric/compound tokens as text in the public JSON."""
    term = term.strip()
    if len(term) >= 2 and term[0] in "\"'" and term[-1] == term[0]:
        quote = term[0]
        value = term[1:-1].replace(quote + quote, quote)
        return re.sub(r"\\([\\'\"])", r"\1", value)
    return term


def term_key(term: str) -> tuple[str, object]:
    # '2049' is an atom, 2049 a number. Do not confuse them in dif/2.
    term = term.strip()
    if re.fullmatch(r"[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?", term):
        # Decimal equality is exact; normalize() could round a very long token
        # under the current decimal context and accidentally merge values.
        return "number", Decimal(term)
    return "atom", atom_value(term)


def is_variable(term: str) -> bool:
    return bool(re.fullmatch(r"[A-Z_]\w*", term))


def rule_description(label: str) -> str:
    match = re.fullmatch(r"\s*RULE\s+\d+\s*\((.*)\)\s*", label, re.S)
    # Only whitespace is normalized; a renamed rule is NOT silently aliased.
    return " ".join((match[1] if match else label).split())
