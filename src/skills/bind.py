"""图节点 → 卡：卡自己声明它回答哪种节点（`when`），绑定器只做匹配。

爷爷 2026-10-04："既然你知道有需要删的，就直接删掉，然后基于上下工作流的需求，重新做。"

旧路把这件事拆成四层（检索索引、别名打分、叶映射、选择器），因为卡里有机器契约要满足。
轻卡只要求卡回答两件事：**我回答哪种节点**（`when`）和**我需要哪几个固定输入**（`inputs`）。
节点自己带着它的 `case`（`semantics.case_id`，图那一层算好的）、`service` 与 `attack_id`，
所以绑定就是一次字段匹配 —— 没有索引、没有打分、没有"叶"。

`when` 没写的卡不参与绑定（它可能是别的发布或纯参考卡）；匹配不到就是**具名缺口**，
而不是悄悄挑一张差不多的。
The preceding description documents the retired single-pass matcher.
Current retrieval uses explicit TTP gates, declared match states, and checked model tie selection.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import layout
from .bind_prompts import SYSTEM
from .lean import load_card

TERMS = ("service", "case", "problem_tags", "aliases", "keywords")
STATES = ("required", "preferred", "unspecified")


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False)


def _terms(values, where):
    if (not isinstance(values, list)
            or any(not isinstance(value, str) or not value.strip() for value in values)):
        raise ValueError("CARD_METADATA_INVALID: " + where)
    normal = [" ".join(value.split()).casefold() for value in values]
    if len(normal) != len(set(normal)):
        raise ValueError("CARD_METADATA_DUPLICATE: " + where)
    return normal


def _entry(row):
    fields = {"id", "path", "technique", "categories", "allowed_tools",
              "permission_source", "match", *TERMS}
    if not isinstance(row, dict) or set(row) != fields:
        raise ValueError("CARD_METADATA_INVALID: fields")
    for field in ("id", "path"):
        if not isinstance(row[field], str) or not row[field].strip():
            raise ValueError("CARD_METADATA_INVALID: " + field)
    for field in ("technique", "categories", "allowed_tools", *TERMS):
        _terms(row[field], row["id"] + "." + field)
    if not row["categories"] or not row["allowed_tools"]:
        raise ValueError("CARD_METADATA_INVALID: categories/allowed_tools")
    if row["permission_source"] not in ("allowed_tools", "legacy_tools"):
        raise ValueError("CARD_METADATA_INVALID: permission_source")
    if not isinstance(row["match"], list):
        raise ValueError("CARD_METADATA_INVALID: match")
    rules, assigned = [], set()
    for rule in row["match"]:
        if (not isinstance(rule, dict) or not {"field", "state"} <= set(rule)
                or set(rule) - {"field", "state", "values"}
                or rule["field"] not in TERMS or rule["state"] not in STATES):
            raise ValueError("CARD_METADATA_INVALID: match rule")
        field, state = rule["field"], rule["state"]
        values = _terms(rule.get("values", row[field]), field)
        if ((state != "unspecified" and not values)
                or not set(values) <= set(_terms(row[field], field))):
            raise ValueError("CARD_METADATA_INVALID: match values")
        for value in values:
            if (field, value) in assigned:
                raise ValueError("CARD_METADATA_DUPLICATE: match value")
            assigned.add((field, value))
        rules.append({"field": field, "state": state, "values": sorted(values)})
    if assigned != {(field, value) for field in TERMS for value in _terms(row[field], field)}:
        raise ValueError("CARD_METADATA_INVALID: unclassified values")
    return {"technique": sorted(row["technique"]),
            "categories": sorted(_terms(row["categories"], "categories")),
            "match": sorted(rules, key=_canonical)}


def build_index(registry):
    """Compile declared TTP/category memberships; the registry owns scoring declarations."""
    if (not isinstance(registry, dict) or set(registry) != {"schema", "skills"}
            or registry["schema"] != 2 or not isinstance(registry["skills"], list)):
        raise ValueError("CARD_REGISTRY_INVALID")
    techniques, categories, seen = {}, {}, set()
    for row in registry["skills"]:
        spec = _entry(row)
        if row["id"] in seen:
            raise ValueError("CARD_METADATA_DUPLICATE: id")
        seen.add(row["id"])
        for field, target in (("technique", techniques), ("categories", categories)):
            for value in spec[field]:
                target.setdefault(value, []).append(row["id"])
    return {"schema": 2,
            "registry_digest": hashlib.sha256(_canonical(registry).encode("utf-8")).hexdigest(),
            "techniques": {key: sorted(value) for key, value in sorted(techniques.items())},
            "categories": {key: sorted(value) for key, value in sorted(categories.items())}}


def faces(root: Path) -> list:
    """Read both indexes and retain the actual card's execution permissions."""
    root = Path(root)
    registry = json.loads((root / "skills" / "registry.json").read_text(encoding="utf-8"))
    index = json.loads((root / "skills" / "index.json").read_text(encoding="utf-8"))
    if _canonical(index) != _canonical(build_index(registry)):
        raise ValueError("CARD_INDEX_STALE")
    found = []
    for row in sorted(registry["skills"], key=lambda item: item["id"]):
        card = load_card(row["id"], root)
        if (root / row["path"]).resolve() != layout.skill_dir(row["id"], root).resolve():
            raise ValueError("CARD_METADATA_PATH_CHANGED: " + row["id"])
        source = "allowed_tools" if "allowed_tools" in card else "legacy_tools"
        if row["permission_source"] != source or row["allowed_tools"] != card["tools"]:
            raise ValueError("CARD_PERMISSION_PROJECTION_CHANGED: " + row["id"])
        declared = (card.get("when") or {}).get("technique")
        if row["technique"] != ([declared] if declared else []):
            raise ValueError("CARD_TECHNIQUE_PROJECTION_CHANGED: " + row["id"])
        spec = _entry(row)
        for field in ("service", "case"):
            declared = (card.get("when") or {}).get(field)
            if not declared:
                continue
            normal = set(_terms([declared], field))
            required = [rule for rule in spec["match"]
                        if rule["field"] == field and rule["state"] == "required"]
            if (set(_terms(row[field], field)) != normal or len(required) != 1
                    or set(required[0]["values"]) != normal):
                raise ValueError("CARD_MATCH_PROJECTION_CHANGED: " + row["id"] + "." + field)
        spec["technique"] = [key for key, ids in index["techniques"].items() if row["id"] in ids]
        spec["categories"] = [key for key, ids in index["categories"].items() if row["id"] in ids]
        found.append(dict(card, retrieval=spec))
    return found


def node_terms(node, context=None):
    """Use explicit semantic fields, never IDs, hostnames, or narrative text."""
    context = {} if context is None else context
    if (not isinstance(node, dict) or not isinstance(context, dict)
            or set(context) - {"aliases", "keywords", "problem_tags", "categories"}):
        raise ValueError("CARD_QUERY_INVALID")
    technique = []
    for key in ("job_id", "attack_id"):
        value = node.get(key)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError("CARD_QUERY_INVALID: " + key)
            if value.strip():
                technique.append(value.strip())
    if len(set(technique)) > 1:
        raise ValueError("CARD_QUERY_TECHNIQUE_CONFLICT")
    semantics = node.get("semantics") or {}
    if not isinstance(semantics, dict):
        raise ValueError("CARD_QUERY_INVALID: semantics")
    terms = {"technique": technique[:1]}
    for field, value in (("case", semantics.get("case_id")), ("service", node.get("service"))):
        if value is not None and not isinstance(value, str):
            raise ValueError("CARD_QUERY_INVALID: " + field)
        terms[field] = _terms([value] if value and value.strip() else [], field)
    for field in ("aliases", "keywords", "problem_tags", "categories"):
        terms[field] = _terms(context.get(field, node.get(field, [])), field)
    return terms


def retrieve(node, cards, *, context=None):
    """Required groups all apply; alternatives within a group need one exact match."""
    terms = node_terms(node, context)
    ranked, rejected, seen = [], [], set()
    for card in cards:
        identity, spec = card.get("id"), card.get("retrieval")
        if not isinstance(identity, str) or identity in seen:
            raise ValueError("CARD_METADATA_INVALID: id")
        seen.add(identity)
        if not isinstance(spec, dict) or set(spec) != {"technique", "categories", "match"}:
            raise ValueError("CARD_METADATA_MISSING: " + identity)
        reasons, failures, matched = [], [], set()
        if terms["technique"]:
            if not spec["technique"]:
                failures.append({"code": "CARD_TTP_UNDECLARED", "field": "technique"})
            elif terms["technique"][0] not in spec["technique"]:
                failures.append({"code": "CARD_TTP_MISMATCH", "field": "technique",
                                 "expected": terms["technique"], "declared": spec["technique"]})
            else:
                reasons.append({"code": "TTP_MATCH", "values": terms["technique"]})
        elif "verification" not in spec["categories"]:
            failures.append({"code": "CARD_VERIFICATION_PACKAGE_REQUIRED", "field": "categories"})
        elif spec["technique"]:
            failures.append({"code": "CARD_NODE_TTP_MISSING", "field": "technique"})
        else:
            reasons.append({"code": "VERIFICATION_PACKAGE", "values": ["verification"]})
        if terms["categories"] and not set(terms["categories"]) & set(spec["categories"]):
            failures.append({"code": "CARD_CATEGORY_MISMATCH", "field": "categories",
                             "expected": terms["categories"], "declared": spec["categories"]})
        if not failures:
            for rule in spec["match"]:
                field, state = rule["field"], rule["state"]
                if state == "unspecified":
                    continue
                hits = sorted(value for value in rule["values"] if any(
                    value == actual or (field == "case" and actual.startswith(value + "_"))
                    for actual in terms[field]))
                if state == "required" and not hits:
                    failures.append({"code": "CARD_REQUIRED_MISSING", "field": field,
                                     "expected": rule["values"], "actual": terms[field]})
                elif hits:
                    matched.add(field)
                    reasons.append({"code": "TERM_MATCH", "field": field,
                                    "state": state, "values": hits})
        if failures:
            rejected.append({"card_id": identity, "reasons": failures})
        else:
            ranked.append({"card_id": identity, "score": len(matched), "reasons": reasons})
    ranked.sort(key=lambda row: (-row["score"], row["card_id"]))
    rejected.sort(key=lambda row: row["card_id"])
    top = [row for row in ranked if row["score"] == ranked[0]["score"]] if ranked else []
    return {"state": "gap" if not top else "selected" if len(top) == 1 else "choice_required",
            "selected_id": top[0]["card_id"] if len(top) == 1 else None,
            "terms": terms, "candidates": top, "ranked": ranked, "rejected": rejected}


def accept_choice(result, answer):
    """The model may choose only a supplied highest-score card, without editing its contract."""
    if result["state"] != "choice_required":
        raise ValueError("CARD_CHOICE_NOT_REQUIRED")
    if (not isinstance(answer, dict) or set(answer) != {"card_id", "reason"}
            or not isinstance(answer["card_id"], str)
            or not isinstance(answer["reason"], str) or not answer["reason"].strip()):
        raise ValueError("CARD_CHOICE_INVALID")
    if answer["card_id"] not in {row["card_id"] for row in result["candidates"]}:
        raise ValueError("CARD_CHOICE_NOT_ELIGIBLE")
    return {**result, "state": "selected", "selected_id": answer["card_id"],
            "model_reason": answer["reason"].strip()}


def bind(node, cards, *, context=None, client=None, timeout=None):
    """Return (card, refusal, selection_receipt); never attach the receipt to the card."""
    result = retrieve(node, cards, context=context)
    if result["state"] == "gap":
        return None, "CARD_GAP: " + _canonical(result), result
    if result["state"] == "choice_required":
        available = getattr(client, "available", None)
        try:
            usable = callable(getattr(client, "complete", None))
            if available is not None:
                usable = usable and bool(available() if callable(available) else available)
            if not usable:
                return None, "CARD_MODEL_UNAVAILABLE: " + _canonical(result), result
            by_id = {card["id"]: card for card in cards}
            payload = {"node": node, "terms": result["terms"], "candidates": [
                {**row, "description": by_id[row["card_id"]].get("description", ""),
                 "body": by_id[row["card_id"]].get("body", ""),
                 "allowed_tools": by_id[row["card_id"]].get("tools", [])}
                for row in result["candidates"]]}
            options = {"timeout": timeout} if timeout is not None else {}
            reply = client.complete(
                task="choose_card",
                system=SYSTEM,
                user=json.dumps(payload, ensure_ascii=False), **options)
            if not getattr(reply, "ok", False):
                return None, "CARD_MODEL_REPLY_UNCONFIRMED: " + _canonical(result), result
            result = accept_choice(result, getattr(reply, "payload", None))
        except (ValueError, OSError, RuntimeError, TypeError) as error:
            return (
                None,
                "CARD_MODEL_CHOICE_REFUSED: " + str(error) + ": " + _canonical(result),
                result,
            )
    chosen = next(card for card in cards if card["id"] == result["selected_id"])
    return dict(chosen), "", result


