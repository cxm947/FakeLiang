"""Proved account facts backed by external or derived private material references.

The ledger contains binding and provenance only. Actual material is resolved in memory
at dispatch, and a changed source entry is a named refusal rather than a new credential.
"""
from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from graph.terms import atom_value, is_variable, parse_fact
from runtime import harvest
from runtime.redact import redact_text

from runtime.credential_source import (
    REPOSITORY, MODES, _error, _private_path, validate_materials_dir, _material,
    load_source, known_secrets, declared_roles, _digest, _resolve, _external_key,
)
from runtime.credential_facts import (
    FACT_FIELDS, ACCOUNT_FACT, graph_symbols, _fact, _dependencies, produced_facts, _bindings,
)
from runtime.credential_selection import (
    _check_host, _matching, _select_records, select, select_candidates,
)




ROW_FIELDS = ("credential_id", *FACT_FIELDS, "host", "source_node", "source_call",
              "source_path", "source_key", "source_digest", "source_run", "parent")
DERIVED_FIELDS = (*ROW_FIELDS, "source_kind", "source_quote", "source_summary")
SOURCE_CALL = re.compile(r"call-[0-9]{8}T[0-9]{6}-[0-9a-f]{6}(?:-[A-Za-z0-9_-]+)?")


def path_for(run_dir):
    #: 凭据也是"收获"，与会话行同表（runtime.harvest）。
    return harvest.path_for(run_dir)


def read(run_dir):
    """Read every row; corrupted evidence is a named refusal, never silently skipped."""
    try:
        #: strict: a credential ledger that lost a row must say so, not read short.
        rows = [dict(row) for row in harvest.read(run_dir, row_type="credential", strict=True)]
    except (OSError, UnicodeError, ValueError):
        _error("LEDGER_INVALID")
    for row in rows:
        row.pop("row_type", None)
    for row in rows:
        if (not isinstance(row, dict) or set(row) not in (set(ROW_FIELDS), set(DERIVED_FIELDS))
                or any(not isinstance(value, str) for value in row.values())
                or ("source_kind" in row and (row["source_kind"] != "derived"
                    or not SOURCE_CALL.fullmatch(row["source_call"])
                    or not row["source_quote"] or not row["source_summary"]))
                or not all(row[key] for key in ("credential_id", *FACT_FIELDS, "host",
                                                 "source_node", "source_path", "source_key",
                                                 "source_digest", "source_run"))):
            _error("LEDGER_INVALID")
    return rows


def _encoded_rows(rows, *, secrets=()):
    text = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    if any(secret and (secret in text or any(secret in value for row in rows
                                            for value in row.values()))
           for secret in secrets):
        _error("METADATA_CONTAINS_SECRET")
    return text.encode("utf-8")


def _append(run_dir, rows, *, secrets=()):
    if not rows:
        return
    _encoded_rows(rows, secrets=secrets)      # the secret guard runs before anything is written
    for row in rows:
        harvest.record(run_dir, "credential", row)


def _derived(entry, node_id):
    required = {"realm", "user", "value", "kind", "source_call", "quote"}
    if (not isinstance(entry, dict) or not required <= entry.keys()
            or set(entry) - required - {"stream"}
            or any(not isinstance(entry[key], str) for key in required)
            or entry["kind"] not in {"password", "ntlm"}
            or not SOURCE_CALL.fullmatch(entry["source_call"])
            or entry.get("stream", "stdout") not in {"stdout", "stderr"}
            or not entry["quote"].strip()):
        _error("DERIVED_INVALID")
    material = _material({"user": entry["user"], "realm": entry["realm"],
                          "secret": entry["value"], "mode": entry["kind"]})
    if any(value and value not in entry["quote"]
           for value in (material["user"], material["domain"], material["secret"])):
        _error("DERIVED_QUOTE_MISMATCH")
    provenance = {"source_node": str(node_id), "source_call": entry["source_call"],
                  "quote": entry["quote"], "stream": entry.get("stream", "stdout")}
    return material, provenance


def _masked_quote(quote, secrets):
    from runtime.lean import mask_secrets

    return redact_text(mask_secrets(quote, secrets))


def record_proved(run_dir, *, document, node_id, proved, source, host_map=None,
                  source_call="", secrets=(), materials=(), materials_dir=None, run_dirs=()):
    """Append proven references; derived values were checked against raw calls by LeanRun."""
    if not proved:
        return []
    facts = produced_facts(document, node_id)
    if not facts:
        return []
    if not isinstance(materials, (list, tuple)):
        _error("DERIVED_INVALID")
    if source is None and not materials:
        _error("SOURCE_BINDING_MISSING")
    if materials and len(facts) != 1:
        # ponytail: a finish has one account binding; multiple facts need an explicit selector.
        _error("DERIVED_BINDING_AMBIGUOUS")
    private_dir = (validate_materials_dir(materials_dir, run_dirs=(run_dir, *run_dirs))
                   if materials else None)
    derived = [_derived(entry, node_id) for entry in materials]
    known = known_secrets(source) + list(secrets or ()) + [item[0]["secret"] for item in derived]
    existing, pending, result, private_files = read(run_dir), [], [], []
    source_path = (_private_path(source["path"], run_dirs=(run_dir, *run_dirs))
                   if source is not None else None)
    for logical, graph_user, symbol, privilege in facts:
        base = {"logical": logical, "graph_user": graph_user, "symbol": symbol,
                "privilege": privilege, "host": str((host_map or {}).get(logical) or logical),
                "source_node": str(node_id), "source_call": str(source_call),
                "source_run": str(Path(run_dir).resolve()), "parent": ""}
        choices = []
        if source is not None:
            key = _external_key(source, graph_user, symbol)
            if key is None and not derived:
                _error("SOURCE_BINDING_MISSING")
            if key is not None:
                choices.append(({**base, "credential_id": "cred-" + uuid4().hex,
                                 "source_path": str(source_path), "source_key": key,
                                 "source_digest": _digest(source["credentials"][key])}, None))
        for material, provenance in derived:
            credential_id = "cred-" + uuid4().hex
            path = private_dir / (credential_id + ".json")
            row = {**base, "credential_id": credential_id, "source_call": provenance["source_call"],
                   "source_path": str(path), "source_key": symbol, "source_kind": "derived",
                   "source_digest": _digest({"material": material, "provenance": provenance}),
                   "source_quote": _masked_quote(provenance["quote"], known),
                   "source_summary": json.dumps({"realm": material["domain"], "user": material["user"],
                                                 "kind": material["mode"]}, ensure_ascii=False)}
            choices.append((row, {"credentials": {symbol: material}, "provenance": provenance}))
        for row, private in choices:
            identity = (*FACT_FIELDS, "host", "source_node", "source_key", "source_digest")
            duplicate = next((old for old in existing + pending
                              if old.get("source_kind", "external") == row.get("source_kind", "external")
                              and all(old[key] == row[key] for key in identity)
                              and (private is not None or old["source_path"] == row["source_path"])), None)
            if duplicate is None:
                pending.append(row)
                if private is not None:
                    private_files.append((Path(row["source_path"]), private))
            result.append(duplicate or row)
    # Validate the whole public batch before creating private files or appending ledger rows.
    _encoded_rows(pending, secrets=known)
    for path, private in private_files:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write((json.dumps(private, ensure_ascii=False) + "\n").encode("utf-8"))
    _append(run_dir, pending, secrets=known)
    return result


def secrets_for_rows(rows, *, run_dirs=(), repository=None):
    """Resolve carried references before any model call, retaining secrets in memory only."""
    return list(dict.fromkeys(_resolve(row, run_dirs=run_dirs, repository=repository)["secret"]
                              for row in rows))


def carry(from_dir, to_dir, *, host_map=None, repository=None, secrets=()):
    """Copy proven references with parent ids; original source/proof fields stay unchanged."""
    rows, pending = read(from_dir), []
    known = list(secrets or ())
    existing = read(to_dir)
    for row in rows:
        _check_host(row, host_map)
        material = _resolve(row, run_dirs=(from_dir, to_dir), repository=repository)
        known.append(material["secret"])
        duplicate = next((item for item in existing if item["parent"] == row["credential_id"]), None)
        if duplicate is None:
            copied = {**row, "credential_id": "cred-" + uuid4().hex,
                      "parent": row["credential_id"]}
            pending.append(copied)
    _append(to_dir, pending, secrets=known)
    return pending
