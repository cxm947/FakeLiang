"""Private credential material sources and reference validation."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path




REPOSITORY = Path(__file__).resolve().parents[2]
MODES = frozenset({"password", "pass", "plain", "ntlm", "hash", "hashes"})


def _error(code):
    # Error text never interpolates a source path, entry, parser error or secret.
    raise ValueError("CREDENTIAL_" + code)


def _private_path(path, *, run_dirs=(), repository=None):
    try:
        resolved = Path(path).resolve()
        roots = [Path(repository or REPOSITORY).resolve()]
        roots.extend(Path(item).resolve() for item in run_dirs if item)
    except (OSError, ValueError, RuntimeError):
        _error("SOURCE_UNAVAILABLE")
    if any(resolved == root or resolved.is_relative_to(root) for root in roots):
        _error("SOURCE_NOT_PRIVATE")
    if any(part.casefold() == "output" for part in resolved.parts[:-1]):
        _error("SOURCE_NOT_PRIVATE")
    return resolved


def validate_materials_dir(path, *, run_dirs=(), repository=None):
    """Validate a private destination before dispatch, without creating any directory."""
    if path is None or not str(path).strip():
        _error("MATERIALS_DIR_REQUIRED")
    resolved = _private_path(path, run_dirs=run_dirs, repository=repository)
    if any(part.casefold() == "output" for part in resolved.parts):
        _error("SOURCE_NOT_PRIVATE")
    return resolved


def _material(entry):
    if not isinstance(entry, dict):
        _error("SOURCE_INVALID")
    user, secret = entry.get("user"), entry.get("secret")
    if not isinstance(user, str) or not user.strip() or not isinstance(secret, str) or not secret:
        _error("SOURCE_BINDING_MISSING")
    domain, realm = entry.get("domain", ""), entry.get("realm", "")
    if not isinstance(domain, str) or not isinstance(realm, str):
        _error("SOURCE_INVALID")
    if domain and realm and domain != realm:
        _error("REALM_CONFLICT")
    mode = entry.get("mode", "password")
    if not isinstance(mode, str) or mode.lower() not in MODES:
        _error("SOURCE_MODE_UNSUPPORTED")
    return {"user": user, "secret": secret, "domain": domain or realm, "mode": mode.lower()}


def load_source(path, *, run_dirs=(), repository=None):
    """Read credentials.<graph user>; keep its normalized material only in memory."""
    resolved = _private_path(path, run_dirs=run_dirs, repository=repository)
    try:
        document = json.loads(resolved.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, ValueError):
        _error("SOURCE_UNAVAILABLE")
    entries = document.get("credentials") if isinstance(document, dict) else None
    if not isinstance(entries, dict):
        _error("SOURCE_INVALID")
    return {"path": str(resolved),
            "credentials": {key: _material(entry) for key, entry in entries.items()},
            "provenance": document.get("provenance", {})}


def known_secrets(source):
    """Every external credential value, including short passwords, for pre-write masking."""
    return list(dict.fromkeys(entry["secret"]
                              for entry in (source or {}).get("credentials", {}).values()))


def declared_roles(source) -> dict:
    """Which real account each graph role stands for, as the deployment declares it.

    Identity only -- the secret never leaves ``_material``. The verifier needs this to relate an
    account it observed to the role a fact names: ``getAccount(pc1,domain_administrator,…)`` is
    about the account this deployment calls ``WHOAMIANONY\\Administrator``, and without the
    declaration the honest answer stays UNKNOWN even with the credential already in hand
    (measured 2026-10-08, walk-134 node 5: kiwi dumped the account and the fact could not be
    connected to it).
    """
    roles = {}
    for name, entry in ((source or {}).get("credentials") or {}).items():
        if not isinstance(name, str) or not name.strip() or not isinstance(entry, dict):
            continue
        user, domain = entry.get("user"), entry.get("domain")
        if not isinstance(user, str) or not user.strip():
            continue
        roles[name.strip()] = {"user": user.strip(),
                               "domain": domain.strip() if isinstance(domain, str) else ""}
    return roles


def _digest(material):
    return sha256(json.dumps(material, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8")).hexdigest()


def _external_key(source, graph_user, symbol):
    entries = source["credentials"]
    return symbol if symbol in entries else graph_user if graph_user in entries else None


def _resolve(row, *, run_dirs=(), repository=None):
    source = load_source(row["source_path"],
                         run_dirs=(*run_dirs, row["source_run"]), repository=repository)
    material = source["credentials"].get(row["source_key"])
    if material is None:
        _error("SOURCE_BINDING_MISSING")
    digest_input = material
    if row.get("source_kind") == "derived":
        provenance = source["provenance"]
        if (not isinstance(provenance, dict)
                or provenance.get("source_node") != row["source_node"]
                or provenance.get("source_call") != row["source_call"]):
            _error("SOURCE_CHANGED")
        digest_input = {"material": material, "provenance": provenance}
    if _digest(digest_input) != row["source_digest"]:
        _error("SOURCE_CHANGED")
    return material
