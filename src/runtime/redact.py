"""Mask secrets before anything reaches a log, an artifact or the model.

Two channels, on purpose (run77):

1. the log channel - :func:`redact_text` / :func:`redact_argv`: explicit values plus shape
   rules (NTLM hash pairs, ``password=...`` fragments, Authorization headers). Unchanged:
   this is log hygiene, not DLP, and a redacted log still has to stay readable.
2. the model channel - :func:`project_secrets` / :func:`rebind`: one minimal projection that
   only touches what is certain - a secret in a named field or a known value of this call
   becomes a call-private token; nothing is guessed from shape. The mapping stays with the
   call and is the only thing that may restore a token before dispatch.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

MASK = "<redacted>"
MIN_SECRET_LENGTH = 4

#: Flags whose following token is always a secret. Kept deliberately unambiguous:
#: "-p" means "port" for nmap and "password" for impacket, so the adapters that do
#: need it pass their own set instead of us guessing from the tool name.
SECRET_ARG_FLAGS = frozenset({"--password", "-hashes", "--hashes", "-aesKey", "-pw"})

_HASH_PAIR = re.compile(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b")
_HASH_SINGLE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_PASSWORD_FRAGMENT = re.compile(r"(?i)\b(password|passwd|pwd|secret|token)\b(\s*[:=]\s*)(\S+)")
_AUTH_HEADER = re.compile(r"(?i)\b(authorization\s*:\s*\S+\s+)(\S+)")

#: Internal identifiers are not credentials, and their hex tails must survive masking. A call
#: id ends in 32 hex characters, so the NTLM shape rule ate it: every "this request already
#: ran" refusal handed the model a *truncated* id, so the one sanctioned rerun (`retry_of`)
#: could never match - 109 such refusals in the history and exactly zero model-declared reruns
#: (measured 2026-10-09). The ids the model is told to quote back are named here, not guessed.
ID_SPAN = re.compile(r"\b(?:call-[0-9]{8}T[0-9]{6}-[0-9a-f]{6}-[0-9a-f]{32}"
                     r"|(?:session|context|delivery|channel)-[0-9a-f]{32,64}"
                     r"|(?:web|ssh|ch|entry)-[0-9a-f]{8,16})\b")


def redact_text(text, secrets: Iterable[str] = ()) -> str:
    """Return ``text`` with known secrets and secret-shaped fragments masked."""
    if not text:
        return "" if text is None else str(text)
    out = str(text)
    #: Identifiers step aside for the masking pass and come back untouched.
    held: list[str] = []

    def hold(match):
        held.append(match.group(0))
        return "\x00" + str(len(held) - 1) + "\x00"

    out = ID_SPAN.sub(hold, out)
    for secret in secrets:
        value = str(secret)
        if len(value) >= MIN_SECRET_LENGTH and value in out:
            out = out.replace(value, MASK)
    out = _HASH_PAIR.sub(MASK, out)
    out = _HASH_SINGLE.sub(MASK, out)
    out = _PASSWORD_FRAGMENT.sub(lambda match: match.group(1) + match.group(2) + MASK, out)
    out = _AUTH_HEADER.sub(lambda match: match.group(1) + MASK, out)
    return re.sub(r"\x00(\d+)\x00", lambda match: held[int(match.group(1))], out) if held else out


def redact_argv(
    argv: Iterable[str],
    secrets: Iterable[str] = (),
    secret_flags: Iterable[str] | None = None,
) -> list[str]:
    """Mask secret-bearing flags; the flag itself stays so the log shows intent."""
    flags = SECRET_ARG_FLAGS if secret_flags is None else frozenset(secret_flags)
    out: list[str] = []
    hide_next = False
    for token in argv:
        if hide_next:
            out.append(MASK)
            hide_next = False
            continue
        text = str(token)
        out.append(redact_text(text, secrets))
        if text in flags:
            hide_next = True
    return out


# --- model channel: minimal secret isolation (run77) ---------------------------------
#
# The projection is deliberately small: a secret is either *named* (a field like ``secret``
# or ``password``) or *known* (a value this call actually holds). Nothing here guesses a
# secret from a string's shape, and nothing here is allowed to damage ordinary business
# text: a 32-character checksum is not a credential.

#: What a model sees in place of a secret value - and the only thing rebind restores.
#: Invariant: a token never occurs in material handed to :func:`project_secrets`.
TOKEN_RE = re.compile(r"«secret:([1-9][0-9]*)»")

#: The residue check uses a looser pattern on purpose: a malformed token must be refused
#: just like an unknown one, so nothing token-shaped can reach a dispatch by accident.
TOKEN_RESIDUE_RE = re.compile(r"«secret:[^»]*»?")

#: Field names that carry an actual secret *value*. Small on purpose (run77): no suffix
#: guessing. A bare ``key`` is a routing key, ``graph_hash`` is binding data, and
#: ``credential_ref`` is a reference to walk into - none of them is a secret to erase.
SECRET_FIELDS = frozenset({"secret", "secrets", "password", "passwd", "pwd", "pass",
                           "passphrase", "token", "tokens", "bearer"})


class RedactError(ValueError):
    """The material cannot be projected safely, or a token cannot be restored."""


def _is_secret_field(name) -> bool:
    key = re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")
    return key in SECRET_FIELDS


def is_secret_field(name) -> bool:
    """The public face of the named-secret rule: a secret-named declaration's value is one."""
    return _is_secret_field(name)


def project_secrets(value, *, secrets=()):
    """The one model-channel projection: known secrets become call-private tokens.

    Returns ``(view, mapping)``. ``view`` is a fresh structure - the input is never touched;
    ``mapping`` maps each ``«secret:N»`` back to its real value and stays private to the
    call: it never enters a prompt, a model transcript or a model reply. A value in a named
    secret field always becomes a token; a known value found inside any string becomes one
    too (longest match first, a single left-to-right pass, and the text a replacement just
    produced is never scanned again; only the empty string is left alone).

    Material that already contains token-shaped text is refused: a plain string must never
    be mistaken for a placeholder.
    """
    _assert_no_reserved_tokens(value)
    known = []
    _collect_named_secrets(value, known)
    for extra in secrets or ():
        text = str(extra)
        if text:
            if TOKEN_RESIDUE_RE.search(text):
                raise RedactError("a supplied secret is token-shaped; refusing to project")
            if text not in known:
                known.append(text)
    state = {"next": 1, "tokens": {}, "mapping": {}}
    view = _project(value, known, state)
    return view, dict(state["mapping"])


def _assert_no_reserved_tokens(value):
    for text in _walk_strings(value):
        if TOKEN_RESIDUE_RE.search(text):
            raise RedactError("material already contains token-shaped text; refusing to project")


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_strings(item)


def _collect_named_secrets(value, out):
    if isinstance(value, dict):
        for key, item in value.items():
            if _is_secret_field(key):
                if isinstance(item, str):
                    if item and item not in out:
                        out.append(item)
                    continue
                if item is None:
                    continue
                if isinstance(item, (dict, list, tuple)):
                    _collect_strings_deep(item, out)
                    continue
                raise RedactError("secret field " + str(key) + " carries "
                                  + type(item).__name__ + ", not a string")
            else:
                _collect_named_secrets(item, out)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _collect_named_secrets(item, out)


def _collect_strings_deep(value, out):
    if isinstance(value, str):
        if value and value not in out:
            out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            _collect_strings_deep(item, out)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _collect_strings_deep(item, out)


def _project(value, known, state):
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _is_secret_field(key) and isinstance(item, str):
                out[str(key)] = _tokenize(item, state) if item else item
                continue
            if _is_secret_field(key) and isinstance(item, (dict, list, tuple)):
                out[str(key)] = _project_deep(item, state)
                continue
            out[str(key)] = _project(item, known, state)
        return out
    if isinstance(value, (list, tuple)):
        return [_project(item, known, state) for item in value]
    if isinstance(value, str):
        return _replace_known(value, known, state)
    return value


def _project_deep(value, state):
    if isinstance(value, str):
        return _tokenize(value, state) if value else value
    if isinstance(value, dict):
        return {str(key): _project_deep(item, state) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_project_deep(item, state) for item in value]
    return value


def _tokenize(value, state):
    token = state["tokens"].get(value)
    if token is None:
        token = "«secret:" + str(state["next"]) + "»"
        state["next"] += 1
        state["tokens"][value] = token
        state["mapping"][token] = value
    return token


def _replace_known(text, known, state):
    if not text:
        return text
    ordered = sorted(known, key=len, reverse=True)
    out = []
    index = 0
    while index < len(text):
        hit = ""
        for candidate in ordered:
            if candidate and text.startswith(candidate, index):
                hit = candidate
                break
        if hit:
            out.append(_tokenize(hit, state))
            index += len(hit)
        else:
            out.append(text[index])
            index += 1
    return "".join(out)


def rebind(value, mapping):
    """Restore a whole-value token; the card's declared assembly owns anything else.

    Only a string that is exactly one token is restored (run77): a parameter value or a
    JSON data-file field may carry ``«secret:1»`` on its own, but ``prefix-«secret:1»`` is
    not guessed here - that is the card's encoding job. Unknown tokens are refused.
    """
    if isinstance(value, str) and TOKEN_RE.fullmatch(value):
        if value not in mapping:
            raise RedactError("token " + value + " is not in this call's mapping")
        return mapping[value]
    return value


def residual_tokens(value):
    """Every token-shaped fragment still present; a dispatch refuses when this is not empty."""
    found = []
    for text in _walk_strings(value):
        found.extend(match.group(0) for match in TOKEN_RESIDUE_RE.finditer(text))
    return found


_HEADER_SECRETS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}


_HEADER_VALUE = re.compile(r"(?im)\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*([^\r\n]+)")


def collect_secrets(value, secrets=()):
    """Collect named material for every lean caller, including one-character values."""
    known = [str(item) for item in secrets if item]

    def named(item):
        if isinstance(item, str):
            if item and not residual_tokens(item):
                known.append(item)
        elif isinstance(item, dict):
            for child in item.values():
                named(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                named(child)

    def visit(item):
        if isinstance(item, dict):
            if item.get("kind") in ("password", "ntlm") and isinstance(item.get("value"), str):
                named(item["value"])
            for key, child in item.items():
                if key == "materials" and isinstance(child, list):
                    for material in child:
                        if isinstance(material, dict):
                            named(material.get("value"))
                if is_secret_field(key) or str(key).lower() in _HEADER_SECRETS:
                    named(child)
                else:
                    visit(child)
        elif isinstance(item, (list, tuple)):
            if (len(item) == 2 and isinstance(item[0], str)
                    and item[0].lower() in _HEADER_SECRETS and isinstance(item[1], str)):
                named(item[1])
            for child in item:
                visit(child)
        elif isinstance(item, str):
            for match in _HEADER_VALUE.finditer(item):
                named(match.group(1).strip())

    visit(value)
    return tuple(dict.fromkeys(known))


def mask_secrets(value, secrets=()):
    """Mask before persistence; unlike general log hygiene, known short values count."""
    known = sorted(set(collect_secrets(value, secrets)), key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(item) for item in [MASK, *known])) if known else None

    def text(item):
        # One substitution pass: never rescan text inserted by the masker.
        return pattern.sub(lambda _match: MASK, item) if pattern else item

    def visit(item):
        if isinstance(item, dict):
            return {text(str(key)): MASK if is_secret_field(key) or str(key).lower() in
                    _HEADER_SECRETS or (key == "value" and item.get("kind") in
                    ("password", "ntlm")) else visit(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [visit(child) for child in item]
        return text(item) if isinstance(item, str) else item

    return visit(value)
