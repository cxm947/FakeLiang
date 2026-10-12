"""Declared tools and attributable native exchanges for the existing LeanRun."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import fields
import io
import json
import os
import re
from uuid import uuid4

from jsonschema import Draft202012Validator

from agents._model.contract import ModelReply
from agents._prompt_resources import read_prompt
from runtime import dispatch
from runtime.lean_journal import _bytes, _sha
from runtime.recovery import digest, safe_data, model_reply_record
from runtime.redact import MASK, TOKEN_RESIDUE_RE, collect_secrets

OVERLAY = read_prompt("agents.executor", "templates/native.txt")

#: The base prompt still teaches the flat action shape, and the overlay alone did not stop the model
#: from following those examples: walk-235 measured `deepseek-flash` answering a flat object inside
#: `content` while the declared tool schema sat unused. The rewrites below match by line, so they
#: survive indentation changes, and the count is asserted so a template edit fails loudly instead of
#: silently reverting the model to the flat protocol.
FLAT_SECTION = "* The target-action shape is FLAT"
FLAT_EVIDENCE = "To inspect saved text use "
FLAT_CMDLINE = "always write `{"
FLAT_FUNCTION = (
    "* The target action is ONE declared function call: choose exactly one of the functions supplied"
    " with this request and give its arguments. The function names and argument schemas travel with"
    " the request; never return a flat action object or an action array. Local evidence reads are"
    " separate and call the `evidence` function."
)
FLAT_EVIDENCE_NEW = (
    "Call the `evidence` function to inspect saved text: give call_id and stream, plus either"
    " start/limit or contains."
)
#: The "four things per call" section teaches the flat object one key at a time; with a declared
#: tool schema the argument meanings come from the definitions, so the section is replaced rather
#: than kept. (walk-236 measured the model rebuilding `{"cmd":…,"name":…,"via":…}` out of it.)
FLAT_FOUR = "Four things per call:"
FLAT_FOUR_NEW = (
    "Each declared function's arguments carry the same information the old flat object did: which"
    " program, what content, and where it runs. The definitions supplied with this request say"
    " which arguments a function takes."
)
FLAT_TOOL_LINE = '  * "'


def native_system(base):
    """Rewrite the flat-JSON directions the base prompt still contains, for the native backend."""
    lines = base.splitlines()
    out, index, rewritten = [], 0, 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        indent = line[:len(line) - len(line.lstrip())]
        if stripped.startswith(FLAT_SECTION):
            out.append(indent + FLAT_FUNCTION)
            index += 1
            while index < len(lines) and (not lines[index].strip()
                                          or lines[index].strip().startswith("{")):
                index += 1
            rewritten += 1
            continue
        if FLAT_EVIDENCE in line:
            out.append(indent + FLAT_EVIDENCE_NEW)
            index += 1
            if index < len(lines) and '"limit":2000}' in lines[index]:
                index += 1
            rewritten += 1
            continue
        if FLAT_CMDLINE in line and '"tool":"cmd"' in line:
            out.append(re.sub(r"always write `\{[^`]*\}` -",
                              "call the `cmd` function with the command line as its argument -",
                              line))
            rewritten += 1
            index += 1
            continue
        if FLAT_FOUR in line:
            out.append(indent + FLAT_FOUR_NEW)
            index += 1
            #: The heading wraps onto a second line ("CONTENT (cmd / args / code). \"via\" must
            #: name this step's position - the engine checks it."), and the per-tool bullets
            #: follow. Both keep teaching the flat keys, so both go.
            if (index < len(lines) and lines[index].strip()
                    and not lines[index].strip().startswith("*")):
                index += 1
            while index < len(lines) and (not lines[index].strip()
                                          or lines[index].strip().startswith('* "')):
                index += 1
            rewritten += 1
            continue
        out.append(line)
        index += 1
    #: The shipped prompt carries all three; a caller may hand over a minimal system text that
    #: carries none (the offline tests do). A partial rewrite means the template moved.
    if rewritten not in (0, 4):
        raise ValueError("NATIVE_PROMPT_REWRITE_INCOMPLETE: %d of 4" % rewritten)
    text = "\n".join(out)
    return text + "\n" if base.endswith("\n") else text
STRING = {"type": "string"}
RETRY = {"retry_of": {"type": ["string", "null"]},
         "retry_reason": {"type": "string", "maxLength": 200}}
HEADERS = {"type": "object", "additionalProperties": STRING}
CITATION = {
    "type": "object",
    "properties": {"quote": {"type": "string", "minLength": 1},
                   "call_id": STRING, "stream": {"enum": ["stdout", "stderr"]},
                   "require_marker": {"type": "boolean"}},
    "required": ["quote"], "additionalProperties": False}
MATERIAL = {
    "type": "object",
    "properties": {**{key: STRING for key in
                      ("realm", "user", "value", "source_call", "quote")},
                   "kind": {"enum": ["password", "ntlm"]},
                   "stream": {"enum": ["stdout", "stderr"]}},
    "required": ["realm", "user", "value", "kind", "source_call", "quote"],
    "additionalProperties": False}


def obj(properties, required=(), **extra):
    return {"type": "object", "properties": properties,
            "required": list(required), "additionalProperties": False, **extra}


COMMAND = obj({
    "cmd": {"type": "string", "minLength": 1, "maxLength": dispatch.COMMAND_MAX},
    "name": STRING, "via": STRING, **RETRY}, ("cmd",))
PARAMETERS = {
    **{name: deepcopy(COMMAND) for name in ("msf", "cmd", "pws")},
    "tool": obj({
        "name": {"type": "string", "minLength": 1},
        "args": {"type": "array", "maxItems": dispatch.ARGV_MAX,
                 "items": {"type": "string", "minLength": 1,
                           "maxLength": dispatch.ARG_MAX}},
        "cmd": {"type": "string", "minLength": 1},
        "via": STRING, **RETRY}, ("name",),
        anyOf=[{"required": ["args"]}, {"required": ["cmd"]}]),
    "code": obj({
        "code": {"type": "string", "minLength": 1, "maxLength": dispatch.COMMAND_MAX},
        "lang": STRING, "name": STRING, "via": STRING, **RETRY}, ("code",)),
    "http": obj({
        "method": {"enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]},
        "path": {"type": "string", "minLength": 1}, "headers": HEADERS,
        "body": {"type": ["string", "null"]}, **RETRY}, ("method", "path")),
    "stage": obj({"payload": STRING, "headers": HEADERS, "cookie": STRING, **RETRY}),
    "evidence": obj({
        "call_id": STRING, "stream": {"enum": ["stdout", "stderr"]},
        "start": {"type": "integer", "minimum": 0},
        "limit": {"type": "integer", "minimum": 1, "maximum": 2000},
        "contains": {"type": "string", "maxLength": 200}}, ("call_id",)),
    "abandon": obj({"call_id": STRING, "reason": {"type": "string", "maxLength": 200}},
                   ("call_id",)),
    "finish": obj({
        "claim": {"type": "string", "minLength": 1},
        "verdict": {"enum": ["pass", "unsatisfied", "uncertain"]},
        "citations": {"type": "array", "items": CITATION},
        "materials": {"type": "array", "items": MATERIAL}},
        ("claim", "verdict", "citations")),
}
DESCRIPTIONS = {
    "msf": "Run one command through the frozen meterpreter session.",
    "cmd": "Run one command through the frozen execution position.",
    "pws": "Run one PowerShell command through the frozen Windows position.",
    "tool": "Run one bare program name with args; legacy cmd is also accepted.",
    "code": "Run python or php code; name overrides lang; default is python.",
    "http": "Make one structured HTTP request to the frozen endpoint.",
    "stage": "Issue the current card's frozen delivery step.",
    "evidence": "Read a bounded registered local receipt; never dispatch.",
    "abandon": "Stop local waiting; never cancel, settle or authorize replay.",
    "finish": "Submit this node's claim with exact receipt-backed quotations.",
}


def names(card):
    allowed = dispatch.known_tools(card)
    if "allowed_tools" not in card and "finish" not in allowed:
        allowed.append("finish")
    return [name for name in PARAMETERS
            if name in allowed or name in {"evidence", "abandon"}]


def schemas(card):
    return [{"type": "function", "function": {
        "name": name, "description": DESCRIPTIONS[name], "strict": False,
        "parameters": deepcopy(PARAMETERS[name])}} for name in names(card)]


def shape_error(name, error):
    path = list(error.absolute_path)
    head = path[0] if path else ""
    if name in {"cmd", "pws", "msf"}:
        if head == "cmd" or error.validator == "required":
            return ("LEAN_COMMAND_TOO_LONG" if error.validator == "maxLength"
                    else "LEAN_COMMAND_MISSING")
        return "LEAN_REQUEST_INVALID"
    if name == "tool":
        return "LEAN_TOOL_NAME_INVALID" if head == "name" else "LEAN_TOOL_ARGS_INVALID"
    if name == "code":
        if head == "code" or error.validator == "required":
            return "LEAN_CODE_TOO_LONG" if error.validator == "maxLength" else "LEAN_CODE_MISSING"
        return "LEAN_REQUEST_INVALID"
    if name == "http":
        return {"method": "LEAN_HTTP_METHOD_UNSUPPORTED",
                "path": "LEAN_HTTP_PATH_INVALID"}.get(head, "LEAN_HTTP_REQUEST_INVALID")
    if name == "stage":
        return {"cookie": "LEAN_STAGE_COOKIE_INVALID",
                "headers": "LEAN_STAGE_HEADERS_INVALID"}.get(head, "LEAN_STAGE_REQUEST_INVALID")
    return "LEAN_ACTION_UNSUPPORTED"


def action_for(message, card):
    calls = message.get("tool_calls") if isinstance(message, dict) else None
    if not isinstance(calls, list) or not calls:
        raise ValueError("LEAN_ACTION_UNSUPPORTED: use one declared function")
    if len(calls) != 1:
        raise ValueError("LEAN_ONE_ACTION_PER_ANSWER: exactly one native tool call")
    call = calls[0]
    if (not isinstance(call, dict) or call.get("type") != "function"
            or not isinstance(call.get("function"), dict)
            or not isinstance(call.get("id"), str) or not call["id"]):
        raise ValueError("LEAN_ACTION_UNSUPPORTED: native call envelope invalid")
    function = call["function"]
    name = function.get("name")
    if not isinstance(name, str) or name not in names(card):
        raise ValueError("LEAN_TOOL_UNDECLARED: native function is not available")
    try:
        args = json.loads(function.get("arguments", ""))
    except (ValueError, TypeError):
        raise ValueError("LEAN_REQUEST_INVALID: invalid function arguments") from None
    errors = list(Draft202012Validator(PARAMETERS[name]).iter_errors(args))
    if errors:
        raise ValueError(shape_error(name, errors[0]) + ": native argument contract refused")
    if name == "tool":
        bare = args["name"].strip()
        if not bare or any(char in bare for char in (" ", "/", "\\")):
            raise ValueError("LEAN_TOOL_NAME_INVALID")
        args["name"] = bare
    if name == "code":
        lang = str(args.get("name") or args.get("lang") or "python").strip().lower()
        if lang not in dispatch.CODE_LANGS:
            raise ValueError("LEAN_CODE_LANG_UNSUPPORTED")
        if "lang" not in args and "name" not in args:
            args["lang"] = "python"
    if name == "finish":
        return {"kind": "finish", "claim": args["claim"],
                "claimed_verdict": args["verdict"], "citations": args["citations"],
                **({"materials": args["materials"]} if "materials" in args else {})}
    if name in {"evidence", "abandon"}:
        return {"kind": name, **args}
    return {"kind": "call", "request": {"tool": name, **args}}


def neutralize(value):
    if isinstance(value, str):
        return TOKEN_RESIDUE_RE.sub(MASK, value)
    if isinstance(value, list):
        return [neutralize(item) for item in value]
    if isinstance(value, dict):
        return {key: neutralize(item) for key, item in value.items()}
    return value


def ids(message):
    if not isinstance(message, dict) or message.get("role") != "assistant":
        return []
    calls = message.get("tool_calls") or []
    if not isinstance(calls, list) or not calls:
        return []
    if any(not isinstance(call, dict) or call.get("type") != "function"
           or not isinstance(call.get("function"), dict)
           or not isinstance(call["function"].get("name"), str)
           or not isinstance(call["function"].get("arguments"), str) for call in calls):
        return []
    values = [call.get("id") for call in calls]
    if any(not isinstance(item, str) or not item for item in values):
        return []
    return values if len(set(values)) == len(values) else []


class NativeSession:
    """Native exchanges; target dispatch and proof remain exclusively LeanRun's."""
    backend = "native"

    def __init__(self, client, run):
        self.client, self.run = client, run
        key = getattr(client, "_api_key", "")
        if key and key not in run.secrets:
            run.secrets.append(key)
        self.path = run.root / "native_tools.jsonl"
        self.rows, self.pending, self.replay = [], None, None
        self.binding = _sha(_bytes({
            "run_id": run.run_id, "card_digest": run.card["digest"],
            "task": run.task, "scope": run.scope, "protocol": "native-tools-v1"}))
        if not self.path.exists():
            if any(row.get("kind") in {"decision", "intent", "receipt", "conclusion"}
                   for row in run._read()):
                raise ValueError("MODEL_BACKEND_FROZEN: existing lean run is legacy")
            return
        try:
            raw = self.path.read_bytes()
            if raw and not raw.endswith(b"\n"):
                raise ValueError("unterminated native exchange")
            previous, active, seen = "", {}, set()
            for line in raw.decode("utf-8").splitlines():
                row = json.loads(line)
                checksum = row.pop("row_sha256")
                if (row.get("previous_sha256") != previous
                        or row.get("binding") != self.binding
                        or _sha(_bytes(row)) != checksum):
                    raise ValueError("invalid native exchange chain")
                row["row_sha256"] = checksum
                previous = checksum
                key, phase = row["exchange_id"], row["phase"]
                if phase == "request":
                    if key in seen or active:
                        raise ValueError("invalid request ordering")
                    seen.add(key)
                    active[key] = {"request": row}
                elif phase in {"response", "accepted"}:
                    if key not in active or phase in active[key]:
                        raise ValueError("invalid response ordering")
                    if phase == "accepted" and "response" not in active[key]:
                        raise ValueError("accepted without response")
                    active[key][phase] = row
                elif phase == "result":
                    if key not in active or "response" not in active[key]:
                        raise ValueError("result without response")
                    active.pop(key)
                elif phase == "unknown":
                    if key not in active or "response" in active[key]:
                        raise ValueError("invalid unknown ordering")
                else:
                    raise ValueError("invalid phase")
                self.rows.append(row)
        except (KeyError, TypeError, ValueError, OSError):
            raise ValueError("MODEL_CALL_UNKNOWN: native exchange integrity failed") from None
        if active:
            self.pending = next(iter(active.values()))
            if "response" not in self.pending:
                raise ValueError("MODEL_CALL_UNKNOWN: native request outcome unconfirmed")
            result = self.associated_result()
            if result is not None:
                self.finish(result)
            else:
                saved = self.pending["response"]["reply"]
                if digest(saved) != self.pending["response"]["reply_digest"]:
                    raise ValueError("MODEL_CALL_UNKNOWN: private native reply unavailable")
                valid = {field.name for field in fields(ModelReply)}
                self.replay = ModelReply(**{key: value for key, value in saved.items()
                                            if key in valid})

    def __getattr__(self, name):
        return getattr(self.client, name)

    def append(self, exchange_id, phase, **data):
        row = safe_data({
            "binding": self.binding, "exchange_id": exchange_id, "phase": phase,
            "previous_sha256": self.rows[-1]["row_sha256"] if self.rows else "",
            **data}, self.run.secrets)
        row["row_sha256"] = _sha(_bytes(row))
        with io.open(self.path, "a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.rows.append(row)
        return row

    def bounded(self, rows):
        rows = deepcopy(rows)
        for event in rows:
            if event.get("kind") == "receipt":
                for field in ("stdout", "stderr"):
                    text = str(event["receipt"].get(field) or "")
                    event["receipt"][field] = text[:6000]
                    if len(text) > 6000:
                        event["receipt"][field + "_excerpted"] = True
                        event["receipt"][field + "_chars"] = len(text)
        return safe_data(rows, self.run.secrets)

    def accept(self, action):
        if self.pending is None:
            raise ValueError("MODEL_CALL_UNKNOWN: native action has no exchange")
        identity = digest(action)
        previous = self.pending.get("accepted")
        if previous is not None:
            if previous["action_digest"] != identity:
                raise ValueError("MODEL_CALL_UNKNOWN: resumed native action changed")
            return
        logical = {key: value for key, value in (action.get("request") or {}).items()
                   if key not in {"retry_of", "retry_reason"}}
        rows = self.run._read()
        accepted = self.append(
            self.pending["request"]["exchange_id"], "accepted",
            action=action, action_digest=identity,
            source_cursor=rows[-1]["seq"] if rows else 0,
            request_digest=_sha(_bytes(logical)),
            provider_ids=ids(self.pending["response"]["reply"].get("native_message")))
        self.pending["accepted"] = accepted

    def associated_result(self):
        if self.pending is None:
            return None
        accepted = self.pending.get("accepted")
        cursor = (accepted["source_cursor"] if accepted
                  else self.pending["request"]["start_seq"])
        events = [row for row in self.run.model_history() if row["seq"] > cursor]
        controls = [row for row in events if row.get("kind") == "refusal"]
        if accepted is None:
            if any(row.get("kind") in {"intent", "receipt", "conclusion",
                                      "receipt_read", "abandon"} for row in events):
                raise ValueError("MODEL_CALL_UNKNOWN: native action association missing")
            if controls:
                return {"events": self.bounded(controls), "source": "native argument refusal"}
            reply = self.pending["response"]["reply"]
            if not reply.get("ok"):
                return {"events": [], "source": "confirmed unusable model answer",
                        "error": reply.get("error", "")}
            return None
        action = accepted["action"]
        kind = action.get("kind")
        if kind == "call":
            intents, receipts = self.run._calls(self.run._read())
            fresh = [row for row in intents.values()
                     if row["seq"] > cursor and not row.get("parent_call_id")]
            matching = [row for row in fresh
                        if row["request_digest"] == accepted["request_digest"]]
            if len(matching) > 1 or any(row not in matching for row in fresh):
                raise ValueError("MODEL_CALL_UNKNOWN: source-call association changed")
            if matching:
                call_id = matching[0]["call_id"]
                receipt = receipts.get(call_id)
                if receipt is None or receipt.get("status") != "completed_transport":
                    raise ValueError("MODEL_CALL_UNKNOWN: target outcome unconfirmed")
                view = self.run._view(receipt)
                chosen = [{"kind": "receipt", "call_id": call_id, "receipt": view}]
                return {"events": self.bounded(chosen + controls),
                        "internal_call_ids": [call_id],
                        "source": "matched LeanRun intent and verified receipt"}
            for refusal in controls:
                if refusal.get("refusal", {}).get("reason_code") != "LEAN_CALL_ALREADY_RAN":
                    continue
                for item in refusal["refusal"].get("already_ran") or []:
                    call_id = item.get("call_id")
                    intent, receipt = intents.get(call_id), receipts.get(call_id)
                    if (intent and receipt
                            and intent["request_digest"] == accepted["request_digest"]
                            and receipt.get("status") == "completed_transport"):
                        chosen = [{"kind": "receipt", "call_id": call_id,
                                   "receipt": self.run._view(receipt)}, refusal]
                        return {"events": self.bounded(chosen),
                                "internal_call_ids": [call_id],
                                "source": "duplicate refusal and original verified receipt"}
            if controls:
                return {"events": self.bounded(controls), "source": "refused before dispatch"}
            return None
        if kind == "evidence":
            selected = [row for row in events if row.get("kind") == "receipt_read"
                        and row.get("evidence", {}).get("call_id") == action.get("call_id")]
            selected += [row for row in controls
                         if row.get("refusal", {}).get("reason_code") in
                         {"LEAN_EVIDENCE_READ_LIMIT", "LEAN_EVIDENCE_READ_REFUSED"}]
        elif kind == "abandon":
            selected = [row for row in events if row.get("kind") == "abandon"
                        and row.get("call_id") == action.get("call_id")]
        elif kind == "finish":
            selected = [row for row in events if row.get("kind") == "conclusion"] + controls
        else:
            selected = controls
        if selected:
            return {"events": self.bounded(selected), "source": "associated local LeanRun result"}
        return None

    def finish(self, result):
        self.append(self.pending["request"]["exchange_id"], "result", result=result)
        self.pending, self.replay = None, None

    def close(self):
        if self.pending is None:
            return
        result = self.associated_result()
        if result is None:
            raise ValueError("MODEL_CALL_UNKNOWN: native action has no associated result")
        self.finish(result)

    def history(self, byte_budget):
        from langchain_core.messages import (
            AIMessage, convert_to_messages, convert_to_openai_messages, trim_messages)
        if byte_budget <= 0:
            return []
        responses = {row["exchange_id"]: row for row in self.rows
                     if row["phase"] == "response"}
        history = []
        for row in self.rows:
            response = responses.get(row["exchange_id"])
            if row["phase"] != "result" or not response or not response["reply"].get("ok"):
                continue
            message = deepcopy(response["reply"].get("native_message"))
            values = ids(message)
            if not values:
                continue
            for call in message["tool_calls"]:
                try:
                    arguments = json.loads(call["function"]["arguments"])
                    call["function"]["arguments"] = json.dumps(
                        neutralize(arguments), ensure_ascii=False)
                except (ValueError, TypeError):
                    call["function"]["arguments"] = neutralize(call["function"]["arguments"])
            history.append(neutralize(message))
            history.extend(
                {"role": "tool", "tool_call_id": value,
                 "content": json.dumps(neutralize(row["result"]), ensure_ascii=False)}
                for value in values)
        if not history:
            return []
        typed = convert_to_messages(history)
        trimmed = trim_messages(
            typed, max_tokens=4,
            token_counter=lambda rows: sum(isinstance(row, AIMessage) for row in rows),
            strategy="last", start_on="ai", end_on="tool", allow_partial=False)
        trimmed = trim_messages(
            trimmed, max_tokens=byte_budget,
            token_counter=lambda rows: len(json.dumps(
                convert_to_openai_messages(rows), ensure_ascii=False).encode("utf-8")),
            strategy="last", start_on="ai", end_on="tool", allow_partial=False)
        wire = convert_to_openai_messages(trimmed)
        pending = set()
        for row in wire:
            if row["role"] == "assistant":
                if pending:
                    raise ValueError("MODEL_CALL_UNKNOWN: native history pairing failed")
                pending = set(ids(row))
                if not pending:
                    raise ValueError("MODEL_CALL_UNKNOWN: native history pairing failed")
            elif row["role"] == "tool" and row.get("tool_call_id") in pending:
                pending.remove(row["tool_call_id"])
            else:
                raise ValueError("MODEL_CALL_UNKNOWN: native history pairing failed")
        if pending:
            raise ValueError("MODEL_CALL_UNKNOWN: native history pairing failed")
        return wire

    def complete(self, *, task, system, user, **kwargs):
        if task != "lean_action":
            return self.client.complete(task=task, system=system, user=user, **kwargs)
        prompt_hash = _sha(_bytes({"system": system, "user": user}))
        if self.replay is not None:
            if prompt_hash != self.pending["request"]["prompt_hash"]:
                raise ValueError("MODEL_CALL_UNKNOWN: native resume prompt changed")
            reply, self.replay = self.replay, None
            if reply.ok:
                reply.payload = {"native": True}
            return reply
        self.close()
        messages = [
            {"role": "system", "content": native_system(system) + OVERLAY},
            {"role": "user", "content": user},
            *self.history(max(0, 24000 - len(user.encode("utf-8"))))]
        tools = schemas(self.run.card)
        rows = self.run._read()
        exchange_id = uuid4().hex
        request = self.append(
            exchange_id, "request", start_seq=rows[-1]["seq"] if rows else 0,
            prompt_hash=prompt_hash, messages=messages, tools=tools)
        reply = self.client.invoke_tools(
            task=task, messages=messages, tools=tools, **kwargs)
        if not getattr(reply, "response_confirmed", False):
            self.append(exchange_id, "unknown", error="MODEL_CALL_UNKNOWN")
            raise ValueError("MODEL_CALL_UNKNOWN: native outcome unconfirmed")
        parsed = []
        for call in (getattr(reply, "native_message", None) or {}).get("tool_calls") or []:
            try:
                parsed.append(json.loads(call["function"]["arguments"]))
            except (ValueError, TypeError, KeyError):
                pass
        self.run.secrets[:] = list(collect_secrets(parsed, self.run.secrets))
        original_digest, saved = model_reply_record(reply, self.run.secrets)
        response = self.append(
            exchange_id, "response", reply=saved, reply_digest=original_digest)
        self.pending = {"request": request, "response": response}
        if reply.ok:
            reply.payload = {"native": True}
        return reply

    def native_action(self, reply):
        return action_for(getattr(reply, "native_message", None), self.run.card)
