"""Synchronous ChatOpenAI with explicit retry, deadline and secrecy policies."""
from __future__ import annotations

from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
import logging
import queue
import re
import threading
import time

from .contract import (
    EMPTY_CONTENT_ERROR, TRUNCATED_ERROR, UNPARSEABLE_ANSWER_ERROR,
    ModelClient, ModelReply, WIRES,
)
from .text import _json_object_prompts, _parse_json_text


class _QuietTransport(logging.Filter):
    def filter(self, record):
        return False


def _mute_transport_logs():
    prefixes = ("openai", "httpx", "httpx2", "httpcore", "httpcore2",
                "langchain_openai", "langsmith")
    names = set(logging.Logger.manager.loggerDict)
    names.update(prefixes)
    names.add("openai._base_client")
    for name in names:
        if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes):
            logger = logging.getLogger(name)
            if not any(isinstance(item, _QuietTransport) for item in logger.filters):
                logger.addFilter(_QuietTransport())


def secret_echo(value, secret):
    if not secret:
        return False
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
        elif isinstance(item, str):
            if secret in item:
                return True
            decoded_escapes = re.sub(
                r"\\u([0-9a-fA-F]{4})",
                lambda match: chr(int(match.group(1), 16)), item)
            if decoded_escapes != item:
                pending.append(decoded_escapes)
            try:
                decoded = json.loads(item)
            except (ValueError, TypeError):
                continue
            if decoded != item:
                pending.append(decoded)
    return False


class ChatModel(ModelClient):
    backend = "native"
    supports_deadline = True

    def __init__(self, *, name, base_url, api_key, timeout=60.0, retries=2,
                 max_tokens=None, temperature=0.0, reasoning_effort="", wire="chat",
                 factory=None, converter=None, clock=None):
        self.name = str(name or "")
        self.base_url = str(base_url or "").rstrip("/")
        self._api_key = str(api_key or "")
        self.timeout = float(timeout)
        self.retries = max(0, int(retries))
        self.max_tokens = int(max_tokens or 0)
        self.temperature = float(temperature)
        self.reasoning_effort = str(reasoning_effort or "").strip().lower()
        self.wire = str(wire or "chat").strip().lower()
        if self.wire not in WIRES:
            raise ValueError("MODEL_WIRE_UNKNOWN")
        self._factory, self._converter = factory, converter
        self._clock = clock or time

    def available(self):
        return bool(self.name and self.base_url and self._api_key)

    def complete(self, *, task, system, user, **options):
        system, user = _json_object_prompts(str(system), str(user))
        return self._invoke(
            task, [{"role": "system", "content": system},
                   {"role": "user", "content": user}], None, **options)

    def invoke_tools(self, *, task, messages, tools, **options):
        if not isinstance(messages, list) or not messages:
            raise ValueError("MODEL_MESSAGES_INVALID")
        if not isinstance(tools, list) or not tools:
            raise ValueError("MODEL_TOOLS_INVALID")
        return self._invoke(task, messages, tools, **options)

    def _model(self, timeout, effort, budget, tools=None):
        factory = self._factory
        if factory is None:
            try:
                from langchain_openai import ChatOpenAI
                from langchain_core.globals import set_debug, set_verbose
            except ImportError:
                raise ValueError("MODEL_DEPENDENCY_UNAVAILABLE: langchain_openai") from None
            set_debug(False)
            set_verbose(False)
            factory = ChatOpenAI
        _mute_transport_logs()
        options = {
            "model": self.name, "base_url": self.base_url,
            "api_key": self._api_key, "timeout": timeout,
            "max_retries": 0, "temperature": self.temperature,
            "streaming": False, "callbacks": [], "verbose": False,
        }
        if budget:
            options["max_tokens"] = budget
        #: "Thinking off" and declared tools do not mix on this provider: with
        #: `extra_body={"thinking": {"type": "disabled"}}` the model answers the tool request as a
        #: flat object inside `content` and returns no tool call at all (measured 2026-10-12, the
        #: same messages and schemas return a proper call with thinking left alone). So native
        #: calls keep the provider's own thinking behaviour.
        #: A tool-carrying request must not carry a thinking directive at all. Measured
        #: 2026-10-12 on this provider: with `extra_body={"thinking": {"type": "disabled"}}` the
        #: model answers the tool request as a flat object inside `content` and returns no tool
        #: call, and forwarding `reasoning_effort="none"` keeps it in that behaviour too - the same
        #: messages and schemas return a proper call when neither is sent.
        if effort and tools is None:
            if effort == "none" and self.wire == "chat":
                options["extra_body"] = {"thinking": {"type": "disabled"}}
            else:
                options["reasoning_effort"] = effort
        if self.wire == "responses":
            options["use_responses_api"] = True
        try:
            return factory(**options)
        except Exception:
            raise ValueError("MODEL_CONFIGURATION_INVALID") from None

    def _once(self, runnable, messages, remaining):
        result = queue.Queue(maxsize=1)
        expires = self._clock.monotonic() + remaining

        def call():
            try:
                if self._factory is None:
                    from langsmith.run_helpers import tracing_context
                    context = tracing_context(enabled=False)
                else:
                    context = nullcontext()
                with context:
                    _mute_transport_logs()
                    if self._clock.monotonic() >= expires:
                        raise ValueError("MODEL_CALL_UNKNOWN")
                    answer = runnable.invoke(messages, config={"callbacks": []})
                result.put(("reply", answer))
            except BaseException as error:
                result.put(("error", error))

        threading.Thread(target=call, name="agv-model-call", daemon=True).start()
        try:
            return result.get(timeout=max(0.0, remaining))
        except queue.Empty:
            raise ValueError("MODEL_CALL_UNKNOWN: deadline elapsed") from None

    def _failure(self, error, attempt, started, request_id, confirmed=True):
        return ModelReply(
            ok=False, model=self.name, error=error, attempts=attempt,
            latency_ms=int((self._clock.monotonic() - started) * 1000),
            request_sha256=request_id, response_confirmed=confirmed)

    def _invoke(self, task, messages, tools, *, timeout=None, retries=None,
                max_tokens=None, reasoning_effort="", deadline_at=None):
        limit = float(self.timeout if timeout is None else timeout)
        if limit <= 0:
            raise ValueError("MODEL_TIMEOUT_INVALID")
        tries = self.retries if retries is None else max(0, int(retries))
        budget = int(max_tokens or self.max_tokens or 0)
        effort = str(reasoning_effort or self.reasoning_effort or "").strip().lower()
        started = self._clock.monotonic()
        deadline = started + max(120.0, limit * (tries + 1) + 90.0)
        if deadline_at is not None:
            deadline = min(deadline, started + max(
                0.0, float(deadline_at) - self._clock.time()))
        identity = {
            "task": task, "messages": messages, "tools": tools,
            "backend": self.backend, "model": self.name, "base_url": self.base_url,
            "wire": self.wire, "temperature": self.temperature,
            "reasoning_effort": effort, "max_tokens": budget,
            "tool_choice": "auto" if tools is not None else None,
            "parallel_tool_calls": False if tools is not None else None,
        }
        request_id = hashlib.sha256(json.dumps(
            identity, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()
        attempt, allowed, bonus, last_status = 0, tries, False, None
        while attempt <= allowed:
            remaining = deadline - self._clock.monotonic()
            if remaining <= 0:
                if last_status is not None:
                    return self._failure("HTTP " + str(last_status), attempt,
                                         started, request_id)
                raise ValueError("MODEL_CALL_UNKNOWN: deadline elapsed")
            model = self._model(min(limit, remaining), effort, budget, tools)
            runnable = (model.bind(response_format={"type": "json_object"})
                        if tools is None else model.bind_tools(
                            tools, tool_choice="auto", parallel_tool_calls=False))
            remaining = deadline - self._clock.monotonic()
            if remaining <= 0:
                raise ValueError("MODEL_CALL_UNKNOWN: deadline elapsed")
            attempt += 1
            kind, value = self._once(runnable, messages, remaining)
            if kind == "reply":
                if self._clock.monotonic() >= deadline:
                    raise ValueError("MODEL_CALL_UNKNOWN: late response")
                try:
                    return self._response(value, tools is not None, attempt,
                                          started, request_id, budget)
                except Exception:
                    return self._failure(
                        UNPARSEABLE_ANSWER_ERROR + ": response envelope",
                        attempt, started, request_id)
            if isinstance(value, (KeyboardInterrupt, SystemExit)):
                raise value
            status = getattr(value, "status_code", None)
            if status is None:
                status = getattr(getattr(value, "response", None), "status_code", None)
            if not isinstance(status, int) or status < 400:
                raise ValueError(
                    "MODEL_CALL_UNKNOWN: unconfirmed transport outcome") from None
            last_status = status
            if not (status == 429 or 500 <= status < 600):
                return self._failure("HTTP " + str(status), attempt, started, request_id)
            if not bonus:
                allowed += 4
                bonus = True
            if attempt > allowed:
                break
            remaining = deadline - self._clock.monotonic()
            if remaining <= 0:
                break
            self._clock.sleep(min(5.0 * attempt, 30.0, remaining))
        return self._failure("HTTP " + str(last_status), attempt, started, request_id)

    def _response(self, message, native, attempt, started, request_id, budget):
        dump = message.model_dump()
        if secret_echo(dump, self._api_key):
            return self._failure(
                "provider response included the transport credential",
                attempt, started, request_id)
        metadata = getattr(message, "response_metadata", None) or {}
        usage = getattr(message, "usage_metadata", None) or {}
        tokens = metadata.get("token_usage") or metadata.get("usage") or {}
        details = usage.get("output_token_details") or {}
        completion = tokens.get("completion_tokens_details") or {}
        output = tokens.get("output_tokens_details") or {}
        reason = str(metadata.get("finish_reason") or metadata.get("status") or "")
        if reason == "incomplete":
            if (metadata.get("incomplete_details") or {}).get("reason") == "max_output_tokens":
                reason = "length"
        content = getattr(message, "content", "")
        if isinstance(content, list):
            content = "".join(str(item.get("text") or "") for item in content
                              if isinstance(item, dict)
                              and item.get("type") in ("text", "output_text"))
        if not isinstance(content, str):
            content = ""
        reply = ModelReply(
            ok=False, text=content,
            model=str(metadata.get("model_name") or metadata.get("model") or self.name),
            attempts=attempt, request_sha256=request_id,
            latency_ms=int((self._clock.monotonic() - started) * 1000),
            prompt_tokens=int(usage.get("input_tokens") or tokens.get("prompt_tokens")
                              or tokens.get("input_tokens") or 0),
            completion_tokens=int(usage.get("output_tokens") or tokens.get("completion_tokens")
                                  or tokens.get("output_tokens") or 0),
            reasoning_tokens=int(details.get("reasoning") or completion.get("reasoning_tokens")
                                 or output.get("reasoning_tokens") or 0),
            finish_reason=reason, max_tokens=budget, response_confirmed=True)
        if native:
            converter = self._converter
            if converter is None:
                from langchain_core.messages import convert_to_openai_messages
                converter = convert_to_openai_messages
            wire = converter(message)
            if isinstance(wire, list):
                wire = wire[0] if len(wire) == 1 else None
            if not isinstance(wire, dict) or wire.get("role") != "assistant":
                return self._failure(UNPARSEABLE_ANSWER_ERROR + ": native response",
                                     attempt, started, request_id)
            wire = deepcopy(wire)
            raw_calls = (getattr(message, "additional_kwargs", None) or {}).get("tool_calls")
            if raw_calls is not None:
                wire["tool_calls"] = deepcopy(raw_calls)
            reply.native_message = wire
            reply.tool_calls = deepcopy(getattr(message, "tool_calls", None) or [])
            reply.text = json.dumps(wire, ensure_ascii=False, allow_nan=False)
        if reason == "length":
            reply.error = TRUNCATED_ERROR
            return reply
        if native:
            if getattr(message, "invalid_tool_calls", None):
                reply.error = UNPARSEABLE_ANSWER_ERROR + ": invalid native arguments"
            elif not reply.native_message.get("tool_calls"):
                reply.error = EMPTY_CONTENT_ERROR + " (no native tool call)"
            else:
                reply.ok = True
            return reply
        if not content:
            reply.error = EMPTY_CONTENT_ERROR
            return reply
        parsed, problem = _parse_json_text(content)
        if parsed is None:
            reply.error = problem
            return reply
        if secret_echo(parsed, self._api_key):
            reply.text = ""
            reply.error = "provider response included the transport credential"
            return reply
        reply.ok, reply.payload = True, parsed
        return reply
