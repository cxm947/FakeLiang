"""One scoped TCP endpoint, no proxy/redirect: the lean pilot transport."""
from __future__ import annotations

import base64
import ipaddress
import json
import re
from urllib.parse import urlsplit
from uuid import uuid4


# ponytail: HTTP only and 64 KiB bodies; HTTPS/streaming need their own transport guards.
CLIENT_SOURCE = r'''
import base64, codecs, hashlib, json, sys
from http.client import HTTPConnection
p = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
marker = p["marker"]
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
print(marker + "start", flush=True)
conn = HTTPConnection(p["host"], p["port"], timeout=10)
try:
    conn.connect()
    peer = conn.sock.getpeername()
    body = p.get("body")
    conn.request(p["method"], p["path"], body=None if body is None else body.encode("utf-8"), headers=p["headers"])
    response = conn.getresponse()
    limit = 64 * 1024
    captured = response.read(limit + 1)
    truncated = len(captured) > limit
    captured = captured[:limit]
    declared = response.headers.get_param("charset", header="content-type")
    selected = "utf-8" if declared is None else declared
    decoding = {"declared_charset": declared, "selected_encoding": selected,
                "source": "default_utf8" if declared is None else "content_type", "status": "decoded"}
    text = ""
    try:
        selected = codecs.lookup(selected).name
        decoding["selected_encoding"] = selected
        text = captured.decode(selected, errors="strict")
    except (LookupError, TypeError) as error:
        decoding.update(status="unknown_charset", error=str(error))
    except UnicodeError as error:
        decoding.update(status="decode_failed", error=str(error))
    # ponytail: no credential harvesting or cookie jar in the pilot; keep only sensitive header names.
    headers = [(name, "<redacted>" if name.lower() in {"authorization", "proxy-authorization", "cookie", "set-cookie"}
                else value) for name, value in response.getheaders()]
    print(json.dumps({"origin": p["origin"], "request": {"method": p["method"], "path": p["path"]},
        "peer": {"host": peer[0], "port": peer[1]}, "status": response.status, "reason": response.reason,
        "headers": headers, "body": text, "body_sha256": hashlib.sha256(captured).hexdigest(),
        "body_decoding": decoding, "truncation": {"truncated": truncated, "body_limit": limit, "body_bytes": len(captured)}},
        ensure_ascii=False), flush=True)
    #: **原文也要单独给一份**（爷爷 2026-10-07）：上面那行 JSON 会把响应体再转义一层
    #: （`\"`、`\\/`），于是"回执里存的"和"模型看到的"差一层皮 —— 模型照抄会被判引文无效，
    #: 而我们为了核对还要写一堆"转义层级不算内容"的补丁。记账格式改成"机械报告一行 + 原文块"：
    #: 账本里存的就是原文，所见即所存，核对按原文比。
    if text:
        print("<<<agv-body>>>", flush=True)
        print(text, flush=True)
        print("<<<agv-body-end>>>", flush=True)
except Exception as error:
    print(json.dumps({"error": {"type": type(error).__name__, "message": str(error)}}), flush=True)
    raise SystemExit(2)
finally:
    conn.close()
print(marker + "end 0", flush=True)
'''.strip()


def endpoint_parts(scope):
    """Validate the runtime-owned scope; model arguments cannot supply an endpoint.

    The endpoint is a host and a port over TCP. 爷爷 2026-10-04: "http 也是 tcp 的嘛，
    只需要在处理攻击图的时候统一成 tcp" - so the graph's service spelling is folded to
    ``tcp`` when the graph is read, and this module never carries a second endpoint concept
    (no URL, no scheme, no default port).

    A *position* scope (``resources`` = ``execution_position``) has no port of its own: the step
    happens on a machine that was reached through a handle, not at a service port. It is still
    validated here, and it still answers with one host, so every caller keeps exactly one shape
    to reason about - a position simply answers with ``None`` where an endpoint answers with its
    port, and the request builders refuse that ``None`` instead of inventing a port.
    """
    if isinstance(scope, dict) and scope.get("resources") == "execution_position":
        return position_parts(scope), None
    if not isinstance(scope, dict) or scope.get("resources") != "whole_endpoint":
        raise ValueError("LEAN_ENDPOINT_RESOURCE_SCOPE_UNSUPPORTED: whole_endpoint required")
    if set(scope) != {"host", "port", "protocol", "vantage", "resources"}:
        raise ValueError("LEAN_ENDPOINT_SCOPE_INVALID: host, port, protocol, vantage and "
                         "resources required")
    if scope.get("protocol") != "tcp":
        raise ValueError("LEAN_ENDPOINT_PROTOCOL_UNSUPPORTED: tcp only")
    if not isinstance(scope["vantage"], str) or not scope["vantage"].strip():
        raise ValueError("LEAN_ENDPOINT_SCOPE_INVALID: vantage required")
    try:
        host = str(ipaddress.ip_address(str(scope["host"])))
    except (ValueError, TypeError):
        raise ValueError("LEAN_ENDPOINT_HOST_INVALID: literal IP required") from None
    port = scope["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("LEAN_ENDPOINT_PORT_INVALID")
    return host, port


def position_parts(scope):
    """Validate an *execution position*: which host a command runs on, with no endpoint.

    Some steps only exist on a machine that a handle already reaches (a path inside one sandbox,
    a local identity read, a local privilege step). Demanding a host+port for them is what used
    to stop a walk dead, so the scope names the position instead - and names the handle that
    reaches it, because an address is not a position: the same address may front different
    isolated contexts, and only the handle says which one we are in.
    """
    if not isinstance(scope, dict) or scope.get("resources") != "execution_position":
        raise ValueError("LEAN_POSITION_RESOURCE_SCOPE_UNSUPPORTED: execution_position required")
    if set(scope) - {"host", "vantage", "resources", "carrier", "logical"}:
        raise ValueError("LEAN_POSITION_SCOPE_INVALID: host, vantage, resources, carrier, logical")
    if not {"host", "vantage", "resources"} <= set(scope):
        raise ValueError("LEAN_POSITION_SCOPE_INVALID: host, vantage and resources required")
    if not isinstance(scope["vantage"], str) or not scope["vantage"].strip():
        raise ValueError("LEAN_POSITION_SCOPE_INVALID: vantage required")
    try:
        host = str(ipaddress.ip_address(str(scope["host"])))
    except (ValueError, TypeError):
        raise ValueError("LEAN_POSITION_HOST_INVALID: literal IP required") from None
    return host


def stage_request(stage, request):
    """Turn the card's fixed stage step into the plain http request the runtime already knows.

    The card owns the wire shape (field names, file name, content type, payload); the model only
    asks for the step, and may override the payload. Everything the model does not have to guess is
    a step it cannot waste - the measured failure was three upload attempts while it searched for
    the right multipart shape.
    """
    if not isinstance(stage, dict):
        raise ValueError("LEAN_STAGE_UNDECLARED: this card has no fixed stage step")
    if (set(request or {}) - {"tool", "payload", "headers", "cookie"}):
        raise ValueError("LEAN_STAGE_REQUEST_INVALID: tool, an optional payload, headers or cookie")
    payload = str((request or {}).get("payload") or stage.get("payload") or "")
    if not payload:
        raise ValueError("LEAN_STAGE_PAYLOAD_MISSING")
    boundary = "agv" + uuid4().hex
    parts = []
    for name, value in stage.get("fields") or []:
        parts.append("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                     % (boundary, name, value))
    parts.append("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
                 "Content-Type: %s\r\n\r\n"
                 % (boundary, stage.get("file_field") or "ATTACHMENT",
                    stage.get("filename") or "agv.bin",
                    stage.get("content_type") or "application/octet-stream"))
    parts.append(payload)
    parts.append("\r\n--%s--\r\n" % boundary)
    # A deployment that wants a session puts a cookie on *every* step, this one included. The
    # stage step is the card's shape, but its headers are the caller's - dropping them would make
    # the "convenient" action silently unusable exactly where it is most needed.
    extra = request.get("headers") or {}
    if (not isinstance(extra, dict)
            or any(not isinstance(name, str) or not isinstance(value, str)
                   for name, value in extra.items())):
        raise ValueError("LEAN_STAGE_HEADERS_INVALID: a string-to-string map")
    headers = dict(extra)
    cookie = request.get("cookie")
    if cookie is not None and not isinstance(cookie, str):
        raise ValueError("LEAN_STAGE_COOKIE_INVALID: a string")
    cookie = str(cookie or "").strip()
    if cookie:
        headers["Cookie"] = cookie
    headers.setdefault("Content-Type", "multipart/form-data; boundary=%s" % boundary)
    return {"tool": "http", "method": "POST", "path": str(stage.get("path") or "/"),
            "headers": headers,
            "body": "".join(parts)}


def prepare(request, scope, marker, python="python3"):
    """Pure validation/argv preparation; no executor, filesystem or network activity."""
    host, port = endpoint_parts(scope)
    if port is None:
        # A request needs somewhere to send: a position scope has no port, and inventing one
        # would send traffic at a port the graph never named.
        raise ValueError("LEAN_HTTP_NEEDS_ENDPOINT: a structured request needs host and port; "
                         "this scope is an execution position")
    if (not isinstance(request, dict) or set(request) - {"tool", "method", "path", "headers", "body"}
            or request.get("tool") != "http"):
        raise ValueError("LEAN_HTTP_REQUEST_INVALID: only structured http requests are supported")
    method, path = request.get("method"), request.get("path")
    if not isinstance(method, str) or method.upper() not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise ValueError("LEAN_HTTP_METHOD_UNSUPPORTED")
    if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
            or "\\" in path or "#" in path or any(ord(c) <= 32 or ord(c) == 127 for c in path)):
        raise ValueError("LEAN_HTTP_PATH_INVALID: relative request target required")
    headers = request.get("headers", {})
    if not isinstance(headers, dict):
        raise ValueError("LEAN_HTTP_HEADERS_INVALID")
    folded = set()
    for name, value in headers.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_|~0-9A-Za-z-]+", name)
                or not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise ValueError("LEAN_HTTP_HEADERS_INVALID")
        key = name.lower()
        if key in {"host", "content-length", "transfer-encoding", "proxy-authorization", "proxy-connection"}:
            raise ValueError("LEAN_HTTP_HEADER_FORBIDDEN: " + name)
        if key in folded:
            raise ValueError("LEAN_HTTP_HEADERS_INVALID: duplicate header")
        folded.add(key)
    # A model that writes "body": null means "no body" (the field is optional); refusing that
    # answer stops a whole node for a formality. A non-string, non-null body is still refused.
    if request.get("body") is None:
        request = dict(request, body="")
    elif not isinstance(request["body"], str):
        raise ValueError("LEAN_HTTP_BODY_INVALID: UTF-8 string required")
    if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", marker):
        raise ValueError("LEAN_HTTP_MARKER_INVALID")
    if not isinstance(python, str) or not python.strip() or "\x00" in python:
        raise ValueError("LEAN_HTTP_INTERPRETER_INVALID")
    authority = "[" + host + "]" if ":" in host else host
    payload = dict(request, host=host, port=port, origin="http://" + authority + ":" + str(port),
                   method=method.upper(), headers=headers, marker=marker)
    encoded = base64.b64encode(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode("ascii")
    return [python, "-c", CLIENT_SOURCE, encoded]
