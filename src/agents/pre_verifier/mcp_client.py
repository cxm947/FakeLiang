"""Official MCP session, with a synchronous facade for the checkpointed graph."""

from contextlib import asynccontextmanager, AsyncExitStack, ExitStack
from datetime import timedelta
from pathlib import Path
import json
import os
import shlex
import sys
from typing import Literal

from anyio.from_thread import start_blocking_portal
from jsonschema import validate
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from pydantic import BaseModel, ConfigDict, Field
import yaml

from .schema import ExecutionRequest


class MCPConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    transport: Literal["stdio", "streamable_http"] = "stdio"
    command: str = sys.executable
    args: list[str] = Field(default_factory=list)
    url: str | None = None
    tool_name: str = "execute_command"
    timeout: float = Field(default=45.0, gt=0, le=300)


def load_mcp_config(path):
    return MCPConfig.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def command_for(request):
    request = ExecutionRequest.model_validate(request)
    if request.tool == "cmd":
        # `cmd` names its interpreter too; the Kali entry is POSIX, so the wrapper is built for
        # that platform. Naming the platform's own shell leaves the line untouched.
        from src.agents.executor.tool_contracts import interpreter_command

        return interpreter_command(request.name, request.content, platform="linux")
    if request.tool == "tool":
        return shlex.join([request.name, *request.content])
    if request.tool == "session":
        # A console command is one line on the channel's own console layer. This function
        # only builds the duplicate-detection key; the dispatcher owns the real delivery.
        content = request.content
        text = content.get("command", "") if isinstance(content, dict) else content
        return "session: " + str(text)
    if isinstance(request.content, (dict, list)):
        # Any other structured request is compared by its canonical shape, never passed to
        # shlex (live 2026-10-17: a `session` request reached shlex and raised TypeError
        # before the check could run).
        return request.tool + ": " + json.dumps(request.content, sort_keys=True,
                                                ensure_ascii=False)
    flag = "-c"  # python3, bash and sh all accept script text via -c.
    return shlex.join([request.name, flag, request.content])


@asynccontextmanager
async def session_for(config):
    async with AsyncExitStack() as stack:
        if config.transport == "stdio":
            environment = {"PYTHONIOENCODING": "utf-8"}
            # Windows OpenSSH exits 255 without diagnostics if ProgramData is absent.
            # MCP's minimal inherited environment omits it; do not inherit API keys.
            if os.name == "nt" and os.environ.get("ProgramData"):
                environment["ProgramData"] = os.environ["ProgramData"]
            streams = await stack.enter_async_context(stdio_client(StdioServerParameters(
                command=config.command, args=config.args, env=environment)))
        else:
            if not config.url:
                raise ValueError("Streamable HTTP requires an MCP URL")
            streams = await stack.enter_async_context(streamablehttp_client(config.url))
        session = await stack.enter_async_context(ClientSession(*streams[:2],
            read_timeout_seconds=timedelta(seconds=config.timeout)))
        await session.initialize()
        yield session


class KaliMCP:
    def __init__(self, config):
        self.config = config

    def __enter__(self):
        self.stack = ExitStack()
        try:
            self.portal = self.stack.enter_context(start_blocking_portal())
            self.session = self.stack.enter_context(self.portal.wrap_async_context_manager(session_for(self.config)))
            tools, cursor = [], None
            while True:
                page = self.portal.call(self.session.list_tools, cursor)
                tools.extend(t.model_dump(mode="json") for t in page.tools)
                cursor = page.nextCursor
                if cursor is None:
                    break
            selected = [t for t in tools if t["name"] == self.config.tool_name]
            if len(selected) != 1:
                raise ValueError("Configured command tool is not exposed by Kali MCP")
            self.definition = selected[0]
            validate({"command": "true"}, self.definition["inputSchema"])
            # Expose only the configured Pre execution bridge, not Action/Post tools.
            self.definitions = selected
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *exc):
        return self.stack.__exit__(*exc)

    def execute(self, request):
        if ExecutionRequest.model_validate(request).via != "kali":
            raise ValueError("The kali entry only executes via=kali requests")
        arguments = {"command": command_for(request)}
        validate(arguments, self.definition["inputSchema"])
        result = self.portal.call(self.session.call_tool, self.config.tool_name, arguments)
        payload = result.model_dump(mode="json", exclude_none=True)
        data = payload.get("structuredContent")
        if data is None and len(payload.get("content", [])) == 1:
            try:
                data = json.loads(payload["content"][0].get("text", ""))
            except (ValueError, TypeError):
                pass
        transport_error = isinstance(data, dict) and bool(data.get("transport_error") or data.get("timed_out"))
        return {"tool_name": self.config.tool_name, "arguments": arguments,
                "is_error": bool(result.isError or transport_error), "response": payload}
