"""Official MCP/stdio bridge to Kali HTTP or an existing SSH connection."""

import argparse
import shlex
import subprocess
import httpx
from mcp.server.fastmcp import FastMCP


def create_server(server_url=None, timeout=30.0, *, ssh_target=None, identity_file=None):
    if bool(server_url) == bool(ssh_target):
        raise ValueError("Select exactly one Kali transport: HTTP or SSH")
    server = FastMCP("agv-pre-kali", log_level="WARNING")

    @server.tool()
    def execute_command(command: str) -> dict:
        """Run a bounded inspection command on the configured Kali host, returning its actual output.

        The caller must use observation-only checks. No installation, repair or new access.
        This command transport does not determine whether the LEAF condition is satisfied.
        """
        # GNU timeout bounds the process on Kali, not merely the HTTP wait.
        bounded = f"timeout --signal=TERM --kill-after=2s {timeout:g}s sh -c {shlex.quote(command)}"
        if ssh_target:
            argv = ["ssh", "-n", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                    "-o", "ConnectTimeout=5"]
            if identity_file:
                argv += ["-i", identity_file]
            done = subprocess.run([*argv, ssh_target, bounded], capture_output=True, stdin=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace", timeout=timeout + 10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return {"stdout": done.stdout, "stderr": done.stderr, "return_code": done.returncode,
                    "transport_error": done.returncode == 255, "timed_out": done.returncode in {124, 137}}
        with httpx.Client(timeout=timeout + 5, trust_env=False) as client:
            response = client.post(server_url.rstrip("/") + "/api/command", json={"command": bounded})
            response.raise_for_status()
            data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Kali returned a non-object response")
        return data

    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--server")
    transport.add_argument("--ssh-target")
    parser.add_argument("--identity-file")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    if not 0 < args.timeout <= 240:
        parser.error("timeout must be between 0 and 240 seconds")
    create_server(args.server, args.timeout, ssh_target=args.ssh_target,
                  identity_file=args.identity_file).run(transport="stdio")


if __name__ == "__main__":
    main()
