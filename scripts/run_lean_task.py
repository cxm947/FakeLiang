#!/usr/bin/env python
"""Opt-in single-task HTTP executor; does not register graph facts or sessions."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
from copy import deepcopy
from pathlib import Path
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents._model.contract import EMPTY_CONTENT_ERROR, TRUNCATED_ERROR
from agents._model.client import client_from_env
from runtime import artifacts
from runtime import model_log
from runtime.lean import LeanRun, collect_secrets, mask_secrets
from runtime.lean_http import endpoint_parts
from runtime.redact import TOKEN_RE, project_secrets, rebind, residual_tokens
from runtime.remote import SshExecutor, parse_remote
from runtime.runner import subprocess_executor
from skills import lean as card_reader
from skills.lean import load_card

from agents.executor.action import (
    _LEGACY_TOOL, flat_action, restore_action, restore_request, restore_secrets,
)
from agents.executor.driver import drive
from agents.executor.input import read_json, select_executor, validate_task
from agents.executor.observation import (
    OBSERVATION_LIMIT, REFUSABLE, REFUSAL_LIMIT,
    refusal_record, show_run, trim_observation,
)
from agents.executor.prompts import (
    SYSTEM, CORRECTION_HINT, UNRESOLVED_HINT, SHORT_KEEP,
    SHORT_OBSERVATION_LIMIT, COMPACT_AFTER_TRUNCATION,
    CLOSING_TURNS, budget_hint, STAGE_HINT,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--card", required=True)
    parser.add_argument("--task", required=True, help="JSON task file or inline object")
    parser.add_argument("--run-dir", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--actions", help="JSON action list file or inline array")
    source.add_argument("--model")
    remote = parser.add_mutually_exclusive_group()
    remote.add_argument("--remote")
    remote.add_argument("--chain")
    parser.add_argument("--password")
    parser.add_argument("--key")
    parser.add_argument("--python", default="python3")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--max-steps", type=int, default=8)
    parser.add_argument("--model-base-url", default="")
    parser.add_argument("--model-api-key-env", default="AGV_MODEL_API_KEY")
    parser.add_argument("--model-timeout", type=float, default=60)
    parser.add_argument("--channel", default="",
                        help="channel row (JSON file or inline) to run this task through")
    args = parser.parse_args(argv)
    owner = None
    secrets = [args.password or os.environ.get("AGV_SSH_PASSWORD", "")]
    result = {"status": "uncertain", "reason": "LEAN_ACTIONS_EXHAUSTED"}
    try:
        from agents._model.backend import freeze_backend
        backend = freeze_backend(args.run_dir)
        if args.max_steps <= 0 or args.timeout <= 0 or args.model_timeout <= 0:
            raise ValueError("LEAN_LIMIT_INVALID")
        card, task = load_card(args.card, ROOT), read_json(args.task)
        secrets = collect_secrets({"task": task}, secrets)
        channel = read_json(args.channel) if args.channel else None
        validate_task(card, task)
        actions = read_json(args.actions) if args.actions is not None else None
        if actions is not None and (not isinstance(actions, list)
                                    or any(not isinstance(x, dict) for x in actions)):
            raise ValueError("LEAN_ACTIONS_INVALID: list of objects required")
        secrets = collect_secrets({"actions": actions, "channel": channel}, secrets)
#: --chain 只做具名拒绝：多跳载体（MSF / 会话接管）是另一个模块，这里不做。
        executor, owner = select_executor(args, card, task["scope"])
        client = client_from_env(name=args.model or "", base_url=args.model_base_url,
                                 api_key_env=args.model_api_key_env, timeout=args.model_timeout,
                                 retries=0, backend=backend)
        result = drive(card, task, task["scope"], executor, actions=actions, client=client,
                       run_dir=args.run_dir, python=args.python, timeout=args.timeout,
                       max_steps=args.max_steps, model_timeout=args.model_timeout,
                       secrets=secrets, channel=channel, private_result=True)
    except (ValueError, OSError, RuntimeError) as error:
        result = {"status": "uncertain", "reason": str(error)}
    finally:
        if owner:
            owner.close()
    exit_code = 0 if result.get("status") == "model_reported" else 2
    result = mask_secrets(result, secrets)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
