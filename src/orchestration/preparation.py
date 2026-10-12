"""Preparation: pre-dispatch run setup, kept to what the graph and the card already say."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from runtime import assets
from runtime import credentials as credential_ledger

from .contracts import CredentialInputs


def bind_config_paths(card, task, destinations):
    """Bind a card's `from: config` path input to the one tool this run just placed for it.

    A card names its tool in prose and lets the deployment say *where* it went; the step then has to
    find that path before it can run anything (measured 2026-10-08: the laravel step passed twice by
    discovering the PoC and failed once by hand-rolling the chain instead). When the shape is
    unambiguous -- one placed tool, one path-shaped config input that is still empty -- the runtime
    answers it. Anything less clear is left alone rather than guessed.
    """
    inputs = card.get("inputs") or {}
    #: 卡的前言里 inputs 通常**不写 `type`**（2026-10-08 walk-166 node 28 实测：原先要求
    #: type=="path" 于是这条绑定从来没生效过，模型只好靠 `ls` 去猜路径，猜不猜看运气）。
    #: 形状判据改成"来源是 config、名字以 `_path` 结尾、当前还空着"；再要求"只放了一件制品"。
    wanted = [str(name) for name, spec in inputs.items()
              if isinstance(spec, dict) and str(spec.get("from") or "") == "config"
              and str(name).endswith("_path")
              and not str((task.get("inputs") or {}).get(name) or "")]
    placed = [str(item) for item in destinations or ()]
    if len(wanted) != 1 or len(placed) != 1:
        return {}
    return {wanted[0]: placed[0]}


def prepare_inputs(
    *,
    node,
    card,
    document,
    root,
    repository,
    host_map,
    carrier,
    executor,
    credentials: CredentialInputs,
    prepare_task,
    prepared_assets=None,
):
    node_id = str(node.get("id"))
    task, scope = prepare_task(node, host_map, card, carrier=carrier)
    placed = (assets.ensure(card, executor, root=repository, run_dir=root, node=node_id)
              if prepared_assets is None else list(prepared_assets))
    if placed:
        print("card assets: " + "; ".join(placed))
        pinned = dict(prepared_assets or {})
        for dest, asset_path in assets.declared(card, repository):
            pinned[str(dest)] = {
                "source": str(
                    Path(asset_path).resolve().relative_to(
                        Path(repository).resolve()
                    )
                ),
                "sha256": sha256(Path(asset_path).read_bytes()).hexdigest(),
            }
        task["inputs"]["placed_assets"] = pinned
        bound = bind_config_paths(card, task, list(pinned))
        if bound:
            task["inputs"].update(bound)
            print(
                "card inputs bound: "
                + json.dumps(bound, ensure_ascii=False)
            )
        if prepared_assets is None:
            run_dir = root / ("node" + node_id)
            run_dir.mkdir(parents=True, exist_ok=True)
            with (run_dir / "assets.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {"node": node_id, "card": card["id"], "placed": placed},
                        ensure_ascii=False,
                    ) + "\n"
                )

    if {"credential_ref", "credential_candidates"} & (
        card.get("inputs") or {}
    ).keys():
        candidates = credential_ledger.select_candidates(
            document,
            node,
            credential_ledger.read(root),
            host_map=host_map,
            run_dirs=credentials.run_dirs,
            repository=repository,
            source=credentials.source,
            user=task["inputs"].get("user", ""),
            realm=(
                task["inputs"].get("realm")
                or task["inputs"].get("domain", "")
            ),
        )
        task["inputs"]["credential_candidates"] = candidates
        task["inputs"]["credential_ref"] = candidates[0]["credential_ref"]

    if carrier and "session_ref" in (card.get("inputs") or {}):
        task["inputs"]["session_ref"] = carrier["channel_id"]
    if carrier:
        platform = str(
            carrier.get("platform") or carrier.get("session_type") or ""
        )
        if platform:
            task["inputs"]["position_platform"] = platform
        task["inputs"].update(
            position_logical=str(carrier.get("logical") or ""),
            position_host=str(carrier.get("host") or ""),
            position_session=str(carrier.get("channel_id") or ""),
            position_speaks=str(carrier.get("session_type") or ""),
        )
    return task, scope
