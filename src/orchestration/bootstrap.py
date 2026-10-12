"""Bootstrap: read the compiled graph document the walk is about to run."""
from __future__ import annotations

import json
from pathlib import Path

from graph import rehydrate
from graph.paths import resolve_path
from runtime import credentials as credential_ledger

from .contracts import CredentialInputs


def load_graph_document(graph_arg, *, host_map="", assets="", run_root=None):
    """读图，返回 (实际用的路径, 已加载文档)。

    ``.json`` 直接读；**``.txt`` 先编译**——"从攻击图 TXT + 主机映射表起手"是正规入口，不是某个临时
    脚本里的两行。编译产物落在 ``<run>/graph/`` 下，于是"这一轮用的是哪张图、哪份映射表、指纹是什么"
    跟着这一轮走，事后复核不必去翻 shell 历史。
    """
    path = resolve_path(graph_arg)
    if path.suffix.lower() == ".json":
        return path, rehydrate.load_file(path)
    from graph import cli as graph_cli          # 只在要吃 TXT 时才牵出编译链
    out_dir = (Path(run_root) if run_root else path.parent) / "graph"
    out_dir.mkdir(parents=True, exist_ok=True)
    document = graph_cli.compile_document(path, host_map=host_map, assets=assets)
    built = out_dir / (path.stem + ".action_graph.json")
    built.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n",
                     encoding="utf-8", newline="\n")
    print("图：从 %s 编译 -> %s（%d 个节点）" % (path.name, built, len(document.get("nodes") or [])),
          flush=True)
    return built, rehydrate.load_file(built)


def load_credentials(
    *,
    root,
    repository,
    document,
    host_map,
    carry_from,
    source_path,
    materials_dir,
    secrets,
):
    run_dirs = [root] + ([carry_from] if carry_from is not None else [])
    source = None
    role_accounts = {}

    if materials_dir is not None:
        credential_ledger.validate_materials_dir(
            materials_dir, run_dirs=run_dirs, repository=repository
        )
    if source_path is not None:
        source = credential_ledger.load_source(
            source_path, run_dirs=run_dirs, repository=repository
        )
        secrets.extend(credential_ledger.known_secrets(source))
        role_accounts = credential_ledger.declared_roles(source)
        symbols = credential_ledger.graph_symbols(document)
        for role, row in role_accounts.items():
            if symbols.get(role):
                row["symbols"] = symbols[role]

    rows = credential_ledger.read(root)
    if carry_from is not None:
        rows += credential_ledger.read(carry_from)
    secrets.extend(
        credential_ledger.secrets_for_rows(
            rows, run_dirs=run_dirs, repository=repository
        )
    )
    if carry_from is not None:
        credential_ledger.carry(
            carry_from,
            root,
            host_map=host_map,
            repository=repository,
            secrets=secrets,
        )
    return CredentialInputs(
        source=source,
        run_dirs=run_dirs,
        materials_dir=materials_dir,
        role_accounts=role_accounts,
    )


def rpc_config(value, *, control):
    if not value:
        return {}
    head, _, tail = value.partition("@")
    rpc_user, _, rpc_password = head.partition(":")
    rpc_host, _, rpc_port = tail.partition(":")
    return {
        "rpc_user": rpc_user,
        "rpc_password": rpc_password,
        "rpc_port": int(rpc_port or 55553),
        "rpc_host": rpc_host or control,
    }
