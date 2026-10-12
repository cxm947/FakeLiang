"""The command line surface of scripts/run_plan.py."""
import argparse
import os


def parse_args(argv=None, *, description=None):
    parser = argparse.ArgumentParser(
        prog="run_plan.py", description=description
    )
    parser.add_argument("--graph", required=True)
    parser.add_argument("--host-map", default="")
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--resume", action="store_true",
                        help="resume an unfinished checkpoint at the same run root")
    parser.add_argument("--remote", required=True)
    parser.add_argument("--password", default=None)
    parser.add_argument("--key", default=None)
    parser.add_argument("--python", default="python3")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--max-steps", type=int, default=8)
    parser.add_argument("--max-nodes", type=int, default=12)
    parser.add_argument(
        "--carry-from", default="",
        help="a standing run to carry handles and credential references from before the walk",
    )
    parser.add_argument(
        "--credentials", default="",
        help="private JSON credentials source outside the repository and run directories",
    )
    parser.add_argument(
        "--materials-dir", default="",
        help="private directory outside the repository/run roots for derived material references",
    )
    parser.add_argument(
        "--msf-rpc", default="",
        help="user:password@host:port of the resident framework RPC; empty = no migration",
    )
    parser.add_argument(
        "--control", default="",
        help="the control box address; empty = the host map's control row",
    )
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-base-url", default="")
    parser.add_argument("--model-api-key-env", default="AGV_MODEL_API_KEY")
    parser.add_argument("--model-timeout", type=float, default=90.0)
    parser.add_argument(
        "--model-wire", default=os.environ.get("AGV_MODEL_WIRE", "chat"),
        help="模型线协议：chat（OpenAI 兼容 /chat/completions）或 responses（原生 /responses）",
    )
    parser.add_argument(
        "--verify-facts", action="store_true",
        help="compatibility option; fact verification always runs",
    )
    parser.add_argument(
        "--graph-assets", default="",
        help="--graph 是 TXT 时用的可选部署画像（多网卡 / 容器地址）",
    )
    return parser.parse_args(argv)
