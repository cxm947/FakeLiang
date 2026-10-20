"""Local task API: python serve.py (after starting the database)."""

import argparse
import os
from pathlib import Path

import uvicorn
import yaml
from pydantic import BaseModel, ConfigDict, SecretStr

from src.session.planner_api import create_app


class StorageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    database_url: SecretStr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--storage", type=Path, default=Path("configs/storage.local.yaml"))
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not os.environ.get("AGV_DATABASE_URL"):
        config = StorageConfig.model_validate(yaml.safe_load(args.storage.read_text(encoding="utf-8")))
        os.environ["AGV_DATABASE_URL"] = config.database_url.get_secret_value()
    # Local API only. External/multi-user access needs authentication first.
    uvicorn.run(create_app(), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
