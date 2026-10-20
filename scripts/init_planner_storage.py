"""Create local Docker/connection configuration without printing credentials."""

from pathlib import Path
import secrets

import yaml


def main():
    root = Path(__file__).resolve().parents[1]
    env = root / ".env.database"
    config = root / "configs/storage.local.yaml"
    if env.exists() or config.exists():
        if env.exists() and config.exists():
            print("Existing database configuration retained.")
            return
        raise SystemExit("Partial database configuration exists; restore its matching file before continuing.")
    password = secrets.token_urlsafe(32)
    with env.open("x", encoding="utf-8") as stream:
        stream.write("POSTGRES_PASSWORD=" + password + "\n")
    with config.open("x", encoding="utf-8") as stream:
        yaml.safe_dump({"database_url": f"postgresql+psycopg://agv:{password}@127.0.0.1:55432/agv"}, stream)
    print("Local database configuration created; credentials are not displayed.")


if __name__ == "__main__":
    main()
