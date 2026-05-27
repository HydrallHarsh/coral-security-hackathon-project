import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


def load_dotenv() -> None:
    env_paths = [
        Path(__file__).resolve().parent / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]

    for env_path in env_paths:
        if not env_path.exists():
            continue

        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            value = os.path.expandvars(value)

            if key:
                os.environ.setdefault(key, value)


@dataclass
class CoralResult:
    rows: list[dict]
    sql: str


class CoralClientError(RuntimeError):
    pass


class CoralClient:
    def __init__(self) -> None:
        load_dotenv()
        self.coral_bin = os.getenv("CORAL_BIN", "coral")
        self.config_dir = os.getenv("CORAL_CONFIG_DIR")

    def query(self, sql: str) -> CoralResult:
        command = [self.coral_bin, "sql", "--format", "json", sql]

        env = os.environ.copy()
        if self.config_dir:
            env["CORAL_CONFIG_DIR"] = self.config_dir

        completed = subprocess.run(
            command,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip()
            raise CoralClientError(message or "Coral query failed")

        try:
            rows = json.loads(completed.stdout or "[]")
        except json.JSONDecodeError as error:
            raise CoralClientError(f"Coral returned invalid JSON: {error}") from error

        if not isinstance(rows, list):
            raise CoralClientError("Coral returned JSON, but it was not a row list")

        return CoralResult(rows=rows, sql=sql)
