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

            if not key:
                continue

            if value:
                os.environ[key] = value


def coral_env(config_dir: str | None) -> dict[str, str]:
    env = os.environ.copy()
    if config_dir:
        env["CORAL_CONFIG_DIR"] = config_dir
    else:
        env.pop("CORAL_CONFIG_DIR", None)
    return env


@dataclass
class CoralResult:
    rows: list[dict]
    sql: str


@dataclass
class CoralCommandResult:
    returncode: int
    stdout: str
    stderr: str


class CoralClientError(RuntimeError):
    pass


class CoralClient:
    def __init__(self) -> None:
        load_dotenv()
        self.coral_bin = os.getenv("CORAL_BIN", "coral")
        self.config_dir = os.getenv("CORAL_CONFIG_DIR") or None
        self.timeout_seconds = float(os.getenv("CORAL_QUERY_TIMEOUT_SECONDS", "20"))

    def query(self, sql: str, timeout_seconds: float | None = None) -> CoralResult:
        command = [self.coral_bin, "sql", "--format", "json", sql]
        timeout = timeout_seconds or self.timeout_seconds

        try:
            completed = subprocess.run(
                command,
                env=coral_env(self.config_dir),
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise CoralClientError(
                f"Coral query timed out after {timeout:g}s"
            ) from error

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

    def source_list(self) -> CoralCommandResult:
        completed = subprocess.run(
            [self.coral_bin, "source", "list"],
            env=coral_env(self.config_dir),
            text=True,
            capture_output=True,
            check=False,
            timeout=self.timeout_seconds,
        )
        return CoralCommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
