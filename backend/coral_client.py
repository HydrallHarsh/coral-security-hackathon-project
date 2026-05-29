import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("harborguard.coral")


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
        started_at = time.perf_counter()
        logger.info(
            "coral.sql.start timeout=%ss sql=%s",
            f"{timeout:g}",
            compact_sql(sql),
        )

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
            duration_ms = elapsed_ms(started_at)
            logger.warning(
                "coral.sql.timeout duration_ms=%s timeout=%ss",
                duration_ms,
                f"{timeout:g}",
            )
            raise CoralClientError(
                f"Coral query timed out after {timeout:g}s"
            ) from error

        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip()
            logger.warning(
                "coral.sql.failed duration_ms=%s returncode=%s error=%s",
                elapsed_ms(started_at),
                completed.returncode,
                compact_text(message),
            )
            raise CoralClientError(message or "Coral query failed")

        try:
            rows = json.loads(completed.stdout or "[]")
        except json.JSONDecodeError as error:
            logger.warning(
                "coral.sql.invalid_json duration_ms=%s error=%s",
                elapsed_ms(started_at),
                error,
            )
            raise CoralClientError(f"Coral returned invalid JSON: {error}") from error

        if not isinstance(rows, list):
            logger.warning(
                "coral.sql.invalid_shape duration_ms=%s",
                elapsed_ms(started_at),
            )
            raise CoralClientError("Coral returned JSON, but it was not a row list")

        logger.info(
            "coral.sql.ok duration_ms=%s rows=%s",
            elapsed_ms(started_at),
            len(rows),
        )
        return CoralResult(rows=rows, sql=sql)

    def source_list(self) -> CoralCommandResult:
        started_at = time.perf_counter()
        logger.info("coral.source_list.start timeout=%ss", f"{self.timeout_seconds:g}")
        completed = subprocess.run(
            [self.coral_bin, "source", "list"],
            env=coral_env(self.config_dir),
            text=True,
            capture_output=True,
            check=False,
            timeout=self.timeout_seconds,
        )
        logger.info(
            "coral.source_list.done duration_ms=%s returncode=%s",
            elapsed_ms(started_at),
            completed.returncode,
        )
        return CoralCommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


def elapsed_ms(started_at: float) -> int:
    return round((time.perf_counter() - started_at) * 1000)


def compact_sql(sql: str, limit: int = 320) -> str:
    return compact_text(" ".join(sql.split()), limit)


def compact_text(text: str, limit: int = 320) -> str:
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."
