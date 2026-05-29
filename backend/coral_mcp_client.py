import json
import logging
import os
import queue
import subprocess
import threading
import time
from typing import Any

from coral_client import coral_env, load_dotenv

logger = logging.getLogger("harborguard.mcp")


class CoralMCPError(RuntimeError):
    pass


def mcp_discovery_enabled() -> bool:
    return os.getenv("HARBORGUARD_DISCOVERY_BACKEND", "").lower() == "mcp"


class CoralMCPClient:
    def __init__(self) -> None:
        load_dotenv()
        self.coral_bin = os.getenv("CORAL_BIN", "coral")
        self.config_dir = os.getenv("CORAL_CONFIG_DIR") or None
        self.timeout_seconds = float(os.getenv("CORAL_MCP_TIMEOUT_SECONDS", "8"))
        self.next_id = 1
        self.process: subprocess.Popen[str] | None = None
        self.responses: queue.Queue[dict[str, Any]] = queue.Queue()
        self.reader_thread: threading.Thread | None = None

    def __enter__(self) -> "CoralMCPClient":
        logger.info(
            "mcp.process.start command=%s timeout=%ss",
            f"{self.coral_bin} mcp-stdio",
            f"{self.timeout_seconds:g}",
        )
        self.process = subprocess.Popen(
            [self.coral_bin, "mcp-stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=coral_env(self.config_dir),
        )
        self._start_reader()
        try:
            self._initialize()
        except Exception:
            self._stop_process()
            raise
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._stop_process()

    def _stop_process(self) -> None:
        if not self.process:
            return

        logger.info("mcp.process.stop")
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()

    def _start_reader(self) -> None:
        def read_loop() -> None:
            if not self.process or not self.process.stdout:
                return

            for line in self.process.stdout:
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    self.responses.put(payload)

            stderr = ""
            if self.process and self.process.stderr:
                stderr = self.process.stderr.read()
            self.responses.put({"_closed": True, "stderr": stderr})

        self.reader_thread = threading.Thread(target=read_loop, daemon=True)
        self.reader_thread.start()

    def _send(self, payload: dict[str, Any]) -> None:
        if not self.process or not self.process.stdin:
            raise CoralMCPError("MCP process is not running")
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()

    def _read_response(self, request_id: int) -> dict[str, Any]:
        if not self.process:
            raise CoralMCPError("MCP process is not running")

        while True:
            try:
                payload = self.responses.get(timeout=self.timeout_seconds)
            except queue.Empty as error:
                raise CoralMCPError(
                    f"MCP request timed out after {self.timeout_seconds:g}s"
                ) from error

            if payload.get("_closed"):
                stderr = str(payload.get("stderr") or "")
                raise CoralMCPError(f"MCP process closed unexpectedly. {stderr}".strip())

            if payload.get("id") != request_id:
                continue

            if payload.get("error"):
                raise CoralMCPError(json.dumps(payload["error"]))
            return payload

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        started_at = time.perf_counter()
        logger.info("mcp.request.start id=%s method=%s", request_id, method)
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        self._send(payload)
        try:
            response = self._read_response(request_id)
        except CoralMCPError:
            logger.warning(
                "mcp.request.failed id=%s method=%s duration_ms=%s",
                request_id,
                method,
                elapsed_ms(started_at),
            )
            raise
        logger.info(
            "mcp.request.ok id=%s method=%s duration_ms=%s",
            request_id,
            method,
            elapsed_ms(started_at),
        )
        return response

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        logger.info("mcp.notify method=%s", method)
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _initialize(self) -> None:
        self._request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "harborguard-backend",
                    "version": "0.1.0",
                },
            },
        )
        self._notify("notifications/initialized")

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        logger.info("mcp.tool.start name=%s", name)
        response = self._request(
            "tools/call",
            {
                "name": name,
                "arguments": arguments or {},
            },
        )
        result = response.get("result")
        if not isinstance(result, dict):
            raise CoralMCPError("MCP tool response did not include a result object")
        structured = result.get("structuredContent") or result.get("structured_content")
        if isinstance(structured, dict):
            logger.info("mcp.tool.ok name=%s structured=true", name)
            return structured
        logger.info("mcp.tool.ok name=%s structured=false", name)
        return result

    def list_catalog(
        self,
        schema: str | None = None,
        kind: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> dict[str, Any]:
        arguments: dict[str, Any] = {"limit": limit, "offset": offset}
        if schema:
            arguments["schema"] = schema
        if kind:
            arguments["kind"] = kind
        return self.call_tool("list_catalog", arguments)


def elapsed_ms(started_at: float) -> int:
    return round((time.perf_counter() - started_at) * 1000)
