import json
import os
import subprocess
from typing import Any


class CoralMCPError(RuntimeError):
    pass


def mcp_discovery_enabled() -> bool:
    return os.getenv("HARBORGUARD_DISCOVERY_BACKEND", "").lower() == "mcp"


class CoralMCPClient:
    def __init__(self) -> None:
        self.coral_bin = os.getenv("CORAL_BIN", "coral")
        self.config_dir = os.getenv("CORAL_CONFIG_DIR")
        self.next_id = 1
        self.process: subprocess.Popen[str] | None = None

    def __enter__(self) -> "CoralMCPClient":
        env = os.environ.copy()
        if self.config_dir:
            env["CORAL_CONFIG_DIR"] = self.config_dir

        self.process = subprocess.Popen(
            [self.coral_bin, "mcp-stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        self._initialize()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if not self.process:
            return

        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()

    def _send(self, payload: dict[str, Any]) -> None:
        if not self.process or not self.process.stdin:
            raise CoralMCPError("MCP process is not running")
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()

    def _read_response(self, request_id: int) -> dict[str, Any]:
        if not self.process or not self.process.stdout:
            raise CoralMCPError("MCP process is not running")

        while True:
            line = self.process.stdout.readline()
            if not line:
                stderr = ""
                if self.process.stderr:
                    stderr = self.process.stderr.read()
                raise CoralMCPError(f"MCP process closed unexpectedly. {stderr}".strip())

            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

            if payload.get("id") != request_id:
                continue

            if payload.get("error"):
                raise CoralMCPError(json.dumps(payload["error"]))
            return payload

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        self._send(payload)
        return self._read_response(request_id)

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
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
            return structured
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
