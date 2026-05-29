import json
import logging
import os
import socket
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger("harborguard.llm")


class LLMPlannerError(RuntimeError):
    pass


def llm_planner_enabled() -> bool:
    return os.getenv("HARBORGUARD_USE_LLM_PLANNER", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _compact_tools(capabilities: dict[str, Any]) -> dict[str, Any]:
    tools = capabilities.get("tools")
    if not isinstance(tools, dict):
        return {}

    compact: dict[str, Any] = {}
    for name, tool in tools.items():
        if not isinstance(tool, dict) or not tool.get("available"):
            continue

        required_filters = [
            row.get("filter_name")
            for row in tool.get("filters", [])
            if isinstance(row, dict) and row.get("is_required")
        ]
        compact[name] = {
            "purpose": tool.get("purpose"),
            "kind": tool.get("kind"),
            "source": tool.get("source"),
            "capabilities": tool.get("capabilities", []),
            "required_filters": required_filters,
        }

    return compact


def _request_context(req: Any) -> dict[str, Any]:
    return {
        "question": req.question,
        "owner": req.owner,
        "repo": req.repo,
        "org": req.org or req.owner,
        "slack_channel_provided": bool(req.slack_channel),
        "policy_query": req.policy_query,
        "package_system": req.package_system,
        "package_ecosystem": req.package_ecosystem,
        "package_name": req.package_name,
        "package_version": req.package_version,
        "days": req.days,
    }


def _extract_json_object(content: str) -> dict[str, Any]:
    content = content.strip()
    if content.startswith("```"):
        content = content.strip("`").strip()
        if content.startswith("json"):
            content = content[4:].strip()

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as error:
        raise LLMPlannerError(f"Planner returned invalid JSON: {error}") from error

    if not isinstance(parsed, dict):
        raise LLMPlannerError("Planner returned JSON, but it was not an object")
    return parsed


def plan_with_openrouter(
    req: Any,
    capabilities: dict[str, Any],
    allowed_tools: list[str],
) -> dict[str, Any]:
    if not llm_planner_enabled():
        logger.info("llm.planner.skipped reason=disabled")
        raise LLMPlannerError("LLM planner is disabled")

    api_key = os.getenv("OPENROUTER_API_KEY")
    model = os.getenv("OPENROUTER_MODEL")
    if not api_key:
        raise LLMPlannerError("OPENROUTER_API_KEY is not set")
    if not model:
        raise LLMPlannerError("OPENROUTER_MODEL is not set")

    started_at = time.perf_counter()
    available_tools = _compact_tools(capabilities)
    logger.info(
        "llm.openrouter.start model=%s available_tools=%s allowed_tools=%s",
        model,
        len(available_tools),
        len(allowed_tools),
    )
    payload = {
        "model": model,
        "temperature": 0.1,
        "max_tokens": 700,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are HarborGuard's security investigation orchestrator. "
                    "Choose tools from the provided allowed tool list only. "
                    "Do not write SQL. Do not invent tools. Return only JSON."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": "Create an investigation plan.",
                        "request": _request_context(req),
                        "allowed_tools": allowed_tools,
                        "available_tools": available_tools,
                        "output_schema": {
                            "intent": "short_snake_case_string",
                            "selected_tools": ["tool.name"],
                            "skipped_tools": [
                                {"tool": "tool.name", "reason": "short reason"}
                            ],
                            "reasoning_trace": [
                                "operational audit step, not hidden chain-of-thought"
                            ],
                        },
                    },
                    indent=2,
                ),
            },
        ],
    }

    request = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:8000",
            "X-Title": "HarborGuard",
        },
        method="POST",
    )

    timeout_seconds = float(os.getenv("OPENROUTER_TIMEOUT_SECONDS", "15"))
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            response_body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        logger.warning(
            "llm.openrouter.http_error duration_ms=%s status=%s body=%s",
            elapsed_ms(started_at),
            error.code,
            compact_text(body),
        )
        raise LLMPlannerError(f"OpenRouter HTTP {error.code}: {body}") from error
    except urllib.error.URLError as error:
        logger.warning(
            "llm.openrouter.failed duration_ms=%s error=%s",
            elapsed_ms(started_at),
            compact_text(str(error)),
        )
        raise LLMPlannerError(f"OpenRouter request failed: {error}") from error
    except (TimeoutError, socket.timeout) as error:
        logger.warning(
            "llm.openrouter.timeout duration_ms=%s timeout=%ss",
            elapsed_ms(started_at),
            f"{timeout_seconds:g}",
        )
        raise LLMPlannerError("OpenRouter request timed out") from error

    try:
        data = json.loads(response_body)
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        logger.warning(
            "llm.openrouter.invalid_response duration_ms=%s error=%s",
            elapsed_ms(started_at),
            compact_text(str(error)),
        )
        raise LLMPlannerError("OpenRouter response did not contain chat content") from error

    plan = _extract_json_object(content)
    selected_tools = plan.get("selected_tools", [])
    skipped_tools = plan.get("skipped_tools", [])
    reasoning_trace = plan.get("reasoning_trace", [])

    if not isinstance(selected_tools, list):
        selected_tools = []
    if not isinstance(skipped_tools, list):
        skipped_tools = []
    if not isinstance(reasoning_trace, list):
        reasoning_trace = []

    allowed = set(allowed_tools)
    valid_selected = [
        tool for tool in selected_tools if isinstance(tool, str) and tool in allowed
    ]
    invalid_selected = [
        tool for tool in selected_tools if not isinstance(tool, str) or tool not in allowed
    ]

    normalized_skips = [
        item
        for item in skipped_tools
        if isinstance(item, dict)
        and isinstance(item.get("tool"), str)
        and item.get("tool") in allowed
        and isinstance(item.get("reason"), str)
    ]
    for tool in invalid_selected:
        normalized_skips.append(
            {"tool": str(tool), "reason": "rejected because it is not an allowed tool"}
        )

    logger.info(
        "llm.openrouter.ok duration_ms=%s selected_tools=%s rejected_tools=%s",
        elapsed_ms(started_at),
        len(valid_selected),
        len(invalid_selected),
    )
    return {
        "intent": str(plan.get("intent") or "llm_planned_investigation"),
        "selected_tools": valid_selected,
        "skipped_tools": normalized_skips,
        "reasoning_trace": [
            "LLM planner used OpenRouter to choose investigation tools.",
            *[str(item) for item in reasoning_trace],
        ],
        "planner_source": "openrouter",
        "model": model,
    }


def elapsed_ms(started_at: float) -> int:
    return round((time.perf_counter() - started_at) * 1000)


def compact_text(text: str, limit: int = 320) -> str:
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."
