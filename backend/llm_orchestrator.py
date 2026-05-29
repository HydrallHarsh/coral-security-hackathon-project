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


def openrouter_chat_json(
    payload: dict[str, Any],
    started_at: float,
    log_prefix: str,
) -> dict[str, Any]:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise LLMPlannerError("OPENROUTER_API_KEY is not set")

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
            "%s.http_error duration_ms=%s status=%s body=%s",
            log_prefix,
            elapsed_ms(started_at),
            error.code,
            compact_text(body),
        )
        raise LLMPlannerError(f"OpenRouter HTTP {error.code}: {body}") from error
    except urllib.error.URLError as error:
        logger.warning(
            "%s.failed duration_ms=%s error=%s",
            log_prefix,
            elapsed_ms(started_at),
            compact_text(str(error)),
        )
        raise LLMPlannerError(f"OpenRouter request failed: {error}") from error
    except (TimeoutError, socket.timeout) as error:
        logger.warning(
            "%s.timeout duration_ms=%s timeout=%ss",
            log_prefix,
            elapsed_ms(started_at),
            f"{timeout_seconds:g}",
        )
        raise LLMPlannerError("OpenRouter request timed out") from error

    try:
        data = json.loads(response_body)
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        logger.warning(
            "%s.invalid_response duration_ms=%s error=%s",
            log_prefix,
            elapsed_ms(started_at),
            compact_text(str(error)),
        )
        raise LLMPlannerError("OpenRouter response did not contain chat content") from error

    return _extract_json_object(content)


def openrouter_chat_tools(
    payload: dict[str, Any],
    started_at: float,
    log_prefix: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise LLMPlannerError("OPENROUTER_API_KEY is not set")

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

    timeout_seconds = float(os.getenv("OPENROUTER_TIMEOUT_SECONDS", "30"))
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            response_body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        logger.warning(
            "%s.http_error duration_ms=%s status=%s body=%s",
            log_prefix,
            elapsed_ms(started_at),
            error.code,
            compact_text(body),
        )
        raise LLMPlannerError(f"OpenRouter HTTP {error.code}: {body}") from error
    except urllib.error.URLError as error:
        logger.warning(
            "%s.failed duration_ms=%s error=%s",
            log_prefix,
            elapsed_ms(started_at),
            compact_text(str(error)),
        )
        raise LLMPlannerError(f"OpenRouter request failed: {error}") from error
    except (TimeoutError, socket.timeout) as error:
        logger.warning(
            "%s.timeout duration_ms=%s timeout=%ss",
            log_prefix,
            elapsed_ms(started_at),
            f"{timeout_seconds:g}",
        )
        raise LLMPlannerError("OpenRouter request timed out") from error

    try:
        data = json.loads(response_body)
        message = data["choices"][0]["message"]
        tool_calls = message.get("tool_calls", [])
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        logger.warning(
            "%s.invalid_response duration_ms=%s error=%s",
            log_prefix,
            elapsed_ms(started_at),
            compact_text(str(error)),
        )
        raise LLMPlannerError("OpenRouter response did not contain message or tool_calls") from error

    return tool_calls, message

def plan_with_openrouter(
    req: Any,
    capabilities: dict[str, Any],
    allowed_tools: list[str],
) -> dict[str, Any]:
    if not llm_planner_enabled():
        logger.info("llm.planner.skipped reason=disabled")
        raise LLMPlannerError("LLM planner is disabled")

    model = os.getenv("OPENROUTER_MODEL")
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
        "max_tokens": 4000,
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

    plan = openrouter_chat_json(payload, started_at, "llm.openrouter")
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


def extract_package_candidates_with_openrouter(
    req: Any,
    pull_rows: list[dict[str, Any]],
    alert_rows: list[dict[str, Any]],
    deterministic_candidates: list[dict[str, Any]],
    commit_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not llm_planner_enabled():
        logger.info("llm.extractor.skipped reason=disabled")
        raise LLMPlannerError("LLM planner is disabled")

    model = os.getenv("OPENROUTER_MODEL")
    if not model:
        raise LLMPlannerError("OPENROUTER_MODEL is not set")

    started_at = time.perf_counter()
    commit_rows = commit_rows or []
    logger.info(
        "llm.extractor.start model=%s pulls=%s commits=%s alerts=%s deterministic_candidates=%s",
        model,
        len(pull_rows),
        len(commit_rows),
        len(alert_rows),
        len(deterministic_candidates),
    )

    compact_pulls = [
        {
            "number": row.get("number"),
            "title": row.get("title"),
            "body": compact_text(str(row.get("body") or ""), 700),
            "url": row.get("html_url") or row.get("url"),
        }
        for row in pull_rows[:10]
    ]
    compact_alerts = [
        {
            "number": row.get("number"),
            "package_name": row.get("dependency__package__name"),
            "ecosystem": row.get("dependency__package__ecosystem"),
            "severity": row.get("security_advisory__severity"),
            "summary": row.get("security_advisory__summary"),
            "url": row.get("html_url"),
        }
        for row in alert_rows[:10]
    ]
    compact_commits = [
        {
            "sha": row.get("sha"),
            "message": row.get("commit__message"),
            "url": row.get("html_url"),
            "date": row.get("commit__author__date") or row.get("commit__committer__date"),
        }
        for row in commit_rows[:10]
    ]
    payload = {
        "model": model,
        "temperature": 0.0,
        "max_tokens": 4000,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You extract dependency package targets for a security scanner. "
                    "Use only evidence in the provided pull requests, alerts, and deterministic candidates. "
                    "Return only JSON. Do not invent versions."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": "Find dependency package/version candidates for deep vulnerability scanning.",
                        "request": _request_context(req),
                        "pull_requests": compact_pulls,
                        "commits": compact_commits,
                        "dependabot_alerts": compact_alerts,
                        "deterministic_candidates": deterministic_candidates[:10],
                        "output_schema": {
                            "candidates": [
                                {
                                    "package_name": "string",
                                    "version": "exact version string or null",
                                    "ecosystem": "npm/pypi/go/maven/cargo/nuget/etc or null",
                                    "system": "NPM/PYPI/GO/MAVEN/CARGO/NUGET/etc or null",
                                    "confidence": 0.0,
                                    "source": "github.pulls|github.alerts|deterministic",
                                    "reason": "short evidence-based reason",
                                }
                            ]
                        },
                    },
                    indent=2,
                ),
            },
        ],
    }

    result = openrouter_chat_json(payload, started_at, "llm.extractor")
    candidates = result.get("candidates", [])
    if not isinstance(candidates, list):
        candidates = []
    normalized = [
        item
        for item in candidates
        if isinstance(item, dict) and isinstance(item.get("package_name"), str)
    ]
    logger.info(
        "llm.extractor.ok duration_ms=%s candidates=%s",
        elapsed_ms(started_at),
        len(normalized),
    )
    return {
        "candidates": normalized,
        "extractor_source": "openrouter",
        "model": model,
        "duration_ms": elapsed_ms(started_at),
    }


def elapsed_ms(started_at: float) -> int:
    return round((time.perf_counter() - started_at) * 1000)


def compact_text(text: str, limit: int = 320) -> str:
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def build_dynamic_investigation_payload(
    req: Any,
    capabilities: dict[str, Any],
) -> dict[str, Any] | None:
    if not llm_planner_enabled():
        return None

    model = os.getenv("OPENROUTER_MODEL")
    if not model:
        return None

    tools = []
    
    if "tools" in capabilities:
        for t_name, t_info in capabilities["tools"].items():
            if not t_info.get("available"):
                continue
                
            safe_name = t_name.replace(".", "_")
            properties = {}
            required = []
            
            for f in t_info.get("filters", []):
                col_name = str(f.get("filter_name"))
                properties[col_name] = {"type": "string", "description": f"Filter by {col_name}"}
                if f.get("is_required"):
                    required.append(col_name)
                    
            tools.append({
                "type": "function",
                "function": {
                    "name": safe_name,
                    "description": str(t_info.get("purpose") or f"Query {t_name}"),
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": required
                    }
                }
            })

    if not tools:
        return None

    logger.info("llm.dynamic_tools.init model=%s tools=%s", model, len(tools))
    return {
        "model": model,
        "temperature": 0.2,
        "max_tokens": 4000,
        "tools": tools,
        "tool_choice": "auto",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are HarborGuard's dynamic autonomous investigation agent. "
                    "Your goal is to autonomously determine the project stack, read the appropriate manifest files (like package.json, pom.xml, go.mod), "
                    "and cross-reference the discovered dependencies with deps_dev and osv.\n"
                    "Workflow:\n"
                    "1. Call github_search_code to find package manifests and determine the stack.\n"
                    "2. Once you see the file paths, if they belong to supported ecosystems (npm, pypi, go, maven, cargo, nuget), "
                    "call deps_dev_versions and osv_query_by_version on the relevant packages.\n"
                    "You will receive the output of your tool calls. Make up to 3 turns of tool calls to complete the investigation.\n"
                    "CRITICAL RULE: When investigating, always restrict your searches, commits, and pull requests to the default branch (e.g. 'main' or 'master') only."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": "Investigate the target repository and its dependencies autonomously.",
                        "request": _request_context(req),
                    },
                    indent=2,
                ),
            },
        ],
    }
