import ast
import json
import logging
import os
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from coral_mcp_client import CoralMCPClient, CoralMCPError, mcp_discovery_enabled
from coral_client import CoralClient, CoralClientError, load_dotenv
from llm_orchestrator import LLMPlannerError, plan_with_openrouter

load_dotenv()


def configure_logging() -> None:
    level = os.getenv("HARBORGUARD_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("harborguard").setLevel(level)


configure_logging()
logger = logging.getLogger("harborguard.api")

app = FastAPI(
    title="HarborGuard",
    description="Security and compliance investigation agent powered by Coral.",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

coral = CoralClient()


def env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def fixtures_enabled() -> bool:
    return env_truthy("HARBORGUARD_USE_FIXTURES")


def load_fixture(name: str) -> dict[str, object] | None:
    if not fixtures_enabled():
        return None

    fixture_dir = os.getenv("HARBORGUARD_FIXTURES_DIR")
    if fixture_dir:
        path = Path(fixture_dir) / f"{name}.json"
    else:
        path = Path(__file__).resolve().parent / "fixtures" / f"{name}.json"

    if not path.exists():
        logger.warning("fixture.missing name=%s path=%s", name, path)
        return None

    try:
        return json.loads(path.read_text())
    except Exception as error:
        logger.warning("fixture.load_failed name=%s error=%s", name, error)
        return None


@app.middleware("http")
async def log_http_requests(request: Request, call_next):
    request_id = uuid.uuid4().hex[:8]
    started_at = time.perf_counter()
    logger.info(
        "http.request.start request_id=%s method=%s path=%s",
        request_id,
        request.method,
        request.url.path,
    )
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "http.request.error request_id=%s method=%s path=%s duration_ms=%s",
            request_id,
            request.method,
            request.url.path,
            elapsed_ms(started_at),
        )
        raise

    response.headers["X-HarborGuard-Request-Id"] = request_id
    logger.info(
        "http.request.done request_id=%s method=%s path=%s status=%s duration_ms=%s",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms(started_at),
    )
    return response


class PackageInvestigationReq(BaseModel):
    system: str
    ecosystem: str
    package_name: str
    version: str


class AgentInvestigationReq(BaseModel):
    question: str
    owner: str
    repo: str
    org: str | None = None
    slack_channel: str | None = None
    policy_query: str = "dependency security review secrets access control"
    package_system: str = "NPM"
    package_ecosystem: str = "npm"
    package_name: str = "minimist"
    package_version: str = "0.0.8"
    days: int = 7


REQUIRED_SOURCES = ("github", "slack", "notion", "osv", "deps_dev")

INVESTIGATION_TOOLS = {
    "github.pulls": {
        "source": "github",
        "kind": "table",
        "purpose": "Inspect merged pull requests for sensitive security changes.",
        "capabilities": ["change_risk", "access_change_detection"],
        "step": "github_recent_pulls",
    },
    "github.alerts": {
        "source": "github",
        "kind": "table",
        "purpose": "Inspect GitHub Dependabot alerts for known vulnerabilities.",
        "capabilities": ["dependabot_alerts", "known_vulnerability_detection"],
        "step": "github_dependabot_alerts",
    },
    "github.search_code": {
        "source": "github",
        "kind": "table_function",
        "purpose": "Search repository code for likely secret-bearing files.",
        "capabilities": ["secret_file_search"],
        "step": "github_secret_file_search",
    },
    "deps_dev.versions": {
        "source": "deps_dev",
        "kind": "table",
        "purpose": "Inspect package version metadata and advisory keys.",
        "capabilities": ["package_metadata", "dependency_risk"],
        "step": "deps_dev_package_version",
    },
    "deps_dev.dependencies": {
        "source": "deps_dev",
        "kind": "table",
        "purpose": "Inspect package dependency graph context.",
        "capabilities": ["dependency_context"],
        "step": "deps_dev_dependencies",
    },
    "deps_dev.advisories": {
        "source": "deps_dev",
        "kind": "table",
        "purpose": "Inspect advisory details and CVSS scores.",
        "capabilities": ["advisory_context"],
        "step": "deps_dev_advisories",
    },
    "osv.query_by_version": {
        "source": "osv",
        "kind": "table",
        "purpose": "Lookup known vulnerabilities for a package version.",
        "capabilities": ["vulnerability_lookup", "cve_context"],
        "step": "osv_package_vulnerabilities",
    },
    "notion.search": {
        "source": "notion",
        "kind": "table",
        "purpose": "Find internal security and compliance policy context.",
        "capabilities": ["policy_context"],
        "step": "notion_policy_context",
    },
    "slack.messages": {
        "source": "slack",
        "kind": "table_function",
        "purpose": "Find related engineering or security discussion.",
        "capabilities": ["discussion_context"],
        "step": "slack_security_discussion",
    },
}


def sql_string(value: str) -> str:
    return value.replace("'", "''")


def deps_dev_advisories_sql(advisory_keys: list[str]) -> str | None:
    if not advisory_keys:
        return None
    normalized = [sql_string(key) for key in advisory_keys if key]
    if not normalized:
        return None
    key_list = ", ".join(f"'{key}'" for key in normalized[:5])
    return f"""
    SELECT advisory_id, title, advisory_url, cvss3_score, aliases
    FROM deps_dev.advisories
    WHERE advisory_id IN ({key_list})
    LIMIT 20
    """


def query_step(name: str, sql: str) -> dict[str, object]:
    return query_step_with_timeout(name, sql, None)


def query_step_with_timeout(
    name: str,
    sql: str,
    timeout_seconds: float | None,
) -> dict[str, object]:
    started_at = time.perf_counter()
    logger.info(
        "agent.step.start name=%s timeout=%s sql=%s",
        name,
        f"{timeout_seconds:g}s" if timeout_seconds else "default",
        compact_sql(sql),
    )
    try:
        result = coral.query(sql, timeout_seconds=timeout_seconds)
    except CoralClientError as error:
        duration_ms = elapsed_ms(started_at)
        logger.warning(
            "agent.step.failed name=%s duration_ms=%s error=%s",
            name,
            duration_ms,
            compact_text(str(error)),
        )
        return {
            "name": name,
            "ok": False,
            "rows": [],
            "sql": sql,
            "error": str(error),
            "duration_ms": duration_ms,
        }

    duration_ms = elapsed_ms(started_at)
    logger.info(
        "agent.step.ok name=%s duration_ms=%s rows=%s",
        name,
        duration_ms,
        len(result.rows),
    )
    return {
        "name": name,
        "ok": True,
        "rows": result.rows,
        "sql": result.sql,
        "error": None,
        "duration_ms": duration_ms,
    }


def severity_score(severity: str | None) -> int:
    values = {
        "critical": 90,
        "high": 75,
        "medium": 50,
        "moderate": 50,
        "low": 25,
    }
    return values.get((severity or "").lower(), 40)


def level_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def package_level_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def recommendation_from_score(score: int) -> str:
    level = package_level_from_score(score)
    if level == "critical":
        return "Block release until the issue is resolved."
    if level == "high":
        return "Require security review before release."
    if level == "medium":
        return "Require maintainer acknowledgement."
    return "Allow with normal review."


def normalize_advisory_keys(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            try:
                parsed = ast.literal_eval(text)
            except (ValueError, SyntaxError):
                parsed = None

        if isinstance(parsed, list):
            return [str(item) for item in parsed if item]
        if isinstance(parsed, str):
            return [parsed]
        if "," in text:
            return [chunk.strip() for chunk in text.split(",") if chunk.strip()]
        return [text]
    return []


def advisory_keys_from_version(version_row: dict | None) -> list[str]:
    if not version_row:
        return []
    return normalize_advisory_keys(version_row.get("advisory_keys"))


def advisory_rows_have_cvss(advisory_rows: list[dict]) -> bool:
    for row in advisory_rows:
        score = row.get("cvss3_score") or row.get("cvss_score")
        try:
            if float(score) >= 5:
                return True
        except (TypeError, ValueError):
            continue
    return False


def version_deprecated(version_row: dict | None) -> bool:
    if not version_row:
        return False
    for key in ("is_deprecated", "deprecated"):
        value = version_row.get(key)
        if isinstance(value, bool) and value:
            return True
        if isinstance(value, str) and value.strip().lower() in {"1", "true", "yes", "on"}:
            return True
    return False


def package_risk_assessment(
    osv_rows: list[dict],
    deps_version: dict | None,
    advisory_rows: list[dict],
    dependency_rows: list[dict],
    advisory_keys: list[str],
) -> dict[str, object]:
    score = 0
    reasons: list[str] = []

    if osv_rows:
        score += 50
        reasons.append("osv_vulnerability")

    if advisory_rows_have_cvss(advisory_rows):
        score += 20
        reasons.append("deps_dev_advisory_cvss")

    if advisory_keys and not osv_rows:
        score += 10
        reasons.append("deps_dev_advisory_keys")

    if version_deprecated(deps_version):
        score += 10
        reasons.append("version_deprecated")

    if dependency_rows:
        score += 5
        reasons.append("dependency_context")

    summary_parts: list[str] = []
    if osv_rows:
        summary_parts.append("OSV reports vulnerabilities for this package version.")
    if advisory_rows:
        summary_parts.append("deps.dev advisory details are available.")
    elif advisory_keys:
        summary_parts.append("deps.dev advisory keys are present.")
    if dependency_rows:
        summary_parts.append("Dependency graph includes direct dependencies.")
    if version_deprecated(deps_version):
        summary_parts.append("Package version is marked deprecated.")

    summary = (
        " ".join(summary_parts)
        if summary_parts
        else "No vulnerability evidence found for this package version."
    )

    return {
        "score": score,
        "severity": package_level_from_score(score),
        "summary": summary,
        "recommendation": recommendation_from_score(score),
        "reasons": reasons,
    }


def build_package_evidence(
    osv_rows: list[dict],
    deps_version: dict | None,
    advisory_rows: list[dict],
    dependency_rows: list[dict],
    advisory_keys: list[str],
) -> list[dict[str, object]]:
    evidence: list[dict[str, object]] = []

    for vuln in osv_rows[:5]:
        osv_id = vuln.get("id")
        evidence.append(
            {
                "source": "osv.query_by_version",
                "text": vuln.get("summary") or osv_id or "OSV vulnerability match",
                "url": f"https://osv.dev/vulnerability/{osv_id}" if osv_id else None,
            }
        )

    if advisory_keys:
        evidence.append(
            {
                "source": "deps_dev.versions",
                "text": f"deps.dev advisory keys: {advisory_keys}",
                "url": None,
            }
        )

    for advisory in advisory_rows[:5]:
        title = advisory.get("title") or advisory.get("advisory_id") or "deps.dev advisory"
        cvss = advisory.get("cvss3_score") or advisory.get("cvss_score")
        if cvss is not None:
            title = f"{title} (CVSS {cvss})"
        evidence.append(
            {
                "source": "deps_dev.advisories",
                "text": title,
                "url": advisory.get("advisory_url") or advisory.get("url"),
            }
        )

    for dep in dependency_rows[:5]:
        name = dep.get("dependency_name") or dep.get("dependency")
        version = dep.get("dependency_version")
        relation = dep.get("relation")
        if name and version:
            text = f"{name}@{version}"
        elif name:
            text = str(name)
        elif version:
            text = str(version)
        else:
            text = "dependency"
        if relation:
            text = f"{text} ({relation})"
        evidence.append(
            {
                "source": "deps_dev.dependencies",
                "text": text,
                "url": None,
            }
        )

    return evidence


def first_rows(step: dict[str, object], limit: int = 3) -> list[dict]:
    rows = step.get("rows")
    if not isinstance(rows, list):
        return []
    return rows[:limit]


def step_by_name(
    steps: list[dict[str, object]],
    name: str,
) -> dict[str, object] | None:
    for step in steps:
        if step.get("name") == name:
            return step
    return None


def skipped_step(name: str, reason: str) -> dict[str, object]:
    logger.info("agent.step.skipped name=%s reason=%s", name, reason)
    return {
        "name": name,
        "ok": True,
        "skipped": True,
        "rows": [],
        "sql": None,
        "error": None,
        "reason": reason,
        "duration_ms": 0,
    }


def elapsed_ms(started_at: float) -> int:
    return round((time.perf_counter() - started_at) * 1000)


def compact_sql(sql: str, limit: int = 320) -> str:
    return compact_text(" ".join(sql.split()), limit)


def compact_text(text: str, limit: int = 320) -> str:
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def query_capability_metadata() -> list[dict[str, object]]:
    metadata_timeout = float(os.getenv("CORAL_METADATA_TIMEOUT_SECONDS", "6"))
    source_list = ", ".join(f"'{source}'" for source in REQUIRED_SOURCES)
    tool_tables = sorted(
        {
            tool_name.split(".", 1)[1]
            for tool_name, tool in INVESTIGATION_TOOLS.items()
            if tool["kind"] == "table"
        }
    )
    table_list = ", ".join(f"'{table}'" for table in tool_tables)

    return [
        query_step_with_timeout(
            "metadata_tables",
            f"""
            SELECT schema_name, table_name, description, guide, required_filters
            FROM coral.tables
            WHERE schema_name IN ({source_list})
            ORDER BY schema_name, table_name
            """,
            metadata_timeout,
        ),
        query_step_with_timeout(
            "metadata_table_functions",
            f"""
            SELECT schema_name, function_name, description, arguments_json,
                   result_columns_json, kind
            FROM coral.table_functions
            WHERE schema_name IN ({source_list})
            ORDER BY schema_name, function_name
            """,
            metadata_timeout,
        ),
        query_step_with_timeout(
            "metadata_columns",
            f"""
            SELECT schema_name, table_name, column_name, data_type, is_nullable,
                   is_virtual, is_required_filter, filter_mode, description
            FROM coral.columns
            WHERE schema_name IN ({source_list})
              AND table_name IN ({table_list})
            ORDER BY schema_name, table_name, ordinal_position
            """,
            metadata_timeout,
        ),
        query_step_with_timeout(
            "metadata_filters",
            f"""
            SELECT schema_name, table_name, filter_name, filter_mode, is_required,
                   data_type, description
            FROM coral.filters
            WHERE schema_name IN ({source_list})
            ORDER BY schema_name, table_name, filter_name
            """,
            metadata_timeout,
        ),
        query_step_with_timeout(
            "metadata_inputs",
            f"""
            SELECT schema_name, key, kind, required, is_set
            FROM coral.inputs
            WHERE schema_name IN ({source_list})
            ORDER BY schema_name, key
            """,
            metadata_timeout,
        ),
    ]


def query_capability_metadata_from_mcp() -> list[dict[str, object]]:
    try:
        with CoralMCPClient() as client:
            items: list[dict[str, object]] = []
            for source in REQUIRED_SOURCES:
                catalog = client.list_catalog(schema=source, limit=200)
                catalog_items = catalog.get("items")
                if isinstance(catalog_items, list):
                    items.extend(
                        item for item in catalog_items if isinstance(item, dict)
                    )

        table_rows = []
        function_rows = []
        for item in items:
            name = str(item.get("name") or "")
            if "." not in name:
                continue
            schema_name, item_name = name.split(".", 1)
            kind = item.get("kind")
            if kind == "table":
                table_rows.append(
                    {
                        "schema_name": schema_name,
                        "table_name": item_name,
                        "description": item.get("description") or "",
                        "guide": item.get("guide") or "",
                        "required_filters": item.get("required_filters") or "",
                    }
                )
            elif kind == "table_function":
                table_function = item.get("table_function")
                function_rows.append(
                    {
                        "schema_name": schema_name,
                        "function_name": item_name,
                        "description": item.get("description") or "",
                        "arguments_json": json_dumps(
                            table_function.get("arguments", [])
                            if isinstance(table_function, dict)
                            else []
                        ),
                        "result_columns_json": json_dumps(
                            table_function.get("result_columns", [])
                            if isinstance(table_function, dict)
                            else []
                        ),
                        "kind": table_function.get("kind")
                        if isinstance(table_function, dict)
                        else "table_function",
                    }
                )

        sql_metadata = query_capability_metadata()
        by_name = {step["name"]: step for step in sql_metadata}
        sql_tables = first_rows(by_name["metadata_tables"], limit=1000)
        sql_functions = first_rows(by_name["metadata_table_functions"], limit=1000)
        merged_tables = merge_metadata_rows(
            table_rows,
            sql_tables,
            ("schema_name", "table_name"),
        )
        merged_functions = merge_metadata_rows(
            function_rows,
            sql_functions,
            ("schema_name", "function_name"),
        )
        return [
            {
                "name": "metadata_tables",
                "ok": True,
                "rows": merged_tables,
                "sql": None,
                "error": None,
                "discovery_backend": "coral_mcp",
                "fallback": "merged_with_coral_sql_metadata",
            },
            {
                "name": "metadata_table_functions",
                "ok": True,
                "rows": merged_functions,
                "sql": None,
                "error": None,
                "discovery_backend": "coral_mcp",
                "fallback": "merged_with_coral_sql_metadata",
            },
            by_name["metadata_columns"],
            by_name["metadata_filters"],
            by_name["metadata_inputs"],
        ]
    except CoralMCPError as error:
        fallback_steps = query_capability_metadata()
        fallback_steps.append(
            {
                "name": "metadata_mcp_discovery",
                "ok": False,
                "rows": [],
                "sql": None,
                "error": str(error),
                "discovery_backend": "coral_mcp",
                "fallback": "coral_sql_metadata",
            }
        )
        return fallback_steps


def merge_metadata_rows(
    primary_rows: list[dict[str, object]],
    fallback_rows: list[dict],
    key_fields: tuple[str, ...],
) -> list[dict[str, object]]:
    merged: dict[tuple[object, ...], dict[str, object]] = {}
    for row in fallback_rows:
        merged[tuple(row.get(field) for field in key_fields)] = row
    for row in primary_rows:
        merged[tuple(row.get(field) for field in key_fields)] = row
    return list(merged.values())


def json_dumps(value: object) -> str:
    try:
        return json.dumps(value)
    except TypeError:
        return "[]"


def discover_capabilities() -> dict[str, object]:
    started_at = time.perf_counter()
    backend = "coral_mcp_with_sql_fallback" if mcp_discovery_enabled() else "coral_sql_metadata"
    logger.info("capabilities.discovery.start backend=%s", backend)
    metadata_steps = (
        query_capability_metadata_from_mcp()
        if mcp_discovery_enabled()
        else query_capability_metadata()
    )
    capabilities = build_capabilities(metadata_steps)
    capabilities["discovery_backend"] = backend
    capabilities["duration_ms"] = elapsed_ms(started_at)
    logger.info(
        "capabilities.discovery.done backend=%s duration_ms=%s available_tools=%s metadata_ok=%s",
        backend,
        capabilities["duration_ms"],
        capabilities["summary"]["available_tool_count"],
        capabilities["summary"]["metadata_ok"],
    )
    return capabilities


def capability_rows(metadata_steps: list[dict[str, object]], name: str) -> list[dict]:
    for step in metadata_steps:
        if step.get("name") == name:
            return first_rows(step, limit=1000)
    return []


def build_capabilities(metadata_steps: list[dict[str, object]]) -> dict[str, object]:
    tables = capability_rows(metadata_steps, "metadata_tables")
    table_functions = capability_rows(metadata_steps, "metadata_table_functions")
    columns = capability_rows(metadata_steps, "metadata_columns")
    filters = capability_rows(metadata_steps, "metadata_filters")
    inputs = capability_rows(metadata_steps, "metadata_inputs")
    required_metadata_ok = all(
        step.get("ok")
        for step in metadata_steps
        if step.get("name") != "metadata_mcp_discovery"
    )

    table_names = {
        f"{row.get('schema_name')}.{row.get('table_name')}"
        for row in tables
    }
    function_names = {
        f"{row.get('schema_name')}.{row.get('function_name')}"
        for row in table_functions
    }

    source_names = {
        str(row.get("schema_name"))
        for row in tables + table_functions
        if row.get("schema_name")
    }

    tools: dict[str, dict[str, object]] = {}
    for tool_name, definition in INVESTIGATION_TOOLS.items():
        is_available = (
            tool_name in table_names
            if definition["kind"] == "table"
            else tool_name in function_names
        )
        tools[tool_name] = {
            **definition,
            "name": tool_name,
            "available": is_available,
            "columns": [
                row
                for row in columns
                if f"{row.get('schema_name')}.{row.get('table_name')}" == tool_name
            ],
            "filters": [
                row
                for row in filters
                if f"{row.get('schema_name')}.{row.get('table_name')}" == tool_name
            ],
        }

    sources = {}
    for source in REQUIRED_SOURCES:
        source_inputs = [row for row in inputs if row.get("schema_name") == source]
        required_inputs = [
            row
            for row in source_inputs
            if row.get("required")
        ]
        missing_inputs = [
            str(row.get("key"))
            for row in required_inputs
            if not row.get("is_set")
        ]
        sources[source] = {
            "available": source in source_names,
            "inputs": source_inputs,
            "configured": all(
                bool(row.get("is_set"))
                for row in required_inputs
            )
            if source_inputs
            else source in source_names,
            "missing_inputs": missing_inputs,
            "tools": [
                tool_name
                for tool_name, tool in tools.items()
                if tool["source"] == source
            ],
        }

    return {
        "sources": sources,
        "tools": tools,
        "summary": {
            "required_source_count": len(REQUIRED_SOURCES),
            "available_source_count": sum(
                1 for source in sources.values() if source["available"]
            ),
            "available_tool_count": sum(
                1 for tool in tools.values() if tool["available"]
            ),
            "metadata_ok": required_metadata_ok,
            "unavailable_sources": [
                source for source, status in sources.items() if not status["available"]
            ],
            "unconfigured_sources": [
                source for source, status in sources.items() if not status["configured"]
            ],
        },
        "metadata_steps": metadata_steps,
    }


def tool_available(capabilities: dict[str, object], tool_name: str) -> bool:
    tools = capabilities.get("tools")
    if not isinstance(tools, dict):
        return False
    tool = tools.get(tool_name)
    return isinstance(tool, dict) and bool(tool.get("available"))


def plan_investigation(
    req: AgentInvestigationReq,
    capabilities: dict[str, object],
) -> dict[str, object]:
    question = req.question.lower()
    selected_tools: list[str] = []
    skipped_tools: list[dict[str, str]] = []
    trace: list[str] = [
        "Discovered Coral source and tool metadata before planning.",
    ]

    def consider(tool_name: str, reason: str, required: bool = True) -> None:
        if not required:
            skipped_tools.append({"tool": tool_name, "reason": reason})
            trace.append(f"Skipped {tool_name}: {reason}.")
            return

        if tool_available(capabilities, tool_name):
            selected_tools.append(tool_name)
            trace.append(f"Selected {tool_name}: {reason}.")
        else:
            skipped_tools.append(
                {"tool": tool_name, "reason": "tool is not available in Coral metadata"}
            )
            trace.append(f"Skipped {tool_name}: not available in Coral metadata.")

    wants_dependency = any(
        word in question
        for word in ("dependency", "package", "cve", "vulnerability", "vulnerable")
    )
    wants_policy = any(word in question for word in ("policy", "compliance", "review"))
    wants_discussion = any(word in question for word in ("slack", "discussion", "bypass"))
    wants_secret = any(word in question for word in ("secret", "token", "credential", ".env"))
    wants_change = any(
        word in question
        for word in ("change", "release", "merged", "pr", "pull request", "access")
    )

    if not any(
        (wants_dependency, wants_policy, wants_discussion, wants_secret, wants_change)
    ):
        trace.append("No narrow intent detected, so planned a broad security review.")
        wants_dependency = wants_policy = wants_secret = wants_change = True

    if wants_change or wants_policy:
        consider("github.pulls", "question needs recent code/change context")

    if wants_dependency:
        consider("github.alerts", "question needs GitHub dependency alert context")
        consider("deps_dev.versions", "question needs package metadata")
        consider("deps_dev.dependencies", "question needs dependency context")
        consider("deps_dev.advisories", "question needs advisory detail")
        consider("osv.query_by_version", "question needs vulnerability lookup")

    if wants_secret:
        consider("github.search_code", "question needs likely secret-file search")

    if wants_policy:
        consider("notion.search", "question needs internal policy context")

    if wants_discussion or req.slack_channel:
        consider(
            "slack.messages",
            "slack_channel was not provided",
            required=bool(req.slack_channel),
        )
    else:
        skipped_tools.append(
            {"tool": "slack.messages", "reason": "discussion context was not requested"}
        )
        trace.append("Skipped slack.messages: discussion context was not requested.")

    return {
        "intent": {
            "dependency_risk": wants_dependency,
            "policy_review": wants_policy,
            "discussion_context": wants_discussion or bool(req.slack_channel),
            "secret_detection": wants_secret,
            "change_risk": wants_change,
        },
        "selected_tools": selected_tools,
        "skipped_tools": skipped_tools,
        "reasoning_trace": trace,
    }


def validate_plan(
    plan: dict[str, object],
    req: AgentInvestigationReq,
    capabilities: dict[str, object],
) -> dict[str, object]:
    allowed_tools = set(INVESTIGATION_TOOLS)
    selected_tools = []
    skipped_tools = [
        item
        for item in plan.get("skipped_tools", [])
        if isinstance(item, dict)
        and isinstance(item.get("tool"), str)
        and isinstance(item.get("reason"), str)
    ]
    trace = [str(item) for item in plan.get("reasoning_trace", []) if item]

    for tool in plan.get("selected_tools", []):
        if not isinstance(tool, str) or tool not in allowed_tools:
            skipped_tools.append(
                {"tool": str(tool), "reason": "rejected because it is not allowed"}
            )
            continue
        if not tool_available(capabilities, tool):
            skipped_tools.append(
                {"tool": tool, "reason": "tool is not available in Coral metadata"}
            )
            continue
        if tool == "slack.messages" and not req.slack_channel:
            skipped_tools.append({"tool": tool, "reason": "slack_channel was not provided"})
            continue
        selected_tools.append(tool)

    if not selected_tools:
        fallback = plan_investigation(req, capabilities)
        fallback["planner_source"] = "deterministic_fallback"
        fallback["fallback_reason"] = "LLM plan selected no runnable tools"
        return fallback

    return {
        "intent": plan.get("intent") or "llm_planned_investigation",
        "selected_tools": selected_tools,
        "skipped_tools": skipped_tools,
        "reasoning_trace": trace,
        "planner_source": plan.get("planner_source", "unknown"),
        "model": plan.get("model"),
    }


def plan_with_orchestrator(
    req: AgentInvestigationReq,
    capabilities: dict[str, object],
) -> dict[str, object]:
    allowed_tools = list(INVESTIGATION_TOOLS)
    started_at = time.perf_counter()
    logger.info(
        "planner.start question=%s allowed_tools=%s",
        compact_text(req.question),
        len(allowed_tools),
    )
    try:
        llm_plan = plan_with_openrouter(req, capabilities, allowed_tools)
        plan = validate_plan(llm_plan, req, capabilities)
        plan["duration_ms"] = elapsed_ms(started_at)
        logger.info(
            "planner.done source=%s duration_ms=%s selected_tools=%s",
            plan.get("planner_source"),
            plan["duration_ms"],
            len(plan.get("selected_tools", [])),
        )
        return plan
    except LLMPlannerError as error:
        fallback = plan_investigation(req, capabilities)
        fallback["planner_source"] = "deterministic_fallback"
        fallback["fallback_reason"] = str(error)
        fallback["duration_ms"] = elapsed_ms(started_at)
        fallback["reasoning_trace"] = [
            f"LLM planner unavailable, falling back to deterministic planner: {error}.",
            *fallback["reasoning_trace"],
        ]
        logger.warning(
            "planner.fallback duration_ms=%s reason=%s selected_tools=%s",
            fallback["duration_ms"],
            compact_text(str(error)),
            len(fallback.get("selected_tools", [])),
        )
        return fallback


def build_agent_findings(
    req: AgentInvestigationReq,
    steps: list[dict[str, object]],
) -> list[dict[str, object]]:
    by_name = {str(step["name"]): step for step in steps}
    findings: list[dict[str, object]] = []

    alerts = first_rows(by_name["github_dependabot_alerts"], limit=10)
    for alert in alerts:
        package = alert.get("dependency__package__name") or "unknown package"
        severity = str(alert.get("security_advisory__severity") or "medium")
        findings.append(
            {
                "type": "known_vulnerability",
                "title": f"Dependabot reports {package} vulnerability",
                "severity": level_from_score(severity_score(severity)),
                "score": severity_score(severity),
                "evidence": [
                    {
                        "source": "github.alerts",
                        "text": alert.get("security_advisory__summary")
                        or "GitHub returned a Dependabot alert.",
                        "url": alert.get("html_url"),
                    }
                ],
                "recommendation": "Prioritize remediation or require security approval.",
            }
        )

    osv_vulns = first_rows(by_name.get("osv_package_vulnerabilities", {}), limit=10)
    deps_versions = first_rows(by_name.get("deps_dev_package_version", {}), limit=1)
    deps_version = deps_versions[0] if deps_versions else None
    deps_dependencies = first_rows(by_name.get("deps_dev_dependencies", {}), limit=10)
    deps_advisories = first_rows(by_name.get("deps_dev_advisories", {}), limit=10)
    advisory_keys = advisory_keys_from_version(deps_version)

    package_risk = package_risk_assessment(
        osv_vulns,
        deps_version,
        deps_advisories,
        deps_dependencies,
        advisory_keys,
    )
    evidence = build_package_evidence(
        osv_vulns,
        deps_version,
        deps_advisories,
        deps_dependencies,
        advisory_keys,
    )

    if evidence:
        findings.append(
            {
                "type": "vulnerable_dependency",
                "title": f"{req.package_name}@{req.package_version} has vulnerability evidence",
                "severity": package_risk["severity"],
                "score": package_risk["score"],
                "evidence": evidence,
                "recommendation": package_risk["recommendation"],
            }
        )

    secret_hits = first_rows(by_name["github_secret_file_search"], limit=10)
    if secret_hits:
        findings.append(
            {
                "type": "possible_secret_exposure",
                "title": "Repository contains files that may expose secrets",
                "severity": "high",
                "score": 70,
                "evidence": [
                    {
                        "source": "github.search_code",
                        "text": f"{row.get('path') or row.get('name')}",
                        "url": row.get("html_url"),
                    }
                    for row in secret_hits[:5]
                ],
                "recommendation": "Review matched files and rotate exposed credentials if needed.",
            }
        )

    risky_keywords = (
        "auth",
        "token",
        "secret",
        "password",
        "permission",
        "admin",
        "iam",
        "package",
        "dependency",
        "lock",
        "terraform",
        ".env",
    )
    pull_rows = first_rows(by_name["github_recent_pulls"], limit=20)

    def _risky_keyword_count(row: dict) -> int:
        text = f"{row.get('title', '')} {row.get('body', '')} {row.get('label_names', '')}".lower()
        return sum(1 for word in risky_keywords if word in text)

    risky_pulls = [
        (row, _risky_keyword_count(row))
        for row in pull_rows
        if _risky_keyword_count(row) > 0
    ]
    # Sort by keyword count descending so the riskiest PRs surface first
    risky_pulls.sort(key=lambda item: item[1], reverse=True)

    if risky_pulls:
        # Score scales: 25 base + 5 per keyword hit across all risky PRs, capped at 65
        total_hits = sum(count for _, count in risky_pulls)
        pr_score = min(25 + total_hits * 5, 65)
        findings.append(
            {
                "type": "risky_change",
                "title": f"{len(risky_pulls)} recent merged pull request(s) mention sensitive areas",
                "severity": level_from_score(pr_score),
                "score": pr_score,
                "evidence": [
                    {
                        "source": "github.pulls",
                        "text": f"PR #{row.get('number')}: {row.get('title')}",
                        "url": row.get("html_url") or row.get("url"),
                    }
                    for row, _ in risky_pulls[:5]
                ],
                "recommendation": "Ask the security reviewer to inspect these changes.",
            }
        )

    policy_rows = first_rows(by_name["notion_policy_context"], limit=3)
    slack_rows = first_rows(by_name["slack_security_discussion"], limit=3)
    for finding in findings:
        finding["policy_context"] = [
            {
                "source": "notion.search",
                "text": row.get("url") or row.get("id"),
                "url": row.get("url"),
            }
            for row in policy_rows
        ]
        finding["discussion_context"] = [
            {
                "source": "slack.messages",
                "text": row.get("text"),
                "url": None,
            }
            for row in slack_rows
        ]

    return sorted(findings, key=lambda item: int(item["score"]), reverse=True)


def build_evidence_graph(
    req: AgentInvestigationReq,
    findings: list[dict[str, object]],
) -> dict[str, list[dict[str, object]]]:
    nodes: dict[str, dict[str, object]] = {}
    edges: list[dict[str, object]] = []

    # Narrative-driven causal graph construction
    package_id = f"pkg:{req.package_ecosystem}:{req.package_name}:{req.package_version}"
    nodes[package_id] = {
        "id": package_id,
        "type": "package",
        "label": f"{req.package_name}@{req.package_version}",
    }

    for index, finding in enumerate(findings, start=1):
        # We DO NOT create a finding node in the graph anymore.
        # Instead, we construct the causal chain from the evidence.
        
        vuln_nodes = []
        source_nodes = []
        other_evidence = []
        
        for evidence_index, evidence in enumerate(finding.get("evidence", []), start=1):
            if not isinstance(evidence, dict):
                continue
            
            source = str(evidence.get("source") or "evidence")
            label = str(evidence.get("text") or source)
            evidence_id = f"evidence:{index}:{evidence_index}"
            
            node = {
                "id": evidence_id,
                "label": label,
                "source": source,
                "url": evidence.get("url"),
            }
            
            # --- Extract canonical vuln ID from URL or label ---
            import re
            ghsa_match = re.search(r'(GHSA-[\w-]+)', label) or (
                re.search(r'(GHSA-[\w-]+)', str(evidence.get("url") or ""))
            )
            cve_match = re.search(r'(CVE-\d{4}-\d+)', label)
            canonical_vuln_id = None
            if ghsa_match:
                canonical_vuln_id = f"vuln:{ghsa_match.group(1)}"
            elif cve_match:
                canonical_vuln_id = f"vuln:{cve_match.group(1)}"
            
            if source == "osv.query_by_version" and evidence.get("url"):
                evidence_id = canonical_vuln_id or f"vuln:{str(evidence['url']).rsplit('/', 1)[-1]}"
                node["id"] = evidence_id
                node["type"] = "vulnerability"
                if finding.get("severity"): node["severity"] = finding.get("severity")
                if finding.get("score"): node["score"] = finding.get("score")
                vuln_nodes.append(evidence_id)
            elif source == "deps_dev.advisories":
                # Merge into existing vuln node if same advisory
                evidence_id = canonical_vuln_id or evidence_id
                if evidence_id in nodes:
                    # Enrich existing node with deps.dev info (e.g. CVSS score from label)
                    cvss_match = re.search(r'CVSS\s+([\d.]+)', label)
                    if cvss_match and not nodes[evidence_id].get("score"):
                        nodes[evidence_id]["score"] = float(cvss_match.group(1))
                    if evidence.get("url") and not nodes[evidence_id].get("url"):
                        nodes[evidence_id]["url"] = evidence.get("url")
                    # Don't create a duplicate node or edge
                    continue
                node["id"] = evidence_id
                node["type"] = "vulnerability"
                if finding.get("severity"): node["severity"] = finding.get("severity")
                if finding.get("score"): node["score"] = finding.get("score")
                vuln_nodes.append(evidence_id)
            elif source == "deps_dev.versions":
                # This is metadata about the package itself, not a separate evidence node.
                # Skip creating a standalone node — the info is already in the package node.
                continue
            elif source == "github.pulls":
                node["type"] = "pull_request"
                source_nodes.append(evidence_id)
            elif source == "github.alerts":
                node["type"] = "github_alert"
                vuln_nodes.append(evidence_id)
            elif source == "github.search_code":
                node["type"] = "code_search_result"
                other_evidence.append(evidence_id)
            else:
                node["type"] = "evidence"
                other_evidence.append(evidence_id)
                
            nodes[evidence_id] = node

        # Build causality
        # 1. Sources -> Package
        for src_id in source_nodes:
            edges.append({"from": src_id, "to": package_id, "type": "introduced"})
            
        # 2. Package -> Vulnerabilities
        for v_id in vuln_nodes:
            edges.append({"from": package_id, "to": v_id, "type": "matched"})
            
        # 3. Vulnerabilities -> Other Evidence
        # If no vuln, Package -> Other Evidence
        for ev_id in other_evidence:
            if vuln_nodes:
                for v_id in vuln_nodes:
                    edges.append({"from": v_id, "to": ev_id, "type": "documented_by"})
            else:
                edges.append({"from": package_id, "to": ev_id, "type": "supported_by"})
                
        # Policies
        for policy_index, policy in enumerate(finding.get("policy_context", []), start=1):
            if not isinstance(policy, dict):
                continue
            policy_id = f"policy:{index}:{policy_index}"
            nodes[policy_id] = {
                "id": policy_id,
                "type": "policy",
                "label": str(policy.get("text") or "Notion policy"),
                "source": policy.get("source"),
                "url": policy.get("url"),
            }
            # Policy -> Vuln if exists, else Policy -> Package
            if vuln_nodes:
                for v_id in vuln_nodes:
                    edges.append({"from": v_id, "to": policy_id, "type": "violates"})
            else:
                edges.append({"from": package_id, "to": policy_id, "type": "violates"})
                
        # Discussions
        for discussion_index, discussion in enumerate(finding.get("discussion_context", []), start=1):
            if not isinstance(discussion, dict):
                continue
            discussion_id = f"discussion:{index}:{discussion_index}"
            nodes[discussion_id] = {
                "id": discussion_id,
                "type": "discussion",
                "label": str(discussion.get("text") or "Slack discussion"),
                "source": discussion.get("source"),
            }
            # Discussion connects to Package
            edges.append({"from": package_id, "to": discussion_id, "type": "discussed_in"})

    # Deduplicate edges
    seen_edges = set()
    unique_edges = []
    for edge in edges:
        key = (edge["from"], edge["to"], edge["type"])
        if key not in seen_edges:
            seen_edges.add(key)
            unique_edges.append(edge)

    return {"nodes": list(nodes.values()), "edges": unique_edges}


def build_debug_timeline(
    metadata_steps: object,
    plan: dict[str, object],
    steps: list[dict[str, object]],
    total_duration_ms: int,
) -> list[dict[str, object]]:
    timeline: list[dict[str, object]] = [
        {
            "phase": "metadata",
            "name": "discover_capabilities",
            "ok": all(
                bool(step.get("ok"))
                for step in metadata_steps
                if isinstance(step, dict)
            )
            if isinstance(metadata_steps, list)
            else False,
            "duration_ms": sum_step_durations(metadata_steps),
        },
        {
            "phase": "planning",
            "name": str(plan.get("planner_source") or "planner"),
            "ok": not bool(plan.get("fallback_reason")),
            "duration_ms": int(plan.get("duration_ms") or 0),
            "selected_tools": plan.get("selected_tools", []),
            "fallback_reason": plan.get("fallback_reason"),
        },
    ]

    for step in steps:
        timeline.append(
            {
                "phase": "execution",
                "name": step.get("name"),
                "ok": step.get("ok"),
                "skipped": step.get("skipped", False),
                "duration_ms": int(step.get("duration_ms") or 0),
                "rows": len(step.get("rows", []))
                if isinstance(step.get("rows"), list)
                else 0,
                "error": step.get("error"),
                "reason": step.get("reason"),
            }
        )

    timeline.append(
        {
            "phase": "synthesis",
            "name": "risk_assessment",
            "ok": True,
            "duration_ms": total_duration_ms,
        }
    )
    return timeline


def sum_step_durations(steps: object) -> int:
    if not isinstance(steps, list):
        return 0
    return sum(
        int(step.get("duration_ms") or 0)
        for step in steps
        if isinstance(step, dict)
    )


@app.get("/")
def read_root() -> dict[str, str]:
    return {"name": "HarborGuard", "status": "READY"}


@app.post("/agent/plan")
def agent_plan(req: AgentInvestigationReq) -> dict[str, object]:
    """Dry-run planner endpoint: discovers capabilities and returns the investigation
    plan without executing any Coral queries.  Useful for debugging and the frontend
    Coral capability panel."""
    started_at = time.perf_counter()
    logger.info(
        "endpoint.agent_plan.start owner=%s repo=%s question=%s",
        req.owner,
        req.repo,
        compact_text(req.question),
    )
    capabilities = discover_capabilities()
    plan = plan_with_orchestrator(req, capabilities)
    duration_ms = elapsed_ms(started_at)
    logger.info(
        "endpoint.agent_plan.done duration_ms=%s selected_tools=%s planner=%s",
        duration_ms,
        len(plan.get("selected_tools", [])),
        plan.get("planner_source"),
    )
    return {
        "question": req.question,
        "plan": plan,
        "capability_summary": capabilities["summary"],
        "capabilities": capabilities,
        "duration_ms": duration_ms,
    }


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.get("/sources")
def sources() -> dict[str, object]:
    sql = """
    SELECT schema_name, table_name
    FROM coral.tables
    WHERE schema_name IN ('osv', 'deps_dev', 'github', 'slack', 'notion')
    ORDER BY schema_name, table_name
    """

    try:
        result = coral.query(sql)
    except CoralClientError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error

    return {
        "sources": [
            {"schema": row["schema_name"], "table": row["table_name"]}
            for row in result.rows
        ],
        "sql": result.sql,
    }


@app.get("/agent/capabilities")
def agent_capabilities() -> dict[str, object]:
    logger.info("endpoint.agent_capabilities.start")
    capabilities = discover_capabilities()
    logger.info(
        "endpoint.agent_capabilities.done available_sources=%s available_tools=%s",
        capabilities["summary"]["available_source_count"],
        capabilities["summary"]["available_tool_count"],
    )

    return {
        "description": "Coral metadata-derived HarborGuard investigation capabilities.",
        "required_sources": list(REQUIRED_SOURCES),
        "capabilities": capabilities,
    }


@app.get("/agent/coral-debug")
def agent_coral_debug() -> dict[str, object]:
    try:
        source_list = coral.source_list()
    except Exception as error:
        source_list_payload: dict[str, object] = {
            "ok": False,
            "error": str(error),
        }
    else:
        source_list_payload = {
            "ok": source_list.returncode == 0,
            "returncode": source_list.returncode,
            "stdout": source_list.stdout,
            "stderr": source_list.stderr,
        }

    return {
        "coral_bin": coral.coral_bin,
        "coral_config_dir": coral.config_dir,
        "source_list": source_list_payload,
        "sql_metadata": query_capability_metadata(),
    }


@app.post("/investigate/package")
def package_investigation(req: PackageInvestigationReq) -> dict[str, object]:
    started_at = time.perf_counter()
    logger.info(
        "endpoint.package_investigation.start system=%s ecosystem=%s package=%s version=%s",
        req.system,
        req.ecosystem,
        req.package_name,
        req.version,
    )
    fixture = load_fixture("package_investigate")
    if fixture:
        response = dict(fixture)
        response["subject"] = req.model_dump()
        response["fixture_used"] = True
        return response
    package_name = sql_string(req.package_name)
    version = sql_string(req.version)
    system = sql_string(req.system)
    ecosystem = sql_string(req.ecosystem)

    deps_sql = f"""
    SELECT version, published_at, licenses, advisory_keys, related_projects, links
    FROM deps_dev.versions
    WHERE system = '{system}'
      AND package_name = '{package_name}'
      AND version = '{version}'
    LIMIT 1
    """
    osv_sql = f"""
    SELECT id, summary, severity, references
    FROM osv.query_by_version
    WHERE package_name = '{package_name}'
      AND ecosystem = '{ecosystem}'
      AND version = '{version}'
    LIMIT 20
    """
    deps_dependencies_sql = f"""
    SELECT dependency_name, dependency_version, relation
    FROM deps_dev.dependencies
    WHERE system = '{system}'
      AND package_name = '{package_name}'
      AND version = '{version}'
    LIMIT 20
    """

    deps_step = query_step("deps_dev_package_version", deps_sql)
    deps_dependencies_step = query_step("deps_dev_dependencies", deps_dependencies_sql)
    osv_step = query_step("osv_package_vulnerabilities", osv_sql)
    deps_version_rows = first_rows(deps_step, limit=1)
    deps_version = deps_version_rows[0] if deps_version_rows else None
    advisory_keys = advisory_keys_from_version(deps_version)
    advisories_sql = deps_dev_advisories_sql(advisory_keys)
    if advisories_sql:
        deps_advisories_step = query_step("deps_dev_advisories", advisories_sql)
    else:
        deps_advisories_step = skipped_step(
            "deps_dev_advisories",
            "deps.dev version metadata did not include advisory keys",
        )

    osv_rows = first_rows(osv_step, limit=20)
    deps_dependencies_rows = first_rows(deps_dependencies_step, limit=20)
    deps_advisory_rows = first_rows(deps_advisories_step, limit=20)
    package_risk = package_risk_assessment(
        osv_rows,
        deps_version,
        deps_advisory_rows,
        deps_dependencies_rows,
        advisory_keys,
    )
    evidence = build_package_evidence(
        osv_rows,
        deps_version,
        deps_advisory_rows,
        deps_dependencies_rows,
        advisory_keys,
    )

    findings = build_agent_findings(
        AgentInvestigationReq(
            question=f"Is {req.package_name}@{req.version} risky?",
            owner="",
            repo="",
            package_system=req.system,
            package_ecosystem=req.ecosystem,
            package_name=req.package_name,
            package_version=req.version,
        ),
        [
            {"name": "github_dependabot_alerts", "rows": []},
            osv_step,
            deps_step,
            deps_dependencies_step,
            deps_advisories_step,
            {"name": "github_secret_file_search", "rows": []},
            {"name": "github_recent_pulls", "rows": []},
            {"name": "notion_policy_context", "rows": []},
            {"name": "slack_security_discussion", "rows": []},
        ],
    )

    duration_ms = elapsed_ms(started_at)
    logger.info(
        "endpoint.package_investigation.done duration_ms=%s findings=%s",
        duration_ms,
        len(findings),
    )
    steps = [deps_step, deps_dependencies_step, deps_advisories_step, osv_step]
    return {
        "subject": req.model_dump(),
        "risk_level": package_risk["severity"],
        "severity": package_risk["severity"],
        "score": package_risk["score"],
        "summary": package_risk["summary"],
        "recommendation": package_risk["recommendation"],
        "evidence": evidence,
        "sql": {
            "osv": osv_sql,
            "deps_dev_version": deps_sql,
            "deps_dev_dependencies": deps_dependencies_sql,
            "deps_dev_advisories": advisories_sql,
        },
        "findings": findings,
        "steps": steps,
        "debug_timeline": build_debug_timeline([], {}, steps, duration_ms),
    }


@app.post("/agent/investigate")
def agent_investigate(req: AgentInvestigationReq) -> dict[str, object]:
    started_at = time.perf_counter()
    logger.info(
        "endpoint.agent_investigate.start owner=%s repo=%s package=%s version=%s question=%s",
        req.owner,
        req.repo,
        req.package_name,
        req.package_version,
        compact_text(req.question),
    )
    fixture = load_fixture("agent_investigate")
    if fixture:
        response = dict(fixture)
        response["question"] = req.question
        response["fixture_used"] = True
        return response
    owner = sql_string(req.owner)
    repo = sql_string(req.repo)
    org = sql_string(req.org or req.owner)
    package_name = sql_string(req.package_name)
    package_version = sql_string(req.package_version)
    package_system = sql_string(req.package_system)
    package_ecosystem = sql_string(req.package_ecosystem)
    policy_query = sql_string(req.policy_query)

    github_recent_pulls_sql = f"""
    SELECT number, title, body, user__login, merged_at, url, label_names
    FROM github.pulls
    WHERE owner = '{owner}'
      AND repo = '{repo}'
      AND state = 'closed'
      AND merged_at IS NOT NULL
    ORDER BY merged_at DESC
    LIMIT 20
    """
    github_dependabot_alerts_sql = f"""
    SELECT number, state, dependency__package__ecosystem, dependency__package__name,
           security_advisory__severity, security_advisory__summary, html_url, created_at
    FROM github.alerts
    WHERE org = '{org}'
      AND state = 'open'
    LIMIT 20
    """
    github_secret_file_search_sql = f"""
    SELECT name, path, html_url, repository_full_name
    FROM github.search_code(q => 'repo:{owner}/{repo} filename:.env')
    LIMIT 10
    """
    deps_dev_package_version_sql = f"""
    SELECT version, published_at, licenses, advisory_keys, related_projects, links
    FROM deps_dev.versions
    WHERE system = '{package_system}'
      AND package_name = '{package_name}'
      AND version = '{package_version}'
    LIMIT 1
    """
    deps_dev_dependencies_sql = f"""
    SELECT dependency_name, dependency_version, relation
    FROM deps_dev.dependencies
    WHERE system = '{package_system}'
      AND package_name = '{package_name}'
      AND version = '{package_version}'
    LIMIT 20
    """
    osv_package_vulnerabilities_sql = f"""
    SELECT id, summary, severity, references
    FROM osv.query_by_version
    WHERE package_name = '{package_name}'
      AND ecosystem = '{package_ecosystem}'
      AND version = '{package_version}'
    LIMIT 20
    """
    notion_policy_context_sql = f"""
    SELECT id, object, url, public_url, raw
    FROM notion.search
    WHERE query = '{policy_query}'
    LIMIT 5
    """

    capabilities = discover_capabilities()
    metadata_steps = capabilities.get("metadata_steps", [])
    plan = plan_with_orchestrator(req, capabilities)
    selected_tools = set(plan["selected_tools"])

    runnable_steps = {
        "github.pulls": ("github_recent_pulls", github_recent_pulls_sql),
        "github.alerts": ("github_dependabot_alerts", github_dependabot_alerts_sql),
        "github.search_code": (
            "github_secret_file_search",
            github_secret_file_search_sql,
        ),
        "deps_dev.versions": ("deps_dev_package_version", deps_dev_package_version_sql),
        "deps_dev.dependencies": (
            "deps_dev_dependencies",
            deps_dev_dependencies_sql,
        ),
        "osv.query_by_version": (
            "osv_package_vulnerabilities",
            osv_package_vulnerabilities_sql,
        ),
        "notion.search": ("notion_policy_context", notion_policy_context_sql),
    }

    steps = []
    for tool_name, (step_name, sql) in runnable_steps.items():
        if tool_name in selected_tools:
            steps.append(query_step(step_name, sql))
        else:
            skipped = next(
                (
                    item
                    for item in plan["skipped_tools"]
                    if item["tool"] == tool_name
                ),
                {"reason": "planner did not select this tool"},
            )
            steps.append(skipped_step(step_name, skipped["reason"]))

    deps_version_step = step_by_name(steps, "deps_dev_package_version")
    deps_version_rows = first_rows(deps_version_step or {}, limit=1)
    deps_version = deps_version_rows[0] if deps_version_rows else None
    advisory_keys = advisory_keys_from_version(deps_version)
    advisories_sql = deps_dev_advisories_sql(advisory_keys)
    if "deps_dev.advisories" in selected_tools:
        if advisories_sql:
            advisories_step = query_step("deps_dev_advisories", advisories_sql)
        else:
            advisories_step = skipped_step(
                "deps_dev_advisories",
                "deps.dev version metadata did not include advisory keys",
            )
    else:
        skipped = next(
            (
                item
                for item in plan["skipped_tools"]
                if item["tool"] == "deps_dev.advisories"
            ),
            {"reason": "planner did not select this tool"},
        )
        advisories_step = skipped_step("deps_dev_advisories", skipped["reason"])

    steps.append(advisories_step)

    if req.slack_channel:
        slack_channel = sql_string(req.slack_channel)
        slack_security_discussion_sql = f"""
        SELECT user_id, text, ts, thread_ts, reply_count
        FROM slack.messages(channel => '{slack_channel}')
        WHERE text ILIKE '%security%'
           OR text ILIKE '%dependency%'
           OR text ILIKE '%secret%'
           OR text ILIKE '%access%'
           OR text ILIKE '%{package_name}%'
        LIMIT 20
        """
        if "slack.messages" in selected_tools:
            steps.append(query_step("slack_security_discussion", slack_security_discussion_sql))
        else:
            skipped = next(
                (
                    item
                    for item in plan["skipped_tools"]
                    if item["tool"] == "slack.messages"
                ),
                {"reason": "planner did not select this tool"},
            )
            steps.append(skipped_step("slack_security_discussion", skipped["reason"]))
    else:
        skipped = next(
            (
                item
                for item in plan["skipped_tools"]
                if item["tool"] == "slack.messages"
            ),
            {"reason": "slack_channel was not provided"},
        )
        steps.append(skipped_step("slack_security_discussion", skipped["reason"]))

    findings = build_agent_findings(req, steps)
    evidence_graph = build_evidence_graph(req, findings)
    max_score = max([int(finding["score"]) for finding in findings], default=0)
    risk_level = level_from_score(max_score)
    failed_steps = [step for step in steps if not step.get("ok")]
    total_duration_ms = elapsed_ms(started_at)
    debug_timeline = build_debug_timeline(
        metadata_steps,
        plan,
        steps,
        total_duration_ms,
    )
    reasoning_trace = [
        *plan["reasoning_trace"],
        f"Executed {len([step for step in steps if not step.get('skipped')])} selected investigation step(s).",
        f"Generated {len(findings)} finding(s) with maximum score {max_score}.",
    ]
    logger.info(
        "endpoint.agent_investigate.done duration_ms=%s risk=%s score=%s findings=%s failed_steps=%s",
        total_duration_ms,
        risk_level,
        max_score,
        len(findings),
        len(failed_steps),
    )

    return {
        "question": req.question,
        "answer": (
            f"HarborGuard found {len(findings)} security or compliance finding(s)."
            if findings
            else "HarborGuard did not find high-confidence risk evidence in the configured sources."
        ),
        "risk_level": risk_level,
        "score": max_score,
        "findings": findings,
        "evidence_graph": evidence_graph,
        "reasoning_trace": reasoning_trace,
        "planner": plan,
        "capability_summary": capabilities["summary"],
        "steps": steps,
        "metadata_steps": metadata_steps,
        "debug_timeline": debug_timeline,
        "source_status": {
            "ok": len(failed_steps) == 0,
            "failed_steps": [
                {"name": step["name"], "error": step.get("error")}
                for step in failed_steps
            ],
        },
    }
