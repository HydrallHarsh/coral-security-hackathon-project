import json

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from coral_mcp_client import CoralMCPClient, CoralMCPError, mcp_discovery_enabled
from coral_client import CoralClient, CoralClientError
from llm_orchestrator import LLMPlannerError, plan_with_openrouter

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


def query_step(name: str, sql: str) -> dict[str, object]:
    try:
        result = coral.query(sql)
    except CoralClientError as error:
        return {
            "name": name,
            "ok": False,
            "rows": [],
            "sql": sql,
            "error": str(error),
        }

    return {
        "name": name,
        "ok": True,
        "rows": result.rows,
        "sql": result.sql,
        "error": None,
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


def first_rows(step: dict[str, object], limit: int = 3) -> list[dict]:
    rows = step.get("rows")
    if not isinstance(rows, list):
        return []
    return rows[:limit]


def skipped_step(name: str, reason: str) -> dict[str, object]:
    return {
        "name": name,
        "ok": True,
        "skipped": True,
        "rows": [],
        "sql": None,
        "error": None,
        "reason": reason,
    }


def query_capability_metadata() -> list[dict[str, object]]:
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
        query_step(
            "metadata_tables",
            f"""
            SELECT schema_name, table_name, description, guide, required_filters
            FROM coral.tables
            WHERE schema_name IN ({source_list})
            ORDER BY schema_name, table_name
            """,
        ),
        query_step(
            "metadata_table_functions",
            f"""
            SELECT schema_name, function_name, description, arguments_json,
                   result_columns_json, kind
            FROM coral.table_functions
            WHERE schema_name IN ({source_list})
            ORDER BY schema_name, function_name
            """,
        ),
        query_step(
            "metadata_columns",
            f"""
            SELECT schema_name, table_name, column_name, data_type, is_nullable,
                   is_virtual, is_required_filter, filter_mode, description
            FROM coral.columns
            WHERE schema_name IN ({source_list})
              AND table_name IN ({table_list})
            ORDER BY schema_name, table_name, ordinal_position
            """,
        ),
        query_step(
            "metadata_filters",
            f"""
            SELECT schema_name, table_name, filter_name, filter_mode, is_required,
                   data_type, description
            FROM coral.filters
            WHERE schema_name IN ({source_list})
            ORDER BY schema_name, table_name, filter_name
            """,
        ),
        query_step(
            "metadata_inputs",
            f"""
            SELECT schema_name, key, kind, required, is_set
            FROM coral.inputs
            WHERE schema_name IN ({source_list})
            ORDER BY schema_name, key
            """,
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
        return [
            {
                "name": "metadata_tables",
                "ok": True,
                "rows": table_rows,
                "sql": None,
                "error": None,
                "discovery_backend": "coral_mcp",
            },
            {
                "name": "metadata_table_functions",
                "ok": True,
                "rows": function_rows,
                "sql": None,
                "error": None,
                "discovery_backend": "coral_mcp",
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


def json_dumps(value: object) -> str:
    try:
        return json.dumps(value)
    except TypeError:
        return "[]"


def discover_capabilities() -> dict[str, object]:
    metadata_steps = (
        query_capability_metadata_from_mcp()
        if mcp_discovery_enabled()
        else query_capability_metadata()
    )
    capabilities = build_capabilities(metadata_steps)
    capabilities["discovery_backend"] = (
        "coral_mcp_with_sql_fallback"
        if mcp_discovery_enabled()
        else "coral_sql_metadata"
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
        sources[source] = {
            "available": source in source_names,
            "inputs": source_inputs,
            "configured": all(
                bool(row.get("is_set"))
                for row in source_inputs
                if row.get("required")
            )
            if source_inputs
            else source in source_names,
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
            "metadata_ok": all(step.get("ok") for step in metadata_steps),
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
    try:
        llm_plan = plan_with_openrouter(req, capabilities, allowed_tools)
        return validate_plan(llm_plan, req, capabilities)
    except LLMPlannerError as error:
        fallback = plan_investigation(req, capabilities)
        fallback["planner_source"] = "deterministic_fallback"
        fallback["fallback_reason"] = str(error)
        fallback["reasoning_trace"] = [
            f"LLM planner unavailable, falling back to deterministic planner: {error}.",
            *fallback["reasoning_trace"],
        ]
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

    osv_vulns = first_rows(by_name["osv_package_vulnerabilities"], limit=10)
    deps_versions = first_rows(by_name["deps_dev_package_version"], limit=1)
    deps_version = deps_versions[0] if deps_versions else None
    advisory_keys = deps_version.get("advisory_keys") if deps_version else None

    if osv_vulns or advisory_keys:
        evidence = [
            {
                "source": "osv.query_by_version",
                "text": vuln.get("summary") or vuln.get("id") or "OSV vulnerability match",
                "url": f"https://osv.dev/vulnerability/{vuln.get('id')}"
                if vuln.get("id")
                else None,
            }
            for vuln in osv_vulns[:5]
        ]
        if advisory_keys:
            evidence.append(
                {
                    "source": "deps_dev.versions",
                    "text": f"deps.dev advisory keys: {advisory_keys}",
                    "url": None,
                }
            )

        findings.append(
            {
                "type": "vulnerable_dependency",
                "title": f"{req.package_name}@{req.package_version} has vulnerability evidence",
                "severity": "high",
                "score": 80,
                "evidence": evidence,
                "recommendation": "Require security review before release.",
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
    risky_pulls = [
        row
        for row in pull_rows
        if any(
            word in f"{row.get('title', '')} {row.get('body', '')} {row.get('label_names', '')}".lower()
            for word in risky_keywords
        )
    ]
    if risky_pulls:
        findings.append(
            {
                "type": "risky_change",
                "title": "Recent merged pull requests mention sensitive areas",
                "severity": "medium",
                "score": 45,
                "evidence": [
                    {
                        "source": "github.pulls",
                        "text": f"PR #{row.get('number')}: {row.get('title')}",
                        "url": row.get("url"),
                    }
                    for row in risky_pulls[:5]
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

    package_id = f"pkg:{req.package_ecosystem}:{req.package_name}:{req.package_version}"
    nodes[package_id] = {
        "id": package_id,
        "type": "package",
        "label": f"{req.package_name}@{req.package_version}",
    }

    for index, finding in enumerate(findings, start=1):
        finding_id = f"finding:{index}"
        nodes[finding_id] = {
            "id": finding_id,
            "type": "finding",
            "label": str(finding.get("title") or finding.get("type")),
            "severity": finding.get("severity"),
            "score": finding.get("score"),
        }
        edges.append({"from": finding_id, "to": package_id, "type": "concerns"})
        finding["graph_node_id"] = finding_id

        for evidence_index, evidence in enumerate(finding.get("evidence", []), start=1):
            if not isinstance(evidence, dict):
                continue

            source = str(evidence.get("source") or "evidence")
            label = str(evidence.get("text") or source)
            evidence_id = f"evidence:{index}:{evidence_index}"

            if source == "osv.query_by_version" and evidence.get("url"):
                evidence_id = f"vuln:{str(evidence['url']).rsplit('/', 1)[-1]}"
                edge_type = "affected_by"
                node_type = "vulnerability"
            elif source == "github.pulls":
                edge_type = "introduced_or_related_to"
                node_type = "pull_request"
            elif source == "github.alerts":
                edge_type = "reported_by"
                node_type = "github_alert"
            elif source == "github.search_code":
                edge_type = "found_in"
                node_type = "code_search_result"
            else:
                edge_type = "supported_by"
                node_type = "evidence"

            nodes[evidence_id] = {
                "id": evidence_id,
                "type": node_type,
                "label": label,
                "source": source,
                "url": evidence.get("url"),
            }
            edges.append({"from": finding_id, "to": evidence_id, "type": edge_type})

        for policy_index, policy in enumerate(
            finding.get("policy_context", []),
            start=1,
        ):
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
            edges.append({"from": policy_id, "to": finding_id, "type": "informs"})

        for discussion_index, discussion in enumerate(
            finding.get("discussion_context", []),
            start=1,
        ):
            if not isinstance(discussion, dict):
                continue
            discussion_id = f"discussion:{index}:{discussion_index}"
            nodes[discussion_id] = {
                "id": discussion_id,
                "type": "discussion",
                "label": str(discussion.get("text") or "Slack discussion"),
                "source": discussion.get("source"),
            }
            edges.append(
                {"from": discussion_id, "to": finding_id, "type": "discusses"}
            )

    return {"nodes": list(nodes.values()), "edges": edges}


@app.get("/")
def read_root() -> dict[str, str]:
    return {"name": "HarborGuard", "status": "READY"}


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
    capabilities = discover_capabilities()

    return {
        "description": "Coral metadata-derived HarborGuard investigation capabilities.",
        "required_sources": list(REQUIRED_SOURCES),
        "capabilities": capabilities,
    }


@app.post("/investigate/package")
def package_investigation(req: PackageInvestigationReq) -> dict[str, object]:
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

    deps_step = query_step("deps_dev_package_version", deps_sql)
    osv_step = query_step("osv_package_vulnerabilities", osv_sql)
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
            {"name": "github_secret_file_search", "rows": []},
            {"name": "github_recent_pulls", "rows": []},
            {"name": "notion_policy_context", "rows": []},
            {"name": "slack_security_discussion", "rows": []},
        ],
    )

    return {
        "subject": req.model_dump(),
        "risk_level": findings[0]["severity"] if findings else "low",
        "findings": findings,
        "steps": [deps_step, osv_step],
    }


@app.post("/agent/investigate")
def agent_investigate(req: AgentInvestigationReq) -> dict[str, object]:
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
    reasoning_trace = [
        *plan["reasoning_trace"],
        f"Executed {len([step for step in steps if not step.get('skipped')])} selected investigation step(s).",
        f"Generated {len(findings)} finding(s) with maximum score {max_score}.",
    ]

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
        "source_status": {
            "ok": len(failed_steps) == 0,
            "failed_steps": [
                {"name": step["name"], "error": step.get("error")}
                for step in failed_steps
            ],
        },
    }
