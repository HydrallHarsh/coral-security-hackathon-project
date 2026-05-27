from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from coral_client import CoralClient, CoralClientError

app = FastAPI(
    title="HarborGuard",
    description="Security and compliance investigation agent powered by Coral.",
    version="0.1.0",
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

    steps = [
        query_step("github_recent_pulls", github_recent_pulls_sql),
        query_step("github_dependabot_alerts", github_dependabot_alerts_sql),
        query_step("github_secret_file_search", github_secret_file_search_sql),
        query_step("deps_dev_package_version", deps_dev_package_version_sql),
        query_step("osv_package_vulnerabilities", osv_package_vulnerabilities_sql),
        query_step("notion_policy_context", notion_policy_context_sql),
    ]

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
        steps.append(query_step("slack_security_discussion", slack_security_discussion_sql))
    else:
        steps.append(
            {
                "name": "slack_security_discussion",
                "ok": True,
                "skipped": True,
                "rows": [],
                "sql": None,
                "error": None,
            }
        )

    findings = build_agent_findings(req, steps)
    max_score = max([int(finding["score"]) for finding in findings], default=0)
    risk_level = level_from_score(max_score)
    failed_steps = [step for step in steps if not step.get("ok")]

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
        "agent_plan": [
            "Inspect recent merged GitHub pull requests for sensitive-change signals.",
            "Inspect GitHub Dependabot alerts for known vulnerable dependencies.",
            "Search the repository for likely secret-bearing files.",
            "Cross-check the demo package target against deps.dev and OSV.",
            "Retrieve internal policy context from Notion.",
            "Retrieve related discussion context from Slack when a channel is provided.",
            "Synthesize prioritized findings with evidence and recommendations.",
        ],
        "steps": steps,
        "source_status": {
            "ok": len(failed_steps) == 0,
            "failed_steps": [
                {"name": step["name"], "error": step.get("error")}
                for step in failed_steps
            ],
        },
    }
