import ast
import json
import logging
import os
import re
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from coral_mcp_client import CoralMCPClient, CoralMCPError, mcp_discovery_enabled
from coral_client import CoralClient, CoralClientError, load_dotenv
from llm_orchestrator import (
    LLMPlannerError,
    extract_package_candidates_with_openrouter,
    plan_with_openrouter,
    build_dynamic_investigation_payload,
    openrouter_chat_tools,
)


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


def github_alerts_enabled() -> bool:
    return env_truthy("HARBORGUARD_ENABLE_GITHUB_ALERTS")


def github_query_timeout() -> float:
    return float(os.getenv("HARBORGUARD_GITHUB_QUERY_TIMEOUT_SECONDS", "10"))


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
    package_system: str | None = None
    package_ecosystem: str | None = None
    package_name: str | None = None
    package_version: str | None = None
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
    "github.commits": {
        "source": "github",
        "kind": "table",
        "purpose": "Inspect recent commit messages for dependency changes.",
        "capabilities": ["change_risk", "dependency_change_detection"],
        "step": "github_recent_commits",
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


ECOSYSTEM_TO_DEPS_SYSTEM = {
    "npm": "NPM",
    "javascript": "NPM",
    "node": "NPM",
    "pypi": "PYPI",
    "pip": "PYPI",
    "python": "PYPI",
    "go": "GO",
    "golang": "GO",
    "maven": "MAVEN",
    "java": "MAVEN",
    "cargo": "CARGO",
    "rust": "CARGO",
    "nuget": "NUGET",
}

DEPS_SYSTEM_TO_OSV_ECOSYSTEM = {
    "NPM": "npm",
    "PYPI": "PyPI",
    "GO": "Go",
    "MAVEN": "Maven",
    "CARGO": "crates.io",
    "NUGET": "NuGet",
}


def normalize_ecosystem(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered in {"pip", "python"}:
        return "PyPI"
    if lowered == "pypi":
        return "PyPI"
    if lowered in {"go", "golang"}:
        return "Go"
    if lowered in {"cargo", "rust", "crates.io"}:
        return "crates.io"
    if lowered == "nuget":
        return "NuGet"
    if lowered in {"maven", "java"}:
        return "Maven"
    if lowered in {"npm", "javascript", "node"}:
        return "npm"
    return text


def infer_deps_system(ecosystem: object, explicit_system: object = None) -> str | None:
    if explicit_system:
        normalized = str(explicit_system).strip().upper()
        return normalized or None
    if not ecosystem:
        return None
    key = str(ecosystem).strip().lower()
    return ECOSYSTEM_TO_DEPS_SYSTEM.get(key)


def infer_osv_ecosystem(system: object, ecosystem: object = None) -> str | None:
    normalized_ecosystem = normalize_ecosystem(ecosystem)
    if normalized_ecosystem:
        return normalized_ecosystem
    if system:
        return DEPS_SYSTEM_TO_OSV_ECOSYSTEM.get(str(system).strip().upper())
    return None


def normalize_version(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip().strip("`'\",;)")
    if not text:
        return None
    if text.lower() in {"latest", "current", "unknown", "none", "null"}:
        return None
    return text


PACKAGE_NAME_STOPWORDS = {
    "a",
    "an",
    "and",
    "app",
    "build",
    "change",
    "changes",
    "dependency",
    "dependencies",
    "deps",
    "feature",
    "fix",
    "from",
    "helper",
    "into",
    "it",
    "lock",
    "package",
    "release",
    "source",
    "sources",
    "support",
    "this",
    "up",
    "use",
    "using",
}


def is_plausible_package_name(value: str) -> bool:
    name = value.strip().strip("`'\",")
    lowered = name.lower()
    if not name or lowered in PACKAGE_NAME_STOPWORDS:
        return False
    if len(name) < 2:
        return False
    return bool(
        "/" in name
        or ":" in name
        or "-" in name
        or "_" in name
        or "." in name
        or name.startswith("@")
        or any(char.isalpha() for char in name)
    )


def is_plausible_dependency_version(value: str | None) -> bool:
    if not value:
        return False
    version = value.strip().lstrip("v")
    if version.isdigit():
        return False
    return bool(re.search(r"\d+\.\d+", version) or re.search(r"\d+[a-zA-Z-]+\d*", version))


def normalize_package_candidate(candidate: dict[str, object]) -> dict[str, object] | None:
    package_name = str(candidate.get("package_name") or "").strip().strip("`'\",")
    if not is_plausible_package_name(package_name):
        return None

    version = normalize_version(candidate.get("version"))
    if version and not is_plausible_dependency_version(version):
        version = None
    ecosystem = infer_osv_ecosystem(candidate.get("system"), candidate.get("ecosystem"))
    system = infer_deps_system(ecosystem, candidate.get("system"))
    confidence = candidate.get("confidence")
    try:
        confidence_float = float(confidence)
    except (TypeError, ValueError):
        confidence_float = 0.5

    return {
        "package_name": package_name,
        "version": version,
        "previous_version": normalize_version(candidate.get("previous_version")),
        "ecosystem": ecosystem,
        "system": system,
        "confidence": max(0.0, min(confidence_float, 1.0)),
        "source": str(candidate.get("source") or "unknown"),
        "reason": str(candidate.get("reason") or "Package candidate discovered."),
        "evidence": candidate.get("evidence"),
    }


def request_override_candidate(req: AgentInvestigationReq) -> dict[str, object] | None:
    if not req.package_name:
        return None
    candidate = normalize_package_candidate(
        {
            "package_name": req.package_name,
            "version": req.package_version,
            "system": req.package_system,
            "ecosystem": req.package_ecosystem,
            "confidence": 1.0,
            "source": "user_override",
            "reason": "Advanced package override was provided in the request.",
        }
    )
    if candidate and not candidate.get("version"):
        candidate["reason"] = "Advanced package override provided a package name without an exact version."
    return candidate


DEPENDENCY_PATTERNS = [
    re.compile(
        r"\b(?:bump|bumped|upgrade|upgraded|update|updated)\s+"
        r"(?P<package>@?[\w][\w./:@+-]*?)\s+"
        r"(?:from\s+(?P<from>v?\d[\w.+:-]*)\s+)?to\s+(?P<to>v?\d[\w.+:-]*)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:bump|bumped|upgrade|upgraded|update|updated)\s+"
        r"(?P<package>@?[\w][\w./:@+-]*?)\s+"
        r"(?:=>|->)\s+(?P<to>v?\d[\w.+:-]*)",
        re.IGNORECASE,
    ),
]


def ecosystem_from_text(text: str) -> str | None:
    lowered = text.lower()
    if any(token in lowered for token in ("package.json", "package-lock", "npm", "yarn", "pnpm")):
        return "npm"
    if any(token in lowered for token in ("requirements.txt", "pyproject", "pip", "pypi")):
        return "PyPI"
    if any(token in lowered for token in ("go.mod", "golang", "go module")):
        return "Go"
    if any(token in lowered for token in ("pom.xml", "maven", "gradle")):
        return "Maven"
    if any(token in lowered for token in ("cargo.toml", "cargo.lock", "crate")):
        return "crates.io"
    if any(token in lowered for token in ("nuget", ".csproj", "packages.config")):
        return "NuGet"
    return None


def extract_candidates_from_pulls(pull_rows: list[dict]) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for row in pull_rows:
        title = str(row.get("title") or "")
        body = str(row.get("body") or "")
        text = f"{title}\n{body[:1200]}"
        ecosystem = ecosystem_from_text(text)
        for pattern in DEPENDENCY_PATTERNS:
            for match in pattern.finditer(text):
                package_name = match.group("package").strip("`'\",")
                if not is_plausible_package_name(package_name):
                    continue
                candidate = normalize_package_candidate(
                    {
                        "package_name": package_name,
                        "version": match.group("to"),
                        "previous_version": match.groupdict().get("from"),
                        "ecosystem": ecosystem,
                        "confidence": 0.82 if ecosystem else 0.68,
                        "source": "github.pulls",
                        "reason": f"PR #{row.get('number')} mentions {package_name} upgraded to {match.group('to')}.",
                        "evidence": {
                            "pull_number": row.get("number"),
                            "title": title,
                            "url": row.get("html_url") or row.get("url"),
                        },
                    }
                )
                if candidate:
                    candidates.append(candidate)
    return candidates


def extract_candidates_from_commits(commit_rows: list[dict]) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for row in commit_rows:
        message = str(row.get("commit__message") or "")
        first_line = message.splitlines()[0] if message else ""
        ecosystem = ecosystem_from_text(message)
        for pattern in DEPENDENCY_PATTERNS:
            for match in pattern.finditer(message[:1500]):
                package_name = match.group("package").strip("`'\",")
                if not is_plausible_package_name(package_name):
                    continue
                candidate = normalize_package_candidate(
                    {
                        "package_name": package_name,
                        "version": match.group("to"),
                        "previous_version": match.groupdict().get("from"),
                        "ecosystem": ecosystem,
                        "confidence": 0.78 if ecosystem else 0.62,
                        "source": "github.commits",
                        "reason": f"Commit {str(row.get('sha') or '')[:7]} mentions {package_name} upgraded to {match.group('to')}.",
                        "evidence": {
                            "sha": row.get("sha"),
                            "message": first_line,
                            "url": row.get("html_url"),
                        },
                    }
                )
                if candidate:
                    candidates.append(candidate)
    return candidates


def alert_candidate_version(row: dict) -> str | None:
    for key in (
        "dependency__package__version",
        "dependency__version",
        "vulnerable_version_range",
        "security_vulnerability__vulnerable_version_range",
    ):
        version = normalize_version(row.get(key))
        if version and not any(char in version for char in "<>=|,* "):
            return version
    return None


def extract_candidates_from_alerts(alert_rows: list[dict]) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for row in alert_rows:
        package_name = row.get("dependency__package__name")
        if not package_name:
            continue
        severity = str(row.get("security_advisory__severity") or "medium").lower()
        severity_boost = {
            "critical": 0.22,
            "high": 0.16,
            "medium": 0.1,
            "moderate": 0.1,
            "low": 0.04,
        }.get(severity, 0.08)
        candidate = normalize_package_candidate(
            {
                "package_name": package_name,
                "version": alert_candidate_version(row),
                "ecosystem": row.get("dependency__package__ecosystem"),
                "confidence": 0.58 + severity_boost,
                "source": "github.alerts",
                "reason": f"Open Dependabot alert reports {package_name} with {severity} severity.",
                "evidence": {
                    "alert_number": row.get("number"),
                    "summary": row.get("security_advisory__summary"),
                    "url": row.get("html_url"),
                },
            }
        )
        if candidate:
            candidates.append(candidate)
    return candidates


def dedupe_candidates(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: dict[tuple[object, object, object], dict[str, object]] = {}
    for candidate in candidates:
        normalized = normalize_package_candidate(candidate)
        if not normalized:
            continue
        key = (
            normalized.get("package_name"),
            normalized.get("version"),
            normalized.get("system") or normalized.get("ecosystem"),
        )
        existing = deduped.get(key)
        if not existing or float(normalized["confidence"]) > float(existing["confidence"]):
            deduped[key] = normalized
    return sorted(
        deduped.values(),
        key=lambda item: (
            bool(item.get("version")),
            bool(item.get("system")),
            float(item.get("confidence") or 0),
        ),
        reverse=True,
    )


def extract_package_target(
    req: AgentInvestigationReq,
    pull_step: dict[str, object],
    alert_step: dict[str, object],
    commit_step: dict[str, object] | None = None,
) -> tuple[dict[str, object] | None, dict[str, object]]:
    started_at = time.perf_counter()
    pull_rows = first_rows(pull_step, limit=20)
    alert_rows = first_rows(alert_step, limit=20)
    commit_rows = first_rows(commit_step or {}, limit=20)
    trace: list[str] = []
    llm_status: dict[str, object] = {"used": False}

    override = request_override_candidate(req)
    if override:
        candidates = [override]
        trace.append("Used advanced package override from the request.")
    else:
        deterministic_candidates = [
            *extract_candidates_from_pulls(pull_rows),
            *extract_candidates_from_commits(commit_rows),
            *extract_candidates_from_alerts(alert_rows),
        ]
        candidates = list(deterministic_candidates)
        trace.append(
            f"Deterministic extraction found {len(deterministic_candidates)} package candidate(s)."
        )

        try:
            llm_result = extract_package_candidates_with_openrouter(
                req,
                pull_rows,
                alert_rows,
                deterministic_candidates,
                commit_rows,
            )
            llm_candidates = [
                candidate
                for candidate in (
                    normalize_package_candidate(item)
                    for item in llm_result.get("candidates", [])
                    if isinstance(item, dict)
                )
                if candidate
            ]
            candidates = [*llm_candidates, *candidates]
            llm_status = {
                "used": True,
                "model": llm_result.get("model"),
                "duration_ms": llm_result.get("duration_ms"),
                "candidate_count": len(llm_candidates),
            }
            trace.append(f"LLM extraction returned {len(llm_candidates)} package candidate(s).")
        except LLMPlannerError as error:
            llm_status = {
                "used": False,
                "error": str(error),
            }
            trace.append(f"LLM extraction skipped or failed: {error}.")

    candidates = dedupe_candidates(candidates)
    selected = candidates[0] if candidates else None
    if selected:
        trace.append(
            "Selected "
            f"{selected.get('package_name')}@{selected.get('version') or 'unknown version'} "
            f"from {selected.get('source')}."
        )
    else:
        trace.append("No exact dependency target was discovered from repository context.")

    return selected, {
        "candidates": candidates,
        "selected": selected,
        "trace": trace,
        "llm": llm_status,
        "duration_ms": elapsed_ms(started_at),
    }


def package_extraction_step(extraction: dict[str, object]) -> dict[str, object]:
    return {
        "name": "package_target_extraction",
        "ok": True,
        "rows": extraction.get("candidates", []),
        "sql": None,
        "error": None,
        "duration_ms": int(extraction.get("duration_ms") or 0),
        "selected": extraction.get("selected"),
        "llm": extraction.get("llm"),
    }


def build_package_sql(
    target: dict[str, object],
) -> dict[str, str | None]:
    package_name = sql_string(str(target.get("package_name") or ""))
    version = sql_string(str(target.get("version") or ""))
    system = sql_string(str(target.get("system") or ""))
    ecosystem = sql_string(str(target.get("ecosystem") or ""))

    if not package_name or not version or not system:
        return {
            "deps_version": None,
            "deps_dependencies": None,
            "osv_version": None,
        }

    return {
        "deps_version": f"""
        SELECT version, published_at, licenses, advisory_keys, related_projects, links
        FROM deps_dev.versions
        WHERE system = '{system}'
          AND package_name = '{package_name}'
          AND version = '{version}'
        LIMIT 1
        """,
        "deps_dependencies": f"""
        SELECT dependency_name, dependency_version, relation
        FROM deps_dev.dependencies
        WHERE system = '{system}'
          AND package_name = '{package_name}'
          AND version = '{version}'
        LIMIT 20
        """,
        "osv_version": f"""
        SELECT id, summary, severity, references
        FROM osv.query_by_version
        WHERE package_name = '{package_name}'
          AND ecosystem = '{ecosystem}'
          AND version = '{version}'
        LIMIT 20
        """ if ecosystem else None,
    }


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
            if tool_name not in selected_tools:
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
        consider("github.commits", "question needs recent commit context")

    if wants_dependency:
        consider(
            "github.alerts",
            "GitHub Dependabot org alerts are disabled by default",
            required=github_alerts_enabled(),
        )
        consider("github.commits", "question needs dependency change context")
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
        if tool == "github.alerts" and not github_alerts_enabled():
            skipped_tools.append(
                {
                    "tool": tool,
                    "reason": "GitHub Dependabot org alerts are disabled by default",
                }
            )
            continue
        if tool == "slack.messages" and not req.slack_channel:
            skipped_tools.append({"tool": tool, "reason": "slack_channel was not provided"})
            continue
        if tool not in selected_tools:
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

    if evidence and package_risk["score"] >= 10:
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


SENSITIVE_REVIEW_KEYWORDS = (
    "oauth",
    "auth",
    "authentication",
    "authorization",
    "token",
    "secret",
    "password",
    "permission",
    "admin",
    "iam",
    "terraform",
    ".env",
)

DEPENDENCY_REVIEW_KEYWORDS = (
    "dependency",
    "dependencies",
    "package-lock",
    "pnpm-lock",
    "yarn.lock",
    "lockfile",
)


def matched_review_keywords(text: str, include_dependency_words: bool) -> list[str]:
    lowered = text.lower()
    keywords = list(SENSITIVE_REVIEW_KEYWORDS)
    if include_dependency_words:
        keywords.extend(DEPENDENCY_REVIEW_KEYWORDS)

    matches: list[str] = []
    for keyword in keywords:
        if keyword == ".env":
            matched = keyword in lowered
        elif any(char in keyword for char in ".-"):
            matched = keyword in lowered
        else:
            matched = bool(re.search(rf"\b{re.escape(keyword)}\b", lowered))
        if matched:
            matches.append(keyword)
    return matches


def pull_request_state(row: dict) -> str:
    state = str(row.get("state") or "").lower()
    if state == "open":
        return "open"
    if row.get("merged_at"):
        return "merged"
    if state == "closed":
        return "closed"
    return "unknown"


def build_review_signals(
    req: AgentInvestigationReq,
    steps: list[dict[str, object]],
) -> list[dict[str, object]]:
    by_name = {str(step["name"]): step for step in steps}
    pull_rows = first_rows(by_name.get("github_recent_pulls", {}), limit=20)
    include_dependency_words = bool(req.package_name and req.package_version)

    matched_pulls = []
    for row in pull_rows:
        text = f"{row.get('title', '')} {row.get('body', '')} {row.get('label_names', '')}"
        matches = matched_review_keywords(text, include_dependency_words)
        if matches:
            matched_pulls.append((row, matches, pull_request_state(row)))

    signals = []

    osv_step = step_by_name(steps, "osv_package_vulnerabilities")
    if osv_step and osv_step.get("ok"):
        rows = osv_step.get("rows")
        if isinstance(rows, list) and not rows and req.package_name:
            signals.append({
                "type": "clean_bill_of_health",
                "title": f"Dependency Deep Scan Passed: No confirmed vulnerabilities found for {req.package_name}@{req.package_version}.",
                "severity": "informational",
                "score": 0,
                "evidence": [
                    {
                        "source": "osv.query_by_version",
                        "text": "The target dependency package was scanned against OSV and deps.dev, and no vulnerabilities were found. This package appears to be safe.",
                        "url": None
                    }
                ],
                "recommendation": "No action required. The package passed the deep scan."
            })

    if matched_pulls:
        matched_pulls.sort(key=lambda item: (item[2] == "merged", len(item[1])), reverse=True)
        merged_count = sum(1 for _, _, state in matched_pulls if state == "merged")
        open_count = sum(1 for _, _, state in matched_pulls if state == "open")
        signal_score = min(10 + len(matched_pulls) * 3, 25)
        title_parts = []
        if merged_count:
            title_parts.append(f"{merged_count} merged")
        if open_count:
            title_parts.append(f"{open_count} open")
        title_prefix = " and ".join(title_parts) or str(len(matched_pulls))

        signals.append(
            {
                "type": "change_review_signal",
                "title": f"{title_prefix} pull request(s) mention security-sensitive terms",
                "severity": "informational",
                "score": signal_score,
                "evidence": [
                    {
                        "source": "github.pulls",
                        "text": (
                            f"PR #{row.get('number')} [{state}]: {row.get('title')} "
                            f"(matched: {', '.join(matches)})"
                        ),
                        "url": row.get("html_url") or row.get("url"),
                    }
                    for row, matches, state in matched_pulls[:5]
                ],
                "recommendation": (
                    "Review these PRs for context. This signal does not count as confirmed vulnerability evidence."
                ),
            }
        )

    for step in steps:
        if step.get("is_dynamic") and step.get("ok") and step.get("rows"):
            rows = step.get("rows")
            if not isinstance(rows, list) or not rows:
                continue
                
            def format_row(r):
                parts = []
                for k, v in r.items():
                    if v is None or k in ("url", "html_url"):
                        continue
                    val_str = str(v)
                    if val_str.startswith("{"):
                        try:
                            import json
                            parsed = json.loads(val_str)
                            if isinstance(parsed, dict):
                                if "login" in parsed:
                                    val_str = parsed["login"]
                                elif "name" in parsed:
                                    val_str = parsed["name"]
                                else:
                                    val_str = "{...}"
                        except Exception:
                            pass
                    if len(val_str) > 50:
                        val_str = val_str[:47] + "..."
                    parts.append(f"{k}: {val_str}")
                txt = " | ".join(parts)
                return txt[:200] + "..." if len(txt) > 200 else txt
                
            signals.append({
                "type": "dynamic_investigation",
                "title": f"Dynamic Query: {step.get('purpose', 'Ad-hoc investigation')}",
                "severity": "informational",
                "score": 15,
                "evidence": [
                    {
                        "source": "llm.dynamic_sql",
                        "text": format_row(row),
                        "url": row.get("html_url") or row.get("url") or None,
                    }
                    for row in rows[:5]
                ],
                "recommendation": "Review these LLM-generated dynamic SQL query results for anomalies."
            })

    return signals


def build_evidence_graph(
    req: AgentInvestigationReq,
    findings: list[dict[str, object]],
) -> dict[str, list[dict[str, object]]]:
    nodes: dict[str, dict[str, object]] = {}
    edges: list[dict[str, object]] = []

    # Narrative-driven causal graph construction. A package node is only present
    # when the repo-first extraction phase found a concrete target.
    package_id = None
    if req.package_name:
        package_label = (
            f"{req.package_name}@{req.package_version}"
            if req.package_version
            else str(req.package_name)
        )
        package_id = f"pkg:{req.package_ecosystem or 'unknown'}:{req.package_name}:{req.package_version or 'unknown'}"
        nodes[package_id] = {
            "id": package_id,
            "type": "package",
            "label": package_label,
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
            if package_id:
                edges.append({"from": src_id, "to": package_id, "type": "introduced"})
            
        # 2. Package -> Vulnerabilities
        for v_id in vuln_nodes:
            if package_id:
                edges.append({"from": package_id, "to": v_id, "type": "matched"})
            
        # 3. Vulnerabilities -> Other Evidence
        # If no vuln, Package -> Other Evidence
        for ev_id in other_evidence:
            if vuln_nodes:
                for v_id in vuln_nodes:
                    edges.append({"from": v_id, "to": ev_id, "type": "documented_by"})
            elif package_id:
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
            elif package_id:
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
            if package_id:
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


def build_assessment_answer(
    finding_count: int,
    review_signal_count: int,
    target_text: str,
) -> str:
    target_suffix = f" Target: {target_text}."
    if finding_count:
        if review_signal_count:
            return (
                f"HarborGuard found {finding_count} confirmed security or compliance "
                f"finding(s) and {review_signal_count} review signal(s).{target_suffix}"
            )
        return (
            f"HarborGuard found {finding_count} confirmed security or compliance "
            f"finding(s).{target_suffix}"
        )
    if review_signal_count:
        return (
            "HarborGuard found no confirmed vulnerability evidence, but found "
            f"{review_signal_count} PR review signal(s).{target_suffix}"
        )
    return (
        "HarborGuard did not find high-confidence risk evidence in the configured "
        f"sources.{target_suffix}"
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
    policy_query = sql_string(req.policy_query)

    github_recent_pulls_sql = f"""
    SELECT number, title, body, state, user__login, created_at, updated_at, merged_at, html_url, url
    FROM github.pulls
    WHERE owner = '{owner}'
      AND repo = '{repo}'
      AND state = 'all'
      AND sort = 'updated'
      AND direction = 'desc'
    LIMIT 8
    """
    github_recent_commits_sql = f"""
    SELECT sha, commit__message, commit__author__date, commit__committer__date, html_url
    FROM github.commits
    WHERE owner = '{owner}'
      AND repo = '{repo}'
    LIMIT 12
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

    steps: list[dict[str, object]] = []

    # Phase 1: always discover repository context first. This is what lets the
    # agent infer the package target from the repo instead of relying on defaults.
    github_timeout = github_query_timeout()
    if tool_available(capabilities, "github.pulls"):
        github_pulls_step = query_step_with_timeout(
            "github_recent_pulls",
            github_recent_pulls_sql,
            github_timeout,
        )
    else:
        github_pulls_step = skipped_step(
            "github_recent_pulls",
            "github.pulls is not available in Coral metadata",
        )
    steps.append(github_pulls_step)

    if tool_available(capabilities, "github.commits"):
        github_commits_step = query_step_with_timeout(
            "github_recent_commits",
            github_recent_commits_sql,
            github_timeout,
        )
    else:
        github_commits_step = skipped_step(
            "github_recent_commits",
            "github.commits is not available in Coral metadata",
        )
    steps.append(github_commits_step)

    if github_alerts_enabled() and tool_available(capabilities, "github.alerts"):
        github_alerts_step = query_step_with_timeout(
            "github_dependabot_alerts",
            github_dependabot_alerts_sql,
            github_timeout,
        )
    else:
        github_alerts_step = skipped_step(
            "github_dependabot_alerts",
            "GitHub Dependabot org alerts are disabled by default because the org endpoint often returns 404 without matching permissions",
        )
    steps.append(github_alerts_step)

    # Phase 2: extract target package/version from PRs and alerts.
    package_target, extraction = extract_package_target(
        req,
        github_pulls_step,
        github_alerts_step,
        github_commits_step,
    )
    steps.append(package_extraction_step(extraction))

    deep_scan_target = (
        package_target
        if package_target
        and package_target.get("package_name")
        and package_target.get("version")
        and package_target.get("system")
        else None
    )

    analysis_req = req
    if deep_scan_target:
        analysis_req = req.model_copy(
            update={
                "package_name": deep_scan_target.get("package_name"),
                "package_version": deep_scan_target.get("version"),
                "package_system": deep_scan_target.get("system"),
                "package_ecosystem": deep_scan_target.get("ecosystem"),
            }
        )
    selected_package_text = (
        f"{deep_scan_target.get('package_name')}@{deep_scan_target.get('version')}"
        if deep_scan_target
        else "none"
    )
    logger.info("agent.package_target.selected target=%s", selected_package_text)

    # Phase 3: run deep package analysis only after a real target is known.
    if deep_scan_target:
        package_sql = build_package_sql(deep_scan_target)
        if package_sql["deps_version"] and tool_available(capabilities, "deps_dev.versions"):
            steps.append(query_step("deps_dev_package_version", package_sql["deps_version"]))
        else:
            steps.append(
                skipped_step(
                    "deps_dev_package_version",
                    "package target did not include enough deps.dev version inputs or tool is unavailable",
                )
            )

        if package_sql["deps_dependencies"] and tool_available(capabilities, "deps_dev.dependencies"):
            steps.append(query_step("deps_dev_dependencies", package_sql["deps_dependencies"]))
        else:
            steps.append(
                skipped_step(
                    "deps_dev_dependencies",
                    "package target did not include enough deps.dev dependency inputs or tool is unavailable",
                )
            )

        if package_sql["osv_version"] and tool_available(capabilities, "osv.query_by_version"):
            steps.append(query_step("osv_package_vulnerabilities", package_sql["osv_version"]))
        else:
            steps.append(
                skipped_step(
                    "osv_package_vulnerabilities",
                    "OSV exact version lookup skipped because package, ecosystem, or version was missing",
                )
            )
    else:
        reason = (
            "dependency package was discovered but no exact version was found"
            if package_target
            else "no dependency package target was discovered from repository context"
        )
        steps.append(skipped_step("deps_dev_package_version", reason))
        steps.append(skipped_step("deps_dev_dependencies", reason))
        steps.append(skipped_step("osv_package_vulnerabilities", reason))

    deps_version_step = step_by_name(steps, "deps_dev_package_version")
    deps_version_rows = first_rows(deps_version_step or {}, limit=1)
    deps_version = deps_version_rows[0] if deps_version_rows else None
    advisory_keys = advisory_keys_from_version(deps_version)
    advisories_sql = deps_dev_advisories_sql(advisory_keys)
    if deep_scan_target and tool_available(capabilities, "deps_dev.advisories"):
        if advisories_sql:
            advisories_step = query_step("deps_dev_advisories", advisories_sql)
        else:
            advisories_step = skipped_step(
                "deps_dev_advisories",
                "deps.dev version metadata did not include advisory keys",
            )
    else:
        advisories_step = skipped_step(
            "deps_dev_advisories",
            "no exact package target was available for advisory expansion",
        )

    steps.append(advisories_step)

    # Phase 4: run selected contextual enrichments around the repo/package.
    if "github.search_code" in selected_tools and tool_available(capabilities, "github.search_code"):
        steps.append(query_step("github_secret_file_search", github_secret_file_search_sql))
    else:
        skipped = next(
            (
                item
                for item in plan["skipped_tools"]
                if item["tool"] == "github.search_code"
            ),
            {"reason": "planner did not select this tool"},
        )
        steps.append(skipped_step("github_secret_file_search", skipped["reason"]))

    if "notion.search" in selected_tools and tool_available(capabilities, "notion.search"):
        steps.append(query_step("notion_policy_context", notion_policy_context_sql))
    else:
        skipped = next(
            (
                item
                for item in plan["skipped_tools"]
                if item["tool"] == "notion.search"
            ),
            {"reason": "planner did not select this tool"},
        )
        steps.append(skipped_step("notion_policy_context", skipped["reason"]))

    if req.slack_channel:
        slack_channel = sql_string(req.slack_channel)
        package_search_term = sql_string(str(package_target.get("package_name") or "")) if package_target else ""
        slack_security_discussion_sql = f"""
        SELECT user_id, text, ts, thread_ts, reply_count
        FROM slack.messages(channel => '{slack_channel}')
        WHERE text ILIKE '%security%'
           OR text ILIKE '%dependency%'
           OR text ILIKE '%secret%'
           OR text ILIKE '%access%'
           {f"OR text ILIKE '%{package_search_term}%'" if package_search_term else ""}
        LIMIT 20
        """
        if "slack.messages" in selected_tools and tool_available(capabilities, "slack.messages"):
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

    # Phase 5: Dynamic LLM Tool Calls (Multi-Turn)
    import json
    payload = build_dynamic_investigation_payload(req, capabilities)
    if payload:
        turn = 0
        while turn < 3:
            turn += 1
            started_at_t = time.perf_counter()
            try:
                tool_calls, raw_message = openrouter_chat_tools(payload, started_at_t, f"llm.dynamic_turn_{turn}")
            except Exception as e:
                logger.warning("llm.dynamic_turn.error turn=%s error=%s", turn, e)
                break
                
            if not tool_calls:
                break
                
            payload["messages"].append(raw_message)
            
            for i, call in enumerate(tool_calls, start=1):
                tool_name = call.get("function", {}).get("name")
                call_id = call.get("id")
                if not tool_name:
                    continue
                    
                args_str = call.get("function", {}).get("arguments", "{}")
                try:
                    args = json.loads(args_str)
                except Exception:
                    args = {}
                    
                original_name = tool_name.replace("_", ".", 1)
                tool_info = capabilities.get("tools", {}).get(original_name, {})
                kind = tool_info.get("kind", "table")
                
                if kind in ("function", "table_function"):
                    args_list = []
                    for k, v in args.items():
                        args_list.append(f"{k} => '{sql_string(str(v))}'")
                    args_str_sql = ", ".join(args_list)
                    sql = f"SELECT * FROM {original_name}({args_str_sql}) LIMIT 10"
                else:
                    filters = []
                    for k, v in args.items():
                        filters.append(f"{k} = '{sql_string(str(v))}'")
                    where_clause = f" WHERE {' AND '.join(filters)}" if filters else ""
                    sql = f"SELECT * FROM {original_name}{where_clause} LIMIT 10"

                purpose = f"Dynamic query for {original_name}"
                step_name = f"dynamic_tool_{turn}_{i}"
                try:
                    started_at_q = time.perf_counter()
                    logger.info("agent.dynamic_tool.start name=%s sql=%s", step_name, compact_sql(sql))
                    result = coral.query(sql)
                    duration_ms = elapsed_ms(started_at_q)
                    steps.append({
                        "name": step_name,
                        "ok": True,
                        "rows": result.rows,
                        "sql": sql,
                        "purpose": purpose,
                        "error": None,
                        "duration_ms": duration_ms,
                        "is_dynamic": True,
                    })
                    payload["messages"].append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": json.dumps(result.rows[:10])
                    })
                    logger.info("agent.dynamic_tool.ok name=%s duration_ms=%s rows=%s", step_name, duration_ms, len(result.rows))
                except Exception as error:
                    logger.warning("agent.dynamic_tool.error name=%s error=%s", step_name, error)
                    steps.append({
                        "name": step_name,
                        "ok": False,
                        "rows": [],
                        "sql": sql,
                        "purpose": purpose,
                        "error": str(error),
                        "duration_ms": elapsed_ms(started_at_q),
                        "is_dynamic": True,
                    })
                    payload["messages"].append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": json.dumps({"error": str(error)})
                    })

    findings = build_agent_findings(analysis_req, steps)
    review_signals = build_review_signals(analysis_req, steps)
    evidence_graph = build_evidence_graph(analysis_req, findings)
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
        "Repository context discovery ran before dependency scanning.",
        *[str(item) for item in extraction.get("trace", [])],
        f"Executed {len([step for step in steps if not step.get('skipped')])} selected investigation step(s).",
        f"Generated {len(findings)} confirmed finding(s) and {len(review_signals)} review signal(s).",
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
        "answer": build_assessment_answer(
            len(findings),
            len(review_signals),
            selected_package_text,
        ),
        "target_package": deep_scan_target,
        "package_candidate": package_target,
        "package_extraction": extraction,
        "risk_level": risk_level,
        "score": max_score,
        "findings": findings,
        "review_signals": review_signals,
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
