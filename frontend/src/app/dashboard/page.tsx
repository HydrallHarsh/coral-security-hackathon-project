"use client";

import { Suspense, useEffect, useState, useRef } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useSearchParams, useRouter } from "next/navigation";
import { EvidenceGraph } from "../components/EvidenceGraph";
import { LoadingQuipDisplay } from "../components/LoadingQuipDisplay";
import { SchemaPanel } from "../components/SchemaPanel";
import {
  MODE_META,
  detectMode,
  getCompletionQuip,
  getLoadingQuip,
  DEFAULT_LOADING_QUIP,
  type LoadingQuipContext,
} from "../utils/flavor";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000";

/* ─── Types ─── */
type SourceCapabilities = { available?: boolean; configured?: boolean; tools?: string[] };
type ToolCapability = { available?: boolean; purpose?: string; source?: string; capabilities?: string[] };
type CapabilitiesResponse = {
  capabilities?: {
    discovery_backend?: string;
    summary?: Record<string, unknown>;
    sources?: Record<string, SourceCapabilities>;
    tools?: Record<string, ToolCapability>;
  };
};
type LiveQuery = { id: number; name: string; sql: string; rows: number; duration_ms: number; preview: any[] };
type Step = { name: string; ok?: boolean; skipped?: boolean; rows?: unknown[]; error?: string | null; reason?: string; sql?: string };
type Finding = {
  type: string; title: string; severity: string; score: number; recommendation: string;
  graph_node_id?: string;
  evidence?: Array<{ source?: string; text?: string; url?: string | null }>;
  policy_context?: Array<{ source?: string; text?: string; url?: string | null }>;
  discussion_context?: Array<{ source?: string; text?: string }>;
};
type Planner = {
  planner_source?: string; model?: string; fallback_reason?: string;
  selected_tools?: string[]; skipped_tools?: Array<{ tool: string; reason: string }>; intent?: unknown;
};
type GraphNode = { id: string; type: string; label: string; severity?: string; score?: number; source?: string; url?: string | null };
type GraphEdge = { from: string; to: string; type: string };
type EvidenceGraphData = { nodes?: GraphNode[]; edges?: GraphEdge[] };
type Verdict = { verdict: "escalate" | "monitor" | "close"; confidence: number; headline: string; because: string[]; next_action: string | null };
type InvestigationResponse = {
  verdict?: Verdict;
  answer?: string; risk_level?: string; score?: number; findings?: Finding[];
  review_signals?: Finding[];
  planner?: Planner; reasoning_trace?: string[]; evidence_graph?: EvidenceGraphData;
  steps?: Step[]; capability_summary?: Record<string, unknown>;
  target_package?: {
    package_name?: string;
    version?: string | null;
    ecosystem?: string | null;
    system?: string | null;
    confidence?: number;
    source?: string;
    reason?: string;
  } | null;
  package_extraction?: { candidates?: unknown[]; trace?: string[] };
  source_status?: { ok?: boolean; failed_steps?: Array<{ name: string; error?: string | null }> };
};
type InvestigationForm = {
  question: string; owner: string; repo: string; org: string; slack_channel: string;
  policy_query: string; package_system: string; package_ecosystem: string;
  package_name: string; package_version: string;
};

/* ─── Constants ─── */
const initialForm: InvestigationForm = {
  question: "Did dependency upgrades introduce risk and require policy review?",
  owner: "withcoral", repo: "coral", org: "withcoral", slack_channel: "",
  policy_query: "dependency security review secrets access control",
  package_system: "", package_ecosystem: "", package_name: "", package_version: "",
};

const CASE_PRESETS = [
  { id: "dep", label: "Dependency Risk", desc: "Audit upgrades for CVEs & supply chain threats", question: "Did dependency upgrades introduce risk and require policy review?" },
  { id: "policy", label: "Policy Violation", desc: "Check changes against org security policies", question: "Are there any security policy violations in recent code changes?" },
  { id: "secrets", label: "Secrets Exposure", desc: "Scan for leaked credentials & API keys", question: "Have any secrets or credentials been exposed in recent commits?" },
  { id: "release", label: "Release Safety", desc: "Validate release readiness & risk posture", question: "Is the latest release safe to deploy to production?" },
];

const LOADING_STEPS = [
  "Connecting to intelligence sources",
  "Analyzing dependency graph",
  "Scanning vulnerability databases",
  "Cross-referencing org policies",
  "Correlating evidence chains",
  "Generating risk assessment",
];

const NODE_COLORS: Record<string, string> = {
  vulnerability: "#ef4444", advisory: "#ef4444", github_alert: "#ef4444",
  package: "#f5b731", finding: "#f0734a",
  pull_request: "#60a5fa", commit: "#60a5fa", code_search_result: "#60a5fa",
  policy: "#3dd68c", discussion: "#8b5cf6", evidence: "#9e99ab",
};

const NODE_ICONS: Record<string, string> = {
  package: "📦", vulnerability: "🛡️", advisory: "🛡️", github_alert: "⚠️",
  finding: "🔍", pull_request: "↗", commit: "●", code_search_result: "🔎",
  policy: "📋", discussion: "💬", evidence: "📄",
};

/* ═══════════════════════════════════════════════
   MAIN COMPONENT
   ═══════════════════════════════════════════════ */

export default function Dashboard() {
  return (
    <Suspense fallback={<div className="loadingScreen"><h2 className="loadingTitle">Loading Dashboard...</h2></div>}>
      <DashboardContent />
    </Suspense>
  );
}

function DashboardContent() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const [capabilities, setCapabilities] = useState<CapabilitiesResponse | null>(null);
  const [result, setResult] = useState<InvestigationResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSchemaOpen, setIsSchemaOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<"trace" | "execution" | "planner" | "sql" | "raw">("trace");
  const [liveSteps, setLiveSteps] = useState<string[]>([]);
  const [liveQueries, setLiveQueries] = useState<LiveQuery[]>([]);
  const [loadingQuip, setLoadingQuip] = useState(DEFAULT_LOADING_QUIP);
  const [completionQuip, setCompletionQuip] = useState<string | null>(null);
  const hasRun = useRef(false);

  // Extract query parameters for the payload
  const question = searchParams.get("question") || "";
  const owner = searchParams.get("owner") || "";
  const repo = searchParams.get("repo") || "";
  const org = searchParams.get("org") || "";
  const slack_channel = searchParams.get("slack_channel") || "";
  const policy_query = searchParams.get("policy_query") || "";
  const package_system = searchParams.get("package_system") || "";
  const package_ecosystem = searchParams.get("package_ecosystem") || "";
  const package_name = searchParams.get("package_name") || "";
  const package_version = searchParams.get("package_version") || "";

  const investigationMode = detectMode(question);
  const modeMeta = MODE_META[investigationMode];

  async function refreshCapabilities() {
    try {
      const r = await fetch(`${API_BASE}/agent/capabilities`);
      if (!r.ok) throw new Error(`${r.status}`);
      setCapabilities(await r.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load capabilities");
    }
  }

  useEffect(() => { void refreshCapabilities(); }, []);

  const latestQueryName =
    liveQueries.length > 0 ? liveQueries[liveQueries.length - 1]?.name : undefined;
  const latestProgress =
    liveSteps.length > 0 ? liveSteps[liveSteps.length - 1] : undefined;

  const buildLoadingQuipContext = (overrides?: Partial<LoadingQuipContext>) => ({
    mode: investigationMode,
    queryCount: liveQueries.length,
    stepCount: liveSteps.length,
    latestQueryName,
    latestProgress,
    owner,
    repo,
    ...overrides,
  });

  /* Pick a fun quip only after mount — pickRandom() must not run during SSR. */
  useEffect(() => {
    setLoadingQuip(
      getLoadingQuip(buildLoadingQuipContext({ queryCount: 0, stepCount: 0 })),
    );
  }, []);

  useEffect(() => {
    if (!loading) return;
    setLoadingQuip(getLoadingQuip(buildLoadingQuipContext()));
    const id = setInterval(
      () => setLoadingQuip(getLoadingQuip(buildLoadingQuipContext())),
      4500,
    );
    return () => clearInterval(id);
  }, [
    loading,
    liveQueries.length,
    liveSteps.length,
    latestQueryName,
    latestProgress,
    investigationMode,
    owner,
    repo,
  ]);

  useEffect(() => {
    if (hasRun.current) return;
    if (!question || !owner || !repo) {
      router.push("/");
      return;
    }
    hasRun.current = true;
    void runInvestigation();
  }, [question, owner, repo, router]);

  const sources = capabilities?.capabilities?.sources ?? {};

  async function runInvestigation() {
    setLoading(true);
    setError(null);
    setResult(null);
    setLiveSteps(["Initializing investigation..."]);
    setLiveQueries([]);
    const payload = {
      question, owner, repo, org: org || owner, slack_channel: slack_channel || null,
      policy_query, package_system: package_system || null,
      package_ecosystem: package_ecosystem || null,
      package_name: package_name || null, package_version: package_version || null,
      days: 7,
    };
    try {
      const r = await fetch(`${API_BASE}/agent/investigate/stream`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!r.ok || !r.body) {
        const data = await r.json().catch(() => ({}));
        throw new Error(data.detail ?? `${r.status}`);
      }
      
      const reader = r.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let receivedComplete = false;

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.type === "progress") {
                setLiveSteps(prev => [...prev, data.message]);
              } else if (data.type === "query") {
                if (typeof data.name === "string" && data.name.startsWith("metadata_")) {
                  continue;
                }
                setLiveQueries(prev => [
                  ...prev,
                  { ...(data as Omit<LiveQuery, "id">), id: prev.length },
                ]);
              } else if (data.type === "complete") {
                setResult(data.data);
                setCompletionQuip(
                  getCompletionQuip(
                    data.data?.risk_level,
                    (data.data?.findings ?? []).length,
                  ),
                );
                setLoading(false);
                receivedComplete = true;
              } else if (data.type === "error") {
                setError(data.error);
                setLoading(false);
                receivedComplete = true;
              }
            } catch (e) {
              console.error("Parse error on chunk:", line, e);
            }
          }
        }
      }
      if (!receivedComplete) {
        setError("Investigation stream closed unexpectedly. Check backend logs.");
        setLoading(false);
      }
      void refreshCapabilities();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Investigation failed");
      setLoading(false);
    }
  }

  /* ─── PHASE: LOADING ─── */
  if (loading) {
    return (
      <div className="loadingScreen">
        <motion.div
          className="loadWrap"
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
        >
          <header className="loadHero">
            <div className="loadingRings">
              <div className="ring r1" />
              <div className="ring r2" />
              <div className="ring r3" />
            </div>
            <div className="loadHeroText">
              <span className={`modeBadge mode-${investigationMode}`}>
                {modeMeta.emoji} {modeMeta.label}
              </span>
              <h2 className="loadingTitle">Investigation in Progress</h2>
              <LoadingQuipDisplay text={loadingQuip} mode={investigationMode} />
              <p className="loadRepoTag">{owner}/{repo}</p>
            </div>
          </header>

          <section className="loadCard">
            <div className="loadSection">
              <div className="loadSectionHead">
                <span className="loadSectionLabel">Pipeline</span>
                <span className="loadBadge">{liveSteps.length}</span>
              </div>
              <div className="loadStepsScroll">
                {liveSteps.map((step, i) => (
                  <div
                    key={i}
                    className={`lStep ${i < liveSteps.length - 1 ? "done" : "active"}`}
                  >
                    <span className="lDot">{i < liveSteps.length - 1 ? "✓" : "●"}</span>
                    <span className="lStepText">{step}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="loadDivider" />

            <div className="loadSection loadSectionQueries">
              <div className="loadSectionHead">
                <span className="loadSectionLabel">Live queries</span>
                <span className="loadBadge">{liveQueries.length}</span>
              </div>
              <LiveQueriesFeed queries={liveQueries} />
            </div>
          </section>
        </motion.div>
      </div>
    );
  }

  /* ─── PHASE: RESULTS ─── */
  if (result) {
    const findings = result.findings ?? [];
    const reviewSignals = result.review_signals ?? [];
    const trace = result.reasoning_trace ?? [];
    const steps = result.steps ?? [];

    return (
      <motion.div className="workspace"
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }}>
        {/* ─── Top Bar ─── */}
        <header className="topBar">
          <div className="tbBrand">
            <strong className="tbLogo">HarborGuard</strong>
            <span className={`modeBadge mode-${investigationMode}`}>
              {modeMeta.emoji} {modeMeta.label}
            </span>
          </div>
          <div className="tbCenter">
            <span className="tbRepo">{owner}/{repo}</span>
            <span className="tbQ">{question}</span>
          </div>
          <div className="tbRight">
            <div className="tbSources">
              {/* Removed sources from top nav as requested */}
            </div>
            <button className="tbBtn" style={{ background: 'rgba(167, 139, 250, 0.1)', color: '#a78bfa', borderColor: 'rgba(167, 139, 250, 0.3)' }} onClick={() => setIsSchemaOpen(true)}>
              Coral Schema Intelligence
            </button>
            <button className="tbBtn" onClick={() => router.push("/")}>
              ← New Investigation
            </button>
          </div>
        </header>

        {error && <div className="wError">{error}</div>}

        {/* ─── Assessment ─── */}
        <section className="assessment">
          <div className="aBody">
            {result.verdict ? (
              <>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
                  <span style={{ 
                    padding: "2px 8px", borderRadius: "4px", fontSize: "0.75rem", fontWeight: 700, letterSpacing: "0.05em",
                    background: result.verdict.verdict === "escalate" ? "rgba(239,68,68,0.2)" : result.verdict.verdict === "monitor" ? "rgba(245,158,11,0.2)" : "rgba(16,185,129,0.2)",
                    color: result.verdict.verdict === "escalate" ? "#fca5a5" : result.verdict.verdict === "monitor" ? "#fcd34d" : "#6ee7b7",
                    border: `1px solid ${result.verdict.verdict === "escalate" ? "rgba(239,68,68,0.4)" : result.verdict.verdict === "monitor" ? "rgba(245,158,11,0.4)" : "rgba(16,185,129,0.4)"}`
                  }}>
                    {result.verdict.verdict.toUpperCase()}
                  </span>
                  <span className="aLabel" style={{ margin: 0 }}>Final Verdict</span>
                </div>
                <h2 className="aAnswer" style={{ color: "#fff", fontSize: "1.1rem", lineHeight: 1.4 }}>{result.verdict.headline}</h2>
                {result.verdict.because && result.verdict.because.length > 0 && (
                  <ul style={{ margin: "12px 0 16px 0", paddingLeft: "20px", color: "#a1a1aa", fontSize: "0.9rem", lineHeight: 1.5, display: "flex", flexDirection: "column", gap: "6px" }}>
                    {result.verdict.because.map((r, i) => <li key={i}>{r}</li>)}
                  </ul>
                )}
                {result.verdict.next_action && (
                  <div style={{ marginTop: "12px", padding: "12px", background: "rgba(255,255,255,0.03)", borderRadius: "6px", borderLeft: "3px solid #6366f1", fontSize: "0.9rem", color: "#e2e8f0" }}>
                    <strong style={{ color: "#818cf8", marginRight: "6px" }}>Next Action:</strong> {result.verdict.next_action}
                  </div>
                )}
              </>
            ) : (
              <>
                <span className="aLabel">Assessment</span>
                <h2 className="aAnswer">{result.answer}</h2>
              </>
            )}
            {result.target_package && (
              <div className="targetPill">
                <span>Target</span>
                <strong>
                  {result.target_package.package_name}
                  {result.target_package.version ? `@${result.target_package.version}` : ""}
                </strong>
                {result.target_package.source && <em>{result.target_package.source}</em>}
              </div>
            )}
          </div>
          <div className={`riskScore ${result.risk_level ?? "low"}`}>
            <span className="rsLevel">{result.risk_level ?? "low"}</span>
            <strong className="rsValue">{result.score ?? 0}</strong>
          </div>
        </section>

        {completionQuip && (
          <p className="completionQuip">{completionQuip}</p>
        )}

        {/* ─── Main Area ─── */}
        <div className="mainArea">
          <section className="graphPanel">
            <EvidenceGraph graph={result.evidence_graph} />
          </section>

          <aside className="feedPanel">
            <h3 className="secTitle">Findings <span className="badge">{findings.length}</span></h3>
            <div className="feedScroll">
              {findings.map((f, i) => (
                <FindingCard key={f.graph_node_id ?? f.title} finding={f} delay={i * 0.1} />
              ))}
              {findings.length === 0 && (
                <p className="feedEmpty">
                  No findings detected. {completionQuip ?? "The harbor is calm."}
                </p>
              )}
              {reviewSignals.length > 0 && (
                <>
                  <h3 className="secTitle reviewTitle">Review Signals <span className="badge">{reviewSignals.length}</span></h3>
                  {reviewSignals.map((f, i) => (
                    <FindingCard key={`signal-${f.graph_node_id ?? f.title}`} finding={f} delay={(i + findings.length) * 0.1} />
                  ))}
                </>
              )}
            </div>
          </aside>
        </div>

        {/* ─── Bottom Dock ─── */}
        <section className="dock">
          {/* Left: tabbed debug panel */}
          <div className="dockLeft">
            <div className="dockTabs">
              {([
                { id: "trace",     label: "Reasoning Trace",  count: trace.length },
                { id: "execution", label: "Execution Steps",   count: steps.length },
                { id: "planner",   label: "Planner",           count: 0 },
                { id: "sql",       label: "SQL Queries",       count: steps.filter(s => s.sql).length },
                { id: "raw",       label: "Raw Results",       count: 0 },
              ] as const).map(t => (
                <button
                  key={t.id}
                  className={`dTab ${activeTab === t.id ? "active" : ""}`}
                  onClick={() => setActiveTab(t.id)}
                >
                  {t.label}
                  {t.count > 0 && <span className="tBadge">{t.count}</span>}
                </button>
              ))}
            </div>
            <div className="dockBody">
              {activeTab === "trace" && (
                <ol className="traceList">
                  {trace.map((item, i) => (
                    <li key={i} className="traceItem" style={{ animationDelay: `${i * 0.04}s` }}>{item}</li>
                  ))}
                  {trace.length === 0 && <p className="dockEmpty">No reasoning trace available.</p>}
                </ol>
              )}
              {activeTab === "execution" && (
                <div className="execList">
                  {steps.map(s => <StepRow key={s.name} step={s} />)}
                </div>
              )}
              {activeTab === "planner" && (
                <div className="planView">
                  <div className="planMeta">
                    <span>Source: <strong>{result.planner?.planner_source ?? "unknown"}</strong></span>
                    {result.planner?.model && <span>Model: <strong>{result.planner.model}</strong></span>}
                  </div>
                  {result.planner?.fallback_reason && <p className="planWarn">{result.planner.fallback_reason}</p>}
                  <div className="planSection">
                    <span className="planLabel">Selected Tools</span>
                    <div className="chipRow">
                      {(result.planner?.selected_tools ?? []).map(t => <span key={t} className="chip">{t}</span>)}
                      {(result.planner?.selected_tools ?? []).length === 0 && <span className="dockEmpty">None</span>}
                    </div>
                  </div>
                  {(result.planner?.skipped_tools ?? []).length > 0 && (
                    <div className="planSection">
                      <span className="planLabel">Skipped</span>
                      {result.planner!.skipped_tools!.map(s => (
                        <div key={s.tool} className="skipRow"><strong>{s.tool}</strong><span>{s.reason}</span></div>
                      ))}
                    </div>
                  )}
                </div>
              )}
              {activeTab === "sql" && (
                <div className="execList">
                  {steps.filter(s => s.sql).map(s => (
                    <div key={s.name} style={{ marginBottom: 16 }}>
                      <span className="execDetailLabel">{s.name}</span>
                      <pre className="execPre" style={{ marginBottom: "6px" }}>{s.sql}</pre>
                      {s.rows && s.rows.length > 0 && (
                        <details style={{ background: "rgba(0,0,0,0.2)", borderRadius: "4px" }}>
                          <summary style={{ padding: "6px 10px", fontSize: "0.75rem", color: "#a1a1aa", cursor: "pointer" }}>
                            View Results ({s.rows.length} rows)
                          </summary>
                          <pre className="execPre" style={{ margin: 0, padding: "10px", maxHeight: "300px", overflow: "auto", fontSize: "0.7rem", color: "#e2e8f0" }}>
                            {JSON.stringify(s.rows, null, 2)}
                          </pre>
                        </details>
                      )}
                      {(!s.rows || s.rows.length === 0) && !s.error && (
                        <div style={{ fontSize: "0.75rem", color: "#64748b", padding: "4px 0" }}>0 rows returned</div>
                      )}
                      {s.error && (
                        <div style={{ fontSize: "0.75rem", color: "#ef4444", padding: "4px 0" }}>Error: {s.error}</div>
                      )}
                    </div>
                  ))}
                  {steps.filter(s => s.sql).length === 0 && <p className="dockEmpty">No SQL queries recorded.</p>}
                </div>
              )}
              {activeTab === "raw" && (
                <pre className="execPre" style={{ fontSize: "0.68rem" }}>
                  {JSON.stringify(result, null, 2).slice(0, 4000)}
                </pre>
              )}
            </div>
          </div>

          {/* Right: Source Status */}
          <div className="dockRight">
            <div className="dockRightTitle">
              Source Status
              <span className="badge">{Object.keys(sources).length}</span>
            </div>
            <div className="srcStatusList">
              {Object.entries(sources).map(([name, s]) => {
                let logoPath = "https://api.iconify.design/lucide:file-text.svg?color=%2394a3b8";
                if (name.includes("github")) logoPath = "/logos/github.png";
                else if (name.includes("slack")) logoPath = "/logos/slack.png";
                else if (name.includes("notion")) logoPath = "/logos/notion.png";
                else if (name.includes("osv")) logoPath = "/logos/osv.png";
                else if (name.includes("deps")) logoPath = "https://api.iconify.design/logos:npm-icon.svg";

                const isOn = s.available;
                const toolCount = (s.tools ?? []).length;
                return (
                  <div key={name} className="srcStatusRow">
                    <div className="srcStatusIcon" style={{ background: 'transparent', padding: 0 }}>
                      <img src={logoPath} alt={name} style={{ width: 20, height: 20, objectFit: 'contain', borderRadius: name.includes("osv") ? '50%' : 4 }} />
                    </div>
                    <div className="srcStatusBody">
                      <span className="srcStatusName">{name.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</span>
                      {toolCount > 0 && <span className="srcStatusMeta">{toolCount} tool{toolCount !== 1 ? "s" : ""} available</span>}
                    </div>
                    <span className={`srcStatusBadge ${isOn ? "ok" : "off"}`}>
                      {isOn ? "Connected" : "Offline"}
                    </span>
                  </div>
                );
              })}
              {Object.keys(sources).length === 0 && (
                <p className="dockEmpty">No source data.</p>
              )}
            </div>
          </div>
        </section>

        <SchemaPanel isOpen={isSchemaOpen} onClose={() => setIsSchemaOpen(false)} />
      </motion.div>
    );
  }

  // The briefing phase has been moved to the landing page.
  return null;
}

/* ═══════════════════════════════════════════════
   FINDING CARD — Proper structured display
   ═══════════════════════════════════════════════ */
function FindingCard({ finding: f, delay }: { finding: Finding; delay: number }) {
  const [expanded, setExpanded] = useState(false);
  const allEvidence = [...(f.evidence ?? []), ...(f.policy_context ?? []), ...(f.discussion_context ?? [])];
  const hasDetails = allEvidence.length > 0;

  return (
    <motion.article 
      className="fCard"
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.1 + delay, type: "spring", stiffness: 200, damping: 20 }}>
      <div className="fHead">
        <div className="fLeft">
          <span className="fType">{f.type.replace(/_/g, " ")}</span>
          <h4 className="fTitle">{f.title}</h4>
        </div>
        <div className={`fScore ${f.severity}`}>{f.score}</div>
      </div>
      <p className="fRec">{f.recommendation}</p>

      {hasDetails && (
        <div className="fEvidence">
          <button className="fToggle" onClick={() => setExpanded(!expanded)}>
            {expanded ? "Hide" : "Show"} evidence ({allEvidence.length})
            <span className="fToggleIcon">{expanded ? "▾" : "▸"}</span>
          </button>
          {expanded && (
            <div className="fEvList">
              {(f.evidence ?? []).map((ev, i) => (
                <div key={`ev-${i}`} className="fEvItem">
                  <span className="fEvSource">{ev.source}</span>
                  <span className="fEvText">{cleanEvidenceText(ev.text ?? "")}</span>
                  {ev.url && <a href={ev.url} target="_blank" rel="noreferrer" className="fEvLink">View ↗</a>}
                </div>
              ))}
              {(f.policy_context ?? []).map((p, i) => (
                <div key={`pol-${i}`} className="fEvItem policy">
                  <span className="fEvSource">policy</span>
                  <span className="fEvText">{cleanEvidenceText(p.text ?? "")}</span>
                  {p.url && <a href={p.url} target="_blank" rel="noreferrer" className="fEvLink">View ↗</a>}
                </div>
              ))}
              {(f.discussion_context ?? []).map((d, i) => (
                <div key={`disc-${i}`} className="fEvItem discussion">
                  <span className="fEvSource">discussion</span>
                  <span className="fEvText">{cleanEvidenceText(d.text ?? "")}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </motion.article>
  );
}

/** Clean evidence text: truncate JSON blobs, keep readable parts */
function cleanEvidenceText(text: string): string {
  if (!text) return "";
  // If it's a JSON blob, try to make it readable
  if (text.startsWith("[{") || text.startsWith("{")) {
    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed)) {
        return parsed.map((item: Record<string, string>) => {
          const id = item.id || item.name || "";
          const summary = item.summary || item.details || item.title || "";
          return [id, summary].filter(Boolean).join(": ");
        }).slice(0, 3).join(" · ");
      }
      if (typeof parsed === "object") {
        return parsed.id || parsed.summary || parsed.title || text.slice(0, 100);
      }
    } catch { /* not JSON, use as-is */ }
  }
  // Truncate very long text
  if (text.length > 200) return text.slice(0, 197) + "…";
  return text;
}

/* ═══════════════════════════════════════════════
   LIVE QUERY FEED — loading screen
   ═══════════════════════════════════════════════ */
function LiveQueriesFeed({ queries }: { queries: LiveQuery[] }) {
  const feedRef = useRef<HTMLDivElement>(null);
  const stickToBottom = useRef(true);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [showJumpLatest, setShowJumpLatest] = useState(false);

  useEffect(() => {
    if (queries.length === 0) return;
    setExpandedId(queries[queries.length - 1].id);
  }, [queries.length]);

  useEffect(() => {
    const el = feedRef.current;
    if (!el || !stickToBottom.current) return;
    requestAnimationFrame(() => {
      el.scrollTop = el.scrollHeight;
    });
  }, [queries]);

  function handleScroll() {
    const el = feedRef.current;
    if (!el) return;
    const distFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    stickToBottom.current = distFromBottom < 80;
    setShowJumpLatest(distFromBottom >= 80);
  }

  function jumpToLatest() {
    const el = feedRef.current;
    if (!el) return;
    stickToBottom.current = true;
    setShowJumpLatest(false);
    el.scrollTop = el.scrollHeight;
    if (queries.length > 0) {
      setExpandedId(queries[queries.length - 1].id);
    }
  }

  if (queries.length === 0) {
    return <p className="loadQueriesEmpty">Waiting for first Coral query…</p>;
  }

  return (
    <div className="loadQueriesWrap">
      {showJumpLatest && (
        <button type="button" className="loadJumpLatest" onClick={jumpToLatest}>
          ↓ Jump to latest
        </button>
      )}
      <div className="loadQueriesScroll" ref={feedRef} onScroll={handleScroll}>
        {queries.map((q) => (
          <LiveQueryCard
            key={q.id}
            query={q}
            open={expandedId === q.id}
            onToggle={() => setExpandedId(expandedId === q.id ? null : q.id)}
          />
        ))}
      </div>
    </div>
  );
}

function LiveQueryCard({
  query,
  open,
  onToggle,
}: {
  query: LiveQuery;
  open: boolean;
  onToggle: () => void;
}) {
  async function copySql() {
    try {
      await navigator.clipboard.writeText(query.sql);
    } catch {
      /* ignore */
    }
  }

  return (
    <div className={`loadQueryItem ${open ? "open" : ""}`}>
      <button type="button" className="loadQueryHead" onClick={onToggle}>
        <span className="loadQueryName">{query.name}</span>
        <span className="loadQueryMeta">
          <span>{query.duration_ms}ms</span>
          <span className="loadQueryRows">{query.rows} rows</span>
          <span className="loadQueryChevron">{open ? "▾" : "▸"}</span>
        </span>
      </button>
      {open && query.sql && (
        <div className="loadQueryBody">
          <pre className="execPre loadQuerySql">{query.sql}</pre>
          <button type="button" className="loadCopyBtn" onClick={() => void copySql()}>
            Copy SQL
          </button>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════
   EXECUTION STEP ROW — Expandable with data preview
   ═══════════════════════════════════════════════ */
function StepRow({ step }: { step: Step }) {
  const [expanded, setExpanded] = useState(false);
  const rows = (step.rows ?? []) as Record<string, unknown>[];
  const hasData = rows.length > 0 || step.sql || step.error;

  return (
    <motion.div 
      className={`execBlock ${step.ok ? "ok" : step.skipped ? "skip" : "fail"}`}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: "spring", stiffness: 300, damping: 25 }}>
      <div className="execRow" onClick={() => hasData && setExpanded(!expanded)} style={{ cursor: hasData ? "pointer" : "default" }}>
        <span className="execIcon">{step.ok ? "✓" : step.skipped ? "—" : "✗"}</span>
        <strong className="execName">{step.name}</strong>
        {step.skipped && step.reason && <span className="execReason">{step.reason}</span>}
        <span className="execMeta">
          {step.skipped ? "skipped" : `${rows.length} rows`}
        </span>
        {hasData && <span className="execExpand">{expanded ? "▾" : "▸"}</span>}
      </div>
      {expanded && (
        <div className="execDetail">
          {step.sql && (
            <div className="execSql">
              <span className="execDetailLabel">SQL Query</span>
              <pre className="execPre">{step.sql}</pre>
            </div>
          )}
          {step.error && (
            <div className="execErrorDetail">
              <span className="execDetailLabel">Error</span>
              <pre className="execPre err">{step.error}</pre>
            </div>
          )}
          {rows.length > 0 && (
            <div className="execRows">
              <span className="execDetailLabel">Results ({rows.length} rows)</span>
              <div className="execTable">
                {rows.slice(0, 5).map((row, i) => (
                  <div key={i} className="execTableRow">
                    {Object.entries(row).map(([key, val]) => {
                      const display = formatCellValue(val);
                      if (!display) return null;
                      return (
                        <div key={key} className="execCell">
                          <span className="cellKey">{key}</span>
                          <span className="cellVal">{display}</span>
                        </div>
                      );
                    })}
                  </div>
                ))}
                {rows.length > 5 && <p className="execMore">+ {rows.length - 5} more rows</p>}
              </div>
            </div>
          )}
        </div>
      )}
    </motion.div>
  );
}

function formatCellValue(val: unknown): string {
  if (val === null || val === undefined || val === "") return "";
  if (typeof val === "string") {
    if (val.length > 120) return val.slice(0, 117) + "…";
    return val;
  }
  if (typeof val === "number" || typeof val === "boolean") return String(val);
  // Arrays and objects: compact display
  try {
    const s = JSON.stringify(val);
    if (s.length > 120) return s.slice(0, 117) + "…";
    return s;
  } catch { return String(val); }
}

/* ─── Tiny helpers ─── */
function TF({ label, value, set, ph }: { label: string; value: string; set: (v: string) => void; ph?: string }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input value={value} placeholder={ph} onChange={e => set(e.target.value)} />
    </label>
  );
}
