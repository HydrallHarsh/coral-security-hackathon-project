"use client";

import { FormEvent, useEffect, useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { EvidenceGraph } from "./components/EvidenceGraph";

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
type InvestigationResponse = {
  answer?: string; risk_level?: string; score?: number; findings?: Finding[];
  planner?: Planner; reasoning_trace?: string[]; evidence_graph?: EvidenceGraphData;
  steps?: Step[]; capability_summary?: Record<string, unknown>;
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
  package_system: "NPM", package_ecosystem: "npm", package_name: "minimist", package_version: "0.0.8",
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
export default function Home() {
  const [form, setForm] = useState<InvestigationForm>(initialForm);
  const [capabilities, setCapabilities] = useState<CapabilitiesResponse | null>(null);
  const [result, setResult] = useState<InvestigationResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("trace");
  const [loadingStep, setLoadingStep] = useState(0);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

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

  useEffect(() => {
    if (!loading) { setLoadingStep(0); return; }
    const id = setInterval(() => {
      setLoadingStep(p => (p < LOADING_STEPS.length - 1 ? p + 1 : p));
    }, 1800);
    return () => clearInterval(id);
  }, [loading]);

  const sources = capabilities?.capabilities?.sources ?? {};

  async function runInvestigation() {
    setLoading(true);
    setError(null);
    setResult(null);
    setSelectedNode(null);
    const payload = {
      question: form.question, owner: form.owner, repo: form.repo,
      org: form.org || form.owner, slack_channel: form.slack_channel || null,
      policy_query: form.policy_query, package_system: form.package_system,
      package_ecosystem: form.package_ecosystem, package_name: form.package_name,
      package_version: form.package_version, days: 7,
    };
    try {
      const r = await fetch(`${API_BASE}/agent/investigate`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail ?? `${r.status}`);
      setResult(data);
      void refreshCapabilities();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Investigation failed");
      setLoading(false);
    } finally {
      setLoading(false);
    }
  }

  /* ─── PHASE: LOADING ─── */
  if (loading) {
    return (
      <motion.div className="loadingScreen"
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }}>
        <div className="loadingRings">
          <div className="ring r1" />
          <div className="ring r2" />
          <div className="ring r3" />
        </div>
        <h2 className="loadingTitle">Investigation in Progress</h2>
        <div className="loadingSteps">
          {LOADING_STEPS.map((step, i) => (
            <motion.div key={step}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.08, type: "spring", stiffness: 200, damping: 20 }}
              className={`lStep ${i < loadingStep ? "done" : i === loadingStep ? "active" : ""}`}>
              <span className="lDot">{i < loadingStep ? "✓" : "●"}</span>
              {step}
            </motion.div>
          ))}
        </div>
      </motion.div>
    );
  }

  /* ─── PHASE: RESULTS ─── */
  if (result) {
    const findings = result.findings ?? [];
    const trace = result.reasoning_trace ?? [];
    const steps = result.steps ?? [];

    return (
      <motion.div className="workspace"
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }}>
        {/* ─── Top Bar ─── */}
        <header className="topBar">
          <div className="tbBrand">
            <strong className="tbLogo">HarborGuard</strong>
            <span className="tbTag">Investigation</span>
          </div>
          <div className="tbCenter">
            <span className="tbQ">{form.question}</span>
          </div>
          <div className="tbRight">
            <div className="tbSources">
              {Object.entries(sources).map(([n, s]) => (
                <div key={n} className={`tbSrc ${s.available ? "on" : ""}`}>
                  <span className="tbSrcDot" />
                  <span className="tbSrcName">{n.replace(/_/g, " ")}</span>
                </div>
              ))}
            </div>
            <button className="tbBtn" onClick={() => { setResult(null); setError(null); }}>
              ← New Investigation
            </button>
          </div>
        </header>

        {error && <div className="wError">{error}</div>}

        {/* ─── Assessment ─── */}
        <section className="assessment">
          <div className="aBody">
            <span className="aLabel">Assessment</span>
            <h2 className="aAnswer">{result.answer}</h2>
          </div>
          <div className={`riskScore ${result.risk_level ?? "low"}`}>
            <span className="rsLevel">{result.risk_level ?? "low"}</span>
            <strong className="rsValue">{result.score ?? 0}</strong>
          </div>
        </section>

        {/* ─── Main Area ─── */}
        <div className="mainArea">
          <section className="graphPanel">
            <h3 className="secTitle">Evidence Graph</h3>
            <EvidenceGraph graph={result.evidence_graph} />
          </section>

          <aside className="feedPanel">
            <h3 className="secTitle">Findings <span className="badge">{findings.length}</span></h3>
            <div className="feedScroll">
              {findings.map((f, i) => (
                <FindingCard key={f.graph_node_id ?? f.title} finding={f} delay={i * 0.1} />
              ))}
              {findings.length === 0 && <p className="feedEmpty">No findings detected.</p>}
            </div>
          </aside>
        </div>

        {/* ─── Bottom Dock ─── */}
        <section className="dock">
          <div className="dockTabs">
            {(["trace", "execution", "planner"] as const).map(t => (
              <button key={t} className={`dTab ${activeTab === t ? "active" : ""}`} onClick={() => setActiveTab(t)}>
                {t === "trace" ? "Reasoning Trace" : t === "execution" ? "Execution Steps" : "Planner"}
                {t === "trace" && trace.length > 0 && <span className="tBadge">{trace.length}</span>}
                {t === "execution" && steps.length > 0 && <span className="tBadge">{steps.length}</span>}
              </button>
            ))}
          </div>
          <div className="dockBody">
            {activeTab === "trace" && (
              <ol className="traceList">
                {trace.map((item, i) => <li key={i} className="traceItem" style={{ animationDelay: `${i * 0.04}s` }}>{item}</li>)}
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
          </div>
        </section>
      </motion.div>
    );
  }

  /* ─── PHASE: BRIEFING ─── */
  return (
    <motion.div className="briefing"
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.5 }}>
      <div className="bCenter">
        <motion.span className="bEyebrow"
          initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1, type: "spring", stiffness: 200, damping: 20 }}>
          Security Intelligence Platform
        </motion.span>
        <motion.h1 className="bTitle"
          initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15, type: "spring", stiffness: 150, damping: 20 }}>
          HarborGuard
        </motion.h1>
        <motion.p className="bSub"
          initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, type: "spring", stiffness: 180, damping: 20 }}>
          Coral-powered investigation across GitHub, Slack, Notion, and vulnerability databases.
        </motion.p>

        <div className="caseGrid">
          {CASE_PRESETS.map((p, i) => (
            <motion.button key={p.id}
              className={`caseFile ${form.question === p.question ? "active" : ""}`}
              onClick={() => setForm({ ...form, question: p.question })}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.25 + i * 0.06, type: "spring", stiffness: 200, damping: 20 }}
              whileHover={{ y: -3 }}
              whileTap={{ scale: 0.98 }}>
              <strong>{p.label}</strong>
              <span>{p.desc}</span>
            </motion.button>
          ))}
        </div>

        <form onSubmit={(e: FormEvent) => { e.preventDefault(); void runInvestigation(); }}>
          <div className="qArea">
            <textarea className="qInput" value={form.question}
              onChange={e => setForm({ ...form, question: e.target.value })}
              placeholder="Ask a security question..." rows={3} />
            <button type="submit" className="qBtn" disabled={loading || !form.question.trim()}>
              Begin Investigation →
            </button>
          </div>

          <details className="cfgDrawer">
            <summary className="cfgSummary">Configure parameters</summary>
            <div className="cfgGrid">
              <TF label="Owner" value={form.owner} set={v => setForm({ ...form, owner: v })} />
              <TF label="Repository" value={form.repo} set={v => setForm({ ...form, repo: v })} />
              <TF label="Org" value={form.org} set={v => setForm({ ...form, org: v })} />
              <TF label="Slack channel" value={form.slack_channel} set={v => setForm({ ...form, slack_channel: v })} ph="optional" />
              <TF label="Policy query" value={form.policy_query} set={v => setForm({ ...form, policy_query: v })} />
              <TF label="Package system" value={form.package_system} set={v => setForm({ ...form, package_system: v })} />
              <TF label="Ecosystem" value={form.package_ecosystem} set={v => setForm({ ...form, package_ecosystem: v })} />
              <TF label="Package" value={form.package_name} set={v => setForm({ ...form, package_name: v })} />
              <TF label="Version" value={form.package_version} set={v => setForm({ ...form, package_version: v })} />
            </div>
          </details>
        </form>

        <div className="srcPills">
          {Object.entries(sources).map(([n, s]) => (
            <div key={n} className={`srcPill ${s.available ? "on" : "off"}`}>
              <span className="srcDot" />{n.replace(/_/g, " ")}
            </div>
          ))}
          {Object.keys(sources).length === 0 && <span className="srcLoading">Loading sources…</span>}
        </div>

        {error && <p className="bError">{error}</p>}
      </div>
    </motion.div>
  );
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
