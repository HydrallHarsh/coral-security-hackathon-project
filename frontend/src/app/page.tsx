"use client";

import { FormEvent, useEffect, useState } from "react";
import { motion } from "motion/react";
import { useRouter } from "next/navigation";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000";

type SourceCapabilities = { available?: boolean; configured?: boolean; tools?: string[] };
type ToolCapability = { available?: boolean; purpose?: string; source?: string; capabilities?: string[] };
type CapabilitiesResponse = {
  capabilities?: {
    sources?: Record<string, SourceCapabilities>;
  };
};

type InvestigationForm = {
  question: string; owner: string; repo: string; org: string; slack_channel: string;
  policy_query: string; package_system: string; package_ecosystem: string;
  package_name: string; package_version: string;
};

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

export default function Home() {
  const router = useRouter();
  const [form, setForm] = useState<InvestigationForm>(initialForm);
  const [capabilities, setCapabilities] = useState<CapabilitiesResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

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

  const sources = capabilities?.capabilities?.sources ?? {};

  function startInvestigation(e: FormEvent) {
    e.preventDefault();
    if (!form.question.trim()) return;
    
    const params = new URLSearchParams();
    Object.entries(form).forEach(([key, val]) => {
      if (val) params.append(key, val);
    });
    
    router.push(`/dashboard?${params.toString()}`);
  }

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

        <form className="qForm" onSubmit={startInvestigation}>
          <div className="qArea">
            <textarea className="qInput" value={form.question}
              onChange={e => setForm({ ...form, question: e.target.value })}
              placeholder="Ask a security question..." rows={3} />
            <button type="submit" className="qBtn" disabled={!form.question.trim()}>
              Begin Investigation →
            </button>
          </div>

          <details className="cfgDrawer">
            <summary className="cfgSummary">Repository scan inputs</summary>
            <div className="cfgGrid">
              <TF label="Owner" value={form.owner} set={v => setForm({ ...form, owner: v })} />
              <TF label="Repository" value={form.repo} set={v => setForm({ ...form, repo: v })} />
              <TF label="Slack channel" value={form.slack_channel} set={v => setForm({ ...form, slack_channel: v })} ph="optional" />
            </div>
            <details className="advancedDrawer">
              <summary className="cfgSummary small">Advanced package override</summary>
              <div className="cfgGrid">
                <TF label="Package" value={form.package_name} set={v => setForm({ ...form, package_name: v })} ph="auto-detect" />
                <TF label="Version" value={form.package_version} set={v => setForm({ ...form, package_version: v })} ph="auto-detect" />
                <TF label="System" value={form.package_system} set={v => setForm({ ...form, package_system: v })} ph="NPM, PYPI, GO" />
                <TF label="Ecosystem" value={form.package_ecosystem} set={v => setForm({ ...form, package_ecosystem: v })} ph="npm, PyPI, Go" />
              </div>
            </details>
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

function TF({ label, value, set, ph }: { label: string; value: string; set: (v: string) => void; ph?: string }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input value={value} placeholder={ph} onChange={e => set(e.target.value)} />
    </label>
  );
}
