import { Handle, Position } from '@xyflow/react';
import { motion } from 'motion/react';
import React from 'react';

export type NodeData = {
  label: string;
  type: string;
  severity?: string;
  score?: number;
  source?: string;
  url?: string | null;
  icon?: string;
  isHero?: boolean;
  layout?: 'LR' | 'TB';
};

const colors = {
  source: '#a78bfa',
  package: '#fb923c',
  vulnerability: '#f87171',
  discussion: '#60a5fa',
  policy: '#34d399',
  evidence: '#9ca3af',
  finding: '#f59e0b',
};

const CategoryHeader = ({ title, color }: { title: string; color: string }) => (
  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', fontWeight: 600, letterSpacing: '0.05em', color, marginBottom: '6px', textTransform: 'uppercase' }}>
    {title}
  </div>
);

const NodeContainer = ({ children, borderColor, className }: { children: React.ReactNode; borderColor: string; className?: string }) => (
  <div style={{
    background: '#18181b', // matching the dark background of the node
    border: `1px solid ${borderColor}`,
    borderRadius: '12px',
    padding: '16px',
    color: 'var(--text)',
    width: '260px',
    boxSizing: 'border-box',
    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.02) inset'
  }} className={`nodeShell${className ? ` ${className}` : ''}`}>
    {children}
  </div>
);

const MetaRow = ({ label, value }: { label: string; value?: string }) => {
  if (!value) return null;
  return (
    <div className="nodeMetaRow">
      <span className="nodeMetaLabel">{label}</span>
      <span className="nodeMetaValue">{value}</span>
    </div>
  );
};

const Pill = ({ text, tone }: { text: string; tone: 'danger' | 'warn' | 'info' | 'ok' | 'muted' }) => (
  <span className={`nodePill ${tone}`}>{text}</span>
);

function toTitleCase(input: string) {
  return input
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

function formatTypeLabel(type: string) {
  if (!type) return 'Unknown';
  const lower = type.toLowerCase();
  if (lower.includes('pull_request') || lower === 'pr') return 'Pull request';
  if (lower.includes('commit')) return 'Commit';
  if (lower.includes('github')) return 'GitHub activity';
  if (lower.includes('package')) return 'Dependency package';
  if (lower.includes('vulnerab') || lower.includes('advis')) return 'Security advisory';
  if (lower.includes('policy')) return 'Policy requirement';
  if (lower.includes('discuss') || lower.includes('slack')) return 'Discussion';
  if (lower.includes('finding')) return 'Investigation finding';
  if (lower.includes('evidence')) return 'Supporting evidence';
  return toTitleCase(type);
}

function formatSource(source?: string) {
  if (!source) return undefined;
  const lower = source.toLowerCase();
  if (lower.includes('github')) return 'GitHub';
  if (lower.includes('slack')) return 'Slack';
  if (lower.includes('notion')) return 'Notion';
  if (lower.includes('deps.dev')) return 'deps.dev';
  if (lower.includes('osv')) return 'OSV';
  return source;
}

function formatSeverity(severity?: string) {
  if (!severity) return undefined;
  return severity.toUpperCase();
}

function formatScore(score?: number) {
  if (score === null || score === undefined || Number.isNaN(score)) return undefined;
  return score.toFixed(1);
}

function severityTone(severity?: string) {
  if (!severity) return 'muted' as const;
  const lower = severity.toLowerCase();
  if (lower.includes('critical') || lower.includes('high')) return 'danger' as const;
  if (lower.includes('medium') || lower.includes('moderate')) return 'warn' as const;
  if (lower.includes('low')) return 'ok' as const;
  return 'info' as const;
}

function scoreTone(score?: number) {
  if (score === null || score === undefined || Number.isNaN(score)) return 'muted' as const;
  if (score >= 8) return 'danger' as const;
  if (score >= 5) return 'warn' as const;
  if (score >= 3) return 'info' as const;
  return 'ok' as const;
}

function splitPackageLabel(label: string) {
  const trimmed = label.trim();
  const atMatch = trimmed.match(/^([^@]+)@(\d[\w.-]*)$/);
  if (atMatch) return { name: atMatch[1], version: atMatch[2] };
  const vMatch = trimmed.match(/^(.+?)\s+v?(\d+\.\d+[\w.-]*)$/);
  if (vMatch) return { name: vMatch[1], version: vMatch[2] };
  return { name: trimmed };
}

function safeTitle(label: string, fallback: string) {
  const trimmed = label.trim();
  return trimmed ? trimmed : fallback;
}

// SVG Icons
const GithubIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.462-1.11-1.462-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.161 22 16.418 22 12c0-5.523-4.477-10-10-10z"/></svg>
);
const BoxIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
);
const ShieldIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
);
const SlackIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
);
const NotionIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="9" y1="9" x2="15" y2="15"></line><line x1="15" y1="9" x2="15" y2="15"></line><line x1="9" y1="9" x2="9" y2="15"></line></svg>
);
const DocumentIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
);

export function SourceNode({ data }: { data: NodeData }) {
  const title = safeTitle(data.label, 'Source record');
  const typeLabel = formatTypeLabel(data.type);
  const sourceLabel = formatSource(data.source);
  return (
    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: "spring", stiffness: 300, damping: 20 }}>
      <Handle type="target" position={data.layout === 'LR' ? Position.Left : Position.Top} style={{ opacity: 0 }} />
      <CategoryHeader title="CHANGE SOURCE" color={colors.source} />
      <NodeContainer borderColor="rgba(255,255,255,0.1)">
        <div className="nodeHeader">
          <div className="nodeIcon" style={{ color: colors.source }}><GithubIcon /></div>
          <div>
            <strong className="nodeTitle">{title}</strong>
            <div className="nodeSubtitle">{typeLabel}</div>
          </div>
        </div>
        <div className="nodeMetaGrid">
          <MetaRow label="Origin" value={sourceLabel} />
          {data.url && <a className="nodeLink" href={data.url} target="_blank" rel="noreferrer">Open source</a>}
        </div>
      </NodeContainer>
      <Handle type="source" position={data.layout === 'LR' ? Position.Right : Position.Bottom} style={{ opacity: 0 }} />
    </motion.div>
  );
}

export function PackageNode({ data }: { data: NodeData }) {
  const typeLabel = formatTypeLabel(data.type);
  const sourceLabel = formatSource(data.source);
  const { name, version } = splitPackageLabel(data.label);
  return (
    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: "spring", stiffness: 300, damping: 20 }}>
      <Handle type="target" position={data.layout === 'LR' ? Position.Left : Position.Top} style={{ opacity: 0 }} />
      <CategoryHeader title="DEPENDENCY" color={colors.package} />
      <NodeContainer borderColor={colors.package}>
        <div className="nodeHeader">
          <div className="nodeIcon" style={{ color: colors.package }}><BoxIcon /></div>
          <div>
            <strong className="nodeTitle">{safeTitle(name, 'Package')}</strong>
            <div className="nodeSubtitle">{typeLabel}</div>
          </div>
        </div>
        <div className="nodeMetaGrid">
          <MetaRow label="Version" value={version} />
          <MetaRow label="Registry" value={sourceLabel} />
          {data.url && <a className="nodeLink" href={data.url} target="_blank" rel="noreferrer">Open package</a>}
        </div>
      </NodeContainer>
      <Handle type="source" position={data.layout === 'LR' ? Position.Right : Position.Bottom} style={{ opacity: 0 }} />
    </motion.div>
  );
}

export function VulnerabilityNode({ data }: { data: NodeData }) {
  const title = safeTitle(data.label, 'Security issue');
  const typeLabel = formatTypeLabel(data.type);
  const severity = formatSeverity(data.severity);
  const score = formatScore(data.score);
  const sourceLabel = formatSource(data.source);
  return (
    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: "spring", stiffness: 300, damping: 20 }}>
      <Handle type="target" position={data.layout === 'LR' ? Position.Left : Position.Top} style={{ opacity: 0 }} />
      <CategoryHeader title="RISK SIGNAL" color={colors.vulnerability} />
      <NodeContainer borderColor={colors.vulnerability}>
        <div className="nodeHeader">
          <div className="nodeIcon" style={{ color: colors.vulnerability }}><ShieldIcon /></div>
          <div>
            <strong className="nodeTitle">{title}</strong>
            <div className="nodeSubtitle">{typeLabel}</div>
          </div>
        </div>
        <div className="nodePills">
          {severity && <Pill text={`Severity ${severity}`} tone={severityTone(data.severity)} />}
          {score && <Pill text={`Score ${score}`} tone={scoreTone(data.score)} />}
        </div>
        <div className="nodeMetaGrid">
          <MetaRow label="Source" value={sourceLabel} />
          {data.url && <a className="nodeLink" href={data.url} target="_blank" rel="noreferrer">View advisory</a>}
        </div>
      </NodeContainer>
      <Handle type="source" position={data.layout === 'LR' ? Position.Right : Position.Bottom} style={{ opacity: 0 }} />
    </motion.div>
  );
}

export function DiscussionNode({ data }: { data: NodeData }) {
  const title = safeTitle(data.label, 'Discussion note');
  const typeLabel = formatTypeLabel(data.type);
  const sourceLabel = formatSource(data.source);
  return (
    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: "spring", stiffness: 300, damping: 20 }}>
      <Handle type="target" position={data.layout === 'LR' ? Position.Left : Position.Top} style={{ opacity: 0 }} />
      <CategoryHeader title="DISCUSSION" color={colors.discussion} />
      <NodeContainer borderColor={colors.discussion}>
        <div className="nodeHeader">
          <div className="nodeIcon" style={{ color: colors.discussion }}><SlackIcon /></div>
          <div>
            <strong className="nodeTitle">{title}</strong>
            <div className="nodeSubtitle">{typeLabel}</div>
          </div>
        </div>
        <div className="nodeMetaGrid">
          <MetaRow label="Source" value={sourceLabel} />
          {data.url && <a className="nodeLink" href={data.url} target="_blank" rel="noreferrer">Open thread</a>}
        </div>
      </NodeContainer>
      <Handle type="source" position={data.layout === 'LR' ? Position.Right : Position.Bottom} style={{ opacity: 0 }} />
    </motion.div>
  );
}

export function PolicyNode({ data }: { data: NodeData }) {
  const title = safeTitle(data.label, 'Policy requirement');
  const typeLabel = formatTypeLabel(data.type);
  const sourceLabel = formatSource(data.source);
  return (
    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: "spring", stiffness: 300, damping: 20 }}>
      <Handle type="target" position={data.layout === 'LR' ? Position.Left : Position.Top} style={{ opacity: 0 }} />
      <CategoryHeader title="POLICY" color={colors.policy} />
      <NodeContainer borderColor={colors.policy}>
        <div className="nodeHeader">
          <div className="nodeIcon" style={{ color: colors.policy }}><NotionIcon /></div>
          <div>
            <strong className="nodeTitle">{title}</strong>
            <div className="nodeSubtitle">{typeLabel}</div>
          </div>
        </div>
        <div className="nodeMetaGrid">
          <MetaRow label="Source" value={sourceLabel} />
          {data.url && <a className="nodeLink" href={data.url} target="_blank" rel="noreferrer">Open policy</a>}
        </div>
      </NodeContainer>
      <Handle type="source" position={data.layout === 'LR' ? Position.Right : Position.Bottom} style={{ opacity: 0 }} />
    </motion.div>
  );
}

export function EvidenceNode({ data }: { data: NodeData }) {
  const title = safeTitle(data.label, 'Evidence record');
  const typeLabel = formatTypeLabel(data.type);
  const sourceLabel = formatSource(data.source);
  return (
    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: "spring", stiffness: 300, damping: 20 }}>
      <Handle type="target" position={data.layout === 'LR' ? Position.Left : Position.Top} style={{ opacity: 0 }} />
      <CategoryHeader title="SUPPORTING EVIDENCE" color={colors.evidence} />
      <NodeContainer borderColor="rgba(255,255,255,0.1)">
        <div className="nodeHeader">
          <div className="nodeIcon" style={{ color: colors.evidence }}><DocumentIcon /></div>
          <div>
            <strong className="nodeTitle">{title}</strong>
            <div className="nodeSubtitle">{typeLabel}</div>
          </div>
        </div>
        <div className="nodeMetaGrid">
          <MetaRow label="Source" value={sourceLabel} />
          {data.url && <a className="nodeLink" href={data.url} target="_blank" rel="noreferrer">Open record</a>}
        </div>
      </NodeContainer>
      <Handle type="source" position={data.layout === 'LR' ? Position.Right : Position.Bottom} style={{ opacity: 0 }} />
    </motion.div>
  );
}

export function FindingNode({ data }: { data: NodeData }) {
  const title = safeTitle(data.label, 'Investigation finding');
  const typeLabel = formatTypeLabel(data.type);
  const sourceLabel = formatSource(data.source);
  const severity = formatSeverity(data.severity);
  const score = formatScore(data.score);
  return (
    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: "spring", stiffness: 300, damping: 20 }}>
      <Handle type="target" position={data.layout === 'LR' ? Position.Left : Position.Top} style={{ opacity: 0 }} />
      <CategoryHeader title="FINDING" color={colors.finding} />
      <NodeContainer borderColor={colors.finding}>
        <div className="nodeHeader">
          <div className="nodeIcon" style={{ color: colors.finding }}><ShieldIcon /></div>
          <div>
            <strong className="nodeTitle">{title}</strong>
            <div className="nodeSubtitle">{typeLabel}</div>
          </div>
        </div>
        <div className="nodePills">
          {severity && <Pill text={`Severity ${severity}`} tone={severityTone(data.severity)} />}
          {score && <Pill text={`Score ${score}`} tone={scoreTone(data.score)} />}
        </div>
        <div className="nodeMetaGrid">
          <MetaRow label="Source" value={sourceLabel} />
          {data.url && <a className="nodeLink" href={data.url} target="_blank" rel="noreferrer">Open detail</a>}
        </div>
      </NodeContainer>
      <Handle type="source" position={data.layout === 'LR' ? Position.Right : Position.Bottom} style={{ opacity: 0 }} />
    </motion.div>
  );
}
