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
  layout?: 'LR' | 'TB';
};

// ─── Palette ─────────────────────────────────────────────────────────────────
const palette = {
  source:        { accent: '#a78bfa', border: 'rgba(167,139,250,0.4)' },
  package:       { accent: '#fb923c', border: 'rgba(251,146,60,0.45)' },
  vulnerability: { accent: '#f87171', border: 'rgba(248,113,113,0.45)' },
  discussion:    { accent: '#60a5fa', border: 'rgba(96,165,250,0.4)' },
  policy:        { accent: '#34d399', border: 'rgba(52,211,153,0.4)' },
  evidence:      { accent: '#94a3b8', border: 'rgba(148,163,184,0.3)' },
  finding:       { accent: '#f59e0b', border: 'rgba(245,158,11,0.45)' },
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
function formatSource(source?: string): string {
  if (!source) return '';
  const s = source.toLowerCase();
  if (s.includes('osv'))          return 'OSV';
  if (s.includes('deps_dev') || s.includes('deps.dev')) return 'deps.dev';
  if (s.includes('github'))       return 'GitHub';
  if (s.includes('slack'))        return 'Slack';
  if (s.includes('notion'))       return 'Notion';
  return source;
}

function formatTypeLabel(type: string): string {
  const lower = (type || '').toLowerCase();
  if (lower.includes('pull_request') || lower === 'pr') return 'Pull Request';
  if (lower.includes('github_alert'))   return 'Dependabot Alert';
  if (lower.includes('code_search'))    return 'Code Search';
  if (lower.includes('package'))        return 'NPM Package';
  if (lower.includes('vulnerab') || lower.includes('advis')) return 'Security Advisory';
  if (lower.includes('policy'))         return 'Policy Requirement';
  if (lower.includes('discuss') || lower.includes('slack')) return 'Slack Thread';
  if (lower.includes('finding'))        return 'Investigation Finding';
  if (lower.includes('evidence'))       return 'Supporting Evidence';
  return type.replace(/_/g, ' ').replace(/\b\w/g, m => m.toUpperCase());
}

function splitPackageLabel(label: string) {
  const trimmed = label.trim();
  const atMatch = trimmed.match(/^([^@]+)@(\d[\w.-]*)$/);
  if (atMatch) return { name: atMatch[1], version: atMatch[2] };
  const vMatch = trimmed.match(/^(.+?)\s+v?(\d+\.\d+[\w.-]*)$/);
  if (vMatch) return { name: vMatch[1], version: vMatch[2] };
  return { name: trimmed };
}

function severityColor(severity?: string): string {
  const s = (severity || '').toLowerCase();
  if (s.includes('critical') || s.includes('high')) return '#f87171';
  if (s.includes('medium') || s.includes('moderate')) return '#fbbf24';
  if (s.includes('low')) return '#34d399';
  return '#94a3b8';
}

// ─── Source logo: reads data.source to show the right brand ─────────────────
// These are 40x40 so they're ACTUALLY visible and recognizable.
function SourceLogo({ source }: { source?: string }) {
  const s = (source || '').toLowerCase();

  // ── GitHub ──
  if (s.includes('github')) return (
    <div style={{ width: 40, height: 40, borderRadius: 10, background: '#24292f', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
      <img src="/logos/github.png" width="26" height="26" alt="GitHub" />
    </div>
  );

  // ── Slack ──
  if (s.includes('slack')) return (
    <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(74,21,75,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
      <img src="/logos/slack.png" width="30" height="30" alt="Slack" />
    </div>
  );

  // ── Notion ──
  if (s.includes('notion')) return (
    <div style={{ width: 40, height: 40, borderRadius: 10, background: '#ffffff', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
      <img src="/logos/notion.png" width="30" height="30" alt="Notion" style={{ objectFit: 'contain' }} />
    </div>
  );

  // ── OSV ──
  if (s.includes('osv')) return (
    <div style={{ width: 40, height: 40, borderRadius: 10, background: '#ffffff', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
      <img src="/logos/osv.png" width="34" height="34" alt="OSV" style={{ borderRadius: '50%' }} />
    </div>
  );

  // ── deps.dev ──
  if (s.includes('deps')) return (
    <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(251,146,60,0.1)', border: '1px solid rgba(251,146,60,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <img src="https://api.iconify.design/logos:npm-icon.svg" width="30" height="30" alt="NPM" />
    </div>
  );

  // ── Fallback ──
  return (
    <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(148,163,184,0.08)', border: '1px solid rgba(148,163,184,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <img src="https://api.iconify.design/lucide:file-text.svg?color=%2394a3b8" width="22" height="22" alt="Fallback" />
    </div>
  );
}

// ─── Node Shell ──────────────────────────────────────────────────────────────
function NodeShell({ children, typeKey, layout, outerLabel, source }: {
  children: React.ReactNode;
  typeKey: keyof typeof palette;
  layout?: 'LR' | 'TB';
  outerLabel?: string;
  source?: string;
}) {
  const { accent, border } = palette[typeKey] || palette.evidence;
  return (
    <motion.div
      initial={{ opacity: 0, y: 8, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ type: 'spring', stiffness: 280, damping: 22 }}
    >
      <Handle type="target" position={layout === 'LR' ? Position.Left : Position.Top} style={{ opacity: 0, pointerEvents: 'none' }} />

      {outerLabel && (
        <div style={{
          color: accent,
          fontSize: '0.68rem',
          fontFamily: 'var(--font-mono)',
          textTransform: 'uppercase',
          marginBottom: 8,
          letterSpacing: '0.06em',
          fontWeight: 700,
        }}>
          {outerLabel}
        </div>
      )}

      <div style={{
        width: 260,
        background: 'rgba(14, 13, 19, 0.92)',
        border: `1px solid ${border}`,
        borderRadius: 12,
        padding: '18px 20px 20px',
      }}>
        <div style={{ marginBottom: 14 }}>
          <SourceLogo source={source} />
        </div>
        {children}
      </div>

      <Handle type="source" position={layout === 'LR' ? Position.Right : Position.Bottom} style={{ opacity: 0, pointerEvents: 'none' }} />
    </motion.div>
  );
}

// ─── Sub-components ──────────────────────────────────────────────────────────
function NodeTitle({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f0edf5', lineHeight: 1.3, wordBreak: 'break-word', marginBottom: 4 }}>
      {children}
    </div>
  );
}

function NodeTypeLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'rgba(160,153,180,0.7)', marginBottom: 2 }}>
      {children}
    </div>
  );
}

function SeverityBadge({ severity, score }: { severity?: string; score?: number }) {
  if (!severity && score === undefined) return null;
  const color = severityColor(severity);
  return (
    <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap', alignItems: 'center' }}>
      {severity && (
        <span style={{
          padding: '2px 10px', borderRadius: 4,
          background: `${color}18`, border: `1px solid ${color}44`,
          fontSize: '0.72rem', fontWeight: 700, fontFamily: 'var(--font-mono)',
          color, textTransform: 'uppercase',
        }}>
          {severity.toUpperCase()}
        </span>
      )}
      {score !== undefined && !Number.isNaN(score) && (
        <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'rgba(230,228,240,0.7)' }}>
          CVSS {score}
        </span>
      )}
    </div>
  );
}

function NodeLink({ url, label, color }: { url?: string | null; label: string; color?: string }) {
  if (!url) return null;
  return (
    <a href={url} target="_blank" rel="noreferrer" style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      marginTop: 10, fontSize: '0.72rem', fontFamily: 'var(--font-mono)',
      color: color || 'var(--accent)', textDecoration: 'none',
    }}>
      {label} ↗
    </a>
  );
}

// ─── Exported Nodes ──────────────────────────────────────────────────────────

export function SourceNode({ data }: { data: NodeData }) {
  const typeLabel = formatTypeLabel(data.type);
  const { accent } = palette.source;
  const src = formatSource(data.source);
  return (
    <NodeShell typeKey="source" layout={data.layout} outerLabel="SOURCE" source={data.source}>
      <NodeTitle>{data.label || 'GitHub PR'}</NodeTitle>
      <NodeTypeLabel>{typeLabel}</NodeTypeLabel>
      <NodeLink url={data.url} label={src || 'Open source'} color={accent} />
    </NodeShell>
  );
}

export function PackageNode({ data }: { data: NodeData }) {
  const { name, version } = splitPackageLabel(data.label);
  const { accent } = palette.package;
  return (
    <NodeShell typeKey="package" layout={data.layout} outerLabel="ROOT PACKAGE" source={data.source || 'deps_dev'}>
      <NodeTitle>{name || 'Package'}</NodeTitle>
      <NodeTypeLabel>NPM Package</NodeTypeLabel>
      {version && (
        <div style={{
          display: 'inline-block', padding: '2px 10px', marginTop: 10, borderRadius: 4,
          background: `${accent}18`, border: `1px solid ${accent}33`,
          fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: accent, fontWeight: 600,
        }}>
          v{version}
        </div>
      )}
    </NodeShell>
  );
}

export function VulnerabilityNode({ data }: { data: NodeData }) {
  const typeLabel = formatTypeLabel(data.type);
  const { accent } = palette.vulnerability;
  return (
    <NodeShell typeKey="vulnerability" layout={data.layout} outerLabel="VULNERABILITY" source={data.source || 'osv'}>
      <NodeTitle>{data.label || 'Security issue'}</NodeTitle>
      <NodeTypeLabel>{typeLabel}</NodeTypeLabel>
      <SeverityBadge severity={data.severity} score={data.score} />
      <NodeLink url={data.url} label="View advisory" color={accent} />
    </NodeShell>
  );
}

export function DiscussionNode({ data }: { data: NodeData }) {
  const label = (data.label || 'Discussion note').slice(0, 90) + ((data.label || '').length > 90 ? '…' : '');
  const { accent } = palette.discussion;
  return (
    <NodeShell typeKey="discussion" layout={data.layout} outerLabel="DISCUSSION" source={data.source || 'slack'}>
      <NodeTitle>Slack Thread</NodeTitle>
      <NodeTypeLabel>{label}</NodeTypeLabel>
      <NodeLink url={data.url} label="Open thread" color={accent} />
    </NodeShell>
  );
}

export function PolicyNode({ data }: { data: NodeData }) {
  const { accent } = palette.policy;
  return (
    <NodeShell typeKey="policy" layout={data.layout} outerLabel="POLICY" source={data.source || 'notion'}>
      <NodeTitle>{data.label || 'Security Policy'}</NodeTitle>
      <NodeTypeLabel>{formatTypeLabel(data.type)}</NodeTypeLabel>
      <div style={{
        display: 'inline-block', padding: '2px 10px', marginTop: 10, borderRadius: 4,
        background: `${accent}18`, border: `1px solid ${accent}33`,
        fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: accent, fontWeight: 600,
      }}>
        Active
      </div>
      <NodeLink url={data.url} label="Open policy" color={accent} />
    </NodeShell>
  );
}

export function EvidenceNode({ data }: { data: NodeData }) {
  const typeLabel = formatTypeLabel(data.type);
  const { accent } = palette.evidence;
  const src = formatSource(data.source);
  return (
    <NodeShell typeKey="evidence" layout={data.layout} outerLabel="EVIDENCE" source={data.source}>
      <NodeTitle>{data.label || 'Supporting record'}</NodeTitle>
      <NodeTypeLabel>{src ? `${src} · ${typeLabel}` : typeLabel}</NodeTypeLabel>
      <NodeLink url={data.url} label="Open record" color={accent} />
    </NodeShell>
  );
}

export function FindingNode({ data }: { data: NodeData }) {
  const typeLabel = formatTypeLabel(data.type);
  const { accent } = palette.finding;
  return (
    <NodeShell typeKey="finding" layout={data.layout} outerLabel="FINDING" source={data.source}>
      <NodeTitle>{data.label || 'Investigation finding'}</NodeTitle>
      <NodeTypeLabel>{typeLabel}</NodeTypeLabel>
      <SeverityBadge severity={data.severity} score={data.score} />
      <NodeLink url={data.url} label="Open detail" color={accent} />
    </NodeShell>
  );
}
