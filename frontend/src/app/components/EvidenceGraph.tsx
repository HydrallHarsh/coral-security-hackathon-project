import React, { useMemo, useState } from 'react';
import {
  ReactFlow,
  Background,
  Edge,
  Node as ReactFlowNode,
  Position,
  MarkerType,
  DefaultEdgeOptions,
  ReactFlowInstance,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from 'dagre';
import {
  SourceNode,
  PackageNode,
  VulnerabilityNode,
  DiscussionNode,
  PolicyNode,
  EvidenceNode,
  FindingNode,
  NodeData,
} from './nodes/CustomNodes';
import { AnimatedEdge } from './edges/AnimatedEdge';
import { resolveTopology, LayoutMode } from '../utils/topologyResolver';

const nodeTypes = {
  source:        SourceNode,
  package:       PackageNode,
  vulnerability: VulnerabilityNode,
  discussion:    DiscussionNode,
  policy:        PolicyNode,
  evidence:      EvidenceNode,
  finding:       FindingNode,
};

const edgeTypes = { animated: AnimatedEdge };

const defaultEdgeOptions: DefaultEdgeOptions = {
  type: 'animated',
  markerEnd: {
    type: MarkerType.ArrowClosed,
    color: 'rgba(167,139,250,0.5)',
    width: 12,
    height: 12,
  },
};

// ─── Legend items shown in the header bar ───────────────────────────────────
const LEGEND = [
  { key: 'package',       label: 'Dependency', color: '#fb923c' },
  { key: 'vulnerability', label: 'Risk Signal', color: '#f87171' },
  { key: 'source',        label: 'Source',      color: '#a78bfa' },
  { key: 'policy',        label: 'Policy',      color: '#34d399' },
  { key: 'discussion',    label: 'Discussion',  color: '#60a5fa' },
  { key: 'evidence',      label: 'Evidence',    color: '#94a3b8' },
];

// ─── Types ──────────────────────────────────────────────────────────────────
type GraphNode = {
  id: string;
  type: string;
  label: string;
  severity?: string;
  score?: number;
  source?: string;
  url?: string | null;
};
type GraphEdge = { from: string; to: string; type: string };

// ─── Edge label map ─────────────────────────────────────────────────────────
function mapEdgeLabel(type: string): string {
  const map: Record<string, string> = {
    introduced:    'introduces',
    matched:       'matched',
    documented_by: 'documented by',
    violates:      'violates',
    discussed_in:  'discussed in',
    supported_by:  'supported by',
    affects:       'affects',
    related_to:    'related to',
  };
  return map[type] ?? type.replace(/_/g, ' ').toLowerCase();
}

// ─── Label cleanup ───────────────────────────────────────────────────────────
function cleanNodeLabel(label: string): string {
  if (label.includes('{"') || label.includes('[{')) {
    try {
      const match = label.match(/keys:\s*(\[.*\])/);
      if (match) {
        const arr = JSON.parse(match[1]);
        if (Array.isArray(arr)) {
          return (arr as Record<string, string>[])
            .map(item => item.id || item.name || JSON.stringify(item))
            .slice(0, 3)
            .join(', ');
        }
      }
      const parsed = JSON.parse(label);
      if (Array.isArray(parsed))
        return (parsed as Record<string, string>[])
          .map(x => x.id || x.name || '')
          .filter(Boolean)
          .slice(0, 3)
          .join(', ') || label;
      if (typeof parsed === 'object')
        return (parsed as Record<string, string>).id ||
               (parsed as Record<string, string>).name ||
               (parsed as Record<string, string>).title ||
               label;
    } catch {
      const readable = label.split(/[{[]/)[0].trim();
      if (readable.length > 5) return readable;
    }
  }
  if (label.length > 90) return label.slice(0, 87) + '…';
  return label;
}

// ─── Dagre layout ────────────────────────────────────────────────────────────
const NODE_W = 290;
const NODE_H = 168;

function mapToReactFlowData(
  nodes: GraphNode[],
  edges: GraphEdge[],
  mode: LayoutMode,
) {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  const isHorizontal = mode !== 'hub' && mode !== 'cluster';
  const rankdir  = isHorizontal ? 'LR' : 'TB';
  const ranksep  = isHorizontal ? 220 : mode === 'hub' ? 140 : 150;
  const nodesep  = isHorizontal ? 100 : mode === 'hub' ? 130 : 90;
  const layout   = rankdir as 'LR' | 'TB';

  dagreGraph.setGraph({ rankdir, ranksep, nodesep });

  const rfNodes: ReactFlowNode<NodeData>[] = nodes.map(n => {
    const type = n.type.toLowerCase();
    let rfType = 'evidence';
    if (type.includes('vulnerab') || type.includes('advis') || type.includes('alert'))
      rfType = 'vulnerability';
    else if (type.includes('discuss') || type.includes('slack'))
      rfType = 'discussion';
    else if (type.includes('polic'))
      rfType = 'policy';
    else if (type.includes('package'))
      rfType = 'package';
    else if (type.includes('finding'))
      rfType = 'finding';
    else if (type.includes('source') || type.includes('pr') || type.includes('pull') || type.includes('github'))
      rfType = 'source';

    dagreGraph.setNode(n.id, { width: NODE_W, height: NODE_H });

    return {
      id: n.id,
      type: rfType,
      position: { x: 0, y: 0 },
      data: {
        label:    cleanNodeLabel(n.label),
        type:     n.type,
        severity: n.severity,
        score:    n.score,
        source:   n.source,
        url:      n.url,
        layout,
      },
    };
  });

  const outgoingCount = new Map<string, number>();
  for (const e of edges) {
    outgoingCount.set(e.from, (outgoingCount.get(e.from) ?? 0) + 1);
  }
  const outgoingIndex = new Map<string, number>();

  const rfEdges: Edge[] = edges.map((e, i) => {
    dagreGraph.setEdge(e.from, e.to);
    const totalFromSource = outgoingCount.get(e.from) ?? 1;
    const idx = outgoingIndex.get(e.from) ?? 0;
    outgoingIndex.set(e.from, idx + 1);
    const pathOffset =
      totalFromSource <= 1 ? 0 : (idx - (totalFromSource - 1) / 2) * 24;

    return {
      id:     `e-${e.from}-${e.to}-${i}`,
      source: e.from,
      target: e.to,
      type:   'animated',
      label:  totalFromSource > 4 ? undefined : mapEdgeLabel(e.type),
      data:   { kind: e.type, pathOffset },
    };
  });

  dagre.layout(dagreGraph);

  rfNodes.forEach(node => {
    const n = dagreGraph.node(node.id);
    node.position = { x: n.x - n.width / 2, y: n.y - n.height / 2 };
    node.targetPosition = layout === 'LR' ? Position.Left  : Position.Top;
    node.sourcePosition = layout === 'LR' ? Position.Right : Position.Bottom;
  });

  return { nodes: rfNodes, edges: rfEdges };
}

// ─── Main Component ──────────────────────────────────────────────────────────
export function EvidenceGraph({
  graph,
}: {
  graph?: { nodes?: GraphNode[]; edges?: GraphEdge[] };
}) {
  const allNodes = graph?.nodes ?? [];
  const allEdges = graph?.edges ?? [];
  const [flowInstance, setFlowInstance] = useState<ReactFlowInstance | null>(null);

  const mode = resolveTopology(allNodes, allEdges);

  const { nodes: rfNodes, edges: rfEdges } = useMemo(() => {
    if (allNodes.length === 0) return { nodes: [], edges: [] };
    return mapToReactFlowData(allNodes, allEdges, mode);
  }, [allNodes, allEdges, mode]);

  if (allNodes.length === 0) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)' }}>
        No evidence graph available.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: 0 }}>

      {/* ── Header row: title + legend + controls ── */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '10px 16px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        flexShrink: 0,
        flexWrap: 'wrap',
        gap: 10,
      }}>
        {/* Left: title + stat */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.72rem',
            fontWeight: 700,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            color: '#e5e7eb',
          }}>
            Evidence Graph
          </div>
          <div style={{
            fontSize: '0.68rem',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-3)',
            padding: '2px 8px',
            borderRadius: 999,
            border: '1px solid rgba(255,255,255,0.07)',
            background: 'rgba(255,255,255,0.03)',
          }}>
            {allNodes.length} nodes · {allEdges.length} edges
          </div>
        </div>

        {/* Center: compact legend */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
          {LEGEND.map(item => (
            <div
              key={item.key}
              style={{ display: 'flex', alignItems: 'center', gap: 5 }}
            >
              <span style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: item.color,
                flexShrink: 0,
              }} />
              <span style={{
                fontSize: '0.68rem',
                fontFamily: 'var(--font-mono)',
                color: 'rgba(200,196,215,0.7)',
                whiteSpace: 'nowrap',
              }}>
                {item.label}
              </span>
            </div>
          ))}
        </div>

        {/* Right: controls */}
        <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
          <button
            className="graphControlBtn"
            onClick={() => flowInstance?.fitView({ padding: 0.18, duration: 450 })}
          >
            Fit view
          </button>
          <button
            className="graphControlBtn"
            aria-label="Zoom out"
            onClick={() => flowInstance?.zoomOut({ duration: 200 })}
          >
            −
          </button>
          <button
            className="graphControlBtn"
            aria-label="Zoom in"
            onClick={() => flowInstance?.zoomIn({ duration: 200 })}
          >
            +
          </button>
        </div>
      </div>

      {/* ── Canvas ── */}
      <div style={{
        flex: 1,
        minHeight: 0,
        position: 'relative',
        borderRadius: '0 0 10px 10px',
        overflow: 'hidden',
        background: `
          radial-gradient(ellipse at 15% 20%, rgba(96,165,250,0.07) 0%, transparent 50%),
          radial-gradient(ellipse at 85% 80%, rgba(248,113,113,0.07) 0%, transparent 45%),
          #0e0d13
        `,
      }}>
        <ReactFlow
          nodes={rfNodes}
          edges={rfEdges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          defaultEdgeOptions={defaultEdgeOptions}
          fitView
          fitViewOptions={{ padding: 0.18 }}
          onInit={setFlowInstance}
          nodesDraggable={true}
          nodesConnectable={false}
          panOnDrag
          panOnScroll={false}
          zoomOnScroll={true}
          zoomOnDoubleClick={false}
          preventScrolling={false}
          minZoom={0.3}
          maxZoom={2}
        >
          <Background
            gap={28}
            color="rgba(255,255,255,0.035)"
            size={1.2}
          />
        </ReactFlow>

        {/* Subtle flow direction hint — bottom right */}
        <div style={{
          position: 'absolute',
          bottom: 12,
          right: 14,
          fontSize: '0.62rem',
          fontFamily: 'var(--font-mono)',
          color: 'rgba(160,153,180,0.4)',
          pointerEvents: 'none',
          userSelect: 'none',
          display: 'flex',
          alignItems: 'center',
          gap: 6,
        }}>
          <span style={{ width: 20, height: 1, background: 'rgba(255,255,255,0.12)', display: 'inline-block' }} />
          causal flow →
        </div>
      </div>
    </div>
  );
}
