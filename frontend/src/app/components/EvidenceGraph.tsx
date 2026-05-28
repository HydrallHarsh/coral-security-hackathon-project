import React, { useMemo, useState } from 'react';
import { ReactFlow, Background, Edge, Node as ReactFlowNode, Position, MarkerType, DefaultEdgeOptions, ReactFlowInstance } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from 'dagre';
import { SourceNode, PackageNode, VulnerabilityNode, DiscussionNode, PolicyNode, EvidenceNode, FindingNode, NodeData } from './nodes/CustomNodes';
import { AnimatedEdge } from './edges/AnimatedEdge';
import { resolveTopology, LayoutMode } from '../utils/topologyResolver';

const nodeTypes = {
  source: SourceNode,
  package: PackageNode,
  vulnerability: VulnerabilityNode,
  discussion: DiscussionNode,
  policy: PolicyNode,
  evidence: EvidenceNode,
  finding: FindingNode,
};

const edgeTypes = {
  animated: AnimatedEdge,
};

const defaultEdgeOptions: DefaultEdgeOptions = {
  type: 'animated',
  markerEnd: {
    type: MarkerType.ArrowClosed,
    color: 'rgba(255, 255, 255, 0.2)',
  },
};

type GraphNode = { id: string; type: string; label: string; severity?: string; score?: number; source?: string; url?: string | null };
type GraphEdge = { from: string; to: string; type: string };

function mapToReactFlowData(nodes: GraphNode[], edges: GraphEdge[], mode: LayoutMode) {
  // Setup Dagre graph
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  
  // Apply Layout Mode configurations
  let rankdir = 'LR';
  let align = undefined;
  let ranksep = 200;
  let nodesep = 80;

  if (mode === 'hub') {
    // Hub works best top-down and centered
    rankdir = 'TB';
    align = 'DL'; // Center alignment approximation in dagre
    nodesep = 120; // more horizontal space for radial-like feel
  } else if (mode === 'cluster') {
    rankdir = 'TB';
    ranksep = 150;
  }
  
  const layout = rankdir as 'LR' | 'TB';
  
  // Set graph layout configuration
  dagreGraph.setGraph({ rankdir, align, ranksep, nodesep });

  // Add nodes to dagre
  const rfNodes: ReactFlowNode<NodeData>[] = nodes.map(n => {
    // Determine dimensions based on type
    let width = 260;
    let height = 190;
    
    let rfType = 'evidence';
    let icon = '📄';
    let isHero = false;
    const type = n.type.toLowerCase();

    if (type.includes('vulnerab')) {
      rfType = 'vulnerability';
      icon = '🛡️';
    } else if (type.includes('discuss') || type.includes('slack')) {
      rfType = 'discussion';
      icon = '💬';
    } else if (type.includes('polic')) {
      rfType = 'policy';
      icon = '📋';
    } else if (type.includes('package')) {
      rfType = 'package';
      icon = '📦';
    } else if (type.includes('finding')) {
      rfType = 'finding';
      icon = '🔍';
      width = 260;
      height = 210;
    } else if (type.includes('source') || type.includes('pr') || type.includes('github')) {
      rfType = 'source';
      icon = '🔗';
    } else {
      rfType = 'evidence';
      icon = '📄';
    }

    dagreGraph.setNode(n.id, { width, height });

    return {
      id: n.id,
      type: rfType,
      position: { x: 0, y: 0 }, // Will be set by dagre
      data: {
        label: cleanNodeLabel(n.label),
        type: n.type,
        severity: n.severity,
        score: n.score,
        source: n.source,
        url: n.url,
        icon,
        isHero,
        layout
      }
    };
  });

  // Add edges to dagre
  const rfEdges: Edge[] = edges.map((e, i) => {
    dagreGraph.setEdge(e.from, e.to);
    return {
      id: `e-${e.from}-${e.to}-${i}`,
      source: e.from,
      target: e.to,
      type: 'animated',
      label: mapEdgeLabel(e.type),
      data: { kind: e.type },
    };
  });

  // Execute Layout
  dagre.layout(dagreGraph);

  // Apply computed positions to React Flow nodes
  rfNodes.forEach((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    // Dagre returns the center, React Flow needs the top-left
    node.position = {
      x: nodeWithPosition.x - nodeWithPosition.width / 2,
      y: nodeWithPosition.y - nodeWithPosition.height / 2,
    };
    // Ensure all nodes have correct target and source positions for React Flow rendering
    node.targetPosition = layout === 'LR' ? Position.Left : Position.Top;
    node.sourcePosition = layout === 'LR' ? Position.Right : Position.Bottom;
  });

  return { nodes: rfNodes, edges: rfEdges };
}

function mapEdgeLabel(type: string): string {
  const map: Record<string, string> = {
    'HAS_VULNERABILITY': 'flags risk',
    'HAS_EVIDENCE': 'supported by',
    'VIOLATES_POLICY': 'policy conflict',
    'AFFECTS': 'affects',
    'INTRODUCED_BY': 'introduced by',
    'DISCUSSED_IN': 'discussed in',
    'RELATED_TO': 'related to'
  };
  return map[type] || type.replace(/_/g, ' ').toLowerCase();
}

/** Clean up labels that contain raw JSON or overly long text */
function cleanNodeLabel(label: string): string {
  if (label.includes('{"') || label.includes('[{')) {
    try {
      const match = label.match(/keys:\s*(\[.*\])/);
      if (match) {
        const arr = JSON.parse(match[1]);
        if (Array.isArray(arr)) {
          const ids = arr.map((item: Record<string, string>) => item.id || item.name || JSON.stringify(item)).slice(0, 3);
          return ids.join(", ");
        }
      }
      const parsed = JSON.parse(label);
      if (Array.isArray(parsed)) return parsed.map((x: Record<string, string>) => x.id || x.name || "").filter(Boolean).slice(0, 3).join(", ") || label;
      if (typeof parsed === "object") return parsed.id || parsed.name || parsed.title || label;
    } catch {
      const readable = label.split(/[{[]/)[0].trim();
      if (readable.length > 5) return readable;
    }
  }
  if (label.length > 80) return label.slice(0, 77) + "…";
  return label;
}

export function EvidenceGraph({ graph }: { graph?: { nodes?: GraphNode[], edges?: GraphEdge[] } }) {
  const allNodes = graph?.nodes || [];
  const allEdges = graph?.edges || [];
  const [flowInstance, setFlowInstance] = useState<ReactFlowInstance | null>(null);
  
  // 1. Resolve Topology
  const mode = resolveTopology(allNodes, allEdges);

  // 2. Map to React Flow
  const { nodes: rfNodes, edges: rfEdges } = useMemo(() => {
    if (allNodes.length === 0) return { nodes: [], edges: [] };
    return mapToReactFlowData(allNodes, allEdges, mode);
  }, [allNodes, allEdges, mode]);

  if (allNodes.length === 0) {
    return <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-3)' }}>No evidence graph available.</div>;
  }

  return (
    <div className="graphCanvas">
      
      {/* Header */}
      <div className="graphHeader">
        <h2 className="graphHeaderTitle">Evidence map</h2>
        <div className="graphHeaderMeta">
          {allNodes.length} nodes and {allEdges.length} relationships
        </div>
      </div>

      <div className="graphGuide" aria-hidden="true">
        <div className="graphGuideTitle">How to read</div>
        <div className="graphGuideRow">
          <span className="graphGuideDot" style={{ backgroundColor: '#f87171' }} />
          Start with risk or finding cards.
        </div>
        <div className="graphGuideRow">
          <span className="graphGuideDot" style={{ backgroundColor: '#fb923c' }} />
          Follow arrows to supporting evidence.
        </div>
        <div className="graphGuideRow">
          <span className="graphGuideDot" style={{ backgroundColor: '#60a5fa' }} />
          Dashed links add policy or discussion context.
        </div>
      </div>

      {/* Top Right Controls */}
      <div className="graphControls">
        <button className="graphControlBtn" onClick={() => flowInstance?.fitView({ padding: 0.2, duration: 400 })}>
          Fit view
        </button>
        <button className="graphControlBtn" aria-label="Zoom out" onClick={() => flowInstance?.zoomOut({ duration: 200 })}>
          -
        </button>
        <button className="graphControlBtn" aria-label="Zoom in" onClick={() => flowInstance?.zoomIn({ duration: 200 })}>
          +
        </button>
      </div>

      {/* Legend */}
      <div className="graphLegend" aria-hidden="true">
        <div className="graphLegendTitle">Legend</div>
        <div className="graphLegendList">
          {[
            { label: 'Source', desc: 'PRs, commits, alerts', color: '#a78bfa' },
            { label: 'Entity', desc: 'Packages and assets', color: '#fb923c' },
            { label: 'Finding', desc: 'Investigation output', color: '#f59e0b' },
            { label: 'Vulnerability', desc: 'Known risk signals', color: '#f87171' },
            { label: 'Discussion', desc: 'Human context', color: '#60a5fa' },
            { label: 'Policy', desc: 'Rules and controls', color: '#34d399' },
            { label: 'Evidence', desc: 'Supporting records', color: '#9ca3af' },
          ].map(item => (
            <div key={item.label} className="graphLegendItem">
              <span className="graphLegendDot" style={{ backgroundColor: item.color }} />
              <div>
                <div className="graphLegendLabel">{item.label}</div>
                <div className="graphLegendDesc">{item.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        defaultEdgeOptions={defaultEdgeOptions}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        onInit={setFlowInstance}
        nodesDraggable={false}
        nodesConnectable={false}
        panOnDrag
        panOnScroll={false}
        zoomOnScroll={false}
        zoomOnDoubleClick={false}
        preventScrolling={false}
      >
        <Background gap={20} color="rgba(255, 255, 255, 0.05)" size={2} />
      </ReactFlow>
    </div>
  );
}
