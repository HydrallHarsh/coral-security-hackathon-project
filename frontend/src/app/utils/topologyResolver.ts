export type LayoutMode = 'compact-chain' | 'investigation-dag' | 'hub' | 'cluster';

export type GraphNodeRef = { id: string; type: string };
export type GraphEdgeRef = { from: string; to: string };

export function resolveTopology(nodes: GraphNodeRef[], edges: GraphEdgeRef[]): LayoutMode {
  if (!nodes || nodes.length === 0) return 'compact-chain';
  if (nodes.length <= 2) return 'compact-chain'; // 1 or 2 nodes is always a simple chain

  // Build adjacency list and calculate degrees
  const adj = new Map<string, string[]>();
  const inDegree = new Map<string, number>();
  const outDegree = new Map<string, number>();

  nodes.forEach(n => {
    adj.set(n.id, []);
    inDegree.set(n.id, 0);
    outDegree.set(n.id, 0);
  });

  edges.forEach(e => {
    if (adj.has(e.from) && adj.has(e.to)) {
      adj.get(e.from)!.push(e.to);
      outDegree.set(e.from, outDegree.get(e.from)! + 1);
      inDegree.set(e.to, inDegree.get(e.to)! + 1);
    }
  });

  let maxDegree = 0;
  let maxInDegree = 0;
  let maxOutDegree = 0;

  nodes.forEach(n => {
    const inD = inDegree.get(n.id)!;
    const outD = outDegree.get(n.id)!;
    const totalD = inD + outD;
    
    if (totalD > maxDegree) maxDegree = totalD;
    if (inD > maxInDegree) maxInDegree = inD;
    if (outD > maxOutDegree) maxOutDegree = outD;
  });

  // Check connectivity (are there multiple disconnected clusters?)
  // Using BFS starting from the first node
  const visited = new Set<string>();
  if (nodes.length > 0) {
    const queue = [nodes[0].id];
    visited.add(nodes[0].id);
    
    // Convert to undirected for connectivity check
    const undirectedAdj = new Map<string, string[]>();
    nodes.forEach(n => undirectedAdj.set(n.id, []));
    edges.forEach(e => {
      if (undirectedAdj.has(e.from) && undirectedAdj.has(e.to)) {
        undirectedAdj.get(e.from)!.push(e.to);
        undirectedAdj.get(e.to)!.push(e.from);
      }
    });

    while (queue.length > 0) {
      const curr = queue.shift()!;
      for (const neighbor of undirectedAdj.get(curr) || []) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push(neighbor);
        }
      }
    }
  }

  // If not all nodes are visited, we have disconnected clusters
  if (visited.size < nodes.length) {
    return 'cluster';
  }

  // Evaluate Topology Rules
  
  // Rule 1: High connectivity hub (e.g., 3 evidences pointing to 1 finding)
  if (maxInDegree >= 3 || maxOutDegree >= 3) {
    return 'hub';
  }

  // Rule 2: Simple linear chain (A -> B -> C -> D)
  // Max degree is 2, and no branching (max in/out degree <= 1)
  if (nodes.length <= 4 && maxDegree <= 2 && maxInDegree <= 1 && maxOutDegree <= 1) {
    return 'compact-chain';
  }

  // Fallback: Medium complexity directional graph
  return 'investigation-dag';
}
