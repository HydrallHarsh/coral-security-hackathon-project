import React from 'react';
import { BaseEdge, EdgeLabelRenderer, EdgeProps, getSmoothStepPath } from '@xyflow/react';

export function AnimatedEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  markerEnd,
  label,
  data,
}: EdgeProps) {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    borderRadius: 0,
  });

  const edgeKind = typeof (data as { kind?: string } | undefined)?.kind === 'string'
    ? (data as { kind?: string }).kind!.toLowerCase()
    : '';
  const labelText = typeof label === 'string' ? label.toLowerCase() : '';
  const isContext = edgeKind.includes('policy') || edgeKind.includes('discuss') || labelText.includes('policy') || labelText.includes('discuss');
  const isDashed = isContext || labelText.includes('context');
  const strokeDasharray = isDashed ? '4 4' : 'none';
  const strokeColor = isContext ? 'rgba(96, 165, 250, 0.4)' : 'rgba(255, 255, 255, 0.25)';

  return (
    <>
      <BaseEdge path={edgePath} markerEnd={markerEnd} style={{ ...style, strokeWidth: 1.5, stroke: strokeColor, strokeDasharray }} />
      {label && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              background: 'rgba(9, 9, 11, 0.9)',
              padding: '2px 6px',
              fontSize: '0.65rem',
              fontFamily: 'var(--font-mono)',
              color: 'var(--text-3)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '6px',
              pointerEvents: 'none',
              zIndex: 10,
            }}
          >
            {label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
