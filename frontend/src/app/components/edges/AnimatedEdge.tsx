import React from 'react';
import { EdgeLabelRenderer, EdgeProps, getSmoothStepPath } from '@xyflow/react';

/**
 * Zapier / n8n style lightning-bolt animated edge.
 *
 * 3 layers:
 *   1. Faint "track" — always visible base line
 *   2. Blurred "aura" — purple glow dash that moves (CSS class .bolt-aura)
 *   3. Bright "core" — white dash on top (CSS class .bolt-core)
 *
 * The animation keyframes live in globals.css so they actually work.
 */
export function AnimatedEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  markerEnd,
  label,
}: EdgeProps) {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition,
    borderRadius: 16,
  });

  return (
    <>
      {/* SVG filter for the glow */}
      <defs>
        <filter id={`glow-${id}`} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3.5" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* 1 — faint track */}
      <path
        d={edgePath}
        fill="none"
        stroke="rgba(255,255,255,0.07)"
        strokeWidth={1.5}
      />

      {/* 2 — glow aura */}
      <path
        className="bolt-aura"
        d={edgePath}
        fill="none"
        stroke="rgba(167,139,250,0.4)"
        strokeWidth={5}
        strokeDasharray="20 180"
        strokeLinecap="round"
        filter={`url(#glow-${id})`}
      />

      {/* 3 — bright core */}
      <path
        className="bolt-core"
        d={edgePath}
        fill="none"
        stroke="rgba(255,255,255,0.85)"
        strokeWidth={1.5}
        strokeDasharray="20 180"
        strokeLinecap="round"
        markerEnd={markerEnd as string}
      />

      {label && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              background: 'rgba(14,13,19,0.95)',
              padding: '3px 8px',
              fontSize: '0.65rem',
              fontFamily: 'var(--font-mono)',
              color: 'rgba(200,196,215,0.8)',
              pointerEvents: 'none',
              zIndex: 10,
              borderRadius: 4,
              border: '1px solid rgba(255,255,255,0.06)',
              whiteSpace: 'nowrap',
            }}
          >
            {label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
