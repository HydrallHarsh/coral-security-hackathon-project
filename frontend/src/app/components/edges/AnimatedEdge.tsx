'use client';

import React, { useId, useMemo } from 'react';
import { EdgeLabelRenderer, EdgeProps } from '@xyflow/react';
import { motion } from 'motion/react';

type EdgeBeamData = { pathOffset?: number };

const GRADIENT_START = '#e8693f';
const GRADIENT_STOP = '#c4b5fd';

/** Beam timing & size — tune here */
const BEAM_DURATION_S = 7;
const BEAM_REPEAT_DELAY_S = 4;
const BEAM_STROKE_WIDTH = 3.5;
const TRACK_STROKE_WIDTH = 3.5;
/** Length of the glowing packet as a fraction of edge length */
const BEAM_PACKET_FRACTION = 0.14;

function delayFromId(id: string): number {
  let h = 0;
  for (let i = 0; i < id.length; i += 1) {
    h = (h * 31 + id.charCodeAt(i)) % 4500;
  }
  return h;
}

/** Quadratic curve — same family as Magic UI Animated Beam. */
function quadraticPath(
  sx: number,
  sy: number,
  tx: number,
  ty: number,
  curvature: number,
): string {
  const cx = (sx + tx) / 2;
  const cy = sy - curvature;
  return `M ${sx},${sy} Q ${cx},${cy} ${tx},${ty}`;
}

function quadLabelPoint(
  sx: number,
  sy: number,
  tx: number,
  ty: number,
  curvature: number,
): { x: number; y: number } {
  const cx = (sx + tx) / 2;
  const cy = sy - curvature;
  const t = 0.5;
  const mt = 1 - t;
  return {
    x: mt * mt * sx + 2 * mt * t * cx + t * t * tx,
    y: mt * mt * sy + 2 * mt * t * cy + t * t * ty,
  };
}

/**
 * Magic UI–style animated beam for React Flow edges.
 * @see https://magicui.design/docs/components/animated-beam
 */
export function AnimatedEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  markerEnd,
  label,
  data,
}: EdgeProps) {
  const pathOffset = (data as EdgeBeamData | undefined)?.pathOffset ?? 0;
  const gradId = useId().replace(/:/g, '');
  const beamDelay = useMemo(() => delayFromId(id), [id]);

  const curvature = 55 + Math.abs(pathOffset) * 0.35;
  const pathD = quadraticPath(sourceX, sourceY, targetX, targetY, curvature);
  const { x: labelX, y: labelY } = quadLabelPoint(
    sourceX,
    sourceY,
    targetX,
    targetY,
    curvature,
  );

  const dx = targetX - sourceX;
  const dy = targetY - sourceY;
  const pathLen = Math.hypot(dx, dy) || 1;
  const ux = dx / pathLen;
  const uy = dy / pathLen;
  const band = pathLen * BEAM_PACKET_FRACTION;

  const x1Start = sourceX;
  const y1Start = sourceY;
  const x2Start = sourceX + ux * band;
  const y2Start = sourceY + uy * band;
  const x1End = targetX - ux * band;
  const y1End = targetY - uy * band;
  const x2End = targetX;
  const y2End = targetY;

  return (
    <>
      <defs>
        <motion.linearGradient
          id={gradId}
          gradientUnits="userSpaceOnUse"
          initial={{
            x1: x1Start,
            y1: y1Start,
            x2: x2Start,
            y2: y2Start,
          }}
          animate={{
            x1: [x1Start, x1End],
            y1: [y1Start, y1End],
            x2: [x2Start, x2End],
            y2: [y2Start, y2End],
          }}
          transition={{
            delay: beamDelay / 1000,
            duration: BEAM_DURATION_S,
            ease: 'linear',
            repeat: Infinity,
            repeatDelay: BEAM_REPEAT_DELAY_S,
          }}
        >
          <stop stopColor={GRADIENT_START} stopOpacity="0" />
          <stop stopColor={GRADIENT_START} stopOpacity="0.9" />
          <stop offset="32.5%" stopColor={GRADIENT_STOP} stopOpacity="1" />
          <stop offset="100%" stopColor={GRADIENT_STOP} stopOpacity="0" />
        </motion.linearGradient>
      </defs>

      <path
        d={pathD}
        fill="none"
        stroke="rgba(167, 139, 250, 0.35)"
        strokeWidth={TRACK_STROKE_WIDTH}
        strokeLinecap="round"
        strokeOpacity={0.28}
        markerEnd={markerEnd as string}
      />

      <path
        d={pathD}
        fill="none"
        stroke={`url(#${gradId})`}
        strokeWidth={BEAM_STROKE_WIDTH}
        strokeLinecap="round"
        style={{ pointerEvents: 'none' }}
      />

      {label && (
        <EdgeLabelRenderer>
          <div
            className="edgeLabelPill"
            style={{
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
            }}
          >
            {label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
