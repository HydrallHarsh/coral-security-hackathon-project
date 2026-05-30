"use client";

import { AnimatePresence, motion } from "motion/react";
import type { InvestigationMode } from "../utils/flavor";

type Props = {
  text: string;
  mode?: InvestigationMode;
};

export function LoadingQuipDisplay({ text, mode = "general" }: Props) {
  return (
    <div
      className={`loadQuipWrap mode-${mode}`}
      aria-live="polite"
      aria-atomic="true"
    >
      <span className="loadQuipMark" aria-hidden="true">
        &ldquo;
      </span>
      <div className="loadQuipBody">
        <AnimatePresence mode="wait" initial={false}>
          <motion.p
            key={text}
            className="loadSubtitle"
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -3 }}
            transition={{ duration: 0.38, ease: [0.22, 1, 0.36, 1] }}
          >
            {text}
          </motion.p>
        </AnimatePresence>
        <span className="loadQuipShimmer" aria-hidden="true" />
      </div>
    </div>
  );
}
