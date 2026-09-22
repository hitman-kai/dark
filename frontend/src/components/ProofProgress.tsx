"use client";

import { useState, useEffect } from "react";

interface ProofProgressProps {
  stage: "idle" | "decoding" | "merkle" | "proving" | "claiming" | "withdrawing" | "done" | "error";
  error?: string;
}

const STAGES = [
  { key: "decoding", label: "Decoding claim code", step: "1/4" },
  { key: "proving", label: "Generating ZK proof", step: "2/4" },
  { key: "claiming", label: "Submitting claim credit", step: "3/4" },
  { key: "withdrawing", label: "Submitting withdrawal", step: "4/4" },
  { key: "done", label: "Claimed", step: "" },
];

// Map merkle stage to decoding for display (they're both part of step 1)
function effectiveStage(stage: string): string {
  return stage === "merkle" ? "decoding" : stage;
}

export default function ProofProgress({ stage, error }: ProofProgressProps) {
  const [dots, setDots] = useState("");

  useEffect(() => {
    if (stage === "idle" || stage === "done" || stage === "error") return;
    const interval = setInterval(() => {
      setDots((d) => (d.length >= 3 ? "" : d + "."));
    }, 400);
    return () => clearInterval(interval);
  }, [stage]);

  if (stage === "idle") return null;

  const mapped = effectiveStage(stage);

  return (
    <div className="arcade-panel arcade-glow">
      <div className="arcade-panel-header">
        <span className="arcade-dot animate-pulse" />
        <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">PROOF PIPELINE</span>
      </div>
      <div className="arcade-panel-body space-y-3">
        {STAGES.map(({ key, label, step }) => {
          const isActive = mapped === key;
          const isPast = STAGES.findIndex((s) => s.key === mapped) > STAGES.findIndex((s) => s.key === key);
          const isDone = stage === "done";

          return (
            <div key={key} className="flex items-center gap-3 text-sm">
              <span className={`font-mono font-bold ${isDone || isPast ? "text-[var(--accent)]" : isActive ? "text-[var(--accent)] animate-pulse" : "text-[rgba(224,224,224,0.15)]"}`}>
                {isDone || isPast ? "[+]" : isActive ? "[>]" : "[ ]"}
              </span>
              <span className="font-mono text-[10px] text-[rgba(224,224,224,0.25)] w-6">
                {step}
              </span>
              <span className={`font-mono text-[11px] ${isDone || isPast ? "text-[var(--text)]" : isActive ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.25)]"}`}>
                {label}{isActive ? dots : ""}
              </span>
            </div>
          );
        })}
        {stage === "error" && error && (
          <div className="mt-4 border-2 border-[rgba(255,0,68,0.3)] bg-[rgba(255,0,68,0.04)] px-5 py-3">
            <p className="text-xs text-[var(--danger)] font-semibold">{error}</p>
          </div>
        )}
      </div>
    </div>
  );
}
