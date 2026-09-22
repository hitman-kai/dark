"use client";

import { useState, useRef, useCallback } from "react";
import { QRCodeCanvas } from "qrcode.react";

interface CodeDisplayProps {
  code: string;
  label?: string;
}

export default function CodeDisplay({ code, label = "CLAIM CODE" }: CodeDisplayProps) {
  const [copied, setCopied] = useState(false);
  const qrRef = useRef<HTMLDivElement>(null);

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadQR = useCallback(() => {
    const canvas = qrRef.current?.querySelector("canvas");
    if (!canvas) return;
    const url = canvas.toDataURL("image/png");
    const a = document.createElement("a");
    a.href = url;
    a.download = "darkdrop-claim-qr.png";
    a.click();
  }, []);

  return (
    <div className="arcade-panel">
      <div className="arcade-panel-header">
        <span className="arcade-dot" />
        <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(0,255,65,0.6)]">{label}</span>
      </div>
      <div className="arcade-panel-body">
        <div className="flex flex-col sm:flex-row gap-4">
          {/* QR Code — dark themed */}
          <div ref={qrRef} className="shrink-0 self-center sm:self-start border-2 border-[var(--border)] p-2 bg-[#111] arcade-glow">
            <QRCodeCanvas
              value={code}
              size={120}
              bgColor="#111111"
              fgColor="#00ff41"
              level="L"
            />
          </div>
          {/* Code text */}
          <div className="flex-1 min-w-0">
            <div
              className="border-2 border-[var(--border-dim)] bg-[#030303] p-4 cursor-pointer hover:border-[var(--border)] transition-colors shadow-[var(--shadow-inset)]"
              onClick={copyToClipboard}
              title="Click to copy"
            >
              <p className="break-all font-mono text-[11px] leading-relaxed text-[var(--accent)]">{code}</p>
            </div>
          </div>
        </div>
        <div className="mt-3 flex gap-2">
          <button
            type="button"
            onClick={copyToClipboard}
            className="flex-1 py-2.5 font-mono text-[9px] tracking-[0.15em]"
          >
            {copied ? "COPIED" : "COPY CODE"}
          </button>
          <button
            type="button"
            onClick={downloadQR}
            className="flex-1 py-2.5 font-mono text-[9px] tracking-[0.15em]"
          >
            DOWNLOAD QR
          </button>
        </div>
      </div>
    </div>
  );
}
