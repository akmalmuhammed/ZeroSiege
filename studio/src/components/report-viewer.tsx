"use client";

import { useMemo, useState } from "react";

interface Props {
  markdown: string | null;
}

export function ReportViewer({ markdown }: Props) {
  const [copied, setCopied] = useState(false);
  const text = markdown || "No report generated yet.";
  const lineCount = useMemo(() => text.split(/\r?\n/).length, [text]);

  async function copyReport(): Promise<void> {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  }

  return (
    <section className="panel report-panel">
      <div className="row space-between">
        <h3>Assessment Report</h3>
        <button
          className="ghost-button"
          type="button"
          disabled={!markdown}
          onClick={copyReport}
        >
          {copied ? "Copied" : "Copy Markdown"}
        </button>
      </div>
      <p className="muted">{lineCount} lines</p>
      <pre className="report-pre">{text}</pre>
    </section>
  );
}
