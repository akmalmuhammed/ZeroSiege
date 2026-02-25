"use client";

import { useEffect, useState } from "react";
import { StatusBadge } from "@/components/status-badge";

interface Props {
  workflowId: string;
}

interface WorkflowProgressResponse {
  ok: boolean;
  status?: string;
  progress?: {
    currentPhase?: string | null;
    currentAgent?: string | null;
    completedAgents?: string[];
    elapsedMs?: number;
  };
  error?: string;
}

function prettyDuration(ms: number | undefined): string {
  if (!ms) return "0s";
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

export function LiveWorkflowCard({ workflowId }: Props) {
  const [data, setData] = useState<WorkflowProgressResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    async function load(): Promise<void> {
      const response = await fetch(`/api/scans/${encodeURIComponent(workflowId)}/progress`, {
        cache: "no-store",
      });
      const payload = (await response.json().catch(() => null)) as
        | WorkflowProgressResponse
        | null;

      if (!mounted) return;
      if (!response.ok || !payload?.ok) {
        setError(payload?.error || "Unable to fetch progress");
        return;
      }
      setError(null);
      setData(payload);
    }

    const timer = setInterval(load, 8000);
    load();

    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, [workflowId]);

  return (
    <section className="panel live-panel">
      <div className="row space-between">
        <h3>Live Workflow</h3>
        <StatusBadge status={data?.status || "unknown"} />
      </div>
      <p className="mono-wrap">{workflowId}</p>
      {error ? <p className="error-text">{error}</p> : null}
      <div className="live-grid">
        <article>
          <p className="kicker">Phase</p>
          <p>{data?.progress?.currentPhase || "Waiting"}</p>
        </article>
        <article>
          <p className="kicker">Agent</p>
          <p>{data?.progress?.currentAgent || "N/A"}</p>
        </article>
        <article>
          <p className="kicker">Completed Agents</p>
          <p>{data?.progress?.completedAgents?.length ?? 0} / 13</p>
        </article>
        <article>
          <p className="kicker">Elapsed</p>
          <p>{prettyDuration(data?.progress?.elapsedMs)}</p>
        </article>
      </div>
    </section>
  );
}
