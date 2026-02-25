import Link from "next/link";
import { StatusBadge } from "@/components/status-badge";
import { formatDuration, formatUsd } from "@/lib/format";
import { listWorkspaces } from "@/lib/workspaces";

export default async function DashboardPage() {
  const workspaces = await listWorkspaces();
  const running = workspaces.filter((workspace) => workspace.status === "in-progress").length;
  const failed = workspaces.filter((workspace) => workspace.status === "failed").length;
  const completed = workspaces.filter((workspace) => workspace.status === "completed").length;
  const totalCost = workspaces.reduce(
    (sum, workspace) => sum + workspace.totalCostUsd,
    0
  );

  return (
    <div className="view">
      <header className="page-header">
        <h1>Security Control Plane</h1>
        <p>Operate Shannon like a SaaS platform: launch, monitor, and report from one console.</p>
      </header>

      <section className="stats-grid">
        <article className="metric-card">
          <p className="metric-label">Active</p>
          <p className="metric-value">{running}</p>
        </article>
        <article className="metric-card">
          <p className="metric-label">Completed</p>
          <p className="metric-value">{completed}</p>
        </article>
        <article className="metric-card">
          <p className="metric-label">Failed</p>
          <p className="metric-value">{failed}</p>
        </article>
        <article className="metric-card">
          <p className="metric-label">Spend</p>
          <p className="metric-value">{formatUsd(totalCost)}</p>
        </article>
      </section>

      <section className="grid-two">
        <article className="panel">
          <div className="row space-between">
            <h3>Latest Workspaces</h3>
            <Link href="/workspaces" className="table-link">
              View all
            </Link>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Workspace</th>
                  <th>Status</th>
                  <th>Duration</th>
                  <th>Cost</th>
                </tr>
              </thead>
              <tbody>
                {workspaces.slice(0, 8).map((workspace) => (
                  <tr key={workspace.name}>
                    <td>
                      <Link
                        href={`/workspaces/${encodeURIComponent(workspace.name)}`}
                        className="table-link"
                      >
                        {workspace.name}
                      </Link>
                    </td>
                    <td>
                      <StatusBadge status={workspace.status} />
                    </td>
                    <td>{formatDuration(workspace.totalDurationMs)}</td>
                    <td>{formatUsd(workspace.totalCostUsd)}</td>
                  </tr>
                ))}
                {workspaces.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="muted">
                      No workspaces yet. Launch your first scan.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </article>

        <article className="panel tutorial-card">
          <h3>Quick Start Tutorial</h3>
          <ol>
            <li>Open `Launch Scan` and set target URL.</li>
            <li>Optionally add manual source (git URL or local repo name).</li>
            <li>Use a new named workspace for each run (resume disabled).</li>
            <li>Track live phase + agent execution in workspace details.</li>
            <li>Review exploit evidence and export report markdown.</li>
          </ol>
          <p className="muted">
            Use `/tutorials` for full feature-by-feature guidance.
          </p>
        </article>
      </section>
    </div>
  );
}
