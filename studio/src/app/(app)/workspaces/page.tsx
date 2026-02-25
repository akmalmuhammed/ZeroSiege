import Link from "next/link";
import { StatusBadge } from "@/components/status-badge";
import { formatDuration, formatUsd } from "@/lib/format";
import { listWorkspaces } from "@/lib/workspaces";

export default async function WorkspacesPage() {
  const workspaces = await listWorkspaces();

  return (
    <div className="view">
      <header className="page-header">
        <h1>Workspaces</h1>
        <p>Every run is stored as an immutable URL-first workspace with full audit artifacts.</p>
      </header>

      <section className="panel">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Workspace</th>
                <th>Target</th>
                <th>Status</th>
                <th>Duration</th>
                <th>Cost</th>
                <th>Workflow</th>
              </tr>
            </thead>
            <tbody>
              {workspaces.map((workspace) => (
                <tr key={workspace.name}>
                  <td>
                    <Link href={`/workspaces/${encodeURIComponent(workspace.name)}`} className="table-link">
                      {workspace.name}
                    </Link>
                  </td>
                  <td className="mono-wrap">{workspace.webUrl}</td>
                  <td>
                    <StatusBadge status={workspace.status} />
                  </td>
                  <td>{formatDuration(workspace.totalDurationMs)}</td>
                  <td>{formatUsd(workspace.totalCostUsd)}</td>
                  <td className="mono-wrap">{workspace.latestWorkflowId}</td>
                </tr>
              ))}
              {workspaces.length === 0 ? (
                <tr>
                  <td colSpan={6} className="muted">
                    No workspaces found yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
