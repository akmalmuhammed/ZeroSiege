import { notFound } from "next/navigation";
import { LiveWorkflowCard } from "@/components/live-workflow-card";
import { ReportViewer } from "@/components/report-viewer";
import { StatusBadge } from "@/components/status-badge";
import { formatDuration, formatUsd } from "@/lib/format";
import { getWorkspace } from "@/lib/workspaces";

interface PageProps {
  params: Promise<{ workspace: string }>;
}

export default async function WorkspacePage({
  params,
}: PageProps) {
  const { workspace } = await params;

  let details: Awaited<ReturnType<typeof getWorkspace>>;
  try {
    details = await getWorkspace(workspace);
  } catch {
    notFound();
  }

  return (
    <div className="view">
      <header className="page-header">
        <div className="row space-between">
          <h1>{details.name}</h1>
          <StatusBadge status={details.status} />
        </div>
        <p className="mono-wrap">{details.webUrl}</p>
      </header>

      <section className="stats-grid">
        <article className="metric-card">
          <p className="metric-label">Cost</p>
          <p className="metric-value">{formatUsd(details.totalCostUsd)}</p>
        </article>
        <article className="metric-card">
          <p className="metric-label">Duration</p>
          <p className="metric-value">{formatDuration(details.totalDurationMs)}</p>
        </article>
        <article className="metric-card">
          <p className="metric-label">Findings</p>
          <p className="metric-value">{details.findings.length}</p>
        </article>
        <article className="metric-card">
          <p className="metric-label">Workflow ID</p>
          <p className="metric-value mono-wrap">{details.latestWorkflowId}</p>
        </article>
      </section>

      <LiveWorkflowCard workflowId={details.latestWorkflowId} />

      <section className="grid-two">
        <article className="panel">
          <h3>Exploit Findings Index</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Section</th>
                </tr>
              </thead>
              <tbody>
                {details.findings.map((finding) => (
                  <tr key={`${finding.section}-${finding.title}`}>
                    <td>{finding.title}</td>
                    <td>{finding.severity}</td>
                    <td>{finding.section}</td>
                  </tr>
                ))}
                {details.findings.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="muted">
                      Findings will appear once exploitation evidence is generated.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </article>
        <article className="panel tutorial-card">
          <h3>Feature Tutorial: Report Review</h3>
          <ol>
            <li>Start from `Exploit Findings Index` to triage high-impact issues first.</li>
            <li>Open workflow logs to verify each proof path and agent decision.</li>
            <li>Use copied markdown in tickets or compliance evidence stores.</li>
            <li>Use a new workspace for reruns; URL-first mode intentionally disables resume.</li>
          </ol>
        </article>
      </section>

      <ReportViewer markdown={details.reportMarkdown} />

      <section className="panel">
        <div className="row space-between">
          <h3>Workflow Log Tail</h3>
          <p className="muted">{details.workflowLogTail.length} lines loaded</p>
        </div>
        <pre className="log-pre">{details.workflowLogTail.join("\n")}</pre>
      </section>
    </div>
  );
}
