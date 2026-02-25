import { ScanLaunchForm } from "@/components/scan-launch-form";
import { listConfigFiles, listRepos } from "@/lib/workspaces";

export default async function NewScanPage() {
  const [repoHints, configFiles] = await Promise.all([listRepos(), listConfigFiles()]);

  return (
    <div className="view">
      <header className="page-header">
        <h1>Launch Autonomous Pentest</h1>
        <p>
          Configure target URL and optional source hints, then start a full five-phase Shannon pipeline with a
          single action.
        </p>
      </header>
      <section className="grid-two">
        <ScanLaunchForm repoHints={repoHints} configFiles={configFiles} />
        <article className="panel tutorial-card">
          <h3>Feature Tutorial: Launch Workflow</h3>
          <ol>
            <li>Use staging URLs only. Do not run against production.</li>
            <li>Optionally provide a git URL or local repo name to enrich source context.</li>
            <li>Supply a new workspace name (URL-first mode does not support resume).</li>
            <li>Add config YAML for auth flows, scope rules, and URL harvest tuning.</li>
            <li>Turn on pipeline testing only for fast prompt iteration.</li>
          </ol>
        </article>
      </section>
    </div>
  );
}
