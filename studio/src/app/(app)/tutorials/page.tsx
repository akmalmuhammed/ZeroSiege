import { listSampleReports } from "@/lib/workspaces";

const TUTORIALS = [
  {
    title: "Environment Setup",
    steps: [
      "Set ANTHROPIC_API_KEY / CLAUDE_CODE_OAUTH_TOKEN in root .env, or provide a run-only key in Launch Scan.",
      "Confirm Docker, Temporal, worker, and Studio containers are healthy.",
      "Ensure targets/ volume is mounted so harvested URL workspaces persist.",
    ],
  },
  {
    title: "Config Builder Workflow",
    steps: [
      "Create config YAML in configs/ with authentication and scope rules.",
      "Use avoid/focus rules to constrain legal attack boundaries.",
      "Tune url_harvest limits when aggressive discovery needs tighter caps.",
      "Set pipeline.retry_preset/subscription for long rate-limit windows.",
    ],
  },
  {
    title: "Launch URL-first Runs",
    steps: [
      "Use Launch Scan and provide target URL.",
      "Choose AI Credential Source and optionally paste a run-only key/token.",
      "Optionally supply manual source as git URL or local repo name.",
      "Use a brand-new workspace each run (resume is intentionally disabled).",
    ],
  },
  {
    title: "Live Operations",
    steps: [
      "Track phase transitions and current agent in workspace details.",
      "Watch completed agent count to estimate remaining runtime.",
      "Inspect workflow log tail to debug retries and recoveries.",
    ],
  },
  {
    title: "Report and Evidence",
    steps: [
      "Review finding index by section and severity.",
      "Copy markdown report to ticketing, GRC, or audit workflows.",
      "Validate final severity and exploit impact with human review.",
    ],
  },
  {
    title: "Safety + Legal Guardrails",
    steps: [
      "Only run on authorized targets in staging/local environments.",
      "Never run Shannon against production systems.",
      "Treat exploit code in reports as sensitive security material.",
    ],
  },
];

export default async function TutorialsPage() {
  const sampleReports = await listSampleReports();

  return (
    <div className="view">
      <header className="page-header">
        <h1>Feature Tutorials</h1>
        <p>Step-by-step operational guidance for every major Shannon Studio feature.</p>
      </header>

      <section className="tutorial-grid">
        {TUTORIALS.map((tutorial) => (
          <article key={tutorial.title} className="panel tutorial-card">
            <h3>{tutorial.title}</h3>
            <ol>
              {tutorial.steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
          </article>
        ))}
      </section>

      <section className="panel">
        <h3>Sample Reports for Hands-on Learning</h3>
        <p className="muted">
          Use these bundled reports to train stakeholders before running against your own app.
        </p>
        <ul>
          {sampleReports.map((report) => (
            <li key={report}>
              <code>{report}</code>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
