"use client";

import { useState } from "react";
import type { FormEvent } from "react";
import { useRouter } from "next/navigation";

interface Props {
  repoHints?: string[];
  configFiles: string[];
}

export function ScanLaunchForm({ repoHints = [], configFiles }: Props) {
  const router = useRouter();
  const [webUrl, setWebUrl] = useState("");
  const [manualSource, setManualSource] = useState("");
  const [workspace, setWorkspace] = useState("");
  const [configFile, setConfigFile] = useState("");
  const [pipelineTestingMode, setPipelineTestingMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setLoading(true);
    setError(null);

    const response = await fetch("/api/scans/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        webUrl,
        manualSource: manualSource || undefined,
        workspace: workspace || undefined,
        configFile: configFile || undefined,
        pipelineTestingMode,
      }),
    });

    const payload = (await response.json().catch(() => null)) as
      | { ok?: boolean; error?: string; workspace?: string }
      | null;

    setLoading(false);
    if (!response.ok || !payload?.ok || !payload.workspace) {
      setError(payload?.error || "Failed to launch workflow");
      return;
    }

    router.push(`/workspaces/${encodeURIComponent(payload.workspace)}`);
    router.refresh();
  }

  return (
    <form className="panel" onSubmit={onSubmit}>
      <h2>Launch Scan</h2>
      <p className="muted">Start a new URL-first run. Existing workspace names cannot be resumed.</p>
      <label className="field">
        Target URL
        <input
          type="url"
          required
          placeholder="https://staging.example.com"
          value={webUrl}
          onChange={(event) => setWebUrl(event.target.value)}
        />
      </label>
      <label className="field">
        Manual Source (optional)
        <input
          value={manualSource}
          onChange={(event) => setManualSource(event.target.value)}
          placeholder="https://github.com/org/repo.git or local repo-name"
          list="repo-hints"
        />
        {repoHints.length > 0 ? (
          <datalist id="repo-hints">
            {repoHints.map((repo) => (
              <option key={repo} value={repo} />
            ))}
          </datalist>
        ) : null}
      </label>
      <label className="field">
        Workspace Name (optional)
        <input
          value={workspace}
          onChange={(event) => setWorkspace(event.target.value)}
          placeholder="q1-security-audit"
        />
      </label>
      <label className="field">
        Config File (optional)
        <select value={configFile} onChange={(event) => setConfigFile(event.target.value)}>
          <option value="">No config file</option>
          {configFiles.map((file) => (
            <option key={file} value={file}>
              {file}
            </option>
          ))}
        </select>
      </label>
      <label className="checkbox-row">
        <input
          type="checkbox"
          checked={pipelineTestingMode}
          onChange={(event) => setPipelineTestingMode(event.target.checked)}
        />
        Run in pipeline testing mode (minimal prompts and faster retries)
      </label>
      {error ? <p className="error-text">{error}</p> : null}
      <button className="primary-button" type="submit" disabled={loading}>
        {loading ? "Starting workflow..." : "Start Workflow"}
      </button>
    </form>
  );
}
