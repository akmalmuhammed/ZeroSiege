import fs from "node:fs/promises";
import path from "node:path";
import { studioEnv } from "@/lib/env";
import { assertRepoName, assertWorkspaceName, joinSafe } from "@/lib/paths";
import type { SessionFile, WorkspaceDetail, WorkspaceSummary } from "@/lib/types";

async function exists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function parseJson<T>(value: string): T {
  return JSON.parse(value) as T;
}

export function sanitizeHostname(url: string): string {
  return new URL(url).hostname.replace(/[^a-zA-Z0-9-]/g, "-");
}

export function getLatestWorkflowId(session: SessionFile["session"]): string {
  if (session.resumeAttempts && session.resumeAttempts.length > 0) {
    return session.resumeAttempts[session.resumeAttempts.length - 1].workflowId;
  }
  return session.originalWorkflowId || session.id;
}

function toSummary(name: string, file: SessionFile): WorkspaceSummary {
  return {
    name,
    status: file.session.status,
    webUrl: file.session.webUrl,
    createdAt: file.session.createdAt,
    completedAt: file.session.completedAt,
    totalCostUsd: file.metrics.total_cost_usd,
    totalDurationMs: file.metrics.total_duration_ms,
    latestWorkflowId: getLatestWorkflowId(file.session),
    resumable: file.session.resumeSupported === true && file.session.status !== "completed",
  };
}

function inferSeverity(title: string, section: string): string {
  const text = `${title} ${section}`.toLowerCase();
  if (text.includes("critical")) return "critical";
  if (text.includes("high")) return "high";
  if (text.includes("medium")) return "medium";
  if (text.includes("low")) return "low";
  return "unknown";
}

function parseFindings(reportMarkdown: string): WorkspaceDetail["findings"] {
  const findings: WorkspaceDetail["findings"] = [];
  const lines = reportMarkdown.split(/\r?\n/);
  let section = "General";
  for (const line of lines) {
    if (line.startsWith("## ")) {
      section = line.slice(3).trim();
    }
    if (line.startsWith("### ")) {
      const title = line.slice(4).trim();
      findings.push({
        title,
        section,
        severity: inferSeverity(title, section),
      });
    }
  }
  return findings;
}

export async function listWorkspaces(): Promise<WorkspaceSummary[]> {
  const entries = await fs
    .readdir(studioEnv.auditLogsDir, { withFileTypes: true })
    .catch(() => []);

  const summaries: WorkspaceSummary[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const name = entry.name;
    const sessionPath = path.join(studioEnv.auditLogsDir, name, "session.json");
    if (!(await exists(sessionPath))) continue;
    const raw = await fs.readFile(sessionPath, "utf8");
    const file = parseJson<SessionFile>(raw);
    summaries.push(toSummary(name, file));
  }

  return summaries.sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );
}

export async function getWorkspace(workspace: string): Promise<WorkspaceDetail> {
  const name = assertWorkspaceName(workspace);
  const workspaceDir = joinSafe(studioEnv.auditLogsDir, name);
  const sessionPath = path.join(workspaceDir, "session.json");

  if (!(await exists(sessionPath))) {
    throw new Error(`Workspace not found: ${name}`);
  }

  const session = parseJson<SessionFile>(await fs.readFile(sessionPath, "utf8"));
  const summary = toSummary(name, session);

  const reportPath = path.join(
    workspaceDir,
    "deliverables",
    "comprehensive_security_assessment_report.md"
  );
  const reportMarkdown = (await exists(reportPath))
    ? await fs.readFile(reportPath, "utf8")
    : null;

  const workflowLogPath = path.join(workspaceDir, "workflow.log");
  const workflowLogTail = (await exists(workflowLogPath))
    ? (await fs.readFile(workflowLogPath, "utf8")).split(/\r?\n/).slice(-220)
    : [];

  return {
    ...summary,
    session: session.session,
    metrics: session.metrics,
    reportPath: (await exists(reportPath)) ? reportPath : null,
    reportMarkdown,
    findings: reportMarkdown ? parseFindings(reportMarkdown) : [],
    workflowLogTail,
  };
}

export async function readReport(workspace: string): Promise<string | null> {
  const name = assertWorkspaceName(workspace);
  const reportPath = path.join(
    studioEnv.auditLogsDir,
    name,
    "deliverables",
    "comprehensive_security_assessment_report.md"
  );
  if (!(await exists(reportPath))) {
    return null;
  }
  return fs.readFile(reportPath, "utf8");
}

export async function readWorkflowLogTail(
  workspace: string,
  lines: number = 250
): Promise<string[]> {
  const name = assertWorkspaceName(workspace);
  const workflowLogPath = path.join(studioEnv.auditLogsDir, name, "workflow.log");
  if (!(await exists(workflowLogPath))) {
    return [];
  }
  const content = await fs.readFile(workflowLogPath, "utf8");
  return content.split(/\r?\n/).slice(-lines);
}

export async function listRepos(): Promise<string[]> {
  const entries = await fs
    .readdir(studioEnv.reposDir, { withFileTypes: true })
    .catch(() => []);
  const repos: string[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const repoName = entry.name;
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(repoName)) continue;
    const gitDir = path.join(studioEnv.reposDir, repoName, ".git");
    if (await exists(gitDir)) {
      repos.push(repoName);
    }
  }
  return repos.sort();
}

export async function listConfigFiles(): Promise<string[]> {
  const entries = await fs
    .readdir(studioEnv.configsDir, { withFileTypes: true })
    .catch(() => []);
  return entries
    .filter((entry) => entry.isFile() && /\.(ya?ml)$/i.test(entry.name))
    .map((entry) => entry.name)
    .sort();
}

export async function readSessionFile(workspace: string): Promise<SessionFile> {
  const name = assertWorkspaceName(workspace);
  const sessionPath = path.join(studioEnv.auditLogsDir, name, "session.json");
  const raw = await fs.readFile(sessionPath, "utf8");
  return parseJson<SessionFile>(raw);
}

export function buildRepoContainerPath(repoName: string): string {
  return `/repos/${assertRepoName(repoName)}`;
}

export function buildWorkerConfigPath(configFile: string): string {
  const configName = path.basename(configFile);
  return `/app/configs/${configName}`;
}

export async function listSampleReports(): Promise<string[]> {
  const entries = await fs
    .readdir(studioEnv.sampleReportsDir, { withFileTypes: true })
    .catch(() => []);
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
    .map((entry) => entry.name)
    .sort();
}
