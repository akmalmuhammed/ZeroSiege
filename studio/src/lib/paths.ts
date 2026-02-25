import path from "node:path";

const WORKSPACE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const REPO_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function assertPattern(value: string, pattern: RegExp, label: string): string {
  if (!pattern.test(value)) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return value;
}

export function assertWorkspaceName(workspace: string): string {
  return assertPattern(workspace, WORKSPACE_PATTERN, "workspace");
}

export function assertRepoName(repo: string): string {
  return assertPattern(repo, REPO_PATTERN, "repo");
}

export function joinSafe(root: string, child: string): string {
  const resolved = path.resolve(root, child);
  const normalizedRoot = path.resolve(root);
  if (!resolved.startsWith(normalizedRoot)) {
    throw new Error("Path traversal blocked");
  }
  return resolved;
}
