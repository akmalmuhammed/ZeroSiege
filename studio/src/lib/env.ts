import path from "node:path";

function fromRoot(relative: string): string {
  return path.resolve(process.cwd(), "..", relative);
}

export const studioEnv = {
  adminUsername: process.env.STUDIO_ADMIN_USERNAME || "admin",
  adminPassword: process.env.STUDIO_ADMIN_PASSWORD || "change-me-now",
  cookieSecure: process.env.STUDIO_COOKIE_SECURE === "true",
  sessionSecret:
    process.env.STUDIO_SESSION_SECRET || "insecure-dev-secret-change-me",
  temporalAddress: process.env.TEMPORAL_ADDRESS || "temporal:7233",
  auditLogsDir: process.env.STUDIO_AUDIT_LOGS_DIR || fromRoot("audit-logs"),
  reposDir: process.env.STUDIO_REPOS_DIR || fromRoot("repos"),
  configsDir: process.env.STUDIO_CONFIGS_DIR || fromRoot("configs"),
  runtimeSecretsDir:
    process.env.STUDIO_RUNTIME_SECRETS_DIR ||
    path.join(process.env.STUDIO_CONFIGS_DIR || fromRoot("configs"), ".runtime-secrets"),
  sampleReportsDir:
    process.env.STUDIO_SAMPLE_REPORTS_DIR || fromRoot("sample-reports"),
  targetsDir: process.env.STUDIO_TARGETS_DIR || fromRoot("targets"),
};
