import fs from "node:fs/promises";
import { NextResponse } from "next/server";
import { studioEnv } from "@/lib/env";

export async function GET(): Promise<NextResponse> {
  const checks = {
    auditLogs: false,
    repos: false,
    configs: false,
    targets: false,
  };
  try {
    await fs.access(studioEnv.auditLogsDir);
    checks.auditLogs = true;
  } catch {
    checks.auditLogs = false;
  }
  try {
    await fs.access(studioEnv.reposDir);
    checks.repos = true;
  } catch {
    checks.repos = false;
  }
  try {
    await fs.access(studioEnv.configsDir);
    checks.configs = true;
  } catch {
    checks.configs = false;
  }
  try {
    await fs.access(studioEnv.targetsDir);
    checks.targets = true;
  } catch {
    checks.targets = false;
  }
  return NextResponse.json({
    ok: true,
    temporalAddress: studioEnv.temporalAddress,
    checks,
    ts: new Date().toISOString(),
  });
}
