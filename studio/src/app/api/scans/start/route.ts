import fs from "node:fs/promises";
import path from "node:path";
import { NextResponse, type NextRequest } from "next/server";
import { requireApiAuth } from "@/lib/api-auth";
import { studioEnv } from "@/lib/env";
import { assertWorkspaceName } from "@/lib/paths";
import {
  makeWorkflowId,
  startPipelineWorkflow,
} from "@/lib/temporal";
import type { PipelineInputDto } from "@/lib/types";
import {
  buildWorkerConfigPath,
  sanitizeHostname,
} from "@/lib/workspaces";

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function isValidWebUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function isValidManualSource(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  if (trimmed.startsWith("https://")) {
    return /^https:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/.test(
      trimmed
    );
  }
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(trimmed);
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const unauthorized = requireApiAuth(request);
  if (unauthorized) {
    return unauthorized;
  }

  const body = (await request.json().catch(() => null)) as PipelineInputDto | null;
  if (!body) {
    return NextResponse.json({ ok: false, error: "Invalid JSON body" }, { status: 400 });
  }

  const webUrl = body.webUrl?.trim();
  if (!webUrl) {
    return NextResponse.json({ ok: false, error: "webUrl is required" }, { status: 400 });
  }

  if (!isValidWebUrl(webUrl)) {
    return NextResponse.json({ ok: false, error: "Invalid webUrl" }, { status: 400 });
  }

  const manualSource = body.manualSource?.trim();
  if (manualSource && !isValidManualSource(manualSource)) {
    return NextResponse.json(
      {
        ok: false,
        error:
          "Invalid manualSource. Use https://<host>/<org>/<repo>(.git) or local repo name.",
      },
      { status: 400 }
    );
  }

  let workflowId: string;
  let sessionId: string;
  const mode: "new" = "new";

  const requestedWorkspace = body.workspace?.trim();
  if (requestedWorkspace) {
    const workspace = assertWorkspaceName(requestedWorkspace);
    const sessionPath = path.join(studioEnv.auditLogsDir, workspace, "session.json");
    if (await fileExists(sessionPath)) {
      return NextResponse.json(
        { ok: false, error: "Resume is disabled for URL-first runs. Start a new workspace." },
        { status: 400 }
      );
    }
    workflowId = makeWorkflowId(sanitizeHostname(webUrl), workspace);
    sessionId = workspace;
  } else {
    workflowId = makeWorkflowId(sanitizeHostname(webUrl));
    sessionId = workflowId;
  }

  const pipelineInput: Record<string, unknown> = {
    webUrl,
    analysisMode: "url-first",
    discoveryProfile: "aggressive-broad",
    workflowId,
    sessionId,
  };

  if (manualSource) {
    pipelineInput.manualSource = manualSource;
  }

  if (body.configFile) {
    const configName = path.basename(body.configFile);
    const configHostPath = path.join(studioEnv.configsDir, configName);
    if (!(await fileExists(configHostPath))) {
      return NextResponse.json(
        { ok: false, error: `Config file not found: ${configName}` },
        { status: 400 }
      );
    }
    pipelineInput.configPath = buildWorkerConfigPath(configName);
  }

  if (body.pipelineTestingMode === true) {
    pipelineInput.pipelineTestingMode = true;
  }

  await startPipelineWorkflow(
    workflowId,
    pipelineInput as {
      webUrl: string;
      analysisMode: "url-first";
      discoveryProfile?: "aggressive-broad";
      manualSource?: string;
      repoPath?: string;
      configPath?: string;
      outputPath?: string;
      pipelineTestingMode?: boolean;
      workflowId?: string;
      sessionId?: string;
    }
  );

  return NextResponse.json({
    ok: true,
    mode,
    workflowId,
    workspace: sessionId,
    terminatedWorkflows: [],
  });
}
