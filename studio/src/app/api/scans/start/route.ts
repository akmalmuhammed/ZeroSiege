import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
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

type AiCredentialMode = "env" | "anthropic_api_key" | "claude_oauth_token";

function isValidAiCredentialMode(value: string): value is AiCredentialMode {
  return (
    value === "env" ||
    value === "anthropic_api_key" ||
    value === "claude_oauth_token"
  );
}

function buildRuntimeCredentialEnv(
  mode: Exclude<AiCredentialMode, "env">,
  value: string
): Record<string, string> {
  if (mode === "anthropic_api_key") {
    return { ANTHROPIC_API_KEY: value };
  }
  return { CLAUDE_CODE_OAUTH_TOKEN: value };
}

async function writeRuntimeCredentialSecret(
  env: Record<string, string>
): Promise<string> {
  const ref = crypto.randomBytes(16).toString("hex");
  await fs.mkdir(studioEnv.runtimeSecretsDir, { recursive: true, mode: 0o777 });
  await fs.chmod(studioEnv.runtimeSecretsDir, 0o777).catch(() => undefined);
  const secretPath = path.join(studioEnv.runtimeSecretsDir, `${ref}.json`);
  await fs.writeFile(
    secretPath,
    JSON.stringify(
      {
        createdAt: new Date().toISOString(),
        env,
      },
      null,
      2
    ),
    { encoding: "utf8", mode: 0o644 }
  );
  return ref;
}

async function removeRuntimeCredentialSecret(ref: string): Promise<void> {
  const secretPath = path.join(studioEnv.runtimeSecretsDir, `${ref}.json`);
  await fs.rm(secretPath, { force: true }).catch(() => undefined);
}

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

  const webUrl = typeof body.webUrl === "string" ? body.webUrl.trim() : "";
  if (!webUrl) {
    return NextResponse.json({ ok: false, error: "webUrl is required" }, { status: 400 });
  }

  if (!isValidWebUrl(webUrl)) {
    return NextResponse.json({ ok: false, error: "Invalid webUrl" }, { status: 400 });
  }

  const manualSource =
    typeof body.manualSource === "string" ? body.manualSource.trim() : undefined;
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

  const aiCredentialModeRaw =
    typeof body.aiCredentialMode === "string" ? body.aiCredentialMode.trim() : "env";
  if (!isValidAiCredentialMode(aiCredentialModeRaw)) {
    return NextResponse.json(
      {
        ok: false,
        error:
          "Invalid aiCredentialMode. Use env, anthropic_api_key, or claude_oauth_token.",
      },
      { status: 400 }
    );
  }

  const aiCredentialMode = aiCredentialModeRaw as AiCredentialMode;
  const aiCredentialValue =
    typeof body.aiCredentialValue === "string"
      ? body.aiCredentialValue.trim()
      : undefined;
  if (aiCredentialMode !== "env") {
    if (!aiCredentialValue) {
      return NextResponse.json(
        { ok: false, error: "AI credential value is required for selected mode." },
        { status: 400 }
      );
    }
    if (aiCredentialValue.length > 16_384) {
      return NextResponse.json(
        { ok: false, error: "AI credential value is too long." },
        { status: 400 }
      );
    }
  }

  let workflowId: string;
  let sessionId: string;
  const mode: "new" = "new";

  const requestedWorkspace =
    typeof body.workspace === "string" ? body.workspace.trim() : undefined;
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

  if (typeof body.configFile === "string" && body.configFile.trim()) {
    const configName = path.basename(body.configFile.trim());
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

  let credentialRef: string | undefined;
  if (aiCredentialMode !== "env" && aiCredentialValue) {
    const env = buildRuntimeCredentialEnv(aiCredentialMode, aiCredentialValue);
    credentialRef = await writeRuntimeCredentialSecret(env);
    pipelineInput.credentialRef = credentialRef;
  }

  try {
    await startPipelineWorkflow(
      workflowId,
      pipelineInput as {
        webUrl: string;
        analysisMode: "url-first";
        discoveryProfile?: "aggressive-broad";
        manualSource?: string;
        credentialRef?: string;
        repoPath?: string;
        configPath?: string;
        outputPath?: string;
        pipelineTestingMode?: boolean;
        workflowId?: string;
        sessionId?: string;
      }
    );
  } catch (error) {
    if (credentialRef) {
      await removeRuntimeCredentialSecret(credentialRef);
    }
    const message = error instanceof Error ? error.message : String(error);
    return NextResponse.json(
      { ok: false, error: `Failed to start workflow: ${message}` },
      { status: 500 }
    );
  }

  return NextResponse.json({
    ok: true,
    mode,
    workflowId,
    workspace: sessionId,
    terminatedWorkflows: [],
  });
}
