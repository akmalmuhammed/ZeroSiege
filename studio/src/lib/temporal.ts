import { Client, Connection, WorkflowNotFoundError } from "@temporalio/client";
import { studioEnv } from "@/lib/env";
import type { SessionFile } from "@/lib/types";

interface PipelineInput {
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

let connectionPromise: Promise<Connection> | null = null;

async function getConnection(): Promise<Connection> {
  if (!connectionPromise) {
    connectionPromise = Connection.connect({ address: studioEnv.temporalAddress });
  }
  return connectionPromise;
}

async function getClient(): Promise<Client> {
  const connection = await getConnection();
  return new Client({ connection });
}

export async function startPipelineWorkflow(
  workflowId: string,
  input: PipelineInput
): Promise<void> {
  const client = await getClient();
  await client.workflow.start("pentestPipelineWorkflow", {
    taskQueue: "shannon-pipeline",
    workflowId,
    args: [input],
  });
}

export async function getWorkflowProgress(
  workflowId: string
): Promise<Record<string, unknown>> {
  const client = await getClient();
  const handle = client.workflow.getHandle(workflowId);
  const description = await handle.describe();

  let progress: unknown = null;
  try {
    progress = await handle.query("getProgress");
  } catch {
    progress = null;
  }

  return {
    workflowId,
    status: description.status.name,
    progress,
  };
}

export function makeWorkflowId(hostname: string, workspace?: string): string {
  if (workspace) {
    return `${workspace}_shannon-${Date.now()}`;
  }
  return `${hostname}_shannon-${Date.now()}`;
}

export function makeResumeWorkflowId(workspace: string): string {
  return `${workspace}_resume_${Date.now()}`;
}

export async function terminateAssociatedWorkflows(
  session: SessionFile
): Promise<string[]> {
  const client = await getClient();
  const workflowIds = [
    session.session.originalWorkflowId || session.session.id,
    ...(session.session.resumeAttempts?.map((attempt) => attempt.workflowId) || []),
  ].filter((id): id is string => Boolean(id));

  const terminated: string[] = [];

  for (const workflowId of workflowIds) {
    try {
      const handle = client.workflow.getHandle(workflowId);
      const description = await handle.describe();
      if (description.status.name === "RUNNING") {
        await handle.terminate("Superseded by Shannon Studio resume");
        terminated.push(workflowId);
      }
    } catch (error) {
      if (!(error instanceof WorkflowNotFoundError)) {
        console.error("terminateAssociatedWorkflows error:", error);
      }
    }
  }

  return terminated;
}
