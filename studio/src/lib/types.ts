export interface SessionFile {
  session: {
    id: string;
    webUrl: string;
    repoPath?: string;
    analysisMode?: "url-first";
    analysisPath?: string;
    sourceOrigins?: string[];
    resumeSupported?: boolean;
    status: "in-progress" | "completed" | "failed";
    createdAt: string;
    completedAt?: string;
    originalWorkflowId?: string;
    resumeAttempts?: Array<{
      workflowId: string;
      timestamp: string;
      terminatedPrevious?: string;
      resumedFromCheckpoint?: string;
    }>;
  };
  metrics: {
    total_duration_ms: number;
    total_cost_usd: number;
    phases: Record<
      string,
      {
        duration_ms: number;
        duration_percentage: number;
        cost_usd: number;
        agent_count: number;
      }
    >;
    agents: Record<
      string,
      {
        status: "in-progress" | "success" | "failed";
        attempts: Array<{
          attempt_number: number;
          duration_ms: number;
          cost_usd: number;
          success: boolean;
          timestamp: string;
          model?: string;
          error?: string;
        }>;
        final_duration_ms: number;
        total_cost_usd: number;
        model?: string;
        checkpoint?: string;
      }
    >;
  };
}

export interface WorkspaceSummary {
  name: string;
  status: SessionFile["session"]["status"];
  webUrl: string;
  createdAt: string;
  completedAt?: string;
  totalCostUsd: number;
  totalDurationMs: number;
  latestWorkflowId: string;
  resumable: boolean;
}

export interface WorkspaceDetail extends WorkspaceSummary {
  session: SessionFile["session"];
  metrics: SessionFile["metrics"];
  reportPath: string | null;
  reportMarkdown: string | null;
  findings: Array<{
    title: string;
    severity: string;
    section: string;
  }>;
  workflowLogTail: string[];
}

export interface PipelineInputDto {
  webUrl: string;
  manualSource?: string;
  workspace?: string;
  configFile?: string;
  pipelineTestingMode?: boolean;
  aiCredentialMode?: "env" | "anthropic_api_key" | "claude_oauth_token";
  aiCredentialValue?: string;
}
