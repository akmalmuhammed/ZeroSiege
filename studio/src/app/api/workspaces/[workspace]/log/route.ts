import { NextResponse, type NextRequest } from "next/server";
import { requireApiAuth } from "@/lib/api-auth";
import { readWorkflowLogTail } from "@/lib/workspaces";

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ workspace: string }> }
): Promise<NextResponse> {
  const unauthorized = requireApiAuth(request);
  if (unauthorized) {
    return unauthorized;
  }

  const { workspace } = await context.params;
  const linesRaw = request.nextUrl.searchParams.get("lines");
  const lines = linesRaw ? Math.min(1000, Math.max(10, Number(linesRaw))) : 250;

  try {
    const logLines = await readWorkflowLogTail(workspace, lines);
    return NextResponse.json({ ok: true, lines: logLines });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        error: error instanceof Error ? error.message : "Failed to read logs",
      },
      { status: 400 }
    );
  }
}
