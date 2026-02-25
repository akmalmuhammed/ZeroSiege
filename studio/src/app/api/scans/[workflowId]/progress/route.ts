import { NextResponse, type NextRequest } from "next/server";
import { requireApiAuth } from "@/lib/api-auth";
import { getWorkflowProgress } from "@/lib/temporal";

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ workflowId: string }> }
): Promise<NextResponse> {
  const unauthorized = requireApiAuth(request);
  if (unauthorized) {
    return unauthorized;
  }
  const { workflowId } = await context.params;
  try {
    const progress = await getWorkflowProgress(workflowId);
    return NextResponse.json({ ok: true, ...progress });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        error: error instanceof Error ? error.message : "Unable to fetch progress",
      },
      { status: 404 }
    );
  }
}
