import { NextResponse, type NextRequest } from "next/server";
import { requireApiAuth } from "@/lib/api-auth";
import { getWorkspace } from "@/lib/workspaces";

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ workspace: string }> }
): Promise<NextResponse> {
  const unauthorized = requireApiAuth(request);
  if (unauthorized) {
    return unauthorized;
  }
  const { workspace } = await context.params;
  try {
    const details = await getWorkspace(workspace);
    return NextResponse.json({ ok: true, workspace: details });
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: error instanceof Error ? error.message : "Workspace not found" },
      { status: 404 }
    );
  }
}
