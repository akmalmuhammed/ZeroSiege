import { NextResponse, type NextRequest } from "next/server";
import { requireApiAuth } from "@/lib/api-auth";
import { readReport } from "@/lib/workspaces";

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
    const report = await readReport(workspace);
    if (!report) {
      return NextResponse.json(
        { ok: false, error: "Report not found" },
        { status: 404 }
      );
    }
    return NextResponse.json({ ok: true, report });
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: error instanceof Error ? error.message : "Failed to read report" },
      { status: 400 }
    );
  }
}
