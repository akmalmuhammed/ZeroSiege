import { NextResponse, type NextRequest } from "next/server";
import { requireApiAuth } from "@/lib/api-auth";
import { listSampleReports, listWorkspaces } from "@/lib/workspaces";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const unauthorized = requireApiAuth(request);
  if (unauthorized) {
    return unauthorized;
  }
  const [workspaces, sampleReports] = await Promise.all([
    listWorkspaces(),
    listSampleReports(),
  ]);
  return NextResponse.json({ ok: true, workspaces, sampleReports });
}
