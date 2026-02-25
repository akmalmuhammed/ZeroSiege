import { NextResponse } from "next/server";
import { getSessionFromCookies } from "@/lib/auth";

export async function GET(): Promise<NextResponse> {
  const session = await getSessionFromCookies();
  if (!session) {
    return NextResponse.json({ ok: false, user: null }, { status: 401 });
  }
  return NextResponse.json({ ok: true, user: { username: session.u } });
}
