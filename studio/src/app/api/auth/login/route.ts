import { NextResponse } from "next/server";
import { setSessionCookie, verifyCredentials } from "@/lib/auth";

export async function POST(request: Request): Promise<NextResponse> {
  const body = (await request.json().catch(() => null)) as
    | { username?: string; password?: string }
    | null;
  if (!body?.username || !body?.password) {
    return NextResponse.json(
      { ok: false, error: "username and password are required" },
      { status: 400 }
    );
  }

  const valid = verifyCredentials(body.username, body.password);
  if (!valid) {
    return NextResponse.json(
      { ok: false, error: "Invalid credentials" },
      { status: 401 }
    );
  }

  await setSessionCookie(body.username);
  return NextResponse.json({ ok: true });
}
