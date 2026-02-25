import crypto from "node:crypto";
import { cookies } from "next/headers";
import type { NextRequest } from "next/server";
import { studioEnv } from "@/lib/env";

const COOKIE_NAME = "studio_session";
const TOKEN_TTL_SECONDS = 60 * 60 * 12;

interface SessionPayload {
  u: string;
  exp: number;
}

function hmac(value: string): string {
  return crypto
    .createHmac("sha256", studioEnv.sessionSecret)
    .update(value)
    .digest("base64url");
}

function safeEqual(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);
  if (aBuffer.length !== bBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(aBuffer, bBuffer);
}

function encodePayload(payload: SessionPayload): string {
  return Buffer.from(JSON.stringify(payload)).toString("base64url");
}

function decodePayload(encoded: string): SessionPayload | null {
  try {
    return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

export function createSessionToken(username: string): string {
  const payload: SessionPayload = {
    u: username,
    exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS,
  };
  const encoded = encodePayload(payload);
  const signature = hmac(encoded);
  return `${encoded}.${signature}`;
}

function verifyToken(token: string | undefined): SessionPayload | null {
  if (!token) {
    return null;
  }
  const [encoded, signature] = token.split(".");
  if (!encoded || !signature) {
    return null;
  }
  const expected = hmac(encoded);
  if (!safeEqual(signature, expected)) {
    return null;
  }
  const payload = decodePayload(encoded);
  if (!payload) {
    return null;
  }
  if (payload.exp < Math.floor(Date.now() / 1000)) {
    return null;
  }
  return payload;
}

export async function setSessionCookie(username: string): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.set(COOKIE_NAME, createSessionToken(username), {
    httpOnly: true,
    secure: studioEnv.cookieSecure,
    sameSite: "lax",
    path: "/",
    maxAge: TOKEN_TTL_SECONDS,
  });
}

export async function clearSessionCookie(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(COOKIE_NAME);
}

export async function getSessionFromCookies(): Promise<SessionPayload | null> {
  const cookieStore = await cookies();
  const token = cookieStore.get(COOKIE_NAME)?.value;
  return verifyToken(token);
}

export function getSessionFromRequest(
  request: NextRequest
): SessionPayload | null {
  return verifyToken(request.cookies.get(COOKIE_NAME)?.value);
}

export function verifyCredentials(username: string, password: string): boolean {
  const usernameMatches = safeEqual(username, studioEnv.adminUsername);
  const passwordMatches = safeEqual(password, studioEnv.adminPassword);
  return usernameMatches && passwordMatches;
}

export { COOKIE_NAME };
