"use client";

import { useState } from "react";
import type { FormEvent } from "react";
import { useEffect } from "react";
import { useRouter } from "next/navigation";

export function LoginForm() {
  const router = useRouter();
  const [nextPath, setNextPath] = useState("/");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setNextPath(params.get("next") || "/");
  }, []);

  async function onSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setError(null);
    setLoading(true);
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    setLoading(false);

    if (!response.ok) {
      const payload = (await response.json().catch(() => null)) as
        | { error?: string }
        | null;
      setError(payload?.error || "Login failed");
      return;
    }

    router.push(nextPath);
    router.refresh();
  }

  return (
    <form className="panel login-panel" onSubmit={onSubmit}>
      <p className="eyebrow">Operator Access</p>
      <h1>Shannon Studio</h1>
      <p className="muted">
        Launch autonomous pentests, monitor pipelines, and review exploit-grade evidence.
      </p>
      <label className="field">
        Username
        <input
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          autoComplete="username"
          required
        />
      </label>
      <label className="field">
        Password
        <input
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          type="password"
          autoComplete="current-password"
          required
        />
      </label>
      {error ? <p className="error-text">{error}</p> : null}
      <button className="primary-button" disabled={loading} type="submit">
        {loading ? "Signing in..." : "Sign in"}
      </button>
    </form>
  );
}
