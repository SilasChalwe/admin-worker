export type SessionUser = {
  id: string;
  email: string;
  displayName: string;
  role: "client" | "staff" | "admin";
  emailVerified: boolean;
  employeeRole: "marketing" | "media" | "designer" | "engineer" | "hr" | null;
  department: string | null;
  position: string | null;
};

export function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

export function failure(status: number, message: string): Response {
  return json({ error: message }, status);
}

export function corsPreflight(request: Request, allowedOrigins: string): Response | null {
  if (request.method !== "OPTIONS") return null;
  const origin = request.headers.get("Origin");
  if (!origin || !allowedOrigins.split(",").map((item) => item.trim()).includes(origin)) {
    return failure(403, "Origin is not allowed");
  }
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type, Idempotency-Key, X-CSRF-Token, X-Filename",
      "Access-Control-Max-Age": "600",
      Vary: "Origin",
    },
  });
}

export function corsResponse(request: Request, response: Response, allowedOrigins: string): Response {
  if (response.status === 101) return response;
  const origin = request.headers.get("Origin");
  if (!origin || !allowedOrigins.split(",").map((item) => item.trim()).includes(origin)) return response;
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", origin);
  headers.append("Vary", "Origin");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export async function bodyJson(request: Request): Promise<Record<string, unknown> | null> {
  if (!request.headers.get("content-type")?.startsWith("application/json")) return null;
  const length = Number(request.headers.get("content-length") || 0);
  if (length > 65536) return null;
  const text = await request.text();
  if (text.length > 65536) return null;
  try {
    const data: unknown = JSON.parse(text);
    return data !== null && typeof data === "object" && !Array.isArray(data)
      ? data as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

export function field(data: Record<string, unknown>, key: string, max: number): string | null {
  const value = data[key];
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length <= max ? trimmed : null;
}

export function requiredField(data: Record<string, unknown>, key: string, max: number): string | null {
  const value = field(data, key, max);
  return value && value.length > 0 ? value : null;
}

export function cookie(request: Request, name: string): string | null {
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index > 0 && part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }
  return null;
}

export async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function authorize(
  request: Request,
  auth: Fetcher,
  allowed: SessionUser["role"][] = ["client", "staff", "admin"],
): Promise<SessionUser | Response> {
  const headers = new Headers({
    "X-Original-Method": request.method,
    "X-Original-Path": new URL(request.url).pathname,
  });
  for (const name of ["Authorization", "Cookie", "Origin", "X-CSRF-Token"]) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
  const result = await auth.fetch(new Request("https://auth.internal/internal/authorize", { headers }));
  if (!result.ok) return failure(result.status, "Authentication or permission check failed");
  const data = await result.json() as { user: SessionUser };
  if (!allowed.includes(data.user.role)) return failure(403, "Permission denied");
  return data.user;
}

export function isResponse(value: SessionUser | Response): value is Response {
  return value instanceof Response;
}
