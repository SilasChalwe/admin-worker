import { authorize, bodyJson, corsPreflight, corsResponse, failure, field, isResponse, json, randomToken, requiredField, sha256 } from "../shared/http";

interface AdminEnv {
  DB: D1Database;
  ASSETS: Fetcher;
  FILES: R2Bucket;
  AUTH: Fetcher;
  CLIENT: Fetcher;
  AUTH_ORIGIN: string;
  ALLOWED_ORIGINS: string;
  INTERNAL_SERVICE_KEY: string;
}

const htmlAssets: Record<string, string> = {
  "/": "/Pages/",
  "/index.html": "/Pages/",
  "/login.html": "/Pages/login",
  "/coming-soon.html": "/Pages/coming-soon",
  "/page.html": "/Pages/page",
  "/onboarding.html": "/Pages/onboarding",
  "/dashboard.html": "/Pages/dashboard",
  "/admin.html": "/Pages/admin",
};

function assetRequest(request: Request): Request {
  const url = new URL(request.url);
  const target = htmlAssets[url.pathname];
  if (!target) return request;
  url.pathname = target;
  return new Request(url, request);
}

type RequestRow = {
  id: string; organization_id: string; status: string; assigned_to: string | null;
};

const transitions: Record<string, string[]> = {
  submitted: ["reviewing", "closed"],
  reviewing: ["quoted", "closed"],
  quoted: ["accepted", "closed"],
  accepted: ["closed"],
  closed: [],
};
const employeeRoles = ["marketing", "media", "designer", "engineer", "hr"] as const;
const newsRoles = ["marketing", "media", "hr"] as const;

function canManageNews(user: { role: string; employeeRole?: string | null }, category?: string): boolean {
  if (user.role === "admin") return true;
  if (user.role !== "staff" || !user.employeeRole || !newsRoles.includes(user.employeeRole as typeof newsRoles[number])) return false;
  return category === undefined || (user.employeeRole === "hr" ? category === "careers" : category === "news");
}

function validNewsMedia(bytes: Uint8Array, contentType: string): boolean {
  if (contentType === "image/png") return bytes.length >= 8 &&
    bytes.slice(0, 8).join(",") === "137,80,78,71,13,10,26,10";
  if (contentType === "image/jpeg") return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  if (contentType === "image/webp") return bytes.length >= 12 &&
    String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" && String.fromCharCode(...bytes.slice(8, 12)) === "WEBP";
  if (contentType === "video/mp4") return bytes.length >= 12 && String.fromCharCode(...bytes.slice(4, 8)) === "ftyp";
  if (contentType === "video/webm") return bytes.length >= 4 &&
    bytes.slice(0, 4).join(",") === "26,69,223,163";
  return false;
}

async function newsApi(request: Request, env: AdminEnv, path: string): Promise<Response | null> {
  if (!path.startsWith("/api/admin/news")) return null;
  const user = await authorize(request, env.AUTH, ["admin", "staff"]);
  if (isResponse(user)) return user;
  const mediaMatch = path.match(/^\/api\/admin\/news\/media\/([a-f0-9-]{36})$/);
  if (mediaMatch && request.method === "POST") {
    if (!canManageNews(user)) return failure(403, "Permission denied");
    const contentType = (request.headers.get("Content-Type") || "").split(";")[0]?.trim().toLowerCase() || "";
    const lengthHeader = request.headers.get("Content-Length");
    const length = lengthHeader === null ? null : Number(lengthHeader);
    if (!request.body || length !== null && (!Number.isSafeInteger(length) || length < 1 || length > 50_000_000)) {
      return failure(413, "Media must be at most 50 MB");
    }
    const reader = request.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > 50_000_000) {
        await reader.cancel();
        return failure(413, "Media must be at most 50 MB");
      }
      chunks.push(value);
    }
    if (total < 1 || length !== null && total !== length) {
      return failure(400, "Upload a valid PNG, JPEG, WebP, MP4, or WebM file");
    }
    const buffer = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      buffer.set(chunk, offset);
      offset += chunk.byteLength;
    }
    if (!validNewsMedia(buffer, contentType)) {
      return failure(400, "Upload a valid PNG, JPEG, WebP, MP4, or WebM file");
    }
    const key = `public-news/${crypto.randomUUID()}`;
    await env.FILES.put(key, buffer, { httpMetadata: { contentType } });
    return json({ mediaKey: key, mediaType: contentType.startsWith("video/") ? "video" : "image", contentType }, 201);
  }

  if (path === "/api/admin/news" && request.method === "GET") {
    if (!canManageNews(user)) return failure(403, "Permission denied");
    const result = await env.DB.prepare(`SELECT id, slug, title, summary, body, category, media_key, media_type,
      media_content_type, media_alt, published, created_at, updated_at, author_id
      FROM compiler_news WHERE ? = 1 OR author_id = ? ORDER BY created_at DESC LIMIT 100`)
      .bind(user.role === "admin" ? 1 : 0, user.id).all();
    return json({ news: result.results });
  }

  if (path === "/api/admin/news" && request.method === "POST") {
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const title = requiredField(data, "title", 160);
    const summary = requiredField(data, "summary", 400);
    const body = requiredField(data, "body", 12000);
    const category = data.category;
    const mediaKey = data.mediaKey === null || data.mediaKey === undefined ? null : requiredField(data, "mediaKey", 100);
    const mediaAlt = data.mediaAlt === null || data.mediaAlt === undefined ? null : field(data, "mediaAlt", 300);
    const published = data.published;
    if (!title || !summary || !body || typeof category !== "string" ||
        !["news", "careers"].includes(category) || !canManageNews(user, category) ||
        (mediaKey !== null && (!mediaKey || !/^public-news\/[a-f0-9-]{36}$/.test(mediaKey))) ||
        mediaAlt === null && data.mediaAlt !== null && data.mediaAlt !== undefined ||
        typeof published !== "boolean") {
      return failure(400, "Complete the news details correctly");
    }
    let media: { media_type: string; content_type: string } | null = null;
    if (mediaKey) {
      const object = await env.FILES.head(mediaKey);
      if (!object) return failure(400, "Uploaded media was not found");
      media = { media_type: object.httpMetadata?.contentType?.startsWith("video/") ? "video" : "image",
        content_type: object.httpMetadata?.contentType || "" };
      if (!["image/png", "image/jpeg", "image/webp", "video/mp4", "video/webm"].includes(media.content_type)) {
        return failure(400, "Unsupported media type");
      }
    }
    const slugBase = title.toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 100) || "news";
    const id = crypto.randomUUID();
    const slug = `${slugBase}-${id.slice(0, 8)}`;
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO compiler_news
        (id, slug, title, summary, body, category, media_key, media_type, media_content_type,
          media_alt, published, author_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(id, slug, title, summary, body, category, mediaKey, media?.media_type || null,
          media?.content_type || null, mediaAlt, published ? 1 : 0, user.id, now, now),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'news.create', 'news', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, id, JSON.stringify({ category, published }), now),
    ]);
    return json({ news: { id, slug, title, summary, body, category, published } }, 201);
  }

  const postMatch = path.match(/^\/api\/admin\/news\/([a-f0-9-]{36})$/);
  if (postMatch && request.method === "PUT") {
    const existing = await env.DB.prepare("SELECT id, author_id, category FROM compiler_news WHERE id = ?")
      .bind(postMatch[1]).first<{ id: string; author_id: string; category: string }>();
    if (!existing) return failure(404, "News item not found");
    if (!canManageNews(user, existing.category) || user.role !== "admin" && existing.author_id !== user.id) {
      return failure(403, "Permission denied");
    }
    const data = await bodyJson(request);
    const published = data?.published;
    if (typeof published !== "boolean") return failure(400, "Invalid publication status");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("UPDATE compiler_news SET published = ?, updated_at = ? WHERE id = ?")
        .bind(published ? 1 : 0, now, existing.id),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'news.publish', 'news', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, existing.id, JSON.stringify({ published }), now),
    ]);
    return json({ ok: true, published });
  }
  return failure(404, "Not found");
}

async function handle(request: Request, env: AdminEnv, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  if (request.method === "GET" && path === "/") {
    return Response.redirect(new URL("/admin.html", url), 302);
  }
  if (request.method === "GET" && (path === "/login" || path === "/login.html")) {
    return Response.redirect(`${env.AUTH_ORIGIN}/login${url.search}`, 302);
  }
  if (request.method === "GET" && /^\/staff\/(marketing|media|designer|engineer|hr)$/.test(path)) {
    return env.ASSETS.fetch(assetRequest(new Request(new URL("/index.html", url), request)));
  }
  if (path.startsWith("/staff/")) return failure(404, "Not found");
  if (!path.startsWith("/api/") && !path.startsWith("/internal/")) return env.ASSETS.fetch(assetRequest(request));

  if (path.startsWith("/api/admin/news")) {
    const response = await newsApi(request, env, path);
    if (response) return response;
  }
  const user = await authorize(request, env.AUTH, ["admin"]);
  if (isResponse(user)) return user;

  if (path === "/api/admin/overview" && request.method === "GET") {
    const [clients, requests, open] = await Promise.all([
      env.DB.prepare("SELECT count(*) AS n FROM compiler_organizations").first<{ n: number }>(),
      env.DB.prepare("SELECT count(*) AS n FROM compiler_requests").first<{ n: number }>(),
      env.DB.prepare("SELECT count(*) AS n FROM compiler_requests WHERE status != 'closed'").first<{ n: number }>(),
    ]);
    return json({ clients: clients?.n || 0, requests: requests?.n || 0, openRequests: open?.n || 0 });
  }

  if (path === "/api/admin/clients" && request.method === "GET") {
    const result = await env.DB.prepare(`SELECT o.*, u.email AS owner_email
      FROM compiler_organizations o JOIN compiler_users u ON u.id = o.owner_user_id
      ORDER BY o.created_at DESC LIMIT 100`).all();
    return json({ clients: result.results });
  }
  if (path === "/api/admin/inquiries" && request.method === "GET") {
    const result = await env.DB.prepare("SELECT * FROM compiler_inquiries ORDER BY created_at DESC LIMIT 100").all();
    return json({ inquiries: result.results });
  }

  if (path === "/api/admin/requests" && request.method === "GET") {
    const status = url.searchParams.get("status");
    if (status && !Object.hasOwn(transitions, status)) return failure(400, "Invalid status");
    const result = status
      ? await env.DB.prepare(`SELECT r.*, o.name AS organization_name, u.email AS requester_email
          FROM compiler_requests r JOIN compiler_organizations o ON o.id = r.organization_id
          JOIN compiler_users u ON u.id = r.created_by WHERE r.status = ?
          ORDER BY r.created_at DESC LIMIT 100`).bind(status).all()
      : await env.DB.prepare(`SELECT r.*, o.name AS organization_name, u.email AS requester_email
          FROM compiler_requests r JOIN compiler_organizations o ON o.id = r.organization_id
          JOIN compiler_users u ON u.id = r.created_by ORDER BY r.created_at DESC LIMIT 100`).all();
    return json({ requests: result.results });
  }

  const requestMatch = path.match(/^\/api\/admin\/requests\/([a-f0-9-]{36})$/);
  if (requestMatch && request.method === "PATCH") {
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const status = requiredField(data, "status", 30);
    const assignedTo = data.assignedTo === null ? null : field(data, "assignedTo", 80);
    if (!status || !Object.hasOwn(transitions, status) || assignedTo === null && data.assignedTo !== null && data.assignedTo !== undefined) {
      return failure(400, "Invalid request update");
    }
    const existing = await env.DB.prepare("SELECT id, organization_id, status, assigned_to FROM compiler_requests WHERE id = ?")
      .bind(requestMatch[1]).first<RequestRow>();
    if (!existing) return failure(404, "Request not found");
    if (status !== existing.status && !transitions[existing.status]?.includes(status)) return failure(409, "Status transition is not allowed");
    if (assignedTo) {
      const assignee = await env.DB.prepare("SELECT role FROM compiler_users WHERE id = ?").bind(assignedTo).first<{ role: string }>();
      if (!assignee || !["staff", "admin"].includes(assignee.role)) return failure(400, "Assignee must be staff");
    }
    const nextAssignee = data.assignedTo === undefined ? existing.assigned_to : assignedTo;
    if (status === existing.status && nextAssignee === existing.assigned_to) return failure(400, "No changes submitted");
    const now = new Date().toISOString();
    const results = await env.DB.batch([
      env.DB.prepare("UPDATE compiler_requests SET status = ?, assigned_to = ?, updated_at = ? WHERE id = ? AND status = ? AND assigned_to IS ?")
        .bind(status, nextAssignee, now, existing.id, existing.status, existing.assigned_to),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        SELECT ?, ?, 'request.update', 'request', ?, ?, ? WHERE changes() = 1`)
        .bind(crypto.randomUUID(), user.id, existing.id, JSON.stringify({ from: existing.status, to: status, assignedTo: nextAssignee }), now),
    ]);
    if (!results[0].meta.changes) return failure(409, "Request changed; reload and try again");
    ctx.waitUntil(env.CLIENT.fetch(new Request("https://client.internal/internal/events", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Internal-Key": env.INTERNAL_SERVICE_KEY },
      body: JSON.stringify({ organizationId: existing.organization_id, type: "request.updated", requestId: existing.id, status }),
    })).then(() => undefined));
    return json({ request: { id: existing.id, status, assignedTo: nextAssignee } });
  }

  if (path === "/api/admin/content" && request.method === "GET") {
    const result = await env.DB.prepare("SELECT * FROM compiler_content ORDER BY title").all();
    return json({ pages: result.results });
  }
  const contentMatch = path.match(/^\/api\/admin\/content\/([a-zA-Z][a-zA-Z0-9]{0,79})$/);
  if (contentMatch && request.method === "PUT") {
    if (user.role !== "admin") return failure(403, "Admin role required");
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const title = requiredField(data, "title", 160);
    const eyebrow = field(data, "eyebrow", 80);
    const body = requiredField(data, "body", 20000);
    if (!title || eyebrow === null || !body || typeof data.published !== "boolean") return failure(400, "Invalid page content");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO compiler_content (slug, title, eyebrow, body, published, updated_at)
        VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(slug) DO UPDATE SET title = excluded.title,
        eyebrow = excluded.eyebrow, body = excluded.body, published = excluded.published, updated_at = excluded.updated_at`)
        .bind(contentMatch[1], title, eyebrow, body, data.published ? 1 : 0, now),
      env.DB.prepare("INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(crypto.randomUUID(), user.id, "content.update", "content", contentMatch[1], JSON.stringify({ published: data.published }), now),
    ]);
    return json({ page: { slug: contentMatch[1], title, eyebrow, body, published: data.published } });
  }

  if (path === "/api/admin/services" && request.method === "GET") {
    const result = await env.DB.prepare("SELECT * FROM compiler_services ORDER BY name").all();
    return json({ services: result.results });
  }
  const serviceMatch = path.match(/^\/api\/admin\/services\/([a-z][a-z0-9-]{0,79})$/);
  if (serviceMatch && request.method === "PUT") {
    if (user.role !== "admin") return failure(403, "Admin role required");
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const name = requiredField(data, "name", 160);
    const description = requiredField(data, "description", 2000);
    if (!name || !description || typeof data.active !== "boolean") return failure(400, "Invalid service");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO compiler_services (slug, name, description, active)
        VALUES (?, ?, ?, ?) ON CONFLICT(slug) DO UPDATE SET name = excluded.name,
        description = excluded.description, active = excluded.active`)
        .bind(serviceMatch[1], name, description, data.active ? 1 : 0),
      env.DB.prepare("INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(crypto.randomUUID(), user.id, "service.update", "service", serviceMatch[1], JSON.stringify({ active: data.active }), now),
    ]);
    return json({ service: { slug: serviceMatch[1], name, description, active: data.active } });
  }

  if (path === "/api/admin/advisory-services" && request.method === "GET") {
    const result = await env.DB.prepare("SELECT * FROM compiler_advisory_services ORDER BY sort_order, name").all();
    return json({ advisoryServices: result.results });
  }
  const advisoryMatch = path.match(/^\/api\/admin\/advisory-services\/([a-z][a-z0-9-]{0,79})$/);
  if (advisoryMatch && request.method === "PUT") {
    if (user.role !== "admin") return failure(403, "Admin role required");
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const name = requiredField(data, "name", 160);
    const description = requiredField(data, "description", 2000);
    if (!name || !description || typeof data.active !== "boolean") return failure(400, "Invalid advisory service");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO compiler_advisory_services (slug, name, description, active, sort_order)
        VALUES (?, ?, ?, ?, COALESCE((SELECT sort_order FROM compiler_advisory_services WHERE slug = ?), 1000))
        ON CONFLICT(slug) DO UPDATE SET name = excluded.name,
        description = excluded.description, active = excluded.active`)
        .bind(advisoryMatch[1], name, description, data.active ? 1 : 0, advisoryMatch[1]),
      env.DB.prepare("INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(crypto.randomUUID(), user.id, "advisory-service.update", "advisory-service", advisoryMatch[1], JSON.stringify({ active: data.active }), now),
    ]);
    return json({ advisoryService: { slug: advisoryMatch[1], name, description, active: data.active } });
  }

  const roleMatch = path.match(/^\/api\/admin\/users\/([a-f0-9-]{36})\/role$/);
  if (roleMatch && request.method === "PUT") {
    if (roleMatch[1] === user.id) return failure(400, "You cannot change your own role");
    const data = await bodyJson(request);
    if (!data || !["client", "staff", "admin"].includes(String(data.role))) return failure(400, "Invalid role");
    const role = data.role as "client" | "staff" | "admin";
    const employeeRole = data.employeeRole;
    const department = field(data, "department", 120);
    const position = field(data, "position", 120);
    if (role === "staff") {
      if (typeof employeeRole !== "string" || !employeeRoles.includes(employeeRole as typeof employeeRoles[number]) ||
          !department || !position) return failure(400, "Staff require a role, department, and position");
    }
    const target = await env.DB.prepare("SELECT id, role FROM compiler_users WHERE id = ?").bind(roleMatch[1]).first<{ id: string; role: string }>();
    if (!target) return failure(404, "User not found");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`UPDATE compiler_users SET role = ?, employee_role = ?, department = ?, position = ?, updated_at = ?
        WHERE id = ?`).bind(role, role === "staff" ? employeeRole : null, role === "staff" ? department : null,
        role === "staff" ? position : null, now, target.id),
      env.DB.prepare("DELETE FROM compiler_sessions WHERE user_id = ?").bind(target.id),
      env.DB.prepare("INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(crypto.randomUUID(), user.id, "user.role", "user", target.id,
          JSON.stringify({ from: target.role, to: role, employeeRole: role === "staff" ? employeeRole : null,
            department: role === "staff" ? department : null, position: role === "staff" ? position : null }), now),
    ]);
    return json({ user: { id: target.id, role, employeeRole: role === "staff" ? employeeRole : null } });
  }

  if (path === "/api/admin/users/invitations" && request.method === "POST") {
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const email = requiredField(data, "email", 320);
    const displayName = requiredField(data, "displayName", 160);
    const position = requiredField(data, "position", 120);
    const department = requiredField(data, "department", 120);
    const employeeRole = data.employeeRole;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !displayName || !position || !department ||
        typeof employeeRole !== "string" || !employeeRoles.includes(employeeRole as typeof employeeRoles[number])) {
      return failure(400, "Enter a valid email, name, role, department, and position");
    }
    const emailNormalized = email.toLowerCase();
    const existing = await env.DB.prepare(`SELECT 1 FROM compiler_credentials WHERE email_normalized = ?
      UNION ALL SELECT 1 FROM compiler_email_verifications
        WHERE email_normalized = ? AND expires_at > ? LIMIT 1`)
      .bind(emailNormalized, emailNormalized, new Date().toISOString()).first();
    if (existing) return failure(409, "An account already exists for that email. Change its role from the user list instead.");
    const token = randomToken();
    const tokenHash = await sha256(token);
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
    const setupUrl = `${env.AUTH_ORIGIN}/login#employee-invitation=${encodeURIComponent(token)}`;
    const message = [
      `Hello ${displayName},`,
      "",
      "An administrator invited you to Compiler Technologies.",
      `Role: ${employeeRole}`,
      `Department: ${department}`,
      `Position: ${position}`,
      "",
      "Use this one-time link within 24 hours to set your password:",
      setupUrl,
      "",
      "If you were not expecting this invitation, you can ignore this message.",
    ].join("\n");
    const result = await env.DB.batch([
      env.DB.prepare(`INSERT INTO compiler_employee_invitations
        (id, email_normalized, email, display_name, role, employee_role, department, position,
          token_hash, expires_at, created_by, created_at)
        VALUES (?, ?, ?, ?, 'staff', ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(email_normalized) DO UPDATE SET id = excluded.id, email = excluded.email,
          display_name = excluded.display_name, role = excluded.role, employee_role = excluded.employee_role,
          department = excluded.department, position = excluded.position, token_hash = excluded.token_hash,
          expires_at = excluded.expires_at, created_by = excluded.created_by, used_at = NULL,
          created_at = excluded.created_at
        WHERE compiler_employee_invitations.used_at IS NOT NULL OR compiler_employee_invitations.expires_at <= ?`)
        .bind(crypto.randomUUID(), emailNormalized, email, displayName, employeeRole, department, position,
          tokenHash, expiresAt, user.id, now, now),
      env.DB.prepare(`INSERT INTO compiler_outbox (id, recipient, subject, body, created_at)
        SELECT ?, ?, ?, ?, ? WHERE EXISTS (
          SELECT 1 FROM compiler_employee_invitations WHERE token_hash = ? AND used_at IS NULL
        )`)
        .bind(crypto.randomUUID(), email, "Your Compiler employee invitation", message, now, tokenHash),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        SELECT ?, ?, 'employee.invite', 'invitation', ?, ?, ? WHERE EXISTS (
          SELECT 1 FROM compiler_employee_invitations WHERE token_hash = ?
        )`)
        .bind(crypto.randomUUID(), user.id, emailNormalized,
          JSON.stringify({ employeeRole, department, position }), now, tokenHash),
    ]);
    if (result[0]?.meta.changes !== 1 || result[1]?.meta.changes !== 1) {
      return failure(409, "There is already an active invitation for that email.");
    }
    return json({ invitation: { email, expiresAt } }, 201);
  }

  if (path === "/api/admin/users" && request.method === "GET") {
    const result = await env.DB.prepare(`SELECT id, email, display_name, role, employee_role, department, position, created_at
      FROM compiler_users ORDER BY created_at DESC LIMIT 100`).all();
    return json({ users: result.results });
  }
  if (path === "/api/admin/audit" && request.method === "GET") {
    if (user.role !== "admin") return failure(403, "Admin role required");
    const result = await env.DB.prepare("SELECT * FROM compiler_audit ORDER BY created_at DESC LIMIT 100").all();
    return json({ events: result.results });
  }
  return failure(404, "Not found");
}

export default {
  async fetch(request: Request, env: AdminEnv, ctx: ExecutionContext): Promise<Response> {
    const preflight = corsPreflight(request, env.ALLOWED_ORIGINS);
    if (preflight) return preflight;
    try { return corsResponse(request, await handle(request, env, ctx), env.ALLOWED_ORIGINS); }
    catch (error) { console.error("Admin request failed", error); return corsResponse(request, failure(500, "Admin service error"), env.ALLOWED_ORIGINS); }
  },
};
