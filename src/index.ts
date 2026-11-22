import {
  authorize,
  bodyJson,
  corsPreflight,
  corsResponse,
  failure,
  field,
  isResponse,
  json,
  randomToken,
  requiredField,
  sha256,
  type SessionUser,
} from "../shared/http";

interface AdminEnv {
  DB: D1Database;
  ASSETS: Fetcher;
  FILES: R2Bucket;
  AUTH: Fetcher;
  CLIENT: Fetcher;
  SITE_ORIGIN?: string;
  AUTH_ORIGIN: string;
  ALLOWED_ORIGINS: string;
  INTERNAL_SERVICE_KEY: string;
}

const htmlAssets: Record<string, string> = {
  "/": "/Pages/",
  "/index": "/Pages/",
  "/index.html": "/Pages/",
  "/login": "/Pages/login",
  "/login.html": "/Pages/login",
  "/coming-soon": "/Pages/coming-soon",
  "/coming-soon.html": "/Pages/coming-soon",
  "/onboarding": "/Pages/onboarding",
  "/onboarding.html": "/Pages/onboarding",
  "/dashboard": "/Pages/dashboard",
  "/dashboard.html": "/Pages/dashboard",
  "/admin": "/Pages/admin",
  "/admin.html": "/Pages/admin",
  "/admin/content": "/Pages/admin",
  "/admin/content.html": "/Pages/admin",
};

function publicSiteOrigin(env: AdminEnv): string {
  return (env.SITE_ORIGIN || "https://thecompiler.tech").replace(/\/+$/, "");
}

function isPublicSitePath(pathname: string): boolean {
  return (
    pathname === "/page" ||
    pathname === "/page.html" ||
    pathname === "/portfolio" ||
    pathname === "/portfolio.html" ||
    pathname === "/policies" ||
    pathname === "/policies.html" ||
    pathname.startsWith("/policies/") ||
    pathname.startsWith("/news/") ||
    pathname === "/request-service" ||
    pathname === "/request-service.html" ||
    pathname === "/career-application" ||
    pathname === "/career-application.html"
  );
}

function assetRequest(request: Request): Request {
  const url = new URL(request.url);
  const target = htmlAssets[url.pathname];
  if (!target) return request;
  url.pathname = target;
  return new Request(url, request);
}

type RequestRow = {
  id: string;
  organization_id: string;
  status: string;
  assigned_to: string | null;
};

const transitions: Record<string, string[]> = {
  submitted: ["reviewing", "closed"],
  reviewing: ["quoted", "closed"],
  quoted: ["accepted", "closed"],
  accepted: ["closed"],
  closed: [],
};

const employeeRoles = ["marketing", "media", "designer", "engineer", "hr"] as const;
const departments = ["marketing", "media", "designer", "ict", "hr", "admin"] as const;
type DepartmentKey = typeof departments[number];

function departmentForUser(user: SessionUser): DepartmentKey | null {
  if (user.role === "admin") return "admin";
  if (user.role !== "staff") return null;
  if (user.employeeRole === "engineer") return "ict";
  if (user.employeeRole === "marketing") return "marketing";
  if (user.employeeRole === "media") return "media";
  if (user.employeeRole === "designer") return "designer";
  if (user.employeeRole === "hr") return "hr";
  return null;
}

function canManageNews(user: SessionUser, category?: string): boolean {
  if (user.role === "admin") return true;
  if (user.role !== "staff") return false;
  if (user.employeeRole === "marketing" || user.employeeRole === "media") {
    return true;
  }
  if (user.employeeRole === "hr") {
    return category === undefined || category === "careers";
  }
  return false;
}

function canManageCareers(user: SessionUser): boolean {
  return user.role === "admin" || (user.role === "staff" && user.employeeRole === "hr");
}

function canManageServices(user: SessionUser): boolean {
  return user.role === "admin" || (user.role === "staff" && user.employeeRole === "engineer");
}

function canManagePortfolio(user: SessionUser): boolean {
  return (
    user.role === "admin" ||
    (user.role === "staff" &&
      (user.employeeRole === "engineer" || user.employeeRole === "designer" || user.employeeRole === "marketing"))
  );
}

function canManageContentPages(user: SessionUser): boolean {
  return (
    user.role === "admin" ||
    (user.role === "staff" && (user.employeeRole === "designer" || user.employeeRole === "marketing"))
  );
}

function canManagePartners(user: SessionUser): boolean {
  return user.role === "admin" || (user.role === "staff" && user.employeeRole === "marketing");
}

function canManageLeads(user: SessionUser): boolean {
  return (
    user.role === "admin" ||
    (user.role === "staff" && (user.employeeRole === "marketing" || user.employeeRole === "engineer"))
  );
}

function canManageProjectRequests(user: SessionUser): boolean {
  return user.role === "admin" || (user.role === "staff" && user.employeeRole === "engineer");
}

function canManageDepartment(user: SessionUser, dept: DepartmentKey): boolean {
  if (user.role === "admin") return true;
  return departmentForUser(user) === dept;
}

function slugify(value: string, fallback: string, maxLen = 70): string {
  return (
    value
      .toLowerCase()
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, maxLen) || fallback
  );
}

function validNewsMedia(bytes: Uint8Array, contentType: string): boolean {
  if (contentType === "image/png") {
    return bytes.length >= 8 && bytes.slice(0, 8).join(",") === "137,80,78,71,13,10,26,10";
  }
  if (contentType === "image/jpeg") {
    return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  }
  if (contentType === "image/webp") {
    return (
      bytes.length >= 12 &&
      String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" &&
      String.fromCharCode(...bytes.slice(8, 12)) === "WEBP"
    );
  }
  if (contentType === "video/mp4") {
    return bytes.length >= 12 && String.fromCharCode(...bytes.slice(4, 8)) === "ftyp";
  }
  if (contentType === "video/webm") {
    return bytes.length >= 4 && bytes.slice(0, 4).join(",") === "26,69,223,163";
  }
  if (contentType === "audio/mpeg") {
    return (
      bytes.length >= 3 &&
      (String.fromCharCode(...bytes.slice(0, 3)) === "ID3" || (bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0))
    );
  }
  if (contentType === "audio/ogg") {
    return bytes.length >= 4 && String.fromCharCode(...bytes.slice(0, 4)) === "OggS";
  }
  if (contentType === "audio/wav") {
    return (
      bytes.length >= 12 &&
      String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" &&
      String.fromCharCode(...bytes.slice(8, 12)) === "WAVE"
    );
  }
  if (contentType === "audio/webm") {
    return bytes.length >= 4 && bytes.slice(0, 4).join(",") === "26,69,223,163";
  }
  if (contentType === "audio/mp4") {
    return bytes.length >= 12 && String.fromCharCode(...bytes.slice(4, 8)) === "ftyp";
  }
  return false;
}

function mediaType(contentType: string): "image" | "video" | "audio" {
  return contentType.startsWith("video/") ? "video" : contentType.startsWith("audio/") ? "audio" : "image";
}

async function readBinaryBody(request: Request, maxBytes: number): Promise<Uint8Array | Response> {
  const lengthHeader = request.headers.get("Content-Length");
  const length = lengthHeader === null ? null : Number(lengthHeader);
  if (!request.body || (length !== null && (!Number.isSafeInteger(length) || length < 1 || length > maxBytes))) {
    return failure(413, `Upload must be at most ${Math.round(maxBytes / 1_000_000)} MB`);
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return failure(413, `Upload must be at most ${Math.round(maxBytes / 1_000_000)} MB`);
    }
    chunks.push(value);
  }
  if (total < 1 || (length !== null && total !== length)) {
    return failure(400, "Upload body is empty or truncated");
  }
  const buffer = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return buffer;
}

async function newsApi(request: Request, env: AdminEnv, path: string, user: SessionUser): Promise<Response | null> {
  if (!path.startsWith("/api/admin/news")) return null;
  if (!canManageNews(user)) return failure(403, "Permission denied");

  const mediaMatch = path.match(/^\/api\/admin\/news\/media\/([a-f0-9-]{36})$/);
  if (mediaMatch && request.method === "POST") {
    const contentType = (request.headers.get("Content-Type") || "").split(";")[0]?.trim().toLowerCase() || "";
    const buffer = await readBinaryBody(request, 50_000_000);
    if (buffer instanceof Response) return buffer;
    if (!validNewsMedia(buffer, contentType)) {
      return failure(400, "Upload a valid image, video, or audio file");
    }
    const key = `public-news/${crypto.randomUUID()}`;
    await env.FILES.put(key, buffer, { httpMetadata: { contentType } });
    return json({ mediaKey: key, mediaType: mediaType(contentType), contentType }, 201);
  }

  if (path === "/api/admin/news/comments" && request.method === "GET") {
    const hrOnly = user.role === "staff" && user.employeeRole === "hr";
    const result = hrOnly
      ? await env.DB.prepare(`SELECT c.id, c.news_id, n.title AS news_title, n.slug AS news_slug,
          c.author_name, c.author_email, c.rating, c.body, c.status, c.created_at, c.updated_at
          FROM compiler_news_comments c JOIN compiler_news n ON n.id = c.news_id
          WHERE n.category = 'careers' ORDER BY c.created_at DESC LIMIT 200`).all()
      : await env.DB.prepare(`SELECT c.id, c.news_id, n.title AS news_title, n.slug AS news_slug,
          c.author_name, c.author_email, c.rating, c.body, c.status, c.created_at, c.updated_at
          FROM compiler_news_comments c JOIN compiler_news n ON n.id = c.news_id
          ORDER BY c.created_at DESC LIMIT 200`).all();
    return json({ comments: result.results });
  }

  const commentMatch = path.match(/^\/api\/admin\/news\/comments\/([a-f0-9-]{36})$/);
  if (commentMatch && request.method === "PUT") {
    const existing = await env.DB.prepare(`SELECT c.id, n.category FROM compiler_news_comments c
      JOIN compiler_news n ON n.id = c.news_id WHERE c.id = ?`)
      .bind(commentMatch[1]).first<{ id: string; category: string }>();
    if (!existing) return failure(404, "Comment not found");
    if (!canManageNews(user, existing.category)) return failure(403, "Permission denied");
    const data = await bodyJson(request);
    if (!data || !["published", "hidden"].includes(String(data.status))) {
      return failure(400, "Invalid comment status");
    }
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("UPDATE compiler_news_comments SET status = ?, updated_at = ? WHERE id = ?")
        .bind(data.status, now, existing.id),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'news-comment.moderate', 'news-comment', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, existing.id, JSON.stringify({ status: data.status }), now),
    ]);
    return json({ ok: true, id: existing.id, status: data.status });
  }

  if (commentMatch && request.method === "DELETE") {
    const existing = await env.DB.prepare(`SELECT c.id, n.category FROM compiler_news_comments c
      JOIN compiler_news n ON n.id = c.news_id WHERE c.id = ?`)
      .bind(commentMatch[1]).first<{ id: string; category: string }>();
    if (!existing) return failure(404, "Comment not found");
    if (!canManageNews(user, existing.category)) return failure(403, "Permission denied");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM compiler_news_comments WHERE id = ?").bind(existing.id),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'news-comment.delete', 'news-comment', ?, '{}', ?)`)
        .bind(crypto.randomUUID(), user.id, existing.id, now),
    ]);
    return json({ deleted: true, id: existing.id });
  }

  if (path === "/api/admin/news" && request.method === "GET") {
    const hrOnly = user.role === "staff" && user.employeeRole === "hr";
    const result = hrOnly
      ? await env.DB.prepare(`SELECT n.id, n.slug, n.title, n.summary, n.body, n.category, n.media_key, n.media_type,
          n.media_content_type, n.media_alt, n.published, n.created_at, n.updated_at, n.author_id,
          COALESCE(u.display_name, 'Team') AS author_name,
          COALESCE(m.views, 0) AS views, COALESCE(m.clicks, 0) AS clicks,
          COALESCE(m.likes, 0) AS likes, COALESCE(m.watch_seconds, 0) AS watch_seconds,
          (SELECT count(*) FROM compiler_news_comments c WHERE c.news_id = n.id AND c.status = 'published') AS comment_count,
          (SELECT ROUND(AVG(c.rating), 1) FROM compiler_news_comments c WHERE c.news_id = n.id AND c.status = 'published' AND c.rating IS NOT NULL) AS average_rating
          FROM compiler_news n
          LEFT JOIN compiler_users u ON u.id = n.author_id
          LEFT JOIN compiler_news_metrics m ON m.news_id = n.id
          WHERE n.category = 'careers'
          ORDER BY n.created_at DESC LIMIT 150`).all()
      : await env.DB.prepare(`SELECT n.id, n.slug, n.title, n.summary, n.body, n.category, n.media_key, n.media_type,
          n.media_content_type, n.media_alt, n.published, n.created_at, n.updated_at, n.author_id,
          COALESCE(u.display_name, 'Team') AS author_name,
          COALESCE(m.views, 0) AS views, COALESCE(m.clicks, 0) AS clicks,
          COALESCE(m.likes, 0) AS likes, COALESCE(m.watch_seconds, 0) AS watch_seconds,
          (SELECT count(*) FROM compiler_news_comments c WHERE c.news_id = n.id AND c.status = 'published') AS comment_count,
          (SELECT ROUND(AVG(c.rating), 1) FROM compiler_news_comments c WHERE c.news_id = n.id AND c.status = 'published' AND c.rating IS NOT NULL) AS average_rating
          FROM compiler_news n
          LEFT JOIN compiler_users u ON u.id = n.author_id
          LEFT JOIN compiler_news_metrics m ON m.news_id = n.id
          ORDER BY n.created_at DESC LIMIT 150`).all();
    return json({ news: result.results });
  }

  if (path === "/api/admin/news" && request.method === "POST") {
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const title = requiredField(data, "title", 160);
    const summary = requiredField(data, "summary", 400);
    const body = requiredField(data, "body", 12000);
    const category = data.category;
    const mediaKey = data.mediaKey === null || data.mediaKey === undefined || data.mediaKey === ""
      ? null
      : requiredField(data, "mediaKey", 100);
    const mediaAlt = data.mediaAlt === null || data.mediaAlt === undefined ? null : field(data, "mediaAlt", 300);
    const published = data.published;
    if (
      !title || !summary || !body || typeof category !== "string" ||
      !["news", "careers"].includes(category) || !canManageNews(user, category) ||
      (mediaKey !== null && (!mediaKey || !/^public-news\/[a-f0-9-]{36}$/.test(mediaKey))) ||
      (mediaAlt === null && data.mediaAlt !== null && data.mediaAlt !== undefined) ||
      typeof published !== "boolean"
    ) {
      return failure(400, "Complete the news details correctly");
    }
    let media: { media_type: string; content_type: string } | null = null;
    if (mediaKey) {
      const object = await env.FILES.head(mediaKey);
      if (!object) return failure(400, "Uploaded media was not found");
      const ct = object.httpMetadata?.contentType || "";
      if (!["image/png", "image/jpeg", "image/webp", "video/mp4", "video/webm", "audio/mpeg", "audio/ogg", "audio/wav", "audio/webm", "audio/mp4"].includes(ct)) {
        return failure(400, "Unsupported media type");
      }
      media = { media_type: mediaType(ct), content_type: ct };
    }
    const id = crypto.randomUUID();
    const slug = `${slugify(title, "news", 100)}-${id.slice(0, 8)}`;
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
    const existing = await env.DB.prepare(`SELECT id, slug, title, summary, body, category, media_key,
      media_type, media_content_type, media_alt, published
      FROM compiler_news WHERE id = ?`)
      .bind(postMatch[1]).first<{
        id: string; slug: string; title: string; summary: string; body: string; category: string;
        media_key: string | null; media_type: string | null; media_content_type: string | null;
        media_alt: string | null; published: number;
      }>();
    if (!existing) return failure(404, "News item not found");
    if (!canManageNews(user, existing.category)) return failure(403, "Permission denied");

    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");

    const hasFullFields = data.title !== undefined || data.summary !== undefined || data.body !== undefined;
    const nextTitle = data.title !== undefined ? requiredField(data, "title", 160) : existing.title;
    const nextSummary = data.summary !== undefined ? requiredField(data, "summary", 400) : existing.summary;
    const nextBody = data.body !== undefined ? requiredField(data, "body", 12000) : existing.body;
    const nextCategory = typeof data.category === "string" ? data.category : existing.category;
    const nextPublished = typeof data.published === "boolean" ? data.published : existing.published === 1;
    const nextMediaAlt = data.mediaAlt === undefined
      ? existing.media_alt
      : data.mediaAlt === null ? null : field(data, "mediaAlt", 300);

    if (
      !nextTitle || !nextSummary || !nextBody ||
      !["news", "careers"].includes(nextCategory) || !canManageNews(user, nextCategory) ||
      (nextMediaAlt === null && data.mediaAlt !== undefined && data.mediaAlt !== null)
    ) {
      return failure(400, "Complete the news details correctly");
    }

    let nextMediaKey = existing.media_key;
    let nextMediaType = existing.media_type;
    let nextMediaContentType = existing.media_content_type;
    let oldMediaToDelete: string | null = null;

    if (data.removeMedia === true || data.mediaKey === null) {
      if (existing.media_key) oldMediaToDelete = existing.media_key;
      nextMediaKey = null;
      nextMediaType = null;
      nextMediaContentType = null;
    } else if (typeof data.mediaKey === "string" && data.mediaKey && data.mediaKey !== existing.media_key) {
      if (!/^public-news\/[a-f0-9-]{36}$/.test(data.mediaKey)) return failure(400, "Invalid media key");
      const object = await env.FILES.head(data.mediaKey);
      if (!object) return failure(400, "Uploaded media was not found");
      const ct = object.httpMetadata?.contentType || "";
      if (!["image/png", "image/jpeg", "image/webp", "video/mp4", "video/webm", "audio/mpeg", "audio/ogg", "audio/wav", "audio/webm", "audio/mp4"].includes(ct)) {
        return failure(400, "Unsupported media type");
      }
      if (existing.media_key) oldMediaToDelete = existing.media_key;
      nextMediaKey = data.mediaKey;
      nextMediaType = mediaType(ct);
      nextMediaContentType = ct;
    }

    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`UPDATE compiler_news
        SET title = ?, summary = ?, body = ?, category = ?, media_key = ?, media_type = ?,
            media_content_type = ?, media_alt = ?, published = ?, updated_at = ?
        WHERE id = ?`)
        .bind(nextTitle, nextSummary, nextBody, nextCategory, nextMediaKey, nextMediaType,
          nextMediaContentType, nextMediaAlt, nextPublished ? 1 : 0, now, existing.id),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, ?, 'news', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, hasFullFields ? "news.update" : "news.publish", existing.id,
          JSON.stringify({ category: nextCategory, published: nextPublished }), now),
    ]);
    if (oldMediaToDelete) {
      await env.FILES.delete(oldMediaToDelete).catch(() => undefined);
    }
    return json({ ok: true, id: existing.id, published: nextPublished });
  }

  if (postMatch && request.method === "DELETE") {
    const existing = await env.DB.prepare("SELECT id, title, category, media_key FROM compiler_news WHERE id = ?")
      .bind(postMatch[1]).first<{ id: string; title: string; category: string; media_key: string | null }>();
    if (!existing) return failure(404, "News item not found");
    if (!canManageNews(user, existing.category)) return failure(403, "Permission denied");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM compiler_news WHERE id = ?").bind(existing.id),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'news.delete', 'news', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, existing.id, JSON.stringify({ title: existing.title }), now),
    ]);
    if (existing.media_key) {
      await env.FILES.delete(existing.media_key).catch(() => undefined);
    }
    return json({ deleted: true, id: existing.id });
  }

  return failure(404, "Not found");
}

async function careersApi(request: Request, env: AdminEnv, path: string, url: URL, user: SessionUser): Promise<Response | null> {
  if (!path.startsWith("/api/admin/careers") && !path.startsWith("/api/admin/career-applications")) return null;
  if (!canManageCareers(user)) return failure(403, "HR or Admin role required");

  if (path === "/api/admin/careers/media" && request.method === "POST") {
    const contentType = (request.headers.get("Content-Type") || "").split(";")[0]?.trim().toLowerCase() || "";
    if (!["image/png", "image/jpeg", "image/webp"].includes(contentType)) {
      return failure(400, "Upload a PNG, JPEG, or WebP image for the career thumbnail");
    }
    const buffer = await readBinaryBody(request, 10_000_000);
    if (buffer instanceof Response) return buffer;
    if (!validNewsMedia(buffer, contentType)) {
      return failure(400, "Invalid image file signature");
    }
    const key = `public-careers/${crypto.randomUUID()}`;
    await env.FILES.put(key, buffer, { httpMetadata: { contentType } });
    return json({ imageKey: key, contentType }, 201);
  }

  if (path === "/api/admin/careers" && request.method === "GET") {
    const result = await env.DB.prepare(`SELECT c.*, count(a.id) AS application_count
      FROM compiler_careers c LEFT JOIN compiler_career_applications a ON a.career_id = c.id
      GROUP BY c.id ORDER BY c.sort_order, c.created_at DESC`).all();
    return json({ careers: result.results });
  }

  if (path === "/api/admin/careers" && request.method === "POST") {
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const title = requiredField(data, "title", 160);
    const summary = requiredField(data, "summary", 600);
    const description = requiredField(data, "description", 8000);
    const location = requiredField(data, "location", 160);
    const employmentType = requiredField(data, "employmentType", 80);
    const department = data.department === undefined ? "" : field(data, "department", 120);
    const closingDate = data.closingDate === undefined || data.closingDate === "" ? null : field(data, "closingDate", 40);
    const imageKey = data.imageKey === undefined || data.imageKey === null || data.imageKey === ""
      ? null
      : requiredField(data, "imageKey", 120);
    const imageAlt = data.imageAlt === undefined || data.imageAlt === null ? null : field(data, "imageAlt", 240);
    const published = typeof data.published === "boolean" ? data.published : true;

    if (
      !title || !summary || !description || !location || !employmentType || department === null ||
      (imageKey !== null && !/^public-careers\/[a-f0-9-]{36}$/.test(imageKey))
    ) {
      return failure(400, "Complete all required job fields");
    }
    let imageContentType: string | null = null;
    if (imageKey) {
      const head = await env.FILES.head(imageKey);
      if (!head) return failure(400, "Uploaded career image was not found");
      imageContentType = head.httpMetadata?.contentType || "image/jpeg";
    }
    const id = `career-${crypto.randomUUID().slice(0, 12)}`;
    const slug = `${slugify(title, "career", 60)}-${id.slice(-6)}`;
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO compiler_careers
        (id, slug, title, summary, description, location, employment_type, department,
         image_key, image_content_type, image_alt, closing_date, published, sort_order, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 100, ?, ?, ?)`)
        .bind(id, slug, title, summary, description, location, employmentType, department,
          imageKey, imageContentType, imageAlt, closingDate, published ? 1 : 0, user.id, now, now),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'career.create', 'career', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, id, JSON.stringify({ title, published }), now),
    ]);
    return json({ career: { id, slug, title, summary, description, location, employment_type: employmentType, department, published } }, 201);
  }

  const careerMatch = path.match(/^\/api\/admin\/careers\/([a-zA-Z0-9-]{1,80})$/);
  if (careerMatch && request.method === "PUT") {
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const title = requiredField(data, "title", 160);
    const summary = requiredField(data, "summary", 600);
    const description = requiredField(data, "description", 8000);
    const location = requiredField(data, "location", 160);
    const employmentType = requiredField(data, "employmentType", 80);
    const department = data.department === undefined ? "" : field(data, "department", 120);
    const closingDate = data.closingDate === undefined || data.closingDate === "" ? null : field(data, "closingDate", 40);
    const imageAlt = data.imageAlt === undefined ? undefined : data.imageAlt === null ? null : field(data, "imageAlt", 240);
    if (!title || !summary || !description || !location || !employmentType || department === null || typeof data.published !== "boolean") {
      return failure(400, "Complete the career details correctly");
    }
    const existing = await env.DB.prepare("SELECT id, image_key, image_content_type, image_alt FROM compiler_careers WHERE id = ?")
      .bind(careerMatch[1]).first<{ id: string; image_key: string | null; image_content_type: string | null; image_alt: string | null }>();
    if (!existing) return failure(404, "Career not found");

    let nextImageKey = existing.image_key;
    let nextImageContentType = existing.image_content_type;
    let oldImageToDelete: string | null = null;
    if (data.removeImage === true || data.imageKey === null) {
      if (existing.image_key) oldImageToDelete = existing.image_key;
      nextImageKey = null;
      nextImageContentType = null;
    } else if (typeof data.imageKey === "string" && data.imageKey && data.imageKey !== existing.image_key) {
      if (!/^public-careers\/[a-f0-9-]{36}$/.test(data.imageKey)) return failure(400, "Invalid image key");
      const head = await env.FILES.head(data.imageKey);
      if (!head) return failure(400, "Uploaded career image was not found");
      if (existing.image_key) oldImageToDelete = existing.image_key;
      nextImageKey = data.imageKey;
      nextImageContentType = head.httpMetadata?.contentType || "image/jpeg";
    }
    const nextImageAlt = imageAlt === undefined ? existing.image_alt : imageAlt;
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`UPDATE compiler_careers
        SET title = ?, summary = ?, description = ?, location = ?, employment_type = ?,
            department = ?, closing_date = ?, image_key = ?, image_content_type = ?, image_alt = ?,
            published = ?, updated_at = ?
        WHERE id = ?`)
        .bind(title, summary, description, location, employmentType, department, closingDate,
          nextImageKey, nextImageContentType, nextImageAlt, data.published ? 1 : 0, now, existing.id),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'career.update', 'career', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, existing.id, JSON.stringify({ published: data.published }), now),
    ]);
    if (oldImageToDelete) {
      await env.FILES.delete(oldImageToDelete).catch(() => undefined);
    }
    return json({ career: { id: existing.id, title, summary, description, location, employment_type: employmentType, department, published: data.published } });
  }

  if (careerMatch && request.method === "DELETE") {
    const existing = await env.DB.prepare("SELECT id, title, image_key FROM compiler_careers WHERE id = ?")
      .bind(careerMatch[1]).first<{ id: string; title: string; image_key: string | null }>();
    if (!existing) return failure(404, "Career not found");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM compiler_career_applications WHERE career_id = ?").bind(existing.id),
      env.DB.prepare("DELETE FROM compiler_careers WHERE id = ?").bind(existing.id),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'career.delete', 'career', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, existing.id, JSON.stringify({ title: existing.title }), now),
    ]);
    if (existing.image_key) {
      await env.FILES.delete(existing.image_key).catch(() => undefined);
    }
    return json({ deleted: true, id: existing.id });
  }

  if (path === "/api/admin/career-applications" && request.method === "GET") {
    const rawPage = url.searchParams.get("page") || "1";
    const rawLimit = url.searchParams.get("limit") || "50";
    const page = Number(rawPage);
    const limit = Number(rawLimit);
    const status = url.searchParams.get("status");
    if (!Number.isInteger(page) || page < 1 || page > 10000 || !Number.isInteger(limit) || limit < 1 || limit > 100 ||
        (status && !["new", "reviewed", "closed"].includes(status))) {
      return failure(400, "Invalid application query");
    }
    const offset = (page - 1) * limit;
    const count = status
      ? await env.DB.prepare("SELECT count(*) AS total FROM compiler_career_applications WHERE status = ?").bind(status).first<{ total: number }>()
      : await env.DB.prepare("SELECT count(*) AS total FROM compiler_career_applications").first<{ total: number }>();
    const result = status
      ? await env.DB.prepare(`SELECT a.*, c.title AS career_title FROM compiler_career_applications a
          JOIN compiler_careers c ON c.id = a.career_id WHERE a.status = ? ORDER BY a.created_at DESC LIMIT ? OFFSET ?`)
        .bind(status, limit, offset).all()
      : await env.DB.prepare(`SELECT a.*, c.title AS career_title FROM compiler_career_applications a
          JOIN compiler_careers c ON c.id = a.career_id ORDER BY a.created_at DESC LIMIT ? OFFSET ?`)
        .bind(limit, offset).all();
    const total = count?.total || 0;
    return json({ applications: result.results, pagination: { page, pageSize: limit, total, totalPages: Math.max(1, Math.ceil(total / limit)) } });
  }

  const applicationMatch = path.match(/^\/api\/admin\/career-applications\/([a-f0-9-]{36})$/);
  if (applicationMatch && request.method === "PUT") {
    const data = await bodyJson(request);
    if (!data || !["new", "reviewed", "closed"].includes(String(data.status))) return failure(400, "Invalid application status");
    const existing = await env.DB.prepare("SELECT id FROM compiler_career_applications WHERE id = ?").bind(applicationMatch[1]).first();
    if (!existing) return failure(404, "Application not found");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("UPDATE compiler_career_applications SET status = ? WHERE id = ?").bind(data.status, applicationMatch[1]),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'career-application.update', 'career-application', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, applicationMatch[1], JSON.stringify({ status: data.status }), now),
    ]);
    return json({ application: { id: applicationMatch[1], status: data.status } });
  }

  if (applicationMatch && request.method === "DELETE") {
    const existing = await env.DB.prepare("SELECT id FROM compiler_career_applications WHERE id = ?").bind(applicationMatch[1]).first();
    if (!existing) return failure(404, "Application not found");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM compiler_career_applications WHERE id = ?").bind(applicationMatch[1]),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'career-application.delete', 'career-application', ?, '{}', ?)`)
        .bind(crypto.randomUUID(), user.id, applicationMatch[1], now),
    ]);
    return json({ deleted: true, id: applicationMatch[1] });
  }

  return failure(404, "Not found");
}

async function serviceRequestsApi(request: Request, env: AdminEnv, path: string, user: SessionUser): Promise<Response | null> {
  if (!path.startsWith("/api/admin/service-requests")) return null;
  if (!canManageLeads(user)) return failure(403, "Permission denied");

  if (path === "/api/admin/service-requests" && request.method === "GET") {
    const result = await env.DB.prepare(`SELECT r.*, s.name AS service_name
      FROM compiler_service_requests r LEFT JOIN compiler_services s ON s.slug = r.service_slug
      ORDER BY r.created_at DESC LIMIT 150`).all();
    return json({ serviceRequests: result.results });
  }
  const match = path.match(/^\/api\/admin\/service-requests\/([a-f0-9-]{36})$/);
  if (match && request.method === "PUT") {
    const data = await bodyJson(request);
    if (!data || !["new", "contacted", "closed"].includes(String(data.status))) return failure(400, "Invalid service request status");
    const existing = await env.DB.prepare("SELECT id, status FROM compiler_service_requests WHERE id = ?")
      .bind(match[1]).first<{ id: string; status: string }>();
    if (!existing) return failure(404, "Service request not found");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("UPDATE compiler_service_requests SET status = ? WHERE id = ?").bind(data.status, match[1]),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'service-request.update', 'service-request', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, match[1], JSON.stringify({ from: existing.status, to: data.status }), now),
    ]);
    return json({ serviceRequest: { id: match[1], status: data.status } });
  }
  if (match && request.method === "DELETE") {
    const existing = await env.DB.prepare("SELECT id FROM compiler_service_requests WHERE id = ?").bind(match[1]).first();
    if (!existing) return failure(404, "Service request not found");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM compiler_service_requests WHERE id = ?").bind(match[1]),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'service-request.delete', 'service-request', ?, '{}', ?)`)
        .bind(crypto.randomUUID(), user.id, match[1], now),
    ]);
    return json({ deleted: true, id: match[1] });
  }
  return failure(404, "Not found");
}

async function partnersApi(request: Request, env: AdminEnv, path: string, user: SessionUser): Promise<Response | null> {
  if (!path.startsWith("/api/admin/partners")) return null;
  if (!canManagePartners(user)) return failure(403, "Marketing or Admin role required");

  if (path === "/api/admin/partners" && request.method === "GET") {
    const result = await env.DB.prepare("SELECT * FROM compiler_partners ORDER BY sort_order, name").all();
    return json({ partners: result.results });
  }
  if (path === "/api/admin/partners" && request.method === "POST") {
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const name = requiredField(data, "name", 160);
    const websiteUrl = requiredField(data, "websiteUrl", 400);
    const logoPath = requiredField(data, "logoPath", 300);
    const active = typeof data.active === "boolean" ? data.active : true;
    const rawSlug = data.slug ? field(data, "slug", 80) : slugify(name || "", "partner", 60);
    if (!name || !websiteUrl || !/^https?:\/\//.test(websiteUrl) || !logoPath || !rawSlug || !/^[a-z0-9-]{2,80}$/.test(rawSlug)) {
      return failure(400, "Enter a valid partner name, HTTPS website URL, and logo path");
    }
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO compiler_partners (slug, name, website_url, logo_path, sort_order, active)
        VALUES (?, ?, ?, ?, 100, ?)
        ON CONFLICT(slug) DO UPDATE SET name = excluded.name, website_url = excluded.website_url,
        logo_path = excluded.logo_path, active = excluded.active`)
        .bind(rawSlug, name, websiteUrl, logoPath, active ? 1 : 0),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'partner.upsert', 'partner', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, rawSlug, JSON.stringify({ name, active }), now),
    ]);
    return json({ partner: { slug: rawSlug, name, website_url: websiteUrl, logo_path: logoPath, active: active ? 1 : 0 } }, 201);
  }
  const match = path.match(/^\/api\/admin\/partners\/([a-z0-9-]{2,80})$/);
  if (match && request.method === "PUT") {
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const name = requiredField(data, "name", 160);
    const websiteUrl = requiredField(data, "websiteUrl", 400);
    const logoPath = requiredField(data, "logoPath", 300);
    if (!name || !websiteUrl || !/^https?:\/\//.test(websiteUrl) || !logoPath || typeof data.active !== "boolean") {
      return failure(400, "Enter valid partner details");
    }
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("UPDATE compiler_partners SET name = ?, website_url = ?, logo_path = ?, active = ? WHERE slug = ?")
        .bind(name, websiteUrl, logoPath, data.active ? 1 : 0, match[1]),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'partner.update', 'partner', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, match[1], JSON.stringify({ active: data.active }), now),
    ]);
    return json({ ok: true, slug: match[1] });
  }
  if (match && request.method === "DELETE") {
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM compiler_partners WHERE slug = ?").bind(match[1]),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'partner.delete', 'partner', ?, '{}', ?)`)
        .bind(crypto.randomUUID(), user.id, match[1], now),
    ]);
    return json({ deleted: true, slug: match[1] });
  }
  return failure(404, "Not found");
}

async function portfolioApi(request: Request, env: AdminEnv, path: string, user: SessionUser): Promise<Response | null> {
  if (!path.startsWith("/api/admin/portfolio")) return null;
  if (!canManagePortfolio(user)) return failure(403, "Permission denied");

  if (path === "/api/admin/portfolio" && request.method === "GET") {
    const result = await env.DB.prepare("SELECT * FROM compiler_portfolio_items ORDER BY sort_order, updated_at DESC").all();
    return json({ portfolio: result.results });
  }
  if (path === "/api/admin/portfolio" && request.method === "POST") {
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const title = requiredField(data, "title", 160);
    const divisionSlug = requiredField(data, "divisionSlug", 80);
    const clientSector = requiredField(data, "clientSector", 120);
    const summary = requiredField(data, "summary", 600);
    const deliverables = requiredField(data, "deliverables", 2000);
    const status = String(data.status || "completed");
    const completedYear = data.completedYear ? field(data, "completedYear", 12) : null;
    const published = typeof data.published === "boolean" ? data.published : true;
    if (!title || !divisionSlug || !clientSector || !summary || !deliverables || !["completed", "ongoing", "archived"].includes(status)) {
      return failure(400, "Complete all required portfolio fields");
    }
    const id = `port-${crypto.randomUUID().slice(0, 12)}`;
    const slug = `${slugify(title, "work", 60)}-${id.slice(-6)}`;
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO compiler_portfolio_items
        (id, slug, title, division_slug, client_sector, summary, deliverables, status, completed_year, published, sort_order, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 100, ?, ?)`)
        .bind(id, slug, title, divisionSlug, clientSector, summary, deliverables, status, completedYear, published ? 1 : 0, now, now),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'portfolio.create', 'portfolio', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, id, JSON.stringify({ title, published }), now),
    ]);
    return json({ item: { id, slug, title, published } }, 201);
  }
  const match = path.match(/^\/api\/admin\/portfolio\/([a-zA-Z0-9-]{2,80})$/);
  if (match && request.method === "PUT") {
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const title = requiredField(data, "title", 160);
    const divisionSlug = requiredField(data, "divisionSlug", 80);
    const clientSector = requiredField(data, "clientSector", 120);
    const summary = requiredField(data, "summary", 600);
    const deliverables = requiredField(data, "deliverables", 2000);
    const status = String(data.status || "completed");
    const completedYear = data.completedYear ? field(data, "completedYear", 12) : null;
    if (!title || !divisionSlug || !clientSector || !summary || !deliverables ||
        !["completed", "ongoing", "archived"].includes(status) || typeof data.published !== "boolean") {
      return failure(400, "Complete all required portfolio fields");
    }
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`UPDATE compiler_portfolio_items
        SET title = ?, division_slug = ?, client_sector = ?, summary = ?, deliverables = ?,
            status = ?, completed_year = ?, published = ?, updated_at = ?
        WHERE id = ?`)
        .bind(title, divisionSlug, clientSector, summary, deliverables, status, completedYear, data.published ? 1 : 0, now, match[1]),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'portfolio.update', 'portfolio', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, match[1], JSON.stringify({ published: data.published }), now),
    ]);
    return json({ ok: true, id: match[1] });
  }
  if (match && request.method === "DELETE") {
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM compiler_portfolio_items WHERE id = ?").bind(match[1]),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'portfolio.delete', 'portfolio', ?, '{}', ?)`)
        .bind(crypto.randomUUID(), user.id, match[1], now),
    ]);
    return json({ deleted: true, id: match[1] });
  }
  return failure(404, "Not found");
}

async function departmentItemsApi(request: Request, env: AdminEnv, path: string, url: URL, user: SessionUser): Promise<Response | null> {
  if (!path.startsWith("/api/admin/department-items")) return null;

  if (path === "/api/admin/department-items" && request.method === "GET") {
    const reqDept = (url.searchParams.get("department") || departmentForUser(user) || "") as DepartmentKey;
    if (!departments.includes(reqDept)) return failure(400, "Invalid department");
    if (!canManageDepartment(user, reqDept)) return failure(403, "Permission denied");
    const result = await env.DB.prepare(`SELECT d.*, COALESCE(u.display_name, 'Team') AS creator_name
      FROM compiler_department_items d LEFT JOIN compiler_users u ON u.id = d.created_by
      WHERE d.department = ? ORDER BY
        CASE d.priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 ELSE 4 END,
        d.updated_at DESC LIMIT 150`)
      .bind(reqDept).all();
    return json({ items: result.results });
  }

  if (path === "/api/admin/department-items" && request.method === "POST") {
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const dept = String(data.department || departmentForUser(user) || "") as DepartmentKey;
    if (!departments.includes(dept) || !canManageDepartment(user, dept)) return failure(403, "Permission denied");
    const title = requiredField(data, "title", 180);
    const summary = data.summary === undefined ? "" : field(data, "summary", 2000);
    const itemType = field(data, "itemType", 60) || "task";
    const status = String(data.status || "planned");
    const priority = String(data.priority || "normal");
    const dueDate = data.dueDate === undefined || data.dueDate === "" ? null : field(data, "dueDate", 40);
    if (
      !title || summary === null ||
      !["planned", "in_progress", "review", "completed", "archived"].includes(status) ||
      !["low", "normal", "high", "urgent"].includes(priority)
    ) {
      return failure(400, "Complete the work item fields correctly");
    }
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO compiler_department_items
        (id, department, item_type, title, summary, status, priority, due_date, owner_id, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(id, dept, itemType, title, summary, status, priority, dueDate, user.id, user.id, now, now),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'department-item.create', 'department-item', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, id, JSON.stringify({ dept, title, status }), now),
    ]);
    return json({ item: { id, department: dept, item_type: itemType, title, summary, status, priority, due_date: dueDate } }, 201);
  }

  const match = path.match(/^\/api\/admin\/department-items\/([a-f0-9-]{36})$/);
  if (match && request.method === "PUT") {
    const existing = await env.DB.prepare("SELECT * FROM compiler_department_items WHERE id = ?")
      .bind(match[1]).first<{ id: string; department: DepartmentKey; item_type: string; title: string; summary: string; status: string; priority: string; due_date: string | null }>();
    if (!existing) return failure(404, "Item not found");
    if (!canManageDepartment(user, existing.department)) return failure(403, "Permission denied");
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const title = data.title !== undefined ? requiredField(data, "title", 180) : existing.title;
    const summary = data.summary !== undefined ? field(data, "summary", 2000) : existing.summary;
    const itemType = data.itemType !== undefined ? field(data, "itemType", 60) : existing.item_type;
    const status = data.status !== undefined ? String(data.status) : existing.status;
    const priority = data.priority !== undefined ? String(data.priority) : existing.priority;
    const dueDate = data.dueDate !== undefined ? (data.dueDate === "" || data.dueDate === null ? null : field(data, "dueDate", 40)) : existing.due_date;
    if (
      !title || summary === null || !itemType ||
      !["planned", "in_progress", "review", "completed", "archived"].includes(status) ||
      !["low", "normal", "high", "urgent"].includes(priority)
    ) {
      return failure(400, "Invalid update");
    }
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`UPDATE compiler_department_items
        SET title = ?, summary = ?, item_type = ?, status = ?, priority = ?, due_date = ?, updated_at = ?
        WHERE id = ?`)
        .bind(title, summary, itemType, status, priority, dueDate, now, existing.id),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'department-item.update', 'department-item', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, existing.id, JSON.stringify({ status, priority }), now),
    ]);
    return json({ ok: true, id: existing.id });
  }

  if (match && request.method === "DELETE") {
    const existing = await env.DB.prepare("SELECT id, department FROM compiler_department_items WHERE id = ?")
      .bind(match[1]).first<{ id: string; department: DepartmentKey }>();
    if (!existing) return failure(404, "Item not found");
    if (!canManageDepartment(user, existing.department)) return failure(403, "Permission denied");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM compiler_department_items WHERE id = ?").bind(existing.id),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'department-item.delete', 'department-item', ?, '{}', ?)`)
        .bind(crypto.randomUUID(), user.id, existing.id, now),
    ]);
    return json({ deleted: true, id: existing.id });
  }

  return failure(404, "Not found");
}

async function handle(request: Request, env: AdminEnv, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  if ((request.method === "GET" || request.method === "HEAD") && isPublicSitePath(path)) {
    return Response.redirect(`${publicSiteOrigin(env)}${path}${url.search}`, 302);
  }
  if ((request.method === "GET" || request.method === "HEAD") && path === "/") {
    return Response.redirect(new URL("/admin", url), 302);
  }
  if ((request.method === "GET" || request.method === "HEAD") && (path === "/login" || path === "/login.html")) {
    return Response.redirect(`${env.AUTH_ORIGIN}/login${url.search}`, 302);
  }
  if ((request.method === "GET" || request.method === "HEAD") && /^\/staff\/(ict|marketing|media|designer|engineer|hr)$/.test(path)) {
    return env.ASSETS.fetch(assetRequest(new Request(new URL("/admin", url), request)));
  }
  if (path.startsWith("/staff/")) return failure(404, "Not found");
  if (!path.startsWith("/api/") && !path.startsWith("/internal/")) return env.ASSETS.fetch(assetRequest(request));

  const user = await authorize(request, env.AUTH, ["admin", "staff"]);
  if (isResponse(user)) return user;

  // Departmental & shared APIs (admin has full access to all of them!)
  for (const fn of [
    () => newsApi(request, env, path, user),
    () => careersApi(request, env, path, url, user),
    () => serviceRequestsApi(request, env, path, user),
    () => partnersApi(request, env, path, user),
    () => portfolioApi(request, env, path, user),
    () => departmentItemsApi(request, env, path, url, user),
  ]) {
    const response = await fn();
    if (response) return response;
  }

  // Inquiries (Admin, Marketing, ICT)
  if (path === "/api/admin/inquiries" && request.method === "GET") {
    if (!canManageLeads(user)) return failure(403, "Permission denied");
    const result = await env.DB.prepare("SELECT * FROM compiler_inquiries ORDER BY created_at DESC LIMIT 150").all();
    return json({ inquiries: result.results });
  }
  const inquiryMatch = path.match(/^\/api\/admin\/inquiries\/([a-f0-9-]{36})$/);
  if (inquiryMatch && request.method === "DELETE") {
    if (!canManageLeads(user)) return failure(403, "Permission denied");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM compiler_inquiries WHERE id = ?").bind(inquiryMatch[1]),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'inquiry.delete', 'inquiry', ?, '{}', ?)`)
        .bind(crypto.randomUUID(), user.id, inquiryMatch[1], now),
    ]);
    return json({ deleted: true, id: inquiryMatch[1] });
  }

  // Client Project Requests (Admin & ICT)
  if (path === "/api/admin/requests" && request.method === "GET") {
    if (!canManageProjectRequests(user)) return failure(403, "Permission denied");
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
    if (!canManageProjectRequests(user)) return failure(403, "Permission denied");
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const status = requiredField(data, "status", 30);
    const assignedTo = data.assignedTo === null ? null : field(data, "assignedTo", 80);
    if (!status || !Object.hasOwn(transitions, status) || (assignedTo === null && data.assignedTo !== null && data.assignedTo !== undefined)) {
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

  // Public Pages Content (Admin, Designer, Marketing)
  if (path === "/api/admin/content" && request.method === "GET") {
    if (!canManageContentPages(user)) return failure(403, "Permission denied");
    const result = await env.DB.prepare("SELECT * FROM compiler_content ORDER BY title").all();
    return json({ pages: result.results });
  }
  const contentMatch = path.match(/^\/api\/admin\/content\/([a-zA-Z][a-zA-Z0-9]{0,79})$/);
  if (contentMatch && request.method === "PUT") {
    if (!canManageContentPages(user)) return failure(403, "Permission denied");
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

  // Services & Advisory Services (Admin & ICT)
  if (path === "/api/admin/services" && request.method === "GET") {
    if (!canManageServices(user)) return failure(403, "Permission denied");
    const result = await env.DB.prepare("SELECT * FROM compiler_services ORDER BY name").all();
    return json({ services: result.results });
  }
  const serviceMatch = path.match(/^\/api\/admin\/services\/([a-z][a-z0-9-]{0,79})$/);
  if (serviceMatch && request.method === "PUT") {
    if (!canManageServices(user)) return failure(403, "Permission denied");
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const name = requiredField(data, "name", 160);
    const description = requiredField(data, "description", 2000);
    const businessNatureSlug = field(data, "businessNatureSlug", 80) || "information-technology";
    if (!name || !description || typeof data.active !== "boolean") return failure(400, "Invalid service");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO compiler_services (slug, name, description, active, business_nature_slug)
        VALUES (?, ?, ?, ?, ?) ON CONFLICT(slug) DO UPDATE SET name = excluded.name,
        description = excluded.description, active = excluded.active,
        business_nature_slug = COALESCE(compiler_services.business_nature_slug, excluded.business_nature_slug)`)
        .bind(serviceMatch[1], name, description, data.active ? 1 : 0, businessNatureSlug),
      env.DB.prepare("INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(crypto.randomUUID(), user.id, "service.update", "service", serviceMatch[1], JSON.stringify({ active: data.active }), now),
    ]);
    return json({ service: { slug: serviceMatch[1], name, description, active: data.active } });
  }
  if (serviceMatch && request.method === "DELETE") {
    if (!canManageServices(user)) return failure(403, "Permission denied");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM compiler_services WHERE slug = ?").bind(serviceMatch[1]),
      env.DB.prepare("INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at) VALUES (?, ?, 'service.delete', 'service', ?, '{}', ?)")
        .bind(crypto.randomUUID(), user.id, serviceMatch[1], now),
    ]);
    return json({ deleted: true, slug: serviceMatch[1] });
  }

  if (path === "/api/admin/advisory-services" && request.method === "GET") {
    if (!canManageServices(user)) return failure(403, "Permission denied");
    const result = await env.DB.prepare("SELECT * FROM compiler_advisory_services ORDER BY sort_order, name").all();
    return json({ advisoryServices: result.results });
  }
  const advisoryMatch = path.match(/^\/api\/admin\/advisory-services\/([a-z][a-z0-9-]{0,79})$/);
  if (advisoryMatch && request.method === "PUT") {
    if (!canManageServices(user)) return failure(403, "Permission denied");
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
  if (advisoryMatch && request.method === "DELETE") {
    if (!canManageServices(user)) return failure(403, "Permission denied");
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM compiler_advisory_services WHERE slug = ?").bind(advisoryMatch[1]),
      env.DB.prepare("INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at) VALUES (?, ?, 'advisory-service.delete', 'advisory-service', ?, '{}', ?)")
        .bind(crypto.randomUUID(), user.id, advisoryMatch[1], now),
    ]);
    return json({ deleted: true, slug: advisoryMatch[1] });
  }

  // Staff directory read for HR/ICT/Admin (mutations strictly Admin)
  if (path === "/api/admin/users" && request.method === "GET") {
    if (user.role !== "admin" && !(user.role === "staff" && (user.employeeRole === "hr" || user.employeeRole === "engineer"))) {
      return failure(403, "Permission denied");
    }
    const result = await env.DB.prepare(`SELECT id, email, display_name, role, employee_role, department, position, created_at
      FROM compiler_users ORDER BY created_at DESC LIMIT 100`).all();
    return json({ users: result.results });
  }

  // Strictly Admin-only routes below (Director / Super-Administrator)
  if (user.role !== "admin") return failure(403, "Admin role required");

  if (path === "/api/admin/overview" && request.method === "GET") {
    const [clients, requests, open, inquiries, serviceReqs, newsCount, commentsCount, careersCount, appsCount, usersCount, portfolioCount] = await Promise.all([
      env.DB.prepare("SELECT count(*) AS n FROM compiler_organizations").first<{ n: number }>(),
      env.DB.prepare("SELECT count(*) AS n FROM compiler_requests").first<{ n: number }>(),
      env.DB.prepare("SELECT count(*) AS n FROM compiler_requests WHERE status != 'closed'").first<{ n: number }>(),
      env.DB.prepare("SELECT count(*) AS n FROM compiler_inquiries").first<{ n: number }>(),
      env.DB.prepare("SELECT count(*) AS n FROM compiler_service_requests WHERE status != 'closed'").first<{ n: number }>(),
      env.DB.prepare("SELECT count(*) AS n FROM compiler_news WHERE published = 1").first<{ n: number }>(),
      env.DB.prepare("SELECT count(*) AS n FROM compiler_news_comments WHERE status = 'published'").first<{ n: number }>(),
      env.DB.prepare("SELECT count(*) AS n FROM compiler_careers WHERE published = 1").first<{ n: number }>(),
      env.DB.prepare("SELECT count(*) AS n FROM compiler_career_applications WHERE status = 'new'").first<{ n: number }>(),
      env.DB.prepare("SELECT count(*) AS n FROM compiler_users").first<{ n: number }>(),
      env.DB.prepare("SELECT count(*) AS n FROM compiler_portfolio_items WHERE published = 1").first<{ n: number }>(),
    ]);
    return json({
      clients: clients?.n || 0,
      requests: requests?.n || 0,
      openRequests: open?.n || 0,
      inquiries: inquiries?.n || 0,
      openServiceRequests: serviceReqs?.n || 0,
      publishedNews: newsCount?.n || 0,
      publishedComments: commentsCount?.n || 0,
      openCareers: careersCount?.n || 0,
      pendingApplications: appsCount?.n || 0,
      usersCount: usersCount?.n || 0,
      portfolioCount: portfolioCount?.n || 0,
    });
  }

  if (path === "/api/admin/clients" && request.method === "GET") {
    const result = await env.DB.prepare(`SELECT o.*, u.email AS owner_email
      FROM compiler_organizations o JOIN compiler_users u ON u.id = o.owner_user_id
      ORDER BY o.created_at DESC LIMIT 100`).all();
    return json({ clients: result.results });
  }

  const roleMatch = path.match(/^\/api\/admin\/users\/([a-f0-9-]{36})\/role$/);
  if (roleMatch && request.method === "PUT") {
    const data = await bodyJson(request);
    if (!data || !["client", "staff"].includes(String(data.role))) return failure(400, "Invalid role");
    if (roleMatch[1] === user.id) return failure(400, "You cannot change your own role");
    const target = await env.DB.prepare("SELECT role FROM compiler_users WHERE id = ?").bind(roleMatch[1]).first<{ role: string }>();
    if (!target) return failure(404, "User not found");
    if (target.role === "admin") return failure(403, "Admin role cannot be changed here");
    const isStaff = data.role === "staff";
    const employeeRole = isStaff ? data.employeeRole : null;
    const department = isStaff ? requiredField(data, "department", 120) : null;
    const position = isStaff ? requiredField(data, "position", 120) : null;
    if (isStaff && (typeof employeeRole !== "string" || !employeeRoles.includes(employeeRole as typeof employeeRoles[number]) || !department || !position)) {
      return failure(400, "Staff accounts require an employee role, department, and position");
    }
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`UPDATE compiler_users SET role = ?, employee_role = ?, department = ?, position = ?, updated_at = ?
        WHERE id = ? AND role != 'admin'`).bind(data.role, employeeRole, department, position, now, roleMatch[1]),
      env.DB.prepare("DELETE FROM compiler_sessions WHERE user_id = ?").bind(roleMatch[1]),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, 'user.role', 'user', ?, ?, ?)`)
        .bind(crypto.randomUUID(), user.id, roleMatch[1], JSON.stringify({ role: data.role, employeeRole, department, position }), now),
    ]);
    return json({ ok: true });
  }

  if (path === "/api/admin/users/invitations" && request.method === "POST") {
    const data = await bodyJson(request);
    if (!data) return failure(400, "Invalid JSON");
    const email = requiredField(data, "email", 320);
    const displayName = requiredField(data, "displayName", 160);
    const accountRole = data.accountRole === "client" ? "client" : "staff";
    const position = accountRole === "staff" ? requiredField(data, "position", 120) : null;
    const department = accountRole === "staff" ? requiredField(data, "department", 120) : null;
    const employeeRole = accountRole === "staff" ? data.employeeRole : null;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !displayName) {
      return failure(400, "Enter a valid email and full name");
    }
    if (
      accountRole === "staff" &&
      (!position || !department || typeof employeeRole !== "string" ||
        !employeeRoles.includes(employeeRole as typeof employeeRoles[number]))
    ) {
      return failure(400, "Enter a valid department role, department, and position");
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
    const messageLines = accountRole === "client"
      ? [
          `Hello ${displayName},`,
          "",
          "An administrator at Compiler Technologies Limited has provisioned your client portal account.",
          "",
          "Use this one-time link within 24 hours to set your password and sign in:",
          setupUrl,
          "",
          "If you were not expecting this invitation, you can ignore this message.",
        ]
      : [
          `Hello ${displayName},`,
          "",
          "An administrator invited you to Compiler Technologies Limited.",
          `Role: ${employeeRole}`,
          `Department: ${department}`,
          `Position: ${position}`,
          "",
          "Use this one-time link within 24 hours to set your password:",
          setupUrl,
          "",
          "If you were not expecting this invitation, you can ignore this message.",
        ];
    const message = messageLines.join("\n");
    const outboxId = crypto.randomUUID();
    const result = await env.DB.batch([
      env.DB.prepare(`INSERT INTO compiler_employee_invitations
        (id, email_normalized, email, display_name, role, employee_role, department, position,
          token_hash, expires_at, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(email_normalized) DO UPDATE SET id = excluded.id, email = excluded.email,
          display_name = excluded.display_name, role = excluded.role, employee_role = excluded.employee_role,
          department = excluded.department, position = excluded.position, token_hash = excluded.token_hash,
          expires_at = excluded.expires_at, created_by = excluded.created_by, used_at = NULL,
          created_at = excluded.created_at
        WHERE compiler_employee_invitations.used_at IS NOT NULL OR compiler_employee_invitations.expires_at <= ?`)
        .bind(crypto.randomUUID(), emailNormalized, email, displayName, accountRole, employeeRole, department, position,
          tokenHash, expiresAt, user.id, now, now),
      env.DB.prepare(`INSERT INTO compiler_outbox (id, recipient, subject, body, created_at)
        SELECT ?, ?, ?, ?, ? WHERE EXISTS (
          SELECT 1 FROM compiler_employee_invitations WHERE token_hash = ? AND used_at IS NULL
        )`)
        .bind(outboxId, email, "Your Compiler employee invitation", message, now, tokenHash),
      env.DB.prepare(`INSERT INTO compiler_audit (id, actor_id, action, target_type, target_id, details, created_at)
        SELECT ?, ?, ?, 'invitation', ?, ?, ? WHERE EXISTS (
          SELECT 1 FROM compiler_employee_invitations WHERE token_hash = ?
        )`)
        .bind(crypto.randomUUID(), user.id, accountRole === "client" ? "client.invite" : "employee.invite", emailNormalized,
          JSON.stringify({ accountRole, employeeRole, department, position }), now, tokenHash),
    ]);
    if (result[0]?.meta.changes !== 1 || result[1]?.meta.changes !== 1) {
      return failure(409, "There is already an active invitation for that email.");
    }
    const delivery = await env.CLIENT.fetch(new Request("https://client.internal/internal/email/send", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Internal-Key": env.INTERNAL_SERVICE_KEY },
      body: JSON.stringify({ outboxId }),
    }));
    if (!delivery.ok) {
      const detail = await delivery.text().catch(() => "");
      console.error("Invitation email delivery failed", { status: delivery.status, detail });
      await env.DB.batch([
        env.DB.prepare("DELETE FROM compiler_employee_invitations WHERE token_hash = ? AND used_at IS NULL").bind(tokenHash),
        env.DB.prepare("DELETE FROM compiler_outbox WHERE id = ? AND sent_at IS NULL").bind(outboxId),
      ]);
      return failure(502, "Invitation email could not be sent via SMTP. Verify mailbox SMTP access and try again.");
    }
    return json({ invitation: { email, expiresAt } }, 201);
  }

  if (path === "/api/admin/audit" && request.method === "GET") {
    const result = await env.DB.prepare("SELECT * FROM compiler_audit ORDER BY created_at DESC LIMIT 100").all();
    return json({ events: result.results });
  }

  return failure(404, "Not found");
}

export default {
  async fetch(request: Request, env: AdminEnv, ctx: ExecutionContext): Promise<Response> {
    const preflight = corsPreflight(request, env.ALLOWED_ORIGINS);
    if (preflight) return preflight;
    try {
      return corsResponse(request, await handle(request, env, ctx), env.ALLOWED_ORIGINS);
    } catch (error) {
      console.error("Admin request failed", error);
      return corsResponse(request, failure(500, "Admin service error"), env.ALLOWED_ORIGINS);
    }
  },
};
