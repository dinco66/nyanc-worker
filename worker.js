/**
 * 냥크(Nyanc) 서비스 - Cloudflare Worker 백엔드
 *
 * 배포 방법:
 * 1. npm install -g wrangler
 * 2. wrangler login
 * 3. wrangler kv namespace create "LINKS"   → 나온 id를 wrangler.toml에 붙여넣기
 * 4. (선택) Google Safe Browsing API 키 발급 후 secret 등록:
 *      wrangler secret put SAFE_BROWSING_API_KEY
 * 5. wrangler deploy
 *
 * 배포되면 https://프로젝트이름.본인계정.workers.dev 형태의 무료 도메인이 생김.
 * (나중에 커스텀 도메인도 무료로 연결 가능)
 */

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

function randomSlug(length = 6) {
  let out = "";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  for (let i = 0; i < length; i++) out += BASE62[bytes[i] % BASE62.length];
  return out;
}

function isValidUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// 미리보기 이미지는 외부 URL이거나, 앱에서 업로드한 base64 데이터(data:image/...)일 수 있음
function isValidImageValue(str) {
  if (!str) return false;
  if (str.startsWith("data:image/")) {
    return str.length < 2_000_000; // 약 1.5MB 이하로 제한 (KV 저장 용량 보호)
  }
  return isValidUrl(str);
}

function todayStr() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD (UTC)
}

// Google Safe Browsing API로 악성 URL 여부 확인 (무료 티어: 하루 10,000건)
async function isMalicious(url, apiKey) {
  if (!apiKey) return false;

  const body = {
    client: { clientId: "nyanc", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  const res = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }
  );

  if (!res.ok) return false;
  const data = await res.json();
  return Boolean(data.matches && data.matches.length > 0);
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

// 만료(시간제한) 또는 선착순(클릭수 제한) 마감 여부 판단
function getExpiryStatus(record) {
  const now = Date.now();
  if (record.expiresAt && now > Date.parse(record.expiresAt)) {
    return "time"; // 시간 만료
  }
  if (record.maxClicks && (record.clicks || 0) >= record.maxClicks) {
    return "clicks"; // 선착순 마감
  }
  return null; // 아직 유효
}

function escapeHtml(str) {
  return String(str || "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// 카카오톡/디스코드/트위터 등 미리보기 크롤러를 위한 OG 메타 태그 인터스티셜 페이지
function ogInterstitialHtml(record) {
  const title = escapeHtml(record.ogTitle || record.url);
  const desc = escapeHtml(record.ogDescription || "");
  const image = record.ogImage ? escapeHtml(record.ogImage) : "";
  const target = escapeHtml(record.url);
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>${title}</title>
<meta property="og:title" content="${title}">
<meta property="og:description" content="${desc}">
${image ? `<meta property="og:image" content="${image}">` : ""}
<meta name="twitter:card" content="${image ? "summary_large_image" : "summary"}">
<meta http-equiv="refresh" content="0;url=${target}">
<script>location.replace(${JSON.stringify(record.url)});</script>
</head><body>이동 중입니다... <a href="${target}">여기</a>를 눌러주세요.</body></html>`;
}

function expiredHtml(reason) {
  const msg = reason === "clicks"
    ? "선착순 마감되었습니다."
    : "만료되었습니다.";
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${msg}</title></head>
<body style="font-family:sans-serif; text-align:center; padding:60px 20px; color:#444;">
<h2>⏰ ${msg}</h2>
<p>이 링크는 더 이상 사용할 수 없어요.</p>
</body></html>`;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    // POST /api/shorten  { url, slug?, ogTitle?, ogDescription?, ogImage?, expiresAt?, maxClicks? }
    if (request.method === "POST" && url.pathname === "/api/shorten") {
      let payload;
      try {
        payload = await request.json();
      } catch {
        return json({ error: "잘못된 요청 형식입니다.", code: "invalid_request" }, 400);
      }

      const longUrl = (payload.url || "").trim();
      let slug = (payload.slug || "").trim();
      const ogTitle = (payload.ogTitle || "").trim().slice(0, 100);
      const ogDescription = (payload.ogDescription || "").trim().slice(0, 200);
      const ogImage = (payload.ogImage || "").trim();
      const expiresAt = (payload.expiresAt || "").trim();
      const maxClicks = payload.maxClicks ? parseInt(payload.maxClicks, 10) : null;

      if (!isValidUrl(longUrl)) {
        return json({ error: "올바른 URL이 아닙니다. (http:// 또는 https://로 시작해야 함)", code: "invalid_url" }, 400);
      }
      if (ogImage && !isValidImageValue(ogImage)) {
        return json({ error: "미리보기 이미지 주소가 올바르지 않습니다.", code: "invalid_og_image" }, 400);
      }
      if (expiresAt && isNaN(Date.parse(expiresAt))) {
        return json({ error: "만료 시간 형식이 올바르지 않습니다.", code: "invalid_expires" }, 400);
      }
      if (maxClicks !== null && (!Number.isInteger(maxClicks) || maxClicks < 1)) {
        return json({ error: "선착순 인원수는 1 이상의 숫자여야 합니다.", code: "invalid_max_clicks" }, 400);
      }

      const malicious = await isMalicious(longUrl, env.SAFE_BROWSING_API_KEY);
      if (malicious) {
        return json({ error: "이 URL은 악성 사이트로 분류되어 단축할 수 없습니다.", code: "malicious_url" }, 403);
      }

      if (slug) {
        if (!/^[a-zA-Z0-9가-힣-]{1,30}$/.test(slug)) {
          return json({ error: "슬러그는 영문/숫자/한글/하이픈만, 1~30자로 가능합니다.", code: "invalid_slug" }, 400);
        }
        const exists = await env.LINKS.get(slug);
        if (exists) {
          return json({ error: "이미 사용 중인 슬러그입니다.", code: "slug_taken" }, 409);
        }
      } else {
        for (let i = 0; i < 5; i++) {
          const candidate = randomSlug(6);
          const exists = await env.LINKS.get(candidate);
          if (!exists) {
            slug = candidate;
            break;
          }
        }
        if (!slug) return json({ error: "슬러그 생성에 실패했습니다. 다시 시도해주세요.", code: "slug_gen_failed" }, 500);
      }

      const record = {
        url: longUrl,
        createdAt: new Date().toISOString(),
        clicks: 0,
        clicksByDate: {},
        ogTitle: ogTitle || null,
        ogDescription: ogDescription || null,
        ogImage: ogImage || null,
        expiresAt: expiresAt || null,
        maxClicks: maxClicks,
      };
      await env.LINKS.put(slug, JSON.stringify(record));

      const shortUrl = `${url.origin}/${slug}`;
      return json({ shortUrl, slug });
    }

    // GET /api/links  → 저장된 모든 링크 목록 (1000개가 넘어도 전부 조회)
    if (request.method === "GET" && url.pathname === "/api/links") {
      let allKeys = [];
      let cursor = undefined;
      do {
        const list = await env.LINKS.list({ cursor });
        allKeys = allKeys.concat(list.keys);
        cursor = list.list_complete ? undefined : list.cursor;
      } while (cursor);

      const items = await Promise.all(
        allKeys.map(async (k) => {
          const raw = await env.LINKS.get(k.name);
          const record = raw ? JSON.parse(raw) : {};
          return { slug: k.name, ...record, expiryStatus: getExpiryStatus(record) };
        })
      );
      items.sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
      return json({ items });
    }

    // PUT /api/links/:slug  → 원본 URL / 미리보기 / 만료 설정 수정
    if (request.method === "PUT" && url.pathname.startsWith("/api/links/")) {
      const targetSlug = decodeURIComponent(url.pathname.replace("/api/links/", ""));
      const raw = await env.LINKS.get(targetSlug);
      if (!raw) return json({ error: "존재하지 않는 링크입니다.", code: "not_found" }, 404);

      let payload;
      try {
        payload = await request.json();
      } catch {
        return json({ error: "잘못된 요청 형식입니다.", code: "invalid_request" }, 400);
      }

      const record = JSON.parse(raw);

      if (payload.url !== undefined) {
        const newUrl = (payload.url || "").trim();
        if (!isValidUrl(newUrl)) {
          return json({ error: "올바른 URL이 아닙니다.", code: "invalid_url" }, 400);
        }
        const malicious = await isMalicious(newUrl, env.SAFE_BROWSING_API_KEY);
        if (malicious) {
          return json({ error: "이 URL은 악성 사이트로 분류되어 등록할 수 없습니다.", code: "malicious_url" }, 403);
        }
        record.url = newUrl;
      }
      if (payload.ogTitle !== undefined) record.ogTitle = (payload.ogTitle || "").trim().slice(0, 100) || null;
      if (payload.ogDescription !== undefined) record.ogDescription = (payload.ogDescription || "").trim().slice(0, 200) || null;
      if (payload.ogImage !== undefined) {
        const img = (payload.ogImage || "").trim();
        if (img && !isValidImageValue(img)) return json({ error: "미리보기 이미지 주소가 올바르지 않습니다.", code: "invalid_og_image" }, 400);
        record.ogImage = img || null;
      }
      if (payload.expiresAt !== undefined) {
        const exp = (payload.expiresAt || "").trim();
        if (exp && isNaN(Date.parse(exp))) return json({ error: "만료 시간 형식이 올바르지 않습니다.", code: "invalid_expires" }, 400);
        record.expiresAt = exp || null;
      }
      if (payload.maxClicks !== undefined) {
        const mc = payload.maxClicks ? parseInt(payload.maxClicks, 10) : null;
        if (mc !== null && (!Number.isInteger(mc) || mc < 1)) {
          return json({ error: "선착순 인원수는 1 이상의 숫자여야 합니다.", code: "invalid_max_clicks" }, 400);
        }
        record.maxClicks = mc;
      }

      record.updatedAt = new Date().toISOString();
      await env.LINKS.put(targetSlug, JSON.stringify(record));
      return json({ slug: targetSlug, ...record, expiryStatus: getExpiryStatus(record) });
    }

    // DELETE /api/links/:slug
    if (request.method === "DELETE" && url.pathname.startsWith("/api/links/")) {
      const targetSlug = decodeURIComponent(url.pathname.replace("/api/links/", ""));
      await env.LINKS.delete(targetSlug);
      return json({ deleted: true });
    }

    // GET /:slug  → 리다이렉트 (또는 만료 안내 / OG 미리보기 인터스티셜)
    const slug = decodeURIComponent(url.pathname.slice(1));
    if (request.method === "GET" && slug && !slug.startsWith("api/")) {
      const raw = await env.LINKS.get(slug);
      if (!raw) {
        return new Response("존재하지 않는 링크입니다.", { status: 404 });
      }
      const record = JSON.parse(raw);

      const expiry = getExpiryStatus(record);
      if (expiry) {
        return new Response(expiredHtml(expiry), {
          status: 410,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }

      // 클릭 카운트 (총합 + 날짜별)
      record.clicks = (record.clicks || 0) + 1;
      record.clicksByDate = record.clicksByDate || {};
      const day = todayStr();
      record.clicksByDate[day] = (record.clicksByDate[day] || 0) + 1;
      ctx.waitUntil(env.LINKS.put(slug, JSON.stringify(record)));

      // 미리보기 이미지/제목이 설정된 링크는 카카오톡·디스코드 등에서
      // 미리보기를 읽을 수 있도록 OG 메타가 담긴 페이지를 먼저 보여준 뒤 이동시킴
      if (record.ogTitle || record.ogDescription || record.ogImage) {
        return new Response(ogInterstitialHtml(record), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }

      return Response.redirect(record.url, 302);
    }

    return json({ status: "ok", message: "냥크(Nyanc) API" });
  },
};
