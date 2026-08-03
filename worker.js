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
 * (나중에 커스텀 도메인도 무료로 연결 가능: dinko.link 등)
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

// Google Safe Browsing API로 악성 URL 여부 확인 (무료 티어: 하루 10,000건)
// https://developers.google.com/safe-browsing/v4 에서 API 키 발급
async function isMalicious(url, apiKey) {
  if (!apiKey) return false; // 키 없으면 검사 스킵 (초기 개발 단계용)

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

  if (!res.ok) return false; // 검사 실패 시 일단 통과시키되, 운영 시엔 로깅 권장
  const data = await res.json();
  return Boolean(data.matches && data.matches.length > 0);
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    // POST /api/shorten  { url, slug? }
    if (request.method === "POST" && url.pathname === "/api/shorten") {
      let payload;
      try {
        payload = await request.json();
      } catch {
        return json({ error: "잘못된 요청 형식입니다." }, 400);
      }

      const longUrl = (payload.url || "").trim();
      let slug = (payload.slug || "").trim();

      if (!isValidUrl(longUrl)) {
        return json({ error: "올바른 URL이 아닙니다. (http:// 또는 https://로 시작해야 함)" }, 400);
      }

      // 악성 URL 검사
      const malicious = await isMalicious(longUrl, env.SAFE_BROWSING_API_KEY);
      if (malicious) {
        return json({ error: "이 URL은 악성 사이트로 분류되어 단축할 수 없습니다." }, 403);
      }

      // 커스텀 슬러그 검증 (영문/숫자/하이픈/한글 허용, 1~30자)
      if (slug) {
        if (!/^[a-zA-Z0-9가-힣-]{1,30}$/.test(slug)) {
          return json({ error: "슬러그는 영문/숫자/한글/하이픈만, 1~30자로 가능합니다." }, 400);
        }
        const exists = await env.LINKS.get(slug);
        if (exists) {
          return json({ error: "이미 사용 중인 슬러그입니다." }, 409);
        }
      } else {
        // 중복 없는 랜덤 슬러그 생성 (최대 5회 시도)
        for (let i = 0; i < 5; i++) {
          const candidate = randomSlug(6);
          const exists = await env.LINKS.get(candidate);
          if (!exists) {
            slug = candidate;
            break;
          }
        }
        if (!slug) return json({ error: "슬러그 생성에 실패했습니다. 다시 시도해주세요." }, 500);
      }

      const record = {
        url: longUrl,
        createdAt: new Date().toISOString(),
        clicks: 0,
      };
      await env.LINKS.put(slug, JSON.stringify(record));

      const shortUrl = `${url.origin}/${slug}`;
      return json({ shortUrl, slug });
    }

    // GET /api/links  → 저장된 모든 링크 목록
    if (request.method === "GET" && url.pathname === "/api/links") {
      const list = await env.LINKS.list();
      const items = await Promise.all(
        list.keys.map(async (k) => {
          const raw = await env.LINKS.get(k.name);
          const record = raw ? JSON.parse(raw) : {};
          return { slug: k.name, ...record };
        })
      );
      items.sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
      return json({ items });
    }

    // PUT /api/links/:slug  { url }  → 원본 URL 수정
    if (request.method === "PUT" && url.pathname.startsWith("/api/links/")) {
      const targetSlug = decodeURIComponent(url.pathname.replace("/api/links/", ""));
      const raw = await env.LINKS.get(targetSlug);
      if (!raw) return json({ error: "존재하지 않는 링크입니다." }, 404);

      let payload;
      try {
        payload = await request.json();
      } catch {
        return json({ error: "잘못된 요청 형식입니다." }, 400);
      }
      const newUrl = (payload.url || "").trim();
      if (!isValidUrl(newUrl)) {
        return json({ error: "올바른 URL이 아닙니다." }, 400);
      }
      const malicious = await isMalicious(newUrl, env.SAFE_BROWSING_API_KEY);
      if (malicious) {
        return json({ error: "이 URL은 악성 사이트로 분류되어 등록할 수 없습니다." }, 403);
      }

      const record = JSON.parse(raw);
      record.url = newUrl;
      record.updatedAt = new Date().toISOString();
      await env.LINKS.put(targetSlug, JSON.stringify(record));
      return json({ slug: targetSlug, ...record });
    }

    // DELETE /api/links/:slug  → 링크 삭제
    if (request.method === "DELETE" && url.pathname.startsWith("/api/links/")) {
      const targetSlug = decodeURIComponent(url.pathname.replace("/api/links/", ""));
      await env.LINKS.delete(targetSlug);
      return json({ deleted: true });
    }

    // GET /:slug  → 리다이렉트
    const slug = url.pathname.slice(1);
    if (request.method === "GET" && slug && !slug.startsWith("api/")) {
      const raw = await env.LINKS.get(slug);
      if (!raw) {
        return new Response("존재하지 않는 링크입니다.", { status: 404 });
      }
      const record = JSON.parse(raw);
      record.clicks = (record.clicks || 0) + 1;
      ctx.waitUntil(env.LINKS.put(slug, JSON.stringify(record)));
      return Response.redirect(record.url, 302);
    }

    return json({ status: "ok", message: "냥크(Nyanc) API" });
  },
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}
