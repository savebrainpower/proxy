import { Hono } from "hono";

/*
 * sbp-proxy — a deliberately dumb CORS forward proxy.
 *
 * It exists because save brain power is zero-knowledge: the app's servers
 * never see plaintext, so AI calls and integration syncs run in the browser
 * against third-party APIs that don't send CORS headers. This worker relays
 * `https://proxy.../<absolute-url>` to `<absolute-url>` and adds CORS.
 *
 * Protocol (cors-anywhere style, the one convention a browser `fetch` can
 * express for a forward proxy): the target is the proxy path itself —
 *
 *   https://proxy.example/https://api.openai.com/v1/models?limit=10
 *
 * The proxy forwards method/headers/body to that absolute URL and relaxes
 * CORS on the way back. Nothing more.
 *
 * Privacy rules of this codebase:
 *   - No logging of any kind. No console.*, no analytics, and observability
 *     stays disabled in wrangler.toml. Requests carry users' provider keys
 *     and plaintext prompts; the only acceptable memory of a request is the
 *     rate limiter's transient per-IP counter.
 *   - Strip, don't enrich: cookies, origin/referer, and every cf- and
 *     x-forwarded- header die here — the target learns nothing about the
 *     caller beyond what the caller itself put in the request.
 */

/**
 * Recover the absolute target URL from the proxied request URL. Tolerates
 * intermediaries collapsing `https://` to `https:/` in the path. Returns null
 * when the path is not an absolute http(s) URL.
 */
export function extractTargetUrl(requestUrl: string): URL | null {
  const url = new URL(requestUrl);
  const raw = url.pathname.slice(1) + url.search;
  const match = /^(https?):\/+(.+)$/i.exec(raw);
  if (!match) return null;
  try {
    return new URL(`${match[1]}://${match[2]}`);
  } catch {
    return null;
  }
}

// Private / link-local / loopback IPv4 ranges and other targets a public
// proxy has no business reaching. Workers generally can't reach them anyway;
// this is cheap defense in depth, not the security boundary.
const FORBIDDEN_HOSTS = new Set(["localhost", "metadata.google.internal", "0.0.0.0"]);
const PRIVATE_V4 =
  /^(?:127\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.)(?:\d{1,3}\.?){0,3}$/;

/** Reject loopback/private/metadata targets and requests aimed back at the proxy itself. */
export function isForbiddenTarget(target: URL, proxyHost: string): boolean {
  const host = target.hostname.toLowerCase();
  if (host === proxyHost.toLowerCase()) return true; // no loops
  if (FORBIDDEN_HOSTS.has(host)) return true;
  if (host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal"))
    return true;
  if (PRIVATE_V4.test(host)) return true;
  if (host.startsWith("[")) return true; // IPv6 literals: nothing legitimate uses them here
  return false;
}

// Request headers that must not travel to the target: hop-by-hop plumbing,
// browser-added provenance (origin/referer — the target learns nothing about
// where the user is browsing), credentials scoped to the proxy (cookies), and
// everything Cloudflare stamps onto inbound requests (cf-*, x-forwarded-*,
// x-real-ip — the target should not learn the caller's IP from us).
const STRIPPED_REQUEST_HEADERS = new Set([
  "host",
  "connection",
  "keep-alive",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "expect",
  "origin",
  "referer",
  "cookie",
  "cookie2",
  "x-real-ip",
  "true-client-ip",
  "content-length",
  "accept-encoding",
]);

export function filterRequestHeaders(headers: Headers): Headers {
  const out = new Headers();
  headers.forEach((value, name) => {
    const key = name.toLowerCase();
    if (STRIPPED_REQUEST_HEADERS.has(key)) return;
    if (key.startsWith("cf-") || key.startsWith("x-forwarded-") || key.startsWith("proxy-")) return;
    out.set(name, value);
  });
  return out;
}

// Response headers we replace or refuse to relay: the target's own CORS
// answers (ours win), cookies (a target must never set state on the proxy
// domain), and hop-by-hop headers the runtime manages.
const STRIPPED_RESPONSE_HEADERS = new Set([
  "set-cookie",
  "set-cookie2",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "content-encoding",
  "content-length",
]);

export function filterResponseHeaders(headers: Headers): Headers {
  const out = new Headers();
  headers.forEach((value, name) => {
    const key = name.toLowerCase();
    if (STRIPPED_RESPONSE_HEADERS.has(key)) return;
    if (key.startsWith("access-control-")) return;
    out.set(name, value);
  });
  return out;
}

/**
 * Resolve the Access-Control-Allow-Origin value for a request: "*" allows
 * everyone; otherwise the origin must be on the configured list. Returns null
 * when the origin is absent or not allowed (the response then carries no CORS
 * grant, and browsers refuse it — non-browser clients are unaffected).
 */
export function resolveAllowOrigin(
  requestOrigin: string | null,
  allowedOrigins: string,
): string | null {
  const allowed = allowedOrigins
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
  if (allowed.includes("*")) return "*";
  if (requestOrigin && allowed.includes(requestOrigin)) return requestOrigin;
  return null;
}

type RateLimiter = { limit: (options: { key: string }) => Promise<{ success: boolean }> };
type Bindings = { RATE_LIMITER: RateLimiter; ALLOWED_ORIGINS: string };

const app = new Hono<{ Bindings: Bindings }>();

const cors = (allowOrigin: string | null): Record<string, string> =>
  allowOrigin
    ? {
        "Access-Control-Allow-Origin": allowOrigin,
        "Access-Control-Expose-Headers": "*",
        ...(allowOrigin === "*" ? {} : { Vary: "Origin" }),
      }
    : {};

app.options("*", (c) => {
  const allowOrigin = resolveAllowOrigin(c.req.header("Origin") ?? null, c.env.ALLOWED_ORIGINS);
  return c.body(null, 204, {
    ...cors(allowOrigin),
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": c.req.header("Access-Control-Request-Headers") ?? "*",
    "Access-Control-Max-Age": "86400",
  });
});

app.all("*", async (c) => {
  const allowOrigin = resolveAllowOrigin(c.req.header("Origin") ?? null, c.env.ALLOWED_ORIGINS);
  const target = extractTargetUrl(c.req.url);

  // Bare visits get a one-line explanation instead of a mystery 400.
  if (!target && new URL(c.req.url).pathname === "/") {
    return c.text(
      "sbp-proxy: a no-logging CORS forward proxy for save brain power.\n" +
        "Usage: GET/POST https://<this-host>/<absolute-http-url>\n" +
        "Source: https://github.com/savebrainpower/proxy\n",
      200,
      cors(allowOrigin),
    );
  }
  if (!target) {
    return c.text("target must be an absolute http(s) URL in the path", 400, cors(allowOrigin));
  }
  if (isForbiddenTarget(target, new URL(c.req.url).hostname)) {
    return c.text("target not allowed", 403, cors(allowOrigin));
  }

  const key = c.req.header("CF-Connecting-IP") ?? "unknown";
  const { success } = await c.env.RATE_LIMITER.limit({ key });
  if (!success) {
    return c.text("rate limited", 429, { ...cors(allowOrigin), "Retry-After": "60" });
  }

  const method = c.req.method;
  const upstream = await fetch(target, {
    method,
    headers: filterRequestHeaders(c.req.raw.headers),
    body: method === "GET" || method === "HEAD" ? undefined : c.req.raw.body,
    redirect: "follow",
  });

  const headers = filterResponseHeaders(upstream.headers);
  for (const [name, value] of Object.entries(cors(allowOrigin))) headers.set(name, value);
  return new Response(upstream.body, { status: upstream.status, headers });
});

export default app;
