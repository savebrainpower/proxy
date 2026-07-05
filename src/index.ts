import { Hono } from "hono";
import {
  extractTargetUrl,
  filterRequestHeaders,
  filterResponseHeaders,
  isForbiddenTarget,
  resolveAllowOrigin,
} from "./lib";

/*
 * sbp-proxy — a deliberately dumb CORS forward proxy.
 *
 * It exists because save brain power is zero-knowledge: the app's servers
 * never see plaintext, so AI calls and integration syncs run in the browser
 * against third-party APIs that don't send CORS headers. This worker relays
 * `https://proxy.../<absolute-url>` to `<absolute-url>` and adds CORS.
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
