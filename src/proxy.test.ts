import { afterEach, describe, expect, test } from "bun:test";
import app, {
  extractTargetUrl,
  filterRequestHeaders,
  filterResponseHeaders,
  isForbiddenTarget,
  resolveAllowOrigin,
} from "./proxy";

describe("extractTargetUrl", () => {
  test("recovers the absolute target including query string", () => {
    const t = extractTargetUrl("https://proxy.dev/https://api.openai.com/v1/models?limit=10");
    expect(t?.href).toBe("https://api.openai.com/v1/models?limit=10");
  });

  test("tolerates a collapsed scheme slash", () => {
    const t = extractTargetUrl("https://proxy.dev/https:/api.anthropic.com/v1/messages");
    expect(t?.href).toBe("https://api.anthropic.com/v1/messages");
  });

  test("rejects non-absolute and non-http targets", () => {
    expect(extractTargetUrl("https://proxy.dev/")).toBeNull();
    expect(extractTargetUrl("https://proxy.dev/v1/models")).toBeNull();
    expect(extractTargetUrl("https://proxy.dev/ftp://host/file")).toBeNull();
  });
});

describe("isForbiddenTarget", () => {
  const at = (u: string) => isForbiddenTarget(new URL(u), "proxy.dev");

  test("blocks loopback, private ranges, metadata, and self", () => {
    expect(at("http://localhost:3000/x")).toBe(true);
    expect(at("http://127.0.0.1/x")).toBe(true);
    expect(at("http://10.0.0.8/x")).toBe(true);
    expect(at("http://172.20.1.1/x")).toBe(true);
    expect(at("http://192.168.1.1/x")).toBe(true);
    expect(at("http://169.254.169.254/latest/meta-data")).toBe(true);
    expect(at("http://metadata.google.internal/x")).toBe(true);
    expect(at("https://proxy.dev/https://example.com")).toBe(true);
    expect(at("http://foo.internal/x")).toBe(true);
  });

  test("allows normal public hosts", () => {
    expect(at("https://api.openai.com/v1/models")).toBe(false);
    expect(at("https://www.example.com/")).toBe(false);
    expect(at("https://172.example.com/")).toBe(false); // name, not an IP
  });
});

describe("filterRequestHeaders", () => {
  test("strips provenance, cookies, and cloudflare headers; keeps auth and content-type", () => {
    const h = filterRequestHeaders(
      new Headers({
        Authorization: "Bearer sk-123",
        "Content-Type": "application/json",
        "x-api-key": "key",
        Origin: "https://app.example",
        Referer: "https://app.example/page",
        Cookie: "session=abc",
        Host: "proxy.dev",
        "CF-Connecting-IP": "1.2.3.4",
        "cf-ray": "abc",
        "X-Forwarded-For": "1.2.3.4",
        "Accept-Encoding": "br",
      }),
    );
    expect(h.get("authorization")).toBe("Bearer sk-123");
    expect(h.get("content-type")).toBe("application/json");
    expect(h.get("x-api-key")).toBe("key");
    for (const gone of [
      "origin",
      "referer",
      "cookie",
      "host",
      "cf-connecting-ip",
      "cf-ray",
      "x-forwarded-for",
      "accept-encoding",
    ]) {
      expect(h.get(gone)).toBeNull();
    }
  });
});

describe("filterResponseHeaders", () => {
  test("drops cookies and the target's CORS; keeps content headers", () => {
    const h = filterResponseHeaders(
      new Headers({
        "Content-Type": "application/json",
        "Set-Cookie": "sticky=1",
        "Access-Control-Allow-Origin": "https://evil.example",
        "X-Request-Id": "r-1",
      }),
    );
    expect(h.get("content-type")).toBe("application/json");
    expect(h.get("x-request-id")).toBe("r-1");
    expect(h.get("set-cookie")).toBeNull();
    expect(h.get("access-control-allow-origin")).toBeNull();
  });
});

describe("resolveAllowOrigin", () => {
  test("wildcard allows anyone; lists match exactly; otherwise no grant", () => {
    expect(resolveAllowOrigin("https://x.dev", "*")).toBe("*");
    expect(resolveAllowOrigin("https://a.dev", "https://a.dev, https://b.dev")).toBe(
      "https://a.dev",
    );
    expect(resolveAllowOrigin("https://c.dev", "https://a.dev,https://b.dev")).toBeNull();
    expect(resolveAllowOrigin(null, "https://a.dev")).toBeNull();
  });
});

type Env = {
  RATE_LIMITER: { limit: (o: { key: string }) => Promise<{ success: boolean }> };
  ALLOWED_ORIGINS: string;
};

const allowAll: Env = {
  RATE_LIMITER: { limit: async () => ({ success: true }) },
  ALLOWED_ORIGINS: "*",
};

const req = (url: string, init?: RequestInit) => new Request(url, init);

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("OPTIONS preflight", () => {
  test("answers 204 with CORS grant and echoes requested headers", async () => {
    const res = await app.fetch(
      req("https://proxy.dev/https://api.openai.com/v1/models", {
        method: "OPTIONS",
        headers: { Origin: "https://app.dev", "Access-Control-Request-Headers": "authorization" },
      }),
      allowAll,
    );
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    expect(res.headers.get("access-control-allow-methods")).toContain("POST");
    expect(res.headers.get("access-control-allow-headers")).toBe("authorization");
    expect(res.headers.get("access-control-max-age")).toBe("86400");
  });

  test("wildcards allow-headers when none requested", async () => {
    const res = await app.fetch(
      req("https://proxy.dev/https://api.openai.com/", { method: "OPTIONS" }),
      allowAll,
    );
    expect(res.headers.get("access-control-allow-headers")).toBe("*");
  });
});

describe("bare path", () => {
  test("root returns a 200 usage explanation", async () => {
    const res = await app.fetch(req("https://proxy.dev/"), allowAll);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("sbp-proxy");
  });

  test("non-root without an absolute target is a 400", async () => {
    const res = await app.fetch(req("https://proxy.dev/v1/models"), allowAll);
    expect(res.status).toBe(400);
  });
});

describe("forbidden targets", () => {
  test("private/loopback targets are a 403", async () => {
    const res = await app.fetch(req("https://proxy.dev/http://127.0.0.1/x"), allowAll);
    expect(res.status).toBe(403);
  });
});

describe("rate limiting", () => {
  test("returns 429 with Retry-After when the limiter denies", async () => {
    const env: Env = { ...allowAll, RATE_LIMITER: { limit: async () => ({ success: false }) } };
    const res = await app.fetch(req("https://proxy.dev/https://api.openai.com/v1/models"), env);
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60");
  });

  test("keys the limiter by the connecting IP", async () => {
    let seenKey = "";
    const env: Env = {
      ...allowAll,
      RATE_LIMITER: {
        limit: async ({ key }) => {
          seenKey = key;
          return { success: false };
        },
      },
    };
    await app.fetch(
      req("https://proxy.dev/https://api.openai.com/v1/models", {
        headers: { "CF-Connecting-IP": "9.9.9.9" },
      }),
      env,
    );
    expect(seenKey).toBe("9.9.9.9");
  });
});

describe("forwarding", () => {
  test("relays method/body to the target, filtering request headers and adding CORS", async () => {
    let captured: Request | undefined;
    globalThis.fetch = (async (input: Request | string | URL, init?: RequestInit) => {
      captured = new Request(input as Request, init);
      return new Response("upstream-body", {
        status: 201,
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": "s=1",
          "Access-Control-Allow-Origin": "https://evil.dev",
          "X-Request-Id": "r-1",
        },
      });
    }) as unknown as typeof fetch;

    const res = await app.fetch(
      req("https://proxy.dev/https://api.openai.com/v1/chat", {
        method: "POST",
        headers: {
          Origin: "https://app.dev",
          Authorization: "Bearer sk-1",
          Cookie: "session=abc",
          "CF-Connecting-IP": "1.2.3.4",
        },
        body: "hello",
      }),
      allowAll,
    );

    expect(captured?.url).toBe("https://api.openai.com/v1/chat");
    expect(captured?.method).toBe("POST");
    expect(captured?.headers.get("authorization")).toBe("Bearer sk-1");
    expect(captured?.headers.get("cookie")).toBeNull();
    expect(captured?.headers.get("cf-connecting-ip")).toBeNull();

    expect(res.status).toBe(201);
    expect(await res.text()).toBe("upstream-body");
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(res.headers.get("x-request-id")).toBe("r-1");
    expect(res.headers.get("set-cookie")).toBeNull();
    // Our CORS grant wins over the target's.
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
  });

  test("does not forward a body for GET", async () => {
    let hadBody: boolean | undefined;
    globalThis.fetch = (async (_input: Request | string | URL, init?: RequestInit) => {
      hadBody = init?.body != null;
      return new Response("ok", { status: 200 });
    }) as unknown as typeof fetch;

    await app.fetch(req("https://proxy.dev/https://api.openai.com/v1/models"), allowAll);
    expect(hadBody).toBe(false);
  });

  test("withholds the CORS grant when the origin is not allowed", async () => {
    globalThis.fetch = (async () => new Response("ok", { status: 200 })) as unknown as typeof fetch;
    const env: Env = { ...allowAll, ALLOWED_ORIGINS: "https://app.dev" };
    const res = await app.fetch(
      req("https://proxy.dev/https://api.openai.com/v1/models", {
        headers: { Origin: "https://evil.dev" },
      }),
      env,
    );
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });
});
