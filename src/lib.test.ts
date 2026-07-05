import { describe, expect, test } from "bun:test";
import {
  extractTargetUrl,
  filterRequestHeaders,
  filterResponseHeaders,
  isForbiddenTarget,
  resolveAllowOrigin,
} from "./lib";

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
