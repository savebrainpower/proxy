# sbp-proxy

A deliberately dumb, **no-logging** CORS forward proxy on Cloudflare Workers.
It is the hosted default relay for [save brain power](https://savebrainpower.xyz),
and it is designed to be equally easy to run yourself.

This directory is the source for the standalone `savebrainpower/proxy`
repository.

## Why this exists

save brain power is zero-knowledge: the app's servers only ever store
ciphertext, so anything that needs plaintext — AI calls with your own API key,
integration syncs, link previews — runs **in your browser** against third-party
APIs. Most of those APIs don't send CORS headers, so the browser needs a relay.
This is that relay, and nothing more.

You have two options, and both are first-class:

- **Use the hosted default** at `https://proxy.savebrainpower.xyz` — zero setup.
- **Deploy your own** (below) — then your plaintext never touches infrastructure
  you don't control. This is the stronger privacy posture and the reason this
  repo is public: you can read every line the relay runs.

## Protocol

Append the absolute target URL to the proxy origin — the one convention a
browser `fetch` can express for a forward proxy:

```
GET  https://<proxy-host>/https://api.openai.com/v1/models
POST https://<proxy-host>/https://api.anthropic.com/v1/messages
```

Method, body, and headers are forwarded as-is, except for what gets stripped
(see Privacy). The response comes back with permissive CORS for allowed
origins. That's the whole API.

## Privacy properties

- **No logs, no analytics, no storage.** Workers observability is disabled in
  `wrangler.toml` and the source contains no `console.*`. The only per-request
  memory is the rate limiter's transient counter.
- **Stripped on the way in:** `Cookie`, `Origin`, `Referer`, and every `cf-*` /
  `x-forwarded-*` / `x-real-ip` header — the target does not learn who or where
  you are from us.
- **Stripped on the way out:** `Set-Cookie` (a target can't plant state on the
  proxy domain) and the target's own CORS headers (ours win).
- **SSRF guard:** loopback, RFC-1918, link-local, metadata, and self-referential
  targets are refused.

## Abuse control

Per-IP rate limiting via Cloudflare's native rate-limiting binding (default:
100 requests/minute) — chosen precisely because it keeps no logs and needs no
storage. Browser access is additionally scoped by `ALLOWED_ORIGINS`.

## Deploy your own

```sh
bun install            # or npm install
bunx wrangler deploy   # after: remove/adjust `routes` in wrangler.toml
```

Configuration lives in `wrangler.toml` for local use.
If you are using the standalone `savebrainpower/proxy` repository, start from
`wrangler.example.toml` and copy it into place:

```sh
cp wrangler.example.toml wrangler.toml
```

Then edit the copied file:

- `[[unsafe.bindings]] … simple = { limit, period }` — the per-IP rate limit.

## Run it locally

Requirements:

- [Bun](https://bun.sh)
- A Cloudflare account if you want to run `wrangler dev` against the worker

Install dependencies:

```sh
bun install
```

Run the worker locally:

```sh
bun run dev
```

Then configure `http://localhost:8788` on https://app.savebrainpower.xyz/settings?tab=proxy

Other useful commands:

```sh
bun run test
bun run typecheck
bun run fmt
```

If you want to deploy to a Cloudflare worker of your own:

```sh
bun run deploy
```

## License

[MIT](./LICENSE)
