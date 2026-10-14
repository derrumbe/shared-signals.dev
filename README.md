# shared-signals.dev

A developer resource for the OpenID Shared Signals Framework (SSF), CAEP and RISC.
Astro, built to static files, served by a Cloudflare Worker — the same shape as
xebecstudios.org.

## Running it

```
npm install
npm run dev        # Astro dev server, localhost:4321
npm run preview    # build, then serve through the Worker with wrangler, localhost:8787
npm run deploy     # build and `wrangler deploy` (or let Workers Builds do it on push)
npm run smoke      # end-to-end test of the Transmitter/Receiver against a running `npm run preview`
npm run check-worker  # typecheck worker/
```

## Layout

| Path | What it is |
|---|---|
| `src/pages/learn/*.md` | The concepts walkthrough. Markdown, ordered by `LEARN` in `src/consts.ts`. |
| `src/pages/specs.astro` | The specs and the RFCs underneath them. |
| `src/data/events.ts` | The CAEP / RISC / SSF event catalogue; `/events/` renders from it. |
| `src/content/implementations/implementations.json` | Implementations list, schema-checked in `src/content.config.ts`. |
| `src/pages/playground*` | Playground: Transmitter console, sample Receiver, SET inspector (browser code in `src/scripts/playground.ts`). |
| `worker/index.ts` | The Worker: serves `dist/`, and routes discovery, OAuth, `/ssf/*` and `/api/*`. |
| `worker/transmitter.ts` | Sample Transmitter, one Durable Object per OAuth client: streams, subjects, push/poll queues, logs. |
| `worker/receiver.ts` | Sample Receiver, one Durable Object per receiver id. |
| `worker/validate.ts` | SET checks (RFC 8417, SSF, CAEP, Interop Profile), shared by the Receiver and inspector. |
| `worker/auth.ts`, `jose.ts`, `ssrf.ts`, `keysource.ts`, `keys.ts` | OAuth sandbox, JOSE on WebCrypto, outbound URL guard, JWKS discovery, generated key store. |

Facts on these pages were checked against the spec sources in
`github.com/openid/sharedsignals` (commit recorded in `SPECS_SYNC`, `src/consts.ts`). Run `npm run check-specs` to list newer spec commits. When the spec changes, the
event catalogue and Learn pages are what to re-check.

## Sample Transmitter and Receiver

Built to the CAEP Interoperability Profile checklist. Notes for operators:

- **Signing key.** Set `SSF_SIGNING_KEY` (RSA PKCS#8 PEM or JWK, 2048+ bits):
  `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | npx wrangler secret put SSF_SIGNING_KEY`.
  Until then the Worker generates a key once and keeps it in the `KEYS` Durable Object; once the
  secret is set, that generated key is deleted. The `kid` is the
  RFC 7638 thumbprint, so switching keys changes the `kid` in `/jwks.json`.
- **OAuth.** `/ssf/oauth/token` issues HS256 access tokens (60 min, `ssf.read` / `ssf.manage`) to any
  client_id with a 16+ character secret; the hashed pair names a private tenant. No registration, no stored secrets.
- **State** lives only in SQLite-backed Durable Objects (no D1). Idle streams and receivers delete themselves after 7 days.
- **Abuse limits.** Per-IP rate limit (`RATE_LIMITER`, 120/min), per-tenant quotas, push only to public
  `https` hostnames with no redirects (`worker/ssrf.ts`).

## Deploying (first time)

1. Push this repo to GitHub.
2. Cloudflare dashboard → Workers & Pages → Create → Import a repository. Build command
   `npm run build`, deploy command `npx wrangler deploy`.
3. Make sure the Worker name in the dashboard matches `name` in `wrangler.toml`.
4. Worker → Settings → Domains & Routes → add custom domain `shared-signals.dev`
   (and `www.shared-signals.dev` if wanted). The zone must be on the same Cloudflare account.
