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
```

## Layout

| Path | What it is |
|---|---|
| `src/pages/learn/*.md` | The concepts walkthrough. Markdown, ordered by `LEARN` in `src/consts.ts`. |
| `src/pages/specs.astro` | The specs and the RFCs underneath them. |
| `src/data/events.ts` | The CAEP / RISC / SSF event catalogue; `/events/` renders from it. |
| `src/content/implementations/implementations.json` | Implementations list, schema-checked in `src/content.config.ts`. |
| `src/pages/playground.astro` | Placeholder for the sample Transmitter / Receiver. |
| `worker/index.js` | The Worker. Today: serves `dist/`, returns 501 on the reserved API paths. |

Facts on these pages were checked against the spec sources in
`github.com/openid/sharedsignals` (SSF/CAEP final, 2025-08-29). When the spec changes, the
event catalogue and Learn pages are what to re-check.

## Roadmap

1. **Info site** — this.
2. **Sample Transmitter** in the Worker: `/.well-known/ssf-configuration`, stream management
   (`/ssf/stream`, `/ssf/status`, `/ssf/subjects:add|remove`, `/ssf/verify`), push and poll
   delivery, a UI to fire events. Streams in a Durable Object or D1; signing key as a secret.
3. **Sample Receiver**: `/ssf/push/<id>` endpoint, live view of received SETs with validation errors.
4. **SET inspector**: decode / validate / verify against a JWKS.

`wrangler.toml` already routes `/.well-known/ssf-configuration*`, `/ssf/*` and `/api/*` to the
Worker first, so those paths won't need re-plumbing.

## Deploying (first time)

1. Push this repo to GitHub.
2. Cloudflare dashboard → Workers & Pages → Create → Import a repository. Build command
   `npm run build`, deploy command `npx wrangler deploy`.
3. Make sure the Worker name in the dashboard matches `name` in `wrangler.toml`.
4. Worker → Settings → Domains & Routes → add custom domain `shared-signals.dev`
   (and `www.shared-signals.dev` if wanted). The zone must be on the same Cloudflare account.
