/**
 * shared-signals.dev: static site plus (eventually) a live SSF Transmitter and Receiver.
 *
 * Phase 1 serves the built Astro site only. The routes below are reserved so that
 * wrangler.toml's run_worker_first list and the URLs we publish in docs stay stable
 * when the sample implementations arrive:
 *
 *   GET  /.well-known/ssf-configuration   Transmitter Configuration Metadata (SSF §7)
 *   *    /ssf/*                           Stream management, push/poll endpoints
 *   *    /api/*                           Playground helpers (generate SETs, inspect streams)
 */

const json = (body, status = 200) =>
  new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' },
  });

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (pathname.startsWith('/.well-known/ssf-configuration') || pathname.startsWith('/ssf/') || pathname.startsWith('/api/')) {
      return json({ error: 'not_implemented', message: 'The shared-signals.dev sample Transmitter and Receiver are coming soon. See https://shared-signals.dev/playground/' }, 501);
    }

    return env.ASSETS.fetch(request);
  },
};
