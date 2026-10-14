/**
 * shared-signals.dev: the static Astro site, plus a live sample SSF Transmitter and Receiver.
 *
 *   GET  /.well-known/ssf-configuration         Transmitter Configuration Metadata (SSF §7)
 *   GET  /.well-known/oauth-authorization-server RFC 8414 metadata for the sandbox token endpoint
 *   GET  /jwks.json                              Transmitter signing key(s)
 *   POST /ssf/oauth/token                        Client credentials grant → ssf.read / ssf.manage token
 *   POST /ssf/oauth/revoke                       RFC 7009 revocation
 *   *    /ssf/stream, /ssf/status                Stream management (SSF §8)
 *   POST /ssf/subjects:add, /ssf/subjects:remove, /ssf/verify
 *   POST /ssf/poll/<stream_id>                   Poll delivery (RFC 8936)
 *   POST /ssf/push/<receiver_id>                 Sample Receiver push endpoint (RFC 8935)
 *   *    /api/*                                  Playground helpers: fire events, logs, receivers, inspector
 *
 * Everything else is a static file from ./dist.
 */

import { authenticate, isCaller, revokeEndpoint, SCOPES, tokenEndpoint } from './auth';
import { error, readJson, readText, reply, toResponse, type Reply } from './http';
import { getSigner, randomId } from './jose';
import { discoveringResolver, fixedResolver } from './keysource';
import { checkPublicUrl } from './ssrf';
import { POLL, PUSH, type Ctx } from './transmitter';
import { validateSet } from './validate';
import type { Env } from './env';

export { KeyStore } from './keys';
export { Transmitter } from './transmitter';
export { Receiver } from './receiver';

const PUBLIC = { 'access-control-allow-origin': '*' };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;
    const issuer = url.origin;

    if (pathname === '/.well-known/ssf-configuration') return toResponse(reply(200, await metadata(issuer)), { ...PUBLIC, 'cache-control': 'public, max-age=300' });
    if (pathname === '/.well-known/oauth-authorization-server') return toResponse(reply(200, asMetadata(issuer)), { ...PUBLIC, 'cache-control': 'public, max-age=300' });
    if (pathname === '/jwks.json') return toResponse(reply(200, { keys: [(await getSigner(env)).publicJwk] }), { ...PUBLIC, 'cache-control': 'public, max-age=300' });
    if (!pathname.startsWith('/ssf/') && !pathname.startsWith('/api/')) {
      if (pathname.startsWith('/.well-known/ssf-configuration/')) return toResponse(error(404, 'not_found', `This site has one issuer, ${issuer}, with no path component.`));
      return env.ASSETS.fetch(request);
    }

    if (env.RATE_LIMITER) {
      const { success } = await env.RATE_LIMITER.limit({ key: request.headers.get('cf-connecting-ip') ?? 'unknown' });
      if (!success) return toResponse(error(429, 'too_many_requests', 'Slow down: this public sandbox is rate limited per IP address.', { 'retry-after': '60' }));
    }

    try {
      return toResponse(await route(request, env, url, issuer));
    } catch (e: any) {
      console.error(e?.stack ?? e);
      return toResponse(error(500, 'server_error', 'Something went wrong in the sample Transmitter. Please open an issue at github.com/derrumbe/shared-signals.dev.'));
    }
  },
} satisfies ExportedHandler<Env>;

async function metadata(issuer: string) {
  return {
    spec_version: '1_0',
    issuer,
    jwks_uri: `${issuer}/jwks.json`,
    delivery_methods_supported: [PUSH, POLL],
    configuration_endpoint: `${issuer}/ssf/stream`,
    status_endpoint: `${issuer}/ssf/status`,
    add_subject_endpoint: `${issuer}/ssf/subjects:add`,
    remove_subject_endpoint: `${issuer}/ssf/subjects:remove`,
    verification_endpoint: `${issuer}/ssf/verify`,
    authorization_schemes: [{ spec_urn: 'urn:ietf:rfc:6749' }],
    default_subjects: 'ALL',
  };
}

const asMetadata = (issuer: string) => ({
  issuer,
  token_endpoint: `${issuer}/ssf/oauth/token`,
  revocation_endpoint: `${issuer}/ssf/oauth/revoke`,
  grant_types_supported: ['client_credentials'],
  token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
  scopes_supported: [...SCOPES],
  service_documentation: `${issuer}/playground/`,
});

const allow = (...methods: string[]) => error(405, 'invalid_request', `Use ${methods.join(' or ')}.`, { allow: methods.join(', ') });

async function route(request: Request, env: Env, url: URL, issuer: string): Promise<Reply> {
  const { pathname } = url;
  const method = request.method;
  const param = (k: string) => url.searchParams.get(k);

  // ── OAuth ──────────────────────────────────────────────────────────────
  if (pathname === '/ssf/oauth/token') return tokenEndpoint(request, env, issuer);
  if (pathname === '/ssf/oauth/revoke') return revokeEndpoint(request, env, issuer);

  // ── Sample Receiver ────────────────────────────────────────────────────
  const push = pathname.match(/^\/ssf\/push\/([0-9a-f]{32})$/);
  if (push) {
    if (method !== 'POST') return allow('POST');
    const body = await readText(request);
    if (body === null) return reply(413, { err: 'invalid_request', description: 'SET is too large.' });
    return receiver(env, push[1]).receive(request.headers.get('content-type'), request.headers.get('authorization'), body);
  }
  if (pathname === '/api/receivers') {
    if (method !== 'POST') return allow('POST');
    const j = await readJson(request); if ('fail' in j) return j.fail;
    const id = randomId();
    return reply(201, await receiver(env, id).init(id, issuer, j.body));
  }
  const rcv = pathname.match(/^\/api\/receivers\/([0-9a-f]{32})(\/events)?$/);
  if (rcv) {
    const stub = receiver(env, rcv[1]);
    if (rcv[2]) return method === 'DELETE' ? stub.clear() : allow('DELETE');
    if (method === 'GET') return stub.view();
    if (method === 'PATCH') { const j = await readJson(request); if ('fail' in j) return j.fail; return stub.update(j.body); }
    return allow('GET', 'PATCH');
  }

  // ── SET inspector ──────────────────────────────────────────────────────
  if (pathname === '/api/inspect') {
    if (method !== 'POST') return allow('POST');
    const j = await readJson(request); if ('fail' in j) return j.fail;
    const { set, jwks_uri, jwks, issuer: expIss, audience } = j.body;
    if (typeof set !== 'string' || !set.trim()) return error(400, 'invalid_request', 'Paste a SET in "set".');
    let resolver = discoveringResolver(env, issuer);
    if (jwks && typeof jwks === 'object') resolver = fixedResolver({ jwks });
    else if (typeof jwks_uri === 'string' && jwks_uri.trim()) {
      const { problem } = checkPublicUrl(jwks_uri.trim());
      if (problem && !jwks_uri.trim().startsWith(`${issuer}/`)) return error(400, 'invalid_request', `jwks_uri ${problem}.`);
      resolver = jwks_uri.trim() === `${issuer}/jwks.json` ? discoveringResolver(env, issuer) : fixedResolver({ jwksUri: jwks_uri.trim() });
    }
    const str = (v: unknown) => (typeof v === 'string' && v.trim() ? v.trim() : undefined);
    return reply(200, await validateSet(set.trim(), resolver, { issuer: str(expIss), audience: str(audience) }));
  }

  // ── Transmitter: everything below needs a bearer token ─────────────────
  const manage = method !== 'GET';
  const pollMatch = pathname.match(/^\/ssf\/poll\/([0-9a-f]{32})$/);
  const known = ['/ssf/stream', '/ssf/status', '/ssf/subjects:add', '/ssf/subjects:remove', '/ssf/verify', '/api/events', '/api/streams/status', '/api/streams/log'];
  if (!pollMatch && !known.includes(pathname)) return error(404, 'not_found', `No endpoint at ${pathname}. See ${issuer}/.well-known/ssf-configuration.`);

  // Polling only reads, so ssf.read is enough even though it is a POST.
  const caller = await authenticate(request, env, issuer, pollMatch || !manage ? 'ssf.read' : 'ssf.manage');
  if (!isCaller(caller)) return caller;
  const ctx: Ctx = { clientId: caller.clientId, tenant: caller.tenant, iat: caller.iat, issuer };
  const tx = env.TRANSMITTER.get(env.TRANSMITTER.idFromName(caller.tenant));

  let body: Record<string, any> = {};
  if (method === 'POST' || method === 'PATCH' || method === 'PUT') {
    const j = await readJson(request); if ('fail' in j) return j.fail;
    body = j.body;
  }

  if (pollMatch) return method === 'POST' ? tx.poll(ctx, pollMatch[1], body) : allow('POST');
  switch (pathname) {
    case '/ssf/stream':
      switch (method) {
        case 'POST': return tx.createStream(ctx, body);
        case 'GET': return tx.readStream(ctx, param('stream_id'));
        case 'PATCH': return tx.updateStream(ctx, body, false);
        case 'PUT': return tx.updateStream(ctx, body, true);
        case 'DELETE': return tx.deleteStream(ctx, param('stream_id'));
      }
      return allow('GET', 'POST', 'PATCH', 'PUT', 'DELETE');
    case '/ssf/status':
      if (method === 'GET') return tx.readStatus(ctx, param('stream_id'));
      if (method === 'POST') return tx.updateStatus(ctx, body);
      return allow('GET', 'POST');
    case '/ssf/subjects:add': return method === 'POST' ? tx.addSubject(ctx, body) : allow('POST');
    case '/ssf/subjects:remove': return method === 'POST' ? tx.removeSubject(ctx, body) : allow('POST');
    case '/ssf/verify': return method === 'POST' ? tx.verify(ctx, body) : allow('POST');
    case '/api/events': return method === 'POST' ? tx.fire(ctx, body) : allow('POST');
    case '/api/streams/status': return method === 'POST' ? tx.adminStatus(ctx, body) : allow('POST');
    case '/api/streams/log': return method === 'GET' ? tx.logFor(ctx, param('stream_id')) : allow('GET');
  }
  return error(404, 'not_found', 'Not found.');
}

const receiver = (env: Env, id: string) => env.RECEIVER.get(env.RECEIVER.idFromName(id));
