// A tiny OAuth 2.0 authorization server for the sample Transmitter (client credentials grant only),
// plus bearer-token checking for the resource server side, per the CAEP Interoperability Profile:
// scopes ssf.read / ssf.manage, tokens valid for at most 60 minutes, RFC 6750 errors.
//
// There is no client registration. Any client_id with a client_secret of 16+ characters gets a
// token; the pair (hashed) names a private tenant, so streams created with one pair are invisible
// to every other pair. Pick a strong secret and you have your own sandbox.

import { b64u, getSigner, randomId, sha256, signHs256, verifyHs256 } from './jose';
import { error, readText, reply, type Reply } from './http';
import type { Env } from './env';

export const SCOPES = ['ssf.read', 'ssf.manage'] as const;
export const TOKEN_TTL = 3600;

export type Caller = { clientId: string; tenant: string; scopes: string[]; iat: number; issuer: string };

export async function tenantFor(clientId: string, secret: string): Promise<string> {
  return b64u(await sha256(`${clientId}\n${secret}`)).slice(0, 32);
}

const validClientId = (s: unknown): s is string => typeof s === 'string' && /^[\x21-\x7e]{3,128}$/.test(s);

/** POST /ssf/oauth/token */
export async function tokenEndpoint(request: Request, env: Env, issuer: string): Promise<Reply> {
  const noStore = { pragma: 'no-cache' };
  if (request.method !== 'POST') return error(405, 'invalid_request', 'Use POST.', { allow: 'POST' });
  if (!(request.headers.get('content-type') ?? '').startsWith('application/x-www-form-urlencoded'))
    return error(400, 'invalid_request', 'Send the token request as application/x-www-form-urlencoded (RFC 6749 §4.4.2).');
  const text = await readText(request);
  if (text === null) return error(400, 'invalid_request', 'Request body too large.');
  const form = new URLSearchParams(text);

  let clientId = form.get('client_id');
  let secret = form.get('client_secret');
  const basic = request.headers.get('authorization');
  if (basic?.toLowerCase().startsWith('basic ')) {
    try {
      const [id, ...rest] = atob(basic.slice(6).trim()).split(':');
      clientId = decodeURIComponent(id);
      secret = decodeURIComponent(rest.join(':'));
    } catch {
      return error(401, 'invalid_client', 'Malformed HTTP Basic credentials.', { 'www-authenticate': 'Basic realm="shared-signals.dev"' });
    }
  }
  if (form.get('grant_type') !== 'client_credentials') return error(400, 'unsupported_grant_type', 'Only grant_type=client_credentials is supported.', noStore);
  if (!validClientId(clientId)) return error(401, 'invalid_client', 'client_id must be 3–128 printable ASCII characters.', noStore);
  if (typeof secret !== 'string' || secret.length < 16 || secret.length > 256) return error(401, 'invalid_client', 'client_secret must be 16–256 characters. It is never stored; it just names your private sandbox.', noStore);

  const requested = (form.get('scope') ?? SCOPES.join(' ')).split(/\s+/).filter(Boolean);
  const unknown = requested.filter((s) => !(SCOPES as readonly string[]).includes(s));
  if (unknown.length || !requested.length) return error(400, 'invalid_scope', `Supported scopes are ${SCOPES.join(' and ')}.`, noStore);

  const signer = await getSigner(env);
  const iat = Math.floor(Date.now() / 1000);
  const scope = [...new Set(requested)].join(' ');
  const access_token = await signHs256(signer.hmacKey, {
    iss: issuer, aud: `${issuer}/ssf`, sub: clientId, client_id: clientId, tid: await tenantFor(clientId, secret), scope, iat, exp: iat + TOKEN_TTL, jti: randomId(),
  });
  return reply(200, { access_token, token_type: 'Bearer', expires_in: TOKEN_TTL, scope }, noStore);
}

const challenge = (code?: string, description?: string, scope?: string) =>
  ['Bearer realm="shared-signals.dev"', code && `error="${code}"`, description && `error_description="${description}"`, scope && `scope="${scope}"`].filter(Boolean).join(', ');

/**
 * Checks the bearer token and scope. Returns the caller, or an RFC 6750 error reply.
 * Revocation is checked later by the tenant's Durable Object (it holds the revocation time).
 */
export async function authenticate(request: Request, env: Env, issuer: string, need: 'ssf.read' | 'ssf.manage'): Promise<Caller | Reply> {
  const url = new URL(request.url);
  if (url.searchParams.has('access_token'))
    return error(400, 'invalid_request', 'Access tokens in the query string are not accepted (RFC 6750 §2.3). Use the Authorization header.', { 'www-authenticate': challenge('invalid_request') });
  const auth = request.headers.get('authorization') ?? '';
  const m = auth.match(/^Bearer\s+([A-Za-z0-9._~+/-]+=*)$/i);
  if (!m) return error(401, 'invalid_request', 'Send an access token as "Authorization: Bearer <token>". Get one from /ssf/oauth/token.', { 'www-authenticate': challenge() });

  const claims = await verifyHs256((await getSigner(env)).hmacKey, m[1]);
  const now = Math.floor(Date.now() / 1000);
  if (!claims || claims.iss !== issuer || claims.aud !== `${issuer}/ssf`) return error(401, 'invalid_token', 'The access token is malformed or was not issued by this server.', { 'www-authenticate': challenge('invalid_token', 'bad token') });
  if (typeof claims.exp !== 'number' || claims.exp <= now) return error(401, 'invalid_token', 'The access token has expired.', { 'www-authenticate': challenge('invalid_token', 'expired') });

  const scopes = String(claims.scope ?? '').split(' ');
  // ssf.manage includes everything ssf.read allows.
  if (!scopes.includes(need) && !(need === 'ssf.read' && scopes.includes('ssf.manage')))
    return error(403, 'insufficient_scope', `This call needs the ${need} scope.`, { 'www-authenticate': challenge('insufficient_scope', undefined, need) });

  return { clientId: claims.client_id, tenant: claims.tid, scopes, iat: claims.iat, issuer };
}

export const isCaller = (v: Caller | Reply): v is Caller => 'tenant' in v;

/** POST /ssf/oauth/revoke (RFC 7009). Revokes every token for the tenant issued up to now. */
export async function revokeEndpoint(request: Request, env: Env, issuer: string): Promise<Reply> {
  if (request.method !== 'POST') return error(405, 'invalid_request', 'Use POST.', { allow: 'POST' });
  const form = new URLSearchParams((await readText(request)) ?? '');
  const claims = await verifyHs256((await getSigner(env)).hmacKey, form.get('token') ?? '');
  // RFC 7009 §2.2: invalid tokens still get 200.
  if (claims && claims.iss === issuer && typeof claims.tid === 'string') {
    await env.SANDBOX.get(env.SANDBOX.idFromName(claims.tid)).revokeTokens(Math.floor(Date.now() / 1000));
  }
  return reply(200);
}
