// Finds a Transmitter's signing key: SSF discovery (/.well-known/ssf-configuration) → jwks_uri → key
// by kid. Our own issuer is answered locally. Results are cached briefly per isolate.

import { getSigner, type Jwk } from './jose';
import { checkPublicUrl, safeFetch } from './ssrf';
import type { KeyResolver } from './validate';
import type { Env } from './env';

const cache = new Map<string, { at: number; keys?: Jwk[]; problem?: string }>();
const TTL = 5 * 60 * 1000;

/** SSF §7.2: insert /.well-known/ssf-configuration between the host and any path. */
export function discoveryUrl(issuer: string): string {
  const u = new URL(issuer);
  const path = u.pathname.replace(/\/$/, '');
  return `${u.origin}/.well-known/ssf-configuration${path}`;
}

async function fetchJson(raw: string, what: string): Promise<{ json?: any; problem?: string }> {
  const { url, problem } = checkPublicUrl(raw);
  if (!url) return { problem: `${what} ${raw} ${problem}` };
  const r = await safeFetch(url, { headers: { accept: 'application/json' } }, 256 * 1024);
  if (r.error) return { problem: `fetching ${what} ${raw}: ${r.error}` };
  if (!r.ok) return { problem: `${what} ${raw} returned HTTP ${r.status}` };
  try { return { json: JSON.parse(r.text) }; } catch { return { problem: `${what} ${raw} is not JSON` }; }
}

async function loadJwks(jwksUri: string): Promise<{ keys?: Jwk[]; problem?: string }> {
  const { json, problem } = await fetchJson(jwksUri, 'JWKS');
  if (problem) return { problem };
  if (!Array.isArray(json?.keys)) return { problem: `JWKS ${jwksUri} has no "keys" array` };
  return { keys: json.keys };
}

function pick(keys: Jwk[], kid: string | undefined, where: string): { key?: Jwk; problem?: string } {
  const rsa = keys.filter((k) => k.kty === 'RSA' && (!k.use || k.use === 'sig'));
  const key = kid ? rsa.find((k) => k.kid === kid) : rsa.length === 1 ? rsa[0] : undefined;
  if (key) return { key };
  return { problem: kid ? `no RSA key with kid "${kid}" in ${where}` : `the SET has no kid and ${where} holds ${rsa.length} RSA keys` };
}

/** Resolver that discovers keys from the SET's own iss. */
export function discoveringResolver(env: Env, ownIssuer: string): KeyResolver {
  return async (iss, kid) => {
    if (iss === ownIssuer) {
      const s = await getSigner(env);
      return pick([s.publicJwk], kid, 'this site’s JWKS');
    }
    let hit = cache.get(iss);
    if (!hit || Date.now() - hit.at > TTL) {
      let url: string;
      try { url = discoveryUrl(iss); } catch { return { problem: `iss "${iss}" is not a URL, so its keys can't be discovered` }; }
      const { json, problem } = await fetchJson(url, 'Transmitter Configuration Metadata at');
      if (problem) hit = { at: Date.now(), problem };
      else if (json?.issuer !== iss) hit = { at: Date.now(), problem: `the metadata at ${url} has issuer ${JSON.stringify(json?.issuer)}, not "${iss}"` };
      else if (typeof json?.jwks_uri !== 'string') hit = { at: Date.now(), problem: `the metadata at ${url} has no jwks_uri` };
      else hit = { at: Date.now(), ...(await loadJwks(json.jwks_uri)) };
      cache.set(iss, hit);
    }
    if (!hit.keys) return { problem: hit.problem! };
    return pick(hit.keys, kid, 'the issuer’s JWKS');
  };
}

/** Resolver for an explicit JWKS URL or pasted JWKS (SET inspector). */
export function fixedResolver(source: { jwksUri?: string; jwks?: { keys?: Jwk[] } }): KeyResolver {
  return async (_iss, kid) => {
    if (source.jwks) return Array.isArray(source.jwks.keys) ? pick(source.jwks.keys, kid, 'the pasted JWKS') : { problem: 'the pasted JWKS has no "keys" array' };
    const { keys, problem } = await loadJwks(source.jwksUri!);
    return keys ? pick(keys, kid, source.jwksUri!) : { problem: problem! };
  };
}
