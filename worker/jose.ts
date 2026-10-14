// Minimal JOSE helpers on WebCrypto: base64url, RS256 SETs, HS256 access tokens, JWK thumbprints.
// Deliberately small so the whole flow is readable; no external JWT library.

import type { Env } from './env';

const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64u(data: ArrayBuffer | Uint8Array | string): string {
  const bytes = typeof data === 'string' ? enc.encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64u(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('not base64url');
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const randomId = (bytes = 16) => [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, '0')).join('');

export async function sha256(s: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)));
}

export type Jwk = JsonWebKey & { kid?: string; use?: string; alg?: string };

/** RFC 7638 thumbprint of an RSA key. */
export async function thumbprint(jwk: Jwk): Promise<string> {
  return b64u(await sha256(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })));
}

export type Decoded = { header: Record<string, any>; payload: Record<string, any>; signingInput: string; signature: Uint8Array };

/** Splits and parses a compact JWS without verifying it. Throws with a readable message. */
export function decodeJws(token: string): Decoded {
  const parts = token.trim().split('.');
  if (parts.length !== 3) throw new Error(`expected a compact JWS with 3 parts, got ${parts.length}${parts.length === 5 ? ' (this looks like an encrypted JWE)' : ''}`);
  let header, payload;
  try { header = JSON.parse(dec.decode(unb64u(parts[0]))); } catch { throw new Error('the JOSE header is not base64url-encoded JSON'); }
  try { payload = JSON.parse(dec.decode(unb64u(parts[1]))); } catch { throw new Error('the payload is not base64url-encoded JSON'); }
  if (!header || typeof header !== 'object' || Array.isArray(header)) throw new Error('the JOSE header is not a JSON object');
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('the payload is not a JSON object');
  return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: unb64u(parts[2]) };
}

const RS256 = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as const;

export async function verifyRs256(d: Decoded, jwk: Jwk): Promise<boolean> {
  const key = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, RS256, false, ['verify']);
  return crypto.subtle.verify(RS256, key, d.signature, enc.encode(d.signingInput));
}

// ── Transmitter signing key ────────────────────────────────────────────────────────────────
// Preferred: an RSA private key in the SSF_SIGNING_KEY secret (PKCS#8 PEM or JWK JSON).
// Fallback: a 2048-bit key generated once and kept in the KeyStore Durable Object, so a fresh
// deployment works before anyone has set the secret.

export type Signer = { kid: string; publicJwk: Jwk; sign: (header: object, payload: object) => Promise<string>; hmacKey: CryptoKey };

let cached: Promise<Signer> | null = null;

export function getSigner(env: Env): Promise<Signer> {
  cached ??= loadSigner(env).catch((e) => { cached = null; throw e; });
  return cached;
}

async function loadSigner(env: Env): Promise<Signer> {
  let privateJwk: Jwk;
  if (env.SSF_SIGNING_KEY) {
    privateJwk = await parsePrivateKey(env.SSF_SIGNING_KEY);
  } else {
    const stub = env.KEYS.get(env.KEYS.idFromName('signing-key'));
    privateJwk = await stub.privateJwk();
  }
  const key = await crypto.subtle.importKey('jwk', { ...privateJwk, alg: 'RS256' }, RS256, false, ['sign']);
  const publicJwk: Jwk = { kty: 'RSA', n: privateJwk.n, e: privateJwk.e };
  if (unb64u(publicJwk.n!).length < 256) throw new Error('SSF_SIGNING_KEY must be at least 2048 bits');
  const kid = await thumbprint(publicJwk);
  Object.assign(publicJwk, { kid, use: 'sig', alg: 'RS256' });
  // Access tokens are HMAC'd with a key derived from (not equal to) the signing key, so a
  // SET can never be replayed as an access token or vice versa.
  const hmacKey = await crypto.subtle.importKey('raw', await sha256(`ssf-access-token:${privateJwk.d}`), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  return {
    kid,
    publicJwk,
    hmacKey,
    async sign(header, payload) {
      const input = `${b64u(JSON.stringify({ ...header, alg: 'RS256', kid }))}.${b64u(JSON.stringify(payload))}`;
      return `${input}.${b64u(await crypto.subtle.sign(RS256, key, enc.encode(input)))}`;
    },
  };
}

async function parsePrivateKey(secret: string): Promise<Jwk> {
  const s = secret.trim();
  if (s.startsWith('{')) return JSON.parse(s);
  const m = s.match(/-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----/);
  if (!m) throw new Error('SSF_SIGNING_KEY must be a PKCS#8 PEM ("BEGIN PRIVATE KEY") or an RSA JWK');
  const der = Uint8Array.from(atob(m[1].replace(/\s+/g, '')), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('pkcs8', der, RS256, true, ['sign']);
  return (await crypto.subtle.exportKey('jwk', key)) as Jwk;
}

export async function generatePrivateJwk(): Promise<Jwk> {
  const pair = (await crypto.subtle.generateKey({ ...RS256, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, true, ['sign', 'verify'])) as CryptoKeyPair;
  return (await crypto.subtle.exportKey('jwk', pair.privateKey)) as Jwk;
}

// ── HS256 access tokens ────────────────────────────────────────────────────────────────────

export async function signHs256(key: CryptoKey, payload: object): Promise<string> {
  const input = `${b64u(JSON.stringify({ alg: 'HS256', typ: 'at+jwt' }))}.${b64u(JSON.stringify(payload))}`;
  return `${input}.${b64u(await crypto.subtle.sign('HMAC', key, enc.encode(input)))}`;
}

export async function verifyHs256(key: CryptoKey, token: string): Promise<Record<string, any> | null> {
  let d: Decoded;
  try { d = decodeJws(token); } catch { return null; }
  if (d.header.alg !== 'HS256' || d.header.typ !== 'at+jwt') return null;
  return (await crypto.subtle.verify('HMAC', key, d.signature, enc.encode(d.signingInput))) ? d.payload : null;
}
