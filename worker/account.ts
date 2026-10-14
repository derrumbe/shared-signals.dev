// Optional passkey accounts for the playground. An account is a set of passkeys plus one sandbox
// (client_id + secret), so it can be picked up on any device. No email, no
// name, no password. One Durable Object per account, named by the account id, which is also the
// WebAuthn user handle: a discoverable-credential sign-in returns it, so no credential index is needed.
//
// Signing in and out also produces real CAEP signals: session-established and session-revoked about
// the account are sent to every stream in the account's sandbox (unless turned off).

import { DurableObject } from 'cloudflare:workers';
import {
  generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { getSigner, randomId, seal, signHs256, unseal, verifyHs256 } from './jose';
import { error, readJson, reply, type Reply } from './http';
import { tenantFor } from './auth';
import type { Ctx } from './transmitter';
import type { Env } from './env';

const SESSION_TTL = 30 * 24 * 3600;
const CHALLENGE_TTL = 300;
const IDLE_EXPIRY_MS = 90 * 24 * 3600 * 1000;
const MAX_PASSKEYS = 10;
const MAX_SESSIONS = 20;

type Passkey = { id: string; publicKey: string; counter: number; transports?: string[]; label: string; created: number; lastUsed: number };
type Saved = { client_id: string; secret: string; label: string; saved: number }; // secret is sealed (AES-GCM)
type Session = { sid: string; created: number; expires: number };
type Data = { id: string; created: number; lastSeen: number; passkeys: Passkey[]; sandboxes: Saved[]; sessions: Session[]; signals: boolean };

const now = () => Math.floor(Date.now() / 1000);
const b64uBytes = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const bytesB64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const cleanLabel = (v: unknown, fallback: string) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, 60) : fallback);

export class Account extends DurableObject<Env> {
  private data() { return this.ctx.storage.get<Data>('data'); }
  private async save(d: Data) {
    d.lastSeen = Date.now();
    await this.ctx.storage.put('data', d);
    await this.ctx.storage.setAlarm(d.lastSeen + IDLE_EXPIRY_MS);
  }

  async create(id: string, pk: Passkey) {
    if (await this.data()) throw new Error('account exists');
    await this.save({ id, created: Date.now(), lastSeen: Date.now(), passkeys: [pk], sandboxes: [], sessions: [], signals: true });
  }

  async passkey(credId: string): Promise<Passkey | null> {
    return (await this.data())?.passkeys.find((p) => p.id === credId) ?? null;
  }

  async addPasskey(pk: Passkey): Promise<string | null> {
    const d = await this.data(); if (!d) return 'no such account';
    if (d.passkeys.length >= MAX_PASSKEYS) return `at most ${MAX_PASSKEYS} passkeys per account`;
    d.passkeys.push(pk);
    await this.save(d);
    return null;
  }

  async usedPasskey(credId: string, counter: number) {
    const d = await this.data(); if (!d) return;
    const p = d.passkeys.find((x) => x.id === credId);
    if (p) { p.counter = counter; p.lastUsed = Date.now(); }
    await this.save(d);
  }

  async removePasskey(credId: string): Promise<string | null> {
    const d = await this.data(); if (!d) return 'no such account';
    if (!d.passkeys.some((p) => p.id === credId)) return 'no such passkey';
    if (d.passkeys.length === 1) return 'this is your only passkey; delete the account instead';
    d.passkeys = d.passkeys.filter((p) => p.id !== credId);
    await this.save(d);
    return null;
  }

  async startSession(): Promise<Session> {
    const d = (await this.data())!;
    const s = { sid: randomId(), created: now(), expires: now() + SESSION_TTL };
    d.sessions = [...d.sessions.filter((x) => x.expires > now()), s].slice(-MAX_SESSIONS);
    await this.save(d);
    return s;
  }

  async hasSession(sid: string): Promise<boolean> {
    const d = await this.data();
    return !!d?.sessions.some((s) => s.sid === sid && s.expires > now());
  }

  async endSession(sid: string) {
    const d = await this.data(); if (!d) return;
    d.sessions = d.sessions.filter((s) => s.sid !== sid);
    await this.save(d);
  }

  /** Account details for its owner, with saved sandbox secrets decrypted. */
  async view() {
    const d = await this.data(); if (!d) return null;
    const { aesKey } = await getSigner(this.env);
    await this.save(d);
    return {
      created: new Date(d.created).toISOString(),
      expires: new Date(d.lastSeen + IDLE_EXPIRY_MS).toISOString(),
      signals: d.signals,
      passkeys: d.passkeys.map((p) => ({ id: p.id, label: p.label, created: new Date(p.created).toISOString(), last_used: new Date(p.lastUsed).toISOString() })),
      sandboxes: await Promise.all(d.sandboxes.map(async (s) => ({ client_id: s.client_id, client_secret: await unseal(aesKey, s.secret), label: s.label, saved: new Date(s.saved).toISOString() }))),
    };
  }

  async saveSandbox(client_id: string, secret: string, label: string): Promise<string | null> {
    const d = await this.data(); if (!d) return 'no such account';
    const { aesKey } = await getSigner(this.env);
    const entry = { client_id, secret: await seal(aesKey, secret), label, saved: Date.now() };
    // One sandbox per account: saving replaces whatever was there (which is not deleted, just no longer kept).
    d.sandboxes = [entry];
    await this.save(d);
    return null;
  }

  async removeSandbox(client_id: string) {
    const d = await this.data(); if (!d) return;
    d.sandboxes = d.sandboxes.filter((s) => s.client_id !== client_id);
    await this.save(d);
  }

  async setSignals(on: boolean) {
    const d = await this.data(); if (!d) return;
    d.signals = on;
    await this.save(d);
  }

  /** Saved sandboxes (decrypted) if session signals are on, for sending CAEP events. */
  async signalTargets(): Promise<{ client_id: string; secret: string }[]> {
    const d = await this.data(); if (!d?.signals) return [];
    const { aesKey } = await getSigner(this.env);
    return Promise.all(d.sandboxes.map(async (s) => ({ client_id: s.client_id, secret: await unseal(aesKey, s.secret) })));
  }

  async destroy() { await this.ctx.storage.deleteAll(); }

  async alarm() {
    const d = await this.data();
    if (d && Date.now() < d.lastSeen + IDLE_EXPIRY_MS) await this.ctx.storage.setAlarm(d.lastSeen + IDLE_EXPIRY_MS);
    else await this.ctx.storage.deleteAll();
  }
}

// ── HTTP layer ───────────────────────────────────────────────────────────────────────────────

const account = (env: Env, id: string) => env.ACCOUNT.get(env.ACCOUNT.idFromName(id));
const isId = (s: unknown): s is string => typeof s === 'string' && /^[0-9a-f]{32}$/.test(s);

function cookie(url: URL, name: string, value: string, maxAge: number) {
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${url.protocol === 'https:' ? '; Secure' : ''}`;
}
function readCookie(request: Request, name: string): string | null {
  const m = (request.headers.get('cookie') ?? '').match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? m[1] : null;
}

type Me = { aid: string; sid: string };

/** The signed-in account from the session cookie, checked against the account's live sessions. */
async function me(request: Request, env: Env): Promise<Me | null> {
  const raw = readCookie(request, 'ssf_session');
  if (!raw) return null;
  const c = await verifyHs256((await getSigner(env)).hmacKey, raw, 'session+jwt');
  if (!c || !isId(c.aid) || typeof c.sid !== 'string' || c.exp <= now()) return null;
  return (await account(env, c.aid).hasSession(c.sid)) ? { aid: c.aid, sid: c.sid } : null;
}

async function signIn(url: URL, env: Env, aid: string, amr: string[], ec: ExecutionContext): Promise<Reply> {
  const s = await account(env, aid).startSession();
  const token = await signHs256((await getSigner(env)).hmacKey, { aid, sid: s.sid, iat: s.created, exp: s.expires }, 'session+jwt');
  ec.waitUntil(sessionSignal(env, url.origin, aid, s.sid, 'session-established', amr).catch((e) => console.error('session-established signal failed', e)));
  return reply(200, { signed_in: true }, { 'set-cookie': [cookie(url, 'ssf_session', token, SESSION_TTL), clearChallenge(url)] });
}

/** Sends a CAEP session event about this account to every stream in its saved sandboxes. */
async function sessionSignal(env: Env, issuer: string, aid: string, sid: string, type: 'session-established' | 'session-revoked', amr: string[] = []) {
  const targets = await account(env, aid).signalTargets();
  const sub_id = { format: 'complex', user: { format: 'opaque', id: aid }, session: { format: 'opaque', id: sid } };
  const event = type === 'session-established'
    ? { initiating_entity: 'user', amr, reason_admin: { en: 'Signed in to shared-signals.dev with a passkey' } }
    : { initiating_entity: 'user', reason_admin: { en: 'Signed out of shared-signals.dev' } };
  await Promise.all(targets.map(async ({ client_id, secret }) => {
    const tenant = await tenantFor(client_id, secret);
    const ctx: Ctx = { clientId: client_id, tenant, iat: now(), issuer };
    await env.SANDBOX.get(env.SANDBOX.idFromName(tenant)).fire(ctx, { event_type: type, sub_id, event: structuredClone(event) });
  }));
}

/** Challenges travel in a short-lived signed cookie, so nothing is stored before a passkey exists. */
async function setChallenge(url: URL, env: Env, data: object) {
  const t = await signHs256((await getSigner(env)).hmacKey, { ...data, exp: now() + CHALLENGE_TTL }, 'webauthn-challenge+jwt');
  return cookie(url, 'ssf_webauthn', t, CHALLENGE_TTL);
}
async function takeChallenge(request: Request, env: Env, purpose: string): Promise<Record<string, any> | null> {
  const raw = readCookie(request, 'ssf_webauthn');
  const c = raw && (await verifyHs256((await getSigner(env)).hmacKey, raw, 'webauthn-challenge+jwt'));
  return c && c.exp > now() && c.purpose === purpose ? c : null;
}
function clearChallenge(url: URL) { return cookie(url, 'ssf_webauthn', '', 0); }

export async function accountRoute(request: Request, env: Env, url: URL, ec: ExecutionContext): Promise<Reply | null> {
  const { pathname } = url;
  if (!pathname.startsWith('/api/auth/') && pathname !== '/api/account' && !pathname.startsWith('/api/account/')) return null;
  const method = request.method;
  // Cookie-authenticated, so refuse cross-site writes (on top of SameSite=Lax).
  if (method !== 'GET' && request.headers.get('origin') !== url.origin) return error(403, 'access_denied', 'Cross-origin request refused.');
  const rpID = url.hostname;
  const origin = url.origin;
  let body: Record<string, any> = {};
  if (method === 'POST' || method === 'PATCH') { const j = await readJson(request); if ('fail' in j) return j.fail; body = j.body; }

  // ── Registration: new account, or another passkey for the signed-in one ──
  if (pathname === '/api/auth/register/options' && method === 'POST') {
    const current = await me(request, env);
    const aid = current?.aid ?? randomId();
    const existing = current ? (await account(env, aid).view())?.passkeys ?? [] : [];
    const options = await generateRegistrationOptions({
      rpName: 'shared-signals.dev', rpID, userID: new TextEncoder().encode(aid) as Uint8Array<ArrayBuffer>,
      userName: `shared-signals.dev ${aid.slice(0, 6)}`, userDisplayName: 'shared-signals.dev playground',
      attestationType: 'none', excludeCredentials: existing.map((p) => ({ id: p.id })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    });
    return reply(200, options, { 'set-cookie': await setChallenge(url, env, { purpose: 'register', challenge: options.challenge, aid, adding: !!current }) });
  }
  if (pathname === '/api/auth/register/verify' && method === 'POST') {
    const ch = await takeChallenge(request, env, 'register');
    if (!ch) return error(400, 'invalid_request', 'The passkey request expired. Try again.');
    let v;
    try { v = await verifyRegistrationResponse({ response: body.response, expectedChallenge: ch.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: false }); }
    catch (e: any) { return error(400, 'invalid_request', `Passkey not accepted: ${e.message}`); }
    if (!v.verified || !v.registrationInfo) return error(400, 'invalid_request', 'Passkey not accepted.');
    const { credential } = v.registrationInfo;
    const pk: Passkey = { id: credential.id, publicKey: bytesB64u(credential.publicKey), counter: credential.counter, transports: credential.transports, label: cleanLabel(body.label, 'Passkey'), created: Date.now(), lastUsed: Date.now() };
    const headers = { 'set-cookie': clearChallenge(url) };
    if (ch.adding) {
      const current = await me(request, env);
      if (current?.aid !== ch.aid) return error(401, 'invalid_request', 'Sign in again to add a passkey.', headers);
      const problem = await account(env, ch.aid).addPasskey(pk);
      return problem ? error(400, 'invalid_request', problem, headers) : reply(200, { added: true }, headers);
    }
    await account(env, ch.aid).create(ch.aid, pk);
    // Save the sandbox the new user is in before signing in, so session-established reaches its streams.
    const sb = body.sandbox;
    if (sb && typeof sb.client_id === 'string' && /^[\x21-\x7e]{3,128}$/.test(sb.client_id) && typeof sb.client_secret === 'string' && sb.client_secret.length >= 16 && sb.client_secret.length <= 256)
      await account(env, ch.aid).saveSandbox(sb.client_id, sb.client_secret, cleanLabel(sb.label, sb.client_id));
    return signIn(url, env, ch.aid, ['pop', ...(v.registrationInfo.userVerified ? ['user'] : [])], ec);
  }

  // ── Sign in with a discoverable passkey ──
  if (pathname === '/api/auth/login/options' && method === 'POST') {
    const options = await generateAuthenticationOptions({ rpID, userVerification: 'preferred' });
    return reply(200, options, { 'set-cookie': await setChallenge(url, env, { purpose: 'login', challenge: options.challenge }) });
  }
  if (pathname === '/api/auth/login/verify' && method === 'POST') {
    const ch = await takeChallenge(request, env, 'login');
    if (!ch) return error(400, 'invalid_request', 'The sign-in request expired. Try again.');
    let aid = '';
    try { aid = new TextDecoder().decode(b64uBytes(body.response?.response?.userHandle ?? '')); } catch {}
    const pk = isId(aid) ? await account(env, aid).passkey(body.response?.id) : null;
    if (!pk) return error(400, 'invalid_request', 'This passkey isn’t registered here (the account may have expired after 90 days without use).');
    let v;
    try {
      v = await verifyAuthenticationResponse({
        response: body.response, expectedChallenge: ch.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: false,
        credential: { id: pk.id, publicKey: b64uBytes(pk.publicKey), counter: pk.counter, transports: pk.transports as any },
      });
    } catch (e: any) { return error(400, 'invalid_request', `Sign-in failed: ${e.message}`); }
    if (!v.verified) return error(400, 'invalid_request', 'Sign-in failed.');
    await account(env, aid).usedPasskey(pk.id, v.authenticationInfo.newCounter);
    return signIn(url, env, aid, ['pop', ...(v.authenticationInfo.userVerified ? ['user'] : [])], ec);
  }

  // ── Everything below needs a session ──
  const current = await me(request, env);
  if (pathname === '/api/account' && method === 'GET') {
    if (!current) return reply(200, { signed_in: false });
    return reply(200, { signed_in: true, ...(await account(env, current.aid).view()) });
  }
  if (!current) return error(401, 'invalid_request', 'Sign in first.');
  const acct = account(env, current.aid);

  if (pathname === '/api/auth/logout' && method === 'POST') {
    // Send session-revoked before the session (and its signal targets) can change.
    await sessionSignal(env, origin, current.aid, current.sid, 'session-revoked').catch(() => {});
    await acct.endSession(current.sid);
    return reply(200, { signed_in: false }, { 'set-cookie': cookie(url, 'ssf_session', '', 0) });
  }
  if (pathname === '/api/account' && method === 'PATCH') {
    if (typeof body.signals !== 'boolean') return error(400, 'invalid_request', 'signals must be true or false.');
    await acct.setSignals(body.signals);
    return reply(200, await acct.view());
  }
  if (pathname === '/api/account' && method === 'DELETE') {
    await sessionSignal(env, origin, current.aid, current.sid, 'session-revoked').catch(() => {});
    await acct.destroy();
    return reply(204, undefined, { 'set-cookie': cookie(url, 'ssf_session', '', 0) });
  }
  if (pathname === '/api/account/sandboxes') {
    if (method === 'POST') {
      const { client_id, client_secret } = body;
      if (typeof client_id !== 'string' || !/^[\x21-\x7e]{3,128}$/.test(client_id) || typeof client_secret !== 'string' || client_secret.length < 16 || client_secret.length > 256)
        return error(400, 'invalid_request', 'Need the sandbox’s client_id and client_secret (16+ characters).');
      const problem = await acct.saveSandbox(client_id, client_secret, cleanLabel(body.label, client_id));
      return problem ? error(400, 'invalid_request', problem) : reply(200, await acct.view());
    }
    if (method === 'DELETE') { await acct.removeSandbox(url.searchParams.get('client_id') ?? ''); return reply(200, await acct.view()); }
  }
  if (pathname === '/api/account/passkeys' && method === 'DELETE') {
    const problem = await acct.removePasskey(url.searchParams.get('id') ?? '');
    return problem ? error(400, 'invalid_request', problem) : reply(200, await acct.view());
  }
  return error(404, 'not_found', 'Not found.');
}

