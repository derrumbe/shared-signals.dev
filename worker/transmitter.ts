// The sample SSF Transmitter. One Durable Object per OAuth tenant (client_id + secret) holds that
// tenant's streams, subjects, outbound queues and delivery logs, so tenants never see each other.
//
// Built to the CAEP Interoperability Profile 1.0 checklist: stream create / read / update /
// replace / delete, status, subjects, verification, push (RFC 8935) and poll (RFC 8936) delivery,
// RS256-signed SETs with exactly one event each.

import { DurableObject } from 'cloudflare:workers';
import { EVENTS, SCIM_PREFIX, uri } from '../src/data/events';
import { getSigner, randomId } from './jose';
import { challenge } from './auth';
import { error, reply, type Reply } from './http';
import { checkPublicUrl, safeFetch } from './ssrf';
import type { Env } from './env';

export const PUSH = 'urn:ietf:rfc:8935';
export const POLL = 'urn:ietf:rfc:8936';
const VERIFICATION = 'https://schemas.openid.net/secevent/ssf/event-type/verification';
const STREAM_UPDATED = 'https://schemas.openid.net/secevent/ssf/event-type/stream-updated';

/** Every CAEP, RISC and SCIM (RFC 9967) event type in the catalogue. SSF's own events are always sendable. */
export const EVENTS_SUPPORTED = EVENTS.filter((e) => e.spec !== 'ssf').map(uri);

const MAX_STREAMS = 10;
const MAX_QUEUE = 50;
const MAX_LOG = 60; // entries carry their SET (~1.5 KB), so keep the log short
const MAX_SUBJECTS = 100;
const MIN_VERIFICATION_INTERVAL = 15;
const INACTIVITY_TIMEOUT = 7 * 24 * 3600;
const RETRY_DELAYS = [30, 120, 600, 3600]; // seconds; then give up
const FIRE_LIMIT = { perMinute: 30 };

export type Ctx = { clientId: string; tenant: string; iat: number; issuer: string };
type Status = 'enabled' | 'paused' | 'disabled';
type Delivery = { method: string; endpoint_url?: string; authorization_header?: string };
type Config = {
  stream_id: string; iss: string; aud: string; delivery: Delivery;
  events_supported: string[]; events_requested?: string[]; events_delivered: string[];
  description?: string; min_verification_interval: number; inactivity_timeout: number;
};
type Stream = { config: Config; status: Status; reason?: string; removed: unknown[]; added: unknown[]; lastVerify: number; lastActivity: number; created: number };
type Queued = { jti: string; set: string; type: string; held: boolean; attempts: number; nextAt: number };
type LogEntry = { at: number; action: string; ok: boolean; jti?: string; event?: string; detail?: string; set?: string; response?: { status: number; body: unknown } };
type Meta = { revokedBefore: number; fireWindow: number; fireCount: number };

const now = () => Math.floor(Date.now() / 1000);
const isStr = (v: unknown): v is string => typeof v === 'string';

/** JSON with sorted keys, for comparing subjects and config values. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as any)[k])}`).join(',')}}`;
  return JSON.stringify(v);
}

/** SSF §8.1.3.1 subject matching, extended so a simple subject matches a complex one containing it. */
export function subjectsMatch(a: any, b: any): boolean {
  if (canonical(a) === canonical(b)) return true;
  if (a?.format === 'complex' && b?.format === 'complex') {
    const keys = new Set([...Object.keys(a), ...Object.keys(b)].filter((k) => k !== 'format'));
    return [...keys].every((k) => a[k] === undefined || b[k] === undefined || canonical(a[k]) === canonical(b[k]));
  }
  const [complex, simple] = a?.format === 'complex' ? [a, b] : b?.format === 'complex' ? [b, a] : [null, null];
  return !!complex && Object.entries(complex).some(([k, v]) => k !== 'format' && canonical(v) === canonical(simple));
}

function subjectProblem(s: unknown): string | null {
  if (!s || typeof s !== 'object' || Array.isArray(s)) return 'subject must be a JSON object';
  if (!isStr((s as any).format)) return 'subject must have a "format" member';
  if (canonical(s).length > 2048) return 'subject is too large';
  return null;
}

export class Transmitter extends DurableObject<Env> {
  // ── Storage helpers ──────────────────────────────────────────────────

  private async meta(): Promise<Meta> {
    return (await this.ctx.storage.get<Meta>('meta')) ?? { revokedBefore: 0, fireWindow: 0, fireCount: 0 };
  }
  private stream(id: unknown) {
    return isStr(id) && /^[0-9a-f]{32}$/.test(id) ? this.ctx.storage.get<Stream>(`stream:${id}`) : Promise.resolve(undefined);
  }
  private async streams(): Promise<Stream[]> {
    return [...(await this.ctx.storage.list<Stream>({ prefix: 'stream:' })).values()].sort((a, b) => a.created - b.created);
  }
  private async save(s: Stream) {
    await this.ctx.storage.put(`stream:${s.config.stream_id}`, s);
    await this.schedule();
  }
  private async queue(id: string) {
    return (await this.ctx.storage.get<Queued[]>(`queue:${id}`)) ?? [];
  }
  private async log(id: string, entry: Omit<LogEntry, 'at'>) {
    const log = (await this.ctx.storage.get<LogEntry[]>(`log:${id}`)) ?? [];
    log.unshift({ at: Date.now(), ...entry });
    await this.ctx.storage.put(`log:${id}`, log.slice(0, MAX_LOG));
  }

  /** Common entry checks: token not revoked; stream exists and belongs to the caller. */
  private async guard(c: Ctx): Promise<Reply | null> {
    if (c.iat < (await this.meta()).revokedBefore) return error(401, 'invalid_token', 'The access token has been revoked.', { 'www-authenticate': challenge('invalid_token', 'revoked') });
    return null;
  }
  private async find(c: Ctx, id: unknown): Promise<Stream | Reply> {
    if (!isStr(id) || !id) return error(400, 'invalid_request', 'stream_id is required.');
    const s = await this.stream(id);
    if (!s) return error(404, 'not_found', `No stream "${id}" for this Receiver.`);
    s.lastActivity = now();
    return s;
  }

  // ── Tokens ───────────────────────────────────────────────────────────

  async revokeTokens(at: number) {
    const m = await this.meta();
    m.revokedBefore = at + 1;
    await this.ctx.storage.put('meta', m);
  }

  // ── Configuration endpoint ───────────────────────────────────────────

  private checkDelivery(d: unknown, streamId: string, issuer: string): Delivery | Reply {
    if (d === undefined) return { method: POLL, endpoint_url: `${issuer}/ssf/poll/${streamId}` };
    if (!d || typeof d !== 'object' || Array.isArray(d)) return error(400, 'invalid_request', 'delivery must be an object.');
    const { method, endpoint_url, authorization_header } = d as Record<string, unknown>;
    if (method === POLL) return { method: POLL, endpoint_url: `${issuer}/ssf/poll/${streamId}` };
    if (method !== PUSH) return error(400, 'invalid_request', `delivery.method must be "${PUSH}" (push) or "${POLL}" (poll).`);
    if (authorization_header !== undefined && (!isStr(authorization_header) || authorization_header.length > 1024 || /[\r\n]/.test(authorization_header)))
      return error(400, 'invalid_request', 'delivery.authorization_header must be a single-line string.');
    if (!isStr(endpoint_url)) return error(400, 'invalid_request', 'Push delivery needs delivery.endpoint_url.');
    if (!internalReceiver(endpoint_url, issuer)) {
      const { problem } = checkPublicUrl(endpoint_url);
      if (problem) return error(400, 'invalid_request', `delivery.endpoint_url ${problem}.`);
    }
    return { method: PUSH, endpoint_url, ...(authorization_header ? { authorization_header } : {}) };
  }

  private checkReceiverFields(body: Record<string, any>): Reply | null {
    const er = body.events_requested;
    if (er !== undefined && (!Array.isArray(er) || !er.every(isStr) || er.length > 100)) return error(400, 'invalid_request', 'events_requested must be an array of event type URIs.');
    if (body.description !== undefined && !isStr(body.description)) return error(400, 'invalid_request', 'description must be a string.');
    return null;
  }

  async createStream(c: Ctx, body: Record<string, any>): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    const bad = this.checkReceiverFields(body); if (bad) return bad;
    if ((await this.streams()).length >= MAX_STREAMS) return error(403, 'access_denied', `This sandbox allows ${MAX_STREAMS} streams per client. Delete one first.`);
    const id = randomId();
    const delivery = this.checkDelivery(body.delivery, id, c.issuer);
    if ('status' in delivery) return delivery;
    const config: Config = {
      stream_id: id, iss: c.issuer, aud: c.clientId, delivery,
      events_supported: EVENTS_SUPPORTED,
      ...(body.events_requested ? { events_requested: body.events_requested } : {}),
      events_delivered: [],
      ...(body.description ? { description: String(body.description).slice(0, 256) } : {}),
      min_verification_interval: MIN_VERIFICATION_INTERVAL, inactivity_timeout: INACTIVITY_TIMEOUT,
    };
    config.events_delivered = delivered(config);
    const s: Stream = { config, status: 'enabled', removed: [], added: [], lastVerify: 0, lastActivity: now(), created: Date.now() };
    await this.save(s);
    await this.log(id, { action: 'stream created', ok: true, detail: `${delivery.method === PUSH ? 'push to ' + delivery.endpoint_url : 'poll'}; ${config.events_delivered.length} event types delivered` });
    return reply(201, config);
  }

  async readStream(c: Ctx, id: string | null): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    if (id === null) {
      const all = await this.streams();
      for (const s of all) { s.lastActivity = now(); await this.ctx.storage.put(`stream:${s.config.stream_id}`, s); }
      return reply(200, all.map((s) => s.config));
    }
    const s = await this.find(c, id); if (isReply(s)) return s;
    await this.save(s);
    return reply(200, s.config);
  }

  /** PATCH (replace = false) and PUT (replace = true). */
  async updateStream(c: Ctx, body: Record<string, any>, replace: boolean): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    const s = await this.find(c, body.stream_id); if (isReply(s)) return s;
    const bad = this.checkReceiverFields(body); if (bad) return bad;
    const cfg = s.config;
    // Transmitter-supplied properties may be sent, but must match what we have.
    for (const k of ['iss', 'aud', 'events_supported', 'events_delivered', 'min_verification_interval', 'inactivity_timeout'] as const) {
      if (body[k] !== undefined && canonical(body[k]) !== canonical(cfg[k])) return error(400, 'invalid_request', `${k} is Transmitter-supplied and does not match the current value.`);
    }
    if (replace || body.delivery !== undefined) {
      const d = this.checkDelivery(body.delivery, cfg.stream_id, c.issuer);
      if ('status' in d) return d;
      cfg.delivery = d;
    }
    if (replace || body.events_requested !== undefined) {
      if (body.events_requested === undefined) delete cfg.events_requested; else cfg.events_requested = body.events_requested;
    }
    if (replace || body.description !== undefined) {
      if (body.description === undefined) delete cfg.description; else cfg.description = String(body.description).slice(0, 256);
    }
    cfg.events_delivered = delivered(cfg);
    await this.save(s);
    await this.log(cfg.stream_id, { action: replace ? 'stream replaced' : 'stream updated', ok: true });
    if (cfg.delivery.method === PUSH) this.ctx.waitUntil(this.flush(s));
    return reply(200, cfg);
  }

  async deleteStream(c: Ctx, id: string | null): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    const s = await this.find(c, id); if (isReply(s)) return s;
    await this.ctx.storage.delete([`stream:${id}`, `queue:${id}`, `log:${id}`]);
    await this.schedule();
    return reply(204);
  }

  // ── Status endpoint ──────────────────────────────────────────────────

  async readStatus(c: Ctx, id: string | null): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    const s = await this.find(c, id); if (isReply(s)) return s;
    await this.save(s);
    return reply(200, statusOf(s));
  }

  /** Receiver-requested status change (POST /ssf/status). */
  async updateStatus(c: Ctx, body: Record<string, any>): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    const s = await this.find(c, body.stream_id); if (isReply(s)) return s;
    if (!['enabled', 'paused', 'disabled'].includes(body.status)) return error(400, 'invalid_request', 'status must be "enabled", "paused" or "disabled".');
    if (body.reason !== undefined && !isStr(body.reason)) return error(400, 'invalid_request', 'reason must be a string.');
    await this.setStatus(s, body.status, body.reason?.slice(0, 256), 'Receiver');
    return reply(200, statusOf(s));
  }

  /** Transmitter-initiated status change from the playground UI; announces it with stream-updated. */
  async adminStatus(c: Ctx, body: Record<string, any>): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    const s = await this.find(c, body.stream_id); if (isReply(s)) return s;
    const status = body.status as Status;
    if (!['enabled', 'paused', 'disabled'].includes(status)) return error(400, 'invalid_request', 'status must be "enabled", "paused" or "disabled".');
    const reason = isStr(body.reason) && body.reason ? body.reason.slice(0, 256) : undefined;
    const sub = { format: 'opaque', id: s.config.stream_id };
    const ev = { status, ...(reason ? { reason } : {}) };
    let sent;
    // SSF §8.1.5: announce before stopping a stream, and after re-enabling one.
    if (status === 'enabled') {
      await this.setStatus(s, status, reason, 'Transmitter');
      sent = await this.send(s, STREAM_UPDATED, ev, sub);
    } else {
      sent = await this.send(s, STREAM_UPDATED, ev, sub);
      await this.setStatus(s, status, reason, 'Transmitter');
    }
    return reply(200, { ...statusOf(s), stream_updated: sent });
  }

  private async setStatus(s: Stream, status: Status, reason: string | undefined, by: string) {
    const was = s.status;
    s.status = status;
    if (reason) s.reason = reason; else delete s.reason;
    const id = s.config.stream_id;
    if (status === 'disabled') {
      const dropped = (await this.queue(id)).length;
      await this.ctx.storage.delete(`queue:${id}`);
      if (dropped) await this.log(id, { action: 'queue cleared', ok: true, detail: `${dropped} undelivered SET(s) dropped because the stream is disabled` });
    }
    await this.save(s);
    await this.log(id, { action: `status ${was} → ${status}`, ok: true, detail: `by the ${by}${reason ? `: ${reason}` : ''}` });
    if (status === 'enabled' && was !== 'enabled') {
      const q = (await this.queue(id)).map((e) => ({ ...e, held: false, nextAt: 0 }));
      await this.ctx.storage.put(`queue:${id}`, q);
      if (s.config.delivery.method === PUSH) this.ctx.waitUntil(this.flush(s));
    }
  }

  // ── Subjects ─────────────────────────────────────────────────────────

  async addSubject(c: Ctx, body: Record<string, any>): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    const s = await this.find(c, body.stream_id); if (isReply(s)) return s;
    const p = subjectProblem(body.subject); if (p) return error(400, 'invalid_request', p);
    if (body.verified !== undefined && typeof body.verified !== 'boolean') return error(400, 'invalid_request', 'verified must be a boolean.');
    const key = canonical(body.subject);
    s.removed = s.removed.filter((x) => canonical(x) !== key);
    if (!s.added.some((x) => canonical(x) === key)) {
      if (s.added.length >= MAX_SUBJECTS) return error(429, 'too_many_subjects', `This sandbox keeps at most ${MAX_SUBJECTS} subjects per stream.`);
      s.added.push(body.subject);
    }
    await this.save(s);
    await this.log(s.config.stream_id, { action: 'subject added', ok: true, detail: key });
    return reply(200);
  }

  async removeSubject(c: Ctx, body: Record<string, any>): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    const s = await this.find(c, body.stream_id); if (isReply(s)) return s;
    const p = subjectProblem(body.subject); if (p) return error(400, 'invalid_request', p);
    const key = canonical(body.subject);
    if (body.subject.format === 'opaque' && body.subject.id === s.config.stream_id) return error(400, 'invalid_request', 'The stream’s own subject cannot be removed (SSF §8.1.4.1).');
    s.added = s.added.filter((x) => canonical(x) !== key);
    if (!s.removed.some((x) => canonical(x) === key)) {
      if (s.removed.length >= MAX_SUBJECTS) return error(429, 'too_many_subjects', `This sandbox keeps at most ${MAX_SUBJECTS} subjects per stream.`);
      s.removed.push(body.subject);
    }
    await this.save(s);
    await this.log(s.config.stream_id, { action: 'subject removed', ok: true, detail: `${key} — events about it will no longer be sent` });
    return reply(204);
  }

  // ── Verification ─────────────────────────────────────────────────────

  async verify(c: Ctx, body: Record<string, any>): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    const s = await this.find(c, body.stream_id); if (isReply(s)) return s;
    if (body.state !== undefined && (!isStr(body.state) || body.state.length > 1024)) return error(400, 'invalid_request', 'state must be a string of at most 1024 characters.');
    const wait = s.lastVerify + s.config.min_verification_interval - now();
    if (wait > 0) return error(429, 'too_many_requests', `Verification was requested less than ${s.config.min_verification_interval} seconds ago (min_verification_interval).`, { 'retry-after': String(wait) });
    s.lastVerify = now();
    await this.save(s);
    // Sent after we reply, so a Receiver waiting on this 204 can't deadlock its own push endpoint.
    this.ctx.waitUntil(this.send(s, VERIFICATION, body.state === undefined ? {} : { state: body.state }, { format: 'opaque', id: s.config.stream_id }));
    return reply(204);
  }

  // ── Poll delivery (RFC 8936) ─────────────────────────────────────────

  async poll(c: Ctx, id: string, body: Record<string, any>): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    const s = await this.find(c, id); if (isReply(s)) return s;
    if (s.config.delivery.method !== POLL) return error(400, 'invalid_request', 'This stream uses push delivery; change delivery.method to poll to poll it.');
    const { ack = [], setErrs = {}, maxEvents = 10 } = body;
    if (!Array.isArray(ack) || !ack.every(isStr)) return error(400, 'invalid_request', 'ack must be an array of jti strings.');
    if (!setErrs || typeof setErrs !== 'object' || Array.isArray(setErrs)) return error(400, 'invalid_request', 'setErrs must be an object keyed by jti.');
    if (!Number.isInteger(maxEvents) || maxEvents < 0) return error(400, 'invalid_request', 'maxEvents must be a non-negative integer.');

    let q = await this.queue(id);
    for (const jti of ack) {
      const e = q.find((x) => x.jti === jti);
      if (e) await this.log(id, { action: 'acknowledged', ok: true, jti, event: e.type, set: e.set });
    }
    for (const [jti, v] of Object.entries(setErrs as Record<string, any>)) {
      const e = q.find((x) => x.jti === jti);
      if (e) await this.log(id, { action: 'rejected by Receiver', ok: false, jti, event: e.type, detail: `${v?.err ?? 'error'}: ${v?.description ?? ''}`.slice(0, 300) });
    }
    const done = new Set([...ack, ...Object.keys(setErrs)]);
    q = q.filter((e) => !done.has(e.jti));
    await this.ctx.storage.put(`queue:${id}`, q);

    const ready = s.status === 'enabled' ? q.filter((e) => !e.held) : [];
    const out = ready.slice(0, Math.min(maxEvents, 50));
    if (out.length) await this.log(id, { action: 'polled', ok: true, detail: `${out.length} SET(s) returned: ${out.map((e) => e.jti).join(', ')}` });
    await this.save(s);
    return reply(200, { sets: Object.fromEntries(out.map((e) => [e.jti, e.set])), moreAvailable: ready.length > out.length });
  }

  // ── Firing events (the Transmitter's own UI) ─────────────────────────

  async fire(c: Ctx, body: Record<string, any>): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    const type = EVENTS_SUPPORTED.find((u) => u === body.event_type || u.endsWith(`/${body.event_type}`) || u === SCIM_PREFIX + body.event_type);
    if (!type) return error(400, 'invalid_request', 'event_type must be one of the CAEP, RISC or SCIM event types in events_supported.');
    const p = subjectProblem(body.sub_id); if (p) return error(400, 'invalid_request', `sub_id: ${p.replace('subject ', '')}.`);
    const event = body.event ?? {};
    if (!event || typeof event !== 'object' || Array.isArray(event)) return error(400, 'invalid_request', 'event must be a JSON object holding the event’s claims.');
    if (body.txn !== undefined && !isStr(body.txn)) return error(400, 'invalid_request', 'txn must be a string.');

    const m = await this.meta();
    const minute = Math.floor(now() / 60);
    if (m.fireWindow !== minute) { m.fireWindow = minute; m.fireCount = 0; }
    if (++m.fireCount > FIRE_LIMIT.perMinute) return error(429, 'too_many_requests', `At most ${FIRE_LIMIT.perMinute} events a minute, please.`, { 'retry-after': '60' });
    await this.ctx.storage.put('meta', m);

    // The Interoperability Profile requires reason_admin on every CAEP event it profiles.
    const notes: string[] = [];
    if (type.includes('/caep/') && (!event.reason_admin || typeof event.reason_admin !== 'object' || !Object.keys(event.reason_admin).length)) {
      event.reason_admin = { en: 'Sent from the shared-signals.dev playground' };
      notes.push('Added reason_admin, which the CAEP Interoperability Profile requires.');
    }
    if (type.includes('/caep/') && event.event_timestamp === undefined) event.event_timestamp = now();

    const targets = isStr(body.stream_id) && body.stream_id ? [await this.stream(body.stream_id)].filter(Boolean) as Stream[] : await this.streams();
    if (!targets.length) return error(404, 'not_found', isStr(body.stream_id) && body.stream_id ? `No stream "${body.stream_id}".` : 'Create a stream first.');
    const txn = body.txn ?? randomId(8);
    const results = [];
    for (const s of targets) {
      const id = s.config.stream_id;
      if (!s.config.events_delivered.includes(type)) { results.push({ stream_id: id, outcome: 'skipped', detail: 'event type is not in this stream’s events_delivered' }); continue; }
      if (s.removed.some((x) => subjectsMatch(x, body.sub_id))) {
        await this.log(id, { action: 'suppressed', ok: true, event: type, detail: 'subject was removed from the stream' });
        results.push({ stream_id: id, outcome: 'skipped', detail: 'subject was removed from this stream (subjects:remove)' });
        continue;
      }
      results.push({ stream_id: id, ...(await this.send(s, type, structuredClone(event), body.sub_id, txn)) });
    }
    return reply(200, { event_type: type, txn, notes, results });
  }

  /** Deletes the whole sandbox: every stream, queue and log. Tokens issued so far stop working. */
  async deleteSandbox(c: Ctx): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
    await this.revokeTokens(now());
    // The revocation record only matters until those tokens expire; the alarm then clears it.
    await this.ctx.storage.setAlarm(Date.now() + 3600 * 1000);
    return reply(204);
  }

  async logFor(c: Ctx, id: string | null): Promise<Reply> {
    const g = await this.guard(c); if (g) return g;
    const s = await this.find(c, id); if (isReply(s)) return s;
    return reply(200, {
      stream_id: s.config.stream_id, status: s.status, subjects: { added: s.added, removed: s.removed },
      queued: (await this.queue(s.config.stream_id)).map(({ jti, type, held, attempts, nextAt }) => ({ jti, type, held, attempts, next_attempt: nextAt ? new Date(nextAt * 1000).toISOString() : undefined })),
      log: (await this.ctx.storage.get<LogEntry[]>(`log:${s.config.stream_id}`)) ?? [],
    });
  }

  // ── Delivery ─────────────────────────────────────────────────────────

  /** Signs one SET for the stream and transmits, queues or holds it according to status and method. */
  private async send(s: Stream, type: string, event: object, sub: unknown, txn = randomId(8)) {
    const id = s.config.stream_id;
    const jti = randomId();
    if (s.status === 'disabled') {
      await this.log(id, { action: 'dropped', ok: false, jti, event: type, detail: 'stream is disabled' });
      return { outcome: 'dropped', jti, detail: 'stream is disabled, so events are not held' };
    }
    const signer = await getSigner(this.env);
    const set = await signer.sign({ typ: 'secevent+jwt' }, { iss: s.config.iss, jti, iat: now(), aud: s.config.aud, txn, sub_id: sub, events: { [type]: event } });
    const entry: Queued = { jti, set, type, held: s.status === 'paused', attempts: 0, nextAt: 0 };

    if (entry.held || s.config.delivery.method === POLL) {
      await this.enqueue(id, entry);
      const detail = entry.held ? 'held until the stream is enabled again' : 'waiting for the Receiver to poll';
      await this.log(id, { action: entry.held ? 'held' : 'queued', ok: true, jti, event: type, detail, set });
      return { outcome: entry.held ? 'held' : 'queued', jti, detail, set };
    }
    const r = await this.push(s, entry);
    return { outcome: r.ok ? 'delivered' : r.retry ? 'retrying' : 'failed', jti, detail: r.detail, set };
  }

  private async enqueue(id: string, e: Queued) {
    const q = await this.queue(id);
    q.push(e);
    const over = q.length - MAX_QUEUE;
    if (over > 0) await this.log(id, { action: 'dropped', ok: false, detail: `queue full; ${over} oldest SET(s) dropped` });
    await this.ctx.storage.put(`queue:${id}`, q.slice(Math.max(0, over)));
    await this.schedule();
  }

  /** One push attempt (RFC 8935). Retryable failures go (back) on the queue with backoff. */
  private async push(s: Stream, e: Queued): Promise<{ ok: boolean; retry: boolean; detail: string }> {
    const id = s.config.stream_id;
    const d = s.config.delivery;
    e.attempts++;
    const headers: Record<string, string> = { 'content-type': 'application/secevent+jwt', accept: 'application/json' };
    if (d.authorization_header) headers.authorization = d.authorization_header;

    let status: number, text: string, failure: string | undefined;
    const rid = internalReceiver(d.endpoint_url!, s.config.iss);
    if (rid) {
      const r: Reply = await this.env.SAMPLE_RECEIVER.get(this.env.SAMPLE_RECEIVER.idFromName(rid)).receive(headers['content-type'], d.authorization_header ?? null, e.set, id) as Reply;
      status = r.status; text = r.body ? JSON.stringify(r.body) : '';
    } else {
      const { url, problem } = checkPublicUrl(d.endpoint_url);
      if (!url) { status = 0; text = ''; failure = `endpoint_url ${problem}`; }
      else {
        const r = await safeFetch(url, { method: 'POST', headers, body: e.set }, 2048);
        status = r.status; text = r.text; failure = r.error;
      }
    }

    const snippet = text.slice(0, 300);
    // What the Receiver answered, kept with the log entry so the playground can show it.
    let parsed: unknown = snippet || null;
    try { if (text) parsed = JSON.parse(text); } catch {}
    const response = status ? { status, body: parsed } : undefined;
    let ok = false, retry = false, detail: string;
    if (status === 202) { ok = true; detail = `202 Accepted from ${d.endpoint_url}`; }
    else if (status >= 200 && status < 300) { ok = true; detail = `${status} from ${d.endpoint_url} (RFC 8935 expects 202 Accepted)`; }
    else if (status === 400) { detail = `400 from Receiver: ${snippet || '(no body)'}`; }
    else if (status === 401 || status === 403) { detail = `${status} from Receiver — check delivery.authorization_header. ${snippet}`; }
    else { retry = true; detail = failure ? `could not connect: ${failure}` : `${status} from Receiver ${snippet}`; }

    if (retry && e.attempts <= RETRY_DELAYS.length) {
      e.nextAt = now() + RETRY_DELAYS[e.attempts - 1];
      const q = (await this.queue(id)).filter((x) => x.jti !== e.jti);
      await this.ctx.storage.put(`queue:${id}`, q);
      await this.enqueue(id, e);
      detail += `; retry ${e.attempts} of ${RETRY_DELAYS.length} in ${RETRY_DELAYS[e.attempts - 1]}s`;
    } else {
      if (retry) { retry = false; detail += '; giving up'; }
      const q = await this.queue(id);
      if (q.some((x) => x.jti === e.jti)) await this.ctx.storage.put(`queue:${id}`, q.filter((x) => x.jti !== e.jti));
    }
    await this.log(id, { action: ok ? 'pushed' : retry ? 'push failed, will retry' : 'push failed', ok, jti: e.jti, event: e.type, detail, set: e.set, response });
    return { ok, retry, detail };
  }

  /** Pushes everything ready on a push stream, oldest first. */
  private async flush(s: Stream) {
    for (const e of await this.queue(s.config.stream_id)) {
      if (e.held || e.nextAt > now()) continue;
      const fresh = await this.stream(s.config.stream_id);
      if (!fresh || fresh.status !== 'enabled' || fresh.config.delivery.method !== PUSH) return;
      await this.push(fresh, e);
    }
  }

  // ── Alarm: push retries and inactivity cleanup ───────────────────────

  private async schedule() {
    let next = Infinity;
    for (const s of await this.streams()) {
      next = Math.min(next, s.lastActivity + s.config.inactivity_timeout);
      if (s.config.delivery.method === PUSH && s.status === 'enabled')
        for (const e of await this.queue(s.config.stream_id)) if (!e.held && e.nextAt) next = Math.min(next, e.nextAt);
    }
    if (next === Infinity) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(Math.max(next * 1000, Date.now() + 1000));
  }

  async alarm() {
    for (const s of await this.streams()) {
      const id = s.config.stream_id;
      if (now() >= s.lastActivity + s.config.inactivity_timeout) {
        // SSF allows deleting a stream after inactivity_timeout; only pausing or disabling needs a stream-updated event.
        await this.ctx.storage.delete([`stream:${id}`, `queue:${id}`, `log:${id}`]);
        continue;
      }
      if (s.status === 'enabled' && s.config.delivery.method === PUSH) await this.flush(s);
    }
    if (!(await this.streams()).length) { await this.ctx.storage.deleteAll(); return; }
    await this.schedule();
  }
}

function isReply(v: Stream | Reply): v is Reply {
  return typeof (v as Reply).status === 'number';
}

function delivered(cfg: Config): string[] {
  if (!cfg.events_requested) return [...cfg.events_supported];
  return cfg.events_supported.filter((u) => cfg.events_requested!.includes(u));
}

const statusOf = (s: Stream) => ({ stream_id: s.config.stream_id, status: s.status, ...(s.reason ? { reason: s.reason } : {}) });

/** If endpoint_url is this site's own sample Receiver, its id; we call it directly, not over the network. */
export function internalReceiver(endpoint: string, issuer: string): string | null {
  try {
    const u = new URL(endpoint);
    const m = u.pathname.match(/^\/ssf\/push\/([0-9a-f]{32})$/);
    return u.origin === new URL(issuer).origin && m && !u.search ? m[1] : null;
  } catch {
    return null;
  }
}
