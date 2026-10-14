// The sample SSF Receiver: a push endpoint (RFC 8935) that anyone can point a Transmitter at.
// Each receiver is a Durable Object named by a random id. The id is the capability for viewing
// what arrived; pushing additionally needs the receiver's Authorization header value.

import { DurableObject } from 'cloudflare:workers';
import { randomId } from './jose';
import { error, reply, type Reply } from './http';
import { validateSet, type Result } from './validate';
import { discoveringResolver } from './keysource';
import type { Env } from './env';

const MAX_EVENTS = 50;
const PUSH_LIMIT_PER_MINUTE = 60;
const IDLE_EXPIRY_MS = 7 * 24 * 3600 * 1000;

type Config = { id: string; origin: string; authorization: string; issuer?: string; audience?: string; created: number; lastActivity: number };
export type Received = { at: number; status: number; response: unknown; verdict: Result['verdict']; checks: Result['checks']; header?: unknown; payload?: unknown; event_type?: string; raw: string };

export class Receiver extends DurableObject<Env> {
  private window = { minute: 0, count: 0 };

  private config() { return this.ctx.storage.get<Config>('config'); }

  private async touch(cfg: Config) {
    cfg.lastActivity = Date.now();
    await this.ctx.storage.put('config', cfg);
    await this.ctx.storage.setAlarm(cfg.lastActivity + IDLE_EXPIRY_MS);
  }

  async init(id: string, origin: string, opts: { issuer?: string; audience?: string }) {
    const cfg: Config = { id, origin, authorization: `Bearer ${randomId(24)}`, created: Date.now(), lastActivity: Date.now(), ...clean(opts) };
    await this.touch(cfg);
    return describe(cfg);
  }

  async update(opts: { issuer?: string; audience?: string }): Promise<Reply> {
    const cfg = await this.config();
    if (!cfg) return error(404, 'not_found', 'No such receiver (it may have expired after 7 days without use).');
    delete cfg.issuer; delete cfg.audience;
    Object.assign(cfg, clean(opts));
    await this.touch(cfg);
    return reply(200, describe(cfg));
  }

  async view(): Promise<Reply> {
    const cfg = await this.config();
    if (!cfg) return error(404, 'not_found', 'No such receiver (it may have expired after 7 days without use).');
    return reply(200, { ...describe(cfg), events: (await this.ctx.storage.get<Received[]>('events')) ?? [] });
  }

  async clear(): Promise<Reply> {
    await this.ctx.storage.delete('events');
    return reply(204);
  }

  /** Handles one RFC 8935 push. Returns the HTTP response the Transmitter gets. */
  async receive(contentType: string | null, authorization: string | null, body: string): Promise<Reply> {
    const cfg = await this.config();
    if (!cfg) return reply(404, { err: 'invalid_request', description: 'No such receiver at this URL (it may have expired after 7 days without use).' });

    const minute = Math.floor(Date.now() / 60000);
    if (this.window.minute !== minute) this.window = { minute, count: 0 };
    if (++this.window.count > PUSH_LIMIT_PER_MINUTE) return reply(429, { err: 'invalid_request', description: `Rate limited: at most ${PUSH_LIMIT_PER_MINUTE} SETs a minute per receiver.` }, { 'retry-after': '60' });

    let r: Reply, result: Result;
    if (authorization !== cfg.authorization) {
      result = { verdict: 'fail', checks: [{ id: 'authorization', level: 'fail', message: authorization ? 'The Authorization header does not match this receiver’s. Set delivery.authorization_header to the value shown on the receiver page.' : 'No Authorization header. Set delivery.authorization_header in your stream to the value shown on the receiver page.' }] };
      r = reply(401, { err: 'authentication_failed', description: 'Missing or wrong Authorization header.' }, { 'www-authenticate': 'Bearer realm="shared-signals.dev receiver"' });
    } else {
      result = await validateSet(body, discoveringResolver(this.env, cfg.origin), { issuer: cfg.issuer, audience: cfg.audience, contentType });
      result.checks.unshift({ id: 'authorization', level: 'pass', message: 'Authorization header matches.' });
      if (result.verdict === 'fail') {
        const first = result.checks.find((c) => c.level === 'fail')!;
        r = reply(400, { err: result.err ?? 'invalid_request', description: first.message });
      } else {
        r = reply(202);
      }
    }

    const events = (await this.ctx.storage.get<Received[]>('events')) ?? [];
    events.unshift({
      at: Date.now(), status: r.status, response: r.body ?? null, verdict: result.verdict, checks: result.checks,
      header: result.header, payload: result.payload, event_type: result.eventType, raw: body.slice(0, 8192),
    });
    await this.ctx.storage.put('events', events.slice(0, MAX_EVENTS));
    await this.touch(cfg);
    return r;
  }

  async alarm() {
    const cfg = await this.config();
    if (cfg && Date.now() < cfg.lastActivity + IDLE_EXPIRY_MS) await this.ctx.storage.setAlarm(cfg.lastActivity + IDLE_EXPIRY_MS);
    else await this.ctx.storage.deleteAll();
  }
}

function clean(opts: { issuer?: unknown; audience?: unknown }) {
  const out: { issuer?: string; audience?: string } = {};
  if (typeof opts.issuer === 'string' && opts.issuer.trim()) out.issuer = opts.issuer.trim().slice(0, 512);
  if (typeof opts.audience === 'string' && opts.audience.trim()) out.audience = opts.audience.trim().slice(0, 512);
  return out;
}

function describe(cfg: Config) {
  return {
    receiver_id: cfg.id,
    endpoint_url: `${cfg.origin}/ssf/push/${cfg.id}`,
    authorization_header: cfg.authorization,
    expected_issuer: cfg.issuer ?? null,
    expected_audience: cfg.audience ?? null,
    view_url: `${cfg.origin}/playground/receiver/#${cfg.id}`,
    expires: new Date(cfg.lastActivity + IDLE_EXPIRY_MS).toISOString(),
  };
}
