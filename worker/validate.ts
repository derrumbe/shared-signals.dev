// Checks a Security Event Token against RFC 8417, SSF 1.0 and the CAEP Interoperability Profile.
// Used by the sample Receiver (on every push) and by the SET inspector.

import { EVENTS, uri, type EventType } from '../src/data/events';
import { decodeJws, type Decoded, type Jwk, verifyRs256 } from './jose';

export type Level = 'pass' | 'warn' | 'fail';
export type Check = { id: string; level: Level; message: string };
export type Result = {
  verdict: Level;
  checks: Check[];
  header?: Record<string, any>;
  payload?: Record<string, any>;
  eventType?: string;
  /** RFC 8935 §2.4 error code a Receiver would return, when verdict is fail. */
  err?: string;
};

/** Resolves the signing key for an issuer. Returns the key, or a message saying why not. */
export type KeyResolver = (iss: string, kid: string | undefined) => Promise<{ key?: Jwk; problem?: string }>;

export type Expect = { issuer?: string; audience?: string; contentType?: string | null };

const byUri = new Map<string, EventType>(EVENTS.map((e) => [uri(e), e]));
const SSF_VERIFICATION = 'https://schemas.openid.net/secevent/ssf/event-type/verification';
const SSF_STREAM_UPDATED = 'https://schemas.openid.net/secevent/ssf/event-type/stream-updated';
const SUBJECT_FORMATS = ['account', 'email', 'iss_sub', 'opaque', 'phone_number', 'did', 'uri', 'aliases', 'complex', 'jwt_id', 'saml_assertion_id', 'ip-addresses'];

export async function validateSet(token: string, resolveKey: KeyResolver, expect: Expect = {}): Promise<Result> {
  const checks: Check[] = [];
  let err: string | undefined;
  const add = (id: string, level: Level, message: string, code = 'invalid_request') => {
    checks.push({ id, level, message });
    if (level === 'fail') err ??= code;
  };
  const done = (extra: Partial<Result> = {}): Result => ({
    verdict: checks.some((c) => c.level === 'fail') ? 'fail' : checks.some((c) => c.level === 'warn') ? 'warn' : 'pass',
    checks, err, ...extra,
  });

  if (expect.contentType !== undefined) {
    const ct = (expect.contentType ?? '').split(';')[0].trim().toLowerCase();
    if (ct === 'application/secevent+jwt') add('content-type', 'pass', 'Content-Type is application/secevent+jwt.');
    else add('content-type', 'fail', `Content-Type must be application/secevent+jwt (RFC 8935 §2), got ${ct ? `"${ct}"` : 'none'}.`);
  }

  let d: Decoded;
  try {
    d = decodeJws(token);
    add('format', 'pass', 'Compact JWS with a JSON header and payload.');
  } catch (e: any) {
    add('format', 'fail', `Not a readable SET: ${e.message}.`);
    return done();
  }
  const { header: h, payload: p } = d;

  // ── Header ────────────────────────────────────────────────────────────
  const typ = String(h.typ ?? '').toLowerCase();
  if (typ === 'secevent+jwt' || typ === 'application/secevent+jwt') add('typ', 'pass', `typ is "${h.typ}".`);
  else add('typ', 'fail', `typ must be "secevent+jwt" (SSF §4.1.1), got ${h.typ === undefined ? 'nothing' : JSON.stringify(h.typ)}.`);

  if (h.alg === 'RS256') add('alg', 'pass', 'Signed with RS256.');
  else if (h.alg === 'none' || !h.alg) add('alg', 'fail', 'SETs must be signed; alg is "none" or missing.', 'invalid_key');
  else add('alg', 'fail', `The CAEP Interoperability Profile requires RS256; got "${h.alg}".`, 'invalid_key');

  if (typeof h.kid === 'string' && h.kid) add('kid', 'pass', `kid is "${h.kid}".`);
  else add('kid', 'warn', 'No kid in the header, so the Receiver has to try every key in the JWKS.');

  // ── Claims ────────────────────────────────────────────────────────────
  if (typeof p.iss !== 'string' || !p.iss) add('iss', 'fail', 'iss is missing.', 'invalid_issuer');
  else if (expect.issuer && p.iss !== expect.issuer) add('iss', 'fail', `iss is "${p.iss}" but this Receiver expects "${expect.issuer}".`, 'invalid_issuer');
  else add('iss', 'pass', `iss is "${p.iss}"${expect.issuer ? ', as expected' : ''}.`);

  const auds = Array.isArray(p.aud) ? p.aud : p.aud === undefined ? [] : [p.aud];
  if (!auds.length) add('aud', 'fail', 'aud is missing.', 'invalid_audience');
  else if (expect.audience && !auds.includes(expect.audience)) add('aud', 'fail', `aud is ${JSON.stringify(p.aud)} but this Receiver expects "${expect.audience}".`, 'invalid_audience');
  else add('aud', 'pass', `aud is ${JSON.stringify(p.aud)}${expect.audience ? ', as expected' : ''}.`);

  const now = Date.now() / 1000;
  if (typeof p.iat !== 'number') add('iat', 'fail', 'iat is missing or not a number.');
  else if (p.iat > now + 300) add('iat', 'warn', `iat is ${Math.round(p.iat - now)} seconds in the future; check the Transmitter's clock.`);
  else add('iat', 'pass', `iat is ${new Date(p.iat * 1000).toISOString()}.`);

  if (typeof p.jti === 'string' && p.jti) add('jti', 'pass', `jti is "${p.jti}".`);
  else add('jti', 'fail', 'jti is missing; Receivers need it to acknowledge and de-duplicate SETs.');

  if ('sub' in p) add('sub', 'fail', 'The "sub" claim must not appear in an SSF SET (SSF §4.1.2); use sub_id.');
  if ('exp' in p) add('exp', 'fail', 'The "exp" claim must not appear in an SSF SET (SSF §4.1.7).');
  if (!('sub' in p) && !('exp' in p)) add('no-sub-exp', 'pass', 'No "sub" or "exp" claims, so the SET cannot be mistaken for another kind of JWT.');

  if (p.txn === undefined) add('txn', 'warn', 'No txn claim; Transmitters SHOULD set one (SSF §4.1.9).');

  // ── Event ─────────────────────────────────────────────────────────────
  const events = p.events;
  let eventType: string | undefined;
  if (!events || typeof events !== 'object' || Array.isArray(events)) {
    add('events', 'fail', 'The events claim is missing or not an object.');
  } else {
    const types = Object.keys(events);
    if (types.length === 1) add('events', 'pass', 'Exactly one event in the events claim.');
    else add('events', 'fail', `The CAEP Interoperability Profile requires exactly one event per SET; found ${types.length}.`);
    eventType = types[0];
    if (eventType) checkEvent(eventType, events[eventType], p, add);
  }

  // ── Signature last: it needs the network, and a clear claims report is useful even if it fails.
  if (h.alg === 'RS256' && typeof p.iss === 'string') {
    const { key, problem } = await resolveKey(p.iss, h.kid);
    if (!key) add('signature', 'fail', `Could not get the signing key: ${problem}.`, 'invalid_key');
    else {
      let ok = false;
      try { ok = await verifyRs256(d, key); } catch {}
      if (ok) add('signature', 'pass', `Signature verified with key "${key.kid ?? '(no kid)'}".`);
      else add('signature', 'fail', `Signature does not verify with key "${key.kid ?? '(no kid)'}" from the issuer's JWKS.`, 'invalid_key');
    }
  }

  return done({ header: h, payload: p, eventType });
}

function checkEvent(type: string, body: any, p: Record<string, any>, add: (id: string, l: Level, m: string, c?: string) => void) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    add('event-body', 'fail', 'The event value must be a JSON object.');
    return;
  }
  const known = byUri.get(type);
  if (!known) add('event-type', 'warn', `"${type}" is not a CAEP, RISC or SSF event type this tool knows.`);
  else add('event-type', known.deprecated ? 'warn' : 'pass', `${known.spec.toUpperCase()} ${known.name}${known.deprecated ? ` — ${known.deprecated}` : ''}.`);

  const subject = p.sub_id ?? body.subject;
  if (p.sub_id === undefined && body.subject !== undefined) add('sub_id', 'warn', 'The subject is inside the event ("subject"), the pre-1.0 style; SSF 1.0 uses a top-level sub_id claim.');
  else if (p.sub_id === undefined) add('sub_id', 'fail', 'No sub_id claim identifying the subject.');
  if (subject !== undefined) {
    if (!subject || typeof subject !== 'object' || typeof subject.format !== 'string') add('subject-format', 'fail', 'The subject must be an object with a "format" member.');
    else if (!SUBJECT_FORMATS.includes(subject.format)) add('subject-format', 'warn', `Unrecognised subject format "${subject.format}".`);
    else add('subject-format', 'pass', `Subject format is "${subject.format}".`);
  }

  if (type === SSF_VERIFICATION || type === SSF_STREAM_UPDATED) {
    if (subject?.format !== 'opaque' || typeof subject?.id !== 'string') add('stream-subject', 'fail', 'Verification and Stream Updated events must have an opaque sub_id whose id is the stream_id.');
    if (type === SSF_STREAM_UPDATED && !['enabled', 'paused', 'disabled'].includes(body.status)) add('status', 'fail', 'stream-updated needs status "enabled", "paused" or "disabled".');
    return;
  }

  // CAEP Interoperability Profile §2.5: CAEP events use email or iss_sub; opaque is for Verification only.
  if (known?.spec === 'caep' && subject?.format && !['email', 'iss_sub'].includes(subject.format))
    add('iop-subject', 'warn', `The CAEP Interoperability Profile (§2.5) allows only "email" and "iss_sub" subjects on CAEP events ("opaque" is for the Verification event only); this one is "${subject.format}".`);
  else if (known?.spec === 'caep' && subject?.format) add('iop-subject', 'pass', `"${subject.format}" is a subject format the CAEP Interoperability Profile allows.`);

  if (!known) return;
  const missing = known.claims.filter((c) => c.req === 'REQUIRED' && !c.name.includes('/') && body[c.name] === undefined).map((c) => c.name);
  if (missing.length) add('required-claims', 'fail', `Missing required event claim${missing.length > 1 ? 's' : ''}: ${missing.join(', ')}.`);
  else if (known.claims.some((c) => c.req === 'REQUIRED')) add('required-claims', 'pass', 'All required event claims present.');

  if (known.spec === 'caep') {
    const ra = body.reason_admin;
    if (ra && typeof ra === 'object' && !Array.isArray(ra) && Object.keys(ra).length) add('reason_admin', 'pass', 'reason_admin is a non-empty object, as the Interoperability Profile requires.');
    else add('reason_admin', 'warn', 'The CAEP Interoperability Profile requires a non-empty reason_admin object, e.g. {"en": "Policy violation"}.');
    if (body.event_timestamp !== undefined && typeof body.event_timestamp !== 'number') add('event_timestamp', 'fail', 'event_timestamp must be a NumericDate (seconds since the epoch).');
  }
}
