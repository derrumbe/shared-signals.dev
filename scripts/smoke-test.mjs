// End-to-end check of the sample Transmitter and Receiver.
//   npx wrangler dev            (in another terminal)
//   node scripts/smoke-test.mjs [base-url]      default http://127.0.0.1:8787
// Exits non-zero on the first failure.

const BASE = process.argv[2] ?? 'http://127.0.0.1:8787';
let failures = 0;
const ok = (cond, msg, extra) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) { failures++; if (extra !== undefined) console.log('     ', JSON.stringify(extra).slice(0, 600)); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function call(method, path, { token, body, form, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  let b;
  if (form) { h['content-type'] = 'application/x-www-form-urlencoded'; b = new URLSearchParams(form).toString(); }
  else if (body !== undefined) { h['content-type'] = 'application/json'; b = typeof body === 'string' ? body : JSON.stringify(body); }
  const res = await fetch(BASE + path, { method, headers: h, body: b });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch {}
  return { status: res.status, headers: res.headers, json, text };
}

const meta = await call('GET', '/.well-known/ssf-configuration');
ok(meta.status === 200 && meta.json.issuer === BASE && meta.json.spec_version === '1_0', 'discovery metadata', meta.json);
ok(meta.json.authorization_schemes?.[0]?.spec_urn === 'urn:ietf:rfc:6749', 'authorization_schemes has OAuth');
const jwks = await call('GET', '/jwks.json');
ok(jwks.json?.keys?.[0]?.kty === 'RSA' && jwks.json.keys[0].kid && !jwks.json.keys[0].d, 'JWKS has a public RSA key only');

// OAuth
const secret = 'smoke-test-secret-' + Math.random().toString(36).slice(2);
const tok = await call('POST', '/ssf/oauth/token', { form: { grant_type: 'client_credentials', client_id: 'smoke-test', client_secret: secret } });
ok(tok.status === 200 && tok.json.expires_in <= 3600 && tok.json.scope === 'ssf.read ssf.manage', 'token issued', tok.json);
const token = tok.json.access_token;
const readTok = (await call('POST', '/ssf/oauth/token', { form: { grant_type: 'client_credentials', client_id: 'smoke-test', client_secret: secret, scope: 'ssf.read' } })).json.access_token;
const otherTok = (await call('POST', '/ssf/oauth/token', { form: { grant_type: 'client_credentials', client_id: 'smoke-test', client_secret: secret + 'x' } })).json.access_token;
ok((await call('GET', '/ssf/stream')).status === 401, 'no token → 401');
ok((await call('GET', `/ssf/stream?access_token=${token}`)).status === 400, 'token in query string rejected');
ok((await call('POST', '/ssf/stream', { token: readTok, body: {} })).status === 403, 'ssf.read cannot create a stream');

// Receiver
const rcv = await call('POST', '/api/receivers', { body: { audience: 'smoke-test' } });
ok(rcv.status === 201 && rcv.json.endpoint_url.endsWith(rcv.json.receiver_id), 'receiver created', rcv.json);

// Push stream to the sample receiver
const created = await call('POST', '/ssf/stream', { token, body: {
  delivery: { method: 'urn:ietf:rfc:8935', endpoint_url: rcv.json.endpoint_url, authorization_header: rcv.json.authorization_header },
  events_requested: ['https://schemas.openid.net/secevent/caep/event-type/session-revoked', 'https://schemas.openid.net/secevent/caep/event-type/credential-change', 'urn:example:unknown'],
  description: 'smoke test push',
} });
ok(created.status === 201 && created.json.events_delivered.length === 2 && created.json.aud === 'smoke-test', 'push stream created', created.json);
const sid = created.json.stream_id;
ok((await call('GET', `/ssf/stream?stream_id=${sid}`, { token: otherTok })).status === 404, 'other tenant cannot see the stream');
const list = await call('GET', '/ssf/stream', { token: readTok });
ok(Array.isArray(list.json) && list.json.some((s) => s.stream_id === sid), 'list streams with ssf.read');
ok((await call('GET', `/ssf/status?stream_id=${sid}`, { token })).json?.status === 'enabled', 'status enabled');

// Verification → arrives at receiver
ok((await call('POST', '/ssf/verify', { token, body: { stream_id: sid, state: 'abc123' } })).status === 204, 'verify → 204');
ok((await call('POST', '/ssf/verify', { token, body: { stream_id: sid } })).status === 429, 'second verify within min_verification_interval → 429');
await sleep(1000);
let view = await call('GET', `/api/receivers/${rcv.json.receiver_id}`);
const ver = view.json.events.find((e) => e.event_type?.endsWith('/verification'));
ok(ver && ver.status === 202 && ver.payload.events[ver.event_type].state === 'abc123' && ver.payload.sub_id.id === sid, 'verification SET received and valid', ver ?? view.json);

// Fire a CAEP event
const fired = await call('POST', '/api/events', { token, body: { stream_id: sid, event_type: 'session-revoked', sub_id: { format: 'email', email: 'alice@example.com' }, event: {} } });
ok(fired.status === 200 && fired.json.results[0].outcome === 'delivered', 'session-revoked delivered', fired.json);
view = await call('GET', `/api/receivers/${rcv.json.receiver_id}`);
ok(view.json.events[0].verdict === 'pass', 'receiver validated SET with no warnings', view.json.events[0].checks.filter((c) => c.level !== 'pass'));
const notDelivered = await call('POST', '/api/events', { token, body: { stream_id: sid, event_type: 'account-disabled', sub_id: { format: 'email', email: 'alice@example.com' } } });
ok(notDelivered.json.results[0].outcome === 'skipped', 'event not in events_delivered is skipped');

// Subjects
ok((await call('POST', '/ssf/subjects:remove', { token, body: { stream_id: sid, subject: { format: 'email', email: 'bob@example.com' } } })).status === 204, 'subjects:remove → 204');
const sup = await call('POST', '/api/events', { token, body: { stream_id: sid, event_type: 'session-revoked', sub_id: { format: 'email', email: 'bob@example.com' } } });
ok(sup.json.results[0].outcome === 'skipped', 'events about removed subject suppressed');
ok((await call('POST', '/ssf/subjects:add', { token, body: { stream_id: sid, subject: { format: 'email', email: 'bob@example.com' }, verified: true } })).status === 200, 'subjects:add → 200');

// Status: pause holds, enable flushes
await call('POST', '/ssf/status', { token, body: { stream_id: sid, status: 'paused', reason: 'test' } });
const held = await call('POST', '/api/events', { token, body: { stream_id: sid, event_type: 'session-revoked', sub_id: { format: 'email', email: 'bob@example.com' } } });
ok(held.json.results[0].outcome === 'held', 'paused stream holds events', held.json);
await call('POST', '/ssf/status', { token, body: { stream_id: sid, status: 'enabled' } });
await sleep(1000);
const lg = await call('GET', `/api/streams/log?stream_id=${sid}`, { token });
ok(lg.json.queued.length === 0 && lg.json.log.some((l) => l.jti === held.json.results[0].jti && l.action === 'pushed'), 'held event pushed after enabling', lg.json.queued);

// Transmitter-initiated status → stream-updated
const adm = await call('POST', '/api/streams/status', { token, body: { stream_id: sid, status: 'paused', reason: 'maintenance' } });
ok(adm.json.stream_updated?.outcome === 'delivered', 'stream-updated sent before pausing', adm.json);
await call('POST', '/api/streams/status', { token, body: { stream_id: sid, status: 'enabled' } });

// PATCH / PUT
ok((await call('PATCH', '/ssf/stream', { token, body: { stream_id: sid, description: 'renamed' } })).json?.description === 'renamed', 'PATCH description');
ok((await call('PATCH', '/ssf/stream', { token, body: { stream_id: sid, aud: 'someone-else' } })).status === 400, 'PATCH mismatched aud → 400');
const bad = await call('PATCH', '/ssf/stream', { token, body: { stream_id: sid, delivery: { method: 'urn:ietf:rfc:8935', endpoint_url: 'https://169.254.169.254/latest' } } });
ok(bad.status === 400, 'SSRF: IP endpoint_url rejected', bad.json);
ok((await call('PATCH', '/ssf/stream', { token, body: { stream_id: sid, delivery: { method: 'urn:ietf:rfc:8935', endpoint_url: 'http://receiver.example.org/x' } } })).status === 400, 'SSRF: http endpoint_url rejected');

// Wrong auth header at receiver
const wrong = await call('POST', `/ssf/push/${rcv.json.receiver_id}`, { body: 'x.y.z', headers: { 'content-type': 'application/secevent+jwt', authorization: 'Bearer nope' } });
ok(wrong.status === 401 && wrong.json.err === 'authentication_failed', 'receiver rejects wrong auth');

// Poll stream
const pc = await call('POST', '/ssf/stream', { token, body: {} });
ok(pc.status === 201 && pc.json.delivery.method === 'urn:ietf:rfc:8936' && pc.json.delivery.endpoint_url.endsWith(`/ssf/poll/${pc.json.stream_id}`), 'no delivery → poll stream', pc.json);
const psid = pc.json.stream_id;
await call('POST', '/api/events', { token, body: { stream_id: psid, event_type: 'credential-change', sub_id: { format: 'iss_sub', iss: 'https://idp.example.com/', sub: '42' }, event: { credential_type: 'password', change_type: 'update' } } });
const polled = await call('POST', `/ssf/poll/${psid}`, { token: readTok, body: { maxEvents: 5, returnImmediately: true } });
const jtis = Object.keys(polled.json?.sets ?? {});
ok(polled.status === 200 && jtis.length === 1 && polled.json.moreAvailable === false, 'poll returns the SET', polled.json);
const insp = await call('POST', '/api/inspect', { body: { set: polled.json.sets[jtis[0]], audience: 'smoke-test' } });
ok(insp.json?.verdict === 'pass', 'inspector passes our own SET', insp.json?.checks?.filter((c) => c.level !== 'pass'));
const insp2 = await call('POST', '/api/inspect', { body: { set: polled.json.sets[jtis[0]], issuer: 'https://wrong.example.com' } });
ok(insp2.json?.verdict === 'fail' && insp2.json.err === 'invalid_issuer', 'inspector flags wrong issuer');
const acked = await call('POST', `/ssf/poll/${psid}`, { token, body: { ack: jtis, maxEvents: 5 } });
ok(Object.keys(acked.json.sets).length === 0, 'acked SET is not returned again');

// SCIM events (RFC 9967) go out like any other, with a "scim" subject
const scimSub = { format: 'scim', uri: '/Users/2b2f880af6674ac284bae9381673d462', externalId: 'jdoe' };
const scim = await call('POST', '/api/events', { token, body: { stream_id: psid, event_type: 'prov:patch:notice', sub_id: scimSub, event: { attributes: ['emails'] } } });
ok(scim.status === 200 && scim.json.event_type === 'urn:ietf:params:scim:event:prov:patch:notice' && scim.json.results[0]?.outcome === 'queued', 'fire SCIM event', scim.json);
const scimPolled = await call('POST', `/ssf/poll/${psid}`, { token: readTok, body: { maxEvents: 5, returnImmediately: true } });
const scimSet = Object.values(scimPolled.json?.sets ?? {})[0];
const scimInsp = await call('POST', '/api/inspect', { body: { set: scimSet, audience: 'smoke-test' } });
ok(scimInsp.json?.verdict === 'pass', 'inspector passes our SCIM SET', scimInsp.json?.checks?.filter((c) => c.level !== 'pass'));

// Delete + revoke
ok((await call('DELETE', `/ssf/stream?stream_id=${psid}`, { token })).status === 204, 'delete stream');
ok((await call('GET', `/ssf/stream?stream_id=${psid}`, { token })).status === 404, 'deleted stream is gone');
await call('DELETE', `/ssf/stream?stream_id=${sid}`, { token });
await call('POST', '/ssf/oauth/revoke', { form: { token } });
ok((await call('GET', '/ssf/stream', { token })).status === 401, 'revoked token rejected');

console.log(failures ? `\n${failures} failure(s)` : '\nall passed');
process.exit(failures ? 1 : 0);
