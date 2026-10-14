// Credentials, access token and stream list for the sample Transmitter, shared by the playground
// pages. Pairs with components/Credentials.astro.

import { api, badge, copyButtons, errorText, esc, randomHex, store } from './playground';

type Creds = { client_id: string; client_secret: string };
const creds = store<Creds>('ssf.transmitter.creds');
const tokenStore = store<{ token: string; exp: number; key: string }>('ssf.transmitter.token');
const input = (id: string) => document.getElementById(id) as HTMLInputElement;

export const currentCreds = (): Creds => ({ client_id: input('client_id').value.trim(), client_secret: input('client_secret').value });
const credKey = () => `${currentCreds().client_id}\n${currentCreds().client_secret}`;
const newCreds = (): Creds => ({ client_id: `playground-${randomHex(4)}`, client_secret: randomHex(24) });

/** A valid access token, fetching a new one when needed. Errors are shown in the credentials panel. */
export async function token(force = false): Promise<string | null> {
  const t = tokenStore.get();
  if (!force && t && t.key === credKey() && t.exp > Date.now() / 1000 + 60) return t.token;
  const c = currentCreds();
  const out = document.getElementById('token-out')!;
  const r = await api('POST', '/ssf/oauth/token', { form: { grant_type: 'client_credentials', ...c } });
  if (r.status !== 200) { out.innerHTML = `<p class="error">${esc(errorText(r))}</p>`; return null; }
  creds.set(c);
  tokenStore.set({ token: r.json.access_token, exp: Date.now() / 1000 + r.json.expires_in, key: credKey() });
  out.innerHTML = `<p class="muted" style="font-size:.88rem">Token for <code>${esc(c.client_id)}</code>, scope <code>${esc(r.json.scope)}</code>, valid ${Math.round(r.json.expires_in / 60)} minutes.</p>
    <span class="copy"><input type="text" id="token-val" readonly value="${esc(r.json.access_token)}" /><button class="btn small" data-copy="token-val">Copy</button></span>`;
  copyButtons(out);
  return r.json.access_token;
}

/** Loads stored credentials into the panel and wires its buttons. onChange runs after a new token or sandbox. */
export function initCreds(onChange: () => void) {
  const load = () => {
    const c = creds.get() ?? newCreds();
    creds.set(c);
    input('client_id').value = c.client_id;
    input('client_secret').value = c.client_secret;
  };
  document.getElementById('token-btn')!.onclick = () => token(true).then((t) => t && onChange());
  document.getElementById('new-creds')!.onclick = () => {
    if (!confirm('Start a new sandbox? Streams under the current credentials stay where they are, but this page will forget them.')) return;
    creds.set(newCreds()); tokenStore.set(null); load();
    document.getElementById('token-out')!.innerHTML = '';
    onChange();
  };
  load();
}

export type Stream = { stream_id: string; description?: string; delivery: { method: string; endpoint_url?: string }; events_delivered: string[]; status: string };

/** The caller's streams with their current status, or an error message. */
export async function loadStreams(): Promise<Stream[] | string> {
  const t = await token(); if (!t) return 'Get an access token first.';
  const r = await api('GET', '/ssf/stream', { token: t });
  if (r.status !== 200) return errorText(r);
  const statuses = await Promise.all(r.json.map((s: Stream) => api('GET', `/ssf/status?stream_id=${s.stream_id}`, { token: t })));
  return r.json.map((s: Stream, i: number) => ({ ...s, status: statuses[i].json?.status ?? '?' }));
}

export const isPush = (s: Stream) => s.delivery.method === 'urn:ietf:rfc:8935';
export const receiverIdOf = (s: Stream) => s.delivery.endpoint_url?.match(/\/ssf\/push\/([0-9a-f]{32})$/)?.[1];

/** Description first (what people recognise), stream_id underneath. */
export const streamCell = (s: Stream) =>
  `<strong>${esc(s.description || 'Untitled stream')}</strong><br><code style="font-size:.72rem">${esc(s.stream_id)}</code>`;

export const deliveryCell = (s: Stream, here?: string) => {
  const rid = receiverIdOf(s);
  const where = isPush(s)
    ? `push → ${rid ? (rid === here ? 'this Receiver' : `<a href="/playground/receiver/#${rid}">sample Receiver</a>`) : esc(s.delivery.endpoint_url)}`
    : 'poll';
  return `<span style="font-size:.85rem">${where}<br><span class="muted">${s.events_delivered.length} event types</span></span>`;
};

export const statusBadge = (st: string) => badge(st === 'enabled' ? 'pass' : st === 'paused' ? 'warn' : 'fail', st);
