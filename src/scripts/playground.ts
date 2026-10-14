// Browser helpers shared by the playground pages.

export type ApiResult = { status: number; json: any; text: string };

export async function api(method: string, path: string, opts: { token?: string; body?: unknown; form?: Record<string, string> } = {}): Promise<ApiResult> {
  const headers: Record<string, string> = {};
  let body: string | undefined;
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  if (opts.form) { headers['content-type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(opts.form).toString(); }
  else if (opts.body !== undefined) { headers['content-type'] = 'application/json'; body = JSON.stringify(opts.body); }
  const res = await fetch(path, { method, headers, body });
  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch {}
  return { status: res.status, json, text };
}

export const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

export const pretty = (v: unknown) => `<pre><code>${esc(JSON.stringify(v, null, 2))}</code></pre>`;

export function store<T>(key: string): { get(): T | null; set(v: T | null): void } {
  return {
    get() { try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : null; } catch { return null; } },
    set(v) { try { v === null ? localStorage.removeItem(key) : localStorage.setItem(key, JSON.stringify(v)); } catch {} },
  };
}

export const randomHex = (bytes: number) => [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, '0')).join('');

export function decodeJwt(token: string): { header: any; payload: any } | null {
  try {
    const [h, p] = token.split('.').slice(0, 2).map((part) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(part.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)))));
    return { header: h, payload: p };
  } catch { return null; }
}

export type Check = { id: string; level: 'pass' | 'warn' | 'fail'; message: string };

export const badge = (level: string, text = level) => `<span class="badge ${esc(level)}">${esc(text)}</span>`;

/** The check list folded into a tray whose summary gives the counts, e.g. "1 failed · 15 passed". */
export function checksTray(checks: Check[]): string {
  const n = (l: string) => checks.filter((c) => c.level === l).length;
  const plural = (k: number, one: string, many: string) => `${k} ${k === 1 ? one : many}`;
  const parts = [n('fail') && plural(n('fail'), 'failed', 'failed'), n('warn') && plural(n('warn'), 'warning', 'warnings'), n('pass') && `${n('pass')} passed`].filter(Boolean);
  return `<details class="tray"><summary>Checks <span class="muted">— ${parts.join(' · ')}</span></summary>${renderChecks(checks)}</details>`;
}

export function renderChecks(checks: Check[]): string {
  return `<ul class="checks">${checks.map((c) => `<li>${badge(c.level)}<span>${esc(c.message)}</span></li>`).join('')}</ul>`;
}

export const errorText = (r: ApiResult) => r.json?.error_description ?? r.json?.description ?? r.json?.error ?? r.text ?? `HTTP ${r.status}`;

export function copyButtons(root: ParentNode = document) {
  root.querySelectorAll<HTMLButtonElement>('button[data-copy]').forEach((b) => {
    b.onclick = async () => {
      const target = document.getElementById(b.dataset.copy!) as HTMLInputElement | HTMLElement | null;
      const text = target && 'value' in target ? (target as HTMLInputElement).value : target?.textContent ?? '';
      try { await navigator.clipboard.writeText(text); b.textContent = 'Copied'; setTimeout(() => (b.textContent = 'Copy'), 1200); } catch {}
    };
  });
}

// ── Event rows, shared by the Transmitter log and the Receiver feed ─────────────────────────
// One line per event (badge, event type, stream, outcome, time); click to open the detail, which
// always comes in the same order: what happened, checks, header, payload, raw SET.

export type EventRow = {
  at: number;
  level: 'pass' | 'warn' | 'fail' | 'info';
  label?: string; // badge text; defaults to the level
  eventType?: string; // full URI
  title?: string; // shown instead of an event type, for non-event entries ("stream created")
  via?: string; // stream name, already escaped HTML
  outcome?: string; // short, plain text
  detail?: string; // longer explanation, plain text
  response?: unknown; // receiver: the response body it sent
  checks?: Check[];
  set?: string;
  header?: unknown;
  payload?: unknown;
};

const sub = (label: string, html: string) => `<p class="muted" style="font-size:.85rem;margin:.6rem 0 0">${label}</p>${html}`;

export function eventRow(r: EventRow): string {
  const decoded = r.set && (!r.header || !r.payload) ? decodeJwt(r.set) : null;
  const header = r.header ?? decoded?.header, payload = r.payload ?? decoded?.payload;
  const what = r.eventType ? `<code>${esc(r.eventType.split('/').pop())}</code>` : `<strong>${esc(r.title ?? '')}</strong>`;
  const body = [
    r.detail ? `<p style="margin:.4rem 0 0;font-size:.9rem;word-break:break-word">${esc(r.detail)}</p>` : '',
    r.response ? sub('Response body', pretty(r.response)) : '',
    r.checks?.length ? checksTray(r.checks) : '',
    header ? sub('Header', pretty(header)) : '',
    payload ? sub('Payload', pretty(payload)) : '',
    r.set ? sub(`Raw SET${r.set ? ` · <a href="/playground/inspector/#set=${encodeURIComponent(r.set)}" target="_blank">inspect</a>` : ''}`, `<pre><code style="word-break:break-all;white-space:pre-wrap">${esc(r.set)}</code></pre>`) : '',
  ].join('');
  return `<details class="event-row">
    <summary>${badge(r.level, r.label ?? r.level)} ${what}${r.via ? ` <span>via ${r.via}</span>` : ''} ${r.outcome ? `<span class="muted">· ${esc(r.outcome)}</span>` : ''}
      <span class="muted when">${esc(new Date(r.at).toLocaleTimeString())}</span></summary>
    ${body || '<p class="muted" style="margin:.4rem 0 0;font-size:.88rem">No further detail.</p>'}
  </details>`;
}

/** Re-renders a feed but keeps rows the reader opened open (rows are keyed by data-key). */
export function renderRows(el: HTMLElement, rows: { key: string; html: string }[], empty: string) {
  const open = new Set([...el.querySelectorAll<HTMLDetailsElement>('details.event-row[open]')].map((d) => d.dataset.key));
  el.innerHTML = rows.length ? rows.map((r) => r.html.replace('<details class="event-row">', `<details class="event-row" data-key="${esc(r.key)}"${open.has(r.key) ? ' open' : ''}>`)).join('') : empty;
}
