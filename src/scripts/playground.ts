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
