// Outbound requests to URLs that visitors supply (push endpoint_urls, JWKS and issuer URLs in the
// inspector) are a server-side request forgery risk. Workers cannot reach private networks, but we
// still refuse anything that is not plain public HTTPS by name, never follow redirects, time out
// quickly and cap how much of the response we read.

export function checkPublicUrl(raw: unknown): { url?: URL; problem?: string } {
  if (typeof raw !== 'string' || raw.length > 2048) return { problem: 'must be a URL string of at most 2048 characters' };
  let url: URL;
  try { url = new URL(raw); } catch { return { problem: 'is not a valid absolute URL' }; }
  if (url.protocol !== 'https:') return { problem: 'must use https' };
  if (url.username || url.password) return { problem: 'must not contain credentials' };
  if (url.port && url.port !== '443') return { problem: 'must use the default HTTPS port' };
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (/^[\d.]+$/.test(host) || host.includes(':') || host.startsWith('[')) return { problem: 'must use a DNS name, not an IP address' };
  if (!host.includes('.')) return { problem: 'must use a fully qualified domain name' };
  if (/(^|\.)(localhost|local|internal|intranet|lan|home\.arpa|localdomain|corp|test|invalid|example)$/.test(host)) return { problem: `uses a reserved or internal domain (${host})` };
  return { url };
}

export type Fetched = { ok: boolean; status: number; contentType: string; text: string; error?: string };

export async function safeFetch(url: URL, init: RequestInit = {}, maxBytes = 64 * 1024): Promise<Fetched> {
  try {
    const res = await fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(8000) });
    const contentType = res.headers.get('content-type') ?? '';
    if (res.status >= 300 && res.status < 400) {
      await res.body?.cancel();
      return { ok: false, status: res.status, contentType, text: '', error: `redirected to ${res.headers.get('location') ?? '(no location)'}; redirects are not followed` };
    }
    const text = await readCapped(res, maxBytes);
    return { ok: res.ok, status: res.status, contentType, text };
  } catch (e: any) {
    return { ok: false, status: 0, contentType: '', text: '', error: e?.name === 'TimeoutError' ? 'timed out after 8 seconds' : String(e?.message ?? e) };
  }
}

async function readCapped(res: Response, max: number): Promise<string> {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (size < max) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
  }
  await reader.cancel().catch(() => {});
  const all = new Uint8Array(Math.min(size, max));
  let off = 0;
  for (const c of chunks) { all.set(c.subarray(0, all.length - off), off); off += c.length; if (off >= all.length) break; }
  return new TextDecoder().decode(all);
}
