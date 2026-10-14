export type Reply = { status: number; body?: unknown; headers?: Record<string, string> };

export const reply = (status: number, body?: unknown, headers?: Record<string, string>): Reply => ({ status, body, headers });

/** RFC 6749 §5.2 / RFC 6750 §3.1 style error body. */
export const error = (status: number, code: string, description: string, headers?: Record<string, string>): Reply =>
  reply(status, { error: code, error_description: description }, headers);

export function toResponse(r: Reply, extra: Record<string, string> = {}): Response {
  const headers: Record<string, string> = { 'cache-control': 'no-store', ...extra, ...r.headers };
  if (r.body === undefined || r.status === 204) return new Response(null, { status: r.status, headers });
  if (typeof r.body === 'string') return new Response(r.body, { status: r.status, headers });
  headers['content-type'] ??= 'application/json';
  return new Response(JSON.stringify(r.body, null, 2), { status: r.status, headers });
}

export const MAX_BODY = 64 * 1024;

/** Reads a request body as text, refusing anything over MAX_BODY. */
export async function readText(request: Request): Promise<string | null> {
  const len = Number(request.headers.get('content-length') ?? 0);
  if (len > MAX_BODY) return null;
  const text = await request.text();
  return text.length > MAX_BODY ? null : text;
}

/** Parses a JSON object body. */
export async function readJson(request: Request): Promise<{ body: Record<string, any> } | { fail: Reply }> {
  const text = await readText(request);
  if (text === null) return { fail: error(413, 'invalid_request', `Request body is larger than ${MAX_BODY} bytes.`) };
  if (!text.trim()) return { body: {} };
  try {
    const v = JSON.parse(text);
    if (v && typeof v === 'object' && !Array.isArray(v)) return { body: v };
  } catch {}
  return { fail: error(400, 'invalid_request', 'Request body must be a JSON object.') };
}
