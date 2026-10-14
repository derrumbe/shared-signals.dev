// Optional passkey accounts in the playground: sign in, keep sandboxes, and (by default) have the
// sample Transmitter send CAEP session-established / session-revoked about you to your saved sandboxes.

import { browserSupportsWebAuthn, startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { api, badge, errorText, esc } from './playground';
import { currentCreds, useSandbox } from './session';

const body = () => document.getElementById('acct-body')!;
const msg = (html: string) => (document.getElementById('acct-msg')!.innerHTML = html);
const fail = (text: string) => msg(`<p class="error">${esc(text)}</p>`);
const date = (iso: string) => new Date(iso).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });

/** Browser-cancelled passkey prompts aren't errors worth shouting about. */
function passkeyError(e: any) {
  if (e?.name === 'NotAllowedError' || e?.name === 'AbortError') return msg('<p class="muted">Passkey prompt cancelled.</p>');
  fail(e?.message ?? String(e));
}

async function createAccount() {
  const opts = await api('POST', '/api/auth/register/options', { body: {} });
  if (opts.status !== 200) return fail(errorText(opts));
  try {
    const response = await startRegistration({ optionsJSON: opts.json });
    // A new account starts with the sandbox you're using, which is almost always what you want.
    const sandbox = { ...currentCreds(), label: 'My first sandbox' };
    const v = await api('POST', '/api/auth/register/verify', { body: { response, label: deviceLabel(), sandbox } });
    if (v.status !== 200) return fail(errorText(v));
    msg('<p>Account created and signed in. Your current sandbox is saved to it.</p>');
    render();
  } catch (e) { passkeyError(e); }
}

async function signIn() {
  const opts = await api('POST', '/api/auth/login/options', { body: {} });
  if (opts.status !== 200) return fail(errorText(opts));
  try {
    const response = await startAuthentication({ optionsJSON: opts.json });
    const v = await api('POST', '/api/auth/login/verify', { body: { response } });
    if (v.status !== 200) return fail(errorText(v));
    msg('');
    render();
  } catch (e) { passkeyError(e); }
}

async function addPasskey() {
  const opts = await api('POST', '/api/auth/register/options', { body: {} });
  if (opts.status !== 200) return fail(errorText(opts));
  try {
    const response = await startRegistration({ optionsJSON: opts.json });
    const v = await api('POST', '/api/auth/register/verify', { body: { response, label: deviceLabel() } });
    if (v.status !== 200) return fail(errorText(v));
    msg('<p>Passkey added.</p>');
    render();
  } catch (e) { passkeyError(e); }
}

function deviceLabel() {
  const ua = navigator.userAgent;
  const os = /iPhone|iPad/.test(ua) ? 'iPhone/iPad' : /Android/.test(ua) ? 'Android' : /Mac/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'Device';
  return `${os}, added ${new Date().toLocaleDateString()}`;
}

function signedOut() {
  const supported = browserSupportsWebAuthn();
  body().innerHTML = `
    <p class="muted" style="margin:0;font-size:.9rem">Sign in with a passkey to keep your sandboxes on every device. No email or password:
    the site stores your passkey’s public key and the sandboxes you save, nothing else. Accounts unused for 90 days are deleted.
    While signed in, signing in and out also sends real CAEP <code>session-established</code> and <code>session-revoked</code> events to your saved sandboxes’ streams.</p>
    ${supported ? `<div class="actions" style="margin:.8rem 0 0">
      <button class="btn primary" id="acct-signin">Sign in with passkey</button>
      <button class="btn" id="acct-create">Create account</button>
    </div>` : '<p class="error">This browser doesn’t support passkeys.</p>'}`;
  document.getElementById('acct-signin')?.addEventListener('click', signIn);
  document.getElementById('acct-create')?.addEventListener('click', createAccount);
}

function signedIn(a: any) {
  const c = currentCreds();
  const current = a.sandboxes.find((s: any) => s.client_id === c.client_id && s.client_secret === c.client_secret);
  body().innerHTML = `
    <p class="muted" style="margin:0;font-size:.88rem">Kept until ${esc(date(a.expires))} unless you use it before then.</p>
    <h3 style="margin:1rem 0 .3rem">Saved sandboxes</h3>
    ${a.sandboxes.length ? `<div class="table-wrap"><table><tbody>${a.sandboxes.map((s: any) => `<tr>
      <td><strong>${esc(s.label)}</strong><br><code style="font-size:.75rem">${esc(s.client_id)}</code></td>
      <td style="text-align:right;white-space:nowrap">${s === current ? badge('pass', 'in use') : `<button class="btn small" data-use="${esc(s.client_id)}">Use</button>`}
        <button class="btn small" data-forget="${esc(s.client_id)}">Remove</button></td></tr>`).join('')}</tbody></table></div>`
      : '<p class="muted">None yet.</p>'}
    ${current ? '' : `<div class="copy" style="margin:.5rem 0"><input type="text" id="acct-label" placeholder="Name for the current sandbox" maxlength="60" /><button class="btn small" id="acct-save">Save current sandbox</button></div>`}
    <label class="radios" style="margin:.8rem 0;font-size:.88rem"><span><input type="checkbox" id="acct-signals" ${a.signals ? 'checked' : ''} />
      Send CAEP <code>session-established</code> / <code>session-revoked</code> about me to my saved sandboxes when I sign in or out</span></label>
    <details style="margin:.5rem 0"><summary style="cursor:pointer;font-size:.9rem">Passkeys (${a.passkeys.length})</summary>
      <ul class="checks">${a.passkeys.map((p: any) => `<li><span class="muted" style="font-size:.8rem">${esc(date(p.last_used))}</span><span>${esc(p.label)}
        ${a.passkeys.length > 1 ? ` <button class="btn small" data-passkey="${esc(p.id)}">Remove</button>` : ''}</span></li>`).join('')}</ul>
      <button class="btn small" id="acct-addkey">Add a passkey</button>
    </details>
    <div class="actions" style="margin:.8rem 0 0">
      <button class="btn" id="acct-signout">Sign out</button>
      <button class="btn" id="acct-delete">Delete account</button>
    </div>`;

  body().querySelectorAll<HTMLButtonElement>('[data-use]').forEach((b) => (b.onclick = () => {
    const s = a.sandboxes.find((x: any) => x.client_id === b.dataset.use);
    useSandbox({ client_id: s.client_id, client_secret: s.client_secret });
  }));
  body().querySelectorAll<HTMLButtonElement>('[data-forget]').forEach((b) => (b.onclick = async () => {
    if (!confirm('Remove this sandbox from your account? Its streams are not deleted.')) return;
    const r = await api('DELETE', `/api/account/sandboxes?client_id=${encodeURIComponent(b.dataset.forget!)}`);
    r.status === 200 ? render() : fail(errorText(r));
  }));
  body().querySelectorAll<HTMLButtonElement>('[data-passkey]').forEach((b) => (b.onclick = async () => {
    if (!confirm('Remove this passkey? You won’t be able to sign in with it any more.')) return;
    const r = await api('DELETE', `/api/account/passkeys?id=${encodeURIComponent(b.dataset.passkey!)}`);
    r.status === 200 ? render() : fail(errorText(r));
  }));
  document.getElementById('acct-save')?.addEventListener('click', async () => {
    const label = (document.getElementById('acct-label') as HTMLInputElement).value;
    const r = await api('POST', '/api/account/sandboxes', { body: { ...currentCreds(), label } });
    r.status === 200 ? (msg(''), render()) : fail(errorText(r));
  });
  document.getElementById('acct-signals')!.onchange = async (e) => {
    const r = await api('PATCH', '/api/account', { body: { signals: (e.target as HTMLInputElement).checked } });
    if (r.status !== 200) fail(errorText(r));
  };
  document.getElementById('acct-addkey')!.onclick = addPasskey;
  document.getElementById('acct-signout')!.onclick = async () => {
    const r = await api('POST', '/api/auth/logout', { body: {} });
    r.status === 200 ? (msg('<p class="muted">Signed out.</p>'), render()) : fail(errorText(r));
  };
  document.getElementById('acct-delete')!.onclick = async () => {
    if (!confirm('Delete your account? Your passkeys stop working here and saved sandboxes are forgotten. The sandboxes and their streams are not deleted.')) return;
    const r = await api('DELETE', '/api/account');
    r.status === 204 ? (msg('<p class="muted">Account deleted. You may also want to remove the passkey from your device’s password manager.</p>'), render()) : fail(errorText(r));
  };
}

export async function render() {
  const r = await api('GET', '/api/account');
  const badgeEl = document.getElementById('acct-badge')!;
  if (r.status !== 200) { body().innerHTML = `<p class="error">${esc(errorText(r))}</p>`; return; }
  badgeEl.innerHTML = r.json.signed_in ? badge('pass', 'signed in') : '';
  r.json.signed_in ? signedIn(r.json) : signedOut();
}

export const initAccount = render;
