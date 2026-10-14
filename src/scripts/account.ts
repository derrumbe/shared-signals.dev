// Optional passkey accounts in the playground: sign in, keep sandboxes, and (by default) have the
// sample Transmitter send CAEP session-established / session-revoked about you to your saved sandboxes.

import { browserSupportsWebAuthn, startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { api, badge, errorText, esc } from './playground';
import { currentCreds, flashStore, forgetSandbox, modeStore, useSandbox } from './session';

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

const reveal = (show: boolean) => (document.getElementById('playground-body')!.hidden = !show);

/** First visit: choose how to keep the sandbox before the playground appears. */
function chooser() {
  const supported = browserSupportsWebAuthn();
  body().innerHTML = `
    <p style="margin:0">Your playground work lives in a <em>sandbox</em>: a private set of streams and a sample Receiver. How do you want to keep it?</p>
    <div class="grid" style="margin-top:1rem;grid-template-columns:repeat(auto-fit,minmax(min(100%,17rem),1fr))">
      <div class="card">
        <h3>With a passkey</h3>
        <p>Your sandboxes follow you to every device. No email or password: the site stores your passkey’s public key and the sandboxes you save.
        Signing in and out also sends real CAEP <code>session-established</code> / <code>session-revoked</code> events to your streams.</p>
        ${supported ? `<div class="actions" style="margin:.6rem 0 0">
          <button class="btn primary" id="acct-signin">Sign in</button>
          <button class="btn" id="acct-create">Create account</button>
        </div>` : '<p class="error">This browser doesn’t support passkeys.</p>'}
      </div>
      <div class="card">
        <h3>Without an account</h3>
        <p>The sandbox stays in this browser. To use it somewhere else, copy its sandbox link — anyone with the link can use it.
        You can create an account later and keep this sandbox.</p>
        <div class="actions" style="margin:.6rem 0 0"><button class="btn" id="acct-skip">Continue without an account</button></div>
      </div>
    </div>`;
  document.getElementById('acct-signin')?.addEventListener('click', signIn);
  document.getElementById('acct-create')?.addEventListener('click', createAccount);
  document.getElementById('acct-skip')!.onclick = () => { modeStore.set('link'); render(); };
}

/** Chose no account: a one-line reminder, with the passkey options still to hand. */
function signedOut() {
  const supported = browserSupportsWebAuthn();
  body().innerHTML = `
    <p class="muted" style="margin:0;font-size:.9rem">No account: this sandbox lives in this browser. Use <strong>Copy sandbox link</strong> to open it elsewhere,
    or sign in with a passkey to keep it on every device. Accounts store only your passkey’s public key and the sandboxes you save, and are deleted after 90 days unused.</p>
    ${supported ? `<div class="actions" style="margin:.8rem 0 0">
      <button class="btn" id="acct-signin">Sign in with passkey</button>
      <button class="btn" id="acct-create">Create account</button>
    </div>` : ''}`;
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
    if (r.status !== 200) return fail(errorText(r));
    // A sandbox saved to the account goes with it; anything else stays in this browser.
    if (current) return forgetSandbox('Signed out. This browser no longer holds your sandbox; sign in again to pick it up.');
    msg('<p class="muted">Signed out.</p>'); render();
  };
  document.getElementById('acct-delete')!.onclick = async () => {
    if (!confirm('Delete your account? Your passkeys stop working here and saved sandboxes are forgotten. The sandboxes and their streams are not deleted.')) return;
    const r = await api('DELETE', '/api/account');
    if (r.status !== 204) return fail(errorText(r));
    const note = 'Account deleted. You may also want to remove the passkey from your device’s password manager.';
    if (current) return forgetSandbox(`${note} This browser no longer holds the sandbox that was saved to it.`);
    msg(`<p class="muted">${note}</p>`); render();
  };
}

export async function render() {
  const flash = flashStore.get();
  if (flash) { flashStore.set(null); msg(`<p class="muted">${esc(flash)}</p>`); }
  const r = await api('GET', '/api/account');
  const badgeEl = document.getElementById('acct-badge')!;
  if (r.status !== 200) { body().innerHTML = `<p class="error">${esc(errorText(r))}</p>`; return; }
  badgeEl.innerHTML = r.json.signed_in ? badge('pass', 'signed in') : '';
  if (r.json.signed_in) { modeStore.set('passkey'); reveal(true); signedIn(r.json); return; }
  // Signed out after having had an account (or chosen none): no need to ask again.
  if (modeStore.get()) { modeStore.set('link'); reveal(true); signedOut(); return; }
  reveal(false);
  chooser();
}

export const initAccount = render;
