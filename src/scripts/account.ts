// Optional passkey accounts in the playground: sign in, keep sandboxes, and (by default) have the
// sample Transmitter send CAEP session-established / session-revoked about you to your sandbox's streams.

import { browserSupportsWebAuthn, startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { api, badge, errorText, esc } from './playground';
import { currentCreds, flashStore, forgetSandbox, freshBrowser, modeStore, useSandbox } from './session';

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
    const sandbox = { ...currentCreds(), label: 'My sandbox' };
    const v = await api('POST', '/api/auth/register/verify', { body: { response, label: deviceLabel(), sandbox } });
    if (v.status !== 200) return fail(errorText(v));
    msg('<p>Account created and signed in. Your sandbox is now kept with it.</p>');
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
        <p>Your sandbox follows you to every device. No email or password: the site stores your passkey’s public key and your sandbox’s credentials.
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
    or sign in with a passkey to keep it on every device. Accounts store only your passkey’s public key and your sandbox’s credentials, and are deleted after 90 days unused.</p>
    ${supported ? `<div class="actions" style="margin:.8rem 0 0">
      <button class="btn" id="acct-signin">Sign in with passkey</button>
      <button class="btn" id="acct-create">Create account</button>
    </div>` : ''}`;
  document.getElementById('acct-signin')?.addEventListener('click', signIn);
  document.getElementById('acct-create')?.addEventListener('click', createAccount);
}

function signedIn(a: any) {
  // One sandbox per account, kept in step with this browser (see render()).
  const c = currentCreds();
  const saved = a.sandboxes[0];
  const current = saved && saved.client_id === c.client_id && saved.client_secret === c.client_secret ? saved : null;
  const choice = saved && !current
    ? `<div class="callout" style="margin:.6rem 0"><p style="margin:0">This browser holds a different sandbox (<code>${esc(c.client_id)}</code>) from your account’s
       (<code>${esc(saved.client_id)}</code>). Which do you want to keep using? The other is not deleted, just no longer loaded here.</p>
       <div class="actions" style="margin:.6rem 0 0"><button class="btn primary" id="acct-use">Use my account’s sandbox</button>
       <button class="btn" id="acct-keep">Keep this one (it becomes the account’s)</button></div></div>`
    : `<p style="margin:.6rem 0 0">Your sandbox: <code>${esc(c.client_id)}</code> ${badge('pass', 'in use')}</p>`;
  body().innerHTML = `
    <p class="muted" style="margin:0;font-size:.88rem">Kept until ${esc(date(a.expires))} unless you use it before then.</p>
    ${choice}
    <label class="radios" style="margin:.8rem 0;font-size:.88rem"><span><input type="checkbox" id="acct-signals" ${a.signals ? 'checked' : ''} />
      Send CAEP <code>session-established</code> / <code>session-revoked</code> about me to my sandbox’s streams when I sign in or out</span></label>
    <details style="margin:.5rem 0"><summary style="cursor:pointer;font-size:.9rem">Passkeys (${a.passkeys.length})</summary>
      <ul class="checks">${a.passkeys.map((p: any) => `<li><span class="muted" style="font-size:.8rem">${esc(date(p.last_used))}</span><span>${esc(p.label)}
        ${a.passkeys.length > 1 ? ` <button class="btn small" data-passkey="${esc(p.id)}">Remove</button>` : ''}</span></li>`).join('')}</ul>
      <button class="btn small" id="acct-addkey">Add a passkey</button>
    </details>
    <div class="actions" style="margin:.8rem 0 0">
      <button class="btn" id="acct-signout">Sign out</button>
      <button class="btn" id="acct-delete">Delete account</button>
    </div>`;

  document.getElementById('acct-use')?.addEventListener('click', () => useSandbox({ client_id: saved.client_id, client_secret: saved.client_secret }));
  document.getElementById('acct-keep')?.addEventListener('click', async () => {
    const r = await api('POST', '/api/account/sandboxes', { body: { ...currentCreds(), label: 'My sandbox' } });
    r.status === 200 ? (msg(''), render()) : fail(errorText(r));
  });
  body().querySelectorAll<HTMLButtonElement>('[data-passkey]').forEach((b) => (b.onclick = async () => {
    if (!confirm('Remove this passkey? You won’t be able to sign in with it any more.')) return;
    const r = await api('DELETE', `/api/account/passkeys?id=${encodeURIComponent(b.dataset.passkey!)}`);
    r.status === 200 ? render() : fail(errorText(r));
  }));
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
    if (!confirm('Delete your account? Your passkeys stop working here. Your sandbox and its streams are not deleted; use Delete sandbox for that.')) return;
    const r = await api('DELETE', '/api/account');
    if (r.status !== 204) return fail(errorText(r));
    const note = 'Account deleted. You may also want to remove the passkey from your device’s password manager.';
    if (current) return forgetSandbox(`${note} This browser no longer holds the account’s sandbox.`);
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
  if (r.json.signed_in) {
    modeStore.set('passkey'); reveal(true);
    // An account without a sandbox (new, or its sandbox was deleted) takes the one this browser holds.
    if (!r.json.sandboxes.length) {
      const s = await api('POST', '/api/account/sandboxes', { body: { ...currentCreds(), label: 'My sandbox' } });
      if (s.status === 200) return signedIn(s.json);
    }
    // Signing in on a browser whose own sandbox is empty (fresh, or just signed out) loads the account's;
    // if it has streams, signedIn() asks which to keep.
    const saved = r.json.sandboxes[0];
    const c = currentCreds();
    if (saved && (saved.client_id !== c.client_id || saved.client_secret !== c.client_secret) && (await freshBrowser())) return useSandbox({ client_id: saved.client_id, client_secret: saved.client_secret });
    signedIn(r.json); return;
  }
  // Signed out after having had an account (or chosen none): no need to ask again.
  if (modeStore.get()) { modeStore.set('link'); reveal(true); signedOut(); return; }
  reveal(false);
  chooser();
}

export const initAccount = render;
