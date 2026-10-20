// Event catalogue, transcribed from the OpenID CAEP 1.0, RISC 1.0 and SSF 1.0 final
// specifications and IETF RFC 9967 (SCIM Events). Keep summaries in our own words and link to the
// spec for normative text.

export type Claim = { name: string; req: 'REQUIRED' | 'RECOMMENDED' | 'OPTIONAL'; desc: string };
export type EventType = {
  slug: string;
  spec: 'caep' | 'risc' | 'ssf' | 'scim';
  name: string;
  summary: string;
  claims: Claim[];
  deprecated?: string;
  /** Shown under the example: how the CAEP Interoperability Profile differs from it. */
  iopNote?: string;
  example?: Record<string, unknown>;
};

// SCIM event types are URNs registered by RFC 9967; their slugs are the part after the prefix ("prov:create:full").
export const SCIM_PREFIX = 'urn:ietf:params:scim:event:';
export const uri = (e: EventType) => e.spec === 'scim' ? SCIM_PREFIX + e.slug : `https://schemas.openid.net/secevent/${e.spec}/event-type/${e.slug}`;

const ts = { name: 'event_timestamp', req: 'OPTIONAL', desc: 'When the event occurred (NumericDate). Optional on every CAEP event.' } as const;
const caepCommon: Claim[] = [
  ts,
  { name: 'initiating_entity', req: 'OPTIONAL', desc: 'Who caused the event: admin, user, policy, or system.' },
  { name: 'reason_admin / reason_user', req: 'OPTIONAL', desc: 'Localised, human-readable explanation for an administrator or end user.' },
];

const set = (slug: string, spec: string, sub: Record<string, unknown>, body: Record<string, unknown>) => ({
  iss: 'https://tr.example.com/',
  jti: '756E69717565206964656E746966696572',
  iat: 1760390400,
  aud: 'https://rp.example.com/',
  txn: '8675309',
  sub_id: sub,
  events: { [`https://schemas.openid.net/secevent/${spec}/event-type/${slug}`]: body },
});
const email = { format: 'email', email: 'alice@example.com' };
const iss_sub = { format: 'iss_sub', iss: 'https://idp.example.com/', sub: '248289761001' };

// SCIM events (RFC 9967): a SCIM service provider tells receivers about provisioning changes. The
// examples follow the RFC's figures.
const scimSet = (slug: string, sub: Record<string, unknown>, body: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
  iss: 'https://scim.example.com',
  jti: '6164f3bbf6ff41a88dc94f18cb0620e8',
  iat: 1760390400,
  aud: ['https://scim.example.com/Feeds/98d52461fa5bbc879593b7754'],
  txn: 'b7b953f11cc6489bbfb87834747cc4c1',
  ...extra,
  sub_id: sub,
  events: { [`urn:ietf:params:scim:event:${slug}`]: body },
});
const scimUser = { format: 'scim', uri: '/Users/2b2f880af6674ac284bae9381673d462', externalId: 'jdoe' };
const scimGroup = { format: 'scim', uri: '/Groups/176f397ec4c44b94b2cfcb759780b8c2', externalId: 'crmUsers' };
const version = { name: 'version', req: 'OPTIONAL', desc: 'The resource’s ETag version after the change.' } as const;
const full = (what: string): Claim[] => [{ name: 'data', req: 'REQUIRED', desc: `${what} Present only in the :full variant.` }, version];
const notice = (what: string): Claim[] => [{ name: 'attributes', req: 'REQUIRED', desc: `${what} Present only in the :notice variant; the receiver can GET the resource for the values.` }, version];

export const EVENTS: EventType[] = [
  // ── CAEP ─────────────────────────────────────────────────────────────
  {
    slug: 'session-revoked', spec: 'caep', name: 'Session Revoked',
    summary: 'A session for the subject has been terminated. Receivers should end any corresponding sessions they hold.',
    claims: caepCommon,
    iopNote: 'This example, from the CAEP specification, uses an opaque subject. The CAEP Interoperability Profile allows only email and iss_sub subjects on CAEP events (opaque is for the Verification event only), so interoperable Transmitters send one of those.',
    example: set('session-revoked', 'caep', { format: 'opaque', id: 'dMTlD|1600802906337.16|16008.16' }, { event_timestamp: 1760390391 }),
  },
  {
    slug: 'token-claims-change', spec: 'caep', name: 'Token Claims Change',
    summary: 'Claims in a token previously issued for the subject have changed — for example a role or group membership — so the Receiver may want to re-evaluate access.',
    claims: [{ name: 'claims', req: 'REQUIRED', desc: 'Object holding the claim names and their new values.' }, ...caepCommon],
    example: set('token-claims-change', 'caep', iss_sub, { event_timestamp: 1760390391, claims: { role: 'ro-admin' } }),
  },
  {
    slug: 'credential-change', spec: 'caep', name: 'Credential Change',
    summary: 'A credential was created, revoked, updated or deleted — a password reset, a new passkey, a revoked certificate.',
    claims: [
      { name: 'credential_type', req: 'REQUIRED', desc: 'password, pin, x509, fido2-platform, fido2-roaming, fido-u2f, verifiable-credential, phone-voice, phone-sms, app, …' },
      { name: 'change_type', req: 'REQUIRED', desc: 'create, revoke, update, or delete.' },
      { name: 'friendly_name', req: 'OPTIONAL', desc: 'Display name of the credential.' },
      { name: 'x509_issuer / x509_serial', req: 'OPTIONAL', desc: 'Identify an X.509 credential.' },
      { name: 'fido2_aaguid', req: 'OPTIONAL', desc: 'Authenticator model of a FIDO2 credential.' },
      ...caepCommon,
    ],
    example: set('credential-change', 'caep', email, { event_timestamp: 1760390391, credential_type: 'fido2-roaming', change_type: 'create', fido2_aaguid: 'accced6a-63f5-490a-9eea-e59bc1896cfc', friendly_name: 'Security key' }),
  },
  {
    slug: 'assurance-level-change', spec: 'caep', name: 'Assurance Level Change',
    summary: 'The authentication assurance level for the subject went up or down (for example, NIST AAL or eIDAS levels).',
    claims: [
      { name: 'namespace', req: 'REQUIRED', desc: 'Assurance framework: RFC8176, RFC6711, ISO-IEC-29115, NIST-IAL, NIST-AAL, NIST-FAL, or a custom value.' },
      { name: 'current_level', req: 'REQUIRED', desc: 'The new level.' },
      { name: 'previous_level', req: 'OPTIONAL', desc: 'The level before the change.' },
      { name: 'change_direction', req: 'OPTIONAL', desc: 'increase or decrease.' },
      ...caepCommon,
    ],
    example: set('assurance-level-change', 'caep', iss_sub, { event_timestamp: 1760390391, namespace: 'NIST-AAL', current_level: 'nist-aal2', previous_level: 'nist-aal1', change_direction: 'increase' }),
  },
  {
    slug: 'device-compliance-change', spec: 'caep', name: 'Device Compliance Change',
    summary: 'A device moved into or out of compliance with policy — typically sent by an MDM or endpoint security product.',
    claims: [
      { name: 'current_status', req: 'REQUIRED', desc: 'compliant or not-compliant.' },
      { name: 'previous_status', req: 'REQUIRED', desc: 'compliant or not-compliant.' },
      ...caepCommon,
    ],
    iopNote: 'This example, from the CAEP specification, uses a complex subject made of opaque identifiers. The CAEP Interoperability Profile allows only email and iss_sub subjects on CAEP events (opaque is for the Verification event only), so interoperable Transmitters send one of those.',
    example: set('device-compliance-change', 'caep', { format: 'complex', device: { format: 'opaque', id: 'device-1234' }, tenant: { format: 'opaque', id: 'tenant-5678' } } as any, { event_timestamp: 1760390391, current_status: 'not-compliant', previous_status: 'compliant', initiating_entity: 'policy' }),
  },
  {
    slug: 'session-established', spec: 'caep', name: 'Session Established',
    summary: 'A new session was established for the subject — useful for correlating sessions across products.',
    claims: [
      { name: 'ips', req: 'OPTIONAL', desc: 'IP addresses of the user agent.' },
      { name: 'fp_ua', req: 'OPTIONAL', desc: 'Fingerprint of the user agent.' },
      { name: 'acr / amr', req: 'OPTIONAL', desc: 'Authentication context class and methods used.' },
      { name: 'ext_id', req: 'OPTIONAL', desc: 'External session identifier.' },
      ...caepCommon,
    ],
    example: set('session-established', 'caep', email, { event_timestamp: 1760390391, ips: ['192.0.2.10'], acr: 'AAL2', amr: ['pwd', 'otp'], fp_ua: 'abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611' }),
  },
  {
    slug: 'session-presented', spec: 'caep', name: 'Session Presented',
    summary: 'An existing session was presented to the Transmitter — lets a Receiver see where a session is being used.',
    claims: [
      { name: 'ips', req: 'OPTIONAL', desc: 'IP addresses of the user agent.' },
      { name: 'fp_ua', req: 'OPTIONAL', desc: 'Fingerprint of the user agent.' },
      { name: 'ext_id', req: 'OPTIONAL', desc: 'External session identifier.' },
      ...caepCommon,
    ],
    example: set('session-presented', 'caep', email, { event_timestamp: 1760390391, ips: ['198.51.100.7'], fp_ua: 'abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611', ext_id: '12345' }),
  },
  {
    slug: 'risk-level-change', spec: 'caep', name: 'Risk Level Change',
    summary: 'The Transmitter’s assessed risk level for a user, device, session or other principal changed.',
    claims: [
      { name: 'principal', req: 'REQUIRED', desc: 'What the risk is about: USER, DEVICE, SESSION, TENANT, ORG_UNIT, GROUP, …' },
      { name: 'current_level', req: 'REQUIRED', desc: 'LOW, MEDIUM, or HIGH.' },
      { name: 'previous_level', req: 'OPTIONAL', desc: 'LOW, MEDIUM, or HIGH; absent means unknown.' },
      { name: 'risk_reason', req: 'RECOMMENDED', desc: 'Why the risk changed.' },
      ...caepCommon,
    ],
    example: set('risk-level-change', 'caep', email, { event_timestamp: 1760390391, principal: 'USER', current_level: 'HIGH', previous_level: 'LOW', risk_reason: 'PASSWORD_FOUND_IN_DATA_BREACH' }),
  },

  // ── RISC ─────────────────────────────────────────────────────────────
  { slug: 'account-credential-change-required', spec: 'risc', name: 'Account Credential Change Required', summary: 'The account needs a credential change, for example because a password may have been exposed.', claims: [],
    example: set('account-credential-change-required', 'risc', email, {}) },
  { slug: 'account-purged', spec: 'risc', name: 'Account Purged', summary: 'The account has been permanently deleted.', claims: [] },
  { slug: 'account-disabled', spec: 'risc', name: 'Account Disabled', summary: 'The account has been disabled and can no longer be used.', claims: [{ name: 'reason', req: 'OPTIONAL', desc: 'hijacking or bulk-account.' }],
    example: set('account-disabled', 'risc', iss_sub, { reason: 'hijacking' }) },
  { slug: 'account-enabled', spec: 'risc', name: 'Account Enabled', summary: 'A previously disabled account has been re-enabled.', claims: [] },
  { slug: 'identifier-changed', spec: 'risc', name: 'Identifier Changed', summary: 'The subject’s identifier (e.g. email or phone) changed. The SET is about the old identifier.', claims: [{ name: 'new-value', req: 'OPTIONAL', desc: 'The new identifier value.' }],
    example: set('identifier-changed', 'risc', email, { 'new-value': 'alice.smith@example.com' }) },
  { slug: 'identifier-recycled', spec: 'risc', name: 'Identifier Recycled', summary: 'The identifier now belongs to a different person — e.g. a reissued email address or phone number.', claims: [] },
  { slug: 'credential-compromise', spec: 'risc', name: 'Credential Compromise', summary: 'A credential for the subject was found to be compromised.', claims: [
      { name: 'credential_type', req: 'REQUIRED', desc: 'Same values as CAEP Credential Change.' },
      { name: 'event_timestamp', req: 'OPTIONAL', desc: 'When the compromise was detected.' },
      { name: 'reason_admin / reason_user', req: 'OPTIONAL', desc: 'Human-readable explanations.' },
    ],
    example: set('credential-compromise', 'risc', email, { credential_type: 'password', event_timestamp: 1760390391 }) },
  { slug: 'opt-in', spec: 'risc', name: 'Opt In', summary: 'The account owner opted in to RISC event exchange.', claims: [] },
  { slug: 'opt-out-initiated', spec: 'risc', name: 'Opt Out Initiated', summary: 'The account owner started opting out; it takes effect after a grace period.', claims: [] },
  { slug: 'opt-out-cancelled', spec: 'risc', name: 'Opt Out Cancelled', summary: 'A pending opt-out was cancelled.', claims: [] },
  { slug: 'opt-out-effective', spec: 'risc', name: 'Opt Out Effective', summary: 'The opt-out is now in effect; no further events about this subject will be sent.', claims: [] },
  { slug: 'recovery-activated', spec: 'risc', name: 'Recovery Activated', summary: 'Account recovery was started for the subject.', claims: [] },
  { slug: 'recovery-information-changed', spec: 'risc', name: 'Recovery Information Changed', summary: 'Recovery information (backup email, phone, etc.) was changed.', claims: [] },
  { slug: 'sessions-revoked', spec: 'risc', name: 'Sessions Revoked', summary: 'All sessions for the account were revoked.', claims: [], deprecated: 'Deprecated — new implementations MUST use CAEP Session Revoked.' },

  // ── SSF ──────────────────────────────────────────────────────────────
  { slug: 'verification', spec: 'ssf', name: 'Verification', summary: 'Sent by the Transmitter when a Receiver asks it to verify a stream end-to-end; echoes back the Receiver-supplied state.', claims: [{ name: 'state', req: 'OPTIONAL', desc: 'Opaque value the Receiver passed in the verification request.' }],
    example: { iss: 'https://tr.example.com/', jti: '123456', iat: 1760390400, aud: 'https://rp.example.com/', sub_id: { format: 'opaque', id: 'f67e39a0a4d34d56b3aa1bc4cff0069f' },
      events: { 'https://schemas.openid.net/secevent/ssf/event-type/verification': { state: 'VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo=' } } } },
  { slug: 'stream-updated', spec: 'ssf', name: 'Stream Updated', summary: 'The Transmitter changed the stream’s status (enabled, paused, disabled) on its own initiative.', claims: [
      { name: 'status', req: 'REQUIRED', desc: 'enabled, paused, or disabled.' },
      { name: 'reason', req: 'OPTIONAL', desc: 'Why the status changed.' },
    ],
    example: { iss: 'https://tr.example.com/', jti: '123456', iat: 1760390400, aud: 'https://rp.example.com/', sub_id: { format: 'opaque', id: 'f67e39a0a4d34d56b3aa1bc4cff0069f' },
      events: { 'https://schemas.openid.net/secevent/ssf/event-type/stream-updated': { status: 'paused', reason: 'License is not valid' } } } },

  // ── SCIM (RFC 9967) ──────────────────────────────────────────────────
  { slug: 'feed:add', spec: 'scim', name: 'Added to Feed', summary: 'The resource joined the event feed — for example a user gained a role that brings them into scope. It does not mean the resource is new.', claims: [],
    example: scimSet('feed:add', scimUser, {}) },
  { slug: 'feed:remove', spec: 'scim', name: 'Removed from Feed', summary: 'The resource left the event feed. It does not mean the resource was deleted or deactivated.', claims: [],
    example: scimSet('feed:remove', scimUser, {}) },
  { slug: 'prov:create:full', spec: 'scim', name: 'Resource Created (full)', summary: 'The service provider created a resource and added it to the feed; carries the resource as created, including its assigned id, so replicas can share it.',
    claims: full('The resource as created, in the form of a SCIM Bulk operation’s data.'),
    example: scimSet('prov:create:full', { format: 'scim', uri: '/Users/44f6142df96bd6ab61e7521d9', externalId: 'jdoe' }, { data: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], emails: [{ type: 'work', value: 'jdoe@example.com' }], userName: 'jdoe', name: { givenName: 'John', familyName: 'Doe' } } }) },
  { slug: 'prov:create:notice', spec: 'scim', name: 'Resource Created (notice)', summary: 'The service provider created a resource; lists which attributes were set, without their values.',
    claims: notice('The attributes that were set, e.g. ["id","userName","emails"].'),
    example: scimSet('prov:create:notice', { format: 'scim', uri: '/Users/44f6142df96bd6ab61e7521d9', externalId: 'jdoe' }, { attributes: ['id', 'name', 'userName', 'password', 'emails'] }) },
  { slug: 'prov:patch:full', spec: 'scim', name: 'Resource Patched (full)', summary: 'The resource was changed with SCIM PATCH; carries the PATCH operations.',
    claims: full('The SCIM PatchOp request that was applied.'),
    example: scimSet('prov:patch:full', scimGroup, { version: 'a330bc54f0671c9', data: { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'add', path: 'members', value: [{ display: 'Babs Jensen', $ref: '/Users/2819c223-7f76-453a-919d-413861904646', value: '2819c223-7f76-453a-919d-413861904646' }] }] } }) },
  { slug: 'prov:patch:notice', spec: 'scim', name: 'Resource Patched (notice)', summary: 'The resource was changed with SCIM PATCH; lists the modified attributes.',
    claims: notice('The modified attributes, as SCIM paths (e.g. "members", "name.familyName").'),
    example: scimSet('prov:patch:notice', scimGroup, { attributes: ['members'], version: 'a330bc54f0671c9' }) },
  { slug: 'prov:put:full', spec: 'scim', name: 'Resource Replaced (full)', summary: 'The resource was replaced with SCIM PUT; carries the PUT request body.',
    claims: full('The SCIM PUT request body.'),
    example: scimSet('prov:put:full', { format: 'scim', uri: '/Users/2819c223-7f76-453a-919d-413861904646' }, { version: 'a330bc54f0671c9', data: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], userName: 'jdoe', externalId: 'jdoe', name: { formatted: 'Mr. Jon Jack Doe III', familyName: 'Doe', givenName: 'Jon', middleName: 'Jack' }, roles: [], emails: [{ value: 'jdoe@example.com' }, { value: 'anon@jdoe.org' }] } }) },
  { slug: 'prov:put:notice', spec: 'scim', name: 'Resource Replaced (notice)', summary: 'The resource was replaced with SCIM PUT; lists the modified attributes.',
    claims: notice('The modified attributes.'),
    example: scimSet('prov:put:notice', { format: 'scim', uri: '/Users/2819c223-7f76-453a-919d-413861904646' }, { version: 'a330bc54f0671c9', attributes: ['userName', 'externalId', 'name', 'roles', 'emails'] }) },
  { slug: 'prov:delete', spec: 'scim', name: 'Resource Deleted', summary: 'The resource was deleted and is gone from the feed (no separate feed:remove is sent). Has no :full or :notice variant.', claims: [],
    example: scimSet('prov:delete', scimUser, {}) },
  { slug: 'prov:activate', spec: 'scim', name: 'Resource Activated', summary: 'The resource (e.g. a user’s account) is ready for use, as agreed between publisher and receiver — for example, it can now sign in.', claims: [],
    example: scimSet('prov:activate', scimUser, {}) },
  { slug: 'prov:deactivate', spec: 'scim', name: 'Resource Deactivated', summary: 'The resource was deactivated and disabled. Typically the subject should no longer have an active session; the exact meaning is agreed between publisher and receiver.', claims: [],
    example: scimSet('prov:deactivate', scimUser, {}) },
  { slug: 'misc:asyncresp', spec: 'scim', name: 'Asynchronous Request Completion', summary: 'An asynchronous SCIM request finished. The payload is the request’s SCIM Bulk response operation, and txn matches the value returned to the client when it made the request.', claims: [
      { name: 'method', req: 'REQUIRED', desc: 'The HTTP method of the request (POST, PUT, PATCH, DELETE).' },
      { name: 'status', req: 'REQUIRED', desc: 'The HTTP status of the result, e.g. "200" or "400".' },
      { name: 'response', req: 'OPTIONAL', desc: 'A SCIM error response; required when status is not 2xx.' },
      { name: 'bulkId', req: 'OPTIONAL', desc: 'The client’s bulkId, for operations from a Bulk request.' },
      version,
    ],
    example: scimSet('misc:asyncresp', { format: 'scim', uri: '/Users/2819c223-7f76-453a-919d-413861904646' }, { method: 'PUT', version: 'W/"huJj29dMNgu3WXPD"', status: '200' }, { txn: '734f0614e3274f288f93ac74119dcf78' }) },
];
