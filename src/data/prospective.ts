// Prospective event types: profiles of the Shared Signals Framework that are still being drafted.
// They render on /events/ under a "prospective" banner and are deliberately kept out of EVENTS, so
// the sample Transmitter does not advertise them in events_supported, the sample Receiver does not
// offer them, and the validator does not treat them as known. Event names, claims and values change
// between drafts, so re-check `source` before relying on anything here.
//
// Summaries are ours; the draft is the only authority, and it is not a final specification.

import type { Claim, EventType } from './events';

export type ProspectiveProfile = {
  id: EventType['spec'];
  name: string;
  title: string;
  draft: string;
  /** The draft source these entries were transcribed from, and when. */
  source: string;
  sync: { commit: string; checked: string };
  blurb: string;
};

export type ProspectiveEvent = EventType & { category: string };

export const PROSPECTIVE_PROFILES: ProspectiveProfile[] = [
  {
    id: 'wise',
    name: 'WISE',
    title: 'Workload Identity Security Events (WISE)',
    draft: 'Draft 03',
    source: 'https://github.com/openid/ssf-wise-profile/blob/main/openid-wise-profile-1_0.md',
    sync: { commit: '7e09dce', checked: '2026-11-01' },
    blurb: 'Security events about non-human identities: the workloads, services and AI agents named by WIMSE or SPIFFE identifiers. WISE covers credential and key lifecycle, workload suspension and degraded trust, trust anchors and federation between trust domains, issuance and validation policy, posture evaluation, runtime detections, and supply-chain provenance. Where CAEP and RISC describe users’ sessions and accounts, WISE describes workloads and the trust domains that issue their credentials. The subject is usually a uri sub_id holding a WIMSE workload identifier, or the bare trust domain (wimse://trust.example.com) for trust, federation and policy events.',
  },
];

// ── WISE draft 03 ──────────────────────────────────────────────────────
const WISE_BASE = 'https://schemas.openid.net/secevent/wise/event-type/';
const wiseCommon: Claim[] = [
  { name: 'event_timestamp', req: 'REQUIRED', desc: 'When the event occurred, or the decision or detection was made (NumericDate). Required on every WISE event, unlike CAEP.' },
  { name: 'effective_at', req: 'OPTIONAL', desc: 'When the change takes effect (NumericDate); may be in the past or future. Absent means effective from the SET’s iat.' },
  { name: 'initiating_entity', req: 'OPTIONAL', desc: 'As in CAEP: admin, user, policy, or system.' },
  { name: 'reason_admin / reason_user', req: 'OPTIONAL', desc: 'As in CAEP, and always a language-keyed object such as {"en": "…"}, never a plain string.' },
];
const credentialTypes = 'wit, wic, x509_svid, x509_generic, oauth_private_key_jwt, oauth_mtls, oauth_client_secret, or api_key.';
const credType = (verb: string): Claim => ({ name: 'credential_type', req: 'REQUIRED', desc: `The kind of credential ${verb}: ${credentialTypes}` });
const credId = (what: string): Claim => ({ name: 'credential_id', req: 'OPTIONAL', desc: `Identifier of the ${what} credential, e.g. a certificate serial or jti.` });
const anchorType: Claim = { name: 'anchor_type', req: 'REQUIRED', desc: 'x509_ca or jwks.' };
const trustDomain = (what: string): Claim => ({ name: 'trust_domain', req: 'REQUIRED', desc: `FQDN of the trust domain ${what}.` });
const bundles = (what: string): Claim[] => [
  { name: 'jwks_uri', req: 'OPTIONAL', desc: `For jwks anchors, where to fetch the JWK Set ${what}.` },
  { name: 'x509_bundle_uri', req: 'OPTIONAL', desc: `For x509_ca anchors, where to fetch the CA bundle ${what}.` },
];
const reason = (values: string): Claim => ({ name: 'reason', req: 'OPTIONAL', desc: values });
const policyId: Claim = { name: 'policy_id', req: 'OPTIONAL', desc: 'Identifier of the policy that changed.' };

const workload = { format: 'uri', uri: 'wimse://trust.example.com/workload/payment-service' };
const domain = (d: string) => ({ format: 'uri', uri: `wimse://${d}` });
const RP = 'https://rp.partner.example.net/wise';
const PEER = 'https://federation-peer.example.net/wise';
// The examples follow the draft's figures.
const wiseSet = (jti: string, slug: string, sub: Record<string, unknown>, body: Record<string, unknown>, { aud = RP, iat = 1700000000 } = {}) => ({
  iss: 'https://authority.example.com/',
  jti: `wise-evt-${jti}`,
  iat,
  aud,
  sub_id: sub,
  events: { [WISE_BASE + slug]: { ...body, event_timestamp: iat } },
});

const wise = (category: string, slug: string, name: string, summary: string, claims: Claim[], example: Record<string, unknown>): ProspectiveEvent =>
  ({ spec: 'wise', category, slug, name, summary, claims: [...claims, ...wiseCommon], example });

const CRED = 'Credential lifecycle';
const LIFE = 'Workload lifecycle';
const TRUST = 'Trust and federation';
const POLICY = 'Policy and posture evaluation';
const RUNTIME = 'Runtime posture';
const SUPPLY = 'Supply chain';

export const WISE_EVENTS: ProspectiveEvent[] = [
  // Credential lifecycle
  wise(CRED, 'credential-issued', 'Credential Issued',
    'The trust domain authority issued a new credential to the workload.',
    [credType('issued'), credId('issued'),
      { name: 'expiry', req: 'OPTIONAL', desc: 'When the credential expires (NumericDate).' },
      { name: 'key_storage', req: 'OPTIONAL', desc: 'Where the bound private key lives: software, software_encrypted, hardware_tpm, hardware_hsm, hardware_secure_enclave, vaulted, or unknown.' },
      { name: 'key_storage_ecosystem', req: 'OPTIONAL', desc: 'Free text naming the environment that protects the key, e.g. "AWS Nitro Enclave".' }],
    wiseSet('001', 'credential-issued', workload, { credential_type: 'wic', credential_id: 'serial:ABC123DEF456', expiry: 1700086400 })),
  wise(CRED, 'credential-rotated', 'Credential Rotated',
    'A new credential replaced the workload’s previous one, optionally with a grace period during which both are valid.',
    [credType('rotated'),
      { name: 'previous_credential_id', req: 'OPTIONAL', desc: 'The credential being replaced.' },
      { name: 'new_credential_id', req: 'OPTIONAL', desc: 'The replacement credential.' },
      { name: 'grace_period_end', req: 'OPTIONAL', desc: 'Until when the previous credential stays valid (NumericDate).' }],
    wiseSet('002', 'credential-rotated', workload, { credential_type: 'wit', previous_credential_id: 'jti:wit-2024-q4-001', new_credential_id: 'jti:wit-2024-q4-002', grace_period_end: 1700003600 })),
  wise(CRED, 'credential-revoked', 'Credential Revoked',
    'A workload credential was revoked before it expired. A compromised proof-of-possession key is signalled this way too, with reason key_compromise.',
    [credType('revoked'), credId('revoked'), reason('compromise, key_compromise, superseded, cessation, or policy_violation.')],
    wiseSet('003', 'credential-revoked', workload, { credential_type: 'wic', credential_id: 'serial:ABC123DEF456', reason: 'compromise' })),
  wise(CRED, 'credential-compromised', 'Credential Compromised',
    'Advisory: a workload credential is believed compromised. It may come before, or alongside, a Credential Revoked event.',
    [credType('compromised'), credId('compromised')],
    wiseSet('004', 'credential-compromised', workload, { credential_type: 'wit', credential_id: 'jti:wit-signing-key-2024-q4', reason_admin: { en: 'Private key material detected in public repository' } })),
  wise(CRED, 'credential-renewal-failure', 'Credential Renewal Failure',
    'Automatic renewal of a short-lived workload credential failed, so the workload may be unable to authenticate once the current credential expires.',
    [credType('that failed to renew'), credId('unrenewed'),
      { name: 'current_expiry', req: 'OPTIONAL', desc: 'When the last valid credential expires (NumericDate).' },
      { name: 'failure_reason', req: 'OPTIONAL', desc: 'credential_service_unreachable, posture_evaluation_failed, policy_denied, or internal_error.' }],
    wiseSet('005', 'credential-renewal-failure', workload, { credential_type: 'wit', current_expiry: 1700003600, failure_reason: 'posture_evaluation_failed' })),

  // Workload lifecycle
  wise(LIFE, 'workload-disabled', 'Workload Disabled',
    'The authority suspended the workload and will issue it no credentials. The cancelled credentials are announced separately, as Credential Revoked events sharing the same txn.',
    [reason('compromise, policy_violation, administrative, or maintenance.')],
    wiseSet('010', 'workload-disabled', workload, { reason: 'compromise' })),
  wise(LIFE, 'workload-enabled', 'Workload Enabled',
    'A disabled workload is active again and credential issuance resumes; any new credential is announced with Credential Issued.',
    [],
    wiseSet('011', 'workload-enabled', workload, {}, { iat: 1700003600 })),
  wise(LIFE, 'workload-degraded', 'Workload Degraded',
    'The authority reduced the workload’s trust without suspending it, so it keeps running with fewer privileges (for example, no database writes, or network quarantine) instead of being shut down.',
    [{ name: 'trust_level', req: 'REQUIRED', desc: 'The new level, from highest to lowest: reduced, restricted, or minimal.' },
      { name: 'previous_trust_level', req: 'OPTIONAL', desc: 'The level before, on the same scale plus full. If absent, assume nothing about it.' },
      reason('anomaly_detected, policy_drift, missing_provenance, posture_degraded, or compliance_drift.')],
    wiseSet('013', 'workload-degraded', workload, { trust_level: 'restricted', previous_trust_level: 'full', reason: 'anomaly_detected' })),
  wise(LIFE, 'workload-restored', 'Workload Restored',
    'A degraded workload is back at full trust. Advisory: each Receiver restores privileges under its own policy.',
    [{ name: 'previous_trust_level', req: 'OPTIONAL', desc: 'reduced, restricted, or minimal.' },
      reason('remediated, posture_restored, or administrative.')],
    wiseSet('014', 'workload-restored', workload, { previous_trust_level: 'restricted', reason: 'remediated' }, { iat: 1700003600 })),
  wise(LIFE, 'workload-purged', 'Workload Purged',
    'The workload was permanently removed from the trust domain and will not come back; every credential ever issued to it is invalid.',
    [],
    wiseSet('012', 'workload-purged', workload, {})),

  // Trust and federation
  wise(TRUST, 'trust-anchor-added', 'Trust Anchor Added',
    'A new trust anchor joins the domain’s existing ones, for example a key staged ahead of rotation or a new region. Receivers must start accepting it.',
    [anchorType, trustDomain('the anchor belongs to'),
      { name: 'key_id', req: 'OPTIONAL', desc: 'The anchor’s kid (JWKS), or serial or Subject Key Identifier (X.509).' },
      { name: 'key_details', req: 'OPTIONAL', desc: 'Selected JWK parameters of the new key (kty required; alg, use, crv optional) so a Receiver can act without fetching the bundle.' },
      ...bundles('with the new anchor'),
      reason('new_environment, additional_key, or scheduled_rotation.')],
    wiseSet('020', 'trust-anchor-added', domain('trust.example.com'), { anchor_type: 'jwks', trust_domain: 'trust.example.com', jwks_uri: 'https://authority.example.com/.well-known/jwks.json', key_id: 'kid:ecdsa-2026', key_details: { kty: 'EC', alg: 'ES256', use: 'sig', crv: 'P-256' }, effective_at: 1700000000, reason: 'additional_key' }, { aud: PEER })),
  wise(TRUST, 'trust-anchor-rotated', 'Trust Anchor Rotated',
    'New material replaced one of the domain’s trust anchors. Receivers must accept the new anchor, and should drop the old one when any grace period ends.',
    [anchorType, trustDomain('whose anchor rotated'),
      { name: 'previous_key_id', req: 'OPTIONAL', desc: 'The anchor being replaced.' },
      { name: 'new_key_id', req: 'OPTIONAL', desc: 'The replacement anchor.' },
      ...bundles('with the new anchor'),
      { name: 'old_material_expiry', req: 'OPTIONAL', desc: 'When the old material stops being valid (NumericDate).' },
      reason('scheduled_rotation, compromise, policy_change, or expiry.')],
    wiseSet('021', 'trust-anchor-rotated', domain('trust.example.com'), { anchor_type: 'jwks', trust_domain: 'trust.example.com', previous_key_id: 'kid:signing-2024-q4', new_key_id: 'kid:signing-2025-q1', jwks_uri: 'https://authority.example.com/.well-known/jwks.json', effective_at: 1700000000, old_material_expiry: 1700604800, reason: 'scheduled_rotation' }, { aud: PEER })),
  wise(TRUST, 'trust-anchor-revoked', 'Trust Anchor Revoked',
    'A trust anchor was withdrawn, whether compromised or at end of life, and must no longer validate any credential.',
    [anchorType, trustDomain('whose anchor was revoked'),
      { name: 'key_id', req: 'OPTIONAL', desc: 'The revoked anchor’s kid, serial or Subject Key Identifier.' },
      ...bundles('without the revoked anchor'),
      reason('compromise, policy_change, superseded, or expiry.')],
    wiseSet('022', 'trust-anchor-revoked', domain('trust.example.com'), { anchor_type: 'x509_ca', trust_domain: 'trust.example.com', key_id: 'serial:CA-ROOT-2023-001', reason: 'compromise' }, { aud: PEER })),
  wise(TRUST, 'trust-domain-federation-established', 'Federation Established',
    'Another trust domain was federated: Receivers may start accepting its workloads’ credentials, validated against its anchors.',
    [trustDomain('now federated'),
      { name: 'anchor_type', req: 'OPTIONAL', desc: 'x509_ca or jwks, for the new domain’s trust material.' },
      ...bundles('for the federated domain'),
      reason('onboarding, expansion, administrative, or contractual.')],
    wiseSet('023', 'trust-domain-federation-established', domain('newpartner.example.org'), { trust_domain: 'newpartner.example.org', anchor_type: 'jwks', jwks_uri: 'https://authority.newpartner.example.org/.well-known/jwks.json', effective_at: 1700000000, reason: 'onboarding' }, { aud: PEER })),
  wise(TRUST, 'trust-domain-federation-updated', 'Federation Updated',
    'The terms of an existing federation changed, such as which workloads or anchors are trusted, but the domain is still trusted.',
    [trustDomain('whose federation changed'), reason('policy_change, anchor_update, administrative, or contractual.')],
    wiseSet('024', 'trust-domain-federation-updated', domain('newpartner.example.org'), { trust_domain: 'newpartner.example.org', reason: 'anchor_update', effective_at: 1700000000 }, { aud: PEER })),
  wise(TRUST, 'trust-domain-federation-revoked', 'Federation Revoked',
    'A federated trust domain is no longer trusted; Receivers must reject every workload credential from it.',
    [trustDomain('no longer trusted'), reason('compromise, policy_violation, administrative, or contractual.')],
    wiseSet('025', 'trust-domain-federation-revoked', domain('partner.example.org'), { trust_domain: 'partner.example.org', reason: 'administrative', effective_at: 1700604800 }, { aud: PEER })),

  // Policy and posture evaluation
  wise(POLICY, 'issuance-policy-changed', 'Issuance Policy Changed',
    'The policy for issuing workload credentials changed: who is eligible, which credential types, lifetimes, or required posture evidence.',
    [policyId],
    wiseSet('050', 'issuance-policy-changed', domain('trust.example.com'), { policy_id: 'policy:issuance-v3', effective_at: 1700000000 })),
  wise(POLICY, 'posture-evaluation-policy-changed', 'Posture Evaluation Policy Changed',
    'The rules for evaluating a workload’s posture before issuance or renewal changed: the evidence required, or the criteria applied.',
    [policyId],
    wiseSet('051', 'posture-evaluation-policy-changed', domain('trust.example.com'), { policy_id: 'policy:posture-eval-v2', effective_at: 1700000000 })),
  wise(POLICY, 'validation-policy-changed', 'Validation Policy Changed',
    'The policy relying parties use to validate workload credentials changed: anchor rules, claim checks, audiences, or acceptable credential types.',
    [policyId],
    wiseSet('052', 'validation-policy-changed', domain('trust.example.com'), { policy_id: 'policy:validation-v5', effective_at: 1700000000 })),
  wise(POLICY, 'posture-evaluation-failed', 'Posture Evaluation Failed',
    'The workload’s platform, software integrity or deployment context did not meet the requirements for a credential.',
    [{ name: 'evaluation_type', req: 'OPTIONAL', desc: 'platform, workload, or runtime.' },
      reason('platform_integrity_failed, attestation_invalid, image_mismatch, configuration_noncompliant, or policy_denied.')],
    wiseSet('053', 'posture-evaluation-failed', workload, { evaluation_type: 'platform', reason: 'platform_integrity_failed' })),
  wise(POLICY, 'posture-evaluation-succeeded', 'Posture Evaluation Succeeded',
    'The workload passed posture evaluation as part of normal provisioning, and a credential was or will be issued.',
    [{ name: 'evaluation_type', req: 'OPTIONAL', desc: 'platform, workload, or runtime.' }],
    wiseSet('054', 'posture-evaluation-succeeded', workload, { evaluation_type: 'workload' })),

  // Runtime posture
  wise(RUNTIME, 'workload-baseline-changed', 'Workload Baseline Changed',
    'The workload’s runtime environment or deployment context changed (migration, scaling, a new image), which may call for re-evaluating trust.',
    [reason('migration, scaling, redeployment, image_update, config_change, or node_reassignment.'),
      { name: 'previous_context / current_context', req: 'OPTIONAL', desc: 'The environment before and after, with comparable keys such as region, zone, platform, cluster, image.' },
      { name: 'posture_evaluation_status', req: 'OPTIONAL', desc: 'Whether posture was re-evaluated: succeeded, pending, or failed.' }],
    wiseSet('030', 'workload-baseline-changed', workload, { reason: 'migration', previous_context: { region: 'us-east-1', platform: 'kubernetes' }, current_context: { region: 'eu-west-1', platform: 'kubernetes' }, posture_evaluation_status: 'succeeded' })),
  wise(RUNTIME, 'workload-compromised', 'Workload Compromised',
    'High severity: runtime detection suggests the workload is compromised. It should prompt isolation, and a credential authority should also send Credential Revoked (reason compromise) sharing the same txn.',
    [{ name: 'detection_method', req: 'OPTIONAL', desc: 'How the compromise was detected.' }],
    wiseSet('060', 'workload-compromised', workload, { detection_method: 'runtime-anomaly-detection' })),
  wise(RUNTIME, 'anomalous-behavior-detected', 'Anomalous Behavior Detected',
    'Advisory, lower severity than Workload Compromised: unusual behaviour was observed. Intended for SIEM and SOC pipelines.',
    [{ name: 'anomaly_type', req: 'OPTIONAL', desc: 'Category of the anomaly.' },
      { name: 'severity', req: 'OPTIONAL', desc: 'low, medium, high, or critical.' }],
    wiseSet('061', 'anomalous-behavior-detected', workload, { anomaly_type: 'unexpected-egress', severity: 'medium' })),

  // Supply chain
  wise(SUPPLY, 'workload-provenance-changed', 'Provenance Changed',
    'The workload’s provenance, such as an SBOM or build attestation, was updated, revoked, or failed verification.',
    [{ name: 'change_type', req: 'REQUIRED', desc: 'updated, revoked, or verification_failed.' },
      { name: 'provenance_uri', req: 'OPTIONAL', desc: 'Where to fetch the provenance document.' },
      { name: 'provenance_format', req: 'OPTIONAL', desc: 'A hint at the kind of document, e.g. sbom or attestation.' },
      { name: 'artifact_digest', req: 'OPTIONAL', desc: 'Digest of the artifact (e.g. container image) the provenance describes.' }],
    wiseSet('040', 'workload-provenance-changed', workload, { change_type: 'revoked', provenance_uri: 'https://provenance.example.com/payment-service/attestation', reason_admin: { en: 'Build provenance attestation revoked by source repository owner' } })),
  wise(SUPPLY, 'workload-vulnerability-status-changed', 'Vulnerability Status Changed',
    'The workload’s status for a known vulnerability changed, following the VEX model. It can raise a warning, or lift one when a vulnerability turns out not to apply or is fixed.',
    [{ name: 'vulnerability_id', req: 'REQUIRED', desc: 'A public identifier, such as a CVE.' },
      { name: 'status', req: 'REQUIRED', desc: 'affected, not_affected, fixed, or under_investigation.' },
      { name: 'severity', req: 'OPTIONAL', desc: 'low, medium, high, or critical.' },
      { name: 'advisory_uri', req: 'OPTIONAL', desc: 'Where to fetch the full advisory or VEX statement.' }],
    wiseSet('041', 'workload-vulnerability-status-changed', workload, { vulnerability_id: 'CVE-2026-12345', status: 'affected', severity: 'critical', advisory_uri: 'https://advisories.example.com/CVE-2026-12345' })),
];

export const PROSPECTIVE_EVENTS: ProspectiveEvent[] = [...WISE_EVENTS];
