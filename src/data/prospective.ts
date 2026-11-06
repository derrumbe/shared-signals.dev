// Prospective event types: profiles of the Shared Signals Framework that are still being drafted.
// They render on /events/ under a "prospective" banner and are deliberately kept out of EVENTS, so
// the sample Transmitter does not advertise them in events_supported, the sample Receiver does not
// offer them, and the validator does not treat them as known. Event names, claims and values change
// between drafts, so re-check `source` before relying on anything here.
//
// Summaries are ours; each draft is the only authority for its events, and none is a final specification.

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
  /** Caveats specific to this profile, shown under its blurb. */
  notes?: string[];
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
  {
    id: 'iitp',
    name: 'IITP',
    title: 'Internet Infrastructure Threat Profile (IITP)',
    draft: 'Draft 02',
    source: 'https://github.com/derrumbe/openid-iitp/blob/main/openid-iitp-1_0.md',
    sync: { commit: '94bcbe2', checked: '2026-11-06' },
    blurb: 'Environment-level detections. CAEP and RISC describe one user, device, session or account; IITP describes the environment they operate in — a cloud account whose entitlements drifted, a tenant under an active campaign, a workload whose supply chain was poisoned — where the response is taken for a whole tenant, role or workload at once. The Transmitter is a detection provider (a CIEM, SIEM, or runtime security product). IITP events are detections, not commands: severity, confidence and recommended_actions advise, and the Receiver decides what to do. Subjects are often the environment subject format IITP defines (environment_type, id, and optionally provider and domain), or a complex subject pairing an environment with a workload.',
    notes: [
      'IITP’s workload-compromised deliberately shares its name with the WISE event: the same fact reported by a detection provider rather than by the trust domain authority that issued the workload’s credentials.',
      'The draft specifies these three event types. Further candidates are tracked in its separate event catalogue and are not listed here.',
    ],
  },
  {
    id: 'mle',
    name: 'MLE',
    title: 'Mandate Lifecycle Events (MLE)',
    draft: 'Review draft',
    source: 'https://github.com/soosproject/MLE',
    sync: { commit: '3789b12', checked: '2026-11-06' },
    blurb: 'Changes to an AI agent’s mandate: the bounded authority a principal delegated to it, as distinct from its credential or its current task. WISE says whether a workload is authenticated; MLE says whether it is still authorised to be doing what it is doing. Mandates are requested, granted, exercised, replaced (never edited), suspended and revoked, with revocation able to cascade to every delegated child mandate. A revocation can be tracked to completion: Receivers acknowledge enforcement back to the issuer, which can issue a closure receipt. Subjects are a uri sub_id for the agent (using WISE’s workload identifiers), or a complex subject with principal and workload members for requests and grants.',
    notes: [
      'An initial review draft, not yet submitted to a working group. The event type URIs use the base https://schemas.openid.net/secevent/mandate/event-type/, which the draft marks as a placeholder.',
      'Mandate Revocation Enforced travels the other way: from the Receiver of a revocation back to the mandate’s issuer, over a separate stream.',
    ],
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

// ── IITP draft 02 ──────────────────────────────────────────────────────
// Examples are the draft's figures, verbatim.
const iitpCommon: Claim[] = [
  { name: 'severity', req: 'RECOMMENDED', desc: 'The Transmitter’s assessment: low, medium, high, or critical.' },
  { name: 'confidence', req: 'OPTIONAL', desc: 'How sure the Transmitter is that this is not a false positive: low, medium, or high. Receivers should weight automated, high-impact responses by it.' },
  { name: 'recommended_actions', req: 'OPTIONAL', desc: 'Advisory, never commands: freeze-non-admin-access, restrict-role-holders, elevate-detection, require-step-up-auth, restrict-cross-app-access, revoke-workload-identity, block-service-account-traffic, block-agent-communication, quarantine, monitor, or agreed values.' },
  { name: 'event_timestamp', req: 'OPTIONAL', desc: 'When the condition was detected (NumericDate), which may be later than when it arose.' },
  { name: 'initiating_entity', req: 'OPTIONAL', desc: 'What produced the detection: detector, policy, admin, or system.' },
  { name: 'reason_admin / reason_user', req: 'OPTIONAL', desc: 'As in CAEP: a language-keyed object such as {"en": "…"}. reason_user is often omitted, since these events are about environments.' },
];
const indicators: Claim = { name: 'indicators', req: 'OPTIONAL', desc: 'Indicators of compromise a Receiver can use to tune its own detection: objects with type (ip, asn, user-agent, domain, …) and value.' };
const iitp = (slug: string, name: string, summary: string, claims: Claim[], example: Record<string, unknown>): ProspectiveEvent =>
  ({ spec: 'iitp', category: 'Environment detections', slug, name, summary, claims: [...claims, ...iitpCommon], example });

export const IITP_EVENTS: ProspectiveEvent[] = [
  iitp('configuration-drift', 'Configuration Drift',
    'An environment’s security configuration moved away from its known-good state in a way that materially raises risk. The typical case is a privilege explosion: a role quietly gains powerful privileges, so everyone holding it now has far more access than intended. Send it again with drift_status reverted to let Receivers lift restrictions.',
    [{ name: 'drift_type', req: 'REQUIRED', desc: 'privilege-escalation, policy-change, resource-exposure, network-exposure, encryption-change, logging-disabled, or an agreed value.' },
      { name: 'resource', req: 'REQUIRED', desc: 'The item that drifted: type (e.g. iam-role, storage-bucket) and id (e.g. an ARN), optionally provider, region, account.' },
      { name: 'added_privileges / removed_privileges', req: 'OPTIONAL', desc: 'Privileges or controls the drift added or removed.' },
      { name: 'affected_principals', req: 'OPTIONAL', desc: 'Who holds the drifted resource, so Receivers can scope enforcement: count and an agreed selector (e.g. the role name).' },
      { name: 'baseline_ref', req: 'OPTIONAL', desc: 'Opaque reference to the known-good baseline, to correlate with a later reverted event.' },
      { name: 'drift_status', req: 'OPTIONAL', desc: 'detected (the default), persisting, or reverted.' }],
    { iss: 'https://ciem.example.com/', jti: 'f3a1c0de9b7e4a2f8c6d1e0b5a4f7c21', iat: 1782691200, aud: 'https://idp.example.com/ssf', txn: 'drift-2026-0001',
      sub_id: { format: 'environment', environment_type: 'cloud-account', provider: 'aws', id: '123456789012' },
      events: { 'https://schemas.openid.net/secevent/iitp/event-type/configuration-drift': {
        drift_type: 'privilege-escalation',
        resource: { type: 'iam-role', provider: 'aws', account: '123456789012', region: 'us-east-1', id: 'arn:aws:iam::123456789012:role/s3-bucket-admin' },
        added_privileges: ['eks:*', 'eks:AccessKubernetesApi'],
        affected_principals: { selector: 'role:s3-bucket-admin', count: 14 },
        baseline_ref: 'baseline-2026-06-01T00:00:00Z', drift_status: 'detected', severity: 'high', confidence: 'high', initiating_entity: 'detector',
        recommended_actions: ['restrict-role-holders', 'freeze-non-admin-access'],
        reason_admin: { en: 'Role s3-bucket-admin modified to include EKS cluster-admin privileges; treat role as poisoned until reverted.' },
        event_timestamp: 1782691180 } } }),
  iitp('asset-under-attack', 'Asset Under Attack',
    'An application, tenant, domain or organisation is the target of an active campaign — a password spray against a SaaS tenant, or a known adversary operating inside it — so connected applications can raise their guard. Follow-up events move attack_status to contained or resolved.',
    [{ name: 'attack_type', req: 'REQUIRED', desc: 'password-spray, credential-stuffing, brute-force, account-takeover, mfa-fatigue, data-exfiltration, api-abuse, reconnaissance, adversary-presence, or an agreed value.' },
      { name: 'attack_status', req: 'REQUIRED', desc: 'suspected, active, contained, or resolved.' },
      { name: 'scope', req: 'RECOMMENDED', desc: 'How broadly to respond: tenant, domain, application, or organization.' },
      { name: 'threat_actor', req: 'OPTIONAL', desc: 'Attribution, when known: name, attribution_confidence, and a reference URI.' },
      indicators,
      { name: 'recommended_posture', req: 'OPTIONAL', desc: 'Suggested detection sensitivity: normal, heightened, or maximum.' }],
    { iss: 'https://salesforce.example.com/', jti: '7c2e9a1b6f3d4e5a8b0c1d2e3f405162', iat: 1782700000, aud: 'https://servicenow.example.com/ssf', txn: 'attack-tenant-77',
      sub_id: { format: 'environment', environment_type: 'tenant', domain: 'example.com', id: '00D5e000000ABCdEAU' },
      events: { 'https://schemas.openid.net/secevent/iitp/event-type/asset-under-attack': {
        attack_type: 'password-spray', attack_status: 'active', scope: 'tenant', severity: 'high', confidence: 'high', recommended_posture: 'heightened',
        indicators: [{ type: 'asn', value: 'AS14061' }, { type: 'user-agent', value: 'python-requests/2.31' }],
        recommended_actions: ['elevate-detection', 'require-step-up-auth'], initiating_entity: 'detector',
        reason_admin: { en: 'High-volume password spray observed against tenant; integrated apps should raise detection sensitivity.' },
        event_timestamp: 1782699940 } } }),
  iitp('workload-compromised', 'Workload Compromised',
    'A deployed application, service, container or function is believed compromised — typically through its supply chain — and should no longer be trusted. Receivers can block its service account’s traffic, revoke its workload identity, or stop agents talking to it. Send trust_status restored once it is redeployed clean.',
    [{ name: 'compromise_type', req: 'REQUIRED', desc: 'supply-chain, build-pipeline, malicious-artifact, runtime-compromise, secret-exposure, or an agreed value.' },
      { name: 'trust_status', req: 'REQUIRED', desc: 'untrusted, quarantined, or restored.' },
      { name: 'workload', req: 'REQUIRED', desc: 'The workload, as precisely as possible: name, namespace, cluster, image, image_digest, service_account, spiffe_id.' },
      { name: 'affected_component', req: 'OPTIONAL', desc: 'The component believed responsible, e.g. a poisoned package: type, name, version.' },
      indicators],
    { iss: 'https://runtime-sec.example.com/', jti: '9b8a7c6d5e4f30211203a4b5c6d7e8f9', iat: 1782710000, aud: 'https://mesh.example.com/ssf', txn: 'wl-compromise-42',
      sub_id: { format: 'complex', environment: { format: 'environment', environment_type: 'k8s-cluster', id: 'prod-cluster-eu-1' }, workload: { format: 'opaque', id: 'payments-api@prod' } },
      events: { 'https://schemas.openid.net/secevent/iitp/event-type/workload-compromised': {
        compromise_type: 'supply-chain', trust_status: 'untrusted',
        workload: { name: 'payments-api', namespace: 'prod', cluster: 'prod-cluster-eu-1', image: 'registry.example.com/payments-api:1.8.3', image_digest: 'sha256:5e0c...a91f', service_account: 'payments-api-sa', spiffe_id: 'spiffe://example.com/ns/prod/sa/payments-api-sa' },
        affected_component: { type: 'package', name: 'left-pad-utils', version: '4.2.0' },
        severity: 'critical', confidence: 'high', initiating_entity: 'detector',
        recommended_actions: ['revoke-workload-identity', 'block-service-account-traffic', 'block-agent-communication'],
        reason_admin: { en: 'Supply-chain compromise via poisoned dependency left-pad-utils@4.2.0; do not trust payments-api service account.' },
        event_timestamp: 1782709950 } } }),
];

// ── MLE review draft ───────────────────────────────────────────────────
// Base URI is a placeholder in the draft. Examples are the draft's figures, verbatim.
const MLE_BASE = 'https://schemas.openid.net/secevent/mandate/event-type/';
const mleCommon: Claim[] = [
  { name: 'event_timestamp', req: 'REQUIRED', desc: 'When the event occurred, or the decision or detection was made (NumericDate). Receivers use it to order changes to the same mandate.' },
  { name: 'effective_at', req: 'OPTIONAL', desc: 'When the change takes effect (NumericDate), as in WISE. A future value on Mandate Revoked schedules the revocation.' },
  { name: 'initiating_entity', req: 'OPTIONAL', desc: 'As in CAEP: admin, user, policy, or system.' },
  { name: 'reason_admin / reason_user', req: 'OPTIONAL', desc: 'As in CAEP, and always a language-keyed object such as {"en": "…"}.' },
];
const mandateId: Claim = { name: 'mandate_id', req: 'OPTIONAL', desc: 'Identifier of the mandate, e.g. a jti; preferably per-audience.' };
const mandateType: Claim = { name: 'mandate_type', req: 'REQUIRED', desc: 'root, or child (delegated from a parent mandate).' };
const parentId: Claim = { name: 'parent_mandate_id', req: 'OPTIONAL', desc: 'The parent mandate, when mandate_type is child.' };
const scopeDigest: Claim = { name: 'scope_digest', req: 'OPTIONAL', desc: 'Digest of the authoritative mandate, so a Receiver that holds it can confirm the version without the event disclosing it.' };
const scopeRef: Claim = { name: 'scope_ref', req: 'OPTIONAL', desc: 'URI where an authorised Receiver can fetch the authoritative mandate.' };
const scopeSummary: Claim = { name: 'scope_summary', req: 'OPTIONAL', desc: 'Free-text, advisory description of the authority. Not sent outside internal Receivers unless policy allows.' };
const cascade = (kind: string): Claim[] => [
  { name: `${kind}_type`, req: 'REQUIRED', desc: `direct, or cascade (applies to every descendant mandate too).` },
  { name: 'cascade_root_mandate_id', req: 'REQUIRED', desc: `The mandate the cascade started from. Required only when ${kind}_type is cascade.` },
];
const agent = { format: 'uri', uri: 'wimse://trust.example.com/workload/procurement-negotiator' };
const grantSubject = { format: 'complex', principal: { format: 'email', email: 'procurement-lead@example.com' }, workload: agent };
const mleSet = (jti: string, slug: string, sub: Record<string, unknown>, body: Record<string, unknown>,
  { aud = 'https://vendor.partner.example.net/mle', iat = 1700000000, iss = 'https://authority.example.com/', txn }: { aud?: string; iat?: number; iss?: string; txn?: string } = {}) => ({
  iss, jti, iat, aud, ...(txn ? { txn } : {}), sub_id: sub,
  events: { [MLE_BASE + slug]: body },
});
const PDP = 'https://pdp.trust.example.com/mle';

const mle = (category: string, slug: string, name: string, summary: string, claims: Claim[], example: Record<string, unknown>): ProspectiveEvent =>
  ({ spec: 'mle', typeBase: MLE_BASE, category, slug, name, summary, claims: [...claims, ...mleCommon], example });

const REQ = 'Request and grant';
const USE = 'Use and change';
const STOP = 'Suspension and revocation';
const ANOM = 'Anomaly';
const CLOSE = 'Revocation closure';

export const MLE_EVENTS: ProspectiveEvent[] = [
  mle(REQ, 'mandate-requested', 'Mandate Requested',
    'An agent asked a principal for a mandate. It reports that the request was made; the decision follows separately as Mandate Granted or Mandate Denied.',
    [mandateType, parentId, scopeDigest, scopeSummary],
    mleSet('evt-098', 'mandate-requested', grantSubject, { mandate_type: 'root', scope_digest: 'sha-256:mVq2wGZ7k1tYc0x9Ld4hPj8sRb6NfAe3Uo5iKyTnHw0', scope_summary: 'Negotiate vendor contracts up to $50,000, Q3 procurement cycle', event_timestamp: 1700000000 }, { aud: PDP })),
  mle(REQ, 'mandate-denied', 'Mandate Denied',
    'A requested mandate was not granted.',
    [reason('Why, e.g. insufficient_authority, policy_denied, or duplicate_request.')],
    mleSet('evt-099', 'mandate-denied', grantSubject, { reason: 'policy_denied', reason_admin: { en: 'Requested scope exceeds delegation policy for this role' }, event_timestamp: 1700000000 }, { aud: PDP })),
  mle(REQ, 'mandate-granted', 'Mandate Granted',
    'A principal issued a new mandate to an agent: bounded authority to act on their behalf.',
    [mandateType, mandateId, parentId, scopeRef, scopeDigest, scopeSummary,
      { name: 'expiry', req: 'OPTIONAL', desc: 'When the mandate expires (NumericDate).' }],
    mleSet('evt-100', 'mandate-granted', grantSubject, { mandate_type: 'root', mandate_id: 'mandate-2026-q3-0091', scope_ref: 'https://authority.example.com/mandates/mandate-2026-q3-0091', scope_digest: 'sha-256:3Rk8YbLq0ZtW5vNcJx2Gp7HdSa9Mf1Ue4Ko6Ti_yBhE', scope_summary: 'Negotiate vendor contracts up to $50,000, Q3 procurement cycle', expiry: 1706745600, event_timestamp: 1700000000 }, { aud: PDP })),
  mle(USE, 'mandate-executed', 'Mandate Executed',
    'The mandate was exercised, and a credential was issued to carry that authority into a call or transaction. The SET’s txn matches the token’s, so a Receiver can link tokens to mandates and later stop honouring in-flight tokens when the mandate is revoked. Expect it many times per mandate.',
    [mandateId,
      { name: 'credential_type', req: 'REQUIRED', desc: 'opaque, jwt, txn_access_token (Transactional Access Token, for Receivers outside the trust domain), txn_token, or an agreed value.' },
      { name: 'credential_id', req: 'OPTIONAL', desc: 'The issued credential’s jti.' }],
    mleSet('evt-101', 'mandate-executed', agent, { mandate_id: 'mandate-2026-q3-0091', credential_type: 'txn_access_token', credential_id: '0f8b6a4e-2d1c-4b7e-9a3f-6c5d4e3b2a10', event_timestamp: 1700000000 }, { txn: 'k3JdQ9vX2mPz7LwR5tYb8A' })),
  mle(USE, 'mandate-rotated', 'Mandate Rotated',
    'A successor mandate replaced the agent’s mandate. Mandates are never edited in place: renewing, narrowing or widening one issues a new mandate_id. Narrowing takes effect at once; widening must not be honoured until the Receiver has verified the successor.',
    [{ name: 'previous_mandate_id / new_mandate_id', req: 'OPTIONAL', desc: 'The mandate replaced, and its successor.' },
      { name: 'change_class', req: 'REQUIRED', desc: 'renewal (same scope), narrowed (strictly less authority), or expanded (more authority in any respect).' },
      { name: 'scope_ref / scope_digest', req: 'OPTIONAL', desc: 'For the successor mandate.' },
      { name: 'grace_period_end', req: 'OPTIONAL', desc: 'Until when the previous mandate is still acceptable (NumericDate). Never on a narrowed rotation.' }],
    mleSet('evt-102', 'mandate-rotated', agent, { previous_mandate_id: 'mandate-2026-q3-0091', new_mandate_id: 'mandate-2026-q3-0092', change_class: 'narrowed', scope_digest: 'sha-256:Wc5pAz1QhL8tYe3Rn0Kg6VbXu2Mj9Do4Fs7Ii_NqTkU', event_timestamp: 1700000000 })),
  mle(STOP, 'mandate-revoked', 'Mandate Revoked',
    'The agent’s mandate was revoked before it expired, though its credential is still valid. A cascade revokes every delegated child mandate too, one SET per mandate sharing a txn. Receivers must not commit pending work done under it.',
    [mandateId, ...cascade('revocation'),
      reason('principal_revoked, scope_violation, constitutional_violation, irreversible_threshold, compromise, non_response, deadlock, scheduled_rotation, operator_override, or an agreed value.'),
      { name: 'suspension_id', req: 'OPTIONAL', desc: 'The suspension this revocation concludes, if any.' }],
    mleSet('evt-103', 'mandate-revoked', agent, { mandate_id: 'mandate-2026-q3-0092', revocation_type: 'cascade', cascade_root_mandate_id: 'mandate-2026-q3-0091', reason: 'principal_revoked', reason_admin: { en: 'Q3 procurement budget reduced; vendor negotiation halted' }, event_timestamp: 1700000000 }, { txn: 'Rk2vQ8sLmN4pZx7Tb1Ye9w' })),
  mle(STOP, 'mandate-suspended', 'Mandate Suspended',
    'The mandate must not be exercised until the suspension is lifted, but it has not been revoked — typically on an unconfirmed outside report of compromise or misuse. Receivers hold in-progress transactions and keep the mandate’s state. The mandate-level counterpart of WISE’s Workload Disabled.',
    [mandateId,
      { name: 'suspension_id', req: 'REQUIRED', desc: 'Identifies this suspension, the same in every SET about it.' },
      ...cascade('suspension'),
      reason('reported_compromise, reported_violation, pending_review, or an agreed value. Never compromise: a confirmed compromise is a revocation.')],
    mleSet('evt-105', 'mandate-suspended', agent, { mandate_id: 'mandate-2026-q3-0092', suspension_id: 'susp-0192a7c4', suspension_type: 'direct', reason: 'reported_compromise', initiating_entity: 'system', event_timestamp: 1700000000 }, { txn: 'occ-5e21' })),
  mle(STOP, 'mandate-resumed', 'Mandate Resumed',
    'A suspension was lifted without revoking the mandate, restoring it exactly as before. After a reported compromise, Receivers confirm the mandate’s status with the issuer before resuming. The counterpart of WISE’s Workload Enabled.',
    [mandateId,
      { name: 'suspension_id', req: 'REQUIRED', desc: 'The suspension being lifted.' },
      ...cascade('suspension')],
    mleSet('evt-106', 'mandate-resumed', agent, { mandate_id: 'mandate-2026-q3-0092', suspension_id: 'susp-0192a7c4', suspension_type: 'direct', initiating_entity: 'user', event_timestamp: 1700003600 }, { iat: 1700003600 })),
  mle(ANOM, 'mandate-violation-detected', 'Mandate Violation Detected',
    'Advisory: the agent tried, or was found to have taken, an action beyond its mandate. It may precede a revocation but does not require one.',
    [mandateId,
      { name: 'violation_type', req: 'OPTIONAL', desc: 'scope_exceeded, or narrowing_violation (a child mandate claiming more than its parent).' }],
    mleSet('evt-104', 'mandate-violation-detected', agent, { mandate_id: 'mandate-2026-q3-0092', violation_type: 'scope_exceeded', reason_admin: { en: 'Attempted contract value of $75,000 exceeds mandate ceiling of $50,000' }, event_timestamp: 1700000000 })),
  mle(CLOSE, 'mandate-revocation-enforced', 'Mandate Revocation Enforced',
    'Sent back by a Receiver of Mandate Revoked to the mandate’s issuer, over a separate stream: it applied the revocation at its own enforcement points, or could not. Its txn matches the revocation it acknowledges.',
    [{ name: 'mandate_id', req: 'REQUIRED', desc: 'As received in the Mandate Revoked SET.' },
      { name: 'acknowledged_jti', req: 'REQUIRED', desc: 'The jti of the Mandate Revoked SET being acknowledged.' },
      { name: 'enforcement_status', req: 'REQUIRED', desc: 'enforced, partial, failed, or not_applicable.' },
      { name: 'pending_effects', req: 'REQUIRED', desc: 'What happened to work admitted before the revocation: none, cancelled, fenced, or unresolved.' },
      { name: 'scope', req: 'OPTIONAL', desc: 'Coarse classes of effect the status covers, e.g. ["api", "queue", "payment"].' }],
    mleSet('ack-7731', 'mandate-revocation-enforced', agent, { mandate_id: 'mandate-2026-q3-0092', acknowledged_jti: 'evt-103', enforcement_status: 'enforced', pending_effects: 'fenced', scope: ['api', 'queue'], event_timestamp: 1700000003 }, { iss: 'https://vendor.partner.example.net/', aud: 'https://authority.example.com/mle-ack', iat: 1700000004, txn: 'Rk2vQ8sLmN4pZx7Tb1Ye9w' })),
  mle(CLOSE, 'mandate-revocation-closure', 'Mandate Revocation Closure',
    'Optional closure receipt from the issuer of a revoked mandate, for the principal’s organisation or an auditor: how far the revocation has actually taken effect. It may be sent again as the status changes.',
    [{ name: 'mandate_id', req: 'REQUIRED', desc: 'The revoked mandate.' },
      { name: 'closure_status', req: 'REQUIRED', desc: 'propagating, closed, partial, failed, or unknown.' },
      { name: 'receivers_notified / receivers_enforced', req: 'OPTIONAL', desc: 'How many Receivers were sent the revocation, and how many acknowledged enforced or not_applicable.' },
      { name: 'unresolved', req: 'OPTIONAL', desc: 'Opaque per-audience identifiers of Receivers that reported partial or failed, or did not answer in time.' },
      { name: 'closure_budget', req: 'OPTIONAL', desc: 'The time budget the issuer allowed, in seconds.' },
      { name: 'evidence_digest', req: 'OPTIONAL', desc: 'Digest of the acknowledgements and audit records behind the status.' }],
    mleSet('evt-110', 'mandate-revocation-closure', agent, { mandate_id: 'mandate-2026-q3-0092', closure_status: 'closed', receivers_notified: 3, receivers_enforced: 3, closure_budget: 300, evidence_digest: 'sha-256:p8Jc2Ld7Qw0Hs5Nb3Yt9Ra1Ve6Ko4Mi_zUf2Gx7TqA', event_timestamp: 1700000058 }, { aud: 'https://audit.trust.example.com/mle', iat: 1700000060, txn: 'Vb3sN8qLwD1xRt6Yk0Pe4g' })),
];

export const PROSPECTIVE_EVENTS: ProspectiveEvent[] = [...WISE_EVENTS, ...IITP_EVENTS, ...MLE_EVENTS];
