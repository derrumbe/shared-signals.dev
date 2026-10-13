---
layout: ../../layouts/Learn.astro
title: Transmitter discovery
description: The /.well-known/ssf-configuration document and how Receivers use it to find a Transmitter's keys, endpoints and capabilities.
---

<p class="eyebrow">Learn · Discovery</p>

# Transmitter discovery

A Receiver starts with nothing but the Transmitter's **issuer** URL. Everything else comes from the
Transmitter Configuration Metadata, published at a well-known path.

## Where to find it

Insert `/.well-known/ssf-configuration` between the host and any path in the issuer:

| Issuer | Discovery URL |
|---|---|
| `https://tr.example.com` | `https://tr.example.com/.well-known/ssf-configuration` |
| `https://tr.example.com/issuer1` | `https://tr.example.com/.well-known/ssf-configuration/issuer1` |

The path form lets one host serve many issuers — common for multi-tenant products.

<div class="callout">
<p>Older RISC Transmitters published at <code>/.well-known/risc-configuration</code>. Receivers that
need to talk to them may fall back to that path.</p>
</div>

## The document

```json
{
  "spec_version": "1_0",
  "issuer": "https://tr.example.com",
  "jwks_uri": "https://tr.example.com/jwks.json",
  "delivery_methods_supported": ["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"],
  "configuration_endpoint": "https://tr.example.com/ssf/stream",
  "status_endpoint": "https://tr.example.com/ssf/status",
  "add_subject_endpoint": "https://tr.example.com/ssf/subjects:add",
  "remove_subject_endpoint": "https://tr.example.com/ssf/subjects:remove",
  "verification_endpoint": "https://tr.example.com/ssf/verify",
  "authorization_schemes": [{ "spec_urn": "urn:ietf:rfc:6749" }],
  "default_subjects": "NONE"
}
```

| Field | Required | Purpose |
|---|---|---|
| `issuer` | Yes | Must match `iss` in every SET and the URL you started from. |
| `jwks_uri` | — | Keys for verifying SET signatures. |
| `delivery_methods_supported` | — | Which of push/poll are available. |
| `configuration_endpoint` | — | Create, read, update, delete streams. |
| `status_endpoint` | — | Read and change stream status. |
| `add_subject_endpoint`, `remove_subject_endpoint` | — | Subject management. |
| `verification_endpoint` | — | Trigger verification events. |
| `authorization_schemes` | — | How to authenticate to the management API, e.g. OAuth 2.0 (`urn:ietf:rfc:6749`). |
| `default_subjects` | — | `ALL` or `NONE`. |
| `critical_subject_members` | — | Complex-subject members the Receiver must understand. |
| `spec_version` | — | `1_0` for the final spec; absent means the older `1_0-ID1` draft. |

<div class="callout">
<p><strong>Interop baseline.</strong> The <a href="/specs/caep-interop/">CAEP Interoperability Profile</a> makes
<code>spec_version</code>, <code>jwks_uri</code>, <code>delivery_methods_supported</code>, <code>configuration_endpoint</code>,
<code>status_endpoint</code>, <code>verification_endpoint</code> and an OAuth 2.0 <code>authorization_schemes</code> entry mandatory.</p>
</div>

## Validate before you trust

- Only fetch discovery from an issuer you got from a trusted source, over `https`.
- Confirm the `issuer` in the document equals the issuer you used to build the URL.
