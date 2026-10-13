---
layout: ../../layouts/Learn.astro
title: Subjects
description: How SSF identifies who or what an event is about — simple and complex subject identifiers, and subject management on streams.
---

<p class="eyebrow">Learn · Subjects</p>

# Subjects

The **subject** of an event is the thing it is about: a user, a device, a session, a tenant. SSF calls
these *subject principals* and identifies them with *subject identifiers* from
[RFC 9493](https://www.rfc-editor.org/rfc/rfc9493), plus a few formats SSF adds.

## Simple subjects

One identifier, one `format`:

```json
{ "format": "email", "email": "alice@example.com" }
{ "format": "iss_sub", "iss": "https://idp.example.com/", "sub": "248289761001" }
{ "format": "opaque", "id": "11112222333344445555" }
{ "format": "phone_number", "phone_number": "+12065550100" }
```

| Format | Defined in |
|---|---|
| `account`, `email`, `iss_sub`, `opaque`, `phone_number`, `did`, `uri`, `aliases` | RFC 9493 |
| `jwt_id` — a specific JWT by `iss` + `jti` | SSF |
| `saml_assertion_id` — a specific SAML assertion | SSF |
| `ip-addresses` — addresses observed by the Transmitter | SSF |

## Complex subjects

When the event is about a *combination* — this user, on this device, in this tenant — use
`"format": "complex"` with named members:

```json
{
  "format": "complex",
  "user":   { "format": "email",  "email": "alice@example.com" },
  "device": { "format": "opaque", "id": "device-1234" },
  "tenant": { "format": "opaque", "id": "acme" }
}
```

Members defined by SSF: `user`, `device`, `session`, `application`, `tenant`, `org_unit`, `group`.

## Which subjects does a stream cover?

The Transmitter's `default_subjects` setting decides where a new stream starts:

- **`ALL`** — every appropriate subject is included; the Receiver removes the ones it doesn't want.
- **`NONE`** — nothing is included until the Receiver adds subjects.

Receivers add and remove subjects with the `add_subject_endpoint` and `remove_subject_endpoint`.

### Matching complex subjects

A complex subject the Receiver added matches an event if, for every member, either side leaves it
undefined or both sides are identical. So adding just `{ "tenant": … }` matches every event in that
tenant, whatever the user or device.

<div class="callout">
<p><strong>Privacy.</strong> Adding a subject can reveal that the Receiver knows about that person,
and a successful add can reveal that the Transmitter does too. Transmitters should not leak
whether a subject exists, and should only send events about subjects the Receiver is entitled to.</p>
</div>
