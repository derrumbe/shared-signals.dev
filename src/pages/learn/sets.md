---
layout: ../../layouts/Learn.astro
title: Security Event Tokens
description: How SSF events are packaged as signed Security Event Tokens (RFC 8417), and what a Receiver must validate.
---

<p class="eyebrow">Learn · SETs</p>

# Security Event Tokens

Every SSF event travels as a **Security Event Token (SET)** — a JWT defined by
[RFC 8417](https://www.rfc-editor.org/rfc/rfc8417), signed by the Transmitter.

## Anatomy

The header is explicitly typed so a SET can never be mistaken for an ID token or access token:

```json
{ "typ": "secevent+jwt", "alg": "RS256", "kid": "transmitter-key-1" }
```

The payload:

```json
{
  "iss": "https://idp.example.com/",
  "jti": "756E69717565206964656E746966696572",
  "iat": 1760390400,
  "aud": "https://sp.example.com/",
  "txn": "8675309",
  "sub_id": { "format": "email", "email": "alice@example.com" },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "event_timestamp": 1760390391
    }
  }
}
```

| Claim | Notes |
|---|---|
| `iss` | Must equal the `issuer` in the Transmitter's discovery document. |
| `jti` | Unique id — use it to de-duplicate and to acknowledge polled events. |
| `iat` | When the SET was issued. |
| `aud` | The Receiver(s) this SET is for. |
| `sub_id` | The subject (see [Subjects](/learn/subjects/)). |
| `events` | An object with exactly one key — the event type URI — whose value holds the event-specific claims. |
| `txn` | Optional transaction id, linking SETs caused by the same underlying change. |
| `exp` | **Must not** be used in SSF SETs — a defence against confusing a SET with other JWTs. |

## What a Receiver must check

1. `typ` header is `secevent+jwt`.
2. The signature verifies against a key from the Transmitter's `jwks_uri`, using `kid`.
3. `iss` matches the expected Transmitter.
4. `aud` includes this Receiver.
5. The `events` member contains an event type the Receiver asked for.
6. `jti` hasn't been seen before.

Then — and only then — act on the event.

## Informational to mandatory

SSF lets each integration decide how much weight events carry — from purely informational input,
through "please re-evaluate", to enforcement the parties have agreed must happen. That agreement
lives between the Transmitter and Receiver, not in the SET format.

<div class="callout">
<p><strong>Try it.</strong> Paste any SET into the <a href="/playground/inspector/">SET inspector</a> to decode it and run every check above, signature included. Or point your Transmitter at a <a href="/playground/receiver/">sample Receiver</a> to have every SET it sends checked as it arrives.</p>
</div>
