---
layout: ../../layouts/Learn.astro
title: Streams and the management API
description: How SSF Receivers create, configure, pause and verify event streams with a Transmitter.
---

<p class="eyebrow">Learn · Streams</p>

# Streams and the management API

A **stream** is the agreement between one Transmitter and one Receiver about what gets sent and
how. The Receiver creates and manages it through a small REST API whose endpoints the Transmitter
advertises in its [discovery document](/learn/discovery/).

## Creating a stream

```http
POST /ssf/stream HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=
Content-Type: application/json

{
  "delivery": {
    "method": "urn:ietf:rfc:8935",
    "endpoint_url": "https://receiver.example.com/events"
  },
  "events_requested": [
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
    "https://schemas.openid.net/secevent/caep/event-type/credential-change"
  ],
  "description": "Production stream for Acme"
}
```

The Transmitter answers `201 Created` with the full stream configuration. The Receiver **must**
check that the returned `iss` matches the issuer it discovered.

If the request has no `delivery`, the Transmitter assumes **poll** (`urn:ietf:rfc:8936`) and fills
in the `endpoint_url` for the Receiver to poll. If the Transmitter only allows one stream per
Receiver and one already exists, it responds `409 Conflict`.

## The stream configuration

| Field | Set by | Meaning |
|---|---|---|
| `stream_id` | Transmitter | Identifies the stream in every other call. |
| `iss`, `aud` | Transmitter | Issuer and audience that SETs on this stream will carry. |
| `events_supported` | Transmitter | Event types this Transmitter can send. |
| `events_requested` | Receiver | Event types the Receiver wants. |
| `events_delivered` | Transmitter | The intersection actually being sent. |
| `delivery` | Both | `method` and `endpoint_url` (plus `authorization_header` for push). |
| `min_verification_interval` | Transmitter | Minimum seconds between verification requests. |
| `inactivity_timeout` | Transmitter | Seconds of Receiver silence before the Transmitter may pause or delete the stream. |
| `description` | Receiver | Free text. |

## Operations

| Operation | Request |
|---|---|
| Read one or all streams | `GET {configuration_endpoint}?stream_id=…` |
| Update (merge) | `PATCH {configuration_endpoint}` |
| Replace | `PUT {configuration_endpoint}` |
| Delete | `DELETE {configuration_endpoint}?stream_id=…` |
| Read status | `GET {status_endpoint}?stream_id=…` |
| Change status | `POST {status_endpoint}` with `enabled`, `paused` or `disabled` |
| Add a subject | `POST {add_subject_endpoint}` |
| Remove a subject | `POST {remove_subject_endpoint}` |
| Request verification | `POST {verification_endpoint}` |

### Authorization

SSF itself doesn't mandate an auth scheme, but in practice it is OAuth 2.0. The
[CAEP Interoperability Profile](/specs/caep-interop/#oauth) fixes the details: bearer tokens in the
`Authorization` header (never the query string), tokens valid for 60 minutes or less, and two scopes —
`ssf.read` for reading configuration and status, `ssf.manage` for everything else.

## Status: enabled, paused, disabled

- **enabled** — events flow.
- **paused** — the Transmitter *should* hold events and deliver them when the stream is re-enabled (it may drop some).
- **disabled** — the Transmitter drops events; nothing is queued.

If the *Transmitter* changes the status on its own (say, a licence expired), it tells the Receiver
with a [`stream-updated`](/events/#ssf-stream-updated) event.

## Verification

A Receiver can ask, at any time, for proof that the stream works end to end:

```http
POST /ssf/verify HTTP/1.1
Content-Type: application/json

{ "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f", "state": "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo=" }
```

The Transmitter responds `204` and then delivers a [`verification`](/events/#ssf-verification) SET
over the stream, echoing `state`. Seeing that SET arrive confirms discovery, auth, delivery, keys
and validation are all wired correctly — it's the first thing to test with any new partner.

<div class="callout">
<p><strong>Try it.</strong> The sample Transmitter implements this whole API. Drive it as a Receiver from the <a href="/playground/receiver/">Receiver page</a> (create, read, pause, verify, delete) or with curl; pause a stream from the <a href="/playground/transmitter/">Transmitter page</a> to see the Stream Updated event a Transmitter-initiated change sends.</p>
</div>
