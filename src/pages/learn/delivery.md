---
layout: ../../layouts/Learn.astro
title: Push and poll delivery
description: The two ways SSF delivers Security Event Tokens — HTTP push (RFC 8935) and HTTP poll (RFC 8936).
---

<p class="eyebrow">Learn · Delivery</p>

# Push and poll delivery

SSF doesn't invent a transport. It profiles two IETF standards and identifies each by URN in the
stream's `delivery.method`.

## Push — `urn:ietf:rfc:8935`

The Transmitter `POST`s each SET to an endpoint the Receiver hosts.

```http
POST /events HTTP/1.1
Host: receiver.example.com
Content-Type: application/secevent+jwt
Accept: application/json
Authorization: Bearer <value of delivery.authorization_header>

eyJ0eXAiOiJzZWNldmVudCtqd3QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOi...
```

The Receiver replies **`202 Accepted`** once it has validated the SET, or `400` with an error code
(`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`, …).

- **Use push** when the Receiver can expose a public HTTPS endpoint and wants the lowest latency.
- The Receiver supplies `endpoint_url` and, optionally, `authorization_header` when creating the stream.

## Poll — `urn:ietf:rfc:8936`

The Receiver `POST`s to an endpoint the Transmitter hosts, acknowledging what it has processed and
collecting what's new.

```http
POST /ssf/poll/f67e39a0 HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer <access token>
Content-Type: application/json

{ "ack": ["4d3559ec67504aaba65d40b0363faad8"], "maxEvents": 10, "returnImmediately": false }
```

```json
{
  "sets": {
    "3d0c3cf797584bd193bd0fb1bd4e7d30": "eyJ0eXAiOiJzZWNldmVudCtqd3QiLCJhbGciOiJSUzI1NiJ9...."
  },
  "moreAvailable": false
}
```

The keys in `sets` are each SET's `jti`; the Receiver acknowledges them in the next poll. With
`returnImmediately: false`, the Transmitter may hold the request open (long polling) until events
arrive.

- **Use poll** when the Receiver is behind a firewall, or wants to control its own pace.
- The Transmitter supplies `endpoint_url`. If a stream is created without `delivery`, poll is assumed.

## Choosing

| | Push (8935) | Poll (8936) |
|---|---|---|
| Who hosts the endpoint | Receiver | Transmitter |
| Latency | Lowest | Poll interval (or long-poll) |
| Inbound firewall rule needed at Receiver | Yes | No |
| Back-pressure | Transmitter retries | Receiver controls `maxEvents` |

<div class="callout">
<p><strong>Try it.</strong> On the <a href="/playground/receiver/">Receiver page</a>, create one push stream and one poll stream, fire an event at both from the <a href="/playground/transmitter/">Transmitter page</a>, and compare: push shows the Receiver’s <code>202</code>; poll lets you fetch and acknowledge SETs yourself.</p>
</div>
