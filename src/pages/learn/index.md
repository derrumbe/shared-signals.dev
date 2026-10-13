---
layout: ../../layouts/Learn.astro
title: How Shared Signals works
description: The Shared Signals Framework model in ten minutes — Transmitters, Receivers, streams, Security Event Tokens and subjects.
---

<p class="eyebrow">Learn · Overview</p>

# How Shared Signals works

Single sign-on solved *getting in*. It did nothing about what happens next. Once an app has accepted
a login, it typically keeps trusting that session for hours, even if the user's password was
reset, their laptop was stolen, or their account was disabled five minutes later at the identity
provider.

The **OpenID Shared Signals Framework (SSF)** closes that gap. It defines a standard way for one
system to tell another, *as it happens*, that something security-relevant changed about a user,
device, session, or tenant they both care about.

## The cast

**Transmitter** — the system that observes something and sends an event. An identity provider
revoking a session, an MDM noticing a device is out of compliance, an EDR detecting malware.

**Receiver** — the system that receives events and decides what to do. A SaaS app that logs the
user out, a gateway that steps up authentication, an IdP that raises the user's risk score.

Most real deployments are both: an IdP receives device-compliance events from an MDM and transmits
session-revoked events to its apps.

## The moving parts

| Concept | What it is | Read more |
|---|---|---|
| **Stream** | A configured, long-lived channel from one Transmitter to one Receiver: which events, how delivered, for which subjects. | [Streams](/learn/streams/) |
| **SET** | A *Security Event Token* (RFC 8417): a signed JWT carrying one event. | [SETs](/learn/sets/) |
| **Subject** | Who or what the event is about — identified by email, opaque id, issuer + subject, or a *complex* combination like user + device + tenant. | [Subjects](/learn/subjects/) |
| **Delivery** | SETs are **pushed** to the Receiver over HTTP (RFC 8935) or **polled** from the Transmitter (RFC 8936). | [Delivery](/learn/delivery/) |
| **Discovery** | The Transmitter publishes its capabilities at `/.well-known/ssf-configuration`. | [Discovery](/learn/discovery/) |

## The lifecycle, end to end

1. **Discover.** The Receiver fetches the Transmitter's `/.well-known/ssf-configuration` to learn
   its issuer, signing keys, supported delivery methods and management endpoints.
2. **Authorize.** The Receiver obtains credentials for the management API — usually an OAuth access
   token, as advertised in `authorization_schemes`.
3. **Create a stream.** `POST` to the `configuration_endpoint` with the events it wants and how they
   should be delivered.
4. **Add subjects** (if the Transmitter doesn't default to all of them).
5. **Verify.** Ask the Transmitter to send a *verification* event, proving the pipe works end to end.
6. **Receive events.** Validate each SET's signature, `iss`, `aud` and `typ`, then act on it.
7. **Manage.** Pause, resume, reconfigure or delete the stream as needs change.

## Where CAEP and RISC fit

SSF is the framework. The *events* that flow over it are defined by profiles:

- **[CAEP](/specs/#caep)** — Continuous Access Evaluation Profile. Events about sessions and the
  conditions of access while someone is signed in: session revoked, credential changed, device
  compliance changed, risk level changed.
- **[RISC](/specs/#risc)** — Risk Incident Sharing and Coordination. Events about the account
  itself: disabled, purged, credential compromised, identifier recycled.

Both are used in the same streams; a Receiver asks for whichever event types it can act on. See the
full [event catalogue](/events/).

<div class="callout">
<p><strong>SSF is not a policy engine.</strong> A SET says <em>what happened</em>. What the Receiver does
about it — log out, step up, notify, ignore — is entirely the Receiver's decision.</p>
</div>
